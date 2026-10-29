#!/usr/bin/env python3
"""Algorand deploy + hash gate (near-algorand spec §4.9; plan Task 20; R10, R11).

  deploy.py <algod-url>                        create the apps in order — account, relayfee (the router, its executor
                                                salt), one token per ALGORAND_TOKENS entry, mandate, dex — fund every app
                                                address with its base minimum, then the gate; writes
                                                <deployments>/<genesis>.json only when the gate passes
  deploy.py <algod-url> gate <role>=<app id>…  the gate alone (role: account, relayfee, token, mandate, dex)

The gate (R10): each app's approval and clear programs hash (sha512_256) to artifacts.json — those programs reject
update and delete, so a matching app can never change; each token's and the mandate's `account_app` global is the
account app named, the DEX's `router_app` the relayfee named; the router's executor (artifacts.json PREFIX ‖ id ‖
SUFFIX ‖ 20 01 salt) equals its `executor()` and the SDK LogicSig address and is off-curve; every app address holds at
least its minimum balance (an account below it cannot receive the MBR payments of a job).

Router salt (T15 fix 1): the lowest s < 128 whose executor address is off-curve for the app id the create gets
(predicted by simulate). Ids are the chain's transaction counter: when another transaction lands first the router gets
another id; it keeps its salt when that executor is still off-curve, else it is recorded as an orphan (it cannot be
deleted) and the router is created again.

Resumable (task 19 review lesson): the env is checked before any chain step; each create is signed and written to
`<deployments>/<genesis>.<funder>.resume.json` (mode 0600, fsynced, git-ignored) before it is sent, and its app id
after it lands, so a rerun after any failure finds it (algod's pending cache, else the funder's created apps: this code,
the create's arguments as globals, an id at or above the ledger's transaction counter when it was recorded), resends the
same bytes while they are valid, or builds it anew once they can no longer land — never two apps for one role; a resume
file holding apps outside this run's plan is refused; a create still pending is resent only when its recorded bytes
carry this run's programs and parameters, and an app it holds, the deployment file lists or a create landed as is
adopted only with this run's code and parameters (creator, a token's name / symbol / decimals / admin, every link);
funding payments carry a lease (one per app per window); the resume file is removed after the gate.

env:
  ALGORAND_MNEMONIC (25 words) or ALGORAND_PRIVATE_KEY (base64 seed ‖ public key, as kmd exports it): the funding
                    account, every app's creator
  ALGOD_TOKEN       algod's X-Algo-API-Token (optional)
  ALGORAND_TOKENS   "SYMBOL:Name:decimals[,…]" (default "SCT:SCaaS Test:6"; symbol ≤ 8 bytes, name ≤ 32 bytes)
  ALGORAND_ADMIN    the tokens' mint admin (an address; default the funding account)
  ALGORAND_DEPLOYMENTS_DIR  default smartcontracts/algorand/deployments
Programs: smartcontracts/algorand/out/ (smartcontracts/scripts/build.sh algorand first); the venv (scripts/venv.sh).
The deployment file is named by the genesis hash in URL-safe base64 (a '/' cannot be in a file name).
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time

from algosdk import abi, account, encoding, logic, mnemonic, transaction
from algosdk.atomic_transaction_composer import AccountTransactionSigner, AtomicTransactionComposer
from algosdk.error import AlgodHTTPError
from algosdk.v2client import algod, models

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "out")
ARTIFACTS = json.load(open(os.path.join(ROOT, "artifacts.json")))
PROGRAM = {"account": "Account", "relayfee": "RelayFee", "token": "Token", "mandate": "Mandate", "dex": "Dex"}
PAGE = 2048    # protocol bytes per program page (approval + clear); algod refuses a wrong extra_pages
WINDOW = 100   # rounds a deploy transaction stays valid (LastValid − FirstValid, below MaxTxnLife)


def h512(b):
    return hashlib.new("sha512_256", b).hexdigest()


def kind_of(role):
    return role.split(":")[0]


class Spec:
    def __init__(self, name):
        self.approval = open(os.path.join(OUT, f"{name}.approval.bin"), "rb").read()
        self.clear = open(os.path.join(OUT, f"{name}.clear.bin"), "rb").read()
        s = json.load(open(os.path.join(OUT, f"{name}.arc56.json")))
        m = next(m for m in s["methods"] if m["name"] == "create")
        self.create = abi.Method.from_signature("create(%s)%s" % (",".join(a["type"] for a in m["args"]), m["returns"]["type"]))
        self.arg_names = [a["name"] for a in m["args"]]
        g = s["state"]["schema"]["global"]
        self.schema = transaction.StateSchema(g["ints"], g["bytes"])
        self.extra_pages = (len(self.approval) + len(self.clear) - 1) // PAGE


# ------------------------------------------------------------------ executor (T15; the node's `Executor`, conftest's copy)

ED_P = 2**255 - 19
ED_D = (-121665 * pow(121666, ED_P - 2, ED_P)) % ED_P


def on_curve(key):
    """go-algorand basics.IsEdwards25519Point: x^2 = (y^2 - 1) / (d y^2 + 1) has a root mod p (tests/conftest.py)."""
    y = (int.from_bytes(key, "little") & ((1 << 255) - 1)) % ED_P
    u, v = (y * y - 1) % ED_P, (ED_D * y * y + 1) % ED_P
    x = (u * pow(v, 3, ED_P) * pow(u * pow(v, 7, ED_P) % ED_P, (ED_P - 5) // 8, ED_P)) % ED_P
    return (v * x * x) % ED_P in (u % ED_P, (-u) % ED_P)


def executor(router_id, salt):
    r = ARTIFACTS["relayfee"]
    prog = bytes.fromhex(r["executor_prefix"]) + router_id.to_bytes(8, "big") + bytes.fromhex(r["executor_suffix"]) + bytes([0x20, 1, salt])
    return prog, hashlib.new("sha512_256", b"Program" + prog).digest()


def lowest_salt(router_id):
    return next(s for s in range(128) if not on_curve(executor(router_id, s)[1]))


# ------------------------------------------------------------------ algod

def app_info(c, app_id):
    try:
        return c.application_info(app_id)
    except AlgodHTTPError as e:
        if e.code == 404:
            return None
        raise


def globals_of(params):
    out = {}
    for g in params.get("global-state", []):
        v = g["value"]
        out[base64.b64decode(g["key"]).decode("latin1")] = v["uint"] if v["type"] == 2 else base64.b64decode(v["bytes"])
    return out


def sp_window(c):
    sp = c.suggested_params()
    sp.last = sp.first + WINDOW
    return sp


def executor_view(c, router_id, sender):
    """`executor()` by simulate, sent (unsigned) by the router's creator."""
    sel = abi.Method.from_signature("executor()address").get_selector()
    txn = transaction.ApplicationNoOpTxn(sender, c.suggested_params(), router_id, app_args=[sel])
    req = models.SimulateRequest(txn_groups=[models.SimulateRequestTransactionGroup(txns=[transaction.SignedTransaction(txn, None)])],
                                 allow_empty_signatures=True, allow_unnamed_resources=True, extra_opcode_budget=20_000)
    g = c.simulate_transactions(req)["txn-groups"][0]
    if g.get("failure-message"):
        return None
    return base64.b64decode(g["txn-results"][0]["txn-result"]["logs"][-1])[4:]


def gate(c, apps):
    """R10: `apps` = [(kind, app id)]; exits unless every check holds. A token or the mandate is checked against the
    account app named, the DEX against the relayfee named: both must be named (review M3)."""
    bad = []
    acct = [i for k, i in apps if k == "account"]
    rf = [i for k, i in apps if k == "relayfee"]
    kinds = {k for k, _ in apps}
    if kinds & {"token", "mandate"} and not acct:
        bad.append("a token or the mandate is named without account=<the account app>: its account_app link is unchecked")
    if "dex" in kinds and not rf:
        bad.append("the dex is named without relayfee=<the router>: its router_app link is unchecked")
    for kind, i in apps:
        info = app_info(c, i)
        if info is None:
            bad.append(f"{kind} app {i} does not exist")
            continue
        p = info["params"]
        for field, key in (("approval-program", "approval_sha512_256"), ("clear-state-program", "clear_sha512_256")):
            got, want = h512(base64.b64decode(p[field])), ARTIFACTS[kind][key]
            if got != want:
                bad.append(f"{kind} app {i}: {field} sha512_256 {got} is not artifacts.json {want}")
        g = globals_of(p)
        if kind in ("token", "mandate") and acct and g.get("account_app") != acct[0]:
            bad.append(f"{kind} app {i}: its account_app global {g.get('account_app')} is not account={acct[0]}")
        if kind == "dex" and rf and g.get("router_app") != rf[0]:
            bad.append(f"dex app {i}: its router_app global {g.get('router_app')} is not relayfee={rf[0]}")
        if kind == "relayfee":
            salt = g.get("salt")
            if not isinstance(salt, int) or salt >= 128:
                bad.append(f"relayfee app {i}: no salt global below 128 ({salt!r})")
            else:
                prog, addr = executor(i, salt)
                view = executor_view(c, i, p["creator"])
                sdk = transaction.LogicSigAccount(prog).address()
                if view != addr or sdk != encoding.encode_address(addr):
                    bad.append(f"relayfee app {i}: executor() {view and encoding.encode_address(view)} / SDK {sdk} is not the executor "
                               f"rebuilt from salt {salt}: {encoding.encode_address(addr)}")
                if on_curve(addr):
                    bad.append(f"relayfee app {i}: its executor {encoding.encode_address(addr)} (salt {salt}) is on-curve")
        a = c.account_info(logic.get_application_address(i), exclude="all")
        if a["amount"] == 0 or a["amount"] < a["min-balance"]:
            bad.append(f"{kind} app {i}: its address holds {a['amount']} µALGO, below its minimum balance {a['min-balance']}")
    if bad:
        sys.exit("deploy gate FAILED (spec §4.9: every SCaaS app runs the reviewed, non-upgradable program of artifacts.json, "
                 "linked and funded as deployed):\n  " + "\n  ".join(bad))
    print(f"deploy gate: {len(apps)} apps match artifacts.json (approval and clear sha512_256); links, executor and funding checked")


def parse_roles(args):
    out = []
    for a in args:
        m = re.fullmatch(r"(account|relayfee|token|mandate|dex)=(\d+)", a)
        if not m:
            sys.exit(f"gate: {a!r} is not <role>=<app id> (role: account, relayfee, token, mandate, dex)")
        out.append((m.group(1), int(m.group(2))))
    return out or sys.exit("gate: name the apps (<role>=<app id> …)")


# ------------------------------------------------------------------ env (checked before any chain step)

class Funder:
    def __init__(self):
        if os.environ.get("ALGORAND_MNEMONIC"):
            self.sk = mnemonic.to_private_key(os.environ["ALGORAND_MNEMONIC"])
        elif os.environ.get("ALGORAND_PRIVATE_KEY"):
            self.sk = os.environ["ALGORAND_PRIVATE_KEY"]
        else:
            sys.exit("the funding account: set ALGORAND_MNEMONIC (25 words) or ALGORAND_PRIVATE_KEY (base64)")
        self.addr = account.address_from_private_key(self.sk)
        self.signer = AccountTransactionSigner(self.sk)


def parse_tokens():
    tokens = []
    for t in os.environ.get("ALGORAND_TOKENS", "SCT:SCaaS Test:6").split(","):
        parts = t.split(":")
        if (len(parts) != 3 or not re.fullmatch(r"[A-Za-z0-9]{1,8}", parts[0]) or not 1 <= len(parts[1].encode()) <= 32
                or not parts[2].isdigit() or int(parts[2]) > 255):
            sys.exit(f"ALGORAND_TOKENS entry {t!r}: SYMBOL:Name:decimals (symbol ≤ 8 letters / digits, name ≤ 32 bytes, decimals ≤ 255)")
        tokens.append({"symbol": parts[0], "name": parts[1], "decimals": int(parts[2])})
    if len({t["symbol"] for t in tokens}) != len(tokens):
        sys.exit("ALGORAND_TOKENS: a symbol appears twice")
    return tokens


def keep_out_of_git(path):
    """A resume file inside the repository must be one git ignores (`deployments/*.resume.json` is); refused before
    anything is written or sent (task 19 review N3)."""
    try:
        top = subprocess.run(["git", "-C", ROOT, "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return
    if os.path.commonpath([os.path.realpath(top), os.path.realpath(os.path.dirname(path))]) != os.path.realpath(top):
        return
    if subprocess.run(["git", "-C", top, "check-ignore", "-q", path]).returncode != 0:
        sys.exit(f"ALGORAND_DEPLOYMENTS_DIR {os.path.dirname(path)} is inside the repository and git does not ignore "
                 f"{os.path.basename(path)}: use smartcontracts/algorand/deployments or a directory outside it")


# ------------------------------------------------------------------ resumable state

def write_atomic(path, text):
    """tmp (0600), fsync, rename, directory fsync: the file is whole on disk or absent (review M1)."""
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(path + ".tmp", path)
    dfd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class State:
    """Apps by role (the deployment file's, then the resume file's), the signed creates not yet landed, the orphans."""

    def __init__(self, path, deployment):
        self.path = path
        self.resuming = os.path.exists(path)
        r = json.load(open(path)) if self.resuming else {}
        done = json.load(open(deployment))["apps"] if os.path.exists(deployment) else {}
        self.apps = {**done, **r.get("apps", {})}
        self.pending = r.get("pending", {})
        self.orphans = r.get("orphans", [])

    def save(self):
        write_atomic(self.path, json.dumps({"apps": self.apps, "pending": self.pending, "orphans": self.orphans}))  # before a send


# The globals each app's create arguments set, in argument order (the contracts' `create`).
CREATE_GLOBALS = {"account": [], "relayfee": ["salt"], "token": ["name", "symbol", "decimals", "admin", "account_app"],
                  "mandate": ["account_app"], "dex": ["router_app"]}


def recorded(rec):
    """A recorded create as signed: (application arguments, approval, clear) decoded from its bytes."""
    t = encoding.msgpack_decode(rec["stx"]).transaction
    return [bytes(a) for a in (t.app_args or [])], t.approval_program, t.clear_program


def create_globals(s, kind, app_args):
    """The globals create arguments set (bytes / int, as `globals_of` reads them)."""
    out = {}
    for name, a, raw in zip(CREATE_GLOBALS[kind], s.create.args, app_args[1:]):
        v = a.type.decode(raw)
        out[name] = encoding.decode_address(v) if str(a.type) == "address" else bytes(v) if isinstance(v, list) else v
    return out


def encode_args(s, args):
    return [s.create.get_selector()] + [a.type.encode(v) for a, v in zip(s.create.args, args)]


def landed(c, f, role, rec, state):
    """The app id a recorded create got: algod's pending cache, else the funder's created apps (review I2: what a default,
    non-archival node always serves) — an app of this code whose globals are the create's arguments, at or above the id
    predicted when it was recorded, not one of this state's apps or orphans; None = not on chain; two = refused."""
    try:
        info = c.pending_transaction_info(rec["txid"])
        if info.get("confirmed-round"):
            return info["application-index"]
    except AlgodHTTPError as e:
        if e.code != 404:
            raise
    kind = kind_of(role)
    s = Spec(PROGRAM[kind])
    args, _, _ = recorded(rec)
    want = create_globals(s, kind, args)
    known = set(state.apps.values()) | set(state.orphans)
    found = []
    for a in c.account_info(f.addr).get("created-apps", []):
        p = a["params"]
        if (a["id"] >= rec.get("min_id", 0) and a["id"] not in known
                and h512(base64.b64decode(p["approval-program"])) == ARTIFACTS[kind]["approval_sha512_256"]
                and all(globals_of(p).get(k) == v for k, v in want.items())):
            found.append(a["id"])
    if len(found) > 1:
        sys.exit(f"{role}: apps {found} of the funding account all match its recorded create {rec['txid']}: decide which is "
                 f"this deployment's and record it in {state.path}")
    return found[0] if found else None


def txn_counter(c):
    """The last block's transaction counter `tc` (T20 N2: no default; a block without it cannot bound the app id)."""
    rnd = c.status()["last-round"]
    block = c.block_info(round_num=rnd)["block"]
    if "tc" not in block:
        sys.exit(f"block {rnd} has no transaction counter (tc): cannot bound the new app's id; retry after a round")
    return block["tc"]


def send_wait(c, stx_b64, txid, what, state):
    try:
        c.send_raw_transaction(stx_b64)
    except AlgodHTTPError as e:
        if "already in ledger" not in str(e):
            sys.exit(f"{what}: algod refused it: {e} (the deployment so far is kept in {state.path}: rerun to resume)")
    return transaction.wait_for_confirmation(c, txid, WINDOW)


def create(c, f, role, args, state, tokens, admin):
    """Creates `role`'s app (resuming its recorded create) and returns its id; the router's executor must be off-curve."""
    kind = kind_of(role)
    s = Spec(PROGRAM[kind])
    for _ in range(3):
        rec = state.pending.get(role)
        app_id = landed(c, f, role, rec, state) if rec else None
        if app_id is None:
            # review M4: a create whose LastValid is the last round can no longer land (the next block is last + 1)
            if rec is None or c.status()["last-round"] >= rec["last"]:
                # app ids come from the ledger's transaction counter: this create lands at or above the last block's
                min_id = txn_counter(c)
                a = list(args)
                if kind == "relayfee":
                    atc = AtomicTransactionComposer()
                    atc.add_method_call(0, s.create, f.addr, sp_window(c), f.signer, [0], approval_program=s.approval,
                                        clear_program=s.clear, global_schema=s.schema, local_schema=transaction.StateSchema(0, 0),
                                        extra_pages=s.extra_pages)
                    r = atc.simulate(c, models.SimulateRequest(txn_groups=[])).simulate_response["txn-groups"][0]
                    if r.get("failure-message"):
                        sys.exit(f"create {role}: its simulate fails, nothing sent: {r['failure-message'][:300]}")
                    a = [lowest_salt(r["txn-results"][0]["txn-result"]["application-index"])]
                atc = AtomicTransactionComposer()
                sp = sp_window(c)
                atc.add_method_call(0, s.create, f.addr, sp, f.signer, a, approval_program=s.approval, clear_program=s.clear,
                                    global_schema=s.schema, local_schema=transaction.StateSchema(0, 0), extra_pages=s.extra_pages)
                stx = atc.gather_signatures()[0]
                rec = {"txid": stx.get_txid(), "stx": encoding.msgpack_encode(stx), "first": sp.first, "last": sp.last,
                       "min_id": min_id}
                state.pending[role] = rec
                state.save()
            app_id = send_wait(c, rec["stx"], rec["txid"], f"create {role}", state)["application-index"]
        why = adoptable(c, f, role, app_id, tokens, admin, state)
        if why:
            sys.exit(f"{role}: its create landed as {why}: not adopted")
        state.apps[role] = app_id
        del state.pending[role]
        state.save()
        print(f"  create {role}: app {app_id} ({len(s.approval)} B approval, extra_pages {s.extra_pages})")
        if kind != "relayfee":
            return app_id
        salt = globals_of(c.application_info(app_id)["params"])["salt"]
        _, addr = executor(app_id, salt)
        if not on_curve(addr):
            print(f"  relayfee app {app_id}: salt {salt} ({'the lowest' if salt == lowest_salt(app_id) else 'not the lowest'} for this id), "
                  f"executor {encoding.encode_address(addr)} off-curve")
            return app_id
        # ponytail: another transaction took the predicted id; the router (undeletable) is an orphan, created again
        state.orphans.append(app_id)
        del state.apps[role]
        state.save()
        print(f"  relayfee app {app_id} landed off its predicted id and its executor is on-curve: orphaned, created again")
    sys.exit("relayfee: three creates landed off their predicted id with an on-curve executor (a busy chain): rerun")


def fund(c, f, app_id, state):
    """The app address up to its minimum balance (the base minimum of an empty account), once: a lease per app."""
    a = logic.get_application_address(app_id)
    info = c.account_info(a, exclude="all")
    need = info["min-balance"] - info["amount"]
    if info["amount"] > 0 and need <= 0:
        return
    lease = hashlib.sha256(b"scaas.deploy.fund" + app_id.to_bytes(8, "big")).digest()
    txn = transaction.PaymentTxn(f.addr, sp_window(c), a, need, lease=lease)
    stx = f.signer.sign_transactions([txn], [0])[0]
    send_wait(c, encoding.msgpack_encode(stx), stx.get_txid(), f"fund app {app_id}", state)
    print(f"  fund app {app_id} ({a}): {need} µALGO (its minimum balance)")


def want(role, tokens, admin, state):
    """The globals an app of `role` must hold to be adopted (its links to the apps of this run)."""
    kind = kind_of(role)
    if kind == "token":
        t = next(t for t in tokens if role == "token:" + t["symbol"])
        return {"name": t["name"].encode().ljust(32, b"\0"), "symbol": t["symbol"].encode().ljust(8, b"\0"), "decimals": t["decimals"],
                "admin": encoding.decode_address(admin), "account_app": state.apps.get("account")}
    if kind == "mandate":
        return {"account_app": state.apps.get("account")}
    if kind == "dex":
        return {"router_app": state.apps.get("relayfee")}
    return {}


def adoptable(c, f, role, app_id, tokens, admin, state):
    info = app_info(c, app_id)
    if info is None:
        return f"app {app_id} does not exist"
    p = info["params"]
    if h512(base64.b64decode(p["approval-program"])) != ARTIFACTS[kind_of(role)]["approval_sha512_256"]:
        return f"app {app_id} runs another approval program than artifacts.json {kind_of(role)}"
    if p["creator"] != f.addr:
        return f"app {app_id} was created by {p['creator']}, not the funding account {f.addr}"
    g = globals_of(p)
    diff = {k: (g.get(k), v) for k, v in want(role, tokens, admin, state).items() if g.get(k) != v}
    if diff:
        def fmt(k, h):
            if isinstance(h, bytes):
                return h.rstrip(b"\0").decode("latin1") if k in ("name", "symbol") else encoding.encode_address(h)
            return h
        show = {k: tuple(fmt(k, h) for h in pair) for k, pair in diff.items()}
        return f"app {app_id} holds (have, this run's) {show}"
    return None


def create_args(role, tokens, admin, state):
    """`role`'s create arguments in this run (the router's salt is chosen at its create)."""
    kind = kind_of(role)
    if kind == "token":
        t = next(t for t in tokens if role == "token:" + t["symbol"])
        return [t["name"].encode().ljust(32, b"\0"), t["symbol"].encode().ljust(8, b"\0"), t["decimals"], admin, state.apps.get("account")]
    return {"account": [], "relayfee": [], "mandate": [state.apps.get("account")], "dex": [state.apps.get("relayfee")]}[kind]


def deploy(c):
    tokens = parse_tokens()
    f = Funder()
    admin = os.environ.get("ALGORAND_ADMIN", f.addr)
    if not encoding.is_valid_address(admin):
        sys.exit(f"ALGORAND_ADMIN {admin!r} is not an Algorand address")
    sp = c.suggested_params()
    gh, gen = sp.gh, sp.gen
    gfile = gh.replace("+", "-").replace("/", "_")
    d = os.path.abspath(os.environ.get("ALGORAND_DEPLOYMENTS_DIR") or os.path.join(ROOT, "deployments"))
    rpath, dpath = os.path.join(d, f"{gfile}.{f.addr}.resume.json"), os.path.join(d, f"{gfile}.json")
    keep_out_of_git(rpath)
    os.makedirs(d, exist_ok=True)
    state = State(rpath, dpath)
    plan = ["account", "relayfee"] + ["token:" + t["symbol"] for t in tokens] + ["mandate", "dex"]
    stray = sorted((set(state.apps) | set(state.pending)) - set(plan))
    if stray:
        sys.exit(f"{rpath if state.resuming else dpath} holds the apps of {stray}, which this run's plan (ALGORAND_TOKENS) does not "
                 "include: rerun with the original ALGORAND_TOKENS / ALGORAND_ADMIN so that deployment finishes")
    print(f"deploy on {gen} (genesis {gh}) from {f.addr}: {plan}"
          + (f" (resuming: {sorted(state.apps)} created, {sorted(state.pending)} sent)" if state.resuming else ""))
    # adopt nothing this run would not have created (before any transaction)
    for role in plan:
        if role in state.apps:
            why = adoptable(c, f, role, state.apps[role], tokens, admin, state)
            if why:
                sys.exit(f"{role}: {why}: not adopted (change ALGORAND_TOKENS / ALGORAND_ADMIN back, or use another funding account "
                         "or deployments directory)")
    # review I1: a create still pending is resent or adopted only when it was signed with this run's code and parameters
    for role, rec in state.pending.items():
        kind = kind_of(role)
        s = Spec(PROGRAM[kind])
        args, approval, clear = recorded(rec)
        if (approval, clear) != (s.approval, s.clear):
            sys.exit(f"{role}: its recorded create {rec['txid']} carries other programs than out/: not resent (rebuild the same "
                     "programs, or remove its pending entry once it can no longer land)")
        if kind != "relayfee" and args != encode_args(s, create_args(role, tokens, admin, state)):
            show = lambda raw: {k: (v.rstrip(b"\0").decode("latin1") if k in ("name", "symbol") else encoding.encode_address(v))
                                if isinstance(v, bytes) else v for k, v in create_globals(s, kind, raw).items()}
            sys.exit(f"{role}: its recorded create {rec['txid']} (not landed yet, or landed) has {show(args)}, not this run's "
                     f"{show(encode_args(s, create_args(role, tokens, admin, state)))}: not resent, not adopted (change "
                     "ALGORAND_TOKENS / ALGORAND_ADMIN back so that create finishes)")
    for role in plan:
        if role in state.apps:
            print(f"  {role}: app {state.apps[role]} adopted")
        else:
            create(c, f, role, create_args(role, tokens, admin, state), state, tokens, admin)
        fund(c, f, state.apps[role], state)
    apps = [(kind_of(r), state.apps[r]) for r in plan]
    gate(c, apps)
    router = state.apps["relayfee"]
    salt = globals_of(c.application_info(router)["params"])["salt"]
    _, xaddr = executor(router, salt)
    out = {
        "network": gh, "genesis_id": gen, "funder": f.addr, "admin": admin, "apps": {r: state.apps[r] for r in plan},
        "account": state.apps["account"], "relayfee": router, "mandate": state.apps["mandate"], "dex": state.apps["dex"],
        "tokens": [{"app": state.apps["token:" + t["symbol"]], **t} for t in tokens],
        "executor": {"salt": salt, "salt_lowest": salt == lowest_salt(router), "address": encoding.encode_address(xaddr), "prefix": ARTIFACTS["relayfee"]["executor_prefix"],
                     "suffix": ARTIFACTS["relayfee"]["executor_suffix"]},
        "approval_sha512_256": {str(i): ARTIFACTS[k]["approval_sha512_256"] for k, i in apps},
        "orphans": state.orphans, "deployed_at": int(time.time()),
    }
    write_atomic(dpath, json.dumps(out, indent=2) + "\n")
    if os.path.exists(rpath):
        os.remove(rpath)
    print(f"wrote {dpath}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    c = algod.AlgodClient(os.environ.get("ALGOD_TOKEN", ""), sys.argv[1])
    if sys.argv[2:3] == ["gate"]:
        gate(c, parse_roles(sys.argv[3:]))
    elif len(sys.argv) == 2:
        deploy(c)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
