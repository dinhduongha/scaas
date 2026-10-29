#!/usr/bin/env python3
"""NEAR keyless deploy (near-algorand spec §3.7, §3.9; plan Task 19; README principle 5).

  deploy.py <rpc-url>                  deploy every SCaaS account, initialise it, register every lane on every token
                                       (storage_deposit), delete every access key, then the gate; writes
                                       <deployments>/<genesis-hash>.json only when the gate passes
  deploy.py <rpc-url> gate <account…>  the gate alone: fails unless view_access_key_list is empty for each account

Accounts are sub-accounts of the funding account F: one token per NEAR_TOKENS entry (`<symbol lower>.F`), `dex.F`,
`relayfee.F` (the escrow router), `relayexec.F` (its executor). Each is created with a temporary full-access key, its
code and its balance (code + NEAR_FUND NEAR) in one transaction; the account itself signs `new(…)` and then, after the
lane registrations, the deletion of that key. Nothing else ever holds a key: the code cannot change (no contract issues
DeployContract / AddKey / DeleteKey / DeleteAccount, checked by check_no_authority.sh), and the node re-checks the key
lists at start (halted otherwise).

Resumable (task review I3): NEAR_LANES / NEAR_TOKENS are checked before any chain step; each temporary key is written
to `<deployments>/<genesis>.<funder>.resume.json` (mode 0600, git-ignored) before it is used; every step is skipped when
already done (account created with this code, `new` run, lane registered, key deleted), so a rerun after any failure or
interruption finishes the deployment; the key deletions and the gate run last, and the resume file is removed after it.

env:
  NEAR_ACCOUNT_ID, NEAR_PRIVATE_KEY (ed25519:<base58>)  the funding account; or NEAR_KEY_FILE, a JSON with account_id and
                                                         secret_key (near-sandbox validator_key.json, near-cli credentials)
  NEAR_TOKENS       "SYMBOL:Name:decimals[,…]" (default "SCT:SCaaS Test:6")
  NEAR_ADMIN        the tokens' mint admin (default the funding account)
  NEAR_LANES        the relayer lanes (implicit account ids, comma-separated), each registered on each token
  NEAR_FUND         NEAR per contract account above its code's storage (default 2)
  NEAR_DEPLOYMENTS_DIR  default smartcontracts/near/deployments
Wasm: smartcontracts/near/target/near/<crate>/<crate>.wasm (smartcontracts/scripts/build.sh near first).
Needs python3 with `cryptography` (as smartcontracts/vectors/metatx/famvec.py).
"""
import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

NEAR_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TGAS = 10**12
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58e(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def b58d(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw


class Rpc:
    def __init__(self, url):
        self.url = url

    def __call__(self, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": "deploy", "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, body, {"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            v = json.load(r)
        if v.get("error"):
            raise RuntimeError(f"{method}: {json.dumps(v['error'])}")
        return v["result"]

    def query(self, **q):
        return self("query", dict(finality="final", **q))

    def view(self, account, method, args=b""):
        r = self.query(request_type="call_function", account_id=account, method_name=method,
                       args_base64=base64.b64encode(args).decode())
        if "error" in r:  # a contract panic comes back inside the result
            raise RuntimeError(f"view {account}.{method}: {r['error']}")
        return bytes(r["result"])


# ------------------------------------------------------------------ Borsh transaction (nearcore Transaction::V0)

def u32(n):
    return struct.pack("<I", n)


def bstr(s):
    b = s if isinstance(s, bytes) else s.encode()
    return u32(len(b)) + b


def pk_borsh(pk):
    return b"\0" + pk  # KeyType::ED25519


def create_account():
    return b"\0"


def deploy_contract(code):
    return b"\1" + bstr(code)


def function_call(method, args, gas, deposit=0):
    return b"\2" + bstr(method) + bstr(args) + struct.pack("<Q", gas) + deposit.to_bytes(16, "little")


def transfer(amount):
    return b"\3" + amount.to_bytes(16, "little")


def add_full_key(pk):
    return b"\5" + pk_borsh(pk) + struct.pack("<Q", 0) + b"\1"  # AccessKey { nonce 0, FullAccess }


def delete_key(pk):
    return b"\6" + pk_borsh(pk)


class Key:
    def __init__(self, account, sk: ed25519.Ed25519PrivateKey):
        self.account, self.sk = account, sk
        self.pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.nonce = None

    @staticmethod
    def parse(account, secret):
        raw = b58d(secret.split(":", 1)[1])
        return Key(account, ed25519.Ed25519PrivateKey.from_private_bytes(raw[:32]))

    def pk_str(self):
        return "ed25519:" + b58e(self.pk)

    def send(self, rpc, receiver, actions, what):
        if self.nonce is None:
            self.nonce = rpc.query(request_type="view_access_key", account_id=self.account, public_key=self.pk_str())["nonce"]
        self.nonce += 1
        block = b58d(rpc("block", {"finality": "final"})["header"]["hash"])
        tx = (bstr(self.account) + pk_borsh(self.pk) + struct.pack("<Q", self.nonce) + bstr(receiver) + block
              + u32(len(actions)) + b"".join(actions))
        h = hashlib.sha256(tx).digest()
        signed = tx + b"\0" + self.sk.sign(h)
        try:
            r = rpc("send_tx", {"signed_tx_base64": base64.b64encode(signed).decode(), "wait_until": "FINAL"})
        except (OSError, RuntimeError) as e:
            if isinstance(e, RuntimeError) and "TIMEOUT_ERROR" not in str(e):
                raise
            # the transaction may have landed (review I3): ask for it instead of failing; a rerun resumes otherwise
            r = rpc("EXPERIMENTAL_tx_status", {"tx_hash": b58e(h), "sender_account_id": self.account, "wait_until": "FINAL"})
        failed = [o for o in [r["transaction_outcome"]] + r["receipts_outcome"] if "Failure" in o["outcome"]["status"]]
        if "Failure" in r["status"] or failed:
            raise RuntimeError(f"{what}: {json.dumps(r['status'])} {[f['outcome']['status'] for f in failed]}")
        burnt = sum(o["outcome"]["gas_burnt"] for o in [r["transaction_outcome"]] + r["receipts_outcome"])
        print(f"  {what}: ok, {burnt / TGAS:.3f} Tgas")
        return r


# ------------------------------------------------------------------ deploy

def wasm(crate):
    p = os.path.join(NEAR_DIR, "target", "near", crate, f"{crate}.wasm")
    if not os.path.exists(p):
        sys.exit(f"{p}: run smartcontracts/scripts/build.sh near first")
    return open(p, "rb").read()


def token_metadata(name, symbol, decimals):
    """FungibleTokenMetadata (NEP-148) Borsh: spec, name, symbol, icon, reference, reference_hash, decimals."""
    return bstr("ft-1.0.0") + bstr(name) + bstr(symbol) + b"\0" + b"\0" + b"\0" + bytes([decimals])


def gate(rpc, accounts):
    """Spec §3.9 / R10: every SCaaS account keyless, else the run fails."""
    bad = []
    for a in accounts:
        keys = rpc.query(request_type="view_access_key_list", account_id=a)["keys"]
        if keys:
            bad.append(f"{a} has {len(keys)} access key(s): {[k['public_key'] for k in keys]}")
    if bad:
        sys.exit("deploy gate FAILED (spec §3.9: every SCaaS NEAR account is keyless):\n  " + "\n  ".join(bad))
    print(f"deploy gate: {len(accounts)} accounts keyless (view_access_key_list empty)")


def funder():
    if os.environ.get("NEAR_KEY_FILE"):
        k = json.load(open(os.environ["NEAR_KEY_FILE"]))
        return Key.parse(k["account_id"], k.get("secret_key") or k["private_key"])
    return Key.parse(os.environ["NEAR_ACCOUNT_ID"], os.environ["NEAR_PRIVATE_KEY"])


def parse_lanes():
    """NEAR_LANES before any chain step (review m6): at least one, each an implicit account id (64 lower-case hex)."""
    lanes = [x.strip() for x in os.environ.get("NEAR_LANES", "").split(",") if x.strip()]
    bad = [x for x in lanes if not re.fullmatch(r"[0-9a-f]{64}", x)]
    if not lanes or bad:
        sys.exit(f"NEAR_LANES must list the relayer lanes (implicit account ids, 64 lower-case hex): {bad or 'none given'}")
    return lanes


def parse_tokens(funder_id):
    tokens = []
    for t in os.environ.get("NEAR_TOKENS", "SCT:SCaaS Test:6").split(","):
        parts = t.split(":")
        if len(parts) != 3 or not re.fullmatch(r"[A-Za-z0-9]{1,16}", parts[0]) or not parts[2].isdigit():
            sys.exit(f"NEAR_TOKENS entry {t!r}: SYMBOL:Name:decimals")
        tokens.append({"account": f"{parts[0].lower()}.{funder_id}", "symbol": parts[0], "name": parts[1], "decimals": int(parts[2])})
    return tokens


# A view that panics with "not initialized" until `new` ran (near-sdk PanicOnDefault), per crate.
INIT_VIEW = {"scaas_near_token": ("network", b""), "scaas_near_dex": ("pending", b"\0" * 32),
             "scaas_near_relayfee": ("executor", b""), "scaas_near_relayexec": ("router", b"")}


def initialised(rpc, account, crate):
    method, args = INIT_VIEW[crate]
    try:
        rpc.view(account, method, args)
        return True
    except RuntimeError as e:
        if "not initialized" in str(e):
            return False
        raise


def view_account(rpc, account):
    try:
        return rpc.query(request_type="view_account", account_id=account)
    except RuntimeError as e:
        if "UNKNOWN_ACCOUNT" in str(e):
            return None
        raise


class Resume:
    """The temporary full-access keys of a run in progress (review I3): a git-ignored 0600 JSON file beside the
    deployment, written before the key is used on chain, removed once the gate passed. A rerun resumes from it."""

    def __init__(self, path):
        self.path = path
        self.keys = json.load(open(path)) if os.path.exists(path) else {}

    def key(self, account):
        if account not in self.keys:
            sk = ed25519.Ed25519PrivateKey.generate()
            raw = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            self.keys[account] = "ed25519:" + b58e(raw + pk)
            fd = os.open(self.path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(self.keys, fh)
                fh.flush()
                os.fsync(fh.fileno())  # review N3: on disk before the key is used on chain
            os.replace(self.path + ".tmp", self.path)
            dfd = os.open(os.path.dirname(self.path), os.O_RDONLY)
            try:
                os.fsync(dfd)  # and the rename
            finally:
                os.close(dfd)
        return Key.parse(account, self.keys[account])


def keep_out_of_git(path):
    """Review N3: a resume file inside the repository must be one git ignores (the default directory's
    `deployments/*.resume.json` is); refused before anything is written or sent."""
    try:
        top = subprocess.run(["git", "-C", NEAR_DIR, "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return  # not in a git checkout
    if os.path.commonpath([os.path.realpath(top), os.path.realpath(os.path.dirname(path))]) != os.path.realpath(top):
        return
    if subprocess.run(["git", "-C", top, "check-ignore", "-q", path]).returncode != 0:
        sys.exit(f"NEAR_DEPLOYMENTS_DIR {os.path.dirname(path)} is inside the repository and git does not ignore "
                 f"{os.path.basename(path)} (the temporary keys): use smartcontracts/near/deployments or a directory outside it")


def deploy(rpc):
    """Every step is skipped when already done, so a rerun after any failure resumes (review I3); the key deletions
    and the gate run last."""
    lanes = parse_lanes()
    f = funder()
    tokens = parse_tokens(f.account)
    status = rpc("status", [])
    genesis = status["genesis_hash"]
    network = b58d(genesis)
    assert len(network) == 32, genesis
    byte_cost = int(rpc("EXPERIMENTAL_protocol_config", {"finality": "final"})["runtime_config"]["storage_amount_per_byte"])
    fund = int(float(os.environ.get("NEAR_FUND", "2")) * 10**24)
    admin = os.environ.get("NEAR_ADMIN", f.account)
    dex, router, executor = (f"{n}.{f.account}" for n in ("dex", "relayfee", "relayexec"))
    plan = [(t["account"], "scaas_near_token", network + bstr(admin) + token_metadata(t["name"], t["symbol"], t["decimals"]))
            for t in tokens]
    plan += [(dex, "scaas_near_dex", b""), (router, "scaas_near_relayfee", bstr(executor)), (executor, "scaas_near_relayexec", bstr(router))]
    d = os.path.abspath(os.environ.get("NEAR_DEPLOYMENTS_DIR") or os.path.join(NEAR_DIR, "deployments"))
    rpath = os.path.join(d, f"{genesis}.{f.account}.resume.json")
    keep_out_of_git(rpath)
    os.makedirs(d, exist_ok=True)
    resume = Resume(rpath)
    # review N2: keys of accounts outside this plan stay with their file (never removed, never orphaned)
    stray = sorted(set(resume.keys) - {p[0] for p in plan})
    if stray:
        sys.exit(f"{rpath} holds the temporary keys of {stray}, which this run's plan (NEAR_TOKENS) does not include: "
                 "rerun with the original NEAR_TOKENS / NEAR_ADMIN so the interrupted deployment finishes")
    print(f"deploy on {status['chain_id']} (genesis {genesis}) from {f.account}: {[p[0] for p in plan]}"
          + (f" (resuming: {sorted(resume.keys)})" if resume.keys else ""))
    # review N1: an existing account is adopted only with this code and, for a token, these parameters (before any send)
    meta = {t["account"]: t for t in tokens}
    for account, crate, _ in plan:
        acct = view_account(rpc, account)
        if acct is None:
            continue
        if acct["code_hash"] != b58e(hashlib.sha256(wasm(crate)).digest()):
            sys.exit(f"{account} exists with other code: not this deployment's (another funding account or NEAR_TOKENS)")
        if account in meta and initialised(rpc, account, crate):
            t, m = meta[account], json.loads(rpc.view(account, "ft_metadata"))
            have = (m["name"], m["symbol"], m["decimals"], json.loads(rpc.view(account, "admin")))
            want = (t["name"], t["symbol"], t["decimals"], admin)
            if have != want:
                sys.exit(f"{account} exists with (name, symbol, decimals, admin) {have}, not this run's {want}: "
                         "not adopted (change NEAR_TOKENS / NEAR_ADMIN back, or use another funding account)")
    for account, crate, init in plan:
        code = wasm(crate)
        acct = view_account(rpc, account)
        if acct is None:
            tmp = resume.key(account)
            amount = len(code) * byte_cost + fund
            f.send(rpc, account, [create_account(), transfer(amount), add_full_key(tmp.pk), deploy_contract(code)],
                   f"create {account} ({crate}, {len(code)} B, {amount / 10**24:.3f} NEAR)")
            acct = view_account(rpc, account)
        if acct is None or acct["code_hash"] != b58e(hashlib.sha256(code).digest()):
            sys.exit(f"{account} exists with other code: not this deployment's (another funding account or NEAR_TOKENS)")
        if not initialised(rpc, account, crate):
            if account not in resume.keys:
                sys.exit(f"{account} is not initialised and its key is not in {resume.path}")
            resume.key(account).send(rpc, account, [function_call("new", init, 100 * TGAS)], f"{account}.new")
        else:
            print(f"  {account}: deployed and initialised")
    for t in tokens:
        bounds = json.loads(rpc.view(t["account"], "storage_balance_bounds"))
        for lane in lanes:
            if json.loads(rpc.view(t["account"], "storage_balance_of", json.dumps({"account_id": lane}).encode())) is not None:
                continue
            args = json.dumps({"account_id": lane, "registration_only": True}).encode()
            f.send(rpc, t["account"], [function_call("storage_deposit", args, 30 * TGAS, int(bounds["min"]))],
                   f"{t['account']}.storage_deposit({lane})")
    for account, _, _ in plan:
        listed = {k["public_key"] for k in rpc.query(request_type="view_access_key_list", account_id=account)["keys"]}
        if account in resume.keys and resume.key(account).pk_str() in listed:
            k = resume.key(account)
            k.send(rpc, account, [delete_key(k.pk)], f"{account}: delete its last access key")
    accounts = [p[0] for p in plan]
    gate(rpc, accounts)
    out = {
        "network": genesis, "chain_id": status["chain_id"], "funder": f.account, "admin": admin,
        "tokens": [{"account": t["account"], "symbol": t["symbol"], "decimals": t["decimals"]} for t in tokens],
        "dex": dex, "relayfee": router, "relayexec": executor, "lanes": lanes,
        "code_hash": {a: rpc.query(request_type="view_account", account_id=a)["code_hash"] for a in accounts},
        "deployed_at": int(time.time()),
    }
    path = os.path.join(d, f"{genesis}.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    if os.path.exists(resume.path):
        os.remove(resume.path)
    print(f"wrote {path}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    rpc = Rpc(sys.argv[1])
    if sys.argv[2:3] == ["gate"]:
        gate(rpc, sys.argv[3:] or sys.exit("gate: name the accounts"))
    elif len(sys.argv) == 2:
        deploy(rpc)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
