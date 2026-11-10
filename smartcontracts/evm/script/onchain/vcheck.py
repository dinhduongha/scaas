#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b, NET-EVM-09 (owner 2026-11-10): every contract on a chain verified on its Blockscout.

Discovery over the whole chain, to a fixed point: every top-level creation (a CREATE transaction, a CREATE2 through the
deterministic deployer), every transaction's `to`, every log's emitter and the address-shaped words of its topics and
data (a block scan, cached in cache/vcheck-<chain>-<genesis>.json), the deployment books (deployments/<key>.json and its
releases json by the chain's key, NET-EVM-13, their headers checked; onchain-<net>-*.json), every broadcast of the chain (broadcast/*/<chain>/*.json), then the getters that
name a child: puller(), EXECUTOR(), modules(), an EIP-1167 clone's implementation, and per factory its releases, its
envs' registry / account implementation / dependencies / libraries and contractsPage per class.

Each address with code ends in one state: verified (full match), verified (partial, harness) (a partial match of a
harness contract: its code's metadata names a script/ source of a snapshot, owner 2026-11-10), linked clone (EIP-1167,
Blockscout links it to its verified implementation), linked (clone, appended data) (vcheck links it, owner 2026-11-10:
the first 45 bytes exactly the EIP-1167 proxy of a fully verified implementation, data after them; Blockscout 9.0.2
answers proxy_type unknown), data (SSTORE2, code 0x00...), create3 proxy (the 8-byte CREATE3 proxy, src/factory/Create3.sol:
bytecode without a Solidity source), genesis (code at block 0: a predeploy, not ours); an address a
book or broadcast names without code on the chain is listed as `no code` (a fork broadcast); anything else is
`unverified`, a fail row, exit 1.

Names come from the code: the metadata hash at the end of the runtime code against the artifacts of the source
snapshots (--root, each built once by verify.sh); a contract whose metadata matches no artifact fails with that
reason. --fix verifies, one contract at a time: `forge verify-contract` in its snapshot, outside scripts/capped under
a memory scope with no slot (VERIFY_MEM, default 1G), bounded by VERIFY_TIMEOUT (default 600 s), a heartbeat every
30 s; constructor arguments are the init code (the creating transaction's input, a broadcast's initCode) after the
artifact's creation bytecode; a child created inside a call has no creation code on Blockscout, which then matches the
deployed code. Any forge output that compiles aborts the run (exit 2): the snapshot build is stale.
  python3 -I script/onchain/vcheck.py <net> [--config] [--root <snapshot> ...] [--fix] [--only a,b]
The explorer (NET-EVM-12) from the environment: VERIFY_EXPLORER blockscout | etherscan (the v2 API, the chain by
`chainid`) | sourcify, VERIFY_URL its API, VERIFY_RPC the chain's RPC, VERIFY_API_KEY_ENV the NAME of the env var that
holds the API key (required for etherscan; forge gets it in its environment, never as an argument), VERIFY_SCAN=1 the
whole-chain scan (a chain of ours only). scaas-testnet defaults: its Blockscout and RPC on loopback (BLOCKSCOUT_API,
RPC_7622), the scan on. A target without an explorer: VERIFY_NOT_CONFIGURED, exit 1. --config checks that and stops.
On Etherscan and Sourcify a clone's own code is its link (no proxy link to read there).
Rows: <state> | <name> | <address> [| note]. Test chains only."""
import glob
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
sys.path.insert(0, os.path.join(EVM, "script"))
import deploybook  # noqa: E402
CLONE_HEAD, CLONE_TAIL = "363d3d373d3d3d363d73", "5af43d82803e903d91602b57fd5bf3"
DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c"  # the deterministic CREATE2 deployer (NET-EVM-05)
CREATE3_PROXY = "0x363d3d37363d34f0"  # src/factory/Create3.sol: the proxy that CREATEs its calldata
STATES = ("verified", "verified (partial, harness)", "linked clone", "linked (clone, appended data)", "data", "create3 proxy", "genesis", "no code", "unverified")
SEL = {  # cast sig
    "puller": "2b1826ea", "EXECUTOR": "630dc7cb", "modules": "f7e80e98", "latestDexVersion": "aca84f05",
    "latestVersion": "7f4782bd", "implementationOf": "c45d1620", "dexImplementationOf": "c4c41b19",
    "latestTokenEnvVersion": "caf571af", "latestDexEnvVersion": "8ace72a2", "tokenEnvOf": "4ae0f85a", "dexEnvOf": "e3eef243",
    "contractsPage": "0ca57b48",
}
PLACEHOLDER = re.compile(r"__\$[0-9a-fA-F]{34}\$__")
COMPILES = re.compile(r"Compiling \d+ files|Compiler run|Solc [0-9.]+ finished")


# ---------------------------------------------------------------- pure helpers (script/onchain/test_vcheck.py)

def clone_impl(code):
    """The implementation of an EIP-1167 clone (data may follow the 45-byte proxy), else None."""
    c = (code or "").lower()
    c = c[2:] if c.startswith("0x") else c
    return "0x" + c[20:60] if c.startswith(CLONE_HEAD) and c[60:90] == CLONE_TAIL else None


def cbor(code):
    """The metadata CBOR at the end of a runtime code (hex), else None."""
    h = (code or "").lower()
    h = h[2:] if h.startswith("0x") else h
    if len(h) < 8:
        return None
    n = int(h[-4:], 16) * 2
    if n < 8 or n + 4 > len(h) or not h[-n - 4:-4].startswith("a"):
        return None
    return h[-n - 4:-4]


def init_args(bytecode, init):
    """The constructor arguments when init code starts with an artifact's creation bytecode (library placeholders are
    wildcards of their length), else None."""
    b = (bytecode or "").lower()
    b = b[2:] if b.startswith("0x") else b
    i = (init or "").lower()
    i = i[2:] if i.startswith("0x") else i
    segs, pos = PLACEHOLDER.split(b), 0
    for k, s in enumerate(segs):
        if i[pos:pos + len(s)] != s.lower():
            return None
        pos += len(s) + (40 if k < len(segs) - 1 else 0)
    return i[pos:] if len(i) >= pos and b else None


def full(sc):
    """Blockscout's smart-contracts answer is a full match."""
    return sc.get("is_verified") is True and not sc.get("is_partially_verified") and sc.get("is_fully_verified") is not False


def harness(hit, sc):
    """The deployed code's metadata names an artifact compiled from script/ (a harness contract) and the explorer's
    match carries that artifact's name."""
    return bool(hit) and hit[2].startswith("script/") and sc.get("name") == hit[3]


def classify(code, sc, impl_verified=False, genesis=False, harness=False):
    """(state, note) of one address from its code, Blockscout's smart-contracts answer, for a clone whether its
    implementation is verified, and whether it is a harness contract (harness())."""
    c = (code or "0x").lower()
    if c in ("0x", "0x0", ""):
        return "no code", ""
    if genesis:
        return "genesis", "code at block 0 (a predeploy, not ours)"
    if c.startswith("0x00"):
        return "data", f"{(len(c) - 2) // 2} B"
    if c == CREATE3_PROXY:
        return "create3 proxy", "the 8-byte CREATE3 proxy of src/factory/Create3.sol, bytecode without a source"
    impl = clone_impl(c)
    if impl:
        li = [(x.get("address_hash") or x.get("address") or "").lower() for x in sc.get("implementations") or []]
        ok = sc.get("proxy_type") in ("eip1167", "clone_with_immutable_arguments") and impl in li and impl_verified
        extra = (len(c) - 2) // 2 - 45
        if ok:
            return "linked clone", f"{sc.get('proxy_type')} of {impl}"
        if extra > 0 and impl_verified:
            return "linked (clone, appended data)", (f"EIP-1167 proxy of {impl} (verified), {extra} B appended; the explorer: "
                                                     f"{sc.get('proxy_type') or 'no proxy type'}")
        return "unverified", (f"{sc.get('proxy_type') or 'no proxy type'} of {impl}: implementations {li}, "
                              f"implementation verified {bool(impl_verified)}")
    if full(sc):
        return "verified", ""
    if harness and sc.get("is_verified") is True and sc.get("is_partially_verified") is True:
        return "verified (partial, harness)", "partial match (the metadata hash differs) of a script/ harness contract"
    return "unverified", "partial match" if sc.get("is_verified") else "not verified"


def words(hexdata):
    h = (hexdata or "0x")[2:]
    return [h[k:k + 64] for k in range(0, len(h) - 63, 64)]


def addr_words(hexdata):
    """Address-shaped 32-byte words (12 zero bytes, a value above 2^64)."""
    return ["0x" + w[24:] for w in words(hexdata) if w[:24] == "0" * 24 and int(w[24:], 16) >> 64]


def word_addr(hexdata):
    w = words(hexdata)
    return "0x" + w[0][24:] if len(w) == 1 and w[0][:24] == "0" * 24 and int(w[0], 16) else None


def dyn_addrs(hexdata):
    """address[] returned alone."""
    w = words(hexdata)
    try:
        o = int(w[0], 16) // 32
        return ["0x" + x[24:] for x in w[o + 1:o + 1 + int(w[o], 16)]]
    except (IndexError, ValueError):
        return []


def env_addrs(hexdata):
    """The addresses of an IFactoryToken.Env returned alone: registry, smartKeyAccountImpl, deps[], libs[]."""
    w = words(hexdata)
    try:
        t = int(w[0], 16) // 32
        out = ["0x" + w[t][24:], "0x" + w[t + 1][24:]]
        for f in (3, 5):  # deps, libs (offsets relative to the tuple)
            o = t + int(w[t + f], 16) // 32
            out += ["0x" + x[24:] for x in w[o + 1:o + 1 + int(w[o], 16)]]
        return out
    except (IndexError, ValueError):
        return []


def page_addrs(hexdata):
    """(Created[] , uint256): each Created's first field, the address (8 static words per entry)."""
    w = words(hexdata)
    try:
        o = int(w[0], 16) // 32
        return ["0x" + w[o + 1 + 8 * k][24:] for k in range(int(w[o], 16))]
    except (IndexError, ValueError):
        return []


# ---------------------------------------------------------------- explorer kinds (NET-EVM-12)

KINDS = ("blockscout", "etherscan", "sourcify")


class NotConfigured(Exception):
    pass


def config(net, env):
    """The target's verification config from the environment: the explorer kind, its API URL, the RPC, the NAME of
    the env var that holds the API key (never the key in a file or an argument) and whether the whole chain is
    scanned (only a chain of ours: the SCaaS testnet). NotConfigured (VERIFY_NOT_CONFIGURED) when a remote target
    names no explorer."""
    c = {"kind": env.get("VERIFY_EXPLORER", ""), "url": env.get("VERIFY_URL", ""), "rpc": env.get("VERIFY_RPC", ""),
         "key_env": env.get("VERIFY_API_KEY_ENV", ""), "scan": env.get("VERIFY_SCAN", "0") == "1"}
    if net == "scaas-testnet":  # its own Blockscout and RPC, loopback (NET-EVM-09)
        c["kind"] = c["kind"] or "blockscout"
        c["url"] = c["url"] or env.get("BLOCKSCOUT_API", "http://127.0.0.1:4000/api")
        c["rpc"] = c["rpc"] or env.get("RPC_7622", "http://127.0.0.1:8545")
        c["scan"] = env.get("VERIFY_SCAN", "1") == "1"
    if not c["kind"]:
        raise NotConfigured(f"no explorer for target {net}: set VERIFY_EXPLORER ({', '.join(KINDS)}) and VERIFY_URL, "
                            "or VERIFY=none with VERIFY_REASON")
    if c["kind"] not in KINDS:
        raise NotConfigured(f"VERIFY_EXPLORER {c['kind']!r} is not one of {', '.join(KINDS)}")
    if not re.fullmatch(r"https?://\S+", c["url"]):
        raise NotConfigured(f"VERIFY_URL {c['url']!r}: the {c['kind']} API URL is missing or not http(s)")
    if not re.fullmatch(r"https?://\S+", c["rpc"]):
        raise NotConfigured(f"VERIFY_RPC {c['rpc']!r}: the chain's RPC is missing or not http(s)")
    if c["key_env"] and not re.fullmatch(r"[A-Z_][A-Z0-9_]*", c["key_env"]):
        raise NotConfigured(f"VERIFY_API_KEY_ENV {c['key_env']!r} is not an env var name")
    c["key"] = env.get(c["key_env"], "") if c["key_env"] else ""
    if c["kind"] == "etherscan" and not c["key"]:
        raise NotConfigured("etherscan needs VERIFY_API_KEY_ENV naming a set env var that holds the API key")
    c["url"] = c["url"].rstrip("/")
    return c


def lookup_url(kind, url, chain, a, key=""):
    """The explorer request that tells whether an address is verified."""
    if kind == "blockscout":
        return f"{url}/v2/smart-contracts/{a}"
    if kind == "etherscan":  # the v2 API: one endpoint, the chain by `chainid`
        return url + "?" + urllib.parse.urlencode({"chainid": chain, "module": "contract", "action": "getsourcecode",
                                                   "address": a, "apikey": key})
    return f"{url}/v2/contract/{chain}/{a}"  # sourcify


def normalize(kind, j, code):
    """An explorer's answer as Blockscout's smart-contracts fields. Etherscan and Sourcify have no link from an
    EIP-1167 clone to its implementation that this check can read: there the clone's own code is the link."""
    if kind == "blockscout":
        return j
    impl = clone_impl(code)
    if kind == "etherscan":
        r = j.get("result")
        r = r[0] if isinstance(r, list) and r and isinstance(r[0], dict) else {}
        ok = bool(r.get("SourceCode"))
        out = {"is_verified": ok, "is_partially_verified": ok and bool(r.get("SimilarMatch")), "name": r.get("ContractName") or None}
    else:  # sourcify: exact_match = the metadata hash too (full), match = the bytecode only (partial)
        m = j.get("match")
        out = {"is_verified": m in ("exact_match", "match"), "is_partially_verified": m == "match", "name": j.get("name")}
    if impl:
        out.update(proxy_type="eip1167", implementations=[{"address": impl}])
    return out


def forge_args(kind, url, chain):
    """forge verify-contract's explorer arguments; the API key only in the environment (forge_env)."""
    return ["--verifier", kind, "--verifier-url", url + ("/" if kind != "etherscan" else ""), "--chain-id", str(chain)]


def forge_env(env, key):
    e = {k: v for k, v in env.items() if k not in ("FOUNDRY_OUT", "FOUNDRY_CACHE_PATH", "VERIFIER_API_KEY", "ETHERSCAN_API_KEY")}
    e["FOUNDRY_PROFILE"] = env.get("FOUNDRY_PROFILE", "scaas-testnet")
    if key:
        e["VERIFIER_API_KEY"] = e["ETHERSCAN_API_KEY"] = key
    return e


# ---------------------------------------------------------------- chain and explorer

def say(msg):
    print(f"[{NET}/verify] {msg}", flush=True)


def batch(calls, size=100):
    """JSON-RPC batch (the SCaaS testnet's MaxBatchSize is 100); None for an error answer."""
    out = []
    for k in range(0, len(calls), size):
        body = [{"jsonrpc": "2.0", "id": i, "method": m, "params": p} for i, (m, p) in enumerate(calls[k:k + size])]
        for t in range(5):
            try:
                q = urllib.request.Request(RPC, json.dumps(body).encode(), {"Content-Type": "application/json"})
                r = json.load(urllib.request.urlopen(q, timeout=120))
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if t == 4:
                    raise
                time.sleep(3 * (t + 1))
        out += [x.get("result") for x in sorted(r, key=lambda x: x["id"])]
    return out


def rpc(m, p):
    return batch([(m, p)])[0]


def get(url):
    """An explorer GET; {} for a 404; backs off on 429 / 5xx / a timeout / an Etherscan rate-limit answer."""
    for t in range(6):
        try:
            j = json.load(urllib.request.urlopen(url, timeout=30))
            if not (isinstance(j, dict) and isinstance(j.get("result"), str) and "rate limit" in j["result"].lower()):
                return j
        except urllib.error.HTTPError as e:
            if e.code in (404, 422):
                return {}
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError):
            pass
        time.sleep(5 * (t + 1))
    return {}


def bs(path):
    """Blockscout v2 GET (its own calls: an address's is_contract, block 1)."""
    return get(f"{CFG['url']}/v2/{path}")


def lookup(a, code, chain):
    if CFG["kind"] == "etherscan":
        time.sleep(0.25)  # the free API's 5 calls per second
    return normalize(CFG["kind"], get(lookup_url(CFG["kind"], CFG["url"], chain, a, CFG["key"])), code)


def keccak(hexdata):
    return subprocess.run(["cast", "keccak"], input=hexdata, capture_output=True, text=True, check=True).stdout.strip()


def scan(chain, genesis, head):
    """Top-level creations, `to` addresses, log emitters and address words of the chain, blocks 1..head (cached)."""
    path = os.path.join(EVM, f"cache/vcheck-{chain}-{genesis[2:14]}.json")
    try:
        st = json.load(open(path))
    except (OSError, ValueError):
        st = {"next": 1, "creates": {}, "seen": {}}
    lo0 = st["next"]
    for lo in range(lo0, head + 1, 1000):
        hi = min(lo + 999, head)
        blocks = batch([("eth_getBlockByNumber", [hex(n), False]) for n in range(lo, hi + 1)])
        busy = [int(b["number"], 16) for b in blocks if b and b["transactions"]]
        txs = []
        for k in range(0, len(busy), 10):
            for b in batch([("eth_getBlockByNumber", [hex(n), True]) for n in busy[k:k + 10]], 10):
                txs += b["transactions"]
        for t in txs:
            if t.get("to"):
                st["seen"].setdefault(t["to"].lower(), int(t["blockNumber"], 16))
        cr = [t for t in txs if not t.get("to") or t["to"].lower() == DEPLOYER]
        for t, r in zip(cr, batch([("eth_getTransactionReceipt", [t["hash"]]) for t in cr])):
            if not r or r.get("status") != "0x1":
                continue
            if not t.get("to"):
                a = r["contractAddress"].lower()
            else:  # CREATE2 through the deterministic deployer: salt ++ init code
                inp = t["input"][2:]
                a = "0x" + keccak("0xff" + DEPLOYER[2:] + inp[:64] + keccak("0x" + inp[64:])[2:])[-40:]
            st["creates"].setdefault(a, [int(t["blockNumber"], 16), t["hash"], "create" if not t.get("to") else "create2"])
        for lg in rpc("eth_getLogs", [{"fromBlock": hex(lo), "toBlock": hex(hi)}]) or []:
            n = int(lg["blockNumber"], 16)
            for a in [lg["address"]] + addr_words("0x" + "".join(x[2:] for x in lg["topics"][1:])) + addr_words(lg["data"]):
                st["seen"].setdefault(a.lower(), n)
        st["next"] = hi + 1
        if (hi // 1000) % 10 == 0 or hi == head:
            say(f"scan block {hi}/{head}: {len(st['creates'])} creations, {len(st['seen'])} addresses")
            json.dump(st, open(path, "w"))
    json.dump(st, open(path, "w"))
    return st


# ---------------------------------------------------------------- discovery

def discover(chain, books, net, head, st):
    listed, inits, hint, first = set(), {}, {}, {}  # book / broadcast addresses, init codes, names, first block

    def add(a, n=None, code=None, block=None):
        a = a.lower()
        if not re.fullmatch(r"0x[0-9a-f]{40}", a) or int(a, 16) == 0:
            return
        listed.add(a)
        if n and n != "-":
            hint.setdefault(a, n)
        if code:
            inits.setdefault(a, set()).add(code.lower())
        if block is not None:
            first[a] = min(first.get(a, block), block)

    for b in books:
        for k, v in b.items():
            if isinstance(v, str):
                add(v)
            elif isinstance(v, dict) and "address" in v:
                add(v["address"], k)
    for p in glob.glob(os.path.join(EVM, f"deployments/onchain-{net}-*.json")):
        for a, lab in json.load(open(p)).items():
            add(a, lab if isinstance(lab, str) else None)
    for p in sorted(glob.glob(os.path.join(EVM, f"broadcast/*/{chain}/*.json"))):
        for t in json.load(open(p)).get("transactions", []):
            tx = t.get("transaction") or {}
            if str(t.get("transactionType", "")).startswith("CREATE") and t.get("contractAddress"):
                inp = tx.get("input") or ""
                add(t["contractAddress"], t.get("contractName"), ("0x" + inp[66:]) if tx.get("to") else inp)
            for c in t.get("additionalContracts") or []:
                add(c["address"], c.get("contractName"), c.get("initCode"))
    for a, (b, _, _) in st["creates"].items():
        first[a] = min(first.get(a, b), b)
    cand = set(listed) | set(st["creates"]) | set(st["seen"])
    for a, b in st["seen"].items():
        first.setdefault(a, b)

    code, todo = {}, set(cand)
    while todo:
        say(f"discovery: {len(todo)} new addresses, {len(code)} known")
        todo = sorted(todo)
        for a, c in zip(todo, batch([("eth_getCode", [a, "latest"]) for a in todo])):
            code[a] = (c or "0x").lower()
        live = [a for a in todo if code[a] not in ("0x", "0x0") and not code[a].startswith("0x00")]
        new = {}  # child -> parent

        def call(to, sel, args=""):
            return ("eth_call", [{"to": to, "data": "0x" + sel + args}, "latest"])

        for a in live:
            if clone_impl(code[a]):
                new.setdefault(clone_impl(code[a]), a)
        qs = [(a, f) for a in live for f in ("puller", "EXECUTOR", "modules", "latestDexVersion")]
        res = batch([call(a, SEL[f]) for a, f in qs])
        facs = []
        for (a, f), r in zip(qs, res):
            if not r or r == "0x":
                continue
            if f == "modules":
                for m in dyn_addrs(r):
                    new.setdefault(m, a)
            elif f == "latestDexVersion":
                if len(r) == 66 and not clone_impl(code[a]):
                    facs.append(a)
            elif word_addr(r):
                new.setdefault(word_addr(r), a)
        for fa in facs:  # a factory: its releases, envs and contracts by class
            u = lambda v: f"{v:064x}"
            ks = list(range(14))
            lv = batch([call(fa, SEL["latestVersion"], u(k)) for k in ks] + [call(fa, SEL["latestDexVersion"])])
            le = batch([call(fa, SEL["latestTokenEnvVersion"], u(k)) for k in ks] + [call(fa, SEL["latestDexEnvVersion"])])
            n = lambda r: int(r, 16) if r and r != "0x" else 0
            q = [call(fa, SEL["implementationOf"], u(k) + u(v)) for k in ks for v in range(1, n(lv[k]) + 1)]
            q += [call(fa, SEL["dexImplementationOf"], u(v)) for v in range(1, n(lv[14]) + 1)]
            for r in batch(q):
                if word_addr(r):
                    new.setdefault(word_addr(r), fa)
            q = [call(fa, SEL["tokenEnvOf"], u(k) + u(v)) for k in ks for v in range(1, n(le[k]) + 1)]
            q += [call(fa, SEL["dexEnvOf"], u(v)) for v in range(1, n(le[14]) + 1)]
            for r in batch(q):
                for m in env_addrs(r):
                    new.setdefault(m, fa)
            for cls in range(16):
                f0 = 0
                while True:
                    got = page_addrs(batch([call(fa, SEL["contractsPage"], u(cls) + u(f0) + u(200))])[0])
                    for m in got:
                        new.setdefault(m, fa)
                    if len(got) < 200:
                        break
                    f0 += 200
        for m, parent in new.items():
            m = m.lower()
            if m not in code and re.fullmatch(r"0x[0-9a-f]{40}", m) and int(m, 16):
                first.setdefault(m, first.get(parent, head))
        todo = {m.lower() for m in new} - set(code)
        todo = {m for m in todo if re.fullmatch(r"0x[0-9a-f]{40}", m) and int(m, 16)}
    return code, listed, inits, hint, first


# ---------------------------------------------------------------- artifacts and forge

def index(roots):
    """metadata CBOR -> (root, artifact json, source, name) over every snapshot's out/."""
    idx = {}
    for root in roots:
        for p in glob.glob(os.path.join(root, "out", "*", "*.json")):
            try:
                j = json.load(open(p))
                k = cbor(j["deployedBytecode"]["object"])
                src, name = next(iter(j["metadata"]["settings"]["compilationTarget"].items()))
            except (KeyError, ValueError, StopIteration, TypeError, AttributeError):
                continue
            if k and k not in idx and name == os.path.basename(p)[:-5]:
                idx[k] = (root, p, src, name)
    return idx


def tx_init(st, a):
    """The init code of a top-level creation from its transaction."""
    if a not in st["creates"]:
        return None
    _, h, kind = st["creates"][a]
    inp = rpc("eth_getTransactionByHash", [h])["input"]
    return inp if kind == "create" else "0x" + inp[66:]


def forge_verify(a, hit, args, chain):
    """One forge verify-contract; (ok, reason, seconds). Raises SystemExit(2) when forge compiles."""
    root, _, src, name = hit
    cmd = ["systemd-run", "--user", "--scope", "--quiet", "-p", f"MemoryMax={os.environ.get('VERIFY_MEM', '1G')}",
           "-p", "MemorySwapMax=0", "--", "forge", "verify-contract", a, f"{src}:{name}", "--root", root]
    cmd += forge_args(CFG["kind"], CFG["url"], chain) + ["--watch", "--delay", "10", "--retries", "40", "--skip-is-verified-check"]
    cmd += ["--constructor-args", "0x" + args] if args else []
    env = forge_env(os.environ, CFG["key"])
    t0, lim = time.time(), int(os.environ.get("VERIFY_TIMEOUT", "600"))
    p = subprocess.Popen(cmd, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = []
    th = threading.Thread(target=lambda: out.extend(p.stdout), daemon=True)
    th.start()
    while True:
        try:
            p.wait(timeout=30)
            break
        except subprocess.TimeoutExpired:
            s = int(time.time() - t0)
            if s >= lim:
                p.kill()
                p.wait()
                th.join(5)
                return False, f"VERIFY_TIMEOUT {lim}s", s
            say(f"{name} {a} waiting ({s}s)")
    th.join(5)
    text = "".join(out)
    m = COMPILES.search(text)
    if m:
        raise SystemExit(f"forge recompiled ({m.group(0)}) for {name} {a}: the snapshot build {root} is stale")
    s = int(time.time() - t0)
    lines = [x for x in text.splitlines() if re.search(r"Details:|Error|error|Reason|Response|Status|GUID", x)] or text.splitlines() or ["?"]
    tail = lines[-1].strip()[:200]
    return p.returncode == 0, (f"forge ok ({tail})" if p.returncode == 0 else f"forge rc {p.returncode}: {tail}"), s


def main():
    global NET, RPC, CFG
    argv = sys.argv[1:]
    NET = argv[0]
    try:
        CFG = config(NET, os.environ)
    except NotConfigured as e:
        say(f"FAIL VERIFY_NOT_CONFIGURED: {e}")
        sys.exit(1)
    RPC = CFG["rpc"]
    if "--config" in argv:
        say(f"explorer {CFG['kind']} {CFG['url']}" + (f", API key from ${CFG['key_env']}" if CFG["key_env"] else "")
            + (", whole-chain scan" if CFG["scan"] else ""))
        return
    fix = "--fix" in argv
    roots = [os.path.abspath(argv[k + 1]) for k, x in enumerate(argv) if x == "--root"]
    only = {x.lower() for k, x in enumerate(argv) if k and argv[k - 1] == "--only" for x in x.split(",")}
    chain = int(rpc("eth_chainId", []), 16)
    genesis = rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
    head = int(rpc("eth_blockNumber", []), 16)
    say(f"chain {chain}, genesis {genesis[:18]}…, head {head}, explorer {CFG['kind']} {CFG['url']}, snapshots {len(roots)}")
    if CFG["kind"] == "blockscout" and head > 12:  # the explorer indexes this chain, not a copy (same genesis) of it
        n = head - 12  # a block the explorer has indexed; on a copy it lies after the fork once the copy has run
        h = (rpc("eth_getBlockByNumber", [hex(n), False]) or {}).get("hash", "")
        if bs(f"blocks/{n}").get("hash", "").lower() != h.lower():
            say(f"FAIL the explorer's block {n} is not the RPC's ({h[:18]}…): another chain, or a copy of this one")
            sys.exit(1)
    try:  # NET-EVM-13: the chain's books by its key (an unknown chain needs DEPLOY_NAME), headers checked, before the scan
        rel = os.environ.get("RELEASES_JSON") or deploybook.find(
            chain, genesis, "-t66b-releases.json" if NET == "scaas-testnet" else "-releases.json")
        books = [deploybook.load(p) for p in (deploybook.find(chain, genesis), rel) if os.path.exists(os.path.join(EVM, p))]
    except deploybook.BookError as e:
        say(f"FAIL {e}")
        sys.exit(1)
    st = scan(chain, genesis, head) if CFG["scan"] else {"creates": {}, "seen": {}}
    code, listed, inits, hint, first = discover(chain, books, NET, head, st)
    contracts = sorted(a for a, c in code.items() if c not in ("0x", "0x0") and not c.startswith("0x00"))
    gen = {a for a, c in zip(contracts, batch([("eth_getCode", [a, "0x0"]) for a in contracts])) if c not in (None, "0x", "0x0")}
    say(f"discovery done: {len(code)} addresses, {len(contracts)} contracts with code ({len(gen)} at genesis)")

    sc, rows, t0 = {}, {}, time.time()
    for k, a in enumerate(contracts):
        if a not in gen:
            sc[a] = lookup(a, code[a], chain)
        if k % 50 == 49:
            say(f"explorer lookups {k + 1}/{len(contracts)} ({int(time.time() - t0)}s)")

    idx = index(roots)
    say(f"artifacts indexed: {len(idx)} (metadata hashes)")

    def decide(a):
        impl = clone_impl(code[a])
        iv = full(sc.get(impl) or lookup(impl, code.get(impl, ""), chain)) if impl else False
        j = sc.get(a, {})
        return classify(code[a], j, iv, a in gen, harness(idx.get(cbor(code[a])), j))

    for a, c in code.items():
        if c in ("0x", "0x0"):
            if a in listed:
                rows[a] = ("no code", hint.get(a, "?"), "named by a book or broadcast; nothing on this chain")
            continue
        s, note = decide(a)
        rows[a] = (s, sc.get(a, {}).get("name") or hint.get(a) or "?", note)
    cnt = lambda: {s: sum(r[0] == s for r in rows.values()) for s in STATES}
    say("before: " + ", ".join(f"{k} {v}" for k, v in cnt().items()))

    rc = 0
    if fix:
        todo = [a for a, r in rows.items() if r[0] == "unverified" and not clone_impl(code[a]) and (not only or a in only)]
        todo.sort(key=lambda a: (first.get(a, head + 1), a))
        say(f"fix: {len(todo)} contracts, one at a time")
        try:
            for n, a in enumerate(todo, 1):
                hit = idx.get(cbor(code[a]))
                if not hit:
                    rows[a] = ("unverified", hint.get(a, "?"),
                               f"metadata {cbor(code[a]) and cbor(code[a])[18:30]}… matches no artifact of the snapshots: deployed from other sources")
                    say(f"[{n}/{len(todo)}] {rows[a][1]} {a} FAIL {rows[a][2]}")
                    continue
                bc = json.load(open(hit[1]))["bytecode"]["object"]
                cands = set(inits.get(a, ())) | ({tx_init(st, a)} if a in st["creates"] else set())
                args = next((x for x in (init_args(bc, i) for i in cands if i) if x is not None), None)
                if args is None and a in st["creates"] and st["creates"][a][2] == "create":
                    rows[a] = ("unverified", hit[3], "its creating transaction's input does not start with the artifact's bytecode")
                    say(f"[{n}/{len(todo)}] {hit[3]} {a} FAIL {rows[a][2]}")
                    continue
                for _ in range(5 if CFG["kind"] == "blockscout" else 0):  # Blockscout fetches a child's code on demand
                    if bs(f"addresses/{a}").get("is_contract") is True:
                        break
                    time.sleep(3)
                good = lambda j: classify(code[a], j, harness=harness(hit, j))[0] != "unverified"
                for attempt in (1, 2):  # forge "Pass - Verified" with nothing on the explorer was seen once per ~10: retry once
                    ok, why, s = forge_verify(a, hit, args or "", chain)
                    j = {}
                    for _ in range(6):
                        j = lookup(a, code[a], chain)
                        if good(j):
                            break
                        time.sleep(5)
                    if good(j) or not ok or attempt == 2:
                        break
                    say(f"{hit[3]} {a}: {why}, not on the explorer; attempt 2")
                sc[a] = j
                st_, note = classify(code[a], j, harness=harness(hit, j))
                rows[a] = (st_, hit[3], note) if st_ != "unverified" else ("unverified", hit[3], why + (
                    f", the explorer: verified {j.get('is_verified')}, partial {j.get('is_partially_verified')}" if ok else ""))
                say(f"[{n}/{len(todo)}] {hit[3]} {a} {'ok' if good(j) else 'FAIL ' + rows[a][2]} ({s}s)")
            for a in [a for a, r in rows.items() if r[0] == "unverified" and clone_impl(code[a]) and (not only or a in only)]:
                impl = clone_impl(code[a])
                sc[impl] = lookup(impl, code.get(impl, ""), chain)
                if CFG["kind"] == "blockscout" and full(sc[impl]) and bs(f"addresses/{a}").get("is_contract") is not True:
                    hit = idx.get(cbor(code.get(impl) or rpc("eth_getCode", [impl, "latest"])))
                    if hit:  # Blockscout never fetched the clone's code: a request for it makes it fetch (it fails)
                        forge_verify(a, hit, "", chain)
                for _ in range(4 if (len(code[a]) - 2) // 2 == 45 else 1):  # Blockscout never links one with data
                    sc[a] = lookup(a, code[a], chain)
                    s, note = decide(a)
                    if s == "linked clone":
                        break
                    time.sleep(5)
                rows[a] = (s, rows[a][1], note)
                say(f"clone {a} {s} {note}")
        except SystemExit as e:
            say(f"ABORT {e}")
            rc = 2
    out = os.path.join(EVM, f"runs/2026-11-10-ua-mtx-merge-t66b-step5b/verify-{NET}.txt")
    c = cnt()
    with open(out, "w") as f:
        f.write(f"# NET-EVM-09: every contract on chain {chain} ({NET}, head {head}), discovered from a block scan, the books,"
                " the broadcasts and the getters; script/onchain/vcheck.py\n")
        f.write(" | ".join(f"{k} {v}" for k, v in c.items()) + "\n")
        for a in sorted(rows, key=lambda a: (STATES.index(rows[a][0]), first.get(a, head + 1), a)):
            s, n, w = rows[a]
            if s != "data":
                f.write(f"{s} | {n} | {a}" + (f" | {w}" if w else "") + "\n")
        f.write(f"data | SSTORE2 | {c['data']} contracts (code 0x00…), not listed one by one\n")
    for a, (s, n, w) in sorted(rows.items()):
        if s == "unverified":
            say(f"FAIL {n} {a} {w}")
    say("after: " + ", ".join(f"{k} {v}" for k, v in c.items()) + f" (rows {os.path.relpath(out, EVM)})")
    sys.exit(rc or (1 if c["unverified"] else 0))


if __name__ == "__main__":
    main()
