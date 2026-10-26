#!/usr/bin/env python3
"""P6g Tasks 7-8 (plan docs/superpowers/plans/2026-10-16-p6g-contracts.md, D7 / D15): deploy the PQZ contracts on
chain 7622 and run the e2e with REAL proofs. Python stdlib (python3 -I); P6f's eth.py (Keccak, RLP, secp256k1, legacy
EIP-155 transactions: calldata of 100-300 KB cannot pass cast's argv); pqz_kat.py (P6e) for KeyGen, Enc, Dec and the
witnesses; pqz-ffi's example `pqz_prove` (feature prove) for the proofs; `mldsa.mjs` (@noble/post-quantum 0.7.1) for the
ML-DSA signatures. Statements are always read from the token's own views, so the proofs cover exactly what the
contracts build.

Plan 5h Task 4a: the new token API (state redesign: pqzAccount views, accHint instead of acc / inline, proof-free shield,
rollover by count after mtxPrepareAcc, txFee / decoyFee to public balances, wallet restore from the views); the entry-point
names and signatures are the `API` table below (the shared `mtx*` interface of Task 3b).

Plan 5h Task 8d part 2: the parameter set is pqz_kat's (PQZ_SET, default n2304-kmax4096; the contracts must be built at
the same set, smartcontracts/evm/script/pqz/at-set.sh, and the node's library too): its vectors (self-test hash, the
R_REG probe), sizes and offsets. Stored ciphertexts are packed at PACK_BITS = ceil(log2 q) (P46): the op blobs
(`pqzEntryBlob`) and the hint (the packed `acc` stream) are compared in that form (`pack`).

  e2e.py --rpc http://127.0.0.1:8545 --log runs/2026-10-16-p6g-7622.txt [--keys 1,2,3]
  (a redeploy writes a new log, e.g. runs/2026-10-17-ua-index-7622.txt; it also checks the registry's per-kind list)

Deploying contracts and sending transactions only: the node is not touched. Gas price 2·baseFee + 1 gwei (baseFee +
tip). Test keys of the 7622 genesis (0x…01–0x…03). Exit 0 iff every check passed."""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
ROOT = os.path.abspath(os.path.join(EVM, "../.."))
sys.path.insert(0, os.path.join(ROOT, "pqz-core/nethermind/chain"))
sys.path.insert(0, os.path.join(ROOT, "smartcontracts/vectors/pqz"))
from eth import _mul, address, keccak256, legacy_tx, sign  # noqa: E402
import pqz_kat as K  # noqa: E402

PQZ = "0x000000000000000000000000000000005caa0f01"
ML44 = "0x000000000000000000000000000000005caa0012"
ML65 = "0x000000000000000000000000000000005caa0013"
PQZL_ID = K.PQZL_ID
SCALE, MAXS, FEE = 10_000, 1 << 40, 3
MIN_DECOY, DEC_FEE = 1, 2  # the tokens' minDecoyFee (plan 5h fee ruling) and the decoyFee this run puts in op 7 payloads
ROLL_AGE = 5  # PqzCore.ROLL_AGE: an entry rolls up at block_i + ROLL_AGE
SHIELD_POOL = "0x" + keccak256(b"scaas.shield.pool.v1")[12:].hex()
MLDSA44, MLDSA65, PQZ_MLWE, SECP256K1 = 0x0130, 0x0131, 0x0142, 0x0108
CAP_ML, CAP_PQZ, BUDGET = 200_000, 3_000_000, 12_000_000
FAILS, LOG = [], []
RPC = None


def pack(b):
    """P46 (owner 2026-10-21): 64-bit-lane PQZ bytes (be8 coefficients < q) as the token stores them, every coefficient
    in PACK_BITS = ceil(log2 q) bits, big-endian, four per PACK_BITS / 2 bytes"""
    bits = K.Q.bit_length()
    x, n = 0, len(b) // 8
    for i in range(n):
        x = x << bits | int.from_bytes(b[8 * i:8 * i + 8], "big")
    return x.to_bytes(n * bits // 8, "big")


def kc(*parts):
    return keccak256(b"".join(p if isinstance(p, bytes) else p.encode() for p in parts))


P_POP, P_METATX, P_ZAUTH = (kc(f"scaas.ua.purpose.{n}.v1") for n in ("pop", "metatx", "zether-auth"))
MSG_TAG = kc("scaas.ua.msg.v1")
TAG = {MLDSA44: kc("scaas.ua.mldsa44.v1"), MLDSA65: kc("scaas.ua.mldsa65.v1"), SECP256K1: kc("scaas.ua.secp256k1.v1"), PQZ_MLWE: kc("scaas.ua.pqz-mlwe.v1")}


# ------------------------------------------------------------------ the token API in one place (plan 5h Task 3b, spec
# §5.11): the shared `mtx*` names and the shared signature `(payload, proof, auth, beneficiary, accHint[, trailing])`.
# Checked against the built ABI (Task 4b); mtxRollOver / mtxPrepareAcc are relayable (Task R) but this script calls them directly.
SH_S, SH_T = "bytes,bytes,bytes,bytes32,bytes", ["b", "b", "b", "w", "b"]  # payload, proof, auth, beneficiary, accHint
UNWRAP_S = "(address,bytes32,uint256,uint256)"  # IConfidentialToken.Unwrap(underlying, recipient, amount, minOut), a calldata struct
API = dict(
    shield="mtxShield(bytes32,uint256)",
    wrapShield="mtxWrapShield(address,uint256,bytes32)",
    transfer=f"mtxConfidentialTransfer({SH_S})",  # op 7 (M legs)
    transferSingle=f"mtxConfidentialTransferSingle({SH_S})",  # op 1
    unshield=f"mtxUnshield({SH_S},uint256,bytes32)",  # trailing: amount, recipient id (zero-padded address = native)
    unshieldUnwrap=f"mtxUnshieldUnwrap({SH_S},{UNWRAP_S})",
    rollOver="mtxRollOver(bytes32,uint256)",
    prepareAcc="mtxPrepareAcc(bytes32,uint256)",
    # views (names kept by 3b); the recipient word of the burn statements is a bytes32 id since UA-5c (b)
    burnStmt="burnStatement(bytes,uint256,bytes32,bytes32)",
    unwrapStmt=f"unshieldUnwrapStatement(bytes,{UNWRAP_S},bytes32)",
    singleStmt="transferSingleStatement(bytes,bytes32)",
    multiStmt="transferStatement(bytes,bytes32)",
    discStmt="disclosureStatement(bytes32,uint256,uint256,uint8)",
    verifyAmt="verifyTransferAmount(bytes32,uint256,uint256,uint8,bytes)",
    # events carrying the entry reference as topic 1 (as built, IConfidentialToken; only topic 0 is looked up here)
    ev_single=["ConfidentialTransfer(bytes32,bytes32,bytes32,bytes32,uint256,uint64,address)"],
    ev_multi=["ConfidentialTransferMulti(bytes32,bytes32,bytes32,uint256,uint64,bytes32[],uint8,address)"],
)
ACCT = ["pendingCount", "rolled", "floor", "cleared", "accBlob", "accUnits", "flags", "sendCounter", "accHash"]  # pqzAccount


def log(s):
    print(s, flush=True)
    LOG.append(s)


def check(ok, what):
    log(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        FAILS.append(what)
    return ok


def rpc(method, params=()):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
    r = json.load(urllib.request.urlopen(urllib.request.Request(RPC, body, {"content-type": "application/json"}), timeout=300))
    if "error" in r:
        raise RuntimeError(f"{method}: {json.dumps(r['error'])[:600]}")
    return r["result"]


# ------------------------------------------------------------------ ABI (enough for these contracts)

def W(x):
    if isinstance(x, bytes):
        assert len(x) == 32, len(x)
        return x
    if isinstance(x, str):
        return int(x, 16).to_bytes(32, "big")
    return (int(x) % 2**256).to_bytes(32, "big")


def dyn(t):
    return t == "b" or (isinstance(t, tuple) and (t[0] == "a" or any(dyn(x) for x in t[1])))


def ssize(t):
    return 32 if t == "w" else sum(ssize(x) for x in t[1])


def enc(t, v):
    if t == "w":
        return W(v)
    if t == "b":
        v = v.encode() if isinstance(v, str) else v
        return W(len(v)) + v + b"\0" * (-len(v) % 32)
    if t[0] == "t":
        return encs(t[1], v)
    return W(len(v)) + encs([t[1]] * len(v), v)


def encs(ts, vs):
    hl = sum(32 if dyn(t) else ssize(t) for t in ts)
    head, tail = b"", b""
    for t, v in zip(ts, vs):
        if dyn(t):
            head += W(hl + len(tail))
            tail += enc(t, v)
        else:
            head += enc(t, v)
    return head + tail


def sel(sig):
    return keccak256(sig.encode())[:4]


def cd(sig, ts, *vs):
    return sel(sig) + encs(ts, list(vs))


def words(h, n=None):
    b = bytes.fromhex(h[2:])
    return [b[i:i + 32] for i in range(0, len(b), 32)][:n]


def dec_bytes(h):
    b = bytes.fromhex(h[2:])
    o = int.from_bytes(b[0:32], "big")
    n = int.from_bytes(b[o:o + 32], "big")
    return b[o + 32:o + 32 + n]


MTX = ("t", ["w", "b", "w", "w", "w", "w", "w", "w", "w"])
MTX_S = "(address,bytes,uint256,uint256,uint256,uint32,address,uint256,address)"
UMTX_S = "(bytes32,bytes,uint256,uint256,uint256,uint32,address,uint256,address)"
UNWRAP = ("t", ["w", "w", "w", "w"])  # UNWRAP_S: four words
CFG = ("t", ["b", "b", "w", "w", "w", "w", ("t", ["w"] * 5), "w", "w", ("a", ("t", ["w", "w", "w"])), ("t", ["w", "w"]),
             ("t", ["b", "w", "w", "w", "w", "w", "w"])])
# IFactoryToken.Env (plan 5g-Z2): factory, chainUid, registry, smartKeyAccountImpl, hedera, deps, libs, libCodeHashes
ENV = ("t", ["w", "w", "w", "w", "w", ("a", "w"), ("a", "w"), ("a", "w")])
ENV_S = "(address,bytes32,address,address,bool,address[],address[],bytes32[])"


# ------------------------------------------------------------------ transactions

class Sender:
    def __init__(self, key):
        self.key = key
        self.addr = address(key)
        self.nonce = int(rpc("eth_getTransactionCount", [self.addr, "pending"]), 16)

    def send(self, to, data, what, gas=None):
        tx = {"from": self.addr, "data": "0x" + data.hex()}
        if to:
            tx["to"] = to
        head = rpc("eth_getBlockByNumber", ["latest", False])
        if gas is None:
            # Amsterdam (EIP-8037): the estimate is regular + state gas and may pass 2^24 (the chain caps the regular
            # part); the limit is bounded by the chain's block gas limit, read here, never assumed
            try:
                gas = min(int(head["gasLimit"], 16), int(int(rpc("eth_estimateGas", [tx]), 16) * 1.15) + 50_000)
            except RuntimeError as e:
                check(False, f"{what}: estimateGas {e}")
                raise
        fee = int(head["baseFeePerGas"], 16)
        raw = legacy_tx(self.key, self.nonce, 2 * fee + 10**9, gas, to, 0, data, 7622)
        self.nonce += 1
        h = rpc("eth_sendRawTransaction", ["0x" + raw.hex()])
        t0 = time.time()
        while True:
            r = rpc("eth_getTransactionReceipt", [h])
            if r:
                break
            if time.time() - t0 > 300:
                raise RuntimeError(f"no receipt for {h}")
            time.sleep(1)
        used = int(r["gasUsed"], 16)
        check(r["status"] == "0x1", f"tx {what}: {h} block {int(r['blockNumber'], 16)} gasUsed {used:,} "
                                    f"(calldata {len(data):,} B)")
        if r["status"] != "0x1":
            raise RuntimeError(what)
        return r


def call(to, data, frm=None):
    tx = {"to": to, "data": "0x" + data.hex(), "gas": hex(30_000_000)}
    if frm:
        tx["from"] = frm
    return rpc("eth_call", [tx, "latest"])


def gas_of(to, data):
    return int(rpc("eth_estimateGas", [{"to": to, "data": "0x" + data.hex()}]), 16)


def artifact(name, src=None):
    j = json.load(open(os.path.join(EVM, "out", (src or name) + ".sol", name + ".json")))
    return j["bytecode"]["object"].removeprefix("0x"), j["bytecode"].get("linkReferences", {})


class Deployer:
    def __init__(self, s):
        self.s = s
        self.libs = {}
        self.addr = {}

    def lib(self, name):
        if name not in self.libs:
            self.libs[name] = self.deploy(name, b"", label=f"library {name}")
        return self.libs[name]

    def linked(self, name, src=None):
        """The init code without arguments, the libraries linked in, and their addresses (plan 5g-Z2: a release's env
        lists them with their code hashes)."""
        code, links = artifact(name, src)
        libs = []
        for _, ls in links.items():
            for ln, pos in ls.items():
                a = self.lib(ln)[2:]
                libs.append("0x" + a)
                for p in pos:
                    code = code[:2 * p["start"]] + a + code[2 * (p["start"] + p["length"]):]
        return bytes.fromhex(code), libs

    def deploy(self, name, args, src=None, label=None):
        code, _ = self.linked(name, src)
        r = self.s.send(None, code + args, label or f"deploy {name}")
        a = r["contractAddress"]
        log(f"      {name} at {a}")
        self.addr[label or name] = a
        return a


# ------------------------------------------------------------------ provers

class Proc:
    def __init__(self, argv):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        r = self.p.stdout.readline().strip()
        if r.startswith("ERR"):
            raise RuntimeError(r)
        return r


class PQ:
    def __init__(self):
        self.prover = Proc([os.path.join(ROOT, "pqz-core/ffi/target/release/examples/pqz_prove")])
        self.ml = Proc(["node", os.path.join(HERE, "mldsa.mjs"), os.path.join(ROOT, "../../../clients/clientkeys")
                        if not os.path.isdir(os.path.join(ROOT, "clients/clientkeys/node_modules"))
                        else os.path.join(ROOT, "clients/clientkeys")])

    def prove(self, op, stmt, wit):
        rnd = os.urandom(32)
        t = time.time()
        p = bytes.fromhex(self.prover.ask(f"prove {op} {stmt.hex()} {wit.hex()} {rnd.hex()}"))
        dt = time.time() - t
        ok = self.prover.ask(f"verify {op} {stmt.hex()} {p.hex()}").endswith("01")
        check(ok, f"proof op {op}: {len(p):,} B, proved in {dt:.2f} s, pqz-ffi verify = 1 (stmt {len(stmt):,} B)")
        return p

    def ml_pk(self, lvl, seed):
        return bytes.fromhex(self.ml.ask(f"keygen {lvl} {seed.hex()}"))

    def ml_sign(self, lvl, seed, msg):
        return bytes.fromhex(self.ml.ask(f"sign {lvl} {seed.hex()} {msg.hex()}"))


# ------------------------------------------------------------------ the scenario

class UA:
    """An ML-DSA UA (`kind`, seed); a PQZ holder also has the PQZ key (pk, s, e)."""

    def __init__(self, **kw):
        self.__dict__.update(kw)


def ua_msg(kind, purpose, digest):
    return kc(MSG_TAG, TAG[kind], purpose, digest)


def ml_auth(pq, signer, purpose, digest):
    """`abi.encode(bytes(""), sig)` over `pq_msg = keccak256(TAG ‖ ua_msg)` (CTR-UA-23)."""
    m = ua_msg(signer.kind, purpose, digest)
    sig = pq.ml_sign(44 if signer.kind == MLDSA44 else 65, signer.seed, kc(TAG[signer.kind], m))
    return encs(["b", "b"], [b"", sig])


class Client:
    """The wallet side of one PQZ token. It tracks, per UA, the decrypted shielded balance and (after a debit) the `acc`
    bytes it expects; the token's views are the truth (plan 5h D13): `restore()` rebuilds the balance from them alone
    and compares. Public side: `pub` (UA-ledger units paid by the pool, fees), `total` (totalShielded)."""

    def __init__(self, tok, name):
        self.tok, self.name = tok, name
        self.bal, self.acc, self.pub, self.uas, self.total = {}, {}, {}, {}, 0
        self._next = {}

    def state(self, ua):
        w = [int.from_bytes(x, "big") for x in words(call(self.tok, cd("pqzAccount(bytes32)", ["w"], ua.ua)), len(ACCT))]
        return dict(zip(ACCT, w))

    def hint(self, ua):
        """The optional `accHint` (D5): the materialised `acc` packed (P46), used by the token only while its keccak is
        `accHash`."""
        return pack(dec_bytes(call(self.tok, cd("pqzAcc(bytes32)", ["w"], ua.ua)))) if self.state(ua)["flags"] & 1 else b""

    def set_next(self, bal=(), pub=(), acc=None, total=0):
        self._next = dict(bal=list(bal), pub=list(pub), acc=acc or {}, total=total)

    def commit(self):
        n = self._next
        for u, d in n["bal"]:
            self.uas[u.ua] = u
            self.bal[u.ua] = self.bal.get(u.ua, 0) + d
        for u, d in n["pub"]:
            self.pub[u.ua] = self.pub.get(u.ua, 0) + d
        self.total += n["total"]
        for u, acc in n["acc"].items():
            got = dec_bytes(call(self.tok, cd("pqzAcc(bytes32)", ["w"], u)))
            check(got == acc, f"{self.name} pqzAcc({u.hex()[:8]}…) = the new u' ‖ v_f after the debit")
        self._next = {}


def pending_block(tok, ua, i):
    """The block of pending entry `i` (the low 64 bits of the raw slot, D2)."""
    return int(call(tok, cd("pqzPending(bytes32,uint64)", ["w", "w"], ua.ua, i)), 16) & (2**64 - 1)


def wait_block(n):
    t0 = time.time()
    while int(rpc("eth_blockNumber"), 16) < n:
        if time.time() - t0 > 900:
            raise RuntimeError(f"head did not reach block {n}")
        time.sleep(1)


def rollover(s, C, ua, n, what):
    """Plan 5h D8: `mtxPrepareAcc` for both halves (permissionless, idempotent, once per account), wait until the n-th
    entry is `ROLL_AGE` blocks old (D6), then `mtxRollOver(ua, n)` by count."""
    st = C.state(ua)
    for half in (0, 1):
        if not st["flags"] & (2 << half):
            s.send(C.tok, cd(API["prepareAcc"], ["w", "w"], ua.ua, half), f"{C.name} mtxPrepareAcc({ua.name}, {half})")
    wait_block(pending_block(C.tok, ua, st["rolled"] + n - 1) + ROLL_AGE)
    s.send(C.tok, cd(API["rollOver"], ["w", "w"], ua.ua, n), f"{C.name} mtxRollOver({ua.name}, {n}): {what}")
    st2 = C.state(ua)
    check(st2["rolled"] == st["rolled"] + n and st2["flags"] & 1 == 1 and st2["accUnits"] > st["accUnits"],
          f"{C.name} {ua.name} rolled {st['rolled']} → {st2['rolled']}, acc materialised, accUnits {st2['accUnits']}")


def restore(C, what):
    """Wallet restore from the views alone (plan 5h D13): `T = pqzAcc + Σ pqzPendingCt(i), i ∈ [rolled, pendingCount)`,
    decrypted with the UA's key, against the balance this script tracked; the raw slots (`pqzPending`) give kind and
    block of each entry."""
    log(f"wallet restore from the views ({what}):")
    for ua_id, tracked in C.bal.items():
        u = C.uas[ua_id]
        st = C.state(u)
        T = dec_bytes(call(C.tok, cd("pqzAcc(bytes32)", ["w"], ua_id)))
        kinds = []
        for i in range(st["rolled"], st["pendingCount"]):
            T = K.ct_add(T, dec_bytes(call(C.tok, cd("pqzPendingCt(bytes32,uint64)", ["w", "w"], ua_id, i))))
            w = int(call(C.tok, cd("pqzPending(bytes32,uint64)", ["w", "w"], ua_id, i)), 16)
            kinds.append("T" if (w >> 64) & 0xFFFF == 0 else "C")  # TRIVIAL (vOff = 0) or a proven credit
        got = bal(u.s, T)
        check(got == tracked, f"restore {C.name} {u.name}: acc + {st['pendingCount'] - st['rolled']} pending "
                              f"[{''.join(kinds)}] decrypt to {got}, tracked {tracked} (rolled {st['rolled']}, "
                              f"pendingCount {st['pendingCount']}, floor {st['floor']}, flags {st['flags']})")


def check_public(C, what):
    """The pool holds exactly the shielded value (D19), the fee recipients their public units."""
    pool = int.from_bytes(words(call(C.tok, cd("balanceOf(address)", ["w"], SHIELD_POOL)))[0], "big")
    tot = int.from_bytes(words(call(C.tok, cd("totalShielded()", [])))[0], "big")
    check(tot == C.total and pool == tot * SCALE, f"{C.name} {what}: totalShielded {tot} (tracked {C.total}), SHIELD_POOL "
                                                  f"{pool:,} = totalShielded · scale")
    for ua_id, v in C.pub.items():
        got = int.from_bytes(words(call(C.tok, cd("balanceOfUA(bytes32)", ["w"], ua_id)))[0], "big")
        check(got == v * SCALE, f"{C.name} public UA balance of {ua_id.hex()[:8]}… = {got:,} (fees paid from the pool: {v} · scale)")


def bal(s_key, T):
    return K.dec(s_key, T)[2]


def main():
    global RPC
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--log", default=os.path.join(EVM, "runs/2026-10-16-p6g-7622.txt"))
    ap.add_argument("--keys", default="1,2,3")
    a = ap.parse_args()
    RPC = a.rpc
    kd, kr, ke = (int(x) for x in a.keys.split(","))
    try:
        run(kd, kr, ke)
    except Exception as e:  # noqa: BLE001
        check(False, f"aborted: {type(e).__name__}: {e}")
    finally:
        os.makedirs(os.path.dirname(a.log), exist_ok=True)
        with open(a.log, "w") as f:
            f.write("\n".join(LOG) + f"\n\nresult: {len(FAILS)} failure(s)\n")
        log(f"result: {len(FAILS)} failure(s); log {a.log}")
    sys.exit(1 if FAILS else 0)


def run(kd, kr, ke):
    t0 = time.time()
    chain = int(rpc("eth_chainId"), 16)
    g = rpc("eth_getBlockByNumber", ["0x0", False])
    uid = bytes.fromhex(g["hash"][2:])
    head = rpc("eth_getBlockByNumber", ["latest", False])
    log(f"# P6g e2e on chain {chain}, {time.strftime('%Y-%m-%d %H:%M:%S %z')}; genesis {g['hash']}; head "
        f"{int(head['number'], 16)}, gasLimit {int(head['gasLimit'], 16):,}, baseFee {int(head['baseFeePerGas'], 16)}")
    check(chain == 7622, "chain id 7622")
    sd, sr, se = Sender(kd), Sender(kr), Sender(ke)
    log(f"deployer {sd.addr} (key {kd}), relayer {sr.addr} (key {kr}), envelope signer {se.addr} (key {ke})")
    st = call(PQZ, bytes.fromhex("0600000000"))
    want = json.load(open(os.path.join(K.VEC_DIR, "selftest.json")))["hash"]
    check(st[2:] == want, f"PQZ OP_SELFTEST = {st[:18]}… (set {K.SET})")
    pq = PQ()
    D = Deployer(sd)

    # -------------------------------------------------------------- 1. verifiers, registry gen 1, factory, tokens
    log("\n## 1. deploy (P6g plan D15)")
    ext = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/ua/pq_signatures.json")))
    mlv = {}
    for kind, at, lvl, pkl, sgl in ((MLDSA44, ML44, 44, 1312, 2420), (MLDSA65, ML65, 65, 1952, 3309)):
        k = next(x for x in ext["kinds"] if x["name"] == f"mldsa{lvl}")
        pk, sg = bytes.fromhex(k["keyData"][2:]), bytes.fromhex(k["pop"]["sig"][2:])
        valid = pk + sg + kc(TAG[kind], bytes.fromhex(k["pop"]["message"][2:]))
        bad = bytearray(valid)
        bad[pkl + 7] ^= 1
        v = D.deploy("UAMldsaVerifier", encs(["w", "w", "b", "b"], [kind, at, valid, bytes(bad)]), src="MlDsa",
                     label=f"UAMldsaVerifier {lvl}")
        got = words(call(v, cd("PRECOMPILE()", [])))[0][12:]
        check("0x" + got.hex() == at.lower(), f"UAMldsaVerifier({kind:#06x}).PRECOMPILE() = 0x{got.hex()} (probe passed)")
        mlv[kind] = v
    # the set's self-test R_REG vector (UAPqzVerifier's pinned probe, PqzSet.PROBE_PQZL; review 8d1 N1: per set)
    reg_stmt = bytes.fromhex(json.load(open(os.path.join(K.VEC_DIR, "statement_register.json")))["rows"][0]["stmt"])
    reg_proof = bytes.fromhex(json.load(open(os.path.join(K.VEC_DIR, "proof_pqzl.json")))["rows"][4]["proof"])
    pqv = D.deploy("UAPqzVerifier", encs(["w", "w", "b", "w", "b"], [PQZ, PQZL_ID, reg_stmt[96:], reg_stmt[64:96], reg_proof]),
                   label="UAPqzVerifier PQZL")
    check(words(call(pqv, cd("isSupportedOnThisChain()", [])))[0][-1] == 1, "UAPqzVerifier.isSupportedOnThisChain()")
    secv = D.deploy("Secp256k1Verifier", b"", label="Secp256k1Verifier")
    kinds = [(MLDSA44, mlv[MLDSA44], CAP_ML), (MLDSA65, mlv[MLDSA65], CAP_ML), (PQZ_MLWE, pqv, CAP_PQZ),
             (SECP256K1, secv, 50_000)]
    reg = D.deploy("UARegistry", encs(["w", "w", "w", "w", "w", "w", ("a", ("t", ["w", "w", "w"]))],
                                      [uid, 0, 0, BUDGET, 0, 1, kinds]), label="UARegistry gen 1")
    REG[0] = reg
    # plan 5g-Z2: the factory (notice period 0 here) deploys every release itself: env version 1 of each kind
    # (factory, chain_uid, registry, SmartKeyAccount implementation 0, Hedera false, deps, the linked libraries with
    # their code hashes (the PQZ kinds link the four PqzStateLib / PqzTransferLib / PqzBurnLib / PqzViewLib, plan 5h D14,
    # each deployed once by D.lib; the PQZ kinds' one dependency is this run's UAPqzVerifier, CTR-ZTH-20), then the release
    # from the init code without arguments on env 1, named explicitly (owner 2026-10-20; the factory appends
    # envVersion, env, implArgs)
    fac = D.deploy("OpenFactory", encs(["w"] * 3, [sd.addr, uid, 0]))
    for kind, name in ((0, "NoUnderlyingToken"), (4, "NoUnderlyingPqzToken"), (5, "UnderlyingPqzToken")):
        code, libs = D.linked(name)
        hashes = [keccak256(bytes.fromhex(rpc("eth_getCode", [a, "latest"])[2:])) for a in libs]
        env = [fac, uid, reg, 0, 0, [pqv] if kind else [], libs, hashes]
        sd.send(fac, cd(f"publishEnv(uint8,uint16,{ENV_S})", ["w", "w", ENV], kind, 1, env), f"publishEnv(kind {kind}, 1)")
        r = sd.send(fac, cd("deployImplementation(uint8,uint64,uint16,bytes,bytes)", ["w", "w", "w", "b", "b"],
                               kind, 1, 1, code, b""),
                    f"deployImplementation(kind {kind}, 1) {name}")
        lg = next(x for x in r["logs"] if x["address"].lower() == fac.lower() and len(x["topics"]) == 4)
        log(f"      {name} release at 0x{lg['topics'][3][-40:]} ({int(r['gasUsed'], 16):,} gas)")
    for kind in (4, 5):
        sd.send(fac, cd("setKindEnabled(uint8,bool)", ["w", "w"], kind, 1), f"setKindEnabled({kind}, true)")

    # -------------------------------------------------------------- 2. UAs
    log("\n## 2. UAs: ML-DSA UAs and PQZ holders (ML-DSA UA + pqz-mlwe key attribute, real R_REG proofs)")

    def ml_ua(name, kind, seed):
        lvl = 44 if kind == MLDSA44 else 65
        pk = pq.ml_pk(lvl, seed)
        ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], kind, pk)))[0]
        u = UA(name=name, kind=kind, seed=seed, pk=pk, ua=ua)
        pd = words(call(reg, cd("popDigest(bytes32,bytes32)", ["w", "w"], ua, 0)))[0]
        pop = pq.ml_sign(lvl, seed, kc(TAG[kind], ua_msg(kind, P_POP, pd)))
        sd.send(reg, cd("register(uint16,bytes,bytes,bytes,bytes)", ["w", "b", "b", "b", "b"], kind, pk, pop, b"", b""),
                f"register {name} (mldsa{lvl}, seed {seed.hex()[:8]}…)")
        return u

    def pqz_ua(name, seed, mlseed):
        """A PQZ holder (UA-6): an ML-DSA-65 UA with the pqz-mlwe key as an attribute, ONE register call."""
        pk, s, e, _ = K.keygen(seed)
        mlpk = pq.ml_pk(65, mlseed)
        ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], MLDSA65, mlpk)))[0]
        h = words(call(reg, cd("keyHashOf(uint16,bytes)", ["w", "b"], PQZ_MLWE, pk)))[0]
        pd = words(call(reg, cd("popDigest(bytes32,bytes32)", ["w", "w"], ua, h)))[0]
        pop = pq.ml_sign(65, mlseed, kc(TAG[MLDSA65], ua_msg(MLDSA65, P_POP, pd)))
        proof = pq.prove(3, K.build_register(ua_msg(PQZ_MLWE, P_POP, pd), pk), K.i8(s) + K.i16(e))
        sd.send(reg, cd("register(uint16,bytes,bytes,bytes,bytes)", ["w", "b", "b", "b", "b"], MLDSA65, mlpk, pop, pk, proof),
                f"register {name} (mldsa65 + pqz-mlwe key, R_REG {len(proof):,} B, one call)")
        rec = words(call(reg, cd("recordOf(bytes32)", ["w"], ua)))
        check(int.from_bytes(rec[-1], "big") != 0, f"{name} = {ua.hex()[:16]}… recordOf: PQZ key pointer set")
        check(int.from_bytes(words(call(reg, cd("kindOf(bytes32)", ["w"], ua)))[0], "big") == MLDSA65, f"{name} kindOf 0x0131")
        return UA(name=name, kind=MLDSA65, seed=mlseed, pk=pk, s=s, e=e, ua=ua)

    sk = lambda tag: kc("p6g-e2e-7622/", tag)  # noqa: E731  (test seeds, in this log on purpose)
    log(f"test seeds: keccak256('p6g-e2e-7622/<name>')")
    ml44 = ml_ua("mldsa44-ua", MLDSA44, sk("ml44"))
    feeua = ml_ua("fee-ua", MLDSA65, sk("fee"))
    U = {n: pqz_ua(n, sk("pqz-" + n), sk("ml-" + n)) for n in ("alice", "bob", "aud", "carol")}
    alice, bob, aud, carol = U["alice"], U["bob"], U["aud"], U["carol"]
    # op 7 decoys (P6g op 7): five more PQZ holders
    DEC = [pqz_ua(f"decoy{i}", sk(f"pqz-decoy{i}"), sk(f"ml-decoy{i}")) for i in range(5)]

    # secp256k1 (ECDSA, 0x0108; CTR-UA-06, owner 2026-10-17): a secp256k1 key registers a derived id, separate from
    # its EOA address and the same on every chain
    def ecdsa(key, m):
        r, s_, rec = sign(key, m)
        return r.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([27 + rec])

    seck = int.from_bytes(sk("secp256k1"), "big") % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    x, y = _mul(seck)
    secd = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    sec_ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], SECP256K1, secd)))[0]
    check(sec_ua == kc(TAG[SECP256K1], secd), "secp256k1 UA = keccak256(TAG ‖ x ‖ y)")
    pd = words(call(reg, cd("popDigest(bytes32,bytes32)", ["w", "w"], sec_ua, b"\0" * 32)))[0]
    sd.send(reg, cd("register(uint16,bytes,bytes,bytes,bytes)", ["w", "b", "b", "b", "b"], SECP256K1, secd,
                    ecdsa(seck, ua_msg(SECP256K1, P_POP, pd)), b"", b""), "register secp256k1 (ECDSA PoP)")
    kind = int.from_bytes(words(call(reg, cd("kindOf(bytes32)", ["w"], sec_ua)))[0], "big")
    check(kind == SECP256K1, f"secp256k1 UA {sec_ua.hex()[:16]}… kindOf 0x0108; the same key's EOA {address(seck)} is a "
                             f"separate native id")
    d = kc("p6g-gas")
    data = cd("requireAuthorized(bytes32,bytes32,bytes32,bytes)", ["w", "w", "w", "b"], sec_ua, P_METATX, d,
              encs(["b", "b"], [secd, ecdsa(seck, ua_msg(SECP256K1, P_METATX, d))]))
    call(reg, data)
    log(f"      gas registry.requireAuthorized(secp256k1) = {gas_of(reg, data):,} (eth_estimateGas, incl. 21,000 "
        f"intrinsic and calldata)")
    bad = encs(["b", "b"], [secd, ecdsa(seck, ua_msg(SECP256K1, P_METATX, kc("other")))])
    try:
        call(reg, cd("requireAuthorized(bytes32,bytes32,bytes32,bytes)", ["w", "w", "w", "b"], sec_ua, P_METATX, d, bad))
        check(False, "secp256k1 signature over another digest is refused")
    except RuntimeError:
        check(True, "secp256k1 signature over another digest is refused (UAUnauthorized)")

    # the per-kind list (CTR-UA-29, owner 2026-10-17): every UA of a kind in registration order
    for kind, uas in ((PQZ_MLWE, [u.ua for u in list(U.values()) + DEC]), (MLDSA65, [u.ua for u in [feeua] + list(U.values()) + DEC]),
                      (MLDSA44, [ml44.ua]), (SECP256K1, [sec_ua])):
        n = int.from_bytes(words(call(reg, cd("uaCount(uint16)", ["w"], kind)))[0], "big")
        at = [words(call(reg, cd("uaAt(uint16,uint256)", ["w", "w"], kind, i)))[0] for i in range(n)]
        # uaIndex is the UA's position in its own kind list; the 0x0142 list has no reverse index (spec U11)
        idx = list(range(n)) if kind == PQZ_MLWE else [int.from_bytes(words(call(reg, cd("uaIndex(bytes32)", ["w"], ua)))[0], "big") for ua in uas]
        page = call(reg, cd("uaPage(uint16,uint256,uint256)", ["w", "w", "w"], kind, 0, 100))
        check(n == len(uas) and at == uas and idx == list(range(n)) and (len(page) - 2) // 2 == 64 + 32 * n and words(page)[2:] == uas,
              f"registry list of kind {kind:#06x}: uaCount {n}, uaAt / uaIndex (kind lists) in registration order, uaPage {n} ids")

    # ML-DSA verify gas through the registry (both levels, precompile path)
    for u in (ml44, U["alice"]):
        d = kc("p6g-gas")
        data = cd("requireAuthorized(bytes32,bytes32,bytes32,bytes)", ["w", "w", "w", "b"], u.ua, P_METATX, d,
                  ml_auth(pq, u, P_METATX, d))
        call(reg, data)
        log(f"      gas registry.requireAuthorized(mldsa{44 if u.kind == MLDSA44 else 65}) = {gas_of(reg, data):,} "
            f"(eth_estimateGas, incl. 21,000 intrinsic and calldata)")

    # -------------------------------------------------------------- 3. tokens
    log("\n## 3. tokens")

    def create(kind, name, sym, legs, dmode, amode, feat, supply=0, holder=0, conf=True, salt=b"p6g"):
        aud_key = aud.ua if amode else b""
        c = [name, sym, 6, feat, 0, sd.addr, [sd.addr if feat & 2 else 0, 0, 0, 0, 0], supply, holder, legs, [0, 0],
             [aud_key, SCALE, MAXS, FEE, dmode, amode, MIN_DECOY] if conf else [b"", 0, 0, 0, 0, 0, 0]]
        # plan 5g-Z2: initArgs = abi.encode(TokenConfig), opaque to the factory; the verifier is the release's
        data = cd("createToken(uint8,uint64,bytes,bytes32)", ["w", "w", "b", "w"], kind, 1, encs([CFG], [c]), kc(salt))
        r = sd.send(fac, data, f"createToken {sym} (kind {kind})")
        lg = next(x for x in r["logs"] if x["address"].lower() == fac.lower())
        t = "0x" + lg["topics"][1][-40:]
        log(f"      {sym} at {t}")
        D.addr[sym] = t
        return t

    # the leg: a plain ERC-20 (SCaaS tokens give no allowance to an EOA, CTR-TOK-01); test/helpers/Mocks.sol
    tusd = D.deploy("MockERC20", encs(["b", "b", "w"], ["Test USD", "tUSD", 6]), src="Mocks", label="tUSD (MockERC20)")
    sd.send(tusd, cd("mint(address,uint256)", ["w", "w"], sd.addr, 10**12), "tUSD mint")
    t1 = create(4, "PQZ USD", "pqUSD", [], 0, 1, 1 | 2 | 4, salt=b"pq1")  # BUNDLE, FULL auditor, PAYABLE|MINTABLE|BURNABLE
    t2 = create(5, "PQZ wrapped tUSD", "pqW", [[tusd, 1, 1]], 1, 2, 1, salt=b"pq2")  # COMPACT, OPTIONAL

    # -------------------------------------------------------------- 4. the NONE_PQZ life cycle with real proofs
    log("\n## 4. NONE_PQZ (pqUSD: BUNDLE, auditor FULL): shield, transfer, rollover by count, hint, burn, refresh, disclosure")
    C1 = Client(t1, "pqUSD")
    sd.send(t1, cd("mint(address,uint256)", ["w", "w"], sd.addr, 5_000 * SCALE), "pqUSD mint 5,000 public")
    sd.send(t1, cd(API["shield"], ["w", "w"], alice.ua, 1_000), "mtxShield(alice, 1,000): no proof, free, into the pool")
    C1.set_next(bal=[(alice, 1_000)], total=1_000)
    C1.commit()
    st = C1.state(alice)
    w0 = int(call(t1, cd("pqzPending(bytes32,uint64)", ["w", "w"], alice.ua, 0)), 16)
    check(st["pendingCount"] == 1 and (w0 >> 64) & 0xFFFF == 0 and (w0 >> 96) & (2**64 - 1) == 1000,
          "alice pending[0] is a TRIVIAL entry of 1,000 (raw slot: vOff 0, amount in the blob field)")
    check_public(C1, "after the shield")

    xfer = lambda *a, **k: transfer(pq, sd, C1, *a, **k)  # noqa: E731
    r1, ref1, bundle1, enc1 = xfer(alice, bob, carol, 300, True, "mtxConfidentialTransferSingle alice→bob 300, txFee 3 to carol")
    rollover(sd, C1, bob, 1, "bob's first credit")
    xfer(bob, alice, b"\0" * 32, 100, True, "mtxConfidentialTransferSingle bob→alice 100 (no fee; accHint = the materialised acc)")
    xfer(alice, bob, b"\0" * 32, 50, True, "mtxConfidentialTransferSingle alice→bob 50, shieldIn 25, 1 inline entry (p ≥ rolled)",
         shield_in=25)
    burn(pq, sd, C1, alice, 200, sd.addr, "mtxUnshield alice burns 200 → deployer")
    burn(pq, sd, C1, alice, 0, None, "mtxUnshield refresh (amount 0)")
    pub = int.from_bytes(words(call(t1, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    check(pub == (5_000 - 1_000 - 25 + 200) * SCALE, f"deployer public pqUSD = {pub:,} (4,000 − 25 shieldIn + the 200 burnt back)")
    check_public(C1, "after the burns")
    restore(C1, "section 4")

    log("disclosure of the first transfer (view, verifyTransferAmount; the opening is the proof alone, R from the op blob):")
    for kind, op, wit in ((0, 4, K.i8(enc1[0]) + K.i16(enc1[1]) + K.i16(enc1[2][0])),
                          (1, 5, K.i8(bob.s) + K.i16(bob.e)), (2, 5, K.i8(aud.s) + K.i16(aud.e))):
        stmt = dec_bytes(call(t1, cd(API["discStmt"], ["w", "w", "w", "w"], ref1, 0, 300, kind)))
        proof = pq.prove(op, stmt, wit)
        data = cd(API["verifyAmt"], ["w", "w", "w", "w", "b"], ref1, 0, 300, kind, proof)
        okw = int(call(t1, data), 16)
        bad = int(call(t1, cd(API["verifyAmt"], ["w", "w", "w", "w", "b"], ref1, 0, 301, kind, proof)), 16)
        check(okw == 1 and bad == 0, f"verifyTransferAmount kind {kind} (op {op}): 300 ⇒ true, 301 ⇒ false; "
                                     f"eth_estimateGas {gas_of(t1, data):,}")

    # -------------------------------------------------------------- 4b. op 7 on pqUSD (BUNDLE, auditor FULL)
    log("\n## 4b. op 7 multi-recipient transfer on pqUSD: M = 4 (one real leg, three decoys), txFee + decoyFee, disclosure by leg")
    legs4 = [(carol, 0), (bob, 40), (DEC[0], 0), (DEC[1], 0)]
    _, ref7, bundle7, enc7 = transfer_multi(pq, sd, C1, alice, legs4, carol, True,
                                            f"mtxConfidentialTransfer (op 7) alice→[carol 0, bob 40, decoy0 0, decoy1 0], "
                                            f"txFee 3 to carol, decoyFee {DEC_FEE} per leg")
    for kind, op, wit in ((0, 4, K.i8(enc7["rs"][0]) + K.i16(enc7["e1s"][0]) + K.i16(enc7["e2"][1])),
                          (1, 5, K.i8(bob.s) + K.i16(bob.e)), (2, 5, K.i8(aud.s) + K.i16(aud.e))):
        stmt = dec_bytes(call(t1, cd(API["discStmt"], ["w", "w", "w", "w"], ref7, 1, 40, kind)))
        proof = pq.prove(op, stmt, wit)
        okw = int(call(t1, cd(API["verifyAmt"], ["w", "w", "w", "w", "b"], ref7, 1, 40, kind, proof)), 16)
        bad = int(call(t1, cd(API["verifyAmt"], ["w", "w", "w", "w", "b"], ref7, 1, 41, kind, proof)), 16)
        other = int(call(t1, cd(API["verifyAmt"], ["w", "w", "w", "w", "b"], ref7, 0, 40, kind, proof)), 16)
        check(okw == 1 and bad == 0 and other == 0, f"op 7 leg 1 verifyTransferAmount kind {kind} (op {op}): 40 ⇒ true, "
                                                    f"41 ⇒ false, leg 0 ⇒ false")
    check_public(C1, "after op 7 (txFee to carol, decoyFee to every leg)")
    n = C1.state(bob)["pendingCount"] - C1.state(bob)["rolled"]
    rollover(sd, C1, bob, n, f"{n} pending credits (op 1 credit(s) and the op 7 leg)")
    transfer_multi(pq, sd, C1, bob, [(alice, 15), (DEC[2], 0)], b"\0" * 32, True,
                   "mtxConfidentialTransfer (op 7) bob→[alice 15, decoy2 0], the op 7 credit spent")
    check_public(C1, "after the second op 7")
    restore(C1, "section 4b")

    # -------------------------------------------------------------- 5. relayed (v1 address path, v3 UA path)
    log("\n## 5. relayed transfers: v1 (ECDSA envelope signer pays a FIXED outer fee) and v3 (mldsa65 fee UA); the proof binds the mode (D15)")
    sd.send(t1, cd("mint(address,uint256)", ["w", "w"], se.addr, 10 * SCALE), "pqUSD mint 10 public to the envelope signer")
    nonce = int.from_bytes(words(call(t1, cd("mtxNonce(address,uint256)", ["w", "w"], se.addr, 0)))[0], "big")
    m = [se.addr, b"", 0, nonce, int(time.time()) + 3600, 0x20, 0, 5 * SCALE, 0]
    b1 = words(call(t1, cd(f"envelopeBinding({MTX_S})", [MTX], m)))[0]
    _, data, _, _ = transfer(pq, sd, C1, bob, alice, b"\0" * 32, 20, True, "v1", binding=b1, send=False)
    m[1] = data
    dg = words(call(t1, cd(f"mtxDigest({MTX_S})", [MTX], m)))[0]
    r_, s_, rec = sign(se.key, dg)
    sig = r_.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([27 + rec])
    sr.send(t1, cd(f"mtxExecute({MTX_S},bytes)", [MTX, "b"], m, sig), "mtxExecute(mtxConfidentialTransferSingle bob→alice 20), relayer pays gas")
    C1.commit()
    fee_got = int.from_bytes(words(call(t1, cd("balanceOf(address)", ["w"], sr.addr)))[0], "big")
    check(fee_got == 5 * SCALE, f"relayer received the outer fee {fee_got:,}")

    sd.send(t1, cd("mintToUA(bytes32,uint256)", ["w", "w"], feeua.ua, 10 * SCALE), "pqUSD mintToUA(fee UA, 10)")
    un = int.from_bytes(words(call(t1, cd("uaNonce(bytes32,uint256)", ["w", "w"], feeua.ua, 0)))[0], "big")
    m = [feeua.ua, b"", 0, un, int(time.time()) + 3600, 0x20, 0, 2 * SCALE, 0]
    b3 = words(call(t1, cd(f"uaEnvelopeBinding({UMTX_S})", [MTX], m)))[0]
    _, data, _, _ = transfer(pq, sd, C1, alice, bob, b"\0" * 32, 10, True, "v3", binding=b3, send=False)
    m[1] = data
    dg = words(call(t1, cd(f"uaDigest({UMTX_S})", [MTX], m)))[0]
    sr.send(t1, cd(f"uaExecute({UMTX_S},bytes)", [MTX, "b"], m, ml_auth(pq, feeua, P_METATX, dg)),
            "uaExecute(mtxConfidentialTransferSingle alice→bob 10), mldsa65 fee UA pays 2 outer")
    C1.commit()
    left = int.from_bytes(words(call(t1, cd("balanceOfUA(bytes32)", ["w"], feeua.ua)))[0], "big")
    check(left == 8 * SCALE, f"fee UA public balance {left:,} after the outer fee")
    for u in (alice, bob):
        log(f"      {u.name}: {C1.state(u)}")
    check_public(C1, "after the relayed transfers")
    restore(C1, "section 5")

    # -------------------------------------------------------------- 6. UNDERLYING_PQZ (COMPACT, auditor OPTIONAL)
    log("\n## 6. UNDERLYING_PQZ (pqW over tUSD: COMPACT, auditor OPTIONAL): wrap-shield, R_TX0 commit-reveal, unshield-unwrap")
    C2 = Client(t2, "pqW")
    sd.send(tusd, cd("approve(address,uint256)", ["w", "w"], t2, 10**12), "tUSD approve pqW")
    sd.send(t2, cd(API["wrapShield"], ["w", "w", "w"], tusd, 500 * SCALE, alice.ua), "mtxWrapShield(tUSD 500, alice)")
    C2.set_next(bal=[(alice, 500)], total=500)
    C2.commit()
    transfer(pq, sd, C2, alice, bob, b"\0" * 32, 120, False, "mtxConfidentialTransferSingle alice→bob 120, auditor off (R_TX0), commit-reveal")
    rollover(sd, C2, bob, 1, "bob's credit")
    legs8 = [(bob, 30)] + [(u, 0) for u in [carol, aud] + DEC]
    transfer_multi(pq, sd, C2, alice, legs8, b"\0" * 32, False,
                   "mtxConfidentialTransfer (op 7) alice→M = 8 (bob 30, seven decoys), auditor off, commit-reveal (two groups)")
    before = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    burn(pq, sd, C2, bob, 70, sd.addr, "mtxUnshieldUnwrap bob 70 → deployer in tUSD", unwrap=(tusd, 70 * SCALE))
    after = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    check(after - before == 70 * SCALE, f"deployer received {after - before:,} tUSD from the leg")
    check_public(C2, "after the unwrap")
    res = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], t2)))[0], "big")
    check(res >= C2.total * SCALE, f"pqW reserve {res:,} ≥ totalShielded·scale {C2.total * SCALE:,}")
    restore(C2, "section 6")

    log("\n## addresses")
    for k, v in {**D.libs, **D.addr}.items():
        log(f"      {k}: {v}")
    with open(os.path.join(EVM, "deployments/7622-pqz.json") if os.path.isdir(os.path.join(EVM, "deployments"))
              else os.devnull, "w") as f:
        json.dump({**D.libs, **D.addr, "chain_uid": "0x" + uid.hex()}, f, indent=2)
    log(f"elapsed {time.time() - t0:.0f} s")


# ------------------------------------------------------------------ ops

def sent_ref(rc, tok, sigs):
    """The entry reference (topic 1) of the transfer event the token emitted."""
    tops = {"0x" + kc(x).hex() for x in sigs}
    lg = next(x for x in rc["logs"] if x["address"].lower() == tok.lower() and x["topics"][0] in tops)
    return bytes.fromhex(lg["topics"][1][2:])


def transfer(pq, s, C, frm, to, ben, v, aud_on, what, binding=b"\0" * 32, send=True, shield_in=0):
    """A transfer at `p = pendingCount` (the client rule), `shieldIn` taken from the sender's public balance (D5/D18),
    proved over the token's own statement (a `(payload, binding)` view, T read from state); returns (receipt, calldata,
    bundle, (r, e1, e2)). The relayed binding is the envelope's: the view folds the mode itself (D15)."""
    tok = C.tok
    stt = C.state(frm)
    p = stt["pendingCount"]
    compact = int(call(tok, cd("disclosureMode()", [])), 16) == 1
    salt = os.urandom(16)
    memo = salt + os.urandom(41) if compact else b""  # ponytail: memo body random (the token stores it unread);
    # the CTR-ZTH-50 HKDF memo is the client's (P6h)
    fee = FEE if ben != b"\0" * 32 else 0
    ben_ua = ben.ua if isinstance(ben, UA) else ben
    blen = K.CT_BYTES + K.V_BYTES * (2 if aud_on else 1)
    hdr = lambda out: W(p) + W(10**9) + W(shield_in) + frm.ua + to.ua + ben_ua + salt + out + memo  # noqa: E731
    view = lambda pl: dec_bytes(call(tok, cd(API["singleStmt"], ["b", "w"], pl, binding)))  # noqa: E731
    st0 = view(hdr(bytes(blen)))
    tOff = K.HEADER_BYTES + K.PK_BYTES * (3 if aud_on else 2)
    T = st0[tOff:tOff + K.CT_BYTES]
    b = bal(frm.s, T)
    rest = b - v - fee
    assert rest >= 0, (b, v, fee)
    aud_pk = None
    if aud_on:
        a_ua = bytes.fromhex(call(tok, cd("auditorUA()", []))[2:])
        aud_pk = dec_bytes(call(REG[0], cd("keyOf(bytes32)", ["w"], a_ua)))
    pks = [to.pk, frm.pk] + ([aud_pk] if aud_on else [])
    vals = [v, rest] + ([v] if aud_on else [])
    r_, e1, e2, _ = K.enc_sample(os.urandom(32), len(pks))
    u, vs = K.encrypt(pks, [K.digits(x) for x in vals], r_, e1, e2)
    out = u + b"".join(vs)
    pl = hdr(out)
    stmt = view(pl)
    check(stmt[tOff:tOff + K.CT_BYTES] == T and stmt[-len(out):] == out, f"{C.name} statement of {what}: T and out as built")
    wit = K.i8(frm.s) + K.i16(frm.e) + K.i8(r_) + K.i16(e1) + b"".join(K.i16(x) for x in e2) + bytes(K.digits(v)) + bytes(K.digits(rest))
    proof = pq.prove(1, stmt, wit)
    ad = kc("SCAAS-PQZ-AUTH-V1", keccak256(stmt))
    auth = ml_auth(pq, frm, P_ZAUTH, ad)
    hint = C.hint(frm)
    data = cd(API["transferSingle"], SH_T, pl, proof, auth, ben_ua, hint)
    log(f"      {what}: balance {b} → {rest} (+{v} to {to.name}, fee {fee}, shieldIn {shield_in}), p {p}, rolled {stt['rolled']}, "
        f"hint {len(hint)} B, proof {len(proof):,} B, auth {len(auth):,} B")
    # the client's next state: the sender's acc is the new reference u ‖ v_f; the credit is the recipient's
    C.set_next(bal=[(frm, shield_in - v - fee), (to, v)], pub=[(ben, FEE)] if fee else [], acc={frm.ua: u + vs[1]},
               total=shield_in - fee)
    bundle = salt + pack(u + vs[0]) + (pack(vs[2]) if aud_on else b"") + to.ua  # R as stored (P46)
    if not send:
        return None, data, bundle, (r_, e1, e2)
    rc = s.send(tok, data, f"{C.name} {what}")
    C.commit()
    ref = sent_ref(rc, tok, API["ev_single"])
    blob = dec_bytes(call(tok, cd("pqzEntryBlob(bytes32)", ["w"], ref)))
    check(blob == bundle + pack(vs[1]), f"{C.name} pqzEntryBlob(ref) = R ‖ v_f as built, packed ({len(blob):,} B)")
    return rc, ref, bundle, (r_, e1, e2)


def transfer_multi(pq, s, C, frm, legs, ben, aud_on, what):
    """An op 7 transfer (CTR-PQZ-26) at `p = pendingCount`, legs [(UA, amount)] (decoys: amount 0), proved over the
    token's own statement; payload `p ‖ validUntil ‖ shieldIn ‖ from ‖ ben ‖ M ‖ decoyFee ‖ salt ‖ UA_0…`, header fee word
    `txFee + M · decoyFee` (the proof binds the decoyFee); returns (receipt, entryRef, bundle, enc)."""
    tok = C.tok
    stt = C.state(frm)
    p = stt["pendingCount"]
    m, g = len(legs), K.groups(len(legs), aud_on)  # R0-1: S_AUD legs per group with the auditor, 4 without
    compact = int(call(tok, cd("disclosureMode()", [])), 16) == 1
    salt = os.urandom(16)
    memo = salt + os.urandom(2 + 40 * m) if compact else b""  # ponytail: memo body random, as transfer()
    mind = int(call(tok, cd("minDecoyFee()", [])), 16)
    assert DEC_FEE >= mind, (DEC_FEE, mind)
    fee = (FEE if ben != b"\0" * 32 else 0) + m * DEC_FEE
    ben_ua = ben.ua if isinstance(ben, UA) else ben
    olen = K.PK_BYTES * g + K.V_BYTES * (m + 1) + (K.V_BYTES * m if aud_on else 0)
    hdr = lambda out: (W(p) + W(10**9) + W(0) + frm.ua + ben_ua + W(m) + W(DEC_FEE) + salt  # noqa: E731
                       + b"".join(u.ua for u, _ in legs) + out + memo)
    view = lambda pl: dec_bytes(call(tok, cd(API["multiStmt"], ["b", "w"], pl, b"\0" * 32)))  # noqa: E731
    tOff = K.HEADER_BYTES + K.PK_BYTES * (1 + m + (1 if aud_on else 0))
    T = view(hdr(bytes(olen)))[tOff:tOff + K.CT_BYTES]
    b = bal(frm.s, T)
    rest = b - sum(a for _, a in legs) - fee
    assert rest >= 0, (b, legs, fee)
    aud_pk = None
    if aud_on:
        aud_pk = dec_bytes(call(REG[0], cd("keyOf(bytes32)", ["w"], bytes.fromhex(call(tok, cd("auditorUA()", []))[2:]))))
    e = K.enc_multi(frm.pk, K.digits(rest), [(u.pk, K.digits(a)) for u, a in legs], aud_pk, os.urandom(32))
    out = b"".join(e["us"]) + b"".join(e["vs"]) + e["v_f"] + (b"".join(e["v_as"]) if aud_on else b"")
    pl = hdr(out)
    stmt = view(pl)
    check(len(stmt) == K.multi_len(m, aud_on) and stmt[tOff:tOff + K.CT_BYTES] == T and stmt[-len(out):] == out,
          f"{C.name} op 7 statement of {what}: {len(stmt):,} B, T and out as built")
    wit = (K.i8(frm.s) + K.i16(frm.e) + b"".join(K.i8(r) + K.i16(x) for r, x in zip(e["rs"], e["e1s"]))
           + b"".join(K.i16(x) for x in e["e2"] + [e["e2_f"]] + e["e2_a"])
           + b"".join(bytes(K.digits(a)) for a in [a for _, a in legs] + [rest]))
    t0 = time.time()
    proof = pq.prove(7, stmt, wit)
    tp = time.time() - t0
    auth = ml_auth(pq, frm, P_ZAUTH, kc("SCAAS-PQZ-AUTH-V1", keccak256(stmt)))
    hint = C.hint(frm)
    data = cd(API["transfer"], SH_T, pl, proof, auth, ben_ua, hint)
    log(f"      {what}: M {m}, balance {b} → {rest}, header fee {fee}, hint {len(hint)} B, proof {len(proof):,} B in {tp:.2f} s, "
        f"calldata {len(data):,} B")
    newacc = e["us"][0] + e["v_f"]
    C.set_next(bal=[(frm, -sum(a for _, a in legs) - fee)] + [(u, a) for u, a in legs],
               pub=([(ben, FEE)] if ben != b"\0" * 32 else []) + [(u, DEC_FEE) for u, _ in legs], acc={frm.ua: newacc},
               total=-fee)
    bundle = salt + b"".join(pack(x) for x in e["us"]) + b"".join(  # R as stored (P46)
        pack(e["vs"][j]) + (pack(e["v_as"][j]) if aud_on else b"") + u.ua for j, (u, _) in enumerate(legs))
    rc = s.send(tok, data, f"{C.name} {what}")
    C.commit()
    ref = sent_ref(rc, tok, API["ev_multi"])
    blob = dec_bytes(call(tok, cd("pqzEntryBlob(bytes32)", ["w"], ref)))
    check(blob == bundle + pack(e["v_f"]), f"{C.name} pqzEntryBlob(ref) = R ‖ v_f as built, packed ({len(blob):,} B)")
    return rc, ref, bundle, e


def burn(pq, s, C, frm, amount, recipient, what, unwrap=None):
    """Burn / refresh. The recipient is a 32-byte id (UA-5c b): a native address is its zero-padded word."""
    tok = C.tok
    stt = C.state(frm)
    p = stt["pendingCount"]
    rcp = W(recipient) if recipient else b"\0" * 32
    hdr = lambda out: W(p) + W(10**9) + W(0) + frm.ua + b"\0" * 32 + out  # noqa: E731
    if unwrap:
        x = [unwrap[0], rcp, amount, unwrap[1]]
        view = lambda pl: dec_bytes(call(tok, cd(API["unwrapStmt"], ["b", UNWRAP, "w"], pl, x, 0)))  # noqa: E731
    else:
        view = lambda pl: dec_bytes(call(tok, cd(API["burnStmt"], ["b", "w", "w", "w"], pl, amount, rcp, 0)))  # noqa: E731
    tOff = K.HEADER_BYTES + K.PK_BYTES
    T = view(hdr(bytes(K.CT_BYTES)))[tOff:tOff + K.CT_BYTES]
    b = bal(frm.s, T)
    rest = b - amount
    r_, e1, e2, _ = K.enc_sample(os.urandom(32), 1)
    u, vs = K.encrypt([frm.pk], [K.digits(rest)], r_, e1, e2)
    pl = hdr(u + vs[0])
    stmt = view(pl)
    wit = K.i8(frm.s) + K.i16(frm.e) + K.i8(r_) + K.i16(e1) + K.i16(e2[0]) + bytes(K.digits(rest))
    proof = pq.prove(2, stmt, wit)
    auth = ml_auth(pq, frm, P_ZAUTH, kc("SCAAS-PQZ-AUTH-V1", keccak256(stmt)))
    hint = C.hint(frm)
    if unwrap:
        data = cd(API["unshieldUnwrap"], SH_T + [UNWRAP], pl, proof, auth, b"\0" * 32, hint, x)
    else:
        data = cd(API["unshield"], SH_T + ["w", "w"], pl, proof, auth, b"\0" * 32, hint, amount, rcp)
    log(f"      {what}: balance {b} → {rest}, p {p}, rolled {stt['rolled']}, hint {len(hint)} B, proof {len(proof):,} B")
    s.send(tok, data, f"{C.name} {what}")
    C.set_next(bal=[(frm, -amount)], acc={frm.ua: u + vs[0]}, total=-amount)
    C.commit()


REG = [None]

if __name__ == "__main__":
    main()
