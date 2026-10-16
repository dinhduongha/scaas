#!/usr/bin/env python3
"""P6g Tasks 7-8 (plan docs/superpowers/plans/2026-10-16-p6g-contracts.md, D7 / D15): deploy the PQZ contracts on
chain 7622 and run the e2e with REAL proofs. Python stdlib (python3 -I); P6f's eth.py (Keccak, RLP, secp256k1, legacy
EIP-155 transactions: calldata of 100-300 KB cannot pass cast's argv); pqz_kat.py (P6e) for KeyGen, Enc, Dec and the
witnesses; pqz-ffi's example `pqz_prove` (feature prove) for the proofs; `mldsa.mjs` (@noble/post-quantum 0.7.1) for the
ML-DSA signatures. Statements are always read from the token's own views, so the proofs cover exactly what the
contracts build.

  e2e.py --rpc http://127.0.0.1:8545 --log runs/2026-10-16-p6g-7622.txt [--keys 1,2,3]

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
from eth import address, keccak256, legacy_tx, sign  # noqa: E402
import pqz_kat as K  # noqa: E402

PQZ = "0x5caa500000000000000000000000000000000f01"
ML44 = "0x5caa500000000000000000000000000000000012"
ML65 = "0x5caa500000000000000000000000000000000013"
PQZL_ID = K.PQZL_ID
SCALE, MAXS, FEE = 10_000, 1 << 40, 3
MLDSA44, MLDSA65, PQZ_MLWE = 0x0130, 0x0131, 0x0142
CAP_ML, CAP_PQZ, BUDGET = 200_000, 3_000_000, 12_000_000
FAILS, LOG = [], []
RPC = None


def kc(*parts):
    return keccak256(b"".join(p if isinstance(p, bytes) else p.encode() for p in parts))


P_POP, P_AUTHREF, P_METATX, P_ZAUTH = (kc(f"scaas.ua.purpose.{n}.v1") for n in ("pop", "authref", "metatx", "zether-auth"))
MSG_TAG = kc("scaas.ua.msg.v1")
TAG = {MLDSA44: kc("scaas.ua.mldsa44.v1"), MLDSA65: kc("scaas.ua.mldsa65.v1"), PQZ_MLWE: kc("scaas.ua.pqz-mlwe.v1")}


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
UNWRAP = ("t", ["w", "w", "w", "w"])
CFG = ("t", ["b", "b", "w", "w", "w", "w", ("t", ["w"] * 5), "w", "w", ("a", ("t", ["w", "w", "w"])), ("t", ["w", "w"]),
             ("t", ["w", "b", "w", "w", "w", "w", "w"])])
CFG_S = ("(string,string,uint8,uint256,uint256,address,(address,address,address,address,address),uint256,address,"
         "(address,uint256,uint256)[],(uint32,uint16),(address,bytes,uint256,uint256,uint256,uint8,uint8))")


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
        if gas is None:
            try:
                gas = min(16_777_216, int(int(rpc("eth_estimateGas", [tx]), 16) * 1.15) + 50_000)
            except RuntimeError as e:
                check(False, f"{what}: estimateGas {e}")
                raise
        fee = int(rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
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

    def deploy(self, name, args, src=None, label=None):
        code, links = artifact(name, src)
        for _, ls in links.items():
            for ln, pos in ls.items():
                a = self.lib(ln)[2:]
                for p in pos:
                    code = code[:2 * p["start"]] + a + code[2 * (p["start"] + p["length"]):]
        r = self.s.send(None, bytes.fromhex(code) + args, label or f"deploy {name}")
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
    """An ML-DSA UA (`kind`, seed) or a PQZ UA (seed32, pk, s, e, authRef)."""

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
    """The wallet side of one PQZ token: per UA the `acc` bytes, the pending credits (from the token's events, here
    mirrored), the decrypted balance."""

    def __init__(self, tok, name):
        self.tok, self.name = tok, name
        self.acc, self.pend = {}, {}

    def state(self, ua):
        w = [int.from_bytes(x, "big") for x in words(call(self.tok, cd("accountState(bytes32)", ["w"], ua.ua)), 8)]
        return dict(zip(["accHash", "accUnits", "pendingCount", "rolled", "floor", "cleared", "sendCounter", "plainPending"], w))

    def accb(self, ua):
        return self.acc.get(ua.ua, bytes(K.CT_BYTES))

    def inline(self, ua, p):
        r = self.state(ua)["rolled"]
        lo, n = (r, p - r) if p >= r else (p, r - p)
        return self.pend.get(ua.ua, [])[lo:lo + n]


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
    check(st[2:] == "ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205", f"PQZ OP_SELFTEST = {st[:18]}…")
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
    reg_stmt = bytes.fromhex(json.load(open(os.path.join(ROOT, "smartcontracts/vectors/pqz/statement_register.json")))["rows"][0]["stmt"])
    reg_proof = bytes.fromhex(json.load(open(os.path.join(ROOT, "smartcontracts/vectors/pqz/proof_pqzl.json")))["rows"][4]["proof"])
    pqv = D.deploy("UAPqzVerifier", encs(["w", "w", "b", "w", "b"], [PQZ, PQZL_ID, reg_stmt[96:], reg_stmt[64:96], reg_proof]),
                   label="UAPqzVerifier PQZL")
    check(words(call(pqv, cd("isSupportedOnThisChain()", [])))[0][-1] == 1, "UAPqzVerifier.isSupportedOnThisChain()")
    kinds = [(MLDSA44, mlv[MLDSA44], CAP_ML), (MLDSA65, mlv[MLDSA65], CAP_ML), (PQZ_MLWE, pqv, CAP_PQZ)]
    reg = D.deploy("UARegistry", encs(["w", "w", "w", "w", "w", "w", ("a", ("t", ["w", "w", "w"]))],
                                      [uid, 0, 0, BUDGET, 0, 1, kinds]), label="UARegistry gen 1")
    REG[0] = reg
    fac = D.deploy("OpenFactory", encs(["w", "w"], [sd.addr, uid]))
    none_i = D.deploy("NoUnderlyingToken", encs(["w"] * 5, [fac, 0, uid, reg, 0]))
    npqz_i = D.deploy("NoUnderlyingPqzToken", encs(["w"] * 4, [fac, 0, uid, reg]))
    upqz_i = D.deploy("UnderlyingPqzToken", encs(["w"] * 4, [fac, 0, uid, reg]))
    for kind, impl in ((0, none_i), (4, npqz_i), (5, upqz_i)):
        sd.send(fac, cd("registerImplementation(uint8,uint64,address)", ["w", "w", "w"], kind, 1, impl),
                f"registerImplementation(kind {kind})")
    sd.send(fac, cd("setPqzEnabled(bool)", ["w"], 1), "setPqzEnabled(true) (self-test inside)")

    # -------------------------------------------------------------- 2. UAs
    log("\n## 2. UAs: ML-DSA authorities (real signatures) and pqz-mlwe keys (real R_REG proofs)")

    def ml_ua(name, kind, seed):
        lvl = 44 if kind == MLDSA44 else 65
        pk = pq.ml_pk(lvl, seed)
        ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], kind, pk)))[0]
        u = UA(name=name, kind=kind, seed=seed, pk=pk, ua=ua)
        pd = words(call(reg, cd("popDigest(bytes32,bytes32)", ["w", "w"], ua, 0)))[0]
        pop = pq.ml_sign(lvl, seed, kc(TAG[kind], ua_msg(kind, P_POP, pd)))
        sd.send(reg, cd("register(uint16,bytes,bytes,bytes32,bytes)", ["w", "b", "b", "w", "b"], kind, pk, pop, 0, b""),
                f"register {name} (mldsa{lvl}, seed {seed.hex()[:8]}…)")
        return u

    def pqz_ua(name, seed, auth):
        pk, s, e, _ = K.keygen(seed)
        ua = words(call(reg, cd("uaOf(uint16,bytes)", ["w", "b"], PQZ_MLWE, pk)))[0]
        pd = words(call(reg, cd("popDigest(bytes32,bytes32)", ["w", "w"], ua, auth.ua)))[0]
        stmt = K.build_register(ua_msg(PQZ_MLWE, P_POP, pd), pk)
        proof = pq.prove(3, stmt, K.i8(s) + K.i16(e))
        sd.send(reg, cd("register(uint16,bytes,bytes,bytes32,bytes)", ["w", "b", "b", "w", "b"], PQZ_MLWE, pk, proof,
                        auth.ua, ml_auth(pq, auth, P_AUTHREF, pd)), f"register {name} (pqz-mlwe, R_REG {len(proof):,} B)")
        kind = int.from_bytes(words(call(reg, cd("kindOf(bytes32)", ["w"], ua)))[0], "big")
        check(kind == PQZ_MLWE, f"{name} = {ua.hex()[:16]}… kindOf 0x0142")
        return UA(name=name, kind=PQZ_MLWE, seed=seed, pk=pk, s=s, e=e, ua=ua, auth=auth)

    sk = lambda tag: kc("p6g-e2e-7622/", tag)  # noqa: E731  (test seeds, in this log on purpose)
    log(f"test seeds: keccak256('p6g-e2e-7622/<name>')")
    ml = {n: ml_ua(f"auth-{n}", MLDSA65, sk("ml-" + n)) for n in ("alice", "bob", "aud", "carol")}
    ml44 = ml_ua("auth-44", MLDSA44, sk("ml44"))
    feeua = ml_ua("fee-ua", MLDSA65, sk("fee"))
    U = {n: pqz_ua(n, sk("pqz-" + n), ml[n]) for n in ("alice", "bob", "aud", "carol")}
    alice, bob, aud, carol = U["alice"], U["bob"], U["aud"], U["carol"]

    # ML-DSA verify gas through the registry (both levels, precompile path)
    for u in (ml44, ml["alice"]):
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
             [pqv, aud_key, SCALE, MAXS, FEE, dmode, amode] if conf else [0, b"", 0, 0, 0, 0, 0]]
        data = cd(f"createToken(uint8,uint64,{CFG_S},bytes32)", ["w", "w", CFG, "w"], kind, 1, c, kc(salt))
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
    log("\n## 4. NONE_PQZ (pqUSD: BUNDLE, auditor FULL): shield, transfer, rollover, inline, burn, refresh, disclosure")
    C1 = Client(t1, "pqUSD")
    sd.send(t1, cd("mint(address,uint256)", ["w", "w"], sd.addr, 5_000 * SCALE), "pqUSD mint 5,000 public")
    sd.send(t1, cd("pqzShield(bytes32,uint256)", ["w", "w"], alice.ua, 1_000), "pqzShield(alice, 1,000)")
    check(C1.state(alice)["plainPending"] == 1000, "alice plainPending 1,000")

    xfer = lambda *a, **k: transfer(pq, sd, C1, *a, **k)  # noqa: E731
    r1, ref1, bundle1, enc1 = xfer(alice, bob, carol, 300, True, "pqzTransfer alice→bob 300, fee 3 to carol")
    sd.send(t1, cd("pqzRollOver(bytes32,bytes,bytes[])", ["w", "b", ("a", "b")], bob.ua, C1.accb(bob), C1.pend[bob.ua][0:1]),
            "pqzRollOver(bob, 1 credit)")
    C1.acc[bob.ua] = K.ct_add(C1.accb(bob), C1.pend[bob.ua][0])
    xfer(bob, alice, b"\0" * 32, 100, True, "pqzTransfer bob→alice 100 (no fee)")
    xfer(alice, bob, b"\0" * 32, 50, True, "pqzTransfer alice→bob 50 with 1 inline credit (p ≥ rolled)")
    burn(pq, sd, C1, alice, 200, sd.addr, "pqzUnshield alice burns 200 → deployer")
    burn(pq, sd, C1, alice, 0, None, "pqzUnshield refresh (amount 0)")
    pub = int.from_bytes(words(call(t1, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    check(pub == (5_000 - 1_000 + 200) * SCALE, f"deployer public pqUSD = {pub:,} (4,000 + the 200 burnt back)")
    tot = int.from_bytes(words(call(t1, cd("totalShielded()", [])))[0], "big")
    check(tot == 800, f"totalShielded = {tot}")

    log("disclosure of the first transfer (view, verifyTransferAmount):")
    for kind, op, wit in ((0, 4, K.i8(enc1[0]) + K.i16(enc1[1]) + K.i16(enc1[2][0])),
                          (1, 5, K.i8(bob.s) + K.i16(bob.e)), (2, 5, K.i8(aud.s) + K.i16(aud.e))):
        stmt = dec_bytes(call(t1, cd("disclosureStatement(bytes32,uint256,uint8,bytes)", ["w", "w", "w", "b"], ref1, 300,
                                     kind, bundle1)))
        proof = pq.prove(op, stmt, wit)
        opening = encs(["b", "b"], [bundle1, proof])
        data = cd("verifyTransferAmount(bytes32,uint256,uint8,bytes)", ["w", "w", "w", "b"], ref1, 300, kind, opening)
        okw = int(call(t1, data), 16)
        bad = int(call(t1, cd("verifyTransferAmount(bytes32,uint256,uint8,bytes)", ["w", "w", "w", "b"], ref1, 301, kind,
                              opening)), 16)
        check(okw == 1 and bad == 0, f"verifyTransferAmount kind {kind} (op {op}): 300 ⇒ true, 301 ⇒ false; "
                                     f"eth_estimateGas {gas_of(t1, data):,}")

    # -------------------------------------------------------------- 5. relayed (v1 address path, v3 UA path)
    log("\n## 5. relayed transfers: v1 (ECDSA envelope signer pays a FIXED outer fee) and v3 (mldsa65 fee UA)")
    sd.send(t1, cd("mint(address,uint256)", ["w", "w"], se.addr, 10 * SCALE), "pqUSD mint 10 public to the envelope signer")
    nonce = int.from_bytes(words(call(t1, cd("mtxNonce(address,uint256)", ["w", "w"], se.addr, 0)))[0], "big")
    m = [se.addr, b"", 0, nonce, int(time.time()) + 3600, 0x20, 0, 5 * SCALE, 0]
    b1 = words(call(t1, cd(f"envelopeBinding({MTX_S})", [MTX], m)))[0]
    _, data, _, _ = transfer(pq, sd, C1, bob, alice, b"\0" * 32, 20, True, "v1", binding=b1, send=False)
    m[1] = data
    dg = words(call(t1, cd(f"mtxDigest({MTX_S})", [MTX], m)))[0]
    r_, s_, rec = sign(se.key, dg)
    sig = r_.to_bytes(32, "big") + s_.to_bytes(32, "big") + bytes([27 + rec])
    sr.send(t1, cd(f"mtxExecute({MTX_S},bytes)", [MTX, "b"], m, sig), "mtxExecute(pqzTransfer bob→alice 20), relayer pays gas")
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
            "uaExecute(pqzTransfer alice→bob 10), mldsa65 fee UA pays 2 outer")
    C1.commit()
    left = int.from_bytes(words(call(t1, cd("balanceOfUA(bytes32)", ["w"], feeua.ua)))[0], "big")
    check(left == 8 * SCALE, f"fee UA public balance {left:,} after the outer fee")
    for u in (alice, bob):
        stt = C1.state(u)
        log(f"      {u.name}: {stt}")

    # -------------------------------------------------------------- 6. UNDERLYING_PQZ (COMPACT, auditor OPTIONAL)
    log("\n## 6. UNDERLYING_PQZ (pqW over tUSD: COMPACT, auditor OPTIONAL): wrap-shield, R_TX0 commit-reveal, unshield-unwrap")
    C2 = Client(t2, "pqW")
    sd.send(tusd, cd("approve(address,uint256)", ["w", "w"], t2, 10**12), "tUSD approve pqW")
    sd.send(t2, cd("pqzWrapShield(address,uint256,bytes32)", ["w", "w", "w"], tusd, 500 * SCALE, alice.ua),
            "pqzWrapShield(tUSD 500, alice)")
    transfer(pq, sd, C2, alice, bob, b"\0" * 32, 120, False, "pqzTransfer alice→bob 120, auditor off (R_TX0), commit-reveal")
    sd.send(t2, cd("pqzRollOver(bytes32,bytes,bytes[])", ["w", "b", ("a", "b")], bob.ua, C2.accb(bob), C2.pend[bob.ua][0:1]),
            "pqW pqzRollOver(bob)")
    C2.acc[bob.ua] = K.ct_add(C2.accb(bob), C2.pend[bob.ua][0])
    before = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    burn(pq, sd, C2, bob, 70, sd.addr, "pqzUnshieldUnwrap bob 70 → deployer in tUSD", unwrap=(tusd, 70 * SCALE))
    after = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], sd.addr)))[0], "big")
    check(after - before == 70 * SCALE, f"deployer received {after - before:,} tUSD from the leg")
    tot = int.from_bytes(words(call(t2, cd("totalShielded()", [])))[0], "big")
    res = int.from_bytes(words(call(tusd, cd("balanceOf(address)", ["w"], t2)))[0], "big")
    check(res >= tot * SCALE, f"pqW reserve {res:,} ≥ totalShielded·scale {tot * SCALE:,}")

    log("\n## addresses")
    for k, v in {**D.libs, **D.addr}.items():
        log(f"      {k}: {v}")
    with open(os.path.join(EVM, "deployments/7622-pqz.json") if os.path.isdir(os.path.join(EVM, "deployments"))
              else os.devnull, "w") as f:
        json.dump({**D.libs, **D.addr, "chain_uid": "0x" + uid.hex()}, f, indent=2)
    log(f"elapsed {time.time() - t0:.0f} s")


# ------------------------------------------------------------------ ops

def _commit(self):
    for k, v in getattr(self, "_next", {}).items():
        if k == "acc":
            self.acc.update(v)
        else:
            for ua, ct in v:
                self.pend.setdefault(ua, []).append(ct)
    self._next = {}


Client.commit = _commit


def transfer(pq, s, C, frm, to, ben, v, aud_on, what, binding=b"\0" * 32, send=True):
    """A transfer at `p = pendingCount` with `plainUsed = plainPending` (the client rule), proved over the token's own
    statement; returns (receipt, calldata, bundle, (r, e1, e2))."""
    tok = C.tok
    stt = C.state(frm)
    p, plain = stt["pendingCount"], stt["plainPending"]
    inl = C.inline(frm, p)
    compact = int(call(tok, cd("disclosureMode()", [])), 16) == 1
    salt = os.urandom(16)
    memo = salt + os.urandom(41) if compact else b""  # ponytail: memo body random (the token stores it unread);
    # the CTR-ZTH-50 HKDF memo is the client's (P6h)
    fee = FEE if ben != b"\0" * 32 else 0
    ben_ua = ben.ua if isinstance(ben, UA) else ben
    blen = 16_768 if aud_on else 16_640
    hdr = lambda out: W(p) + W(10**9) + W(plain) + frm.ua + to.ua + ben_ua + salt + out + memo  # noqa: E731
    view = lambda pl: dec_bytes(call(tok, cd("transferStatement(bytes,bytes,bytes[],bytes32)", ["b", "b", ("a", "b"), "w"],  # noqa: E731
                                              pl, C.accb(frm), inl, binding)))
    st0 = view(hdr(bytes(blen)))
    tOff = 49_792 if aud_on else 33_408
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
    auth = ml_auth(pq, frm.auth, P_ZAUTH, ad)
    data = cd("pqzTransfer(bytes,bytes,bytes[],bytes,bytes)", ["b", "b", ("a", "b"), "b", "b"], pl, C.accb(frm), inl, proof, auth)
    log(f"      {what}: balance {b} → {rest} (+{v} to {to.name}, fee {fee}), p {p}, plainUsed {plain}, {len(inl)} inline, "
        f"proof {len(proof):,} B, auth {len(auth):,} B")
    # the client's next state
    newacc = u + vs[1]
    if p < stt["rolled"]:
        for x in inl:
            newacc = K.ct_add(newacc, x)
    C._next = {"acc": {frm.ua: newacc}, "pend": [(to.ua, u + vs[0])]}
    bundle = salt + u + vs[0] + (vs[2] if aud_on else b"") + to.ua
    if not send:
        return None, data, bundle, (r_, e1, e2)
    rc = s.send(tok, data, f"{C.name} {what}")
    C.commit()
    topic = "0x" + kc("PqzTransfer(bytes32,bytes32,bytes32,bytes16,bytes)").hex()
    ref = bytes.fromhex(next(x for x in rc["logs"] if x["topics"][0] == topic)["topics"][1][2:])
    return rc, ref, bundle, (r_, e1, e2)


def burn(pq, s, C, frm, amount, recipient, what, unwrap=None):
    tok = C.tok
    stt = C.state(frm)
    p, plain = stt["pendingCount"], stt["plainPending"]
    inl = C.inline(frm, p)
    rcp = recipient or "0x" + "00" * 20
    hdr = lambda out: W(p) + W(10**9) + W(plain) + frm.ua + b"\0" * 32 + out  # noqa: E731
    if unwrap:
        x = [unwrap[0], rcp, amount, unwrap[1]]
        view = lambda pl: dec_bytes(call(tok, cd("unshieldUnwrapStatement(bytes,bytes,bytes[],(address,address,uint256,uint256),bytes32)",  # noqa: E731
                                                  ["b", "b", ("a", "b"), UNWRAP, "w"], pl, C.accb(frm), inl, x, 0)))
    else:
        view = lambda pl: dec_bytes(call(tok, cd("burnStatement(bytes,bytes,bytes[],uint256,address,bytes32)",  # noqa: E731
                                                  ["b", "b", ("a", "b"), "w", "w", "w"], pl, C.accb(frm), inl, amount, rcp, 0)))
    T = view(hdr(bytes(K.CT_BYTES)))[17_024:17_024 + K.CT_BYTES]
    b = bal(frm.s, T)
    rest = b - amount
    r_, e1, e2, _ = K.enc_sample(os.urandom(32), 1)
    u, vs = K.encrypt([frm.pk], [K.digits(rest)], r_, e1, e2)
    pl = hdr(u + vs[0])
    stmt = view(pl)
    wit = K.i8(frm.s) + K.i16(frm.e) + K.i8(r_) + K.i16(e1) + K.i16(e2[0]) + bytes(K.digits(rest))
    proof = pq.prove(2, stmt, wit)
    auth = ml_auth(pq, frm.auth, P_ZAUTH, kc("SCAAS-PQZ-AUTH-V1", keccak256(stmt)))
    if unwrap:
        data = cd("pqzUnshieldUnwrap(bytes,bytes,bytes[],(address,address,uint256,uint256),bytes,bytes)",
                  ["b", "b", ("a", "b"), UNWRAP, "b", "b"], pl, C.accb(frm), inl, x, proof, auth)
    else:
        data = cd("pqzUnshield(bytes,bytes,bytes[],uint256,address,bytes,bytes)", ["b", "b", ("a", "b"), "w", "w", "b", "b"],
                  pl, C.accb(frm), inl, amount, rcp, proof, auth)
    log(f"      {what}: balance {b} → {rest}, p {p}, plainUsed {plain}, {len(inl)} inline, proof {len(proof):,} B")
    s.send(tok, data, f"{C.name} {what}")
    newacc = u + vs[0]
    if p < stt["rolled"]:
        for x_ in inl:
            newacc = K.ct_add(newacc, x_)
    C.acc[frm.ua] = newacc


REG = [None]

if __name__ == "__main__":
    main()
