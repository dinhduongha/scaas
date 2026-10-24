#!/usr/bin/env python3
"""P6f Tasks 7-8 (pq-zero-knowledge.md §10 steps 1-2, 5): probes and end-to-end transactions against a PQZ chain, through
one JSON-RPC endpoint (the follower behind nginx on the copy; 127.0.0.1:8545 on 7622 in Task 10). Python stdlib
(run with python3 -I) with eth.py (keccak, legacy EIP-155 signing); forge artifacts from
smartcontracts/evm/out. Requests are paced (the proxy allows 10 r/s, burst 20) and retried on 429.
Since plan 5h Task 8d part 1 this targets the next image (32-bit addresses, PQZ_SET's self-test hash / MAX_INPUT /
corpus, default n2304-kmax4096), not the live pqz2 chain: for that run the script of the pqz2 commit (RUNBOOK.md).

  e2e.py before  --engine E                 the three addresses empty (code, balance, nonce; eth_call answers nothing)
  e2e.py probe   --engine E [--genesis-hash H]   step 2: chain id, genesis hash, OP_SELFTEST, every vector 1 / 0,
                                            gas = formula for every row (valid = invalid), misses, ML-DSA both levels
  e2e.py stock   --engine E                 the stock image after T: the probe must FAIL (G2 demonstration)
  e2e.py e2e     --engine E --key K [--no-ua]  transactions: probe contract, check() per row, direct > 128 KiB
                                            inputs, UAMldsaVerifier at both levels (not with --no-ua: live 7622)
  e2e.py burst   [--clients 4 --calls 50]   step 5: eth_call spam at PQZ; counts 200 / 429; block interval
  e2e.py fill    --engine E --key K [--n 8] PQZH transfers sent straight to PQZ, to fill a block
  e2e.py head                               number, hash, gasLimit, timestamp of the head

Common: --rpc URL (default http://127.0.0.1:18545); --schedule N: the engine file's schedule in force (default the
last; path A before T: 0). A row the schedule lacks (op 7 before its schedule) is expected as a miss: …00 at the
smallest row. op 7 rows are keyed by (op, id, stmtLen, M, auditorOn) (P6-ANON S8, plan D19); the probe also replays
the op 7 rows of negative.json. Exit 0 iff every check passed."""
import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eth import address, keccak256, legacy_tx  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../.."))
PQZ = "0x000000000000000000000000000000005caa0f01"
ML44 = "0x000000000000000000000000000000005caa0012"
ML65 = "0x000000000000000000000000000000005caa0013"
PROBE_AT = "0x00000000000000000000000000000000000f6f01"  # eth_call state override: the probe without a deployment
# the node library's parameter set (PQZ_SET, default n2304-kmax4096 = pqz-ffi's default; plan 5h Task 8d): its
# OP_SELFTEST hash and input limit (pqz_max_input () = set.json max_input)
PQZ_SET = os.environ.get("PQZ_SET", "n2304-kmax4096")
SELFTEST = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/pqz", "" if PQZ_SET == "n2048-kmax1024" else PQZ_SET,
                                       "selftest.json")))["hash"]
MAX_INPUT = json.load(open(os.path.join(ROOT, "pqz-core/params/sets", PQZ_SET, "set.json")))["max_input"]
CHAIN_ID = 7622
PK44, SIG44, PK65, SIG65 = 1312, 2420, 1952, 3309
FAILS = []
RPC = "http://127.0.0.1:18545"
_last = [0.0]
_lock = threading.Lock()


def log(s):
    print(s, flush=True)


def check(ok, what):
    log(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        FAILS.append(what)
    return ok


def rpc(method, params=(), pace=0.11, url=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
    for attempt in range(200):
        with _lock:
            wait = _last[0] + pace - time.time()
            if wait > 0:
                time.sleep(wait)
            _last[0] = time.time()
        try:
            req = urllib.request.Request(url or RPC, body, {"content-type": "application/json"})
            r = json.load(urllib.request.urlopen(req, timeout=180))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(0.5)
                continue
            raise
        if "error" in r:
            raise RuntimeError(f"{method}: {r['error']}")
        return r["result"]
    raise RuntimeError(f"{method}: still 429")


def keccak(hexdata):
    return keccak256(bytes.fromhex(hexdata.removeprefix("0x"))).hex()


def selector(sig):
    return keccak256(sig.encode()).hex()[:8]


def artifact(path, name):
    j = json.load(open(os.path.join(ROOT, "smartcontracts/evm/out", path, name + ".json")))
    return j["bytecode"]["object"].removeprefix("0x"), j["deployedBytecode"]["object"].removeprefix("0x")


def w(n):
    return format(n, "064x")


def abi_bytes(b):
    return w(len(b)) + b.hex() + "00" * (-len(b) % 32)


def enc_addr_bytes(addr, data):
    """abi.encode(address, bytes)"""
    return w(int(addr, 16)) + w(64) + abi_bytes(data)


def corpus():
    with open(os.path.join(ROOT, "pqz-core/nethermind/bin/corpus.jsonl")) as f:
        return [json.loads(l) for l in f]


SCHEDULE = -1  # --schedule


def small_word(b):
    return b[31] if not any(b[:31]) else -1


class Schedule:
    def __init__(self, path):
        s = json.load(open(path))["schedules"][SCHEDULE]
        self.rows = {(r["op"], r["id"].lower().removeprefix("0x"), r["stmtLen"], r.get("legs", 0), r.get("auditorOn", 0)): r["gas"]
                     for r in s["pqz"]}
        self.min = min(self.rows.values())
        self.selftest = s["selftestGas"]
        self.m44, self.m65 = s["mldsa44Gas"], s["mldsa65Gas"]

    def row(self, b):
        if len(b) < 69:
            return None
        legs = aud = 0
        if b[0] == 7:  # header words 320 / 448, read without validation (as the plugin)
            if len(b) < 5 + 480:
                return None
            legs, aud = small_word(b[5 + 320:5 + 352]), small_word(b[5 + 448:5 + 480])
        return self.rows.get((b[0], b[37:69].hex(), int.from_bytes(b[1:5], "big"), legs, aud))

    def gas(self, b):
        if b and b[0] == 6:
            return self.selftest
        g = self.row(b)
        return (self.min if g is None else g) + 3 * ((len(b) + 31) // 32)


def ml_gas(b, pk, sig, price):
    return price + 6 * ((max(0, len(b) - pk - sig) + 31) // 32)


def ml_rows():
    """(level, input, valid): EIP-8355 cases, the ACVP external cases (valid only with the empty context), the UA
    pq_signatures ML-DSA rows (pk ‖ sig ‖ pq_msg)."""
    ext = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/ua/pq_external.json")))
    rows = []
    v = lambda x: x if isinstance(x, bool) else x == "True"
    for c in ext["eip8355"]["cases"]:
        b = bytes.fromhex(c["input"][2:])
        lv = [44, 65] if "pk" not in c else [44 if len(c["pk"]) // 2 - 1 == PK44 else 65]
        rows += [(l, b, v(c["valid"]), "eip8355 " + c["name"][:40]) for l in lv]
    for c in ext["acvp_mldsa"]["cases"]:
        if c["iface"] != "external":
            continue
        pk, mp = bytes.fromhex(c["pk"][2:]), bytes.fromhex(c["mprime"][2:])
        rows.append((44 if len(pk) == PK44 else 65, pk + bytes.fromhex(c["sig"][2:]) + mp[2 + mp[1]:],
                     mp[1] == 0 and v(c["valid"]), f"acvp {c['set']} tc {c['tc']}"))
    for (lvl, b, ok, name) in ua_rows():
        rows.append((lvl, b, ok, name))
    return rows


def ua_rows():
    d = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/ua/pq_signatures.json")))
    out = []
    for k in d["kinds"] + d["extraKeys"]:
        if k["name"] not in ("mldsa44", "mldsa65"):
            continue
        pk = bytes.fromhex(k["keyData"][2:])
        tag = keccak("0x" + f"scaas.ua.{k['name']}.v1".encode().hex())
        lvl = 44 if k["name"] == "mldsa44" else 65
        for p in ("pop", "popOther"):
            if p in k:
                s = k[p]
                pq = bytes.fromhex(keccak("0x" + tag + s["message"][2:]))
                out.append((lvl, pk + bytes.fromhex(s["sig"][2:]) + pq, True, f"ua {k['name']} {p}"))
    return out


def call_probe(target, data, gas=16_000_000):
    """probe.call(target, data) through eth_call with the probe's code at PROBE_AT (state override)."""
    _, deployed = artifact("PqzPrecompileProbe.sol", "PqzPrecompileProbe")
    cd = "0x" + selector("call(address,bytes)") + enc_addr_bytes(target, data)
    r = rpc("eth_call", [{"to": PROBE_AT, "data": cd, "gas": hex(gas)}, "latest", {PROBE_AT: {"code": "0x" + deployed}}])
    r = r[2:]
    return int(r[0:64], 16), int(r[64:128], 16), int(r[128:192], 16)


def overhead():
    """The probe's constant: gasUsed on the identity precompile (32 bytes: 15 + 3) minus 100 (warm) minus 18."""
    word, used, rlen = call_probe("0x0000000000000000000000000000000000000004", (5).to_bytes(32, "big"))
    assert word == 5 and rlen == 32, (word, rlen)
    return used - 100 - 18


def cmd_head(a):
    b = rpc("eth_getBlockByNumber", ["latest", False])
    log(f"head {int(b['number'], 16)} {b['hash']} gasLimit {int(b['gasLimit'], 16)} gasUsed {int(b['gasUsed'], 16)} ts {int(b['timestamp'], 16)}")


def cmd_before(a):
    for addr in (PQZ, ML44, ML65):
        check(rpc("eth_getCode", [addr, "latest"]) == "0x", f"before T: eth_getCode {addr} empty")
        check(int(rpc("eth_getBalance", [addr, "latest"]), 16) == 0, f"before T: balance {addr} 0")
        check(int(rpc("eth_getTransactionCount", [addr, "latest"]), 16) == 0, f"before T: nonce {addr} 0")
        r = rpc("eth_call", [{"to": addr, "data": "0x0600000000"}, "latest"])
        check(r == "0x", f"before T: eth_call {addr} answers nothing ({r[:20]})")
        word, used, rlen = call_probe(addr, bytes.fromhex("0600000000"))
        check(rlen == 0 and word == 0, f"before T: probe.call({addr}) rlen 0 (word {word}, gas {used})")


def cmd_probe(a, expect_fail=False):
    sch = Schedule(a.engine)
    check(int(rpc("eth_chainId"), 16) == CHAIN_ID, f"eth_chainId = {CHAIN_ID:#x}")
    g = rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
    if a.genesis_hash:
        check(g == a.genesis_hash, f"genesis hash {g} = {a.genesis_hash}")
    else:
        log(f"genesis hash {g}")
    st = rpc("eth_call", [{"to": PQZ, "data": "0x0600000000"}, "latest"])
    ok = check(st == "0x" + SELFTEST, f"OP_SELFTEST eth_call = {SELFTEST[:8]}…{SELFTEST[-4:]} (got {st[:12]}…)")
    if expect_fail:
        return
    oh = overhead()
    log(f"probe overhead (identity precompile) = {oh} gas")
    rows = [r for r in corpus() if r["kind"] in ("honest", "flip", "fee0", "selftest")
            or (r["kind"] == "negative" and r["op"] == 7 and r["expect"] == "0")]
    by = {}
    for r in rows:
        b = bytes.fromhex(r["input"])
        word, used, rlen = call_probe(PQZ, b)
        want = int(r["expect"], 16) if r["kind"] == "selftest" else 0 if sch.row(b) is None else int(r["expect"])
        gas = used - 100 - oh
        check(rlen == 32 and word == want and gas == sch.gas(b),
              f"PQZ {r['kind']:8} {r['name'][:46]:46} {r['id']}: word {word if word < 2 else hex(word)[:10]} (want {want if want < 2 else 'hash'}), gas {gas} = formula {sch.gas(b)}")
        # pair a valid input with its flip by the statement (op 7: one form, several shapes)
        by.setdefault((r["id"], r["form"], b[:5 + max(r["stmt_len"], 0)]), {})[r["kind"]] = gas
    for k, v in sorted(by.items()):
        if "honest" in v and "flip" in v:
            check(v["honest"] == v["flip"], f"gas valid = invalid {k[:2]} ({len(k[2]) - 5:,} B statement): {v['honest']} / {v['flip']}")
    h = bytes.fromhex(next(r for r in rows if r["kind"] == "honest")["input"])
    for name, b in (("unknown id", h[:40] + bytes([h[40] ^ 1]) + h[41:]), ("short (68 B)", h[:68]), ("empty", b""),
                    ("unknown op 9", bytes([9]) + h[1:])):
        word, used, rlen = call_probe(PQZ, b)
        check(rlen == 32 and word == 0 and used - 100 - oh == sch.gas(b) and sch.row(b) is None,
              f"PQZ miss {name}: …00, gas {used - 100 - oh} = smallest row + length term {sch.gas(b)}")
    over = h + bytes(MAX_INPUT + 1 - len(h))
    word, used, rlen = call_probe(PQZ, over)
    check(word == 2**256 - 1 and rlen == 0, f"PQZ input of MAX_INPUT + 1: failed call (word {hex(word)[:6]}, rlen {rlen})")
    for lvl, b, valid, name in ml_rows():
        addr, pk, sig, price = (ML44, PK44, SIG44, sch.m44) if lvl == 44 else (ML65, PK65, SIG65, sch.m65)
        word, used, rlen = call_probe(addr, b)
        gas = used - 100 - oh
        check(rlen == 32 and word == int(valid) and gas == ml_gas(b, pk, sig, price),
              f"MLDSA{lvl} {name[:44]:44}: word {word} (want {int(valid)}), gas {gas} = {ml_gas(b, pk, sig, price)}")
        if valid:
            f = bytearray(b)
            f[pk + 5] ^= 1
            word, used, rlen = call_probe(addr, bytes(f))
            check(word == 0 and rlen == 32 and used - 100 - oh == ml_gas(b, pk, sig, price), f"MLDSA{lvl} {name[:30]} sig bit flipped: 0, same gas")


def cmd_stock(a):
    """G2: a stock node ignores engine.Pqz; after T every probe answers nothing."""
    st = rpc("eth_call", [{"to": PQZ, "data": "0x0600000000"}, "latest"])
    log(f"stock image after T: OP_SELFTEST eth_call = {st!r}")
    h = bytes.fromhex(next(r for r in corpus() if r["kind"] == "honest")["input"])
    for addr, b in ((PQZ, bytes.fromhex("0600000000")), (PQZ, h), (ML44, bytes(3800))):
        word, used, rlen = call_probe(addr, b)
        log(f"stock image after T: probe.call({addr}) word {word} rlen {rlen} gas {used}")
        check(rlen == 0, f"stock image: {addr} is an empty account (the probe fails, as it must)")
    check(st != "0x" + SELFTEST, "stock image: OP_SELFTEST does NOT return the hash (probe failure recorded)")


class Sender:
    """Legacy EIP-155 transactions signed here (eth.py): calldata of 300+ KB cannot pass through cast's argv."""

    def __init__(self, key):
        self.key = int(key.removeprefix("0x"), 16)
        self.addr = address(self.key)
        self.nonce = int(rpc("eth_getTransactionCount", [self.addr, "pending"]), 16)

    def send(self, to, data_hex, gas):
        # gas price max(2·baseFee + 1, 1 gwei) (full blocks raise the base fee by ≥ 1 wei each): once a block passes the EIP-1559 target the base fee is ≥ 1 wei for good (the
        # decrease rounds to 0), and a priority fee of 0 is rejected by the min-gas-price filter (7622's config key
        # Mining.MinGasPrice is not a Nethermind key; Blocks.MinGasPrice defaults to 1 wei)
        fee = int(rpc("eth_getBlockByNumber", ["latest", False])["baseFeePerGas"], 16)
        raw = legacy_tx(self.key, self.nonce, max(2 * fee + 1, 10**9), gas, to, 0, bytes.fromhex(data_hex.removeprefix("0x")), CHAIN_ID)
        self.nonce += 1
        return rpc("eth_sendRawTransaction", ["0x" + raw.hex()])


def receipt(h, timeout=180):
    t = time.time()
    while time.time() - t < timeout:
        r = rpc("eth_getTransactionReceipt", [h], pace=0.3)
        if r:
            return r
        time.sleep(1)
    raise RuntimeError(f"no receipt for {h}")


def tokens(b):
    z = b.count(0)
    return z + 4 * (len(b) - z)


def cmd_e2e(a):
    sch = Schedule(a.engine)
    s = Sender(a.key)
    log(f"sender {s.addr} nonce {s.nonce}")
    code, _ = artifact("PqzPrecompileProbe.sol", "PqzPrecompileProbe")
    r = receipt(s.send(None, "0x" + code, 2_000_000))
    probe = r["contractAddress"]
    check(r["status"] == "0x1", f"probe deployed at {probe} (block {int(r['blockNumber'], 16)}, gas {int(r['gasUsed'], 16)})")
    topic = "0x" + keccak256(b"Probed(address,bytes32,uint256,uint256,uint256)").hex()
    sel = selector("check(address,bytes)")
    rows = [r for r in corpus() if r["kind"] in ("honest", "flip", "fee0")]
    pending = []
    for row in rows:
        b = bytes.fromhex(row["input"])
        gl = min(16_000_000, 21_000 + 10 * tokens(b) + 40 * len(b) + sch.gas(b) + 500_000)
        pending.append((row, b, s.send(probe, "0x" + sel + enc_addr_bytes(PQZ, b), gl)))
    blocks = set()
    for row, b, h in pending:
        rc = receipt(h)
        lg = [l for l in rc["logs"] if l["topics"][0] == topic]
        ok = rc["status"] == "0x1" and len(lg) == 1
        word = int(lg[0]["data"][2 + 64:2 + 128], 16) if ok else None
        used = int(lg[0]["data"][2 + 128:2 + 192], 16) if ok else None
        blocks.add(int(rc["blockNumber"], 16))
        check(ok and word == (0 if sch.row(b) is None else int(row["expect"])),
              f"tx check() {row['kind']:6} {row['name'][:40]:40} {row['id']}: event word {word} (want {row['expect']}), call gas {used}, tx gas {int(rc['gasUsed'], 16)}, block {int(rc['blockNumber'], 16)}")
    log(f"check() transactions in blocks {sorted(blocks)}")
    # direct transactions to PQZ with the largest inputs (> 128 KiB: TxPool.MaxTxSize)
    big = sorted((r for r in corpus() if r["kind"] in ("honest", "fee0") and r["id"] == "pqzh"), key=lambda r: -len(r["input"]))[:2]
    for row in big:
        b = bytes.fromhex(row["input"])
        std = 21_000 + 4 * tokens(b) + sch.gas(b)
        floor = 21_000 + 10 * tokens(b)
        rc = receipt(s.send(PQZ, "0x" + b.hex(), min(16_777_216, max(std, floor) + 10_000)))
        got = int(rc["gasUsed"], 16)
        check(rc["status"] == "0x1" and got == max(std, floor),
              f"direct tx to PQZ, {row['name']} ({len(b):,} B > 131,072): gasUsed {got:,} = max(standard {std:,}, EIP-7623 floor {floor:,}), block {int(rc['blockNumber'], 16)}")
    if a.no_ua:
        log("UAMldsaVerifier skipped (--no-ua: on 7622 it is deployed with the registry in P6g, plan R5)")
        return
    # UAMldsaVerifier(kind, MLDSAxx, valid, flipped) on the copy (R5): the probe must pick the precompile
    vcode, _ = artifact("MlDsa.sol", "UAMldsaVerifier")
    ua = ua_rows()
    d = json.load(open(os.path.join(ROOT, "smartcontracts/vectors/ua/pq_signatures.json")))
    for kind, addr, lvl, pk, sig in ((0x0130, ML44, 44, PK44, SIG44), (0x0131, ML65, 65, PK65, SIG65)):
        valid = next(b for (l, b, ok, n) in ua if l == lvl and ok)
        bad = bytearray(valid)
        bad[pk + 7] ^= 1
        args = w(kind) + w(int(addr, 16)) + w(128) + w(128 + 32 + len(valid) + (-len(valid) % 32)) + abi_bytes(valid) + abi_bytes(bytes(bad))
        rc = receipt(s.send(None, "0x" + vcode + args, 16_000_000))
        v = rc["contractAddress"]
        got = rpc("eth_call", [{"to": v, "data": "0x" + selector("PRECOMPILE()")}, "latest"])
        check(rc["status"] == "0x1" and int(got, 16) == int(addr, 16), f"UAMldsaVerifier({kind:#06x}) at {v}: PRECOMPILE() = {addr} (deploy gas {int(rc['gasUsed'], 16):,})")
        k = next(k for k in d["kinds"] if k["name"] == f"mldsa{lvl}")
        for sg in k["sigs"]:
            for flip in (False, True):
                sb = bytearray(bytes.fromhex(sg["sig"][2:]))
                if flip:
                    sb[11] ^= 1
                kd = bytes.fromhex(k["keyData"][2:])
                cd = "0x" + selector("verify(bytes,bytes32,bytes)") + w(96) + sg["message"][2:] + w(96 + 32 + len(kd) + (-len(kd) % 32)) + abi_bytes(kd) + abi_bytes(bytes(sb))
                res = rpc("eth_call", [{"to": v, "data": cd, "gas": hex(10_000_000)}, "latest"])
                gas = int(rpc("eth_estimateGas", [{"to": v, "data": cd}, "latest"]), 16)
                check(int(res, 16) == (0 if flip else 1), f"UAMldsaVerifier mldsa{lvl}.verify({sg['purpose']}{', sig flipped' if flip else ''}) = {not flip} (estimateGas {gas:,})")


def cmd_burst(a):
    """Step 5: `clients` threads × `calls` eth_call to PQZ (PQZH transfer) through the proxy, no pacing."""
    b = bytes.fromhex(next(r for r in corpus() if r["kind"] == "honest" and r["id"] == "pqzh" and r["form"] == "TRANSFER")["input"])
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"to": PQZ, "data": "0x" + b.hex(), "gas": hex(16_000_000)}, "latest"]}).encode()
    codes = {}
    lk = threading.Lock()
    h0 = rpc("eth_getBlockByNumber", ["latest", False])

    def client():
        for _ in range(a.calls):
            try:
                r = urllib.request.urlopen(urllib.request.Request(RPC, body, {"content-type": "application/json"}), timeout=120)
                ok = json.load(r).get("result") == "0x" + "00" * 31 + "01"
                c = "200 …01" if ok else "200 other"
            except urllib.error.HTTPError as e:
                c = str(e.code)
            with lk:
                codes[c] = codes.get(c, 0) + 1

    t0 = time.time()
    ts = [threading.Thread(target=client) for _ in range(a.clients)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    dt = time.time() - t0
    time.sleep(12)
    h1 = rpc("eth_getBlockByNumber", ["latest", False])
    n0, n1 = int(h0["number"], 16), int(h1["number"], 16)
    stamps = [int(rpc("eth_getBlockByNumber", [hex(n), False])["timestamp"], 16) for n in range(n0, n1 + 1)]
    gaps = [y - x for x, y in zip(stamps, stamps[1:])]
    log(f"burst: {a.clients} clients × {a.calls} eth_call (PQZH transfer, {len(b):,} B) in {dt:.1f} s: {codes}")
    log(f"blocks {n0}..{n1} during and after the burst: intervals {gaps}")
    check(codes.get("429", 0) > 0, "burst: requests beyond the limit get 429")
    check(codes.get("200 other", 0) == 0, "burst: every answered call = …01")
    check(all(4 <= g <= 6 for g in gaps), "burst: signer block interval 5 s ± 1 s")


def cmd_fill(a):
    sch = Schedule(a.engine)
    s = Sender(a.key)
    rows = [r for r in corpus() if r["kind"] in ("honest", "fee0") and r["id"] == "pqzh" and r["op"] == 1]
    hs = []
    for i in range(a.n):
        b = bytes.fromhex(rows[i % len(rows)]["input"])
        std = 21_000 + 4 * tokens(b) + sch.gas(b)
        hs.append((s.send(PQZ, "0x" + b.hex(), max(std, 21_000 + 10 * tokens(b)) + 10_000), len(b)))
    blocks = {}
    for h, n in hs:
        rc = receipt(h)
        check(rc["status"] == "0x1", f"fill tx {h[:12]} {n:,} B ok in block {int(rc['blockNumber'], 16)}")
        blocks.setdefault(int(rc["blockNumber"], 16), []).append(n)
    for bn, ns in sorted(blocks.items()):
        blk = rpc("eth_getBlockByNumber", [hex(bn), False])
        log(f"block {bn}: {len(ns)} PQZ transfers, calldata {sum(ns):,} B, gasUsed {int(blk['gasUsed'], 16):,} / gasLimit {int(blk['gasLimit'], 16):,}, size {int(blk['size'], 16):,} B")


def main():
    global RPC, SCHEDULE
    p = argparse.ArgumentParser()
    p.add_argument("cmd")
    p.add_argument("--rpc", default=RPC)
    p.add_argument("--engine")
    p.add_argument("--genesis-hash")
    p.add_argument("--key")
    p.add_argument("--clients", type=int, default=4)
    p.add_argument("--calls", type=int, default=50)
    p.add_argument("--n", type=int, default=8)
    p.add_argument("--no-ua", action="store_true")
    p.add_argument("--schedule", type=int, default=-1)
    a = p.parse_args()
    RPC, SCHEDULE = a.rpc, a.schedule
    {"head": cmd_head, "before": cmd_before, "probe": cmd_probe, "stock": cmd_stock, "e2e": cmd_e2e,
     "burst": cmd_burst, "fill": cmd_fill}[a.cmd](a)
    log(f"{a.cmd}: {'FAILED ' + str(len(FAILS)) if FAILS else 'all checks passed'}")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
