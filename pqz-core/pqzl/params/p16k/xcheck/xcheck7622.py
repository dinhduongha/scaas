#!/usr/bin/env python3
"""Plan 5h Task 7b: the SCaaS testnet (7622, Nethermind 2.2.0, Amsterdam) cross-check of the Foundry 1.8.5 gas.

Deploys `PqzGasHarness` (xcheck/PqzGasHarness.sol, built in a gas16k.sh work tree at the 16k sizes) with its two
libraries from a FRESH key funded once from the dev key, builds the gas test's rollover state with real transactions
(3 key pointers, `ENTRIES` op blobs of q − 1 coefficients, the pending slots), then sends the measured transactions:
`prepareAcc` half 0 / 1, `rollOver` 16 (the first materialisation), `rollOver` ROLL_MAX and one op 1 (auditor, fee,
fresh sender, a 52,624-byte proof; `pqz` = `PqzOk`, the registry = the harness). For each: eth_estimateGas before the
send and the receipt. Foundry's numbers for the same transactions come from `cast run <hash>` (xcheck7622.sh).

  python3 -I xcheck7622.py --eth <dir of eth.py> --out <work dir>/evm/out --rpc http://127.0.0.1:8545 \
      --dev-key 0x…04 --roll 80 > log
Stdlib only; waits for every receipt, so it leaves no pending transaction.
"""
import argparse, hashlib, json, secrets, sys, time, urllib.request

p = argparse.ArgumentParser()
p.add_argument("--eth", required=True)
p.add_argument("--out", required=True)
p.add_argument("--rpc", default="http://127.0.0.1:8545")
p.add_argument("--dev-key", required=True)
p.add_argument("--roll", type=int, default=80)
p.add_argument("--pre", type=int, default=16)
p.add_argument("--proof", type=int, default=52_624)
a = p.parse_args()
sys.path.insert(0, a.eth)
import eth  # noqa: E402

PK, CT, Q = 20_480, 20_608, 1_125_899_864_532_089
CHAIN = 7622
GAS_PRICE = 1_000  # wei; base fee is 7


def rpc(method, *params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode()
    r = json.load(urllib.request.urlopen(urllib.request.Request(a.rpc, body, {"Content-Type": "application/json"}), timeout=60))
    if "error" in r:
        raise RuntimeError(f"{method}: {r['error']}")
    return r["result"]


def log(*x):
    print(*x, flush=True)


def sel(sig):
    return eth.keccak256(sig.encode())[:4]


def w(x):  # one ABI word
    if isinstance(x, (bytes, bytearray)):
        return bytes(x).rjust(32, b"\0")
    if isinstance(x, str):
        return bytes.fromhex(x[2:]).rjust(32, b"\0")
    return int(x).to_bytes(32, "big")


def enc(*args):
    """ABI encoding of static words (int / bytes32 / address str) and dynamic `bytes` (('b', data)) / address[] (('a', list))."""
    head, tail = b"", b""
    off = 32 * len(args)
    for x in args:
        if isinstance(x, tuple):
            if x[0] == "b":
                d = x[1]
                t = w(len(d)) + d + b"\0" * (-len(d) % 32)
            else:
                t = w(len(x[1])) + b"".join(w(y) for y in x[1])
            head += w(off + len(tail))
            tail += t
        else:
            head += w(x)
    return head + tail


def art(name, file=None):
    d = json.load(open(f"{a.out}/{file or name}.sol/{name}.json"))
    return d["bytecode"]["object"][2:], d["bytecode"].get("linkReferences", {})


def link(code, refs, addrs):
    h = code  # placeholders `__$<34 hex>$__` (40 hex chars) replaced at the artifact's offsets
    for f, libs in refs.items():
        for lib, spots in libs.items():
            for s in spots:
                h = h[:2 * s["start"]] + addrs[lib][2:].lower() + h[2 * (s["start"] + s["length"]):]
    return bytes.fromhex(h)


dev = int(a.dev_key, 16)
key = int.from_bytes(secrets.token_bytes(32), "big") % eth.N
me = eth.address(key)
nonce = 0
rows = []


def send(k, to, data, value=0, label="", measure=False, gas=None):
    global nonce
    frm = eth.address(k)
    n = int(rpc("eth_getTransactionCount", frm, "pending"), 16)
    tx = {"from": frm, "data": "0x" + data.hex(), "value": hex(value)}
    if to:
        tx["to"] = to
    est = int(rpc("eth_estimateGas", tx), 16) if gas is None else gas
    lim = int(rpc("eth_getBlockByNumber", "latest", False)["gasLimit"], 16)
    g = min(est + est // 20 + 50_000, lim) if gas is None else gas
    raw = eth.legacy_tx(k, n, GAS_PRICE, g, to, value, data, CHAIN)
    h = rpc("eth_sendRawTransaction", "0x" + raw.hex())
    while True:
        r = rpc("eth_getTransactionReceipt", h)
        if r:
            break
        time.sleep(1)
    used = int(r["gasUsed"], 16)
    ok = r["status"] == "0x1"
    row = {"label": label, "hash": h, "block": int(r["blockNumber"], 16), "calldata": len(data), "estimate": est,
           "gasLimit": g, "gasUsed": used, "status": r["status"], "contract": r.get("contractAddress"),
           "receiptKeys": sorted(r.keys())}
    if measure:
        rows.append(row)
        log("MEASURED", json.dumps(row))
    else:
        log(f"  {label}: block {row['block']} gasUsed {used} estimate {est} status {r['status']}")
    if not ok:
        raise SystemExit(f"{label} failed: {r}")
    return r


def call(to, data):
    return bytes.fromhex(rpc("eth_call", {"to": to, "data": "0x" + data.hex()}, "latest")[2:])


log(f"== xcheck7622: chain {int(rpc('eth_chainId'), 16)}, head {int(rpc('eth_blockNumber'), 16)}, client {rpc('web3_clientVersion')}")
log(f"fresh key -> {me} (funded once from the dev key)")
send(dev, me, b"", value=10**18, label="fund the fresh key (a new account: EIP-8037 state gas)", measure=True)

# libraries, PqzOk, the harness
addrs = {}
for lib in ["PqzStateLib", "PqzTransferLib"]:
    c, _ = art(lib)
    r = send(key, None, bytes.fromhex(c), label=f"deploy {lib}", measure=True)
    addrs[lib] = r["contractAddress"]
c, _ = art("PqzOk", "PqzGasHarness")
ok_addr = send(key, None, bytes.fromhex(c), label="deploy PqzOk")["contractAddress"]
AUD, ALICE, BOB, CAROL = (b"\x0a" * 32, b"\xa1" * 32, b"\xb0" * 32, b"\xca" * 32)
c, refs = art("PqzGasHarness")
H = send(key, None, link(c, refs, addrs) + enc(ok_addr, AUD), label="deploy PqzGasHarness")["contractAddress"]
log(f"harness {H}, libs {addrs}, PqzOk {ok_addr}")

# the key pointers (SSTORE2 layout: STOP ‖ key), coefficient 0 = seed as the fixture's _pk
for i, ua in enumerate([AUD, BOB, CAROL]):
    k = bytearray(PK)
    k[7] = 3 + i
    r = send(key, H, sel("make(bytes)") + enc(("b", b"\0" + bytes(k))), label=f"key pointer {i}", measure=(i == 0))
    hn = i + 1  # the harness' CREATE nonces: 1, 2, 3 (EIP-161 contract nonce starts at 1)
    ptr = "0x" + eth.keccak256(eth.rlp([bytes.fromhex(H[2:]), hn]))[12:].hex()
    code = rpc("eth_getCode", ptr, "latest")
    assert len(code) == 2 + 2 * (PK + 1), (ptr, len(code))
    send(key, H, sel("setKey(bytes32,address)") + enc(ua, ptr), label=f"setKey {i}")

# the op blobs: STOP ‖ salt(16) ‖ u ‖ v_t ‖ toUA ‖ v_f, every coefficient q − 1 (the gas test's _blobCode)
q1 = (Q - 1).to_bytes(8, "big")
blob = bytearray(1 + 16 + PK + 128 + 32 + 128)
blob[17:17 + CT] = q1 * (CT // 8)
blobs = []
n_blobs = a.pre + a.roll
for i in range(n_blobs):
    send(key, H, sel("make(bytes)") + enc(("b", bytes(blob))), label=f"op blob {i}", measure=(i == 0))
    hn = 4 + i
    blobs.append("0x" + eth.keccak256(eth.rlp([bytes.fromhex(H[2:]), hn]))[12:].hex())
assert len(rpc("eth_getCode", blobs[-1], "latest")) == 2 + 2 * len(blob)
send(key, H, sel("seed(bytes32,uint64,address[],uint256)") + enc(ALICE, 0, ("a", blobs), PK), label=f"seed {n_blobs} entries")
# the measured transactions
send(key, H, sel("setKey(bytes32,address)") + enc(ALICE, blobs[0]), label="setKey alice (any non-zero pointer: registered for prepareAcc)")
send(key, H, sel("prepareAcc(bytes32,uint256)") + enc(ALICE, 0), label="prepareAcc half 0", measure=True)
send(key, H, sel("prepareAcc(bytes32,uint256)") + enc(ALICE, 1), label="prepareAcc half 1", measure=True)
send(key, H, sel("rollOver(bytes32,uint256)") + enc(ALICE, a.pre), label=f"rollOver {a.pre} (first materialisation)", measure=True)
send(key, H, sel("rollOver(bytes32,uint256)") + enc(ALICE, a.roll), label=f"rollOver {a.roll} (ROLL_MAX, distinct cold blobs)", measure=True)

# op 1: carol (fresh, p = 0) -> bob, beneficiary carol, auditor on; out canonical (40-bit lanes), u != 0
def stream(tag, n):
    o, i = b"", 0
    while len(o) < n:
        o += hashlib.sha256(tag + i.to_bytes(4, "big")).digest()
        i += 1
    return o[:n]
mask = bytes.fromhex("000000ffffffffff" * 4)
out = bytes(x & y for x, y in zip(stream(b"out", 20_864), mask * (20_864 // 32)))
head = int(rpc("eth_blockNumber"), 16)
payload = enc(0, head + 1000, 0, CAROL, BOB, CAROL) + (0x5A17).to_bytes(16, "big") + out
auth = enc(("b", b""), ("b", bytes(3309)))
proof = stream(b"proof", a.proof)
send(key, H, sel("transferSingle(bytes,bytes,bytes,bytes)") + enc(("b", payload), ("b", proof), ("b", auth), ("b", b"")),
     label="op 1 BUNDLE, auditor, fee, fresh sender, proof 52,624 B", measure=True)

pend = int(rpc("eth_getTransactionCount", me, "pending"), 16)
lat = int(rpc("eth_getTransactionCount", me, "latest"), 16)
log(f"fresh key nonce latest {lat} pending {pend} (no pending transaction: {pend == lat})")
log("ROWS " + json.dumps(rows))
