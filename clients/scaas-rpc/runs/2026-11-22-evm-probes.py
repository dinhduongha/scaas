#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The EVM probe runner: NET-EVM-19's probes H1-H8 on any EVM profile (chains-arweave plan CA-T12's runner, built in SDK plan
T40) and T40's profile probes. Public reads only: no key, no send, a few JSON-RPC requests per probe and endpoint, one
foreground sample per invocation; the 24-h and 7-day windows are the operator's scheduler calling it, never a loop here.

  python3 -I clients/scaas-rpc/runs/2026-11-22-evm-probes.py --probe <P>[,<P>…]|all --profile <key>[,<key>…] [--rpc <url>,…]
  python3 -I clients/scaas-rpc/runs/2026-11-22-evm-probes.py --summary

The endpoints are the profile's row `sources` in smartcontracts/evm/chain-uids.json (two independent providers) unless --rpc
names others. Each sample is one JSON line appended to `2026-11-22-evm-probes-<key>-<P>.log` beside this file (git-ignored by
`*.log`; an endpoint is named by its host, never its URL, which may hold a key); --summary rewrites the committed
`2026-11-22-evm-probes-summary.txt` from those logs. A progress line per probe on stdout. Exit 1 when a probe FAILs.

Probes (verdict PASS, FAIL, or INFO for a measurement the operator gate reads):
  H1 block 0's hash and the chain id on every endpoint equal the row's (at least two endpoints; ETC and Ethereum share block 0)
  H2 eth_call, eth_getCode, eth_getStorageAt, eth_getBalance, eth_getTransactionCount answer at {blockHash, requireCanonical}
     of the head and refuse a made-up hash (EIP-1898)
  H3 `latest` sampled; earlier samples now final compared with the canonical chain, replaced heads counted
  H4 a block asked by its hash is that block; a made-up hash is null or an error, never another block
  H5 the `latest` - `finalized` gap in blocks and seconds (the summary: p99 over the samples); FAIL when one endpoint's gap
     is above 32 blocks and ten times another's (one provider's `finalized` is its head)
  H6 the largest eth_getLogs span answered (100, 1,000, 10,000, 100,000 blocks ending at `finalized`)
  H7 `finalized` served and never below an earlier sample
  H8 a read pinned by the newest head's hash (its fee recipient's balance), compared with the same read once the block is final
  fork     the fork level by opcodes (PUSH0, TLOAD, CLZ) in eth_call creations and the head's fields (requestsHash,
           blockAccessListHash)
  eip2537  BLS12-381 G1ADD (0x0b) answers its known answer, or the address is empty
  caps     the block gas limit, the per-transaction cap (eth_call at 2^24 and 2^24 + 1; an eth_call may not apply EIP-7825),
           a limit the chain publishes (ArbGasInfo at 0x6c) and the PQ fit of each PQ kind's largest transaction (accounts.md
           MD-5: regular x 1.05 < min(2^24, cap, published), (regular + state) x 1.05 <= min(block limit, published))
  codesize the runtime and init code limits (eth_call creations returning n bytes; init code of n bytes)
  basefee  the head's baseFeePerGas: a self-relay of type 2, else type 0
  l1fee    the L1 fee model: `op-stack` (GasPriceOracle code, getL1Fee answers a uint256), `linea` (linea_estimateGas),
           `in-estimate` (ArbGasInfo answers, or eth_estimateGas of a plain transfer above 21,000: Arbitrum), else `none`
UNAUDITED tooling."""
import json
import math
import re
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CHAIN_UIDS = ROOT / "smartcontracts" / "evm" / "chain-uids.json"
PREFIX = "2026-11-22-evm-probes-"
SUMMARY = HERE / f"{PREFIX}summary.txt"
QUIET = False
MAX_ANSWER = 4 << 20  # bytes of one answer read at most
NO_METHOD = re.compile(r"does not exist|not available|not found|not supported|unsupported|unknown method", re.I)
RATE = re.compile(r"rate.?limit|too many requests|quota|upgrade to paid|exceeded the limit", re.I)

ARB_GAS_INFO = "0x000000000000000000000000000000000000006c"
GAS_PRICE_ORACLE = "0x420000000000000000000000000000000000000f"
GET_L1_FEE = "0x49948e0e"  # getL1Fee(bytes)
GET_GAS_ACCOUNTING = "0x612af178"  # ArbGasInfo.getGasAccountingParams()
BLS_G1ADD = "0x000000000000000000000000000000000000000b"
ONE = "0x0000000000000000000000000000000000000001"
ZERO = "0x0000000000000000000000000000000000000000"
DEAD = "0x000000000000000000000000000000000000dead"
BEEF = "0x000000000000000000000000000000000000beef"
MADE_UP = "0x" + "11" * 32
EIP7825 = 1 << 24
# EIP-2537's G1 generator (x, y as 64-byte field elements); G1ADD(gen, infinity) = gen
G1_GEN = (
    "0x" + "00" * 16 + "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    + "00" * 16 + "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
)
# <op> PUSH1 0 MSTORE PUSH1 32 PUSH1 0 RETURN: a creation returning the word the opcode pushed
_RET = bytes.fromhex("60005260206000f3")
OPCODE_TESTS = {
    "shanghai": (bytes.fromhex("5f") + _RET, 0x5F),  # PUSH0
    "cancun": (bytes.fromhex("60005c") + _RET, 0x5C),  # TLOAD(0)
    "osaka": (bytes.fromhex("60011e") + _RET, 0x1E),  # CLZ(1) = 255
}
# Each PQ kind's largest transaction (regular gas, regular + EIP-8037 state gas), measured at Amsterdam (forge 1.8.5): the ML-DSA
# cache's largest part (smartcontracts/evm/script/DeployGas.sol, the deploy-time rule MD-5); `register` of fndsa512 and
# slhdsa128s (docs/contracts/accounts.md, the UA-8 table); fndsa1024's register is not measured, its verify cap stands in
PQ = {
    "mldsa44": (9_740_000, 9_740_000 + 31_715_370, "cache part 0, DeployGas.sol"),
    "mldsa65": (10_230_000, 10_230_000 + 33_282_090, "cache part 1, DeployGas.sol"),
    "fndsa512": (2_734_649, 2_734_649 + 6_384_690, "register, accounts.md UA-8"),
    "slhdsa128s": (1_116_222, 1_116_222 + 13_246_740, "register, accounts.md UA-8"),
    "fndsa1024": (5_250_000, 5_250_000, "verify cap only; register not measured"),
    "mldsa87": (10_730_000, 10_730_000 + 34_848_810, "cache part 2, DeployGas.sol"),
}


def say(s):
    if not QUIET:
        print(s, flush=True)


def label(url):
    u = urllib.parse.urlsplit(url)
    return f"{u.hostname}:{u.port}" if u.port else str(u.hostname)


def rpc(url, method, params):
    """('ok', result) | ('err', message) for a JSON-RPC error answer | ('down', text) for no answer."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "evm-probes"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read(MAX_ANSWER + 1)
    except urllib.error.HTTPError as e:
        # a 4xx carrying a JSON-RPC error is the endpoint's answer (a method or range it refuses); 429 and the rest are not
        raw = e.read(MAX_ANSWER + 1) if e.code != 429 else b""
        if b'"error"' not in raw:
            return "down", f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 any transport failure is the endpoint's
        return "down", type(e).__name__
    if len(raw) > MAX_ANSWER:
        return "down", "answer too large"
    try:
        a = json.loads(raw)
    except ValueError:
        return "down", "not JSON"
    if not isinstance(a, dict):
        return "down", "not a JSON-RPC answer"
    if "error" in a:
        e = a["error"]
        m = str(e.get("message", e) if isinstance(e, dict) else e)[:160]
        # a provider's quota is the endpoint not answering, never the chain's answer
        return ("down", f"rate limited: {m[:60]}") if RATE.search(m) else ("err", m)
    return "ok", a.get("result")


def need(url, method, params):
    st, r = rpc(url, method, params)
    if st != "ok":
        raise Unread(f"{method}: {st}: {r}")
    return r


def ask(url, method, params):
    """rpc() where an endpoint that does not answer stops the probe (UNREAD); an error answer is the endpoint's answer."""
    st, r = rpc(url, method, params)
    if st == "down":
        raise Unread(f"{method}: {r}")
    return st, r


class Fail(Exception):
    pass


class Unread(Exception):
    """An endpoint did not answer (transport, quota): no verdict on the chain; run the probe again."""


def num(x):
    return int(x, 16)


def header(url, tag):
    b = need(url, "eth_getBlockByNumber", [tag, False])
    if not isinstance(b, dict) or not isinstance(b.get("hash"), str):
        raise Fail(f"block {tag}: no header")
    return b


def finalized_or(url, latest):
    st, b = ask(url, "eth_getBlockByNumber", ["finalized", False])
    return num(b["number"]) if st == "ok" and isinstance(b, dict) else max(num(latest["number"]) - 64, 0)


def earlier(ctx):
    return ctx["earlier"]


def pinned(h):
    return {"blockHash": h, "requireCanonical": True}


# ---- H1-H8


def h1(ctx):
    if len(ctx["eps"]) < 2:
        return "FAIL", {"why": "H1 needs two independent providers", "endpoints": []}
    out, ok = [], True
    for u in ctx["eps"]:
        st, cid = ask(u, "eth_chainId", [])
        st0, b0 = ask(u, "eth_getBlockByNumber", ["0x0", False])
        e = {"chain_id": num(cid) if st == "ok" else None,
             "block0": b0["hash"].lower() if st0 == "ok" and isinstance(b0, dict) else None}
        ok &= e["chain_id"] == ctx["row"]["chainId"] and e["block0"] == ctx["row"]["chainUid"].lower()
        out.append(e)
    return ("PASS" if ok else "FAIL"), {"endpoints": out}


READS = [
    ("eth_call", lambda b: [{"to": ONE, "data": "0x"}, b]),
    ("eth_getCode", lambda b: [ONE, b]),
    ("eth_getStorageAt", lambda b: [ONE, "0x0", b]),
    ("eth_getBalance", lambda b: [ONE, b]),
    ("eth_getTransactionCount", lambda b: [ONE, b]),
]


def h2(ctx):
    out, ok = [], True
    for u in ctx["eps"]:
        h = header(u, "latest")["hash"]
        good = sum(ask(u, m, p(pinned(h)))[0] == "ok" for m, p in READS)
        refused = sum(ask(u, m, p(pinned(MADE_UP)))[0] == "err" for m, p in READS)
        ok &= good == len(READS) and refused == len(READS)
        out.append({"canonical": good, "made_up_refused": refused})
    return ("PASS" if ok else "FAIL"), {"endpoints": out}


def h3(ctx):
    done = {tuple(c) for f in earlier(ctx) for c in f.get("compared", [])}
    todo = [s for f in earlier(ctx) for s in f.get("samples", []) if tuple(s) not in done]
    samples, compared, replaced = [], [], 0
    fin = {}
    for i, u in enumerate(ctx["eps"]):
        b = header(u, "latest")
        samples.append([i, num(b["number"]), b["hash"]])
        fin[i] = finalized_or(u, b)
    for s in todo[:8]:
        i, n, h = s
        if i >= len(ctx["eps"]) or n > fin[i]:
            continue
        c = header(ctx["eps"][i], hex(n))["hash"]
        replaced += c.lower() != h.lower()
        compared.append(s)
    return "INFO", {"samples": samples, "compared": compared, "checked": len(compared), "replaced": replaced}


def h4(ctx):
    out, ok = [], True
    for u in ctx["eps"]:
        h = header(u, "latest")["hash"]
        b = need(u, "eth_getBlockByHash", [h, False])
        canon = "ok" if isinstance(b, dict) and b.get("hash", "").lower() == h.lower() else "wrong"
        st, m = ask(u, "eth_getBlockByHash", [MADE_UP, False])
        made = "refused" if st == "err" else "null" if st == "ok" and m is None else "another block" if st == "ok" else st
        ok &= canon == "ok" and made in ("null", "refused")
        out.append({"canonical": canon, "made_up": made})
    return ("PASS" if ok else "FAIL"), {"endpoints": out}


def h5(ctx):
    out = []
    for u in ctx["eps"]:
        a = header(u, "latest")
        st, f = ask(u, "eth_getBlockByNumber", ["finalized", False])
        if st != "ok" or not isinstance(f, dict):
            return "FAIL", {"why": "no finalized block", "endpoints": out}
        out.append({"blocks": num(a["number"]) - num(f["number"]), "secs": num(a["timestamp"]) - num(f["timestamp"])})
    gaps = [e["blocks"] for e in out]
    # one provider's `finalized` at its head and another's far behind: the tag means two things on one chain
    if max(gaps) > 32 and min(gaps) * 10 < max(gaps):
        return "FAIL", {"why": f"the endpoints' finalized differ: gaps {gaps} blocks", "endpoints": out}
    return "INFO", {"endpoints": out}


def h6(ctx):
    out = []
    for u in ctx["eps"]:
        top = finalized_or(u, header(u, "latest"))
        best, why = 0, None
        for span in (100, 1_000, 10_000, 100_000):
            q = {"fromBlock": hex(max(top - span + 1, 0)), "toBlock": hex(top), "address": DEAD}
            st, r = ask(u, "eth_getLogs", [q])
            if st != "ok":
                why = str(r)[:100]
                break
            best = span
        out.append({"largest_span": best, "refused": why})
    return "INFO", {"endpoints": out}


def h7(ctx):
    out, ok = [], True
    for i, u in enumerate(ctx["eps"]):
        st, f = ask(u, "eth_getBlockByNumber", ["finalized", False])
        if st != "ok" or not isinstance(f, dict):
            ok = False
            out.append({"finalized": None, "why": "finalized not served"})
            continue
        n = num(f["number"])
        prev = [e["endpoints"][i]["finalized"] for e in earlier(ctx)
                if i < len(e.get("endpoints", [])) and e["endpoints"][i].get("finalized") is not None]
        e = {"finalized": n}
        if prev and n < max(prev):
            ok, e["why"] = False, f"moved back from {max(prev)} to {n}"
        out.append(e)
    return ("PASS" if ok else "FAIL"), {"endpoints": out}


def h8(ctx):
    done = {tuple(c) for f in earlier(ctx) for c in f.get("compared_keys", [])}
    todo = [s for f in earlier(ctx) for s in f.get("pending", []) if tuple(s[:3]) not in done]
    pending, compared, mismatch, replaced = [], [], 0, 0
    fin = {}
    for i, u in enumerate(ctx["eps"]):
        b = header(u, "latest")
        st, v = ask(u, "eth_getBalance", [b["miner"], pinned(b["hash"])])
        pending.append([i, num(b["number"]), b["hash"], b["miner"], v if st == "ok" else "refused"])
        fin[i] = finalized_or(u, b)
    for s in todo[:8]:
        i, n, h, who, then = s
        if i >= len(ctx["eps"]) or n > fin[i] or then == "refused":
            continue
        st, now = ask(ctx["eps"][i], "eth_getBalance", [who, pinned(h)])
        if st != "ok":
            replaced += 1
        elif num(now) != num(then):
            mismatch += 1
        compared.append(s[:3])
    v = "FAIL" if mismatch else "PASS" if compared else "INFO"
    return v, {"pending": pending, "compared_keys": compared, "compared": len(compared), "mismatch": mismatch,
               "replaced": replaced}


# ---- the profile probes


def creation(u, code, gas=None):
    tx = {"from": ZERO, "data": "0x" + code.hex()}
    if gas:
        tx["gas"] = hex(gas)
    return ask(u, "eth_call", [tx, "latest"])


def fork(ctx):
    levels = []
    for u in ctx["eps"]:
        has = {}
        for name, (init, _) in OPCODE_TESTS.items():
            st, r = creation(u, init)
            want = "0x" + "00" * 31 + "ff" if name == "osaka" else "0x" + "00" * 32
            has[name] = st == "ok" and isinstance(r, str) and r.lower() == want
        h = header(u, "latest")
        lvl = "before shanghai"
        if has["shanghai"]:
            lvl = "shanghai"
            if has["cancun"]:
                lvl = "prague" if "requestsHash" in h else "cancun"
                if has["osaka"]:
                    lvl = "amsterdam" if "blockAccessListHash" in h else "osaka"
        levels.append(lvl)
    if len(set(levels)) != 1:
        return "FAIL", {"why": "the endpoints differ", "levels": levels}
    return "INFO", {"fork": levels[0]}


def eip2537(ctx):
    seen = []
    for u in ctx["eps"]:
        st, r = ask(u, "eth_call", [{"to": BLS_G1ADD, "data": G1_GEN + "00" * 128}, "latest"])
        seen.append(True if st == "ok" and r == G1_GEN else False if st == "ok" and r == "0x" else f"{st}: {r}"[:80])
    if len(set(map(str, seen))) != 1 or not isinstance(seen[0], bool):
        return "FAIL", {"why": "no agreed answer", "answers": seen}
    return "INFO", {"present": seen[0]}


def accepts(u, gas):
    return ask(u, "eth_call", [{"from": ZERO, "to": ZERO, "gas": hex(gas)}, "latest"])[0] == "ok"


def tx_cap(u, block):
    """The largest gas an eth_call carries: 2^24 when 2^24 + 1 is refused; else none up to the block limit (or 2^30), else
    the exact cap by bisection."""
    if accepts(u, EIP7825):
        if not accepts(u, EIP7825 + 1):
            return EIP7825
        top = min(block, 1 << 30)
        if accepts(u, top):
            return None
        lo, hi = EIP7825 + 1, top
    else:
        lo, hi = 21_000, EIP7825
    while hi - lo > 1:
        mid = (lo + hi) // 2
        lo, hi = (mid, hi) if accepts(u, mid) else (lo, mid)
    return lo


def published(u):
    """A transaction limit the chain publishes: ArbGasInfo.getGasAccountingParams() at 0x6c answers (speed limit, pool max,
    max tx gas limit) on Arbitrum; an empty answer elsewhere (no code there)."""
    st, r = ask(u, "eth_call", [{"to": ARB_GAS_INFO, "data": GET_GAS_ACCOUNTING}, "latest"])
    return num("0x" + r[2 + 128:2 + 192]) if st == "ok" and isinstance(r, str) and len(r) == 2 + 192 else None


def caps(ctx):
    blocks, caps_, pubs = [], [], []
    for u in ctx["eps"]:
        b = num(header(u, "latest")["gasLimit"])
        blocks.append(b)
        caps_.append(tx_cap(u, b))
        pubs.append(published(u))
    if len(set(caps_)) != 1 or len(set(pubs)) != 1:
        return "FAIL", {"why": "the endpoints' caps differ", "caps": caps_, "published": pubs}
    block, cap, pub = min(blocks), caps_[0], pubs[0]
    limit = min(x for x in (EIP7825, cap, pub) if x)
    # a published limit bounds the whole transaction (regular + state), whatever the header's gas limit says
    whole = min(block, pub) if pub else block
    pq = {}
    for k, (reg, tot, src) in PQ.items():
        pq[k] = {"regular": reg, "total": tot, "fits": reg * 105 < limit * 100 and tot * 105 <= whole * 100, "source": src}
    return "INFO", {"block_gas_limit": block, "tx_gas_cap": cap, "published_tx_limit": pub, "pq": pq}


def size_ok(u, code, gas):
    """True (created), False (refused for its size), None (refused for gas: at the node's eth_call gas, then at `gas`)."""
    st, r = creation(u, code)
    if st == "err" and "gas" in r.lower() and "size" not in r.lower():
        st, r = creation(u, code, gas)
        if st == "err" and "gas" in r.lower() and "size" not in r.lower():
            return None
    return st == "ok"


def size_limit(u, sizes, make, gas):
    """The size limit: each of `sizes` and size + 1 asked, then the exact limit by bisection between the last size created and
    the first refused for its size. A size refused for gas (a code deposit the call cannot pay) is untested, never a limit:
    `>=n (gas-bound)`. None when the smallest is refused."""
    last = None
    for n in sizes:
        for m in (n, n + 1):
            ok = size_ok(u, make(m), gas)
            if ok is None:
                return f">={last} (gas-bound)" if last else None
            if not ok:
                if last is None:
                    return None
                lo, hi = last, m
                while hi - lo > 1:
                    mid = (lo + hi) // 2
                    ok = size_ok(u, make(mid), gas)
                    if ok is None:
                        return f">={lo} (gas-bound)"
                    lo, hi = (mid, hi) if ok else (lo, mid)
                return lo
            last = m
    return f">{sizes[-1]}"


def codesize(ctx):
    seen = []
    for u in ctx["eps"]:
        gas = min(num(header(u, "latest")["gasLimit"]), 1 << 30)
        code = size_limit(u, (24_576, 32_768, 49_152, 65_536, 131_072),
                          lambda n: b"\x62" + n.to_bytes(3, "big") + bytes.fromhex("6000f3"), gas)
        init = size_limit(u, (49_152, 98_304, 262_144), lambda n: bytes.fromhex("60006000f3") + bytes(n - 5), gas)
        seen.append((code, init))
    out = {}
    for name, i in (("code_limit", 0), ("initcode_limit", 1)):
        exact = {x[i] for x in seen if isinstance(x[i], int)}
        if len(exact) > 1:
            return "FAIL", {"why": "the endpoints differ", "limits": seen}
        # an endpoint bound by its gas or the candidates defers to one that measured exactly
        out[name] = exact.pop() if exact else seen[0][i]
    return "INFO", dict(out, endpoints=seen)


def basefee(ctx):
    types = []
    for u in ctx["eps"]:
        h = header(u, "latest")
        types.append(2 if h.get("baseFeePerGas") is not None else 0)
    if len(set(types)) != 1:
        return "FAIL", {"why": "the endpoints differ", "types": types}
    return "INFO", {"tx_type": types[0]}


def l1fee(ctx):
    out, models = [], []
    sample = bytes([2]) + bytes(range(199))  # 200 bytes standing for an unsigned transaction
    data = GET_L1_FEE + f"{32:064x}" + f"{len(sample):064x}" + sample.hex() + "00" * (-len(sample) % 32)
    # a plain transfer between two addresses without code (0x01 and 0x02 are precompiles: their gas is above 21,000)
    plain = {"from": BEEF, "to": DEAD, "value": "0x0"}
    for u in ctx["eps"]:
        e = {}
        code = need(u, "eth_getCode", [GAS_PRICE_ORACLE, "latest"])
        if code not in ("0x", "0x0", None):
            st, r = ask(u, "eth_call", [{"to": GAS_PRICE_ORACLE, "data": data}, "latest"])
            if st != "ok" or not isinstance(r, str) or len(r) != 66:
                return "FAIL", {"why": f"getL1Fee answered no uint256: {st}: {str(r)[:80]}", "endpoints": out}
            e["get_l1_fee"] = num(r)
        st, est = ask(u, "eth_estimateGas", [plain])
        e["estimate"] = num(est) if st == "ok" else None
        st, lin = ask(u, "linea_estimateGas", [plain])
        if st == "ok" and isinstance(lin, dict):
            e["linea"] = {k: num(v) for k, v in lin.items() if isinstance(v, str) and v.startswith("0x")}
        elif st == "err" and not NO_METHOD.search(lin):
            e["linea"] = {"served": lin[:80]}  # the method exists (it refused this sender, never the method)
        # Arbitrum: its ArbGasInfo answers; the L1 component is inside eth_estimateGas, whatever the L1 price is today
        e["arb_gas_info"] = published(u) is not None
        models.append("op-stack" if "get_l1_fee" in e else "linea" if "linea" in e
                      else "in-estimate" if e["arb_gas_info"] or (e["estimate"] or 0) > 21_000 else "none")
        out.append(e)
    # linea_estimateGas is the chain's method, which a provider may not serve
    if set(models) == {"linea", "none"}:
        models = ["linea"]
    if len(set(models)) != 1:
        return "FAIL", {"why": "the endpoints differ", "models": models, "endpoints": out}
    return "INFO", {"model": models[0], "endpoints": out}


PROBES = {"H1": h1, "H2": h2, "H3": h3, "H4": h4, "H5": h5, "H6": h6, "H7": h7, "H8": h8, "fork": fork, "eip2537": eip2537,
          "caps": caps, "codesize": codesize, "basefee": basefee, "l1fee": l1fee}


def log_path(logdir, key, probe):
    return Path(logdir) / f"{PREFIX}{key}-{probe}.log"


def run(probe, row, endpoints, logdir):
    """One sample of `probe` on the profile `row` (a chain-uids.json row) through `endpoints`, appended to its log."""
    p = log_path(logdir, row["key"], probe)
    prev = [json.loads(x)["facts"] for x in open(p)] if p.exists() else []
    say(f"[probes] {row['key']} {probe} start ({len(endpoints)} endpoints)")
    try:
        v, f = PROBES[probe]({"row": row, "eps": endpoints, "earlier": prev})
    except Fail as e:
        v, f = "FAIL", {"why": str(e)}
    except Unread as e:
        v, f = "UNREAD", {"why": str(e)}
    f["hosts"] = [label(u) for u in endpoints]
    with open(p, "a") as fh:
        fh.write(json.dumps({"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "verdict": v, "facts": f}) + "\n")
    say(f"[probes] {row['key']} {probe} {v}: {short(probe, [f])}")
    return v, f


def p99(xs):
    xs = sorted(xs)
    return xs[max(math.ceil(0.99 * len(xs)) - 1, 0)] if xs else None


def short(probe, fs):
    """The summary's facts of one log (its samples' facts, oldest first); no path, no URL."""
    f = fs[-1]
    if "why" in f and probe not in ("H7",):
        return f["why"].replace("/", " ")
    if probe == "H1":
        uids = {e["block0"] for x in fs for e in x.get("endpoints", [])}
        e = f["endpoints"]
        return f"chain id {e[0]['chain_id']}, block 0 {str(e[0]['block0'])[:10]}…, {len(uids)} distinct block 0 over {len(fs)} samples"
    if probe == "H2":
        return "; ".join(f"{e['canonical']} of 5 answered, {e['made_up_refused']} of 5 refused" for e in f["endpoints"])
    if probe == "H3":
        return f"{sum(x.get('checked', 0) for x in fs)} checked, {sum(x.get('replaced', 0) for x in fs)} replaced"
    if probe == "H4":
        return "; ".join(f"canonical {e['canonical']}, made-up {e['made_up']}" for e in f["endpoints"])
    if probe == "H5":
        b = [e["blocks"] for x in fs for e in x.get("endpoints", [])]
        s = [e["secs"] for x in fs for e in x.get("endpoints", [])]
        return f"p99 {p99(b)} blocks, {p99(s)} s over {len(b)} endpoint samples (last {b[-len(f['endpoints']):]} blocks)"
    if probe == "H6":
        return "largest span " + ", ".join(str(e["largest_span"]) for e in f["endpoints"])
    if probe == "H7":
        return "; ".join(e.get("why", f"finalized {e['finalized']}") for e in f["endpoints"])
    if probe == "H8":
        c = sum(x.get("compared", 0) for x in fs)
        m = sum(x.get("mismatch", 0) for x in fs)
        r = sum(x.get("replaced", 0) for x in fs)
        return f"{c} compared once final, {m} mismatched, {r} replaced; {len(f['pending'])} pending"
    if probe == "fork":
        return f"fork {f['fork']}"
    if probe == "eip2537":
        return "EIP-2537 present" if f["present"] else "EIP-2537 absent"
    if probe == "caps":
        fit = ", ".join(f"{k} {'fits' if r['fits'] else 'NO'}" for k, r in f["pq"].items())
        pub = f", published tx limit {f['published_tx_limit']:,}" if f.get("published_tx_limit") else ""
        return f"block {f['block_gas_limit']:,}, tx cap {f['tx_gas_cap'] or 'none'}{pub}; {fit}"
    if probe == "codesize":
        return f"runtime {f['code_limit']} B, init {f['initcode_limit']} B"
    if probe == "basefee":
        return f"type {f['tx_type']}"
    if probe == "l1fee":
        return f"model {f['model']}"
    return json.dumps(f)[:120]


def summary(logdir, out):
    rows = []
    for p in sorted(Path(logdir).glob(f"{PREFIX}*.log")):
        key, probe = p.name[len(PREFIX):-4].rsplit("-", 1)
        lines = [json.loads(x) for x in open(p)]
        if not lines:
            continue
        v = lines[-1]["verdict"]
        tally = {x["verdict"] for x in lines[:-1]} - {v}
        if tally:  # an earlier sample's other verdict stays visible
            v += " (earlier: " + ", ".join(f"{t} {sum(x['verdict'] == t for x in lines)}" for t in sorted(tally)) + ")"
        rows.append(f"{key} | {probe} | {len(lines)} | {v} | {short(probe, [x['facts'] for x in lines])} | "
                    f"{lines[0]['t']} .. {lines[-1]['t']}")
    head = ("# EVM probes (NET-EVM-19 H1-H8; SDK plan T40), rewritten by `2026-11-22-evm-probes.py --summary` from the git-ignored "
            "logs; key | probe | samples | last verdict | facts | first .. last sample (UTC)")
    Path(out).write_text(head + "\n" + "\n".join(rows) + "\n")


def main(argv):
    args = dict(zip(argv[::2], argv[1::2])) if "--summary" not in argv else {}
    logdir = HERE
    if "--summary" in argv:
        summary(logdir, SUMMARY)
        print(f"[probes] summary written: {SUMMARY.name}")
        return 0
    if "--probe" not in args or "--profile" not in args:
        print(__doc__)
        return 2
    probes = list(PROBES) if args["--probe"] == "all" else args["--probe"].split(",")
    rows = {r["key"]: r for r in json.load(open(CHAIN_UIDS))["chains"]}
    worst = 0
    for key in args["--profile"].split(","):
        if key not in rows or any(p not in PROBES for p in probes):
            print(f"[probes] unknown profile or probe: {key} {probes}")
            return 2
        eps = args["--rpc"].split(",") if "--rpc" in args else rows[key]["sources"]
        for p in probes:
            v, _ = run(p, rows[key], eps, logdir)
            worst |= v == "FAIL"
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
