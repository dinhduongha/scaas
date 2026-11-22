#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Sepolia's code-size limits from public reads (evm-size-64k study, 2026-11-22). No key, no send.

For each endpoint of `ethereum-testnet` in chain-uids.json: the head's gasLimit, then an `eth_call` creation (no `to`) at
runtime sizes 2^16 - 1, 2^16, 2^16 + 1 (init `PUSH3 n PUSH1 0 RETURN`) and at init sizes 2^17 - 1, 2^17, 2^17 + 1 (init
`PUSH1 0 PUSH1 0 RETURN` padded with zero bytes), each with the call gas at the block's gasLimit; then `eth_estimateGas` of
runtime creations of 4,096, 8,192 and 2^16 B (the slope is the code deposit's gas per byte) and the 2^17 init creation. Requests are spaced 2 s apart (public rate limits). Prints one line per
question: endpoint host, question, `ok <answer size>` or the node's error message. An endpoint is named by its host only.

usage: python3 -I sepolia_limits.py
"""
import json
import time
import pathlib
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[2]  # smartcontracts/evm


def rpc(url, method, params):
    time.sleep(2)  # spacing for public endpoints' rate limits
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "evm-size-probe"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            a = json.loads(r.read(8 << 20))
    except urllib.error.HTTPError as e:
        try:
            a = json.loads(e.read(1 << 16))
        except ValueError:
            return "down", f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 transport failure: the endpoint's, not the chain's
        return "down", type(e).__name__
    if "error" in a:
        e = a["error"]
        return "err", str(e.get("message", e) if isinstance(e, dict) else e)[:160]
    return "ok", a.get("result")


def runtime_init(n):
    return "0x62" + n.to_bytes(3, "big").hex() + "6000f3"


def init_of(n):
    return "0x60006000f3" + "00" * (n - 5)


def main():
    row = next(r for r in json.load(open(ROOT / "chain-uids.json"))["chains"] if r["key"] == "ethereum-testnet")
    for u in row["sources"]:
        host = urllib.parse.urlsplit(u).hostname
        st, h = rpc(u, "eth_getBlockByNumber", ["latest", False])
        if st != "ok":
            print(f"{host} | head | {st} {h}")
            continue
        gas = int(h["gasLimit"], 16)
        print(f"{host} | head | block {int(h['number'], 16)} gasLimit {gas:,}")
        for what, make, sizes in (("runtime", runtime_init, (65_535, 65_536, 65_537)),
                                  ("init", init_of, (131_071, 131_072, 131_073))):
            for n in sizes:
                st, r = rpc(u, "eth_call", [{"from": "0x000000000000000000000000000000000000beef", "data": make(n),
                                             "gas": hex(gas)}, "latest"])
                ans = f"ok {(len(r or '0x') - 2) // 2} B returned" if st == "ok" else f"{st} {r}"
                print(f"{host} | eth_call {what} {n:,} | {ans}")
        for what, data in (("runtime 4,096", runtime_init(4_096)), ("runtime 8,192", runtime_init(8_192)),
                           ("runtime 65,536", runtime_init(65_536)), ("init 131,072", init_of(131_072))):
            st, r = rpc(u, "eth_estimateGas", [{"from": "0x000000000000000000000000000000000000beef", "data": data}])
            ans = f"{int(r, 16):,} gas" if st == "ok" else f"{st} {r}"
            print(f"{host} | eth_estimateGas {what} | {ans}")


if __name__ == "__main__":
    main()
