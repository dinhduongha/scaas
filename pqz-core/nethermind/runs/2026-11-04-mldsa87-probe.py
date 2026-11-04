#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""SCaaS testnet reset 1 (2026-11-04, CTR-UA-39): MLDSA87 at 0x...5caa0014 against the mldsa87 EIP-8355 probe inputs of
smartcontracts/vectors/ua/pq_kat.json (the inputs DeployBase and UAMldsaVerifier probe with): eth_call of the valid input
must return exactly the word 1, of the flipped one exactly the word 0, and the precompile's own gas, measured as e2e.py
probe measures the other rows (test/p6f/PqzPrecompileProbe by state override, minus its overhead on the identity precompile
and the warm call's 100), must equal the plugin's formula mldsa87Gas + 6 * ceil((len - 2592 - 4627) / 32) = 102,006 (the
schedule's mldsa87Gas is PROVISIONAL, 102,000, not calibrated). eth_estimateGas of a plain call is printed too: on Amsterdam
the EIP-7976 calldata floor of these 7,251 B dominates it, so it does not show the precompile's price. Before the schedule that carries mldsa87Gas the address
is a plain account (empty output), so --inactive expects that instead.
  python3 -I 2026-11-04-mldsa87-probe.py <rpc> [--inactive]      exit 0 iff every check passed"""
import json
import os
import sys
import urllib.request

A = "0x000000000000000000000000000000005caa0014"
PROBE_AT = "0x000000000000000000000000000000000000beef"
ART = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../smartcontracts/evm/out/PqzPrecompileProbe.sol/PqzPrecompileProbe.json")
GAS87, PK, SIG = 102_000, 2592, 4627
CALL_SEL = "1b8b921d"  # call(address,bytes)
KAT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../smartcontracts/vectors/ua/pq_kat.json")


def call(rpc, m, p):
    q = urllib.request.Request(rpc, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(q))
    return r.get("result", r.get("error"))


def probe_call(rpc, target, data):
    """PqzPrecompileProbe.call(target, data) at PROBE_AT by state override: (word, gasUsed, returndata length)."""
    code = json.load(open(ART))["deployedBytecode"]["object"]
    d = bytes.fromhex(data[2:])
    cd = ("0x" + CALL_SEL + target[2:].rjust(64, "0") + (64).to_bytes(32, "big").hex() + len(d).to_bytes(32, "big").hex()
          + d.hex() + "00" * (-len(d) % 32))
    r = call(rpc, "eth_call", [{"to": PROBE_AT, "data": cd, "gas": hex(2**24)}, "latest", {PROBE_AT: {"code": code}}])
    r = r[2:]
    return int(r[0:64], 16), int(r[64:128], 16), int(r[128:192], 16)


def main(rpc, *flags):
    inactive = "--inactive" in flags
    k = json.load(open(KAT))["kinds"]["mldsa87"]
    head = call(rpc, "eth_getBlockByNumber", ["latest", False])
    print(f"head {int(head['number'], 16)} ts {int(head['timestamp'], 16)}; MLDSA87 {A}, expect {'inactive' if inactive else 'active'}")
    ok = True
    if not inactive:
        w, used, rlen = probe_call(rpc, "0x0000000000000000000000000000000000000004", "0x" + (5).to_bytes(32, "big").hex())
        assert w == 5 and rlen == 32, (w, rlen)
        oh = used - 100 - 18  # e2e.py overhead(): the identity precompile, 32 bytes = 15 + 3
        print(f"probe overhead (identity precompile) = {oh} gas")
    for name, want in (("eip8355_probe_valid", 1), ("eip8355_probe_invalid", 0)):
        d = k[name]
        out = call(rpc, "eth_call", [{"to": A, "data": d}, "latest"])
        gas = call(rpc, "eth_estimateGas", [{"to": A, "data": d}, "latest"])
        got = int(out, 16) if isinstance(out, str) and len(out) == 66 else None
        good = out == "0x" if inactive else got == want
        print(f"{'ok  ' if good else 'FAIL'} {name} ({(len(d) - 2) // 2} B): eth_call {out} "
              f"(want {'0x' if inactive else f'the word {want}'}); eth_estimateGas {int(gas, 16) if isinstance(gas, str) else gas}")
        ok &= good
        if not inactive:
            w, used, rlen = probe_call(rpc, A, d)
            n = (len(d) - 2) // 2
            want_gas = GAS87 + 6 * ((max(0, n - PK - SIG) + 31) // 32)
            g = used - 100 - oh
            good = w == want and rlen == 32 and g == want_gas
            print(f"{'ok  ' if good else 'FAIL'} {name} through the probe contract: word {w}, precompile gas {g} (want {want_gas} = mldsa87Gas {GAS87} PROVISIONAL + 6 per extra word)")
            ok &= good
    print("mldsa87-probe:", "all checks passed" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
