#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""SCaaS testnet reset 4, T-GAS for `mldsa87` (CTR-UA-39; DeployBase.CAP_MLDSA87 = 250,000, the PROVISIONAL cap of the
precompile path): the gas of MldsaVerifier(0x0134).verify on the live node at mldsaGas87 135,000 (precompile 135,006),
read only, nothing sent. (1) eth_call of the creation code MldsaVerifier(0x0134, 0x...5caa0014, pq_kat.json's mldsa87
EIP-8355 probe pair) runs the constructor (its precompile probe included) on the node and returns the runtime; (2) that
runtime at VER and test/p6f/PqzPrecompileProbe at PROBE_AT by state override; probe.call(VER, verify(pk, ua_msg, sig))
returns the gasUsed of the call; minus the cold account access (2,600) and the probe's own overhead (the identity
precompile row, as 2026-11-04-mldsa87-probe.py) = the verifier's execution, the part the cap bounds. Also a flipped
signature (one bit) and the precompile row itself. Prints the headroom 250,000 - execution; never moves the cap.
  python3 -I tgas.py <rpc>"""
import json
import os
import sys
import urllib.request

H = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.join(H, "../..")
KAT = json.load(open(os.path.join(EVM, "../vectors/ua/pq_kat.json")))["kinds"]["mldsa87"]
ART = lambda p: json.load(open(os.path.join(EVM, "out", p)))
ML87, PROBE_AT, VER, CAP = "0x000000000000000000000000000000005caa0014", "0x" + "00" * 18 + "beef", "0x" + "00" * 18 + "0134", 250_000
enc = lambda *ws: "".join(ws)
u = lambda n: n.to_bytes(32, "big").hex()
by = lambda h: (lambda b: u(len(b)) + b.hex() + "00" * (-len(b) % 32))(bytes.fromhex(h[2:]))


def rpc(url, m, p):
    r = json.load(urllib.request.urlopen(urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(), {"content-type": "application/json"})))
    if "error" in r:
        raise SystemExit(f"FAIL {m}: {r['error']}")
    return r["result"]


def main(url):
    init = ART("MlDsa.sol/MldsaVerifier.json")["bytecode"]["object"]
    args = enc(u(0x0134), ML87[2:].rjust(64, "0"), u(128), u(128 + 32 + (len(KAT["eip8355_probe_valid"]) - 2 + 63) // 64 * 32))
    args += by(KAT["eip8355_probe_valid"]) + by(KAT["eip8355_probe_invalid"])
    code = rpc(url, "eth_call", [{"data": init + args, "gas": hex(30_000_000)}, "latest"])
    print(f"MldsaVerifier(0x0134) runtime from the node's constructor run: {(len(code) - 2) // 2} B")
    probe = ART("PqzPrecompileProbe.sol/PqzPrecompileProbe.json")["deployedBytecode"]["object"]
    ov = {PROBE_AT: {"code": probe}, VER: {"code": code}}

    def pcall(target, data):
        d = bytes.fromhex(data[2:])
        cd = "0x1b8b921d" + target[2:].rjust(64, "0") + u(64) + u(len(d)) + d.hex() + "00" * (-len(d) % 32)
        r = rpc(url, "eth_call", [{"to": PROBE_AT, "data": cd, "gas": hex(2**24)}, "latest", ov])[2:]
        return int(r[0:64], 16), int(r[64:128], 16)

    w, used = pcall("0x0000000000000000000000000000000000000004", "0x" + u(5))
    oh = used - 100 - 18
    print(f"probe overhead (identity precompile) = {oh} gas")
    w, used = pcall(ML87, KAT["eip8355_probe_valid"])
    print(f"precompile row: word {w}, gas {used - 100 - oh} (want 135006)")
    sel = rpc(url, "web3_sha3", ["0x" + b"verify(bytes,bytes32,bytes)".hex()])[:10]
    sig = KAT["sig"]
    flip = sig[:2] + format(int(sig[2:4], 16) ^ 1, "02x") + sig[4:]
    ok = True
    for name, s in (("valid", sig), ("flipped sig", flip)):
        data = sel + u(96) + KAT["ua_msg"][2:] + u(96 + 32 + (len(KAT["pk"]) - 2 + 63) // 64 * 32) + by(KAT["pk"]) + by(s)
        w, used = pcall(VER, data)
        ex = used - 2600 - oh
        want = 1 if name == "valid" else 0
        good = w == want
        ok &= good
        print(f"{'ok  ' if good else 'FAIL'} verify ({name}): word {w} (want {want}); call gasUsed {used}, execution ~{ex} "
              f"(cold access 2,600 and probe overhead removed); cap {CAP:,}: headroom {CAP - ex:,} ({(CAP - ex) / CAP:.1%})")
    print("tgas:", "ok" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
