#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b, group `verifiers`: every UA verifier of the Step 5 deploy asked by eth_call on the node with the
cross-language vectors (smartcontracts/vectors/ua/signatures.json `derived`, pq_signatures.json `kinds`): `verifyPop`
over the PoP and `verify` over the first signature must answer true, and the same with the message flipped must answer
false (a negative). The verifier addresses come from the target's base book (basebook.py, its own deploy); the ML-DSA ones
(round 3zh, owner 2026-11-15, MD-8) from the deploy JSON's `mldsa44/65/87_verifier` (DEPLOY_JSON; a pre-3zh book: the base
book's first two MldsaVerifiers), asked through the path the registry uses on that deploy: on a precompile (`PRECOMPILE()` != 0)
`verifyPop` / `verify` on the FIPS 204 key; without one `verifyCached` on the parts the verifier derives (`expandedKeyPart`,
one eth_call each) placed as code `0x00 ‖ part` by the eth_call's state override, never the uncached FIPS-key verify (over
EIP-7825's 2^24 for 65 / 87, Nethermind's eth_call cap). Records:
runs/…-step5b/records-<net>-verifiers.jsonl, book deployments/onchain-<net>-verifiers.json.
  python3 -I script/onchain/verifiers.py <net> <rpc>
MuSig2 / FROST have no row in these vectors (their keys are aggregates): not asked here. UNAUDITED."""
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
VEC = os.path.join(EVM, "../vectors/ua")
OUTD = os.path.join(EVM, os.environ.get("MATRIX_OUT") or time.strftime("runs/%Y-%m-%d-matrix"))  # matrix.sh's run dir
VERIFY, VERIFY_POP = "024ad318", "53e5293f"
PRECOMPILE, PART, CACHED = "0709d0b1", "b733b5e4", "8e598e38"  # PRECOMPILE(), expandedKeyPart(bytes,uint256), verifyCached(...)
ML = {"mldsa44": 1, "mldsa65": 2, "mldsa87": 3}  # PqUA.mldsaParts
CAP = 1 << 24  # the eth_call gas: EIP-7825's cap, Nethermind's own
BY_NAME = {"webauthn-p256": "WebAuthnP256Verifier", "p256": "P256Verifier", "bip340": "Bip340Verifier",
           "schnorr-bn254": "SchnorrBn254Verifier", "schnorr-bls12381": "SchnorrBls12381Verifier",
           "bls12381-minsig": "BlsMinSigBls12381Verifier", "bls-bn254-minsig": "BlsMinSigBn254Verifier",
           "ed25519": "Ed25519Verifier", "secp256k1": "Secp256k1Verifier", "zether-bls12381": "ZetherSchnorrBls12381Verifier",
           "mldsa44": ("MldsaVerifier", 0), "mldsa65": ("MldsaVerifier", 1), "mldsa87": ("MldsaVerifier", 2),
           "fndsa512": ("FndsaVerifier", 0),
           "fndsa1024": ("FndsaVerifier", 1), "slhdsa128s": ("SlhdsaVerifier", 0)}


def rpc(url, m, p):
    q = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(q, timeout=300))
    if "error" in r:
        raise RuntimeError(r["error"])
    return r["result"]


def enc(sel, kd, msg, sig):
    """`f(bytes keyData, bytes32 message, bytes sig)`."""
    def b(x):
        return len(x).to_bytes(32, "big") + x + b"\0" * (-len(x) % 32)
    t1 = b(kd)
    return "0x" + sel + ((96).to_bytes(32, "big") + msg + (96 + len(t1)).to_bytes(32, "big") + t1 + b(sig)).hex()


def b(x):
    return len(x).to_bytes(32, "big") + x + b"\0" * (-len(x) % 32)


def cached_case(url, addr, name, kd, msg, sig, flip):
    """The registry's path without a precompile: each part by `expandedKeyPart` (eth_call), then `verifyCached` with the parts as
    code at fixed addresses (state override). Returns the verdict (True / False) or a string on a failed call."""
    over, chunks = {}, b""
    for p in range(ML[name]):
        r = rpc(url, "eth_call", [{"to": addr, "data": "0x" + PART + ((64).to_bytes(32, "big") + p.to_bytes(32, "big") + b(kd)).hex(),
                                   "gas": hex(CAP)}, "latest"])
        raw = bytes.fromhex(r[2:])
        part = raw[64:64 + int.from_bytes(raw[32:64], "big")]
        at = "0x" + f"{0x5caac0de0 + p:040x}"
        over[at] = {"code": "0x00" + part.hex()}
        chunks += bytes.fromhex(at[2:])
    m = bytes(x ^ 0xFF for x in msg) if flip else msg
    r = rpc(url, "eth_call", [{"to": addr, "data": enc(CACHED, chunks, m, sig), "gas": hex(CAP)}, "latest", over])
    return int(r, 16) == 1 if r not in ("0x", None) else None


def main():
    net, url = sys.argv[1], sys.argv[2]
    at = {}  # the target's base book (basebook.py), in deploy order: the first MldsaVerifier is 44, the second 65
    for a, name in json.load(open(os.path.join(EVM, f"deployments/onchain-{net}-base.json"))).items():
        at.setdefault(name, []).append(a)
    dj = os.environ.get("DEPLOY_JSON")
    dep = json.load(open(dj if os.path.isabs(dj) else os.path.join(EVM, dj))) if dj else {}
    mlv = {n: dep[f"{n}_verifier"] for n in ML if f"{n}_verifier" in dep}  # 3zh: the registry's own ML-DSA verifiers
    vec = [(x["name"], x) for x in json.load(open(os.path.join(VEC, "signatures.json")))["derived"]]
    vec += [(x["name"], x) for x in json.load(open(os.path.join(VEC, "pq_signatures.json")))["kinds"]]
    rec, book, bad = [], {}, 0
    for name, x in vec:
        v = BY_NAME.get(name)
        if v is None:
            print(f"skip {name}: no verifier of this deploy")
            continue
        label, i = v if isinstance(v, tuple) else (v, 0)
        if name in ML and (mlv or name == "mldsa87"):
            if name not in mlv:
                print(f"skip {name}: the deploy's registry has no {name} verifier")
                continue
            addr = mlv[name]
        elif len(at.get(label, [])) <= i:
            print(f"skip {name}: {label} #{i} not in the deploy")
            continue
        else:
            addr = at[label][i]
        book[addr] = label
        kd = bytes.fromhex(x["keyData"][2:])
        pops = x["pop"] if isinstance(x["pop"], dict) else x["pop"][0]
        cases = [(VERIFY_POP, bytes.fromhex(pops["message"][2:]), bytes.fromhex(pops["sig"][2:]), "verifyPop(PoP)")]
        s0 = x.get("sigs", [None])[0]
        if s0 and "message" in s0:
            cases.append((VERIFY, bytes.fromhex(s0["message"][2:]), bytes.fromhex(s0["sig"][2:]), "verify(signature)"))
        cache = False
        if name in ML:
            r = rpc(url, "eth_call", [{"to": addr, "data": "0x" + PRECOMPILE}, "latest"])
            cache = int(r, 16) == 0
            if cache:  # the registry's path here: verifyCached on the derived parts (MD-8)
                cases = [(CACHED, c[1], c[2], f"verifyCached({c[3].split('(')[1]}") for c in cases]
        for sel, msg, sig, what in cases:
            for flip in (False, True):
                m = bytes(b ^ 0xFF for b in msg) if flip else msg
                try:
                    if cache:
                        got = cached_case(url, addr, name, kd, msg, sig, flip)
                    else:
                        r = rpc(url, "eth_call", [{"to": addr, "data": enc(sel, kd, m, sig), "gas": hex(CAP)}, "latest"])
                        got = int(r, 16) == 1 if r not in ("0x", None) else None
                except RuntimeError as e:
                    got = f"reverted {str(e)[:60]}"
                want = not flip
                ok = got is want or (flip and isinstance(got, str))  # a flipped message may revert as well as answer false
                bad += not ok
                rec.append({"net": net, "to": addr.lower(), "label": label, "sel": sel, "tx": "", "gas": 0,
                            "status": (2 if ok else 0) if flip else (1 if ok else 0),
                            "what": f"{'negative: ' if flip else 'view '}{label}.{what} {name}{', message flipped' if flip else ''}",
                            "script": "verifiers", "got": str(got)})
                print(f"{'ok ' if ok else 'BAD'} {name} {label}.{what}{' flipped' if flip else ''}: {got}")
    with open(os.path.join(OUTD, f"records-{net}-verifiers.jsonl"), "w") as f:
        f.writelines(json.dumps(r) + "\n" for r in rec)
    with open(os.path.join(EVM, f"deployments/onchain-{net}-verifiers.json"), "w") as f:
        json.dump(book, f, indent=1)
    print(f"verifiers: {len(rec)} calls, {bad} not as expected")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
