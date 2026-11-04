# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ML-DSA-87 probe (2026-11-04): extract the NIST ACVP ML-DSA-87 sigVer cases into acvp87.json beside this file.

Input: the downloaded ACVP file, the same pinned commit and SHA-256 as clients/clientkeys/scripts/pq-external.mjs
(ACVP-Server 975de31e, ML-DSA-sigVer-FIPS204/internalProjection.json). The file is untrusted data: run with `python3 -I`,
the path as an argument, a SHA-256 mismatch refuses it before it is parsed. Kept groups as pq-external.mjs keeps them:
pure external (M' = 0 || |ctx| || ctx || M) and internal without external mu (M' = M); preHash and externalMu are
outside the UA kind (CTR-UA-23: pure signing, the verifier hashes tr || M' itself).
    python3 -I runs/2026-11-04-mldsa87-probe/extract.py <download dir>/internalProjection.json
"""
import hashlib
import json
import os
import sys

SOURCE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/"
          "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json")
PIN = "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437"
PK, SIG = 2592, 4627


def main(path):
    raw = open(path, "rb").read()
    if hashlib.sha256(raw).hexdigest() != PIN:
        sys.exit("sha256 mismatch: refused")
    j = json.loads(raw)
    cases = []
    for g in j["testGroups"]:
        if g["parameterSet"] != "ML-DSA-87" or g.get("preHash") == "preHash" or g.get("externalMu"):
            continue
        for t in g["tests"]:
            pk, sig, m = bytes.fromhex(t["pk"]), bytes.fromhex(t["signature"]), bytes.fromhex(t["message"])
            ctx = bytes.fromhex(t.get("context", ""))
            if len(pk) != PK or len(sig) != SIG or len(ctx) > 255:
                sys.exit(f"tc {t['tcId']}: unexpected length")
            internal = g["signatureInterface"] == "internal"
            mprime = m if internal else bytes([0, len(ctx)]) + ctx + m
            cases.append({"tc": t["tcId"], "iface": g["signatureInterface"], "valid": bool(t["testPassed"]),
                          "reason": t["reason"], "pk": "0x" + pk.hex(), "mprime": "0x" + mprime.hex(),
                          "sig": "0x" + sig.hex()})
    if len(cases) != 30 or sum(c["valid"] for c in cases) != 6:
        sys.exit(f"expected 30 cases, 6 valid; got {len(cases)}")
    out = {"source": SOURCE, "sha256": PIN, "note": "ML-DSA-87 pure external and internal sigVer groups (tgId 5, 12)",
           "cases": cases}
    dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "acvp87.json")
    with open(dst, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print(len(cases), "cases,", sum(c["valid"] for c in cases), "valid")


if __name__ == "__main__":
    main(sys.argv[1])
