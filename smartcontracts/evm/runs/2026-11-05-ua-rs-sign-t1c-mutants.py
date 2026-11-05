#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T1c: the external known answers (ACVP ML-KEM-1024, RFC 7748, ACVP sigGen, RFC 6979, the secp256k1 set) and the pinned-source
check catch a change in what they test. One change per run on a clean tree, the suite run, the file restored byte for byte after it;
a mutant that does not load is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t1c-mutants.py [first last]   (from the worktree root, foreground)"""
import sys
import os
import subprocess

CK = "clients/clientkeys/"
KEM, PINNED = CK + "src/kem.js", CK + "scripts/pinned.mjs"
# noble's X25519 clamping lives in node_modules (not tracked): restored from memory like every other file
ED = CK + "node_modules/@noble/curves/ed25519.js"
SUITE = [os.path.abspath("scripts/capped"), "node", "--test", "test/pq.test.js", "test/kem.test.js", "test/ua-wallet.test.js"]
M = [
    ("one ACVP d / z swapped (KeyGen_internal)", KEM, "ml_kem1024.keygen(concatBytes(d, z));", "ml_kem1024.keygen(concatBytes(z, d));"),
    ("X25519 clamping skipped", ED, "    bytes[0] &= 248; // 0b1111_1000", "    return bytes; // clamping skipped"),
    ("modulus bound 4096 for q", KEM, "if ((ek[i] | ((ek[i + 1] & 15) << 8)) >= 3329 || ((ek[i + 1] >> 4) | (ek[i + 2] << 4)) >= 3329) return false;",
     "if ((ek[i] | ((ek[i + 1] & 15) << 8)) >= 4096 || ((ek[i + 1] >> 4) | (ek[i + 2] << 4)) >= 4096) return false;"),
    ("dk check over the wrong range", KEM, "const h = sha3_256(dk.subarray(1536, 3104));", "const h = sha3_256(dk.subarray(1536, 3136));"),
    ("pinned sha256 not compared", PINNED, "if (got !== String(sha256).replace(/^0x/, ''))", "if (false)"),
]
bad = 0
assert len({m[0] for m in M}) == len(M)
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, f, a, b) in enumerate(M[lo - 1:hi], lo):
    src = open(f, encoding="utf-8").read()
    assert src.count(a) == 1, (name, src.count(a))
    open(f, "w", encoding="utf-8").write(src.replace(a, b))
    try:
        r = subprocess.run(SUITE, capture_output=True, text=True, cwd=CK)
    finally:
        open(f, "w", encoding="utf-8").write(src)
    assert open(f, encoding="utf-8").read() == src
    out = r.stdout + r.stderr
    loaded = "SyntaxError" not in out and "ERR_MODULE_NOT_FOUND" not in out and "does not provide an export" not in out
    failed = [x[2:].split(" (")[0] for x in out.splitlines() if x.startswith("✖ ") and "failing tests" not in x]
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    print(f"{verdict} | M{n} {name} | {f.removeprefix(CK)} | rc={r.returncode} | {len(set(failed))} failed: {sorted(set(failed))[0][:90] if failed else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
