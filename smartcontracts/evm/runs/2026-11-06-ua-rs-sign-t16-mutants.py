#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T16 (the external-key interface, spec §9.4, MD-13): the check of an external key's answer (normalise, verify
against its KeyRef under the request's role) and the closed SignRequest are caught by tests/wallet_external.rs and the doc
tests of src/wallet/signer.rs. One mutant per run on a clean tree, its command (cargo test, feature `vectors`), every file
restored byte for byte after it. A mutant whose build fails is NOT-LOADED unless the command is a compile_fail doc test (there a
build that now succeeds is the kill); a mutant whose command passes SURVIVED: both are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t16-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t16-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
SG = R + "src/wallet/signer.rs"
SN = R + "src/wallet/sign.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors"]
EXT = CARGO + ["--test", "wallet_external"]
DOC = CARGO + ["--doc", "wallet::signer"]

M = [
    # the plan's two
    ("verify-after-sign skipped", [(SG, "    if ok {\n        Ok(sig)", "    if ok || !ok {\n        Ok(sig)")], EXT),
    ("SignRequest gains a public constructor (UaMsg no longer non_exhaustive)", [(SG, "    #[non_exhaustive]\n    UaMsg {", "    UaMsg {")], DOC),
    # the controller's
    ("the post-verification ignores the role (always Authorization)", [(SG, "&sig, *role == SigRole::Pop)", "&sig, false)")], EXT),
    ("secp256k1 high s not normalised", [(SG, "if n != s && matches!(*v, 27 | 28) {", "if false && n != s && matches!(*v, 27 | 28) {")], EXT),
    ("v not flipped with s", [(SG, "                        *v = 55 - *v;\n", "")], EXT),
    ("v 0 / 1 not read as 27 / 28", [(SG, "                if *v < 2 {", "                if false {")], EXT),
    ("P-256 high s not normalised", [(SG, "                sig = s.normalize_s().to_bytes().to_vec();", "                let _ = s;")], EXT),
    ("an ed25519 native key verified as secp256k1", [(SG, ".. }, req) if network.ed25519() => {", ".. }, req) if network.ed25519() && false => {")], EXT),
    ("WebAuthn answer not verified against the challenge", [(SG, "verify(0x0100, key_data, challenge, &sig, false)", "verify(0x0100, key_data, &[0; 32], &sig, false)")], EXT),
    ("native_digest: a transaction signs the zero digest", [(SN, "        SignRequest::Transaction { sighash, .. } if secp256k1 => Ok(*sighash),",
                                                             "        SignRequest::Transaction { sighash, .. } if secp256k1 => Ok({ let _ = sighash; [0; 32] }),")], EXT),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=R)
    return r.returncode, r.stdout + r.stderr


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, cmd) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        rc, out = run(cmd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)))
    loaded = cmd is DOC or not re.search(r"^error(\[E\d+\])?: could not compile", out, re.M)
    verdict = "NOT-LOADED" if not loaded else "SURVIVED  " if rc == 0 else "killed    "
    bad += (not loaded) or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
