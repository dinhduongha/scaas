#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T16a (the k-of-n backup of an msig holder's PQZ seed32, owner 2026-11-06): the split, the rebuild's checks, the
dealer's checks and the warning are caught by tests/pqz_backup.rs (feature `vectors`: the known answers and the combine counter);
the C ABI's default k by ua-c's tests/test_vectors.py WalletPqzBackup. One mutant per run on a clean tree, its command, every
file restored byte for byte after it. A mutant whose build fails is NOT-LOADED; a mutant whose command passes SURVIVED: both
are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t16a-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t16a-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
RC = "clients/ua-c/"
B = R + "src/facade/pqz_backup.rs"
Q = R + "src/facade/pqz.rs"
LC = RC + "src/lib.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors"]
T = (R, CARGO + ["--test", "pqz_backup"])
PY = (RC, ["bash", "-c", f"{CAPPED} cargo build --locked --offline -j2 && python3 -I tests/test_vectors.py WalletPqzBackup"])

M = [
    # the plan's three
    ("share header unbound: the expected (msig ua, version, pqzKeyHash) not checked",
     [(B, "let want = (first.msig_ua == *msig_ua) && first.version == version && first.pqz_key_hash == *pqz_key_hash;",
       "let want = { let _ = (msig_ua, version); true };")], T),
    ("the key-hash check skipped", [(Q, "    if crate::key_hash_of(crate::PQZ_SCHEME, &pk)? != Some(*pqz_key_hash) {",
                                     "    if false && crate::key_hash_of(crate::PQZ_SCHEME, &pk)? != Some(*pqz_key_hash) {")], T),
    ("threshold off by one: k - 1 shares accepted", [(B, "shares.len() < usize::from(first.k)", "shares.len() + 1 < usize::from(first.k)")], T),
    # the controller's
    ("threshold off by one in the split: degree k", [(B, "usize::from(k).saturating_sub(1)", "usize::from(k)")], T),
    ("the field: x^8 + x^4 + x^3 + x^2 + 1 (0x1d)", [(B, "(0x1b & 0u8.wrapping_sub(a >> 7))", "(0x1d & 0u8.wrapping_sub(a >> 7))")], T),
    ("Lagrange: x_j / x_j for x_j / (x_j - x_i)", [(B, "mul(*xj, inv(xj ^ xi))", "mul(*xj, inv(*xj))")], T),
    ("x-coordinates from 2", [(B, "    (1..=n)\n        .map(|x| {", "    (2..=n + 1)\n        .map(|x| {")], T),
    ("mixed headers accepted", [(B, "if !want || shares.iter().any(|s| s.h != first) ||", "if !want ||")], T),
    ("a repeated index accepted", [(B, "    if points.iter().enumerate().any(|(i, p)| points.iter().skip(i + 1).any(|q| q.0 == p.0)) {",
                                    "    if false && points.iter().enumerate().any(|(i, p)| points.iter().skip(i + 1).any(|q| q.0 == p.0)) {")], T),
    ("the polynomial dropped: every share is seed32", [(B, "let ys = split_with(&*self.leaf()?, &coeffs(k)?, n);",
                                                        "let ys = split_with(&*self.leaf()?, &{ let _ = coeffs(k)?; Zeroizing::new(Vec::new()) }, n);")], T),
    ("a recipient that is no member accepted", [(B, "if seen.contains(&ua) || !st.members.iter().any(|m| m.id == ua) {", "if seen.contains(&ua) {")], T),
    ("a member twice accepted", [(B, "if seen.contains(&ua) || !st.members.iter().any(|m| m.id == ua) {", "if !st.members.iter().any(|m| m.id == ua) {")], T),
    ("default k is n, not the threshold", [(B, "None => u8::try_from(st.threshold).map_err(|_| Error::Argument)?,", "None => n,")], T),
    ("reseal of another purpose", [(B, "    if expect.purpose != PURPOSE_PQZ_SHARE {\n        return Err(Error::Argument);\n    }\n    Share::from_json",
                                    "    Share::from_json")], T),
    ("the warning ignores the version", [(B, "h.msig_ua == *msig_ua && h.version == version && h.pqz_key_hash", "h.msig_ua == *msig_ua && h.pqz_key_hash")], T),
    ("the warning ignores a missing share", [(B, " && self.shares.len() == usize::from(h.n)\n", "\n")], T),
    ("a single key warns", [(B, "    if kind != MSIG {\n        return None;\n    }\n    let kh", "    let kh")], T),
    ("C ABI: threshold 0 passed as k = 0", [(LC, "let t = (threshold != 0).then_some(threshold);", "let t = Some(threshold);")], PY),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(cwd, cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout + r.stderr


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, (cwd, cmd)) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        rc, out = run(cwd, cmd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)) | set(re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)))
    loaded = not re.search(r"^error(\[E\d+\])?: could not compile", out, re.M)
    verdict = "NOT-LOADED" if not loaded else "SURVIVED  " if rc == 0 else "killed    "
    bad += (not loaded) or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
