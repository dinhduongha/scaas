#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15b (op 7 memoHash per explicit mode, owner 2026-11-06, spec no-decryption-oracle §4.11, F10): the mode field and
the memoHash rule are caught by tests/facade_pqz.rs (`multi_*` and, feature `vectors`, `vectors::multi_rows_per_mode`). One mutant
per run on a clean tree, its command, every file restored byte for byte after it. A mutant whose build fails is NOT-LOADED; a mutant
whose command passes SURVIVED: both are findings (exit 1). M1 is also the positive control of the plan: the old behaviour (memoHash
set on every build) passes the HASH tests and fails the BUNDLE ones.
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t15b-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t15b-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
Q = R + "src/facade/pqz.rs"
CAPPED = os.path.abspath("scripts/capped")
T = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "facade_pqz", "multi"])

M = [
    # the plan's three
    ("memoHash set on BUNDLE (the old behaviour; the positive control)",
     [(Q, "            Mode::Bundle => None,\n",
       "            Mode::Bundle => Some(pqz_ffi::memo::seal(memo_key, &hd, aud, &memo_legs).ok_or(Error::Argument)?),\n")], T),
    ("the salt dropped from the hash: keccak256(sealedMemo)",
     [(Q, "memo.as_deref().map_or([0; 32], crate::keccak256);",
       "memo.as_deref().map_or([0; 32], |m| crate::keccak256(m.get(16..).unwrap_or_default()));")], T),
    ("a default mode: no `mode` is HASH",
     [(Q, "let mode = match f.get(\"mode\")?.as_str() {", "let mode = match f.get(\"mode\").ok().and_then(Value::as_str).or(Some(\"HASH\")) {")], T),
    # the controller's
    ("memoHash 0 on HASH too", [(Q, "memo.as_deref().map_or([0; 32], crate::keccak256);", "[0; 32];")], T),
    ("HASH read as BUNDLE", [(Q, "Some(\"HASH\") => Mode::Hash,", "Some(\"HASH\") => Mode::Bundle,")], T),
    ("any other string read as BUNDLE", [(Q, "Some(\"BUNDLE\") => Mode::Bundle,", "Some(_) => Mode::Bundle,")], T),
    ("BUNDLE returns the memo", [(Q, "if let (Some(o), Some(memo)) = (v.as_object_mut(), memo) {",
                                  "if let (Some(o), Some(memo)) = (v.as_object_mut(), memo.or_else(|| pqz_ffi::memo::seal(memo_key, &hd, aud, &memo_legs))) {")], T),
    ("`mode` off the allow-list", [(Q, "has(&[\"proofSystemId\", \"legs\", \"pkA\", \"T\", \"mode\"])", "has(&[\"proofSystemId\", \"legs\", \"pkA\", \"T\"])")], T),
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
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)))
    passed = sorted(set(re.findall(r"^test (.+?) \.\.\. ok", out, re.M)))
    loaded = not re.search(r"^error(\[E\d+\])?: could not compile", out, re.M)
    verdict = "NOT-LOADED" if not loaded else "SURVIVED  " if rc == 0 else "killed    "
    bad += (not loaded) or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)} | passed: {', '.join(passed)}",
          flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
