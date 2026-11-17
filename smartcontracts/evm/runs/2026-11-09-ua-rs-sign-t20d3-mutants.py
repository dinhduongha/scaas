#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d3, the proof path's word parsers (C-PP-1; no-oracle spec §4.14.4): each mutant undoes one rule of the debit
record parser or the op blob's tail parser (`clients/ua-rs/src/facade/pqz_path.rs`) and names the test that must catch it (the
module's own tests over `state.json`'s `records` and `tails`, and their refusals; M11, after the controller's ruling on
Fable P3-6, the one-fit rule of a transfer blob's shape, which path (A)'s entry parse now shares). One mutant per run on a clean tree, its
command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a
build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d3-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d3-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d3-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
P = R + "src/facade/pqz_path.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
LIB = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--lib", "facade::pqz_path"])

M = [
    # the tail
    ("tail: n from the first byte", [(P, "let n = *d.last().ok_or(Error::Argument)? as usize;", "let n = *d.first().ok_or(Error::Argument)? as usize;")], LIB),
    ("tail: kv little-endian", [(P, "let kv = (0..n).map(|i| be64(d, at + 32 + 8 * i)).collect::<Result<_>>()?;",
                                 "let kv = (0..n).map(|i| be64(d, at + 32 + 8 * i).map(u64::swap_bytes)).collect::<Result<_>>()?;")], LIB),
    ("tail: ownTag one byte late", [(P, "let own_tag = d.get(at..at + 32)", "let own_tag = d.get(at + 1..at + 33)")], LIB),
    ("tail: n above 9 taken", [(P, "    if n > KV_MAX {\n        return Err(Error::Argument);\n    }\n    let at", "    let at")], LIB),
    # the record
    ("record: WIDE ignored", [(P, "let (shield_in, key_version, prev_counter) = if flags & WIDE != 0 {",
                               "let (shield_in, key_version, prev_counter) = if false {")], LIB),
    ("record: a narrow prevCounter left 0", [(P, "        (0, 0, counter.checked_sub(1).ok_or(Error::Argument)?)\n", "        (0, 0, 0)\n")], LIB),
    ("record: RECORD unchecked", [(P, "if *w0 == [0; 32] || flags & RECORD == 0 || flags", "if *w0 == [0; 32] || flags")], LIB),
    ("record: proofStore unbounded", [(P, " || proof_store > 1 || be64(w1, 24)? != 0", " || be64(w1, 24)? != 0")], LIB),
    ("record: Δp bytes swapped", [(P, "u16::from_be_bytes([delta_hi, delta_lo])", "u16::from_be_bytes([delta_lo, delta_hi])")], LIB),
    ("record: a narrow w1 taken", [(P, "    } else if *w1 != [0; 32] {\n        return Err(Error::Argument);\n    } else if has_prev {",
                                    "    } else if has_prev {")], LIB),
    # the shape of a transfer blob's R (Fable P3-6, path (A)'s entries and path (B)'s credits alike)
    ("bundle_shape: the first fit taken", [(P, " && fit.replace((g, m, aud)).is_some() {\n            return Err(Error::Argument);",
                                            " {\n            return Ok((g, m, aud));")], LIB),
]

if sys.argv[1:] == ["count"]:
    print(len(M))
    raise SystemExit(0)
if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, f, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)

NOT_BUILT = re.compile(r"^error(\[E\d+\])?: could not compile", re.M)
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
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env={**os.environ, **ENV})
        rc, out = r.returncode, r.stdout + r.stderr
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
