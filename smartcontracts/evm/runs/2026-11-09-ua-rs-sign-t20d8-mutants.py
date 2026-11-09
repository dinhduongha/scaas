#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d8, path (B)'s bounds and its reference reader (C-PP-7; no-oracle spec §4.14.9, §4.14.11): each mutant undoes one
bound of the session's requests or one rule of `pqz-read --command balanceProven` (the reader's against a local anvil, `ANVIL`
or `anvil` on the PATH) (`clients/ua-rs/src/facade/pqz/proven.rs`) and names the test that must catch it
(`tests/facade_pqz_proof.rs`, feature `vectors`: the key-use counter). The round's own (the plan names none). One mutant per run
on a clean tree, its command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A
failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a
finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d8-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d8-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d8-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
P = R + "src/facade/pqz/proven.rs"
B = R + "src/bin/pqz-read.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
T = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "facade_pqz_proof", "--", "bounds", "window", "interleaved"])
A = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--bin", "pqz-read", "--test", "pqz_read", "--", "--include-ignored", "balance_proven", "proof_log", "transfer_entries"])

M = [
    ("more than K_MAX credits taken", [(P, "    let list = f.list(\"credits\")?;\n    if list.len() > K_MAX {", "    let list = f.list(\"credits\")?;\n    if list.len() > usize::MAX - 1 {")], T),
    ("a sender window past K_MAX taken", [(P, "                    let l = c.list(\"senderPending\")?;\n                    if l.len() > K_MAX {", "                    let l = c.list(\"senderPending\")?;\n                    if l.len() > usize::MAX - 1 {")], T),
    ("more than 10 key records taken", [(P, "                    let l = c.list(\"keyRecords\")?;\n                    if l.len() > KEY_RECORDS_MAX {", "                    let l = c.list(\"keyRecords\")?;\n                    if l.len() > usize::MAX - 1 {")], T),
    ("reader: the envelope binding without validUntil", [(B, "env[0], env[1], env[2], env[3], env[4],", "env[0], env[1], env[2], [0; 32], env[4],")], A),
    ("reader: the sender counter searched one short", [(B, "let k = (counter.saturating_sub(MAX_COUNTER_SEARCH)..counter).rev()", "let k = (counter.saturating_sub(MAX_COUNTER_SEARCH)..counter.saturating_sub(1)).rev()")], A),
    ("reader: a call through another contract read", [(B, "if tx[\"to\"].as_str().map(|t| t.to_ascii_lowercase()) != Some(hx(&a.token)) {", "if false {")], A),
    ("reader: a Compact entry not commit-reveal", [(B, "hash: e.compact || compact_token,", "hash: compact_token,")], A),
    ("reader: a header of any length", [(B, "    if header.len() != 640 {", "    if header.len() == 0 {")], A),
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
