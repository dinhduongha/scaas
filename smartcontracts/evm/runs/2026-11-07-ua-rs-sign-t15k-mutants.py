#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15k (Fable P3-5; ua-mtx-merge T36a): each mutant undoes one rule of op 1's memoHash per `mode` and of op 2's
memoHash 0, and names the test that must catch it. One mutant per run on a clean tree, its command, every file restored byte for byte after it
(the caller also runs `git diff --exit-code` on the paths). A failing command kills; a build that does not compile is
NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1). Tests run in the release cell.
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15k-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15k-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R, Q, P = "clients/ua-rs/", "clients/ua-rs/src/facade/pqz.rs", "clients/ua-rs/src/facade/pqz_pack.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
T = lambda *names: (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--test", "facade_pqz_state", *names])

M = [
    ("op 1 HASH: memoHash left 0", [(Q, "                (crate::keccak256(&m), Some(m))\n            }\n            Memo::Mode(Mode::Bundle) => ([0; 32], None),",
                                    "                ([0; 32], Some(m))\n            }\n            Memo::Mode(Mode::Bundle) => ([0; 32], None),")], T("op1_memo_per_mode")),
    ("op 1 BUNDLE: memoHash set", [(Q, "            Memo::Mode(Mode::Bundle) => ([0; 32], None),", "            Memo::Mode(Mode::Bundle) => ([1; 32], None),")], T("op1_memo_per_mode")),
    ("op 1 HASH: the salt dropped from the hash", [(Q, "                (crate::keccak256(&m), Some(m))", "                (crate::keccak256(m.get(16..).unwrap_or_default()), Some(m))")],
     T("op1_memo_per_mode")),
    ("op 1: a default mode (BUNDLE without the field)", [(Q, "                memo: Memo::Mode(f.mode()?),", "                memo: Memo::Mode(f.mode().unwrap_or(Mode::Bundle)),")],
     T("op1_memo_per_mode")),
    ("op 1 HASH: the memo's leg not (amount, toUA)", [(Q, "&hd, pk_a.is_some(), &[(amount, *to_ua)])", "&hd, pk_a.is_some(), &[(amount, [0; 32])])")],
     T("op1_memo_per_mode")),
    ("op 1 HASH: auditorOn not in the memo's flags", [(Q, "&hd, pk_a.is_some(), &[(amount, *to_ua)])", "&hd, false, &[(amount, *to_ua)])")], T("op1_memo_per_mode")),
    ("burn: a free memoHash taken", [(Q, '"proveBurn" => debit(&["amount", "recipient"]),', '"proveBurn" => debit(&["amount", "recipient", "memoHash"]),'),
                                      (Q, 'recipient: f.word("recipient")?, t: o.t, memo_hash: [0; 32] }', 'recipient: f.word("recipient")?, t: o.t, memo_hash: f.word("memoHash").unwrap_or_default() }')],
     T("burn_and_refresh_memo_hash_is_zero")),
    ("refresh: a free memoHash taken", [(Q, '"proveRefresh" => debit(&[]),', '"proveRefresh" => debit(&["memoHash"]),'),
                                         (Q, "(Req::Refresh { id, h, t: o.t, memo_hash: [0; 32] }", '(Req::Refresh { id, h, t: o.t, memo_hash: f.word("memoHash").unwrap_or_default() }')],
     T("burn_and_refresh_memo_hash_is_zero")),
]

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
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:400]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
