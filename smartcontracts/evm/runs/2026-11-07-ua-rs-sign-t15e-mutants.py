#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15e (ARCH-POS-13; spec no-decryption-oracle §4.3-§4.6, §5): each mutant undoes one guard of the words path and
names the test that must catch it. One mutant per run on a clean tree, its command, every file restored byte for byte after it
(the caller also runs `git diff --exit-code` on the paths). A failing command kills; a build that does not compile is
NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1). Tests run with feature `vectors` (the
key-use counter is how "refused before the key" is observed).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15e-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15e-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R, Q, P = "clients/ua-rs/", "clients/ua-rs/src/facade/pqz.rs", "clients/ua-rs/src/facade/pqz_pack.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
T = lambda *names: (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "facade_pqz_state",
                        *names])

M = [
    # the plan's nine
    ("caller's T accepted (proveTransfer allow-list)", [(Q, '"proveTransfer" => debit(&["toUA", "pkT", "pkA", "amount", "memoHash"]),',
                                                         '"proveTransfer" => debit(&["toUA", "pkT", "pkA", "amount", "memoHash", "T"]),')],
     T("requests_carry_words_only")),
    ("p taken from the request (proveRefresh allow-list)", [(Q, '"proveRefresh" => debit(&["memoHash"]),', '"proveRefresh" => debit(&["memoHash", "p"]),')],
     T("requests_carry_words_only")),
    ("not() skipped on accWords", [(Q, ".flat_map(|w| w.map(|b| !b)).take(CTP)", ".flat_map(|w| *w).take(CTP)")], T()),
    ("TRIVIAL read as blob == 0", [(Q, "        if v_off == 0 {\n            add_trivial(", "        if lo_addr(e, 12)? == [0; 20] {\n            add_trivial(")], T()),
    ("the unpacker's field width off by one", [(P, "let mask = (1u128 << B) - 1;", "let mask = (1u128 << (B - 1)) - 1;")], T("stored_form_is_the_contracts")),
    ("the accHash comparison skipped", [(Q, "        if crate::keccak256(&stream) != a.acc_hash {", "        if false && crate::keccak256(&stream) != a.acc_hash {")],
     T("word_negatives_refused_before_the_key")),
    ("entryRef not recomputed", [(Q, '    if er != f.word("entryRef")? {', '    if false && er != f.word("entryRef")? {')],
     T("entry_and_role_negatives_refused_before_the_key")),
    ("the leg's UA_j not compared", [(Q, '            if holder != f.word("ua")? {', '            if false && holder != f.word("ua")? {')],
     T("entry_and_role_negatives_refused_before_the_key")),
    ("the auditor window w ignored", [(Q, "let window = if auditor_read { j % legs_per_group(true) } else { 0 };", "let window = 0;")], T()),
    # the controller's
    ("psid not checked before the words", [(Q, '    let id = system(&f.word("psid")?)?;\n    let shield_in', '    let id = f.word("psid")?;\n    let shield_in')],
     T("word_negatives_refused_before_the_key")),
    ("the handle not bound to the registered key", [(Q, "        if c.key.as_ref().is_some_and(|k| *k != self.pk) {", "        if false && c.key.as_ref().is_some_and(|k| *k != self.pk) {")],
     T("word_negatives_refused_before_the_key")),
    ("pending selected without its index", [(Q, "        if *i != a.rolled + k as u64 || *e == [0; 32] {", "        if *e == [0; 32] {")],
     T("word_negatives_refused_before_the_key")),
    ("an unused blob accepted", [(Q, "    add_trivial(&mut c, shield_in);\n    blobs.done()?;", "    add_trivial(&mut c, shield_in);")],
     T("word_negatives_refused_before_the_key")),
    ("auditorMode NONE accepted", [(Q, "    if !matches!(lo_u64(&w, 21, 1)?, 1 | 2) {", "    if !matches!(lo_u64(&w, 21, 1)?, 0..=2) {")],
     T("entry_and_role_negatives_refused_before_the_key")),
    ("an auditor read of an entry without the copies", [(Q, "        if j >= self.m || (auditor && !self.aud) {", "        if j >= self.m {")],
     T("entry_and_role_negatives_refused_before_the_key")),
    ("the opened memo not compared with the entry", [(Q, "                if expect.as_ref().is_some_and(", "                if false && expect.as_ref().is_some_and(")],
     T("open_memo_binds_the_entry")),
    ("the units cap (K_MAX) not checked", [(Q, "let room = (K_MAX as u64).checked_sub(a.units + 1).ok_or(Error::Argument)?;", "let room = (K_MAX as u64).saturating_sub(a.units + 1);")],
     T("word_negatives_refused_before_the_key")),
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
