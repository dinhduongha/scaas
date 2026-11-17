#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d7, the MPC quorum's `checkProven` (C-PP-6; no-oracle spec §4.14.8, §4.14.4 step 4): each mutant undoes one
rule of the quorum's check (`clients/ua-rs/src/facade/pqz/proven.rs`) and names the test that must catch it
(`tests/facade_pqz_proof.rs`, feature `vectors`: the key-use counter). The plan names none; the round's own. One mutant per run
on a clean tree, its command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A
failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a
finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d7-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d7-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d7-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
P = R + "src/facade/pqz/proven.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
T = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "facade_pqz_proof"])

M = [
    ("a keyRecords entry of the quorum at the version checked taken (own or credit)",
     [(P, "let ours = |k: &[(Word, u64, Word)]| k.iter().any(|(u, v, _)| *u == o.ua && *v == o.v);",
       "let ours = |k: &[(Word, u64, Word)]| k.iter().any(|(u, v, _)| *u == o.ua && *v == o.v) && false;")], T),
    ("the own burn-form debit not verified", [(P, "            verify_p(form.op(), &stmt, &w.proof)\n", "            let _ = (stmt, &w.proof);\n            Ok(())\n")], T),
    ("the own transfer's pk_f a source's key, not the member's", [(P, "transfer_proven(o, rec, &o.ua, k, multi, hd, pk, &pks, pk_a.as_deref(), &t, &d, &tl, &e, &w.proof)",
       "transfer_proven(o, rec, &o.ua, k, multi, hd, pks.first().map_or(pk, |x| &x[..]), &pks, pk_a.as_deref(), &t, &d, &tl, &e, &w.proof)")], T),
    ("an unwrap's relayed binding taken verbatim", [(P, "if bc.binding == [0; 32] { w } else { crate::keccak256(&[bc.binding, w].concat()) }", "if bc.binding == [0; 32] { w } else { bc.binding }")], T),
    ("an unwrap's direct binding of another tag", [(P, 'crate::keccak256(b"SCAAS-PQZ-UNWRAP-V1")', 'crate::keccak256(b"SCAAS-ZETHER-UNWRAP-V1")')], T),
    ("a refresh's opTag BURN", [(P, "    let f = if bc.amount == 0 { Form::Refresh } else { Form::Burn };", "    let f = Form::Burn;")], T),
    ("a burn's memoHash without its tag", [(P, "    *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = crate::keccak256(&tl.own_tag);", "    *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = [0; 32];")], T),
    ("a credit checked twice", [(P, "let slot = o.need.get(&x.index).filter(|_| seen.insert(x.index)).ok_or(Error::Argument)?;", "let slot = o.need.get(&x.index).filter(|_| { seen.insert(x.index); true }).ok_or(Error::Argument)?;")], T),
    ("own missing taken", [(P, "        (false, false) => None,\n        _ => return Err(Error::Argument),", "        (false, false) => None,\n        _ => None,")], T),
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
