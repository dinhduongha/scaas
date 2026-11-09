#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d4, path (B)'s `balanceProven` (C-PP-2; no-oracle spec §4.14.2–§4.14.4): each mutant undoes one rule of the
session or of a part's check (`clients/ua-rs/src/facade/pqz/proven.rs`) and names the test that must catch it
(`tests/facade_pqz_proof.rs`, feature `vectors`: the key-use counter). The plan's nine, then the round's own. One mutant per run
on a clean tree, its command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A
failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a
finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d4-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d4-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d4-mutants.py count           (the number of mutants)
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
    # the plan's
    ("the leg paired with another group's u (the slot's uOff taken)",
     [(P, "let (u_off, v_off) = (16 + PKP * (j / legs_per_group(aud)), e.leg_at(j));", "let (u_off, v_off) = (slot.u_off, e.leg_at(j));")], T),
    ("the proof check skipped",
     [(P, "        if pqz_ffi::precompile(&pqz_ffi::stmt::input(op, &stmt, proof)) != Ok(pqz_ffi::VALID) {\n            return Err(Error::Argument);\n        }\n", "        let _ = (op, proof);\n")], T),
    ("pk at the holder's leg from the source, not the handle's",
     [(P, "pks.push(if j == l.j { self.pk.clone() } else {", "pks.push(if j == usize::MAX { self.pk.clone() } else {")], T),
    ("kv ignored: the auditor's key at version 0",
     [(P, "key(&o.auditor_ua, *l.t.kv.get(m).ok_or(Error::Argument)?)?", "key(&o.auditor_ua, 0)?")], T),
    ("the credited (u, v) not compared with the pending slot",
     [(P, "    if (slot.u_off, slot.v_off) != (u_off, v_off) {\n        return Err(Error::Argument);\n    }\n", "")], T),
    ("the own v_f's tag check skipped",
     [(P, "            if !bool::from(want.ct_eq(tag)) {\n                return Err(Error::Argument);\n            }\n", "            let _ = (want, tag);\n")], T),
    ("the parts' bound off by one",
     [(P, "if (p - p_last) + u64::from(own.is_some()) + 1 > K_MAX as u64 {", "if (p - p_last) + u64::from(own.is_some()) > K_MAX as u64 {")], T),
    ("a TRIVIAL amount from the wrong bits", [(P, "        Ok(lo_u64(e, 12, 8)?)", "        Ok(lo_u64(e, 4, 8)?)")], T),
    ("a migration credit taken without re-encryption",
     [(P, "if bool::from(enc.0.u[..].ct_eq(u) & v_eq) && coeffs_ok(&ct) {", "if coeffs_ok(&ct) {")], T),
    # the round's own
    ("a migration re-encrypted from another version's seed",
     [(P, "let (account, index, v) = (self.account, self.index, rec.key_version);", "let (account, index, v) = (self.account, self.index, rec.key_version + 1);")], T),
    ("balanceProven before every need index is accepted",
     [(P, "        if !s.open.need.keys().all(|i| s.accepted.contains(i)) {\n            return Err(Error::Argument);\n        }\n", "")], T),
    ("an index accepted twice",
     [(P, "                Some((ct, kind)) if s.accepted.insert(c.index) => {", "                Some((ct, kind)) => {\n                    s.accepted.insert(c.index);")], T),
    ("the record's mode not tied to header or call",
     [(P, "        if (rec.proof_store == 1) != c.header.is_some() {\n            return Err(Error::Argument);\n        }\n", "")], T),
    ("T_k without Trivial(shieldIn)", [(P, "    add_trivial_mod(&mut c, rec.shield_in);\n", "")], T),
    ("T_k without the predecessor's (u, v_f)", [(P, "    if rec.has_prev {", "    if false && rec.has_prev {")], T),
    ("a credit without P's fields refused alone (the whole call is Argument)",
     [(P, "        let verdicts = credits.iter().map(|c| self.check_credit(&s.open, &s.accepted, c, &mut blobs)).collect::<Result<Vec<_>>>()?;",
       "        let verdicts: Vec<_> = credits.iter().map(|c| self.check_credit(&s.open, &s.accepted, c, &mut blobs).ok().flatten()).collect();")], T),
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
