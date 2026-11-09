#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d10, the round's mutants over T20d2-T20d9 (C-PP-9; no-oracle spec §4.14, §5): each mutant undoes one rule
that keeps path (B) from being a decryption oracle (ARCH-POS-13), the leg / group pairing among them (Fable P2-3), and names
the test that must catch it: `clients/ua-rs/tests/no_oracle.rs` (feature `vectors`) `proof_path_refuses_the_fabricated_words_attack`
and `proof_path_negatives`, `tests/facade_pqz_proof.rs` `op7_leg_paired_with_its_own_group`, and through the C ABI ua-py
`Pqz.test_no_oracle_proof_path` (the release ua-c, rebuilt after the run). The per-task harnesses (t20d2, t20d4-t20d8) keep
their own; a rule both name is run again here against the oracle tests. One mutant per run on a clean tree, its command, every
file restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that does
not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d10-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d10-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d10-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
P = R + "src/facade/pqz/proven.rs"
F = R + "src/facade/pqz.rs"
C = "clients/ua-c/src/lib.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors"]
T = (R, CARGO + ["--test", "no_oracle", "proof_path"])
T7 = (R, CARGO + ["--test", "facade_pqz_proof", "op7_leg_paired_with_its_own_group"])
BUILD = [CAPPED, "cargo", "build", "--release", "--locked", "--offline", "-j2", "--manifest-path", "clients/ua-c/Cargo.toml"]
PY = (".", ["sh", "-c", " ".join(BUILD) + " && cd clients/ua-py && python3 -m unittest -v tests.test_wallet.Pqz.test_no_oracle_proof_path"])

M = [
    ("path (B)'s P not verified", [(P, "    if pqz_ffi::precompile(&pqz_ffi::stmt::input(op, stmt, proof)) != Ok(pqz_ffi::VALID) {\n        return Err(Error::Argument);\n    }\n",
       "    let _ = (op, stmt, proof);\n")], T),
    ("the own v_f taken without its tag", [(P, "            if !bool::from(want.ct_eq(tag)) {", "            if false && !bool::from(want.ct_eq(tag)) {")], T),
    ("a migration credit taken without its re-encryption", [(P, "        if bool::from(enc.0.u[..].ct_eq(u) & v_eq) && coeffs_ok(&ct) {",
       "        if (bool::from(enc.0.u[..].ct_eq(u) & v_eq) || true) && coeffs_ok(&ct) {")], T),
    ("balanceProven answers a session that lacks a credit", [(P, "        if !s.open.need.keys().all(|i| s.accepted.contains(i)) {",
       "        if false && !s.open.need.keys().all(|i| s.accepted.contains(i)) {")], T),
    ("a slot not the leg's position taken", [(P, "    if (slot.u_off, slot.v_off) != (u_off, v_off) {", "    if false && (slot.u_off, slot.v_off) != (u_off, v_off) {")], T),
    ("the leg's u always group 0's (the pairing)", [(P, "    let (u_off, v_off) = (16 + PKP * (j / legs_per_group(aud)), e.leg_at(j));",
       "    let (u_off, v_off) = (16 + PKP * (j / legs_per_group(aud)) * 0, e.leg_at(j));")], T7),
    ("a credit's non-canonical coefficient taken", [(P, "    let ct = load(&d, l.u_off, l.v_off)?;\n    if !coeffs_ok(&ct) {",
       "    let ct = load(&d, l.u_off, l.v_off)?;\n    if false && !coeffs_ok(&ct) {")], T),
    ("the account's units past K_MAX taken", [(P, "    let room = (K_MAX as u64).checked_sub(a.units + 1).ok_or(Error::Argument)?;",
       "    let room = (K_MAX as u64).saturating_sub(a.units + 1);")], T),
    ("the quorum's refused credit dropped, not the check", [(P, "        let ct = by_proof(&c.pk, o, &rec, x, slot, &mut blobs)?.ok_or(Error::Argument)?;",
       "        let ct = by_proof(&c.pk, o, &rec, x, slot, &mut blobs)?.unwrap_or_default();")], T),
    ("checkProven's allow-list off", [(F, '    if !v.keys().all(|k| allowed("checkProven", k)) {', '    if false && !v.keys().all(|k| allowed("checkProven", k)) {')], T),
    ("provenOpen's allow-list off", [(F, '        "provenOpen" => has(LOC) || has(ACCT) || has(&["forOp7", "lastRecord", "auditorUA", "chainId", "registry"]),',
       '        "provenOpen" => true,')], T),
    ("provenAdd's allow-list off", [(F, '        "provenAdd" => has(&["session", "blobs", "credits"]),', '        "provenAdd" => true,')], T),
    ("the C ABI's quorum check answers a refusal", [(C, "return write_str(out_json, out_len, &ua::facade::pqz::check_proven(cstr(request_json)?)?);",
       "return write_str(out_json, out_len, &ua::facade::pqz::check_proven(cstr(request_json)?).unwrap_or_default());")], PY),
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
if any(f == C for _, reps, _ in M[lo - 1:hi] for f, _, _ in reps):
    r = subprocess.run(BUILD, capture_output=True, text=True, env={**os.environ, **ENV})
    print(f"rebuild of the release ua-c at the restored tree: rc={r.returncode}", flush=True)
    bad += r.returncode != 0
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
