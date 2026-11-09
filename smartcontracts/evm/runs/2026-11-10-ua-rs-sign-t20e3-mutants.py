#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20e3, path (B)'s NONE call shapes against `ua-mtx-merge` T62a's `noneHeaders` rows: each mutant undoes one rule of
`clients/ua-rs/src/facade/pqz/proven.rs` (`transfer_header`, `burn_header`, `bind_mode`) or of the reader
`clients/ua-rs/src/bin/pqz-read.rs` (`envelope_binding`, `call_fee`) and names the test that must catch it
(`facade::pqz::proven::tests::none_headers_are_the_contracts`, `tests::none_header_rows_envelope_and_fee`). The plan's four (the
direct tag for a relayed binding, the unwrap binding unwrapped, the memo without the salt, the recipients hash over the legs in
another order) and the round's (the unbound relayer kept, the unbound fee recipient kept, the fee without the beneficiary rule,
`decoyFee` once instead of per leg, a refresh's amount check, op 7's tag on op 1). One mutant per run on a clean tree, its
command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a
build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e3-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e3-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e3-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
PR, RD = R + "src/facade/pqz/proven.rs", R + "src/bin/pqz-read.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
C = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
TF = (R, C + ["--lib", "none_headers_are_the_contracts"])
TR = (R, C + ["--bin", "pqz-read", "none_header_rows_envelope_and_fee"])

M = [
    ("the direct tag for a relayed binding", [(PR, 'let b = if *binding == [0; 32] { crate::keccak256(b"SCAAS-PQZ-DIRECT-MODE-V1") } else { *binding };',
                                               'let b = crate::keccak256(b"SCAAS-PQZ-DIRECT-MODE-V1"); let _ = binding;')], TF),
    ("the unwrap binding unwrapped", [(PR, "if bc.binding == [0; 32] { w } else { crate::keccak256(&[bc.binding, w].concat()) }",
                                       "if bc.binding == [0; 32] { w } else { bc.binding }")], TF),
    ("the memo without the salt", [(PR, "(Some(s), Mode::Hash) if s.len() + 16 == pqz_ffi::memo::memo_len(m) => [salt, s].concat(),",
                                    "(Some(s), Mode::Hash) if s.len() + 16 == pqz_ffi::memo::memo_len(m) => s.clone(),")], TF),
    ("the recipients hash over the legs reversed", [(PR, "crate::keccak256(&(0..m).map(|j| e.owner(j)).collect::<Result<Vec<_>>>()?.concat())",
                                                     "crate::keccak256(&(0..m).rev().map(|j| e.owner(j)).collect::<Result<Vec<_>>>()?.concat())")], TF),
    ("a refresh's amount check dropped", [(PR, "    if (form == OwnForm::Refresh) != (bc.amount == 0) {\n        return Err(Error::Argument);\n    }\n    let f = if bc.amount == 0",
                                           "    let f = if form == OwnForm::Refresh || bc.amount == 0")], TF),
    ("op 1 under op 7's header", [(PR, "if multi { Multi::header(&o.id, m, aud) } else { Debit::header(if aud { Form::Transfer } else { Form::Transfer0 }, &o.id) }",
                                   "if multi || m == 1 { Multi::header(&o.id, m, aud) } else { Debit::header(if aud { Form::Transfer } else { Form::Transfer0 }, &o.id) }")], TF),
    ("the unbound relayer kept", [(RD, "*mode, keep(1, relayer), *fee, keep(2, fee_to)]", "*mode, *relayer, *fee, keep(2, fee_to)]")], TR),
    ("the unbound fee recipient kept", [(RD, "*mode, keep(1, relayer), *fee, keep(2, fee_to)]", "*mode, keep(1, relayer), *fee, *fee_to]")], TR),
    ("the fee without the beneficiary rule", [(RD, "(if *beneficiary == [0; 32] { 0 } else { token_fee }).checked_add", "token_fee.checked_add")], TR),
    ("decoyFee once, not per leg", [(RD, "checked_add(m.checked_mul(decoy_fee)?)", "checked_add(decoy_fee + 0 * m)")], TR),
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
