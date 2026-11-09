#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20e1, `PayMeta` v3 (ua-mtx-merge T83): each mutant undoes one rule of `clients/ua-rs/src/pay.rs`, `src/json.rs`
or `src/wallet/policy.rs` and names the test that must catch it (`tests/pay.rs` with feature `json`, `tests/wallet_typed.rs`).
The plan's eight and two of the round's (the JSON's `payNoUuid`, the policy's `save`). One mutant per run on a clean tree, its
command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a
build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e1-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e1-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e1-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
PAY, JSON, POL = R + "src/pay.rs", R + "src/json.rs", R + "src/wallet/policy.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
C = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
TP = (R, C + ["--features", "json", "--test", "pay"])
TW = (R, C + ["--test", "wallet_typed"])

M = [
    ("the v2 tag", [(PAY, 'b"scaas.pay.meta.v3", &m.salt', 'b"scaas.pay.meta.v2", &m.salt')], TP),
    ("save outside the commitment", [(PAY, "&word(m.save as u64), &word(m.schema as u64)", "&word(0), &word(m.schema as u64)")], TP),
    ("save with payNo 0 accepted", [(PAY, " || (m.save && m.pay_no == [0; 32])", "")], TP),
    ("payNo left-aligned by the UUID helper", [(PAY, "for (i, b) in w.iter_mut().skip(16).enumerate() {",
                                                "for (i, b) in w.iter_mut().enumerate() {")], TP),
    ("a version-4 UUID accepted", [(PAY, "w[22] >> 4 == 7", "w[22] >> 4 >= 4")], TP),
    ("the UUID shown for a payNo with a high byte set", [(PAY, "    w[..16] == [0; 16] && w[22]", "    w[22]")], TP),
    ("a v3 pay selector missing from the never-called list",
     [(POL, '        "payWithTax(bytes32,uint256,uint8,uint256,bytes32,(bytes32,bytes32,bool,uint16,bytes))",\n', "")], TW),
    ("a paymentsOf return with trailing bytes accepted", [(PAY, "ret.len() != n.checked_mul(96)?.checked_add(64)?",
                                                          "ret.len() < n.checked_mul(96)?.checked_add(64)?")], TP),
    ("payNoUuid not shown by the JSON", [(JSON, '"payNoUuid": pay_no_to_uuid(&pay_no),', '"payNoUuid": Value::Null,')], TP),
    ("the policy drops save", [(POL, '    let save = m.flag("save")?;', '    let save = m.flag("save")? && false;')], TW),
    ("amount at 2^192 accepted", [(PAY, "(amount[..8] == [0; 8] && block[..24] == [0; 24])", "(block[..24] == [0; 24])")], TP),
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
