#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20e2, the service-pull builder (T80, CLI-SGN-48): each mutant undoes one rule of
`clients/ua-rs/src/wallet/service_pull.rs` or its EIP-712 helpers (`src/wallet/eip712.rs`) and names the test that must catch it
(`tests/service_pull.rs`). The plan's (the payer check, the chain check, the 16-field cap, an array field, a nested struct,
`entryRef` over the struct hash, a dynamic field hashed in the calldata, the relayer not the service, the fee at the pull's own
nonce) and the round's (`int` accepted, a missing field accepted, the first field unchecked, a zero amount, the router as target,
the op tuple's parentheses lost in the selector). One mutant per run on a clean tree, its command, every file restored byte for
byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that does not compile is
NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e2-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e2-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-10-ua-rs-sign-t20e2-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
SP, EIP = R + "src/wallet/service_pull.rs", R + "src/wallet/eip712.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
T = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--test", "service_pull"])

M = [
    ("the payer check dropped", [(SP, '    if word_of("bytes32", mo.get("payer"))? != from {', '    if word_of("bytes32", mo.get("payer"))? == [7; 32] {')], T),
    ("the chain check dropped", [(SP, '    if word_of("uint256", d.get("chainId"))? != u256_from(chain_id) {',
                                  '    if word_of("uint256", d.get("chainId"))? == [7; 32] && chain_id == 0 {')], T),
    ("the 16-field cap off by one", [(SP, "const MAX_OP_FIELDS: usize = 16;", "const MAX_OP_FIELDS: usize = 17;")], T),
    ("an array field accepted", [(EIP, "    atom(ty) && int_bits(ty).is_none()", "    (atom(ty) || ty.ends_with(\"[]\")) && int_bits(ty).is_none()")], T),
    ("a nested struct accepted", [(SP, " || op.struct_count() != 1 ||", " || op.struct_count() == 0 ||"),
                                  (EIP, "    atom(ty) && int_bits(ty).is_none()", "    (atom(ty) || ty == \"Inner\") && int_bits(ty).is_none()")], T),
    ("entryRef over the struct hash", [(SP, "    let entry_ref = op.digest()?;", "    let entry_ref = op.struct_hash()?;")], T),
    ("a string hashed in the calldata", [(EIP, '("string", Some(Value::String(s))) => Ok(Abi::Raw(s.as_bytes().to_vec())),',
                                          '("string", Some(Value::String(s))) => Ok(Abi::Word(keccak256(s.as_bytes()))),')], T),
    ("the relayer not the service", [(SP, '"mode": MODE_RESTRICT_RELAYER, "relayer": to_hex(&service),',
                                      '"mode": MODE_RESTRICT_RELAYER, "relayer": super::eip712::ZERO_ADDRESS,')], T),
    ("the fee at the pull's own nonce accepted", [(SP, "&& nonce == uint_value(t.get(\"nonce\"))? {", "&& nonce == [7; 32] {")], T),
    ("an int field accepted", [(EIP, "    atom(ty) && int_bits(ty).is_none()", "    atom(ty)")], T),
    ("a missing field accepted", [(SP, "    if mo.len() != fields.len() || fields.iter().any(|(n, _)| get(&m, n).is_none()) {",
                                   "    if mo.len() > fields.len() {")], T),
    ("the first field unchecked", [(SP, '    if fields.first().is_none_or(|(n, t)| n != "payer" || t != "bytes32") {',
                                    '    if fields.is_empty() {')], T),
    ("a zero amount accepted", [(SP, "    if value == [0; 32] {\n        return Err(Error::Argument);\n    }\n    let entry_ref",
                                 "    let entry_ref")], T),
    ("the router as the target accepted", [(SP, "if self.service == router || self.service == executor || value == [0; 32] {",
                                            "if self.service == executor || value == [0; 32] {")], T),
    ("the op tuple's parentheses lost", [(SP, 'format!("{entry}(({types}),{UMT},{UASIG})")', 'format!("{entry}({types},{UMT},{UASIG})")')], T),
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
