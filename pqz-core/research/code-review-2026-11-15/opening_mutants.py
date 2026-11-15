#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# opening.rs mutants (review 3w-delta U2-2): each applied alone, the opening test run, the source restored
# usage (from the repo root, under scripts/capped): python3 -I <this> pqz-core/ffi <log>; restores the source after each run
import subprocess, sys, pathlib
root = pathlib.Path(sys.argv[1])  # pqz-core/ffi
log = pathlib.Path(sys.argv[2])
F = "src/opening.rs"
M = [
 ("Ma check_auditor: last outcome Unreadable -> RecipientUnreadable",
  "        _ => AuditorOutcome::Unreadable,\n    }", "        _ => AuditorOutcome::RecipientUnreadable,\n    }"),
 ("Mb open: length checks removed",
  "    if p.opening.len() != OPENING || p.kem_pk.len() != KEM_PK {\n        return None;\n    }\n    let (ct, rest)",
  "    let (ct, rest)"),
 ("Mc seal: kemPk length check removed", "    if kem_pk.len() != KEM_PK || kem_pk[0] != 1 {", "    if kem_pk[0] != 1 {"),
 ("Md seal: scheme check removed", "    if kem_pk.len() != KEM_PK || kem_pk[0] != 1 {", "    if kem_pk.len() != KEM_PK {"),
]
out = []
for name, a, b in M:
    p = root / F
    src = p.read_text()
    assert src.count(a) == 1, name
    p.write_text(src.replace(a, b))
    try:
        r = subprocess.run(["cargo", "test", "-j2", "--release", "--offline", "--features", "prove", "--test", "opening"],
                           cwd=root, capture_output=True, text=True)
    finally:
        p.write_text(src)
    txt = r.stdout + r.stderr
    with log.open("a") as fh:
        fh.write(f"===== {name}\n{txt}\n")
    fails = [l.split()[1] for l in txt.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
    pan = [l for l in txt.splitlines() if "panicked" in l or "failed:" in l][:6]
    print(f"{name}: rc {r.returncode}, {'RED' if r.returncode else 'GREEN (mutant survived)'}; failed: {fails}", *pan, sep="\n  ", flush=True)
    out.append(r.returncode != 0)
print(f"mutants red: {sum(out)}/{len(out)}")
sys.exit(0 if all(out) else 1)
