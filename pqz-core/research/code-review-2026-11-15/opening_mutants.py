#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# opening.rs mutants (review 3w-delta U2-2; Se*: the seal-side seed_enc guard): each applied alone, the opening test run, the source restored
# usage (from the repo root, under scripts/capped): python3 -I <this> pqz-core/ffi <log>; restores the source after each run
# A hung run (owner 2026-11-24, scripts/mutant_guard.py): past 3 x its unmutated baseline (at least 10 min, or `--timeout N`)
# its process group is killed and it reads `killed (timeout N s)`; the source is restored on every exit (SIGINT / SIGTERM
# too); a target file that differs from HEAD refuses the run.
import sys, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
import mutant_guard as guard  # noqa: E402

root = pathlib.Path(sys.argv[1])  # pqz-core/ffi
log = pathlib.Path(sys.argv[2])
F = "src/opening.rs"
M = [
    (
        "Ma check_auditor: last outcome Unreadable -> RecipientUnreadable",
        "        _ => AuditorOutcome::Unreadable,\n    }",
        "        _ => AuditorOutcome::RecipientUnreadable,\n    }",
    ),
    (
        "Mb open: length checks removed",
        "    if p.opening.len() != OPENING || p.kem_pk.len() != KEM_PK {\n        return None;\n    }\n    let (ct, rest)",
        "    let (ct, rest)",
    ),
    (
        "Mc seal: kemPk length check removed",
        "    if kem_pk.len() != KEM_PK || kem_pk[0] != 1 {",
        "    if kem_pk[0] != 1 {",
    ),
    (
        "Md seal: scheme check removed",
        "    if kem_pk.len() != KEM_PK || kem_pk[0] != 1 {",
        "    if kem_pk.len() != KEM_PK {",
    ),
    (
        "Se1 Sealer: fingerprint comparison removed",
        "            Some(f) if *f != fp => return Err(SealError::SeedReused),",
        "            Some(f) if false && *f != fp => return Err(SealError::SeedReused),",
    ),
    (
        "Se2 Sealer: evicts when full instead of refusing",
        "            None if self.seen.len() >= SEALER_CAP => return Err(SealError::Full),",
        "            None if self.seen.len() >= SEALER_CAP => self.seen.clear(),",
    ),
    (
        "Se3 Sealer: seed_leg not the credit's (another UA)",
        "        let mut seed_leg = leg_seed(seed_enc, c.to.ua, c.to.pk);",
        "        let mut seed_leg = leg_seed(seed_enc, &[0u8; 32], c.to.pk);",
    ),
    (
        "Se4 fingerprint without the sender's own u_f, v_f (F-2)",
        "&aud, &pack(&own_u[..]), &pack(&own_v[..])])",
        "&aud])",
    ),
    (
        "Se5 fingerprint without the key versions (F-2)",
        "[&p.ua[..], &p.key_version.to_be_bytes(), &keccak",
        "[&p.ua[..], &keccak",
    ),
    (
        "Se6 fingerprint with the recipient's UA for the auditor's (F-2)",
        "let aud = c.auditor.map(|a| party(&a)).unwrap_or_default();",
        "let aud = c.auditor.map(|a| party(&Party { ua: c.to.ua, ..a })).unwrap_or_default();",
    ),
    (
        "Se7 no check that seed_enc gives the credit's u (F-8)",
        "        let out = if gives_u { seal(role, c, &p, &seed_leg) } else { None };",
        "        let out = if gives_u || true { seal(role, c, &p, &seed_leg) } else { None };",
    ),
]
out = []
guard.refuse_dirty([root / F], root)
for name, a, b in M:
    p = root / F
    src = p.read_text()
    assert src.count(a) == 1, name
    cmd = ["cargo", "test", "-j2", "--release", "--offline", "--features", "prove", "--test", "opening"]
    lim, saved = guard.limit(cmd, cwd=root), {p: p.read_bytes()}
    try:
        p.write_text(src.replace(a, b))
        r = guard.run(cmd, lim, cwd=root, capture_output=True, text=True)
    finally:
        guard.restore(saved)
    txt = r.stdout + r.stderr
    with log.open("a") as fh:
        fh.write(f"===== {name}\n{txt}\n")
    fails = [l.split()[1] for l in txt.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
    pan = [l for l in txt.splitlines() if "panicked" in l or "failed:" in l][:6]
    print(
        f"{name}: rc {r.returncode}, {guard.outcome(r, 'RED') if r.returncode else 'GREEN (mutant survived)'}; failed: {fails}",
        *pan,
        sep="\n  ",
        flush=True,
    )
    out.append(r.returncode != 0)
print(f"mutants red: {sum(out)}/{len(out)}")
sys.exit(0 if all(out) else 1)
