#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# wipe.rs mutants (review 3w-delta U1h-1, 3zh Fable F-10): each applied alone, tests/wipe.rs run, the source restored.
# usage (from the repo root, under scripts/capped): python3 -I <this> pqz-core/pqzl <log>
# A hung run (owner 2026-11-24, scripts/mutant_guard.py): past 3 x its unmutated baseline (at least 10 min, or `--timeout N`)
# its process group is killed and it reads `killed (timeout N s)`; the source is restored on every exit (SIGINT / SIGTERM
# too); a target file that differs from HEAD refuses the run.
import pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[3] / "scripts"))
import mutant_guard as guard  # noqa: E402

root = pathlib.Path(sys.argv[1])
log = pathlib.Path(sys.argv[2])
M = [
    (
        "W-a z3v replaced in place (U1h-1)",
        "rust/src/proof/tbox.rs",
        "            z3v = Wiped(coeffs_i64(&mut y3)?);",
        "            *z3v = coeffs_i64(&mut y3)?;",
    ),
    (
        "W-b z4v replaced in place (U1h-1)",
        "rust/src/proof/tbox.rs",
        "            z4v = Wiped(coeffs_i64(&mut y4)?);",
        "            *z4v = coeffs_i64(&mut y4)?;",
    ),
    (
        "W-c IntVec's wipe empty (the rejection steps' copies)",
        "rust/src/arith/int.rs",
        "impl crate::Wipe for IntVec {\n    fn wipe(&mut self) {\n        crate::wipe(&mut self.w[..]);",
        "impl crate::Wipe for IntVec {\n    fn wipe(&mut self) {\n        let _ = &mut self.w;",
    ),
    (
        "W-d PolyVec's wipe empty (masks, images, s1 / m / s2)",
        "rust/src/lib.rs",
        "impl Wipe for arith::polyvec::PolyVec {\n    fn wipe(&mut self) {\n        wipe(&mut self[..]);",
        "impl Wipe for arith::polyvec::PolyVec {\n    fn wipe(&mut self) {\n        let _ = &mut self[..];",
    ),
]
out = []
guard.refuse_dirty([root / m[1] for m in M], root)
for name, f, a, b in M:
    p = root / f
    src = p.read_text()
    assert src.count(a) == 1, name
    cmd = ["cargo", "test", "-j2", "--release", "--offline", "--features", "test-hooks", "--test", "wipe"]
    lim, saved = guard.limit(cmd, cwd=root / "rust"), {p: p.read_bytes()}
    try:
        p.write_text(src.replace(a, b))
        r = guard.run(cmd, lim, cwd=root / "rust", capture_output=True, text=True)
    finally:
        guard.restore(saved)
    txt = r.stdout + r.stderr
    with log.open("a") as fh:
        fh.write(f"===== {name}\n{txt}\n")
    fails = [l.split()[1] for l in txt.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
    pan = [l for l in txt.splitlines() if "without being cleared" in l][:2]
    print(
        f"{name}: rc {r.returncode}, {guard.outcome(r, 'RED') if r.returncode else 'GREEN (mutant survived)'}; failed: {fails}",
        *pan,
        sep="\n  ",
        flush=True,
    )
    out.append(r.returncode != 0)
print(f"mutants red: {sum(out)}/{len(out)}")
sys.exit(0 if all(out) else 1)
