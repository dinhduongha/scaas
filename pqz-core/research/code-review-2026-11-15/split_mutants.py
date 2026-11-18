#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# split.rs mutants (review 3w-delta U1h-2): each applied alone, the split test run, the source restored
# usage (from the repo root, under scripts/capped): python3 -I <this> pqz-core/pqzl <log> [M1,M2,...]; restores each source after its run
import os, pathlib, subprocess, sys

root = pathlib.Path(sys.argv[1])  # pqz-core/pqzl
log = pathlib.Path(sys.argv[2])
M = [
    (
        "M1 rust generic: u_f rows dropped",
        "rust/src/rel.rs",
        "    for g in 0..h.groups {\n        for i in 0..K {\n            s.lin_row(true",
        "    for g in 0..h.groups.min(if h.split { 1 } else { h.groups }) {\n        for i in 0..K {\n            s.lin_row(true",
        "generic-only",
    ),
    (
        "M2 rust generic: v_f rows dropped on split",
        "rust/src/rel.rs",
        "        s.evaleq(Some(&mut t.pkf), 2 * K + 2 * K * fg, i, i, Some(h.e2f), &mut acc, rhs)?;",
        "        if !h.split { s.evaleq(Some(&mut t.pkf), 2 * K + 2 * K * fg, i, i, Some(h.e2f), &mut acc, rhs)?; }",
        "generic-only",
    ),
    (
        "M3 rust sv: v_f under group 0",
        "rust/src/sv.rs",
        "ox: 2 * NPK + 2 * NPK * usize::from(s.split), win: 0, e2: Some(e2f) }",
        "ox: 2 * NPK, win: 0, e2: Some(e2f) }",
        "test-hooks",
    ),
    (
        "M4 C generic: u_f rows dropped",
        "src/pqz_rel.c",
        "  for (g = 0; g < H.groups; g++)\n    for (i = 0; i < K; i++)\n      add_lin_row",
        "  for (g = 0; g < (H.split ? 1u : H.groups); g++)\n    for (i = 0; i < K; i++)\n      add_lin_row",
        "test-hooks,c-oracle",
    ),
    (
        "M5 C sv: v_f under group 0",
        "src/pqz_sv.c",
        "S->pr[k].ox = 2 * NPK + 2 * NPK * S->split, S->pr[k].e2 = (int)e2f",
        "S->pr[k].ox = 2 * NPK, S->pr[k].e2 = (int)e2f",
        "test-hooks,c-oracle",
    ),
]
out = []
sel = sys.argv[3].split(",") if len(sys.argv) > 3 else None
for name, f, a, b, feat in M:
    if sel and name.split()[0] not in sel:
        continue
    p = root / f
    src = p.read_text()
    assert src.count(a) == 1, name
    p.write_text(src.replace(a, b))
    try:
        args = (
            ["--no-default-features", "--features", f"set-{os.environ.get('PQZ_SET', 'n2304-kmax4096')},test-hooks"]
            if feat == "generic-only"
            else ["--features", feat]
        )
        r = subprocess.run(
            ["cargo", "test", "-j2", "--release", "--offline", *args, "--test", "split", "--", "--test-threads=1"],
            cwd=root / "rust",
            capture_output=True,
            text=True,
        )
    finally:
        p.write_text(src)
    txt = r.stdout + r.stderr
    with log.open("a") as fh:
        fh.write(f"===== {name}\n{txt}\n")
    fails = [l for l in txt.splitlines() if l.startswith("test ") and l.endswith("FAILED")]
    pan = [
        l
        for l in txt.splitlines()
        if "panicked" in l or l.strip().startswith(("left:", "right:")) or "failed:" in l or ": a cheating proof" in l
    ][:12]
    line = f"{name}: rc {r.returncode}, {'RED' if r.returncode else 'GREEN (mutant survived)'}; failed: {[l.split()[1] for l in fails]}"
    print(line, *pan, sep="\n  ", flush=True)
    out.append(r.returncode != 0)
print(f"mutants red: {sum(out)}/{len(out)}")
sys.exit(0 if all(out) else 1)
