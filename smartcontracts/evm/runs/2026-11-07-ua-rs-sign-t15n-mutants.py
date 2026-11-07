#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15n (CTR-UA-29, owner 2026-11-07): each mutant undoes one rule of the decoy selection (`ua-rs` `facade::decoys`,
the facades' `pickDecoys`, `pqz-read --command decoys`, `zether-read-balance --decoy-count` / `--decoy-keys`) and names the
test that must catch it. One mutant per run on a clean tree, its command, every file restored byte for byte after it (the
caller also runs `git diff --exit-code`). A failing command kills; a build that does not compile is NOT-LOADED (a finding); a
mutant whose command passes SURVIVED (a finding, exit 1). The CLIs run against a local anvil (`ANVIL`, default
~/.foundry/bin/anvil; killed by the tests).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15n-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15n-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15n-mutants.py count           (the number of mutants)
T15n2 (2026-11-07): M10, M11 and M12 follow the code's new text (the field list with `recipient`, `pick` through `draw`); the
record (-mutants.txt) is of the code at b08b8a0d. UNAUDITED."""
import os
import re
import subprocess
import sys

R, ZP = "clients/ua-rs/", "clients/zether-prover/"
D, QF, ZF = R + "src/facade/decoys.rs", R + "src/facade/pqz.rs", R + "src/facade/zether.rs"
B, Z = R + "src/bin/pqz-read.rs", ZP + "src/bin/zether-read-balance.rs"
CAPPED = os.path.abspath("scripts/capped")
ANVIL = os.environ.get("ANVIL", os.path.expanduser("~/.foundry/bin/anvil"))
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "ANVIL": ANVIL}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
L = (R, CT + ["--lib", "decoys"])
FP = (R, CT + ["--test", "facade_pqz", "pick_decoys"])
FZ = (R, CT + ["--test", "facade_zether", "pick_decoys"])
PR = (R, CT + ["--test", "pqz_read", "decoy", "--", "--include-ignored"])
ZR = (ZP, CT + ["--test", "read_balance", "decoy", "--", "--include-ignored"])

M = [
    # the pick (facade::decoys)
    ("an excluded UA drawn", [(D, ".filter(|(c, w)| *w > 0 && !exclude.contains(c))", ".filter(|(_, w)| *w > 0)")], L),
    ("weight 0 drawn", [(D, ".filter(|(c, w)| *w > 0 && !exclude.contains(c))", ".filter(|(c, _)| !exclude.contains(c))")], L),
    ("a candidate given twice accepted", [(D, "    if !candidates.iter().all(|c| seen.insert(*c)) {", "    if seen.insert([0u8; 32]) && false {")], L),
    ("too few not refused", [(D, "    if (pool.len() as u64) < count {", "    if false {")], L),
    ("not uniform: always the first", [(D, "                let hit = r < p.1;", "                let hit = true;")], L),
    ("drawn with replacement", [(D, "        out.push(pool.swap_remove(i).0);", "        out.push(pool.get(i).ok_or(Error::Argument)?.0);")], L),
    ("weights ignored", [(D, ".map_or(1, |w| u128::from(*w))", ".map_or(1, |_| 1)")], L),
    ("weights of another length accepted", [(D, "    if weights.is_some_and(|w| w.len() != candidates.len()) {", "    if false {")], L),
    ("no rejection sampling (modulo bias)", [(D, "        if x < zone {", "        if zone > 0 || x < zone {")], L),
    ("a field off the list accepted",
     [(D, '        if !o.keys().all(|k| ["candidates", "exclude", "count", "weights", "recipient"].contains(&k.as_str())) {', "        if false {")], L),
    ("a fixed seed instead of the OS CSPRNG",
     [(D, "        Ok(self.draw(&mut OsRng)?.to_string())",
       "        Ok(self.draw(&mut <rand_chacha::ChaCha20Rng as rand_chacha::rand_core::SeedableRng>::seed_from_u64(0))?.to_string())")], FP),
    # the facades
    ("PQZ: pickDecoys off the allow-list", [(QF, '        "pickDecoys" => has(&["candidates", "exclude", "count", "weights", "recipient"]),\n', "")], FP),
    ("Zether: pickDecoys not routed to the pick", [(ZF, '        if c.cmd == "pickDecoys" {', '        if c.cmd == "pickDecoys!" {')], FZ),
    # pqz-read --command decoys
    ("pqz-read: the sync point ignored", [(B, "    let sync = a.sync_block.unwrap_or(block);", "    let sync = a.sync_block.map_or(block, |_| block);")], PR),
    ("pqz-read: the list's length at the read block", [(B, "    let n = pin(sync)?.word(&a.registry,", "    let n = r.word(&a.registry,")], PR),
    ("pqz-read: --ua not excluded", [(B, "    exclude.push(a.ua);\n", "")], PR),
    ("pqz-read: --exclude ignored", [(B, "    let mut exclude = a.exclude.clone();", "    let mut exclude: Vec<Word> = Vec::new();")], PR),
    ("pqz-read: an unproven key accepted",
     [(B, "                Some((0, pk)) if rec[11] == 1 && pk.len() == PK_BYTES =>", "                Some((0, pk)) if pk.len() == PK_BYTES =>")], PR),
    ("pqz-read: no recency weight", [(B, "            let w = if moved(&mid, &r, &base)? { 2 } else", "            let w = if moved(&mid, &r, &base)? { 1 } else")], PR),
    ("pqz-read: holder counts every activity", [(B, '            if a.filter.as_deref() == Some("holder") || debit {', "            if debit {")], PR),
    ("pqz-read: a window below 2 accepted", [(B, "let old = block.checked_sub(w).filter(|_| w >= 2).ok_or(", "let old = block.checked_sub(w).ok_or(")], PR),
    ("pqz-read: the blocks not re-checked", [(B, "    for (n, h) in &pins {\n        recheck(url, *n, h)?;", "    for (n, h) in &pins {\n        let _ = (url, n, h);")], PR),
    ("pqz-read: a sync point past the read block", [(B, "    if sync > block {\n        return Err(\"--sync-block is past", "    if sync > block + 1 {\n        return Err(\"--sync-block is past")], PR),
    ("pqz-read: decoy flags with another command", [(B, '    if decoy && a.command != "decoys" {', "    if false {")], PR),
    # zether-read-balance --decoy-count / --decoy-keys
    ("zether: the list's length at the read block", [(Z, "    let n = pin(sync)?.word(registry,", "    let n = r.word(registry,")], ZR),
    ("zether: a decoy past the sync point's count", [(Z, "rec[30..] == [0x01, 0x41] && index < n && r.word(", "rec[30..] == [0x01, 0x41] && r.word(")], ZR),
    ("zether: another kind's record", [(Z, "rec[30..] == [0x01, 0x41] && index < n && r.word(", "index < n && r.word(")], ZR),
    ("zether: UA(Y) not compared", [(Z, ".ok().filter(|p| zether_prover::curve::ua_of::<Bls12381>(p) == *ua),", ".ok(),")], ZR),
    ("zether: --exclude ignored", [(Z, "            if !candidates.contains(&u) && !exclude.contains(&u) {", "            if !candidates.contains(&u) {")], ZR),
    ("zether: holder counts every move", [(Z, 'Ok(if a.filter.as_deref() == Some("holder") { sent(&x) != sent(&y) } else { x != y })', "Ok(x != y || sent(&x) != sent(&y))")], ZR),
    ("zether: no recency weight", [(Z, "                let w = if moved(&mid, &r, &slot)? { 2 } else", "                let w = if moved(&mid, &r, &slot)? { 1 } else")], ZR),
    ("zether: the blocks not re-checked", [(Z, "    for (b, h) in &pins {\n        recheck(url, *b, h)?;", "    for (b, h) in &pins {\n        let _ = (url, b, h);")], ZR),
    ("zether: --decoy-count without --exclude", [(Z, "a.decoy_keys.is_none() && a.exclude.is_some() && ", "a.decoy_keys.is_none() && ")], ZR),
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
