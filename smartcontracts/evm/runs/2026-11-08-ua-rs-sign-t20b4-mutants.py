#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20b (owner 2026-11-08): the reference readers read from several named nodes, failover by default, a strict
majority with `--rpc-agree`. Each mutant undoes one rule (the majority's words, the majority's size, the whole-read comparison,
the R3 re-check of every majority node, the failover order, the smallest block number, one node named once) and names the
test that must catch it. One mutant per run on a clean tree, its command, every file restored byte for byte after it (the
caller also runs `git diff --exit-code`). A failing command kills; a build that does not compile is NOT-LOADED (a finding); a
mutant whose command passes SURVIVED (a finding, exit 1). The reading-layer tests run against a local anvil (`ANVIL`, default
~/.foundry/bin/anvil; killed by the tests) behind proxies.
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b4-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b4-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b4-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, ZP = "clients/ua-rs/", "clients/zether-prover/"
B, ZB = R + "src/bin/pqz-read.rs", ZP + "src/bin/zether-read-balance.rs"
CAPPED = os.path.abspath("scripts/capped")
ANVIL = os.environ.get("ANVIL", os.path.expanduser("~/.foundry/bin/anvil"))
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "ANVIL": ANVIL,
       "PATH": os.path.dirname(ANVIL) + os.pathsep + os.environ.get("PATH", "")}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
PR = (R, CT + ["--test", "pqz_read", "--", "--include-ignored"])
RB = (ZP, CT + ["--test", "read_balance", "--", "--include-ignored"])

M = [
    # pqz-read
    ("pqz-read: the minority's words used", [(B, "let best = (0..got.len()).max_by_key(", "let best = (0..got.len()).min_by_key(")], PR),
    ("pqz-read: half the nodes suffice (a 2-2 split accepted)", [(B, "    a.rpc.len() / 2 + 1\n", "    a.rpc.len() / 2\n")], PR),
    ("pqz-read: agreement on the block only, not the whole read",
     [(B, "    let (w, members) = agree(&urls, majority(a), |url| read(a, url, Some(n), pk))?;",
       "    let (w, members) = agree(&urls, majority(a), |url| read(a, url, Some(n), pk).map(|w| (w.block, w.hash)))?;\n    let w = read(a, &a.rpc[0], Some(n), pk)?;")], PR),
    ("pqz-read: the R3 re-check on the first node only", [(B, "    rechecked(&members, &[(w.block, w.hash.clone())], majority(a))?;",
                                                            "    rechecked(&members[..1], &[(w.block, w.hash.clone())], 1)?;")], PR),
    ("pqz-read: failover from the last node", [(B, "    for url in &a.rpc {\n        match read(url) {", "    for url in a.rpc.iter().rev() {\n        match read(url) {")], PR),
    ("pqz-read: the largest block number", [(B, "a.rpc.iter().filter_map(|u| chosen(a, u).ok()).min()", "a.rpc.iter().filter_map(|u| chosen(a, u).ok()).max()")], PR),
    ("pqz-read: one node named twice", [(B, "                if a.rpc.contains(&u) {", "                if false {")], PR),
    # zether-read-balance
    ("zether-read-balance: the minority's words used", [(ZB, "let best = got.iter().max_by_key(|g| count(&g.1))", "let best = got.iter().min_by_key(|g| count(&g.1))")], RB),
    ("zether-read-balance: half the nodes suffice", [(ZB, "    let need = a.rpc.len() / 2 + 1;", "    let need = a.rpc.len() / 2;")], RB),
    ("zether-read-balance: agreement on the block only, not the whole read",
     [(ZB, "    let count = |r: &Pinned| got.iter().filter(|g| g.1 == *r).count();", "    let count = |r: &Pinned| got.iter().filter(|g| g.1 .1 == r.1).count();"),
      (ZB, "    let members: Vec<&str> = got.iter().filter(|g| g.1 == best.1).map(|g| g.0).collect();",
       "    let members: Vec<&str> = got.iter().filter(|g| g.1 .1 == best.1 .1).map(|g| g.0).collect();")], RB),
    ("zether-read-balance: the R3 re-check skipped", [(ZB, "    if members.iter().filter(|u| best.1 .1.iter().all(|(b, h)| recheck(u, *b, h).is_ok())).count() < need {",
                                                         "    if members.iter().take(1).filter(|u| best.1 .1.iter().all(|(b, h)| recheck(u, *b, h).is_ok())).count() < 1 {")], RB),
    ("zether-read-balance: failover from the last node", [(ZB, "    for url in &a.rpc {\n        match read(url) {", "    for url in a.rpc.iter().rev() {\n        match read(url) {")], RB),
    ("zether-read-balance: the largest block number", [(ZB, "a.rpc.iter().filter_map(|u| chosen(a, u).ok()).min()", "a.rpc.iter().filter_map(|u| chosen(a, u).ok()).max()")], RB),
    ("zether-read-balance: one node named twice", [(ZB, "                if a.rpc.contains(&u) {", "                if false {")], RB),
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
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M) + re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)
                        + re.findall(r"^✖ (.+?) \(", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
