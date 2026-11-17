#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15n2 (T15n follow-up, CTR-UA-29, 2026-11-07): each mutant undoes one rule of the recipient's position (`ua-rs`
`facade::decoys` `recipient` / `legs`, the facades' allow-lists, `pqz-read --command decoys --recipient`, `zether-read-balance
--decoy-count --recipient`) and names the test that must catch it. One mutant per run on a clean tree, its command, every file
restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that does not
compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1). The CLIs run against a local
anvil (`ANVIL`, default ~/.foundry/bin/anvil; killed by the tests).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15n2-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15n2-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15n2-mutants.py count           (the number of mutants)
UNAUDITED."""
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
    # the pick's legs (facade::decoys)
    ("no shuffle: the recipient always last", [(D, "        shuffle(&mut legs, rng)?;\n", "")], L),
    ("the recipient omitted from the legs", [(D, "let mut legs = [d.as_slice(), &[r]].concat();", "let mut legs = [d.as_slice(), &[r][..0]].concat();")], L),
    ("the recipient not excluded from the decoys",
     [(D, "let exclude = [self.exclude.as_slice(), self.recipient.as_slice()].concat();", "let exclude = self.exclude.clone();")], L),
    ("biased shuffle: Sattolo (j < i, a leg never stays)", [(D, "below(rng, i as u128 + 1)", "below(rng, i as u128)")], L),
    ("biased shuffle: naive (j over the whole range)", [(D, "below(rng, i as u128 + 1)", "below(rng, v.len() as u128)")], L),
    ("biased shuffle: the last slot never swapped", [(D, "for i in (1..v.len()).rev() {", "for i in (1..v.len().saturating_sub(1)).rev() {")], L),
    ("recipient off the request's field list",
     [(D, '["candidates", "exclude", "count", "weights", "recipient"].contains', '["candidates", "exclude", "count", "weights"].contains')], L),
    # the facades
    ("PQZ: recipient off pickDecoys' allow-list",
     [(QF, '"pickDecoys" => has(&["candidates", "exclude", "count", "weights", "recipient"]),', '"pickDecoys" => has(&["candidates", "exclude", "count", "weights"]),')], FP),
    ("Zether: recipient off pickDecoys' allow-list",
     [(ZF, '"pickDecoys" => has(&["candidates", "exclude", "count", "weights", "recipient"]),', '"pickDecoys" => has(&["candidates", "exclude", "count", "weights"]),')], FZ),
    # pqz-read --command decoys --recipient
    ("pqz-read: --recipient not passed to the pick", [(B, '        request["recipient"] = json!(hx(&u));\n', "        let _ = u;\n")], PR),
    ("pqz-read: the legs not printed", [(B, '        out["legs"] = picked["legs"].clone();', "        let _ = &picked;")], PR),
    ("pqz-read: --recipient not excluded from the candidates", [(B, "    exclude.extend(a.recipient);\n", "")], PR),
    ("pqz-read: --recipient with another command", [(B, '"--count", "--exclude", "--recipient", "--sync-block"', '"--count", "--exclude", "--sync-block"')], PR),
    # zether-read-balance --decoy-count --recipient
    ("zether: --recipient not passed to the pick", [(Z, '            request["recipient"] = json!(hx(&u));\n', "            let _ = u;\n")], ZR),
    ("zether: --recipient not excluded from the candidates", [(Z, "        exclude.extend(a.recipient);\n", "")], ZR),
    ("zether: --recipient with --decoy-keys", [(Z, "a.exclude.is_none() && a.recipient.is_none() && a.filter.is_none()", "a.exclude.is_none() && a.filter.is_none()")], ZR),
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
