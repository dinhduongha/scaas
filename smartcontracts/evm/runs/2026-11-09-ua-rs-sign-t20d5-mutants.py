#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d5, path (B)'s debit commands (C-PP-3; no-oracle spec §4.14.2, §4.14.3): each mutant undoes one rule of
`prove*Proven` (`clients/ua-rs/src/facade/pqz/proven.rs`) and names the test that must catch it
(`tests/facade_pqz_proof.rs`, feature `vectors`: the key-use counter). The plan's ("p from the request", "a part not
re-verified"; "the ownTag of another version" has no mutant: a handle holds one version's seed, as T20d2), then the round's. One mutant per run
on a clean tree, its command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A
failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a
finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d5-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d5-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d5-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
P = R + "src/facade/pqz/proven.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
T = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "facade_pqz_proof"])

M = [
    # the plan's
    ("p not the session's (a request's)", [(P, "                p: o.p,\n                valid_until_block: a.valid_until_block,", "                p: o.p + 1,\n                valid_until_block: a.valid_until_block,")], T),
    ("a part not checked: the debit before every need index is accepted",
     [(P, "            if !o.need.keys().all(|i| s.accepted.contains(i)) || o.op7 != multi ||", "            if o.op7 != multi ||")], T),
    # the round's own
    ("sendCounter not the session's", [(P, "                send_counter: o.send_counter,\n                p: o.p,", "                send_counter: o.send_counter + 1,\n                p: o.p,")], T),
    ("forOp7 not tied to the form", [(P, " || o.op7 != multi || (a.chain_id", " || (a.chain_id")], T),
    ("chainId and registry not the session's", [(P, " || (a.chain_id, a.registry) != (o.chain_id, o.registry) {", " {")], T),
    ("the materialised acc not cross-checked",
     [(P, "                Some(acc) => acc.chunks_exact(8).map(|c| c.iter().fold(0u64, |x, y| x << 8 | u64::from(*y))).eq(s.below.iter().copied()),",
       "                Some(acc) => !acc.is_empty(),")], T),
    ("rolled past p_last taken without acc", [(P, "                None => o.rolled == o.p_last,", "                None => true,")], T),
    ("T without Trivial(shieldIn)", [(P, "            add_trivial_mod(&mut t, a.shield_in);\n", "")], T),
    ("a stale version pays another UA", [(P, "                    if o.stale != (*to_ua == o.ua) {", "                    if !o.stale && *to_ua == o.ua {")], T),
    ("a stale version burns", [(P, "                    if o.stale {\n                        return Err(Error::Argument); // KV-8: a stale version burns nothing", "                    if false {\n                        return Err(Error::Argument); // KV-8: a stale version burns nothing")], T),
    ("the session kept after a debit", [(P, "            with_p(v, &h)\n        };\n        *g = None;", "            with_p(v, &h)\n        };")], T),
    ("the own v_f left out of the sum below rolled", [(P, "            add_mod(&mut below, ct);\n", "")], T),
    ("a credit below rolled left out of that sum", [(P, "                    if c.index < s.open.rolled {\n                        add_mod(&mut s.below, &ct);\n                    }\n", "")], T),
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
