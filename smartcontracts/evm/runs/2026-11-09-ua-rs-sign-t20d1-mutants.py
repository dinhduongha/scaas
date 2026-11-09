#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d1, 3h's formats in every client (after the fourth sync with ua-mtx-merge): each mutant undoes one rule T20d1
added (the 3h layout of `scaas.pqz` in the facade and in pqz-read, the op blob's tail in path (A)'s entry parse, `ownTag` in
the PQZ args structs, the router's `UASetProofStore`, bit 24 in the native binding tables, pqz-read's release probe) and names
the test that must catch it. One mutant per run on a clean tree, its command, every file restored byte for byte after it (the
caller also runs `git diff --exit-code`). A failing command kills; a build that does not compile is NOT-LOADED (a finding); a
mutant whose command passes SURVIVED (a finding, exit 1). The facade's commands name their tests: `memo_hash_is_the_contracts`
stays red until T20d2 (the 3h `memoHash`), so the whole `facade_pqz_state` binary cannot be the command.
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d1-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d1-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d1-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
PQZ, READ, E = R + "src/facade/pqz.rs", R + "src/bin/pqz-read.rs", R + "src/wallet/eip712.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "PATH": os.path.expanduser("~/.foundry/bin") + ":" + os.environ["PATH"]}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
FS = (R, CT + ["--test", "facade_pqz_state", "--", "layout_is_the_pin", "word_negatives_refused_before_the_key",
               "forge_rows_on_another_handle_are_refused_before_the_key", "disclosures_audit_reads_and_memo_over_rebuilt_words"])
FSV = (R, CT + ["--features", "vectors", "--test", "facade_pqz_state", "--", "state_rows_reproduce_the_contract"])
WT = (R, CT + ["--test", "wallet_typed"])
PR = (R, CT + ["--test", "pqz_read", "--", "--include-ignored", "reading_layer_against_anvil", "decoys_against_anvil"])
PY = ("clients/ua-py/", ["python3", "-m", "unittest", "-v", "tests.test_vectors.GovernanceBits"])
GO = ("clients/ua-go/", [CAPPED, "go", "test", "-count=1", "-run", "TestGovernanceBitsRows", "."])

M = [
    # the facade's 3h layout
    ("STATE_LAYOUT: accHash at inner 2", [(PQZ, '("acct[U][7].accHash", 8, 3, 0, 32),', '("acct[U][7].accHash", 8, 2, 0, 32),')], FS),
    ("STATE_LAYOUT: pending at inner 3", [(PQZ, '("acct[U][7].pending[3]", 8, 4, 0, 32),', '("acct[U][7].pending[3]", 8, 3, 0, 32),')], FS),
    ("STATE_LAYOUT: accWords from inner 4", [(PQZ, '("acct[U][7].accWords[0]", 8, 5, 0, 32),', '("acct[U][7].accWords[0]", 8, 4, 0, 32),')], FS),
    ("acct(): accHash read from slot 2", [(PQZ, "let [s0, s1, last_debit, s2] = w else", "let [s0, s1, s2, last_debit] = w else")], FS),
    ("acct(): lastDebit's width unchecked", [(PQZ, "    only_low(last_debit, 8)?;\n", "")], FS),
    # path (A)'s entry parse through the tail
    ("tail: its n ignored", [(R + "src/facade/pqz_path.rs", "let at = d.len().checked_sub(33 + 8 * n)", "let at = d.len().checked_sub(33)")], FSV),
    # the typed rows
    ("PqzBurnArgs without ownTag", [(E, "bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom", "bytes32 beneficiaryUA,bytes u,bytes vFrom")], WT),
    ("UASetProofStore dropped", [(E, '    op("UASetProofStore", "address target,uint8 next", &[ROUTER], None),\n', "")], WT),
    # bit 24 in the native tables
    ("ua-py: bit 24 not in GOVERNANCE_BITS", [("clients/ua-py/scaas_ua/__init__.py", "('TAX', 'power'), ('PQZ_PROOF', 'power'),", "('TAX', 'power'),")], PY),
    ("ua-go: bit 24 not in GovernanceBits", [("clients/ua-go/ua.go", '{"TAX", "power"}, {"PQZ_PROOF", "power"},', '{"TAX", "power"},')], GO),
    # pqz-read
    ("pqz-read: 3 account slots read", [(READ, "let account = (0..4).map(", "let account = (0..3).map(")], PR),
    ("pqz-read: the release probe skipped", [(READ, "    r.release_3h(&a.token)?;\n", "")], PR),
    ("pqz-read: any answer of proofStore() taken", [(READ, "Some(Ok(w)) if w.len() == 32 && w[..31] == [0; 31] && w[31] <= 1 => Ok(()),",
                                                     "Some(Ok(_)) => Ok(()),")], PR),
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
                        + re.findall(r"^--- FAIL: (\S+)", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
