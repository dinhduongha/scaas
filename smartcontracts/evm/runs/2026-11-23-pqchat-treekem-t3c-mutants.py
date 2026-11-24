#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan 2026-11-23-pqchat-treekem T3c (CTR-CHAT-27): each check T3c adds (the `treeRemove` that closes a session, C38;
the tree views and the pages) is caught by a test. One mutant per run, `forge test` over test/pqchat without the
release-size row (a size pin alone kills every mutant of PqChat.sol, so it is left out), every file restored byte for byte
after it; a mutant that does not compile kills nothing; a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3c-mutants.py [first last]   (from the worktree root)
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3c-mutants.py check           (every replacement found once)
A hung run: the run past its deadline (3 x the unmutated baseline, at least 10 min, or `--timeout N`) has its process group killed and reads `killed (timeout N s)`; a target file that differs from HEAD refuses the run; the restore holds on SIGINT / SIGTERM (scripts/mutant_guard.py, owner 2026-11-24)."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

E = "smartcontracts/evm/"
P = E + "src/pqchat/PqChat.sol"
T = E + "src/pqchat/PqChatTree.sol"
G = E + "src/pqgroup/PqGroupTree.sol"
CAPPED = os.path.abspath("scripts/capped")
FORGE = (
    [CAPPED, "forge", "test", "--match-path", "test/pqchat/*.t.sol", "--no-match-test", "test_gas_deployImplementation"],
    E,
)
M = [
    ("the closing treeRemove refused (C24 read without C38)", [(T, " && _treeHasMember(t)) revert IPqChat.PqChatTreeAdmins();", ") revert IPqChat.PqChatTreeAdmins();")]),
    ("a gone UA's leaf counted as a member's (C38)", [(G, "            if (l.live && t.gone[l.ua].kind == 0) return true;", "            if (l.live) return true;")]),
    ("removalAt decoding a tree record as a flat one", [(P, "        if (!_isTree(_s().epochs[epochId].sessionId)) return abi.decode(b, (PqChatRemove, bytes32));\n        PqChatTreeRemove memory t;", "        if (true) return abi.decode(b, (PqChatRemove, bytes32));\n        PqChatTreeRemove memory t;")]),
    ("leaveAt decoding a tree record as a flat one", [(P, "        if (!_isTree(_s().epochs[epochId].sessionId)) return abi.decode(b, (PqChatLeave, bytes32));", "        if (true) return abi.decode(b, (PqChatLeave, bytes32));")]),
    ("leaveSig at the flat record's word for a tree record", [(P, "_isTree(_s().epochs[epochId].sessionId) ? 6 : 5);", "_isTree(_s().epochs[epochId].sessionId) ? 5 : 5);")]),
]

if sys.argv[1:] == ["check"]:
    for name, reps in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
guard.refuse_dirty([f for _, reps in M[lo - 1:hi] for f, _, _ in reps], ".")
lim = guard.limit(FORGE[0], cwd=FORGE[1])
for n, (name, reps) in enumerate(M[lo - 1:hi], lo):
    suite, cwd = FORGE
    files = sorted({f for f, _, _ in reps})
    orig = {f: open(f, encoding="utf-8").read() for f in files}
    saved = {f: open(f, "rb").read() for f in orig}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = guard.run(suite, lim, capture_output=True, text=True, cwd=cwd)
    finally:
        guard.restore(saved)
    out = r.stdout + r.stderr
    loaded = "Compiler run failed" not in out
    failed = sorted(set(re.findall(r"^\[FAIL.*\] (\w+)\(\) \(", out, re.M)))  # a message may hold "]"
    survived = not r.timeout and (r.returncode == 0 or not loaded)
    bad += survived
    verdict = guard.outcome(r, "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  ")
    where = ", ".join(sorted({f.split("/")[-1] for f in files}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
