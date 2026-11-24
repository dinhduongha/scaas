#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan 2026-11-23-pqchat-treekem T3d (owner 2026-11-24, option A; CTR-CHAT-27): each check T3d adds is caught by a test:
the read-only module (a writing entry, a paying entry), the forwarding path (the fallback's target, value, the interface
id, the module list, the constructor's check) and the views with their bounds (C36). One mutant per run, `forge test`
over test/pqchat without the release-size row (a size pin alone kills every mutant of PqChat.sol, so it is left out),
every file restored byte for byte after it; a mutant that does not compile kills nothing; a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3d-mutants.py [first last]   (from the worktree root)
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3d-mutants.py check           (every replacement found once)
A hung run: the run past its deadline (3 x the unmutated baseline, at least 10 min, or `--timeout N`) has its process group killed and reads `killed (timeout N s)`; a target file that differs from HEAD refuses the run; the restore holds on SIGINT / SIGTERM (scripts/mutant_guard.py, owner 2026-11-24)."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

E = "smartcontracts/evm/"
P = E + "src/pqchat/PqChat.sol"
CAPPED = os.path.abspath("scripts/capped")
FORGE = (
    [CAPPED, "forge", "test", "--match-path", "test/pqchat/*.t.sol", "--no-match-test", "test_gas_deployImplementation"],
    E,
)
V = E + "src/pqchat/PqChatTreeViews.sol"
M = [
    # the read-only module (the scan)
    ("a writing entry in the views module", [(V, "    function _slice(", "    function mutantPoke() external {\n        _s().ownerUA = 0;\n    }\n\n    function _slice(")]),
    ("an entry that sends value in the views module", [(V, "    function _slice(", "    function mutantSweep() external {\n        payable(msg.sender).transfer(1);\n    }\n\n    function _slice(")]),
    # the forwarding path
    ("the fallback forwards to the tree module", [(P, "        address v = VIEWS;", "        address v = TREE;")]),
    ("a receive() that takes value (a payable fallback itself the compiler refuses at every typed conversion of an address)", [(P, "    fallback() external {", "    receive() external payable {}\n\n    fallback() external {")]),
    ("the views' interface id not reported", [(P, " || id == type(IPqChatTreeViews).interfaceId;", ";")]),
    ("modules() of two", [(P, "        m = new address[](3);\n        (m[0], m[1], m[2]) = (TOPICS, TREE, VIEWS);", "        m = new address[](2);\n        (m[0], m[1]) = (TOPICS, TREE);")]),
    ("the constructor takes another factory's views module", [(P, " || PqChatTreeViews(views_).FACTORY() != factory_) revert PqChatEnv();", ") revert PqChatEnv();")]),
    # the bounds (C36)
    ("TREE_LEAF_PAGE_MAX 65", [(V, "TREE_LEAF_PAGE_MAX = 64;", "TREE_LEAF_PAGE_MAX = 65;")]),
    ("TREE_RANGE_MAX 257", [(V, "TREE_RANGE_MAX = 256;", "TREE_RANGE_MAX = 257;")]),
    ("a page not cut at the end", [(V, "        return count < total - first ? count : total - first;", "        return count;")]),
    ("a page past the end not empty", [(V, "        if (first >= total) return 0;\n", "")]),
    ("treeLeaves bounded by leaves, not used", [(V, "_page(first, count, t.used, TREE_LEAF_PAGE_MAX)", "_page(first, count, t.leaves, TREE_LEAF_PAGE_MAX)")]),
    ("treeNodes one node past the tree", [(V, "_page(first, count, 2 * uint256(t.leaves) - 1, TREE_RANGE_MAX)", "_page(first, count, 2 * uint256(t.leaves), TREE_RANGE_MAX)")]),
    # the views
    ("a blank leaf read as live", [(V, "            if (!l.live) continue;\n", "")]),
    ("treeNodes: a leaf without its joinEpoch", [(V, "keccak256(_kemPk(reg, l.ua, l.keyId)), l.joinEpoch);", "keccak256(_kemPk(reg, l.ua, l.keyId)), 0);")]),
    ("treeOf without owed", [(V, "t.genesisTreeHash, t.head, t.owed);", "t.genesisTreeHash, t.head, 0);")]),
    ("commitOf decodes epoch 0", [(V, "if (ep.sessionId == epochId || !_isTree(ep.sessionId)) revert", "if (!_isTree(ep.sessionId)) revert")]),
    ("goneOwnKeyOf reads the session-wide set", [(V, "_treeOf(sessionId).goneOwnKey[ua][kemHash];", "_treeOf(sessionId).goneKey[kemHash];")]),
    ("pathCtAt: sealedSecret at the wrong offset", [(V, "_slice(b, 1600, 48)", "_slice(b, 1599, 48)")]),
    ("pathListOf: the hashes read from the targets' part", [(V, "ctHashes[j] = bytes32(_slice(b, 4 * n + 32 * j, 32));", "ctHashes[j] = bytes32(_slice(b, 32 * j, 32));")]),
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
