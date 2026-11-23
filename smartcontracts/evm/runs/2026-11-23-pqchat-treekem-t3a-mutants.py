#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan 2026-11-23-pqchat-treekem T3a (CTR-CHAT-26, CTR-CHAT-27): each check of the tree module, its base `PqGroupTree` and
the dispatch in `PqChat` is caught by a test. One mutant per run, `forge test` over test/pqchat and test/pqvault without the
release-size row (a size pin alone kills every mutant of PqChat.sol, so it is left out), every file restored byte for byte
after it; a mutant that does not compile kills nothing; a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3a-mutants.py [first last]   (from the worktree root)
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3a-mutants.py check           (every replacement found once)"""
import os
import re
import subprocess
import sys

E = "smartcontracts/evm/"
P = E + "src/pqchat/PqChat.sol"
T = E + "src/pqchat/PqChatTree.sol"
G = E + "src/pqgroup/PqGroupTree.sol"
C = E + "src/pqchat/PqChatCore.sol"
CAPPED = os.path.abspath("scripts/capped")
FORGE = (
    [CAPPED, "forge", "test", "--match-path", "test/pq{chat,vault}/*.t.sol", "--no-match-test", "test_gas_deployImplementation"],
    E,
)
M = [
    ("mode 1 accepted on a none home", [(T, "        if (_s().sigStore != SIG_SSTORE2) revert IPqChat.PqChatTreeSigStore();\n", "")]),
    ("mode 1 accepted on a replica", [(T, "        if (!ep.home) revert IPqChat.PqChatTreeHome();\n", "")]),
    ("the leaf cap off by one", [(G, "if (used == 0 || used > leavesMax || admins.length > adminsMax)", "if (used == 0 || used >= leavesMax || admins.length > adminsMax)")]),
    ("the admin cap off by one", [(G, "if (used == 0 || used > leavesMax || admins.length > adminsMax)", "if (used == 0 || used > leavesMax || admins.length >= adminsMax)")]),
    ("the info cap off by one", [(T, "if (s.sealedInfo.length > TREE_INFO_MAX)", "if (s.sealedInfo.length >= TREE_INFO_MAX)")]),
    ("no leaf cap", [(G, "if (used == 0 || used > leavesMax || admins.length > adminsMax)", "if (used == 0 || admins.length > adminsMax)")]),
    ("a leaf hash without its index", [(G, "abi.encode(leafTypehash, uint32(i), ua, keyId, kemHash)", "abi.encode(leafTypehash, uint32(0), ua, keyId, kemHash)")]),
    ("a leaf hash without kemHash", [(G, "abi.encode(leafTypehash, uint32(i), ua, keyId, kemHash)", "abi.encode(leafTypehash, uint32(i), ua, keyId, bytes32(0))")]),
    ("the children swapped", [(G, "h = x < s ? _thParent(_keyHashOf(n.keyAt), h, hs) : _thParent(_keyHashOf(n.keyAt), hs, h);", "h = x < s ? _thParent(_keyHashOf(n.keyAt), hs, h) : _thParent(_keyHashOf(n.keyAt), h, hs);")]),
    ("a blank parent over empty subtrees hashed", [(G, "        if (keyHash == 0 && l == 0 && r == 0) return 0;\n", "")]),
    ("a sibling leaf taken as blank", [(G, "bytes32 hs = s & 1 == 0 ? _thLeaf(reg, t, s / 2) : t.nodeAt[s].hash;", "bytes32 hs = s & 1 == 0 ? bytes32(0) : t.nodeAt[s].hash;")]),
    ("the leaves written in the record's transaction", [
        (T, "        _treeListed(sid, s.creator);\n", "        _treeListed(sid, s.creator);\n        for (uint256 i; i < s.members.length; ++i) {\n            _treeSetLeaf(reg, sid, i, s.members[i].ua, s.members[i].keyId, 0, uint32(i));\n        }\n"),
        (T, "            if (_treeSetLeaf(reg, sid, i, members[i].ua, members[i].keyId, 0, uint32(i))) {", "            if (i == type(uint256).max) {"),
    ]),
    ("every member listed in the record's transaction", [(T, "        _s().sessions[s.creator].push(sid);\n", "        for (uint256 i; i < s.members.length; ++i) {\n            if (!_sameUa(s.members, i)) _s().sessions[s.members[i].ua].push(sid);\n        }\n")]),
    ("the creator not listed with the record", [(T, "        _s().sessions[s.creator].push(sid);\n", "")]),
    ("a UA listed per key", [(T, "            if (_treeSetLeaf(reg, sid, i, members[i].ua, members[i].keyId, 0, uint32(i))) {", "            if (_treeSetLeaf(reg, sid, i, members[i].ua, members[i].keyId, 0, uint32(i)) || true) {")]),
    ("a live key taken twice", [(G, "        if (t.liveKey[kemHash] != 0) _treeFail(T_KEY_LIVE, uint256(kemHash), 0);\n", "")]),
    ("no genesis tree hash", [(T, "            _treeGenesis(reg, sid, sid);\n", "")]),
    ("the admission check reduced to scheme and length", [(G, "        if (pk.length != KEM_PK || pk[0] != 0x01) return false;\n", "        if (pk.length != KEM_PK || pk[0] != 0x01) return false;\n        return true;\n")]),
    ("no coefficient check", [(G, "                if or(iszero(lt(or(b0, shl(8, and(b1, 15))), 3329)), iszero(lt(or(shr(4, b1), shl(4, b2)), 3329))) {", "                if and(0, or(b0, b2)) {")]),
    ("the second coefficient of a triple unchecked", [(G, "if or(iszero(lt(or(b0, shl(8, and(b1, 15))), 3329)), iszero(lt(or(shr(4, b1), shl(4, b2)), 3329)))", "if iszero(lt(or(b0, shl(8, and(b1, 15))), 3329))")]),
    ("pk_X not canonical (any value)", [(G, "        return u < P25519 && u > 1", "        return u > 1")]),
    ("the small orders admitted", [(G, "        return u < P25519 && u > 1 && u != P25519 - 1\n            && u != 325606250916557431795983626356110631294008115727848805560023387167927233504\n            && u != 39382357235489614581723060781553021112529911719440698176882885853963445705823;", "        return u < P25519;")]),
    ("the admission check not run on a leaf", [(G, "        if (!_admissible(pk)) _treeFail(T_KEM_KEY, uint256(ua), keyId);\n", "")]),
    ("rekey on a tree session", [(P, "        if (_isTree(e.sessionId)) revert PqChatModeEntry(1); // CTR-CHAT-27: a tree session's epochs are commits\n", "")]),
    ("addWraps of a tree session not forwarded", [(P, "        if (_isTree(ep.sessionId)) _forward(TREE); // CTR-CHAT-26: the leaves land with the wraps\n", "")]),
    ("mode 2 accepted", [(P, "        if (s.groupMode > 1) revert PqChatModeUnsupported(s.groupMode);", "        if (s.groupMode > 2) revert PqChatModeUnsupported(s.groupMode);")]),
    ("the tree step skipped", [(P, "        if (s.groupMode == 1) _forwardAs(PqChatTree.treeCreate.selector); // CTR-CHAT-26: the tree and its wraps\n", "")]),
    ("the pair set and the group-wide set swapped in the layout", [(G, "        mapping(bytes32 => mapping(bytes32 => GoneKey)) goneOwnKey; // the pair set, by UA then kemHash (R16)\n        mapping(bytes32 => GoneKey) goneKey; // the group-wide set, by kemHash (R16)\n", "        mapping(bytes32 => GoneKey) goneKey; // the group-wide set, by kemHash (R16)\n        mapping(bytes32 => mapping(bytes32 => GoneKey)) goneOwnKey; // the pair set, by UA then kemHash (R16)\n")]),
    ("the tree namespace of another id", [(C, "TREE_SLOT = 0x6dbf1a211620db3f6ac9abbc89a5beccc42b16cce14417bf002a104ad4e19c00;", "TREE_SLOT = 0xc7b36804b17476e9a19a6ebc690cd7b9326d322c515fd7dc91373f9bc6dc3000;")]),
    ("the tree module's constructor check dropped", [(P, "        if (tree_.code.length == 0 || PqChatTree(tree_).FACTORY() != factory_) revert PqChatEnv();\n", "")]),
]

if sys.argv[1:] == ["check"]:
    for name, reps in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps) in enumerate(M[lo - 1:hi], lo):
    suite, cwd = FORGE
    files = sorted({f for f, _, _ in reps})
    orig = {f: open(f, encoding="utf-8").read() for f in files}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(suite, capture_output=True, text=True, cwd=cwd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = r.stdout + r.stderr
    loaded = "Compiler run failed" not in out
    failed = sorted(set(re.findall(r"^\[FAIL.*\] (\w+)\(\) \(", out, re.M)))  # a message may hold "]"
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = ", ".join(sorted({f.split("/")[-1] for f in files}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
