#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan 2026-11-23-pqchat-treekem T3b (CTR-CHAT-27): each check of `commit`, its pieces, completion, `treeLeave`,
`treeRemove` and the dispatch in `PqChat` is caught by a test. One mutant per run, `forge test` over test/pqchat without the
release-size row (a size pin alone kills every mutant of PqChat.sol, so it is left out), every file restored byte for byte
after it; a mutant that does not compile kills nothing; a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3b-mutants.py [first last]   (from the worktree root)
  python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3b-mutants.py check           (every replacement found once)
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
    ("the walk on the tree before the changes", [(G, "if (s == 2 || (s == 0 && t.leafAt[x / 2].live)) tg[n++] = uint32(x);", "if (t.leafAt[x / 2].live) tg[n++] = uint32(x);")]),
    ("one target unchecked (the list's targets against the walk's)", [(T, "        if (keccak256(tb) != g.targetsHash) revert IPqChat.PqChatTreeTargets(n);\n", "")]),
    ("treeHash unchecked", [(G, "        if (w.root != d.treeHash) _treeFail(T_HASH, uint256(w.root), 0);\n", "")]),
    ("the hashes not recomputed (stored ones compared)", [(G, "                w.th[x] = _thParent(w.kh[x], _thOf(reg, t, w, x - h), _thOf(reg, t, w, x + h));", "                w.th[x] = t.nodeAt[x].hash;")]),
    ("completion without the removed-UA check", [(G, "        if (owed != t.owed) _keptFail(t, w);\n", "")]),
    ("a non-admin adding another UA's key", [(G, "            if (d.adds[i].ua != d.author) plain = false;\n", "")]),
    ("the slot taken before the last piece", [(T, "        if (ep.landed + 1 != ep.wraps) return;", "        if (ep.landed + 1 != ep.wraps) {\n            _s().childOf[ep.parent] = eid;\n            return;\n        }")]),
    ("wraps without the extra unit", [(T, "+ c.adds.length + 1);", "+ c.adds.length);")]),
    ("a direct-path node outside the filtered path left with its key", [(G, "            w.st[p] = 1;\n", "")]),
    ("the list kept as its targets only", [(T, "g.list = SSTORE2.write(bytes.concat(tb, abi.encodePacked(ctHashes)));", "g.list = SSTORE2.write(bytes.concat(tb, new bytes(32 * n)));")]),
    ("a ciphertext not kept", [(T, "            _packCt(buf, (q - from) * PATH_CT, ct);\n", "")]),
    ("liveKey not freed by a Remove", [(G, "            t.liveKey[k] = 0;\n", "")]),
    ("owed not reset at completion", [(G, "(t.used, t.leaves, t.head, t.owed) = (uint32(w.used), uint32(w.leaves), head, 0);", "(t.used, t.leaves, t.head) = (uint32(w.used), uint32(w.leaves), head);")]),
    ("the tree hash check moved back to completion", [(G, "        if (w.root != d.treeHash) _treeFail(T_HASH, uint256(w.root), 0);", "        if (completing && w.root != d.treeHash) _treeFail(T_HASH, uint256(w.root), 0);")]),
    ("gone cleared at completion", [(G, "                if (t.gone[r.ua].kind == 0) t.gone[r.ua] = Gone(2, d.epoch);", "                t.gone[r.ua] = Gone(0, 0);")]),
    ("own-key churn written to the session-wide set", [(G, "                t.goneOwnKey[r.ua][k] = g;", "                t.goneKey[k] = g;")]),
    ("a going UA's keys written to the pair set only", [(G, "                t.goneKey[k] = g;", "                t.goneOwnKey[r.ua][k] = g;")]),
    ("the pair set unchecked at an Add", [(G, "            if (t.goneOwnKey[a.ua][k].set) _treeFail(T_OWN_KEY_RETURN, uint256(a.ua), uint256(k));\n", "")]),
    ("the session-wide set unchecked at an Add", [(G, "            if (t.goneKey[k].set) _treeFail(T_KEY_RETURN, uint256(k), 0);\n", "")]),
    ("the level judged before the Adds", [(G, "            if (_liveAfter(t, w, r.ua) == 0) {", "            if (t.keysOf[r.ua].live == 0) {")]),
    ("a leave not counted in owed", [(G, "        uint256 owed = t.owed + t.keysOf[ua].live;", "        uint256 owed = t.owed + (kind == 1 ? 0 : t.keysOf[ua].live);")]),
    ("the admin exemption widened to any change", [(G, "            if (!leafy) _treeFail(T_ADMINS, 0, 0);\n", "")]),
    ("parentTreeHash unchecked", [(T, "        if (c.parentTreeHash != stored) revert IPqChat.PqChatTreeParent(stored);\n", "")]),
    ("the flat leave accepted on a tree session", [(P, "        if (_isTree(l.sessionId)) revert PqChatModeEntry(1); // C30: `treeLeave`\n", "")]),
    ("gone judged between the Removes and the Adds", [(G, "            w.live[_uaAt(t, w, a.ua)] += 1;\n", "            _uaAt(t, w, a.ua);\n")]),
    ("admins judged against the stored gone set only", [(G, "if (t.gone[a[i]].kind != 0 || _goes(t, w, a[i])) _treeFail(", "if (t.gone[a[i]].kind != 0) _treeFail(")]),
    ("the last leave refused", [(T, "        ep.left[l.member] = true;\n", "        ep.left[l.member] = true;\n        if (!_treeLeafyAdmin(t)) revert IPqChat.PqChatTreeAdmins();\n")]),
    ("the Add returning a gone UA", [(G, "            if (t.gone[a.ua].kind != 0) _treeFail(T_RETURN, uint256(a.ua), 0);\n", "")]),
    ("a ciphertext's hash unchecked", [(T, "                    || PqChatTypes.hashPathCt(ct) != bytes32(SSTORE2.read(list, 4 * total + 32 * i, 32))", "")]),
    ("a node key's hash unchecked", [(T, "            if (nk.length != KEM_PK || keccak256(nk) != nodeKeyHashes[k]) revert IPqChat.PqChatPathHash(eid, k);", "            if (nk.length != KEM_PK) revert IPqChat.PqChatPathHash(eid, k);")]),
    ("a node key not admitted", [(T, "            if (!_admissible(nk)) revert IPqChat.PqChatKemKey(eid, uint64(k));\n", "")]),
    ("postMessage of a tree session not forwarded", [(P, "        if (_isTree(m.sessionId)) _forward(TREE); // CTR-CHAT-27: a member holds a live leaf and is not gone\n", "")]),
    ("the same bytes out and in under one UA", [(G, "                if (d.adds[i].ua == r.ua) _treeFail(T_OWN_KEY_RETURN, uint256(r.ua), uint256(w.rmKem[j]));\n", "")]),
    ("a piece landed twice (ciphertext)", [(T, "            if (g.ctAt[i] != 0) revert IPqChat.PqChatPathStored(eid, i);\n", "")]),
    ("a second list", [(T, "            n == 0 || g.list != address(0) || ctTargets.length != n", "            n == 0 || ctTargets.length != n")]),
    ("the backlog unbounded", [(G, "        if (owed > changesMax) _treeFail(T_BACKLOG, owed, 0);\n", "")]),
    ("a treeRemove leaving no admin with a leaf", [(T, "        if (leafy && !_treeLeafyAdmin(t) && _treeHasMember(t)) revert IPqChat.PqChatTreeAdmins();\n", "")]),
    ("the empty list's hash unchecked", [(T, "                || (c.ctCount == 0 && c.ctListHash != EMPTY_PATH_LIST)", "")]),
    ("the info bound off by one", [(T, "c.sealedInfo.length > TREE_INFO_MAX", "c.sealedInfo.length >= TREE_INFO_MAX")]),
    ("the target count unchecked", [(G, "        if (n != d.ctCount) _treeFail(T_TARGETS, n, 0);\n", "")]),
    ("the path length unchecked", [(G, "        if (k != d.nodeKeyHashes.length) _treeFail(T_TARGETS, k, 0);\n", "")]),
    ("goneKey written by the last leave (C38)", [(T, "        ep.left[l.member] = true;\n", "        ep.left[l.member] = true;\n        if (!_treeHasMember(t)) {\n            for (uint256 i; i < t.used; ++i) {\n                Leaf storage f = t.leafAt[i];\n                if (f.live) t.goneKey[keccak256(_kemPk(reg, f.ua, f.keyId))] = GoneKey(f.joinEpoch, ep.epoch, true);\n            }\n        }\n")]),
    ("the session-wide set keyed by (ua, kemHash)", [(G, "                t.goneKey[k] = g;", "                t.goneKey[keccak256(abi.encode(r.ua, k))] = g;"), (G, "            if (t.goneKey[k].set) _treeFail(T_KEY_RETURN, uint256(k), 0);\n", "            if (t.goneKey[keccak256(abi.encode(a.ua, k))].set) _treeFail(T_KEY_RETURN, uint256(k), 0);\n")]),
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
