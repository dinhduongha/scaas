#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The 2026-11-24 review fixes, contract phase (branch review-fix-contract): each check the round adds is caught by a test.
So far: the PqChatTreeMembers split (owner 2026-11-24), E-3's exits at the head with the lag (C9), A-4, D-7 / C40, A-3;
E-3 in mode 0 and PqVault with the replica rule (M21-). One mutant per run, `forge test` over test/pqchat alone, or
test/pqvault for a mutant marked so (FOUNDRY_TEST) without the release-size row (a size pin alone kills
every mutant of PqChat.sol, so it is left out), every file restored byte for byte after it; a mutant that does not compile
kills nothing; a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-24-review-fix-contract-mutants.py [first last]   (from the worktree root)
  python3 -I smartcontracts/evm/runs/2026-11-24-review-fix-contract-mutants.py check           (every replacement found once)
A hung run: the run past its deadline (3 x the unmutated baseline, at least 10 min, or `--timeout N`) has its process group
killed and reads `killed (timeout N s)`; a target file that differs from HEAD refuses the run; the restore holds on SIGINT /
SIGTERM (scripts/mutant_guard.py, ARCH-POS-23)."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

E = "smartcontracts/evm/"
P = E + "src/pqchat/PqChat.sol"
T = E + "src/pqchat/PqChatTree.sol"
S = E + "src/pqchat/PqChatTreeMembers.sol"
B = E + "src/pqgroup/PqGroupBase.sol"
C = E + "src/pqchat/PqChatCore.sol"
V = E + "src/pqvault/PqVault.sol"
CAPPED = os.path.abspath("scripts/capped")
ENV = dict(
    os.environ,
    FOUNDRY_TEST="test/pqchat",
    FOUNDRY_OUT="out/rfc-mutants",
    FOUNDRY_CACHE_PATH="cache/rfc-mutants",
    PATH=os.path.expanduser("~/.foundry/bin") + os.pathsep + os.environ.get("PATH", ""),
)
FORGE = ([CAPPED, "forge", "test", "-j", "1", "--no-match-test", "test_gas_deployImplementation"], E)
M = [
    # the split
    ("treeLeave forwarded to the tree module", [(P, "    function treeLeave(PqChatTreeLeave calldata, IUARegistry.UASig calldata) external {\n        _forward(MEMBERS);", "    function treeLeave(PqChatTreeLeave calldata, IUARegistry.UASig calldata) external {\n        _forward(TREE);")]),
    ("treeRemove forwarded to the tree module", [(P, "    function treeRemove(PqChatTreeRemove calldata, IUARegistry.UASig calldata) external {\n        _forward(MEMBERS);", "    function treeRemove(PqChatTreeRemove calldata, IUARegistry.UASig calldata) external {\n        _forward(TREE);")]),
    ("the constructor takes another factory's members module", [(P, " || PqChatTreeMembers(members_).FACTORY() != factory_) revert PqChatEnv();", ") revert PqChatEnv();")]),
    ("modules() of three", [(P, "        m = new address[](4);\n        (m[0], m[1], m[2], m[3]) = (TOPICS, TREE, VIEWS, MEMBERS);", "        m = new address[](3);\n        (m[0], m[1], m[2]) = (TOPICS, TREE, VIEWS);")]),
    # E-3 (C9): the named epoch
    ("the old C9: the named epoch must have no child", [(S, "        named = ep.epoch;\n", "        if (_s().childOf[epochId] != 0) revert IPqChat.PqChatEpochTaken(epochId, _s().childOf[epochId]);\n        named = ep.epoch;\n")]),
    ("an incomplete epoch named", [(S, "        if (ep.landed != ep.wraps) revert IPqChat.PqChatIncomplete(epochId);\n", "")]),
    ("an epoch of another session named", [(S, "        if (ep.sessionId != sid) revert IPqChat.PqChatUnknown(epochId);\n", "")]),
    # the lag
    ("no lag bound", [(S, "        if (head.epoch > named + EXIT_LAG_MAX) revert IPqChat.PqChatExitLag(named, head.epoch);\n", "")]),
    ("the lag bound off by one", [(S, "if (head.epoch > named + EXIT_LAG_MAX)", "if (head.epoch >= named + EXIT_LAG_MAX)")]),
    ("EXIT_LAG_MAX 17", [(B, "EXIT_LAG_MAX = 16;", "EXIT_LAG_MAX = 17;")]),
    # applied at the head
    ("a leave gone from 0, not the head's number", [(S, "        _treeGo(l.sessionId, l.member, 1, head.epoch);", "        _treeGo(l.sessionId, l.member, 1, 0);")]),
    ("a removal gone from the named number", [(S, "        uint64 at = head.epoch;", "        uint64 at = named;")]),
    ("a leave record under the named epoch", [(S, "        _s().leaves[hid].push(", "        _s().leaves[l.epochId].push(")]),
    ("a removal record under the named epoch", [(S, "        _s().removals[hid].push(", "        _s().removals[r.epochId].push(")]),
    ("the leave's flag not set on the head", [(S, "        head.left[l.member] = true;\n", "")]),
    ("the removal's flags not set on the head", [(S, "            head.removedOf[r.members[i]] = true;\n", "")]),
    ("nextEpoch from the head, not the named epoch", [(S, "_exitAt(t, r.sessionId, r.epochId);\n        if (r.nextEpoch != named + 1) revert", "_exitAt(t, r.sessionId, r.epochId);\n        if (r.nextEpoch != head.epoch + 1) revert")]),
    # A-4
    ("A-4: a gone UA in a removal accepted", [(S, " || t.gone[u].kind != 0) {", ") {")]),
    # D-7 / C40, A-3
    ("D-7: an empty addPath accepted", [(T, "        if (n == 0 || first + n > (list.code.length - 1) / 36)", "        if (first + n > (list.code.length - 1) / 36)")]),
    ("A-3: commit pieces on epoch 0", [(T, "        if (ep.epoch == 0) revert IPqChat.PqChatUnknown(epochId); // A-3: epoch 0 has no commit and no pieces but its wraps\n", "")]),
    # E-3 in mode 0 and PqVault: the base's `_exitAt`
    ("mode 0: no lag at home", [(B, "        if (ep.epoch > named + EXIT_LAG_MAX) _fail(F_EXIT_LAG, named, ep.epoch);\n", "")]),
    ("mode 0: applied at the named epoch, not the head", [(B, "        at = c.length == 0 ? sessionId : c[c.length - 1];\n        ep = _epochs()[at];\n", "")]),
    ("mode 0: an incomplete epoch named at home", [(B, "        if (ep.landed != ep.wraps) _fail(F_INCOMPLETE, uint256(epochId), 0);\n        bytes32[] storage c", "        bytes32[] storage c")]),
    ("PqChatExitLag not mapped", [(C, "        if (code == F_EXIT_LAG) revert IPqChat.PqChatExitLag(uint64(a), uint64(b));\n", "")]),
    ("PqVaultExitLag not mapped", [(V, "        if (code == F_EXIT_LAG) revert PqVaultExitLag(uint64(a), uint64(b));\n", "")], "pqvault"),
    # the replica rule (sc-E-4)
    ("replica: a removed author refused", [(B, "        if (home && pe.removed != 0 && pe.removedOf[author])", "        if (pe.removed != 0 && pe.removedOf[author])")]),
    ("replica: a leaver author refused", [(B, "|| (home && pe.left[author])) {", "|| pe.left[author]) {")]),
    ("replica: an admin's flags refuse", [(B, "        return _has(admins, ua) && (!_epochs()[pe.sessionId].home || (!pe.removedOf[ua] && !pe.left[ua]));", "        return _has(admins, ua) && !pe.removedOf[ua] && !pe.left[ua];")], "pqvault"),
    ("replica: no ancestor walk", [(B, "        if (_epochs()[pe.sessionId].home) return false;\n        Epoch storage a = pe;", "        return false;\n        Epoch storage a = pe;")]),
    ("home: the ancestor walk at home too", [(B, "        if (_epochs()[pe.sessionId].home) return false;\n        Epoch storage a = pe;", "        Epoch storage a = pe;")]),
    ("replica: _noneRemoved runs", [(B, "        if (_epochs()[ep.sessionId].home) {\n            if (_epochs()[ep.parent].removed != 0) _noneRemoved(ep); // P48: whoever authored it; at home only (sc-E-4)\n", "        if (_epochs()[ep.parent].removed != 0) _noneRemoved(ep);\n        if (_epochs()[ep.sessionId].home) {\n")]),
    # mode 0's entries, in PqChatTreeMembers (owner 2026-11-25)
    ("mode 0: a repeated leave accepted", [(S, "        if (_memberAt(m, l.member) == type(uint256).max || ep.left[l.member] || ep.removedOf[l.member]) {", "        if (_memberAt(m, l.member) == type(uint256).max) {")]),
    ("mode 0: A-4, a removed UA accepted", [(S, "            if (!_removable(m, admins, r.members[i]) || ep.removedOf[r.members[i]]) {", "            if (!_removable(m, admins, r.members[i])) {")]),
    ("mode 0: the removal record under the named epoch", [(S, "        _s().removals[at].push(", "        _s().removals[r.epochId].push(")]),
    ("mode 0: the leave event under the named epoch", [(S, "        emit IPqChat.PqChatLeft(l.sessionId, at, l.member);", "        emit IPqChat.PqChatLeft(l.sessionId, l.epochId, l.member);")]),
    ("mode 0: nextEpoch from the head", [(S, "// a replica's epoch named\n        if (r.nextEpoch != named + 1)", "// a replica's epoch named\n        if (r.nextEpoch != ep.epoch + 1)")]),
    ("PqChat.leave forwarded to the tree module", [(P, "    function leave(PqChatLeave calldata, IUARegistry.UASig calldata) external {\n        _forward(MEMBERS);", "    function leave(PqChatLeave calldata, IUARegistry.UASig calldata) external {\n        _forward(TREE);")]),
    # PqVault
    ("PqVault: a repeated leave accepted", [(V, "        if (_memberAt(m, l.member) == type(uint256).max || ep.left[l.member] || ep.removedOf[l.member]) {", "        if (_memberAt(m, l.member) == type(uint256).max) {")], "pqvault"),
    ("PqVault: A-4, a removed UA accepted", [(V, "            if (!_removable(m, admins, r.members[i]) || ep.removedOf[r.members[i]]) {", "            if (!_removable(m, admins, r.members[i])) {")], "pqvault"),
    ("PqVault: the removal record under the named epoch", [(V, "        _v().removals[at].push(", "        _v().removals[r.epochId].push(")], "pqvault"),
    ("PqVault: nextEpoch from the head", [(V, "        if (r.nextEpoch != named + 1) revert PqVaultEpochNumber", "        if (r.nextEpoch != ep.epoch + 1) revert PqVaultEpochNumber")], "pqvault"),
]

if sys.argv[1:] == ["check"]:
    for name, reps, *_ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
guard.refuse_dirty([f for _, reps, *_ in M[lo - 1:hi] for f, _, _ in reps], ".")
for n, (name, reps, *rest) in enumerate(M[lo - 1:hi], lo):
    d = rest[0] if rest else "pqchat"
    env = dict(ENV, FOUNDRY_TEST="test/" + d, FOUNDRY_OUT="out/rfc-mutants-" + d, FOUNDRY_CACHE_PATH="cache/rfc-mutants-" + d)
    lim = guard.limit(FORGE[0], cwd=FORGE[1], env=env)
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
        r = guard.run(suite, lim, capture_output=True, text=True, cwd=cwd, env=env)
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
