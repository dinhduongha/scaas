#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The 2026-11-24 review fixes, contract phase (branch review-fix-contract): each check the round adds is caught by a test.
So far: the PqChatTreeMembers split (owner 2026-11-24), E-3's exits at the head with the lag (C9), A-4, D-7 / C40, A-3;
E-3 in mode 0 and PqVault with the replica rule (M21-); A-7's table, A-6, F-5, D-4, A-9 and G-3 (M42-); R8, C10 (M74-);
the re-review of 2026-11-25: E-2, A-16, A-13, A-14, A-15 (M80-M107), G-7, G-9, G-10 (M108-M112). One mutant per run, `forge test` over test/pqchat alone, or the
directory a mutant names (FOUNDRY_TEST), with **no gas or size row** (A-14 of the re-review: a row moves with any code
change, so it is not the test of a rule): every contract whose name holds `Gas` and every gas or size test elsewhere
(`NO_GAS`) is left out for every mutant, so a kill is a behavioural test's; each result line names every test that
failed. Every file restored byte for byte after it; a mutant that does not compile kills nothing; a mutant that passes
is a finding (exit 1).
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
G = E + "src/pqgroup/PqGroupTree.sol"
F = E + "src/factory/OpenFactoryLib.sol"
O = E + "src/factory/OpenFactory.sol"
R = E + "src/governance/GovernanceRouterBase.sol"
DB = E + "script/DeployBase.sol"
CAPPED = os.path.abspath("scripts/capped")
ENV = dict(
    os.environ,
    FOUNDRY_TEST="test/pqchat",
    FOUNDRY_OUT="out/rfc-mutants",
    FOUNDRY_CACHE_PATH="cache/rfc-mutants",
    PATH=os.path.expanduser("~/.foundry/bin") + os.pathsep + os.environ.get("PATH", ""),
)
# test_lastLiveLeafAtTheSpecBound was left out for M74-M77 (its ML-DSA-87 row red at 32 changes); green at C10's 20, it runs
# A-14 of the re-review (2026-11-25): no gas or size row kills a mutant. The contracts named `*Gas*`, and elsewhere the gas
# rows (`test_gas_*`, `test_gasA_` to `test_gasP_` style rows, `test_gasPerEntry`, `test_gasCalldata`, `test_gasBatch*`, the
# `*_gas` rows) and the size pin `test_sizes`; behavioural tests whose names hold "gas" (`test_gasBurning*`, `*Gasless*`) stay.
NO_GAS = r"^test_gas_|^test_gas[A-Z]_|^test_gasPerEntry$|^test_gasCalldata$|^test_gasBatch|_gas$|^test_sizes$"
FORGE = ([CAPPED, "forge", "test", "-j", "1", "--no-match-contract", "Gas", "--no-match-test", NO_GAS], E)
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
    ("mode 0: a repeated leave accepted", [(S, " || (home && (ep.left[l.member] || ep.removedOf[l.member]))) {\n            revert IPqChat", ") {\n            revert IPqChat")]),
    ("mode 0: A-4, a removed UA accepted", [(S, " || (home && ep.removedOf[r.members[i]])) {\n                revert IPqChat", ") {\n                revert IPqChat")]),
    ("mode 0: the removal record under the named epoch", [(S, "        _s().removals[at].push(", "        _s().removals[r.epochId].push(")]),
    ("mode 0: the leave event under the named epoch", [(S, "        emit IPqChat.PqChatLeft(l.sessionId, at, l.member);", "        emit IPqChat.PqChatLeft(l.sessionId, l.epochId, l.member);")]),
    ("mode 0: nextEpoch from the head", [(S, "// a replica's epoch named\n        if (r.nextEpoch != named + 1)", "// a replica's epoch named\n        if (r.nextEpoch != ep.epoch + 1)")]),
    ("PqChat.leave forwarded to the tree module", [(P, "    function leave(PqChatLeave calldata, IUARegistry.UASig calldata) external {\n        _forward(MEMBERS);", "    function leave(PqChatLeave calldata, IUARegistry.UASig calldata) external {\n        _forward(TREE);")]),
    # PqVault
    ("PqVault: a repeated leave accepted", [(V, " || (home && (ep.left[l.member] || ep.removedOf[l.member]))) {\n            revert PqVault", ") {\n            revert PqVault")], "pqvault"),
    ("PqVault: A-4, a removed UA accepted", [(V, " || (home && ep.removedOf[r.members[i]])) {\n                revert PqVault", ") {\n                revert PqVault")], "pqvault"),
    ("PqVault: the removal record under the named epoch", [(V, "        _v().removals[at].push(", "        _v().removals[r.epochId].push(")], "pqvault"),
    ("PqVault: nextEpoch from the head", [(V, "        if (r.nextEpoch != named + 1) revert PqVaultEpochNumber", "        if (r.nextEpoch != ep.epoch + 1) revert PqVaultEpochNumber")], "pqvault"),
    # A-7 (fable-A's table, by row; row 5, `_treeGo`'s early return, unreachable since A-4: equivalent, not run)
    ("A-7 row 1: treeLeave without its treeId check", [(S, "        if (l.treeId != t.treeId) revert IPqChat.PqChatTreeHome();\n", "")]),
    ("A-7 row 1: treeRemove without its treeId check", [(S, "        if (r.treeId != t.treeId) revert IPqChat.PqChatTreeHome();\n", "")]),
    ("A-7 row 2: _head without the session check", [(T, "        if (ep.sessionId != sid) revert IPqChat.PqChatUnknown(epochId);\n        if (ep.landed != ep.wraps) revert IPqChat.PqChatIncomplete(epochId);\n        bytes32 child", "        if (ep.landed != ep.wraps) revert IPqChat.PqChatIncomplete(epochId);\n        bytes32 child")]),
    ("A-7 row 3: _head without the child check", [(T, "        if (child != 0) revert IPqChat.PqChatEpochTaken(epochId, child);\n", "        child;\n")]),
    ("A-7 row 4: a gone admin is an admin", [(G, "        return t.gone[ua].kind == 0 && _in(t.admins, ua);", "        return _in(t.admins, ua);")]),
    ("A-7 row 6: an Add's kemHash not the registry's", [(G, "            if (k != a.kemHash) _treeFail(T_KEM_KEY, uint256(a.ua), a.keyId);\n", "")]),
    ("A-7 row 7: a key added twice in one commit", [(G, "                if (d.adds[j].kemHash == k) _treeFail(T_KEY_LIVE, uint256(k), 0);\n", "                k;\n")]),
    ("A-7 row 8: the author removes its own leaf", [(G, "r.leaf >= t.used || r.leaf == d.leaf || !l.live", "r.leaf >= t.used || !l.live")]),
    ("A-7 row 9: treeLeave of a non-member", [(S, "        if (!_treeMember(t, l.member)) revert IPqChat.PqChatNotMember(l.member); // A-4: a gone UA too\n", "")]),
    ("A-7 row 10: treeRemove of a UA that is no member and no admin", [(S, "            if ((t.keysOf[u].live == 0 && !_in(t.admins, u)) || t.gone[u].kind != 0) {", "            if (t.gone[u].kind != 0) {")]),
    ("A-7 row 11: changes unbounded", [(G, "        if (nr + d.adds.length > changesMax) _treeFail(T_SHAPE, 0, 0);\n", "        changesMax;\n")]),
    ("A-7 row 12: keys per UA unbounded in a commit", [(G, "            if (w.live[i] > keysMax) _treeFail(T_SHAPE, 0, 0);\n", "            keysMax;\n")]),
    ("A-7 row 13: admins unbounded in a commit", [(G, "        if (a.length > adminsMax) _treeFail(T_SHAPE, 0, 0);\n", "        adminsMax;\n")]),
    ("A-7 row 14: an Add above used", [(G, "            if (l > used || l >= leavesMax || l >= TREE_LEAVES_LIMIT) _treeFail(T_LEAF, l, 0);", "            if (l >= leavesMax || l >= TREE_LEAVES_LIMIT) _treeFail(T_LEAF, l, 0);")]),
    ("A-7 row 15: a ciphertext's sizes unchecked", [(T, "ct.mlkemCt.length != MLKEM_CT || ct.sealedSecret.length != SEALED_KEY\n                    || PqChatTypes", "PqChatTypes")]),
    ("A-7 row 16: commit without its nonce", [(T, "        _useNonce(PqChatTypes.scopeEpoch(c.sessionId, c.author), c.nonce);\n", "")]),
    ("A-7 row 17: treeRemove without its nonce", [(S, "        _auth(reg, r.admin, PqChatTypes.hashTreeRemove(r), sig);\n        _useNonce(PqChatTypes.scopeEpoch(r.sessionId, r.admin), r.nonce);\n", "        _auth(reg, r.admin, PqChatTypes.hashTreeRemove(r), sig);\n")]),
    ("A-7 row 18: treeLeave without its nonce", [(S, "        _auth(reg, l.member, PqChatTypes.hashTreeLeave(l), sig);\n        _useNonce(PqChatTypes.scopeEpoch(l.sessionId, l.member), l.nonce);\n", "        _auth(reg, l.member, PqChatTypes.hashTreeLeave(l), sig);\n")]),
    ("A-7 row 19: treeRemove without the nextEpoch check", [(S, "        if (r.nextEpoch != named + 1) revert IPqChat.PqChatEpochNumber(named + 1, r.nextEpoch);\n        if (!_treeAdmin(t, r.admin))", "        if (!_treeAdmin(t, r.admin))")]),
    ("A-7 row 20: treeRemove members unsorted", [(S, "            if (i > 0 && u <= r.members[i - 1]) revert IPqChat.PqChatShape();\n", "")]),
    ("A-7 row 21: an empty treeRemove", [(S, "        uint256 n = r.members.length;\n        if (n == 0) revert IPqChat.PqChatShape();\n", "        uint256 n = r.members.length;\n")]),
    ("A-7 row 22: wrapHashes against adds unchecked", [(T, "c.wrapHashes.length != c.adds.length || c.sealedInfo.length == 0", "c.sealedInfo.length == 0")]),
    ("A-7 row 23: ctCount at leaves accepted", [(G, "d.nodeKeyHashes.length > depth || d.ctCount >= d.leaves ||", "d.nodeKeyHashes.length > depth ||")]),
    ("A-7 row 24: ciphertexts past the list", [(T, "        if (n == 0 || first + n > (list.code.length - 1) / 36)", "        if (n == 0)")]),
    # A-6, F-5, D-4, A-9
    ("A-6: the base's 256 positions at opening", [(G, "used > leavesMax || used > TREE_LEAVES_LIMIT || admins", "used > leavesMax || admins")]),
    ("A-6: the base's 256 positions for an Add", [(G, "l >= leavesMax || l >= TREE_LEAVES_LIMIT)", "l >= leavesMax)")]),
    ("F-5: a one-leaf root 0", [(G, "w.root = w.leaves == 1 ? _thOf(reg, t, w, 0) : w.th[w.leaves - 1];", "w.root = w.th[w.leaves - 1];")]),
    ("D-4: 257 member keys at creation", [(G, "if (used == 0 || used > leavesMax || used > TREE_LEAVES_LIMIT ||", "if (used == 0 ||")]),
    ("D-4: 33 admins at creation", [(G, "|| admins.length > adminsMax) {", ") {")]),
    ("D-4: sealedInfo unbounded at creation", [(T, "        if (s.sealedInfo.length > TREE_INFO_MAX) revert IPqChat.PqChatShape();\n", "")]),
    ("A-9: Staged's list and keys swapped", [(G, "        address list;\n        address keys;", "        address keys;\n        address list;")]),
    # G-3 (test/v2)
    ("G-3: configureChain without the router's factory() check", [(F, "        if (!okF || fw != uint256(uint160(self))) revert IOpenFactory.RouterFactoryMismatch(address(uint160(fw)));\n", "")], "v2"),
    # R8 256 -> 512 (owner 2026-11-25). M74's first form (the buffer 10 -> 9) survived, equivalent: a direct path of depth 9
    # has 9 parents, so 9 slots hold it; the buffer is 9 again (dd7748a8c) and M74 takes it to 8
    ("R8: the walk's path buffer one short of depth 9", [(G, "uint256[] memory path = new uint256[](9);", "uint256[] memory path = new uint256[](8);")]),
    ("R8: the base's limit back at 256", [(G, "uint256 internal constant TREE_LEAVES_LIMIT = 512;", "uint256 internal constant TREE_LEAVES_LIMIT = 256;")]),
    ("R8: PqChat's cap back at 256", [(C, "uint256 internal constant TREE_LEAVES_MAX = 512;", "uint256 internal constant TREE_LEAVES_MAX = 256;")]),
    ("R8: PqChat's cap at 513", [(C, "uint256 internal constant TREE_LEAVES_MAX = 512;", "uint256 internal constant TREE_LEAVES_MAX = 513;"), (G, "uint256 internal constant TREE_LEAVES_LIMIT = 512;", "uint256 internal constant TREE_LEAVES_LIMIT = 513;")]),
    # C10 32 -> 20 (owner 2026-11-25)
    ("C10: 21 changes", [(C, "uint256 internal constant TREE_CHANGES_MAX = 20;", "uint256 internal constant TREE_CHANGES_MAX = 21;")]),
    ("C10: 19 changes", [(C, "uint256 internal constant TREE_CHANGES_MAX = 20;", "uint256 internal constant TREE_CHANGES_MAX = 19;")]),
    # the re-review of 2026-11-25. E-2: at home an exit's UAs in the named epoch's lists too
    ("E-2 mode 0: a leaver not checked on the epoch named", [(S, "            if (_memberAt(m, l.member) == type(uint256).max) revert IPqChat.PqChatNotMember(l.member);\n", "")]),
    ("E-2 mode 0: a removal's lists not checked on the epoch named", [(S, "        if (at != r.epochId) _namedLists(r.epochId, r.admin, r.members); // E-2 (controller call 2026-11-25)\n", "")]),
    ("E-2: the named epoch's admin check dropped", [(B, "        if (!_has(admins, admin)) _fail(F_NOT_ADMIN, uint256(admin), 0);\n", "")]),
    ("E-2: the named epoch's UA check dropped", [(B, "            if (!_removable(m, admins, uas[i])) _fail(F_NOT_MEMBER, uint256(uas[i]), 0);\n", "")]),
    ("E-2 PqVault: a leaver not checked on the epoch named", [(V, "            if (_memberAt(m, l.member) == type(uint256).max) revert PqVaultNotMember(l.member);\n", "")], "pqvault"),
    ("E-2 PqVault: a removal's lists not checked on the epoch named", [(V, "        if (at != r.epochId) _namedLists(r.epochId, r.admin, r.members); // E-2 (controller call 2026-11-25)\n", "")], "pqvault"),
    # A-16: a replica takes a repeat
    ("A-16 mode 0: a replica refuses a repeated leave", [(S, "(home && (ep.left[l.member] || ep.removedOf[l.member]))) {\n            revert IPqChat", "(ep.left[l.member] || ep.removedOf[l.member])) {\n            revert IPqChat")]),
    ("A-16 mode 0: a replica refuses a repeated removal", [(S, "(home && ep.removedOf[r.members[i]])) {\n                revert IPqChat", "ep.removedOf[r.members[i]]) {\n                revert IPqChat")]),
    ("A-16 PqVault: a replica refuses a repeated leave", [(V, "(home && (ep.left[l.member] || ep.removedOf[l.member]))) {\n            revert PqVault", "(ep.left[l.member] || ep.removedOf[l.member])) {\n            revert PqVault")], "pqvault"),
    ("A-16 PqVault: a replica refuses a repeated removal", [(V, "(home && ep.removedOf[r.members[i]])) {\n                revert PqVault", "ep.removedOf[r.members[i]]) {\n                revert PqVault")], "pqvault"),
    ("A-16 mode 0: the removed count not kept", [(S, "        ep.removed += _flagRemoved(ep, r.members);", "        _flagRemoved(ep, r.members);")]),
    ("A-16: _flagRemoved sets no flag", [(B, "                ep.removedOf[uas[i]] = true;\n", "")]),
    # A-13: the replica's ancestor walk
    ("A-13: the walk bound 16 -> 1", [(B, "for (uint256 k; k < EXIT_LAG_MAX && a.epoch != 0; ++k)", "for (uint256 k; k < 1 && a.epoch != 0; ++k)")]),
    ("A-13: the walk bound 16 -> 15", [(B, "for (uint256 k; k < EXIT_LAG_MAX && a.epoch != 0; ++k)", "for (uint256 k; k < EXIT_LAG_MAX - 1 && a.epoch != 0; ++k)")]),
    ("A-13: the walk unbounded", [(B, "for (uint256 k; k < EXIT_LAG_MAX && a.epoch != 0; ++k)", "for (uint256 k; a.epoch != 0; ++k)")]),
    ("A-13: an ancestor's removedOf not read", [(B, "            if (a.left[ua] || a.removedOf[ua]) return true;", "            if (a.left[ua]) return true;")]),
    # A-14: fable-A's ten rows
    ("A-14 row 1: mode 0's leave record under the named epoch", [(S, "if (_keep()) _s().leaves[at].push(", "if (_keep()) _s().leaves[l.epochId].push(")]),
    ("A-14 row 2: treeLeave's PqChatLeft with the epoch named", [(S, "emit IPqChat.PqChatLeft(l.sessionId, hid, l.member);", "emit IPqChat.PqChatLeft(l.sessionId, l.epochId, l.member);")]),
    ("A-14 row 3: treeRemove's PqChatRemoved with the epoch named", [(S, "emit IPqChat.PqChatRemoved(r.sessionId, hid, r.admin, r.members);", "emit IPqChat.PqChatRemoved(r.sessionId, r.epochId, r.admin, r.members);")]),
    ("A-14 row 4: mode 0's PqChatRemoved with the epoch named", [(S, "emit IPqChat.PqChatRemoved(r.sessionId, at, r.admin, r.members);", "emit IPqChat.PqChatRemoved(r.sessionId, r.epochId, r.admin, r.members);")]),
    ("A-14 row 5: mode 0 remove without the replica's Incomplete check", [(S, "        if (ep.landed != ep.wraps) revert IPqChat.PqChatIncomplete(r.epochId); // a replica's epoch named\n", "")]),
    ("A-14 row 6: mode 0, a UA removed at the head may leave", [(S, "(home && (ep.left[l.member] || ep.removedOf[l.member]))) {\n            revert IPqChat", "(home && ep.left[l.member])) {\n            revert IPqChat")]),
    ("A-14 row 7: PqVaultLeft with the epoch named", [(V, "emit PqVaultLeft(l.vaultId, at, l.member);", "emit PqVaultLeft(l.vaultId, l.epochId, l.member);")], "pqvault"),
    ("A-14 row 8: PqVaultRemoved with the epoch named", [(V, "emit PqVaultRemoved(r.vaultId, at, r.admin, r.members);", "emit PqVaultRemoved(r.vaultId, r.epochId, r.admin, r.members);")], "pqvault"),
    ("A-14 row 9: removeVaultMembers without the replica's Incomplete check", [(V, "        if (ep.landed != ep.wraps) revert PqVaultIncomplete(r.epochId); // a replica's epoch named\n", "")], "pqvault"),
    ("A-14 row 10: PqVault, a UA removed at the head may leave", [(V, "(home && (ep.left[l.member] || ep.removedOf[l.member]))) {\n            revert PqVault", "(home && ep.left[l.member])) {\n            revert PqVault")], "pqvault"),
    # A-15: an empty addWraps / addVaultWraps refused in the entries
    ("A-15: an empty addWraps accepted", [(P, "        if (wraps.length == 0) revert PqChatShape(); // A-15 (as C40): both modes, before the tree's forward\n", "")]),
    ("A-15: an empty addVaultWraps accepted", [(V, "        if (wraps.length == 0) revert PqVaultShape(); // A-15 (as C40)\n", "")], "pqvault"),
    # G-7, G-9, G-10 (the re-review of 2026-11-25)
    ("G-7: a keyed cancel for a target with no code", [(R, "        if (target.code.length == 0) revert TargetHasNoCode(target);\n        bool outer = _enter();\n        (MtxPipelineLib.Out memory o, address r) = _pre(\n            GovernanceRouterTypes.UA_CANCEL_NONCE_FOR", "        bool outer = _enter();\n        (MtxPipelineLib.Out memory o, address r) = _pre(\n            GovernanceRouterTypes.UA_CANCEL_NONCE_FOR")], "governance"),
    ("G-9: a token indexed after its initializer", [(O, "        _index(token, creatorId, CLASS_TOKEN, uint16(kind), version); // G-1: indexed before its code runs\n        IFactoryToken(token).initialize(creatorId, version, initArgs);\n", "        IFactoryToken(token).initialize(creatorId, version, initArgs);\n        _index(token, creatorId, CLASS_TOKEN, uint16(kind), version);\n")], "v2"),
    ("G-9: a DEX indexed after its initializer", [(O, "        _index(dex, creatorId, CLASS_DEX, 0, version); // G-1: indexed before its code runs\n        ISCaaSDex(dex).initialize(creatorId, version, initArgs);\n", "        ISCaaSDex(dex).initialize(creatorId, version, initArgs);\n        _index(dex, creatorId, CLASS_DEX, 0, version);\n")], "governance"),
    ("G-9: an instance indexed after its initializer", [(O, "        _index(instance, creatorId, id.contractClass, id.kind, id.version); // G-1: indexed before its code runs\n        _initInstance(instance, creatorId, initCall);\n", "        _initInstance(instance, creatorId, initCall);\n        _index(instance, creatorId, id.contractClass, id.kind, id.version);\n")], "governance"),
    ("G-10: the book's open_factory_lib another address", [(DB, 'vm.serializeAddress("deploy", "open_factory_lib", address(OpenFactoryLib));', 'vm.serializeAddress("deploy", "open_factory_lib", address(uint160(1)));')], "governance"),
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
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
