// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatTreeModel} from "./PqChatTreeModel.sol";
import {stdJson} from "forge-std/StdJson.sol";

/// The code review of 2026-11-24, area A (fable-A A-7): one negative test with its positive control for each guard of the
/// tree's 24-row mutant table (row 5, `_treeGo`'s early return, is unreachable since A-4 refuses a `gone` UA in both exits:
/// equivalent, no test), each row a mutant of `runs/2026-11-24-review-fix-contract-mutants.py`; D-4's contract side at
/// creation (513 member keys, 33 admins, 4,125 B of `sealedInfo`); and the plan's T11 tree rows not covered elsewhere.
/// Commits built on the test's own tree model. **UNAUDITED.**
contract PqChatTreeGuardsTest is PqChatTreeModel {
    using stdJson for string;

    bytes32 internal A;
    bytes32 internal B;
    bytes32 internal C;
    bytes32 internal E;

    function setUp() public override {
        super.setUp();
        (A, B, C, E) = (person["A"], person["B"], person["C"], person["E"]);
    }

    /// [A, B, E] (key 1 each) with `admins`.
    function _abe(bytes32[] memory admins) internal returns (M memory) {
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](3);
        (mk[0], mk[1], mk[2]) = (_mk(A, 1), _mk(B, 1), _mk(E, 1));
        return _open(mk, admins);
    }

    function _rm(uint32 leaf, bytes32 ua, uint64 kid) internal pure returns (Ch memory) {
        return Ch(false, leaf, ua, kid);
    }

    function _add(uint32 leaf, bytes32 ua, uint64 kid) internal pure returns (Ch memory) {
        return Ch(true, leaf, ua, kid);
    }

    function _err(bytes4 sel) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel);
    }

    function _err(bytes4 sel, bytes32 a) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, a);
    }

    function _sorted(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory) {
        return a < b ? _list(a, b) : _list(b, a);
    }

    function _sort(bytes32[] memory l) internal pure returns (bytes32[] memory) {
        for (uint256 i = 1; i < l.length; ++i) {
            for (uint256 j = i; j > 0 && l[j] < l[j - 1]; --j) {
                (l[j], l[j - 1]) = (l[j - 1], l[j]);
            }
        }
        return l;
    }

    function _plain(M memory m, uint32 leaf, bytes32[] memory admins) internal view returns (Step memory st) {
        (st,) = _build(m, leaf, _noCh(), admins);
    }

    function _tl(M memory m, bytes32 treeId, bytes32 ua) internal returns (IPqChat.PqChatTreeLeave memory) {
        return IPqChat.PqChatTreeLeave(m.sid, treeId, m.head, ua, ++nonceN);
    }

    function _tr(M memory m, bytes32 admin, bytes32[] memory uas) internal returns (IPqChat.PqChatTreeRemove memory) {
        return IPqChat.PqChatTreeRemove(m.sid, m.treeId, m.head, m.epoch + 1, uas, admin, ++nonceN);
    }

    function _leaveRefused(IPqChat.PqChatTreeLeave memory l, bytes memory err) internal {
        IUARegistry.UASig memory sg = _sig(l.member, th2.treeLeave(l));
        vm.expectRevert(err);
        vchat.treeLeave(l, sg);
    }

    function _removeRefused(IPqChat.PqChatTreeRemove memory r, bytes memory err) internal {
        IUARegistry.UASig memory sg = _sig(r.admin, th2.treeRemove(r));
        vm.expectRevert(err);
        vchat.treeRemove(r, sg);
    }

    function _remove(IPqChat.PqChatTreeRemove memory r) internal {
        vchat.treeRemove(r, _sig(r.admin, th2.treeRemove(r)));
    }

    function _msg(bytes32 sid, bytes32 eid, bytes32 sender) internal returns (IPqChat.PqChatMessage memory m) {
        (m.sessionId, m.epochId, m.sender, m.counter) = (sid, eid, sender, ++nonceN);
        m.ciphertext = hex"01";
    }

    function _post(IPqChat.PqChatMessage memory m) internal {
        vchat.postMessage(m, _sig(m.sender, h.message(m)));
    }

    function _postRefused(IPqChat.PqChatMessage memory m, bytes memory err) internal {
        IUARegistry.UASig memory sg = _sig(m.sender, h.message(m));
        vm.expectRevert(err);
        vchat.postMessage(m, sg);
    }

    // ------------------------------------------------------------------ the exits (rows 1, 4, 9, 10, 17-21)

    /// Row 1 (C30, codex-r2-5): a `treeLeave` of the session's twin at another home (another `treeId`) is
    /// `PqChatTreeHome`; the session's own lands.
    function test_a7_treeLeaveOfAnotherTreeIdRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        _leaveRefused(_tl(m, keccak256("the twin at another home"), B), _err(IPqChat.PqChatTreeHome.selector));
        _leaveT(m, B); // control
    }

    /// Row 1: the same for a `treeRemove`.
    function test_a7_treeRemoveOfAnotherTreeIdRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        IPqChat.PqChatTreeRemove memory r = _tr(m, A, _list(B));
        r.treeId = keccak256("the twin at another home");
        _removeRefused(r, _err(IPqChat.PqChatTreeHome.selector));
        _remove(_tr(m, A, _list(B))); // control
    }

    /// Row 4: an admin removed at the head (still in the head's list until the next commit) is no admin: its removal of
    /// another UA is `PqChatNotAdmin`; the remaining admin's lands.
    function test_a7_removedAdminRemovesNobody() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_sorted(A, E));
        _remove(_tr(m, E, _list(A)));
        _removeRefused(_tr(m, A, _list(B)), _err(IPqChat.PqChatNotAdmin.selector, A));
        _remove(_tr(m, E, _list(B))); // control
    }

    /// Row 9: a registered UA that holds no leaf leaves: `PqChatNotMember`; a member's leave lands.
    function test_a7_leaveOfANonMemberRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        _leaveRefused(_tl(m, m.treeId, C), _err(IPqChat.PqChatNotMember.selector, C));
        _leaveT(m, B); // control
    }

    /// Row 10: an admin's removal of a registered UA that never joined (no leaf, no admin) is `PqChatNotMember`; of a
    /// member it lands.
    function test_a7_removalOfANonMemberRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        _removeRefused(_tr(m, A, _list(C)), _err(IPqChat.PqChatNotMember.selector, C));
        _remove(_tr(m, A, _list(B))); // control
    }

    /// Row 17: one admin's nonce serves one removal: another record at the same nonce is `PqChatNonceUsed`; at a fresh
    /// nonce it lands.
    function test_a7_removalNonceUsedOnce() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        IPqChat.PqChatTreeRemove memory r = _tr(m, A, _list(B));
        _remove(r);
        IPqChat.PqChatTreeRemove memory again = _tr(m, A, _list(E));
        again.nonce = r.nonce;
        bytes32 scope = PqChatTypes.scopeEpoch(m.sid, A);
        _removeRefused(again, abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, scope, r.nonce));
        _remove(_tr(m, A, _list(E))); // control
    }

    /// Row 18: a leave spends its nonce (`nonceUsed` true after it, false before).
    function test_a7_leaveSpendsItsNonce() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        bytes32 scope = PqChatTypes.scopeEpoch(m.sid, B);
        assertFalse(vchat.nonceUsed(scope, nonceN + 1), "control: free before");
        _leaveT(m, B);
        assertTrue(vchat.nonceUsed(scope, nonceN), "spent by the leave");
    }

    /// Row 19: `nextEpoch` must be the named epoch's number plus one: `PqChatEpochNumber`; the right one lands.
    function test_a7_removalNextEpochChecked() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        IPqChat.PqChatTreeRemove memory r = _tr(m, A, _list(B));
        r.nextEpoch = m.epoch + 2;
        _removeRefused(r, abi.encodeWithSelector(IPqChat.PqChatEpochNumber.selector, m.epoch + 1, m.epoch + 2));
        _remove(_tr(m, A, _list(B))); // control
    }

    /// Row 20: a removal's UAs strictly sorted: the reversed pair and a repeated UA are `PqChatShape`; sorted, it lands.
    function test_a7_removalMembersSorted() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        bytes32[] memory s = _sorted(B, E);
        _removeRefused(_tr(m, A, _list(s[1], s[0])), _err(IPqChat.PqChatShape.selector));
        _removeRefused(_tr(m, A, _list(B, B)), _err(IPqChat.PqChatShape.selector));
        _remove(_tr(m, A, s)); // control
    }

    /// Row 21: a removal of nobody is `PqChatShape`; of one UA it lands.
    function test_a7_emptyRemovalRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        _removeRefused(_tr(m, A, new bytes32[](0)), _err(IPqChat.PqChatShape.selector));
        _remove(_tr(m, A, _list(B))); // control
    }

    // ------------------------------------------------------------------ the head of a message (rows 2, 3)

    /// Row 2: a message of session S naming another session's head is `PqChatUnknown`; at its own head it lands.
    function test_a7_messageNamingAnotherSessionsHead() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        M memory o = _abe(_list(A));
        _postRefused(_msg(m.sid, o.head, B), _err(IPqChat.PqChatUnknown.selector, o.head));
        _post(_msg(m.sid, m.head, B)); // control
    }

    /// Row 3: a message on an epoch that is no longer the head is `PqChatEpochTaken(old, new)`; on the head it lands.
    function test_a7_messageOnAnOldHead() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 1, _noCh(), _list(A));
        n = _land(st, n, m);
        _postRefused(_msg(m.sid, m.head, B), abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, m.head, n.head));
        _post(_msg(m.sid, n.head, B)); // control
    }

    // ------------------------------------------------------------------ a commit's Removes and Adds (rows 6-8, 14)

    /// Row 6 (C18, codex-1): an Add whose `kemHash` is another valid registry key (D's) is `PqChatKemKey(ua, keyId)`; with
    /// the registry's own it lands.
    function test_a7_addKemHashIsTheRegistrys() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 0, _chs(_add(3, C, 1)), _list(A));
        Step memory x = _copyStep(st);
        x.c.adds[0].kemHash = _kemHash(person["D"], 1);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, C, uint64(1)));
        _land(st, n, m); // control
    }

    /// Row 7: one key added at two leaves of one commit is `PqChatTreeKeyLive`; at one leaf it lands.
    function test_a7_keyAddedTwiceInOneCommit() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory x,) = _build(m, 0, _chs(_add(3, C, 1), _add(4, C, 1)), _list(A));
        _refused(x, _err(IPqChat.PqChatTreeKeyLive.selector, _kemHash(C, 1)));
        (Step memory st, M memory n) = _build(m, 0, _chs(_add(3, C, 1)), _list(A));
        _land(st, n, m); // control
    }

    /// Row 8: the author's Remove of the leaf it commits from is `PqChatTreeLeaf(leaf)`; its Remove of another UA's leaf
    /// lands (an admin's).
    function test_a7_authorRemovesItsOwnLeaf() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory x,) = _build(m, 0, _chs(_rm(0, A, 1)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeLeaf.selector, uint32(0)));
        (Step memory st, M memory n) = _build(m, 0, _chs(_rm(1, B, 1)), _list(A));
        _land(st, n, m); // control
    }

    /// Row 14: an Add at a position above `used` (leaf 4 of 3 used) is `PqChatTreeLeaf(4)`; at `used` it lands.
    function test_a7_addAboveUsedRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory x,) = _build(m, 0, _chs(_add(4, C, 1)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeLeaf.selector, uint32(4)));
        (Step memory st, M memory n) = _build(m, 0, _chs(_add(3, C, 1)), _list(A));
        _land(st, n, m); // control
    }

    // ------------------------------------------------------------------ a commit's bounds (rows 11-13)

    /// `ua` holds `n` more admitted KEM versions, `first..first + n - 1` (device `name`'s bytes with other `pk_X`).
    function _keys(bytes32 ua, string memory name, uint64 first, uint256 n) internal {
        for (uint256 i; i < n; ++i) {
            _setKem(ua, first + uint64(i), _variant(name, first + i));
        }
    }

    /// `n` Adds from leaf `at` of `ua`'s versions `first..`.
    function _adds(Ch[] memory c, uint256 from, uint32 at, bytes32 ua, uint64 first, uint256 n) internal pure {
        for (uint256 i; i < n; ++i) {
            c[from + i] = _add(at + uint32(i), ua, first + uint64(i));
        }
    }

    /// Row 11 (C10, owner 2026-11-25: 20): 21 changes in one commit are `PqChatShape`; 20 land (C, D eight keys each, F
    /// four).
    function test_a7_changesBound() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        Ch[] memory c = new Ch[](21);
        _keys(person["C"], "C", 40, 8);
        _adds(c, 0, 3, person["C"], 40, 8);
        _keys(person["D"], "D", 40, 8);
        _adds(c, 8, 11, person["D"], 40, 8);
        _keys(person["F"], "F", 40, 4);
        _adds(c, 16, 19, person["F"], 40, 4);
        c[20] = _add(23, person["H"], 1);
        (Step memory x,) = _build(m, 0, c, _list(A));
        _refused(x, _err(IPqChat.PqChatShape.selector));
        assembly ("memory-safe") {
            mstore(c, 20)
        }
        (Step memory st, M memory n) = _build(m, 0, c, _list(A));
        _land(st, n, m); // control
    }

    /// Row 12 (C10): a ninth live key of one UA by Adds is `PqChatShape`; the eighth lands.
    function test_a7_keysPerUaBound() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        _keys(A, "A", 50, 8);
        Ch[] memory c = new Ch[](8);
        _adds(c, 0, 3, A, 50, 8); // A: 1 + 8 live
        (Step memory x,) = _build(m, 0, c, _list(A));
        _refused(x, _err(IPqChat.PqChatShape.selector));
        assembly ("memory-safe") {
            mstore(c, 7)
        }
        (Step memory st, M memory n) = _build(m, 0, c, _list(A));
        _land(st, n, m); // control: A at 8
    }

    /// Row 13 (C24): 33 admins in a commit are `PqChatShape` (every one registered, sorted); 32 land.
    function test_a7_adminsBound() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        for (uint8 s = 6; s < 26; ++s) {
            _member(s);
        }
        string[8] memory names = ["A", "B", "C", "D", "E", "F", "G", "H"];
        bytes32[] memory all = new bytes32[](33);
        for (uint256 i; i < 8; ++i) {
            all[i] = person[names[i]];
        }
        for (uint256 i; i < 25; ++i) {
            all[8 + i] = ids[i];
        }
        _sort(all);
        (Step memory x,) = _build(m, 0, _noCh(), all);
        _refused(x, _err(IPqChat.PqChatShape.selector));
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _without(all, all[0] == A ? all[1] : all[0]));
        _land(st, n, m); // control: 32
    }

    /// `l` less `x` (kept in order).
    function _without(bytes32[] memory l, bytes32 x) internal pure returns (bytes32[] memory r) {
        r = new bytes32[](l.length - 1);
        uint256 k;
        for (uint256 i; i < l.length; ++i) {
            if (l[i] != x) r[k++] = l[i];
        }
    }

    // ------------------------------------------------------------------ the record and its pieces (rows 15, 16, 22-24)

    /// Row 15: a path ciphertext of 1,567 B whose hash the signed list holds is `PqChatPathHash(eid, 0)` (the stored
    /// 1,648 B would not be the signed bytes); at 1,568 B it lands.
    function test_a7_ciphertextSizesChecked() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 1, _noCh(), _list(A));
        assertGt(st.c.ctCount, 0);
        Step memory x = _copyStep(st);
        x.cts = new IPqChat.PathCt[](st.cts.length);
        x.ctHashes = new bytes32[](st.ctHashes.length);
        for (uint256 i; i < st.cts.length; ++i) {
            (x.cts[i], x.ctHashes[i]) = (st.cts[i], st.ctHashes[i]);
        }
        x.cts[0] = IPqChat.PathCt(new bytes(1567), st.cts[0].x25519Eph, st.cts[0].sealedSecret);
        x.ctHashes[0] = th2.pathCt(x.cts[0]);
        x.c.ctListHash = th2.pathList(x.ctTargets, x.ctHashes);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatPathHash.selector, x.epochId, uint256(0)));
        _land(st, n, m); // control
    }

    /// Row 16: a staged record sent again is `PqChatNonceUsed` (the author's nonce spent at acceptance); the first lands.
    function test_a7_commitNonceUsedOnce() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st,) = _build(m, 1, _noCh(), _list(A));
        ++nonceN;
        _commitAlone(vchat, st); // control: staged
        IUARegistry.UASig memory sg = _signC(st.c);
        bytes32 scope = PqChatTypes.scopeEpoch(m.sid, st.c.author);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, scope, st.c.nonce));
        vchat.commit(
            st.c, new uint32[](0), new bytes32[](0), new bytes[](0), new IPqChat.PathCt[](0), new IPqChat.Wrap[](0), sg
        );
    }

    /// Row 22: `wrapHashes` one per Add: none for one Add is `PqChatShape`; one lands.
    function test_a7_wrapHashesPerAdd() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 0, _chs(_add(3, C, 1)), _list(A));
        Step memory x = _copyStep(st);
        x.c.wrapHashes = new bytes32[](0);
        _refused(x, _err(IPqChat.PqChatShape.selector));
        _land(st, n, m); // control
    }

    /// Row 23 (C24): `ctCount` at `leaves` is `PqChatShape` at acceptance (not the walk's `PqChatTreeTargets`); the
    /// walk's count lands.
    function test_a7_ctCountAtLeavesRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 1, _noCh(), _list(A));
        Step memory x = _copyStep(st);
        x.c.ctCount = x.c.leaves;
        _refused(x, _err(IPqChat.PqChatShape.selector));
        _land(st, n, m); // control
    }

    /// Row 24: ciphertexts past the list (`firstCt` at `ctCount`) are `PqChatShape`; from 0 they land.
    function test_a7_ciphertextPastTheListRefused() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st,) = _build(m, 1, _noCh(), _list(A));
        ++nonceN;
        vchat.commit(st.c, st.ctTargets, st.ctHashes, st.nodeKeys, new IPqChat.PathCt[](0), st.wraps, _signC(st.c));
        IPqChat.PathCt[] memory one = new IPqChat.PathCt[](1);
        one[0] = st.cts[0];
        vm.expectRevert(_err(IPqChat.PqChatShape.selector));
        vchat.addPath(st.epochId, st.c.ctCount, one);
        vchat.addPath(st.epochId, 0, st.cts); // control
        assertTrue(vchat.epochComplete(st.epochId), "complete");
    }

    // ------------------------------------------------------------------ D-4: a tree session's bounds at creation

    /// `n` registered `mldsa65` UAs, each with a KEM key version 0 (scheme 1; not admitted: nothing lands here), sorted.
    function _many(uint256 n) internal returns (bytes32[] memory u) {
        u = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            bytes memory key = new bytes(1952);
            bytes32 w = keccak256(abi.encode("d4 key", i));
            for (uint256 j; j < 1952; j += 32) {
                assembly ("memory-safe") {
                    mstore(add(add(key, 32), j), w)
                }
                w = keccak256(abi.encode(w));
            }
            IUARegistry.UAAttrs memory a;
            a.kem.scheme = 1;
            a.kem.mlkemEk = abi.encodePacked(keccak256(abi.encode("d4 ek", i)), new bytes(1536));
            a.kem.x25519 = bytes32((i + 2) << 8 | 9);
            u[i] = _register(p, ML, key, a, _pop(p, ML, key, a), "");
            keyOf_[u[i]] = key;
        }
        _sort(u);
    }

    /// The tree session of `members` (`u[0..members)`, key 0 each, `u[0]` the creator) with admins `u[0..admins)` and
    /// `info` B of `sealedInfo`, at the vectors' home; no wrap sent.
    function _session(bytes32[] memory u, uint256 members, uint256 admins, uint256 info)
        internal
        returns (IPqChat.PqChatSession memory s, IUARegistry.UASig memory sg)
    {
        (s.creator, s.nonce, s.homeChain, s.homeChatContract) =
        (u[0], ++nonceN, _j().readBytes32(".scenarios[0].genesis.record.homeChain"), address(vchat));
        s.admins = new bytes32[](admins);
        for (uint256 i; i < admins; ++i) {
            s.admins[i] = u[i];
        }
        s.members = new IPqChat.MemberKey[](members);
        s.wrapHashes = new bytes32[](members);
        for (uint256 i; i < members; ++i) {
            (s.members[i], s.wrapHashes[i]) = (_mk(u[i], 0), keccak256(abi.encode(i)));
        }
        (s.groupMode, s.sealedInfo) = (1, new bytes(info));
        sg = _sig(s.creator, h.session(s));
    }

    function _createRefused(bytes32[] memory u, uint256 members, uint256 admins, uint256 info) internal {
        (IPqChat.PqChatSession memory s, IUARegistry.UASig memory sg) = _session(u, members, admins, info);
        vm.expectRevert(_err(IPqChat.PqChatShape.selector));
        vchat.createSession(s, new IPqChat.Wrap[](0), sg);
    }

    function _create(bytes32[] memory u, uint256 members, uint256 admins, uint256 info) internal {
        (IPqChat.PqChatSession memory s, IUARegistry.UASig memory sg) = _session(u, members, admins, info);
        bytes32 sid = vchat.createSession(s, new IPqChat.Wrap[](0), sg);
        (uint256 used,,) = _sizes(vchat, sid);
        assertEq(used, members, "the tree's positions");
    }

    /// D-4 (C10, C24 at creation): 513 member keys, 33 admins, a 4,125-B `sealedInfo` are `PqChatShape`; 512, 32 and
    /// 4,124 B are created.
    function test_d4_createSessionBounds() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory u = _many(513);
        _createRefused(u, 513, 1, 4);
        _create(u, 512, 1, 4); // control
        _createRefused(u, 2, 33, 4);
        _create(u, 2, 32, 4); // control
        _createRefused(u, 2, 1, 4125);
        _create(u, 2, 1, 4124); // control
    }

    // ------------------------------------------------------------------ T11's tree rows (C9, C38)

    /// C9: after two commits, a leave naming epoch 0 (two below the head) lands and is kept under the head, `gone` at the
    /// head's number.
    function test_t11_exitNamingEpoch0AfterTwoCommits() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        bytes32 sid = m.sid;
        (Step memory s1, M memory n1) = _build(m, 1, _noCh(), _list(A));
        n1 = _land(s1, n1, m);
        (Step memory s2, M memory n2) = _build(n1, 2, _noCh(), _list(A));
        n2 = _land(s2, n2, n1);
        IPqChat.PqChatTreeLeave memory l = IPqChat.PqChatTreeLeave(sid, m.treeId, sid, B, ++nonceN);
        vchat.treeLeave(l, _sig(B, th2.treeLeave(l)));
        (uint256 kind, uint256 ep) = _gone(vchat, sid, B);
        assertEq(kind, 1, "left");
        assertEq(ep, n2.epoch, "at the head's number");
        assertEq(vchat.leaveCount(n2.head), 1, "kept under the head");
        assertEq(vchat.leaveCount(sid), 0, "not under the epoch named");
    }

    /// C9, the front-run: B's commit of 7 own Adds completes, then the removal of B naming the epoch before it lands:
    /// all 8 of B's leaves are owed at the head; the next commit that keeps them is `PqChatRemovedKept`, the one that
    /// removes them lands.
    function test_t11_frontRunThenRemoval() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        _keys(B, "B", 60, 7);
        Ch[] memory c = new Ch[](7);
        _adds(c, 0, 3, B, 60, 7);
        (Step memory st, M memory n) = _build(m, 1, c, _list(A));
        n = _land(st, n, m);
        _remove(_tr(m, A, _list(B))); // names the epoch before B's commit
        (,, uint256 owed) = _sizes(vchat, m.sid);
        assertEq(owed, 8, "all of B's leaves at the head");
        (Step memory kept,) = _build(n, 0, _noCh(), _list(A));
        _refused(kept, abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, n.head, B));
        Ch[] memory r = new Ch[](8);
        r[0] = _rm(1, B, 1);
        for (uint256 i; i < 7; ++i) {
            r[1 + i] = _rm(3 + uint32(i), B, 60 + uint64(i));
        }
        (Step memory ok, M memory n2) = _build(n, 0, r, _list(A));
        _land(ok, n2, n); // control
    }

    /// C38, C24: a keyless admin's removal naming its own UA lands (it is `gone`).
    function test_t11_keylessAdminRemovesItself() public {
        _open(); // the vectors in this call's memory
        bytes32 G = person["G"];
        M memory m = _abe(_sorted(A, G));
        _remove(_tr(m, G, _list(G)));
        (uint256 kind,) = _gone(vchat, m.sid, G);
        assertEq(kind, 2, "removed");
    }

    /// C9: one admin's removal then its own leave on one head both land.
    function test_t11_removeThenLeaveByOneAdmin() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_sorted(A, E));
        _remove(_tr(m, A, _list(B)));
        _leaveT(m, A);
        (uint256 kb,) = _gone(vchat, m.sid, B);
        (uint256 ka,) = _gone(vchat, m.sid, A);
        assertEq(kb, 2, "B removed");
        assertEq(ka, 1, "A left");
    }

    function _copyStep(Step memory s) internal pure returns (Step memory t) {
        (t.ctTargets, t.ctHashes, t.nodeKeys, t.cts, t.wraps) = (s.ctTargets, s.ctHashes, s.nodeKeys, s.cts, s.wraps);
        (t.treeHash, t.epochId) = (s.treeHash, s.epochId);
        t.c = abi.decode(abi.encode(s.c), (IPqChat.PqChatCommit));
    }
}
