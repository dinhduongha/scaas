// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqChatTreeViews} from "../../src/pqchat/IPqChatTreeViews.sol";
import {PqChatTreeModel} from "./PqChatTreeModel.sol";

/// The path-less Adds of TreeKEM mode 1 (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §5, §13 rows 1-22; owner
/// R17-R20, controller calls C41-C47): the shape exactly when `pathless` is true, R19's conditions, the bound of R18, the
/// counter `sincePath` (moved at completion only, reset by every completed path commit), no path walk (each Add blanks its
/// own direct path, the author's other nodes keep their keys) and no targets hash. Each refusal beside its positive twin.
/// **UNAUDITED.**
contract PqChatTreePathlessTest is PqChatTreeModel {
    bytes32 internal A;
    bytes32 internal B;
    bytes32 internal C;
    bytes32 internal D;
    bytes32 internal E;
    bytes32 internal F;

    function setUp() public override {
        super.setUp();
        (A, B, C, D, E, F) = (person["A"], person["B"], person["C"], person["D"], person["E"], person["F"]);
    }

    function _add(uint32 leaf, bytes32 ua, uint64 kid) internal pure returns (Ch memory) {
        return Ch(true, leaf, ua, kid);
    }

    function _rm(uint32 leaf, bytes32 ua, uint64 kid) internal pure returns (Ch memory) {
        return Ch(false, leaf, ua, kid);
    }

    /// Members `uas` (key 1 each, sorted), admins `admins`, the bound `bound`.
    function _s(bytes32[] memory uas, bytes32[] memory admins, uint32 bound) internal returns (M memory) {
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](uas.length);
        for (uint256 i; i < uas.length; ++i) {
            mk[i] = _mk(uas[i], 1);
        }
        return _openB(mk, admins, bound);
    }

    function _l3(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](3);
        (l[0], l[1], l[2]) = (a, b, c);
    }

    /// `sincePath`, `pathBound` (slot 3 of the tree, after `used`, `leaves`, `owed`).
    function _since(bytes32 sid) internal view returns (uint256 since, uint256 bound) {
        uint256 w = _at(vchat, _t(sid) + 3);
        (since, bound) = (w >> 96 & 0xffffffff, w >> 128 & 0xffffffff);
    }

    /// The stored `keyAt` of parent `x` (0: blank).
    function _keyAt(bytes32 sid, uint256 x) internal view returns (uint256) {
        return _at(vchat, _m(bytes32(x), _t(sid) + 5) + 1);
    }

    function _targetsHash(bytes32 eid) internal view returns (uint256) {
        return _at(vchat, uint256(keccak256(abi.encode(eid, TREE_ROOT + 1))));
    }

    /// `a` then `b`.
    function _cat(Ch[] memory a, Ch[] memory b) internal pure returns (Ch[] memory r) {
        r = new Ch[](a.length + b.length);
        for (uint256 i; i < a.length; ++i) {
            r[i] = a[i];
        }
        for (uint256 i; i < b.length; ++i) {
            r[a.length + i] = b[i];
        }
    }

    /// `n` fresh registered keys of `ua` (key ids `from..`, unused ones), added at leaves `leaf..`.
    function _keys(bytes32 ua, uint64 from, uint256 n, uint32 leaf) internal returns (Ch[] memory adds) {
        adds = new Ch[](n);
        for (uint256 i; i < n; ++i) {
            _setKem(ua, from + uint64(i), _variant("H", uint256(keccak256(abi.encode(ua, from + i)))));
            adds[i] = _add(leaf + uint32(i), ua, from + uint64(i));
        }
    }

    /// A path-less Add of `adds` by `leaf` with the head's `admins`, landed whole.
    function _pl(M memory m, uint32 leaf, Ch[] memory adds, bytes32[] memory admins) internal returns (M memory) {
        (Step memory st, M memory n) = _buildPl(m, leaf, adds, admins);
        return _land(st, n, m);
    }

    // ----- rows 1, 20: the tree of a path-less Add -----

    /// Row 1: on a warm tree (B's and F's path commits), A adds D in the far half: completed, `sincePath` 1, A's path nodes off
    /// D's direct path (1, 3) keep their keys, the shared root and D's path (9, 11, 7) are blank, the root is the model's,
    /// no targets hash. Control: C adds its own key at its sibling: every node of C's path (5, 3) blank.
    function test_r1_aPathlessAddKeepsTheAuthorsOtherNodes() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory five = new bytes32[](5);
        (five[0], five[1], five[2], five[3], five[4]) = (A, B, C, E, F);
        M memory m = _s(five, _list(A), 0);
        (Step memory st, M memory n) = _build(m, 1, _noCh(), _list(A));
        m = _land(st, n, m);
        (st, n) = _build(m, 4, _noCh(), _list(A));
        m = _land(st, n, m);
        assertTrue(_keyAt(m.sid, 1) != 0 && _keyAt(m.sid, 3) != 0 && _keyAt(m.sid, 7) != 0, "warm");
        (st, n) = _buildPl(m, 0, _chs(_add(5, D, 1)), _list(A));
        assertEq(st.c.ctCount, 0);
        assertEq(st.c.nodeKeyHashes.length, 0);
        m = _land(st, n, m);
        (uint256 since,) = _since(m.sid);
        assertEq(since, 1);
        assertTrue(_keyAt(m.sid, 1) != 0 && _keyAt(m.sid, 3) != 0, "A's nodes off D's path kept");
        assertEq(_keyAt(m.sid, 7) | _keyAt(m.sid, 9) | _keyAt(m.sid, 11), 0, "D's direct path and the root blank");
        assertEq(_targetsHash(st.epochId), 0, "no targets hash for ctCount 0");
        // the control: the Add at the author's sibling
        M memory k = _s(_l3(A, B, C), _list(A), 0);
        (st, n) = _build(k, 0, _noCh(), _list(A));
        k = _land(st, n, k);
        assertTrue(_keyAt(k.sid, 1) != 0 && _keyAt(k.sid, 3) != 0);
        k = _pl(k, 2, _chs(_add(3, C, 2)), _list(A));
        assertEq(_keyAt(k.sid, 3) | _keyAt(k.sid, 5), 0, "every node of C's path blank");
        assertTrue(_keyAt(k.sid, 1) != 0, "A's other node kept");
    }

    /// The path-less review's A-3: the slot `_targetsHash` reads holds a path commit's staged targets hash (the positive
    /// control of row 1's "no targets hash for ctCount 0"): the record alone of a path commit stores one, a path-less one none.
    function test_r1_theTargetsHashSlot() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_l3(A, B, C), _list(A), 0);
        (Step memory p,) = _build(m, 0, _chs(_add(3, D, 1)), _list(A));
        _commitAlone(vchat, p);
        assertTrue(_targetsHash(p.epochId) != 0, "a path commit's targets hash in the slot");
        M memory k = _s(_l3(A, B, C), _list(A), 0);
        (Step memory q,) = _buildPl(k, 0, _chs(_add(3, D, 1)), _list(A));
        _commitAlone(vchat, q);
        assertEq(_targetsHash(q.epochId), 0, "none for a path-less record");
    }

    /// Row 20: the first commit after creation is path-less (parent epoch 0).
    function test_r20_firstCommitPathless() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_list(A, B), _list(A), 0);
        m = _pl(m, 0, _chs(_add(2, C, 1)), _list(A));
        (uint256 since,) = _since(m.sid);
        assertEq(since, 1);
        assertEq(m.epoch, 1);
    }

    // ----- rows 2-5b: R19's conditions -----

    /// Row 2: path-less with a Remove: `PqChatTreePathRequired`; the same Remove with a path completes.
    function test_r2_aRemoveNeedsAPath() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_l3(A, B, C), _list(A), 0);
        (Step memory x,) = _buildPl(m, 0, _chs(_rm(2, C, 1), _add(3, D, 1)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreePathRequired.selector));
        (Step memory st, M memory n) = _build(m, 0, _chs(_rm(2, C, 1), _add(3, D, 1)), _list(A));
        _land(st, n, m);
    }

    /// Row 3: path-less with an admin added, and with a live admin dropped: `PqChatTreePathRequired`; the list unchanged
    /// completes.
    function test_r3_anAdminChangeNeedsAPath() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_l3(A, B, C), _list(A), 0);
        (Step memory x,) = _buildPl(m, 0, _chs(_add(3, D, 1)), _list(A, B));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreePathRequired.selector));
        M memory m2 = _s(_l3(A, B, C), _list(A, B), 0);
        (x,) = _buildPl(m2, 0, _chs(_add(3, D, 1)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreePathRequired.selector));
        // the same length, another admin (B replaced by C): element for element, not the count
        (x,) = _buildPl(m2, 0, _chs(_add(3, D, 1)), _list(A, C));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreePathRequired.selector));
        _pl(m2, 0, _chs(_add(3, D, 1)), _list(A, B));
    }

    /// Row 4: path-less on a head that owes leaves (after `treeLeave`, after `treeRemove`): `PqChatRemovedKept`; the
    /// honouring path commit completes, then path-less is accepted.
    function test_r4_nothingOwed() public {
        _open(); // the vectors in this call's memory
        for (uint256 how; how < 2; ++how) {
            M memory m = _s(_l3(A, B, C), _list(A), 0);
            if (how == 0) _leaveT(m, C);
            else _removeT(m, A, _list(C));
            (Step memory x,) = _buildPl(m, 0, _chs(_add(3, D, 1)), _list(A));
            _refused(x, abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, m.sid, C));
            (Step memory st, M memory n) = _build(m, 0, _chs(_rm(2, C, 1)), _list(A));
            m = _land(st, n, m);
            _pl(m, 0, _chs(_add(3, D, 1)), _list(A));
        }
    }

    /// Rows 5, 5b: a keyless head admin G removed and kept (`owed` 0): path-less with the head's list is `PqChatRemovedKept`;
    /// with the list less G `PqChatTreePathRequired` (dropping a gone admin is an admin change, R19); a path commit drops
    /// G, then path-less is accepted.
    function test_r5_aGoneAdminNeedsAPath() public {
        _open(); // the vectors in this call's memory
        bytes32 G = person["G"];
        M memory m = _s(_l3(A, B, C), _list(A, G), 0);
        _removeT(m, A, _list(G));
        (,, uint256 owed) = _sizes(vchat, m.sid);
        assertEq(owed, 0);
        (Step memory x,) = _buildPl(m, 0, _chs(_add(3, D, 1)), _list(A, G));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, m.sid, G));
        (x,) = _buildPl(m, 0, _chs(_add(3, D, 1)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreePathRequired.selector));
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _list(A));
        m = _land(st, n, m);
        _pl(m, 0, _chs(_add(3, D, 1)), _list(A));
    }

    // ----- rows 6, 7, 18, 14, 13: the bound and the counter -----

    /// Row 6: bound 24; from `sincePath` 22 an Add of 3 is `PqChatTreePathBound(22, 24)` (refused whole); an Add of 2
    /// completes; then an Add of 1 is `PqChatTreePathBound(24, 24)`; a path commit resets to 0 and path-less is accepted
    /// again. Row 18: that path commit's own Adds are not counted.
    function test_r6_theBound() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_list(A, B), _list(A), 24);
        (, uint256 bound) = _since(m.sid);
        assertEq(bound, 24);
        m = _pl(m, 0, _cat(_keys(C, 100, 8, 2), _keys(D, 100, 8, 10)), _list(A));
        m = _pl(m, 0, _keys(E, 100, 6, 18), _list(A));
        (uint256 since,) = _since(m.sid);
        assertEq(since, 22);
        (Step memory x,) = _buildPl(m, 0, _keys(F, 100, 3, 24), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreePathBound.selector, uint32(22), uint32(24)));
        m = _pl(m, 0, _keys(F, 103, 2, 24), _list(A));
        (since,) = _since(m.sid);
        assertEq(since, 24);
        bytes32 G = person["G"];
        (x,) = _buildPl(m, 0, _keys(G, 100, 1, 26), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreePathBound.selector, uint32(24), uint32(24)));
        (Step memory st, M memory n) = _build(m, 0, _keys(G, 101, 1, 26), _list(A));
        m = _land(st, n, m);
        (since,) = _since(m.sid);
        assertEq(since, 0, "a path commit resets and does not count its own Adds (row 18)");
        m = _pl(m, 0, _keys(G, 102, 1, 27), _list(A));
        (since,) = _since(m.sid);
        assertEq(since, 1);
    }

    /// Row 7: bound 0: 30 path-less leaves in a row accepted.
    function test_r7_boundZeroNeverForces() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_list(A, B), _list(A), 0);
        m = _pl(m, 0, _cat(_keys(C, 100, 8, 2), _keys(D, 100, 8, 10)), _list(A));
        m = _pl(m, 0, _cat(_keys(E, 100, 8, 18), _keys(F, 100, 6, 26)), _list(A));
        (uint256 since,) = _since(m.sid);
        assertEq(since, 30);
    }

    /// Row 14: from `sincePath` > 0, the last live leaf's commit (an empty path, no Add) resets it.
    function test_r14_theLastLiveLeafResets() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_list(A, B), _list(A), 0);
        m = _pl(m, 0, _chs(_add(2, C, 1)), _list(A));
        (Step memory st, M memory n) = _build(m, 0, _chs(_rm(1, B, 1), _rm(2, C, 1)), _list(A));
        assertEq(st.c.ctCount, 0);
        m = _land(st, n, m);
        (uint256 since,) = _since(m.sid);
        assertEq(since, 0);
    }

    /// Rows 13, 19: a staged path commit loses its slot to a one-transaction path-less Add (`PqChatEpochTaken`, its record
    /// in state); `sincePath` moved by the winner only, never by the staged or losing record. The control: the path commit
    /// alone completes.
    function test_r13_r19_theCounterMovesAtCompletionOnly() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_l3(A, B, C), _list(A), 0);
        (Step memory sb,) = _build(m, 1, _noCh(), _list(A));
        ++nonceN;
        _commitAlone(vchat, sb);
        (Step memory sp,) = _buildPl(m, 0, _chs(_add(3, D, 1)), _list(A));
        ++nonceN;
        _commitAlone(vchat, sp); // staged: one Welcome wrap missing
        (uint256 since,) = _since(m.sid);
        assertEq(since, 0, "a staged record does not count");
        (Step memory st, M memory n) = _buildPl(m, 2, _chs(_add(3, C, 2)), _list(A));
        _land(st, n, m);
        (since,) = _since(m.sid);
        assertEq(since, 1, "the winner counts");
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, m.head, st.epochId));
        vchat.addPathList(sb.epochId, sb.ctTargets, sb.ctHashes);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, m.head, st.epochId));
        vchat.addWraps(sp.epochId, 0, sp.wraps);
        (since,) = _since(m.sid);
        assertEq(since, 1, "a losing record does not count");
        // the control
        M memory k = _s(_l3(A, B, C), _list(A), 0);
        (sb, n) = _build(k, 1, _noCh(), _list(A));
        _land(sb, n, k);
    }

    /// Row 12: 12 Adds staged (the record and some wraps), a `treeLeave` lands: the last wrap fails completion's step 1
    /// (`PqChatRemovedKept`). The control: without the exit the last wrap completes.
    function test_r12_anExitBetweenStagedWraps() public {
        _open(); // the vectors in this call's memory
        for (uint256 exit; exit < 2; ++exit) {
            M memory m = _s(_l3(A, B, C), _list(A), 0);
            (Step memory st, M memory n) = _buildPl(
                m, 0, _cat(_keys(D, 100 + 10 * uint64(exit), 8, 3), _keys(E, 100 + 10 * uint64(exit), 4, 11)), _list(A)
            );
            ++nonceN;
            IPqChat.Wrap[] memory first = new IPqChat.Wrap[](11);
            for (uint256 i; i < 11; ++i) {
                first[i] = st.wraps[i];
            }
            vchat.commit(
                st.c, new uint32[](0), new bytes32[](0), new bytes[](0), new IPqChat.PathCt[](0), first, _signC(st.c)
            );
            IPqChat.Wrap[] memory last = new IPqChat.Wrap[](1);
            last[0] = st.wraps[11];
            if (exit == 0) {
                _leaveT(m, C);
                vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, m.sid, C));
                vchat.addWraps(st.epochId, 11, last);
            } else {
                vchat.addWraps(st.epochId, 11, last);
                assertTrue(vchat.epochComplete(st.epochId));
                assertEq(_root(vchat, m.sid), _mRoot(n));
            }
        }
    }

    // ----- rows 8, 9, 11: shapes and rights -----

    /// Row 8 (mode 1): a bound of 511 is `PqChatShape` at creation; 510 and 0 open.
    function test_r8_theCapOnTheBound() public {
        _open(); // the vectors in this call's memory
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](2);
        (mk[0], mk[1]) = (_mk(A, 1), _mk(B, 1));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        this.openAt(mk, 511);
        M memory m = _openB(mk, _list(A), 510);
        (, uint256 bound) = _since(m.sid);
        assertEq(bound, 510);
        _openB(mk, _list(A), 0);
    }

    function openAt(IPqChat.MemberKey[] memory mk, uint32 bound) external {
        _openB(mk, _list(A), bound);
    }

    /// Row 9: a non-admin's path-less Add of its own key; of another UA's key `PqChatNotAdmin`; up to `KEYS_PER_UA_MAX` live
    /// keys, the ninth `PqChatShape`.
    function test_r9_aMembersOwnKeys() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_list(A, B), _list(A), 0);
        (Step memory x,) = _buildPl(m, 1, _chs(_add(2, C, 1)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, B));
        m = _pl(m, 1, _keys(B, 40, 7, 2), _list(A));
        assertEq(_liveCount(vchat, m.sid, B), 8, "KEYS_PER_UA_MAX reached exactly");
        (x,) = _buildPl(m, 1, _keys(B, 47, 1, 9), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
    }

    /// Row 11: the pieces of a path on a path-less epoch are refused as for `ctCount` 0; `pathless` true with a node key,
    /// with `ctCount` above 0, with another list hash, with a whole consistent path or with no Add is `PqChatShape`; `pathless` false with Adds and an empty
    /// path is `PqChatTreeTargets`. The control: `addWraps` lands the wraps and the same Adds with `pathless` true complete.
    function test_r11_theShapeExactlyWhenPathless() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_l3(A, B, C), _list(A), 0);
        (Step memory good, M memory n) = _buildPl(m, 0, _chs(_add(3, D, 1)), _list(A));
        Step memory x = _copy2(good);
        x.c.nodeKeyHashes = new bytes32[](1);
        x.c.nodeKeyHashes[0] = keccak256(nodeKey);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        x = _copy2(good);
        x.c.ctCount = 1;
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        x = _copy2(good);
        x.c.ctListHash = keccak256("another list");
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        (Step memory none,) = _buildPl(m, 0, _noCh(), _list(A));
        _refused(none, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        x = _copy2(good);
        x.c.pathless = false;
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeTargets.selector, uint256(2)));
        // a whole path on a path-less record (node keys, ciphertexts and their list, each consistent with the others, so no
        // other shape rule refuses it): `PqChatShape` by the path-less rule alone
        (Step memory p,) = _build(m, 0, _chs(_add(3, D, 1)), _list(A));
        p.c.pathless = true;
        _refused(p, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        // staged: the record alone; the path pieces refused, the wrap lands and completes
        ++nonceN;
        _commitAlone(vchat, good);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathList.selector, good.epochId));
        vchat.addPathList(good.epochId, new uint32[](0), new bytes32[](0));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        vchat.addPathKeys(good.epochId, new bytes[](1));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathList.selector, good.epochId));
        vchat.addPath(good.epochId, 0, new IPqChat.PathCt[](1));
        vchat.addWraps(good.epochId, 0, good.wraps);
        assertTrue(vchat.epochComplete(good.epochId));
        assertEq(_root(vchat, m.sid), _mRoot(n));
    }

    function _copy2(Step memory s) internal pure returns (Step memory t) {
        (t.ctTargets, t.ctHashes, t.nodeKeys, t.cts, t.wraps) = (s.ctTargets, s.ctHashes, s.nodeKeys, s.cts, s.wraps);
        (t.treeHash, t.epochId) = (s.treeHash, s.epochId);
        t.c = abi.decode(abi.encode(s.c), (IPqChat.PqChatCommit));
    }

    /// Row 10: on a warm tree with the Add in the far half and the author's lower nodes keyed, a `treeHash` with the
    /// author's path blanked, and one keeping the root's key, are `PqChatTreeHash`; the path-less tree completes.
    function test_r10_theTreeHashIsThePathlessTree() public {
        _open(); // the vectors in this call's memory
        bytes32[] memory five = new bytes32[](5);
        (five[0], five[1], five[2], five[3], five[4]) = (A, B, C, E, F);
        M memory m = _s(five, _list(A), 0);
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _list(A));
        m = _land(st, n, m);
        (Step memory good, M memory g) = _buildPl(m, 0, _chs(_add(5, D, 1)), _list(A));
        bytes32 right = good.c.treeHash;
        M memory wrong = _copy(g);
        _blank(wrong, 0); // the author's path blanked too
        Step memory x = _copy2(good);
        x.c.treeHash = _mRoot(wrong);
        assertTrue(x.c.treeHash != right);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeHash.selector, right));
        wrong = _copy(g);
        wrong.key[7] = m.key[7]; // the root keeps its key
        x = _copy2(good);
        x.c.treeHash = _mRoot(wrong);
        assertTrue(x.c.treeHash != right);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeHash.selector, right));
        _land(good, g, m);
    }

    // ----- rows 15, 16, 21, 22 -----

    /// Row 15: an Add at `used` that doubles `leaves`, path-less.
    function test_r15_aPathlessAddGrowsTheTree() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_list(A, B), _list(A), 0);
        assertEq(m.leaves, 2);
        m = _pl(m, 0, _chs(_add(2, C, 1)), _list(A));
        (, uint256 leaves,) = _sizes(vchat, m.sid);
        assertEq(leaves, 4);
    }

    /// Row 16: R16's sets on a path-less Add: a key of a gone UA (`PqChatTreeKeyReturn`), a key its own UA took out
    /// (`PqChatTreeOwnKeyReturn`), a gone UA (`PqChatTreeReturn`); a fresh key accepted.
    function test_r16_theNoReturnSets() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_l3(A, B, C), _list(A), 0);
        // B adds and takes out its key 2 (the pair); A removes C (gone, its key group-wide)
        (Step memory st, M memory n) = _build(m, 1, _chs(_add(3, B, 2)), _list(A));
        m = _land(st, n, m);
        (st, n) = _build(m, 1, _chs(_rm(3, B, 2)), _list(A));
        m = _land(st, n, m);
        (st, n) = _build(m, 0, _chs(_rm(2, C, 1)), _list(A));
        m = _land(st, n, m);
        (Step memory x,) = _buildPl(m, 1, _chs(_add(2, B, 2)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeOwnKeyReturn.selector, B, _kemHash(B, 2)));
        (x,) = _buildPl(m, 0, _chs(_add(2, C, 2)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeReturn.selector, C));
        _setKem(D, 9, _kemOf(_kemPkOf(C, 1)));
        (x,) = _buildPl(m, 0, _chs(_add(2, D, 9)), _list(A));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeKeyReturn.selector, _kemHash(C, 1)));
        _pl(m, 0, _chs(_add(2, D, 1)), _list(A));
    }

    function _kemPkOf(bytes32 ua, uint64 kid) internal view returns (bytes memory) {
        (IUARegistry.KemKey memory k,) = p.kemKeyAt(ua, kid);
        return abi.encodePacked(k.scheme, k.mlkemEk, k.x25519);
    }

    /// Row 21: a one-leaf tree. A chat opens none (`_checkLists` wants two UAs at creation) and `leaves` never shrinks, so
    /// the chat's case is one live leaf: after A's path commit removes B, A adds its own second key path-less at B's blank
    /// leaf; an admin's Add of a new UA (C) likewise. Both complete, `leaves` stays 2.
    function test_r21_aOneLeafTree() public {
        _open(); // the vectors in this call's memory
        for (uint256 who; who < 2; ++who) {
            M memory m = _s(_list(A, B), _list(A), 0);
            (Step memory st, M memory n) = _build(m, 0, _chs(_rm(1, B, 1)), _list(A));
            m = _land(st, n, m);
            m = _pl(m, 0, who == 0 ? _keys(A, 100, 1, 1) : _chs(_add(1, C, 1)), _list(A));
            (uint256 used, uint256 leaves,) = _sizes(vchat, m.sid);
            assertEq(used, 2);
            assertEq(leaves, 2);
            (uint256 since,) = _since(m.sid);
            assertEq(since, 1);
        }
    }

    /// Row 22: `treeOf` returns `sincePath`; `sessionOf` returns `pathRefreshBound` and `confirmTag`.
    function test_r22_theViews() public {
        _open(); // the vectors in this call's memory
        M memory m = _s(_l3(A, B, C), _list(A), 7);
        m = _pl(m, 0, _chs(_add(3, D, 1)), _list(A));
        (,,,,,,, uint32 since) = IPqChatTreeViews(address(vchat)).treeOf(m.sid);
        assertEq(since, 1);
        (IPqChat.PqChatSession memory s,) = vchat.sessionOf(m.sid);
        assertEq(s.pathRefreshBound, 7);
        assertEq(s.confirmTag, keccak256("epoch 0's tag"));
        (IPqChat.PqChatCommit memory c,) = IPqChatTreeViews(address(vchat)).commitOf(m.head);
        assertTrue(c.pathless);
        assertEq(c.confirmTag, keccak256(abi.encode("tag", c.nonce)));
    }
}
