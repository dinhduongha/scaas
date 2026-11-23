// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {PqChatTreeModel} from "./PqChatTreeModel.sol";

/// CTR-CHAT-27 (plan 2026-11-23-pqchat-treekem T3b): the acceptance checks of spec §8 and the rights of §9, each refusal next
/// to its positive twin and with nothing written; the pieces; races on the head; leave and removal (C21, C28, C38); the
/// two key levels of R16 (tests (1)-(5)); codex-r3-10 and fable-r3-4. Commits built on the test's own tree model.
/// **UNAUDITED.**
contract PqChatTreeRulesTest is PqChatTreeModel {
    using stdJson for string;

    bytes32 internal A;
    bytes32 internal B;
    bytes32 internal E;

    function setUp() public override {
        super.setUp();
        (A, B, E) = (person["A"], person["B"], person["E"]);
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

    function _err(bytes4 sel, bytes32 a) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, a);
    }

    // ----- acceptance (R12, C7, C24, C31) -----

    /// Each of a wrong `treeHash`, `ctCount`, path length, `parentTreeHash`, `treeId`, `sealedInfo`, admin order and author
    /// leaf refused at acceptance with nothing written (fable-r2-3, codex-r2-11, codex-20); the same record accepted.
    function test_acceptanceRefusalsWriteNothing() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 1, _noCh(), _list(A));
        assertEq(st.c.ctCount, 2);
        Step memory x = _build2(m, 1);
        x.c.treeHash = bytes32(uint256(1));
        _refused(x, _err(IPqChat.PqChatTreeHash.selector, st.c.treeHash));
        IUARegistry.UASig memory sg = _signC(x.c); // the record alone: refused at acceptance, not at a completion
        vm.expectRevert(_err(IPqChat.PqChatTreeHash.selector, st.c.treeHash));
        vchat.commit(
            x.c, new uint32[](0), new bytes32[](0), new bytes[](0), new IPqChat.PathCt[](0), new IPqChat.Wrap[](0), sg
        );
        x = _build2(m, 1);
        x.c.ctCount = 3;
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeTargets.selector, uint256(2)));
        x = _build2(m, 1);
        bytes32[] memory one = new bytes32[](1);
        one[0] = x.c.nodeKeyHashes[0];
        x.c.nodeKeyHashes = one;
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeTargets.selector, uint256(2)));
        x = _build2(m, 1);
        x.c.parentTreeHash = bytes32(uint256(7));
        _refused(x, _err(IPqChat.PqChatTreeParent.selector, _root(vchat, m.sid)));
        x = _build2(m, 1);
        x.c.treeId = bytes32(uint256(7));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeHome.selector));
        x = _build2(m, 1);
        x.c.sealedInfo = "";
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        x = _build2(m, 1);
        x.c.sealedInfo = new bytes(4125);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        x = _build2(m, 1);
        x.c.admins = _list(E, A);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        x = _build2(m, 1);
        x.c.leaf = 2;
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeLeaf.selector, uint32(2)));
        st.c.sealedInfo = new bytes(4124); // the bound itself
        _land(st, n, m);
    }

    function _build2(M memory m, uint32 leaf) internal view returns (Step memory st) {
        (st,) = _build(m, leaf, _noCh(), _list(A));
    }

    /// A zero-target commit: its list hash the empty list's (codex-r2-14); `ctCount` at `leaves` refused (C24).
    function test_zeroTargetCommit() public {
        _open(); // the vectors in this call\'s memory
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](2);
        (mk[0], mk[1]) = (_mk(A, 1), _mk(B, 1));
        M memory m = _open(mk, _list(A));
        (Step memory st, M memory n) = _build(m, 0, _chs(_rm(1, B, 1)), _list(A));
        assertEq(st.c.ctCount, 0);
        Step memory x = _copyStep(st);
        x.c.ctListHash = keccak256("not the empty list");
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        n = _land(st, n, m);
        (uint256 kind, uint256 ep) = _gone(vchat, m.sid, B);
        assertEq(kind, 2, "removed by a commit alone (fable-r3-4)");
        assertEq(ep, 1);
    }

    function _copyStep(Step memory s) internal pure returns (Step memory t) {
        (t.ctTargets, t.ctHashes, t.nodeKeys, t.cts, t.wraps) = (s.ctTargets, s.ctHashes, s.nodeKeys, s.cts, s.wraps);
        (t.treeHash, t.epochId) = (s.treeHash, s.epochId);
        t.c = abi.decode(abi.encode(s.c), (IPqChat.PqChatCommit));
    }

    /// The modes (C30): the tree entries on a flat session, the flat ones on a tree session.
    function test_modeEntries() public {
        _open(); // the vectors in this call\'s memory
        (bytes32 flat,) = _newSession(2);
        M memory m = _abe(_list(A));
        (Step memory st,) = _build(m, 1, _noCh(), _list(A));
        st.c.sessionId = flat;
        IUARegistry.UASig memory sg = _signC(st.c);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, uint8(0)));
        chat.commit(st.c, st.ctTargets, st.ctHashes, st.nodeKeys, st.cts, st.wraps, sg);
        IPqChat.PqChatTreeLeave memory tl = IPqChat.PqChatTreeLeave(flat, m.treeId, flat, ids[0], 5);
        sg = _sig(ids[0], th2.treeLeave(tl));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, uint8(0)));
        chat.treeLeave(tl, sg);
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(m.sid, m.sid, B, 5);
        sg = _sig(B, h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, uint8(1)));
        vchat.leave(l, sg);
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(m.sid, m.sid, 1, _list(B), A, 5);
        sg = _sig(A, h.remove(r));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, uint8(1)));
        vchat.remove(r, sg);
        (Step memory ok, M memory n) = _build(m, 1, _noCh(), _list(A));
        _land(ok, n, m);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeEntry.selector, uint8(1)));
        vchat.epochOf(ok.epochId);
    }

    // ----- the pieces (§8) -----

    /// The record alone by a third party, then each piece checked when it lands; a wrong piece refused and the right one
    /// landing; a piece twice; the list, the node keys and the ciphertexts read back byte for byte from state.
    function test_piecesByAThirdParty() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 1, _noCh(), _list(A));
        vm.startPrank(STRANGER);
        bytes32 eid = _commitAlone(vchat, st);
        assertFalse(vchat.epochComplete(eid));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathList.selector, eid));
        vchat.addPath(eid, 0, st.cts);
        bytes32[] memory swapped = new bytes32[](2);
        (swapped[0], swapped[1]) = (st.ctHashes[1], st.ctHashes[0]);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathList.selector, eid));
        vchat.addPathList(eid, st.ctTargets, swapped);
        vchat.addPathList(eid, st.ctTargets, st.ctHashes);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathList.selector, eid));
        vchat.addPathList(eid, st.ctTargets, st.ctHashes);
        bytes[] memory wrong = new bytes[](st.nodeKeys.length);
        for (uint256 i; i < wrong.length; ++i) {
            wrong[i] = _j().readBytes(".devices.G.kemPk");
        }
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathHash.selector, eid, uint256(0)));
        vchat.addPathKeys(eid, wrong);
        vchat.addPathKeys(eid, st.nodeKeys);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathStored.selector, eid, uint256(0)));
        vchat.addPathKeys(eid, st.nodeKeys);
        IPqChat.PathCt[] memory one = new IPqChat.PathCt[](1);
        one[0] = st.cts[1];
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathHash.selector, eid, uint256(0)));
        vchat.addPath(eid, 0, one);
        one[0] = st.cts[0];
        vchat.addPath(eid, 0, one);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatPathStored.selector, eid, uint256(0)));
        vchat.addPath(eid, 0, one);
        assertFalse(vchat.epochComplete(eid), "one ciphertext held back");
        one[0] = st.cts[1];
        vchat.addPath(eid, 1, one);
        vm.stopPrank();
        assertTrue(vchat.epochComplete(eid));
        assertEq(_root(vchat, m.sid), _mRoot(n));
        _readBack(st); // never lose ciphertext: every piece in state
    }

    function _readBack(Step memory st) internal view {
        bytes32 eid = st.epochId;
        uint256 g = _m(eid, TREE_ROOT + 1);
        address list = address(uint160(_at(vchat, g + 1)));
        assertEq(_code(list), bytes.concat(_p4(st.ctTargets), abi.encodePacked(st.ctHashes)), "the list");
        address keys = address(uint160(_at(vchat, g + 2)));
        assertEq(_code(keys), bytes.concat(st.nodeKeys[0], st.nodeKeys[1]), "the node keys");
        for (uint256 i; i < 2; ++i) {
            uint256 at = _at(vchat, _m(bytes32(i), g + 3));
            bytes memory b = _code(address(uint160(at)));
            bytes memory ct = new bytes(1648);
            for (uint256 j; j < 1648; ++j) {
                ct[j] = b[(at >> 160) + j];
            }
            assertEq(ct, bytes.concat(st.cts[i].mlkemCt, st.cts[i].x25519Eph, st.cts[i].sealedSecret), "a ciphertext");
        }
    }

    function _code(address a) internal view returns (bytes memory b) {
        bytes memory c = a.code;
        b = new bytes(c.length - 1);
        for (uint256 i; i < b.length; ++i) {
            b[i] = c[i + 1];
        }
    }

    function _p4(uint32[] memory t) internal pure returns (bytes memory b) {
        for (uint256 i; i < t.length; ++i) {
            b = bytes.concat(b, bytes4(t[i]));
        }
    }

    /// Two commits on one head (C17): the first to complete takes the slot; the other is `PqChatEpochTaken` at its next
    /// piece, and nothing completes it.
    function test_twoCommitsRaceForOneHead() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A));
        (Step memory sb,) = _build(m, 1, _noCh(), _list(A));
        ++nonceN;
        _commitAlone(vchat, sb);
        (Step memory se, M memory n) = _build(m, 2, _noCh(), _list(A));
        _land(se, n, m);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, m.sid, se.epochId));
        vchat.addPathList(sb.epochId, sb.ctTargets, sb.ctHashes);
        assertFalse(vchat.epochComplete(sb.epochId));
    }

    /// A `treeRemove` landed between acceptance and completion: completion fails step 1; the honouring commit completes.
    function test_removalVoidsAStagedCommit() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A));
        (Step memory sb,) = _build(m, 1, _noCh(), _list(A));
        ++nonceN;
        _commitAlone(vchat, sb);
        vchat.addPathList(sb.epochId, sb.ctTargets, sb.ctHashes);
        vchat.addPathKeys(sb.epochId, sb.nodeKeys);
        IPqChat.PathCt[] memory one = new IPqChat.PathCt[](1);
        one[0] = sb.cts[0];
        vchat.addPath(sb.epochId, 0, one);
        _removeT(m, A, _list(E));
        (,, uint256 owed) = _sizes(vchat, m.sid);
        assertEq(owed, 1);
        one[0] = sb.cts[1];
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, m.sid, E));
        vchat.addPath(sb.epochId, 1, one);
        // the honouring commit, by a member that is no admin (dropping gone UAs is plain)
        (Step memory st, M memory n) = _build(m, 1, _chs(_rm(2, E, 1)), _list(A));
        _land(st, n, m);
        (bool set,,) = _goneKey(vchat, m.sid, _kemHash(E, 1));
        assertTrue(set, "a gone UA's key is session-wide");
        (,, owed) = _sizes(vchat, m.sid);
        assertEq(owed, 0);
    }

    // ----- leave, removal, the closed session (C21, C28, C38) -----

    /// A leave is forced like a removal: a commit that keeps the leaver's leaf is refused; the one that blanks it completes.
    function test_leaveIsForced() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A));
        _leaveT(m, E);
        Step memory x = _build2(m, 1);
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, m.sid, E));
        (Step memory st, M memory n) = _build(m, 1, _chs(_rm(2, E, 1)), _list(A));
        _land(st, n, m);
        (uint256 kind,) = _gone(vchat, m.sid, E);
        assertEq(kind, 1);
        // R14: no return, whoever signs
        (Step memory back,) = _build(n, 0, _chs(_add(2, E, 2)), _list(A));
        _refused(back, _err(IPqChat.PqChatTreeReturn.selector, E));
    }

    /// C38 (codex-r3-11): the last two members leave on one head; the records are accepted, nothing more is written, no
    /// commit or message is accepted; the leaves stay, `owed` above 0, no key-set entry. Control: one member left that is
    /// not gone honours the leaves and completes.
    function test_closedSession() public {
        _open(); // the vectors in this call\'s memory
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](2);
        (mk[0], mk[1]) = (_mk(A, 1), _mk(B, 1));
        M memory m = _open(mk, _list(A));
        _leaveT(m, A);
        _leaveT(m, B);
        (,, uint256 owed) = _sizes(vchat, m.sid);
        assertEq(owed, 2);
        (bool set,,) = _goneKey(vchat, m.sid, _kemHash(A, 1));
        assertFalse(set);
        Step memory x = _build2(m, 0);
        _refused(x, _err(IPqChat.PqChatNotMember.selector, A));
        IPqChat.PqChatMessage memory msg_;
        (msg_.sessionId, msg_.epochId, msg_.sender, msg_.counter) = (m.sid, m.sid, B, 1);
        msg_.ciphertext = hex"01";
        IUARegistry.UASig memory sg = _sig(B, h.message(msg_));
        vm.expectRevert(_err(IPqChat.PqChatNotMember.selector, B));
        vchat.postMessage(msg_, sg);
        // control
        M memory c = _abe(_list(A));
        _leaveT(c, A);
        _leaveT(c, B);
        (Step memory st, M memory n) = _build(c, 2, _chs(_rm(0, A, 1), _rm(1, B, 1)), new bytes32[](0));
        _land(st, n, c);
    }

    // ----- R16 -----

    /// (1) B registers A's next key as its own version, adds it by a plain commit and takes it out: only the pair is set;
    /// B's re-add under another keyId is `PqChatTreeOwnKeyReturn`; A's own plain commit adds the key.
    function test_r16_ownKeyChurnHarmsNobody() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A, E));
        bytes32 k = _kemHash(A, 2);
        _setKem(B, 12, _kemOf(_j().readBytes(".devices.A2.kemPk")));
        _setKem(B, 13, _kemOf(_j().readBytes(".devices.A2.kemPk")));
        (Step memory st, M memory n) = _build(m, 1, _chs(_add(3, B, 12)), _list(A, E));
        n = _land(st, n, m);
        // A's Add while B holds it live
        (Step memory live,) = _build(n, 0, _chs(_add(4, A, 2)), _list(A, E));
        _refused(live, _err(IPqChat.PqChatTreeKeyLive.selector, k));
        (st, m) = _build(n, 1, _chs(_rm(3, B, 12)), _list(A, E));
        m = _land(st, m, n);
        (bool own,,) = _goneOwnKey(vchat, m.sid, B, k);
        (bool wide,,) = _goneKey(vchat, m.sid, k);
        assertTrue(own, "the pair");
        assertFalse(wide, "not session-wide");
        (Step memory again,) = _build(m, 1, _chs(_add(3, B, 13)), _list(A, E));
        _refused(again, abi.encodeWithSelector(IPqChat.PqChatTreeOwnKeyReturn.selector, B, k));
        (st, n) = _build(m, 0, _chs(_add(3, A, 2)), _list(A, E));
        _land(st, n, m);
    }

    /// (3) the burn by leave: B holds A's key, leaves, the honouring commit writes it session-wide; A's Add of it is
    /// `PqChatTreeKeyReturn`, an Add of B `PqChatTreeReturn`, B commits nothing.
    function test_r16_burnByLeave() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A, E));
        bytes32 k = _kemHash(A, 2);
        _setKem(B, 12, _kemOf(_j().readBytes(".devices.A2.kemPk")));
        (Step memory st, M memory n) = _build(m, 1, _chs(_add(3, B, 12)), _list(A, E));
        n = _land(st, n, m);
        _leaveT(n, B);
        (st, m) = _build(n, 2, _chs(_rm(1, B, 1), _rm(3, B, 12)), _list(A, E));
        m = _land(st, m, n);
        (bool wide,,) = _goneKey(vchat, m.sid, k);
        assertTrue(wide);
        (Step memory x,) = _build(m, 0, _chs(_add(1, A, 2)), _list(A, E));
        _refused(x, _err(IPqChat.PqChatTreeKeyReturn.selector, k));
        (x,) = _build(m, 0, _chs(_add(1, B, 2)), _list(A, E));
        _refused(x, _err(IPqChat.PqChatTreeReturn.selector, B));
    }

    /// (4) a Remove and an Add of the same bytes in one commit: under the same UA the pair; under another UA accepted
    /// while the removed UA keeps a leaf, session-wide when the commit leaves it none.
    function test_r16_sameBytesInOneCommit() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A, E));
        bytes32 k = _kemHash(A, 2);
        _setKem(B, 12, _kemOf(_j().readBytes(".devices.A2.kemPk")));
        _setKem(B, 13, _kemOf(_j().readBytes(".devices.A2.kemPk")));
        (Step memory st, M memory n) = _build(m, 1, _chs(_add(3, B, 12)), _list(A, E));
        n = _land(st, n, m);
        (Step memory x,) = _build(n, 2, _chs(_rm(3, B, 12), _add(3, B, 13)), _list(A, E));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeOwnKeyReturn.selector, B, k));
        Ch[] memory gone3 = new Ch[](3);
        (gone3[0], gone3[1], gone3[2]) = (_rm(1, B, 1), _rm(3, B, 12), _add(3, A, 2));
        (x,) = _build(n, 2, gone3, _list(A, E));
        _refused(x, _err(IPqChat.PqChatTreeKeyReturn.selector, k));
        (st, m) = _build(n, 2, _chs(_rm(3, B, 12), _add(3, A, 2)), _list(A, E));
        _land(st, m, n);
    }

    /// (5) and fable-r3-4: an admin's commit that removes X's only leaf and adds X's new key completes; X stays a member,
    /// its old key at the pair level, `owed` 0. The Remove alone makes X gone (kind 2), and a later Add of X is refused.
    function test_r16_replacementOfAnOnlyKey() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A, E));
        (Step memory st, M memory n) = _build(m, 2, _chs(_rm(1, B, 1), _add(1, B, 2)), _list(A, E));
        n = _land(st, n, m);
        (uint256 kind,) = _gone(vchat, m.sid, B);
        assertEq(kind, 0, "B stays");
        (bool own,,) = _goneOwnKey(vchat, m.sid, B, _kemHash(B, 1));
        (bool wide,,) = _goneKey(vchat, m.sid, _kemHash(B, 1));
        assertTrue(own && !wide, "the pair, not session-wide");
        assertEq(_liveCount(vchat, m.sid, B), 1);
        (st, m) = _build(n, 1, _noCh(), _list(A, E));
        m = _land(st, m, n); // B commits from its new key
        (st, n) = _build(m, 2, _chs(_rm(1, B, 2)), _list(A, E));
        n = _land(st, n, m);
        (kind,) = _gone(vchat, m.sid, B);
        assertEq(kind, 2);
        (Step memory x,) = _build(n, 2, _chs(_add(1, B, 1)), _list(A, E));
        _refused(x, _err(IPqChat.PqChatTreeReturn.selector, B));
    }

    // ----- codex-r3-10, C24 -----

    /// An admin's commit that removes another admin's last leaf and keeps it in `admins` is refused at acceptance; without
    /// that UA in `admins` it completes and the UA is gone; with an Add of its new key it completes, the UA kept.
    function test_adminsJudgedAgainstTheProspectiveGoneSet() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A, B));
        (Step memory x,) = _build(m, 0, _chs(_rm(1, B, 1)), _list(A, B));
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, m.sid, B));
        (Step memory st, M memory n) = _build(m, 0, _chs(_rm(1, B, 1)), _list(A));
        _land(st, n, m);
        (uint256 kind,) = _gone(vchat, m.sid, B);
        assertEq(kind, 2);
        M memory m2 = _abe(_list(A, B));
        (Step memory kept, M memory k2) = _build(m2, 0, _chs(_rm(1, B, 1), _add(1, B, 2)), _list(A, B));
        _land(kept, k2, m2);
    }

    /// C24: a `treeRemove` that leaves no admin with a leaf is `PqChatTreeAdmins`; a non-admin's change of another UA is
    /// `PqChatNotAdmin`.
    function test_adminRules() public {
        _open(); // the vectors in this call\'s memory
        M memory m = _abe(_list(A));
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, m.head, m.epoch + 1, _list(A), A, ++nonceN);
        IUARegistry.UASig memory sg = _sig(A, th2.treeRemove(r));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatTreeAdmins.selector));
        vchat.treeRemove(r, sg);
        (Step memory x,) = _build(m, 1, _chs(_rm(2, E, 1)), _list(A));
        _refused(x, _err(IPqChat.PqChatNotAdmin.selector, B));
        (x,) = _build(m, 1, _chs(_add(3, E, 2)), _list(A)); // a non-admin adds another UA's key
        _refused(x, _err(IPqChat.PqChatNotAdmin.selector, B));
        (x,) = _build(m, 0, _noCh(), new bytes32[](0)); // A drops itself, not gone: no admin with a leaf would remain
        _refused(x, abi.encodeWithSelector(IPqChat.PqChatTreeAdmins.selector));
        (x,) = _build(m, 0, _noCh(), _list(A, E)); // E added as an admin: an admin change, by an admin
        (, M memory e2) = _build(m, 0, _noCh(), _list(A, E));
        _land(x, e2, m);
        m = e2;
        (Step memory st, M memory n) = _build(m, 0, _chs(_rm(2, E, 1)), _list(A));
        _land(st, n, m);
    }

    /// codex-8: a node key that fails the admission check with every hash matching: the record is accepted (only its hash
    /// is public then, fable-r3-6), the key is refused when it lands, nothing completes it.
    function test_nodeKeyFailsAdmission() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        bytes memory good = nodeKey;
        nodeKey = _j().readBytes(".devices.G.kemPk");
        nodeKey[1600] = 0x80; // pk_X with bit 255 set: not canonical
        (Step memory st,) = _build(m, 1, _noCh(), _list(A));
        nodeKey = good;
        bytes32 eid = _commitAlone(vchat, st);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, eid, uint64(0)));
        vchat.addPathKeys(eid, st.nodeKeys);
    }

    /// C7, C14: a record that signs the hash of a list whose targets differ from the walk's is accepted (the list is not
    /// in the record), its list refused when it lands (`PqChatTreeTargets`); the walk's list lands for the twin record.
    function test_listTargetsAgainstTheWalk() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st,) = _build(m, 1, _noCh(), _list(A));
        Step memory x = _copyStep(st);
        (x.ctTargets, x.ctHashes) = (new uint32[](2), new bytes32[](2));
        (x.ctTargets[0], x.ctTargets[1], x.ctHashes[0], x.ctHashes[1]) =
        (st.ctTargets[1], st.ctTargets[0], st.ctHashes[1], st.ctHashes[0]);
        x.c.ctListHash = th2.pathList(x.ctTargets, x.ctHashes);
        bytes32 eid = _commitAlone(vchat, x);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatTreeTargets.selector, uint256(2)));
        vchat.addPathList(eid, x.ctTargets, x.ctHashes);
        ++nonceN;
        (st,) = _build(m, 1, _noCh(), _list(A));
        eid = _commitAlone(vchat, st);
        vchat.addPathList(eid, st.ctTargets, st.ctHashes);
    }

    // ----- C21 -----

    /// 32 owed leaves accepted, one more leave `PqChatTreeBacklog(33)`; the commit of the 32 forced Removes completes.
    function test_backlogBound() public {
        _open(); // the vectors in this call\'s memory
        string[4] memory who = ["B", "C", "D", "E"];
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](33);
        mk[0] = _mk(A, 1);
        bytes32[] memory gone = new bytes32[](4);
        for (uint256 u; u < 4; ++u) {
            bytes32 ua = person[who[u]];
            gone[u] = ua;
            for (uint64 v = 20; v < 28; ++v) {
                _setKem(ua, v, _variant(who[u], v));
                mk[1 + u * 8 + (v - 20)] = _mk(ua, v);
            }
        }
        M memory m = _open(mk, _list(A));
        _removeT(m, A, gone);
        (,, uint256 owed) = _sizes(vchat, m.sid);
        assertEq(owed, 32);
        IPqChat.PqChatTreeLeave memory l = IPqChat.PqChatTreeLeave(m.sid, m.treeId, m.head, A, ++nonceN);
        IUARegistry.UASig memory sg = _sig(A, th2.treeLeave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatTreeBacklog.selector, uint256(33)));
        vchat.treeLeave(l, sg);
        Ch[] memory all = new Ch[](32);
        for (uint256 i; i < 32; ++i) {
            all[i] = _rm(uint32(1 + i), mk[1 + i].ua, mk[1 + i].keyId);
        }
        (Step memory st, M memory n) = _build(m, 0, all, _list(A));
        uint256 g0 = gasleft();
        _land(st, n, m);
        emit log_named_uint("gas: commit of 32 forced Removes (whole, isolated off)", g0 - gasleft());
    }
    // ----- gas (recorded only; T3c measures and pins the fixtures of spec §13) -----

    function _g(string memory what, uint256 g0) internal {
        emit log_named_uint(string.concat("gas: ", what), g0 - gasleft());
    }

    /// Each new entry once, on [A, B, E] (4 leaves): the record alone, the list, the node keys, a ciphertext, the last
    /// ciphertext with the completion, a whole commit with an Add and its Welcome wrap, `addWraps` of a Welcome wrap with
    /// the completion, `treeLeave`, `treeRemove`, `postMessage` on a tree session.
    function test_gasPerEntry() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe(_list(A));
        (Step memory st, M memory n) = _build(m, 1, _noCh(), _list(A));
        ++nonceN;
        uint256 g0 = gasleft();
        _commitAlone(vchat, st);
        _g("commit, the record alone (plain, 2 targets)", g0);
        g0 = gasleft();
        vchat.addPathList(st.epochId, st.ctTargets, st.ctHashes);
        _g("addPathList (2 targets)", g0);
        g0 = gasleft();
        vchat.addPathKeys(st.epochId, st.nodeKeys);
        _g("addPathKeys (2 node keys)", g0);
        IPqChat.PathCt[] memory one = new IPqChat.PathCt[](1);
        one[0] = st.cts[0];
        g0 = gasleft();
        vchat.addPath(st.epochId, 0, one);
        _g("addPath (1 ciphertext)", g0);
        one[0] = st.cts[1];
        g0 = gasleft();
        vchat.addPath(st.epochId, 1, one);
        _g("addPath (the last ciphertext, with the completion)", g0);
        (Step memory sa, M memory na) = _build(n, 0, _chs(_add(3, B, 2)), _list(A));
        ++nonceN;
        g0 = gasleft();
        _commitAll(vchat, sa);
        _g("commit whole (an Add, 3 targets, its Welcome wrap)", g0);
        (Step memory sw,) = _build(na, 0, _chs(_add(4, A, 2)), _list(A));
        ++nonceN;
        vchat.commit(sw.c, sw.ctTargets, sw.ctHashes, sw.nodeKeys, sw.cts, new IPqChat.Wrap[](0), _signC(sw.c));
        g0 = gasleft();
        vchat.addWraps(sw.epochId, 0, sw.wraps);
        _g("addWraps (a Welcome wrap, with the completion)", g0);
        M memory h3 = _copy(na);
        (h3.head, h3.epoch) = (sw.epochId, sw.c.epoch);
        IPqChat.PqChatMessage memory msg_;
        (msg_.sessionId, msg_.epochId, msg_.sender, msg_.counter) = (m.sid, h3.head, E, 1);
        msg_.ciphertext = new bytes(1040);
        IUARegistry.UASig memory sg = _sig(E, h.message(msg_));
        g0 = gasleft();
        vchat.postMessage(msg_, sg);
        _g("postMessage (tree session, 1,040 B)", g0);
        IPqChat.PqChatTreeLeave memory l = IPqChat.PqChatTreeLeave(m.sid, m.treeId, h3.head, E, ++nonceN);
        sg = _sig(E, th2.treeLeave(l));
        g0 = gasleft();
        vchat.treeLeave(l, sg);
        _g("treeLeave", g0);
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, h3.head, h3.epoch + 1, _list(B), A, ++nonceN);
        sg = _sig(A, th2.treeRemove(r));
        g0 = gasleft();
        vchat.treeRemove(r, sg);
        _g("treeRemove (1 UA, 2 leaves)", g0);
    }
}
