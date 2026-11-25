// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqChatTreeModel} from "./PqChatTreeModel.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqChatTreeViews} from "../../src/pqchat/IPqChatTreeViews.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

/// C9 (Change 2026-11-24, E-3; owner: chain-level front-running is in the threat model): a `treeLeave` or `treeRemove`
/// names a complete epoch of the session, the head or an ancestor at most `EXIT_LAG_MAX` = 16 below it, and is checked and
/// applied at the head; A-4: a removal naming a UA already gone is refused whole. In `PqChatTreeMembers` (owner 2026-11-24).
contract PqChatTreeExitsTest is PqChatTreeModel {
    bytes32 internal A;
    bytes32 internal B;
    bytes32 internal E;

    function setUp() public override {
        super.setUp();
        (A, B, E) = (person["A"], person["B"], person["E"]);
    }

    function _abe() internal returns (M memory) {
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](3);
        (mk[0], mk[1], mk[2]) = (_mk(A, 1), _mk(B, 1), _mk(E, 1));
        return _open(mk, _list(A));
    }

    /// A's plain commit on `m` (no change): the next head.
    function _next(M memory m) internal returns (M memory) {
        (Step memory st, M memory n) = _build(m, 0, _noCh(), _list(A));
        return _land(st, n, m);
    }

    function _leaveAt(M memory m, bytes32 named, bytes32 ua) internal returns (IPqChat.PqChatTreeLeave memory l) {
        l = IPqChat.PqChatTreeLeave(m.sid, m.treeId, named, ua, ++nonceN);
    }

    function _v() internal view returns (IPqChatTreeViews) {
        return IPqChatTreeViews(address(vchat));
    }

    /// The front-run of E-3: a commit completes after the epoch an exit names; the exit still lands, at the head.
    function test_e3_exitNamingTheParentAppliesAtTheHead() public {
        _open(); // the vectors in this call's memory
        M memory m0 = _abe();
        M memory m1 = _next(m0); // the front-running commit
        IPqChat.PqChatTreeLeave memory l = _leaveAt(m1, m0.head, B);
        vchat.treeLeave(l, _sig(B, th2.treeLeave(l)));
        (uint8 kind, uint64 at) = _v().goneOf(m1.sid, B);
        assertEq(kind, 1);
        assertEq(at, 1, "gone from the head's number, not the named one");
        assertEq(vchat.leaveCount(m1.head), 1, "the record under the head");
        assertEq(vchat.leaveCount(m0.head), 0);
        assertTrue(vchat.leftIn(m1.head, B), "the flag on the head");
        assertFalse(vchat.leftIn(m0.head, B));
        // a removal naming the parent: `nextEpoch` is the named number plus one, not the head's
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m1.sid, m1.treeId, m0.head, 2, _list(E), A, ++nonceN);
        IUARegistry.UASig memory rs = _sig(A, th2.treeRemove(r));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochNumber.selector, uint64(1), uint64(2)));
        vchat.treeRemove(r, rs);
        r.nextEpoch = 1;
        vchat.treeRemove(r, _sig(A, th2.treeRemove(r)));
        (kind, at) = _v().goneOf(m1.sid, E);
        assertEq(kind, 2);
        assertEq(at, 1);
        assertEq(vchat.removalCount(m1.head), 1, "the record under the head");
        assertEq(vchat.removalCount(m0.head), 0);
        assertTrue(vchat.removedIn(m1.head, E), "the flag on the head");
        assertFalse(vchat.removedIn(m0.head, E));
    }

    /// C9: a staged epoch (its record accepted, its pieces not landed) is `PqChatIncomplete`; its parent, the head, is
    /// accepted (the control).
    function test_e3_exitNamingAStagedEpoch() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe();
        (Step memory st,) = _build(m, 0, _noCh(), _list(A));
        assertGt(st.c.ctCount, 0, "a commit with pieces");
        bytes32 staged = _commitAlone(vchat, st);
        assertFalse(vchat.epochComplete(staged));
        IPqChat.PqChatTreeLeave memory l = _leaveAt(m, staged, B);
        IUARegistry.UASig memory sg = _sig(B, th2.treeLeave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatIncomplete.selector, staged));
        vchat.treeLeave(l, sg);
        l.epochId = m.head;
        vchat.treeLeave(l, _sig(B, th2.treeLeave(l)));
        assertEq(vchat.leaveCount(m.head), 1);
    }

    /// The lag bound at its edge: head 17 refuses an exit naming epoch 0 and accepts one naming epoch 1 (17 <= 1 + 16).
    function test_e3_exitLagBound() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe();
        bytes32 e0 = m.head;
        bytes32 e1;
        for (uint256 i; i < 17; ++i) {
            m = _next(m);
            if (i == 0) e1 = m.head;
        }
        assertEq(m.epoch, 17);
        IPqChat.PqChatTreeLeave memory l = _leaveAt(m, e0, B);
        IUARegistry.UASig memory sg = _sig(B, th2.treeLeave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatExitLag.selector, uint64(0), uint64(17)));
        vchat.treeLeave(l, sg);
        IPqChat.PqChatTreeRemove memory r = IPqChat.PqChatTreeRemove(m.sid, m.treeId, e0, 1, _list(E), A, ++nonceN);
        sg = _sig(A, th2.treeRemove(r));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatExitLag.selector, uint64(0), uint64(17)));
        vchat.treeRemove(r, sg);
        l.epochId = e1; // the control: one epoch younger
        vchat.treeLeave(l, _sig(B, th2.treeLeave(l)));
        (uint8 kind, uint64 at) = _v().goneOf(m.sid, B);
        assertEq(kind, 1);
        assertEq(at, 17);
        assertEq(vchat.leaveCount(m.head), 1);
    }

    /// C9: an unknown epoch, or one of another session, is `PqChatUnknown`.
    function test_e3_exitNamingAnUnknownEpoch() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe();
        M memory o = _abe(); // another session of the same instance
        IPqChat.PqChatTreeLeave memory l = _leaveAt(m, keccak256("nope"), B);
        IUARegistry.UASig memory sg = _sig(B, th2.treeLeave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, keccak256("nope")));
        vchat.treeLeave(l, sg);
        l.epochId = o.head;
        sg = _sig(B, th2.treeLeave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, o.head));
        vchat.treeLeave(l, sg);
    }

    /// A-4: a removal naming a UA already gone is refused whole (nothing stored); without it the removal lands. A repeat
    /// leave is `PqChatNotMember` too.
    function test_a4_removalNamingAGoneUaRefusedWhole() public {
        _open(); // the vectors in this call's memory
        M memory m = _abe();
        IPqChat.PqChatTreeLeave memory l = _leaveAt(m, m.head, B);
        vchat.treeLeave(l, _sig(B, th2.treeLeave(l)));
        l.nonce = ++nonceN;
        IUARegistry.UASig memory sg = _sig(B, th2.treeLeave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, B));
        vchat.treeLeave(l, sg);
        IPqChat.PqChatTreeRemove memory r =
            IPqChat.PqChatTreeRemove(m.sid, m.treeId, m.head, m.epoch + 1, _list(B, E), A, ++nonceN);
        if (B > E) (r.members[0], r.members[1]) = (E, B);
        sg = _sig(A, th2.treeRemove(r));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, B));
        vchat.treeRemove(r, sg);
        assertEq(vchat.removalCount(m.head), 0, "nothing stored");
        r.members = _list(E);
        vchat.treeRemove(r, _sig(A, th2.treeRemove(r)));
        assertEq(vchat.removalCount(m.head), 1);
    }
}
