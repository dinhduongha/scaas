// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// Plan 3c T86 (UA-7 T6; spec P9-P13, O2, O4): epochs, the home-instance slot, roles and leave. Sessions of three members:
/// `ids[0]` creator and only admin, `ids[1]` and `ids[2]` members. Every refusal beside its positive control.
contract PqChatEpochsTest is PqChatBase {
    bytes32 internal sid;

    function setUp() public override {
        super.setUp();
        (sid,) = _newSession(3);
    }

    function _admins() internal view returns (bytes32[] memory) {
        return _list(ids[0]);
    }

    function _leave(PqChat c, bytes32 epochId, bytes32 member, uint64 nonce) internal {
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, epochId, member, nonce);
        c.leave(l, _sig(member, h.leave(l)));
    }

    // ----- plain rekeys and membership changes (P10, 3C-D7) -----

    function test_rekey_plainByMember() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
        bytes32 eid = PqChatTypes.epochId(sid, ids[1], 1);
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatEpochAdded(sid, eid, sid, 1, ids[1]);
        vm.prank(STRANGER);
        assertEq(_rekey(chat, e, w), eid);
        assertTrue(chat.epochComplete(eid));
        assertEq(chat.childOf(sid), eid, "the home slot");
        (IPqChat.PqChatEpoch memory got, bytes32 sigHash) = chat.epochOf(eid);
        assertEq(keccak256(abi.encode(got)), keccak256(abi.encode(e)));
        assertEq(sigHash, keccak256(abi.encode(_sig(e.author, h.epoch(e)))));
        assertTrue(chat.nonceUsed(PqChatTypes.scopeEpoch(sid, ids[1]), 1));
        // a new KEM version is a plain rekey too (keyId changes)
        IUARegistry.KemKey memory k = _kem(77);
        IPqChat.MemberKey[] memory m = _members(3);
        _setKem(m[2].ua, 1, k);
        m[2].keyId = 1;
        (e, w) = _epoch(sid, ids[2], 2, 2, eid, _admins(), m);
        _rekey(chat, e, w);
    }

    function _setKem(bytes32 ua, uint64 version, IUARegistry.KemKey memory k) internal {
        p.setKemKey(ua, version, k, _kemSig(ua, version, k));
    }

    function _kemSig(bytes32 ua, uint64 version, IUARegistry.KemKey memory k) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sig(keyOf_[ua], UAKinds.uaMessage(ML, UAKinds.PURPOSE_KEM, p.kemRecordDigest(ua, version, k)));
    }

    function test_rekey_plainDropsLeaversOnly() public {
        _leave(chat, sid, ids[2], 1);
        assertTrue(chat.leftIn(sid, ids[2]));
        // a member drops a member who did not leave: a membership change
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[2], 2, 1, sid, _admins(), _without(_members(3), ids[1]));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[2]));
        chat.rekey(e, w, sig);
        // dropping the leaver only: plain
        (e, w) = _epoch(sid, ids[1], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(chat, e, w);
        assertEq(chat.childOf(sid), eid);
    }

    function test_rekey_membershipChangeNeedsAdmin() public {
        // ids[1] (no admin) removes ids[2], adds ids[3], or adds itself as admin: each refused
        for (uint256 k; k < 3; ++k) {
            IPqChat.MemberKey[] memory m = _members(3);
            bytes32[] memory a = _admins();
            if (k == 0) m = _without(m, ids[2]);
            if (k == 1) m = _members(4);
            if (k == 2) a = _list(ids[0], ids[1]);
            (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[1], uint64(k + 1), 1, sid, a, m);
            IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
            vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
            chat.rekey(e, w, sig);
        }
        // the admin does all three at once
        (IPqChat.PqChatEpoch memory c, IPqChat.Wrap[] memory cw) =
            _epoch(sid, ids[0], 1, 1, sid, _list(ids[0], ids[1]), _without(_members(4), ids[2]));
        _rekey(chat, c, cw);
    }

    /// P9: the removal attack, both ways.
    function test_rekey_removalAttackRefused() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        bytes32 e1 = _rekey(chat, e, w);
        // the removed member's own child of the same parent (a plain rekey keeping it): the slot is taken
        (e, w) = _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, sid, e1));
        chat.rekey(e, w, sig);
        // a far epoch number from the same parent
        (e, w) = _epoch(sid, ids[2], 2, 1000, sid, _admins(), _members(3));
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochNumber.selector, uint64(1), uint64(1000)));
        chat.rekey(e, w, sig);
        // a child of the admin's epoch adding itself back: a membership change, no admin
        (e, w) = _epoch(sid, ids[2], 3, 2, e1, _admins(), _members(3));
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[2]));
        chat.rekey(e, w, sig);
        // a plain rekey of the admin's epoch: no longer a member
        (e, w) = _epoch(sid, ids[2], 4, 2, e1, _admins(), _without(_members(3), ids[2]));
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.rekey(e, w, sig);
        // the control: a remaining member's plain rekey of e1
        (e, w) = _epoch(sid, ids[1], 1, 2, e1, _admins(), _without(_members(3), ids[2]));
        _rekey(chat, e, w);
    }

    /// An incomplete child never takes the slot; anyone may finish it; once another child holds the slot it cannot land.
    function test_rekey_incompleteChildNeverTakesSlot() public {
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) = _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
        bytes32 ea = chat.rekey(a, _slice(aw, 0, 1), _sig(a.author, h.epoch(a)));
        assertEq(chat.childOf(sid), bytes32(0));
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        bytes32 eb = _rekey(chat, b, bw);
        assertEq(chat.childOf(sid), eb, "the first complete child");
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, sid, eb));
        chat.addWraps(ea, 1, _slice(aw, 1, 3));
        // the control: an incomplete child of a free slot finished by a stranger takes it
        (IPqChat.PqChatEpoch memory c, IPqChat.Wrap[] memory cw) = _epoch(sid, ids[1], 2, 2, eb, _admins(), b.members);
        bytes32 ec = chat.rekey(c, _slice(cw, 0, 1), _sig(c.author, h.epoch(c)));
        vm.prank(STRANGER);
        chat.addWraps(ec, 1, _slice(cw, 1, 2));
        assertEq(chat.childOf(eb), ec);
    }

    /// A parent not complete, unknown, or of another session.
    function test_rekey_parentRules() public {
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) = _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
        bytes32 ea = chat.rekey(a, _slice(aw, 0, 1), _sig(a.author, h.epoch(a)));
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[1], 2, 2, ea, _admins(), _members(3));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatIncomplete.selector, ea));
        chat.rekey(e, w, sig);
        bytes32 x = keccak256("x");
        (e, w) = _epoch(sid, ids[1], 3, 1, x, _admins(), _members(3));
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, x));
        chat.rekey(e, w, sig);
        // another session's epoch as the parent
        (IPqChat.PqChatSession memory s2, IPqChat.Wrap[] memory w2) = _session(3, 2, address(chat));
        bytes32 sid2 = _create(chat, s2, w2);
        (e, w) = _epoch(sid, ids[1], 4, 1, sid2, _admins(), _members(3));
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, sid2));
        chat.rekey(e, w, sig);
        // an epoch record of a session this instance does not hold
        (e, w) = _epoch(x, ids[1], 5, 1, sid, _admins(), _members(3));
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, sid));
        chat.rekey(e, w, sig);
        chat.addWraps(ea, 1, _slice(aw, 1, 3));
        (e, w) = _epoch(sid, ids[1], 2, 2, ea, _admins(), _members(3));
        _rekey(chat, e, w); // the control
    }

    function test_rekey_nonceAndShapes() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
        bytes32 e1 = _rekey(chat, e, w);
        // the same (session, author, nonce) again, another record (a child of e1)
        (e, w) = _epoch(sid, ids[1], 1, 2, e1, _admins(), _members(3));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, PqChatTypes.scopeEpoch(sid, ids[1]), uint64(1)));
        chat.rekey(e, w, sig);
        // a forged record burns no nonce
        (e, w) = _epoch(sid, ids[1], 2, 2, e1, _admins(), _members(3));
        sig = _sig(ids[2], h.epoch(e));
        vm.expectRevert(_unauthorized(ids[1]));
        chat.rekey(e, w, sig);
        assertFalse(chat.nonceUsed(PqChatTypes.scopeEpoch(sid, ids[1]), 2));
        // unsorted members
        IPqChat.MemberKey[] memory m = _members(3);
        (m[0], m[1]) = (m[1], m[0]);
        (e, w) = _epoch(sid, ids[1], 2, 2, e1, _admins(), m);
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.rekey(e, w, sig);
        (e, w) = _epoch(sid, ids[1], 2, 2, e1, _admins(), _members(3));
        _rekey(chat, e, w); // the control
    }

    // ----- the home instance and replicas (P9, P32) -----

    /// The same records in instance B (a replica of a session homed in A): every complete child lands, `childOf` reads 0,
    /// and they land in any order; at home the second complete child is refused.
    function test_replica_storesEveryChild() public {
        (IPqChat.PqChatSession memory s0, IPqChat.Wrap[] memory sw) = _session(3, 1, address(chat));
        chatB.createSession(s0, sw, _sig(s0.creator, h.session(s0))); // the copy of the session homed in A
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) = _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
        bytes32 ea = _rekey(chat, a, aw);
        IUARegistry.UASig memory bs = _sig(b.author, h.epoch(b));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, sid, ea));
        chat.rekey(b, bw, bs);
        // the replica, in reverse order
        bytes32 eb = chatB.rekey(b, bw, bs);
        assertEq(_rekey(chatB, a, aw), ea);
        assertTrue(chatB.epochComplete(ea) && chatB.epochComplete(eb));
        assertEq(chatB.childOf(sid), bytes32(0));
        assertEq(chat.childOf(sid), ea);
    }

    /// The chain dimension of the home check: `homeContract` this instance but `homeChain` another chain's `chain_uid`.
    function test_replica_otherChainUid() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 7, address(chat));
        s.homeChain = keccak256("another chain");
        bytes32 sid2 = _create(chat, s, w);
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid2, ids[0], 1, 1, sid2, _admins(), _without(_members(3), ids[2]));
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) = _epoch(sid2, ids[2], 1, 1, sid2, _admins(), _members(3));
        _rekey(chat, a, aw);
        _rekey(chat, b, bw);
        assertEq(chat.childOf(sid2), bytes32(0));
    }

    // ----- O2, O4, msig admins -----

    /// O2: a member's plain rekey takes the slot before the admin's change; the admin's next rekey from it removes the member.
    function test_O2_plainRekeyFirstThenAdminFromIt() public {
        (IPqChat.PqChatEpoch memory g, IPqChat.Wrap[] memory gw) = _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
        bytes32 eg = _rekey(chat, g, gw);
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        IUARegistry.UASig memory as_ = _sig(a.author, h.epoch(a));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, sid, eg));
        chat.rekey(a, aw, as_);
        (a, aw) = _epoch(sid, ids[0], 2, 2, eg, _admins(), _without(_members(3), ids[2]));
        bytes32 ea = _rekey(chat, a, aw);
        assertEq(chat.childOf(eg), ea);
    }

    /// O4: with no admin left, a membership change is refused and a plain rekey accepted.
    function test_O4_noAdminFreezesMembership() public {
        _leave(chat, sid, ids[0], 1);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[1], 1, 1, sid, new bytes32[](0), _without(_members(3), ids[0]));
        bytes32 e1 = _rekey(chat, e, w); // the admin left: dropping it from both lists is plain
        (e, w) = _epoch(sid, ids[1], 2, 2, e1, new bytes32[](0), _without(_without(_members(3), ids[0]), ids[2]));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
        chat.rekey(e, w, sig);
        (e, w) = _epoch(sid, ids[2], 1, 2, e1, new bytes32[](0), _without(_members(3), ids[0]));
        _rekey(chat, e, w); // the plain rekey continues
    }

    /// A 2-of-2 `msig` of two classical keys, both slots accepted.
    function _msig2() internal returns (bytes32 ms, uint16 lo, uint16 hi) {
        _register(p, 0x0101, _key(0x0101));
        _register(p, 0x0102, _key(0x0102));
        (lo, hi) = UAKinds.uaOf(0x0101, _key(0x0101)) < UAKinds.uaOf(0x0102, _key(0x0102))
            ? (uint16(0x0101), uint16(0x0102)) : (uint16(0x0102), uint16(0x0101));
        Member[] memory mm = new Member[](2);
        mm[0] = Member(lo, UAKinds.uaOf(lo, _key(lo)), 1);
        mm[1] = Member(hi, UAKinds.uaOf(hi, _key(hi)), 1);
        bytes memory d = _msigKey(2, mm);
        ms = UACall.register(p, UAKinds.MSIG, d, _none(), "", "");
        p.acceptMembership(ms, _acceptKeySig(d, lo, _key(lo)));
        p.acceptMembership(ms, _acceptKeySig(d, hi, _key(hi)));
    }

    /// The `msig`'s portable signature over `digest` by its first `n` slots.
    function _quorum(bytes32 ms, uint16 lo, uint16 hi, bytes32 digest, uint256 n)
        internal view returns (IUARegistry.UASig memory q)
    {
        bytes32 md = _memberDigest(ms, UAKinds.PURPOSE_PQCHAT, digest);
        q.members = new IUARegistry.MemberSig[](n);
        for (uint256 i; i < n; ++i) {
            uint16 k = i == 0 ? lo : hi;
            q.members[i] = IUARegistry.MemberSig(uint16(i), new IUARegistry.InnerSig[](0),
                _sig(_key(k), UAKinds.uaMessage(k, UAKinds.PURPOSE_MEMBER, md)));
        }
    }

    /// An `msig` admin signs its epoch records by its quorum (`UASig.members`).
    function test_msigAdminSignsByQuorum() public {
        (bytes32 ms, uint16 lo, uint16 hi) = _msig2();
        // a session whose admins are the creator and the msig
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 4, address(chat));
        s.admins = ms < ids[0] ? _list(ms, ids[0]) : _list(ids[0], ms);
        bytes32 sid2 = _create(chat, s, w);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(sid2, ms, 1, 1, sid2, s.admins, _without(_members(3), ids[2]));
        IUARegistry.UASig memory one = _quorum(ms, lo, hi, h.epoch(e), 1);
        vm.expectRevert(_unauthorized(ms));
        chat.rekey(e, ew, one); // below the threshold
        chat.rekey(e, ew, _quorum(ms, lo, hi, h.epoch(e), 2));
        assertTrue(chat.epochComplete(PqChatTypes.epochId(sid2, ms, 1)));
    }

    // ----- leave (P12) -----

    function test_leave_rules() public {
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[3], 1);
        IUARegistry.UASig memory sig = _sig(ids[3], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[3]));
        chat.leave(l, sig);
        l = IPqChat.PqChatLeave(sid, sid, ids[2], 1);
        sig = _sig(ids[1], h.leave(l));
        vm.expectRevert(_unauthorized(ids[2]));
        chat.leave(l, sig); // forged: no nonce burnt
        assertFalse(chat.nonceUsed(PqChatTypes.scopeEpoch(sid, ids[2]), 1));
        l = IPqChat.PqChatLeave(keccak256("x"), sid, ids[2], 1);
        sig = _sig(ids[2], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, sid));
        chat.leave(l, sig); // the epoch is not that session's
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatLeft(sid, sid, ids[2]);
        _leave(chat, sid, ids[2], 1);
        assertTrue(chat.leftIn(sid, ids[2]));
        assertFalse(chat.leftIn(sid, ids[1]));
        l = IPqChat.PqChatLeave(sid, sid, ids[2], 1);
        sig = _sig(ids[2], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, PqChatTypes.scopeEpoch(sid, ids[2]), uint64(1)));
        chat.leave(l, sig);
    }
}
