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

    // ----- removal by an admin (P48, owner 2026-11-10) -----

    function _rm(bytes32 epochId, uint64 next, bytes32[] memory members, bytes32 admin, uint64 nonce)
        internal
        view
        returns (IPqChat.PqChatRemove memory r)
    {
        r = IPqChat.PqChatRemove(sid, epochId, next, members, admin, nonce);
    }

    function _remove(PqChat c, IPqChat.PqChatRemove memory r) internal {
        c.remove(r, _sig(r.admin, h.remove(r)));
    }

    function _refusedRemove(IPqChat.PqChatRemove memory r, bytes32 signer, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(signer, h.remove(r));
        vm.expectRevert(err);
        chat.remove(r, sig);
    }

    /// Fable P1-2: the race. After the admin removes `ids[2]` from epoch 0, `ids[2]`'s plain rekey keeping itself is
    /// refused (`PqChatNotMember`), another member's rekey keeping it too (`PqChatRemovedKept`), and the admin's removal
    /// rekey lands; the record is in state.
    function test_remove_raceIsClosed() public {
        IPqChat.PqChatRemove memory r = _rm(sid, 1, _list(ids[2]), ids[0], 7);
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatRemoved(sid, sid, ids[0], _list(ids[2]));
        vm.prank(STRANGER);
        _remove(chat, r);
        assertTrue(chat.removedIn(sid, ids[2]));
        assertFalse(chat.removedIn(sid, ids[1]));
        assertEq(chat.removalCount(sid), 1);
        (IPqChat.PqChatRemove memory got, bytes32 sigHash) = chat.removalAt(sid, 0);
        assertEq(keccak256(abi.encode(got)), keccak256(abi.encode(r)));
        assertEq(sigHash, keccak256(abi.encode(_sig(r.admin, h.remove(r)))));
        assertTrue(chat.nonceUsed(PqChatTypes.scopeEpoch(sid, ids[0]), 7));
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.rekey(e, w, sig); // the removed member, plain
        (e, w) = _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
        sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, sid, ids[2]));
        chat.rekey(e, w, sig); // another member keeping it
        (e, w) = _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(chat, e, w); // the admin's removal rekey
        assertEq(chat.childOf(sid), eid);
    }

    /// P48: dropping a removed member is plain, so a remaining member lands the child too (no admin needed).
    function test_remove_dropIsPlain() public {
        _remove(chat, _rm(sid, 1, _list(ids[2]), ids[0], 7));
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[1], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        assertEq(chat.childOf(sid), bytes32(0));
        _rekey(chat, e, w);
        assertTrue(chat.childOf(sid) != 0);
    }

    /// P48: a child stored incomplete before the removal (in chunks, keeping the member) cannot complete after it; the
    /// admin's child completes and takes the slot.
    function test_remove_incompleteChildCannotComplete() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        bytes32 kept = chat.rekey(e, _slice(w, 0, 1), sig);
        _remove(chat, _rm(sid, 1, _list(ids[2]), ids[0], 7));
        IPqChat.Wrap[] memory rest = _slice(w, 1, 3);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, sid, ids[2]));
        chat.addWraps(kept, 1, rest);
        (e, w) = _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(chat, e, w);
        assertEq(chat.childOf(sid), eid);
    }

    /// P48: the child may not keep a removed UA among its admins either.
    function test_remove_childAdminsExcludeRemoved() public {
        IPqChat.MemberKey[] memory m = _members(3);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[0], 1, 1, sid, _list(ids[0], ids[1]), m);
        bytes32 e1 = _rekey(chat, e, w); // ids[1] made an admin
        IPqChat.PqChatRemove memory r = _rm(e1, 2, _list(ids[1]), ids[0], 8);
        _remove(chat, r);
        (e, w) = _epoch(sid, ids[0], 9, 2, e1, _list(ids[0], ids[1]), _without(m, ids[1]));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, e1, ids[1]));
        chat.rekey(e, w, sig);
        (e, w) = _epoch(sid, ids[0], 9, 2, e1, _admins(), _without(m, ids[1]));
        _rekey(chat, e, w);
    }

    /// P48 refusals, each beside the control that lands last.
    function test_remove_refusals() public {
        IPqChat.PqChatRemove memory r = _rm(sid, 1, _list(ids[2]), ids[0], 7);
        _refusedRemove(r, ids[1], _unauthorized(ids[0])); // forged: another key signs for the admin
        r.admin = ids[1];
        _refusedRemove(r, ids[1], abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1])); // not an admin
        r.admin = ids[0];
        r.nextEpoch = 2;
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatEpochNumber.selector, uint64(1), uint64(2)));
        r.nextEpoch = 1;
        r.members = new bytes32[](0);
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        r.members = new bytes32[](17); // over REMOVE_MAX = 16
        for (uint256 i; i < 17; ++i) {
            r.members[i] = bytes32(i + 1);
        }
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        r.members = _list(ids[2], ids[1]); // not sorted
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        r.members = _list(keccak256("stranger"));
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, keccak256("stranger")));
        bytes32 x = keccak256("unknown epoch");
        r.members = _list(ids[2]);
        r.epochId = x;
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, x));
        r.epochId = sid;
        assertEq(chat.REMOVE_MAX(), 16);
        _remove(chat, r); // the control
        // replayed: the UA is removed there already, so the record is refused whole (A-4, before the nonce)
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        r.members = _list(ids[1]); // the same nonce for another UA: spent
        _refusedRemove(
            r,
            ids[0],
            abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, PqChatTypes.scopeEpoch(sid, ids[0]), uint64(7))
        );
        r.members = _list(ids[2]); // replayed
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(chat, e, w);
        r.nonce = 8;
        // E-3 (C9): epoch 0 named after a child took its slot is checked and applied at the head, where ids[2] is no member
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        r.members = _list(ids[1]);
        _remove(chat, r); // the control: applied at the head
        assertTrue(chat.removedIn(eid, ids[1]), "at the head");
        assertFalse(chat.removedIn(sid, ids[1]));
        assertEq(chat.removalCount(eid), 1);
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

    /// Fable P1-2 (a): a member who left the parent authors no plain rekey of it; another member's plain rekey of the same
    /// parent (keeping the leaver) is the control.
    function test_rekey_leaverAuthorsNoPlainRekey() public {
        _leave(chat, sid, ids[2], 1);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[2], 2, 1, sid, _admins(), _members(3));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.rekey(e, w, sig);
        (e, w) = _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
        assertEq(chat.childOf(sid), bytes32(0));
        _rekey(chat, e, w);
        assertTrue(chat.childOf(sid) != 0);
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
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
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
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[1], 1, 1, sid, _admins(), _members(3));
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
        vm.expectRevert(
            abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, PqChatTypes.scopeEpoch(sid, ids[1]), uint64(1))
        );
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
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
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

    /// The chain dimension of the home check: `homeChatContract` this instance but `homeChain` another chain's `chain_uid`.
    function test_replica_otherChainUid() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 7, address(chat));
        s.homeChain = keccak256("another chain");
        bytes32 sid2 = _create(chat, s, w);
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid2, ids[0], 1, 1, sid2, _admins(), _without(_members(3), ids[2]));
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(sid2, ids[2], 1, 1, sid2, _admins(), _members(3));
        _rekey(chat, a, aw);
        _rekey(chat, b, bw);
        assertEq(chat.childOf(sid2), bytes32(0));
    }

    // ----- O2, O4, msig admins -----

    /// O2: a member's plain rekey takes the slot before the admin's change; the admin's next rekey from it removes the member.
    function test_O2_plainRekeyFirstThenAdminFromIt() public {
        (IPqChat.PqChatEpoch memory g, IPqChat.Wrap[] memory gw) =
            _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
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
            ? (uint16(0x0101), uint16(0x0102))
            : (uint16(0x0102), uint16(0x0101));
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
        internal
        view
        returns (IUARegistry.UASig memory q)
    {
        bytes32 md = _memberDigest(ms, UAKinds.PURPOSE_PQCHAT, digest);
        q.members = new IUARegistry.MemberSig[](n);
        for (uint256 i; i < n; ++i) {
            uint16 k = i == 0 ? lo : hi;
            q.members[i] = IUARegistry.MemberSig(
                uint16(i),
                new IUARegistry.InnerSig[](0),
                _sig(_key(k), UAKinds.uaMessage(k, UAKinds.PURPOSE_MEMBER, md))
            );
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

    /// `updateMsig` of `ms` to its own structure, every slot enabled, the next version, signed by both slots.
    function _bump(bytes32 ms, uint16 lo, uint16 hi) internal {
        (uint64 v, uint256 en,) = p.msigStateOf(ms);
        IUARegistry.MsigStructure memory st = p.msigOf(ms);
        bytes32 typed = UAKinds.msigUpdateDigest(ms, chainUidA, address(p), v + 1, st, en, uint64(block.number + 100));
        _send(ms, v + 1, st, en, _updSigs(ms, lo, hi, typed));
    }

    /// Both slots of the 2-of-2 `msig` over the update digest `typed` (each under `member`, CTR-UA-44).
    function _updSigs(bytes32 ms, uint16 lo, uint16 hi, bytes32 typed)
        internal
        view
        returns (IUARegistry.MemberSig[] memory q)
    {
        bytes32 md = _memberDigest(ms, UAKinds.PURPOSE_MSIG_UPDATE, typed);
        q = new IUARegistry.MemberSig[](2);
        q[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(_key(lo), UAKinds.uaMessage(lo, UAKinds.PURPOSE_MEMBER, md))
        );
        q[1] = IUARegistry.MemberSig(
            1, new IUARegistry.InnerSig[](0), _sig(_key(hi), UAKinds.uaMessage(hi, UAKinds.PURPOSE_MEMBER, md))
        );
    }

    function _send(
        bytes32 ms,
        uint64 v,
        IUARegistry.MsigStructure memory st,
        uint256 en,
        IUARegistry.MemberSig[] memory q
    ) internal {
        p.updateMsig(ms, v, st, en, uint64(block.number + 100), q, chainUidA);
    }

    /// A-1 of the Fable fix check (CTR-UA-74 "What a consumer keeps", controller call 2026-11-26): an `msig` admin's mode-0
    /// epoch record signed at version 0 lands at home; after `updateMsig` the home's bytes copied verbatim to the replica are
    /// `UAUnauthorized`, the copy with the replica registry's current tag lands there under another `sigHash`. The fixture's
    /// two instances share one registry, so one update is the home's and the replica's. A-2: a new record after the update is
    /// refused with the empty tag and lands with the 8-byte one.
    function test_a1_replicaCopyCarriesTheReplicaTag() public {
        (bytes32 ms, uint16 lo, uint16 hi) = _msig2();
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 4, address(chat));
        s.admins = ms < ids[0] ? _list(ms, ids[0]) : _list(ids[0], ms);
        bytes32 sid2 = _create(chat, s, w);
        _create(chatB, s, w);
        bytes32 e1 = _a1Copy(ms, lo, hi, sid2, s.admins);
        // A-2: a record signed after the update names version 1
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(sid2, ms, 2, 2, e1, s.admins, _without(_without(_members(3), ids[2]), ids[1]));
        IUARegistry.UASig memory n = _quorum(ms, lo, hi, h.epoch(e), 2);
        vm.expectRevert(_unauthorized(ms));
        chat.rekey(e, ew, n);
        n.signature = abi.encodePacked(uint64(1));
        chat.rekey(e, ew, n);
        assertTrue(chat.epochComplete(PqChatTypes.epochId(sid2, ms, 2)));
    }

    function _a1Copy(bytes32 ms, uint16 lo, uint16 hi, bytes32 sid2, bytes32[] memory admins)
        internal
        returns (bytes32 e1)
    {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(sid2, ms, 1, 1, sid2, admins, _without(_members(3), ids[2]));
        IUARegistry.UASig memory v0 = _quorum(ms, lo, hi, h.epoch(e), 2);
        e1 = chat.rekey(e, ew, v0);
        _bump(ms, lo, hi);
        vm.expectRevert(_unauthorized(ms));
        chatB.rekey(e, ew, v0); // the home's bytes: the tag of version 0
        IUARegistry.UASig memory v1 = _quorum(ms, lo, hi, h.epoch(e), 2);
        v1.signature = abi.encodePacked(uint64(1));
        assertEq(chatB.rekey(e, ew, v1), e1);
        assertEq(_kept(chat, e1), keccak256(abi.encode(v0)));
        assertEq(_kept(chatB, e1), keccak256(abi.encode(v1)), "the replica keeps its own tag");
    }

    function _kept(PqChat c, bytes32 epochId) internal view returns (bytes32 sigHash) {
        (, sigHash) = c.epochOf(epochId);
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
        // a repeated leave: the member is flagged there already (sc-E-5, before the nonce)
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.leave(l, sig);
    }

    // ----- Fable code review of PqVault V1-V8, F1 / F2 / F7 in the shared base (controller call 2026-11-21) -----

    /// A session whose admins are `ids[0]` and `ids[1]` (sorted), three members.
    function _twoAdmins() internal returns (bytes32 sid2, bytes32[] memory admins) {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 9, address(chat));
        admins = ids[0] < ids[1] ? _list(ids[0], ids[1]) : _list(ids[1], ids[0]);
        s.admins = admins;
        sid2 = _create(chat, s, w);
    }

    /// F1: admin `ids[1]` stages a child that leaves itself out (incomplete), `ids[0]` removes it; the child no longer completes
    /// (`PqChatRemovedKept(parent, ids[1])`). The control: not removed, the same child completes.
    function test_removedAuthorsStagedChildCannotComplete() public {
        (bytes32 sid2,) = _twoAdmins();
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid2, ids[1], 1, 1, sid2, _list(ids[0]), _without(_members(3), ids[1]));
        bytes32 staged = chat.rekey(e, _slice(w, 0, 1), _sig(e.author, h.epoch(e)));
        IPqChat.Wrap[] memory rest = _slice(w, 1, 2);
        uint256 snap = vm.snapshotState();
        chat.addWraps(staged, 1, rest); // the control
        assertEq(chat.childOf(sid2), staged);
        vm.revertToState(snap);
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(sid2, sid2, 1, _list(ids[1]), ids[0], 2);
        chat.remove(r, _sig(r.admin, h.remove(r)));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, sid2, ids[1]));
        chat.addWraps(staged, 1, rest);
    }

    /// F2: once removed, an admin removes nobody (`PqChatNotAdmin`); the other admin still does.
    function test_removedAdminRemovesNobody() public {
        (bytes32 sid2,) = _twoAdmins();
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(sid2, sid2, 1, _list(ids[1]), ids[0], 2);
        chat.remove(r, _sig(r.admin, h.remove(r)));
        IPqChat.PqChatRemove memory back = IPqChat.PqChatRemove(sid2, sid2, 1, _list(ids[0]), ids[1], 3);
        IUARegistry.UASig memory sig = _sig(back.admin, h.remove(back));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
        chat.remove(back, sig);
        r = IPqChat.PqChatRemove(sid2, sid2, 1, _list(ids[2]), ids[0], 4);
        chat.remove(r, _sig(r.admin, h.remove(r))); // the control
    }

    /// F7 (as O3 (b)): an admin that left makes no membership change and removes nobody (`PqChatNotAdmin`); the controls run the
    /// same calls before the leave.
    function test_leftAdminNeitherChangesNorRemoves() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        IPqChat.PqChatRemove memory r = _rm(sid, 1, _list(ids[2]), ids[0], 2);
        uint256 snap = vm.snapshotState();
        _rekey(chat, e, w);
        vm.revertToState(snap);
        _remove(chat, r);
        vm.revertToState(snap);
        _leave(chat, sid, ids[0], 3);
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[0]));
        chat.rekey(e, w, sig);
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[0]));
    }

    /// F3 (controller call 2026-11-21, one rule everywhere): an admin that is no member (an `msig`, which holds no KEM key) is
    /// removable, and a child keeping it as an admin is then `PqChatRemovedKept`; the child without it lands.
    function test_adminOnlyMsigRemovable() public {
        (bytes32 ms,,) = _msig2();
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 6, address(chat));
        s.admins = ms < ids[0] ? _list(ms, ids[0]) : _list(ids[0], ms);
        bytes32 sid2 = _create(chat, s, w);
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(sid2, sid2, 1, _list(ms), ids[0], 1);
        chat.remove(r, _sig(r.admin, h.remove(r)));
        assertTrue(chat.removedIn(sid2, ms));
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(sid2, ids[0], 2, 1, sid2, s.admins, _members(3));
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, sid2, ms));
        chat.rekey(e, ew, sig);
        (e, ew) = _epoch(sid2, ids[0], 3, 1, sid2, _admins(), _members(3));
        _rekey(chat, e, ew); // the control
    }

    // ----- E-3 in mode 0 (CTR-CHAT-10, CTR-CHAT-20; Change 2026-11-24; owner: "Yes, both modes") -----

    /// A plain rekey of the head by `author` (nonce `n`, epoch `number`), all three members kept.
    function _plain(PqChat c, bytes32 author, uint64 n, uint64 number, bytes32 parent) internal returns (bytes32) {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, author, n, number, parent, _admins(), _members(3));
        return _rekey(c, e, w);
    }

    /// At home a leave naming the parent of the head lands at the head (the front-run of E-3); a repeat is refused there, and
    /// the next plain rekey of the head may drop the leaver.
    function test_e3_leaveNamingTheParentAppliesAtTheHead() public {
        bytes32 e1 = _plain(chat, ids[0], 1, 1, sid); // the front-running epoch
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatLeft(sid, e1, ids[2]);
        _leave(chat, sid, ids[2], 1);
        assertTrue(chat.leftIn(e1, ids[2]), "at the head");
        assertFalse(chat.leftIn(sid, ids[2]));
        assertEq(chat.leaveCount(e1), 1, "A-14: the kept record under the head"); // pqchat-core reads it under the parent
        assertEq(chat.leaveCount(sid), 0);
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[2], 2);
        IUARegistry.UASig memory sg = _sig(ids[2], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.leave(l, sg); // flagged at the head already
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[1], 1, 2, e1, _admins(), _without(_members(3), ids[2]));
        _rekey(chat, e, w); // a plain drop by a member that is no admin
    }

    /// The lag at its edge: the head at 17 refuses a removal naming epoch 0 and takes one naming epoch 1.
    function test_e3_exitLagBound() public {
        bytes32 p = sid;
        bytes32 e1;
        for (uint64 i = 1; i <= 17; ++i) {
            p = _plain(chat, ids[0], i, i, p);
            if (i == 1) e1 = p;
        }
        IPqChat.PqChatRemove memory r = _rm(sid, 1, _list(ids[2]), ids[0], 100);
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqChat.PqChatExitLag.selector, uint64(0), uint64(17)));
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[1], 1);
        IUARegistry.UASig memory sg = _sig(ids[1], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatExitLag.selector, uint64(0), uint64(17)));
        chat.leave(l, sg);
        (r.epochId, r.nextEpoch) = (e1, 2); // the control: one epoch younger
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatRemoved(sid, p, ids[0], _list(ids[2])); // A-14: the head's id
        _remove(chat, r);
        assertTrue(chat.removedIn(p, ids[2]), "at the head");
        assertFalse(chat.removedIn(e1, ids[2]));
        assertEq(chat.removalCount(p), 1);
    }

    /// At home a staged epoch (a prefix of its wraps landed) is `PqChatIncomplete` for a leave; its parent, the head, is not.
    function test_e3_leaveNamingAStagedEpochAtHome() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[0], 1, 1, sid, _admins(), _members(3));
        IPqChat.Wrap[] memory one = new IPqChat.Wrap[](1);
        one[0] = w[0];
        bytes32 staged = chat.rekey(e, one, _sig(e.author, h.epoch(e)));
        assertFalse(chat.epochComplete(staged));
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, staged, ids[2], 1);
        IUARegistry.UASig memory sg = _sig(ids[2], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatIncomplete.selector, staged));
        chat.leave(l, sg);
        _leave(chat, sid, ids[2], 1); // the control
        assertTrue(chat.leftIn(sid, ids[2]));
    }

    /// T11 (C9, mode 0): a removal by a UA that is an admin of the epoch it names and not of the head is `PqChatNotAdmin`
    /// (checked at the head); the head's admin's removal naming the same epoch lands at the head.
    function test_e3_removalByAnAdminOfTheNamedEpochOnly() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[0], 1, 1, sid, _list(ids[0], ids[1]), _members(3));
        bytes32 e1 = _rekey(chat, e, w); // ids[1] an admin of e1
        (e, w) = _epoch(sid, ids[0], 2, 2, e1, _admins(), _members(3));
        bytes32 e2 = _rekey(chat, e, w); // and not of the head e2
        IPqChat.PqChatRemove memory r = _rm(e1, 2, _list(ids[2]), ids[1], 100);
        _refusedRemove(r, ids[1], abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
        _remove(chat, _rm(e1, 2, _list(ids[2]), ids[0], 100)); // control
        assertTrue(chat.removedIn(e2, ids[2]), "at the head");
    }

    /// The replica rule (sc-E-4): the home applied a leave naming epoch 0 at its head e1; the replica flags epoch 0 and still
    /// stores the home's child of e1 that drops the leaver (a flag one epoch above the parent), copied in either order. A drop
    /// nobody flagged is a membership change there as at home.
    function test_replica_flagAtAnAncestorAllowsADrop() public {
        (IPqChat.PqChatSession memory s0, IPqChat.Wrap[] memory sw) = _session(3, 1, address(chat));
        chatB.createSession(s0, sw, _sig(s0.creator, h.session(s0)));
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _members(3));
        bytes32 e1 = _rekey(chat, a, aw);
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[2], 1);
        IUARegistry.UASig memory ls = _sig(ids[2], h.leave(l));
        chat.leave(l, ls); // at home: applied at e1
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(sid, ids[1], 1, 2, e1, _admins(), _without(_members(3), ids[2]));
        IUARegistry.UASig memory bs = _sig(b.author, h.epoch(b));
        bytes32 e2 = chat.rekey(b, bw, bs);
        // the replica: e1, then the leave (it flags epoch 0, the epoch it names), then e2
        assertEq(_rekey(chatB, a, aw), e1);
        chatB.leave(l, ls);
        assertTrue(chatB.leftIn(sid, ids[2]) && !chatB.leftIn(e1, ids[2]), "a replica flags the epoch named");
        // the control: a drop of ids[0] nobody flagged, by a member that is no admin
        (IPqChat.PqChatEpoch memory c, IPqChat.Wrap[] memory cw) =
            _epoch(sid, ids[1], 2, 2, e1, _admins(), _without(_members(3), ids[0]));
        IUARegistry.UASig memory cs = _sig(c.author, h.epoch(c));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
        chatB.rekey(c, cw, cs);
        assertEq(chatB.rekey(b, bw, bs), e2);
        assertTrue(chatB.epochComplete(e2));
    }

    /// The replica rule (sc-E-4): in a replica a removal's flag refuses nothing, so the removed UA's child of that epoch is
    /// stored there; at home it is `PqChatNotMember`.
    function test_replica_removalFlagRefusesNothing() public {
        (IPqChat.PqChatSession memory s0, IPqChat.Wrap[] memory sw) = _session(3, 1, address(chat));
        chatB.createSession(s0, sw, _sig(s0.creator, h.session(s0)));
        IPqChat.PqChatRemove memory r = _rm(sid, 1, _list(ids[2]), ids[0], 7);
        _remove(chatB, r);
        assertTrue(chatB.removedIn(sid, ids[2]));
        _remove(chat, r);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[2], 1, 1, sid, _admins(), _members(3));
        IUARegistry.UASig memory es = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.rekey(e, w, es); // at home
        bytes32 eid = chatB.rekey(e, w, es);
        assertTrue(chatB.epochComplete(eid), "a replica stores it");
    }

    /// At home a flag allows a plain drop at its own epoch only (exits apply at the head): a leaver flagged at epoch 0 and kept
    /// by e1 is no plain drop from e1, so a member that is no admin may not drop it; an admin may (a membership change).
    function test_home_flagAtAnAncestorAllowsNoPlainDrop() public {
        _leave(chat, sid, ids[2], 1);
        bytes32 e1 = _plain(chat, ids[0], 1, 1, sid); // keeps the leaver
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[1], 1, 2, e1, _admins(), _without(_members(3), ids[2]));
        IUARegistry.UASig memory es = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
        chat.rekey(e, w, es);
        (e, w) = _epoch(sid, ids[0], 2, 2, e1, _admins(), _without(_members(3), ids[2]));
        _rekey(chat, e, w); // the control
    }

    /// The replica rule (sc-E-4): a leaver's own plain rekey keeping itself is refused at home (Fable P1-2 (a)) and stored in
    /// a replica, where the flag refuses nothing.
    function test_replica_leaverAuthorRefusedAtHomeOnly() public {
        (IPqChat.PqChatSession memory s0, IPqChat.Wrap[] memory sw) = _session(3, 1, address(chat));
        chatB.createSession(s0, sw, _sig(s0.creator, h.session(s0)));
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[2], 1);
        IUARegistry.UASig memory ls = _sig(ids[2], h.leave(l));
        chat.leave(l, ls);
        chatB.leave(l, ls);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[2], 2, 1, sid, _admins(), _members(3));
        IUARegistry.UASig memory es = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.rekey(e, w, es);
        assertTrue(chatB.epochComplete(chatB.rekey(e, w, es)), "a replica stores it");
    }

    // ----- E-2, A-16 (controller call 2026-11-25): a replica copies every exit the home took -----

    /// The replica of `sid` in `chatB`.
    function _replicaOfSid() internal {
        (IPqChat.PqChatSession memory s0, IPqChat.Wrap[] memory sw) = _session(3, 1, address(chat));
        chatB.createSession(s0, sw, _sig(s0.creator, h.session(s0)));
    }

    /// e1 of `sid`, by the admin: `ids[1]` made an admin and `ids[3]` added; at home and in the replica.
    function _e1Grows() internal returns (bytes32 e1) {
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[0], 1, 1, sid, _list(ids[0], ids[1]), _members(4));
        e1 = _rekey(chat, a, aw);
        assertEq(_rekey(chatB, a, aw), e1);
    }

    /// E-2: `ids[3]`, added at e1, signs a leave naming epoch 0, where it is no member: at home it is refused, as a replica
    /// (which checks on the epoch named) would refuse it, so no replica is stopped by it. The control names e1: it lands at
    /// home and in the replica, and the plain drop of the leaver by a member that is no admin is stored in both.
    function test_e2_leaveNamesAnEpochTheLeaverIsIn() public {
        _replicaOfSid();
        bytes32 e1 = _e1Grows();
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[3], 1);
        IUARegistry.UASig memory ls = _sig(ids[3], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[3]));
        chat.leave(l, ls);
        l.epochId = e1; // the control
        ls = _sig(ids[3], h.leave(l));
        chat.leave(l, ls);
        chatB.leave(l, ls);
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(sid, ids[2], 1, 2, e1, _list(ids[0], ids[1]), _members(3));
        IUARegistry.UASig memory bs = _sig(b.author, h.epoch(b));
        bytes32 e2 = chat.rekey(b, bw, bs);
        assertEq(chatB.rekey(b, bw, bs), e2);
        assertTrue(chatB.epochComplete(e2), "the replica copies the home's chain");
    }

    /// E-2: a removal naming epoch 0 by `ids[1]`, an admin of e1 only, and one naming `ids[3]`, added at e1, are refused at
    /// home. The control names e1 and lands at home and in the replica; the plain drop after it is stored in both.
    function test_e2_removalNamesAnEpochItsUAsAreIn() public {
        _replicaOfSid();
        bytes32 e1 = _e1Grows();
        _refusedRemove(
            _rm(sid, 1, _list(ids[2]), ids[1], 1),
            ids[1],
            abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1])
        );
        _refusedRemove(
            _rm(sid, 1, _list(ids[3]), ids[0], 5),
            ids[0],
            abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[3])
        );
        IPqChat.PqChatRemove memory r = _rm(e1, 2, _list(ids[3]), ids[1], 1); // the control
        IUARegistry.UASig memory rs = _sig(ids[1], h.remove(r));
        chat.remove(r, rs);
        chatB.remove(r, rs);
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(sid, ids[2], 1, 2, e1, _list(ids[0], ids[1]), _members(3));
        IUARegistry.UASig memory bs = _sig(b.author, h.epoch(b));
        bytes32 e2 = chat.rekey(b, bw, bs);
        assertEq(chatB.rekey(b, bw, bs), e2);
    }

    /// A-16: the home takes a second leave of `ids[2]` naming epoch 0 (the first was applied at epoch 0, the second at the
    /// head e1, which kept the leaver); a replica takes it too, though it flags nobody new there, and holds both records. The
    /// plain drop after it is stored in both.
    function test_a16_replicaTakesASecondLeaveNamingOneEpoch() public {
        _replicaOfSid();
        IPqChat.PqChatLeave memory l1 = IPqChat.PqChatLeave(sid, sid, ids[2], 1);
        IUARegistry.UASig memory s1 = _sig(ids[2], h.leave(l1));
        chat.leave(l1, s1);
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[0], 1, 1, sid, _admins(), _members(3));
        bytes32 e1 = _rekey(chat, a, aw); // keeps the leaver
        IPqChat.PqChatLeave memory l2 = IPqChat.PqChatLeave(sid, sid, ids[2], 2);
        IUARegistry.UASig memory s2 = _sig(ids[2], h.leave(l2));
        chat.leave(l2, s2);
        assertTrue(chat.leftIn(e1, ids[2]));
        chatB.leave(l1, s1);
        assertEq(_rekey(chatB, a, aw), e1);
        chatB.leave(l2, s2);
        assertEq(chatB.leaveCount(sid), 2, "both records, under the epoch named");
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(sid, ids[1], 1, 2, e1, _admins(), _without(_members(3), ids[2]));
        IUARegistry.UASig memory bs = _sig(b.author, h.epoch(b));
        bytes32 e2 = chat.rekey(b, bw, bs);
        assertEq(chatB.rekey(b, bw, bs), e2);
    }

    /// A-16, the removal form: `ids[2]` removed naming epoch 0, dropped at e1, added again at e2, removed naming epoch 0 again
    /// (inside the lag) at the head e2. A replica takes the second record too and holds both under epoch 0.
    function test_a16_replicaTakesASecondRemovalNamingOneEpoch() public {
        _replicaOfSid();
        IPqChat.PqChatRemove memory r1 = _rm(sid, 1, _list(ids[2]), ids[0], 10);
        IUARegistry.UASig memory s1 = _sig(ids[0], h.remove(r1));
        chat.remove(r1, s1);
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[1], 1, 1, sid, _admins(), _without(_members(3), ids[2]));
        bytes32 e1 = _rekey(chat, a, aw); // the plain drop
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) = _epoch(sid, ids[0], 1, 2, e1, _admins(), _members(3));
        bytes32 e2 = _rekey(chat, b, bw); // added again
        IPqChat.PqChatRemove memory r2 = _rm(sid, 1, _list(ids[2]), ids[0], 11);
        IUARegistry.UASig memory s2 = _sig(ids[0], h.remove(r2));
        chat.remove(r2, s2);
        assertTrue(chat.removedIn(e2, ids[2]));
        chatB.remove(r1, s1);
        assertEq(_rekey(chatB, a, aw), e1);
        assertEq(_rekey(chatB, b, bw), e2);
        chatB.remove(r2, s2);
        assertEq(chatB.removalCount(sid), 2, "both records, under the epoch named");
    }

    // ----- A-13, A-14 (the re-review of 2026-11-25): the replica walk's bound, the flags read at home -----

    /// A-14: a member removed at the head leaves no more (`removedOf` at the head, CTR-CHAT-10); another member's leave of the
    /// same head lands (the control).
    function test_a14_removedAtTheHeadLeavesNoMore() public {
        _remove(chat, _rm(sid, 1, _list(ids[2]), ids[0], 7));
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[2], 1);
        IUARegistry.UASig memory ls = _sig(ids[2], h.leave(l));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[2]));
        chat.leave(l, ls);
        _leave(chat, sid, ids[1], 1);
        assertTrue(chat.leftIn(sid, ids[1]));
    }

    /// A-14: in a replica a removal naming a staged epoch is `PqChatIncomplete`; naming its complete parent it lands.
    function test_a14_replicaRemovalNamingAStagedEpoch() public {
        _replicaOfSid();
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[0], 1, 1, sid, _admins(), _members(3));
        bytes32 staged = chatB.rekey(e, _slice(w, 0, 1), _sig(e.author, h.epoch(e)));
        assertFalse(chatB.epochComplete(staged));
        _refusedRemoveAt(
            chatB,
            _rm(staged, 2, _list(ids[2]), ids[0], 7),
            abi.encodeWithSelector(IPqChat.PqChatIncomplete.selector, staged)
        );
        _remove(chatB, _rm(sid, 1, _list(ids[2]), ids[0], 7)); // the control
        assertTrue(chatB.removedIn(sid, ids[2]));
    }

    function _refusedRemoveAt(PqChat c, IPqChat.PqChatRemove memory r, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(r.admin, h.remove(r));
        vm.expectRevert(err);
        c.remove(r, sig);
    }

    /// A-13 (plan T11; CTR-CHAT-20's replica rule): a replica chain e1..e17 of plain rekeys that keep `ids[2]`, with a
    /// removal's flag on epoch 0 (copied before the chain or after it, `first`). A drop of `ids[2]` by a member that is no
    /// admin from e16 (the flag 16 epochs above) is stored as a plain rekey; from e17 (17 above) it is `PqChatNotAdmin`.
    function _replicaWalkBound(bool first) internal {
        _replicaOfSid();
        IPqChat.PqChatRemove memory r = _rm(sid, 1, _list(ids[2]), ids[0], 100);
        if (first) _remove(chatB, r);
        bytes32 p = sid;
        bytes32 e16;
        for (uint64 i = 1; i <= 17; ++i) {
            p = _plain(chatB, ids[0], i, i, p);
            if (i == 16) e16 = p;
        }
        if (!first) _remove(chatB, r);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(sid, ids[1], 1, 18, p, _admins(), _without(_members(3), ids[2]));
        IUARegistry.UASig memory es = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
        chatB.rekey(e, w, es); // a flag 17 above is not used
        (e, w) = _epoch(sid, ids[1], 1, 17, e16, _admins(), _without(_members(3), ids[2]));
        assertTrue(chatB.epochComplete(_rekey(chatB, e, w)), "a flag 16 above allows the plain drop");
    }

    function test_a13_replicaWalkBoundRemovalFirst() public {
        _replicaWalkBound(true);
    }

    function test_a13_replicaWalkBoundRemovalLast() public {
        _replicaWalkBound(false);
    }

    // ----- A-15 (controller call 2026-11-25, as C40): an empty `addWraps` is refused -----

    /// An empty `addWraps` on a staged flat epoch is `PqChatShape` (it wrote nothing and emitted a piece event of count 0);
    /// on the complete session epoch too. The control lands the staged epoch's remaining wraps.
    function test_a15_emptyAddWrapsRefusedFlat() public {
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[0], 1, 1, sid, _admins(), _members(3));
        bytes32 staged = chat.rekey(e, _slice(w, 0, 1), _sig(e.author, h.epoch(e)));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.addWraps(staged, 1, new IPqChat.Wrap[](0));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.addWraps(sid, 0, new IPqChat.Wrap[](0));
        chat.addWraps(staged, 1, _slice(w, 1, 3)); // the control
        assertTrue(chat.epochComplete(staged));
    }
}
