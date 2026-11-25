// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V3: PqChat's epoch suite ported (the removal attack, the slot, replicas, leavers, removals, an `msig` admin) with
/// PqVault's rule that every rekey is an admin's (CTR-PQV-13, VC16). Vaults of three members in mode 0: `ids[0]` creator and only
/// admin. Every refusal beside its positive control.
contract PqVaultEpochsTest is PqVaultBase {
    bytes32 internal vid;

    function setUp() public override {
        super.setUp();
        (vid,) = _newVault(3, 0);
    }

    function _admins() internal view returns (bytes32[] memory) {
        return _list(ids[0]);
    }

    function _leave(PqVault c, bytes32 epochId, bytes32 member, uint64 nonce) internal {
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, epochId, member, nonce);
        c.leaveVault(l, _sig(member, h.leave(l, PqVaultTypes.DS_V)));
    }

    function _rm(bytes32 epochId, uint64 next, bytes32[] memory members, bytes32 admin, uint64 nonce)
        internal
        view
        returns (IPqVault.PqVaultRemove memory)
    {
        return IPqVault.PqVaultRemove(vid, epochId, next, members, admin, nonce);
    }

    function _remove(PqVault c, IPqVault.PqVaultRemove memory r) internal {
        c.removeVaultMembers(r, _sig(r.admin, h.remove(r, PqVaultTypes.DS_V)));
    }

    function _refusedRemove(IPqVault.PqVaultRemove memory r, bytes32 signer, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(signer, h.remove(r, PqVaultTypes.DS_V));
        vm.expectRevert(err);
        vault.removeVaultMembers(r, sig);
    }

    function _refusedRekey(IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e, PqVaultTypes.DS_V));
        vm.expectRevert(err);
        vault.rekeyVault(e, w, sig);
    }

    // ----- every rekey is an admin's (CTR-PQV-13) -----

    /// A member who is no admin is refused `PqVaultNotAdmin` even for a rekey that keeps everyone (PqChat would call it plain);
    /// the admin's rekey lands, the record and its full `UASig` read back.
    function test_rekey_onlyAnAdmin() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[1], 1, 1, vid, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[1]));
        (e, w) = _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        bytes32 eid = PqVaultTypes.epochId(vid, ids[0], 1);
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultEpochAdded(vid, eid, vid, 1, ids[0]);
        vm.prank(STRANGER);
        assertEq(_rekey(vault, e, w, 0), eid);
        assertEq(vault.childOf(vid), eid, "the home slot");
        bytes memory got = _raw(address(vault), abi.encodeCall(IPqVault.epochOf, (eid)));
        assertEq(got, abi.encode(e, _sig(e.author, h.epoch(e, PqVaultTypes.DS_V))), "the record and its full UASig");
        assertEq(keccak256(abi.encode(abi.decode(got, (IPqVault.PqVaultEpoch)))), keccak256(abi.encode(e)));
        assertTrue(vault.nonceUsed(PqVaultTypes.scopeEpoch(vid, ids[0]), 1));
        assertEq(vault.epochCount(vid), 2);
        assertEq(vault.latestEpoch(vid), eid);
        assertEq(vault.epochsOf(vid, 0, 9)[1], eid);
    }

    /// A removed admin is refused `PqVaultNotAdmin`; the other admin is the control.
    function test_rekey_removedAdminRefused() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0], ids[1]), _members(3));
        bytes32 e1 = _rekey(vault, e, w, 0); // ids[1] made an admin
        _remove(vault, _rm(e1, 2, _list(ids[1]), ids[0], 2));
        (e, w) = _epoch(vid, ids[1], 3, 2, e1, _admins(), _without(_members(3), ids[1]));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[1]));
        (e, w) = _epoch(vid, ids[0], 3, 2, e1, _admins(), _without(_members(3), ids[1]));
        _rekey(vault, e, w, 0);
    }

    /// The admin adds, drops and changes admins in one rekey; the added member's `vaultsOf` gains the vault.
    function test_rekey_adminChangesMembership() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0], ids[1]), _without(_members(4), ids[2]));
        assertEq(vault.vaultCount(ids[3]), 0);
        _rekey(vault, e, w, 0);
        assertEq(vault.vaultCount(ids[3]), 1);
        assertEq(vault.vaultCount(ids[1]), 1, "a kept member gains no entry");
    }

    /// A passphrase change is an admin's rekey (VC10): the shape rule holds on epochs too.
    function test_rekey_passphraseShape() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        e.passSalt = 0;
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        e.passKdf = 0;
        _rekey(vault, e, w, 0); // off: the control
    }

    // ----- removal by an admin (CTR-CHAT-20 as PqVault's) -----

    /// The race: after the admin removes `ids[2]` from epoch 0, an admin's child keeping it is refused `PqVaultRemovedKept` at
    /// completion; the admin's child without it lands; the record and its full `UASig` are in state.
    function test_remove_raceIsClosed() public {
        IPqVault.PqVaultRemove memory r = _rm(vid, 1, _list(ids[2]), ids[0], 7);
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultRemoved(vid, vid, ids[0], _list(ids[2]));
        vm.prank(STRANGER);
        _remove(vault, r);
        assertTrue(vault.removedIn(vid, ids[2]));
        assertFalse(vault.removedIn(vid, ids[1]));
        assertEq(vault.removalCount(vid), 1);
        bytes memory got = _raw(address(vault), abi.encodeCall(IPqVault.removalAt, (vid, 0)));
        assertEq(got, abi.encode(r, _sig(r.admin, h.remove(r, PqVaultTypes.DS_V))), "the record and its full UASig");
        assertTrue(vault.nonceUsed(PqVaultTypes.scopeEpoch(vid, ids[0]), 7));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultRemovedKept.selector, vid, ids[2]));
        (e, w) = _epoch(vid, ids[0], 1, 1, vid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(vault, e, w, 0);
        assertEq(vault.childOf(vid), eid);
    }

    /// A child stored incomplete before the removal (keeping the member) cannot complete after it.
    function test_remove_incompleteChildCannotComplete() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        bytes32 kept = vault.rekeyVault(e, _slice(w, 0, 1), _sig(e.author, h.epoch(e, PqVaultTypes.DS_V)));
        _remove(vault, _rm(vid, 1, _list(ids[2]), ids[0], 7));
        IPqChat.Wrap[] memory rest = _slice(w, 1, 3);
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultRemovedKept.selector, vid, ids[2]));
        vault.addVaultWraps(kept, 1, rest);
        (e, w) = _epoch(vid, ids[0], 2, 1, vid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(vault, e, w, 0);
        assertEq(vault.childOf(vid), eid);
    }

    /// The child may not keep a removed UA among its admins either.
    function test_remove_childAdminsExcludeRemoved() public {
        IPqChat.MemberKey[] memory m = _members(3);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0], ids[1]), m);
        bytes32 e1 = _rekey(vault, e, w, 0);
        _remove(vault, _rm(e1, 2, _list(ids[1]), ids[0], 8));
        (e, w) = _epoch(vid, ids[0], 9, 2, e1, _list(ids[0], ids[1]), _without(m, ids[1]));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultRemovedKept.selector, e1, ids[1]));
        (e, w) = _epoch(vid, ids[0], 9, 2, e1, _admins(), _without(m, ids[1]));
        _rekey(vault, e, w, 0);
    }

    function test_remove_refusals() public {
        IPqVault.PqVaultRemove memory r = _rm(vid, 1, _list(ids[2]), ids[0], 7);
        _refusedRemove(r, ids[1], _unauthorized(ids[0])); // forged
        r.admin = ids[1];
        _refusedRemove(r, ids[1], abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[1]));
        r.admin = ids[0];
        r.nextEpoch = 2;
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultEpochNumber.selector, uint64(1), uint64(2)));
        r.nextEpoch = 1;
        r.members = new bytes32[](0);
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        r.members = new bytes32[](17);
        for (uint256 i; i < 17; ++i) {
            r.members[i] = bytes32(i + 1);
        }
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        r.members = new bytes32[](2);
        (r.members[0], r.members[1]) = (ids[2], ids[1]); // not sorted
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        r.members = _list(keccak256("stranger"));
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, keccak256("stranger")));
        bytes32 x = keccak256("unknown epoch");
        r.members = _list(ids[2]);
        r.epochId = x;
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, x));
        r.epochId = vid;
        _remove(vault, r); // the control
        // replayed: the UA is removed there already, so the record is refused whole (A-4, before the nonce)
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ids[2]));
        r.members = _list(ids[1]); // the same nonce for another UA: spent
        _refusedRemove(
            r,
            ids[0],
            abi.encodeWithSelector(IPqVault.PqVaultNonceUsed.selector, PqVaultTypes.scopeEpoch(vid, ids[0]), uint64(7))
        );
        r.members = _list(ids[2]);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(vault, e, w, 0);
        r.nonce = 8;
        // E-3 (C9): epoch 0 named after a child took its slot is checked and applied at the head, where ids[2] is no member
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ids[2]));
        r.members = _list(ids[1]);
        _remove(vault, r); // the control: applied at the head
        assertTrue(vault.removedIn(eid, ids[1]), "at the head");
        assertFalse(vault.removedIn(vid, ids[1]));
        assertEq(vault.removalCount(eid), 1);
    }

    // ----- the slot, the parent, nonces (P9, P10) -----

    /// The removal attack: once the admin's child holds the slot, another child of the same parent cannot land.
    function test_rekey_slotTaken() public {
        (IPqVault.PqVaultEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _without(_members(3), ids[2]));
        bytes32 e1 = _rekey(vault, a, aw, 0);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 2, 1, vid, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultEpochTaken.selector, vid, e1));
        (e, w) = _epoch(vid, ids[0], 3, 1000, vid, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultEpochNumber.selector, uint64(1), uint64(1000)));
        // the removed member, no admin, from the admin's epoch: refused
        (e, w) = _epoch(vid, ids[2], 1, 2, e1, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[2]));
        (e, w) = _epoch(vid, ids[0], 4, 2, e1, _admins(), _without(_members(3), ids[2]));
        _rekey(vault, e, w, 0); // the control
    }

    /// An incomplete child never takes the slot; anyone finishes it; once another child holds the slot it cannot land.
    function test_rekey_incompleteChildNeverTakesSlot() public {
        (IPqVault.PqVaultEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        bytes32 ea = vault.rekeyVault(a, _slice(aw, 0, 1), _sig(a.author, h.epoch(a, PqVaultTypes.DS_V)));
        assertEq(vault.childOf(vid), bytes32(0));
        (IPqVault.PqVaultEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(vid, ids[0], 2, 1, vid, _admins(), _without(_members(3), ids[2]));
        bytes32 eb = _rekey(vault, b, bw, 0);
        assertEq(vault.childOf(vid), eb);
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultEpochTaken.selector, vid, eb));
        vault.addVaultWraps(ea, 1, _slice(aw, 1, 3));
        (IPqVault.PqVaultEpoch memory c, IPqChat.Wrap[] memory cw) = _epoch(vid, ids[0], 3, 2, eb, _admins(), b.members);
        bytes32 ec = vault.rekeyVault(c, _slice(cw, 0, 1), _sig(c.author, h.epoch(c, PqVaultTypes.DS_V)));
        vm.prank(STRANGER);
        vault.addVaultWraps(ec, 1, _slice(cw, 1, 2));
        assertEq(vault.childOf(eb), ec);
    }

    /// A parent not complete, unknown, of another vault; a record naming another vault than its parent's (review r2 R11).
    function test_rekey_parentRules() public {
        (IPqVault.PqVaultEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        bytes32 ea = vault.rekeyVault(a, _slice(aw, 0, 1), _sig(a.author, h.epoch(a, PqVaultTypes.DS_V)));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 2, 2, ea, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultIncomplete.selector, ea));
        bytes32 x = keccak256("x");
        (e, w) = _epoch(vid, ids[0], 3, 1, x, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, x));
        (IPqVault.PqVaultCreate memory v2, IPqChat.Wrap[] memory w2) = _vault(3, 2, 0, address(vault));
        bytes32 vid2 = _create(vault, v2, w2);
        (e, w) = _epoch(vid, ids[0], 4, 1, vid2, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid2)); // another vault's epoch
        (e, w) = _epoch(vid2, ids[0], 5, 1, vid, _admins(), _members(3));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid)); // the record names vid2
        vault.addVaultWraps(ea, 1, _slice(aw, 1, 3));
        (e, w) = _epoch(vid, ids[0], 2, 2, ea, _admins(), _members(3));
        _rekey(vault, e, w, 0); // the control
    }

    function test_rekey_nonceAndShapes() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        bytes32 e1 = _rekey(vault, e, w, 0);
        (e, w) = _epoch(vid, ids[0], 1, 2, e1, _admins(), _members(3));
        _refusedRekey(
            e,
            w,
            abi.encodeWithSelector(IPqVault.PqVaultNonceUsed.selector, PqVaultTypes.scopeEpoch(vid, ids[0]), uint64(1))
        );
        (e, w) = _epoch(vid, ids[0], 2, 2, e1, _admins(), _members(3));
        IUARegistry.UASig memory sig = _sig(ids[1], h.epoch(e, PqVaultTypes.DS_V));
        vm.expectRevert(_unauthorized(ids[0]));
        vault.rekeyVault(e, w, sig);
        assertFalse(vault.nonceUsed(PqVaultTypes.scopeEpoch(vid, ids[0]), 2), "a forged record burns no nonce");
        IPqChat.MemberKey[] memory m = _members(3);
        (m[0], m[1]) = (m[1], m[0]);
        (e, w) = _epoch(vid, ids[0], 2, 2, e1, _admins(), m);
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        (e, w) = _epoch(vid, ids[0], 2, 2, e1, _admins(), new IPqChat.MemberKey[](0));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultShape.selector)); // at least one member
        (e, w) = _epoch(vid, ids[0], 2, 2, e1, _admins(), _members(1));
        _rekey(vault, e, w, 0); // the control: one member
    }

    // ----- replicas (mode 0) -----

    /// The same records in instance B: every complete child lands, `childOf` reads 0, in any order; at home the second is
    /// refused.
    function test_replica_storesEveryChild() public {
        (IPqVault.PqVaultCreate memory v0, IPqChat.Wrap[] memory vw) = _vault(3, 1, 0, address(vault));
        vaultB.createVault(v0, vw, _createSig(v0, address(vault)));
        (IPqVault.PqVaultEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _without(_members(3), ids[2]));
        (IPqVault.PqVaultEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(vid, ids[0], 2, 1, vid, _admins(), _members(3));
        bytes32 ea = _rekey(vault, a, aw, 0);
        IUARegistry.UASig memory bs = _sig(b.author, h.epoch(b, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultEpochTaken.selector, vid, ea));
        vault.rekeyVault(b, bw, bs);
        bytes32 eb = vaultB.rekeyVault(b, bw, bs);
        assertEq(_rekey(vaultB, a, aw, 0), ea);
        assertTrue(vaultB.epochComplete(ea) && vaultB.epochComplete(eb));
        assertEq(vaultB.childOf(vid), bytes32(0));
        assertEq(vault.childOf(vid), ea);
    }

    // ----- leavers; no admin left (O4) -----

    /// Dropping a member that left is an admin's rekey; a member that left authors nothing.
    function test_leave_thenAdminDrops() public {
        _leave(vault, vid, ids[2], 1);
        assertTrue(vault.leftIn(vid, ids[2]));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[2], 2, 1, vid, _admins(), _without(_members(3), ids[2]));
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[2]));
        (e, w) = _epoch(vid, ids[0], 1, 1, vid, _admins(), _without(_members(3), ids[2]));
        bytes32 eid = _rekey(vault, e, w, 0);
        assertEq(vault.childOf(vid), eid);
    }

    /// O4: the only admin left; nobody can rekey (membership and keys frozen).
    /// Fable code review F7 (controller call 2026-11-21, as O3 (b)): the only admin leaves; its own rekey and its own removal
    /// are refused `PqVaultNotAdmin`, so membership and keys are frozen. The control runs the same calls before the leave.
    function test_leftAdminNeitherRekeysNorRemoves() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _without(_members(3), ids[2]));
        IPqVault.PqVaultRemove memory r = _rm(vid, 1, _list(ids[2]), ids[0], 2);
        uint256 snap = vm.snapshotState();
        _rekey(vault, e, w, 0); // the control: before the leave
        vm.revertToState(snap);
        _remove(vault, r); // the control: before the leave
        vm.revertToState(snap);
        _leave(vault, vid, ids[0], 3);
        _refusedRekey(e, w, abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[0]));
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[0]));
    }

    /// Fable code review F1 (P1): admin `ids[1]` stages a child of `e1` that leaves itself out (incomplete), then `ids[0]` removes
    /// it; the staged child can no longer complete (`PqVaultRemovedKept(e1, ids[1])`: its author is removed from the parent),
    /// and the slot stays free for `ids[0]`'s rekey. The control: the same staged child completes when nobody removed its author.
    function test_removedAuthorsStagedChildCannotComplete() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0], ids[1]), _members(3));
        bytes32 e1 = _rekey(vault, e, w, 0); // ids[1] made an admin
        (IPqVault.PqVaultEpoch memory c, IPqChat.Wrap[] memory cw) =
            _epoch(vid, ids[1], 2, 2, e1, _list(ids[3]), _without(_members(4), ids[1]));
        bytes32 staged = vault.rekeyVault(c, _slice(cw, 0, 1), _sig(c.author, h.epoch(c, PqVaultTypes.DS_V)));
        IPqChat.Wrap[] memory rest = _slice(cw, 1, 3);
        uint256 snap = vm.snapshotState();
        vault.addVaultWraps(staged, 1, rest); // the control: not removed, it completes
        assertEq(vault.childOf(e1), staged);
        vm.revertToState(snap);
        _remove(vault, _rm(e1, 2, _list(ids[1]), ids[0], 3));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultRemovedKept.selector, e1, ids[1]));
        vault.addVaultWraps(staged, 1, rest);
        assertEq(vault.childOf(e1), bytes32(0));
        (e, w) = _epoch(vid, ids[0], 4, 2, e1, _admins(), _without(_members(3), ids[1]));
        assertEq(vault.childOf(e1), bytes32(0));
        _rekey(vault, e, w, 0);
    }

    /// Fable code review F2: once removed, an admin removes nobody (`PqVaultNotAdmin`); the remaining admin still does.
    function test_removedAdminRemovesNobody() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0], ids[1]), _members(3));
        bytes32 e1 = _rekey(vault, e, w, 0);
        _remove(vault, _rm(e1, 2, _list(ids[1]), ids[0], 2));
        _refusedRemove(
            _rm(e1, 2, _list(ids[0]), ids[1], 3),
            ids[1],
            abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[1])
        );
        _remove(vault, _rm(e1, 2, _list(ids[2]), ids[0], 4)); // the control
    }

    /// Fable code review F3: an admin that is no member (an `msig`, which holds no KEM key) is removable, and a child keeping it
    /// as an admin is then `PqVaultRemovedKept`; the child without it lands.
    function test_adminOnlyMsigRemovable() public {
        bytes32 ms = _nativeMsig();
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 7, 0, address(vault));
        v.admins = _list(ms, ids[0]);
        bytes32 v2 = _create(vault, v, w);
        IPqVault.PqVaultRemove memory r = IPqVault.PqVaultRemove(v2, v2, 1, _list(ms), ids[0], 1);
        vault.removeVaultMembers(r, _sig(ids[0], h.remove(r, PqVaultTypes.DS_V)));
        assertTrue(vault.removedIn(v2, ms));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(v2, ids[0], 2, 1, v2, v.admins, _members(3));
        _refusedRekey(e, ew, abi.encodeWithSelector(IPqVault.PqVaultRemovedKept.selector, v2, ms));
        (e, ew) = _epoch(v2, ids[0], 3, 1, v2, _admins(), _members(3));
        _rekey(vault, e, ew, 0); // the control
    }

    function test_leave_rules() public {
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, vid, ids[3], 1);
        IUARegistry.UASig memory sig = _sig(ids[3], h.leave(l, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ids[3]));
        vault.leaveVault(l, sig);
        l = IPqVault.PqVaultLeave(vid, vid, ids[2], 1);
        sig = _sig(ids[1], h.leave(l, PqVaultTypes.DS_V));
        vm.expectRevert(_unauthorized(ids[2]));
        vault.leaveVault(l, sig);
        assertFalse(vault.nonceUsed(PqVaultTypes.scopeEpoch(vid, ids[2]), 1));
        l = IPqVault.PqVaultLeave(keccak256("x"), vid, ids[2], 1);
        sig = _sig(ids[2], h.leave(l, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid));
        vault.leaveVault(l, sig); // the record names another vault than its epoch's
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultLeft(vid, vid, ids[2]);
        _leave(vault, vid, ids[2], 1);
        assertTrue(vault.leftIn(vid, ids[2]));
        l = IPqVault.PqVaultLeave(vid, vid, ids[2], 1);
        sig = _sig(ids[2], h.leave(l, PqVaultTypes.DS_V));
        // a repeated leave: the member is flagged there already (sc-E-5, before the nonce)
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ids[2]));
        vault.leaveVault(l, sig);
    }

    // ----- an msig admin (a derived quorum) -----

    function test_msigAdminSignsByQuorum() public {
        bytes32 ms = _nativeMsig();
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 4, 0, address(vault));
        v.admins = _list(ms, ids[0]);
        bytes32 vid2 = _create(vault, v, w);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(vid2, ms, 1, 1, vid2, v.admins, _without(_members(3), ids[2]));
        IUARegistry.UASig memory bad = _nativeMsigSig(ms, h.epoch(e, PqVaultTypes.DS_V), 1); // the mode-1 form
        vm.expectRevert(_unauthorized(ms));
        vault.rekeyVault(e, ew, bad);
        vault.rekeyVault(e, ew, _nativeMsigSig(ms, h.epoch(e, PqVaultTypes.DS_V), 0));
        assertTrue(vault.epochComplete(PqVaultTypes.epochId(vid2, ms, 1)));
    }

    /// `updateMsig` of the 1-of-1 native `msig` to its own structure, the next version (the EOA signs the update digest).
    function _bump(bytes32 ms) internal {
        (uint64 v, uint256 en,) = p.msigStateOf(ms);
        IUARegistry.MsigStructure memory st = p.msigOf(ms);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](1);
        bytes32 typed = UAKinds.msigUpdateDigest(ms, chainUidA, address(p), v + 1, st, en, uint64(block.number + 100));
        s[0] = IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), _ecdsa(EOA_SK, typed));
        _send(ms, v + 1, st, en, s);
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

    /// A-1 of the Fable fix check (CTR-UA-74, CTR-PQV-14; controller call 2026-11-26): PqChat's replica copy of an `msig` admin's
    /// mode-0 epoch after `updateMsig` (one registry under both instances): the home's bytes `UAUnauthorized` in the replica, the
    /// replica's tag lands and is kept; A-2: a new record names version 1, the empty tag refused.
    function test_a1_replicaCopyCarriesTheReplicaTag() public {
        bytes32 ms = _nativeMsig();
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 4, 0, address(vault));
        v.admins = _list(ms, ids[0]);
        bytes32 vid2 = _create(vault, v, w);
        vaultB.createVault(v, w, _createSig(v, address(vault)));
        _a2Next(ms, vid2, _a1Copy(ms, vid2, v.admins), v.admins);
    }

    function _a2Next(bytes32 ms, bytes32 vid2, bytes32 e1, bytes32[] memory admins) internal {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(vid2, ms, 2, 2, e1, admins, _without(_members(3), ids[2]));
        IUARegistry.UASig memory n = _nativeMsigSig(ms, h.epoch(e, PqVaultTypes.DS_V), 0);
        vm.expectRevert(_unauthorized(ms));
        vault.rekeyVault(e, ew, n);
        n.signature = abi.encodePacked(uint64(1));
        vault.rekeyVault(e, ew, n);
        assertTrue(vault.epochComplete(PqVaultTypes.epochId(vid2, ms, 2)));
    }

    function _a1Copy(bytes32 ms, bytes32 vid2, bytes32[] memory admins) internal returns (bytes32 e1) {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) =
            _epoch(vid2, ms, 1, 1, vid2, admins, _without(_members(3), ids[2]));
        IUARegistry.UASig memory v0 = _nativeMsigSig(ms, h.epoch(e, PqVaultTypes.DS_V), 0);
        e1 = vault.rekeyVault(e, ew, v0);
        _bump(ms);
        vm.expectRevert(_unauthorized(ms));
        vaultB.rekeyVault(e, ew, v0); // the home's bytes: the tag of version 0
        IUARegistry.UASig memory v1 = _nativeMsigSig(ms, h.epoch(e, PqVaultTypes.DS_V), 0);
        v1.signature = abi.encodePacked(uint64(1));
        assertEq(vaultB.rekeyVault(e, ew, v1), e1);
        assertEq(_raw(address(vault), abi.encodeCall(IPqVault.epochOf, (e1))), abi.encode(e, v0));
        assertEq(
            _raw(address(vaultB), abi.encodeCall(IPqVault.epochOf, (e1))),
            abi.encode(e, v1),
            "the replica keeps its own tag"
        );
    }

    // ----- E-3 (CTR-PQV-06 with CTR-CHAT-10 / -20; Change 2026-11-24; owner: "Yes, both modes") -----

    function _plain(PqVault c, uint64 n, uint64 number, bytes32 parent, IPqChat.MemberKey[] memory m)
        internal
        returns (bytes32)
    {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(vid, ids[0], n, number, parent, _admins(), m);
        return _rekey(c, e, w, 0);
    }

    /// At home exits naming epoch 0 after an admin rekey took its slot land at the head; the lag refuses at 17 above.
    function test_e3_exitsApplyAtTheHeadWithinTheLag() public {
        bytes32 e1 = _plain(vault, 1, 1, vid, _members(3)); // the front-running admin rekey
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultLeft(vid, e1, ids[1]); // A-14: the head's id
        _leave(vault, vid, ids[1], 1);
        assertTrue(vault.leftIn(e1, ids[1]), "at the head");
        assertFalse(vault.leftIn(vid, ids[1]));
        IPqVault.PqVaultRemove memory r = _rm(vid, 1, _list(ids[2]), ids[0], 50);
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultRemoved(vid, e1, ids[0], _list(ids[2])); // A-14: the head's id
        _remove(vault, r);
        assertTrue(vault.removedIn(e1, ids[2]), "at the head");
        assertFalse(vault.removedIn(vid, ids[2]));
        assertEq(vault.removalCount(e1), 1);
        IPqChat.MemberKey[] memory two = _without(_members(3), ids[2]); // P48: e1's child drops the removed UA
        bytes32 p = e1;
        for (uint64 i = 2; i <= 17; ++i) {
            p = _plain(vault, i, i, p, two); // ids[1], the leaver, kept: the admin's choice
        }
        r = _rm(vid, 1, _list(ids[1]), ids[0], 51);
        _refusedRemove(r, ids[0], abi.encodeWithSelector(IPqVault.PqVaultExitLag.selector, uint64(0), uint64(17)));
        (r.epochId, r.nextEpoch) = (e1, 2); // the control: one epoch younger
        _remove(vault, r);
        assertTrue(vault.removedIn(p, ids[1]));
    }

    /// The replica rule (sc-E-4): an admin flagged as removed in a replica still rekeys there; at home it is
    /// `PqVaultNotAdmin`.
    function test_replica_removalFlagRefusesNoAdmin() public {
        (IPqVault.PqVaultCreate memory v0, IPqChat.Wrap[] memory vw) = _vault(3, 1, 0, address(vault));
        vaultB.createVault(v0, vw, _createSig(v0, address(vault)));
        IPqVault.PqVaultRemove memory r = _rm(vid, 1, _list(ids[0]), ids[0], 7); // a removal may name its signer
        _remove(vault, r);
        _remove(vaultB, r);
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        IUARegistry.UASig memory es = _sig(e.author, h.epoch(e, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[0]));
        vault.rekeyVault(e, w, es); // at home
        bytes32 eid = vaultB.rekeyVault(e, w, es);
        assertTrue(vaultB.epochComplete(eid), "a replica stores it");
    }

    // ----- E-2, A-16 (controller call 2026-11-25): a replica copies every exit the home took -----

    /// The replica of `vid` in `vaultB`, and e1 (by the admin: `ids[1]` made an admin, `ids[3]` added) at home and there.
    function _replicaE1Grows() internal returns (bytes32 e1) {
        (IPqVault.PqVaultCreate memory v0, IPqChat.Wrap[] memory vw) = _vault(3, 1, 0, address(vault));
        vaultB.createVault(v0, vw, _createSig(v0, address(vault)));
        (IPqVault.PqVaultEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0], ids[1]), _members(4));
        e1 = _rekey(vault, a, aw, 0);
        assertEq(_rekey(vaultB, a, aw, 0), e1);
    }

    /// E-2: a leave naming epoch 0 by `ids[3]` (added at e1), a removal naming epoch 0 by `ids[1]` (an admin of e1 only) and
    /// one naming `ids[3]` are refused at home, as a replica would refuse them. The controls name e1 and land in both.
    function test_e2_exitsNameAnEpochTheirUAsAreIn() public {
        bytes32 e1 = _replicaE1Grows();
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, vid, ids[3], 1);
        IUARegistry.UASig memory ls = _sig(ids[3], h.leave(l, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ids[3]));
        vault.leaveVault(l, ls);
        _refusedRemove(
            _rm(vid, 1, _list(ids[2]), ids[1], 1),
            ids[1],
            abi.encodeWithSelector(IPqVault.PqVaultNotAdmin.selector, ids[1])
        );
        _refusedRemove(
            _rm(vid, 1, _list(ids[3]), ids[0], 5),
            ids[0],
            abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ids[3])
        );
        l.epochId = e1; // the controls
        ls = _sig(ids[3], h.leave(l, PqVaultTypes.DS_V));
        vault.leaveVault(l, ls);
        vaultB.leaveVault(l, ls);
        IPqVault.PqVaultRemove memory r = _rm(e1, 2, _list(ids[2]), ids[1], 1);
        _remove(vault, r);
        _remove(vaultB, r);
        assertTrue(vaultB.leftIn(e1, ids[3]) && vaultB.removedIn(e1, ids[2]));
    }

    /// A-16: a second leave of `ids[2]` naming epoch 0 (applied at the head e1, which kept the leaver) and a second removal of
    /// `ids[1]` naming epoch 0 (after e1 dropped it and e2 added it again) are taken in a replica too, which flags nobody new.
    function test_a16_replicaTakesRepeatsNamingOneEpoch() public {
        (IPqVault.PqVaultCreate memory v0, IPqChat.Wrap[] memory vw) = _vault(3, 1, 0, address(vault));
        vaultB.createVault(v0, vw, _createSig(v0, address(vault)));
        IPqVault.PqVaultLeave memory l1 = IPqVault.PqVaultLeave(vid, vid, ids[2], 1);
        IUARegistry.UASig memory s1 = _sig(ids[2], h.leave(l1, PqVaultTypes.DS_V));
        vault.leaveVault(l1, s1);
        IPqVault.PqVaultRemove memory r1 = _rm(vid, 1, _list(ids[1]), ids[0], 10);
        _remove(vault, r1);
        (IPqVault.PqVaultEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _without(_members(3), ids[1]));
        bytes32 e1 = _rekey(vault, a, aw, 0); // drops the removed UA, keeps the leaver
        (IPqVault.PqVaultEpoch memory b, IPqChat.Wrap[] memory bw) =
            _epoch(vid, ids[0], 2, 2, e1, _admins(), _members(3));
        bytes32 e2 = _rekey(vault, b, bw, 0); // adds it again
        IPqVault.PqVaultLeave memory l2 = IPqVault.PqVaultLeave(vid, vid, ids[2], 2);
        IUARegistry.UASig memory s2 = _sig(ids[2], h.leave(l2, PqVaultTypes.DS_V));
        vault.leaveVault(l2, s2);
        IPqVault.PqVaultRemove memory r2 = _rm(vid, 1, _list(ids[1]), ids[0], 11);
        _remove(vault, r2);
        assertTrue(vault.leftIn(e2, ids[2]) && vault.removedIn(e2, ids[1]));
        vaultB.leaveVault(l1, s1);
        _remove(vaultB, r1);
        assertEq(_rekey(vaultB, a, aw, 0), e1);
        assertEq(_rekey(vaultB, b, bw, 0), e2);
        vaultB.leaveVault(l2, s2);
        _remove(vaultB, r2);
        assertEq(vaultB.removalCount(vid), 2, "both records, under the epoch named");
    }

    // ----- A-14 (the re-review of 2026-11-25): the flags read at home, a replica's named epoch complete -----

    /// A member removed at the head leaves no more; another member's leave of the same head lands (the control).
    function test_a14_removedAtTheHeadLeavesNoMore() public {
        _remove(vault, _rm(vid, 1, _list(ids[2]), ids[0], 7));
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, vid, ids[2], 1);
        IUARegistry.UASig memory ls = _sig(ids[2], h.leave(l, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ids[2]));
        vault.leaveVault(l, ls);
        _leave(vault, vid, ids[1], 1);
        assertTrue(vault.leftIn(vid, ids[1]));
    }

    /// In a replica a removal naming a staged epoch is `PqVaultIncomplete`; naming its complete parent it lands.
    function test_a14_replicaRemovalNamingAStagedEpoch() public {
        (IPqVault.PqVaultCreate memory v0, IPqChat.Wrap[] memory vw) = _vault(3, 1, 0, address(vault));
        vaultB.createVault(v0, vw, _createSig(v0, address(vault)));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        bytes32 staged = vaultB.rekeyVault(e, _slice(w, 0, 1), _sig(e.author, h.epoch(e, PqVaultTypes.DS_V)));
        assertFalse(vaultB.epochComplete(staged));
        IPqVault.PqVaultRemove memory r = _rm(staged, 2, _list(ids[2]), ids[0], 7);
        IUARegistry.UASig memory rs = _sig(ids[0], h.remove(r, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultIncomplete.selector, staged));
        vaultB.removeVaultMembers(r, rs);
        _remove(vaultB, _rm(vid, 1, _list(ids[2]), ids[0], 7)); // the control
        assertTrue(vaultB.removedIn(vid, ids[2]));
    }

    /// A-15 (controller call 2026-11-25, as C40): an empty `addVaultWraps` on a staged epoch or on the complete vault epoch
    /// is `PqVaultShape`; the control lands the staged epoch's remaining wraps.
    function test_a15_emptyAddVaultWrapsRefused() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _admins(), _members(3));
        bytes32 staged = vault.rekeyVault(e, _slice(w, 0, 1), _sig(e.author, h.epoch(e, PqVaultTypes.DS_V)));
        vm.expectRevert(IPqVault.PqVaultShape.selector);
        vault.addVaultWraps(staged, 1, new IPqChat.Wrap[](0));
        vm.expectRevert(IPqVault.PqVaultShape.selector);
        vault.addVaultWraps(vid, 0, new IPqChat.Wrap[](0));
        vault.addVaultWraps(staged, 1, _slice(w, 1, 3)); // the control
        assertTrue(vault.epochComplete(staged));
    }
}
