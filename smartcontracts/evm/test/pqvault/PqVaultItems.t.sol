// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVault} from "../../src/pqvault/PqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V4 (spec §5.6, §5.7, §11; CTR-PQV-07, CTR-PQV-08, CTR-PQV-14): items and versions. A vault of three members in
/// mode 0, `ids[0]` its creator and only admin. Every refusal beside its positive control, one change at a time.
contract PqVaultItemsTest is PqVaultBase {
    bytes32 internal vid;

    function setUp() public override {
        super.setUp();
        (vid,) = _newVault(3, 0);
    }

    function _ct(uint256 n, uint8 seed) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) {
            c[i] = bytes1(uint8(i) ^ seed);
        }
    }

    function _it(bytes32 epochId, bytes32 author, uint64 nonce, uint256 len)
        internal
        view
        returns (IPqVault.PqVaultItem memory)
    {
        return IPqVault.PqVaultItem(vid, epochId, author, nonce, _ct(len, uint8(nonce)));
    }

    function _create(PqVault c, IPqVault.PqVaultItem memory it) internal returns (bytes32) {
        return c.createItem(it, _sig(it.author, h.item(it, PqVaultTypes.DS_V)));
    }

    function _createRefused(IPqVault.PqVaultItem memory it, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(it.author, h.item(it, PqVaultTypes.DS_V));
        vm.expectRevert(err);
        vault.createItem(it, sig);
    }

    function _ed(bytes32 iid, bytes32 epochId, bytes32 author, uint64 nonce, uint32 version)
        internal
        pure
        returns (IPqVault.PqVaultEdit memory)
    {
        return IPqVault.PqVaultEdit(iid, epochId, author, nonce, version, _ct(288, uint8(nonce) ^ 0x55));
    }

    function _edit(IPqVault.PqVaultEdit memory d) internal {
        vault.editItem(d, _sig(d.author, h.edit(d, PqVaultTypes.DS_V)));
    }

    function _editRefused(IPqVault.PqVaultEdit memory d, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(d.author, h.edit(d, PqVaultTypes.DS_V));
        vm.expectRevert(err);
        vault.editItem(d, sig);
    }

    function _one(bytes32 epochId, bytes32 author, uint64 nonce)
        internal
        view
        returns (IPqVault.PqVaultBatch memory b)
    {
        b = IPqVault.PqVaultBatch(vid, epochId, author, nonce, new IPqVault.PqVaultItem[](1));
        b.items[0] = _it(epochId, author, nonce + 1, 288);
    }

    function _batchRefused(IPqVault.PqVaultBatch memory b, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(b.author, h.batch(b, PqVaultTypes.DS_V));
        vm.expectRevert(err);
        vault.createItems(b, sig);
    }

    function _notMember(bytes32 ua) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IPqVault.PqVaultNotMember.selector, ua);
    }

    // ----- create and read back -----

    /// A member who is not the creator writes version 1: the blob, the list, the nonce, the event with the signature.
    function test_createItem() public {
        IPqVault.PqVaultItem memory it = _it(vid, ids[1], 7, 288);
        bytes32 iid = PqVaultTypes.itemId(vid, ids[1], 7);
        IUARegistry.UASig memory sig = _sig(it.author, h.item(it, PqVaultTypes.DS_V));
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultItemCreated(vid, iid, ids[1], 0, sig);
        vm.prank(STRANGER);
        assertEq(vault.createItem(it, sig), iid);
        assertEq(vault.itemCount(vid), 1);
        IPqVault.ItemView memory v = vault.itemOf(iid);
        assertEq(v.vaultId, vid);
        assertEq(v.versionCount, 1);
        assertEq(v.batchId, bytes32(0));
        IPqVault.VersionView memory w = vault.versionAt(iid, 1);
        assertEq(w.epochId, vid);
        assertEq(w.author, ids[1]);
        assertEq(w.nonce, 7);
        assertEq(w.version, 1);
        assertEq(w.ciphertext, it.ciphertext);
        assertEq(w.sigHash, keccak256(abi.encode(sig)));
        assertTrue(vault.nonceUsed(PqVaultTypes.scopeItem(vid, ids[1]), 7));
        _createRefused(
            it,
            abi.encodeWithSelector(IPqVault.PqVaultNonceUsed.selector, PqVaultTypes.scopeItem(vid, ids[1]), uint64(7))
        );
    }

    /// Any member edits (not only the creator); every version stays; the event carries the signature.
    function test_editItem_byAnotherMember() public {
        bytes32 iid = _create(vault, _it(vid, ids[1], 7, 288));
        IPqVault.PqVaultEdit memory d = _ed(iid, vid, ids[2], 1, 2);
        IUARegistry.UASig memory sig = _sig(d.author, h.edit(d, PqVaultTypes.DS_V));
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultItemEdited(iid, 2, ids[2], sig);
        vault.editItem(d, sig);
        assertEq(vault.itemOf(iid).versionCount, 2);
        IPqVault.VersionView memory w = vault.versionAt(iid, 2);
        assertEq(w.author, ids[2]);
        assertEq(w.version, 2);
        assertEq(w.ciphertext, d.ciphertext);
        assertEq(w.sigHash, keccak256(abi.encode(sig)));
        assertEq(vault.versionAt(iid, 1).author, ids[1], "version 1 stays");
        assertTrue(vault.nonceUsed(PqVaultTypes.scopeItem(vid, ids[2]), 1));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultVersion.selector, uint32(2), uint32(3)));
        vault.versionAt(iid, 3);
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultVersion.selector, uint32(2), uint32(0)));
        vault.versionAt(iid, 0);
    }

    /// Two writers of version 2 race: the first lands, the second is refused `PqVaultVersion(3, 2)` (the conflict signal); a
    /// skipped number too; the merged version 3 lands.
    function test_versionRace() public {
        bytes32 iid = _create(vault, _it(vid, ids[1], 7, 288));
        _edit(_ed(iid, vid, ids[1], 8, 2));
        _editRefused(
            _ed(iid, vid, ids[2], 1, 2), abi.encodeWithSelector(IPqVault.PqVaultVersion.selector, uint32(3), uint32(2))
        );
        _editRefused(
            _ed(iid, vid, ids[2], 1, 4), abi.encodeWithSelector(IPqVault.PqVaultVersion.selector, uint32(3), uint32(4))
        );
        _edit(_ed(iid, vid, ids[2], 1, 3));
        assertEq(vault.itemOf(iid).versionCount, 3);
    }

    // ----- write rights (CTR-PQV-07, CTR-PQV-14, O3 (b)) -----

    /// A removed member writes nothing under the epoch it was removed from, in each of the three writes; a kept member does.
    function test_removedMemberRefusedInEachWrite() public {
        bytes32 iid = _create(vault, _it(vid, ids[1], 7, 288));
        IPqVault.PqVaultRemove memory r = IPqVault.PqVaultRemove(vid, vid, 1, _list(ids[2]), ids[0], 1);
        vault.removeVaultMembers(r, _sig(ids[0], h.remove(r, PqVaultTypes.DS_V)));
        _createRefused(_it(vid, ids[2], 1, 288), _notMember(ids[2]));
        _editRefused(_ed(iid, vid, ids[2], 2, 2), _notMember(ids[2]));
        _batchRefused(_one(vid, ids[2], 3), _notMember(ids[2]));
        _create(vault, _it(vid, ids[1], 1, 288)); // the controls
        _edit(_ed(iid, vid, ids[1], 2, 2));
        IPqVault.PqVaultBatch memory b = _one(vid, ids[1], 3);
        vault.createItems(b, _sig(b.author, h.batch(b, PqVaultTypes.DS_V)));
    }

    /// T11 (C9, CTR-PQV-06, E-3): a removal naming the parent of the head applies at the head, so the removed member's item
    /// write under the head is `PqVaultNotMember`; a kept member's lands there.
    function test_e3_removedAtTheHeadWritesNothing() public {
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0]), _members(3));
        bytes32 e1 = _rekey(vault, e, w, 0); // the head
        IPqVault.PqVaultRemove memory r = IPqVault.PqVaultRemove(vid, vid, 1, _list(ids[2]), ids[0], 2);
        vault.removeVaultMembers(r, _sig(ids[0], h.remove(r, PqVaultTypes.DS_V))); // names the parent
        _createRefused(_it(e1, ids[2], 1, 288), _notMember(ids[2]));
        _create(vault, _it(e1, ids[1], 1, 288)); // the control
    }

    /// O3 (b): a member that left writes nothing under the epoch it left, in each of the three writes.
    function test_leaverRefusedInEachWrite() public {
        bytes32 iid = _create(vault, _it(vid, ids[1], 7, 288));
        IPqVault.PqVaultLeave memory l = IPqVault.PqVaultLeave(vid, vid, ids[2], 1);
        vault.leaveVault(l, _sig(ids[2], h.leave(l, PqVaultTypes.DS_V)));
        _createRefused(_it(vid, ids[2], 1, 288), _notMember(ids[2]));
        _editRefused(_ed(iid, vid, ids[2], 2, 2), _notMember(ids[2]));
        _batchRefused(_one(vid, ids[2], 3), _notMember(ids[2]));
        _create(vault, _it(vid, ids[1], 1, 288)); // the control
    }

    function test_notAMemberRefused() public {
        _createRefused(_it(vid, ids[3], 1, 288), _notMember(ids[3]));
        _createRefused(
            _it(vid, bytes32(uint256(uint160(address(0xBEEF)))), 1, 288), _notMember(bytes32(uint256(0xBEEF)))
        );
        _create(vault, _it(vid, ids[2], 1, 288));
    }

    /// An old epoch is refused at home once a child completes (`PqVaultEpochTaken`, apart from the rekey's own check) and
    /// taken in a replica, which orders nothing.
    function test_oldEpochRefusedAtHomeTakenInReplica() public {
        (IPqVault.PqVaultCreate memory v0, IPqChat.Wrap[] memory w0) = _vault(3, 1, 0, address(vault));
        vaultB.createVault(v0, w0, _createSig(v0, address(vault)));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0]), _members(3));
        bytes32 e1 = _rekey(vault, e, w, 0);
        _rekey(vaultB, e, w, 0);
        IPqVault.PqVaultItem memory it = _it(vid, ids[1], 7, 288);
        _createRefused(it, abi.encodeWithSelector(IPqVault.PqVaultEpochTaken.selector, vid, e1));
        _create(vaultB, it); // the replica takes it
        _create(vault, _it(e1, ids[1], 7, 288)); // the control: the new epoch at home
    }

    function test_epochRules() public {
        bytes32 x = keccak256("x");
        _createRefused(_it(x, ids[1], 1, 288), abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, x));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory w) =
            _epoch(vid, ids[0], 1, 1, vid, _list(ids[0]), _members(3));
        bytes32 e1 = vault.rekeyVault(e, _slice(w, 0, 1), _sig(e.author, h.epoch(e, PqVaultTypes.DS_V)));
        _createRefused(_it(e1, ids[1], 1, 288), abi.encodeWithSelector(IPqVault.PqVaultIncomplete.selector, e1));
        vault.addVaultWraps(e1, 1, _slice(w, 1, 3));
        _create(vault, _it(e1, ids[1], 1, 288));
    }

    function test_editRules() public {
        bytes32 x = keccak256("unknown item");
        _editRefused(_ed(x, vid, ids[1], 1, 2), abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, x));
        bytes32 iid = _create(vault, _it(vid, ids[1], 7, 288));
        // an epoch of another vault (the item's vault is read from its version-1 blob)
        (IPqVault.PqVaultCreate memory v2, IPqChat.Wrap[] memory w2) = _vault(3, 2, 0, address(vault));
        bytes32 vid2 = _create(vault, v2, w2);
        _editRefused(_ed(iid, vid2, ids[1], 1, 2), abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid2));
        _edit(_ed(iid, vid, ids[1], 1, 2)); // the control
    }

    /// Review r2 R11: an item record naming a vault other than its stored epoch's.
    function test_recordVaultMustMatchItsEpoch() public {
        (IPqVault.PqVaultCreate memory v2, IPqChat.Wrap[] memory w2) = _vault(3, 2, 0, address(vault));
        bytes32 vid2 = _create(vault, v2, w2);
        IPqVault.PqVaultItem memory it = _it(vid2, ids[1], 1, 288); // vaultId = vid, epoch of vid2
        _createRefused(it, abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid2));
        IPqVault.PqVaultBatch memory b = _one(vid2, ids[1], 3);
        _batchRefused(b, abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, vid2));
        it.vaultId = vid2;
        vault.createItem(it, _sig(it.author, h.item(it, PqVaultTypes.DS_V))); // the control
    }

    /// VC9: 31 and 16,417 B refused, 32 and 16,416 B accepted, in createItem and editItem.
    function test_ciphertextBounds() public {
        bytes memory shape = abi.encodeWithSelector(IPqVault.PqVaultShape.selector);
        _createRefused(_it(vid, ids[1], 1, 31), shape);
        _createRefused(_it(vid, ids[1], 1, 16_417), shape);
        bytes32 iid = _create(vault, _it(vid, ids[1], 1, 32));
        _create(vault, _it(vid, ids[1], 2, 16_416));
        IPqVault.PqVaultEdit memory d = _ed(iid, vid, ids[1], 3, 2);
        d.ciphertext = _ct(31, 1);
        _editRefused(d, shape);
        d.ciphertext = _ct(16_417, 1);
        _editRefused(d, shape);
        d.ciphertext = _ct(16_416, 1);
        _edit(d);
    }

    /// A forged item burns no nonce; a `PURPOSE_PQCHAT` signature is no PqVault signature.
    function test_signatureRules() public {
        IPqVault.PqVaultItem memory it = _it(vid, ids[1], 1, 288);
        IUARegistry.UASig memory bad = _sig(ids[2], h.item(it, PqVaultTypes.DS_V));
        vm.expectRevert(_unauthorized(ids[1]));
        vault.createItem(it, bad);
        assertFalse(vault.nonceUsed(PqVaultTypes.scopeItem(vid, ids[1]), 1));
        bad.signature =
            _sig(keyOf_[ids[1]], UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQCHAT, h.item(it, PqVaultTypes.DS_V)));
        vm.expectRevert(_unauthorized(ids[1]));
        vault.createItem(it, bad);
        _create(vault, it);
    }
}
