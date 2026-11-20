// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V4 (spec §5.8, CTR-PQV-09): `createItems`, one signature over the whole list. Field mixing, a nonce reused inside
/// a batch, each item nonce marked, the header rebuilt from state equals the signed digest. Every refusal beside its control.
contract PqVaultBatchTest is PqVaultBase {
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

    /// `n` password-sized items of `ids[1]` under epoch 0, nonces `nonce + 1 ..`.
    function _batch(uint64 nonce, uint256 n) internal view returns (IPqVault.PqVaultBatch memory b) {
        b = IPqVault.PqVaultBatch(vid, vid, ids[1], nonce, new IPqVault.PqVaultItem[](n));
        for (uint256 i; i < n; ++i) {
            uint64 k = nonce + 1 + uint64(i);
            b.items[i] = IPqVault.PqVaultItem(vid, vid, ids[1], k, _ct(288, uint8(k)));
        }
    }

    function _refused(IPqVault.PqVaultBatch memory b, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(b.author, h.batch(b, PqVaultTypes.DS_V));
        vm.expectRevert(err);
        vault.createItems(b, sig);
    }

    function test_createItems() public {
        IPqVault.PqVaultBatch memory b = _batch(10, 3);
        bytes32 bid = PqVaultTypes.batchId(vid, ids[1], 10);
        IUARegistry.UASig memory sig = _sig(b.author, h.batch(b, PqVaultTypes.DS_V));
        IUARegistry.UASig memory none;
        for (uint256 i; i < 3; ++i) {
            vm.expectEmit(address(vault));
            emit IPqVault.PqVaultItemCreated(vid, PqVaultTypes.itemId(vid, ids[1], uint64(11 + i)), ids[1], bid, none);
        }
        vm.expectEmit(address(vault));
        emit IPqVault.PqVaultBatchCreated(vid, bid, ids[1], 3, sig);
        vm.prank(STRANGER);
        assertEq(vault.createItems(b, sig), bid);
        assertEq(vault.itemCount(vid), 3);
        bytes32 scope = PqVaultTypes.scopeItem(vid, ids[1]);
        assertTrue(vault.nonceUsed(scope, 10), "the batch nonce");
        for (uint64 k = 11; k <= 13; ++k) {
            assertTrue(vault.nonceUsed(scope, k), "each item nonce");
            bytes32 iid = PqVaultTypes.itemId(vid, ids[1], k);
            IPqVault.ItemView memory v = vault.itemOf(iid);
            assertEq(v.batchId, bid);
            assertEq(v.versionCount, 1);
            assertEq(vault.versionAt(iid, 1).sigHash, keccak256(abi.encode(sig)));
        }
        // the header rebuilt from state equals the signed record
        (bytes32 hv, bytes32 he, bytes32 ha, uint64 hn, bytes32[] memory iids, bytes32 sh) = vault.batchOf(bid);
        assertEq(sh, keccak256(abi.encode(sig)));
        IPqVault.PqVaultBatch memory r = IPqVault.PqVaultBatch(hv, he, ha, hn, new IPqVault.PqVaultItem[](iids.length));
        for (uint256 i; i < iids.length; ++i) {
            IPqVault.VersionView memory w = vault.versionAt(iids[i], 1);
            r.items[i] = IPqVault.PqVaultItem(hv, w.epochId, w.author, w.nonce, w.ciphertext);
        }
        assertEq(h.batch(r, PqVaultTypes.DS_V), h.batch(b, PqVaultTypes.DS_V));
        vm.expectRevert(abi.encodeWithSelector(IPqVault.PqVaultUnknown.selector, keccak256("x")));
        vault.batchOf(keccak256("x"));
        _refused(b, abi.encodeWithSelector(IPqVault.PqVaultNonceUsed.selector, scope, uint64(10)));
    }

    /// Every item's vault, epoch and author equal the batch's: each changed alone is `PqVaultShape`; an empty list too.
    function test_mixedFieldsRefused() public {
        bytes memory shape = abi.encodeWithSelector(IPqVault.PqVaultShape.selector);
        (IPqVault.PqVaultCreate memory v2,) = _vault(3, 2, 0, address(vault));
        for (uint256 k; k < 3; ++k) {
            IPqVault.PqVaultBatch memory b = _batch(10, 2);
            if (k == 0) b.items[1].vaultId = PqVaultTypes.vaultId(v2.creator, 2, 0, chainUidA, address(vault));
            if (k == 1) b.items[1].epochId = keccak256("another epoch");
            if (k == 2) b.items[1].author = ids[2];
            _refused(b, shape);
        }
        IPqVault.PqVaultBatch memory e = _batch(10, 0);
        _refused(e, shape);
        IPqVault.PqVaultBatch memory c = _batch(10, 2);
        vault.createItems(c, _sig(c.author, h.batch(c, PqVaultTypes.DS_V))); // the control
    }

    /// One nonce reused inside a batch (an item's equal to the batch's, two items' equal): `PqVaultNonceUsed`, nothing stored.
    function test_nonceReusedInsideRefused() public {
        bytes32 scope = PqVaultTypes.scopeItem(vid, ids[1]);
        IPqVault.PqVaultBatch memory b = _batch(10, 2);
        b.items[1].nonce = 10;
        _refused(b, abi.encodeWithSelector(IPqVault.PqVaultNonceUsed.selector, scope, uint64(10)));
        b = _batch(10, 2);
        b.items[1].nonce = 11;
        _refused(b, abi.encodeWithSelector(IPqVault.PqVaultNonceUsed.selector, scope, uint64(11)));
        assertEq(vault.itemCount(vid), 0);
        assertFalse(vault.nonceUsed(scope, 10));
        b = _batch(10, 2);
        vault.createItems(b, _sig(b.author, h.batch(b, PqVaultTypes.DS_V))); // the control
    }

    /// The ciphertext bound per item; a forged batch.
    function test_boundsAndSignature() public {
        IPqVault.PqVaultBatch memory b = _batch(10, 2);
        b.items[1].ciphertext = _ct(31, 1);
        _refused(b, abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        b.items[1].ciphertext = _ct(16_417, 1);
        _refused(b, abi.encodeWithSelector(IPqVault.PqVaultShape.selector));
        b.items[1].ciphertext = _ct(16_416, 1);
        IUARegistry.UASig memory bad = _sig(ids[2], h.batch(b, PqVaultTypes.DS_V));
        vm.expectRevert(_unauthorized(ids[1]));
        vault.createItems(b, bad);
        vault.createItems(b, _sig(b.author, h.batch(b, PqVaultTypes.DS_V)));
    }
}
