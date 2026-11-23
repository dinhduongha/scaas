// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// Owner ruling (M) of 2026-11-23 in the shared `PqGroupBase` (CTR-PQV-12, one rule for both apps): a vault member may hold
/// several KEM keys in an epoch, `(ua, keyId)` strictly ascending, one wrap each, at most 8 per UA; `vaultsOf` stays per UA.
contract PqVaultDevicesTest is PqVaultBase {
    function _mk(bytes32 ua, uint64 keyId) internal pure returns (IPqChat.MemberKey memory) {
        return IPqChat.MemberKey(ua, keyId, bytes32(0));
    }

    function test_aVaultMemberWithTwoKeys() public {
        _devices(ids[0], 1);
        _devices(ids[1], 1);
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(1, 1, 0, address(vault));
        IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](2);
        (m[0], m[1]) = (_mk(ids[0], 0), _mk(ids[0], 1));
        v.members = m;
        w = _wraps(m, PqVaultTypes.vaultId(v.creator, v.nonce, v.mode, chainUidA, address(vault)));
        v.wrapHashes = _hashes(w);
        bytes32 vid = _create(vault, v, w);
        assertTrue(vault.epochComplete(vid), "both wraps landed");
        assertEq(vault.vaultCount(ids[0]), 1, "one entry per UA");
        // the admin adds a member with two keys: one new entry for it
        IPqChat.MemberKey[] memory m2 = new IPqChat.MemberKey[](3);
        (m2[0], m2[1], m2[2]) = (_mk(ids[0], 0), _mk(ids[1], 0), _mk(ids[1], 1));
        if (ids[1] < ids[0]) (m2[0], m2[1], m2[2]) = (_mk(ids[1], 0), _mk(ids[1], 1), _mk(ids[0], 0));
        (IPqVault.PqVaultEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(vid, ids[0], 1, 1, vid, v.admins, m2);
        bytes32 e1 = _rekey(vault, e, ew, 0);
        assertTrue(vault.epochComplete(e1));
        assertEq(vault.vaultCount(ids[1]), 1, "the added member once");
        // keys out of order: refused
        (m2[1], m2[2]) = (m2[2], m2[1]);
        (e, ew) = _epoch(vid, ids[0], 2, 2, e1, v.admins, m2);
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e, _ds(0, address(vault))));
        vm.expectRevert(IPqVault.PqVaultShape.selector);
        vault.rekeyVault(e, ew, sig);
    }
}
