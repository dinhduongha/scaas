// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";
import {PqVaultBase} from "./PqVaultBase.sol";

/// PqVault plan V3 (spec §5.4, CTR-PQV-02): `PqVault`'s storage is the ERC-7201 namespace `scaas.pqvault` only (no plain slot:
/// `test/v2/layout/PqVault.json` is empty), each field at its pinned slot inside it, read with `vm.load` after a write.
contract PqVaultLayoutTest is PqVaultBase {
    using stdJson for string;

    function _root() internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(uint256(keccak256("scaas.pqvault")) - 1))) & ~uint256(0xff);
    }

    function test_storageLayoutIsPinned() public view {
        string memory art =
            vm.readFile(string.concat("./", vm.envOr("FOUNDRY_OUT", string("out")), "/PqVault.sol/PqVault.json"));
        string memory pin = vm.readFile("./test/v2/layout/PqVault.json");
        assertEq(pin.readStringArray(".labels").length, 0);
        assertFalse(vm.keyExistsJson(art, ".storageLayout.storage[0]"), "no plain slot");
        assertEq(_root(), 0x5bab91edb5f7201959ccc400acb38a4632e4bb30c3ed3cf98f817b8f10b48800);
    }

    function _at(uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(address(vault), bytes32(slot)));
    }

    function _map(bytes32 key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    /// owner +0, initialized +1, epochs +2 (PqChat's Epoch layout), childOf +3, nonces +4, chain +5, removals +6, vaults +7,
    /// modes +12 (items, record, edits, batches +8..+11: PqVaultItems / the layout of V4).
    function test_namespaceFieldsArePinned() public {
        uint256 r = _root();
        assertEq(bytes32(_at(r)), OWNER_UA);
        assertEq(_at(r + 1), 1);
        (IPqVault.PqVaultCreate memory v, IPqChat.Wrap[] memory w) = _vault(3, 5, 1, address(vault));
        bytes32 vid = vault.createVault(v, _slice(w, 0, 2), _createSig(v, address(vault)));
        uint256 e = _map(vid, r + 2);
        assertEq(bytes32(_at(e)), vid);
        uint256 packed = _at(e + 1);
        assertTrue(address(uint160(packed)).code.length > 0, "the record blob");
        assertEq(packed >> 224, 3, "wraps");
        assertEq(_at(e + 2), 2 | 1 << 32, "landed 2, home");
        uint256 nw = _map(bytes32(0), _map(PqVaultTypes.scopeVault(v.creator), r + 4));
        assertEq(_at(nw), 1 << 5, "nonce 5");
        assertEq(_at(_map(v.members[0].ua, r + 7)), 1, "vaults[member]: one vault");
        assertEq(_at(_map(vid, r + 12)), 1, "modes[vid] = 1");
        vault.addVaultWraps(vid, 2, _slice(w, 2, 3));
        IPqVault.PqVaultRemove memory rm = IPqVault.PqVaultRemove(vid, vid, 1, _list(ids[2]), ids[0], 7);
        vault.removeVaultMembers(rm, _sig(ids[0], h.remove(rm, h.dsB(address(vault)))));
        assertEq(_at(_map(vid, r + 6)), 1, "removals: one record");
        (IPqVault.PqVaultEpoch memory ep, IPqChat.Wrap[] memory ew) =
            _epoch(vid, ids[0], 8, 1, vid, _list(ids[0]), _without(_members(3), ids[2]));
        bytes32 e1 = _rekey(vault, ep, ew, 1);
        assertEq(bytes32(_at(_map(vid, r + 3))), e1, "childOf");
        assertEq(_at(_map(vid, r + 5)), 1, "chain: one epoch");
    }
}
