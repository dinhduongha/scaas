// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqVault} from "../../src/pqvault/IPqVault.sol";
import {PqVaultTypes} from "../../src/pqvault/PqVaultTypes.sol";

/// The struct hashes and typed digests of `PqVaultTypes` over calldata, as the contract computes them (the tests build records
/// in memory); `ds` is the vault's domain (`PqVaultTypes.DS_V` or `dsB(instance)`).
contract PqVaultHasher {
    function create(IPqVault.PqVaultCreate calldata v, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashCreate(v));
    }

    function epoch(IPqVault.PqVaultEpoch calldata e, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashEpoch(e));
    }

    function leave(IPqVault.PqVaultLeave calldata l, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashLeave(l));
    }

    function remove(IPqVault.PqVaultRemove calldata r, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashRemove(r));
    }

    function item(IPqVault.PqVaultItem calldata it, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashItem(it));
    }

    function edit(IPqVault.PqVaultEdit calldata d, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashEdit(d));
    }

    function batch(IPqVault.PqVaultBatch calldata b, bytes32 ds) external pure returns (bytes32) {
        return PqVaultTypes.typed(ds, PqVaultTypes.hashBatch(b));
    }

    function structHashes(IPqVault.PqVaultCreate calldata v, IPqVault.PqVaultBatch calldata b)
        external
        pure
        returns (bytes32, bytes32)
    {
        return (PqVaultTypes.hashCreate(v), PqVaultTypes.hashBatch(b));
    }

    function dsB(address c) external view returns (bytes32) {
        return PqVaultTypes.dsB(c);
    }
}
