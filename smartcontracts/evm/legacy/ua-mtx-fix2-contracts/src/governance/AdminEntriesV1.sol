// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../../src/ua/IUARegistry.sol";
import {IOpenFactory} from "../../../../src/factory/IOpenFactory.sol";

/// @title The admin entries without the chain word, as they stood at a18e9464 (superseded by Fable recheck-2 P3-1, owner
///        2026-11-12, CTR-GOV-27): `renounceAdmin()` on `OpenFactory`, every token kind and `SCaaSDex`; the three release
///        deploys of `OpenFactory` without the last `bytes32 chainUid_`; the router's `mtxRenounceAdmin` and its typehash
///        without `bytes32 chainUid`. Their bodies are those of a18e9464 (`OpenFactory.sol`, `GovernanceBase.sol`,
///        `GovernanceRouterBase.sol`). Not built. UNAUDITED.
interface IAdminEntriesV1 {
    /// `0x8bad0c0a`
    function renounceAdmin() external;
    function deployTokenImplementation(uint8 kind, uint64 version, uint16 envVersion, bytes calldata initcode,
        bytes calldata implArgs) external returns (address implementation);
    function deployDexImplementation(uint64 version, uint16 envVersion, bytes calldata initcode, bytes calldata implArgs)
        external returns (address implementation);
    function deployImplementation(IOpenFactory.ReleaseId calldata id, uint16 envVersion, bytes4 initSelector,
        bytes4 interfaceId, bytes calldata initcode, bytes calldata implArgs) external returns (address implementation);
    /// `0xfeedac3d`
    function mtxRenounceAdmin(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external;
}

library AdminEntriesV1 {
    /// `0x4be88ff950da1b2063111810c97fc341fb457a71d9719475cf513a9f09dde5ba`
    bytes32 internal constant UA_RENOUNCE_ADMIN = keccak256(
        "UARenounceAdmin(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
}
