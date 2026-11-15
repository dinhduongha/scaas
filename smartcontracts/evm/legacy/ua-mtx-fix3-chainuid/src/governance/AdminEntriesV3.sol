// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../../src/ua/IUARegistry.sol";
import {IGovernance} from "../../../../src/governance/IGovernance.sol";

/// @title The direct admin entries without the chain word, as they stood at cac043bc (superseded by CTR-GOV-28, owner
///        2026-11-13 "có thêm."): on the 12 token kinds and `SCaaSDex` `grantRole`, `setGrant`, `cancelGrant`, `revokeRole`,
///        `disableFeature`; on kinds 8-13 `enableFeature`; on the PQZ kinds 4, 5, 12, 13 `pqzSetVerifier`,
///        `pqzCancelVerifier`, `pqzRevokeVerifier`, `setVerifierFee`; on `ComplianceRegistry` `setKycProvider` and
///        `setCompliance`; the router's twelve ops and typehashes of the same. Their bodies are those of cac043bc
///        (`GovernanceBase.sol`, `RegulatedBase.sol`, `PqzLayer.sol`, `ComplianceRegistry.sol`, `SCaaSDexAdmin.sol`,
///        `GovernanceRouterBase.sol`, `GovernanceRouter.sol`). Then a holder's own `renounceRole(uint8)` on the 12 kinds and
///        `SCaaSDex`, `mtxRenounceRole` and `UARenounceRole` without the word, as they stood at baa42a33 (superseded by the
///        owner's ruling of 2026-11-13 renounceRole carries the chain word too, CTR-GOV-28). Not built. UNAUDITED.
interface IAdminEntriesV3 {
    function grantRole(uint8 bit, bytes32 account) external;
    function setGrant(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata terms) external;
    function cancelGrant(uint8 bit, bytes32 account) external;
    function revokeRole(uint8 bit, bytes32 account) external;
    function disableFeature(uint8 bit) external;
    function enableFeature(uint8 bit) external;
    function pqzSetVerifier(bytes32 next) external;
    function pqzCancelVerifier() external;
    function pqzRevokeVerifier() external;
    function setVerifierFee(uint64 next) external;
    function setKycProvider(bytes32 provider, bool enabled) external;
    function setCompliance(bytes32[] calldata accounts, uint64[] calldata flags, uint64[] calldata until) external;
    function renounceRole(uint8 bit) external; // 0x057c9cb8
    function mtxGrantRole(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 account,
        IUARegistry.UASig calldata auth) external;
    function mtxRevokeRole(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 account,
        IUARegistry.UASig calldata auth) external;
    function mtxSetGrant(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 holder,
        IGovernance.GrantTerms calldata terms, IUARegistry.UASig calldata auth) external;
    function mtxCancelGrant(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 account,
        IUARegistry.UASig calldata auth) external;
    function mtxDisableFeature(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, IUARegistry.UASig calldata auth)
        external;
    function mtxEnableFeature(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, IUARegistry.UASig calldata auth)
        external;
    function mtxPqzSetVerifier(MetaTxLib.UAEnvelope calldata e, address target, bytes32 next, IUARegistry.UASig calldata auth)
        external;
    function mtxPqzCancelVerifier(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external;
    function mtxPqzRevokeVerifier(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external;
    function mtxSetVerifierFee(MetaTxLib.UAEnvelope calldata e, address target, uint64 next, IUARegistry.UASig calldata auth)
        external;
    function mtxSetKycProvider(MetaTxLib.UAEnvelope calldata e, address target, bytes32 provider, bool enabled,
        IUARegistry.UASig calldata auth) external;
    function mtxSetCompliance(MetaTxLib.UAEnvelope calldata e, address target, bytes32[] calldata accounts,
        uint64[] calldata flags, uint64[] calldata until, IUARegistry.UASig calldata auth) external;
    function mtxRenounceRole(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, IUARegistry.UASig calldata auth)
        external; // 0xb0c1c360
}

library AdminEntriesV3 {
    /// `0x6eb86b2377b08b35d4ba9aea808b9f8291b350ae6aefdaa1c62b291013b79a6d`
    bytes32 internal constant UA_GRANT_ROLE = keccak256(
        "UAGrantRole(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0x2485b5c9b89864d24866c5f8cd84f9b306e3d837034f8d8232e51f31518594e0`
    bytes32 internal constant UA_REVOKE_ROLE = keccak256(
        "UARevokeRole(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0xc98bbb9ea43c430a7dbc43f74b8a5454c65373047ee3b5f0c727407d69a89fcf`
    bytes32 internal constant UA_SET_GRANT = keccak256(
        "UASetGrant(bytes32 from,address target,uint8 bit,bytes32 holder,GrantTerms terms,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
        "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)");
    /// `0x739f1688b6c65ab49c43063518ad450a1f15587a4ae1d9346f616483b2a71ea9`
    bytes32 internal constant UA_CANCEL_GRANT = keccak256(
        "UACancelGrant(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0x245ae38b9763de03075abd2d8b1f0e14d547af425936778038cc4d0d059f0394`
    bytes32 internal constant UA_DISABLE_FEATURE = keccak256(
        "UADisableFeature(bytes32 from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0x4cbb50807ee9d23bb7eaedea39a2a3df6eca4b6ad9b5f9dab35fcb03d1347114`
    bytes32 internal constant UA_ENABLE_FEATURE = keccak256(
        "UAEnableFeature(bytes32 from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0xc7b836ae14938e0da524ac8a888c602948164c3e01c450a2d4a60d8b257a2aee`
    bytes32 internal constant UA_PQZ_SET_VERIFIER = keccak256(
        "UAPqzSetVerifier(bytes32 from,address target,bytes32 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0x7f04a47d44fd0fc31c5bea71922bca3fdee4f3c7dbf0460b73526499ed942911`
    bytes32 internal constant UA_PQZ_CANCEL_VERIFIER = keccak256(
        "UAPqzCancelVerifier(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0xb395011f54af6f642333ddf8e664418b27c5ddeea94d7750852501c6d640a6d6`
    bytes32 internal constant UA_PQZ_REVOKE_VERIFIER = keccak256(
        "UAPqzRevokeVerifier(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0xffa3baec15773742773872cec5ac6e8000b668a4576324f215b5e663818dd14d`
    bytes32 internal constant UA_SET_VERIFIER_FEE = keccak256(
        "UASetVerifierFee(bytes32 from,address target,uint64 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0x297e6c85a9b9a8cf52deb0f6d2fb8cbed155b848764c47c54c1e720e8c16e4d6`
    bytes32 internal constant UA_SET_KYC_PROVIDER = keccak256(
        "UASetKycProvider(bytes32 from,address target,bytes32 provider,bool enabled,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0x0c697df193b5723555deb0270f8f1ef84c57975443e12cbb327dcef4ed923455`
    bytes32 internal constant UA_SET_COMPLIANCE = keccak256(
        "UASetCompliance(bytes32 from,address target,bytes32[] accounts,uint64[] flags,uint64[] until,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0x1a32125783655840c2b0717e59159708af35ca4638bf313676e325dd5029c3e1`
    bytes32 internal constant UA_RENOUNCE_ROLE = keccak256(
        "UARenounceRole(bytes32 from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
}
