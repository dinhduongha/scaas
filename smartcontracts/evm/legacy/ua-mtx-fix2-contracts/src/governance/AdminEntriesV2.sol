// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../../src/ua/IUARegistry.sol";
import {IOpenFactory} from "../../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../../src/factory/IFactoryToken.sol";

/// @title The admin entries without the chain word, as they stood at aeb1da09 (superseded by CTR-GOV-27, the rest of Fable
///        recheck-2 P3-1, owner 2026-11-12 "đồng ý."): `transferAdmin(bytes32)` on every `IAdmin` contract (the token kinds,
///        `SCaaSDex`, `OpenFactory`, `ComplianceRegistry`, whose constructor took `(admin_, govRouter_)` and held no chain
///        word); `OpenFactory`'s three env publishes, `revokeApproval(bytes32)` and the nine flat parameters of
///        `setChainEntries`; the router's ops and typehashes of the same. Their bodies are those of aeb1da09
///        (`UAAdmin.sol`, `OpenFactory.sol`, `GovernanceBase.sol`, `GovernanceRouterBase.sol`, `GovernanceRouter.sol`).
///        Not built. UNAUDITED.
interface IAdminEntriesV2 {
    /// `0xe923bc3d`
    function transferAdmin(bytes32 newAdmin) external;
    function publishTokenEnv(IOpenFactory.TokenKind kind, uint16 envVersion, IFactoryToken.Env calldata env) external;
    function publishDexEnv(uint16 envVersion, IFactoryToken.Env calldata env) external;
    function publishClassEnv(uint16 contractClass, uint16 kind, uint16 envVersion, IFactoryToken.Env calldata env) external;
    function revokeApproval(bytes32 key) external;
    function setChainEntries(address relayFeeRouter_, bytes32 relayFeeRouterCodeHash, bytes32 relayFeeExecutorCodeHash,
        address complianceRegistry_, bytes32 complianceRegistryCodeHash, address smartKeyAccountFactory_,
        bytes32 smartKeyAccountFactoryCodeHash, address zetherStatements_, bytes32 zetherStatementsCodeHash) external;
    function mtxTransferAdmin(MetaTxLib.UAEnvelope calldata e, address target, bytes32 newAdmin,
        IUARegistry.UASig calldata auth) external;
    function mtxPublishTokenEnv(MetaTxLib.UAEnvelope calldata e, address target, IOpenFactory.TokenKind kind,
        uint16 envVersion, IFactoryToken.Env calldata env, IUARegistry.UASig calldata auth) external;
    function mtxPublishDexEnv(MetaTxLib.UAEnvelope calldata e, address target, uint16 envVersion,
        IFactoryToken.Env calldata env, IUARegistry.UASig calldata auth) external;
    function mtxPublishClassEnv(MetaTxLib.UAEnvelope calldata e, address target, uint16 contractClass, uint16 kind,
        uint16 envVersion, IFactoryToken.Env calldata env, IUARegistry.UASig calldata auth) external;
    function mtxRevokeApproval(MetaTxLib.UAEnvelope calldata e, address target, bytes32 key, IUARegistry.UASig calldata auth)
        external;
    function mtxSetChainEntries(MetaTxLib.UAEnvelope calldata e, address target, address relayFeeRouter,
        bytes32 relayFeeRouterCodeHash, bytes32 relayFeeExecutorCodeHash, address complianceRegistry,
        bytes32 complianceRegistryCodeHash, address smartKeyAccountFactory, bytes32 smartKeyAccountFactoryCodeHash,
        address zetherStatements, bytes32 zetherStatementsCodeHash, IUARegistry.UASig calldata auth) external;
}

library AdminEntriesV2 {
    /// `0x36dbad09794ba40c4846013eebf3fab8fb57877cc3f2287d6f5b504b992cd4da`
    bytes32 internal constant UA_TRANSFER_ADMIN = keccak256(
        "UATransferAdmin(bytes32 from,address target,bytes32 newAdmin,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0xd739c124313a7e6faf3cda213ec65bbbb0083682bd92c65f30828f91a5834534`
    bytes32 internal constant UA_PUBLISH_TOKEN_ENV = keccak256(
        "UAPublishTokenEnv(bytes32 from,address target,uint8 kind,uint16 envVersion,Env env,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
        "Env(address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes)");
    /// `0x42e54c113b9b8ab5b05033dd7baea5349084f5779102c99b6ff28d8ff92e6781`
    bytes32 internal constant UA_PUBLISH_DEX_ENV = keccak256(
        "UAPublishDexEnv(bytes32 from,address target,uint16 envVersion,Env env,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
        "Env(address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes)");
    /// `0x12ce6dcb2eb22885385796a41cbb587b1912c1296e63d99e48341f6915cec5c9`
    bytes32 internal constant UA_PUBLISH_CLASS_ENV = keccak256(
        "UAPublishClassEnv(bytes32 from,address target,uint16 contractClass,uint16 kind,uint16 envVersion,Env env,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
        "Env(address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes)");
    /// `0x98785e6c230282e5c1148de5c064e5024d037af5951ca73fcf8887ebcf7adbb7`
    bytes32 internal constant UA_REVOKE_APPROVAL = keccak256(
        "UARevokeApproval(bytes32 from,address target,bytes32 key,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    /// `0xc26de6f6c81a262ba1f4c9d4b6e9202632cae0d9c8276af5136a5ee58e16f2d3`
    bytes32 internal constant UA_SET_CHAIN_ENTRIES = keccak256(
        "UASetChainEntries(bytes32 from,address target,address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,address zetherStatements,bytes32 zetherStatementsCodeHash,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
}
