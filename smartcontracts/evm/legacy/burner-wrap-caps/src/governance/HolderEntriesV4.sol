// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../../src/ua/IUARegistry.sol";
import {IWrappedToken} from "../../../../src/metatx/IWrappedToken.sol";

/// @title The role holders' direct entries and `setWrapLimits` without the chain word, as they stood at 3fa153e4 (superseded
///        by CTR-GOV-28's Change of round 3zb + 3zc, owner 2026-11-13 "(2), gộp vào round 3zb + 3zc."; `setWrapLimits` by
///        "OQ1, OQ2 theo đề xuất"): the 24 holder entries of the 12 token kinds and `SCaaSDex`, `setWrapLimits`, the router's
///        25 ops and their typehashes of the same. Their bodies are those of 3fa153e4 (`NormalTokenCore.sol`,
///        `WrappedTokenCore.sol`, `RegulatedBase.sol`, `PqzLayer.sol`, `SCaaSDex.sol`, `GovernanceRouter.sol`,
///        `GovernanceRouterBase.sol`). Not built. UNAUDITED.
interface IHolderEntriesV4 {
    function mint(address to, uint256 amount) external; // 0x40c10f19
    function mintToUA(bytes32 to, uint256 amount) external;
    function disableWrap(address underlying, bytes32 reason) external;
    function proposeRate(address underlying, uint96 num, uint96 den) external;
    function cancelRate() external;
    function executeRate() external;
    function setWrapLimits(IWrappedToken.WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList) external;
    function setWrapMember(bytes32 account, bool canWrap, bool canUnwrap) external;
    function setAllowed(bytes32[] calldata accounts, bool on) external;
    function setDenied(bytes32[] calldata accounts, bool on) external;
    function freeze(bytes32 account, bytes32 ref, bytes32 recordId) external;
    function unfreeze(bytes32 account, bytes32 ref) external;
    function forceTransfer(bytes32 recordId, uint256 amount) external;
    function pause(bytes32 ref, uint64 until) external;
    function unpause(bytes32 ref) external;
    function recordOrder(bytes32 orderId, bytes32 documentHash, bytes32 subject, bytes32 beneficiary, uint256 maxAmount,
        uint64 freezeUntil) external;
    function revokeOrder(bytes32 recordId, bytes32 reasonRef) external;
    function operatorTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref) external;
    function setTaxRate(uint32 ratePpm) external;
    function setTaxRecipient(bytes32 taxRecipient) external;
    function setProofStore(uint8 next) external;
    function setMarket(address base, address quote, bool listed) external;
    function setExchangeTarget(address target, bool listed) external;
    function setListedOnly(bool on) external;
    function setFeeSplit(uint32 relayerSharePpm, address treasury) external;
    function mtxMint(MetaTxLib.UAEnvelope calldata e, address target, address to, uint256 amount, IUARegistry.UASig calldata auth) external;
    function mtxMintToUA(MetaTxLib.UAEnvelope calldata e, address target, bytes32 to, uint256 amount, IUARegistry.UASig calldata auth) external;
    function mtxDisableWrap(MetaTxLib.UAEnvelope calldata e, address target, address leg, bytes32 reason, IUARegistry.UASig calldata auth) external;
    function mtxProposeRate(MetaTxLib.UAEnvelope calldata e, address target, address leg, uint96 num, uint96 den, IUARegistry.UASig calldata auth) external;
    function mtxCancelRate(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external;
    function mtxExecuteRate(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external;
    function mtxFreeze(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bytes32 ref, bytes32 recordId, IUARegistry.UASig calldata auth) external;
    function mtxUnfreeze(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bytes32 ref, IUARegistry.UASig calldata auth) external;
    function mtxForceTransfer(MetaTxLib.UAEnvelope calldata e, address target, bytes32 recordId, uint256 amount, IUARegistry.UASig calldata auth) external;
    function mtxPause(MetaTxLib.UAEnvelope calldata e, address target, bytes32 ref, uint64 until, IUARegistry.UASig calldata auth) external;
    function mtxUnpause(MetaTxLib.UAEnvelope calldata e, address target, bytes32 ref, IUARegistry.UASig calldata auth) external;
    function mtxRecordOrder(MetaTxLib.UAEnvelope calldata e, address target, bytes32 orderId, bytes32 documentHash, bytes32 subject, bytes32 beneficiary, uint256 maxAmount, uint64 freezeUntil, IUARegistry.UASig calldata auth) external;
    function mtxRevokeOrder(MetaTxLib.UAEnvelope calldata e, address target, bytes32 recordId, bytes32 reasonRef, IUARegistry.UASig calldata auth) external;
    function mtxOperatorTransfer(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bytes32 to, uint256 amount, bytes32 ref, IUARegistry.UASig calldata auth) external;
    function mtxSetTaxRate(MetaTxLib.UAEnvelope calldata e, address target, uint32 ratePpm, IUARegistry.UASig calldata auth) external;
    function mtxSetTaxRecipient(MetaTxLib.UAEnvelope calldata e, address target, bytes32 taxRecipient, IUARegistry.UASig calldata auth) external;
    function mtxSetAllowed(MetaTxLib.UAEnvelope calldata e, address target, bytes32[] calldata accounts, bool on, IUARegistry.UASig calldata auth) external;
    function mtxSetDenied(MetaTxLib.UAEnvelope calldata e, address target, bytes32[] calldata accounts, bool on, IUARegistry.UASig calldata auth) external;
    function mtxSetProofStore(MetaTxLib.UAEnvelope calldata e, address target, uint8 next, IUARegistry.UASig calldata auth) external;
    function mtxSetWrapLimits(MetaTxLib.UAEnvelope calldata e, address target, IWrappedToken.WrapLegLimits[] calldata legs, bool netUnwrap, bool wrapList, bool unwrapList, IUARegistry.UASig calldata auth) external;
    function mtxSetWrapMember(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bool canWrap, bool canUnwrap, IUARegistry.UASig calldata auth) external;
    function mtxSetMarket(MetaTxLib.UAEnvelope calldata e, address target, address base, address quote, bool listed, IUARegistry.UASig calldata auth) external;
    function mtxSetExchangeTarget(MetaTxLib.UAEnvelope calldata e, address target, address exchangeTarget, bool listed, IUARegistry.UASig calldata auth) external;
    function mtxSetListedOnly(MetaTxLib.UAEnvelope calldata e, address target, bool on, IUARegistry.UASig calldata auth) external;
    function mtxSetFeeSplit(MetaTxLib.UAEnvelope calldata e, address target, uint32 relayerSharePpm, address treasury, IUARegistry.UASig calldata auth) external;
}

library HolderTypesV4 {
    bytes32 internal constant UA_MINT_V4 = keccak256(
        "UAMint(bytes32 from,address target,address to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_MINT_TO_UA_V4 = keccak256(
        "UAMintToUA(bytes32 from,address target,bytes32 to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_DISABLE_WRAP_V4 = keccak256(
        "UADisableWrap(bytes32 from,address target,address leg,bytes32 reason,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_PROPOSE_RATE_V4 = keccak256(
        "UAProposeRate(bytes32 from,address target,address leg,uint96 num,uint96 den,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_CANCEL_RATE_V4 = keccak256(
        "UACancelRate(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_EXECUTE_RATE_V4 = keccak256(
        "UAExecuteRate(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_MARKET_V4 = keccak256(
        "UASetMarket(bytes32 from,address target,address base,address quote,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_EXCHANGE_TARGET_V4 = keccak256(
        "UASetExchangeTarget(bytes32 from,address target,address exchangeTarget,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_LISTED_ONLY_V4 = keccak256(
        "UASetListedOnly(bytes32 from,address target,bool on,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_FEE_SPLIT_V4 = keccak256(
        "UASetFeeSplit(bytes32 from,address target,uint32 relayerSharePpm,address treasury,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_FREEZE_V4 = keccak256(
        "UAFreeze(bytes32 from,address target,bytes32 account,bytes32 ref,bytes32 recordId,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_UNFREEZE_V4 = keccak256(
        "UAUnfreeze(bytes32 from,address target,bytes32 account,bytes32 ref,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_FORCE_TRANSFER_V4 = keccak256(
        "UAForceTransfer(bytes32 from,address target,bytes32 recordId,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_PAUSE_V4 = keccak256(
        "UAPause(bytes32 from,address target,bytes32 ref,uint64 until,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_UNPAUSE_V4 = keccak256(
        "UAUnpause(bytes32 from,address target,bytes32 ref,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_RECORD_ORDER_V4 = keccak256(
        "UARecordOrder(bytes32 from,address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_REVOKE_ORDER_V4 = keccak256(
        "UARevokeOrder(bytes32 from,address target,bytes32 recordId,bytes32 reasonRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_TAX_RATE_V4 = keccak256(
        "UASetTaxRate(bytes32 from,address target,uint32 ratePpm,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_TAX_RECIPIENT_V4 = keccak256(
        "UASetTaxRecipient(bytes32 from,address target,bytes32 taxRecipient,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_PROOF_STORE_V4 = keccak256(
        "UASetProofStore(bytes32 from,address target,uint8 next,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_OPERATOR_TRANSFER_V4 = keccak256(
        "UAOperatorTransfer(bytes32 from,address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_WRAP_LIMITS_V4 = keccak256(
        "UASetWrapLimits(bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
        "WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)"
        "WrapLimit(uint24 perUser,uint64 tokenWide,uint32 period)");
    bytes32 internal constant UA_SET_WRAP_MEMBER_V4 = keccak256(
        "UASetWrapMember(bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_ALLOWED_V4 = keccak256(
        "UASetAllowed(bytes32 from,address target,bytes32[] accounts,bool on,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_DENIED_V4 = keccak256(
        "UASetDenied(bytes32 from,address target,bytes32[] accounts,bool on,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
}
