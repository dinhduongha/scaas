// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UAMetaTxBase} from "../metatx/UAMetaTxBase.sol";
import {MtxPipelineLib} from "../metatx/MtxPipelineLib.sol";
import {IUALedger} from "../metatx/IUALedger.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {IGovernance} from "./IGovernance.sol";
import {IGovernanceRouter} from "./IGovernanceRouter.sol";

/// @title The typed structs of `GovernanceRouter` (spec `2026-11-04-governance-ua-identity.md` §3; governance spec §3.2): one
///        `UA<Op>` per op of the closed table, `from` first, `target` the first op word, then the op's own
///        parameters with `bytes32` identities, then the seven envelope words. Pinned by `GovRouterTypehash.t.sol`.
/// ua-mtx-merge T7 (R14): one struct per op, `UA<Op>`; the address `<Op>` structs left with their entries
///        (legacy/ua-mtx-merge/src/governance/; their hashes stay pinned as legacy pins).
library GovernanceRouterTypes {
    bytes32 internal constant GRANT_TERMS = keccak256(
        "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)");

    // ---- the owner and the holder of a bit: every `GovernanceBase` contract
    bytes32 internal constant UA_GRANT_ROLE = keccak256(
        "UAGrantRole(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_REVOKE_ROLE = keccak256(
        "UARevokeRole(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_GRANT = keccak256(
        "UASetGrant(bytes32 from,address target,uint8 bit,bytes32 holder,GrantTerms terms,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
        "GrantTerms(uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope)");
    bytes32 internal constant UA_CANCEL_GRANT = keccak256(
        "UACancelGrant(bytes32 from,address target,uint8 bit,bytes32 account,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_DISABLE_FEATURE = keccak256(
        "UADisableFeature(bytes32 from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_TRANSFER_OWNERSHIP = keccak256(
        "UATransferOwnership(bytes32 from,address target,bytes32 newOwner,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_ACCEPT_OWNERSHIP = keccak256(
        "UAAcceptOwnership(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_RENOUNCE_OWNERSHIP = keccak256(
        "UARenounceOwnership(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_RENOUNCE_ROLE = keccak256(
        "UARenounceRole(bytes32 from,address target,uint8 bit,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");

    // ---- the powers on the token kinds
    bytes32 internal constant UA_MINT = keccak256(
        "UAMint(bytes32 from,address target,address to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_MINT_TO_UA = keccak256(
        "UAMintToUA(bytes32 from,address target,bytes32 to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_DISABLE_WRAP = keccak256(
        "UADisableWrap(bytes32 from,address target,address leg,bytes32 reason,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_PROPOSE_RATE = keccak256(
        "UAProposeRate(bytes32 from,address target,address leg,uint96 num,uint96 den,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_CANCEL_RATE = keccak256(
        "UACancelRate(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_EXECUTE_RATE = keccak256(
        "UAExecuteRate(bytes32 from,address target,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");

    // ---- the powers on the DEX
    bytes32 internal constant UA_SET_MARKET = keccak256(
        "UASetMarket(bytes32 from,address target,address base,address quote,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_EXCHANGE_TARGET = keccak256(
        "UASetExchangeTarget(bytes32 from,address target,address exchangeTarget,bool listed,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_LISTED_ONLY = keccak256(
        "UASetListedOnly(bytes32 from,address target,bool on,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
    bytes32 internal constant UA_SET_FEE_SPLIT = keccak256(
        "UASetFeeSplit(bytes32 from,address target,uint32 relayerSharePpm,address treasury,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
}

/// @title What every governance router of a chain shares (CTR-GOV-15 Change, owner 2026-11-04): the flow and the owner's and
///        a holder's ops of `IGovernance`, which every `GovernanceBase` contract has. `GovernanceRouter` adds the powers of
///        SCaaS's kinds and the DEX; a router for other powers (an application's bits 128-255, the regulated kinds' bits) is
///        another child of this base, named by the governed contract's `GOV_ROUTER` (`Env.govRouter` for a release).
/// @notice No owner, no state of its own, no `receive`: it holds nothing. Fee mode `NONE` (`supportedModes() == 0x03`), every
///         entry relayable at fee 0. Each op is one signed entry `mtx<Op>(UAEnvelope, target, <op params>, UASig)` over `UA<Op>`
///         (ua-mtx-merge T7, R14: the `ua<Op>` body under the `mtx<Op>` name; the address `Envelope` + `bytes` forms are in
///         legacy): a native id signs with its own key and no registry call, a derived id (a PQ key, an `msig`, …) through
///         the registry; `target` a signed word. One flow: the lock, the signature and the nonce (`MtxPipelineLib.preNamedUA`), the
///         transient pair `(subject, target)`, the typed call `target.<op>(…)`, the pair cleared; a reverting target
///         reverts the whole call, the nonce included. `subject()` names the subject only to the live target. No generic
///         path: `executeMetaTransaction`, `mtxExecute` and `mtxBatch` refuse; the router's ops are on neither allow-list.
///         `cancelNonce` and the ordered `mtxCancelNonce(UAEnvelope, lane, UASig)` stay. **UNAUDITED.**
abstract contract GovernanceRouterBase is UAMetaTxBase, IGovernanceRouter {
    /// @notice A signed op names a `target` with no code: the call would do nothing and spend the nonce.
    error TargetHasNoCode(address target);

    // Transient slots, written as literals (assembly takes no keccak256 constant).
    bytes32 private constant _SUBJECT = 0x20935f8cb59257160a8ea6e9f7009952d0d53b805b693a0e0c04a129f2a5ab0e; // keccak256("scaas.govrouter.subject")
    bytes32 private constant _TARGET = 0xa1dd93cf1660937b99999b07adb12f34b563f6b0925eff1ae679d08fb0b5a482; // keccak256("scaas.govrouter.target")

    constructor(string memory domainName, bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        UAMetaTxBase(domainName, chainUid_, registry_, smartKeyAccountImpl_, hedera_)
    {}

    /// @notice The subject of the live call, to the live target only; 0 to any other caller and outside a call.
    function subject() external view returns (bytes32 s) {
        address t;
        assembly ("memory-safe") { t := tload(_TARGET) }
        if (msg.sender == t) assembly ("memory-safe") { s := tload(_SUBJECT) }
    }

    // ------------------------------------------------------------------ the owner and a holder (IGovernance)

    function mtxGrantRole(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 account,
        IUARegistry.UASig calldata auth) external
    {
        _ua(GovernanceRouterTypes.UA_GRANT_ROLE, e, target, IGovernance.grantRole.selector, abi.encode(bit, account), auth);
    }

    function mtxRevokeRole(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 account,
        IUARegistry.UASig calldata auth) external
    {
        _ua(GovernanceRouterTypes.UA_REVOKE_ROLE, e, target, IGovernance.revokeRole.selector, abi.encode(bit, account), auth);
    }

    function mtxSetGrant(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 holder,
        IGovernance.GrantTerms calldata terms, IUARegistry.UASig calldata auth) external
    {
        _uaCall(GovernanceRouterTypes.UA_SET_GRANT, e, target, abi.encode(bit, holder, _termsHash(terms)),
            abi.encodeCall(IGovernance.setGrant, (bit, holder, terms)), auth);
    }

    function mtxCancelGrant(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, bytes32 account,
        IUARegistry.UASig calldata auth) external
    {
        _ua(GovernanceRouterTypes.UA_CANCEL_GRANT, e, target, IGovernance.cancelGrant.selector, abi.encode(bit, account), auth);
    }

    function mtxDisableFeature(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, IUARegistry.UASig calldata auth)
        external
    {
        _ua(GovernanceRouterTypes.UA_DISABLE_FEATURE, e, target, IGovernance.disableFeature.selector, abi.encode(bit), auth);
    }

    function mtxTransferOwnership(MetaTxLib.UAEnvelope calldata e, address target, bytes32 newOwner,
        IUARegistry.UASig calldata auth) external
    {
        _ua(GovernanceRouterTypes.UA_TRANSFER_OWNERSHIP, e, target, IGovernance.transferOwnership.selector,
            abi.encode(newOwner), auth);
    }

    function mtxAcceptOwnership(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external {
        _ua(GovernanceRouterTypes.UA_ACCEPT_OWNERSHIP, e, target, IGovernance.acceptOwnership.selector, "", auth);
    }

    function mtxRenounceOwnership(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth)
        external
    {
        _ua(GovernanceRouterTypes.UA_RENOUNCE_OWNERSHIP, e, target, IGovernance.renounceOwnership.selector, "", auth);
    }

    function mtxRenounceRole(MetaTxLib.UAEnvelope calldata e, address target, uint8 bit, IUARegistry.UASig calldata auth)
        external
    {
        _ua(GovernanceRouterTypes.UA_RENOUNCE_ROLE, e, target, IGovernance.renounceRole.selector, abi.encode(bit), auth);
    }

    // ------------------------------------------------------------------ no generic path (governance spec §3.6, B-14)

    /// @dev `executeMetaTransaction`: an op signed as a `bytes data` blob is refused, whatever it calls.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata) internal pure override returns (bytes memory) {
        revert MtxSelectorNotAllowed(bytes4(m.data));
    }

    /// @dev The generic entries on ids refuse likewise (ua-mtx-merge T1: the `uaExecute` / `uaBatch` refusals, renamed).
    function mtxExecute(MetaTxLib.UAMetaTransaction calldata m, IUARegistry.UASig calldata)
        public pure override returns (bytes memory)
    {
        revert MtxSelectorNotAllowed(bytes4(m.data));
    }

    function mtxBatch(MetaTxLib.UAMetaTransaction[] calldata, IUARegistry.UASig[] calldata)
        public pure override returns (bool)
    {
        revert MtxSelectorNotAllowed(bytes4(0));
    }

    /// @notice Empty: the generic path refuses every call (`_execute`, `mtxExecute`, `mtxBatch`), `cancelNonce` included, so
    ///         the router publishes no allow-list row; its typed entries are no row either (governance spec §3.2). The
    ///         node's list for the router equals this, both directions.
    function mtxSelectors() public pure override returns (bytes4[] memory, uint8[] memory, uint8[] memory) {}

    // ------------------------------------------------------------------ the flow

    /// @dev An op whose struct words after `target` are the call's arguments.
    function _ua(bytes32 typehash, MetaTxLib.UAEnvelope calldata e, address target, bytes4 sel, bytes memory args,
        IUARegistry.UASig calldata auth) internal
    {
        _uaCall(typehash, e, target, args, bytes.concat(sel, args), auth);
    }

    /// @dev One flow for every subject (ua-mtx-merge T7, R14; `MtxPipelineLib._authorize`, invariant 1): a native id by its
    ///      own key, no registry call (EOA, ERC-1271, HIP-632 on Hedera; R17), the subject `pad(addr)` as the retired
    ///      `_mtxCall` wrote it, so `_govSubject()` is unchanged (spec §3.1); a derived id through `requireAuthorized` under
    ///      `PURPOSE_METATX`, the subject that id. The `UA…` event only (R18).
    function _uaCall(bytes32 typehash, MetaTxLib.UAEnvelope calldata e, address target, bytes memory words,
        bytes memory data, IUARegistry.UASig calldata auth) internal
    {
        bool outer = _enter();
        MtxPipelineLib.Envelope memory env = MtxPipelineLib.Envelope(
            e.from, 0, e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
        MtxPipelineLib.Out memory o =
            MtxPipelineLib.preNamedUA(_mtxCtx(), typehash, env, _signed(target, words), _facts(data), auth);
        _call(e.from, target, data);
        emit IUALedger.UAMetaTransactionExecuted(e.from, msg.sender, e.batch, e.nonce, o.digest, o.feeTo, o.fee);
        _exit(outer);
    }

    /// @dev The struct's words after `from`: `target`, then the op's.
    function _signed(address target, bytes memory words) private pure returns (bytes memory) {
        return bytes.concat(bytes32(uint256(uint160(target))), words);
    }

    /// @dev Step 3 of the pipeline for a typed op: fee class `ABSOLUTE`, on the UA allowlist of this entry only, against
    ///      `supportedModes()` (fee mode `NONE`).
    function _facts(bytes memory data) private view returns (MtxPipelineLib.CallFacts memory) {
        return MtxPipelineLib.CallFacts(bytes4(data), data.length, FEE_CLASS_ABSOLUTE, 0, 0, 0, true, supportedModes());
    }

    function _termsHash(IGovernance.GrantTerms calldata t) private pure returns (bytes32) {
        return keccak256(abi.encode(GovernanceRouterTypes.GRANT_TERMS, t));
    }

    /// @dev The pair lives exactly as long as the typed call; a failed call reverts with the target's own data.
    function _call(bytes32 s, address target, bytes memory data) private {
        if (target.code.length == 0) revert TargetHasNoCode(target);
        assembly ("memory-safe") {
            tstore(_SUBJECT, s)
            tstore(_TARGET, target)
        }
        (bool ok, bytes memory ret) = target.call(data);
        assembly ("memory-safe") {
            tstore(_SUBJECT, 0)
            tstore(_TARGET, 0)
        }
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }
}
