// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceRouterBase, GovernanceRouterTypes as T} from "./GovernanceRouterBase.sol";
import {IWrappedToken} from "../metatx/IWrappedToken.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
import {IRegulatedToken} from "../regulated/IRegulatedToken.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IPqzToken} from "../pqz/IPqzToken.sol";

/// @title One per chain, CREATE2 at a predictable address (CTR-GOV-15 Change, owner 2026-11-04; spec
///        `2026-11-04-governance-ua-identity.md` §3): the closed table of governance spec §3.2 over every governed contract
///        of SCaaS whose `GOV_ROUTER` it is. The owner's and a holder's ops come from `GovernanceRouterBase`; here the powers
///        of the token kinds (`mint`, `mintToUA`, `disableWrap`, the rate entries; the eight controls of the regulated kinds
///        8-13, plan T32; the PQZ verifier UA of the PQZ kinds, group 3f) and of `SCaaSDex` (the market setters, `setFeeSplit`), each one `mtx<Op>(UAEnvelope, …, UASig)`
///        (ua-mtx-merge T7). Domain
///        `("SCaaS GovernanceRouter", "1", chainId, router, chain_uid)`. **UNAUDITED.**
contract GovernanceRouter is GovernanceRouterBase {
    constructor(bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        GovernanceRouterBase("SCaaS GovernanceRouter", chainUid_, registry_, smartKeyAccountImpl_, hedera_)
    {}

    // ------------------------------------------------------------------ the powers on the token kinds

    function mtxMint(MetaTxLib.UAEnvelope calldata e, address target, address to, uint256 amount,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_MINT, e, target, IWrappedToken.mint.selector, abi.encode(to, amount), auth);
    }

    function mtxMintToUA(MetaTxLib.UAEnvelope calldata e, address target, bytes32 to, uint256 amount,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_MINT_TO_UA, e, target, IWrappedToken.mintToUA.selector, abi.encode(to, amount), auth);
    }

    function mtxDisableWrap(MetaTxLib.UAEnvelope calldata e, address target, address leg, bytes32 reason,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_DISABLE_WRAP, e, target, IWrappedToken.disableWrap.selector, abi.encode(leg, reason), auth);
    }

    function mtxProposeRate(MetaTxLib.UAEnvelope calldata e, address target, address leg, uint96 num, uint96 den,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_PROPOSE_RATE, e, target, IWrappedToken.proposeRate.selector, abi.encode(leg, num, den), auth);
    }

    function mtxCancelRate(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external {
        _ua(T.UA_CANCEL_RATE, e, target, IWrappedToken.cancelRate.selector, "", auth);
    }

    function mtxExecuteRate(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external {
        _ua(T.UA_EXECUTE_RATE, e, target, IWrappedToken.executeRate.selector, "", auth);
    }

    // ------------------------------------------------------------------ the controls of the regulated kinds 8-13 (plan T32)

    function mtxFreeze(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bytes32 ref, bytes32 recordId,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_FREEZE, e, target, IRegulatedToken.freeze.selector, abi.encode(account, ref, recordId), auth);
    }

    function mtxUnfreeze(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bytes32 ref,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_UNFREEZE, e, target, IRegulatedToken.unfreeze.selector, abi.encode(account, ref), auth);
    }

    function mtxForceTransfer(MetaTxLib.UAEnvelope calldata e, address target, bytes32 recordId, uint256 amount,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_FORCE_TRANSFER, e, target, IRegulatedToken.forceTransfer.selector, abi.encode(recordId, amount), auth);
    }

    function mtxPause(MetaTxLib.UAEnvelope calldata e, address target, bytes32 ref, uint64 until,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_PAUSE, e, target, IRegulatedToken.pause.selector, abi.encode(ref, until), auth);
    }

    function mtxUnpause(MetaTxLib.UAEnvelope calldata e, address target, bytes32 ref, IUARegistry.UASig calldata auth)
        external
    {
        _ua(T.UA_UNPAUSE, e, target, IRegulatedToken.unpause.selector, abi.encode(ref), auth);
    }

    function mtxRecordOrder(MetaTxLib.UAEnvelope calldata e, address target, bytes32 orderId, bytes32 documentHash,
        bytes32 subject, bytes32 beneficiary, uint256 maxAmount, uint64 freezeUntil, IUARegistry.UASig calldata auth)
        external
    {
        _ua(T.UA_RECORD_ORDER, e, target, IRegulatedToken.recordOrder.selector,
            abi.encode(orderId, documentHash, subject, beneficiary, maxAmount, freezeUntil), auth);
    }

    function mtxRevokeOrder(MetaTxLib.UAEnvelope calldata e, address target, bytes32 recordId, bytes32 reasonRef,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_REVOKE_ORDER, e, target, IRegulatedToken.revokeOrder.selector, abi.encode(recordId, reasonRef), auth);
    }

    /// @notice CTR-GOV-20: any holder of bit 22; `account` is the direct entry's `from` (the struct's `from` is the signer).
    function mtxOperatorTransfer(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bytes32 to,
        uint256 amount, bytes32 ref, IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_OPERATOR_TRANSFER, e, target, IRegulatedToken.operatorTransfer.selector, abi.encode(account, to, amount, ref),
            auth);
    }

    /// @notice Bit 23 `TAX` (pay-meta-tax spec §6.2): any holder; fee mode `NONE`, relayable at fee 0.
    function mtxSetTaxRate(MetaTxLib.UAEnvelope calldata e, address target, uint32 ratePpm, IUARegistry.UASig calldata auth)
        external
    {
        _ua(T.UA_SET_TAX_RATE, e, target, IRegulatedToken.setTaxRate.selector, abi.encode(ratePpm), auth);
    }

    function mtxSetTaxRecipient(MetaTxLib.UAEnvelope calldata e, address target, bytes32 taxRecipient,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_TAX_RECIPIENT, e, target, IRegulatedToken.setTaxRecipient.selector, abi.encode(taxRecipient), auth);
    }

    // ------------------------------------------------------------------ the PQZ verifier UA (group 3f, spec §4.2, §4.3)

    /// @notice The owner proposes, then confirms after the notice period, `next` as a transferable `OFFCHAIN` token's
    ///         verifier; fee mode `NONE`, relayable at fee 0.
    function mtxPqzSetVerifier(MetaTxLib.UAEnvelope calldata e, address target, bytes32 next, IUARegistry.UASig calldata auth)
        external
    {
        _ua(T.UA_PQZ_SET_VERIFIER, e, target, IPqzToken.pqzSetVerifier.selector, abi.encode(next), auth);
    }

    function mtxPqzCancelVerifier(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external {
        _ua(T.UA_PQZ_CANCEL_VERIFIER, e, target, IPqzToken.pqzCancelVerifier.selector, "", auth);
    }

    function mtxPqzRevokeVerifier(MetaTxLib.UAEnvelope calldata e, address target, IUARegistry.UASig calldata auth) external {
        _ua(T.UA_PQZ_REVOKE_VERIFIER, e, target, IPqzToken.pqzRevokeVerifier.selector, "", auth);
    }

    /// @notice Bit 24 `PQZ_PROOF` (group 3h, PQZ proof path spec §5): any holder sets a PQZ token's `proofStore` (`NONE` /
    ///         `LOG`, from its next debit); fee mode `NONE`, relayable at fee 0.
    function mtxSetProofStore(MetaTxLib.UAEnvelope calldata e, address target, uint8 next, IUARegistry.UASig calldata auth)
        external
    {
        _ua(T.UA_SET_PROOF_STORE, e, target, IPqzToken.setProofStore.selector, abi.encode(next), auth);
    }

    // ------------------------------------------------------------------ wrap limits on the hybrids (group 3l, spec 2026-11-10 §9)

    /// @notice The owner's limits of every leg, the net rule and the two lists (`setWrapLimits`): a wrap-side relaxation or an
    ///         unwrap-side tightening is proposed by the first call and applied by the same call after the factory's
    ///         `noticePeriod()`; fee mode `NONE`, relayable at fee 0. The struct words: `target`, the leg array's hash, the
    ///         three flags.
    function mtxSetWrapLimits(MetaTxLib.UAEnvelope calldata e, address target, IWrappedToken.WrapLegLimits[] calldata legs,
        bool netUnwrap, bool wrapList, bool unwrapList, IUARegistry.UASig calldata auth) external
    {
        _uaCall(T.UA_SET_WRAP_LIMITS, e, target, abi.encode(_legsHash(legs), netUnwrap, wrapList, unwrapList),
            abi.encodeCall(IWrappedToken.setWrapLimits, (legs, netUnwrap, wrapList, unwrapList)), auth);
    }

    /// @notice Bit 26's holder: `account`'s membership of the wrapper and unwrapper lists, at once.
    function mtxSetWrapMember(MetaTxLib.UAEnvelope calldata e, address target, bytes32 account, bool canWrap, bool canUnwrap,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_WRAP_MEMBER, e, target, IWrappedToken.setWrapMember.selector, abi.encode(account, canWrap, canUnwrap),
            auth);
    }

    /// @dev EIP-712 `WrapLegLimits[]`: `keccak256` of the concatenated struct hashes.
    function _legsHash(IWrappedToken.WrapLegLimits[] calldata legs) private pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](legs.length);
        for (uint256 i; i < legs.length; ++i) {
            IWrappedToken.WrapLegLimits calldata l = legs[i];
            h[i] = keccak256(abi.encode(T.WRAP_LEG_LIMITS, l.underlying, l.unitExp, l.decayDays, _limitHash(l.wrapShort),
                _limitHash(l.wrapLong), _limitHash(l.unwrapShort), _limitHash(l.unwrapLong)));
        }
        return keccak256(abi.encodePacked(h));
    }

    function _limitHash(IWrappedToken.WrapLimit calldata x) private pure returns (bytes32) {
        return keccak256(abi.encode(T.WRAP_LIMIT, x.perUser, x.tokenWide, x.period));
    }

    // ------------------------------------------------------------------ the powers on the DEX

    function mtxSetMarket(MetaTxLib.UAEnvelope calldata e, address target, address base, address quote, bool listed,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_MARKET, e, target, ISCaaSDex.setMarket.selector, abi.encode(base, quote, listed), auth);
    }

    function mtxSetExchangeTarget(MetaTxLib.UAEnvelope calldata e, address target, address exchangeTarget, bool listed,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_EXCHANGE_TARGET, e, target, ISCaaSDex.setExchangeTarget.selector, abi.encode(exchangeTarget, listed),
            auth);
    }

    function mtxSetListedOnly(MetaTxLib.UAEnvelope calldata e, address target, bool on, IUARegistry.UASig calldata auth)
        external
    {
        _ua(T.UA_SET_LISTED_ONLY, e, target, ISCaaSDex.setListedOnly.selector, abi.encode(on), auth);
    }

    function mtxSetFeeSplit(MetaTxLib.UAEnvelope calldata e, address target, uint32 relayerSharePpm, address treasury,
        IUARegistry.UASig calldata auth) external
    {
        _ua(T.UA_SET_FEE_SPLIT, e, target, ISCaaSDex.setFeeSplit.selector, abi.encode(relayerSharePpm, treasury), auth);
    }

    // ------------------------------------------------------------------ the factory's creations (S3)

    /// @notice Chain-neutral spec §4.4 (S3, owner 2026-11-07; plan T76): the signing UA creates. `target` is the chain's
    ///         `OpenFactory`, which reads `subject()` once at entry as the creator; `initHash = keccak256(initArgs)` is
    ///         signed, the arguments go to the factory as they are.
    function mtxCreateToken(MetaTxLib.UAEnvelope calldata e, address target, IOpenFactory.TokenKind kind, uint64 version,
        bytes calldata initArgs, bytes32 salt, IUARegistry.UASig calldata auth) external
    {
        _uaCall(T.UA_CREATE_TOKEN, e, target, abi.encode(kind, version, keccak256(initArgs), salt),
            abi.encodeCall(IOpenFactory.createToken, (kind, version, initArgs, salt)), auth);
    }

    function mtxCreateDex(MetaTxLib.UAEnvelope calldata e, address target, uint64 version, bytes calldata initArgs,
        bytes32 salt, IUARegistry.UASig calldata auth) external
    {
        _uaCall(T.UA_CREATE_DEX, e, target, abi.encode(version, keccak256(initArgs), salt),
            abi.encodeCall(IOpenFactory.createDex, (version, initArgs, salt)), auth);
    }

    /// @notice The generic class's creation (index spec §8.4): the release's three ids flat, `initHash = keccak256(initCall)`.
    function mtxCreateInstance(MetaTxLib.UAEnvelope calldata e, address target, uint16 contractClass, uint16 kind,
        uint64 version, bytes calldata initCall, bytes32 salt, IUARegistry.UASig calldata auth) external
    {
        _uaCall(T.UA_CREATE_INSTANCE, e, target, abi.encode(contractClass, kind, version, keccak256(initCall), salt),
            abi.encodeCall(IOpenFactory.createInstance, (IOpenFactory.ReleaseId(contractClass, kind, version), salt,
                initCall)), auth);
    }
}
