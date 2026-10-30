// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "./IZetherVerifier.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {IUALedger} from "../metatx/IUALedger.sol";
import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";

/// @title The confidential layer of the kinds `NORMAL_ZETHER` and `WRAPPED_ZETHER` (CTR-ZTH-44, CTR-ZTH-45): ElGamal
///        `acc`/`pending` balances over the token's public ERC-20 balance.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Byte-exact contract with the prover: `docs/contracts/zether.md`.
///         The token is also an `IERC20MetaTx` on the one meta-transaction base: every proof-carrying entry point is a
///         direct call (statement `ZTX_V1_DIRECT`, binding 0) or an allowlisted self-call of `mtxExecute` / `uaExecute`
///         whose envelope binding the statement carries (`ZTX_V1_RELAYED`, CTR-ZTH-34, CTR-ZTH-51). The shared entry points
///         and events are `IConfidentialToken`'s (`auth` and `accHint` must be empty here); `mtxWrapShield` and
///         `mtxUnshieldUnwrap` are on `WRAPPED_ZETHER` only (`IConfidentialWrappedToken`); the prover views are in
///         `ZetherStatements` (CTR-ZTH-46).
interface IZetherToken is IUALedger, IConfidentialToken {
    /// @notice One account at one block. An unset point is `O`.
    struct AccountState {
        bytes accC;
        bytes accD;
        bytes pendingC;
        bytes pendingD;
        uint64 accSeq;
        uint64 pendingSeq;
        uint64 sendCounter;
        uint64 modeNonce;
        ZetherTypes.RollOverMode mode;
    }

    /// @notice Commit-reveal (HASH): the record `R = salt ‖ B_1 ‖ … ‖ B_M` (also kept in state by SSTORE2, `transferEntry`;
    ///         for off-chain indexers, who see `keccak256(R)` as the commitment).
    event TransferBundles(bytes32 indexed entryRef, bytes bundles);
    event RollOverModeChanged(ZetherTypes.UA indexed account, ZetherTypes.RollOverMode mode);

    error AccountNotRegistered(ZetherTypes.UA account);
    /// @notice A multi-recipient `decoyFee` below the token's `minDecoyFee`, or `≥ 2^64` (owner 2026-10-20; as PQZ's).
    error DecoyFeeOutOfRange(uint256 decoyFee, uint256 minDecoyFee);
    error AmountOutOfRange(uint256 amount, uint256 max);
    error ProofRejected();
    error StaleAccSeq(uint256 expected, uint256 got);
    error StaleSendCounter(uint256 expected, uint256 got);
    error SelfTransfer();
    error BadRecipientCount(uint256 count);
    error DuplicateRecipient(ZetherTypes.UA recipient);
    error BadPayload(uint256 length);
    error RollOverOwnerOnly(ZetherTypes.UA account);
    error RollOverExpired(uint256 validUntilBlock);
    error PendingSeqMismatch(uint256 expected, uint256 got);
    error ZeroRecipient();
    /// @notice `OPTIONAL` auditor: every `C_aud_j` is `O` (left out) or none is (CTR-ZTH-42).
    error AuditorLegsMixed();
    /// @notice `FULL` auditor: a transfer left the auditor out (some `C_aud_j = O`).
    error AuditorRequired();
    /// @notice `NONE` auditor: a transfer carries an auditor leg (some `C_aud_j ≠ O`).
    error AuditorForbidden();
    /// @notice With the auditor on (statement `Y_a` = the token key), the auditor key is the sender (`Y_f`) or a recipient
    ///         (`Y_t`, any `Y_tj`): refused on every transfer form, direct, relayed and in the statement views (review C0-1;
    ///         the Zether twin of PQZ F-4).
    error AuditorKeyAsParty();
    /// @notice A transfer or unshield statement past its `validUntilBlock` (`block.number > validUntilBlock`; payload word
    ///         2, header word 15), the rule of the PQZ header (review C0-9).
    error TransferExpired(uint256 validUntilBlock);
    /// @notice Commit-reveal: the memo's clear salt is not the payload's (storage-only recovery needs it, CTR-ZTH-50).
    error MemoSaltMismatch();
    /// @notice A `COMPACT` token refuses `mtxConfidentialTransferSingle` (CTR-ZTH-48).
    error TransferEntryDisabled(uint8 disclosureMode);
    /// @notice `ConfidentialConfig.disclosureMode` is neither BUNDLE nor COMPACT (CTR-ZTH-48).
    error BadDisclosureMode(uint8 mode);
    /// @notice `ConfidentialConfig.auditorMode` unknown, FULL or OPTIONAL without a key, or NONE with one (CTR-ZTH-49).
    error BadAuditorMode(uint8 mode);
    /// @notice The release's verifier does not run on this chain (`isSupportedOnThisChain()` false or unanswered: a
    ///         BLS12-381 verifier without EIP-2537); `curve` its `curveName()` (plan 5g-Z2, from the factory's gate).
    error VerifierUnsupportedOnThisChain(address verifier, string curve);
    /// @notice A `ConfidentialConfig` the token refuses (CTR-ZTH-04, CTR-ZTH-26).
    error BadInit();
    /// @notice `mtxWrapShield`: the public-equivalent of the deposit is not a whole number of shielded units.
    error AmountNotScaled(uint256 minted, uint256 shieldScale);
    /// @notice A shared proof-taking entry point got a non-empty `auth`: the Zether proof alone authorises (UA-6).
    error AuthNotEmpty();
    /// @notice A shared proof-taking entry point got a non-empty `accHint` (Zether has no materialised `acc`).
    error AccHintNotEmpty();
    /// @notice `mtxRollOver` with `n = 0`.
    error RollOverRange(uint256 n);

    // ------------------------------------------------------------------ per-token parameters (immutable)

    /// @notice The total cap in shielded units, `≤ 2^54` (CTR-ZTH-26).
    function maxDecryptableShielded() external view returns (uint256);
    /// @notice Public units per shielded unit (CTR-ZTH-04).
    function shieldScale() external view returns (uint256);
    /// @notice The inner fee, `< 2^64` and `< maxDecryptableShielded`; never a function of `v` (CTR-ZTH-07).
    function confidentialFee() external view returns (uint256);
    /// @notice The least per-leg `decoyFee` of a multi-recipient transfer (owner 2026-10-20); `confidentialFee + 16 ·
    ///         minDecoyFee` is `< 2^64` and `< maxDecryptableShielded`. 0 allowed.
    function minDecoyFee() external view returns (uint256);
    /// @notice The auditor key (`ITransferDisclosure.AUDITOR`), empty exactly when `auditorMode()` is `NONE` (CTR-ZTH-09).
    function auditorKey() external view returns (bytes memory);
    /// @notice `NONE`, `FULL` (every transfer includes the auditor) or `OPTIONAL` (the sender's choice per transfer).
    function auditorMode() external view returns (ZetherTypes.AuditorMode);
    /// @notice `BUNDLE` (`mtxConfidentialTransfer` stores the record inline; `…Compact` stores it by SSTORE2) or `COMPACT`
    ///         (`mtxConfidentialTransfer` and `…Compact` are commit-reveal; single refused). Both keep `R` in state.
    function disclosureMode() external view returns (ZetherTypes.DisclosureMode);
    /// @notice The canonical `ZetherDisclosure` (stateless, shared), an implementation immutable (CTR-ZTH-43).
    function disclosure() external view returns (ITransferDisclosure);
    /// @notice The curve's transfer verifier (transfers, the group operations), an implementation immutable that
    ///         `OpenFactory` checks against its canonical set at registration (CTR-ZTH-20).
    function verifier() external view returns (IZetherVerifier);
    /// @notice The curve's burn verifier (unshield, unshield-unwrap), likewise (CTR-ZTH-20).
    function burnVerifier() external view returns (IZetherBurnVerifier);
    /// @notice The release's curve, `"bls12-381"` (the transfer verifier's `curveName()`): an attribute of
    ///         the implementation version; version numbers carry no curve meaning.
    function curve() external view returns (string memory);
    // `registry()` (the account registry, an implementation immutable, CTR-ZTH-44) is the UA ledger's (`IUALedger`).

    // ------------------------------------------------------------------ state

    /// @notice Record of `entryRef` for `disclosure()`, always read from state (review C0-3): `R = salt ‖ B_1 ‖ … ‖ B_M`
    ///         (BUNDLE and the single format inline, commit-reveal by SSTORE2), empty for an unknown ref. Multi-recipient
    ///         `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j ‖ D_aud_j` (review C0-1); the single format `B = Y_t ‖ C_out ‖ D_out ‖
    ///         C_aud` (`16 + 4P` bytes).
    function transferEntry(bytes32 entryRef) external view returns (bytes memory R);
    /// @notice The sender memo of a commit-reveal entry (`49 + 40·M` bytes, CTR-ZTH-50), empty otherwise.
    function transferMemo(bytes32 entryRef) external view returns (bytes memory);
    /// @notice Σ of every `acc` and `pending` exponent (shielded units); `totalSupply()` counts public units only.
    function totalShielded() external view returns (uint256);
    function registered(ZetherTypes.UA account) external view returns (bool);
    function accountState(ZetherTypes.UA account) external view returns (AccountState memory);
    function sendCounter(ZetherTypes.UA account) external view returns (uint256);
    /// @notice The binding a relayed proof carries (CTR-ZTH-06): every envelope field except `data`, plus `chainUid`.
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    /// @notice The UA path's binding (CTR-ZTH-51): tag `SCAAS-ZETHER-UA-ENVELOPE-V1`, `from` as `bytes32`.
    function uaEnvelopeBinding(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32);

    // ------------------------------------------------------------------ Zether-only entry points (CTR-ZTH-45)

    /// @notice Skips `OWNER_ONLY` items.
    function mtxRollOverBatch(ZetherTypes.UA[] calldata accounts) external;
    /// @notice Owner roll-over: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function mtxRollOverSigned(ZetherTypes.UA account, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external;
    /// @notice Owner mode change: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function mtxSetRollOverMode(
        ZetherTypes.UA account,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig
    ) external;
}
