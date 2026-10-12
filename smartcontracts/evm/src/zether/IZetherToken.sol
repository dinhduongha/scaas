// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";

/// @title The confidential layer of the kinds `NONE_ZETHER` and `UNDERLYING_ZETHER` (CTR-ZTH-44, CTR-ZTH-45): ElGamal
///        `acc`/`pending` balances over the token's public ERC-20 balance.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Byte-exact contract with the prover: `docs/contracts/zether.md`.
///         The token is also an `IERC20MetaTx` on the one meta-transaction base: every proof-carrying entry point is a
///         direct call (statement `ZTX_V1_DIRECT`, binding 0) or an allowlisted self-call of `mtxExecute` whose envelope
///         binding the statement carries (`ZTX_V1_RELAYED`, CTR-ZTH-34). `zetherWrapShield` and `zetherUnshieldUnwrap`
///         are on `UNDERLYING_ZETHER` only; the prover views are in `ZetherStatements` (CTR-ZTH-46).
interface IZetherToken {
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

    event ZetherShielded(ZetherTypes.UA indexed account, uint256 amount);
    /// @notice The single-recipient format (`zetherTransferSingle`).
    event ZetherTransfer(
        ZetherTypes.UA indexed from,
        ZetherTypes.UA indexed to,
        ZetherTypes.UA indexed beneficiary,
        uint256 fee,
        uint256 sendCounter,
        bytes32 entryRef
    );
    /// @notice `M` recipients (decoys included), one proof; the recipients are public, the amounts encrypted.
    event ZetherTransferMulti(
        ZetherTypes.UA indexed from,
        ZetherTypes.UA indexed beneficiary,
        uint256 fee,
        uint256 sendCounter,
        bytes32 entryRef,
        ZetherTypes.UA[] recipients,
        ZetherTypes.TransferMode mode
    );
    /// @notice Commit-reveal (HASH): the record `R = salt ‖ B_1 ‖ … ‖ B_M`, whose hash `entryRef` stores.
    event TransferBundles(bytes32 indexed entryRef, bytes bundles);
    /// @notice `recipient` received `amount · shieldScale` public units (`zetherUnshield`) or the underlying they are
    ///         worth (`zetherUnshieldUnwrap`).
    event ZetherUnshielded(ZetherTypes.UA indexed account, uint256 amount, address indexed recipient);
    event RolledOver(ZetherTypes.UA indexed account, uint256 accSeq);
    event RollOverModeChanged(ZetherTypes.UA indexed account, ZetherTypes.RollOverMode mode);

    error AccountNotRegistered(ZetherTypes.UA account);
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
    /// @notice Commit-reveal: the memo's clear salt is not the payload's (storage-only recovery needs it, CTR-ZTH-50).
    error MemoSaltMismatch();
    /// @notice A `COMPACT` token refuses `zetherTransferNoBundle` and `zetherTransferSingle` (CTR-ZTH-48).
    error TransferEntryDisabled(uint8 disclosureMode);
    /// @notice `ConfidentialConfig.disclosureMode` is neither BUNDLE nor COMPACT (CTR-ZTH-48).
    error BadDisclosureMode(uint8 mode);
    /// @notice `ConfidentialConfig.auditorMode` unknown, FULL or OPTIONAL without a key, or NONE with one (CTR-ZTH-49).
    error BadAuditorMode(uint8 mode);
    /// @notice A `ConfidentialConfig` the token refuses (CTR-ZTH-04, CTR-ZTH-26).
    error BadInit();
    /// @notice `zetherWrapShield`: the public-equivalent of the deposit is not a whole number of shielded units.
    error AmountNotScaled(uint256 minted, uint256 shieldScale);

    // ------------------------------------------------------------------ per-token parameters (immutable)

    /// @notice The total cap in shielded units, `≤ 2^54` (CTR-ZTH-26).
    function maxDecryptableShielded() external view returns (uint256);
    /// @notice Public units per shielded unit (CTR-ZTH-04).
    function shieldScale() external view returns (uint256);
    /// @notice The inner fee, `< 2^64` and `< maxDecryptableShielded`; never a function of `v` (CTR-ZTH-07).
    function confidentialFee() external view returns (uint256);
    /// @notice The auditor key (`ITransferDisclosure.AUDITOR`), empty exactly when `auditorMode()` is `NONE` (CTR-ZTH-09).
    function auditorKey() external view returns (bytes memory);
    /// @notice `NONE`, `FULL` (every transfer includes the auditor) or `OPTIONAL` (the sender's choice per transfer).
    function auditorMode() external view returns (ZetherTypes.AuditorMode);
    /// @notice `BUNDLE` (`zetherTransfer` stores the record; `zetherTransferCompact`, `zetherTransferNoBundle` save gas)
    ///         or `COMPACT` (`zetherTransfer` and `zetherTransferCompact` are commit-reveal; no-bundle and single refused).
    function disclosureMode() external view returns (ZetherTypes.DisclosureMode);
    /// @notice The canonical `ZetherDisclosure` (stateless, shared), an implementation immutable (CTR-ZTH-43).
    function disclosure() external view returns (ITransferDisclosure);
    function verifier() external view returns (IZetherVerifier);
    /// @notice The account registry, an implementation immutable (CTR-ZTH-44).
    function registry() external view returns (address);

    // ------------------------------------------------------------------ state

    /// @notice Raw record of `entryRef` for `disclosure()`: `R = salt ‖ B_1 ‖ … ‖ B_M` (BUNDLE, the single format),
    ///         `keccak256(R) ‖ memo` (commit-reveal, CTR-ZTH-50), empty (NONE, unknown). `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
    function transferEntry(bytes32 entryRef) external view returns (bytes memory);
    /// @notice Σ of every `acc` and `pending` exponent (shielded units); `totalSupply()` counts public units only.
    function totalShielded() external view returns (uint256);
    function registered(ZetherTypes.UA account) external view returns (bool);
    function accountState(ZetherTypes.UA account) external view returns (AccountState memory);
    function sendCounter(ZetherTypes.UA account) external view returns (uint256);
    /// @notice The binding a relayed proof carries (CTR-ZTH-06): every envelope field except `data`, plus `chainUid`.
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);

    // ------------------------------------------------------------------ roll-over (CTR-ZTH-16, CTR-ZTH-17)

    /// @notice `PUBLIC` accounts: anyone, a silent no-op without a new credit; `OWNER_ONLY` reverts.
    function zetherRollOver(ZetherTypes.UA account) external;
    /// @notice Skips `OWNER_ONLY` items.
    function zetherRollOverBatch(ZetherTypes.UA[] calldata accounts) external;
    function zetherRollOverSigned(ZetherTypes.UA account, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external;
    function zetherSetRollOverMode(
        ZetherTypes.UA account,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig
    ) external;

    // ------------------------------------------------------------------ shield / transfer / unshield (CTR-ZTH-45)

    /// @notice Burns `amount · shieldScale` public units of the caller; `pending[ua] += [amount]G` (CTR-ZTH-35).
    function zetherShield(bytes calldata encodedY, uint256 amount) external;
    /// @notice `M` recipients, one proof, the token's default (CTR-ZTH-38): the record stored (BUNDLE) on a `BUNDLE`
    ///         token, commit-reveal (HASH: the commitment and the sender memo stored, the record in `TransferBundles`) on
    ///         a `COMPACT` token.
    function zetherTransfer(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    /// @notice Commit-reveal (HASH) on every token: the commitment and the sender memo stored, the record in the event.
    function zetherTransferCompact(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    /// @notice Stores nothing (NONE, disclosure off chain from calldata); `TransferEntryDisabled` on a `COMPACT` token.
    function zetherTransferNoBundle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    /// @notice The single-recipient format, its record stored in full; `TransferEntryDisabled` on a `COMPACT` token.
    function zetherTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata authSig, ZetherTypes.UA beneficiary)
        external returns (bytes32 entryRef);
    /// @notice Proves the unshield statement, then mints `amount · shieldScale` public units to `to`.
    function zetherUnshield(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        address to,
        uint256 amount
    ) external;
}
