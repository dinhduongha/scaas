// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";

/// @title Events, errors, the account view and the PQZ-only entry points of the PQZ layer (pq-zero-knowledge.md §7.1,
///        §7.8, §9.4); the shared entry points and events are `IConfidentialToken`'s (plan 5h D20).
/// @notice **UNAUDITED.** `bytes32` ids are signing UAs holding a PQZ key (UA-6 U7).
interface IPqzToken is IConfidentialToken {
    /// @notice `pqzAccount` (pq-zero-knowledge.md §9.4; plan 5h D2 / D3, D13): the counters, the `acc` reference (`accBlob`,
    ///         0 for `Trivial(0)`; ignored while `flags & 1`, the materialised `acc`), `flags` (1 MATERIALISED, 2 / 4 the
    ///         prepared halves), `accHash` (the keccak of the materialised `acc`'s
    ///         packed stream, P46: `PqzCt.CTP` bytes; stale once a debit clears flag 1).
    struct AccountState {
        uint64 pendingCount;
        uint64 rolled;
        uint64 floor;
        uint64 cleared;
        address accBlob;
        uint32 accUnits;
        uint8 flags;
        uint64 sendCounter;
        bytes32 accHash;
    }

    /// @notice Proven credit `index` of `ua`; its bytes `u ‖ v_t` are in state (`pqzPendingCt`, the op blob of
    ///         `entryRef`; plan 5h D1 / D2).
    event Credited(bytes32 indexed ua, uint64 indexed index, bytes32 entryRef);
    /// @notice Every debit (D12, review N4): `rolled = floor = p`, `acc` now references `blob` (the op blob).
    event Debited(bytes32 indexed ua, uint64 rolled, uint64 floor, address blob);

    error BadInit();
    /// @notice `init` with the PQZH proof system at a set without PQZH value tokens (`PqzSet.PQZH_VALUE`): no debit of
    ///         such a token fits one transaction (C2-1; owner 2026-10-27, C0-2).
    error PqzhValueUnsupported();
    /// @notice A PQZH value token refuses a holder that is not a single-key `mldsa44` / `mldsa65` / `fndsa512` UA on
    ///         every entry that creates its pending entry (shield, op 1 and op 7 legs; owner 2026-10-27, C0-2).
    error PqzhHolderKind(bytes32 ua, uint16 kind);
    error BadDisclosureMode(uint8 mode);
    error BadAuditorMode(uint8 mode);
    error AccountNotRegistered(bytes32 ua);
    error AmountOutOfRange(uint256 amount, uint256 max);
    error AmountNotScaled(uint256 minted, uint256 shieldScale);
    error BadPayload(uint256 length);
    error NonCanonical();
    error Expired(uint256 validUntilBlock);
    error SelfTransfer();
    error BadRecipientCount(uint256 legs);
    error DuplicateRecipient(bytes32 ua);
    error ZeroRecipient();
    error RefreshRecipient(bytes32 recipient);
    error PendingRange(uint256 p, uint256 floor, uint256 pendingCount);
    error InlineTooFar(uint256 n);
    error UnitsInvariant();
    error AuditorRequired();
    error AuditorForbidden();
    /// F-4: with the auditor copies on, the auditor UA is neither the sender nor a recipient (op 1, op 7)
    error AuditorAsParty(bytes32 ua);
    error MemoSaltMismatch();
    error TransferEntryDisabled(uint8 disclosureMode);
    error AuthRejected();
    error ProofRejected();
    error RollOverRange(uint256 n);
    /// @notice `acc` holds `K_MAX − 1` units: refresh (plan 5h D8).
    error CapReached(bytes32 ua);
    /// @notice Entry `index` is younger than `ROLL_AGE` blocks (D6).
    error RollTooYoung(uint256 index);
    /// @notice A rollover before `mtxPrepareAcc` wrote both halves of the account's `acc` words (D8).
    error AccNotPrepared(bytes32 ua);
    /// @notice A shared `u` (any `u_g`, a burn's `u'`) all zero (D24, Codex T2 CHAIN-01).
    error ZeroU();
    error UnknownEntry(bytes32 entryRef);
    /// @notice An op 7 `decoyFee` below the token's `minDecoyFee`, or `≥ 2^64` (owner 2026-10-20).
    error DecoyFeeOutOfRange(uint256 decoyFee, uint256 minDecoyFee);
    /// @notice The shared `beneficiary` argument is not the payload's beneficiary word (plan 5h D20).
    error BeneficiaryMismatch(bytes32 payload, bytes32 given);

    /// @notice Single-recipient, commit-reveal on every token.
    function mtxConfidentialTransferSingleCompact(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);
    /// @notice The account (pq-zero-knowledge.md §9.4): counters, the `acc` reference, `accUnits`, flags, `sendCounter`, `accHash`.
    function pqzAccount(bytes32 ua) external view returns (AccountState memory);
    /// @notice Pending slot `i`: `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`; 0 once deleted.
    function pqzPending(bytes32 ua, uint64 i) external view returns (uint256);
    /// @notice The `acc` ciphertext from state.
    function pqzAcc(bytes32 ua) external view returns (bytes memory);
    /// @notice Entry `i` as a ciphertext from state.
    function pqzPendingCt(bytes32 ua, uint64 i) external view returns (bytes memory);
    /// @notice The op blob of a transfer as stored (empty if unknown).
    function pqzEntryBlob(bytes32 entryRef) external view returns (bytes memory);
    /// @notice Anyone, once per account and half (0, 1) before its first rollover (idempotent; plan 5h D8).
    function mtxPrepareAcc(bytes32 ua, uint256 half) external;
}
