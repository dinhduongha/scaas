// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Events, errors and the account view of the PQZ layer (pq-zero-knowledge.md §7.1, §7.8, §9.4).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** `bytes32` ids are `pqz-mlwe` UAs (CTR-PQZ-13).
interface IPqzToken {
    /// @notice pq-zero-knowledge.md §9.4 `accountState` (plan 5h D2 / D3): the counters, the `acc` reference (`accBlob`,
    ///         0 for `Trivial(0)`; ignored while `flags & 1`, the materialised `acc`), `flags` (1 MATERIALISED, 2 / 4 the
    ///         prepared halves), `accHash` (the materialised `acc`'s keccak; stale once a debit clears flag 1).
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

    /// @notice A TRIVIAL entry (plan 5h D18): `amount` appended as entry `index` of `ua`, or merged into it (shield,
    ///         wrap-shield, a confidential fee).
    event PqzTrivialCredit(bytes32 indexed ua, uint64 indexed index, uint256 amount);
    /// @notice Proven credit `index` of `ua`; its bytes `u ‖ v_t` are in state (`pqzPendingCt`, the op blob of
    ///         `entryRef`; plan 5h D1 / D2) and in the `PqzTransfer` of `entryRef`.
    event PqzCredit(bytes32 indexed ua, uint64 indexed index, bytes32 entryRef);
    /// @notice `out = u ‖ v_t ‖ v_f ‖ [v_a]`; with the salt, `R = salt ‖ u ‖ v_t ‖ [v_a] ‖ toUA` (P6g D14).
    event PqzTransfer(bytes32 indexed entryRef, bytes32 indexed fromUA, bytes32 indexed toUA, bytes16 salt, bytes out);
    /// @notice Op 7 (CTR-PQZ-26): `out = u_0 … u_{G−1} ‖ v_0 … v_{M−1} ‖ v_f ‖ [v_{a,0} … v_{a,M−1}]`; the legs' UAs are
    ///         the `PqzCredit` events of `entryRef`, in leg order (`recipientsHash = keccak256(UA_0 ‖ … ‖ UA_{M−1})`).
    event PqzTransferMulti(
        bytes32 indexed entryRef, bytes32 indexed fromUA, bytes32 recipientsHash, uint256 legs, bytes16 salt, bytes out
    );
    event PqzRolled(bytes32 indexed ua, uint64 rolled, bytes32 accHash);
    /// @notice Burn (`amount > 0`) or refresh (`amount = 0`); `newAcc = u' ‖ v_f`, the new `acc` (plan 5h D4).
    event PqzBurned(bytes32 indexed ua, uint256 amount, address recipient, bytes newAcc);

    error BadInit();
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
    error RefreshRecipient(address recipient);
    error PendingRange(uint256 p, uint256 floor, uint256 pendingCount);
    error InlineTooFar(uint256 n);
    error UnitsInvariant();
    error AuditorRequired();
    error AuditorForbidden();
    error MemoSaltMismatch();
    error TransferEntryDisabled(uint8 disclosureMode);
    error AuthRejected();
    error ProofRejected();
    error RollOverRange(uint256 n);
    /// @notice `acc` holds `K_MAX − 1` units: refresh (plan 5h D8).
    error CapReached(bytes32 ua);
    /// @notice Entry `index` is younger than `ROLL_AGE` blocks (D6).
    error RollTooYoung(uint256 index);
    /// @notice A rollover before `pqzPrepareAcc` wrote both halves of the account's `acc` words (D8).
    error AccNotPrepared(bytes32 ua);
    /// @notice A shared `u` (any `u_g`, a burn's `u'`) all zero (D24, Codex T2 CHAIN-01).
    error ZeroU();
    error UnknownEntry(bytes32 entryRef);
}
