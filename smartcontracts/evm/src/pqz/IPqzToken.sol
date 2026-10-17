// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Events, errors and the account view of the PQZ layer (pq-zero-knowledge.md §7.1, §7.8, §9.4).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** `bytes32` ids are `pqz-mlwe` UAs (CTR-PQZ-13).
interface IPqzToken {
    /// @notice pq-zero-knowledge.md §9.4 `accountState`: `accHash` is the zero ciphertext's hash for a new account (P6g D10).
    struct AccountState {
        bytes32 accHash;
        uint16 accUnits;
        uint64 pendingCount;
        uint64 rolled;
        uint64 floor;
        uint64 cleared;
        uint64 sendCounter;
        uint256 plainPending;
    }

    /// @notice A public amount into `plainPending` (shield, wrap-shield, a confidential fee).
    event PqzPlainCredit(bytes32 indexed ua, uint256 amount, uint256 plainPending);
    /// @notice Proven credit `index` of `ua`; its bytes `u ‖ v_t` are in the `PqzTransfer` of `entryRef`.
    event PqzCredit(bytes32 indexed ua, uint64 indexed index, bytes32 entryRef);
    /// @notice `out = u ‖ v_t ‖ v_f ‖ [v_a]`; with the salt, `R = salt ‖ u ‖ v_t ‖ [v_a] ‖ toUA` (P6g D14).
    event PqzTransfer(bytes32 indexed entryRef, bytes32 indexed fromUA, bytes32 indexed toUA, bytes16 salt, bytes out);
    /// @notice Op 7 (CTR-PQZ-26): `out = u_0 … u_{G−1} ‖ v_0 … v_{M−1} ‖ v_f ‖ [v_{a,0} … v_{a,M−1}]`; the legs' UAs are
    ///         the `PqzCredit` events of `entryRef`, in leg order (`recipientsHash = keccak256(UA_0 ‖ … ‖ UA_{M−1})`).
    event PqzTransferMulti(
        bytes32 indexed entryRef, bytes32 indexed fromUA, bytes32 recipientsHash, uint256 legs, bytes16 salt, bytes out
    );
    event PqzRolled(bytes32 indexed ua, uint64 rolled, bytes32 accHash);
    /// @notice Burn (`amount > 0`) or refresh (`amount = 0`); `newAcc = u' ‖ v_f` (before re-adding kept inline credits).
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
    error PlainOverdraw(uint256 plainUsed, uint256 plainPending);
    error AccMismatch();
    error PendingRange(uint256 p, uint256 floor, uint256 pendingCount);
    error InlineTooFar(uint256 n);
    error InlineMismatch(uint256 index);
    error RefreshRequired(bytes32 ua);
    error UnitsInvariant();
    error AuditorRequired();
    error AuditorForbidden();
    error MemoSaltMismatch();
    error TransferEntryDisabled(uint8 disclosureMode);
    error AuthRejected();
    error ProofRejected();
    error RollOverRange(uint256 n);
    error UnknownEntry(bytes32 entryRef);
}
