// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The regulated kinds 8-13 (CTR-GOV-03, regulated-kinds spec §3.1): the controls as direct entries, the views, the
///        errors and events. A regulated kind answers `type(IRegulatedToken).interfaceId` in ERC-165 (M-10); kinds 0-5 do not.
/// @notice **UNAUDITED.** Every entry is `nonReentrant` and gated by `GovernanceUse.use(bit, subject, scalar)`; a relayed
///         holder comes through the `GovernanceRouter` (G19: no `mtx*` twin here). Ids are `bytes32` UA ids (CTR-GOV-01).
interface IRegulatedToken {
    /// @notice `regulatedConfig()`: the hot slot, the flags and the terms in one struct (fewer selectors, spec §3.1).
    struct RegulatedConfig {
        address complianceRegistry;
        uint8 controls; // bits 5-10 of `features`, shifted (I12)
        uint64 requiredFlags;
        uint64 deniedFlags;
        bytes32 termsHash;
        uint64 pausedUntil;
        uint64 pauseCooldownUntil;
    }

    /// @notice One account's freeze (spec §2.3): slot a `until ‖ episodeStart ‖ issuerCooldownUntil ‖ recordBacked`, slot b.
    struct FreezeState {
        uint64 until;
        uint64 episodeStart;
        uint64 issuerCooldownUntil;
        bool recordBacked;
        bytes32 recordId;
    }

    /// @notice A recorded order (CTR-AS-04, spec §2.3); `recordId = keccak256(abi.encode(orderId, subject, beneficiary))`.
    struct OrderRecord {
        bytes32 subject;
        bytes32 beneficiary;
        uint64 freezeUntil;
        bool revoked;
        uint256 maxAmount;
        uint256 executed;
    }

    event AccountFrozen(bytes32 indexed account, bytes32 indexed ref, bytes32 recordId, uint64 until);
    event AccountUnfrozen(bytes32 indexed account, bytes32 indexed ref);
    event ForcedTransfer(bytes32 indexed recordId, bytes32 indexed from, bytes32 indexed to, uint256 amount);
    event Paused(bytes32 indexed ref, uint64 until);
    event Unpaused(bytes32 indexed ref);
    event OrderRecorded(bytes32 indexed recordId, bytes32 indexed orderId, bytes32 indexed subject, bytes32 beneficiary,
        uint256 maxAmount, uint64 freezeUntil, bytes32 documentHash);
    event OrderRevoked(bytes32 indexed recordId, bytes32 reasonRef);
    event OperatorTransfer(bytes32 indexed from, bytes32 indexed to, uint256 amount, bytes32 indexed ref);

    error Frozen(bytes32 account);
    error TokenPaused(uint64 until);
    /// @notice `reason` 0: refused by `hasFlags` on the hot path; 1-4 from `canReceive`.
    error NotEligible(bytes32 account, uint8 reason);
    error FeeRecipientFrozen(bytes32 account);
    error RefRequired();
    error RegulatedConfigInvalid();
    error RegistryCodeMismatch(address registry, bytes32 codehash);
    error RegistryUnavailable(address registry);
    error RegistryGasStarved(uint256 cap, uint256 left);
    error OrderExists(bytes32 recordId);
    error OrderUnknown(bytes32 recordId);
    error OrderInactive(bytes32 recordId);
    error SubjectNotFrozen(bytes32 subject);
    error OrderExceeded(uint256 remaining);
    error FreezeTooLong(uint64 maxUntil);
    error FreezeCooldown(uint64 until);
    error NotFrozen(bytes32 account);
    error AlreadyRecordFrozen(bytes32 account);
    error RecordFreezeShorter(uint64 until);
    error FreezeTargetRefused(bytes32 account);
    error PauseTooLong(uint64 until);
    error PauseCooldown(uint64 until);
    error ForceTargetRefused(bytes32 account);
    /// @notice `operatorTransfer`'s refusals of CTR-GOV-08 (CTR-GOV-20; spec §3.1's `ModerateTargetRefused`, read for bit
    ///         22): `from == to`, 0, `pad(UA_POOL)`, `pad(SHIELD_POOL)` or the token on either side, a native `from` with code.
    error OperatorTargetRefused(bytes32 account);
    /// @notice `forceTransfer(…, 0)` and `operatorTransfer(…, 0, …)` (F-08). Not in spec §3.1's list (plan T28).
    error AmountZero();
    /// @notice `unpause` while not paused (spec §3.4 "unpause: paused"). Not in spec §3.1's list (plan T28).
    error NotPaused();

    /// @notice Bit 5, issuer (T1, T2, T4 of spec §3.3).
    function freeze(bytes32 account, bytes32 ref, bytes32 recordId) external;
    /// @notice Bit 5, issuer (T5).
    function unfreeze(bytes32 account, bytes32 ref) external;
    /// @notice Bit 6, issuer, scalar `amount`: the subject's public balance to the record's beneficiary.
    function forceTransfer(bytes32 recordId, uint256 amount) external;
    /// @notice Bit 7, issuer (CTR-AS-06).
    function pause(bytes32 ref, uint64 until) external;
    function unpause(bytes32 ref) external;
    /// @notice Bit 10, compliance.
    function recordOrder(bytes32 orderId, bytes32 documentHash, bytes32 subject, bytes32 beneficiary, uint256 maxAmount,
        uint64 freezeUntil) external;
    /// @notice Bit 10, compliance; with `RECORD` disabled the role alone (T8).
    function revokeOrder(bytes32 recordId, bytes32 reasonRef) external;
    /// @notice Bit 22, any holder, scalar `amount` (CTR-GOV-20): public balances only.
    function operatorTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref) external;

    function regulatedConfig() external view returns (RegulatedConfig memory);
    function freezeOf(bytes32 account) external view returns (FreezeState memory);
    /// @notice `F(account)` of spec §3.2.
    function isFrozen(bytes32 account) external view returns (bool);
    /// @notice `reason` 1-4 from the registry's `attestationOf` and `attesterEnabled`.
    function canReceive(bytes32 account) external view returns (bool ok, uint8 reason);
    function order(bytes32 recordId) external view returns (OrderRecord memory);
}
