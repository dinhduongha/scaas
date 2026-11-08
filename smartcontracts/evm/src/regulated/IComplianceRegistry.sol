// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The receiver check's registry (CTR-AS-07, CTR-AS-16, regulated-kinds spec §5): `bytes32` account ⇒ `{uint64 flags,
///        uint64 validUntil, uint32 attesterId}` in one slot; an `admin` contract, written once by the constructor, enables
///        and disables attesters; disabling an attester voids its attestations at once. No personal data.
/// @notice **UNAUDITED.** A regulated token never calls this through a Solidity interface: `RegulatedBase` makes a bounded
///         `STATICCALL` of `hasFlags` (and, for `canReceive`, of `attestationOf` and `attesterEnabled`), and its release pins
///         the canonical runtime's `extcodehash` (`REGISTRY_CODEHASH`).
interface IComplianceRegistry {
    event AttesterSet(address indexed attester, uint32 indexed attesterId, bool enabled);
    event Attested(bytes32 indexed account, uint64 flags, uint64 validUntil, uint32 indexed attesterId);

    error NotAdmin();
    error NotAttester();
    error AdminNotContract(address a);
    error LengthMismatch();
    /// @notice `ELIGIBLE_CONTRACT` (8) set by anyone but the admin, or with a `validUntil` other than `type(uint64).max`
    ///         (CTR-AS-16).
    error EligibleContractAdminOnly();
    /// @notice An attester (id != 0) wrote over or revoked a row the admin wrote: a stored `attesterId == 0` with
    ///         `flags != 0` (owner 2026-11-06). An empty slot and an admin row of flags 0 stay open.
    error AdminWrittenSlot(bytes32 account);

    /// @notice Set once by the constructor, a contract (CTR-AS-07); never written again.
    function admin() external view returns (address);
    /// @notice Admin only. An attester's id is assigned at its first enabling and never reused; id 0 is the admin.
    function setAttester(address attester, bool enabled) external;
    function attesterId(address attester) external view returns (uint32);
    /// @notice Id 0 (the admin) is always enabled; an id never assigned is not.
    function attesterEnabled(uint32 id) external view returns (bool);
    /// @notice An enabled attester, or the admin (id 0). Flags 0 revoke. `ELIGIBLE_CONTRACT` only by the admin, with
    ///         `validUntil == type(uint64).max` (CTR-AS-16). A row the admin wrote (`attesterId == 0 && flags != 0`) only
    ///         the admin overwrites or revokes; an attester gets `AdminWrittenSlot` (owner 2026-11-06).
    function attest(bytes32[] calldata accounts, uint64[] calldata flags, uint64[] calldata validUntil) external;
    function attestationOf(bytes32 account) external view returns (uint64 flags, uint64 validUntil, uint32 attesterId);
    /// @notice `(required == 0 || (active && ((f & required) == required || f & ELIGIBLE_CONTRACT != 0)))
    ///         && !(active && f & denied != 0)`, `active = attesterEnabled(id) && validUntil >= now`.
    function hasFlags(bytes32 account, uint64 required, uint64 denied) external view returns (bool);
}
