// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IAdmin} from "../governance/IAdmin.sol";

/// @title The receiver check's registry (CTR-AS-07, CTR-AS-16, regulated-kinds spec §5; round 3r, spec
///        2026-11-10-admin-not-owner.md §5.3, §5.3.1): `bytes32` account ⇒ a compliance row `{uint64 flags, uint64
///        validUntil, uint32 providerId}` in one slot. Its admin is a UA id (`IAdmin`: a two-step transfer, no renounce),
///        acting directly as its native id or through the registry's router; it enables and disables KYC providers, each a
///        UA id too; disabling a KYC provider voids its rows at once. No personal data.
/// @notice **UNAUDITED.** A regulated token never calls this through a Solidity interface on its hot path: `RegulatedBase`
///         makes a bounded `STATICCALL` of `hasFlags` (and, for `canReceive`, of `complianceOf` and `kycProviderEnabled`),
///         and its release pins the canonical runtime's `extcodehash` (`COMPLIANCE_REGISTRY_CODEHASH`); at creation
///         `RegulatedLib.init` reads `govRouter()` after that pin.
interface IComplianceRegistry is IAdmin {
    event KycProviderSet(bytes32 indexed provider, uint32 indexed providerId, bool enabled);
    event ComplianceSet(bytes32 indexed account, uint64 flags, uint64 validUntil, uint32 indexed providerId);

    /// @notice The constructor's admin is 0.
    error AdminZero();
    /// @notice A derived admin (high 96 bits set) with no router: nobody could act as it (Fable P2-3).
    error AdminUnreachable(bytes32 admin);
    /// @notice The constructor's router is not 0 and has no code.
    error RouterNotContract(address govRouter);
    /// @notice `setCompliance` by a subject that is neither the admin nor an enabled KYC provider; or a provider disabled
    ///         before it was ever enabled.
    error NotKycProvider();
    /// @notice `setKycProvider(0, …)`: 0 is what a router read outside a live call answers (Fable P3).
    error KycProviderZero();
    /// @notice More than 256 rows in one `setCompliance` (the node's decode bound, spec §5.3.1).
    error TooManyRows(uint256 n);
    error LengthMismatch();
    /// @notice `ELIGIBLE_CONTRACT` (8) set by anyone but the admin, or with a `validUntil` other than `type(uint64).max`
    ///         (CTR-AS-16).
    error EligibleContractAdminOnly();
    /// @notice A KYC provider (id != 0) wrote over or revoked a row the admin wrote: a stored `providerId == 0` with
    ///         `flags != 0` (owner 2026-11-06). An empty slot and an admin row of flags 0 stay open.
    error AdminWrittenSlot(bytes32 account);

    /// @notice The one router whose `subject()` the registry asks (0 = none), written once by the constructor. A
    ///         regulated token takes only a registry whose router is 0 or its own (`ComplianceRegistryRouterMismatch`).
    function govRouter() external view returns (address);
    /// @notice Admin only. A KYC provider's id is assigned at its first enabling and never reused; id 0 is the admin.
    function setKycProvider(bytes32 provider, bool enabled) external;
    function kycProviderId(bytes32 provider) external view returns (uint32);
    /// @notice Id 0 (the admin) is always enabled; an id never assigned is not.
    function kycProviderEnabled(uint32 id) external view returns (bool);
    /// @notice The subject (`pad(msg.sender)`, or the router's `subject()`): the admin (id 0) or an enabled KYC provider
    ///         (its id), at most 256 rows. Flags 0 revoke. `ELIGIBLE_CONTRACT` only by the admin, with
    ///         `until == type(uint64).max` (CTR-AS-16). A row the admin wrote (`providerId == 0 && flags != 0`) only the
    ///         admin overwrites or revokes; a KYC provider gets `AdminWrittenSlot` (owner 2026-11-06). `until` is the
    ///         row's `validUntil` (the router's envelope has a `validUntil` of its own).
    function setCompliance(bytes32[] calldata accounts, uint64[] calldata flags, uint64[] calldata until) external;
    function complianceOf(bytes32 account) external view returns (uint64 flags, uint64 validUntil, uint32 providerId);
    /// @notice `(required == 0 || (active && ((f & required) == required || f & ELIGIBLE_CONTRACT != 0)))
    ///         && !(active && f & denied != 0)`, `active = kycProviderEnabled(id) && validUntil >= now`.
    function hasFlags(bytes32 account, uint64 required, uint64 denied) external view returns (bool);
}
