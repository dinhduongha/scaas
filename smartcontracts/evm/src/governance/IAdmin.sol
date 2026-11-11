// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title One admin per contract (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §4.1): every admin has this one selector
///        set and error shape. The admin is a UA id (`bytes32`); a transfer takes two steps, `transferAdmin(next)` then
///        `next`'s `acceptAdmin()`. `IGovernance` adds `renounceAdmin()`. UNAUDITED.
interface IAdmin {
    event AdminTransferStarted(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);
    event AdminTransferred(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);

    error NotAdmin(bytes32 caller);
    error NotPendingAdmin(bytes32 caller);

    function admin() external view returns (bytes32);
    function pendingAdmin() external view returns (bytes32);
    function transferAdmin(bytes32 newAdmin) external;
    function acceptAdmin() external;
}
