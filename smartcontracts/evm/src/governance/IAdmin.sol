// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title One admin per contract (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §4.1): every admin has this one selector
///        set and error shape. The admin is a UA id (`bytes32`); a transfer takes two steps, `transferAdmin(next, chainUid_)`
///        then `next`'s `acceptAdmin()`. `IGovernance` adds `renounceAdmin(chainUid_)`. UNAUDITED.
interface IAdmin {
    event AdminTransferStarted(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);
    event AdminTransferred(bytes32 indexed previousAdmin, bytes32 indexed newAdmin);

    error NotAdmin(bytes32 caller);
    error NotPendingAdmin(bytes32 caller);
    /// @notice An admin entry's `chainUid_` is not this contract's chain word (`expected`; Fable recheck-2 P3-1,
    ///         CTR-GOV-27): a native admin's direct call made for a sibling with the same chain id is void here.
    error ChainUidMismatch(bytes32 expected, bytes32 got);

    function admin() external view returns (bytes32);
    function pendingAdmin() external view returns (bytes32);
    /// @notice The admin names its successor (0 cancels a pending); the admin first (`NotAdmin`), then `chainUid_` this
    ///         contract's word (`ChainUidMismatch`), before any write (CTR-GOV-27).
    function transferAdmin(bytes32 newAdmin, bytes32 chainUid_) external;
    function acceptAdmin() external;
}
