// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The governance surface of every SCaaS contract (CTR-GOV-01, CTR-TOK-22); events and errors raised by
///        `GovernanceLib`. Every name of the former `ITokenAdmin` is kept.
interface IGovernance {
    /// @notice A capability has no holder and binds or serves everyone; a power has holders. The type is `_roleBits()`.
    enum BitType { CAPABILITY, POWER }

    event RoleGranted(uint8 indexed bit, address indexed account, address indexed sender);
    event RoleRevoked(uint8 indexed bit, address indexed account, address indexed sender);
    event FeatureDisabled(uint8 indexed bit, address indexed by);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error FeatureInvalidForKind(uint8 bit);
    error FeatureNotBuilt(uint8 bit);
    error LockedNotSubset();
    error RoleWithoutFeature(uint8 bit);
    error RoleNotContract(uint8 bit, address account);
    error RoleAccountZero(uint8 bit);
    error NoSuchRole(uint8 bit);
    error FeatureLocked(uint8 bit);
    error FeatureNotSet(uint8 bit);
    error NotOwner(address caller);
    error NotPendingOwner(address caller);
    error MissingRole(uint8 bit, address account);
    /// @notice Bits 128 and above are refused (CTR-GOV-10).
    error FeatureReserved(uint8 bit);
    /// @notice `UA_POOL` and `SHIELD_POOL` hold no power.
    error RoleAccountPool(uint8 bit, address account);

    function features() external view returns (uint256);
    function lockedFeatures() external view returns (uint256);
    function owner() external view returns (address);
    function pendingOwner() external view returns (address);
    function hasRole(uint8 bit, address account) external view returns (bool);
    function validBits() external view returns (uint256);
    /// @notice The label of an application bit (64–127): its type, the entry it gates, a name for a wallet.
    function bitLabel(uint8 bit) external view returns (BitType, bytes4, string memory);
    function grantRole(uint8 bit, address account) external;
    function revokeRole(uint8 bit, address account) external;
    function renounceRole(uint8 bit) external;
    function disableFeature(uint8 bit) external;
    function transferOwnership(address newOwner) external;
    function acceptOwnership() external;
    function renounceOwnership() external;
}
