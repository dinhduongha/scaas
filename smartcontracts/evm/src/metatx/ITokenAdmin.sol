// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title Administration surface of every SCaaS token (CTR-TOK-22); events and errors raised by `AdminLib`.
interface ITokenAdmin {
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

    function features() external view returns (uint256);
    function lockedFeatures() external view returns (uint256);
    function owner() external view returns (address);
    function pendingOwner() external view returns (address);
    function hasRole(uint8 bit, address account) external view returns (bool);
    function grantRole(uint8 bit, address account) external;
    function revokeRole(uint8 bit, address account) external;
    function renounceRole(uint8 bit) external;
    function disableFeature(uint8 bit) external;
    function transferOwnership(address newOwner) external;
    function acceptOwnership() external;
    function renounceOwnership() external;
}
