// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The governance surface of every SCaaS contract (CTR-GOV-01, CTR-TOK-22); events and errors raised by
///        `GovernanceLib`. Every name of the former `ITokenAdmin` is kept.
interface IGovernance {
    /// @notice A capability has no holder and binds or serves everyone; a power has holders. The type is `_roleBits()`.
    enum BitType { CAPABILITY, POWER }

    /// @notice What a grantor chooses (CTR-GOV-02). 0 = no bound, except `max`: `type(uint128).max` = no bound. `delegable`
    ///         only from the owner: a leaf cannot delegate. `scope` is opaque to the base; the contract reads it.
    struct GrantTerms {
        uint128 min;
        uint128 max;
        uint128 total;
        uint128 perWindow;
        uint32 window;
        uint64 validUntil;
        uint32 maxUses;
        bool delegable;
        bytes32 scope;
    }

    /// @notice A limited holder's record: the terms plus what has been spent, which an edit carries (six slots).
    struct Grant {
        uint128 min;
        uint128 max;
        uint128 total;
        uint128 spentTotal;
        uint128 perWindow;
        uint128 spentInWindow;
        uint32 window;
        uint32 windowStart;
        uint64 validUntil;
        uint32 maxUses;
        uint32 uses;
        bytes32 scope;
        address grantor;
        uint32 grantorEpoch;
        bool delegable;
    }

    event RoleGranted(uint8 indexed bit, address indexed account, address indexed sender);
    event RoleRevoked(uint8 indexed bit, address indexed account, address indexed sender);
    event FeatureDisabled(uint8 indexed bit, address indexed by);
    event GrantSet(uint8 indexed bit, address indexed holder, address indexed grantor);
    event GrantUsed(uint8 indexed bit, address indexed holder, uint256 scalar);
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
    /// @notice A leaf's term is wider than its parent's (`field`: 0 min, 1 max, 2 total, 3 perWindow, 4 validUntil, 5 maxUses,
    ///         6 delegable, 7 scope).
    error GrantNotNarrower(uint8 field);
    /// @notice The scalar or the use is outside the grant (`field`: 0 min, 1 max, 2 total, 3 perWindow, 5 maxUses, 7 parent).
    error GrantExhausted(uint8 field);
    error GrantExpired(uint8 bit, address holder);
    /// @notice `renounceOwnership` while a bit that is not locked has holders (CTR-GOV-02).
    error OwnerHasHolders(uint8 bit);

    function features() external view returns (uint256);
    function lockedFeatures() external view returns (uint256);
    function owner() external view returns (address);
    function pendingOwner() external view returns (address);
    function hasRole(uint8 bit, address account) external view returns (bool);
    function validBits() external view returns (uint256);
    function holderCount(uint8 bit) external view returns (uint256);
    function grantOf(uint8 bit, address holder) external view returns (Grant memory);
    function setGrant(uint8 bit, address holder, GrantTerms calldata terms) external;
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
