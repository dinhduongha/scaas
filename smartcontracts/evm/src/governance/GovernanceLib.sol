// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SigCheck} from "../common/SigCheck.sol";
import {IGovernance} from "./IGovernance.sol";
import {GovernanceBits} from "./GovernanceBits.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Features, owner and roles of every SCaaS contract (CTR-GOV-01, CTR-TOK-22), in the ERC-7201 namespace
///        `scaas.governance`.
/// @notice External library: the contract keeps one-line wrappers (`GovernanceBase`), the logic is linked at deploy
///         (CTR-TOK-24). `features`/`lockedFeatures` are written once by `init`; a flag can later only be cleared, once, by
///         the owner and only when not locked. One `owner` (0 = no administration ever) grants and revokes the role of a
///         set flag, disables disableable flags, transfers (two-step) or renounces ownership. Role holders keep their
///         roles after the owner renounces; a holder may renounce its own role.
library GovernanceLib {
    /// @dev The value of `roles` for a whole-shape holder.
    uint8 internal constant WHOLE = 1;

    /// @notice Initial role holders (CTR-TOK-25 `Roles`); each only for a set flag, 0 = none.
    struct Roles {
        address minter;      // MINTABLE
        address rateAdmin;   // RATE_ADJUSTABLE, contract only
        address guardian;    // WRAP_DISABLEABLE
        address issuer;      // FREEZE / FORCE / PAUSE (not built)
        address compliance;  // FORCE / ALLOWLIST (not built)
    }

    /// @custom:storage-location erc7201:scaas.governance
    struct GovernanceStorage {
        uint256 features;
        uint256 lockedFeatures;
        address owner;
        address pendingOwner;
        mapping(uint256 bit => mapping(address account => uint8)) roles;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.governance")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;

    function $() internal pure returns (GovernanceStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init (CTR-TOK-22 "Validation in the token")

    /// @notice Validates the flags against the contract's masks and writes features, owner and initial roles. Called
    ///         once by the contract's `initialize`.
    function init(uint256 features, uint256 locked, address owner, Roles memory roles, uint256 valid, uint256 roleBits,
        uint256 contractOnly) public
    {
        if (features >> 128 != 0) revert IGovernance.FeatureReserved(_lowest(features >> 128) + 128);
        uint256 bad = features & ~valid;
        if (bad != 0) revert IGovernance.FeatureInvalidForKind(_lowest(bad));
        if (features & GovernanceBits.REGULATED != 0) {
            revert IGovernance.FeatureNotBuilt(_lowest(features & GovernanceBits.REGULATED));
        }
        if (locked & ~features != 0) revert IGovernance.LockedNotSubset();
        GovernanceStorage storage s = $();
        s.features = features;
        s.lockedFeatures = locked | (features & GovernanceBits.ALWAYS_LOCKED);
        if (roles.issuer != address(0)) revert IGovernance.RoleWithoutFeature(GovernanceBits.FREEZE);
        if (roles.compliance != address(0)) revert IGovernance.RoleWithoutFeature(GovernanceBits.ALLOWLIST);
        if (roles.minter != address(0)) _grant(s, GovernanceBits.MINTABLE, roles.minter, address(0), roleBits, contractOnly);
        if (roles.rateAdmin != address(0)) {
            _grant(s, GovernanceBits.RATE_ADJUSTABLE, roles.rateAdmin, address(0), roleBits, contractOnly);
        }
        if (roles.guardian != address(0)) {
            _grant(s, GovernanceBits.WRAP_DISABLEABLE, roles.guardian, address(0), roleBits, contractOnly);
        }
        if (owner != address(0)) {
            s.owner = owner;
            emit IGovernance.OwnershipTransferred(address(0), owner);
        }
    }

    // ------------------------------------------------------------------ owner

    function grantRole(uint8 bit, address account, address caller, uint256 roleBits, uint256 contractOnly) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        _grant(s, bit, account, caller, roleBits, contractOnly);
    }

    function revokeRole(uint8 bit, address account, address caller) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        if (s.roles[bit][account] != 0) {
            s.roles[bit][account] = 0;
            emit IGovernance.RoleRevoked(bit, account, caller);
        }
    }

    /// @notice A holder gives up its own role (replaces `renounceMinter`/`renounceRateAdmin`/`renounceGuardian`).
    function renounceRole(uint8 bit, address caller) public {
        GovernanceStorage storage s = $();
        if (s.roles[bit][caller] == 0) revert IGovernance.MissingRole(bit, caller);
        s.roles[bit][caller] = 0;
        emit IGovernance.RoleRevoked(bit, caller, caller);
    }

    /// @notice One-way: clears a set, unlocked flag (replaces `disableControls`).
    function disableFeature(uint8 bit, address caller) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        uint256 m = _bit(bit);
        if ((s.lockedFeatures | GovernanceBits.ALWAYS_LOCKED) & m != 0) revert IGovernance.FeatureLocked(bit);
        if (s.features & m == 0) revert IGovernance.FeatureNotSet(bit);
        s.features &= ~m;
        emit IGovernance.FeatureDisabled(bit, caller);
    }

    function transferOwnership(address newOwner, address caller) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        s.pendingOwner = newOwner;
        emit IGovernance.OwnershipTransferStarted(caller, newOwner);
    }

    function acceptOwnership(address caller) public {
        GovernanceStorage storage s = $();
        if (caller != s.pendingOwner || caller == address(0)) revert IGovernance.NotPendingOwner(caller);
        address previous = s.owner;
        s.owner = caller;
        s.pendingOwner = address(0);
        emit IGovernance.OwnershipTransferred(previous, caller);
    }

    /// @notice The owner becomes 0 forever; role holders keep their roles (to freeze everything, revoke first).
    function renounceOwnership(address caller) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        s.owner = address(0);
        s.pendingOwner = address(0);
        emit IGovernance.OwnershipTransferred(caller, address(0));
    }

    // ------------------------------------------------------------------ checks used inline by the token

    function hasFeature(uint8 bit) internal view returns (bool) {
        return $().features & _bit(bit) != 0;
    }

    function hasRole(uint8 bit, address account) internal view returns (bool) {
        return $().roles[bit][account] != 0;
    }

    /// @dev The flag is set and `account` holds its role.
    function requireRole(uint8 bit, address account) internal view {
        GovernanceStorage storage s = $();
        if (s.features & _bit(bit) == 0) revert IGovernance.FeatureNotSet(bit);
        if (s.roles[bit][account] == 0) revert IGovernance.MissingRole(bit, account);
    }

    function requireFeature(uint8 bit) internal view {
        if ($().features & _bit(bit) == 0) revert IGovernance.FeatureNotSet(bit);
    }

    // ------------------------------------------------------------------ internals

    function _grant(GovernanceStorage storage s, uint8 bit, address account, address caller, uint256 roleBits,
        uint256 contractOnly) private
    {
        if (bit >= 128) revert IGovernance.FeatureReserved(bit);
        if (account == address(0)) revert IGovernance.RoleAccountZero(bit);
        if (account == MetaTxLib.UA_POOL || account == MetaTxLib.SHIELD_POOL) revert IGovernance.RoleAccountPool(bit, account);
        if (roleBits & _bit(bit) == 0) revert IGovernance.NoSuchRole(bit);
        if (s.features & _bit(bit) == 0) revert IGovernance.RoleWithoutFeature(bit);
        if (contractOnly & _bit(bit) != 0 && !SigCheck.isContract(account)) revert IGovernance.RoleNotContract(bit, account);
        if (s.roles[bit][account] != 0) return;
        s.roles[bit][account] = WHOLE;
        emit IGovernance.RoleGranted(bit, account, caller);
    }

    function _onlyOwner(address caller) private view returns (GovernanceStorage storage s) {
        s = $();
        if (caller != s.owner || caller == address(0)) revert IGovernance.NotOwner(caller);
    }

    function _bit(uint8 bit) private pure returns (uint256) {
        return uint256(1) << bit;
    }

    function _lowest(uint256 x) private pure returns (uint8 i) {
        while (x & 1 == 0) { x >>= 1; ++i; }
    }
}
