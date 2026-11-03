// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IGovernance} from "./IGovernance.sol";
import {GovernanceLib} from "./GovernanceLib.sol";

/// @title The one check of a power (CTR-GOV-02, spec §1.3, B-26), inlined into its caller: the flag is set and `account`
///        holds it. A whole-shape holder returns 0 here, with no call; a limited holder's grant binds `scalar`, which must
///        be the number the contract acts on, by one DELEGATECALL to `GovernanceLib.useLimited`, which returns the grant's
///        `scope`. solc refuses a qualified call from `GovernanceLib` into itself, so the fast path lives here.
library GovernanceUse {
    function use(uint8 bit, address account, uint256 scalar) internal returns (bytes32) {
        GovernanceLib.GovernanceStorage storage s = GovernanceLib.$();
        if (s.features & (uint256(1) << bit) == 0) revert IGovernance.FeatureNotSet(bit);
        uint8 r = s.roles[bit][account];
        if (r == GovernanceLib.WHOLE) return bytes32(0);
        if (r == 0) revert IGovernance.MissingRole(bit, account);
        return GovernanceLib.useLimited(bit, account, scalar);
    }
}

/// @title One layer for owner, features and roles (owner 2026-11-02, CTR-GOV-01), for any contract: one-line wrappers
///        over `GovernanceLib`, the masks of compile-time constants, nothing of its own in storage. Every power runs
///        through `GovernanceUse.use`; `hasRole` is a view (listed, not able to act).
abstract contract GovernanceBase is IGovernance {
    /// @dev The contract's guard (`MetaTxBase` on a token, the transient guard's check on the DEX).
    modifier governed() {
        bool outer = _guardIn();
        _;
        _guardOut(outer);
    }

    function _guardIn() internal virtual returns (bool);
    function _guardOut(bool outer) internal virtual;

    /// @dev The caller as this contract authenticates it (`_msgSender()` on a token).
    function _caller() internal view virtual returns (address);

    /// @dev Bits this contract implements (both bands).
    function _validBits() internal pure virtual returns (uint256);
    /// @dev Subset with a holder; a valid bit outside it is a capability.
    function _roleBits() internal pure virtual returns (uint256);
    /// @dev Subset whose holder must have code.
    function _contractOnlyBits() internal pure virtual returns (uint256);
    /// @dev Subset whose power passes the number it acts on to `use` (B-09).
    function _scalarBits() internal pure virtual returns (uint256);
    /// @dev Subset whose power reads `use`'s returned scope (B-10).
    function _scopeBits() internal pure virtual returns (uint256);

    /// @dev Whether `child` narrows `parent` for `bit`: equality unless the contract defines an order on its scopes.
    function _scopeNarrows(uint8, bytes32 parent, bytes32 child) internal view virtual returns (bool) {
        return parent == child;
    }

    function features() external view returns (uint256) { return GovernanceLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return GovernanceLib.$().lockedFeatures; }
    function owner() external view returns (address) { return GovernanceLib.$().owner; }
    function pendingOwner() external view returns (address) { return GovernanceLib.$().pendingOwner; }
    function hasRole(uint8 bit, address account) external view returns (bool) { return GovernanceLib.hasRole(bit, account); }
    function validBits() external pure returns (uint256) { return _validBits(); }
    function holderCount(uint8 bit) external view returns (uint256) { return GovernanceLib.$().counts[bit].holders; }
    function grantOf(uint8 bit, address holder) external view returns (Grant memory) {
        return GovernanceLib.$().grants[bit][holder];
    }

    /// @notice Bits 64–127 only; a contract with no application bit answers with a refusal.
    function bitLabel(uint8 bit) external view virtual returns (BitType, bytes4, string memory) {
        revert FeatureInvalidForKind(bit);
    }

    function grantRole(uint8 bit, address account) external governed {
        GovernanceLib.grantRole(bit, account, _caller(), _roleBits(), _contractOnlyBits());
    }
    /// @notice The owner sets any holder's grant; a holder with a `delegable` grant sets a narrower leaf. Spent is carried.
    function setGrant(uint8 bit, address holder, GrantTerms calldata terms) external governed {
        (bool leaf, bytes32 parentScope) =
            GovernanceLib.setGrant(bit, holder, terms, _caller(), _roleBits(), _contractOnlyBits());
        if (leaf && !_scopeNarrows(bit, parentScope, terms.scope)) revert GrantNotNarrower(7);
    }

    function revokeRole(uint8 bit, address account) external governed { GovernanceLib.revokeRole(bit, account, _caller()); }
    function renounceRole(uint8 bit) external governed { GovernanceLib.renounceRole(bit, _caller()); }
    function disableFeature(uint8 bit) external virtual governed { GovernanceLib.disableFeature(bit, _caller()); }
    function transferOwnership(address newOwner) external governed { GovernanceLib.transferOwnership(newOwner, _caller()); }
    function acceptOwnership() external governed { GovernanceLib.acceptOwnership(_caller()); }
    function renounceOwnership() external governed { GovernanceLib.renounceOwnership(_caller(), _roleBits()); }
}
