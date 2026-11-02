// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IGovernance} from "./IGovernance.sol";
import {GovernanceLib} from "./GovernanceLib.sol";

/// @title One layer for owner, features and roles (owner 2026-11-02, CTR-GOV-01), for any contract: one-line wrappers
///        over `GovernanceLib`, three masks of compile-time constants, nothing of its own in storage. Prototype.
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

    function features() external view returns (uint256) { return GovernanceLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return GovernanceLib.$().lockedFeatures; }
    function owner() external view returns (address) { return GovernanceLib.$().owner; }
    function pendingOwner() external view returns (address) { return GovernanceLib.$().pendingOwner; }
    function hasRole(uint8 bit, address account) external view returns (bool) { return GovernanceLib.hasRole(bit, account); }
    function validBits() external pure returns (uint256) { return _validBits(); }

    /// @notice Bits 64–127 only; a contract with no application bit answers with a refusal.
    function bitLabel(uint8 bit) external view virtual returns (BitType, bytes4, string memory) {
        revert FeatureInvalidForKind(bit);
    }

    function grantRole(uint8 bit, address account) external governed {
        GovernanceLib.grantRole(bit, account, _caller(), _roleBits(), _contractOnlyBits());
    }
    function revokeRole(uint8 bit, address account) external governed { GovernanceLib.revokeRole(bit, account, _caller()); }
    function renounceRole(uint8 bit) external governed { GovernanceLib.renounceRole(bit, _caller()); }
    function disableFeature(uint8 bit) external virtual governed { GovernanceLib.disableFeature(bit, _caller()); }
    function transferOwnership(address newOwner) external governed { GovernanceLib.transferOwnership(newOwner, _caller()); }
    function acceptOwnership() external governed { GovernanceLib.acceptOwnership(_caller()); }
    function renounceOwnership() external governed { GovernanceLib.renounceOwnership(_caller()); }
}
