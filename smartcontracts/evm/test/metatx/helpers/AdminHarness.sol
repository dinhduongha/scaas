// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {AdminLib} from "../../../src/metatx/AdminLib.sol";

/// Exposes `AdminLib` on its own storage, for every kind (the built tokens use NONE and, transitionally, UNDERLYING).
contract AdminHarness {
    function init(uint8 kind, uint256 features_, uint256 locked, address owner_, AdminLib.Roles memory roles) external {
        AdminLib.init(kind, features_, locked, owner_, roles);
    }

    function grantRole(uint8 bit, address account) external { AdminLib.grantRole(bit, account, msg.sender); }
    function revokeRole(uint8 bit, address account) external { AdminLib.revokeRole(bit, account, msg.sender); }
    function renounceRole(uint8 bit) external { AdminLib.renounceRole(bit, msg.sender); }
    function disableFeature(uint8 bit) external { AdminLib.disableFeature(bit, msg.sender); }
    function transferOwnership(address o) external { AdminLib.transferOwnership(o, msg.sender); }
    function acceptOwnership() external { AdminLib.acceptOwnership(msg.sender); }
    function renounceOwnership() external { AdminLib.renounceOwnership(msg.sender); }

    function features() external view returns (uint256) { return AdminLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return AdminLib.$().lockedFeatures; }
    function owner() external view returns (address) { return AdminLib.$().owner; }
    function pendingOwner() external view returns (address) { return AdminLib.$().pendingOwner; }
    function hasRole(uint8 bit, address a) external view returns (bool) { return AdminLib.hasRole(bit, a); }
    function requireRole(uint8 bit, address a) external view { AdminLib.requireRole(bit, a); }
}
