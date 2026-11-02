// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceLib} from "../../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../../src/metatx/TokenStore.sol";

/// Exposes `GovernanceLib` on its own storage, for every kind (the built tokens use NORMAL and, transitionally, WRAPPED).
contract AdminHarness {
    function init(uint8 kind, uint256 features_, uint256 locked, address owner_, GovernanceLib.Roles memory roles) external {
        GovernanceLib.init(features_, locked, owner_, roles, _validFor(kind), GovernanceBits.TOKEN_ROLES,
            GovernanceBits.TOKEN_CONTRACT_ONLY);
    }

    /// The per-kind masks the token kinds declare (`_validBits()`), by kind id; an unknown kind has no valid flag.
    function _validFor(uint8 kind) private pure returns (uint256) {
        if (kind == TokenStore.KIND_NORMAL) return GovernanceBits.NORMAL_BITS | GovernanceBits.REGULATED;
        if (kind == TokenStore.KIND_WRAPPED) return GovernanceBits.WRAPPED_BITS | GovernanceBits.REGULATED;
        if (kind == TokenStore.KIND_NORMAL_ZETHER || kind == TokenStore.KIND_NORMAL_PQZ) return GovernanceBits.NORMAL_BITS;
        if (kind == TokenStore.KIND_WRAPPED_ZETHER || kind == TokenStore.KIND_WRAPPED_PQZ) return GovernanceBits.WRAPPED_BITS;
        return 0;
    }

    function grantRole(uint8 bit, address account) external { GovernanceLib.grantRole(bit, account, msg.sender, GovernanceBits.TOKEN_ROLES, GovernanceBits.TOKEN_CONTRACT_ONLY); }
    function revokeRole(uint8 bit, address account) external { GovernanceLib.revokeRole(bit, account, msg.sender); }
    function renounceRole(uint8 bit) external { GovernanceLib.renounceRole(bit, msg.sender); }
    function disableFeature(uint8 bit) external { GovernanceLib.disableFeature(bit, msg.sender); }
    function transferOwnership(address o) external { GovernanceLib.transferOwnership(o, msg.sender); }
    function acceptOwnership() external { GovernanceLib.acceptOwnership(msg.sender); }
    function renounceOwnership() external { GovernanceLib.renounceOwnership(msg.sender); }

    function features() external view returns (uint256) { return GovernanceLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return GovernanceLib.$().lockedFeatures; }
    function owner() external view returns (address) { return GovernanceLib.$().owner; }
    function pendingOwner() external view returns (address) { return GovernanceLib.$().pendingOwner; }
    function hasRole(uint8 bit, address a) external view returns (bool) { return GovernanceLib.hasRole(bit, a); }
    function requireRole(uint8 bit, address a) external view { GovernanceLib.requireRole(bit, a); }
}
