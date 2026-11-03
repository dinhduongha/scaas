// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceLib} from "../../../src/governance/GovernanceLib.sol";
import {GovernanceUse} from "../../../src/governance/GovernanceBase.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../../src/metatx/TokenStore.sol";

/// Exposes `GovernanceLib` on its own storage, for every kind, with the masks that kind passes (spec §1.2, GD-19).
contract GovernanceLibHarness {
    uint8 internal k;

    function init(uint8 kind, uint256 features_, uint256 locked, address owner_, GovernanceLib.Roles memory roles) external {
        k = kind;
        GovernanceLib.init(features_, locked, owner_, roles, _validFor(kind), _roles(), _contractOnly());
    }

    /// The valid mask each kind passes to `init`: the plain kinds `_validBits() | REGULATED`, so 5-9 reach
    /// `FeatureNotBuilt`; the confidential kinds `_validBits()`; an unknown kind has no valid flag.
    function _validFor(uint8 kind) private pure returns (uint256) {
        if (kind == TokenStore.KIND_NORMAL) return GovernanceBits.NORMAL_BITS | GovernanceBits.REGULATED;
        if (kind == TokenStore.KIND_WRAPPED) return GovernanceBits.WRAPPED_BITS | GovernanceBits.REGULATED;
        if (kind == TokenStore.KIND_NORMAL_ZETHER || kind == TokenStore.KIND_NORMAL_PQZ) return GovernanceBits.NORMAL_BITS;
        if (kind == TokenStore.KIND_WRAPPED_ZETHER || kind == TokenStore.KIND_WRAPPED_PQZ) return GovernanceBits.WRAPPED_BITS;
        return 0;
    }

    function _wrapped() private view returns (bool) {
        return k == TokenStore.KIND_WRAPPED || k == TokenStore.KIND_WRAPPED_ZETHER || k == TokenStore.KIND_WRAPPED_PQZ;
    }

    function _roles() private view returns (uint256) {
        return _wrapped() ? GovernanceBits.WRAPPED_ROLES : GovernanceBits.NORMAL_ROLES;
    }

    function _contractOnly() private view returns (uint256) {
        return _wrapped() ? GovernanceBits.WRAPPED_CONTRACT_ONLY : 0;
    }

    function grantRole(uint8 bit, address account) external { GovernanceLib.grantRole(bit, account, msg.sender, _roles(), _contractOnly()); }
    function revokeRole(uint8 bit, address account) external { GovernanceLib.revokeRole(bit, account, msg.sender); }
    function renounceRole(uint8 bit) external { GovernanceLib.renounceRole(bit, msg.sender); }
    function disableFeature(uint8 bit) external { GovernanceLib.disableFeature(bit, msg.sender); }
    function transferOwnership(address o) external { GovernanceLib.transferOwnership(o, msg.sender); }
    function acceptOwnership() external { GovernanceLib.acceptOwnership(msg.sender); }
    function renounceOwnership() external { GovernanceLib.renounceOwnership(msg.sender, _roles()); }
    function use(uint8 bit, address a) external returns (bytes32) { return GovernanceUse.use(bit, a, 0); }

    function features() external view returns (uint256) { return GovernanceLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return GovernanceLib.$().lockedFeatures; }
    function owner() external view returns (address) { return GovernanceLib.$().owner; }
    function pendingOwner() external view returns (address) { return GovernanceLib.$().pendingOwner; }
    function hasRole(uint8 bit, address a) external view returns (bool) { return GovernanceLib.hasRole(bit, a); }
}
