// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceLib} from "../../../src/governance/GovernanceLib.sol";
import {GovernanceUse} from "../../../src/governance/GovernanceBase.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../../src/metatx/TokenStore.sol";
import {nid} from "../../helpers/Ids.sol";

/// Exposes `GovernanceLib` on its own storage, for every kind, with the masks that kind passes (spec §1.2, GD-19).
contract GovernanceLibHarness {
    uint8 internal k;

    function init(uint8 kind, uint256 features_, uint256 locked, bytes32 owner_, GovernanceLib.Roles memory roles) external {
        k = kind;
        GovernanceLib.init(features_, locked, owner_, 0, address(0), roles, _validFor(kind), _roles(), _contractOnly(),
            address(0));
    }

    /// The valid mask each kind passes to `init`: `_validBits()`, so 5-9 reach `FeatureInvalidForKind` on every plain kind
    /// (ua-mtx-merge T24, regulated-kinds spec Q3: before, `NORMAL` and `WRAPPED` passed `| REGULATED` and reached
    /// `FeatureNotBuilt`); an unknown kind has no valid flag.
    function _validFor(uint8 kind) private pure returns (uint256) {
        if (kind == TokenStore.KIND_NORMAL) return GovernanceBits.NORMAL_BITS;
        if (kind == TokenStore.KIND_WRAPPED) return GovernanceBits.WRAPPED_BITS;
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

    function grantRole(uint8 bit, bytes32 account) external {
        GovernanceLib.grantRole(bit, account, nid(msg.sender), _roles(), _contractOnly(), address(0));
    }
    function revokeRole(uint8 bit, bytes32 account) external { GovernanceLib.revokeRole(bit, account, nid(msg.sender), 0); }
    function renounceRole(uint8 bit) external { GovernanceLib.renounceRole(bit, nid(msg.sender), 0); }
    function disableFeature(uint8 bit) external { GovernanceLib.disableFeature(bit, nid(msg.sender), 0); }
    function transferOwnership(bytes32 o) external { GovernanceLib.transferOwnership(o, nid(msg.sender)); }
    function acceptOwnership() external { GovernanceLib.acceptOwnership(nid(msg.sender)); }
    function renounceOwnership() external { GovernanceLib.renounceOwnership(nid(msg.sender), _roles()); }
    function use(uint8 bit, bytes32 a) external returns (bytes32) { return GovernanceUse.use(bit, a, 0); }

    function features() external view returns (uint256) { return GovernanceLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return GovernanceLib.$().lockedFeatures; }
    function owner() external view returns (bytes32) { return GovernanceLib.$().owner; }
    function pendingOwner() external view returns (bytes32) { return GovernanceLib.$().pendingOwner; }
    function hasRole(uint8 bit, bytes32 a) external view returns (bool) { return GovernanceLib.hasRole(bit, a); }
}
