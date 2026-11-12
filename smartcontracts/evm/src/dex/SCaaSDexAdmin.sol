// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";

/// @title The DEX's governance hooks (T66b, spec 2026-11-09-t66b-library-organisation.md §4.2, owner 2026-11-09 ruling (a)):
///        one definition, inherited by `SCaaSDex` and by its governance module `SCaaSDexGovernanceModule`, so a governance
///        body runs under the same rules in both. No state of its own: the DEX's state is in its ERC-7201 namespaces
///        (`scaas.dex`, the governance and trade ones) and its guard is transient. UNAUDITED.
abstract contract SCaaSDexGovernance is ReentrancyGuardTransient, GovernanceBaseCore {
    /// @notice The governance module's `moduleGroup()` (`script/modules/gen_faces.py` `GROUP_ID`).
    uint8 internal constant GROUP_GOVERNANCE = 10;

    constructor() GovernanceBaseCore(address(0)) {}

    /// @dev A governance entry never runs inside a settlement: no outside call of a running plan reaches it.
    function _guardIn() internal view override returns (bool) {
        if (_reentrancyGuardEntered()) revert ReentrancyGuardReentrantCall();
        return false;
    }

    function _guardOut(bool) internal pure override {}

    /// @dev An admin or holder that is an EIP-7702 designator is refused (owner ruling 2026-10-30, D2).
    function _caller() internal view override returns (address) {
        SigCheck.requireNotDelegated(msg.sender);
        return msg.sender;
    }

    function _validBits() internal pure override returns (uint256) { return GovernanceBits.DEX_VALID; }
    function _roleBits() internal pure override returns (uint256) { return GovernanceBits.DEX_BITS; }
    function _contractOnlyBits() internal pure override returns (uint256) { return 0; }
    function _scalarBits() internal pure override returns (uint256) { return 0; }
    function _scopeBits() internal pure override returns (uint256) { return 0; }

    function _govRouter() internal view override returns (address) { return ChainEnvCode.govRouter(); }

    function _govChainUid() internal view override returns (bytes32) { return ChainEnvCode.chainUid(); }
}

/// @title SCaaSDexGovernanceModule: the DEX's governance module (named D until owner ruling R7, 2026-11-10; T66b, spec §4.2,
///        owner 2026-11-09 ruling (a)): its 22 governance entries, reached only by DELEGATECALL from the DEX's stubs (M2;
///        `validBits` is `pure` and reads nothing), no guard of its own (the stub's `_forward` holds it, M3), no state of its
///        own (M6). UNAUDITED.
contract SCaaSDexGovernanceModule is SCaaSDexGovernance {
    /// @notice A module-face entry called other than by DELEGATECALL from its DEX (M2).
    error NotDelegated();

    address private immutable _SELF = address(this);
    address private immutable _FACTORY;

    modifier onlyDelegated() {
        if (address(this) == _SELF) revert NotDelegated();
        _;
    }

    /// @param factory_ the DEX's factory (the DEX's own constructor argument; M1); the bytes are the DEX's, unused.
    constructor(address factory_, bytes memory) {
        _FACTORY = factory_;
    }

    function moduleGroup() external pure returns (uint8) { return GROUP_GOVERNANCE; }

    /// @notice The factory of the DEX releases this module serves (checked by `SCaaSDex`'s constructor).
    function factory() external view returns (address) { return _FACTORY; }

    function GOV_ROUTER() external view onlyDelegated returns (address) { return _GOV_ROUTERBody(); }
    function features() external view onlyDelegated returns (uint256) { return _featuresBody(); }
    function lockedFeatures() external view onlyDelegated returns (uint256) { return _lockedFeaturesBody(); }
    function admin() external view onlyDelegated returns (bytes32) { return _adminBody(); }
    function pendingAdmin() external view onlyDelegated returns (bytes32) { return _pendingAdminBody(); }

    function hasRole(uint8 bit, bytes32 account) external view onlyDelegated returns (bool) {
        return _hasRoleBody(bit, account);
    }

    function validBits() external pure returns (uint256) { return _validBitsBody(); }
    function holderCount(uint8 bit) external view onlyDelegated returns (uint256) { return _holderCountBody(bit); }
    function grantDelay() external view onlyDelegated returns (uint64) { return _grantDelayBody(); }
    function lastProposedAt() external view onlyDelegated returns (uint64) { return _lastProposedAtBody(); }

    function pendingGrant(uint8 bit, bytes32 account) external view onlyDelegated returns (uint64, bytes32, bytes32, bool) {
        return _pendingGrantBody(bit, account);
    }

    function grantOf(uint8 bit, bytes32 holder) external view onlyDelegated returns (IGovernance.Grant memory) {
        return _grantOfBody(bit, holder);
    }

    function bitLabel(uint8 bit) external view onlyDelegated returns (IGovernance.BitType, bytes4, string memory) {
        return _bitLabelBody(bit);
    }

    function grantRole(uint8 bit, bytes32 account, bytes32 chainUid_) external onlyDelegated {
        _grantRoleBody(bit, account, chainUid_);
    }

    function setGrant(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata terms, bytes32 chainUid_)
        external
        onlyDelegated
    {
        _setGrantBody(bit, holder, terms, chainUid_);
    }

    function cancelGrant(uint8 bit, bytes32 account, bytes32 chainUid_) external onlyDelegated {
        _cancelGrantBody(bit, account, chainUid_);
    }
    function revokeRole(uint8 bit, bytes32 account, bytes32 chainUid_) external onlyDelegated {
        _revokeRoleBody(bit, account, chainUid_);
    }
    function renounceRole(uint8 bit) external onlyDelegated { _renounceRoleBody(bit); }
    function disableFeature(uint8 bit, bytes32 chainUid_) external onlyDelegated { _disableFeatureBody(bit, chainUid_); }
    function transferAdmin(bytes32 newAdmin, bytes32 chainUid_) external onlyDelegated {
        _transferAdminBody(newAdmin, chainUid_);
    }
    function acceptAdmin() external onlyDelegated { _acceptAdminBody(); }
    function renounceAdmin(bytes32 chainUid_) external onlyDelegated { _renounceAdminBody(chainUid_); }
}
