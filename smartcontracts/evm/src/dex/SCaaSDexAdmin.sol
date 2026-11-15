// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {GovernanceBaseCore} from "../governance/GovernanceBase.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {GovernanceUse} from "../governance/GovernanceBase.sol";
import {ISCaaSDex} from "./ISCaaSDex.sol";
import {SCaaSDexCore} from "./SCaaSDexCore.sol";

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
///        owner 2026-11-09 ruling (a)): its 26 entries (22 governance; the four powers `setMarket`, `setExchangeTarget`,
///        `setListedOnly`, `setFeeSplit` since round 3zb + 3zc, O8, CTR-TOK-30 Change), reached only by DELEGATECALL from the DEX's
///        stubs (M2; `validBits` is `pure` and reads nothing), no guard of its own (the stub's `_forward` holds it, M3), no
///        state of its own (M6): it writes `scaas.dex` and `scaas.governance` at the DEX's slots. UNAUDITED.
contract SCaaSDexGovernanceModule is SCaaSDexGovernance, SCaaSDexCore {
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
    function renounceRole(uint8 bit, bytes32 chainUid_) external onlyDelegated {
        _renounceRoleBody(bit, chainUid_);
    }
    function disableFeature(uint8 bit, bytes32 chainUid_) external onlyDelegated { _disableFeatureBody(bit, chainUid_); }
    function transferAdmin(bytes32 newAdmin, bytes32 chainUid_) external onlyDelegated {
        _transferAdminBody(newAdmin, chainUid_);
    }
    function acceptAdmin() external onlyDelegated { _acceptAdminBody(); }
    function renounceAdmin(bytes32 chainUid_) external onlyDelegated { _renounceAdminBody(chainUid_); }

    // ------------------------------------------------------------------ the powers (O8, CTR-TOK-30 Change; bodies moved verbatim)

    /// @dev The DEX's factory: this module's immutable, equal to the DEX's (its constructor checks `factory()`).
    function _factoryAt() internal view override returns (address) { return _FACTORY; }

    /// @dev A power: the holder's chain word (CTR-GOV-28 Change, `_holderOnChain`) before the use and any write.
    function _power(uint8 bit, bytes32 chainUid_) private returns (DexStorage storage) {
        GovernanceUse.use(bit, _holderOnChain(bit, chainUid_), 0);
        return _s();
    }

    /// @notice Lists or delists the pair and records each token's kind from the factory (never from a leg).
    function setMarket(address base, address quote, bool listed, bytes32 chainUid_) external onlyDelegated {
        DexStorage storage s = _power(GovernanceBits.LISTING, chainUid_);
        if (base == quote || base == address(0) || quote == address(0)) revert ISCaaSDex.BadMarket(base, quote); // C6-9
        bytes32 k = _pair(base, quote);
        if (s.listed[k] != listed) {
            s.listed[k] = listed;
            if (listed) {
                ++s.listings[base];
                ++s.listings[quote];
            } else {
                --s.listings[base];
                --s.listings[quote];
            }
        }
        s.kind[base] = _classify(base);
        s.kind[quote] = _classify(quote);
        emit ISCaaSDex.MarketSet(base, quote, listed);
    }

    function setFeeSplit(uint32 relayerSharePpm_, address treasury_, bytes32 chainUid_) external onlyDelegated {
        _setFeeSplit(_power(GovernanceBits.FEE_ROUTING, chainUid_), relayerSharePpm_, treasury_);
    }

    /// @notice Lists or delists an interaction target or an executor (CTR-DEX-23).
    function setExchangeTarget(address target, bool listed, bytes32 chainUid_) external onlyDelegated {
        _power(GovernanceBits.LISTING, chainUid_).exchangeTarget[target] = listed;
        emit ISCaaSDex.ExchangeTargetSet(target, listed);
    }

    /// @notice DEX-wide listed-only mode for the exchange path (CTR-DEX-23); a leg's `LISTED_POOLS` asks the same.
    function setListedOnly(bool on, bytes32 chainUid_) external onlyDelegated {
        _power(GovernanceBits.LISTING, chainUid_).listedOnly = on;
        emit ISCaaSDex.ListedOnlySet(on);
    }
}
