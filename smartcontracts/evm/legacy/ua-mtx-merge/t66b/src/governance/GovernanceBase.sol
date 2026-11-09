// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IGovernance} from "./IGovernance.sol";
import {GovernanceLib} from "./GovernanceLib.sol";
import {IGovernanceRouter} from "./IGovernanceRouter.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title The one check of a power (CTR-GOV-02, spec §1.3, B-26), inlined into its caller: the flag is set and `account`
///        holds it. A whole-shape holder returns 0 here, with no call; a limited holder's grant binds `scalar`, which must
///        be the number the contract acts on, by one DELEGATECALL to `GovernanceLib.useLimited`, which returns the grant's
///        `scope`. solc refuses a qualified call from `GovernanceLib` into itself, so the fast path lives here.
library GovernanceUse {
    function use(uint8 bit, bytes32 account, uint256 scalar) internal returns (bytes32) {
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
///        through `GovernanceUse.use`; `hasRole` is a view (listed, not able to act). Every identity is a UA id
///        (`bytes32`, CTR-GOV-01 Change, owner 2026-11-04), and `_govSubject()` names the caller.
abstract contract GovernanceBase is IGovernance {
    /// @dev This chain's router, a constructor immutable; 0 on a factory-made contract, which reads its clone's code.
    address private immutable _GOV_ROUTER;

    constructor(address govRouter) {
        _GOV_ROUTER = govRouter;
    }

    /// @notice This chain's `GovernanceRouter` (0 = none on this chain): a call from it acts for the UA it authenticated
    ///         (spec `2026-11-04-governance-ua-identity.md` §2). Factory-made: the instance's `ChainEnv.govRouter`, from its
    ///         clone's code (CTR-TOK-29; the name of the immutable it was).
    function GOV_ROUTER() external view returns (address) {
        return _govRouter();
    }

    function _govRouter() internal view virtual returns (address) { return _GOV_ROUTER; }

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

    /// @dev The subject of every governance check and every power's entry: from the router, the UA it authenticated for
    ///      this call (0 outside a live call, which every check refuses); from any other caller, its native id. A router
    ///      0 is no router: no caller is asked for a subject. No signature is verified here.
    function _govSubject() internal view returns (bytes32) {
        address r = _govRouter();
        if (r != address(0) && msg.sender == r) return IGovernanceRouter(msg.sender).subject();
        return MetaTxLib.pad(_caller());
    }

    /// @dev Bits this contract implements, in both bands: SCaaS's 0-127 and the application's 128-255 (CTR-GOV-10). A bit
    ///      outside it is refused by `init` (`FeatureInvalidForKind`), so the mask is the only band check.
    function _validBits() internal pure virtual returns (uint256);
    /// @dev Subset with a holder; a valid bit outside it is a capability.
    function _roleBits() internal pure virtual returns (uint256);
    /// @dev Subset whose holder must have code.
    function _contractOnlyBits() internal pure virtual returns (uint256);
    /// @dev Subset whose power passes the number it acts on to `use` (B-09).
    function _scalarBits() internal pure virtual returns (uint256);
    /// @dev Subset whose power reads `use`'s returned scope (B-10).
    function _scopeBits() internal pure virtual returns (uint256);
    /// @dev Subset whose relaxation (revoke, renounce, disable, a `validUntil` cut) waits `grantDelay` (CTR-GOV-09,
    ///      regulated-kinds spec §3.6): 5, 6, 7 on the regulated kinds 8-13; none elsewhere.
    function _delayedRelaxBits() internal pure virtual returns (uint256) { return 0; }
    /// @dev The UA registry a grant asks `kindOf` of a derived holder of a regulated contract-only bit (RK-1); 0 = none,
    ///      so no derived id holds such a bit.
    function _uaRegistry() internal view virtual returns (address) { return address(0); }

    /// @dev Whether `child` narrows `parent` for `bit`: equality unless the contract defines an order on its scopes.
    function _scopeNarrows(uint8, bytes32 parent, bytes32 child) internal view virtual returns (bool) {
        return parent == child;
    }

    function features() external view returns (uint256) { return GovernanceLib.$().features; }
    function lockedFeatures() external view returns (uint256) { return GovernanceLib.$().lockedFeatures; }
    function owner() external view returns (bytes32) { return GovernanceLib.$().owner; }
    function pendingOwner() external view returns (bytes32) { return GovernanceLib.$().pendingOwner; }
    function hasRole(uint8 bit, bytes32 account) external view returns (bool) { return GovernanceLib.hasRole(bit, account); }
    function validBits() external pure returns (uint256) { return _validBits(); }
    function holderCount(uint8 bit) external view returns (uint256) { return GovernanceLib.$().counts[bit].holders; }
    function grantDelay() external view returns (uint64) { return GovernanceLib.$().grantDelay; }
    function lastProposedAt() external view returns (uint64) { return GovernanceLib.$().lastProposedAt; }
    function pendingGrant(uint8 bit, bytes32 account) external view returns (uint64, bytes32, bytes32, bool) {
        return GovernanceLib.pendingGrant(bit, account);
    }
    function grantOf(uint8 bit, bytes32 holder) external view returns (Grant memory) {
        return GovernanceLib.$().grants[bit][holder];
    }

    /// @notice Bits 128-255 only (CTR-GOV-10); a contract with no application bit answers with a refusal.
    function bitLabel(uint8 bit) external view virtual returns (BitType, bytes4, string memory) {
        revert FeatureInvalidForKind(bit);
    }

    function grantRole(uint8 bit, bytes32 account) external governed {
        GovernanceLib.grantRole(bit, account, _govSubject(), _roleBits(), _contractOnlyBits(), _uaRegistry());
    }
    /// @notice The owner sets any holder's grant, a widening in two calls (spec §1.6); a holder with a `delegable` grant sets
    ///         a narrower leaf at once. Spent is carried.
    function setGrant(uint8 bit, bytes32 holder, GrantTerms calldata terms) external governed {
        (bool leaf, bytes32 parentScope) = GovernanceLib.setGrant(bit, holder, terms, _govSubject(), _roleBits(),
            _contractOnlyBits(), _scalarBits(), _scopeBits(), _uaRegistry(), _delayedRelaxBits());
        if (leaf && !_scopeNarrows(bit, parentScope, terms.scope)) revert GrantNotNarrower(7);
    }

    function cancelGrant(uint8 bit, bytes32 account) external governed {
        GovernanceLib.cancelGrant(bit, account, _govSubject());
    }
    function revokeRole(uint8 bit, bytes32 account) external governed {
        GovernanceLib.revokeRole(bit, account, _govSubject(), _delayedRelaxBits());
    }
    function renounceRole(uint8 bit) external governed {
        GovernanceLib.renounceRole(bit, _govSubject(), _delayedRelaxBits());
    }
    function disableFeature(uint8 bit) external virtual governed {
        GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());
    }
    function transferOwnership(bytes32 newOwner) external governed {
        GovernanceLib.transferOwnership(newOwner, _govSubject());
    }
    function acceptOwnership() external governed { GovernanceLib.acceptOwnership(_govSubject()); }
    function renounceOwnership() external governed { GovernanceLib.renounceOwnership(_govSubject(), _roleBits()); }
}
