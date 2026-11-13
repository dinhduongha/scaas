// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IGovernance} from "./IGovernance.sol";
import {IAdmin} from "./IAdmin.sol";
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

/// @title One layer for admin, features and roles (owner 2026-11-02, CTR-GOV-01), for any contract: one-line wrappers
///        over `GovernanceLib`, the masks of compile-time constants, nothing of its own in storage. Every power runs
///        through `GovernanceUse.use`; `hasRole` is a view (listed, not able to act). Every identity is a UA id
///        (`bytes32`, CTR-GOV-01 Change, owner 2026-11-04), and `_govSubject()` names the caller.
abstract contract GovernanceBaseCore {
    /// @dev This chain's router, a constructor immutable; 0 on a factory-made contract, which reads its clone's code.
    address private immutable _GOV_ROUTER;

    constructor(address govRouter) {
        _GOV_ROUTER = govRouter;
    }

    /// @notice This chain's `GovernanceRouter` (0 = none on this chain): a call from it acts for the UA it authenticated
    ///         (spec `2026-11-04-governance-ua-identity.md` §2). Factory-made: the instance's `ChainEnv.govRouter`, from its
    ///         clone's code (CTR-TOK-29; the name of the immutable it was).
    function _GOV_ROUTERBody() internal view returns (address) {
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

    function _featuresBody() internal view returns (uint256) { return GovernanceLib.$().features; }
    function _lockedFeaturesBody() internal view returns (uint256) { return GovernanceLib.$().lockedFeatures; }
    function _adminBody() internal view returns (bytes32) { return GovernanceLib.$().admin; }
    function _pendingAdminBody() internal view returns (bytes32) { return GovernanceLib.$().pendingAdmin; }
    function _hasRoleBody(uint8 bit, bytes32 account) internal view returns (bool) { return GovernanceLib.hasRole(bit, account); }
    function _validBitsBody() internal pure returns (uint256) { return _validBits(); }
    function _holderCountBody(uint8 bit) internal view returns (uint256) { return GovernanceLib.$().counts[bit].holders; }
    function _grantDelayBody() internal view returns (uint64) { return GovernanceLib.$().grantDelay; }
    function _lastProposedAtBody() internal view returns (uint64) { return GovernanceLib.$().lastProposedAt; }
    function _pendingGrantBody(uint8 bit, bytes32 account) internal view returns (uint64, bytes32, bytes32, bool) {
        return GovernanceLib.pendingGrant(bit, account);
    }
    function _grantOfBody(uint8 bit, bytes32 holder) internal view returns (IGovernance.Grant memory) {
        return GovernanceLib.$().grants[bit][holder];
    }

    /// @notice Bits 128-255 only (CTR-GOV-10); a contract with no application bit answers with a refusal.
    function _bitLabelBody(uint8 bit) internal view virtual returns (IGovernance.BitType, bytes4, string memory) {
        revert IGovernance.FeatureInvalidForKind(bit);
    }

    /// @dev CTR-GOV-28 (owner 2026-11-13): every direct admin entry carries the chain word. An admin-only entry checks the
    ///      admin, then the word (`_adminOnChain`), before any write. An entry a holder, a grantor or a proposer may call too
    ///      (`setGrant`, `revokeRole`, `cancelGrant`; `_subjectWord`): the admin's call checks the word before any write; any
    ///      other caller is checked by `GovernanceLib` first (a stranger `NotAdmin`), then the word, the call reverting whole.
    function _grantRoleBody(uint8 bit, bytes32 account, bytes32 chainUid_) internal {
        GovernanceLib.grantRole(bit, account, _adminOnChain(chainUid_), _roleBits(), _contractOnlyBits(), _uaRegistry());
    }
    /// @notice The admin sets any holder's grant, a widening in two calls (spec §1.6); a holder with a `delegable` grant sets
    ///         a narrower leaf at once. Spent is carried.
    function _setGrantBody(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata terms, bytes32 chainUid_) internal {
        (bytes32 c, bool admin) = _subjectWord(chainUid_);
        (bool leaf, bytes32 parentScope) = GovernanceLib.setGrant(bit, holder, terms, c, _roleBits(),
            _contractOnlyBits(), _scalarBits(), _scopeBits(), _uaRegistry(), _delayedRelaxBits());
        if (leaf && !_scopeNarrows(bit, parentScope, terms.scope)) revert IGovernance.GrantNotNarrower(7);
        if (!admin) _govChainWord(chainUid_);
    }

    function _cancelGrantBody(uint8 bit, bytes32 account, bytes32 chainUid_) internal {
        (bytes32 c, bool admin) = _subjectWord(chainUid_);
        GovernanceLib.cancelGrant(bit, account, c);
        if (!admin) _govChainWord(chainUid_);
    }
    function _revokeRoleBody(uint8 bit, bytes32 account, bytes32 chainUid_) internal {
        (bytes32 c, bool admin) = _subjectWord(chainUid_);
        GovernanceLib.revokeRole(bit, account, c, _delayedRelaxBits());
        if (!admin) _govChainWord(chainUid_);
    }
    /// @dev CTR-GOV-28 (owner 2026-11-13): a holder's word before any write; a caller without the bit stays `MissingRole`.
    function _renounceRoleBody(uint8 bit, bytes32 chainUid_) internal {
        bytes32 c = _govSubject();
        if (GovernanceLib.$().roles[bit][c] != 0) _govChainWord(chainUid_);
        GovernanceLib.renounceRole(bit, c, _delayedRelaxBits());
    }
    /// @dev The entry's body: the admin, then the word (CTR-GOV-28), then the kind's disable (`_disableFeatureBody(bit)`).
    function _disableFeatureBody(uint8 bit, bytes32 chainUid_) internal {
        _adminOnChain(chainUid_);
        _disableFeatureBody(bit);
    }
    function _disableFeatureBody(uint8 bit) internal virtual {
        GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits());
    }
    function _transferAdminBody(bytes32 newAdmin, bytes32 chainUid_) internal {
        GovernanceLib.transferAdmin(newAdmin, _adminOnChain(chainUid_));
    }
    function _acceptAdminBody() internal { GovernanceLib.acceptAdmin(_govSubject()); }
    /// @dev The contract's chain word (`ChainEnvCode.chainUid()` on a factory-made token or DEX): the check of
    ///      every direct admin entry (CTR-GOV-27, CTR-GOV-28).
    function _govChainUid() internal view virtual returns (bytes32);

    /// @dev Fable recheck-2 P3-1, CTR-GOV-27, CTR-GOV-28: the admin (`NotAdmin`, as every admin entry refuses a stranger
    ///      first), then `chainUid_` this contract's word (`IAdmin.ChainUidMismatch`), before any write: a native admin's
    ///      direct admin entry made for a sibling with the same chain id is void here. Returns the admin.
    function _adminOnChain(bytes32 chainUid_) internal view returns (bytes32 c) {
        c = _govSubject();
        if (c == 0 || c != GovernanceLib.$().admin) revert IAdmin.NotAdmin(c);
        _govChainWord(chainUid_);
    }

    /// @dev CTR-GOV-28, an entry the admin and others may call: the subject, and whether it is the admin; the admin's
    ///      word is checked here, before any write; another caller's after its own checks (the caller's body).
    function _subjectWord(bytes32 chainUid_) internal view returns (bytes32 c, bool admin) {
        c = _govSubject();
        admin = c != 0 && c == GovernanceLib.$().admin;
        if (admin) _govChainWord(chainUid_);
    }

    /// @dev CTR-GOV-28: `chainUid_` this contract's word (`IAdmin.ChainUidMismatch`), the whole check.
    function _govChainWord(bytes32 chainUid_) internal view {
        bytes32 u = _govChainUid();
        if (chainUid_ != u) revert IAdmin.ChainUidMismatch(u, chainUid_);
    }

    function _renounceAdminBody(bytes32 chainUid_) internal {
        GovernanceLib.renounceAdmin(_adminOnChain(chainUid_), _roleBits());
    }
}

/// @notice `GovernanceBaseCore` with its external entries, each calling its body (T66b, spec 2026-11-09-t66b-library-organisation.md §4.4):
///         the form its non-token users inherit, ABI and modifiers unchanged. UNAUDITED.
abstract contract GovernanceBase is GovernanceBaseCore, IGovernance {
    function GOV_ROUTER() external view returns (address) {
        return _GOV_ROUTERBody();
    }

    function features() external view override returns (uint256) {
        return _featuresBody();
    }

    function lockedFeatures() external view override returns (uint256) {
        return _lockedFeaturesBody();
    }

    function admin() external view override returns (bytes32) {
        return _adminBody();
    }

    function pendingAdmin() external view override returns (bytes32) {
        return _pendingAdminBody();
    }

    function hasRole(uint8 bit, bytes32 account) external view override returns (bool) {
        return _hasRoleBody(bit, account);
    }

    function validBits() external pure override returns (uint256) {
        return _validBitsBody();
    }

    function holderCount(uint8 bit) external view override returns (uint256) {
        return _holderCountBody(bit);
    }

    function grantDelay() external view override returns (uint64) {
        return _grantDelayBody();
    }

    function lastProposedAt() external view override returns (uint64) {
        return _lastProposedAtBody();
    }

    function pendingGrant(uint8 bit, bytes32 account) external view override returns (uint64, bytes32, bytes32, bool) {
        return _pendingGrantBody(bit, account);
    }

    function grantOf(uint8 bit, bytes32 holder) external view override returns (Grant memory) {
        return _grantOfBody(bit, holder);
    }

    function bitLabel(uint8 bit) external view virtual override returns (BitType, bytes4, string memory) {
        return _bitLabelBody(bit);
    }

    function grantRole(uint8 bit, bytes32 account, bytes32 chainUid_) external override governed {
        _grantRoleBody(bit, account, chainUid_);
    }

    function setGrant(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata terms, bytes32 chainUid_)
        external
        override
        governed
    {
        _setGrantBody(bit, holder, terms, chainUid_);
    }

    function cancelGrant(uint8 bit, bytes32 account, bytes32 chainUid_) external override governed {
        _cancelGrantBody(bit, account, chainUid_);
    }

    function revokeRole(uint8 bit, bytes32 account, bytes32 chainUid_) external override governed {
        _revokeRoleBody(bit, account, chainUid_);
    }

    function renounceRole(uint8 bit, bytes32 chainUid_) external override governed {
        _renounceRoleBody(bit, chainUid_);
    }

    function disableFeature(uint8 bit, bytes32 chainUid_) external virtual override governed {
        _disableFeatureBody(bit, chainUid_);
    }

    function transferAdmin(bytes32 newAdmin, bytes32 chainUid_) external override governed {
        _transferAdminBody(newAdmin, chainUid_);
    }

    function acceptAdmin() external override governed {
        _acceptAdminBody();
    }

    function renounceAdmin(bytes32 chainUid_) external override governed {
        _renounceAdminBody(chainUid_);
    }
}
