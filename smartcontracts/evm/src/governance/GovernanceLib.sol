// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {IGovernance} from "./IGovernance.sol";
import {IAdmin} from "./IAdmin.sol";
import {GovernanceBits} from "./GovernanceBits.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IRescuable} from "./IRescuable.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title Features, admin and roles of every SCaaS contract (CTR-GOV-01, CTR-TOK-22), in the ERC-7201 namespace
///        `scaas.governance`.
/// @notice External library: the contract keeps one-line wrappers (`GovernanceBase`), the logic is linked at deploy
///         (CTR-TOK-24). `features`/`lockedFeatures` are written once by `init`; a flag can later only be cleared, once, by
///         the admin and only when not locked. One `admin` (0 = no administration ever) grants and revokes the role of a
///         set flag, disables disableable flags, transfers (two-step) or renounces the admin role. The renounce is refused while
///         a set bit that is not locked has holders (CTR-GOV-02, spec §1.7); a locked bit's holders survive it, since a lock
///         promises the power is permanent. A holder may renounce its own role. A power runs through `GovernanceUse.use`
///         (`GovernanceBase.sol`): a whole-shape holder inline, a limited one by one DELEGATECALL to `useLimited` (B-26).
library GovernanceLib {
    using SafeERC20 for IERC20;
    /// @dev The value of `roles`: 0 none, `WHOLE` no limit, `LIMITED` a `Grant` binds it.
    uint8 internal constant WHOLE = 1;
    uint8 internal constant LIMITED = 2;
    /// @dev The longest `grantDelay` (spec §1.4, B-27): `MAX_NOTICE_PERIOD`'s reason applies.
    uint64 internal constant MAX_GRANT_DELAY = 30 days;
    /// @dev The action a pending commits to (regulated-kinds spec §3.6, RK-2).
    uint8 internal constant GRANT = 1;
    uint8 internal constant SET = 2;
    uint8 internal constant REVOKE = 3;
    uint8 internal constant RENOUNCE = 4;
    uint8 internal constant DISABLE = 5;

    /// @notice Initial role holders (CTR-TOK-25 `Roles`); each only for a set flag, 0 = none.
    struct Roles {
        bytes32 minter;      // MINTABLE
        bytes32 rateAdmin;   // RATE_ADJUSTABLE, contract only: a native id with code
        bytes32 guardian;    // WRAP_DISABLEABLE
        bytes32 issuer;      // each set bit of FREEZE / FORCE / PAUSE (5-7); contract only, an `msig` UA too (RK-1)
        bytes32 compliance;  // RECORD (bit 10), contract only, an `msig` UA too: bits 8 and 9 have no holder (spec §1.2)
    }

    /// @notice A bit's holders, leaves included, and its live roots (`grantor == 0`): `holderCount` is `holders`, the
    ///         renounce rule reads `roots` (spec §1.7). One slot.
    struct Counts {
        uint128 holders;
        uint128 roots;
    }

    /// @notice A proposed grant or relaxation (spec §1.6; regulated-kinds spec §3.6): live while `eta != 0`,
    ///         `generation == adminGeneration` and `now <= eta + grantDelay`. `commit` is `keccak256(abi.encode(action, bit,
    ///         account, argsHash))` (`GRANT` .. `DISABLE`); the slot of the former `termsHash`.
    struct PendingGrant {
        uint64 eta;
        uint32 generation;
        bytes32 proposer;
        bytes32 commit;
    }

    /// @custom:storage-location erc7201:scaas.governance
    /// @dev Spec §1.4. Every identity is a UA id (`bytes32`, CTR-GOV-01 Change, owner 2026-11-04): a native account's id
    ///      is its padded address, a derived UA its registered id. `rescueTo` is a payout address and stays one.
    struct GovernanceStorage {
        uint256 features;                                                       // +0, written by init, cleared one-way
        uint256 lockedFeatures;                                                 // +1, no writer after init
        bytes32 admin;                                                          // +2
        bytes32 pendingAdmin;                                                   // +3
        uint64 grantDelay;                                                      // +4, no writer after init (spec §1.6)
        uint32 adminGeneration;                                                 //    completed changes of admin
        uint64 lastProposedAt;
        mapping(uint256 bit => mapping(bytes32 account => uint8)) roles;        // +5, 0 none, 1 WHOLE, 2 LIMITED
        mapping(uint256 bit => Counts) counts;                                  // +6
        mapping(uint256 bit => mapping(bytes32 holder => IGovernance.Grant)) grants; // +7
        /// @dev Bumped when a holder loses the bit, which kills every leaf it granted, without a walk.
        mapping(uint256 bit => mapping(bytes32 holder => uint32)) epoch;        // +8
        mapping(uint256 bit => mapping(bytes32 account => PendingGrant)) pending; // +9
        address rescueTo;                                                       // +10, no writer after init (spec §6.2)
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.governance")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;

    function $() internal pure returns (GovernanceStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init (CTR-TOK-22 "Validation in the token")

    /// @notice Validates the flags against the contract's masks and writes features, admin, `grantDelay` and initial roles.
    ///         Called once by the contract's `initialize`. `grantDelay` above 30 days is refused (B-27); `rescueTo` comes with
    ///         bit 17 and is never the contract itself or a pool (spec §6.2, `RescueConfigInvalid`). `roles.issuer` holds
    ///         each set bit of 5-7, `roles.compliance` bit 10 (regulated-kinds spec §2.4); `uaRegistry` answers `kindOf` for
    ///         a derived holder of a regulated contract-only bit (RK-1).
    function init(uint256 features, uint256 locked, bytes32 admin, uint64 grantDelay, address rescueTo, Roles memory roles,
        uint256 valid, uint256 roleBits, uint256 contractOnly, address uaRegistry) public
    {
        if (grantDelay > MAX_GRANT_DELAY) revert IGovernance.GrantDelayTooLong(grantDelay);
        uint256 bad = features & ~valid;
        if (bad != 0) revert IGovernance.FeatureInvalidForKind(_lowest(bad));
        if ((features & _bit(GovernanceBits.RESCUABLE) != 0) != (rescueTo != address(0)) || rescueTo == address(this)
            || rescueTo == MetaTxLib.UA_POOL || rescueTo == MetaTxLib.SHIELD_POOL) revert IRescuable.RescueConfigInvalid();
        if (locked & ~features != 0) revert IGovernance.LockedNotSubset();
        GovernanceStorage storage s = $();
        s.features = features;
        s.lockedFeatures = locked | (features & GovernanceBits.ALWAYS_LOCKED);
        s.grantDelay = grantDelay;
        s.rescueTo = rescueTo;
        if (roles.minter != 0) _grant(s, GovernanceBits.MINTABLE, roles.minter, 0, roleBits, contractOnly, uaRegistry);
        if (roles.rateAdmin != 0) {
            _grant(s, GovernanceBits.RATE_ADJUSTABLE, roles.rateAdmin, 0, roleBits, contractOnly, uaRegistry);
        }
        if (roles.guardian != 0) {
            _grant(s, GovernanceBits.WRAP_DISABLEABLE, roles.guardian, 0, roleBits, contractOnly, uaRegistry);
        }
        if (roles.issuer != 0) {
            uint256 iss = features & GovernanceBits.ISSUER_BITS;
            if (iss == 0) revert IGovernance.RoleWithoutFeature(GovernanceBits.FREEZE);
            for (; iss != 0; iss &= iss - 1) _grant(s, _lowest(iss), roles.issuer, 0, roleBits, contractOnly, uaRegistry);
        }
        if (roles.compliance != 0) {
            if (features & _bit(GovernanceBits.RECORD) == 0) revert IGovernance.RoleWithoutFeature(GovernanceBits.RECORD);
            _grant(s, GovernanceBits.RECORD, roles.compliance, 0, roleBits, contractOnly, uaRegistry);
        }
        if (admin != 0) {
            _notPool(admin);
            s.admin = admin;
            emit IAdmin.AdminTransferred(0, admin);
        } else {
            _noLiveHolder(s, roleBits); // B-06: no token is born in the state a renounce refuses (spec §1.7)
        }
    }

    /// @notice The DEX's admin holds bits 11 and 12 from `initialize` (spec §2.3, B-27): an INIT grant, undelayed, as
    ///         `init`'s roles. Reachable from a contract's `initialize` alone.
    function initHolder(uint8 bit, bytes32 account, uint256 roleBits, uint256 contractOnly, address uaRegistry) public {
        _grant($(), bit, account, 0, roleBits, contractOnly, uaRegistry);
    }

    // ------------------------------------------------------------------ admin

    /// @notice Spec §1.6: on a `WHOLE` holder a no-op; else, with a `grantDelay`, two calls (action `GRANT`).
    function grantRole(uint8 bit, bytes32 account, bytes32 caller, uint256 roleBits, uint256 contractOnly, address uaRegistry)
        public
    {
        GovernanceStorage storage s = _onlyAdmin(caller);
        _check(s, bit, account, roleBits, contractOnly, uaRegistry);
        if (s.roles[bit][account] == WHOLE) return;
        IGovernance.GrantTerms memory none;
        if (s.grantDelay != 0 && !_due(s, bit, account, caller, GRANT, none)) return;
        _grant(s, bit, account, caller, roleBits, contractOnly, uaRegistry);
    }

    /// @notice Deletes a pending of any action, live or dead; none is a no-op (spec §1.6, agy C-3). The admin, or the
    ///         pending's proposer (regulated-kinds spec §3.6).
    function cancelGrant(uint8 bit, bytes32 account, bytes32 caller) public {
        GovernanceStorage storage s = $();
        PendingGrant storage p = s.pending[bit][account];
        if (caller == 0 || (caller != s.admin && caller != p.proposer)) revert IAdmin.NotAdmin(caller);
        if (p.eta == 0) return;
        delete s.pending[bit][account];
        emit IGovernance.GrantCancelled(bit, account, caller);
    }

    /// @notice The admin, or the grantor of a leaf while the account is its `LIMITED` leaf and the grantor still holds the
    ///         bit (B-04). The admin's revoke bars the account, a non-holder too, before `_clear`'s early return: only the admin
    ///         re-admits it (B-05, Claude M-8). On a bit of `delayedRelax` with a `grantDelay`, two calls by the same caller
    ///         (regulated-kinds spec §3.6): the first only proposes; the bar and `_clear` happen at the confirm.
    function revokeRole(uint8 bit, bytes32 account, bytes32 caller, uint256 delayedRelax) public {
        GovernanceStorage storage s = $();
        bool admin = caller != 0 && caller == s.admin;
        if (!admin && (caller == 0 || caller != s.grants[bit][account].grantor || s.roles[bit][account] != LIMITED
            || s.roles[bit][caller] == 0))
        {
            revert IAdmin.NotAdmin(caller);
        }
        if (_delayed(s, bit, delayedRelax)) {
            IGovernance.GrantTerms memory none;
            if (!_due(s, bit, account, caller, REVOKE, none)) return;
        } else if (admin) {
            delete s.pending[bit][account]; // a confirm must not restore what the revoke took (agy C-3)
        }
        if (admin) s.grants[bit][account].barred = true;
        _clear(s, bit, account, caller);
    }

    /// @notice A holder gives up its own role (replaces `renounceMinter`/`renounceRateAdmin`/`renounceGuardian`). On a bit
    ///         of `delayedRelax` with a `grantDelay`, two calls (regulated-kinds spec §3.6).
    function renounceRole(uint8 bit, bytes32 caller, uint256 delayedRelax) public {
        GovernanceStorage storage s = $();
        if (s.roles[bit][caller] == 0) revert IGovernance.MissingRole(bit, caller);
        if (_delayed(s, bit, delayedRelax)) {
            IGovernance.GrantTerms memory none;
            if (!_due(s, bit, caller, caller, RENOUNCE, none)) return;
        } else {
            delete s.pending[bit][caller];
        }
        _clear(s, bit, caller, caller);
    }

    /// @dev A relaxation of `bit` waits `grantDelay` (CTR-GOV-09, regulated-kinds spec §3.6).
    function _delayed(GovernanceStorage storage s, uint8 bit, uint256 delayedRelax) private view returns (bool) {
        return delayedRelax & _bit(bit) != 0 && s.grantDelay != 0;
    }

    /// @notice CTR-GOV-02: the admin replaces any grant; a holder with a `delegable` grant sets a leaf that narrows its own,
    ///         on an account that holds nothing or is its own leaf. Spent, uses and the window carry over: an edit never
    ///         refreshes a budget. Returns whether this is a leaf and its parent's scope: the order on scopes is the contract's.
    ///         Every caller: a word the contract does not bind is refused (`scalarBits`, `scopeBits`, B-09, B-10), and a
    ///         `delegable` grant needs a finite budget (B-02), which bounds what is spent, not the number of leaves: a leaf
    ///         spends nothing until it acts, so a wallet prints "can add unlimited leaves at once, sharing a remaining budget".
    ///         On a bit of `delayedRelax` with a `grantDelay`, terms whose `validUntil` ends before `now + grantDelay` are a
    ///         relaxation: two calls on either path, never a narrowing (regulated-kinds spec §3.6).
    function setGrant(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata t, bytes32 caller, uint256 roleBits,
        uint256 contractOnly, uint256 scalarBits, uint256 scopeBits, address uaRegistry, uint256 delayedRelax)
        public returns (bool leaf, bytes32 parentScope)
    {
        (leaf, parentScope) = _leafPath(bit, holder, t, caller);
        _check($(), bit, holder, roleBits, contractOnly, uaRegistry);
        _words(bit, t, scalarBits, scopeBits);
        if (_setDue(bit, holder, t, caller, leaf, delayedRelax)) _write(bit, holder, t, caller, leaf);
    }

    /// @dev Whether a `setGrant` applies now: a leaf's or, with no `grantDelay`, at once; the admin's narrowing at once (spec
    ///      §1.6); a widening, or a `validUntil` cut on a bit of `delayedRelax`, in two calls (regulated-kinds spec §3.6).
    function _setDue(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata t, bytes32 caller, bool leaf,
        uint256 delayedRelax) private returns (bool)
    {
        GovernanceStorage storage s = $();
        bool cut = _delayed(s, bit, delayedRelax) && t.validUntil != 0 && t.validUntil < block.timestamp + s.grantDelay;
        if (!cut && (leaf || s.grantDelay == 0)) return true;
        if (!cut && _narrowing(s, bit, holder, t)) {
            delete s.pending[bit][holder];
            return true;
        }
        return _due(s, bit, holder, caller, SET, t);
    }

    /// @dev Spec §1.6: a pure narrowing of a root, applied at once. On a `WHOLE` root any terms not `delegable`; on a
    ///      `LIMITED` root every word field by field: `min` not lower, `max` not higher, each of `total`, `perWindow`,
    ///      `validUntil`, `maxUses` 0 before (0 is no bound, so `0 → finite` narrows) or finite and not higher, `window`
    ///      equal or new with the limit it carries, `scope` equal, `delegable` not raised. A leaf the admin would make a root
    ///      drops its parent's bound, and a new holder adds one: neither is a narrowing.
    function _narrowing(GovernanceStorage storage s, uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata t)
        private view returns (bool)
    {
        uint8 r = s.roles[bit][holder];
        if (r == WHOLE) return !t.delegable;
        IGovernance.Grant storage g = s.grants[bit][holder];
        if (r == 0 || g.grantor != 0) return false;
        return t.min >= g.min && t.max <= g.max && _within(g.total, t.total) && _within(g.perWindow, t.perWindow)
            && _within(g.validUntil, t.validUntil) && _within(g.maxUses, t.maxUses)
            && (t.window == g.window || (g.perWindow == 0 && t.perWindow != 0)) && t.scope == g.scope
            && (!t.delegable || g.delegable);
    }

    /// @dev A bound with 0 = none: `next` narrows `was`.
    function _within(uint256 was, uint256 next) private pure returns (bool) {
        return was == 0 || (next != 0 && next <= was);
    }

    /// @dev Spec §1.6, regulated-kinds spec §3.6 (RK-2): a live pending at `(bit, account)` with the same commitment,
    ///      confirmed by its proposer in its window, is deleted and the call applies (true); another commitment reverts
    ///      `GrantTermsMismatch`, another caller `NotProposer`, before `eta` `GrantNotReady`; with no live pending the call
    ///      proposes (false) and changes nothing else. `commit` binds the action, the key and, for `SET`, the terms.
    function _due(GovernanceStorage storage s, uint8 bit, bytes32 account, bytes32 caller, uint8 action,
        IGovernance.GrantTerms memory t) private returns (bool)
    {
        bytes32 c = keccak256(abi.encode(action, bit, account, action == SET ? keccak256(abi.encode(t)) : bytes32(0)));
        PendingGrant storage p = s.pending[bit][account];
        if (_live(s, p)) {
            if (p.commit != c) revert IGovernance.GrantTermsMismatch(bit, account);
            if (p.proposer != caller) revert IGovernance.NotProposer(bit, account, p.proposer);
            if (block.timestamp < p.eta) revert IGovernance.GrantNotReady(bit, account, p.eta);
            delete s.pending[bit][account];
            return true;
        }
        uint64 eta = uint64(block.timestamp) + s.grantDelay;
        (p.eta, p.proposer, p.generation, p.commit) = (eta, caller, s.adminGeneration, c);
        s.lastProposedAt = uint64(block.timestamp);
        if (action <= SET) emit IGovernance.GrantProposed(bit, account, caller, eta, action == GRANT, t);
        else emit IGovernance.RelaxProposed(bit, account, action, caller, eta);
        return false;
    }

    /// @dev Live: proposed, by the current admin generation, and `now <= eta + grantDelay`.
    function _live(GovernanceStorage storage s, PendingGrant storage p) private view returns (bool) {
        return p.eta != 0 && p.generation == s.adminGeneration && block.timestamp <= uint256(p.eta) + s.grantDelay;
    }

    /// @notice `pendingGrant(bit, account)`: dead ones too, with `live`.
    function pendingGrant(uint8 bit, bytes32 account)
        public view returns (uint64 eta, bytes32 proposer, bytes32 commit, bool live)
    {
        GovernanceStorage storage s = $();
        PendingGrant storage p = s.pending[bit][account];
        return (p.eta, p.proposer, p.commit, _live(s, p));
    }

    /// @dev A caller that is not the admin sets a leaf (spec §1.5): it holds a `delegable` `LIMITED` grant, an admin exists
    ///      (B-08: nothing above changes once the admin is 0, the holder list included), the caller is not expired, the target
    ///      holds nothing or is its own leaf and is not barred (B-05), and the terms narrow its own, so an expired parent or
    ///      one with nothing left adds nobody. Returns the parent's scope, which the contract's order checks.
    function _leafPath(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata t, bytes32 caller)
        private view returns (bool leaf, bytes32 parentScope)
    {
        GovernanceStorage storage s = $();
        leaf = caller != s.admin || caller == 0;
        if (leaf) {
            IGovernance.Grant storage p = s.grants[bit][caller];
            if (s.admin == 0 || s.roles[bit][caller] != LIMITED || !p.delegable) revert IAdmin.NotAdmin(caller);
            if (p.validUntil != 0 && block.timestamp > p.validUntil) revert IGovernance.GrantExpired(bit, caller);
            IGovernance.Grant storage h = s.grants[bit][holder];
            if (s.roles[bit][holder] != 0 && h.grantor != caller) revert IAdmin.NotAdmin(caller);
            if (h.barred) revert IGovernance.GrantBarred(bit, holder);
            _narrows(t, p);
            parentScope = p.scope;
        }
    }

    /// @dev Writes the terms; spent, uses and the window's start carry (an edit never refreshes a budget). `Counts` by spec §1.7,
    ///      `r` read first: a leaf is a holder with `grantor != 0`. The admin's apply makes a root (`grantor`, `grantorEpoch`,
    ///      `barred` cleared) and, on a `LIMITED` holder whose `scope` changes or whose delegation ends, kills its leaves (B-11).
    function _write(uint8 bit, bytes32 holder, IGovernance.GrantTerms calldata t, bytes32 caller, bool leaf) private {
        GovernanceStorage storage s = $();
        IGovernance.Grant storage g = s.grants[bit][holder];
        uint8 r = s.roles[bit][holder];
        if (r != WHOLE && t.window != g.window && g.spentInWindow != 0) _windowFree(bit, holder, g, t.window);
        if (leaf) {
            if (r == 0) ++s.counts[bit].holders; // row 2; row 3 moves nothing
            (g.grantor, g.grantorEpoch) = (caller, s.epoch[bit][caller]);
        } else {
            if (r == LIMITED && (t.scope != g.scope || (g.delegable && !t.delegable))) ++s.epoch[bit][holder];
            _root(s, bit, r, g);
        }
        (g.min, g.max, g.total, g.perWindow) = (t.min, t.max, t.total, t.perWindow);
        (g.window, g.validUntil, g.maxUses, g.scope, g.delegable) = (t.window, t.validUntil, t.maxUses, t.scope, t.delegable);
        if (r == 0) emit IGovernance.RoleGranted(bit, holder, caller); // B-31: the indexed holder list is whole
        s.roles[bit][holder] = LIMITED;
        emit IGovernance.GrantSet(bit, holder, leaf ? caller : bytes32(0));
    }

    /// @dev The admin's apply, by either entry (spec §1.5, §1.7): rows 1, 4, 5, 6; the record becomes a root's.
    function _root(GovernanceStorage storage s, uint8 bit, uint8 r, IGovernance.Grant storage g) private {
        Counts storage c = s.counts[bit];
        if (r == 0) {
            ++c.holders;
            ++c.roots;
        } else if (g.grantor != 0) {
            ++c.roots;
        }
        if (g.grantor != 0 || g.barred) (g.grantor, g.grantorEpoch, g.barred) = (0, 0, false);
    }

    /// @dev B-12, agy I-1: a holder that spent in a period which ends after the start of the current period on the new grid
    ///      cannot change `window`, or `_debit` would read that spent as another period's. `uint256`, `now` for a window of 0.
    function _windowFree(uint8 bit, bytes32 holder, IGovernance.Grant storage g, uint32 window) private view {
        uint256 start = window == 0 ? block.timestamp : block.timestamp - block.timestamp % window;
        if (uint256(g.windowStart) + g.window > start) revert IGovernance.GrantWindowInUse(bit, holder);
    }

    /// @notice One-way: clears a set, unlocked flag (replaces `disableControls`). On a bit of `delayedRelax` with a
    ///         `grantDelay`, two calls keyed `(bit, 0)` (regulated-kinds spec §3.6): the first proposes and returns false;
    ///         `applied` is true only when `features` was cleared, and a contract acts on the disable only then (RK-3).
    function disableFeature(uint8 bit, bytes32 caller, uint256 delayedRelax) public returns (bool applied) {
        GovernanceStorage storage s = _onlyAdmin(caller);
        uint256 m = _bit(bit);
        if ((s.lockedFeatures | GovernanceBits.ALWAYS_LOCKED) & m != 0) revert IGovernance.FeatureLocked(bit);
        if (s.features & m == 0) revert IGovernance.FeatureNotSet(bit);
        if (_delayed(s, bit, delayedRelax)) {
            IGovernance.GrantTerms memory none;
            if (!_due(s, bit, 0, caller, DISABLE, none)) return false;
        }
        s.features &= ~m;
        emit IGovernance.FeatureDisabled(bit, caller);
        return true;
    }

    function transferAdmin(bytes32 newAdmin, bytes32 caller) public {
        GovernanceStorage storage s = _onlyAdmin(caller);
        _notPool(newAdmin);
        s.pendingAdmin = newAdmin;
        emit IAdmin.AdminTransferStarted(caller, newAdmin);
    }

    function acceptAdmin(bytes32 caller) public {
        GovernanceStorage storage s = $();
        if (caller != s.pendingAdmin || caller == 0) revert IAdmin.NotPendingAdmin(caller);
        bytes32 previous = s.admin;
        s.admin = caller;
        s.pendingAdmin = 0;
        ++s.adminGeneration; // every pending of the previous term dies (Codex 2)
        emit IAdmin.AdminTransferred(previous, caller);
    }

    /// @notice The admin becomes 0 forever. Refused while a set bit that is not locked has holders (CTR-GOV-02): revoke
    ///         first. A locked bit's holders survive: a lock promises the power is permanent.
    function renounceAdmin(bytes32 caller, uint256 roleBits) public {
        GovernanceStorage storage s = _onlyAdmin(caller);
        _noLiveHolder(s, roleBits);
        s.admin = 0;
        s.pendingAdmin = 0;
        ++s.adminGeneration;
        emit IAdmin.AdminTransferred(caller, 0);
    }

    // ------------------------------------------------------------------ checks used inline by the token

    function hasFeature(uint8 bit) internal view returns (bool) {
        return $().features & _bit(bit) != 0;
    }

    function hasRole(uint8 bit, bytes32 account) internal view returns (bool) {
        return $().roles[bit][account] != 0;
    }

    /// @notice A limited holder: its own terms, then, for a leaf, the parent's epoch and the parent's terms on the same scalar.
    function useLimited(uint8 bit, bytes32 account, uint256 scalar) public returns (bytes32) {
        GovernanceStorage storage s = $();
        IGovernance.Grant storage g = s.grants[bit][account];
        _debit(bit, account, g, scalar);
        bytes32 p = g.grantor;
        if (p != 0) {
            if (s.roles[bit][p] != LIMITED || s.epoch[bit][p] != g.grantorEpoch) revert IGovernance.GrantExhausted(7);
            _debit(bit, p, s.grants[bit][p], scalar);
        }
        emit IGovernance.GrantUsed(bit, account, scalar);
        return g.scope;
    }

    // ------------------------------------------------------------------ rescue (CTR-GOV-06, spec §6.2)

    /// @notice `NORMAL*`: the whole balance of `asset` (the native coin by value) to `rescueTo`; the token owes none of it.
    ///         The caller's guard is the token's `nonReentrant`.
    function rescue(address asset) public {
        address to = rescueOpen(asset);
        uint256 amount = asset == address(0) ? address(this).balance : IERC20(asset).balanceOf(address(this));
        rescueSend(asset, to, amount);
        emit IRescuable.Rescued(asset, to, amount);
    }

    /// @dev The two first rows of spec §6.2 on every kind: bit 17, and never the token's own units. Returns `rescueTo`.
    function rescueOpen(address asset) internal view returns (address) {
        GovernanceStorage storage s = $();
        if (s.features & _bit(GovernanceBits.RESCUABLE) == 0) revert IGovernance.FeatureNotSet(GovernanceBits.RESCUABLE);
        if (asset == address(this)) revert IRescuable.RescueAssetInvalid(asset);
        return s.rescueTo;
    }

    /// @dev The native coin by value, refused to a designator as `WrappedLib.payOut` refuses it; an ERC-20 by `safeTransfer`.
    function rescueSend(address asset, address to, uint256 amount) internal {
        if (asset == address(0)) {
            if (SigCheck.isDesignator(to)) revert IRescuable.RescueAssetInvalid(asset);
            Address.sendValue(payable(to), amount);
        } else {
            IERC20(asset).safeTransfer(to, amount);
        }
    }

    function requireFeature(uint8 bit) internal view {
        if ($().features & _bit(bit) == 0) revert IGovernance.FeatureNotSet(bit);
    }

    // ------------------------------------------------------------------ internals

    function _grant(GovernanceStorage storage s, uint8 bit, bytes32 account, bytes32 caller, uint256 roleBits,
        uint256 contractOnly, address uaRegistry) private
    {
        _check(s, bit, account, roleBits, contractOnly, uaRegistry);
        uint8 r = s.roles[bit][account];
        if (r == WHOLE) return;
        if (r == LIMITED) ++s.epoch[bit][account]; // B-18: an upgrade kills the leaves; a later narrowing revives none
        _root(s, bit, r, s.grants[bit][account]);
        s.roles[bit][account] = WHOLE;
        emit IGovernance.RoleGranted(bit, account, caller);
    }

    /// @dev Every grant path, at every call (the propose and the confirm): the holder is no pool and not this contract
    ///      (F-07), the bit is a set role bit, a contract-only bit's holder is a contract, and no id holds both `FORCE` and
    ///      `RECORD` (CTR-AS-03).
    function _check(GovernanceStorage storage s, uint8 bit, bytes32 account, uint256 roleBits, uint256 contractOnly,
        address uaRegistry) private view
    {
        if (account == 0) revert IGovernance.RoleAccountZero(bit);
        if (_isPool(account)) revert IGovernance.RoleAccountPool(bit, account);
        if (roleBits & _bit(bit) == 0) revert IGovernance.NoSuchRole(bit);
        if (s.features & _bit(bit) == 0) revert IGovernance.RoleWithoutFeature(bit);
        // contract-only: a native id (top 96 bits 0) whose address has code; on a regulated bit also a threshold (`msig`)
        // UA, its kind read from the registry here, at the grant, never at a use (RK-1)
        if (contractOnly & _bit(bit) != 0 && (uint256(account) >> 160 == 0
            ? !SigCheck.isContract(address(uint160(uint256(account))))
            : (GovernanceBits.REGULATED_ROLES & _bit(bit) == 0 || uaRegistry == address(0)
                || IUARegistry(uaRegistry).kindOf(account) != UAKinds.MSIG)))
        {
            revert IGovernance.RoleNotContract(bit, account);
        }
        if ((bit == GovernanceBits.FORCE && s.roles[GovernanceBits.RECORD][account] != 0)
            || (bit == GovernanceBits.RECORD && s.roles[GovernanceBits.FORCE][account] != 0))
        {
            revert IGovernance.RoleConflict(bit, account);
        }
    }

    /// @dev The renounce rule (CTR-GOV-02, spec §1.7): no set, unlocked power bit has a live root. A dead leaf does not count
    ///      (B-07); an expired root does until it is revoked (C7). `renounceAdmin`, and `init` with no admin.
    function _noLiveHolder(GovernanceStorage storage s, uint256 roleBits) private view {
        for (uint256 live = s.features & ~s.lockedFeatures & roleBits; live != 0; live &= live - 1) {
            uint8 bit = _lowest(live);
            if (s.counts[bit].roots != 0) revert IGovernance.AdminHasHolders(bit);
        }
    }

    function _notPool(bytes32 account) private view {
        if (_isPool(account)) revert IGovernance.AdminAccountPool(account);
    }

    /// @dev `UA_POOL`, `SHIELD_POOL` and the contract itself as native ids: never admin, never holder (B-19, F-07).
    function _isPool(bytes32 account) private view returns (bool) {
        return account == MetaTxLib.pad(MetaTxLib.UA_POOL) || account == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)
            || account == MetaTxLib.pad(address(this));
    }

    /// @dev The words `bit` binds on this contract (spec §1.5): a scalarless bit takes only `validUntil`, `maxUses` and
    ///      `delegable`; `scope` is non-zero exactly on a scoped bit; `perWindow` and `window` come together; a delegable grant
    ///      has a finite budget.
    function _words(uint8 bit, IGovernance.GrantTerms calldata t, uint256 scalarBits, uint256 scopeBits) private pure {
        bool scalar = scalarBits & _bit(bit) != 0;
        if (!scalar) {
            if (t.min != 0) revert IGovernance.GrantWordRefused(bit, 0);
            if (t.max != type(uint128).max) revert IGovernance.GrantWordRefused(bit, 1);
            if (t.total != 0) revert IGovernance.GrantWordRefused(bit, 2);
            if (t.perWindow != 0) revert IGovernance.GrantWordRefused(bit, 3);
            if (t.window != 0) revert IGovernance.GrantWordRefused(bit, 8);
        }
        if ((scopeBits & _bit(bit) == 0) != (t.scope == 0)) revert IGovernance.GrantWordRefused(bit, 7);
        if ((t.perWindow == 0) != (t.window == 0)) revert IGovernance.GrantWordRefused(bit, 3);
        if (t.delegable && (scalar ? t.total == 0 : t.maxUses == 0)) revert IGovernance.GrantBudgetRequired(bit);
    }

    /// @dev Rows 7 and 8 of spec §1.7: `grantor` read before `r` is cleared; the record is kept; the epoch bump kills the
    ///      leaves of `account` without a walk.
    function _clear(GovernanceStorage storage s, uint8 bit, bytes32 account, bytes32 caller) private {
        if (s.roles[bit][account] == 0) return;
        bool root = s.grants[bit][account].grantor == 0;
        s.roles[bit][account] = 0;
        Counts storage c = s.counts[bit];
        --c.holders;
        if (root) --c.roots;
        ++s.epoch[bit][account];
        emit IGovernance.RoleRevoked(bit, account, caller);
    }

    /// @dev One holder's terms against `x`, spent written back. Windows are MandateWallet's grid on multiples of `window`.
    function _debit(uint8 bit, bytes32 account, IGovernance.Grant storage g, uint256 x) private {
        if (g.validUntil != 0 && block.timestamp > g.validUntil) revert IGovernance.GrantExpired(bit, account);
        if (x < g.min) revert IGovernance.GrantExhausted(0);
        if (x > g.max) revert IGovernance.GrantExhausted(1);
        if (g.maxUses != 0) {
            if (g.uses >= g.maxUses) revert IGovernance.GrantExhausted(5);
            ++g.uses;
        }
        if (g.total != 0) {
            uint256 spent = uint256(g.spentTotal) + x;
            if (spent > g.total) revert IGovernance.GrantExhausted(2);
            g.spentTotal = uint128(spent);
        }
        if (g.perWindow != 0) {
            uint32 w = g.window;
            uint32 start = uint32(block.timestamp - block.timestamp % w);
            uint256 spent = (start == g.windowStart ? uint256(g.spentInWindow) : 0) + x;
            if (spent > g.perWindow) revert IGovernance.GrantExhausted(3);
            (g.spentInWindow, g.windowStart) = (uint128(spent), start);
        }
    }

    /// @dev Child within parent, field by field (spec §1.5); for the four fields with 0 = no bound, a bounded parent wants a
    ///      bounded child. `total` and `maxUses` against what remains, by comparison, never a subtraction (B-18, agy I-3); under
    ///      a window the child's `window` equals the parent's (B-17).
    function _narrows(IGovernance.GrantTerms calldata t, IGovernance.Grant storage p) private view {
        if (t.delegable) revert IGovernance.GrantNotNarrower(6);
        if (t.min < p.min) revert IGovernance.GrantNotNarrower(0);
        if (t.max > p.max) revert IGovernance.GrantNotNarrower(1);
        if (p.total != 0 && (t.total == 0 || uint256(p.spentTotal) + t.total > p.total)) revert IGovernance.GrantNotNarrower(2);
        if (p.perWindow != 0) {
            if (t.perWindow == 0 || t.perWindow > p.perWindow) revert IGovernance.GrantNotNarrower(3);
            if (t.window != p.window) revert IGovernance.GrantNotNarrower(8);
        }
        if (p.validUntil != 0 && (t.validUntil == 0 || t.validUntil > p.validUntil)) revert IGovernance.GrantNotNarrower(4);
        if (p.maxUses != 0 && (t.maxUses == 0 || uint256(p.uses) + t.maxUses > p.maxUses)) revert IGovernance.GrantNotNarrower(5);
    }

    function _onlyAdmin(bytes32 caller) private view returns (GovernanceStorage storage s) {
        s = $();
        if (caller != s.admin || caller == 0) revert IAdmin.NotAdmin(caller);
    }

    function _bit(uint8 bit) private pure returns (uint256) {
        return uint256(1) << bit;
    }

    function _lowest(uint256 x) private pure returns (uint8 i) {
        while (x & 1 == 0) { x >>= 1; ++i; }
    }
}
