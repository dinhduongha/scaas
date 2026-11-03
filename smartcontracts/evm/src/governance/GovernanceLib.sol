// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {SigCheck} from "../common/SigCheck.sol";
import {IGovernance} from "./IGovernance.sol";
import {GovernanceBits} from "./GovernanceBits.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Features, owner and roles of every SCaaS contract (CTR-GOV-01, CTR-TOK-22), in the ERC-7201 namespace
///        `scaas.governance`.
/// @notice External library: the contract keeps one-line wrappers (`GovernanceBase`), the logic is linked at deploy
///         (CTR-TOK-24). `features`/`lockedFeatures` are written once by `init`; a flag can later only be cleared, once, by
///         the owner and only when not locked. One `owner` (0 = no administration ever) grants and revokes the role of a
///         set flag, disables disableable flags, transfers (two-step) or renounces ownership. The renounce is refused while
///         a set bit that is not locked has holders (CTR-GOV-02, spec §1.7); a locked bit's holders survive it, since a lock
///         promises the power is permanent. A holder may renounce its own role. A power runs through `GovernanceUse.use`
///         (`GovernanceBase.sol`): a whole-shape holder inline, a limited one by one DELEGATECALL to `useLimited` (B-26).
library GovernanceLib {
    /// @dev The value of `roles`: 0 none, `WHOLE` no limit, `LIMITED` a `Grant` binds it.
    uint8 internal constant WHOLE = 1;
    uint8 internal constant LIMITED = 2;

    /// @notice Initial role holders (CTR-TOK-25 `Roles`); each only for a set flag, 0 = none.
    struct Roles {
        address minter;      // MINTABLE
        address rateAdmin;   // RATE_ADJUSTABLE, contract only
        address guardian;    // WRAP_DISABLEABLE
        address issuer;      // FREEZE / FORCE / PAUSE (bit 5; not built)
        address compliance;  // RECORD (bit 10; not built): bits 8 and 9 have no holder (spec §1.2)
    }

    /// @notice A bit's holders, leaves included, and its live roots (`grantor == 0`): `holderCount` is `holders`, the
    ///         renounce rule reads `roots` (spec §1.7). One slot.
    struct Counts {
        uint128 holders;
        uint128 roots;
    }

    /// @notice A proposed grant (spec §1.6): live while `eta != 0`, `generation == ownerGeneration` and
    ///         `now <= eta + grantDelay`. `termsHash` 0 is a `grantRole`.
    struct PendingGrant {
        uint64 eta;
        address proposer;
        uint32 generation;
        bytes32 termsHash;
    }

    /// @custom:storage-location erc7201:scaas.governance
    /// @dev Spec §1.4, the final shape (GD-2): `grantDelay`, `ownerGeneration`, `lastProposedAt`, `pending`, `rescueTo`,
    ///      `Counts.roots` and `Grant.barred` have no writer until their task; no slot moves after.
    struct GovernanceStorage {
        uint256 features;                                                       // +0, written by init, cleared one-way
        uint256 lockedFeatures;                                                 // +1, no writer after init
        address owner;                                                          // +2
        uint64 grantDelay;                                                      //    no writer after init (spec §1.6)
        uint32 ownerGeneration;                                                 //    completed changes of owner
        address pendingOwner;                                                   // +3
        uint64 lastProposedAt;
        mapping(uint256 bit => mapping(address account => uint8)) roles;        // +4, 0 none, 1 WHOLE, 2 LIMITED
        mapping(uint256 bit => Counts) counts;                                  // +5
        mapping(uint256 bit => mapping(address holder => IGovernance.Grant)) grants; // +6
        /// @dev Bumped when a holder loses the bit, which kills every leaf it granted, without a walk.
        mapping(uint256 bit => mapping(address holder => uint32)) epoch;        // +7
        mapping(uint256 bit => mapping(address account => PendingGrant)) pending; // +8
        address rescueTo;                                                       // +9, no writer after init
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.governance")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;

    function $() internal pure returns (GovernanceStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init (CTR-TOK-22 "Validation in the token")

    /// @notice Validates the flags against the contract's masks and writes features, owner and initial roles. Called
    ///         once by the contract's `initialize`.
    function init(uint256 features, uint256 locked, address owner, Roles memory roles, uint256 valid, uint256 roleBits,
        uint256 contractOnly) public
    {
        if (features >> 128 != 0) revert IGovernance.FeatureReserved(_lowest(features >> 128) + 128);
        uint256 bad = features & ~valid;
        if (bad != 0) revert IGovernance.FeatureInvalidForKind(_lowest(bad));
        if (features & GovernanceBits.REGULATED != 0) {
            revert IGovernance.FeatureNotBuilt(_lowest(features & GovernanceBits.REGULATED));
        }
        if (locked & ~features != 0) revert IGovernance.LockedNotSubset();
        GovernanceStorage storage s = $();
        s.features = features;
        s.lockedFeatures = locked | (features & GovernanceBits.ALWAYS_LOCKED);
        if (roles.issuer != address(0)) revert IGovernance.RoleWithoutFeature(GovernanceBits.FREEZE);
        if (roles.compliance != address(0)) revert IGovernance.RoleWithoutFeature(GovernanceBits.RECORD);
        if (roles.minter != address(0)) _grant(s, GovernanceBits.MINTABLE, roles.minter, address(0), roleBits, contractOnly);
        if (roles.rateAdmin != address(0)) {
            _grant(s, GovernanceBits.RATE_ADJUSTABLE, roles.rateAdmin, address(0), roleBits, contractOnly);
        }
        if (roles.guardian != address(0)) {
            _grant(s, GovernanceBits.WRAP_DISABLEABLE, roles.guardian, address(0), roleBits, contractOnly);
        }
        if (owner != address(0)) {
            s.owner = owner;
            emit IGovernance.OwnershipTransferred(address(0), owner);
        }
    }

    /// @notice The DEX's owner holds bits 11 and 12 from `initialize` (spec §2.3, B-27): an INIT grant, undelayed, as
    ///         `init`'s roles. Reachable from a contract's `initialize` alone.
    function initHolder(uint8 bit, address account, uint256 roleBits, uint256 contractOnly) public {
        _grant($(), bit, account, address(0), roleBits, contractOnly);
    }

    // ------------------------------------------------------------------ owner

    function grantRole(uint8 bit, address account, address caller, uint256 roleBits, uint256 contractOnly) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        _grant(s, bit, account, caller, roleBits, contractOnly);
    }

    /// @notice The owner, or the grantor of a leaf.
    function revokeRole(uint8 bit, address account, address caller) public {
        GovernanceStorage storage s = $();
        if (caller == address(0) || (caller != s.owner && caller != s.grants[bit][account].grantor)) {
            revert IGovernance.NotOwner(caller);
        }
        _clear(s, bit, account, caller);
    }

    /// @notice A holder gives up its own role (replaces `renounceMinter`/`renounceRateAdmin`/`renounceGuardian`).
    function renounceRole(uint8 bit, address caller) public {
        GovernanceStorage storage s = $();
        if (s.roles[bit][caller] == 0) revert IGovernance.MissingRole(bit, caller);
        _clear(s, bit, caller, caller);
    }

    /// @notice CTR-GOV-02: the owner replaces any grant; a holder with a `delegable` grant sets a leaf that narrows its own,
    ///         on an account that holds nothing or is its own leaf. Spent, uses and the window carry over: an edit never
    ///         refreshes a budget. Returns whether this is a leaf and its parent's scope: the order on scopes is the contract's.
    function setGrant(uint8 bit, address holder, IGovernance.GrantTerms calldata t, address caller, uint256 roleBits,
        uint256 contractOnly) public returns (bool leaf, bytes32 parentScope)
    {
        GovernanceStorage storage s = $();
        IGovernance.Grant storage g = s.grants[bit][holder];
        uint8 r = s.roles[bit][holder];
        leaf = caller != s.owner || caller == address(0);
        if (leaf) {
            IGovernance.Grant storage p = s.grants[bit][caller];
            if (s.roles[bit][caller] != LIMITED || !p.delegable) revert IGovernance.NotOwner(caller);
            if (r != 0 && g.grantor != caller) revert IGovernance.NotOwner(caller);
            _narrows(t, p);
            parentScope = p.scope;
        }
        _check(s, bit, holder, roleBits, contractOnly);
        if (t.perWindow != 0 && t.window == 0) revert IGovernance.GrantNotNarrower(3);
        (g.min, g.max, g.total, g.perWindow) = (t.min, t.max, t.total, t.perWindow);
        (g.window, g.validUntil, g.maxUses, g.scope, g.delegable) = (t.window, t.validUntil, t.maxUses, t.scope, t.delegable);
        (g.grantor, g.grantorEpoch) = leaf ? (caller, s.epoch[bit][caller]) : (address(0), uint32(0));
        if (r == 0) ++s.counts[bit].holders;
        s.roles[bit][holder] = LIMITED;
        emit IGovernance.GrantSet(bit, holder, leaf ? caller : address(0));
    }

    /// @notice One-way: clears a set, unlocked flag (replaces `disableControls`).
    function disableFeature(uint8 bit, address caller) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        uint256 m = _bit(bit);
        if ((s.lockedFeatures | GovernanceBits.ALWAYS_LOCKED) & m != 0) revert IGovernance.FeatureLocked(bit);
        if (s.features & m == 0) revert IGovernance.FeatureNotSet(bit);
        s.features &= ~m;
        emit IGovernance.FeatureDisabled(bit, caller);
    }

    function transferOwnership(address newOwner, address caller) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        s.pendingOwner = newOwner;
        emit IGovernance.OwnershipTransferStarted(caller, newOwner);
    }

    function acceptOwnership(address caller) public {
        GovernanceStorage storage s = $();
        if (caller != s.pendingOwner || caller == address(0)) revert IGovernance.NotPendingOwner(caller);
        address previous = s.owner;
        s.owner = caller;
        s.pendingOwner = address(0);
        emit IGovernance.OwnershipTransferred(previous, caller);
    }

    /// @notice The owner becomes 0 forever. Refused while a set bit that is not locked has holders (CTR-GOV-02): revoke
    ///         first. A locked bit's holders survive: a lock promises the power is permanent.
    function renounceOwnership(address caller, uint256 roleBits) public {
        GovernanceStorage storage s = _onlyOwner(caller);
        for (uint256 live = s.features & ~s.lockedFeatures & roleBits; live != 0; live &= live - 1) {
            uint8 bit = _lowest(live);
            if (s.counts[bit].holders != 0) revert IGovernance.OwnerHasHolders(bit);
        }
        s.owner = address(0);
        s.pendingOwner = address(0);
        emit IGovernance.OwnershipTransferred(caller, address(0));
    }

    // ------------------------------------------------------------------ checks used inline by the token

    function hasFeature(uint8 bit) internal view returns (bool) {
        return $().features & _bit(bit) != 0;
    }

    function hasRole(uint8 bit, address account) internal view returns (bool) {
        return $().roles[bit][account] != 0;
    }

    /// @notice A limited holder: its own terms, then, for a leaf, the parent's epoch and the parent's terms on the same scalar.
    function useLimited(uint8 bit, address account, uint256 scalar) public returns (bytes32) {
        GovernanceStorage storage s = $();
        IGovernance.Grant storage g = s.grants[bit][account];
        _debit(bit, account, g, scalar);
        address p = g.grantor;
        if (p != address(0)) {
            if (s.roles[bit][p] != LIMITED || s.epoch[bit][p] != g.grantorEpoch) revert IGovernance.GrantExhausted(7);
            _debit(bit, p, s.grants[bit][p], scalar);
        }
        emit IGovernance.GrantUsed(bit, account, scalar);
        return g.scope;
    }

    function requireFeature(uint8 bit) internal view {
        if ($().features & _bit(bit) == 0) revert IGovernance.FeatureNotSet(bit);
    }

    // ------------------------------------------------------------------ internals

    function _grant(GovernanceStorage storage s, uint8 bit, address account, address caller, uint256 roleBits,
        uint256 contractOnly) private
    {
        _check(s, bit, account, roleBits, contractOnly);
        uint8 r = s.roles[bit][account];
        if (r == WHOLE) return;
        if (r == 0) ++s.counts[bit].holders;
        s.roles[bit][account] = WHOLE;
        emit IGovernance.RoleGranted(bit, account, caller);
    }

    function _check(GovernanceStorage storage s, uint8 bit, address account, uint256 roleBits, uint256 contractOnly)
        private view
    {
        if (bit >= 128) revert IGovernance.FeatureReserved(bit);
        if (account == address(0)) revert IGovernance.RoleAccountZero(bit);
        if (account == MetaTxLib.UA_POOL || account == MetaTxLib.SHIELD_POOL) revert IGovernance.RoleAccountPool(bit, account);
        if (roleBits & _bit(bit) == 0) revert IGovernance.NoSuchRole(bit);
        if (s.features & _bit(bit) == 0) revert IGovernance.RoleWithoutFeature(bit);
        if (contractOnly & _bit(bit) != 0 && !SigCheck.isContract(account)) revert IGovernance.RoleNotContract(bit, account);
    }

    /// @dev Epoch first: the leaves of `account` die with its right.
    function _clear(GovernanceStorage storage s, uint8 bit, address account, address caller) private {
        if (s.roles[bit][account] == 0) return;
        s.roles[bit][account] = 0;
        --s.counts[bit].holders;
        ++s.epoch[bit][account];
        emit IGovernance.RoleRevoked(bit, account, caller);
    }

    /// @dev One holder's terms against `x`, spent written back. Windows are MandateWallet's grid on multiples of `window`.
    function _debit(uint8 bit, address account, IGovernance.Grant storage g, uint256 x) private {
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

    /// @dev Child within parent, field by field; for the four fields with 0 = no bound, a bounded parent wants a bounded child.
    function _narrows(IGovernance.GrantTerms calldata t, IGovernance.Grant storage p) private view {
        if (t.delegable) revert IGovernance.GrantNotNarrower(6);
        if (t.min < p.min) revert IGovernance.GrantNotNarrower(0);
        if (t.max > p.max) revert IGovernance.GrantNotNarrower(1);
        if (p.total != 0 && (t.total == 0 || t.total > p.total - p.spentTotal)) revert IGovernance.GrantNotNarrower(2);
        if (p.perWindow != 0 && (t.perWindow == 0 || t.perWindow > p.perWindow)) revert IGovernance.GrantNotNarrower(3);
        if (p.validUntil != 0 && (t.validUntil == 0 || t.validUntil > p.validUntil)) revert IGovernance.GrantNotNarrower(4);
        if (p.maxUses != 0 && (t.maxUses == 0 || t.maxUses > p.maxUses)) revert IGovernance.GrantNotNarrower(5);
    }

    function _onlyOwner(address caller) private view returns (GovernanceStorage storage s) {
        s = $();
        if (caller != s.owner || caller == address(0)) revert IGovernance.NotOwner(caller);
    }

    function _bit(uint8 bit) private pure returns (uint256) {
        return uint256(1) << bit;
    }

    function _lowest(uint256 x) private pure returns (uint8 i) {
        while (x & 1 == 0) { x >>= 1; ++i; }
    }
}
