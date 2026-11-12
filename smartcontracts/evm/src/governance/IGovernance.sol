// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IAdmin} from "./IAdmin.sol";

/// @title The governance surface of every SCaaS contract (CTR-GOV-01, CTR-TOK-22); events and errors raised by
///        `GovernanceLib`. The admin's views, entries, events and errors are `IAdmin`'s (CTR-GOV-23); this adds `renounceAdmin(chainUid_)`.
interface IGovernance is IAdmin {
    /// @notice A capability has no holder and binds or serves everyone; a power has holders. The type is `_roleBits()`.
    enum BitType { CAPABILITY, POWER }

    /// @notice What a grantor chooses (CTR-GOV-02). 0 = no bound, except `max`: `type(uint128).max` = no bound. `delegable`
    ///         only from the admin: a leaf cannot delegate. `scope` is opaque to the base; the contract reads it.
    struct GrantTerms {
        uint128 min;
        uint128 max;
        uint128 total;
        uint128 perWindow;
        uint32 window;
        uint64 validUntil;
        uint32 maxUses;
        bool delegable;
        bytes32 scope;
    }

    /// @notice A limited holder's record: the terms plus what has been spent, which an edit carries (six slots).
    ///         Every identity this interface names is a UA id (`bytes32`): a native account's is its padded address, a
    ///         derived UA's its registered id (CTR-GOV-01 Change, owner 2026-11-04).
    struct Grant {
        uint128 min;
        uint128 max;
        uint128 total;
        uint128 spentTotal;
        uint128 perWindow;
        uint128 spentInWindow;
        uint32 window;
        uint32 windowStart;
        uint64 validUntil;
        uint32 maxUses;
        uint32 uses;
        uint32 grantorEpoch;
        bool delegable;
        /// @dev Set by the admin's revoke: only the admin re-admits the account (B-05, spec §1.5).
        bool barred;
        bytes32 scope;
        /// @dev The UA that granted a leaf; 0 on a root (CTR-GOV-01 Change: every identity is a UA id).
        bytes32 grantor;
    }

    event RoleGranted(uint8 indexed bit, bytes32 indexed account, bytes32 indexed sender);
    event RoleRevoked(uint8 indexed bit, bytes32 indexed account, bytes32 indexed sender);
    event FeatureDisabled(uint8 indexed bit, bytes32 indexed by);
    /// @notice Round 3s (CTR-GOV-24): `enableFeature` of 8, 9 or 28 on a regulated kind, at once.
    event FeatureEnabled(uint8 indexed bit, bytes32 indexed by);
    event GrantSet(uint8 indexed bit, bytes32 indexed holder, bytes32 indexed grantor);
    event GrantUsed(uint8 indexed bit, bytes32 indexed holder, uint256 scalar);
    /// @notice The first of the admin's two calls (spec §1.6): `terms` for a wallet to compare with the pending's
    ///         `commit`; `whole` is a `grantRole`, its terms empty.
    event GrantProposed(uint8 indexed bit, bytes32 indexed account, bytes32 indexed proposer, uint64 eta, bool whole,
        GrantTerms terms);
    event GrantCancelled(uint8 indexed bit, bytes32 indexed account, bytes32 indexed by);
    /// @notice The first call of a relaxation on a bit of the contract's `_delayedRelaxBits()` (spec
    ///         `2026-11-05-regulated-kinds.md` §3.6, RK-2): `action` 3 revoke, 4 renounce, 5 disable (`account` 0). Nothing
    ///         changes now (RK-3); `proposer` alone confirms, in `[eta, eta + grantDelay]` and the same admin generation.
    event RelaxProposed(uint8 indexed bit, bytes32 indexed account, uint8 action, bytes32 proposer, uint64 eta);

    error FeatureInvalidForKind(uint8 bit);
    error FeatureNotBuilt(uint8 bit);
    error LockedNotSubset();
    error RoleWithoutFeature(uint8 bit);
    error RoleNotContract(uint8 bit, bytes32 account);
    error RoleAccountZero(uint8 bit);
    error NoSuchRole(uint8 bit);
    error FeatureLocked(uint8 bit);
    error FeatureNotSet(uint8 bit);
    /// @notice Round 3s (CTR-GOV-24): `enableFeature` of a bit outside 8, 9, 28; `disableFeature` of 8 or 9 (once on, never
    ///         off); `enableFeature` of a bit already set.
    error FeatureNotEnableable(uint8 bit);
    error FeatureNotDisableable(uint8 bit);
    error FeatureAlreadySet(uint8 bit);
    error MissingRole(uint8 bit, bytes32 account);
    /// @notice No band is refused since CTR-GOV-10's Change (owner 2026-11-04): bits 0-127 are SCaaS's, 128-255 each
    ///         application's, and a `uint8` bit and the `uint256` word hold no other. No path raises it; the declaration stays.
    error FeatureReserved(uint8 bit);
    /// @notice `UA_POOL` and `SHIELD_POOL` hold no power.
    error RoleAccountPool(uint8 bit, bytes32 account);
    /// @notice A leaf's term is wider than its parent's (`field`: 0 min, 1 max, 2 total, 3 perWindow, 4 validUntil, 5 maxUses,
    ///         6 delegable, 7 scope, 8 window).
    error GrantNotNarrower(uint8 field);
    /// @notice A word the contract does not bind for `bit` (spec §1.5, B-09, B-10): outside `_scalarBits()` any of `min` (0),
    ///         `max` (1), `total` (2), `perWindow` (3), `window` (8); outside `_scopeBits()` a non-zero `scope`, inside it a zero
    ///         one (7); `perWindow` and `window` not set together (3).
    error GrantWordRefused(uint8 bit, uint8 field);
    /// @notice A `delegable` grant with no finite budget: `total` on a scalar bit, `maxUses` on another (B-02). The budget
    ///         bounds what the leaves spend, not how many leaves exist: a leaf spends nothing until it acts.
    error GrantBudgetRequired(uint8 bit);
    /// @notice `UA_POOL` and `SHIELD_POOL` are never admin (B-19).
    error AdminAccountPool(bytes32 account);
    /// @notice The scalar or the use is outside the grant (`field`: 0 min, 1 max, 2 total, 3 perWindow, 5 maxUses, 7 parent).
    error GrantExhausted(uint8 field);
    error GrantExpired(uint8 bit, bytes32 holder);
    /// @notice The admin's revoke barred `account`: only the admin re-admits it (B-05, spec §1.5).
    error GrantBarred(uint8 bit, bytes32 account);
    /// @notice A change of `window` while the spent period still runs on the new grid (B-12, spec §1.5).
    error GrantWindowInUse(uint8 bit, bytes32 holder);
    /// @notice `renounceAdmin` while a bit that is not locked has holders (CTR-GOV-02).
    error AdminHasHolders(uint8 bit);
    /// @notice A `grantDelay` above 30 days at creation (B-27).
    error GrantDelayTooLong(uint64 delay);
    /// @notice The confirm before `eta`.
    error GrantNotReady(uint8 bit, bytes32 account, uint64 eta);
    /// @notice A live pending at `(bit, account)` commits to another action or other terms (spec §3.6): cancel it, or let it
    ///         die, and propose again.
    error GrantTermsMismatch(uint8 bit, bytes32 account);
    /// @notice The confirm of a live pending by another id than the one that proposed it (spec §3.6, RK-2).
    error NotProposer(uint8 bit, bytes32 account, bytes32 proposer);
    /// @notice One id would hold both `FORCE` (6) and `RECORD` (10) (CTR-AS-03): `bit` is the one being granted.
    error RoleConflict(uint8 bit, bytes32 account);

    function features() external view returns (uint256);
    function lockedFeatures() external view returns (uint256);
    function hasRole(uint8 bit, bytes32 account) external view returns (bool);
    function validBits() external view returns (uint256);
    function holderCount(uint8 bit) external view returns (uint256);
    function grantDelay() external view returns (uint64);
    function lastProposedAt() external view returns (uint64);
    /// @notice A pending at `(bit, account)`, dead ones too: `live` while `eta != 0`, the admin generation that proposed it
    ///         is the current one and `now <= eta + grantDelay` (spec §1.6). `commit` is `keccak256(abi.encode(action, bit,
    ///         account, argsHash))`: action 1 grant, 2 set (`argsHash` the terms' hash), 3 revoke, 4 renounce, 5 disable
    ///         (`account` 0), `argsHash` 0 but for set (regulated-kinds spec §3.6).
    function pendingGrant(uint8 bit, bytes32 account)
        external view returns (uint64 eta, bytes32 proposer, bytes32 commit, bool live);
    /// @notice The admin, or the pending's proposer, deletes a pending of any action. `chainUid_` this contract's chain word
    ///         (`ChainUidMismatch`, CTR-GOV-28), as on `setGrant` and `revokeRole`: a stranger is `NotAdmin` first; the
    ///         admin's word is checked before any write, another caller's after its own checks (the call reverting whole).
    function cancelGrant(uint8 bit, bytes32 account, bytes32 chainUid_) external;
    function grantOf(uint8 bit, bytes32 holder) external view returns (Grant memory);
    function setGrant(uint8 bit, bytes32 holder, GrantTerms calldata terms, bytes32 chainUid_) external;
    /// @notice The label of an application bit (128-255): its type, the entry it gates, a name for a wallet.
    function bitLabel(uint8 bit) external view returns (BitType, bytes4, string memory);
    /// @notice The admin's; `NotAdmin`, then `chainUid_` not this contract's chain word (`ChainUidMismatch`, CTR-GOV-28), as
    ///         on `disableFeature`.
    function grantRole(uint8 bit, bytes32 account, bytes32 chainUid_) external;
    /// @notice The admin, or a leaf's grantor; the caller, then the word (`ChainUidMismatch`, CTR-GOV-28).
    function revokeRole(uint8 bit, bytes32 account, bytes32 chainUid_) external;
    /// @notice A holder's own, no word (a role entry, not an admin entry).
    function renounceRole(uint8 bit) external;
    function disableFeature(uint8 bit, bytes32 chainUid_) external;
    /// @notice The admin becomes 0 for good. Refused in order: `NotAdmin`, then `chainUid_` not this contract's chain word
    ///         (`ChainUidMismatch`, Fable recheck-2 P3-1: a native admin's direct call is void on a sibling), then
    ///         `AdminHasHolders` while a live holder stays.
    function renounceAdmin(bytes32 chainUid_) external;
}
