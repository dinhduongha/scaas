// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IRegulatedToken} from "./IRegulatedToken.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceUse} from "../governance/GovernanceBase.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @notice Placeholder of what is not built yet: T32 (`operatorTransfer`).
error RegulatedNotBuilt();

/// @title The bodies of the regulated controls (CTR-AS-02's shape, regulated-kinds spec §3.1, §3.3, §3.4), reached by
///        `DELEGATECALL` from the thin stubs of `RegulatedBase`: storage is the token's `scaas.regulated` namespace,
///        `address(this)` the token, `msg.sender` the direct caller (the router or the holder, never the subject): the token
///        passes `_govSubject()` and every immutable it needs as arguments. The checks `F` and `P` and the namespace accessor
///        are `internal`, so the token inlines the same bodies (one rule, one place).
/// @notice **UNAUDITED.** In the release's link closure of every regulated kind 8-13 (`Env.libs`, `libCodeHashes`); it
///         links `GovernanceLib` (`GovernanceUse.use`'s `useLimited`).
library RegulatedLib {
    /// @dev `controls` holds bits 5-10 of `features`, shifted down by 5 (I12).
    uint8 internal constant C_FREEZE = 1;
    uint8 internal constant C_PAUSE = 1 << 2;
    uint8 internal constant C_ALLOW = 1 << 3;
    uint8 internal constant C_DENY = 1 << 4;
    uint8 internal constant C_LISTS = C_ALLOW | C_DENY;
    uint8 internal constant C_RECORD = 1 << 5;
    /// @dev CTR-AS-05, CTR-AS-06 (spec §3.5).
    uint64 internal constant FREEZE_SPAN = 30 days;
    uint64 internal constant EPISODE_SPAN = 60 days;
    uint64 internal constant FREEZE_COOLDOWN = 30 days;
    uint64 internal constant PAUSE_SPAN = 7 days;
    /// @dev The bits whose token carries `termsHash` (spec §2.4): 5-9, 10, 21.
    uint256 internal constant TERMS_BITS =
        GovernanceBits.REGULATED | (1 << GovernanceBits.RECORD) | (1 << GovernanceBits.MODERATE);

    /// @custom:storage-location erc7201:scaas.regulated
    /// @dev Spec §2.3. Slot +0 is the hot slot `F` and `P` read first.
    struct RegulatedStorage {
        address complianceRegistry;                                       // +0
        uint8 controls;
        uint64 pausedUntil;
        uint64 requiredFlags;                                             // +1
        uint64 deniedFlags;
        uint64 pauseCooldownUntil;
        bytes32 termsHash;                                                // +2
        mapping(bytes32 account => IRegulatedToken.FreezeState) freezes;  // +3
        mapping(bytes32 recordId => IRegulatedToken.OrderRecord) orders;  // +4
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.regulated")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xb2c09f76d73c73fd19cb676c5bc2ea2b05d0674d12ed1b6dc6508457a3913d00;

    function $() internal pure returns (RegulatedStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ the checks (spec §3.2), inlined by the token

    /// @notice `F(a)`: bit 5 in `controls`, `until > now`, a record-backed freeze only while `RECORD` is in `controls`,
    ///         and a live issuer root of bit 5 (spec §3.6). An unfrozen holder costs the hot slot and `FreezeState.a`.
    function frozen(bytes32 a) internal view returns (bool) {
        RegulatedStorage storage r = $();
        uint8 c = r.controls;
        return c & C_FREEZE != 0 && _counts(r.freezes[a], c) && GovernanceLib.$().counts[GovernanceBits.FREEZE].roots != 0;
    }

    /// @notice `P`: bit 7 in `controls`, `pausedUntil > now`, a live issuer root of bit 7.
    function paused() internal view returns (bool) {
        RegulatedStorage storage r = $();
        return r.controls & C_PAUSE != 0 && r.pausedUntil > block.timestamp
            && GovernanceLib.$().counts[GovernanceBits.PAUSE].roots != 0;
    }

    /// @dev `frozen(a)` of spec §3.3: `F(a)` without the bit-5 and root terms; a record-backed freeze counts only while
    ///      `RECORD` is in `controls` (T8), so T1 may replace one that no longer counts.
    function _counts(IRegulatedToken.FreezeState storage s, uint8 c) private view returns (bool) {
        return s.until > block.timestamp && (!s.recordBacked || c & C_RECORD != 0);
    }

    // ------------------------------------------------------------------ init (spec §2.4)

    /// @notice The checks of spec §2.4 on the factory's raw `initArgs`, before the kind's own init and any mint, and the
    ///         namespace written from them. `valid` is the kind's `_validBits()`: a bit outside it is refused first, as
    ///         `GovernanceLib.init` would (bit 8 on 10-13). The roles' holder rules, `RoleConflict` and the owner-0 rule are
    ///         `GovernanceLib.init`'s; the initial-supply recipient's `R` is the mint's own `_regMove`. A registry must
    ///         carry `registryCodehash`, the release's `REGISTRY_CODEHASH` (F-11), and is written in slot +0.
    function init(bytes calldata initArgs, uint256 valid, bytes32 registryCodehash) public {
        IFactoryToken.TokenConfig memory cfg = abi.decode(initArgs, (IFactoryToken.TokenConfig));
        uint256 f = cfg.features;
        if (f & ~valid != 0) {
            uint8 b;
            for (uint256 x = f & ~valid; x & 1 == 0; x >>= 1) ++b;
            revert IGovernance.FeatureInvalidForKind(b);
        }
        IFactoryToken.RegulatedParams memory p = cfg.reg;
        bool freeze_ = f & (1 << GovernanceBits.FREEZE) != 0;
        bool record = f & (1 << GovernanceBits.RECORD) != 0;
        bool allow = f & (1 << GovernanceBits.ALLOWLIST) != 0;
        bool deny = f & (1 << GovernanceBits.DENYLIST) != 0;
        if ((f & (1 << GovernanceBits.FORCE) != 0 && !record) || (record && !freeze_)
            || allow != (p.requiredFlags != 0) || deny != (p.deniedFlags != 0)
            || (p.complianceRegistry != address(0)) != (allow || deny) || (p.termsHash != 0) != (f & TERMS_BITS != 0))
        {
            revert IRegulatedToken.RegulatedConfigInvalid();
        }
        address reg = p.complianceRegistry;
        if (reg != address(0) && reg.codehash != registryCodehash) {
            revert IRegulatedToken.RegistryCodeMismatch(reg, reg.codehash);
        }
        RegulatedStorage storage s = $();
        (s.complianceRegistry, s.controls) = (reg, uint8(f >> GovernanceBits.FREEZE) & 0x3F);
        (s.requiredFlags, s.deniedFlags, s.termsHash) = (p.requiredFlags, p.deniedFlags, p.termsHash);
    }

    // ------------------------------------------------------------------ FREEZE (spec §3.3 T1-T5)

    /// @notice T1-T4: an issuer-only freeze (`recordId` 0) or a record-backed one.
    function freeze(bytes32 account, bytes32 ref, bytes32 recordId, bytes32 subject) public {
        GovernanceUse.use(GovernanceBits.FREEZE, subject, 0);
        _target(account);
        if (ref == 0) revert IRegulatedToken.RefRequired();
        RegulatedStorage storage r = $();
        IRegulatedToken.FreezeState storage s = r.freezes[account];
        bool on = _counts(s, r.controls);
        uint64 now_ = uint64(block.timestamp);
        if (recordId == 0) {
            if (!on) { // T1
                if (now_ < s.issuerCooldownUntil) revert IRegulatedToken.FreezeCooldown(s.issuerCooldownUntil);
                (s.episodeStart, s.until, s.recordBacked, s.recordId) = (now_, now_ + FREEZE_SPAN, false, 0);
            } else { // T2, T3
                if (s.recordBacked) revert IRegulatedToken.AlreadyRecordFrozen(account);
                uint64 cap = s.episodeStart + EPISODE_SPAN;
                uint64 n = now_ + FREEZE_SPAN < cap ? now_ + FREEZE_SPAN : cap;
                if (n <= s.until) revert IRegulatedToken.FreezeTooLong(cap);
                s.until = n;
            }
            s.issuerCooldownUntil = s.until + FREEZE_COOLDOWN;
        } else { // T4
            IRegulatedToken.OrderRecord storage o = _live(r, recordId);
            if (o.subject != account || o.freezeUntil <= now_) revert IRegulatedToken.OrderInactive(recordId);
            if (on && o.freezeUntil < s.until) revert IRegulatedToken.RecordFreezeShorter(s.until);
            (s.until, s.recordBacked, s.recordId) = (o.freezeUntil, true, recordId);
        }
        emit IRegulatedToken.AccountFrozen(account, ref, recordId, s.until);
    }

    /// @notice T5: ends a freeze that counts, issuer-only or record-backed; the issuer cooldown starts.
    function unfreeze(bytes32 account, bytes32 ref, bytes32 subject) public {
        GovernanceUse.use(GovernanceBits.FREEZE, subject, 0);
        if (ref == 0) revert IRegulatedToken.RefRequired();
        RegulatedStorage storage r = $();
        IRegulatedToken.FreezeState storage s = r.freezes[account];
        if (!_counts(s, r.controls)) revert IRegulatedToken.NotFrozen(account);
        _end(s, account, ref);
    }

    /// @dev T5's effect (also T6's): `until = now`, record cleared, the issuer cooldown from now.
    function _end(IRegulatedToken.FreezeState storage s, bytes32 account, bytes32 ref) private {
        uint64 now_ = uint64(block.timestamp);
        (s.until, s.recordBacked, s.recordId, s.issuerCooldownUntil) = (now_, false, 0, now_ + FREEZE_COOLDOWN);
        emit IRegulatedToken.AccountUnfrozen(account, ref);
    }

    /// @dev Spec §3.3 T1: never 0, either pool or the token itself.
    function _target(bytes32 a) private view {
        if (a == 0 || _pool(a)) revert IRegulatedToken.FreezeTargetRefused(a);
    }

    function _pool(bytes32 a) private view returns (bool) {
        return a == MetaTxLib.pad(MetaTxLib.UA_POOL) || a == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)
            || a == MetaTxLib.pad(address(this));
    }

    /// @dev A live record (F-02): it exists, is not revoked, and `RECORD` is in `controls`.
    function _live(RegulatedStorage storage r, bytes32 recordId)
        private view returns (IRegulatedToken.OrderRecord storage o)
    {
        o = r.orders[recordId];
        if (o.subject == 0) revert IRegulatedToken.OrderUnknown(recordId);
        if (o.revoked || r.controls & C_RECORD == 0) revert IRegulatedToken.OrderInactive(recordId);
    }

    // ------------------------------------------------------------------ FORCE, RECORD (spec §3.3)

    /// @notice Bit 6 (`use` with the amount) and `RECORD` active (bit 10 in `controls` and a live compliance root); the
    ///         record live, `amount != 0`, `F(subject)`, within `maxAmount`, `!F(beneficiary)`; then `executed += amount`.
    ///         Returns the move the token makes on `_poolMove` (after `R(beneficiary)` and the receiver rule).
    function forceTransfer(bytes32 recordId, uint256 amount, bytes32 subject) public returns (bytes32, bytes32) {
        GovernanceUse.use(GovernanceBits.FORCE, subject, amount);
        RegulatedStorage storage r = $();
        IRegulatedToken.OrderRecord storage o = _live(r, recordId);
        if (GovernanceLib.$().counts[GovernanceBits.RECORD].roots == 0) revert IRegulatedToken.OrderInactive(recordId);
        if (amount == 0) revert IRegulatedToken.AmountZero();
        bytes32 from = o.subject;
        bytes32 to = o.beneficiary;
        if (!frozen(from)) revert IRegulatedToken.SubjectNotFrozen(from);
        uint256 done = o.executed;
        if (amount > o.maxAmount - done) revert IRegulatedToken.OrderExceeded(o.maxAmount - done);
        if (frozen(to)) revert IRegulatedToken.Frozen(to);
        o.executed = done + amount;
        emit IRegulatedToken.ForcedTransfer(recordId, from, to, amount);
        return (from, to);
    }

    /// @notice Bit 10, compliance (spec §3.3): refs set, two distinct ids neither a pool nor the token, an amount or a
    ///         future freeze, a fresh `recordId`.
    function recordOrder(bytes32 orderId, bytes32 documentHash, bytes32 recordSubject, bytes32 beneficiary,
        uint256 maxAmount, uint64 freezeUntil, bytes32 subject) public
    {
        GovernanceUse.use(GovernanceBits.RECORD, subject, 0);
        if (orderId == 0 || documentHash == 0) revert IRegulatedToken.RefRequired();
        if (recordSubject == 0 || _pool(recordSubject)) revert IRegulatedToken.ForceTargetRefused(recordSubject);
        if (beneficiary == 0 || beneficiary == recordSubject || _pool(beneficiary)) {
            revert IRegulatedToken.ForceTargetRefused(beneficiary);
        }
        bytes32 id = keccak256(abi.encode(orderId, recordSubject, beneficiary));
        if (maxAmount == 0 && freezeUntil <= block.timestamp) revert IRegulatedToken.OrderInactive(id);
        IRegulatedToken.OrderRecord storage o = $().orders[id];
        if (o.subject != 0) revert IRegulatedToken.OrderExists(id);
        (o.subject, o.beneficiary, o.freezeUntil, o.maxAmount) = (recordSubject, beneficiary, freezeUntil, maxAmount);
        emit IRegulatedToken.OrderRecorded(id, orderId, recordSubject, beneficiary, maxAmount, freezeUntil, documentHash);
    }

    /// @notice T6: bit 10 by `use`, or, with `RECORD` disabled, the role alone (a revoke only relaxes, T8); the record
    ///         revoked, and the freeze it backs ended (`AccountUnfrozen`, the issuer cooldown starts).
    function revokeOrder(bytes32 recordId, bytes32 reasonRef, bytes32 subject) public {
        RegulatedStorage storage r = $();
        if (r.controls & C_RECORD != 0) {
            GovernanceUse.use(GovernanceBits.RECORD, subject, 0);
        } else if (!GovernanceLib.hasRole(GovernanceBits.RECORD, subject)) {
            revert IGovernance.MissingRole(GovernanceBits.RECORD, subject);
        }
        if (reasonRef == 0) revert IRegulatedToken.RefRequired();
        IRegulatedToken.OrderRecord storage o = r.orders[recordId];
        if (o.subject == 0) revert IRegulatedToken.OrderUnknown(recordId);
        if (o.revoked) revert IRegulatedToken.OrderInactive(recordId);
        o.revoked = true;
        emit IRegulatedToken.OrderRevoked(recordId, reasonRef);
        IRegulatedToken.FreezeState storage s = r.freezes[o.subject];
        if (s.recordId == recordId && _counts(s, r.controls)) _end(s, o.subject, reasonRef);
    }

    // ------------------------------------------------------------------ PAUSE (spec §3.4, CTR-AS-06)

    function pause(bytes32 ref, uint64 until, bytes32 subject) public {
        GovernanceUse.use(GovernanceBits.PAUSE, subject, 0);
        if (ref == 0) revert IRegulatedToken.RefRequired();
        uint64 now_ = uint64(block.timestamp);
        if (until <= now_ || until > now_ + PAUSE_SPAN) revert IRegulatedToken.PauseTooLong(now_ + PAUSE_SPAN);
        RegulatedStorage storage r = $();
        if (now_ < r.pauseCooldownUntil) revert IRegulatedToken.PauseCooldown(r.pauseCooldownUntil);
        (r.pausedUntil, r.pauseCooldownUntil) = (until, until + PAUSE_SPAN);
        emit IRegulatedToken.Paused(ref, until);
    }

    function unpause(bytes32 ref, bytes32 subject) public {
        GovernanceUse.use(GovernanceBits.PAUSE, subject, 0);
        if (ref == 0) revert IRegulatedToken.RefRequired();
        RegulatedStorage storage r = $();
        uint64 now_ = uint64(block.timestamp);
        if (r.pausedUntil <= now_) revert IRegulatedToken.NotPaused();
        (r.pausedUntil, r.pauseCooldownUntil) = (now_, now_ + PAUSE_SPAN);
        emit IRegulatedToken.Unpaused(ref);
    }

    // ------------------------------------------------------------------ OPERATOR_TRANSFER (T32)

    /// @notice The refusals of CTR-GOV-08 and CTR-GOV-13 and the power's `use`; the token then moves on `_uaMove` (hooked).
    function operatorTransfer(bytes32 /* from */, bytes32 /* to */, uint256 /* amount */, bytes32 /* ref */,
        bytes32 /* subject */, address /* uaRegistry */) public pure
    {
        revert RegulatedNotBuilt();
    }
}
