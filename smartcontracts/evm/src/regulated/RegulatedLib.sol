// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IRegulatedToken} from "./IRegulatedToken.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceUse} from "../governance/GovernanceBase.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {MtxPipelineLib} from "../metatx/MtxPipelineLib.sol";
import {IUALedger} from "../metatx/IUALedger.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IComplianceRegistry} from "./IComplianceRegistry.sol";

/// @title The bodies of the regulated controls (CTR-AS-02's shape, regulated-kinds spec §3.1, §3.3, §3.4), reached by
///        `DELEGATECALL` from the thin stubs of `RegulatedBase`: storage is the token's `scaas.regulated` namespace,
///        `address(this)` the token, `msg.sender` the direct caller (the router or the holder, never the subject): the token
///        passes `_govSubject()` and every immutable it needs as arguments. The checks `F` and `P` and the namespace accessor
///        are `internal`, so the token inlines the same bodies (one rule, one place).
/// @notice **UNAUDITED.** In the release's link closure of every regulated kind 8-13 (`Env.libs`, `libCodeHashes`); it
///         links `GovernanceLib` (`GovernanceUse.use`'s `useLimited`).
library RegulatedLib {
    /// @dev `controls` holds bits 5-10 of `features`, shifted down by 5, and bit 28 `KYC` in byte bit 6 (I12, round 3s):
    ///      `controls == ((features >> 5) & 0x3F) | (((features >> 28) & 1) << 6)`.
    uint8 internal constant C_FREEZE = 1;
    uint8 internal constant C_PAUSE = 1 << 2;
    uint8 internal constant C_ALLOW = 1 << 3;
    uint8 internal constant C_DENY = 1 << 4;
    uint8 internal constant C_LISTS = C_ALLOW | C_DENY;
    uint8 internal constant C_RECORD = 1 << 5;
    uint8 internal constant C_KYC = 1 << 6;
    /// @dev Round 3s (spec §4.1): an account's byte in `listFlags`, both lists in one slot.
    uint8 internal constant ALLOWED = 1;
    uint8 internal constant DENIED = 2;
    /// @dev The longest `setAllowed` / `setDenied` batch (spec §6.1): 3r's row bound, the node's decode bound.
    uint256 internal constant MAX_LIST_BATCH = 256;
    /// @dev CTR-AS-05, CTR-AS-06 (spec §3.5).
    uint64 internal constant FREEZE_SPAN = 30 days;
    uint64 internal constant EPISODE_SPAN = 60 days;
    uint64 internal constant FREEZE_COOLDOWN = 30 days;
    uint64 internal constant PAUSE_SPAN = 7 days;
    /// @dev The bits whose token carries `termsHash` (spec §2.4): 5-9, 10, 21, 28; and each of 8, 9, 28 that can still be
    ///      enabled (round 3s, spec §5.5).
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
        bytes32 taxRecipient;                                             // +5 (pay-meta-tax spec §6.2)
        IRegulatedToken.TaxRate taxRate;                                  // +6
        mapping(bytes32 account => uint8) listFlags;                      // +7 (round 3s, spec §4.1): ALLOWED | DENIED
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

    /// @notice The checks of spec §2.4 (round 3s: §3's rows) on the factory's raw `initArgs`, before the kind's own init and any mint, and the
    ///         namespace written from them. `valid` is the kind's `_validBits()`: a bit outside it is refused first, as
    ///         `GovernanceLib.init` would (bit 8 on 10-13). The roles' holder rules, `RoleConflict` and the owner-0 rule are
    ///         `GovernanceLib.init`'s; the initial-supply recipient's `R` is the mint's own `_regMove`. A compliance
    ///         registry must carry `complianceRegistryCodehash`, the release's `COMPLIANCE_REGISTRY_CODEHASH` (F-11), and its
    ///         `govRouter()` must be 0 or `govRouter`, the token's own `ChainEnv.govRouter` (round 3r, spec
    ///         2026-11-10-admin-not-owner.md §5.3, Fable P1-1: the code hash pins the code, not the router, so another
    ///         router could answer `subject() = admin`); it is written in slot +0. The `govRouter()` read is a plain call
    ///         made only after the code-hash check: on the canonical runtime it is a storage read, and any failure reverts
    ///         the creation (fail closed).
    function init(bytes calldata initArgs, uint256 valid, bytes32 complianceRegistryCodehash, address uaRegistry,
        address govRouter) public
    {
        IFactoryToken.TokenConfig memory cfg = abi.decode(initArgs, (IFactoryToken.TokenConfig));
        uint256 f = cfg.features;
        if (f & ~valid != 0) {
            uint8 b;
            for (uint256 x = f & ~valid; x & 1 == 0; x >>= 1) ++b;
            revert IGovernance.FeatureInvalidForKind(b);
        }
        IFactoryToken.RegulatedParams memory p = cfg.reg;
        address reg = p.complianceRegistry;
        bool freeze_ = f & (1 << GovernanceBits.FREEZE) != 0;
        bool record = f & (1 << GovernanceBits.RECORD) != 0;
        // round 3s (spec §3): `KYC ⇒ registry`; `registry ⇔ masks` (the registry may be set while `KYC` is off, to enable
        // later); no required mask where bit 8 is not valid (10-13: a shielded receiver cannot be checked, I9); `termsHash`
        // for each bit of `TERMS_BITS` set or of 8, 9, 28 that can still be enabled (§5.5)
        if ((f & (1 << GovernanceBits.FORCE) != 0 && !record) || (record && !freeze_)
            || (f & (1 << GovernanceBits.KYC) != 0 && reg == address(0))
            || (reg != address(0)) != ((p.requiredFlags | p.deniedFlags) != 0)
            || (valid & (1 << GovernanceBits.ALLOWLIST) == 0 && p.requiredFlags != 0)
            || (p.termsHash != 0) != (f & TERMS_BITS != 0
                || GovernanceBits.enableable(f, cfg.lockedFeatures, valid, cfg.admin, reg != address(0)) != 0)
            || (p.taxRecipient != 0) != (f & (1 << GovernanceBits.TAX) != 0))
        {
            revert IRegulatedToken.RegulatedConfigInvalid();
        }
        if (reg != address(0)) {
            if (reg.codehash != complianceRegistryCodehash) {
                revert IRegulatedToken.ComplianceRegistryCodeMismatch(reg, reg.codehash);
            }
            address got = IComplianceRegistry(reg).govRouter();
            if (got != address(0) && got != govRouter) revert IRegulatedToken.ComplianceRegistryRouterMismatch(reg, got);
        }
        RegulatedStorage storage s = $();
        (s.complianceRegistry, s.controls) = (reg, mirror(f));
        (s.requiredFlags, s.deniedFlags, s.termsHash) = (p.requiredFlags, p.deniedFlags, p.termsHash);
        if (p.taxRecipient != 0) _taxRecipient(s, p.taxRecipient, uaRegistry); // the rate starts at 0
        // round 3s (spec §3, §6.3, Fable P1-2): under `ALLOWLIST` the initial supply's holder is listed before its mint
        if (f & (1 << GovernanceBits.ALLOWLIST) != 0 && cfg.initialSupply != 0) {
            bytes32 h = MetaTxLib.pad(cfg.initialHolder);
            s.listFlags[h] = ALLOWED;
            emit IRegulatedToken.AllowedSet(h, 0, true);
        }
    }

    /// @notice I12: the `controls` byte of `features` (bits 5-10 shifted down by 5, `KYC` in byte bit 6).
    function mirror(uint256 f) internal pure returns (uint8) {
        return uint8(f >> GovernanceBits.FREEZE) & 0x3F | uint8((f >> GovernanceBits.KYC) & 1) << 6;
    }

    // ------------------------------------------------------------------ the lists (round 3s, spec §6.1, §6.3)

    /// @notice `setAllowed` (`bit` 8, `flag` `ALLOWED`) and `setDenied` (9, `DENIED`), at once both ways: the role as
    ///         `GovernanceUse.use` checks it, without its feature test (a holder writes a dormant list, §6.3), then `1 ≤
    ///         length ≤ MAX_LIST_BATCH`, each account not 0; the other flag never touched; one event per account, `by` the
    ///         subject.
    function setList(uint8 bit, uint8 flag, bytes32[] calldata accounts, bool on, bytes32 subject) public {
        uint8 role = GovernanceLib.$().roles[bit][subject];
        if (role == 0) revert IGovernance.MissingRole(bit, subject);
        if (role == GovernanceLib.LIMITED) GovernanceLib.useLimited(bit, subject, 0);
        uint256 n = accounts.length;
        if (n == 0 || n > MAX_LIST_BATCH) revert IRegulatedToken.ListBatchInvalid(n);
        mapping(bytes32 => uint8) storage m = $().listFlags;
        for (uint256 i; i < n; ++i) {
            bytes32 a = accounts[i];
            if (a == 0) revert IRegulatedToken.ListAccountZero();
            uint8 fl = m[a];
            m[a] = on ? fl | flag : fl & ~flag;
            if (flag == ALLOWED) emit IRegulatedToken.AllowedSet(a, subject, on);
            else emit IRegulatedToken.DeniedSet(a, subject, on);
        }
    }

    // ------------------------------------------------------------------ TAX (pay-meta-tax spec §6, bit 23)

    /// @notice The rate a PERCENT tax is checked against now: the pending one once its `eta` passed.
    function effectiveRate() internal view returns (uint32) {
        IRegulatedToken.TaxRate storage t = $().taxRate;
        return t.eta != 0 && block.timestamp >= t.eta ? t.pendingPpm : t.ratePpm;
    }

    /// @notice Bit 23 (`use`, no scalar). A matured pending rate is folded first; then a rate at or under the effective one
    ///         applies at once and clears the pending one; a higher one waits the factory's `noticePeriod()` (0 possible;
    ///         the token passes its `FACTORY`, an immutable the library cannot read, F-20).
    function setTaxRate(uint32 ratePpm, address factory, bytes32 subject) public {
        GovernanceUse.use(GovernanceBits.TAX, subject, 0);
        if (ratePpm > 1_000_000) revert IRegulatedToken.TaxRateInvalid(ratePpm);
        IRegulatedToken.TaxRate storage t = $().taxRate;
        uint32 eff = effectiveRate();
        uint64 at = uint64(block.timestamp);
        if (ratePpm <= eff) (t.ratePpm, t.pendingPpm, t.eta) = (ratePpm, 0, 0);
        else (t.ratePpm, t.pendingPpm, t.eta) = (eff, ratePpm, at += IOpenFactory(factory).noticePeriod());
        emit IRegulatedToken.TaxRateSet(ratePpm, at);
    }

    /// @notice Spec §5.3 step 3-4: the mode (1 PERCENT, 2 AMOUNT), `tax <= value`, PERCENT `tax == floor(value x rate /
    ///         10^6)` at the effective rate (PT-6), the recipient not the payee. Returns the recipient.
    function checkTax(bytes32 to, uint256 value, uint8 taxMode, uint256 tax) public view returns (bytes32 r) {
        if (taxMode != 1 && taxMode != 2) revert IRegulatedToken.TaxModeInvalid(taxMode);
        if (tax > value) revert IRegulatedToken.TaxExceedsAmount(tax, value);
        if (taxMode == 1) {
            uint256 expected = Math.mulDiv(value, effectiveRate(), 1_000_000);
            if (tax != expected) revert IRegulatedToken.TaxMismatch(expected, tax);
        }
        r = $().taxRecipient;
        if (r == to) revert IRegulatedToken.TaxRecipientIsPayee();
    }

    /// @notice `payWithTax` after its moves (lever 8): `UAPaymentSettled` gross (no fee) and `PaymentTaxed` with digest 0,
    ///         emitted here under `DELEGATECALL` (the logs carry the token's address).
    function directTaxed(bytes32 entryRef, bytes32 to, bytes32 r, bytes32 payer, uint256 amount, uint8 taxMode, uint256 tax)
        public
    {
        emit IUALedger.UAPaymentSettled(payer, to, amount, 0, address(0), entryRef);
        emit IRegulatedToken.PaymentTaxed(entryRef, to, r, payer, taxMode, tax, 0);
    }

    /// @notice `PaymentTaxed` (spec §5.3 step 6), emitted here under `DELEGATECALL`: the log carries the token's address.
    function taxed(bytes32 entryRef, bytes32 payee, bytes32 r, bytes32 from, uint8 taxMode, uint256 tax, bytes32 digest)
        public
    {
        emit IRegulatedToken.PaymentTaxed(entryRef, payee, r, from, taxMode, tax, digest);
    }

    /// @notice Bit 23 (`use`, no scalar), at once (Q4). The token checks `R` after it.
    function setTaxRecipient(bytes32 r, bytes32 subject, address uaRegistry) public {
        GovernanceUse.use(GovernanceBits.TAX, subject, 0);
        _taxRecipient($(), r, uaRegistry);
    }

    /// @dev Not 0, either pool or the token; a derived id registered SIGNING (a record never changes kind); not frozen.
    function _taxRecipient(RegulatedStorage storage s, bytes32 r, address uaRegistry) private {
        if (r == 0 || _pool(r)) revert IRegulatedToken.TaxRecipientInvalid(r);
        if (!UAKinds.inNativeSpace(r)) MtxPipelineLib._checkTo(uaRegistry, r);
        if (frozen(r)) revert IRegulatedToken.Frozen(r);
        s.taxRecipient = r;
        emit IRegulatedToken.TaxRecipientSet(r);
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

    // ------------------------------------------------------------------ OPERATOR_TRANSFER (spec §3.4, CTR-GOV-20)

    /// @notice Bit 22 by `use` with the amount (any holder; `LIMITED` debits its window), then the refusals of CTR-GOV-08:
    ///         `amount` 0, `ref` 0, `from == to`, 0, either pool or the token on either side, a native `from` with code, an
    ///         unregistered or non-SIGNING derived `to` (`_checkTo`). The token then moves on `_uaMove` (hooked: `P`,
    ///         `F(from)`, `R(to)`): public balances only (CTR-GOV-13), never a confidential slot.
    function operatorTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref, bytes32 subject, address uaRegistry)
        public
    {
        GovernanceUse.use(GovernanceBits.OPERATOR_TRANSFER, subject, amount);
        if (amount == 0) revert IRegulatedToken.AmountZero();
        if (ref == 0) revert IRegulatedToken.RefRequired();
        if (from == 0 || from == to || _pool(from)
            || (UAKinds.inNativeSpace(from) && address(uint160(uint256(from))).code.length != 0))
        {
            revert IRegulatedToken.OperatorTargetRefused(from);
        }
        if (to == 0 || _pool(to)) revert IRegulatedToken.OperatorTargetRefused(to);
        MtxPipelineLib._checkTo(uaRegistry, to);
        emit IRegulatedToken.OperatorTransfer(from, to, amount, ref);
    }
}
