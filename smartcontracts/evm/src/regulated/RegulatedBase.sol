// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {IRegulatedToken} from "./IRegulatedToken.sol";
import {RegulatedLib} from "./RegulatedLib.sol";
import {IComplianceRegistry} from "./IComplianceRegistry.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {MtxPipelineLib} from "../metatx/MtxPipelineLib.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The regulated layer of kinds 8-13 (CTR-GOV-03, regulated-kinds spec §2.1, §2.2, §3): abstract over `MetaTokenBase`,
///        it overrides the ledger and fee hooks, the masks it shares, `disableFeature`, `supportsInterface`, the init path,
///        and holds the checks `F`, `P`, `R` as internal functions; each control is a thin stub that `DELEGATECALL`s
///        `RegulatedLib` with `_govSubject()` as a word. Each kind lists its base kind first and this second.
/// @notice **UNAUDITED.** Plan T28: `F`, `P`, the pause-open set, the mirror sync, the views and FREEZE, RECORD, FORCE,
///         PAUSE in `RegulatedLib`. Plan T29: `R` through the bounded `hasFlags` call, `canReceive`, `REGISTRY_CODEHASH`.
///         Plan T32: `operatorTransfer` (bit 22, CTR-GOV-20). Bit 21 `MODERATE` has no body (owner 2026-11-05).
abstract contract RegulatedBase is MetaTokenBase {
    /// @dev The bits the regulated kinds add to their base kind's `_validBits()` (spec §2.1, bit 22 CTR-GOV-20): 5-10, 21,
    ///      22 on 8 and 9; without `ALLOWLIST` (8) on the confidential kinds 10-13 (CTR-GOV-17).
    uint256 internal constant REG_BITS = GovernanceBits.REGULATED | (1 << GovernanceBits.RECORD)
        | (1 << GovernanceBits.MODERATE) | (1 << GovernanceBits.OPERATOR_TRANSFER) | (1 << GovernanceBits.TAX);
    uint256 internal constant REG_BITS_CONFIDENTIAL = REG_BITS & ~(uint256(1) << GovernanceBits.ALLOWLIST);
    /// @dev Added to `_roleBits()`: 5, 6, 7, 10, 21 (contract-only, an `msig` UA counts, RK-1) and 22, 23 (any holder).
    uint256 internal constant REG_ROLES = GovernanceBits.REGULATED_ROLES | (1 << GovernanceBits.OPERATOR_TRANSFER)
        | (1 << GovernanceBits.TAX);
    /// @dev Added to `_contractOnlyBits()`: 5, 6, 7, 10, 21; never 22 or 23.
    uint256 internal constant REG_CONTRACT_ONLY = GovernanceBits.REGULATED_ROLES;
    /// @dev The pause-open set (spec §3.2, RK-7), by the inner selector: `unwrap(uint256,address,uint256)`,
    ///      `unwrap(address,uint256,address,uint256)`, `unwrapToUA(address,uint256,bytes32,uint256)`, `burn(uint256)`. A kind
    ///      that does not list one refuses it in `pre*` anyway.
    bytes4 private constant SEL_UNWRAP_MIN = 0x3f069a43;
    bytes4 private constant SEL_UNWRAP_LEG = 0xb5819a02;
    bytes4 private constant SEL_UNWRAP_TO_UA = 0xe4a9f766;
    bytes4 private constant SEL_BURN = 0x42966c68;
    /// @dev The registry flag that satisfies any `requiredFlags`, never `deniedFlags` (CTR-AS-16).
    uint256 private constant ELIGIBLE_CONTRACT = 8;

    /// @dev The registry call's gas cap (spec §5, Codex 4): at least twice the canonical `hasFlags` measured cold, pinned
    ///      (`RegistryFailure.t.sol`). The margin covers the call's own cost (a cold account) before the 63/64 forward.
    uint256 internal constant REGISTRY_GAS = 50_000;
    uint256 internal constant REGISTRY_GAS_MARGIN = 5_000;

    /// @notice The canonical `ComplianceRegistry` runtime's `extcodehash` (F-11), from the release's `implArgs`
    ///         (`abi.encode(bytes32)`, not 0): `initialize` refuses a registry of any other code (`RegistryCodeMismatch`).
    bytes32 public immutable REGISTRY_CODEHASH;

    constructor(bytes memory implArgs) {
        bytes32 h = abi.decode(implArgs, (bytes32));
        if (h == 0) revert IRegulatedToken.RegulatedConfigInvalid();
        REGISTRY_CODEHASH = h;
    }

    /// @dev Base | 6, 21, 22: each power passes the amount it acts on (B-09).
    function _scalarBits() internal pure virtual override returns (uint256) {
        return GovernanceBits.TOKEN_SCALAR | (1 << GovernanceBits.FORCE) | (1 << GovernanceBits.MODERATE)
            | (1 << GovernanceBits.OPERATOR_TRANSFER);
    }

    /// @dev 5, 6, 7: losing them relaxes only after `grantDelay` (spec §3.6); never 23 (pay-meta-tax Q5: the owner's
    ///      revoke of a compromised single-key holder is immediate) or 24 (PQZ proof path spec §5: disabling it freezes).
    function _delayedRelaxBits() internal pure virtual override returns (uint256) {
        return GovernanceBits.ISSUER_BITS & ~((uint256(1) << GovernanceBits.TAX) | (uint256(1) << GovernanceBits.PQZ_PROOF));
    }

    /// @dev `RegulatedLib.init` (spec §2.4) before the kind's own init, so before any mint.
    function _initRaw(bytes calldata initArgs) internal virtual override {
        RegulatedLib.init(initArgs, _validBits(), REGISTRY_CODEHASH, _registry());
        bytes32 r = RegulatedLib.$().taxRecipient;
        if (r != 0) _eligible(r); // `R` at creation too (pay-meta-tax spec §6.2, B-5)
        super._initRaw(initArgs);
    }

    /// @notice Kinds 0-5's answer, and `IRegulatedToken` (M-10).
    function _supportsInterfaceBody(bytes4 id) internal view virtual override returns (bool) {
        return id == type(IRegulatedToken).interfaceId || super._supportsInterfaceBody(id);
    }

    /// @notice The mirror (`controls`) follows `features` only when the disable applied (Codex 3): a proposal changes nothing.
    function _disableFeatureBody(uint8 bit) internal virtual override {
        if (GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) _regDisabled(bit);
    }

    // ------------------------------------------------------------------ the controls (spec §3.1): thin stubs

    function _freezeBody(bytes32 account, bytes32 ref, bytes32 recordId) internal {
        RegulatedLib.freeze(account, ref, recordId, _govSubject());
    }

    function _unfreezeBody(bytes32 account, bytes32 ref) internal {
        RegulatedLib.unfreeze(account, ref, _govSubject());
    }

    /// @notice The library checks the record and counts it; the token checks the beneficiary as a receiver (`R`, a derived
    ///         one registered SIGNING) and moves the public balance on `_poolMove` (no hook: the subject is frozen,
    ///         CTR-GOV-08 Change).
    function _forceTransferBody(bytes32 recordId, uint256 amount) internal {
        (bytes32 from, bytes32 to) = RegulatedLib.forceTransfer(recordId, amount, _govSubject());
        _eligible(to);
        MtxPipelineLib._checkTo(_registry(), to);
        _poolMove(from, to, amount);
    }

    function _pauseBody(bytes32 ref, uint64 until) internal {
        RegulatedLib.pause(ref, until, _govSubject());
    }

    function _unpauseBody(bytes32 ref) internal {
        RegulatedLib.unpause(ref, _govSubject());
    }

    function _recordOrderBody(bytes32 orderId, bytes32 documentHash, bytes32 subject, bytes32 beneficiary, uint256 maxAmount,
        uint64 freezeUntil) internal {
        RegulatedLib.recordOrder(orderId, documentHash, subject, beneficiary, maxAmount, freezeUntil, _govSubject());
    }

    function _revokeOrderBody(bytes32 recordId, bytes32 reasonRef) internal {
        RegulatedLib.revokeOrder(recordId, reasonRef, _govSubject());
    }

    /// @notice Bit 23 (pay-meta-tax spec §6.2): the one PERCENT rate; the factory's `noticePeriod()` read by the library
    ///         from the `FACTORY` passed here, after the holder check (F-20).
    function _setTaxRateBody(uint32 ratePpm) internal {
        RegulatedLib.setTaxRate(ratePpm, FACTORY, _govSubject());
    }

    /// @notice Bit 23: the tax recipient, at once (Q4); the library's checks, then `R` here (F-15).
    function _setTaxRecipientBody(bytes32 taxRecipient) internal {
        RegulatedLib.setTaxRecipient(taxRecipient, _govSubject(), _registry());
        _eligible(taxRecipient);
    }

    /// @notice The payment `t` with its tax (pay-meta-tax spec §5.3, CTR-AS-18 proposed): the payer signs `UAPayWithTax`
    ///         (`t`, `taxMode`, `tax`); `PAYABLE` and `TAX`; `PayMeta`; the tax checked (PERCENT against the effective rate,
    ///         AMOUNT as signed) and its recipient read here (`R`, `F` at the fee-leg seat, RK-6); then one execution:
    ///         payer -> payee `value - tax`, payer -> recipient `tax` (O13); `UAPaymentSettled` gross; `PaymentTaxed`.
    function _mtxPayWithTaxBody(MetaTxLib.UAMetaTransfer calldata t, uint8 taxMode, uint256 tax, IUARegistry.UASig calldata auth,
        MetaTxLib.PayMeta calldata meta) internal returns (bool)
    {
        _taxGates(t.entryRef, meta);
        bytes32 r = _taxTo(t.to, t.value, taxMode, tax);
        bytes32 d = _uaExecuteTransfer(t, _pipePayWithTaxHash(t, taxMode, tax), auth, tax, r); // lever 6
        RegulatedLib.taxed(t.entryRef, t.to, r, t.from, taxMode, tax, d);
        _payRecord(meta, t.to, t.value - tax); // net of the tax withheld (plan T83)
        return true;
    }

    /// @notice The direct twin for a contract payer (spec §5.6, O13): the caller pays, no signature, nonce or fee; not on
    ///         the generic self-call's allow-list (`mtxPayWithTax` is the relayed form).
    function _payWithTaxBody(bytes32 to, uint256 amount, uint8 taxMode, uint256 tax, bytes32 entryRef,
        MetaTxLib.PayMeta calldata meta) internal returns (bool)
    {
        _taxGates(entryRef, meta);
        MtxPipelineLib._checkTo(_registry(), to);
        bytes32 r = _taxTo(to, amount, taxMode, tax);
        bytes32 payer = MetaTxLib.pad(_msgSender());
        _uaSplit(payer, to, amount, tax, r);
        RegulatedLib.directTaxed(entryRef, to, r, payer, amount, taxMode, tax); // lever 8: the two events
        _payRecord(meta, to, amount - tax); // net of the tax withheld (plan T83)
        return true;
    }

    function _taxGates(bytes32 entryRef, MetaTxLib.PayMeta calldata meta) private {
        GovernanceLib.requireFeature(GovernanceBits.PAYABLE);
        GovernanceLib.requireFeature(GovernanceBits.TAX);
        _payMeta(entryRef, meta);
    }

    /// @dev Spec §5.3 steps 3-4: the library's checks return the recipient; `F(r)`, `R(r)` at the fee-leg seat (RK-6).
    function _taxTo(bytes32 to, uint256 value, uint8 taxMode, uint256 tax) private view returns (bytes32 r) {
        r = RegulatedLib.checkTax(to, value, taxMode, tax);
        _regFeeTo(r, tax);
    }

    /// @notice The library refuses and `use`s; the move is `_uaMove`, hooked, so `P`, `F(from)` and `R(to)` apply (§3.4).
    function _operatorTransferBody(bytes32 from, bytes32 to, uint256 amount, bytes32 ref) internal {
        RegulatedLib.operatorTransfer(from, to, amount, ref, _govSubject(), _registry());
        _uaMove(from, to, amount);
    }

    // ------------------------------------------------------------------ views

    function _regulatedConfigBody() internal view returns (IRegulatedToken.RegulatedConfig memory) {
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        return IRegulatedToken.RegulatedConfig(r.complianceRegistry, r.controls, r.requiredFlags, r.deniedFlags, r.termsHash, r.pausedUntil,
            r.pauseCooldownUntil);
    }
    function _freezeOfBody(bytes32 account) internal view returns (IRegulatedToken.FreezeState memory) { return RegulatedLib.$().freezes[account]; }

    /// @notice What a wallet and the node read to build and check a taxed payment (pay-meta-tax spec §6.2).
    function _taxConfigBody() internal view returns (IRegulatedToken.TaxConfig memory c) {
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        IRegulatedToken.TaxRate memory t = r.taxRate;
        c = IRegulatedToken.TaxConfig(r.taxRecipient, GovernanceLib.hasFeature(GovernanceBits.TAX), t.ratePpm, t.pendingPpm, t.eta,
            RegulatedLib.effectiveRate(), IOpenFactory(FACTORY).noticePeriod());
    }
    function _isFrozenBody(bytes32 account) internal view returns (bool) { return RegulatedLib.frozen(account); }

    /// @notice `R(account)` with its reason (spec §3.1): 1 not attested or flags missing, 2 expired, 3 attester disabled,
    ///         4 denied; (true, 0) when it may receive, and with both lists off, without a call. Two bounded calls
    ///         (`attestationOf`, `attesterEnabled`); `ok` equals `hasFlags` on the same masks.
    function _canReceiveBody(bytes32 account) internal view returns (bool ok, uint8 reason) {
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        uint8 c = r.controls;
        if (c & RegulatedLib.C_LISTS == 0) return (true, 0);
        address reg = r.complianceRegistry;
        uint256[3] memory a = _regCall(reg, abi.encodeCall(IComplianceRegistry.attestationOf, (account)), 96);
        uint256 on = _regCall(reg, abi.encodeCall(IComplianceRegistry.attesterEnabled, (uint32(a[2]))), 32)[0];
        if (on > 1) revert IRegulatedToken.RegistryUnavailable(reg);
        bool active = on == 1 && a[1] >= block.timestamp;
        uint256 req = c & RegulatedLib.C_ALLOW != 0 ? r.requiredFlags : 0;
        if (req != 0 && !(active && (a[0] & req == req || a[0] & ELIGIBLE_CONTRACT != 0))) {
            return (false, a[1] == 0 ? 1 : on == 0 ? 3 : !active ? 2 : 1);
        }
        if (c & RegulatedLib.C_DENY != 0 && active && a[0] & r.deniedFlags != 0) return (false, 4);
        return (true, 0);
    }
    function _orderBody(bytes32 recordId) internal view returns (IRegulatedToken.OrderRecord memory) { return RegulatedLib.$().orders[recordId]; }

    // ------------------------------------------------------------------ the hooks (spec §2.2, the rows of §3.2)

    /// @dev The pre row of the public kinds 8, 9, before `pre*` and any signature check (F-09, RK-8): `P` unless the inner
    ///      selector is in the pause-open set and the envelope is not fee-bearing (RK-7); `F(from)`. The confidential kinds
    ///      override it (fee-bearing only, no open set).
    function _regPre(bytes32 from, bytes4 sel, uint32 mode) internal view virtual override {
        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE
            || (sel != SEL_UNWRAP_MIN && sel != SEL_UNWRAP_LEG && sel != SEL_UNWRAP_TO_UA && sel != SEL_BURN)) _notPaused();
        _notFrozen(from);
    }

    /// @dev The fee leg of an envelope and of the pay entries: `fee != 0` ⇒ `F(feeTo)` refused `FeeRecipientFrozen`, `R(feeTo)`.
    function _regFeeTo(bytes32 feeTo, uint256 fee) internal view virtual override {
        if (fee != 0) _feeRecipient(feeTo);
    }

    /// @dev The ledger rows: a mint (`from` 0) `P`, `R(to)`; a burn (`to` 0) `F(from)`, never `P`; a move `P`, `F(from)`, `R(to)`.
    function _regMove(bytes32 from, bytes32 to, uint256) internal view virtual override {
        if (to != 0) _notPaused();
        if (from != 0) _notFrozen(from);
        if (to != 0) _eligible(to);
    }

    /// @dev The payer the moved balance's own call does not name: `_subject()` (a derived signer's ticket, else the caller).
    function _regPayer() internal view virtual override {
        _regSender(_subject());
    }

    function _regSender(bytes32 a) internal view virtual override {
        _notPaused();
        _notFrozen(a);
    }

    function _regName(bytes32 beneficiary) internal view virtual override {
        if (beneficiary != 0) _feeRecipient(beneficiary);
    }

    function _regReceiver(bytes32 recipient) internal view virtual override {
        _eligible(recipient);
    }

    // ------------------------------------------------------------------ the checks (spec §3.2)

    function _notPaused() internal view {
        if (RegulatedLib.paused()) revert IRegulatedToken.TokenPaused(RegulatedLib.$().pausedUntil);
    }

    function _notFrozen(bytes32 a) internal view {
        if (RegulatedLib.frozen(a)) revert IRegulatedToken.Frozen(a);
    }

    function _feeRecipient(bytes32 a) internal view {
        if (RegulatedLib.frozen(a)) revert IRegulatedToken.FeeRecipientFrozen(a);
        _eligible(a);
    }

    /// @dev `R(a)` (CTR-GOV-18), refused `NotEligible(a, 0)`: both lists off, no call; else the bounded `hasFlags(a,
    ///      ALLOWLIST ? requiredFlags : 0, DENYLIST ? deniedFlags : 0)`.
    function _eligible(bytes32 a) internal view {
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        uint8 c = r.controls;
        if (c & RegulatedLib.C_LISTS == 0) return;
        address reg = r.complianceRegistry;
        uint256 w = _regCall(reg, abi.encodeCall(IComplianceRegistry.hasFlags, (a,
            c & RegulatedLib.C_ALLOW != 0 ? r.requiredFlags : 0, c & RegulatedLib.C_DENY != 0 ? r.deniedFlags : 0)), 32)[0];
        if (w > 1) revert IRegulatedToken.RegistryUnavailable(reg);
        if (w == 0) revert IRegulatedToken.NotEligible(a, 0);
    }

    /// @dev The bounded call (spec §5, Codex 4, F-11): never through a Solidity interface. With less than
    ///      `REGISTRY_GAS x 64/63 + margin` left the call is not made (`RegistryGasStarved`: a relayer cannot starve it into
    ///      a failure); a `STATICCALL` with gas `REGISTRY_GAS` into a fixed buffer of `len` bytes; success iff the call
    ///      succeeded and returned exactly `len` bytes, else `RegistryUnavailable`. A failure never means eligible.
    function _regCall(address reg, bytes memory cd, uint256 len) private view returns (uint256[3] memory out) {
        uint256 left = gasleft();
        if (left < REGISTRY_GAS * 64 / 63 + REGISTRY_GAS_MARGIN) revert IRegulatedToken.RegistryGasStarved(REGISTRY_GAS, left);
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            ok := staticcall(REGISTRY_GAS, reg, add(cd, 0x20), mload(cd), out, len)
            size := returndatasize()
        }
        if (!ok || size != len) revert IRegulatedToken.RegistryUnavailable(reg);
    }

    /// @dev Clears `bit` in the mirror when it is one of 5-10, once the disable applied (Codex 3, I12).
    function _regDisabled(uint8 bit) internal {
        if (bit >= GovernanceBits.FREEZE && bit <= GovernanceBits.RECORD) {
            RegulatedLib.$().controls &= ~uint8(1 << (bit - GovernanceBits.FREEZE));
        }
    }
}
