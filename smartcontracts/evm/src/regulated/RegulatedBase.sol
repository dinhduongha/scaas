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

/// @title The regulated layer of kinds 8-13 (CTR-GOV-03, regulated-kinds spec §2.1, §2.2, §3): abstract over `MetaTokenBase`,
///        it overrides the ledger and fee hooks, the masks it shares, `disableFeature`, `supportsInterface`, the init path,
///        and holds the checks `F`, `P`, `R` as internal functions; each control is a thin stub that `DELEGATECALL`s
///        `RegulatedLib` with `_govSubject()` as a word. Each kind lists its base kind first and this second.
/// @notice **UNAUDITED.** Plan T28: `F`, `P`, the pause-open set, the mirror sync, the views and FREEZE, RECORD, FORCE,
///         PAUSE in `RegulatedLib`. Plan T29: `R` through the bounded `hasFlags` call, `canReceive`, `REGISTRY_CODEHASH`.
///         Not yet built (it reverts `RegulatedNotBuilt` in `RegulatedLib`): `operatorTransfer` (T32).
abstract contract RegulatedBase is MetaTokenBase, IRegulatedToken {
    /// @dev The bits the regulated kinds add to their base kind's `_validBits()` (spec §2.1, bit 22 CTR-GOV-20): 5-10, 21,
    ///      22 on 8 and 9; without `ALLOWLIST` (8) on the confidential kinds 10-13 (CTR-GOV-17).
    uint256 internal constant REG_BITS = GovernanceBits.REGULATED | (1 << GovernanceBits.RECORD)
        | (1 << GovernanceBits.MODERATE) | (1 << GovernanceBits.OPERATOR_TRANSFER);
    uint256 internal constant REG_BITS_CONFIDENTIAL = REG_BITS & ~(uint256(1) << GovernanceBits.ALLOWLIST);
    /// @dev Added to `_roleBits()`: 5, 6, 7, 10, 21 (contract-only, an `msig` UA counts, RK-1) and 22 (any holder).
    uint256 internal constant REG_ROLES = GovernanceBits.REGULATED_ROLES | (1 << GovernanceBits.OPERATOR_TRANSFER);
    /// @dev Added to `_contractOnlyBits()`: 5, 6, 7, 10, 21; never 22.
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
        if (h == 0) revert RegulatedConfigInvalid();
        REGISTRY_CODEHASH = h;
    }

    /// @dev Base | 6, 21, 22: each power passes the amount it acts on (B-09).
    function _scalarBits() internal pure virtual override returns (uint256) {
        return GovernanceBits.TOKEN_SCALAR | (1 << GovernanceBits.FORCE) | (1 << GovernanceBits.MODERATE)
            | (1 << GovernanceBits.OPERATOR_TRANSFER);
    }

    /// @dev 5, 6, 7: losing them relaxes only after `grantDelay` (spec §3.6).
    function _delayedRelaxBits() internal pure virtual override returns (uint256) {
        return GovernanceBits.ISSUER_BITS;
    }

    /// @dev `RegulatedLib.init` (spec §2.4) before the kind's own init, so before any mint.
    function _initRaw(bytes calldata initArgs) internal virtual override {
        RegulatedLib.init(initArgs, _validBits(), REGISTRY_CODEHASH);
        super._initRaw(initArgs);
    }

    /// @notice Kinds 0-5's answer, and `IRegulatedToken` (M-10).
    function supportsInterface(bytes4 id) public view virtual override returns (bool) {
        return id == type(IRegulatedToken).interfaceId || super.supportsInterface(id);
    }

    /// @notice The mirror (`controls`) follows `features` only when the disable applied (Codex 3): a proposal changes nothing.
    function disableFeature(uint8 bit) external virtual override nonReentrant {
        if (GovernanceLib.disableFeature(bit, _govSubject(), _delayedRelaxBits())) _regDisabled(bit);
    }

    // ------------------------------------------------------------------ the controls (spec §3.1): thin stubs

    function freeze(bytes32 account, bytes32 ref, bytes32 recordId) external nonReentrant {
        RegulatedLib.freeze(account, ref, recordId, _govSubject());
    }

    function unfreeze(bytes32 account, bytes32 ref) external nonReentrant {
        RegulatedLib.unfreeze(account, ref, _govSubject());
    }

    /// @notice The library checks the record and counts it; the token checks the beneficiary as a receiver (`R`, a derived
    ///         one registered SIGNING) and moves the public balance on `_poolMove` (no hook: the subject is frozen,
    ///         CTR-GOV-08 Change).
    function forceTransfer(bytes32 recordId, uint256 amount) external nonReentrant {
        (bytes32 from, bytes32 to) = RegulatedLib.forceTransfer(recordId, amount, _govSubject());
        _eligible(to);
        MtxPipelineLib._checkTo(_REGISTRY, to);
        _poolMove(from, to, amount);
    }

    function pause(bytes32 ref, uint64 until) external nonReentrant {
        RegulatedLib.pause(ref, until, _govSubject());
    }

    function unpause(bytes32 ref) external nonReentrant {
        RegulatedLib.unpause(ref, _govSubject());
    }

    function recordOrder(bytes32 orderId, bytes32 documentHash, bytes32 subject, bytes32 beneficiary, uint256 maxAmount,
        uint64 freezeUntil) external nonReentrant
    {
        RegulatedLib.recordOrder(orderId, documentHash, subject, beneficiary, maxAmount, freezeUntil, _govSubject());
    }

    function revokeOrder(bytes32 recordId, bytes32 reasonRef) external nonReentrant {
        RegulatedLib.revokeOrder(recordId, reasonRef, _govSubject());
    }

    /// @notice The library refuses and `use`s; the move is `_uaMove`, hooked, so `P`, `F(from)` and `R(to)` apply (§3.4).
    function operatorTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref) external nonReentrant {
        RegulatedLib.operatorTransfer(from, to, amount, ref, _govSubject(), _REGISTRY);
        _uaMove(from, to, amount);
    }

    // ------------------------------------------------------------------ views

    function regulatedConfig() external view returns (RegulatedConfig memory) {
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        return RegulatedConfig(r.complianceRegistry, r.controls, r.requiredFlags, r.deniedFlags, r.termsHash, r.pausedUntil,
            r.pauseCooldownUntil);
    }
    function freezeOf(bytes32 account) external view returns (FreezeState memory) { return RegulatedLib.$().freezes[account]; }
    function isFrozen(bytes32 account) external view returns (bool) { return RegulatedLib.frozen(account); }

    /// @notice `R(account)` with its reason (spec §3.1): 1 not attested or flags missing, 2 expired, 3 attester disabled,
    ///         4 denied; (true, 0) when it may receive, and with both lists off, without a call. Two bounded calls
    ///         (`attestationOf`, `attesterEnabled`); `ok` equals `hasFlags` on the same masks.
    function canReceive(bytes32 account) external view returns (bool ok, uint8 reason) {
        RegulatedLib.RegulatedStorage storage r = RegulatedLib.$();
        uint8 c = r.controls;
        if (c & RegulatedLib.C_LISTS == 0) return (true, 0);
        address reg = r.complianceRegistry;
        uint256[3] memory a = _regCall(reg, abi.encodeCall(IComplianceRegistry.attestationOf, (account)), 96);
        uint256 on = _regCall(reg, abi.encodeCall(IComplianceRegistry.attesterEnabled, (uint32(a[2]))), 32)[0];
        if (on > 1) revert RegistryUnavailable(reg);
        bool active = on == 1 && a[1] >= block.timestamp;
        uint256 req = c & RegulatedLib.C_ALLOW != 0 ? r.requiredFlags : 0;
        if (req != 0 && !(active && (a[0] & req == req || a[0] & ELIGIBLE_CONTRACT != 0))) {
            return (false, a[1] == 0 ? 1 : on == 0 ? 3 : !active ? 2 : 1);
        }
        if (c & RegulatedLib.C_DENY != 0 && active && a[0] & r.deniedFlags != 0) return (false, 4);
        return (true, 0);
    }
    function order(bytes32 recordId) external view returns (OrderRecord memory) { return RegulatedLib.$().orders[recordId]; }

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
        if (RegulatedLib.paused()) revert TokenPaused(RegulatedLib.$().pausedUntil);
    }

    function _notFrozen(bytes32 a) internal view {
        if (RegulatedLib.frozen(a)) revert Frozen(a);
    }

    function _feeRecipient(bytes32 a) internal view {
        if (RegulatedLib.frozen(a)) revert FeeRecipientFrozen(a);
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
        if (w > 1) revert RegistryUnavailable(reg);
        if (w == 0) revert NotEligible(a, 0);
    }

    /// @dev The bounded call (spec §5, Codex 4, F-11): never through a Solidity interface. With less than
    ///      `REGISTRY_GAS x 64/63 + margin` left the call is not made (`RegistryGasStarved`: a relayer cannot starve it into
    ///      a failure); a `STATICCALL` with gas `REGISTRY_GAS` into a fixed buffer of `len` bytes; success iff the call
    ///      succeeded and returned exactly `len` bytes, else `RegistryUnavailable`. A failure never means eligible.
    function _regCall(address reg, bytes memory cd, uint256 len) private view returns (uint256[3] memory out) {
        uint256 left = gasleft();
        if (left < REGISTRY_GAS * 64 / 63 + REGISTRY_GAS_MARGIN) revert RegistryGasStarved(REGISTRY_GAS, left);
        bool ok;
        uint256 size;
        assembly ("memory-safe") {
            ok := staticcall(REGISTRY_GAS, reg, add(cd, 0x20), mload(cd), out, len)
            size := returndatasize()
        }
        if (!ok || size != len) revert RegistryUnavailable(reg);
    }

    /// @dev Clears `bit` in the mirror when it is one of 5-10, once the disable applied (Codex 3, I12).
    function _regDisabled(uint8 bit) internal {
        if (bit >= GovernanceBits.FREEZE && bit <= GovernanceBits.RECORD) {
            RegulatedLib.$().controls &= ~uint8(1 << (bit - GovernanceBits.FREEZE));
        }
    }
}
