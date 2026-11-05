// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {IRegulatedToken} from "./IRegulatedToken.sol";
import {RegulatedLib, RegulatedNotBuilt} from "./RegulatedLib.sol";

/// @title The regulated layer of kinds 8-13 (CTR-GOV-03, regulated-kinds spec §2.1, §2.2, §3): abstract over `MetaTokenBase`,
///        it overrides the ledger and fee hooks, the masks it shares, `disableFeature`, `supportsInterface`, the init path,
///        and holds the checks `F`, `P`, `R` as internal functions; each control is a thin stub that `DELEGATECALL`s
///        `RegulatedLib` with `_govSubject()` as a word. Each kind lists its base kind first and this second.
/// @notice **UNAUDITED.** Skeleton (plan T27): every hook seat and row of spec §3.2 is wired; the three checks, the mirror
///         sync, the views and `RegulatedLib`'s bodies revert `RegulatedNotBuilt` until T28 / T29 / T32. Not yet built
///         here: the pause-open set of the pre row (T28), the bounded registry call (T29), the `REGISTRY_CODEHASH`
///         immutable (T29).
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
        RegulatedLib.init(initArgs);
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

    /// @notice The library checks the record and counts it; the token moves the public balance on `_poolMove` (no hook:
    ///         the subject is frozen, CTR-GOV-08 Change).
    function forceTransfer(bytes32 recordId, uint256 amount) external nonReentrant {
        (bytes32 from, bytes32 to) = RegulatedLib.forceTransfer(recordId, amount, _govSubject());
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

    function regulatedConfig() external view returns (RegulatedConfig memory c) { _notBuilt(); return c; }
    function freezeOf(bytes32) external view returns (FreezeState memory s) { _notBuilt(); return s; }
    function isFrozen(bytes32 account) external view returns (bool) { return _frozen(account); }
    function canReceive(bytes32) external view returns (bool ok, uint8 reason) { _notBuilt(); return (ok, reason); }
    function order(bytes32) external view returns (OrderRecord memory r) { _notBuilt(); return r; }

    // ------------------------------------------------------------------ the hooks (spec §2.2, the rows of §3.2)

    /// @dev The pre row of the public kinds 8, 9, before `pre*` and any signature check (F-09): `P`, `F(from)`. The
    ///      confidential kinds override it (fee-bearing only).
    function _regPre(bytes32 from, bytes4, uint32) internal view virtual override {
        _notPaused();
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
        if (_paused()) revert TokenPaused(0);
    }

    function _notFrozen(bytes32 a) internal view {
        if (_frozen(a)) revert Frozen(a);
    }

    function _feeRecipient(bytes32 a) internal view {
        if (_frozen(a)) revert FeeRecipientFrozen(a);
        _eligible(a);
    }

    /// @dev `P` (T28).
    function _paused() internal view returns (bool) {
        _notBuilt();
        return false;
    }

    /// @dev `F(a)` (T28).
    function _frozen(bytes32) internal view returns (bool) {
        _notBuilt();
        return false;
    }

    /// @dev `R(a)`, refused `NotEligible(a, 0)` (T29: the bounded `hasFlags` call; both lists off, no call).
    function _eligible(bytes32) internal view {
        _notBuilt();
    }

    /// @dev Clears `bit` in the mirror when it is one of 5-10 (T28).
    function _regDisabled(uint8 bit) internal view {
        if (bit >= GovernanceBits.FREEZE && bit <= GovernanceBits.RECORD) _notBuilt();
    }

    /// @dev `view` with a condition always true, as the bodies that replace it read storage (no mutability warning upstream).
    function _notBuilt() private view {
        if (address(this) != address(0)) revert RegulatedNotBuilt();
    }
}
