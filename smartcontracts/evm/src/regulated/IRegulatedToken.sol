// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The regulated kinds 8-13 (CTR-GOV-03, regulated-kinds spec §3.1): the controls as direct entries, the views, the
///        errors and events. A regulated kind answers `type(IRegulatedToken).interfaceId` in ERC-165 (M-10); kinds 0-5 do not.
/// @notice **UNAUDITED.** Every entry is `nonReentrant` and gated by `GovernanceUse.use(bit, subject, scalar)`; a relayed
///         holder comes through the `GovernanceRouter` (G19: no `mtx*` twin here). Ids are `bytes32` UA ids (CTR-GOV-01).
interface IRegulatedToken {
    /// @notice `regulatedConfig()`: the hot slot, the flags and the terms in one struct (fewer selectors, spec §3.1).
    struct RegulatedConfig {
        address complianceRegistry;
        uint8 controls; // bits 5-10 of `features`, shifted; byte bit 6 = bit 28 `KYC` (I12, round 3s)
        uint64 requiredFlags;
        uint64 deniedFlags;
        bytes32 termsHash;
        uint64 pausedUntil;
        uint64 pauseCooldownUntil;
    }

    /// @notice Pay-meta-tax spec §6.2: slot +6 of `scaas.regulated`, the one token-wide PERCENT rate (O10).
    struct TaxRate {
        uint32 ratePpm;
        uint32 pendingPpm;
        uint64 eta;
    }

    /// @notice `taxConfig()` (one struct view, B-1).
    struct TaxConfig {
        bytes32 taxRecipient;
        bool enabled;
        uint32 ratePpm;
        uint32 pendingPpm;
        uint64 eta;
        uint32 effectivePpm;
        uint64 noticePeriod;
    }

    /// @notice One account's freeze (spec §2.3): slot a `until ‖ episodeStart ‖ issuerCooldownUntil ‖ recordBacked`, slot b.
    struct FreezeState {
        uint64 until;
        uint64 episodeStart;
        uint64 issuerCooldownUntil;
        bool recordBacked;
        bytes32 recordId;
    }

    /// @notice A recorded order (CTR-AS-04, spec §2.3); `recordId = keccak256(abi.encode(orderId, subject, beneficiary))`.
    struct OrderRecord {
        bytes32 subject;
        bytes32 beneficiary;
        uint64 freezeUntil;
        bool revoked;
        uint256 maxAmount;
        uint256 executed;
    }

    event AccountFrozen(bytes32 indexed account, bytes32 indexed ref, bytes32 recordId, uint64 until);
    event AccountUnfrozen(bytes32 indexed account, bytes32 indexed ref);
    event ForcedTransfer(bytes32 indexed recordId, bytes32 indexed from, bytes32 indexed to, uint256 amount);
    event Paused(bytes32 indexed ref, uint64 until);
    event Unpaused(bytes32 indexed ref);
    event OrderRecorded(bytes32 indexed recordId, bytes32 indexed orderId, bytes32 indexed subject, bytes32 beneficiary,
        uint256 maxAmount, uint64 freezeUntil, bytes32 documentHash);
    event OrderRevoked(bytes32 indexed recordId, bytes32 reasonRef);
    event OperatorTransfer(bytes32 indexed from, bytes32 indexed to, uint256 amount, bytes32 indexed ref);

    /// @notice Pay-meta-tax spec §6.2: `effectiveAt` is now for a decrease, `now + noticePeriod` for an increase.
    event TaxRateSet(uint32 ratePpm, uint64 effectiveAt);
    event TaxRecipientSet(bytes32 indexed taxRecipient);
    /// @notice After the payment's events, also at `tax == 0` (C6, F-05); `digest` 0 on `payWithTax` (no signed struct).
    event PaymentTaxed(bytes32 indexed entryRef, bytes32 indexed payee, bytes32 indexed taxRecipient, bytes32 from,
        uint8 taxMode, uint256 tax, bytes32 digest);

    /// @notice Round 3s (spec 2026-11-10-token-lists.md §6.1, CTR-GOV-24): one event per account of `setAllowed` /
    ///         `setDenied`, `by` the subject (0 for init's row of the initial holder).
    event AllowedSet(bytes32 indexed account, bytes32 indexed by, bool on);
    event DeniedSet(bytes32 indexed account, bytes32 indexed by, bool on);

    error Frozen(bytes32 account);
    /// @notice Round 3s (spec §4.2): `L(account)`, under `ALLOWLIST` not `ALLOWED`, under `DENYLIST` `DENIED`.
    error NotAllowed(bytes32 account);
    error Denied(bytes32 account);
    /// @notice A list batch of 0 or more than 256 accounts; an account 0 in it.
    error ListBatchInvalid(uint256 length);
    error ListAccountZero();
    /// @notice `enableFeature(28)` with no compliance registry (it is set at creation only).
    error ComplianceRegistryNotSet();
    /// @notice `enableFeature(8 | 9)` while the bit has no holder root (Fable P1-1).
    error ListHolderMissing(uint8 bit);
    error TaxRateInvalid(uint32 ratePpm);
    error TaxRecipientInvalid(bytes32 taxRecipient);
    error TaxModeInvalid(uint8 taxMode);
    error TaxExceedsAmount(uint256 tax, uint256 amount);
    error TaxMismatch(uint256 expected, uint256 got);
    error TaxRecipientIsPayee();
    error TokenPaused(uint64 until);
    /// @notice `reason` 0: refused by `hasFlags` on the hot path (under `KYC`); 1-4 from `canReceive`.
    error NotEligible(bytes32 account, uint8 reason);
    error FeeRecipientFrozen(bytes32 account);
    error RefRequired();
    error RegulatedConfigInvalid();
    error ComplianceRegistryCodeMismatch(address complianceRegistry, bytes32 codehash);
    /// @notice The registry's `govRouter()` is neither 0 nor the token's own `ChainEnv.govRouter` (spec
    ///         2026-11-10-admin-not-owner.md §5.3, Fable P1-1): the code hash pins the code, not the router.
    error ComplianceRegistryRouterMismatch(address complianceRegistry, address got);
    error ComplianceRegistryUnavailable(address complianceRegistry);
    error ComplianceRegistryGasStarved(uint256 cap, uint256 left);
    error OrderExists(bytes32 recordId);
    error OrderUnknown(bytes32 recordId);
    error OrderInactive(bytes32 recordId);
    error SubjectNotFrozen(bytes32 subject);
    error OrderExceeded(uint256 remaining);
    error FreezeTooLong(uint64 maxUntil);
    error FreezeCooldown(uint64 until);
    error NotFrozen(bytes32 account);
    error AlreadyRecordFrozen(bytes32 account);
    error RecordFreezeShorter(uint64 until);
    error FreezeTargetRefused(bytes32 account);
    error PauseTooLong(uint64 until);
    error PauseCooldown(uint64 until);
    error ForceTargetRefused(bytes32 account);
    /// @notice `operatorTransfer`'s refusals of CTR-GOV-08 (CTR-GOV-20; spec §3.1's `ModerateTargetRefused`, read for bit
    ///         22): `from == to`, 0, `pad(UA_POOL)`, `pad(SHIELD_POOL)` or the token on either side, a native `from` with code.
    error OperatorTargetRefused(bytes32 account);
    /// @notice `forceTransfer(…, 0)` and `operatorTransfer(…, 0, …)` (F-08). Not in spec §3.1's list (plan T28).
    error AmountZero();
    /// @notice `unpause` while not paused (spec §3.4 "unpause: paused"). Not in spec §3.1's list (plan T28).
    error NotPaused();

    /// @notice Bit 5, issuer (T1, T2, T4 of spec §3.3).
    function freeze(bytes32 account, bytes32 ref, bytes32 recordId) external;
    /// @notice Bit 5, issuer (T5).
    function unfreeze(bytes32 account, bytes32 ref) external;
    /// @notice Bit 6, issuer, scalar `amount`: the subject's public balance to the record's beneficiary.
    function forceTransfer(bytes32 recordId, uint256 amount) external;
    /// @notice Bit 7, issuer (CTR-AS-06).
    function pause(bytes32 ref, uint64 until) external;
    function unpause(bytes32 ref) external;
    /// @notice Bit 10, compliance.
    function recordOrder(bytes32 orderId, bytes32 documentHash, bytes32 subject, bytes32 beneficiary, uint256 maxAmount,
        uint64 freezeUntil) external;
    /// @notice Bit 10, compliance; with `RECORD` disabled the role alone (T8).
    function revokeOrder(bytes32 recordId, bytes32 reasonRef) external;
    /// @notice Bit 22, any holder, scalar `amount` (CTR-GOV-20): public balances only.
    function operatorTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref) external;

    /// @notice Bit 23, any holder (pay-meta-tax spec §6.2): the one PERCENT rate, `<= 10^6` ppm; a decrease at once, an
    ///         increase after the factory's `noticePeriod()`.
    function setTaxRate(uint32 ratePpm) external;
    /// @notice Bit 23: not 0, a pool or the token; a derived id registered SIGNING; not frozen and eligible (`R`).
    function setTaxRecipient(bytes32 taxRecipient) external;
    function taxConfig() external view returns (TaxConfig memory);
    /// @notice Bits 0 (`PAYABLE`) and 23: a payment with its tax, signed `UAPayWithTax` by `t.from` (spec §5.3).
    function mtxPayWithTax(MetaTxLib.UAMetaTransfer calldata t, uint8 taxMode, uint256 tax, IUARegistry.UASig calldata auth,
        MetaTxLib.PayMeta calldata meta) external returns (bool);
    /// @notice The direct twin, the caller pays (spec §5.6).
    function payWithTax(bytes32 to, uint256 amount, uint8 taxMode, uint256 tax, bytes32 entryRef,
        MetaTxLib.PayMeta calldata meta) external returns (bool);

    /// @notice Round 3s (spec §6.1): bit 8's holder writes the allow list, bit 9's the deny list, 1-256 accounts, at once both
    ///         ways; a dormant list (its bit off) too. On 10-13 `setAllowed` exists and always reverts `MissingRole` (bit 8
    ///         is not valid there, so no holder can exist).
    function setAllowed(bytes32[] calldata accounts, bool on) external;
    function setDenied(bytes32[] calldata accounts, bool on) external;
    /// @notice `ALLOWED` (1) | `DENIED` (2).
    function listFlagsOf(bytes32 account) external view returns (uint8);
    /// @notice Round 3s (spec §5.2): the admin switches on 8, 9 or 28 at once; 8 and 9 never go off again. `NotAdmin`, then
    ///         `chainUid_` not the token's chain word (`ChainUidMismatch`, CTR-GOV-28).
    function enableFeature(uint8 bit, bytes32 chainUid_) external;

    function regulatedConfig() external view returns (RegulatedConfig memory);
    function freezeOf(bytes32 account) external view returns (FreezeState memory);
    /// @notice `F(account)` of spec §3.2.
    function isFrozen(bytes32 account) external view returns (bool);
    /// @notice The lists first (round 3s): 5 not on the allow list, 6 on the deny list; then, under `KYC`, 1-4 from the
    ///         registry's `complianceOf` and `kycProviderEnabled`.
    function canReceive(bytes32 account) external view returns (bool ok, uint8 reason);
    function order(bytes32 recordId) external view returns (OrderRecord memory);
}
