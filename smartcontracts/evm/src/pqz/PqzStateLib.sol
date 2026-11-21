// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken, ENV_PQZ_VERIFIER} from "../factory/IFactoryToken.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";
import {PqzCt} from "./PqzCt.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {PqzKeyVerifier} from "./PqzKeyVerifier.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzSet, PQZ_ACC_WORDS} from "./PqzSet.sol";
import {PqzVerifierRevoked} from "./IPqzToken.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {IAdmin} from "../governance/IAdmin.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {AuditorRules} from "../confidential/AuditorRules.sol";

/// @title init, shield, rollover, prepare-acc and the state views (the account state; D14): one of the four `DELEGATECALL` libraries of the PQZ release (plan 5h D14), in the ERC-7201
///        namespace `scaas.pqz`; the shared steps are `internal` in `PqzCore`, compiled into each.
/// @notice **UNAUDITED.** `address(this)` is the token.
library PqzStateLib {
    /// @notice The PQZ kinds' checks of an instance env (CTR-ZTH-20 / CTR-PQZ-10; the constructors' before chain-neutral
    ///         releases, now `validateEnv`, which the factory calls once per release and chain): exactly one dep, the
    ///         release's `PqzKeyVerifier` (`ENV_PQZ_VERIFIER`) with code or 0 (group 3f, spec §3, C6: the zero-dep release of
    ///         a chain where it cannot be deployed; only an `OFFCHAIN` token initialises on it), never Hedera, a registry
    ///         with code. The mode is never inferred from a missing dependency.
    function validateEnv(address[] calldata d, bool hedera, address registry) public view {
        if (
            d.length != 1 || hedera || (d[ENV_PQZ_VERIFIER] != address(0) && !SigCheck.isContract(d[ENV_PQZ_VERIFIER]))
                || !SigCheck.isContract(registry)
        ) {
            revert IPqzToken.BadInit();
        }
    }

    /// @notice The kind's `_init` (P6g plan D9): `verifier` the release's `PqzKeyVerifier` (CTR-ZTH-20: the creator never
    ///         chooses one; precompile and proof system: exactly `PqzSafety.PQZ`, PQZL or PQZH,
    ///         the self-test passing now; review W-B), `auditorKey` empty or the auditor's 32-byte `pqz-mlwe` UA, cap
    ///         `≤ 2^62`, `confidentialFee + 8 · minDecoyFee` `< 2^64` and `< cap` (no chain-level floor, owner 2026-10-20).
    ///         Group 3f (spec §3, §4): the mode, written here only (I1). `PRECOMPILE`: no verifier field set, a release
    ///         verifier 0 refused `SelfTestFailed(address(0))` before any call, then the reads and the self-test as before.
    ///         `OFFCHAIN`: a verifier UA of spec §4.1 (`verifierShape` strict), its shape, fixed or transferable, the
    ///         factory's `noticePeriod()` stored (nothing later shortens it); `psid` the build's PQZL id; nothing read
    ///         from the release verifier, the precompile never called. The auditor's key passes the mode's check.
    ///         Round 3t (CTR-PQZ-36, verifier fee spec §3.3), in this order: the range row with the cap,
    ///         `confidentialFee + verifierFeeMax + 8 · minDecoyFee` `< 2^64` and `< cap` (`BadInit`; controller call 2: every
    ///         fee the setter can write keeps it); `PRECOMPILE` with a fee or a cap `PqzVerifyConfigInvalid`; `OFFCHAIN` with
    ///         `verifierFee > verifierFeeMax` `VerifierFeeAboveMax`; both written on `OFFCHAIN`.
    function init(IFactoryToken.ConfidentialConfig memory c, address registry, address verifier, address factory)
        public
    {
        bytes memory aud = c.auditorKey;
        if (
            c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > PqzCore.MAX_TOTAL_SHIELDED
                || c.confidentialFee >= PqzCore.VALUE_BOUND || c.confidentialFee >= c.maxShielded
                || c.minDecoyFee >= PqzCore.VALUE_BOUND
                || c.confidentialFee + c.verifierFeeMax + 8 * c.minDecoyFee >= PqzCore.VALUE_BOUND
                || c.confidentialFee + c.verifierFeeMax + 8 * c.minDecoyFee >= c.maxShielded
                || (aud.length != 0 && aud.length != 32) || c.maxShielded > type(uint256).max / c.shieldScale
        ) {
            revert IPqzToken.BadInit();
        }
        if (c.disclosureMode > uint8(ZetherTypes.DisclosureMode.COMPACT)) {
            revert IPqzToken.BadDisclosureMode(c.disclosureMode);
        }
        if (
            c.auditorMode > uint8(ZetherTypes.AuditorMode.OPTIONAL)
                || (aud.length == 0) != (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE))
        ) {
            revert IPqzToken.BadAuditorMode(c.auditorMode);
        }
        {
            // CTR-GOV-31, after `GovernanceLib.init`: bit 32 needs an auditor and an admin (as `ZetherLib.auditorBitAtInit`)
            GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
            if (g.features >> GovernanceBits.AUDITOR & 1 != 0) {
                if (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE)) {
                    revert IPqzToken.BadAuditorMode(c.auditorMode);
                }
                if (g.admin == 0) revert IGovernance.FeatureNeedsAdmin(GovernanceBits.AUDITOR);
            }
        }
        bytes32 a = aud.length == 32 ? bytes32(aud) : bytes32(0);
        uint8 m = c.pqzVerifyMode;
        if (m > PqzCore.OFFCHAIN) revert IPqzToken.PqzVerifyModeInvalid(m);
        bool off = m == PqzCore.OFFCHAIN;
        // CTR-PQZ-37: `PRECOMPILE` neither flag; `OFFCHAIN` the shared key with the opening, or its own key either way
        if (off
                ? (c.pqzVerifierUA == 0 || (!c.pqzOwnKey && !c.pqzOpening))
                : (c.pqzVerifierUA != 0 || c.pqzVerifierFixed || c.verifierFee != 0 || c.verifierFeeMax != 0
                        || c.pqzOwnKey || c.pqzOpening)) {
            revert IPqzToken.PqzVerifyConfigInvalid();
        }
        if (c.verifierFee > c.verifierFeeMax) revert IPqzToken.VerifierFeeAboveMax(c.verifierFee, c.verifierFeeMax);
        if (!off && verifier == address(0)) revert PqzSafety.SelfTestFailed(address(0));
        PqzCore.PqzStorage storage s = PqzCore.$();
        s.pqzVerifyMode = m;
        // group 3h (PP-4): `NONE` or `LOG`, any other value refused
        if (c.proofStore > PqzCore.LOG) revert IPqzToken.ProofStoreInvalid(c.proofStore);
        s.proofStore = c.proofStore;
        (s.pqzOwnKey, s.pqzOpening) = (c.pqzOwnKey, c.pqzOpening);
        // C2-3 / C2-4: an auditor is required whenever the mode is not NONE, and its key must be usable (`_keyPtr`, the
        // mode's check by the token's class; the zero id is never registered). Class `offchain-token`: no record of the token
        // can exist before its creation, so not checked here (CTR-UA-43; a transfer refuses until the auditor registers)
        if (aud.length == 32 && !c.pqzOwnKey) PqzCore._keyPtr(registry, a);
        if (off) {
            s.psid = c.pqzOpening ? PqzSet.PQZL_SPLIT_ID : PqzSet.PQZL_ID; // CTR-PQZ-38
            s.pqzVerifierUA = c.pqzVerifierUA;
            s.pqzVerifierShape = PqzCore.verifierShape(registry, c.pqzVerifierUA, true);
            s.pqzVerifierFixed = c.pqzVerifierFixed;
            s.noticePeriod = IOpenFactory(factory).noticePeriod();
            (s.verifierFee, s.verifierFeeMax) = (c.verifierFee, c.verifierFeeMax);
        } else {
            PqzKeyVerifier v = PqzKeyVerifier(verifier);
            s.pqz = v.PRECOMPILE();
            s.psid = v.PROOF_SYSTEM_ID();
            PqzSafety.requirePqz(s.pqz, s.psid); // the token's verdicts come from `s.pqz`, never from the verifier (W-B)
            // C2-1 (owner 2026-10-27, C0-2): a PQZH value token only where its debits fit one transaction; registration
            // and disclosure through `PqzKeyVerifier` stay at every set that has PQZH
            if (s.psid == PqzSet.PQZH_ID && !PqzSet.PQZH_VALUE) revert IPqzToken.PqzhValueUnsupported();
        }
        s.verifier = verifier;
        s.disclosureMode = ZetherTypes.DisclosureMode(c.disclosureMode);
        s.auditorMode = ZetherTypes.AuditorMode(c.auditorMode);
        s.shieldScale = c.shieldScale;
        s.maxShielded = c.maxShielded;
        s.confidentialFee = c.confidentialFee;
        s.minDecoyFee = c.minDecoyFee;
        s.auditorUA = a;
    }

    // ------------------------------------------------------------------ the verifier UA (group 3f, spec §4.2, §4.3)

    /// @notice The admin's transfer of a transferable `OFFCHAIN` verifier (spec §4.2, AV-4; no bit, C4): a first call
    ///         proposes `next` (admin; not the current, `PqzVerifierSame`; spec §4.1's kinds, `verifierShape` strict; none
    ///         live, else `PqzVerifierPending`) with `eta = now + noticePeriod`; the second, with the same `next`, by the
    ///         same proposer, still the admin, in the same admin generation and in `[eta, eta + noticePeriod]`, confirms
    ///         (before `eta`: `PqzVerifierNotReady`): the verifier, its shape and `pqzVerifierEpoch + 1` written. An admin
    ///         change, or the window passed, leaves the pending dead. A notice period 0 applies the first call at once.
    ///         After the admin check: `PRECOMPILE` `PqzVerifyConfigInvalid`, fixed `PqzVerifierFixed`. A confirm by
    ///         another caller than the proposer: `NotProposer` (no bit: 0, `account` the pending verifier).
    function setVerifier(bytes32 next, bytes32 caller, address registry) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        bool live = _live(s, g);
        bool confirm = live && next == s.pqzPendingVerifier;
        if (confirm && caller != s.pqzProposer) revert IGovernance.NotProposer(0, next, s.pqzProposer);
        _admin(caller, g);
        _transferable(s);
        if (confirm) {
            if (block.timestamp < s.eta) revert IPqzToken.PqzVerifierNotReady(s.eta);
            _assign(s, next, registry);
            return;
        }
        if (live) revert IPqzToken.PqzVerifierPending(s.pqzPendingVerifier);
        if (next == s.pqzVerifierUA) revert IPqzToken.PqzVerifierSame();
        PqzCore.verifierShape(registry, next, true);
        uint64 eta = uint64(block.timestamp) + s.noticePeriod;
        emit IPqzToken.PqzVerifierProposed(s.pqzVerifierUA, next, eta);
        if (s.noticePeriod == 0) {
            _assign(s, next, registry);
            return;
        }
        (s.pqzPendingVerifier, s.pqzProposer, s.pqzProposerGeneration, s.eta) = (next, caller, g.adminGeneration, eta);
    }

    /// @notice The admin deletes a live pending transfer (`PqzVerifierCancelled`); none live: nothing happens.
    function cancelVerifier(bytes32 caller) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        _admin(caller, g);
        _transferable(s);
        if (!_live(s, g)) return;
        emit IPqzToken.PqzVerifierCancelled(s.pqzPendingVerifier);
        _dropPending(s);
    }

    /// @notice The admin's immediate revocation (spec §4.3, R4; freeze only): verifier 0, `pqzVerifierEpoch + 1`, any pending
    ///         deleted; every proof-carrying op then refuses `PqzVerifierRevoked` until a transfer sets a new verifier.
    function revokeVerifier(bytes32 caller) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        _admin(caller, GovernanceLib.$());
        _transferable(s);
        bytes32 previous = s.pqzVerifierUA;
        s.pqzVerifierUA = 0;
        s.pqzVerifierShape = 0;
        uint32 e = s.pqzVerifierEpoch + 1;
        s.pqzVerifierEpoch = e;
        _dropPending(s);
        emit PqzVerifierRevoked(previous, e);
    }

    // ------------------------------------------------------------------ the verifier fee (round 3t, CTR-PQZ-36, spec §7.1)

    /// @notice The admin's verifier fee of an `OFFCHAIN` token within `[0, verifierFeeMax]` (no bit; `pqzSetVerifier`'s
    ///         pattern, its own state because a verifier transfer and a fee increase may be pending at once): a decrease, to
    ///         0 included, at once (a live pending increase dropped, controller call 3); an increase proposed by the first
    ///         call (`VerifierFeeProposed`, `eta = now + noticePeriod`; notice 0: at once) and confirmed by the same call of
    ///         the same proposer, still the admin, in the same admin generation, within `[eta, eta + noticePeriod]`
    ///         (`VerifierFeeNotReady` before `eta`); the current value cancels a live pending (`VerifierFeeSet(cur, cur)`,
    ///         Fable P3-1), else `VerifierFeeSame`. Refusals in order: `NotProposer`, `NotAdmin`, `PqzVerifyConfigInvalid`
    ///         (`PRECOMPILE`), `VerifierFeeNotReady`, `VerifierFeeAboveMax`, `VerifierFeeSame`, `VerifierFeePending`.
    ///         `verifierFeeMax` is never written here (I-V1).
    function setVerifierFee(uint64 next, bytes32 caller) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        bool live = _feeLive(s, g);
        bool confirm = live && next == s.verifierFeePending;
        if (confirm && caller != s.verifierFeeProposer) {
            revert IGovernance.NotProposer(0, bytes32(uint256(next)), s.verifierFeeProposer);
        }
        _admin(caller, g);
        if (s.pqzVerifyMode != PqzCore.OFFCHAIN) revert IPqzToken.PqzVerifyConfigInvalid();
        uint64 cur = s.verifierFee;
        if (confirm) {
            if (block.timestamp < s.verifierFeeEta) revert IPqzToken.VerifierFeeNotReady(s.verifierFeeEta);
            _setFee(s, cur, next);
            return;
        }
        if (next > s.verifierFeeMax) revert IPqzToken.VerifierFeeAboveMax(next, s.verifierFeeMax);
        if (next == cur) {
            if (!live) revert IPqzToken.VerifierFeeSame();
            _setFee(s, cur, cur);
            return;
        }
        if (next < cur) {
            _setFee(s, cur, next);
            return;
        }
        if (live) revert IPqzToken.VerifierFeePending(s.verifierFeePending);
        uint64 eta = uint64(block.timestamp) + s.noticePeriod;
        emit IPqzToken.VerifierFeeProposed(cur, next, eta);
        if (s.noticePeriod == 0) {
            _setFee(s, cur, next);
            return;
        }
        (s.verifierFeePending, s.verifierFeeEta, s.verifierFeeProposer, s.verifierFeeProposerGeneration) =
        (next, eta, caller, g.adminGeneration);
    }

    /// @dev A pending increase still confirmable: proposed in this admin generation, `[eta, eta + noticePeriod]` not passed.
    ///      An increase is `> verifierFee ≥ 0`, so `verifierFeePending ≠ 0` marks one.
    function _feeLive(PqzCore.PqzStorage storage s, GovernanceLib.GovernanceStorage storage g)
        private
        view
        returns (bool)
    {
        return s.verifierFeePending != 0 && s.verifierFeeProposerGeneration == g.adminGeneration
            && block.timestamp <= uint256(s.verifierFeeEta) + s.noticePeriod;
    }

    /// @dev Writes the fee, drops any pending increase, `VerifierFeeSet(previous, next)`.
    function _setFee(PqzCore.PqzStorage storage s, uint64 previous, uint64 next) private {
        s.verifierFee = next;
        (s.verifierFeePending, s.verifierFeeEta, s.verifierFeeProposer, s.verifierFeeProposerGeneration) = (0, 0, 0, 0);
        emit IPqzToken.VerifierFeeSet(previous, next);
    }

    /// @notice Group 3h (PQZ proof path spec §5, O10): the body of bit 24's power, after the token's `use(24)` (in
    ///         `PqzLayer`, so this library makes no DELEGATECALL into `GovernanceLib`): `next` 0 `NONE` or 1 `LOG`
    ///         (`ProofStoreInvalid` otherwise), slot 0 byte 23, read by the next debit in either direction; the current value
    ///         is a no-op without an event.
    function setProofStore(uint8 next) public {
        if (next > PqzCore.LOG) revert IPqzToken.ProofStoreInvalid(next);
        PqzCore.PqzStorage storage s = PqzCore.$();
        uint8 previous = s.proofStore;
        if (previous == next) return;
        s.proofStore = next;
        emit IPqzToken.ProofStoreSet(previous, next);
    }

    // ------------------------------------------------------------------ the auditor's replacement (bit 32, CTR-PQZ-43)

    /// @notice Bit 32 `AUDITOR`'s body (set-auditor spec §5.1), after the token's `_holderOnChain(32)` and `use(32)`
    ///         (`caller`), with `delay = max(factory noticePeriod, grantDelay)` read by the token (never `noticePeriod` of
    ///         this namespace: 0 on every `PRECOMPILE` token). `epoch` must be `auditorEpoch + 1`. A live proposal takes only
    ///         its own UA (the proposer's confirm from `eta` on: the checks again, then the apply) or the current one (the
    ///         proposer's cancel); anything else `AuditorPending`. Without one, the current UA is `AuditorSame`; else the
    ///         checks and a proposal that applies at once when `delay` is 0. An expired or void proposal is overwritten.
    function setAuditorUA(
        bytes32 newAuditor,
        uint32 epoch,
        IUARegistry.UASig calldata consent,
        bytes32 caller,
        uint64 delay,
        address registry,
        bytes32 domainSeparator,
        bytes32 chainUid
    ) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        AuditorRules.requireNext(s.auditorEpoch, epoch);
        if (AuditorRules.live(s.auditorEta, s.auditorProposerRoleEpoch, s.auditorProposer)) {
            if (newAuditor == s.pendingAuditorUA) {
                AuditorRules.requireProposer(caller, s.auditorProposer);
                if (block.timestamp < s.auditorEta) revert IConfidentialToken.AuditorNotReady(s.auditorEta);
                _auditorChecks(newAuditor, epoch, consent, registry, domainSeparator, chainUid);
                _applyAuditor(s, newAuditor, epoch);
            } else if (newAuditor == s.auditorUA) {
                AuditorRules.requireProposer(caller, s.auditorProposer);
                _clearAuditorProposal(s);
                emit IConfidentialToken.AuditorProposalCancelled(epoch);
            } else {
                revert IConfidentialToken.AuditorPending();
            }
            return;
        }
        if (newAuditor == s.auditorUA) revert IConfidentialToken.AuditorSame();
        _auditorChecks(newAuditor, epoch, consent, registry, domainSeparator, chainUid);
        uint64 eta = uint64(block.timestamp) + delay;
        emit IPqzToken.AuditorUAProposed(epoch, newAuditor, caller, eta);
        if (delay == 0) {
            _applyAuditor(s, newAuditor, epoch);
            return;
        }
        (s.auditorEta, s.auditorProposerRoleEpoch, s.auditorProposer, s.pendingAuditorUA) =
        (eta, AuditorRules.roleEpochOf(caller), caller, newAuditor);
    }

    /// @dev Spec §5.2, at the proposal and again at the apply: the new auditor's current key of the token's class and scope
    ///      under the mode's check (`_keyOf`, `_usable`; `AccountNotRegistered`); `proven` where the registry has a `0x0142`
    ///      verifier, `_usable`'s rule ("proven, or nothing": without the verifier no proven check, the key-copy residual of
    ///      T3 stands); on an opening token the opening KEM key of that scoped version; then its consent, a signature under
    ///      `PURPOSE_AUDITOR_CONSENT` over the `AuditorConsent` digest (the registry's refusal).
    function _auditorChecks(
        bytes32 a,
        uint32 epoch,
        IUARegistry.UASig calldata consent,
        address registry,
        bytes32 ds,
        bytes32 chainUid
    ) private view {
        PqzCore.PqzStorage storage s = PqzCore.$();
        (uint64 v, address ptr, bool proven) = PqzCore._keyOf(registry, a);
        // spec 2026-11-19-registry-verify-only-kinds §11.2: a `0x0142` verifier anywhere on the registry's line asks for proven
        if (
            !PqzCore._usable(proven, ptr) || (!proven && IUARegistry(registry).kindHome(UAKinds.PQZ_MLWE) != address(0))
        ) {
            revert IPqzToken.AccountNotRegistered(a);
        }
        if (
            s.pqzOpening
                && IUARegistry(registry).pqzOpenKemAt(a, s.pqzOwnKey ? address(this) : address(0), v).mlkemEk.length
                    == 0
        ) {
            revert IPqzToken.AccountNotRegistered(a);
        }
        IUARegistry(registry)
            .requireAuthorized(
                a, UAKinds.PURPOSE_AUDITOR_CONSENT, AuditorRules.consentDigest(ds, a, epoch, chainUid), consent
            );
    }

    /// @dev Spec §5.4: the outgoing UA enters the history at its epoch, `next` is the auditor from `epoch` on.
    function _applyAuditor(PqzCore.PqzStorage storage s, bytes32 next, uint32 epoch) private {
        bytes32 previous = s.auditorUA;
        s.auditorUAs[epoch - 1] = previous;
        s.auditorUA = next;
        s.auditorEpoch = epoch;
        _clearAuditorProposal(s);
        emit IPqzToken.AuditorUASet(epoch, previous, next);
    }

    function _clearAuditorProposal(PqzCore.PqzStorage storage s) private {
        (s.auditorEta, s.auditorProposerRoleEpoch, s.auditorProposer, s.pendingAuditorUA) = (0, 0, 0, 0);
    }

    /// @notice `pqzVerifyConfig()` (spec §4.4): a dead pending reads as none. Round 3t (CTR-PQZ-36, spec §7.3): the fee, the
    ///         cap and a live pending increase with its `eta` (a dead one 0, 0; `PRECOMPILE` 0 for the four).
    function verifyConfig() public view returns (IPqzToken.PqzVerifyConfig memory c) {
        PqzCore.PqzStorage storage s = PqzCore.$();
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        (c.pqzVerifyMode, c.verifier, c.fixed_, c.pqzVerifierEpoch, c.noticePeriod) =
        (s.pqzVerifyMode, s.pqzVerifierUA, s.pqzVerifierFixed, s.pqzVerifierEpoch, s.noticePeriod);
        if (_live(s, g)) (c.pending, c.eta) = (s.pqzPendingVerifier, s.eta);
        (c.verifierFee, c.verifierFeeMax) = (s.verifierFee, s.verifierFeeMax);
        if (_feeLive(s, g)) (c.verifierFeePending, c.verifierFeeEta) = (s.verifierFeePending, s.verifierFeeEta);
        (c.pqzOwnKey, c.pqzOpening) = (s.pqzOwnKey, s.pqzOpening);
    }

    /// @dev The admin first (a stranger learns nothing of the configuration), then an `OFFCHAIN` token with a transferable
    ///      verifier.
    function _admin(bytes32 caller, GovernanceLib.GovernanceStorage storage g) private view {
        if (caller == 0 || caller != g.admin) revert IAdmin.NotAdmin(caller);
    }

    function _transferable(PqzCore.PqzStorage storage s) private view {
        if (s.pqzVerifyMode != PqzCore.OFFCHAIN) revert IPqzToken.PqzVerifyConfigInvalid();
        if (s.pqzVerifierFixed) revert IPqzToken.PqzVerifierFixed();
    }

    /// @dev A pending transfer still confirmable: proposed in this admin generation, its window `[eta, eta + notice]` not
    ///      passed.
    function _live(PqzCore.PqzStorage storage s, GovernanceLib.GovernanceStorage storage g)
        private
        view
        returns (bool)
    {
        return s.pqzPendingVerifier != 0 && s.pqzProposerGeneration == g.adminGeneration
            && block.timestamp <= uint256(s.eta) + s.noticePeriod;
    }

    function _assign(PqzCore.PqzStorage storage s, bytes32 next, address registry) private {
        bytes32 previous = s.pqzVerifierUA;
        s.pqzVerifierUA = next;
        s.pqzVerifierShape = PqzCore.verifierShape(registry, next, true);
        uint32 e = s.pqzVerifierEpoch + 1;
        s.pqzVerifierEpoch = e;
        _dropPending(s);
        emit IPqzToken.PqzVerifierSet(previous, next, e);
    }

    function _dropPending(PqzCore.PqzStorage storage s) private {
        (s.pqzPendingVerifier, s.pqzProposer, s.pqzProposerGeneration, s.eta) = (0, 0, 0, 0);
    }

    /// @notice The proof-free shield (plan 5h D18): `totalShielded += amount` within the cap and a TRIVIAL entry
    ///         `(amount, block)` appended to `pending[ua]` or merged into its tail (`PqzCore._trivial`); anyone, into
    ///         any PQZ holder, free (owner 2026-10-20). The token moves the public units of `from` (`mtxShield`) or mints
    ///         a leg's underlying (`mtxWrapShield`) into `SHIELD_POOL` (D19).
    function shield(bytes32 ua, uint256 amount, address from, address registry) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        // C2-4: the key is checked as every debit does; C0-2: a PQZH holder's kind; KV-7: its current version, one read
        (, uint64 v) = PqzCore._creditKey(registry, ua);
        uint256 room = s.maxShielded - s.totalShielded;
        if (amount == 0 || amount > room) revert IPqzToken.AmountOutOfRange(amount, room);
        s.totalShielded += amount;
        PqzCore._trivial(ua, v, amount, from);
    }

    /// @notice Anyone (plan 5h D8): `acc += Σ pending[rolled .. rolled + n')` strictly in order, `n' = min(n, K_MAX − 1 −
    ///         accUnits)` (`CapReached` at 0), `1 ≤ n ≤ ROLL_MAX`, each entry at least `ROLL_AGE` blocks old
    ///         (`RollTooYoung`), the account prepared (`AccNotPrepared`); the sum is packed (P46) and written to the
    ///         `acc` slots as `not(stream word)` (never 0, so none is zeroed; D3) with `accHash = keccak256(packed
    ///         stream)`; `cleared` and `floor` follow `rolled − INLINE_MAX`, never lowered, and no slot is deleted (group 3h
    ///         PP-1: every pending slot is kept for good). Group 3g (KV-10): the
    ///         account of key version `v`, stale versions included; `PqzRolledOver` names it. The version's key check is
    ///         `prepareAcc`'s (a rollover needs both prepared halves, `AccNotPrepared`, and a key once eligible stays so), not
    ///         repeated here: the registry read would put `ROLL_MAX` at n2560-kmax16384 over its 0.75 · 2^24 bound.
    function rollOver(bytes32 ua, uint64 v, uint256 n) public {
        if (PqzCore.$().pqzOpening) revert IPqzToken.RollOverSignedOnly(); // CTR-PQZ-41: only the holder rolls
        if (n == 0 || n > PqzCore.ROLL_MAX) revert IPqzToken.RollOverRange(n);
        (uint64 nr, uint32 units, bytes32 h) = _roll(PqzCore.$().acct[ua][v], ua, n);
        emit IPqzToken.PqzRolledOver(ua, v, nr, units, h);
    }

    /// @notice CTR-PQZ-41, an opening token's rollover: `ua`'s own signature (`requireAuthorized`, purpose `zether-auth`, an
    ///         `msig` by its quorum) over the typed `PqzRollOver` in the token's domain, `rollSeq` and `rolled` the state's,
    ///         `entriesHash` recomputed from state over the contents of the `n` entries from `rolled` and of each skipped one
    ///         (`entryHash`): a reorg or an un-roll in between is `AuthRejected`. Then each `skip` index (strictly ascending,
    ///         in `[rolled, pendingCount)`, a credit; `SkipRange`, `SkipTrivial`) gets the skip mark, never cleared
    ///         (`PqzSkipped` each, none for an index already marked), then, for `n > 0`, `rollOver`'s rules and body (`PqzRolledOver`). `n = 0` with no skip:
    ///         `RollOverRange(0)`. `rollSeq + 1` on every accepted call.
    function rollOverSigned(
        PqzCore.Env memory e,
        bytes32 ua,
        uint64 v,
        uint64 n,
        uint64[] calldata skip,
        uint64 validUntilBlock,
        IUARegistry.UASig calldata sig
    ) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        if (!s.pqzOpening) revert IPqzToken.OpUnsupported();
        if (block.number > validUntilBlock) revert IPqzToken.Expired(validUntilBlock);
        if (n > PqzCore.ROLL_MAX || (n == 0 && skip.length == 0)) revert IPqzToken.RollOverRange(n);
        if (skip.length > PqzCore.ROLL_MAX) revert IPqzToken.RollOverRange(skip.length);
        PqzCore.Account storage a = s.acct[ua][v];
        PqzCore.requireHolder(e.registry, ua, _rollDigest(e, a, ua, v, n, skip, validUntilBlock), sig);
        a.rollSeq += 1;
        for (uint256 j; j < skip.length; ++j) {
            uint256 x = a.pending[skip[j]];
            if (x & PqzCore.SKIP != 0) continue; // already marked: no second `PqzSkipped` (Fable P3-3)
            a.pending[skip[j]] = x | PqzCore.SKIP;
            emit IPqzToken.PqzSkipped(ua, v, skip[j]);
        }
        if (n != 0) {
            (uint64 nr, uint32 units, bytes32 hh) = _roll(a, ua, n);
            emit IPqzToken.PqzRolledOver(ua, v, nr, units, hh);
        }
    }

    /// @dev The `PqzRollOver` digest from state (the skip list checked on the way: `SkipRange`, `SkipTrivial`).
    function _rollDigest(
        PqzCore.Env memory e,
        PqzCore.Account storage a,
        bytes32 ua,
        uint64 v,
        uint64 n,
        uint64[] calldata skip,
        uint64 validUntilBlock
    ) private view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(
            e.domainSeparator,
            keccak256(
                bytes.concat(
                    abi.encode(PqzCore.ROLL_OVER_TYPEHASH, ua, v, a.rollSeq, a.rolled, n),
                    abi.encode(keccak256(abi.encodePacked(skip)), _entriesHash(a, n, skip), validUntilBlock, e.chainUid)
                )
            )
        );
    }

    /// @dev `entriesHash = keccak256(h(rolled) ‖ … ‖ h(rolled + n − 1) ‖ h(skip_0) ‖ …)`.
    function _entriesHash(PqzCore.Account storage a, uint64 n, uint64[] calldata skip) private view returns (bytes32) {
        uint64 r = a.rolled;
        uint64 pc = a.pendingCount;
        if (r + n > pc) revert IPqzToken.RollOverRange(n);
        bytes32[] memory h = new bytes32[](n + skip.length);
        for (uint256 k; k < n; ++k) {
            h[k] = entryHash(a, r + k);
        }
        for (uint256 j; j < skip.length; ++j) {
            uint64 i = skip[j];
            if (i < r || i >= pc || (j != 0 && i <= skip[j - 1])) revert IPqzToken.SkipRange(i);
            if (uint16(a.pending[i] >> 64) == 0) revert IPqzToken.SkipTrivial(i);
            h[n + j] = entryHash(a, i);
        }
        return keccak256(abi.encodePacked(h));
    }

    /// @notice CTR-PQZ-41: `h(i) = keccak256(abi.encode(i, slot_i with the skip mark cleared, the code hash of slot_i's blob
    ///         or 0 for a TRIVIAL entry))`, the contents of entry `i` a signed rollover binds.
    function entryHash(PqzCore.Account storage a, uint256 i) internal view returns (bytes32) {
        uint256 e = a.pending[uint64(i)] & ~PqzCore.SKIP;
        bytes32 c = uint16(e >> 64) == 0 ? bytes32(0) : address(uint160(e >> 96)).codehash;
        return keccak256(abi.encode(i, e, c));
    }

    /// @notice CTR-PQZ-41: the skip mark of pending entry `i` of `(ua, v)`.
    function skipped(bytes32 ua, uint64 v, uint64 i) public view returns (bool sk) {
        (, sk) = PqzCore.slotBlock(PqzCore.$().acct[ua][v].pending[i]);
    }

    /// @dev `rollOver`'s body on the account (a frame of its own for the stack): the new `rolled`, `accUnits`, `accHash`.
    function _roll(PqzCore.Account storage a, bytes32 ua, uint256 n) private returns (uint64, uint32, bytes32) {
        if (a.flags & PqzCore.PREP != PqzCore.PREP) revert IPqzToken.AccNotPrepared(ua);
        uint256 units = a.accUnits;
        if (units + 1 >= PqzCore.K_MAX) revert IPqzToken.CapReached(ua);
        if (n > PqzCore.K_MAX - 1 - units) n = PqzCore.K_MAX - 1 - units;
        uint64 r = a.rolled;
        if (r + n > a.pendingCount) revert IPqzToken.RollOverRange(n);
        bytes memory c = PqzCore._accOf(a, msg.data[0:0]);
        PqzCore._window(a, c, r, n, true, true);
        PqzCt.reduce(c);
        bytes memory pk_ = PqzCt.packMem(c); // `CTP` bytes and 32 of zero slack: the last slot's padding stores as ones
        uint256[PQZ_ACC_WORDS] storage w = a.accWords;
        uint256 nw = PqzCt.ACC_WORDS;
        assembly ("memory-safe") {
            let b := w.slot
            let d := add(pk_, 32)
            for { let i := 0 } lt(i, nw) { i := add(i, 1) } { sstore(add(b, i), not(mload(add(d, shl(5, i))))) }
        }
        bytes32 h = keccak256(pk_);
        uint64 nr = uint64(r + n);
        a.accHash = h;
        a.rolled = nr;
        a.accUnits = uint32(units + n);
        a.flags |= PqzCore.MAT;
        _clear(a, nr);
        return (nr, uint32(units + n), h);
    }

    /// @dev `cleared` up to `rolled − INLINE_MAX` (`floor` follows, only up); nothing deleted (group 3h PP-1).
    function _clear(PqzCore.Account storage a, uint64 nr) private {
        uint64 end = nr > PqzCore.INLINE_MAX ? nr - uint64(PqzCore.INLINE_MAX) : 0;
        if (end > a.cleared) {
            a.cleared = end;
            if (end > a.floor) a.floor = end;
        }
    }

    /// @notice Permissionless, idempotent (plan 5h D8): writes the non-zero `ACC_MARK` into half `half` (0 or 1) of the
    ///         account's `acc` slots (`HALF_WORDS` and the rest of `PqzCt.ACC_WORDS`), so the first rollover rewrites
    ///         instead of creating them; a no-op once done (a materialised `acc` has both). Group 3g (KV-10): the account
    ///         of key version `v`, a version whose key passes the mode's check.
    function prepareAcc(bytes32 ua, uint64 v, uint256 half, address registry) public {
        if (half > 1) revert IPqzToken.BadPayload(half);
        PqzCore.Account storage a = PqzCore.$().acct[ua][v];
        uint8 bit = uint8(2 << half);
        if (a.flags & bit != 0) return;
        PqzCore._keyAt(registry, ua, v); // C2-4
        uint256[PQZ_ACC_WORDS] storage w = a.accWords;
        uint256 hw = PqzCore.HALF_WORDS;
        uint256 cnt = half == 0 ? hw : PqzCt.ACC_WORDS - hw;
        uint256 mk = PqzCore.ACC_MARK;
        assembly ("memory-safe") {
            let b := add(w.slot, mul(half, hw))
            for { let i := 0 } lt(i, cnt) { i := add(i, 1) } { sstore(add(b, i), mk) }
        }
        a.flags |= bit;
    }

    /// @notice The account's `acc` bytes (D13 `pqzAcc`): the materialised words, or the reference's `u ‖ v`, or 0.
    function accOf(bytes32 ua, uint64 v) public view returns (bytes memory) {
        return PqzCore._accOf(PqzCore.$().acct[ua][v], msg.data[0:0]);
    }

    /// @notice Entry `i` of `ua` as a ciphertext (D13 `pqzPendingCt`): `u_g ‖ v_j` from its blob, or
    ///         `Trivial(digits(amount))` of a TRIVIAL entry, every `i < pendingCount` (group 3h PP-1: none is deleted);
    ///         `Trivial(0)` for an unwritten index.
    function pendingCt(bytes32 ua, uint64 v, uint64 i) public view returns (bytes memory c) {
        uint256 e = PqzCore.$().acct[ua][v].pending[i];
        c = new bytes(PqzCt.CT);
        if (uint16(e >> 64) == 0) PqzCt.addTrivial(c, uint64(e >> 96));
        else PqzCt.loadBlob(address(uint160(e >> 96)), uint16(e >> 80), uint16(e >> 64), c);
    }
}
