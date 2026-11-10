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
import {IGovernance} from "../governance/IGovernance.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";

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
        if (d.length != 1 || hedera || (d[ENV_PQZ_VERIFIER] != address(0) && !SigCheck.isContract(d[ENV_PQZ_VERIFIER]))
            || !SigCheck.isContract(registry)) {
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
    function init(IFactoryToken.ConfidentialConfig memory c, address registry, address verifier, address factory) public {
        bytes memory aud = c.auditorKey;
        if (c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > PqzCore.MAX_TOTAL_SHIELDED
            || c.confidentialFee >= PqzCore.VALUE_BOUND || c.confidentialFee >= c.maxShielded
            || c.minDecoyFee >= PqzCore.VALUE_BOUND || c.confidentialFee + 8 * c.minDecoyFee >= PqzCore.VALUE_BOUND
            || c.confidentialFee + 8 * c.minDecoyFee >= c.maxShielded
            || (aud.length != 0 && aud.length != 32) || c.maxShielded > type(uint256).max / c.shieldScale) {
            revert IPqzToken.BadInit();
        }
        if (c.disclosureMode > uint8(ZetherTypes.DisclosureMode.COMPACT)) revert IPqzToken.BadDisclosureMode(c.disclosureMode);
        if (c.auditorMode > uint8(ZetherTypes.AuditorMode.OPTIONAL)
            || (aud.length == 0) != (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE))) {
            revert IPqzToken.BadAuditorMode(c.auditorMode);
        }
        bytes32 a = aud.length == 32 ? bytes32(aud) : bytes32(0);
        uint8 m = c.pqzVerifyMode;
        if (m > PqzCore.OFFCHAIN) revert IPqzToken.PqzVerifyModeInvalid(m);
        bool off = m == PqzCore.OFFCHAIN;
        if (off ? c.pqzVerifierUA == 0 : (c.pqzVerifierUA != 0 || c.pqzVerifierFixed)) {
            revert IPqzToken.PqzVerifyConfigInvalid();
        }
        if (!off && verifier == address(0)) revert PqzSafety.SelfTestFailed(address(0));
        PqzCore.PqzStorage storage s = PqzCore.$();
        s.pqzVerifyMode = m;
        // group 3h (PP-4): `NONE` or `LOG`, any other value refused
        if (c.proofStore > PqzCore.LOG) revert IPqzToken.ProofStoreInvalid(c.proofStore);
        s.proofStore = c.proofStore;
        // C2-3 / C2-4: an auditor is required whenever the mode is not NONE, and its key must be usable (`_keyPtr`, the
        // mode's check; the zero id is never registered)
        if (aud.length == 32) PqzCore._keyPtr(registry, a);
        if (off) {
            s.psid = PqzSet.PQZL_ID;
            s.pqzVerifierUA = c.pqzVerifierUA;
            s.pqzVerifierShape = PqzCore.verifierShape(registry, c.pqzVerifierUA, true);
            s.pqzVerifierFixed = c.pqzVerifierFixed;
            s.noticePeriod = IOpenFactory(factory).noticePeriod();
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

    /// @notice The owner's transfer of a transferable `OFFCHAIN` verifier (spec §4.2, AV-4; no bit, C4): a first call
    ///         proposes `next` (owner; not the current, `PqzVerifierSame`; spec §4.1's kinds, `verifierShape` strict; none
    ///         live, else `PqzVerifierPending`) with `eta = now + noticePeriod`; the second, with the same `next`, by the
    ///         same proposer, still the owner, in the same owner generation and in `[eta, eta + noticePeriod]`, confirms
    ///         (before `eta`: `PqzVerifierNotReady`): the verifier, its shape and `pqzVerifierEpoch + 1` written. An owner
    ///         change, or the window passed, leaves the pending dead. A notice period 0 applies the first call at once.
    ///         After the owner check: `PRECOMPILE` `PqzVerifyConfigInvalid`, fixed `PqzVerifierFixed`. A confirm by
    ///         another caller than the proposer: `NotProposer` (no bit: 0, `account` the pending verifier).
    function setVerifier(bytes32 next, bytes32 caller, address registry) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        bool live = _live(s, g);
        bool confirm = live && next == s.pqzPendingVerifier;
        if (confirm && caller != s.pqzProposer) revert IGovernance.NotProposer(0, next, s.pqzProposer);
        _owner(caller, g);
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
        (s.pqzPendingVerifier, s.pqzProposer, s.pqzProposerGeneration, s.eta) = (next, caller, g.ownerGeneration, eta);
    }

    /// @notice The owner deletes a live pending transfer (`PqzVerifierCancelled`); none live: nothing happens.
    function cancelVerifier(bytes32 caller) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        _owner(caller, g);
        _transferable(s);
        if (!_live(s, g)) return;
        emit IPqzToken.PqzVerifierCancelled(s.pqzPendingVerifier);
        _dropPending(s);
    }

    /// @notice The owner's immediate revocation (spec §4.3, R4; freeze only): verifier 0, `pqzVerifierEpoch + 1`, any pending
    ///         deleted; every proof-carrying op then refuses `PqzVerifierRevoked` until a transfer sets a new verifier.
    function revokeVerifier(bytes32 caller) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        _owner(caller, GovernanceLib.$());
        _transferable(s);
        bytes32 previous = s.pqzVerifierUA;
        s.pqzVerifierUA = 0;
        s.pqzVerifierShape = 0;
        uint32 e = s.pqzVerifierEpoch + 1;
        s.pqzVerifierEpoch = e;
        _dropPending(s);
        emit PqzVerifierRevoked(previous, e);
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

    /// @notice `pqzVerifyConfig()` (spec §4.4): a dead pending reads as none.
    function verifyConfig() public view returns (IPqzToken.PqzVerifyConfig memory c) {
        PqzCore.PqzStorage storage s = PqzCore.$();
        bool live = _live(s, GovernanceLib.$());
        c = IPqzToken.PqzVerifyConfig(s.pqzVerifyMode, s.pqzVerifierUA, s.pqzVerifierFixed, s.pqzVerifierEpoch,
            live ? s.pqzPendingVerifier : bytes32(0), live ? s.eta : 0, s.noticePeriod);
    }

    /// @dev The owner first (a stranger learns nothing of the configuration), then an `OFFCHAIN` token with a transferable
    ///      verifier.
    function _owner(bytes32 caller, GovernanceLib.GovernanceStorage storage g) private view {
        if (caller == 0 || caller != g.owner) revert IGovernance.NotOwner(caller);
    }

    function _transferable(PqzCore.PqzStorage storage s) private view {
        if (s.pqzVerifyMode != PqzCore.OFFCHAIN) revert IPqzToken.PqzVerifyConfigInvalid();
        if (s.pqzVerifierFixed) revert IPqzToken.PqzVerifierFixed();
    }

    /// @dev A pending transfer still confirmable: proposed in this owner generation, its window `[eta, eta + notice]` not
    ///      passed.
    function _live(PqzCore.PqzStorage storage s, GovernanceLib.GovernanceStorage storage g) private view returns (bool) {
        return s.pqzPendingVerifier != 0 && s.pqzProposerGeneration == g.ownerGeneration
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
        if (n == 0 || n > PqzCore.ROLL_MAX) revert IPqzToken.RollOverRange(n);
        (uint64 nr, uint32 units, bytes32 h) = _roll(PqzCore.$().acct[ua][v], ua, n);
        emit IPqzToken.PqzRolledOver(ua, v, nr, units, h);
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
