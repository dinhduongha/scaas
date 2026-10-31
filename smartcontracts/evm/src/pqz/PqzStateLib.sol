// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";
import {PqzCt} from "./PqzCt.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {UAPqzVerifier} from "./UAPqzVerifier.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzSet, PQZ_ACC_WORDS} from "./PqzSet.sol";

/// @title init, shield, rollover, prepare-acc and the state views (the account state; D14): one of the four `DELEGATECALL` libraries of the PQZ release (plan 5h D14), in the ERC-7201
///        namespace `scaas.pqz`; the shared steps are `internal` in `PqzCore`, compiled into each.
/// @notice **UNAUDITED.** `address(this)` is the token.
library PqzStateLib {
    /// @notice The kind's `_init` (P6g plan D9): `verifier` the release's `UAPqzVerifier` (CTR-ZTH-20: the creator never
    ///         chooses one; precompile and proof system: exactly `PqzSafety.PQZ`, PQZL or PQZH,
    ///         the self-test passing now; review W-B), `auditorKey` empty or the auditor's 32-byte `pqz-mlwe` UA, cap
    ///         `≤ 2^62`, `confidentialFee + 8 · minDecoyFee` `< 2^64` and `< cap` (no chain-level floor, owner 2026-10-20).
    function init(IFactoryToken.ConfidentialConfig memory c, address registry, address verifier) public {
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
        // C2-3 / C2-4: an auditor is required whenever the mode is not NONE, and its key must be usable (`_keyPtr`;
        // the zero id is never registered)
        if (aud.length == 32) PqzCore._keyPtr(registry, a);
        PqzCore.PqzStorage storage s = PqzCore.$();
        UAPqzVerifier v = UAPqzVerifier(verifier);
        s.pqz = v.PRECOMPILE();
        s.psid = v.PROOF_SYSTEM_ID();
        PqzSafety.requirePqz(s.pqz, s.psid); // the token's verdicts come from `s.pqz`, never from the verifier (W-B)
        // C2-1 (owner 2026-10-27, C0-2): a PQZH value token only where its debits fit one transaction; registration
        // and disclosure through `UAPqzVerifier` stay at every set that has PQZH
        if (s.psid == PqzSet.PQZH_ID && !PqzSet.PQZH_VALUE) revert IPqzToken.PqzhValueUnsupported();
        s.verifier = verifier;
        s.disclosureMode = ZetherTypes.DisclosureMode(c.disclosureMode);
        s.auditorMode = ZetherTypes.AuditorMode(c.auditorMode);
        s.shieldScale = c.shieldScale;
        s.maxShielded = c.maxShielded;
        s.confidentialFee = c.confidentialFee;
        s.minDecoyFee = c.minDecoyFee;
        s.auditorUA = a;
    }

    /// @notice The proof-free shield (plan 5h D18): `totalShielded += amount` within the cap and a TRIVIAL entry
    ///         `(amount, block)` appended to `pending[ua]` or merged into its tail (`PqzCore._trivial`); anyone, into
    ///         any PQZ holder, free (owner 2026-10-20). The token moves the public units of `from` (`mtxShield`) or mints
    ///         a leg's underlying (`mtxWrapShield`) into `SHIELD_POOL` (D19).
    function shield(bytes32 ua, uint256 amount, address from, address registry) public {
        PqzCore.PqzStorage storage s = PqzCore.$();
        PqzCore._creditKey(registry, ua); // C2-4: the key is checked as every debit does; C0-2: a PQZH holder's kind
        uint256 room = s.maxShielded - s.totalShielded;
        if (amount == 0 || amount > room) revert IPqzToken.AmountOutOfRange(amount, room);
        s.totalShielded += amount;
        PqzCore._trivial(ua, amount, from);
    }

    /// @notice Anyone (plan 5h D8): `acc += Σ pending[rolled .. rolled + n')` strictly in order, `n' = min(n, K_MAX − 1 −
    ///         accUnits)` (`CapReached` at 0), `1 ≤ n ≤ ROLL_MAX`, each entry at least `ROLL_AGE` blocks old
    ///         (`RollTooYoung`), the account prepared (`AccNotPrepared`); the sum is packed (P46) and written to the
    ///         `acc` slots as `not(stream word)` (never 0, so none is zeroed; D3) with `accHash = keccak256(packed
    ///         stream)`; the slots below `rolled − INLINE_MAX` are deleted (`floor` follows `cleared`).
    function rollOver(bytes32 ua, uint256 n) public {
        if (n == 0 || n > PqzCore.ROLL_MAX) revert IPqzToken.RollOverRange(n);
        PqzCore.Account storage a = PqzCore.$().acct[ua];
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
        uint64 end = nr > PqzCore.INLINE_MAX ? nr - uint64(PqzCore.INLINE_MAX) : 0;
        uint64 c0 = a.cleared;
        if (end > c0) {
            for (uint64 i = c0; i < end; ++i) delete a.pending[i];
            a.cleared = end;
            if (end > a.floor) a.floor = end;
        }
        emit IConfidentialToken.RolledOver(ua, nr, uint32(units + n), h);
    }

    /// @notice Permissionless, idempotent (plan 5h D8): writes the non-zero `ACC_MARK` into half `half` (0 or 1) of the
    ///         account's `acc` slots (`HALF_WORDS` and the rest of `PqzCt.ACC_WORDS`), so the first rollover rewrites
    ///         instead of creating them; a no-op once done (a materialised `acc` has both).
    function prepareAcc(bytes32 ua, uint256 half, address registry) public {
        if (half > 1) revert IPqzToken.BadPayload(half);
        PqzCore.Account storage a = PqzCore.$().acct[ua];
        uint8 bit = uint8(2 << half);
        if (a.flags & bit != 0) return;
        PqzCore._keyPtr(registry, ua); // C2-4
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
    function accOf(bytes32 ua) public view returns (bytes memory) {
        return PqzCore._accOf(PqzCore.$().acct[ua], msg.data[0:0]);
    }

    /// @notice Entry `i` of `ua` as a ciphertext (D13 `pqzPendingCt`): `u_g ‖ v_j` from its blob, or
    ///         `Trivial(digits(amount))` of a TRIVIAL entry; `Trivial(0)` for a deleted or unwritten index.
    function pendingCt(bytes32 ua, uint64 i) public view returns (bytes memory c) {
        uint256 e = PqzCore.$().acct[ua].pending[i];
        c = new bytes(PqzCt.CT);
        if (uint16(e >> 64) == 0) PqzCt.addTrivial(c, uint64(e >> 96));
        else PqzCt.loadBlob(address(uint160(e >> 96)), uint16(e >> 80), uint16(e >> 64), c);
    }
}
