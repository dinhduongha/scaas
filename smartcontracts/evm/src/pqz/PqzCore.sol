// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {PqzCt} from "./PqzCt.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {UAPqzVerifier} from "./UAPqzVerifier.sol";

/// @title The PQZ layer of the `*_PQZ` kinds (CTR-PQZ-15, CTR-PQZ-22; P6g plan D1), in the ERC-7201 namespace
///        `scaas.pqz`: statements, the precompile call, account updates, rollover, shield / burn, entries, disclosure.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** External library, run by `DELEGATECALL` (`address(this)` is the
///         token); the token keeps the public ERC-20 side and the entry points (`PqzLayer`). Byte layouts:
///         pq-zero-knowledge.md §7.4–§7.9 and §8.1. Ciphertexts live in state (plan 5h D1–D3, CTR-PQZ-07): one SSTORE2 op
///         blob per debit (`R ‖ v_f`, or a burn's `u' ‖ v_f`), one slot per pending entry pointing into a blob (or a
///         TRIVIAL entry: a public amount), `acc` a reference to the last debit's blob or materialised in slots by
///         rollovers; every debit rebuilds `T` from state (an optional calldata hint for a materialised `acc`). Every
///         statement is built once, in a buffer `u8(op) ‖ be32(len) ‖ stmt ‖ proof` that is the precompile input
///         (P6g D13); `authDigest = keccak256("SCAAS-PQZ-AUTH-V1" ‖ keccak256(stmt))` is checked by the registry
///         (`requireAuthorized`, the signing UA's own signature, purpose `zether-auth`) before the precompile. The account is
///         the signing UA; its PQZ key is an attribute of its registry record (UA-6 U7), so a UA without one is no
///         PQZ account (`AccountNotRegistered`); there is no `authRef`.
library PqzCore {
    /// @dev Plan 5h D2 / D3. Invariants: `cleared ≤ floor ≤ rolled ≤ pendingCount`; every index `≥ rolled` is pending,
    ///      `[floor, rolled)` is inside `acc` (with the last debit's `(u, v_f)`), `pending[i]` exists for `i ≥ cleared`.
    ///      `pending[i]` = `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)` (`u` and `v` at those byte offsets of the blob's
    ///      data); `vOff = 0` is a TRIVIAL entry (D18) whose amount is the low 64 bits of the blob field. `acc` is
    ///      `(accBlob, accU, accV)` (0: `Trivial(0)`) unless `flags & MAT`: then `accWords`, with `accHash` its keccak.
    struct Account {
        uint64 pendingCount;
        uint64 rolled;
        uint64 floor;
        uint64 cleared;
        address accBlob;
        uint16 accU;
        uint16 accV;
        uint32 accUnits;
        uint8 flags; // MAT | PREP0 | PREP1
        uint64 sendCounter;
        bytes32 accHash;
        mapping(uint64 => uint256) pending;
        uint256[516] accWords; // CT / 32: written once non-zero by `prepareAcc`, never zeroed (D3)
    }

    /// @custom:storage-location erc7201:scaas.pqz
    struct PqzStorage {
        address pqz;
        ZetherTypes.DisclosureMode disclosureMode;
        ZetherTypes.AuditorMode auditorMode;
        address verifier;
        bytes32 psid;
        uint256 shieldScale;
        uint256 maxShielded;
        uint256 confidentialFee;
        uint256 totalShielded;
        bytes32 auditorUA;
        mapping(bytes32 => Account) acct;
        mapping(bytes32 => address) entryPtr; // BUNDLE: SSTORE2(R)
        mapping(bytes32 => bytes32) entryHash; // commit-reveal: keccak256(R)
        mapping(bytes32 => bytes) memos; // commit-reveal: the sender memo
        uint256 multiLegFee; // op 7: per listed leg (CTR-PQZ-25), immutable
    }

    /// @notice The token's immutables a call needs and the statement's `envelopeBinding` word (0 direct).
    ///         A burn's public part rides along: `amount = 0` and `recipient = 0` is a refresh (0 for other ops).
    struct Env {
        address registry;
        bytes32 chainUid;
        bytes32 binding;
        uint256 amount;
        address recipient;
        ZetherTypes.TransferMode mode;
    }

    /// @dev One debit as checked: the header words and the key pointers.
    struct Op {
        bytes32 opTag;
        uint8 op;
        bytes32 from;
        bytes32 to;
        bytes32 ben;
        uint256 fee;
        uint256 amount;
        address recipient;
        uint64 sendCounter;
        uint64 p;
        uint256 validUntil;
        uint256 auditorOn;
        uint256 shieldIn; // the same-call top-up from the signer's public balance (`plainUsed` before 5h, header word 480)
        bytes16 salt;
        bytes32 memoHash;
        address keyF;
        address keyT;
        address keyA;
        address[] keys; // op 7: the legs' key pointers
        uint256 legs; // op 7: M
        uint256 groups; // op 7: G = ⌈M / 4⌉
        uint256 outLen;
        uint256 stLen;
        address registry;
        bytes32 chainUid;
        ZetherTypes.TransferMode mode;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.pqz")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant _STORAGE = 0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500;

    bytes32 internal constant TAG_ENVELOPE = keccak256("SCAAS-PQZ-ENVELOPE-V1");
    bytes32 internal constant TAG_UA_ENVELOPE = keccak256("SCAAS-PQZ-UA-ENVELOPE-V1");
    bytes32 internal constant TAG_UNWRAP = keccak256("SCAAS-PQZ-UNWRAP-V1");
    /// @notice A direct transfer's `envelopeBinding` is `keccak256(abi.encode(TAG_DIRECT_MODE, uint8(mode)))` (review
    ///         W-A): the statement, hence `authSig`, names the storage mode, so `…NoBundle` cannot replay a BUNDLE call.
    bytes32 internal constant TAG_DIRECT_MODE = keccak256("SCAAS-PQZ-DIRECT-MODE-V1");
    bytes32 internal constant TAG_ENTRY = keccak256("SCAAS-PQZ-ENTRY-V1");
    bytes32 internal constant OP_TRANSFER = 0xef22f3d1c1fc2edc565522eb73ca8cb782e8780eaf9b1f677965dd0cd5275414;
    bytes32 internal constant OP_BURN = 0x7383374d83fbb89f84ee079bff7a2742e4acb70f64b0b1e2ef40c34fb4cc1407;
    bytes32 internal constant OP_REFRESH = 0xf118f2df0f018062e2d4c296a01707dcd7ad7c85f6981d68517ac8b2cd75eede;
    bytes32 internal constant OP_DS = 0x868cc07c6ac389251ad6573f65fe35ee4dad66ee305f90c711af904bf5ceef3f;
    bytes32 internal constant OP_DR = 0xd8356cfbd875acb80fe8a8127a57b5c549d20fd65b9acca8672186a1a4296456;
    bytes32 internal constant OP_DA = 0xd6019aa47e04fe91c11df386ddc5bda2178a3f2506c46cdd59b16ef1d21daf81;
    /// @notice `keccak256("SCAAS-PQZ-OP-TRANSFER-MULTI-V1")` (op 7, CTR-PQZ-26).
    bytes32 internal constant OP_TRANSFER_MULTI = 0x6f6a773a4c94af3a446a226ef43f6f5403d6a00b95de446149f484cc02726b90;
    /// @notice The PQZH proof system id: op 7 built for M ∈ {1, 2, 4} and at most `INLINE_MAX_PQZH` inline credits
    ///         (PQZL: M ∈ {1, 2, 4, 8}, `INLINE_MAX`; CTR-PQZ-25).
    bytes32 internal constant PQZH_ID = PqzSafety.PQZH_ID;

    uint256 internal constant K_MAX = 1024;
    uint256 internal constant INLINE_MAX = 16;
    uint256 internal constant INLINE_MAX_PQZH = 10;
    /// @notice The largest rollover under `0.75 · 2^24` gas, a multiple of 16 (plan 5h D8; pinned by `PqzStateGasTest`).
    uint256 internal constant ROLL_MAX = 256;
    /// @notice A rollover takes entry `i` only at `block ≥ block_i + ROLL_AGE` (D6; owner 2026-10-20: 5 blocks).
    uint64 internal constant ROLL_AGE = 5;
    uint8 internal constant MAT = 1; // `acc` is `accWords`
    uint8 internal constant PREP = 6; // both halves of `accWords` written (bits 2, 4: halves 0, 1)
    uint256 internal constant HALF_WORDS = 258;
    uint256 internal constant MAX_TOTAL_SHIELDED = 1 << 62;
    uint256 internal constant VALUE_BOUND = 1 << 64;
    uint256 internal constant HEADER = 640;
    /// @dev Transfer payload: `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ toUA ‖ beneficiaryUA ‖ salt(16)`, then `out`.
    uint256 internal constant T_OUT = 208;
    /// @dev Burn payload: `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ beneficiaryUA`, then `u' ‖ v_f`.
    uint256 internal constant B_OUT = 160;
    uint256 internal constant OUT_ON = 16_768;
    uint256 internal constant OUT_OFF = 16_640;
    uint256 internal constant MEMO = 57;
    uint256 internal constant DISCLOSE = 33_184;

    function $() internal pure returns (PqzStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init


    // ------------------------------------------------------------------ shield (§7.3)


    // ------------------------------------------------------------------ transfer (§7.4)


    /// @notice The statement and every cheap check of a transfer, in the buffer that becomes the precompile input.
    function prepareTransfer(
        Env memory e,
        bytes calldata payload,
        bytes calldata hint,
        uint256 proofLen
    ) internal view returns (Op memory o, bytes memory buf) {
        _bindMode(e);
        o = _parseTransfer(payload, e.mode);
        _common(o, e);
        _receiver(o, e);
        buf = _transferBuffer(o, e, payload[T_OUT:T_OUT + o.outLen], hint, proofLen);
    }

    /// @dev A direct transfer (binding 0) binds its mode (W-A); a relayed one is bound by the envelope signature over
    ///      `data`, selector included.
    function _bindMode(Env memory e) internal pure {
        if (e.binding == 0) e.binding = keccak256(abi.encode(TAG_DIRECT_MODE, uint8(e.mode)));
    }

    /// @dev Not the sender; registered; the auditor's key when `auditorOn`. No credit cap: credits are never refused
    ///      (plan 5h D7).
    function _receiver(Op memory o, Env memory e) internal view {
        if (o.from == o.to) revert IPqzToken.SelfTransfer();
        o.keyT = _keyPtr(e.registry, o.to);
        if (o.auditorOn == 1) o.keyA = _keyPtr(e.registry, $().auditorUA);
    }

    /// @dev `header ‖ pk_f ‖ pk_t ‖ [pk_a] ‖ T ‖ out` (83,072 / 66,560 B).
    function _transferBuffer(
        Op memory o,
        Env memory e,
        bytes calldata out,
        bytes calldata hint,
        uint256 proofLen
    ) internal view returns (bytes memory buf) {
        if (!PqzCt.isCanonical(out)) revert IPqzToken.NonCanonical();
        if (PqzCt.isZero(out[0:PqzCt.PK])) revert IPqzToken.ZeroU();
        bytes memory t = _total(o, hint);
        uint256 nk = 2 + o.auditorOn;
        o.stLen = HEADER + nk * PqzCt.PK + PqzCt.CT + o.outLen;
        buf = _buffer(1, o.stLen, proofLen);
        _header(buf, o, e);
        _key(buf, HEADER, o.keyF);
        _key(buf, HEADER + PqzCt.PK, o.keyT);
        if (o.auditorOn == 1) _key(buf, HEADER + 2 * PqzCt.PK, o.keyA);
        _mem(buf, HEADER + nk * PqzCt.PK, t);
        _cd(buf, HEADER + nk * PqzCt.PK + PqzCt.CT, out);
    }

    /// @dev The payload's shape by the disclosure mode: `out` with or without `v_a`, the memo exactly on HASH.
    function _parseTransfer(bytes calldata payload, ZetherTypes.TransferMode mode) internal view returns (Op memory o) {
        PqzStorage storage s = $();
        if (s.disclosureMode == ZetherTypes.DisclosureMode.COMPACT && mode != ZetherTypes.TransferMode.HASH) {
            revert IPqzToken.TransferEntryDisabled(uint8(s.disclosureMode));
        }
        uint256 memo = mode == ZetherTypes.TransferMode.HASH ? MEMO : 0;
        uint256 len = payload.length;
        if (len < T_OUT + memo) revert IPqzToken.BadPayload(len);
        uint256 outLen = len - T_OUT - memo;
        if (outLen != OUT_ON && outLen != OUT_OFF) revert IPqzToken.BadPayload(len);
        o.outLen = outLen;
        o.auditorOn = outLen == OUT_ON ? 1 : 0;
        if (o.auditorOn == 1 && s.auditorMode == ZetherTypes.AuditorMode.NONE) revert IPqzToken.AuditorForbidden();
        if (o.auditorOn == 0 && s.auditorMode == ZetherTypes.AuditorMode.FULL) revert IPqzToken.AuditorRequired();
        o.opTag = OP_TRANSFER;
        o.mode = mode;
        o.op = 1;
        _head(o, payload);
        o.to = bytes32(payload[128:160]);
        o.ben = bytes32(payload[160:192]);
        o.salt = bytes16(payload[192:208]);
        if (memo != 0) {
            bytes calldata m = payload[len - MEMO:];
            if (bytes16(m[0:16]) != o.salt) revert IPqzToken.MemoSaltMismatch();
            o.memoHash = keccak256(m);
        }
    }

    /// @dev The op blob `R ‖ v_f` with `R = salt ‖ u ‖ v_t ‖ [v_a] ‖ word(toUA)` (plan 5h D1), the debit, the credit
    ///      `(u, v_t)`, the fee (a TRIVIAL entry of the beneficiary), the entry by mode.
    function _settleTransfer(Op memory o, bytes calldata payload) internal returns (bytes32 ref) {
        bytes calldata out = payload[T_OUT:T_OUT + o.outLen];
        bytes memory blob =
            bytes.concat(o.salt, out[0:PqzCt.CT], out[OUT_OFF:o.outLen], o.to, out[PqzCt.CT:PqzCt.CT + PqzCt.V]);
        address ptr = SSTORE2.write(blob);
        _debit(o, ptr, 16, blob.length - PqzCt.V);
        ref = _sent(o);
        _credit(o.to, ptr, 16, 16 + PqzCt.PK, ref);
        if (o.fee != 0) _trivial(o.ben, o.fee);
        _entry(o, ref, ptr, blob, payload, MEMO);
        emit IPqzToken.PqzTransfer(ref, o.from, o.to, o.salt, out);
    }

    /// @dev `pending[ua] ← (blob, uOff, vOff, block)` (D2); never refused (D7).
    function _credit(bytes32 ua, address ptr, uint256 uOff, uint256 vOff, bytes32 ref) internal {
        Account storage b = $().acct[ua];
        uint64 i = b.pendingCount;
        b.pending[i] = uint256(uint160(ptr)) << 96 | uOff << 80 | vOff << 64 | block.number;
        b.pendingCount = i + 1;
        emit IPqzToken.PqzCredit(ua, i, ref);
    }

    /// @dev A TRIVIAL entry `(amount, block)` (D18): merged into the tail when that is TRIVIAL, of this block and still
    ///      pending (index `≥ max(floor, rolled)`: never one a same-block debit spent), else appended.
    function _trivial(bytes32 ua, uint256 amount) internal {
        Account storage b = $().acct[ua];
        uint64 n = b.pendingCount;
        if (n != 0) {
            uint64 i = n - 1;
            uint256 e = b.pending[i];
            uint64 lo = b.floor > b.rolled ? b.floor : b.rolled;
            if (i >= lo && uint16(e >> 64) == 0 && uint64(e) == block.number && (e >> 96) + amount < VALUE_BOUND) {
                b.pending[i] = e + (amount << 96);
                emit IPqzToken.PqzTrivialCredit(ua, i, amount);
                return;
            }
        }
        b.pending[n] = amount << 96 | block.number;
        b.pendingCount = n + 1;
        emit IPqzToken.PqzTrivialCredit(ua, n, amount);
    }

    /// @dev The entry by mode: BUNDLE `entryPtr` = the op blob (`R` is its data minus the trailing `v_f`; D11), HASH
    ///      `keccak256(R)` and the memo (the last `memoLen` payload bytes; P6g D14), NONE nothing.
    function _entry(Op memory o, bytes32 ref, address ptr, bytes memory blob, bytes calldata payload, uint256 memoLen)
        internal
    {
        PqzStorage storage s = $();
        if (o.mode == ZetherTypes.TransferMode.BUNDLE) {
            s.entryPtr[ref] = ptr;
        } else if (o.mode == ZetherTypes.TransferMode.HASH) {
            bytes32 h;
            assembly ("memory-safe") { h := keccak256(add(blob, 32), sub(mload(blob), 128)) }
            s.entryHash[ref] = h;
            s.memos[ref] = payload[payload.length - memoLen:];
        }
    }

    // ------------------------------------------------------------------ multi-recipient transfer (op 7, CTR-PQZ-26)


    /// @notice The op 7 statement and every cheap check, in the precompile buffer.
    function prepareMulti(Env memory e, bytes calldata payload, bytes calldata hint, uint256 proofLen)
        internal view returns (Op memory o, bytes memory buf)
    {
        _bindMode(e);
        o = _parseMulti(payload, e.mode);
        _common(o, e);
        o.fee += o.legs * $().multiLegFee; // the header's public fee: the beneficiary's part + M · multiLegFee
        _legs(o, e, payload);
        uint256 off = T_OUT + 32 * o.legs;
        buf = _multiBuffer(o, e, payload[off:off + o.outLen], hint, proofLen);
    }

    /// @notice True when a multi payload carries the commit-reveal memo (its length says so; any shape error: false).
    function multiHasMemo(bytes calldata payload) internal pure returns (bool) {
        if (payload.length < T_OUT) return false;
        uint256 m = uint256(bytes32(payload[160:192]));
        if (m == 0 || m > 8) return false;
        uint256 base = T_OUT + 32 * m + PqzCt.PK * ((m + 3) / 4) + PqzCt.V * (m + 1);
        uint256 memo = 18 + 40 * m;
        return payload.length == base + memo || payload.length == base + PqzCt.V * m + memo;
    }

    /// @dev `M` in the id's built set, the length fixing `auditorOn`, the auditor mode, the memo on HASH.
    function _parseMulti(bytes calldata payload, ZetherTypes.TransferMode mode) internal view returns (Op memory o) {
        PqzStorage storage s = $();
        if (s.disclosureMode == ZetherTypes.DisclosureMode.COMPACT && mode != ZetherTypes.TransferMode.HASH) {
            revert IPqzToken.TransferEntryDisabled(uint8(s.disclosureMode));
        }
        if (payload.length < T_OUT) revert IPqzToken.BadPayload(payload.length);
        uint256 m = uint256(bytes32(payload[160:192]));
        if (!(m == 1 || m == 2 || m == 4 || (m == 8 && s.psid != PQZH_ID))) revert IPqzToken.BadRecipientCount(m);
        o.legs = m;
        o.groups = (m + 3) / 4;
        o.opTag = OP_TRANSFER_MULTI;
        o.mode = mode;
        o.op = 7;
        uint256 memo = mode == ZetherTypes.TransferMode.HASH ? 18 + 40 * m : 0;
        o.outLen = PqzCt.PK * o.groups + PqzCt.V * (m + 1);
        if (payload.length < T_OUT + 32 * m + memo) revert IPqzToken.BadPayload(payload.length); // m ≤ 8: no overflow
        uint256 rest = payload.length - T_OUT - 32 * m - memo;
        if (rest == o.outLen + PqzCt.V * m) o.auditorOn = 1;
        else if (rest != o.outLen) revert IPqzToken.BadPayload(payload.length);
        if (o.auditorOn == 1 && s.auditorMode == ZetherTypes.AuditorMode.NONE) revert IPqzToken.AuditorForbidden();
        if (o.auditorOn == 0 && s.auditorMode == ZetherTypes.AuditorMode.FULL) revert IPqzToken.AuditorRequired();
        o.outLen += PqzCt.V * m * o.auditorOn;
        _head(o, payload);
        o.ben = bytes32(payload[128:160]);
        o.salt = bytes16(payload[192:208]);
        o.to = keccak256(payload[T_OUT:T_OUT + 32 * m]); // recipientsHash, header word 192
        if (memo != 0) {
            bytes calldata mm = payload[payload.length - memo:];
            if (bytes16(mm[0:16]) != o.salt) revert IPqzToken.MemoSaltMismatch();
            o.memoHash = keccak256(mm);
        }
    }

    /// @dev Every leg: not the sender, pairwise distinct, a PQZ holder (its key); the auditor's key when `auditorOn`.
    function _legs(Op memory o, Env memory e, bytes calldata payload) internal view {
        PqzStorage storage s = $();
        uint256 m = o.legs;
        o.keys = new address[](m);
        for (uint256 j; j < m; ++j) {
            bytes32 ua = bytes32(payload[T_OUT + 32 * j:T_OUT + 32 * j + 32]);
            if (ua == o.from) revert IPqzToken.SelfTransfer();
            for (uint256 k; k < j; ++k) {
                if (bytes32(payload[T_OUT + 32 * k:T_OUT + 32 * k + 32]) == ua) revert IPqzToken.DuplicateRecipient(ua);
            }
            o.keys[j] = _keyPtr(e.registry, ua);
        }
        if (o.auditorOn == 1) o.keyA = _keyPtr(e.registry, s.auditorUA);
    }

    /// @dev `header ‖ pk_f ‖ pk_0 … pk_{M−1} ‖ [pk_a] ‖ T ‖ out` (header word 192 `recipientsHash`, 320 `M`).
    function _multiBuffer(
        Op memory o,
        Env memory e,
        bytes calldata out,
        bytes calldata hint,
        uint256 proofLen
    ) internal view returns (bytes memory buf) {
        if (!PqzCt.isCanonical(out)) revert IPqzToken.NonCanonical();
        for (uint256 g; g < o.groups; ++g) {
            if (PqzCt.isZero(out[PqzCt.PK * g:PqzCt.PK * (g + 1)])) revert IPqzToken.ZeroU();
        }
        bytes memory t = _total(o, hint);
        uint256 nk = 1 + o.legs + o.auditorOn;
        o.stLen = HEADER + nk * PqzCt.PK + PqzCt.CT + o.outLen;
        buf = _buffer(7, o.stLen, proofLen);
        _header(buf, o, e);
        _mem(buf, 320, abi.encode(o.legs));
        _key(buf, HEADER, o.keyF);
        for (uint256 j; j < o.legs; ++j) _key(buf, HEADER + (1 + j) * PqzCt.PK, o.keys[j]);
        if (o.auditorOn == 1) _key(buf, HEADER + (1 + o.legs) * PqzCt.PK, o.keyA);
        _mem(buf, HEADER + nk * PqzCt.PK, t);
        _cd(buf, HEADER + nk * PqzCt.PK + PqzCt.CT, out);
    }

    /// @dev The op blob `R ‖ v_f`, the debit, a credit per leg (the per-leg fee a TRIVIAL entry), the beneficiary's
    ///      fee, the entry by mode.
    function _settleMulti(Op memory o, bytes calldata payload) internal returns (bytes32 ref) {
        bytes calldata out = payload[T_OUT + 32 * o.legs:T_OUT + 32 * o.legs + o.outLen];
        {
            bytes memory blob = _bundleMulti(o, payload, out);
            address ptr = SSTORE2.write(blob);
            _debit(o, ptr, 16, blob.length - PqzCt.V);
            ref = _sent(o);
            _creditLegs(o, ref, payload, ptr);
            _entry(o, ref, ptr, blob, payload, 18 + 40 * o.legs);
        }
        uint256 bf = o.fee - o.legs * $().multiLegFee;
        if (bf != 0) _trivial(o.ben, bf);
        emit IPqzToken.PqzTransferMulti(ref, o.from, o.to, o.legs, o.salt, out);
    }

    /// @dev `pending[UA_j] ← (u_{⌊j/4⌋}, v_j)` of the blob, in leg order.
    function _creditLegs(Op memory o, bytes32 ref, bytes calldata payload, address ptr) internal {
        uint256 us = 16 + PqzCt.PK * o.groups;
        uint256 ls = 160 + PqzCt.V * o.auditorOn;
        uint256 mlf = $().multiLegFee;
        for (uint256 j; j < o.legs; ++j) {
            bytes32 ua = bytes32(payload[T_OUT + 32 * j:T_OUT + 32 * j + 32]);
            _credit(ua, ptr, 16 + PqzCt.PK * (j / 4), us + ls * j, ref);
            if (mlf != 0) _trivial(ua, mlf);
        }
    }

    /// @dev The op blob `R ‖ v_f`, `R = salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ word(UA_j))_{j<M}` — for `M = 1` the
    ///      single transfer's bundle exactly (CTR-PQZ-26).
    function _bundleMulti(Op memory o, bytes calldata payload, bytes calldata out) internal pure returns (bytes memory r) {
        uint256 m = o.legs;
        uint256 us = PqzCt.PK * o.groups;
        uint256 ls = 160 + PqzCt.V * o.auditorOn;
        r = new bytes(16 + us + ls * m + PqzCt.V);
        _putCd(r, 16 + us + ls * m, out[us + PqzCt.V * m:us + PqzCt.V * (m + 1)]);
        _put(r, 0, abi.encodePacked(o.salt));
        _putCd(r, 16, out[0:us]);
        for (uint256 j; j < m; ++j) {
            uint256 d = 16 + us + ls * j;
            _putCd(r, d, out[us + PqzCt.V * j:us + PqzCt.V * (j + 1)]);
            if (o.auditorOn == 1) _putCd(r, d + PqzCt.V, out[us + PqzCt.V * (m + 1 + j):us + PqzCt.V * (m + 2 + j)]);
            _putCd(r, d + ls - 32, payload[T_OUT + 32 * j:T_OUT + 32 * j + 32]);
        }
    }

    function _put(bytes memory r, uint256 off, bytes memory x) internal pure {
        assembly ("memory-safe") { mcopy(add(add(r, 32), off), add(x, 32), mload(x)) }
    }

    function _putCd(bytes memory r, uint256 off, bytes calldata x) internal pure {
        assembly ("memory-safe") { calldatacopy(add(add(r, 32), off), x.offset, x.length) }
    }

    // ------------------------------------------------------------------ burn and refresh (§7.5)


    /// @dev The op blob `u' ‖ v_f` (D1), the debit, the fee, the public amount out of `totalShielded`.
    function _settleBurn(Op memory o, bytes calldata out) internal {
        _debit(o, SSTORE2.write(out), 0, PqzCt.PK);
        _sent(o);
        if (o.fee != 0) _trivial(o.ben, o.fee);
        $().totalShielded -= o.amount;
        emit IPqzToken.PqzBurned(o.from, o.amount, o.recipient, out);
    }

    function prepareBurn(
        Env memory e,
        bytes calldata payload,
        bytes calldata hint,
        uint256 proofLen
    ) internal view returns (Op memory o, bytes memory buf) {
        PqzStorage storage s = $();
        if (payload.length != B_OUT + PqzCt.CT) revert IPqzToken.BadPayload(payload.length);
        if (e.amount == 0) {
            if (e.recipient != address(0)) revert IPqzToken.RefreshRecipient(e.recipient);
            o.opTag = OP_REFRESH;
        } else {
            if (e.amount > s.maxShielded) revert IPqzToken.AmountOutOfRange(e.amount, s.maxShielded);
            if (e.recipient == address(0)) revert IPqzToken.ZeroRecipient();
            o.opTag = OP_BURN;
        }
        o.op = 2;
        o.amount = e.amount;
        o.recipient = e.recipient;
        _head(o, payload);
        o.ben = bytes32(payload[128:160]);
        _common(o, e);
        buf = _burnBuffer(o, e, payload[B_OUT:B_OUT + PqzCt.CT], hint, proofLen);
    }

    /// @dev `header ‖ pk_f ‖ T ‖ u' ‖ v_f` (50,048 B).
    function _burnBuffer(
        Op memory o,
        Env memory e,
        bytes calldata out,
        bytes calldata hint,
        uint256 proofLen
    ) internal view returns (bytes memory buf) {
        if (!PqzCt.isCanonical(out)) revert IPqzToken.NonCanonical();
        if (PqzCt.isZero(out[0:PqzCt.PK])) revert IPqzToken.ZeroU();
        bytes memory t = _total(o, hint);
        o.stLen = HEADER + PqzCt.PK + 2 * PqzCt.CT;
        buf = _buffer(2, o.stLen, proofLen);
        _header(buf, o, e);
        _key(buf, HEADER, o.keyF);
        _mem(buf, HEADER + PqzCt.PK, t);
        _cd(buf, HEADER + PqzCt.PK + PqzCt.CT, out);
    }

    // ------------------------------------------------------------------ rollover (§7.6)


    // ------------------------------------------------------------------ disclosure (§7.9, P6g D11)

    /// @notice The 33,184-byte disclosure statement of leg `j` of `entryRef` for `kind` (0 `SENDER_S`, 1 `RECEIVER_X`,
    ///         2 `AUDITOR`) in its precompile buffer (CTR-PQZ-14, CTR-PQZ-26; a single entry is leg 0): `u_{⌊j/4⌋}` and
    ///         `v_j` (or `v_{a,j}`), the key of `UA_j` (or the auditor). Reverts on an unknown entry, a bundle that is not
    ///         the stored one or has no leg `j`, `kind > 2`, `AUDITOR` without the copies, `amount ≥ 2^64`.
    function disclosureBuffer(
        bytes32 ref,
        uint256 j,
        uint256 amount,
        uint8 kind,
        bytes memory bundle,
        Env memory e,
        uint256 proofLen
    ) internal view returns (bytes memory buf) {
        bytes32 h = ciphertextHash(ref);
        if (h == 0) revert IPqzToken.UnknownEntry(ref);
        if (keccak256(bundle) != h || kind > 2 || amount >= VALUE_BOUND) revert IPqzToken.BadPayload(bundle.length);
        (uint256 uOff, uint256 vOff, bytes32 owner) = _legOf(bundle, j, kind);
        buf = _buffer(kind == 0 ? 4 : 5, DISCLOSE, proofLen);
        _discHead(buf, ref, amount, kind, e);
        _key(buf, 288, _keyPtr(e.registry, owner));
        assembly ("memory-safe") {
            let d := add(add(buf, 37), 16672)
            mcopy(d, add(add(bundle, 32), uOff), 16384)
            mcopy(add(d, 16384), add(add(bundle, 32), vOff), 128)
        }
    }

    /// @dev Leg `j` of a bundle: the offsets of `u_{⌊j/4⌋}` and of `v_j` (`v_{a,j}` for `AUDITOR`), and its owner.
    function _legOf(bytes memory bundle, uint256 j, uint8 kind)
        internal view returns (uint256 uOff, uint256 vOff, bytes32 owner)
    {
        uint256 bl = bundle.length;
        (uint256 g, uint256 m, uint256 a) = _bundleShape(bl);
        if (j >= m || (kind == 2 && a == 0)) revert IPqzToken.BadPayload(bl);
        uint256 ls = 160 + PqzCt.V * a;
        uint256 leg = 16 + PqzCt.PK * g + ls * j;
        uOff = 16 + PqzCt.PK * (j / 4);
        vOff = kind == 2 ? leg + PqzCt.V : leg;
        assembly ("memory-safe") { owner := mload(add(add(bundle, 32), sub(add(leg, ls), 32))) }
        if (kind == 2) owner = $().auditorUA;
    }

    /// @dev `(G, M, auditorOn)` of a bundle `salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ UA_j)_{j<M}` from its length:
    ///      unique for every built `M` (≤ 8: the legs take < 16,384 bytes), else `BadPayload`.
    function _bundleShape(uint256 bl) internal pure returns (uint256 g, uint256 m, uint256 a) {
        if (bl < 16 + PqzCt.PK) revert IPqzToken.BadPayload(bl);
        g = (bl - 16) / PqzCt.PK;
        uint256 rem = bl - 16 - PqzCt.PK * g;
        for (uint256 i; i < 2; ++i) {
            a = 1 - i;
            uint256 ls = 160 + PqzCt.V * a;
            m = rem / ls;
            if (m != 0 && m <= 8 && rem == ls * m && (m + 3) / 4 == g) return (g, m, a);
        }
        revert IPqzToken.BadPayload(bl);
    }

    function _discHead(bytes memory buf, bytes32 ref, uint256 amount, uint8 kind, Env memory e) internal view {
        bytes32 tag = kind == 0 ? OP_DS : kind == 1 ? OP_DR : OP_DA;
        _mem(buf, 0, abi.encode(tag, $().psid, block.chainid, e.chainUid, address(this), e.registry, ref, amount,
            uint256(kind)));
    }

    /// @notice `keccak256(R)` of the entry (stored hash, or the hash of `R` in the stored op blob), 0 if none.
    function ciphertextHash(bytes32 ref) internal view returns (bytes32 h) {
        PqzStorage storage s = $();
        h = s.entryHash[ref];
        if (h == 0 && s.entryPtr[ref] != address(0)) h = keccak256(rOf(s.entryPtr[ref]));
    }

    /// @notice `R` of an op blob: its data without the trailing `v_f` (D1, D11).
    function rOf(address ptr) internal view returns (bytes memory r) {
        r = new bytes(ptr.code.length - 1 - PqzCt.V);
        assembly ("memory-safe") { extcodecopy(ptr, add(r, 32), 1, mload(r)) }
    }

    /// @notice The precompile's verdict on a buffer with its proof already in place (views; disclosure).
    function verdict(address pqz, bytes memory buf) internal view returns (bool ok) {
        assembly ("memory-safe") {
            mstore(0, 0)
            let r := staticcall(gas(), pqz, add(buf, 32), mload(buf), 0, 0x20)
            ok := and(and(r, eq(returndatasize(), 0x20)), eq(mload(0), 1))
        }
    }

    // ------------------------------------------------------------------ statement views (by DELEGATECALL)




    /// @dev `pqzTransfer`'s form: BUNDLE on a BUNDLE token, commit-reveal (HASH) on a COMPACT one.
    function _defaultMode() internal view returns (ZetherTypes.TransferMode) {
        return $().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
            ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;
    }

    /// @dev The statement bytes of a precompile buffer (the 5-byte prefix and the empty proof dropped).
    function _stmtOf(bytes memory buf) internal pure returns (bytes memory st) {
        st = new bytes(buf.length - 5);
        assembly ("memory-safe") { mcopy(add(st, 32), add(buf, 37), mload(st)) }
    }

    // ------------------------------------------------------------------ shared steps

    /// @dev Words 0–2 of both payloads and the sender (`fromUA` at 96).
    function _head(Op memory o, bytes calldata payload) internal pure {
        uint256 p = uint256(bytes32(payload[0:32]));
        if (p > type(uint64).max) revert IPqzToken.BadPayload(payload.length);
        o.p = uint64(p);
        o.validUntil = uint256(bytes32(payload[32:64]));
        o.shieldIn = uint256(bytes32(payload[64:96]));
        o.from = bytes32(payload[96:128]);
    }

    /// @dev Expiry, `shieldIn` within the cap, the sender registered (its key), the beneficiary registered or 0 and the
    ///      fee, the counter.
    function _common(Op memory o, Env memory e) internal view {
        PqzStorage storage s = $();
        if (block.number > o.validUntil) revert IPqzToken.Expired(o.validUntil);
        uint256 room = s.maxShielded - s.totalShielded;
        if (o.shieldIn > room) revert IPqzToken.AmountOutOfRange(o.shieldIn, room);
        o.registry = e.registry;
        o.chainUid = e.chainUid;
        o.keyF = _keyPtr(e.registry, o.from);
        if (o.ben != 0) {
            if (!_registered(e.registry, o.ben)) revert IPqzToken.AccountNotRegistered(o.ben);
            o.fee = s.confidentialFee;
        }
        o.sendCounter = s.acct[o.from].sendCounter;
    }

    /// @dev `T = acc ± Σ pending[min(p, rolled) .. max(p, rolled)) + Trivial(digits(shieldIn))`, everything read from
    ///      state (plan 5h D5): `acc` from the reference or the slots (the hint replaces the slots when it hashes to
    ///      `accHash`), each credit from its blob, each TRIVIAL entry `Trivial(digits(amount))`; `p ∈ [floor,
    ///      pendingCount]`, `|p − rolled| ≤ INLINE_MAX`, `unitsOf(T) = accUnits + (p − rolled) + 1 ≤ K_MAX`.
    ///      A rollover between prove and submit leaves `T` unchanged (D4 / D6, CTR-PQZ-08).
    function _total(Op memory o, bytes calldata hint) internal view returns (bytes memory t) {
        Account storage a = $().acct[o.from];
        uint64 r = a.rolled;
        uint64 p = o.p;
        if (p < a.floor || p > a.pendingCount) revert IPqzToken.PendingRange(p, a.floor, a.pendingCount);
        bool up = p >= r;
        uint256 n = up ? p - r : r - p;
        if (n > (o.op == 7 && $().psid == PQZH_ID ? INLINE_MAX_PQZH : INLINE_MAX)) revert IPqzToken.InlineTooFar(n);
        t = _accOf(a, hint);
        _window(a, t, up ? r : p, n, up, false);
        PqzCt.addTrivial(t, o.shieldIn);
        PqzCt.reduce(t);
        uint256 units = uint256(a.accUnits) + 1;
        if (up) units += n;
        else if (units < n) revert IPqzToken.UnitsInvariant();
        else units -= n;
        if (units > K_MAX) revert IPqzToken.UnitsInvariant();
    }

    /// @dev `acc` (unreduced input to the sums): the materialised words (or the hint when `keccak(hint) == accHash`),
    ///      else the reference's `(u, v)`, else `Trivial(0)`.
    function _accOf(Account storage a, bytes calldata hint) internal view returns (bytes memory c) {
        if (a.flags & MAT != 0) {
            if (hint.length == PqzCt.CT && keccak256(hint) == a.accHash) return PqzCt.load(hint);
            c = new bytes(PqzCt.CT);
            uint256[516] storage w = a.accWords;
            assembly ("memory-safe") {
                let b := w.slot
                let d := add(c, 32)
                for { let i := 0 } lt(i, 516) { i := add(i, 1) } { mstore(add(d, shl(5, i)), sload(add(b, i))) }
            }
            return c;
        }
        c = new bytes(PqzCt.CT);
        if (a.accBlob != address(0)) PqzCt.loadBlob(a.accBlob, a.accU, a.accV, c);
    }

    /// @dev `c ±= Σ pending[lo .. lo + n)` in order; with `aged`, entry `i` only at `block_i + ROLL_AGE` (D6).
    function _window(Account storage a, bytes memory c, uint256 lo, uint256 n, bool up, bool aged) internal view {
        bytes memory x = new bytes(PqzCt.CT);
        for (uint256 k; k < n; ++k) {
            uint256 e = a.pending[uint64(lo + k)];
            if (aged && uint64(e) + ROLL_AGE > block.number) revert IPqzToken.RollTooYoung(lo + k);
            if (uint16(e >> 64) == 0) {
                if (up) PqzCt.addTrivial(c, uint64(e >> 96));
                else PqzCt.subTrivial(c, uint64(e >> 96));
            } else {
                PqzCt.loadBlob(address(uint160(e >> 96)), uint16(e >> 80), uint16(e >> 64), x);
                if (up) PqzCt.addMem(c, x);
                else PqzCt.subMem(c, x);
            }
        }
    }

    /// @dev The authority (registry: the signing UA `from` itself over `authDigest`, purpose `zether-auth`; UA-6 U7),
    ///      then the proof.
    function _check(Op memory o, bytes memory buf, bytes calldata proof, bytes calldata authSig)
        internal view
    {
        uint256 len = o.stLen;
        bytes32 h;
        assembly ("memory-safe") { h := keccak256(add(buf, 37), len) }
        bytes32 d = keccak256(abi.encodePacked("SCAAS-PQZ-AUTH-V1", h));
        try IUARegistry(o.registry).requireAuthorized(o.from, UAKinds.PURPOSE_ZETHER_AUTH, d, authSig) {}
        catch (bytes memory err) {
            if (err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector) revert UAKinds.UAVerifyGas();
            revert IPqzToken.AuthRejected();
        }
        assembly ("memory-safe") {
            calldatacopy(add(add(buf, 37), len), proof.offset, proof.length)
        }
        if (!verdict($().pqz, buf)) revert IPqzToken.ProofRejected();
    }

    /// @dev Plan 5h D4: `acc` = the fresh reference `(blob, uOff, vOff)`, `accUnits = 1`, `rolled = floor = p` (a
    ///      debit with `p < rolled` un-rolls `[p, rolled)`: pending again, rolled again later), the dead slots
    ///      `[cleared, p)` deleted (≤ 2·`INLINE_MAX`); `totalShielded += shieldIn` (the token takes the public units).
    function _debit(Op memory o, address ptr, uint256 uOff, uint256 vOff) internal {
        PqzStorage storage s = $();
        Account storage a = s.acct[o.from];
        uint64 p = o.p;
        (a.accBlob, a.accU, a.accV, a.accUnits, a.flags) = (ptr, uint16(uOff), uint16(vOff), 1, a.flags & ~MAT);
        (a.rolled, a.floor) = (p, p);
        for (uint64 i = a.cleared; i < p; ++i) delete a.pending[i];
        a.cleared = p;
        s.totalShielded += o.shieldIn;
    }

    /// @dev `sendCounter++`; the debit's `entryRef` (counter before the increment).
    function _sent(Op memory o) internal returns (bytes32) {
        $().acct[o.from].sendCounter = o.sendCounter + 1;
        return entryRefOf(o.chainUid, o.from, o.sendCounter);
    }

    /// @notice `entryRef` (§7.4, §8.1).
    function entryRefOf(bytes32 chainUid, bytes32 from, uint64 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_ENTRY, block.chainid, chainUid, address(this), from, uint256(counter)));
    }

    /// @dev A UA holding a PQZ key (UA-6 U7: `recordOf(ua).pqzKey ≠ 0`).
    function _registered(address registry, bytes32 ua) internal view returns (bool) {
        (, address ptr) = IUARegistry(registry).recordOf(ua);
        return ptr != address(0);
    }

    /// @dev The PQZ key pointer of a holder (`AccountNotRegistered` otherwise, or for a key of another length).
    function _keyPtr(address registry, bytes32 ua) internal view returns (address ptr) {
        (, ptr) = IUARegistry(registry).recordOf(ua);
        if (ptr.code.length != PqzCt.PK + 1) revert IPqzToken.AccountNotRegistered(ua);
    }

    // ------------------------------------------------------------------ the buffer `u8(op) ‖ be32(len) ‖ stmt ‖ proof`

    function _buffer(uint8 op, uint256 stLen, uint256 proofLen) internal pure returns (bytes memory buf) {
        buf = new bytes(5 + stLen + proofLen);
        assembly ("memory-safe") { mstore(add(buf, 32), or(shl(248, op), shl(216, stLen))) }
    }

    /// @dev The 20 header words (§7.7) at statement offset 0.
    function _header(bytes memory buf, Op memory o, Env memory e) internal view {
        _mem(buf, 0, abi.encode(o.opTag, $().psid, block.chainid, address(this), e.registry, o.from, o.to, o.ben, o.fee,
            o.amount));
        _mem(buf, 320, abi.encode(o.recipient, uint256(o.sendCounter), uint256(o.p), o.validUntil, o.auditorOn,
            o.shieldIn, e.chainUid, e.binding, uint256(uint128(o.salt)), o.memoHash));
    }

    /// @dev Statement offset `off` (the buffer's 5-byte prefix skipped).
    function _mem(bytes memory buf, uint256 off, bytes memory x) internal pure {
        assembly ("memory-safe") { mcopy(add(add(buf, 37), off), add(x, 32), mload(x)) }
    }

    function _cd(bytes memory buf, uint256 off, bytes calldata x) internal pure {
        assembly ("memory-safe") { calldatacopy(add(add(buf, 37), off), x.offset, x.length) }
    }

    function _key(bytes memory buf, uint256 off, address ptr) internal view {
        assembly ("memory-safe") { extcodecopy(ptr, add(add(buf, 37), off), 1, 16384) }
    }
}
