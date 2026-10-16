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
///         pq-zero-knowledge.md §7.4–§7.9 and §8.1. Ciphertexts are calldata and events, hashes in storage (CTR-PQZ-07). Every
///         statement is built once, in a buffer `u8(op) ‖ be32(len) ‖ stmt ‖ proof` that is the precompile input
///         (P6g D13); `authDigest = keccak256("SCAAS-PQZ-AUTH-V1" ‖ keccak256(stmt))` is checked by the registry
///         (`requireZetherAuthorized`, the `authRef`'s PQ signature) before the precompile.
library PqzLib {
    struct Account {
        bytes32 accHash; // 0 = Trivial(0) (P6g D10)
        uint16 accUnits;
        uint64 pendingCount;
        uint64 rolled;
        uint64 floor;
        uint64 cleared;
        uint64 sendCounter;
        uint256 plainPending;
        mapping(uint64 => bytes32) pendingHash;
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
        uint256 plainUsed;
        bytes16 salt;
        bytes32 memoHash;
        address keyF;
        address keyT;
        address keyA;
        uint256 outLen;
        uint256 stLen;
        address registry;
        bytes32 chainUid;
        ZetherTypes.TransferMode mode;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.pqz")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500;

    bytes32 internal constant TAG_ENVELOPE = keccak256("SCAAS-PQZ-ENVELOPE-V1");
    bytes32 internal constant TAG_UA_ENVELOPE = keccak256("SCAAS-PQZ-UA-ENVELOPE-V1");
    bytes32 internal constant TAG_UNWRAP = keccak256("SCAAS-PQZ-UNWRAP-V1");
    bytes32 private constant TAG_ENTRY = keccak256("SCAAS-PQZ-ENTRY-V1");
    bytes32 internal constant OP_TRANSFER = 0xef22f3d1c1fc2edc565522eb73ca8cb782e8780eaf9b1f677965dd0cd5275414;
    bytes32 internal constant OP_BURN = 0x7383374d83fbb89f84ee079bff7a2742e4acb70f64b0b1e2ef40c34fb4cc1407;
    bytes32 internal constant OP_REFRESH = 0xf118f2df0f018062e2d4c296a01707dcd7ad7c85f6981d68517ac8b2cd75eede;
    bytes32 internal constant OP_DS = 0x868cc07c6ac389251ad6573f65fe35ee4dad66ee305f90c711af904bf5ceef3f;
    bytes32 internal constant OP_DR = 0xd8356cfbd875acb80fe8a8127a57b5c549d20fd65b9acca8672186a1a4296456;
    bytes32 internal constant OP_DA = 0xd6019aa47e04fe91c11df386ddc5bda2178a3f2506c46cdd59b16ef1d21daf81;

    uint256 internal constant K_MAX = 1024;
    uint256 internal constant INLINE_MAX = 16;
    uint256 internal constant ROLL_MAX = 16;
    uint64 internal constant CLEAR_MAX = 32;
    uint256 private constant MAX_TOTAL_SHIELDED = 1 << 62;
    uint256 private constant VALUE_BOUND = 1 << 64;
    uint256 private constant HEADER = 640;
    /// @dev Transfer payload: `p ‖ validUntilBlock ‖ plainUsed ‖ fromUA ‖ toUA ‖ beneficiaryUA ‖ salt(16)`, then `out`.
    uint256 private constant T_OUT = 208;
    /// @dev Burn payload: `p ‖ validUntilBlock ‖ plainUsed ‖ fromUA ‖ beneficiaryUA`, then `u' ‖ v_f`.
    uint256 private constant B_OUT = 160;
    uint256 private constant OUT_ON = 16_768;
    uint256 private constant OUT_OFF = 16_640;
    uint256 private constant MEMO = 57;
    uint256 private constant BUNDLE_ON = 16_688;
    uint256 private constant BUNDLE_OFF = 16_560;
    uint256 private constant DISCLOSE = 33_184;

    function $() internal pure returns (PqzStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init

    /// @notice The kind's `_init` (P6g plan D9): `verifier` a `UAPqzVerifier` (precompile and proof system),
    ///         `auditorKey` empty or the auditor's 32-byte `pqz-mlwe` UA, cap `≤ 2^62`, fee `< 2^64` and `< cap`.
    function init(IFactoryToken.ConfidentialConfig calldata c, address registry) public {
        PqzSafety.requireAllowedChain();
        bytes calldata aud = c.auditorKey;
        if (c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > MAX_TOTAL_SHIELDED
            || c.confidentialFee >= VALUE_BOUND || c.confidentialFee >= c.maxShielded
            || (aud.length != 0 && aud.length != 32) || c.maxShielded > type(uint256).max / c.shieldScale) {
            revert IPqzToken.BadInit();
        }
        if (c.disclosureMode > uint8(ZetherTypes.DisclosureMode.COMPACT)) revert IPqzToken.BadDisclosureMode(c.disclosureMode);
        if (c.auditorMode > uint8(ZetherTypes.AuditorMode.OPTIONAL)
            || (aud.length == 0) != (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE))) {
            revert IPqzToken.BadAuditorMode(c.auditorMode);
        }
        bytes32 a = aud.length == 32 ? bytes32(aud) : bytes32(0);
        if (a != 0 && !_registered(registry, a)) revert IPqzToken.AccountNotRegistered(a);
        PqzStorage storage s = $();
        UAPqzVerifier v = UAPqzVerifier(c.verifier);
        s.pqz = v.PRECOMPILE();
        s.psid = v.PROOF_SYSTEM_ID();
        s.verifier = c.verifier;
        s.disclosureMode = ZetherTypes.DisclosureMode(c.disclosureMode);
        s.auditorMode = ZetherTypes.AuditorMode(c.auditorMode);
        s.shieldScale = c.shieldScale;
        s.maxShielded = c.maxShielded;
        s.confidentialFee = c.confidentialFee;
        s.auditorUA = a;
    }

    // ------------------------------------------------------------------ shield (§7.3)

    /// @notice `plainPending[ua] += amount`, `totalShielded += amount` within the cap. The token takes the public units
    ///         (`pqzShield`) or a leg's underlying (`pqzWrapShield`).
    function shield(bytes32 ua, uint256 amount, address registry) public {
        PqzStorage storage s = $();
        if (!_registered(registry, ua)) revert IPqzToken.AccountNotRegistered(ua);
        uint256 room = s.maxShielded - s.totalShielded;
        if (amount == 0 || amount > room) revert IPqzToken.AmountOutOfRange(amount, room);
        s.totalShielded += amount;
        _plain(ua, amount);
    }

    // ------------------------------------------------------------------ transfer (§7.4)

    /// @notice One-recipient transfer: checks, statement, `authSig`, proof, then the debit, the credit, the fee, the
    ///         entry by `mode` (HASH commit-reveal, BUNDLE stored, NONE nothing).
    ///      Arguments ordered for the stack: the ones used last on top.
    function transfer(
        Env memory e,
        bytes calldata payload,
        bytes calldata acc,
        bytes[] calldata inl,
        bytes calldata proof,
        bytes calldata authSig
    ) public returns (bytes32 ref) {
        (Op memory o, bytes memory buf) = prepareTransfer(e, payload, acc, inl, proof.length);
        _check(o, buf, proof, authSig);
        ref = _settleTransfer(o, payload, inl);
    }

    /// @notice The statement and every cheap check of a transfer, in the buffer that becomes the precompile input.
    function prepareTransfer(
        Env memory e,
        bytes calldata payload,
        bytes calldata acc,
        bytes[] calldata inl,
        uint256 proofLen
    ) internal view returns (Op memory o, bytes memory buf) {
        o = _parseTransfer(payload, e.mode);
        _common(o, e);
        _receiver(o, e);
        buf = _transferBuffer(o, e, payload[T_OUT:T_OUT + o.outLen], acc, inl, proofLen);
    }

    /// @dev Not the sender; registered; the credit cap (`RefreshRequired`); the auditor's key when `auditorOn`.
    function _receiver(Op memory o, Env memory e) private view {
        PqzStorage storage s = $();
        if (o.from == o.to) revert IPqzToken.SelfTransfer();
        o.keyT = _keyPtr(e.registry, o.to);
        Account storage b = s.acct[o.to];
        if (uint256(b.accUnits) + (b.pendingCount - b.rolled) + 2 > K_MAX) revert IPqzToken.RefreshRequired(o.to);
        if (o.auditorOn == 1) o.keyA = _keyPtr(e.registry, s.auditorUA);
    }

    /// @dev `header ‖ pk_f ‖ pk_t ‖ [pk_a] ‖ T ‖ out` (83,072 / 66,560 B).
    function _transferBuffer(
        Op memory o,
        Env memory e,
        bytes calldata out,
        bytes calldata acc,
        bytes[] calldata inl,
        uint256 proofLen
    ) private view returns (bytes memory buf) {
        if (!PqzCt.isCanonical(out)) revert IPqzToken.NonCanonical();
        bytes memory t = _total(o, acc, inl);
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
    function _parseTransfer(bytes calldata payload, ZetherTypes.TransferMode mode) private view returns (Op memory o) {
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

    function _settleTransfer(Op memory o, bytes calldata payload, bytes[] calldata inl) private returns (bytes32 ref) {
        bytes calldata out = payload[T_OUT:T_OUT + o.outLen];
        _debit(o, out[0:PqzCt.PK], out[PqzCt.CT:PqzCt.CT + PqzCt.V], inl);
        ref = _sent(o);
        _credit(o, ref, out);
        if (o.fee != 0) _plain(o.ben, o.fee);
        if (o.mode != ZetherTypes.TransferMode.NONE) _entry(o, ref, payload);
        emit IPqzToken.PqzTransfer(ref, o.from, o.to, o.salt, out);
    }

    /// @dev `pending[to] ← (u, v_t)`.
    function _credit(Op memory o, bytes32 ref, bytes calldata out) private {
        Account storage b = $().acct[o.to];
        uint64 i = b.pendingCount;
        b.pendingHash[i] = keccak256(out[0:PqzCt.CT]); // u ‖ v_t
        b.pendingCount = i + 1;
        emit IPqzToken.PqzCredit(o.to, i, ref);
    }

    /// @dev `R = salt ‖ u ‖ v_t ‖ [v_a] ‖ word(toUA)`: SSTORE2 (BUNDLE) or its hash and the memo (HASH; P6g D14).
    function _entry(Op memory o, bytes32 ref, bytes calldata payload) private {
        PqzStorage storage s = $();
        bytes calldata out = payload[T_OUT:T_OUT + o.outLen];
        bytes memory r = bytes.concat(o.salt, out[0:PqzCt.CT], out[OUT_OFF:o.outLen], o.to);
        if (o.mode == ZetherTypes.TransferMode.BUNDLE) {
            s.entryPtr[ref] = SSTORE2.write(r);
        } else {
            s.entryHash[ref] = keccak256(r);
            s.memos[ref] = payload[payload.length - MEMO:];
        }
    }

    // ------------------------------------------------------------------ burn and refresh (§7.5)

    /// @notice `R_BURN`: the debit with `amount` public (0 = refresh); the token then pays `amount · shieldScale`.
    function unshield(
        Env memory e,
        bytes calldata payload,
        bytes calldata acc,
        bytes[] calldata inl,
        bytes calldata proof,
        bytes calldata authSig
    ) public {
        (Op memory o, bytes memory buf) = prepareBurn(e, payload, acc, inl, proof.length);
        _check(o, buf, proof, authSig);
        _settleBurn(o, payload[B_OUT:B_OUT + PqzCt.CT], inl);
    }

    function _settleBurn(Op memory o, bytes calldata out, bytes[] calldata inl) private {
        _debit(o, out[0:PqzCt.PK], out[PqzCt.PK:PqzCt.CT], inl);
        _sent(o);
        if (o.fee != 0) _plain(o.ben, o.fee);
        $().totalShielded -= o.amount;
        emit IPqzToken.PqzBurned(o.from, o.amount, o.recipient, out);
    }

    function prepareBurn(
        Env memory e,
        bytes calldata payload,
        bytes calldata acc,
        bytes[] calldata inl,
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
        buf = _burnBuffer(o, e, payload[B_OUT:B_OUT + PqzCt.CT], acc, inl, proofLen);
    }

    /// @dev `header ‖ pk_f ‖ T ‖ u' ‖ v_f` (50,048 B).
    function _burnBuffer(
        Op memory o,
        Env memory e,
        bytes calldata out,
        bytes calldata acc,
        bytes[] calldata inl,
        uint256 proofLen
    ) private view returns (bytes memory buf) {
        if (!PqzCt.isCanonical(out)) revert IPqzToken.NonCanonical();
        bytes memory t = _total(o, acc, inl);
        o.stLen = HEADER + PqzCt.PK + 2 * PqzCt.CT;
        buf = _buffer(2, o.stLen, proofLen);
        _header(buf, o, e);
        _key(buf, HEADER, o.keyF);
        _mem(buf, HEADER + PqzCt.PK, t);
        _cd(buf, HEADER + PqzCt.PK + PqzCt.CT, out);
    }

    // ------------------------------------------------------------------ rollover (§7.6)

    /// @notice Anyone: `acc += Σ cts` for the next `1 ≤ n ≤ 16` pending credits.
    function rollOver(bytes32 ua, bytes calldata acc, bytes[] calldata cts) public {
        Account storage a = $().acct[ua];
        uint256 n = cts.length;
        uint64 r = a.rolled;
        if (n == 0 || n > ROLL_MAX || r + n > a.pendingCount) revert IPqzToken.RollOverRange(n);
        if (acc.length != PqzCt.CT || keccak256(acc) != PqzCt.stored(a.accHash)) revert IPqzToken.AccMismatch();
        bytes memory c = PqzCt.load(acc);
        for (uint256 j; j < n; ++j) {
            if (cts[j].length != PqzCt.CT || keccak256(cts[j]) != a.pendingHash[uint64(r + j)]) {
                revert IPqzToken.InlineMismatch(j);
            }
            PqzCt.plus(c, cts[j]);
        }
        PqzCt.reduce(c);
        bytes32 h = keccak256(c);
        a.accHash = h;
        a.rolled = uint64(r + n);
        a.accUnits += uint16(n);
        emit IPqzToken.PqzRolled(ua, uint64(r + n), h);
    }

    // ------------------------------------------------------------------ disclosure (§7.9, P6g D11)

    /// @notice The 33,184-byte disclosure statement of `entryRef` for `kind` (0 `SENDER_S`, 1 `RECEIVER_X`, 2 `AUDITOR`)
    ///         in its precompile buffer; reverts on an unknown entry, a bundle that is not the stored one, `kind > 2`,
    ///         `AUDITOR` without `v_a`, `amount ≥ 2^64`.
    function disclosureBuffer(bytes32 ref, uint256 amount, uint8 kind, bytes memory bundle, Env memory e, uint256 proofLen)
        internal view returns (bytes memory buf)
    {
        bytes32 h = ciphertextHash(ref);
        if (h == 0) revert IPqzToken.UnknownEntry(ref);
        uint256 bl = bundle.length;
        if (keccak256(bundle) != h || kind > 2 || amount >= VALUE_BOUND || (kind == 2 && bl != BUNDLE_ON)) {
            revert IPqzToken.BadPayload(bl);
        }
        bytes32 owner;
        assembly ("memory-safe") { owner := mload(add(add(bundle, 32), sub(bl, 32))) }
        if (kind == 2) owner = $().auditorUA;
        buf = _buffer(kind == 0 ? 4 : 5, DISCLOSE, proofLen);
        _discHead(buf, ref, amount, kind, e);
        _key(buf, 288, _keyPtr(e.registry, owner));
        uint256 vOff = kind == 2 ? 16 + PqzCt.CT : 16 + PqzCt.PK;
        assembly ("memory-safe") {
            let d := add(add(buf, 37), 16672)
            mcopy(d, add(bundle, 48), 16384)
            mcopy(add(d, 16384), add(add(bundle, 32), vOff), 128)
        }
    }

    function _discHead(bytes memory buf, bytes32 ref, uint256 amount, uint8 kind, Env memory e) private view {
        bytes32 tag = kind == 0 ? OP_DS : kind == 1 ? OP_DR : OP_DA;
        _mem(buf, 0, abi.encode(tag, $().psid, block.chainid, e.chainUid, address(this), e.registry, ref, amount,
            uint256(kind)));
    }

    /// @notice `keccak256(R)` of the entry (stored hash, or the hash of the stored bundle), 0 if none.
    function ciphertextHash(bytes32 ref) internal view returns (bytes32 h) {
        PqzStorage storage s = $();
        h = s.entryHash[ref];
        if (h == 0 && s.entryPtr[ref] != address(0)) h = keccak256(SSTORE2.read(s.entryPtr[ref]));
    }

    /// @notice The precompile's verdict on a buffer with its proof already in place (views; disclosure).
    function verdict(address pqz, bytes memory buf) internal view returns (bool ok) {
        assembly ("memory-safe") {
            mstore(0, 0)
            let r := staticcall(gas(), pqz, add(buf, 32), mload(buf), 0, 0x20)
            ok := and(and(r, eq(returndatasize(), 0x20)), eq(mload(0), 1))
        }
    }

    // ------------------------------------------------------------------ shared steps

    /// @dev Words 0–2 of both payloads and the sender (`fromUA` at 96).
    function _head(Op memory o, bytes calldata payload) private pure {
        uint256 p = uint256(bytes32(payload[0:32]));
        if (p > type(uint64).max) revert IPqzToken.BadPayload(payload.length);
        o.p = uint64(p);
        o.validUntil = uint256(bytes32(payload[32:64]));
        o.plainUsed = uint256(bytes32(payload[64:96]));
        o.from = bytes32(payload[96:128]);
    }

    /// @dev Expiry, the sender registered (its key), the beneficiary registered or 0 and the fee, the counter.
    function _common(Op memory o, Env memory e) private view {
        PqzStorage storage s = $();
        if (block.number > o.validUntil) revert IPqzToken.Expired(o.validUntil);
        o.registry = e.registry;
        o.chainUid = e.chainUid;
        o.keyF = _keyPtr(e.registry, o.from);
        if (o.ben != 0) {
            if (!_registered(e.registry, o.ben)) revert IPqzToken.AccountNotRegistered(o.ben);
            o.fee = s.confidentialFee;
        }
        o.sendCounter = s.acct[o.from].sendCounter;
    }

    /// @dev `T = acc ± Σ inline + Trivial(plainUsed)` after every state check of §7.4 on `acc`, `p` and `inline`.
    function _total(Op memory o, bytes calldata acc, bytes[] calldata inl) private view returns (bytes memory t) {
        Account storage a = $().acct[o.from];
        if (o.plainUsed > a.plainPending) revert IPqzToken.PlainOverdraw(o.plainUsed, a.plainPending);
        if (acc.length != PqzCt.CT || keccak256(acc) != PqzCt.stored(a.accHash)) revert IPqzToken.AccMismatch();
        uint64 r = a.rolled;
        uint64 p = o.p;
        if (p < a.floor || p > a.pendingCount) revert IPqzToken.PendingRange(p, a.floor, a.pendingCount);
        bool up = p >= r;
        uint256 n = up ? p - r : r - p;
        if (n > INLINE_MAX) revert IPqzToken.InlineTooFar(n);
        if (inl.length != n) revert IPqzToken.InlineMismatch(inl.length);
        uint256 lo = up ? r : p;
        t = PqzCt.load(acc);
        for (uint256 i; i < n; ++i) {
            if (inl[i].length != PqzCt.CT || keccak256(inl[i]) != a.pendingHash[uint64(lo + i)]) {
                revert IPqzToken.InlineMismatch(i);
            }
            if (up) PqzCt.plus(t, inl[i]);
            else PqzCt.minus(t, inl[i]);
        }
        PqzCt.addTrivial(t, o.plainUsed);
        PqzCt.reduce(t);
        // unitsOf(T) = accUnits + (p − rolled) + 1, signed
        uint256 units = uint256(a.accUnits) + 1;
        if (up) units += n;
        else if (units < n) revert IPqzToken.UnitsInvariant();
        else units -= n;
        if (units > K_MAX) revert IPqzToken.UnitsInvariant();
    }

    /// @dev The authority (registry, the `authRef`'s PQ signature over `authDigest`), then the proof.
    function _check(Op memory o, bytes memory buf, bytes calldata proof, bytes calldata authSig)
        private view
    {
        uint256 len = o.stLen;
        bytes32 h;
        assembly ("memory-safe") { h := keccak256(add(buf, 37), len) }
        bytes32 d = keccak256(abi.encodePacked("SCAAS-PQZ-AUTH-V1", h));
        try IUARegistry(o.registry).requireZetherAuthorized(o.from, d, authSig, true) {}
        catch (bytes memory err) {
            if (err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector) revert UAKinds.UAVerifyGas();
            revert IPqzToken.AuthRejected();
        }
        assembly ("memory-safe") {
            calldatacopy(add(add(buf, 37), len), proof.offset, proof.length)
        }
        if (!verdict($().pqz, buf)) revert IPqzToken.ProofRejected();
    }

    /// @dev §7.4 effects on the sender: the fresh `acc = (u, v_f)` (plus the credits a `p < rolled` debit keeps),
    ///      `floor = p`, up to `CLEAR_MAX` dead `pendingHash` slots deleted, `plainPending −= plainUsed`.
    function _debit(Op memory o, bytes calldata u, bytes calldata vF, bytes[] calldata inl) private {
        Account storage a = $().acct[o.from];
        uint64 r = a.rolled;
        uint64 p = o.p;
        bytes memory c = bytes.concat(u, vF);
        if (p < r) {
            for (uint256 i; i < inl.length; ++i) PqzCt.plus(c, inl[i]);
            PqzCt.reduce(c);
            a.accUnits = uint16(1 + r - p);
        } else {
            a.rolled = p;
            a.accUnits = 1;
        }
        a.accHash = keccak256(c);
        a.floor = p;
        uint64 c0 = a.cleared;
        uint64 end = c0 + CLEAR_MAX < p ? c0 + CLEAR_MAX : p;
        for (uint64 i = c0; i < end; ++i) delete a.pendingHash[i];
        a.cleared = end;
        a.plainPending -= o.plainUsed;
    }

    /// @dev `sendCounter++`; the debit's `entryRef` (counter before the increment).
    function _sent(Op memory o) private returns (bytes32) {
        $().acct[o.from].sendCounter = o.sendCounter + 1;
        return entryRefOf(o.chainUid, o.from, o.sendCounter);
    }

    function _plain(bytes32 ua, uint256 amount) private {
        PqzStorage storage s = $();
        uint256 v = s.acct[ua].plainPending + amount;
        s.acct[ua].plainPending = v;
        emit IPqzToken.PqzPlainCredit(ua, amount, v);
    }

    /// @notice `entryRef` (§7.4, §8.1).
    function entryRefOf(bytes32 chainUid, bytes32 from, uint64 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_ENTRY, block.chainid, chainUid, address(this), from, uint256(counter)));
    }

    function _registered(address registry, bytes32 ua) private view returns (bool) {
        return IUARegistry(registry).kindOf(ua) == UAKinds.PQZ_MLWE;
    }

    /// @dev The `pk` pointer of a registered `pqz-mlwe` UA (`AccountNotRegistered` otherwise).
    function _keyPtr(address registry, bytes32 ua) private view returns (address ptr) {
        (IUARegistry.Record memory r,) = IUARegistry(registry).recordOf(ua);
        if (r.kind != UAKinds.PQZ_MLWE || r.keyPtr.code.length != PqzCt.PK + 1) revert IPqzToken.AccountNotRegistered(ua);
        return r.keyPtr;
    }

    // ------------------------------------------------------------------ the buffer `u8(op) ‖ be32(len) ‖ stmt ‖ proof`

    function _buffer(uint8 op, uint256 stLen, uint256 proofLen) private pure returns (bytes memory buf) {
        buf = new bytes(5 + stLen + proofLen);
        assembly ("memory-safe") { mstore(add(buf, 32), or(shl(248, op), shl(216, stLen))) }
    }

    /// @dev The 20 header words (§7.7) at statement offset 0.
    function _header(bytes memory buf, Op memory o, Env memory e) private view {
        _mem(buf, 0, abi.encode(o.opTag, $().psid, block.chainid, address(this), e.registry, o.from, o.to, o.ben, o.fee,
            o.amount));
        _mem(buf, 320, abi.encode(o.recipient, uint256(o.sendCounter), uint256(o.p), o.validUntil, o.auditorOn,
            o.plainUsed, e.chainUid, e.binding, uint256(uint128(o.salt)), o.memoHash));
    }

    /// @dev Statement offset `off` (the buffer's 5-byte prefix skipped).
    function _mem(bytes memory buf, uint256 off, bytes memory x) private pure {
        assembly ("memory-safe") { mcopy(add(add(buf, 37), off), add(x, 32), mload(x)) }
    }

    function _cd(bytes memory buf, uint256 off, bytes calldata x) private pure {
        assembly ("memory-safe") { calldatacopy(add(add(buf, 37), off), x.offset, x.length) }
    }

    function _key(bytes memory buf, uint256 off, address ptr) private view {
        assembly ("memory-safe") { extcodecopy(ptr, add(add(buf, 37), off), 1, 16384) }
    }
}
