// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUniversalAccountRegistry} from "../registry/IUniversalAccountRegistry.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IZetherVerifier} from "./IZetherVerifier.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherSafety} from "./ZetherSafety.sol";

/// @title The confidential layer of the `*_ZETHER` kinds (CTR-ZTH-44, CTR-TOK-24), in the ERC-7201 namespace
///        `scaas.zether`: statements, verifier calls, account updates, roll-over, shield / unshield, disclosure entries.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** External library: the token keeps the ERC-20 side (it burns the
///         public units a shield takes and mints or pays out what an unshield gives) and the entry points
///         (`ZetherLayer`); the logic runs here by `DELEGATECALL`, so `address(this)` is the token. One implementation
///         for every curve: points are `bytes`, the group operations and the proofs go through the verifier chosen at
///         creation. The statement builders are `internal` so that `ZetherStatements` builds the very same bytes from
///         the token's views (CTR-ZTH-46). Byte layout: `docs/contracts/zether.md` §7, §11, §12.
library ZetherLib {
    /// @dev `acc`/`pending` as `bytes` points (`O` when never written); the counters of zether.md §6.
    struct Account {
        bytes accC;
        bytes accD;
        bytes pendC;
        bytes pendD;
        uint64 accSeq;
        uint64 pendingSeq;
        uint64 lastRolledPendingSeq;
        uint64 sendCounter;
        uint64 modeNonce;
        ZetherTypes.RollOverMode mode;
    }

    /// @custom:storage-location erc7201:scaas.zether
    struct ZetherStorage {
        IZetherVerifier verifier;
        uint256 shieldScale;
        uint256 maxShielded;
        uint256 confidentialFee;
        uint256 totalShielded;
        bytes auditorKey;
        bytes32 psid;
        uint256 p;
        mapping(ZetherTypes.UA => Account) acct;
        /// @dev `B_1 ‖ … ‖ B_M` (single format, BUNDLE); NONE writes nothing.
        mapping(bytes32 => bytes) entries;
        /// @dev HASH: `keccak256(B_1 ‖ … ‖ B_M)` in one slot (CTR-ZTH-38).
        mapping(bytes32 => bytes32) entryHashes;
    }

    /// @notice The token's immutables a call needs, and the statement's binding: `(ZTX_V1_DIRECT, 0)` for a direct
    ///         call, `(ZTX_V1_RELAYED, envelopeBinding)` inside `mtxExecute`, `(ZTX_V1_DIRECT, unwrapBinding)` for a direct
    ///         `zetherUnshieldUnwrap`.
    struct Env {
        address registry;
        bytes32 chainUid;
        bytes32 tag;
        bytes32 binding;
    }

    /// @notice Everything a statement needs besides the payload and the sender's account: from the token's storage
    ///         (`ctx`) or from its views (`ZetherStatements`).
    struct Ctx {
        IZetherVerifier ver;
        address registry;
        address token;
        bytes32 chainUid;
        bytes32 psid;
        uint256 p;
        uint256 fee;
        uint256 maxShielded;
        bytes auditorKey;
        bytes32 tag;
        bytes32 binding;
    }

    /// @notice The sender's part of a statement (points as stored, `O` when unset).
    struct Acct {
        bytes accC;
        bytes accD;
        uint64 accSeq;
        uint64 sendCounter;
    }

    /// @notice A checked statement, before verification.
    struct Prepared {
        ZetherTypes.UA from;
        ZetherTypes.UA beneficiary;
        bytes statement;
        uint256 fee;
        uint64 sendCounter;
        ZetherTypes.UA[] to; // multi-recipient only
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;

    bytes32 internal constant TAG_DIRECT = keccak256("ZTX_V1_DIRECT");
    bytes32 internal constant TAG_RELAYED = keccak256("ZTX_V1_RELAYED");
    bytes32 internal constant TAG_ENVELOPE = keccak256("SCAAS-ZETHER-ENVELOPE-V1");
    bytes32 internal constant TAG_UNWRAP = keccak256("SCAAS-ZETHER-UNWRAP-V1");
    bytes32 private constant OP_TRANSFER = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 private constant OP_BURN = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    bytes32 private constant OP_MULTI_HASH = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH");
    bytes32 private constant OP_MULTI_BUNDLE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE");
    bytes32 private constant OP_MULTI_NONE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/NONE");
    bytes32 private constant TAG_ENTRY = keccak256("SCAAS-ZETHER-ENTRY-V1");
    bytes32 private constant TAG_ROLLOVER = keccak256("ZETHER_ROLLOVER_V1");
    bytes32 private constant TAG_SET_MODE = keccak256("ZETHER_SET_ROLLOVER_MODE_V1");
    bytes private constant AUTH_TAG = "SCAAS-ZETHER-AUTH-V1";
    uint256 private constant MAX_RECIPIENTS = 16;
    uint256 private constant MAX_TOTAL_SHIELDED = 1 << 54;
    /// @dev `2^n_v` (n_v = 64, CTR-ZTH-18): the bound of `confidentialFee`.
    uint256 private constant VALUE_BOUND = 1 << 64;

    function $() internal pure returns (ZetherStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init

    /// @notice The kind's `_init` (dev chains only, CTR-ZTH-02): verifier, scale, cap `≤ 2^54`, inner fee `< 2^64` and
    ///         `< cap`, auditor key empty or a valid point `≠ O` of the verifier's curve; `cap · scale` must not overflow.
    function init(IFactoryToken.ConfidentialConfig calldata c) public {
        ZetherSafety.requireDevChain();
        IZetherVerifier v = IZetherVerifier(c.verifier);
        uint256 p = v.g1EncodedBytes();
        bytes calldata aud = c.auditorKey;
        if (c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > MAX_TOTAL_SHIELDED
            || c.confidentialFee >= VALUE_BOUND || c.confidentialFee >= c.maxShielded
            || (aud.length != 0 && (aud.length != p || !v.isValidPoint(aud) || _isO(aud)))) {
            revert IZetherToken.BadInit();
        }
        if (c.maxShielded > type(uint256).max / c.shieldScale) revert IZetherToken.BadInit();
        ZetherStorage storage s = $();
        s.verifier = v;
        s.shieldScale = c.shieldScale;
        s.maxShielded = c.maxShielded;
        s.confidentialFee = c.confidentialFee;
        s.auditorKey = aud;
        s.psid = v.proofSystemId();
        s.p = p;
    }

    // ------------------------------------------------------------------ shield

    /// @notice `pending[ua] += [amount]G` and `totalShielded += amount` within the cap. The token takes the public units
    ///         (`zetherShield`) or the underlying (`zetherWrapShield`); the minter never mints shielded value.
    function shield(ZetherTypes.UA ua, uint256 amount, address registry) public {
        ZetherStorage storage s = $();
        if (IUniversalAccountRegistry(registry).keyLengthOf(ua) != s.p) revert IZetherToken.AccountNotRegistered(ua);
        uint256 room = s.maxShielded - s.totalShielded;
        if (amount == 0 || amount > room) revert IZetherToken.AmountOutOfRange(amount, room);
        s.totalShielded += amount;
        _credit(s, ua, s.verifier.g1MulBase(amount), "");
        emit IZetherToken.ZetherShielded(ua, amount);
    }

    // ------------------------------------------------------------------ transfer

    /// @notice The single-recipient format: checks, authority, proof, then `acc_f −= (C_deb + [fee]G, D_out)`,
    ///         `pend_t += (C_out, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++`; the bundle stored in full.
    function transferSingle(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        Env memory e
    ) public returns (bytes32) {
        (Ctx memory c, Prepared memory pp) = _prepareSingle(payload, beneficiary, e);
        _check(c, pp, authSig, proof, OP_TRANSFER);
        return _settleSingle(c, pp, payload);
    }

    function _prepareSingle(bytes calldata payload, ZetherTypes.UA beneficiary, Env memory e)
        private view returns (Ctx memory c, Prepared memory pp)
    {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareSingle(c, acct(s.acct[singleFrom(payload, c.p)], c.p), payload, beneficiary);
    }

    function _settleSingle(Ctx memory c, Prepared memory pp, bytes calldata payload) private returns (bytes32 entryRef) {
        ZetherStorage storage s = $();
        bytes calldata pts = payload[64:];
        uint256 p = c.p;
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        _debit(c, s.acct[pp.from], pts[4 * p:5 * p], pts[3 * p:4 * p], pp.fee);
        _credit(s, to, pts[2 * p:3 * p], pts[3 * p:4 * p]);
        _payFee(s, c, pp);
        entryRef = _sent(s, c, pp);
        s.entries[entryRef] = bytes.concat(pts[p:2 * p], pts[2 * p:4 * p], pts[5 * p:6 * p]);
        emit IZetherToken.ZetherTransfer(pp.from, to, pp.beneficiary, pp.fee, pp.sendCounter, entryRef);
    }

    /// @notice `M` recipients, one proof (CTR-ZTH-37/38): `acc_f −= (C_deb + [fee]G, D_out)`, every
    ///         `pend_tj += (C_out_j, D_out)`, `pend_ben += [fee]G`, `sendCounter_f++` once; the bundles by `mode`.
    function transferMulti(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode,
        Env memory e
    ) public returns (bytes32) {
        (Ctx memory c, Prepared memory pp) = _prepareMulti(payload, beneficiary, mode, e);
        _check(c, pp, authSig, proof, OP_MULTI_HASH);
        return _settleMulti(c, pp, payload, mode);
    }

    function _prepareMulti(bytes calldata payload, ZetherTypes.UA beneficiary, ZetherTypes.TransferMode mode, Env memory e)
        private view returns (Ctx memory c, Prepared memory pp)
    {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareMulti(c, acct(s.acct[multiFrom(payload, c.p)], c.p), payload, beneficiary, mode);
    }

    function _settleMulti(Ctx memory c, Prepared memory pp, bytes calldata payload, ZetherTypes.TransferMode mode)
        private returns (bytes32 entryRef)
    {
        ZetherStorage storage s = $();
        uint256 p = c.p;
        _debit(c, s.acct[pp.from], payload[96 + 2 * p:96 + 3 * p], payload[96 + p:96 + 2 * p], pp.fee);
        _creditLegs(s, pp.to, payload, p);
        _payFee(s, c, pp);
        entryRef = _sent(s, c, pp);
        if (mode != ZetherTypes.TransferMode.NONE) _storeBundles(s, p, entryRef, payload, pp.to.length, mode);
        emit IZetherToken.ZetherTransferMulti(pp.from, pp.beneficiary, pp.fee, pp.sendCounter, entryRef, pp.to, mode);
    }

    /// @dev Every `pend_tj += (C_out_j, D_out)`, decoys included.
    function _creditLegs(ZetherStorage storage s, ZetherTypes.UA[] memory to, bytes calldata payload, uint256 p) private {
        bytes calldata dOut = payload[96 + p:96 + 2 * p];
        for (uint256 j; j < to.length; ++j) {
            uint256 o = 96 + 3 * p * (j + 1);
            _credit(s, to[j], payload[o + p:o + 2 * p], dOut);
        }
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement (zether.md §8.2, built name `burn`): checks, authority, proof, then
    ///         `acc_f.C −= [amount + fee]G`, `pend_ben += [fee]G`, `sendCounter_f++`, `totalShielded −= amount`. The token
    ///         then pays `amount · shieldScale` public-equivalent units to `recipient` (mint or a leg's underlying).
    function unshield(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata authSig,
        ZetherTypes.UA beneficiary,
        uint256 amount,
        address recipient,
        Env memory e
    ) public {
        (Ctx memory c, Prepared memory pp) = _prepareUnshield(payload, amount, recipient, beneficiary, e);
        _check(c, pp, authSig, proof, OP_BURN);
        ZetherStorage storage s = $();
        Account storage a = s.acct[pp.from];
        a.accC = c.ver.g1Sub(_pt(a.accC, c.p), c.ver.g1MulBase(amount + pp.fee));
        _sent(s, c, pp);
        s.totalShielded -= amount;
        _payFee(s, c, pp);
        emit IZetherToken.ZetherUnshielded(pp.from, amount, recipient);
    }

    function _prepareUnshield(
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary,
        Env memory e
    ) private view returns (Ctx memory c, Prepared memory pp) {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareUnshield(c, acct(s.acct[unshieldFrom(payload, c.p)], c.p), payload, amount, recipient, beneficiary);
    }

    // ------------------------------------------------------------------ roll-over (zether.md §6)

    /// @notice `PUBLIC` accounts only; a silent no-op without a new credit (anti-DoS).
    function rollOver(ZetherTypes.UA ua) public {
        ZetherStorage storage s = $();
        if (s.acct[ua].mode == ZetherTypes.RollOverMode.OWNER_ONLY) revert IZetherToken.RollOverOwnerOnly(ua);
        _rollOver(s, ua);
    }

    /// @notice Skips `OWNER_ONLY` items, never reverts the batch for them.
    function rollOverBatch(ZetherTypes.UA[] calldata uas) public {
        ZetherStorage storage s = $();
        for (uint256 i; i < uas.length; ++i) {
            if (s.acct[uas[i]].mode == ZetherTypes.RollOverMode.PUBLIC) _rollOver(s, uas[i]);
        }
    }

    /// @notice CTR-ZTH-16/17: `lastRolledPendingSeq < expectedPendingSeq ≤ pendingSeq`, signed by the account's
    ///         authority over `ZETHER_ROLLOVER_V1` with `chainid`, `chainUid`, the token and `accSeq`.
    function rollOverSigned(
        ZetherTypes.UA ua,
        uint64 expectedPendingSeq,
        uint64 validUntilBlock,
        bytes calldata sig,
        Env memory e
    ) public {
        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);
        ZetherStorage storage s = $();
        Account storage a = s.acct[ua];
        if (a.pendingSeq < expectedPendingSeq || expectedPendingSeq <= a.lastRolledPendingSeq) {
            revert IZetherToken.PendingSeqMismatch(expectedPendingSeq, a.pendingSeq);
        }
        bytes32 digest = keccak256(abi.encode(
            TAG_ROLLOVER, block.chainid, e.chainUid, address(this), ua, a.accSeq, expectedPendingSeq, validUntilBlock
        ));
        IUniversalAccountRegistry(e.registry).requireAuthorized(ua, digest, sig, false);
        _rollOver(s, ua);
    }

    /// @notice `ZETHER_SET_ROLLOVER_MODE_V1` with `chainid`, `chainUid`, the token and `modeNonce` (no replay).
    function setRollOverMode(
        ZetherTypes.UA ua,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig,
        Env memory e
    ) public {
        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);
        Account storage a = $().acct[ua];
        bytes32 digest = keccak256(abi.encode(
            TAG_SET_MODE, block.chainid, e.chainUid, address(this), ua, uint8(mode), a.modeNonce, validUntilBlock
        ));
        IUniversalAccountRegistry(e.registry).requireAuthorized(ua, digest, sig, false);
        a.mode = mode;
        a.modeNonce += 1;
        emit IZetherToken.RollOverModeChanged(ua, mode);
    }

    // ------------------------------------------------------------------ statements (shared with ZetherStatements)

    /// @notice The statement context of the token itself (`address(this)` under `DELEGATECALL`).
    function ctx(ZetherStorage storage s, Env memory e) internal view returns (Ctx memory c) {
        c.ver = s.verifier;
        c.registry = e.registry;
        c.token = address(this);
        c.chainUid = e.chainUid;
        c.psid = s.psid;
        c.p = s.p;
        c.fee = s.confidentialFee;
        c.maxShielded = s.maxShielded;
        c.auditorKey = s.auditorKey;
        c.tag = e.tag;
        c.binding = e.binding;
    }

    function acct(Account storage a, uint256 p) internal view returns (Acct memory) {
        return Acct(_pt(a.accC, p), _pt(a.accD, p), a.accSeq, a.sendCounter);
    }

    /// @notice `ZTX_V1_RELAYED` for a non-zero envelope binding, else `ZTX_V1_DIRECT`.
    function tagOf(bytes32 binding) internal pure returns (bytes32) {
        return binding == bytes32(0) ? TAG_DIRECT : TAG_RELAYED;
    }

    /// @notice The binding word of a direct `zetherUnshieldUnwrap`: its leg and `minOut` (controller ruling, pending
    ///         the owner), so a proof lifted from a pending call cannot pick another leg, drop `minOut` or go through
    ///         `zetherUnshield` instead.
    function unwrapBinding(address u, uint256 minOut) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_UNWRAP, u, minOut));
    }

    /// @notice `entryRef` (zether.md §12) with `chainUid` (CTR-ZTH-36); `sendCounter` before the increment.
    function entryRefOf(Ctx memory c, ZetherTypes.UA from, uint64 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_ENTRY, block.chainid, c.chainUid, c.token, from, uint256(counter)));
    }

    /// @notice Single format: `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f ‖ Y_t ‖ C_out ‖ D_out ‖ C_deb ‖ C_aud`.
    function singleFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length != 64 + 6 * p) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[64:64 + p]);
    }

    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ be32(M) ‖ Y_f ‖ D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j)_j`.
    function multiFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length < 96 + 3 * p) revert IZetherToken.BadPayload(payload.length);
        uint256 m = uint256(bytes32(payload[64:96]));
        if (m == 0 || m > MAX_RECIPIENTS) revert IZetherToken.BadRecipientCount(m);
        if (payload.length != 96 + 3 * p * (1 + m)) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[96:96 + p]);
    }

    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ Y_f`.
    function unshieldFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length != 64 + p) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[64:64 + p]);
    }

    /// @notice Every cheap check before verification: self, registration, fee, `accSeq`, `sendCounter`.
    function prepareSingle(Ctx memory c, Acct memory a, bytes calldata payload, ZetherTypes.UA beneficiary)
        internal view returns (Prepared memory pp)
    {
        uint256 p = c.p;
        bytes calldata pts = payload[64:];
        pp.from = ZetherTypes.toUA(pts[0:p]);
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        if (ZetherTypes.UA.unwrap(pp.from) == ZetherTypes.UA.unwrap(to)) revert IZetherToken.SelfTransfer();
        _requireRegistered(c, pp.from);
        _requireRegistered(c, to);
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = bytes.concat(
            _header(c, OP_TRANSFER, c.psid, a, pp.fee, beneficiary, 0, address(0)),
            pts[0:2 * p], _auditorPoint(c, _isO(pts[5 * p:6 * p]) ? 1 : 0, 1), a.accC, a.accD, pts[2 * p:6 * p]
        );
    }

    /// @notice As `prepareSingle`, for `M` recipients: pairwise distinct, none the sender, all registered.
    function prepareMulti(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode
    ) internal view returns (Prepared memory pp) {
        uint256 p = c.p;
        pp.from = ZetherTypes.toUA(payload[96:96 + p]);
        _requireRegistered(c, pp.from);
        pp.to = _recipients(c, payload, pp.from, uint256(bytes32(payload[64:96])));
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = _multiStatement(c, a, payload, pp.fee, beneficiary, mode);
    }

    /// @notice `0 < amount ≤ maxShielded` before the statement (`amount + fee < 2^65 < r`), recipient non-zero.
    function prepareUnshield(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        uint256 amount,
        address recipient,
        ZetherTypes.UA beneficiary
    ) internal view returns (Prepared memory pp) {
        if (amount == 0 || amount > c.maxShielded) revert IZetherToken.AmountOutOfRange(amount, c.maxShielded);
        if (recipient == address(0)) revert IZetherToken.ZeroRecipient();
        uint256 p = c.p;
        pp.from = ZetherTypes.toUA(payload[64:64 + p]);
        _requireRegistered(c, pp.from);
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        pp.sendCounter = _checkSeqs(a, payload);
        pp.statement = bytes.concat(
            _header(c, OP_BURN, c.psid, a, pp.fee, beneficiary, amount, recipient), payload[64:64 + p], a.accC, a.accD
        );
    }

    // ------------------------------------------------------------------ internals

    /// @dev The 416-byte header (zether.md §7), `chainUid` at word 3.
    function _header(
        Ctx memory c,
        bytes32 op,
        bytes32 psid,
        Acct memory a,
        uint256 fee,
        ZetherTypes.UA beneficiary,
        uint256 amount,
        address recipient
    ) private view returns (bytes memory) {
        return bytes.concat(
            abi.encode(op, psid, block.chainid, c.chainUid, c.token, c.tag, c.binding),
            abi.encode(uint256(a.sendCounter), uint256(a.accSeq), fee, beneficiary, amount, recipient)
        );
    }

    /// @dev `header ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ legs`; the mode is in `opTag`.
    function _multiStatement(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        uint256 fee,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode
    ) private view returns (bytes memory) {
        uint256 p = c.p;
        bytes32 op = mode == ZetherTypes.TransferMode.HASH
            ? OP_MULTI_HASH
            : mode == ZetherTypes.TransferMode.BUNDLE ? OP_MULTI_BUNDLE : OP_MULTI_NONE;
        bytes memory head = bytes.concat(
            _header(c, op, c.ver.proofSystemIdMulti(), a, fee, beneficiary, 0, address(0)),
            payload[96:96 + p], _auditorPoint(c, _audOff(payload, p), uint256(bytes32(payload[64:96]))), a.accC, a.accD
        );
        return bytes.concat(head, payload[96 + p:96 + 3 * p], payload[64:96], payload[96 + 3 * p:]);
    }

    /// @dev The recipients: none the sender, pairwise distinct, registered.
    function _recipients(Ctx memory c, bytes calldata payload, ZetherTypes.UA from, uint256 m)
        private view returns (ZetherTypes.UA[] memory to)
    {
        uint256 p = c.p;
        to = new ZetherTypes.UA[](m);
        for (uint256 j; j < m; ++j) {
            uint256 o = 96 + 3 * p * (j + 1);
            to[j] = ZetherTypes.toUA(payload[o:o + p]);
            bytes32 t = ZetherTypes.UA.unwrap(to[j]);
            if (t == ZetherTypes.UA.unwrap(from)) revert IZetherToken.SelfTransfer();
            for (uint256 k; k < j; ++k) if (ZetherTypes.UA.unwrap(to[k]) == t) revert IZetherToken.DuplicateRecipient(to[j]);
            _requireRegistered(c, to[j]);
        }
    }

    function _checkSeqs(Acct memory a, bytes calldata payload) private pure returns (uint64) {
        uint256 provedAccSeq = uint256(bytes32(payload[0:32]));
        uint256 provedSend = uint256(bytes32(payload[32:64]));
        if (provedAccSeq != a.accSeq) revert IZetherToken.StaleAccSeq(a.accSeq, provedAccSeq);
        if (provedSend != a.sendCounter) revert IZetherToken.StaleSendCounter(a.sendCounter, provedSend);
        return a.sendCounter;
    }

    /// @dev `confidentialFee` when a beneficiary is named; the fee is no back door to register on someone's behalf.
    function _innerFee(Ctx memory c, ZetherTypes.UA beneficiary) private view returns (uint256) {
        if (ZetherTypes.UA.unwrap(beneficiary) == bytes32(0)) return 0;
        _requireRegistered(c, beneficiary);
        return c.fee;
    }

    /// @dev Registered on the verifier's curve.
    function _requireRegistered(Ctx memory c, ZetherTypes.UA ua) private view {
        if (IUniversalAccountRegistry(c.registry).keyLengthOf(ua) != c.p) revert IZetherToken.AccountNotRegistered(ua);
    }

    /// @dev The account's spending authority over the statement (registry), then the proof (knowledge of `x`).
    function _check(Ctx memory c, Prepared memory pp, bytes calldata authSig, bytes calldata proof, bytes32 op) private view {
        IUniversalAccountRegistry(c.registry).requireAuthorized(
            pp.from, keccak256(abi.encodePacked(AUTH_TAG, keccak256(pp.statement))), authSig, true
        );
        bool ok = op == OP_TRANSFER
            ? c.ver.verifyTransfer(pp.statement, proof)
            : op == OP_BURN ? c.ver.verifyBurn(pp.statement, proof) : c.ver.verifyTransferMulti(pp.statement, proof);
        if (!ok) revert IZetherToken.ProofRejected();
    }

    /// @dev The inner fee: `[fee]G` into the beneficiary's `pending` (a public scalar, CTR-ZTH-05).
    function _payFee(ZetherStorage storage s, Ctx memory c, Prepared memory pp) private {
        if (pp.fee != 0) _credit(s, pp.beneficiary, c.ver.g1MulBase(pp.fee), "");
    }

    /// @dev `sendCounter_f++` once; the `entryRef` of this debit (with the counter before the increment).
    function _sent(ZetherStorage storage s, Ctx memory c, Prepared memory pp) private returns (bytes32) {
        s.acct[pp.from].sendCounter = pp.sendCounter + 1;
        return entryRefOf(c, pp.from, pp.sendCounter);
    }

    /// @dev `acc_f −= (C_deb + [fee]G, D_out)`.
    function _debit(Ctx memory c, Account storage a, bytes calldata cDeb, bytes calldata dOut, uint256 fee) private {
        bytes memory cc = c.ver.g1Sub(_pt(a.accC, c.p), cDeb);
        if (fee != 0) cc = c.ver.g1Sub(cc, c.ver.g1MulBase(fee));
        a.accC = cc;
        a.accD = c.ver.g1Sub(_pt(a.accD, c.p), dOut);
    }

    function _credit(ZetherStorage storage s, ZetherTypes.UA ua, bytes memory cPt, bytes memory dPt) private {
        Account storage a = s.acct[ua];
        uint256 p = s.p;
        a.pendC = s.verifier.g1Add(_pt(a.pendC, p), cPt);
        if (dPt.length != 0) a.pendD = s.verifier.g1Add(_pt(a.pendD, p), dPt);
        a.pendingSeq += 1;
    }

    /// @dev `acc += pending; pending = O; accSeq++`, only with a new credit. Never called by a transfer or an unshield.
    function _rollOver(ZetherStorage storage s, ZetherTypes.UA ua) private {
        Account storage a = s.acct[ua];
        if (a.pendingSeq == a.lastRolledPendingSeq) return;
        uint256 p = s.p;
        a.accC = s.verifier.g1Add(_pt(a.accC, p), _pt(a.pendC, p));
        a.accD = s.verifier.g1Add(_pt(a.accD, p), _pt(a.pendD, p));
        delete a.pendC;
        delete a.pendD;
        a.accSeq += 1;
        a.lastRolledPendingSeq = a.pendingSeq;
        emit IZetherToken.RolledOver(ua, a.accSeq);
    }

    function _storeBundles(
        ZetherStorage storage s,
        uint256 p,
        bytes32 entryRef,
        bytes calldata payload,
        uint256 m,
        ZetherTypes.TransferMode mode
    ) private {
        bytes memory bundles = _bundles(payload[96 + 3 * p:], payload[96 + p:96 + 2 * p], m, p);
        if (mode == ZetherTypes.TransferMode.BUNDLE) {
            s.entries[entryRef] = bundles;
        } else {
            s.entryHashes[entryRef] = keccak256(bundles);
            emit IZetherToken.TransferBundles(entryRef, bundles);
        }
    }

    /// @dev `B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j`.
    function _bundles(bytes calldata legs, bytes calldata dOut, uint256 m, uint256 p) private pure returns (bytes memory b) {
        for (uint256 j; j < m; ++j) {
            uint256 o = 3 * p * j;
            b = bytes.concat(b, legs[o:o + 2 * p], dOut, legs[o + 2 * p:o + 3 * p]);
        }
    }

    /// @dev `Y_a` of the statement (CTR-ZTH-42): the key when every `C_aud_j ≠ O`, `O` when every one is `O` or the
    ///      token has no auditor (the verifier then requires every `C_aud_j = O`); a mix reverts.
    function _auditorPoint(Ctx memory c, uint256 nOff, uint256 m) private pure returns (bytes memory) {
        if (c.auditorKey.length == 0 || nOff == m) return new bytes(c.p);
        if (nOff != 0) revert IZetherToken.AuditorLegsMixed();
        return c.auditorKey;
    }

    /// @dev Number of legs with `C_aud_j = O`.
    function _audOff(bytes calldata payload, uint256 p) private pure returns (uint256 n) {
        for (uint256 o = 96 + 6 * p; o <= payload.length; o += 3 * p) if (_isO(payload[o - p:o])) ++n;
    }

    /// @dev The stored point, or `O` when never written.
    function _pt(bytes storage b, uint256 p) internal view returns (bytes memory) {
        return b.length == 0 ? new bytes(p) : b;
    }

    function _isO(bytes memory a) internal pure returns (bool) {
        return keccak256(a) == keccak256(new bytes(a.length));
    }
}
