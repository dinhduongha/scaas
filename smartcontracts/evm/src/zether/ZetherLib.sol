// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../confidential/IConfidentialToken.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "./IZetherVerifier.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title The confidential layer of the `*_ZETHER` kinds (CTR-ZTH-44, CTR-TOK-24), in the ERC-7201 namespace
///        `scaas.zether`: statements, verifier calls, account updates, roll-over, shield / unshield, disclosure entries.
/// @notice **UNAUDITED.** External library: the token keeps the ERC-20 side (it moves the
///         public units a shield takes into `SHIELD_POOL` and pays out of it what an unshield gives; D19) and the entry points
///         (`ZetherLayer`); the logic runs here by `DELEGATECALL`, so `address(this)` is the token. One implementation
///         for every curve: points are `bytes`, the group operations and the proofs go through the release's verifier
///         immutables. The statement builders are `internal` so that `ZetherStatements` builds the very same bytes from
///         the token's views (CTR-ZTH-46), all from the explicit parameters (TS-D17): a point's `abi.encode` is its 128
///         bytes, so the statement and the stored record are what the packed payload gave. Byte layout:
///         `docs/contracts/zether.md` §7, §11, §12.
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
        /// @dev Both modes share the verifier's slot (the offsets of the fields below are unchanged).
        ZetherTypes.DisclosureMode disclosureMode;
        ZetherTypes.AuditorMode auditorMode;
        uint256 shieldScale;
        uint256 maxShielded;
        uint256 confidentialFee;
        uint256 totalShielded;
        bytes auditorKey;
        bytes32 psid;
        uint256 p;
        mapping(ZetherTypes.UA => Account) acct;
        /// @dev The record `R = salt ‖ B_1 ‖ … ‖ B_M` (BUNDLE, the single format), inline in state.
        mapping(bytes32 => bytes) entries;
        /// @dev Commit-reveal (HASH): the SSTORE2 pointer of `R` (CTR-ZTH-38, review C0-3: the ciphertext stays in state).
        mapping(bytes32 => address) entryPtrs;
        /// @dev Next to every commitment: the sender memo (CTR-ZTH-50), as given.
        mapping(bytes32 => bytes) memos;
        /// @dev The least per-leg `decoyFee` of a multi-recipient transfer (owner 2026-10-20), immutable.
        uint256 minDecoyFee;
    }

    /// @notice The token's immutables a call needs, and the statement's binding: `(ZTX_V1_DIRECT, 0)` for a direct
    ///         call, `(ZTX_V1_RELAYED, envelopeBinding)` inside `mtxExecute` / `uaExecute` (the UA envelope's binding,
    ///         CTR-ZTH-51), `(ZTX_V1_DIRECT, unwrapBinding)` for a direct `mtxUnshieldUnwrap`.
    struct Env {
        address registry;
        bytes32 chainUid;
        bytes32 tag;
        bytes32 binding;
        /// @dev The implementation's burn verifier (CTR-ZTH-20): the unshield proofs. The transfer verifier is copied to
        ///      storage at `init` (shield and roll-over use its group operations without an `Env`).
        IZetherBurnVerifier burnVer;
        /// @dev The token's EIP-712 domain: the owner digests (TS-D19) are typed under it.
        bytes32 domainSeparator;
    }

    /// @notice Everything a statement needs besides the explicit parameters and the sender's account: from the token's storage
    ///         (`ctx`) or from its views (`ZetherStatements`).
    struct Ctx {
        IZetherVerifier ver;
        address registry;
        address token;
        bytes32 chainUid;
        bytes32 psid;
        uint256 p;
        uint256 fee;
        uint256 minDecoyFee;
        uint256 maxShielded;
        bytes auditorKey;
        ZetherTypes.AuditorMode auditorMode;
        ZetherTypes.DisclosureMode disclosureMode;
        bytes32 tag;
        bytes32 binding;
        /// @dev `Env.burnVer` (unshield only; `ZetherStatements` leaves it 0).
        IZetherBurnVerifier burnVer;
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
        /// @dev The statement's public fee word: the inner fee (when a beneficiary is named), plus `M · decoyFee` on the
        ///      multi-recipient format.
        uint256 fee;
        /// @dev Multi-recipient only: the sender's per-leg `decoyFee`.
        uint256 decoyFee;
        uint64 sendCounter;
        /// @dev The salt (CTR-ZTH-30, header word 13) and, on commit-reveal, `keccak256(memo)` (CTR-ZTH-50, header word
        ///      14); both 0 for an unshield.
        bytes16 salt;
        bytes32 memoHash;
        /// @dev `validUntilBlock` (header word 15, review C0-9): checked `block.number <=` it.
        uint256 validUntil;
        ZetherTypes.UA[] to; // multi-recipient only
    }

    /// @notice What a multi-recipient debit moved out of `totalShielded` besides the transfers: `txFee` (the beneficiary's)
    ///         and `decoyFee` for each of `legs`; the layer pays exactly that from `SHIELD_POOL` (as `PqzCore.Paid`).
    struct Paid {
        uint256 txFee;
        uint256 decoyFee;
        ZetherTypes.UA[] legs;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.zether")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00;

    bytes32 internal constant TAG_DIRECT = keccak256("ZTX_V1_DIRECT");
    bytes32 internal constant TAG_RELAYED = keccak256("ZTX_V1_RELAYED");
    bytes32 internal constant TAG_ENVELOPE = keccak256("SCAAS-ZETHER-ENVELOPE-V1");
    bytes32 internal constant TAG_UA_ENVELOPE = keccak256("SCAAS-ZETHER-UA-ENVELOPE-V1");
    bytes32 internal constant TAG_UNWRAP = keccak256("SCAAS-ZETHER-UNWRAP-V1");
    bytes32 private constant OP_TRANSFER = keccak256("SCAAS-ZETHER-OP-TRANSFER-V1");
    bytes32 private constant OP_BURN = keccak256("SCAAS-ZETHER-OP-BURN-V1");
    bytes32 private constant OP_MULTI_HASH = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH");
    bytes32 private constant OP_MULTI_BUNDLE = keccak256("SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE");
    bytes32 private constant TAG_ENTRY = keccak256("SCAAS-ZETHER-ENTRY-V1");
    /// @dev The typed owner ops (TS-D19), and the structs of the signed entries' explicit parameters (Appendix X.4).
    bytes32 private constant TH_ROLL_OVER = keccak256("ZetherRollOver(bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock)");
    bytes32 private constant TH_SET_MODE = keccak256("ZetherSetRollOverMode(bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock)");
    bytes32 private constant TH_G1 = keccak256("G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)");
    bytes32 private constant TH_SINGLE = keccak256(
        "ZetherSingle(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)"
    );
    bytes32 private constant TH_LEG = keccak256("ZetherLeg(G1 yTo,G1 cOut,G1 cAud,G1 dAud)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)");
    bytes32 private constant TH_MULTI = keccak256(
        "ZetherMulti(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)ZetherLeg(G1 yTo,G1 cOut,G1 cAud,G1 dAud)"
    );
    bytes32 private constant TH_BURN = keccak256(
        "ZetherBurn(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom)G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)"
    );
    bytes32 private constant TH_UNWRAP = keccak256("Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)");
    /// @dev The statement format's maximum, not a gas bound: under EIP-7825's 2^24 regular gas only `M` ≤ 6–8 (by form)
    ///      executes (zether.md §19); the chain refuses the rest and the prover takes 6–8 by form.
    uint256 private constant MAX_RECIPIENTS = 16;
    uint256 private constant MAX_TOTAL_SHIELDED = 1 << 54;
    /// @dev `2^n_v` (n_v = 64, CTR-ZTH-18): the bound of `confidentialFee`.
    uint256 private constant VALUE_BOUND = 1 << 64;

    function $() internal pure returns (ZetherStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init

    /// @notice The kind's `_init` (every chain, CTR-ZTH-02 superseded 2026-10-31): `v` the release's transfer verifier (CTR-ZTH-20, running
    ///         on this chain: `VerifierUnsupportedOnThisChain`), scale, cap `≤ 2^54`, inner fee `< 2^64` and `< cap`,
    ///         `minDecoyFee < 2^64` with `confidentialFee + 16 · minDecoyFee` `< 2^64` and `< cap` (16 legs at most; no
    ///         chain-level floor, owner 2026-10-20),
    ///         auditor key empty or a valid point `≠ O` of the verifier's curve; `cap · scale` must not overflow;
    ///         `disclosureMode` BUNDLE or COMPACT (CTR-ZTH-48), `auditorMode` NONE without a key, FULL or OPTIONAL with
    ///         one (CTR-ZTH-49).
    function init(IFactoryToken.ConfidentialConfig memory c, IZetherVerifier v) public {
        // the release's verifier must run here (an absent precompile answers success with empty output; moved from the
        // factory's creation gate, plan 5g-Z2)
        (bool ok, bytes memory r) = address(v).staticcall(abi.encodeCall(v.isSupportedOnThisChain, ()));
        if (!ok || r.length != 32 || abi.decode(r, (uint256)) != 1) {
            string memory curve;
            try v.curveName() returns (string memory n) { curve = n; } catch {} // keep the typed error (review M-1)
            revert IZetherToken.VerifierUnsupportedOnThisChain(address(v), curve);
        }
        uint256 p = v.g1EncodedBytes();
        bytes memory aud = c.auditorKey;
        if (c.shieldScale == 0 || c.maxShielded == 0 || c.maxShielded > MAX_TOTAL_SHIELDED
            || c.confidentialFee >= VALUE_BOUND || c.confidentialFee >= c.maxShielded || c.minDecoyFee >= VALUE_BOUND
            || c.confidentialFee + MAX_RECIPIENTS * c.minDecoyFee >= VALUE_BOUND
            || c.confidentialFee + MAX_RECIPIENTS * c.minDecoyFee >= c.maxShielded
            || (aud.length != 0 && (aud.length != p || !v.isValidPoint(aud) || _isO(aud)))) {
            revert IZetherToken.BadInit();
        }
        if (c.maxShielded > type(uint256).max / c.shieldScale) revert IZetherToken.BadInit();
        if (c.disclosureMode > uint8(ZetherTypes.DisclosureMode.COMPACT)) revert IZetherToken.BadDisclosureMode(c.disclosureMode);
        if (c.auditorMode > uint8(ZetherTypes.AuditorMode.OPTIONAL)
            || (aud.length == 0) != (c.auditorMode == uint8(ZetherTypes.AuditorMode.NONE))) {
            revert IZetherToken.BadAuditorMode(c.auditorMode);
        }
        ZetherStorage storage s = $();
        s.verifier = v;
        s.disclosureMode = ZetherTypes.DisclosureMode(c.disclosureMode);
        s.auditorMode = ZetherTypes.AuditorMode(c.auditorMode);
        s.shieldScale = c.shieldScale;
        s.maxShielded = c.maxShielded;
        s.confidentialFee = c.confidentialFee;
        s.minDecoyFee = c.minDecoyFee;
        s.auditorKey = aud;
        s.psid = v.proofSystemId();
        s.p = p;
    }

    // ------------------------------------------------------------------ shield

    /// @notice `pending[ua] += [amount]G` and `totalShielded += amount` within the cap. The token takes the public units
    ///         (`mtxShield`) or the underlying (`mtxWrapShield`) of `from` (its `_msgSender()`); the minter never mints
    ///         shielded value.
    function shield(ZetherTypes.UA ua, uint256 amount, address registry, address from) public {
        ZetherStorage storage s = $();
        if (!registeredOn(registry, ua)) revert IZetherToken.AccountNotRegistered(ua);
        uint256 room = s.maxShielded - s.totalShielded;
        if (amount == 0 || amount > room) revert IZetherToken.AmountOutOfRange(amount, room);
        s.totalShielded += amount;
        _credit(s, ua, s.verifier.g1MulBase(amount), "");
        emit IConfidentialToken.Shielded(ZetherTypes.UA.unwrap(ua), from, amount, s.acct[ua].pendingSeq);
    }

    // ------------------------------------------------------------------ transfer

    /// @notice The single-recipient format (BUNDLE tokens only): checks, the proof (the only authority), then
    ///         `acc_f −= (C_deb + [fee]G, D_out)`, `pend_t += (C_out, D_out)`, `totalShielded -= fee` (the fee is paid in public units by the layer), `sendCounter_f++`;
    ///         the record `salt ‖ B` stored in full.
    function transferSingle(IZetherToken.ZetherSingle calldata t, bytes calldata proof, Env memory e)
        public returns (bytes32, uint256)
    {
        (Ctx memory c, Prepared memory pp) = _prepareSingle(t, e);
        _check(c, pp, proof, OP_TRANSFER);
        return (_settleSingle(c, pp, t), pp.fee);
    }

    function _prepareSingle(IZetherToken.ZetherSingle calldata t, Env memory e)
        private view returns (Ctx memory c, Prepared memory pp)
    {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareSingle(c, acct(s.acct[uaOf(t.yFrom)], c.p), t);
    }

    function _settleSingle(Ctx memory c, Prepared memory pp, IZetherToken.ZetherSingle calldata t) private returns (bytes32 entryRef) {
        ZetherStorage storage s = $();
        ZetherTypes.UA to = uaOf(t.yTo);
        bytes memory dOut = abi.encode(t.dOut);
        _debit(c, s.acct[pp.from], abi.encode(t.cDeb), dOut, pp.fee);
        _credit(s, to, abi.encode(t.cOut), dOut);
        _payFee(s, pp);
        entryRef = _sent(s, c, pp);
        s.entries[entryRef] = bytes.concat(pp.salt, abi.encode(t.yTo, t.cOut, t.dOut, t.cAud));
        emit IConfidentialToken.ConfidentialTransfer(entryRef, ZetherTypes.UA.unwrap(pp.from), ZetherTypes.UA.unwrap(to),
            ZetherTypes.UA.unwrap(pp.beneficiary), pp.fee, pp.sendCounter, address(0));
    }

    /// @notice `M` recipients, one proof (CTR-ZTH-37/38): `acc_f −= (C_deb + [fee]G, D_out)` with `fee = txFee + M ·
    ///         decoyFee`, every `pend_tj += (C_out_j, D_out)`, `totalShielded -= fee`, `sendCounter_f++` once; the record by
    ///         `mode` (the stored form, CTR-ZTH-38), which a `COMPACT` token allows only as HASH. Returns `Paid`: `txFee`
    ///         to the beneficiary and `decoyFee` to each leg, decoys included (owner 2026-10-20).
    function transferMulti(
        IZetherToken.ZetherMulti calldata t,
        bytes calldata proof,
        ZetherTypes.TransferMode mode,
        Env memory e
    ) public returns (bytes32, Paid memory) {
        (Ctx memory c, Prepared memory pp) = _prepareMulti(t, mode, e);
        _check(c, pp, proof, OP_MULTI_HASH);
        return (_settleMulti(c, pp, t, mode), Paid(pp.fee - pp.to.length * pp.decoyFee, pp.decoyFee, pp.to));
    }

    function _prepareMulti(IZetherToken.ZetherMulti calldata t, ZetherTypes.TransferMode mode, Env memory e)
        private view returns (Ctx memory c, Prepared memory pp)
    {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareMulti(c, acct(s.acct[multiFrom(t)], c.p), t, mode);
    }

    function _settleMulti(Ctx memory c, Prepared memory pp, IZetherToken.ZetherMulti calldata t, ZetherTypes.TransferMode mode)
        private returns (bytes32 entryRef)
    {
        ZetherStorage storage s = $();
        bytes memory dOut = abi.encode(t.dOut);
        _debit(c, s.acct[pp.from], abi.encode(t.cDeb), dOut, pp.fee);
        _creditLegs(s, pp.to, t.legs, dOut);
        _payFee(s, pp);
        entryRef = _sent(s, c, pp);
        _storeRecord(s, entryRef, t, pp, dOut, mode);
        ZetherTypes.UA[] memory to = pp.to;
        bytes32[] memory rec;
        assembly ("memory-safe") { rec := to } // `UA` is `bytes32`: the same memory array
        emit IConfidentialToken.ConfidentialTransferMulti(entryRef, ZetherTypes.UA.unwrap(pp.from),
            ZetherTypes.UA.unwrap(pp.beneficiary), pp.fee, pp.sendCounter, rec, uint8(mode), address(0));
    }

    /// @dev Every `pend_tj += (C_out_j, D_out)`, decoys included.
    function _creditLegs(ZetherStorage storage s, ZetherTypes.UA[] memory to, IZetherToken.ZetherLeg[] calldata legs, bytes memory dOut) private {
        for (uint256 j; j < to.length; ++j) _credit(s, to[j], abi.encode(legs[j].cOut), dOut);
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement (zether.md §8.2, built name `burn`): checks, the proof (the only authority), then
    ///         `acc_f.C −= [amount + fee]G`, `totalShielded -= fee` (the fee is paid in public units by the layer), `sendCounter_f++`, `totalShielded −= amount`. The token
    ///         then pays `amount · shieldScale` public-equivalent units to `recipient` (a padded address or a derived UA,
    ///         CTR-ZTH-51: the statement's recipient word either way) from the pool or a leg's underlying.
    function unshield(
        IZetherToken.ZetherBurn calldata b,
        bytes calldata proof,
        uint256 amount,
        bytes32 recipient,
        Env memory e
    ) public returns (uint256) {
        (Ctx memory c, Prepared memory pp) = _prepareUnshield(b, amount, recipient, e);
        _check(c, pp, proof, OP_BURN);
        ZetherStorage storage s = $();
        Account storage a = s.acct[pp.from];
        a.accC = c.ver.g1Sub(_pt(a.accC, c.p), c.ver.g1MulBase(amount + pp.fee));
        _sent(s, c, pp);
        s.totalShielded -= amount;
        _payFee(s, pp);
        emit IConfidentialToken.Unshielded(ZetherTypes.UA.unwrap(pp.from), amount, recipient, address(0));
        return pp.fee;
    }

    function _prepareUnshield(IZetherToken.ZetherBurn calldata b, uint256 amount, bytes32 recipient, Env memory e)
        private view returns (Ctx memory c, Prepared memory pp)
    {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareUnshield(c, acct(s.acct[uaOf(b.yFrom)], c.p), b, amount, recipient);
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

    /// @notice CTR-ZTH-16/17: `lastRolledPendingSeq < expectedPendingSeq ≤ pendingSeq`, signed by the account (a Schnorr
    ///         by `x` through `registry.requireAuthorized` under `zether-owner`, UA-6 U9) over the typed `ZetherRollOver`
    ///         in the token's domain (TS-D19), with `accSeq`.
    function rollOverSigned(
        ZetherTypes.UA ua,
        uint64 expectedPendingSeq,
        uint64 validUntilBlock,
        IUARegistry.UASig calldata sig,
        Env memory e
    ) public {
        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);
        if (!registeredOn(e.registry, ua)) revert IZetherToken.AccountNotRegistered(ua); // Zether UA only (2026-10-20)
        ZetherStorage storage s = $();
        Account storage a = s.acct[ua];
        if (a.pendingSeq < expectedPendingSeq || expectedPendingSeq <= a.lastRolledPendingSeq) {
            revert IZetherToken.PendingSeqMismatch(expectedPendingSeq, a.pendingSeq);
        }
        bytes32 digest = MessageHashUtils.toTypedDataHash(e.domainSeparator, keccak256(abi.encode(
            TH_ROLL_OVER, ua, a.accSeq, expectedPendingSeq, validUntilBlock
        )));
        _requireOwner(e, ua, digest, sig);
        _rollOver(s, ua);
    }

    /// @notice The typed `ZetherSetRollOverMode` in the token's domain (TS-D19), with `modeNonce` (no replay).
    function setRollOverMode(
        ZetherTypes.UA ua,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        IUARegistry.UASig calldata sig,
        Env memory e
    ) public {
        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);
        if (!registeredOn(e.registry, ua)) revert IZetherToken.AccountNotRegistered(ua); // Zether UA only (2026-10-20)
        Account storage a = $().acct[ua];
        bytes32 digest = MessageHashUtils.toTypedDataHash(e.domainSeparator, keccak256(abi.encode(
            TH_SET_MODE, ua, uint8(mode), a.modeNonce, validUntilBlock
        )));
        _requireOwner(e, ua, digest, sig);
        a.mode = mode;
        a.modeNonce += 1;
        emit IZetherToken.RollOverModeChanged(ua, mode);
    }

    // ------------------------------------------------------------------ EIP-712 hashes of the explicit parameters (TS-D17)

    function hashSingle(IZetherToken.ZetherSingle calldata t) public pure returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(TH_SINGLE, t.accSeq, t.sendCounter, t.validUntilBlock, t.salt, t.beneficiaryUA),
            abi.encode(_hash(t.yFrom), _hash(t.yTo), _hash(t.cOut), _hash(t.dOut), _hash(t.cDeb), _hash(t.cAud))
        ));
    }

    function hashMulti(IZetherToken.ZetherMulti calldata t) public pure returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(TH_MULTI, t.accSeq, t.sendCounter, t.validUntilBlock, t.salt, t.beneficiaryUA, t.decoyFee),
            abi.encode(_hash(t.yFrom), _hash(t.dOut), _hash(t.cDeb), _hashLegs(t.legs), keccak256(t.sealedMemo))
        ));
    }

    function hashBurn(IZetherToken.ZetherBurn calldata b) public pure returns (bytes32) {
        return keccak256(abi.encode(TH_BURN, b.accSeq, b.sendCounter, b.validUntilBlock, b.beneficiaryUA, _hash(b.yFrom)));
    }

    function hashUnwrap(IConfidentialWrappedToken.Unwrap calldata x) public pure returns (bytes32) {
        return keccak256(abi.encode(TH_UNWRAP, x));
    }

    function _hash(IZetherToken.G1 calldata g) private pure returns (bytes32) {
        return keccak256(abi.encode(TH_G1, g));
    }

    function _hashLegs(IZetherToken.ZetherLeg[] calldata legs) private pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](legs.length);
        for (uint256 j; j < h.length; ++j) {
            IZetherToken.ZetherLeg calldata l = legs[j];
            h[j] = keccak256(abi.encode(TH_LEG, _hash(l.yTo), _hash(l.cOut), _hash(l.cAud), _hash(l.dAud)));
        }
        return keccak256(abi.encodePacked(h));
    }

    // ------------------------------------------------------------------ statements (shared with ZetherStatements)

    /// @notice The statement context of the token itself (`address(this)` under `DELEGATECALL`).
    function ctx(ZetherStorage storage s, Env memory e) internal view returns (Ctx memory c) {
        c.ver = s.verifier;
        c.burnVer = e.burnVer;
        c.registry = e.registry;
        c.token = address(this);
        c.chainUid = e.chainUid;
        c.psid = s.psid;
        c.p = s.p;
        c.fee = s.confidentialFee;
        c.minDecoyFee = s.minDecoyFee;
        c.maxShielded = s.maxShielded;
        c.auditorKey = s.auditorKey;
        c.auditorMode = s.auditorMode;
        c.disclosureMode = s.disclosureMode;
        c.tag = e.tag;
        c.binding = e.binding;
    }

    function acct(Account storage a, uint256 p) internal view returns (Acct memory) {
        return Acct(_pt(a.accC, p), _pt(a.accD, p), a.accSeq, a.sendCounter);
    }

    /// @notice The form `mtxConfidentialTransfer` takes: BUNDLE on a `BUNDLE` token, HASH (commit-reveal) on a `COMPACT` token.
    function defaultMode() internal view returns (ZetherTypes.TransferMode) {
        return $().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
            ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;
    }

    /// @notice `ZTX_V1_RELAYED` for a non-zero envelope binding, else `ZTX_V1_DIRECT`.
    function tagOf(bytes32 binding) internal pure returns (bytes32) {
        return binding == bytes32(0) ? TAG_DIRECT : TAG_RELAYED;
    }

    /// @notice The binding word of a direct `mtxUnshieldUnwrap`: its leg and `minOut` (controller ruling, pending
    ///         the owner), so a proof lifted from a pending call cannot pick another leg, drop `minOut` or go through
    ///         `mtxUnshield` instead.
    function unwrapBinding(address u, uint256 minOut) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_UNWRAP, u, minOut));
    }

    /// @notice `entryRef` (zether.md §12) with `chainUid` (CTR-ZTH-36); `sendCounter` before the increment.
    function entryRefOf(Ctx memory c, ZetherTypes.UA from, uint64 counter) internal view returns (bytes32) {
        return keccak256(abi.encode(TAG_ENTRY, block.chainid, c.chainUid, c.token, from, uint256(counter)));
    }

    /// @notice The UA of a key given as a point (`ZetherTypes.toUA` of its 128 bytes).
    function uaOf(IZetherToken.G1 calldata y) internal pure returns (ZetherTypes.UA) {
        return ZetherTypes.toUA(abi.encode(y));
    }

    /// @notice The sender of `M` legs, `0 < M ≤ 16`.
    function multiFrom(IZetherToken.ZetherMulti calldata t) internal pure returns (ZetherTypes.UA) {
        uint256 m = t.legs.length;
        if (m == 0 || m > MAX_RECIPIENTS) revert IZetherToken.BadRecipientCount(m);
        return uaOf(t.yFrom);
    }

    /// @notice Every cheap check before verification: the mode, self, registration, fee, `accSeq`, `sendCounter`,
    ///         `validUntilBlock`, the auditor key as a party.
    function prepareSingle(Ctx memory c, Acct memory a, IZetherToken.ZetherSingle calldata t)
        internal view returns (Prepared memory pp)
    {
        if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT) {
            revert IZetherToken.TransferEntryDisabled(uint8(c.disclosureMode));
        }
        pp.from = uaOf(t.yFrom);
        ZetherTypes.UA to = uaOf(t.yTo);
        if (ZetherTypes.UA.unwrap(pp.from) == ZetherTypes.UA.unwrap(to)) revert IZetherToken.SelfTransfer();
        _requireRegistered(c, pp.from);
        _requireRegistered(c, to);
        pp.beneficiary = ZetherTypes.UA.wrap(t.beneficiaryUA);
        pp.fee = _innerFee(c, pp.beneficiary);
        (pp.sendCounter, pp.validUntil) = _checkSeqs(a, t.accSeq, t.sendCounter, t.validUntilBlock);
        pp.salt = t.salt;
        bytes memory ya = _auditorPoint(c, _isO(abi.encode(t.cAud)) ? 1 : 0, 1);
        ZetherTypes.UA[] memory parties = new ZetherTypes.UA[](1);
        parties[0] = to;
        _noAuditorParty(ya, pp.from, parties);
        pp.statement = bytes.concat(
            _header(c, OP_TRANSFER, c.psid, a, pp, 0, 0), abi.encode(t.yFrom, t.yTo), ya, a.accC, a.accD,
            abi.encode(t.cOut, t.dOut, t.cDeb, t.cAud)
        );
    }

    /// @notice As `prepareSingle`, for `M` recipients: pairwise distinct, none the sender (nor, with the auditor on, the
    ///         auditor key: `AuditorKeyAsParty`), all registered; a `COMPACT`
    ///         token takes HASH only; the memo exactly on HASH, `salt ‖ sealedMemo`, its hash in the header;
    ///         `minDecoyFee ≤ decoyFee < 2^64` (`DecoyFeeOutOfRange`) and the header's fee word `txFee + M · decoyFee`
    ///         `< 2^64`, so the proof binds the sender's `decoyFee` (no relation change: the fee is already public).
    function prepareMulti(
        Ctx memory c,
        Acct memory a,
        IZetherToken.ZetherMulti calldata t,
        ZetherTypes.TransferMode mode
    ) internal view returns (Prepared memory pp) {
        if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT && mode != ZetherTypes.TransferMode.HASH) {
            revert IZetherToken.TransferEntryDisabled(uint8(c.disclosureMode));
        }
        pp.from = uaOf(t.yFrom);
        _requireRegistered(c, pp.from);
        pp.to = _recipients(c, t.legs, pp.from);
        pp.beneficiary = ZetherTypes.UA.wrap(t.beneficiaryUA);
        uint256 d = t.decoyFee;
        if (d < c.minDecoyFee || d >= VALUE_BOUND) revert IZetherToken.DecoyFeeOutOfRange(d, c.minDecoyFee);
        pp.decoyFee = d;
        pp.fee = _innerFee(c, pp.beneficiary) + pp.to.length * d;
        if (pp.fee >= VALUE_BOUND) revert IZetherToken.AmountOutOfRange(pp.fee, VALUE_BOUND);
        (pp.sendCounter, pp.validUntil) = _checkSeqs(a, t.accSeq, t.sendCounter, t.validUntilBlock);
        pp.salt = t.salt;
        bool hashed = mode == ZetherTypes.TransferMode.HASH;
        if (t.sealedMemo.length != (hashed ? 1 + 40 * pp.to.length : 0)) revert IZetherToken.BadPayload(t.sealedMemo.length);
        if (hashed) pp.memoHash = keccak256(bytes.concat(t.salt, t.sealedMemo));
        pp.statement = _multiStatement(c, a, t, pp, mode);
    }

    /// @notice `0 < amount ≤ maxShielded` before the statement (`amount + fee < 2^65 < r`), recipient non-zero.
    function prepareUnshield(
        Ctx memory c,
        Acct memory a,
        IZetherToken.ZetherBurn calldata b,
        uint256 amount,
        bytes32 recipient
    ) internal view returns (Prepared memory pp) {
        if (amount == 0 || amount > c.maxShielded) revert IZetherToken.AmountOutOfRange(amount, c.maxShielded);
        if (recipient == 0) revert IZetherToken.ZeroRecipient();
        pp.from = uaOf(b.yFrom);
        _requireRegistered(c, pp.from);
        pp.beneficiary = ZetherTypes.UA.wrap(b.beneficiaryUA);
        pp.fee = _innerFee(c, pp.beneficiary);
        (pp.sendCounter, pp.validUntil) = _checkSeqs(a, b.accSeq, b.sendCounter, b.validUntilBlock);
        pp.statement = bytes.concat(
            _header(c, OP_BURN, c.psid, a, pp, amount, recipient), abi.encode(b.yFrom), a.accC, a.accD
        );
    }

    // ------------------------------------------------------------------ internals

    /// @dev The 512-byte header (zether.md §7, `…/v3`): `chainUid` at word 3, the salt at word 13 (16 zero bytes ‖ salt,
    ///      CTR-ZTH-30), `memoHash` at word 14 (CTR-ZTH-50), `validUntilBlock` at word 15 (review C0-9): all are in what
    ///      the sender proves and signs, so a relayer can neither alter nor drop them. `recipient` (word 12) is a padded
    ///      address or a derived UA (CTR-ZTH-51).
    function _header(Ctx memory c, bytes32 op, bytes32 psid, Acct memory a, Prepared memory pp, uint256 amount, bytes32 recipient)
        private view returns (bytes memory)
    {
        return bytes.concat(
            abi.encode(op, psid, block.chainid, c.chainUid, c.token, c.tag, c.binding, uint256(a.sendCounter)),
            abi.encode(uint256(a.accSeq), pp.fee, pp.beneficiary, amount, recipient, uint128(pp.salt), pp.memoHash),
            abi.encode(pp.validUntil)
        );
    }

    /// @dev `header ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ (Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j)_j`; the
    ///      mode is in `opTag`.
    function _multiStatement(
        Ctx memory c,
        Acct memory a,
        IZetherToken.ZetherMulti calldata t,
        Prepared memory pp,
        ZetherTypes.TransferMode mode
    ) private view returns (bytes memory) {
        bytes32 op = mode == ZetherTypes.TransferMode.HASH ? OP_MULTI_HASH : OP_MULTI_BUNDLE;
        bytes memory ya = _auditorPoint(c, _audOff(t.legs), pp.to.length);
        _noAuditorParty(ya, pp.from, pp.to);
        bytes memory head = bytes.concat(
            _header(c, op, c.ver.proofSystemIdMulti(), a, pp, 0, 0), abi.encode(t.yFrom), ya, a.accC, a.accD
        );
        return bytes.concat(head, abi.encode(t.dOut, t.cDeb, pp.to.length), _legPoints(t.legs));
    }

    /// @dev The legs' points in order: `abi.encode(legs)` less its offset and length words (a leg is four static points).
    function _legPoints(IZetherToken.ZetherLeg[] calldata legs) private pure returns (bytes memory b) {
        b = abi.encode(legs);
        assembly ("memory-safe") {
            let n := sub(mload(b), 64)
            b := add(b, 64)
            mstore(b, n)
        }
    }

    /// @dev With the auditor on (`Y_a ≠ O`), neither the sender nor a recipient is the auditor key (review C0-1;
    ///      the Zether twin of PQZ F-4: a party's ciphertext under `Y_a` would sit next to the auditor copies).
    function _noAuditorParty(bytes memory ya, ZetherTypes.UA from, ZetherTypes.UA[] memory to) private pure {
        if (_isO(ya)) return;
        bytes32 a = ZetherTypes.UA.unwrap(ZetherTypes.toUA(ya));
        if (ZetherTypes.UA.unwrap(from) == a) revert IZetherToken.AuditorKeyAsParty();
        for (uint256 j; j < to.length; ++j) if (ZetherTypes.UA.unwrap(to[j]) == a) revert IZetherToken.AuditorKeyAsParty();
    }

    /// @dev The recipients: none the sender, pairwise distinct, registered.
    function _recipients(Ctx memory c, IZetherToken.ZetherLeg[] calldata legs, ZetherTypes.UA from)
        private view returns (ZetherTypes.UA[] memory to)
    {
        uint256 m = legs.length;
        to = new ZetherTypes.UA[](m);
        for (uint256 j; j < m; ++j) {
            to[j] = uaOf(legs[j].yTo);
            bytes32 t = ZetherTypes.UA.unwrap(to[j]);
            if (t == ZetherTypes.UA.unwrap(from)) revert IZetherToken.SelfTransfer();
            for (uint256 k; k < j; ++k) if (ZetherTypes.UA.unwrap(to[k]) == t) revert IZetherToken.DuplicateRecipient(to[j]);
            _requireRegistered(c, to[j]);
        }
    }

    /// @dev `accSeq`, `sendCounter` and `block.number ≤ validUntilBlock` (review C0-9, the PQZ header's rule; the word
    ///      is in the statement, so the proof binds it).
    function _checkSeqs(Acct memory a, uint64 provedAccSeq, uint64 provedSend, uint256 validUntil)
        private view returns (uint64, uint256)
    {
        if (block.number > validUntil) revert IZetherToken.TransferExpired(validUntil);
        if (provedAccSeq != a.accSeq) revert IZetherToken.StaleAccSeq(a.accSeq, provedAccSeq);
        if (provedSend != a.sendCounter) revert IZetherToken.StaleSendCounter(a.sendCounter, provedSend);
        return (a.sendCounter, validUntil);
    }

    /// @dev `confidentialFee` when a beneficiary is named; the fee is no back door to register on someone's behalf.
    function _innerFee(Ctx memory c, ZetherTypes.UA beneficiary) private view returns (uint256) {
        if (ZetherTypes.UA.unwrap(beneficiary) == bytes32(0)) return 0;
        _requireRegistered(c, beneficiary);
        return c.fee;
    }

    /// @dev Registered on the verifier's curve.
    function _requireRegistered(Ctx memory c, ZetherTypes.UA ua) private view {
        if (!registeredOn(c.registry, ua)) revert IZetherToken.AccountNotRegistered(ua);
    }

    /// @notice `ua` is registered as `zether-bls12381` (accounts.md §1.13: `kindOf`).
    function registeredOn(address registry, ZetherTypes.UA ua) internal view returns (bool) {
        return IUARegistry(registry).kindOf(ZetherTypes.UA.unwrap(ua)) == ZetherTypes.KIND_ZETHER_BLS12381;
    }

    /// @dev An owner op (roll-over, mode): a registered Zether UA only (owner ruling 2026-10-20; checked first by both entry
    ///      points: any other kind or an unregistered id reverts `AccountNotRegistered`), its Schnorr by `x` through `requireAuthorized` under
    ///      `zether-owner`, `sig.signature` the Schnorr (UA-6 U9; `Y` from the record).
    function _requireOwner(Env memory e, ZetherTypes.UA ua, bytes32 digest, IUARegistry.UASig calldata sig) private view {
        IUARegistry(e.registry).requireAuthorized(ZetherTypes.UA.unwrap(ua), UAKinds.PURPOSE_ZETHER_OWNER, digest, sig);
    }

    /// @dev The proof is the spending authority (knowledge of `x`; UA-6 U9: no registry call, `from` registered by
    ///      `kindOf` in the prepare step): a transfer on the transfer verifier `c.ver`, a burn on the burn verifier
    ///      `c.burnVer`, both immutables of the implementation (CTR-ZTH-20); their range proofs on the inner-product
    ///      verifier each of them fixes.
    function _check(Ctx memory c, Prepared memory pp, bytes calldata proof, bytes32 op) private view {
        bool ok = op == OP_TRANSFER
            ? c.ver.verifyTransfer(pp.statement, proof)
            : op == OP_BURN ? c.burnVer.verifyBurn(pp.statement, proof) : c.ver.verifyTransferMulti(pp.statement, proof);
        if (!ok) revert IZetherToken.ProofRejected();
    }

    /// @dev The inner fee leaves the shielded set (D19, CTR-ZTH-51): `totalShielded -= fee`; the layer then moves
    ///      `fee · shieldScale` public units from `SHIELD_POOL` to the beneficiary's public balance (no `pend_ben`).
    function _payFee(ZetherStorage storage s, Prepared memory pp) private {
        if (pp.fee != 0) s.totalShielded -= pp.fee;
    }

    /// @dev `sendCounter_f++` once; the `entryRef` of this debit (with the counter before the increment).
    function _sent(ZetherStorage storage s, Ctx memory c, Prepared memory pp) private returns (bytes32) {
        s.acct[pp.from].sendCounter = pp.sendCounter + 1;
        return entryRefOf(c, pp.from, pp.sendCounter);
    }

    /// @dev `acc_f −= (C_deb + [fee]G, D_out)`.
    function _debit(Ctx memory c, Account storage a, bytes memory cDeb, bytes memory dOut, uint256 fee) private {
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
        emit IConfidentialToken.RolledOver(ZetherTypes.UA.unwrap(ua), a.accSeq, 0, 0);
    }

    /// @dev BUNDLE: the record `R` inline in state; HASH (commit-reveal): `R` by SSTORE2 (the slot holds the pointer), the
    ///      sender memo next to it, `R` also in `TransferBundles` (CTR-ZTH-38, CTR-ZTH-50, review C0-3). Every mode keeps
    ///      `R` in state.
    function _storeRecord(
        ZetherStorage storage s,
        bytes32 entryRef,
        IZetherToken.ZetherMulti calldata t,
        Prepared memory pp,
        bytes memory dOut,
        ZetherTypes.TransferMode mode
    ) private {
        bytes memory r = _record(pp.salt, t.legs, dOut);
        if (mode == ZetherTypes.TransferMode.BUNDLE) {
            s.entries[entryRef] = r;
        } else {
            s.entryPtrs[entryRef] = SSTORE2.write(r);
            s.memos[entryRef] = bytes.concat(t.salt, t.sealedMemo);
            emit IZetherToken.TransferBundles(entryRef, r);
        }
    }

    /// @dev `R = salt ‖ B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j ‖ D_aud_j` (5 points, review C0-1; the
    ///      single format's `B` keeps 4, its auditor copy being under `s`).
    function _record(bytes16 salt, IZetherToken.ZetherLeg[] calldata legs, bytes memory dOut) private pure returns (bytes memory b) {
        b = abi.encodePacked(salt);
        for (uint256 j; j < legs.length; ++j) {
            IZetherToken.ZetherLeg calldata l = legs[j];
            b = bytes.concat(b, abi.encode(l.yTo, l.cOut), dOut, abi.encode(l.cAud, l.dAud));
        }
    }

    /// @dev `Y_a` of the statement (CTR-ZTH-42) by the token's auditor mode: `NONE` takes every `C_aud_j = O` (`Y_a = O`);
    ///      `FULL` every `C_aud_j ≠ O` (the key); `OPTIONAL` either, all or nothing across the legs (a mix reverts).
    function _auditorPoint(Ctx memory c, uint256 nOff, uint256 m) private pure returns (bytes memory) {
        if (c.auditorMode == ZetherTypes.AuditorMode.NONE) {
            if (nOff != m) revert IZetherToken.AuditorForbidden();
            return new bytes(c.p);
        }
        if (nOff == 0) return c.auditorKey;
        if (c.auditorMode == ZetherTypes.AuditorMode.FULL) revert IZetherToken.AuditorRequired();
        if (nOff != m) revert IZetherToken.AuditorLegsMixed();
        return new bytes(c.p);
    }

    /// @dev Number of the legs with `C_aud_j = O` (the verifier then requires `D_aud_j = O` too).
    function _audOff(IZetherToken.ZetherLeg[] calldata legs) private pure returns (uint256 n) {
        for (uint256 j; j < legs.length; ++j) if (_isO(abi.encode(legs[j].cAud))) ++n;
    }

    /// @dev The stored point, or `O` when never written.
    function _pt(bytes storage b, uint256 p) internal view returns (bytes memory) {
        return b.length == 0 ? new bytes(p) : b;
    }

    function _isO(bytes memory a) internal pure returns (bool) {
        return keccak256(a) == keccak256(new bytes(a.length));
    }
}
