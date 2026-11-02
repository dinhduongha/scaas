// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// legacy/typed-signing: NOT COMPILED. The packed PQZ surface as it stood before typed-signing C4: the `(payload, proof, auth,
// beneficiary, accHint[, …])` entries, the byte slices of `PqzCore` over the packed payload, the statement views on it, the
// shared-beneficiary check, `selectors` in `WrappedPqzToken`, and the digest `keccak256("SCAAS-PQZ-AUTH-V1" ‖ keccak256(stmt))`.
// Superseded by the explicit parameters (`IPqzToken.PqzTransferArgs`, `PqzMultiArgs`, `PqzBurnArgs`, TS-D17) and the typed
// `PqzAuth` (TS-D19), which give the same statement, op blob and memo bytes: `test/pqz/helpers/PqzPackedRef.sol` keeps the
// statement and blob code live as the reference of `PqzExplicitStatementTest`. Reference only: the fragments are out of their
// contracts.

// ------------------------------------------------------------------ IPqzToken

    error MemoSaltMismatch();
    /// @notice The shared `beneficiary` argument is not the payload's beneficiary word (plan 5h D20).
    error BeneficiaryMismatch(bytes32 payload, bytes32 given);

    /// @notice Multi-recipient, in the token's default storage mode.
    function mtxConfidentialTransfer(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);
    /// @notice Multi-recipient, commit-reveal on every token.
    function mtxConfidentialTransferCompact(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);
    /// @notice Single-recipient, in the token's default storage mode.
    function mtxConfidentialTransferSingle(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);
    /// @notice `amount` shielded units out as `amount · shieldScale` public units from `SHIELD_POOL` to `recipient`: a
    ///         native address as its zero-padded id, or a registered SIGNING UA (credited on the UA ledger); the pools
    ///         are refused. PQZ: `amount = 0` with `recipient = 0` is a refresh.
    function mtxUnshield(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint,
        uint256 amount,
        bytes32 recipient
    ) external;
    /// @notice Single-recipient, commit-reveal on every token.
    function mtxConfidentialTransferSingleCompact(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint
    ) external returns (bytes32 entryRef);

    /// @notice `mtxUnshield`'s debit of `x.amount`, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut`
    ///         to `x.recipient`: a native address, or a derived UA in the leg's own UA ledger (`transferToUA`;
    ///         `UALegNotLedger` otherwise).
    function mtxUnshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint,
        Unwrap calldata x
    ) external;

// ------------------------------------------------------------------ PqzLayer

    /// @notice The op 7 statement the token builds for a multi-recipient `payload`, after every cheap check; a payload
    ///         with the memo is read as commit-reveal. `binding` 0 = a direct call, else the relayed call's envelope
    ///         binding; the statement's word is either folded with the mode (W-A, D15).
    function transferStatement(bytes calldata payload, bytes32 binding) external view returns (bytes memory) {
        return PqzViewLib.statementOf(7, _envOf(binding), payload);
    }

    /// @notice The op 1 statement of a single-recipient `payload` (`mtxConfidentialTransferSingle*`; `binding` as above).
    function transferSingleStatement(bytes calldata payload, bytes32 binding) external view returns (bytes memory) {
        return PqzViewLib.statementOf(1, _envOf(binding), payload);
    }

    /// @notice The burn (`amount > 0`) or refresh (`amount = 0`, `recipient = 0`) statement.
    function burnStatement(bytes calldata payload, uint256 amount, bytes32 recipient, bytes32 binding)
        external view returns (bytes memory)
    {
        PqzCore.Env memory e = _envOf(binding);
        (e.amount, e.recipient) = (amount, recipient);
        return PqzViewLib.statementOf(2, e, payload);
    }

    /// @notice The multi-recipient transfer, op 7 `R_TXM` (`M` legs, decoys included; CTR-PQZ-26), in the token's
    ///         default form: the bundle stored (BUNDLE token) or commit-reveal (COMPACT token). `accHint`: optional,
    ///         the materialised `acc` packed at `PACK_BITS` (P46: `PqzCt.CTP` bytes, `pack(pqzAcc(ua))`; `pqzAcc`
    ///         returns 64-bit lanes), used only when it hashes to `accHash`, else ignored (plan 5h D5).
    function mtxConfidentialTransfer(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        _ben(payload, 128, beneficiary);
        return _transfer(_envTransfer(_defaultMode()), true, payload, proof, auth, accHint);
    }

    function mtxConfidentialTransferCompact(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        _ben(payload, 128, beneficiary);
        return _transfer(_envTransfer(ZetherTypes.TransferMode.HASH), true, payload, proof, auth, accHint);
    }

    /// @notice The single-recipient transfer, op 1 `R_TX` / `R_TX0` (§7.4), in the token's default form.
    function mtxConfidentialTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        _ben(payload, 160, beneficiary);
        return _transfer(_envTransfer(_defaultMode()), false, payload, proof, auth, accHint);
    }

    function mtxConfidentialTransferSingleCompact(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        _ben(payload, 160, beneficiary);
        return _transfer(_envTransfer(ZetherTypes.TransferMode.HASH), false, payload, proof, auth, accHint);
    }

    /// @dev Op 7 (`multi`) or op 1 in the form of `e.mode`; the token pays what the library moved.
    function _transfer(PqzCore.Env memory e, bool multi, bytes calldata payload, bytes calldata proof,
        bytes calldata auth, bytes calldata accHint) private returns (bytes32 r)
    {
        _pullShieldIn(payload);
        PqzCore.Paid memory f;
        if (multi) (r, f) = PqzTransferLib.transferMulti(e, payload, accHint, proof, auth);
        else (r, f) = PqzTransferLib.transfer(e, payload, accHint, proof, auth);
        _pay(f, payload);
    }

    // ------------------------------------------------------------------ burn and refresh (§7.5)

    /// @notice Burn `amount` into `amount · shieldScale` public units moved from `SHIELD_POOL` to `recipient` (D19): a
    ///         padded address (the pools refused) or a registered SIGNING UA, credited on the UA ledger (UA-5c);
    ///         `amount = 0` with `recipient = 0` is a refresh.
    function mtxUnshield(bytes calldata payload, bytes calldata proof, bytes calldata auth, bytes32 beneficiary,
        bytes calldata accHint, uint256 amount, bytes32 recipient) external nonReentrant
    {
        _ben(payload, 128, beneficiary);
        if (!UAKinds.inNativeSpace(recipient)) _requireDerivedReceiver(recipient);
        _burn(_envBurn(amount, recipient), payload, proof, auth, accHint);
        _fromPool(recipient, amount);
    }

    /// @dev The burn / refresh debit of `e` (also `mtxUnshieldUnwrap`'s); the token pays what the library moved.
    function _burn(PqzCore.Env memory e, bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes calldata accHint) internal
    {
        _pullShieldIn(payload);
        _pay(PqzBurnLib.unshield(e, payload, accHint, proof, auth), payload);
    }

    /// @dev C2-5 (owner 2026-10-27, controller proposal): the payload's `shieldIn` (word 64) goes into the pool before
    ///      the authorization and the precompile, so a signer who front-ran its own op with a public transfer costs the
    ///      relayer a cheap revert, not a 9–13 M gas one. The cap is the library's own check (`AmountOutOfRange`), made
    ///      here first so an absurd word never overflows the scaling; a payload too short for the word is left to the
    ///      library (`BadPayload`). No outer-fee pre-check (`mtxUnshield` may pay its fee from its own output).
    function _pullShieldIn(bytes calldata payload) internal {
        if (payload.length < 96) return;
        uint256 units = uint256(bytes32(payload[64:96]));
        PqzCore.PqzStorage storage s = PqzCore.$();
        uint256 room = s.maxShielded - s.totalShielded;
        if (units > room) revert AmountOutOfRange(units, room);
        _toPool(units);
    }

    /// @dev After a debit the library settled: exactly what it moved through `totalShielded` (`f`, D19): `shieldIn`
    ///      was pulled first (`_pullShieldIn`), then txFee (`fee − legs · decoyFee`) to the beneficiary and op 7's `decoyFee` to EVERY
    ///      leg (the real recipient too; owner 2026-10-20). Only the leg UAs are read from the (checked) payload.
    function _pay(PqzCore.Paid memory f, bytes calldata payload) internal {
        _fromPool(f.ben, f.fee - f.legs * f.decoyFee);
        if (f.decoyFee != 0) {
            for (uint256 j; j < f.legs; ++j) {
                _fromPool(bytes32(payload[PqzCore.M_OUT + 32 * j:PqzCore.M_OUT + 32 * j + 32]), f.decoyFee);
            }
        }
    }

    /// @dev The shared `beneficiary` is the payload's word at `off` (op 7 and burn 128, op 1 160); a payload too short
    ///      for it is left to the library (`BadPayload`).
    function _ben(bytes calldata payload, uint256 off, bytes32 beneficiary) internal pure {
        if (payload.length >= off + 32) {
            bytes32 b = bytes32(payload[off:off + 32]);
            if (b != beneficiary) revert BeneficiaryMismatch(b, beneficiary);
        }
    }

// ------------------------------------------------------------------ WrappedPqzToken

    /// @notice The burn of `x.amount` (statement: `amount`, `recipient`; `envelopeBinding` binds `x.underlying` and
    ///         `x.minOut`, direct P6g D12, relayed folded with the envelope's D15), `amount · shieldScale` burnt from
    ///         `SHIELD_POOL`, txFee to the beneficiary, then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥
    ///         minOut` to `x.recipient`: an address, or a derived UA through the leg's `transferToUA` (`UALegNotLedger`
    ///         otherwise).
    function mtxUnshieldUnwrap(bytes calldata payload, bytes calldata proof, bytes calldata auth, bytes32 beneficiary,
        bytes calldata accHint, Unwrap calldata x) external nonReentrant
    {
        _ben(payload, 128, beneficiary);
        _burn(_envUnwrap(x, _ticketBinding()), payload, proof, auth, accHint);
        uint256 wrapped = x.amount * PqzCore.$().shieldScale;
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped);
        WrappedLib.payOutTo(WrappedLib.indexOf(x.underlying), x.recipient, wrapped, x.minOut);
    }

    /// @notice The burn statement of `mtxUnshieldUnwrap` (`binding` 0 = direct, else the relayed call's envelope binding).
    function unshieldUnwrapStatement(bytes calldata payload, Unwrap calldata x, bytes32 binding)
        external view returns (bytes memory)
    {
        return PqzViewLib.statementOf(2, _envUnwrap(x, binding), payload);
    }

    function _init(TokenConfig memory cfg) internal override(WrappedToken, MetaTokenBase) {
        _requireUnused(cfg, true, false, false, false);
        WrappedLib.initToken(cfg, false, AdminLib.KIND_WRAPPED_PQZ);
        PqzStateLib.init(cfg.conf, _REGISTRY, PQZ_VERIFIER);
    }

    /// @notice `WrappedToken`'s eight, then the PQZ ops and the two leg paths, each `ABSOLUTE` (incl. the rollover
    ///         and `mtxPrepareAcc`).
    function mtxSelectors()
        public pure override(WrappedToken, IMetaTx, MetaTxBase)
        returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](18);
        c = new uint8[](18);
        a = new uint8[](18);
        (s[0], c[0]) = (this.cancelNonce.selector, FEE_CLASS_ABSOLUTE);
        (s[1], c[1]) = (SEL_WRAP, FEE_CLASS_ABSOLUTE);
        (s[2], c[2]) = (SEL_UNWRAP_MIN, FEE_CLASS_AMOUNT);
        (s[3], c[3]) = (SEL_WRAP_LEG, FEE_CLASS_ABSOLUTE);
        (s[4], c[4], a[4]) = (SEL_UNWRAP_LEG, FEE_CLASS_AMOUNT, 1);
        (s[5], c[5]) = (SEL_ADD_RESERVE, FEE_CLASS_ABSOLUTE);
        (s[6], c[6]) = (SEL_WRAP_TO_UA, FEE_CLASS_ABSOLUTE);
        (s[7], c[7], a[7]) = (SEL_UNWRAP_TO_UA, FEE_CLASS_AMOUNT, 1);
        (s[8], c[8]) = (IConfidentialToken.mtxShield.selector, FEE_CLASS_ABSOLUTE);
        (s[9], c[9]) = (this.mtxConfidentialTransfer.selector, FEE_CLASS_ABSOLUTE);
        (s[10], c[10]) = (this.mtxConfidentialTransferCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[11], c[11]) = (this.mtxUnshield.selector, FEE_CLASS_ABSOLUTE);
        (s[12], c[12]) = (this.mtxWrapShield.selector, FEE_CLASS_ABSOLUTE);
        (s[13], c[13]) = (this.mtxUnshieldUnwrap.selector, FEE_CLASS_ABSOLUTE);
        (s[14], c[14]) = (this.mtxConfidentialTransferSingle.selector, FEE_CLASS_ABSOLUTE);
        (s[15], c[15]) = (this.mtxConfidentialTransferSingleCompact.selector, FEE_CLASS_ABSOLUTE);
        (s[16], c[16]) = (this.mtxRollOver.selector, FEE_CLASS_ABSOLUTE);
        (s[17], c[17]) = (this.mtxPrepareAcc.selector, FEE_CLASS_ABSOLUTE);
    }

// ------------------------------------------------------------------ PqzCore

    /// @dev Transfer payload: `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ toUA ‖ beneficiaryUA ‖ salt(16)`, then `out`.
    uint256 internal constant T_OUT = 208;
    /// @dev Op 7 payload: `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ beneficiaryUA ‖ M ‖ decoyFee ‖ salt(16)`, then the
    ///      legs' UAs.
    uint256 internal constant M_OUT = 240;
    /// @dev Burn payload: `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖ beneficiaryUA`, then `u' ‖ v_f`.
    uint256 internal constant B_OUT = 160;
    uint256 internal constant MEMO = 57;

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

    /// @dev `header ‖ pk_f ‖ pk_t ‖ [pk_a] ‖ T ‖ out` (`PqzSet.STMT_TRANSFER` / `STMT_TRANSFER0` bytes).
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

    /// @dev The op blob `R ‖ v_f` with `R = salt ‖ u ‖ v_t ‖ [v_a] ‖ word(toUA)` (plan 5h D1; every `u`, `v` packed,
    ///      P46), the debit (the fee out of `totalShielded`; the token pays it from `SHIELD_POOL`, D19), the credit
    ///      `(u, v_t)`, the entry by mode.
    function _settleTransfer(Op memory o, bytes calldata payload) internal returns (bytes32 ref) {
        bytes calldata out = payload[T_OUT:T_OUT + o.outLen];
        // written in ascending order (each pack spills `32 − GROUP` zero bytes past its end; 32 bytes of slack)
        uint256 len = 16 + PqzCt.PKP + PqzCt.VP * (2 + o.auditorOn) + 32;
        bytes memory blob = new bytes(len + 32);
        _put(blob, 0, abi.encodePacked(o.salt));
        PqzCt.packCd(blob, 16, out[0:PqzCt.CT]);
        uint256 q = 16 + PqzCt.PKP + PqzCt.VP;
        if (o.auditorOn == 1) {
            PqzCt.packCd(blob, q, out[OUT_OFF:o.outLen]);
            q += PqzCt.VP;
        }
        _put(blob, q, abi.encode(o.to));
        PqzCt.packCd(blob, q + 32, out[PqzCt.CT:PqzCt.CT + PqzCt.V]);
        assembly ("memory-safe") { mstore(blob, len) }
        address ptr = SSTORE2.write(blob);
        _debit(o, ptr, 16, len - PqzCt.VP);
        ref = _sent(o);
        _credit(o.to, ptr, 16, 16 + PqzCt.PKP, ref);
        _entry(o, ref, ptr, payload, MEMO);
        emit IConfidentialToken.ConfidentialTransfer(ref, o.from, o.to, o.ben, o.fee, o.sendCounter, ptr);
    }

    /// @dev The entry (D11; NONE retired): `entryPtr` = the op blob in both modes (`R` is its data minus the
    ///      trailing `v_f`); commit-reveal (HASH) also keeps the memo (the last `memoLen` payload bytes; P6g D14).
    function _entry(Op memory o, bytes32 ref, address ptr, bytes calldata payload, uint256 memoLen) internal {
        PqzStorage storage s = $();
        s.entryPtr[ref] = ptr;
        if (o.mode == ZetherTypes.TransferMode.HASH) s.memos[ref] = payload[payload.length - memoLen:];
    }

    // ------------------------------------------------------------------ multi-recipient transfer (op 7, CTR-PQZ-26)


    /// @notice The op 7 statement and every cheap check, in the precompile buffer.
    function prepareMulti(Env memory e, bytes calldata payload, bytes calldata hint, uint256 proofLen)
        internal view returns (Op memory o, bytes memory buf)
    {
        _bindMode(e);
        o = _parseMulti(payload, e.mode);
        _common(o, e);
        // the header's public fee `txFee + M · decoyFee` (owner 2026-10-20): the proof binds the sender's `decoyFee`
        uint256 d = uint256(bytes32(payload[192:224]));
        uint256 dMin = $().minDecoyFee;
        if (d < dMin || d >= VALUE_BOUND) revert IPqzToken.DecoyFeeOutOfRange(d, dMin);
        o.decoyFee = d;
        o.fee += o.legs * d;
        if (o.fee >= VALUE_BOUND) revert IPqzToken.AmountOutOfRange(o.fee, VALUE_BOUND);
        _legs(o, e, payload);
        uint256 off = M_OUT + 32 * o.legs;
        buf = _multiBuffer(o, e, payload[off:off + o.outLen], hint, proofLen);
    }

    /// @notice True when a multi payload carries the commit-reveal memo (its length says so; any shape error: false).
    function multiHasMemo(bytes calldata payload) internal pure returns (bool) {
        if (payload.length < M_OUT) return false;
        uint256 m = uint256(bytes32(payload[160:192]));
        if (m == 0 || m > 8) return false;
        uint256 base = M_OUT + 32 * m + PqzCt.V * (m + 1) + 18 + 40 * m;
        return payload.length == base + PqzCt.PK * _groups(m, 0)
            || payload.length == base + PqzCt.PK * _groups(m, 1) + PqzCt.V * m;
    }

    /// @dev `M` in the id's built set, the length fixing `auditorOn`, the auditor mode, the memo on HASH.
    function _parseMulti(bytes calldata payload, ZetherTypes.TransferMode mode) internal view returns (Op memory o) {
        PqzStorage storage s = $();
        if (s.disclosureMode == ZetherTypes.DisclosureMode.COMPACT && mode != ZetherTypes.TransferMode.HASH) {
            revert IPqzToken.TransferEntryDisabled(uint8(s.disclosureMode));
        }
        if (payload.length < M_OUT) revert IPqzToken.BadPayload(payload.length);
        uint256 m = uint256(bytes32(payload[160:192]));
        if (!(m == 1 || m == 2 || m == 4 || (m == 8 && s.psid != PQZH_ID))) revert IPqzToken.BadRecipientCount(m);
        o.legs = m;
        o.opTag = OP_TRANSFER_MULTI;
        o.mode = mode;
        o.op = 7;
        uint256 memo = mode == ZetherTypes.TransferMode.HASH ? 18 + 40 * m : 0;
        if (payload.length < M_OUT + 32 * m + memo) revert IPqzToken.BadPayload(payload.length); // m ≤ 8: no overflow
        // `out` = u_0 … u_{G−1} ‖ v_0 … v_{M−1} ‖ v_f ‖ [v_{a,0} … v_{a,M−1}]; the auditor's G is never below the other's,
        // so the two lengths differ by at least V·M: the length fixes `auditorOn`
        uint256 rest = payload.length - M_OUT - 32 * m - memo;
        if (rest == PqzCt.PK * _groups(m, 1) + PqzCt.V * (2 * m + 1)) o.auditorOn = 1;
        else if (rest != PqzCt.PK * _groups(m, 0) + PqzCt.V * (m + 1)) revert IPqzToken.BadPayload(payload.length);
        if (o.auditorOn == 1 && s.auditorMode == ZetherTypes.AuditorMode.NONE) revert IPqzToken.AuditorForbidden();
        if (o.auditorOn == 0 && s.auditorMode == ZetherTypes.AuditorMode.FULL) revert IPqzToken.AuditorRequired();
        o.groups = _groups(m, o.auditorOn);
        o.outLen = rest;
        _head(o, payload);
        o.ben = bytes32(payload[128:160]);
        o.salt = bytes16(payload[224:240]);
        o.to = keccak256(payload[M_OUT:M_OUT + 32 * m]); // recipientsHash, header word 192
        if (memo != 0) {
            bytes calldata mm = payload[payload.length - memo:];
            if (bytes16(mm[0:16]) != o.salt) revert IPqzToken.MemoSaltMismatch();
            o.memoHash = keccak256(mm);
        }
    }

    /// @dev Every leg: not the sender, pairwise distinct, a PQZ holder (its key); the auditor's key when `auditorOn`,
    ///      and then neither the sender nor a leg is the auditor (F-4, `_noAuditorParty`).
    function _legs(Op memory o, Env memory e, bytes calldata payload) internal view {
        PqzStorage storage s = $();
        uint256 m = o.legs;
        o.keys = new address[](m);
        _noAuditorParty(o, o.from);
        for (uint256 j; j < m; ++j) {
            bytes32 ua = bytes32(payload[M_OUT + 32 * j:M_OUT + 32 * j + 32]);
            if (ua == o.from) revert IPqzToken.SelfTransfer();
            _noAuditorParty(o, ua);
            for (uint256 k; k < j; ++k) {
                if (bytes32(payload[M_OUT + 32 * k:M_OUT + 32 * k + 32]) == ua) revert IPqzToken.DuplicateRecipient(ua);
            }
            o.keys[j] = _creditKey(e.registry, ua);
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

    /// @dev The op blob `R ‖ v_f`, the debit (the fee `txFee + M · decoyFee` out of `totalShielded`; the token pays it
    ///      from `SHIELD_POOL`, D19), a credit per leg, the entry by mode.
    function _settleMulti(Op memory o, bytes calldata payload) internal returns (bytes32 ref) {
        bytes calldata out = payload[M_OUT + 32 * o.legs:M_OUT + 32 * o.legs + o.outLen];
        bytes memory blob = _bundleMulti(o, payload, out);
        address ptr = SSTORE2.write(blob);
        _debit(o, ptr, 16, blob.length - PqzCt.VP);
        ref = _sent(o);
        _creditLegs(o, ref, payload, ptr);
        _entry(o, ref, ptr, payload, 18 + 40 * o.legs);
        bytes32[] memory rec = new bytes32[](o.legs);
        for (uint256 j; j < o.legs; ++j) rec[j] = bytes32(payload[M_OUT + 32 * j:M_OUT + 32 * j + 32]);
        emit IConfidentialToken.ConfidentialTransferMulti(
            ref, o.from, o.ben, o.fee, o.sendCounter, rec, uint8(o.mode), ptr
        );
    }

    /// @dev `pending[UA_j] ← (u_{g(j)}, v_j)` of the blob (packed offsets, `g` = `_groupOf`), in leg order.
    function _creditLegs(Op memory o, bytes32 ref, bytes calldata payload, address ptr) internal {
        uint256 us = 16 + PqzCt.PKP * o.groups;
        uint256 ls = 32 + PqzCt.VP * (1 + o.auditorOn);
        for (uint256 j; j < o.legs; ++j) {
            bytes32 ua = bytes32(payload[M_OUT + 32 * j:M_OUT + 32 * j + 32]);
            _credit(ua, ptr, 16 + PqzCt.PKP * _groupOf(j, o.auditorOn), us + ls * j, ref);
        }
    }

    /// @dev The op blob `R ‖ v_f`, `R = salt ‖ u_0 … u_{G−1} ‖ (v_j ‖ [v_{a,j}] ‖ word(UA_j))_{j<M}` — for `M = 1` the
    ///      single transfer's bundle exactly (CTR-PQZ-26). Every `u`, `v` packed (P46), written in ascending order (each
    ///      pack spills `32 − GROUP` zero bytes past its end; 32 bytes of slack).
    function _bundleMulti(Op memory o, bytes calldata payload, bytes calldata out) internal pure returns (bytes memory r) {
        uint256 m = o.legs;
        uint256 us = PqzCt.PK * o.groups; // in `out` (64-bit lanes)
        uint256 ps = PqzCt.PKP * o.groups; // in the blob
        uint256 ls = 32 + PqzCt.VP * (1 + o.auditorOn);
        uint256 len = 16 + ps + ls * m + PqzCt.VP;
        r = new bytes(len + 32);
        _put(r, 0, abi.encodePacked(o.salt));
        PqzCt.packCd(r, 16, out[0:us]);
        for (uint256 j; j < m; ++j) {
            uint256 d = 16 + ps + ls * j;
            PqzCt.packCd(r, d, out[us + PqzCt.V * j:us + PqzCt.V * (j + 1)]);
            if (o.auditorOn == 1) PqzCt.packCd(r, d + PqzCt.VP, out[us + PqzCt.V * (m + 1 + j):us + PqzCt.V * (m + 2 + j)]);
            _putCd(r, d + ls - 32, payload[M_OUT + 32 * j:M_OUT + 32 * j + 32]);
        }
        PqzCt.packCd(r, 16 + ps + ls * m, out[us + PqzCt.V * m:us + PqzCt.V * (m + 1)]);
        assembly ("memory-safe") { mstore(r, len) }
    }

    function _putCd(bytes memory r, uint256 off, bytes calldata x) internal pure {
        assembly ("memory-safe") { calldatacopy(add(add(r, 32), off), x.offset, x.length) }
    }

    /// @dev The op blob `u' ‖ v_f` (D1; packed, P46), the debit (the amount and the fee out of `totalShielded`; the
    ///      token moves both from `SHIELD_POOL`, D19).
    function _settleBurn(Op memory o, bytes calldata out) internal {
        bytes memory b = new bytes(PqzCt.CTP + 32);
        PqzCt.packCd(b, 0, out);
        uint256 ctp = PqzCt.CTP;
        assembly ("memory-safe") { mstore(b, ctp) }
        address ptr = SSTORE2.write(b);
        _debit(o, ptr, 0, PqzCt.PKP);
        _sent(o);
        emit IConfidentialToken.Unshielded(o.from, o.amount, o.recipient, ptr);
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
            if (e.recipient != 0) revert IPqzToken.RefreshRecipient(e.recipient);
            o.opTag = OP_REFRESH;
        } else {
            if (e.amount > s.maxShielded) revert IPqzToken.AmountOutOfRange(e.amount, s.maxShielded);
            if (e.recipient == 0) revert IPqzToken.ZeroRecipient();
            // D19: the pools are no payees (the unshield pays from `SHIELD_POOL`, the unwrap from a leg)
            if (e.recipient == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)) revert IUALedger.ShieldPoolNotPayable();
            if (e.recipient == MetaTxLib.pad(MetaTxLib.UA_POOL)) revert IUALedger.UAPoolNotPayable();
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

    /// @dev `header ‖ pk_f ‖ T ‖ u' ‖ v_f` (`PqzSet.STMT_BURN` bytes).
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

    /// @dev Words 0–2 of both payloads and the sender (`fromUA` at 96).
    function _head(Op memory o, bytes calldata payload) internal pure {
        uint256 p = uint256(bytes32(payload[0:32]));
        if (p > type(uint64).max) revert IPqzToken.BadPayload(payload.length);
        o.p = uint64(p);
        o.validUntil = uint256(bytes32(payload[32:64]));
        o.shieldIn = uint256(bytes32(payload[64:96]));
        o.from = bytes32(payload[96:128]);
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
        uint256 fmp;
        assembly ("memory-safe") { fmp := mload(0x40) }
        try IUARegistry(o.registry).requireAuthorized(o.from, UAKinds.PURPOSE_ZETHER_AUTH, d, UAKinds.uaSig(o.from, authSig)) {}
        catch (bytes memory err) {
            if (err.length == 4 && bytes4(err) == UAKinds.UAVerifyGas.selector) revert UAKinds.UAVerifyGas();
            revert IPqzToken.AuthRejected();
        }
        // typed-signing R1 (until C2 types `authSig`): the `UASig` copies are dead after the call, so the free pointer
        // goes back to `fmp` (read after `buf`). The conversion still raises the memory high-water mark past the statement
        // buffer once; the verifier call below reuses that memory
        assembly ("memory-safe") { mstore(0x40, fmp) }
        assembly ("memory-safe") {
            calldatacopy(add(add(buf, 37), len), proof.offset, proof.length)
        }
        if (!verdict($().pqz, buf)) revert IPqzToken.ProofRejected();
    }

// ------------------------------------------------------------------ PqzViewLib, PqzTransferLib, PqzBurnLib

    /// @notice The statement an entry point would build for `payload` (`op` 7 multi, 1 single, 2 burn / refresh with
    ///         `e.amount`, `e.recipient`), after every cheap check; a transfer payload with the memo is commit-reveal.
    ///         `T` is read from the current state (plan 5h D5). Public, so the builders stay in the library and out of
    ///         the tokens' code.
    function statementOf(uint8 op, PqzCore.Env memory e, bytes calldata payload)
        public view returns (bytes memory)
    {
        bytes memory buf;
        if (op == 7) {
            e.mode = PqzCore.multiHasMemo(payload) ? ZetherTypes.TransferMode.HASH : PqzCore._defaultMode();
            (, buf) = PqzCore.prepareMulti(e, payload, payload[0:0], 0);
        } else if (op == 1) {
            if (payload.length < PqzCore.T_OUT) revert IPqzToken.BadPayload(payload.length); // C0-13
            uint256 l = payload.length - PqzCore.T_OUT;
            e.mode = l == PqzCore.OUT_ON + PqzCore.MEMO || l == PqzCore.OUT_OFF + PqzCore.MEMO ? ZetherTypes.TransferMode.HASH : PqzCore._defaultMode();
            (, buf) = PqzCore.prepareTransfer(e, payload, payload[0:0], 0);
        } else {
            (, buf) = PqzCore.prepareBurn(e, payload, payload[0:0], 0);
        }
        return PqzCore._stmtOf(buf);
    }

    /// @notice One-recipient transfer: checks, statement, `authSig`, proof, then the debit, the credit, the entry by
    ///         `mode` (BUNDLE or commit-reveal HASH; NONE retired, D11). Returns `paid`: the token moves exactly it
    ///         through `SHIELD_POOL` (D19).
    ///      Arguments ordered for the stack: the ones used last on top.
    function transfer(
        PqzCore.Env memory e,
        bytes calldata payload,
        bytes calldata hint,
        bytes calldata proof,
        bytes calldata authSig
    ) public returns (bytes32 ref, PqzCore.Paid memory paid) {
        (PqzCore.Op memory o, bytes memory buf) = PqzCore.prepareTransfer(e, payload, hint, proof.length);
        PqzCore._check(o, buf, proof, authSig);
        ref = PqzCore._settleTransfer(o, payload);
        paid = PqzCore._paid(o);

    /// @notice `R_BURN`: the debit with `amount` public (0 = refresh); the token then moves `paid` (D19)
    ///         and pays `amount · shieldScale`.
    function unshield(
        PqzCore.Env memory e,
        bytes calldata payload,
        bytes calldata hint,
        bytes calldata proof,
        bytes calldata authSig
    ) public returns (PqzCore.Paid memory paid) {
        (PqzCore.Op memory o, bytes memory buf) = PqzCore.prepareBurn(e, payload, hint, proof.length);
        PqzCore._check(o, buf, proof, authSig);
        PqzCore._settleBurn(o, payload[PqzCore.B_OUT:PqzCore.B_OUT + PqzCt.CT]);
        paid = PqzCore._paid(o);

// ------------------------------------------------------------------ test/pqz/PqzShared.t.sol (the argument is gone)

    /// `beneficiary` must be the payload's beneficiary word (op 1 at 160, op 7 and the burn at 128).
    function test_beneficiaryMismatch() public {
        _fund(tok, alice, 100);
        bytes memory p1 = _payload(1, 0, alice, bob, carol, _out(1, false), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxConfidentialTransferSingle(p1, hex"c0de", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bob));
        tok.mtxConfidentialTransferSingleCompact(p1, hex"c0de", _mlAuth(), bob, "");
        bytes32[] memory rec = new bytes32[](1);
        rec[0] = bob;
        bytes memory p7 = _mpayload(1, 0, alice, carol, rec, _blob(2, _outLen(1, false)), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxConfidentialTransfer(p7, hex"c0de", _mlAuth(), bytes32(0), "");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxConfidentialTransferCompact(p7, hex"c0de", _mlAuth(), bytes32(0), "");
        bytes memory pb = _burnPl(3, carol);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BeneficiaryMismatch.selector, carol, bytes32(0)));
        tok.mtxUnshield(pb, hex"c0de", _mlAuth(), bytes32(0), "", 0, bytes32(0));
        // too short for the word: the library's `BadPayload`
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.BadPayload.selector, 100));
        tok.mtxConfidentialTransfer(new bytes(100), hex"c0de", _mlAuth(), carol, "");
        tok.mtxConfidentialTransferSingle(p1, hex"c0de", _mlAuth(), carol, ""); // the matching word passes
    }
