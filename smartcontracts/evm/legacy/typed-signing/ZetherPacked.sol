// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

// legacy/typed-signing: NOT COMPILED. The packed classical Zether surface as it stood before typed-signing C3: the
// `(payload, proof, auth, beneficiary, accHint[, …])` entries of the shared `IConfidentialToken` signature, the byte slices of
// `ZetherLib` over the packed payload, the `ZetherStatements` views on it, and the owner digests under the tags
// `ZETHER_ROLLOVER_V1` / `ZETHER_SET_ROLLOVER_MODE_V1`. Superseded by the explicit parameters (`IZetherToken.ZetherSingle`,
// `ZetherMulti`, `ZetherBurn`, TS-D17) and the typed `ZetherRollOver` / `ZetherSetRollOverMode` (TS-D19), which give the same
// statement and record bytes. Reference only: the fragments below are out of their contracts.

// ------------------------------------------------------------------ ZetherLayer

    /// @notice The token's default: the record stored (`BUNDLE` token) or commit-reveal (`COMPACT` token).
    function mtxConfidentialTransfer(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        return _multi(payload, proof, auth, beneficiary, accHint, ZetherLib.defaultMode());
    }

    function mtxConfidentialTransferCompact(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        return _multi(payload, proof, auth, beneficiary, accHint, ZetherTypes.TransferMode.HASH);
    }

    function mtxConfidentialTransferSingle(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        _noAuth(auth, accHint);
        ZetherTypes.UA ben = ZetherTypes.UA.wrap(beneficiary);
        (bytes32 ref, uint256 fee) = ZetherLib.transferSingle(payload, proof, ben, _env());
        _fromPool(ben, fee);
        return ref;
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement binds `amount` and `recipient`; moves `amount · shieldScale` public units from
    ///         `SHIELD_POOL` to `recipient` (D19): a padded address (not a pool) or a registered SIGNING UA, credited on
    ///         the UA ledger (CTR-ZTH-51); then the fee to the beneficiary.
    function mtxUnshield(bytes calldata payload, bytes calldata proof, bytes calldata auth, bytes32 beneficiary,
        bytes calldata accHint, uint256 amount, bytes32 recipient) external nonReentrant
    {
        _noAuth(auth, accHint);
        _requireRecipient(recipient);
        ZetherTypes.UA ben = ZetherTypes.UA.wrap(beneficiary);
        uint256 fee = ZetherLib.unshield(payload, proof, ben, amount, recipient, _env());
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), recipient, amount * ZetherLib.$().shieldScale);
        _fromPool(ben, fee);
    }

    /// @dev The shared signature's `auth` and `accHint` are PQZ's: empty here (the proof alone authorises, UA-6).
    function _noAuth(bytes calldata auth, bytes calldata accHint) internal pure {
        if (auth.length != 0) revert AuthNotEmpty();
        if (accHint.length != 0) revert AccHintNotEmpty();
    }

    /// @dev The multi-recipient entry points by stored form `mode`: the library's `txFee` to the beneficiary, then its
    ///      `decoyFee` to EVERY leg, the real recipient included (owner 2026-10-20: uniform, so it reveals no decoy).
    function _multi(bytes calldata payload, bytes calldata proof, bytes calldata auth, bytes32 beneficiary,
        bytes calldata accHint, ZetherTypes.TransferMode mode) private returns (bytes32 ref)
    {
        _noAuth(auth, accHint);
        ZetherTypes.UA ben = ZetherTypes.UA.wrap(beneficiary);
        ZetherLib.Paid memory f;
        (ref, f) = ZetherLib.transferMulti(payload, proof, ben, mode, _env());
        _fromPool(ben, f.txFee);
        if (f.decoyFee != 0) for (uint256 j; j < f.legs.length; ++j) _fromPool(f.legs[j], f.decoyFee);
    }


// ------------------------------------------------------------------ WrappedZetherToken

    /// @notice The unshield proof (`x.amount` and `x.recipient` in the statement; a direct call also binds
    ///         `x.underlying` and `x.minOut`), then leg `x.underlying` pays `⌊amount·shieldScale·den/num⌋ ≥ minOut` from
    ///         its reserve to `x.recipient` — an address, or a derived UA through the leg's `transferToUA`
    ///         (`UALegNotLedger` otherwise, CTR-ZTH-51) — burning `amount·shieldScale` from `SHIELD_POOL`.
    function mtxUnshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        bytes calldata auth,
        bytes32 beneficiary,
        bytes calldata accHint,
        Unwrap calldata x
    ) external nonReentrant {
        _noAuth(auth, accHint);
        _unshieldUnwrap(payload, proof, ZetherTypes.UA.wrap(beneficiary), x);
    }

    /// @dev The leg first (cheap), the proof and the debit, then the payout from the leg's reserve (CEI: the debit
    ///      before the one outside call).
    function _unshieldUnwrap(
        bytes calldata payload,
        bytes calldata proof,
        ZetherTypes.UA beneficiary,
        Unwrap calldata x
    ) private {
        uint256 i = WrappedLib.indexOf(x.underlying);
        // a derived recipient: the leg's `transferToUA` checks it
        if (UAKinds.inNativeSpace(x.recipient)) _requirePayee(address(uint160(uint256(x.recipient))));
        uint256 fee = ZetherLib.unshield(payload, proof, beneficiary, x.amount, x.recipient, _envUnwrap(x.underlying, x.minOut));
        uint256 wrapped = x.amount * ZetherLib.$().shieldScale;
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), bytes32(0), wrapped); // D19: burn from the pool
        _fromPool(beneficiary, fee);
        WrappedLib.payOutTo(i, x.recipient, wrapped, x.minOut);
    }

    /// @dev Relayed: the envelope binding (the signature covers `data`, the leg and `minOut` with it); direct: the leg
    ///      and `minOut` (`ZetherLib.unwrapBinding`) under `ZTX_V1_DIRECT`.
    function _envUnwrap(address u, uint256 minOut) private view returns (ZetherLib.Env memory) {
        bytes32 b = _ticketBinding();
        if (b != bytes32(0)) return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.TAG_RELAYED, b, BURN_VERIFIER);
        return ZetherLib.Env(
            _REGISTRY, CHAIN_UID, ZetherLib.TAG_DIRECT, ZetherLib.unwrapBinding(u, minOut), BURN_VERIFIER
        );
    }


// ------------------------------------------------------------------ ZetherLib: the payload layout

    /// @dev Every payload starts `be32(accSeq) ‖ be32(sendCounter) ‖ be32(validUntilBlock)` (`P_HEAD`). Where the points
    ///      start: the single payload after `… ‖ salt(16)`, the multi-recipient one after `… ‖ salt(16) ‖ be32(M) ‖
    ///      be32(decoyFee)`, the unshield one at `P_HEAD` (zether.md §10, §11). A multi-recipient leg is
    ///      `Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j` (`4P`, review C0-1).
    uint256 private constant P_HEAD = 96;
    uint256 private constant S_PTS = 112;
    uint256 private constant M_PTS = 176;

    /// @notice The single-recipient format (BUNDLE tokens only): checks, the proof (the only authority), then
    ///         `acc_f −= (C_deb + [fee]G, D_out)`, `pend_t += (C_out, D_out)`, `totalShielded -= fee` (the fee is paid in public units by the layer), `sendCounter_f++`;
    ///         the record `salt ‖ B` stored in full.
    function transferSingle(bytes calldata payload, bytes calldata proof, ZetherTypes.UA beneficiary, Env memory e)
        public returns (bytes32, uint256)
    {
        (Ctx memory c, Prepared memory pp) = _prepareSingle(payload, beneficiary, e);
        _check(c, pp, proof, OP_TRANSFER);
        return (_settleSingle(c, pp, payload), pp.fee);
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
        bytes calldata pts = payload[S_PTS:];
        uint256 p = c.p;
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        _debit(c, s.acct[pp.from], pts[4 * p:5 * p], pts[3 * p:4 * p], pp.fee);
        _credit(s, to, pts[2 * p:3 * p], pts[3 * p:4 * p]);
        _payFee(s, pp);
        entryRef = _sent(s, c, pp);
        s.entries[entryRef] = bytes.concat(pp.salt, pts[p:2 * p], pts[2 * p:4 * p], pts[5 * p:6 * p]);
        emit IConfidentialToken.ConfidentialTransfer(entryRef, ZetherTypes.UA.unwrap(pp.from), ZetherTypes.UA.unwrap(to),
            ZetherTypes.UA.unwrap(pp.beneficiary), pp.fee, pp.sendCounter, address(0));
    }

    /// @notice `M` recipients, one proof (CTR-ZTH-37/38): `acc_f −= (C_deb + [fee]G, D_out)` with `fee = txFee + M ·
    ///         decoyFee`, every `pend_tj += (C_out_j, D_out)`, `totalShielded -= fee`, `sendCounter_f++` once; the record by
    ///         `mode` (the stored form, CTR-ZTH-38), which a `COMPACT` token allows only as HASH. Returns `Paid`: `txFee`
    ///         to the beneficiary and `decoyFee` to each leg, decoys included (owner 2026-10-20).
    function transferMulti(
        bytes calldata payload,
        bytes calldata proof,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode,
        Env memory e
    ) public returns (bytes32, Paid memory) {
        (Ctx memory c, Prepared memory pp) = _prepareMulti(payload, beneficiary, mode, e);
        _check(c, pp, proof, OP_MULTI_HASH);
        return (_settleMulti(c, pp, payload, mode), Paid(pp.fee - pp.to.length * pp.decoyFee, pp.decoyFee, pp.to));
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
        _debit(c, s.acct[pp.from], payload[M_PTS + 2 * p:M_PTS + 3 * p], payload[M_PTS + p:M_PTS + 2 * p], pp.fee);
        _creditLegs(s, pp.to, payload, p);
        _payFee(s, pp);
        entryRef = _sent(s, c, pp);
        _storeRecord(s, p, entryRef, payload, pp, mode);
        ZetherTypes.UA[] memory to = pp.to;
        bytes32[] memory rec;
        assembly ("memory-safe") { rec := to } // `UA` is `bytes32`: the same memory array
        emit IConfidentialToken.ConfidentialTransferMulti(entryRef, ZetherTypes.UA.unwrap(pp.from),
            ZetherTypes.UA.unwrap(pp.beneficiary), pp.fee, pp.sendCounter, rec, uint8(mode), address(0));
    }

    /// @dev Every `pend_tj += (C_out_j, D_out)`, decoys included.
    function _creditLegs(ZetherStorage storage s, ZetherTypes.UA[] memory to, bytes calldata payload, uint256 p) private {
        bytes calldata dOut = payload[M_PTS + p:M_PTS + 2 * p];
        for (uint256 j; j < to.length; ++j) {
            uint256 o = _leg(p, j);
            _credit(s, to[j], payload[o + p:o + 2 * p], dOut);
        }
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement (zether.md §8.2, built name `burn`): checks, the proof (the only authority), then
    ///         `acc_f.C −= [amount + fee]G`, `totalShielded -= fee` (the fee is paid in public units by the layer), `sendCounter_f++`, `totalShielded −= amount`. The token
    ///         then pays `amount · shieldScale` public-equivalent units to `recipient` (a padded address or a derived UA,
    ///         CTR-ZTH-51: the statement's recipient word either way) from the pool or a leg's underlying.
    function unshield(
        bytes calldata payload,
        bytes calldata proof,
        ZetherTypes.UA beneficiary,
        uint256 amount,
        bytes32 recipient,
        Env memory e
    ) public returns (uint256) {
        (Ctx memory c, Prepared memory pp) = _prepareUnshield(payload, amount, recipient, beneficiary, e);
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

    function _prepareUnshield(
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary,
        Env memory e
    ) private view returns (Ctx memory c, Prepared memory pp) {
        ZetherStorage storage s = $();
        c = ctx(s, e);
        pp = prepareUnshield(c, acct(s.acct[unshieldFrom(payload, c.p)], c.p), payload, amount, recipient, beneficiary);
    }

    /// @notice Single format: `be32(accSeq) ‖ be32(sendCounter) ‖ be32(validUntilBlock) ‖ salt(16) ‖ Y_f ‖ Y_t ‖ C_out ‖
    ///         D_out ‖ C_deb ‖ C_aud`.
    function singleFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length != S_PTS + 6 * p) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[S_PTS:S_PTS + p]);
    }

    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ be32(validUntilBlock) ‖ salt(16) ‖ be32(M) ‖ be32(decoyFee) ‖ Y_f ‖
    ///         D_out ‖ C_deb ‖ (Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j)_j`,
    ///         then the sender memo (`17 + 40·M` bytes, CTR-ZTH-50) on commit-reveal only (checked by the form,
    ///         `prepareMulti`).
    function multiFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length < M_PTS + 3 * p) revert IZetherToken.BadPayload(payload.length);
        uint256 m = uint256(bytes32(payload[112:144]));
        if (m == 0 || m > MAX_RECIPIENTS) revert IZetherToken.BadRecipientCount(m);
        uint256 legsEnd = _leg(p, m);
        if (payload.length != legsEnd && payload.length != legsEnd + 17 + 40 * m) {
            revert IZetherToken.BadPayload(payload.length);
        }
        return ZetherTypes.toUA(payload[M_PTS:M_PTS + p]);
    }

    /// @notice `be32(accSeq) ‖ be32(sendCounter) ‖ be32(validUntilBlock) ‖ Y_f`.
    function unshieldFrom(bytes calldata payload, uint256 p) internal pure returns (ZetherTypes.UA) {
        if (payload.length != P_HEAD + p) revert IZetherToken.BadPayload(payload.length);
        return ZetherTypes.toUA(payload[P_HEAD:P_HEAD + p]);
    }

    /// @notice Every cheap check before verification: the mode, self, registration, fee, `accSeq`, `sendCounter`,
    ///         `validUntilBlock`, the auditor key as a party.
    function prepareSingle(Ctx memory c, Acct memory a, bytes calldata payload, ZetherTypes.UA beneficiary)
        internal view returns (Prepared memory pp)
    {
        if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT) {
            revert IZetherToken.TransferEntryDisabled(uint8(c.disclosureMode));
        }
        uint256 p = c.p;
        bytes calldata pts = payload[S_PTS:];
        pp.from = ZetherTypes.toUA(pts[0:p]);
        ZetherTypes.UA to = ZetherTypes.toUA(pts[p:2 * p]);
        if (ZetherTypes.UA.unwrap(pp.from) == ZetherTypes.UA.unwrap(to)) revert IZetherToken.SelfTransfer();
        _requireRegistered(c, pp.from);
        _requireRegistered(c, to);
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        (pp.sendCounter, pp.validUntil) = _checkSeqs(a, payload);
        pp.salt = bytes16(payload[P_HEAD:S_PTS]);
        bytes memory ya = _auditorPoint(c, _isO(pts[5 * p:6 * p]) ? 1 : 0, 1);
        ZetherTypes.UA[] memory parties = new ZetherTypes.UA[](1);
        parties[0] = to;
        _noAuditorParty(ya, pp.from, parties);
        pp.statement = bytes.concat(
            _header(c, OP_TRANSFER, c.psid, a, pp, 0, 0), pts[0:2 * p], ya, a.accC, a.accD, pts[2 * p:6 * p]
        );
    }

    /// @notice As `prepareSingle`, for `M` recipients: pairwise distinct, none the sender (nor, with the auditor on, the
    ///         auditor key: `AuditorKeyAsParty`), all registered; a `COMPACT`
    ///         token takes HASH only; the memo exactly on HASH, its clear salt the payload's, its hash in the header;
    ///         `minDecoyFee ≤ decoyFee < 2^64` (`DecoyFeeOutOfRange`) and the header's fee word `txFee + M · decoyFee`
    ///         `< 2^64`, so the proof binds the sender's `decoyFee` (no relation change: the fee is already public).
    function prepareMulti(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode
    ) internal view returns (Prepared memory pp) {
        if (c.disclosureMode == ZetherTypes.DisclosureMode.COMPACT && mode != ZetherTypes.TransferMode.HASH) {
            revert IZetherToken.TransferEntryDisabled(uint8(c.disclosureMode));
        }
        uint256 p = c.p;
        pp.from = ZetherTypes.toUA(payload[M_PTS:M_PTS + p]);
        _requireRegistered(c, pp.from);
        pp.to = _recipients(c, payload, pp.from, uint256(bytes32(payload[112:144])));
        pp.beneficiary = beneficiary;
        uint256 d = uint256(bytes32(payload[144:M_PTS]));
        if (d < c.minDecoyFee || d >= VALUE_BOUND) revert IZetherToken.DecoyFeeOutOfRange(d, c.minDecoyFee);
        pp.decoyFee = d;
        pp.fee = _innerFee(c, beneficiary) + pp.to.length * d;
        if (pp.fee >= VALUE_BOUND) revert IZetherToken.AmountOutOfRange(pp.fee, VALUE_BOUND);
        (pp.sendCounter, pp.validUntil) = _checkSeqs(a, payload);
        pp.salt = bytes16(payload[P_HEAD:P_HEAD + 16]);
        bytes calldata memo = payload[_leg(p, pp.to.length):];
        if (memo.length != (mode == ZetherTypes.TransferMode.HASH ? 17 + 40 * pp.to.length : 0)) {
            revert IZetherToken.BadPayload(payload.length);
        }
        if (memo.length != 0) {
            if (bytes16(memo[0:16]) != pp.salt) revert IZetherToken.MemoSaltMismatch();
            pp.memoHash = keccak256(memo);
        }
        pp.statement = _multiStatement(c, a, payload, pp, mode);
    }

    /// @notice `0 < amount ≤ maxShielded` before the statement (`amount + fee < 2^65 < r`), recipient non-zero.
    function prepareUnshield(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary
    ) internal view returns (Prepared memory pp) {
        if (amount == 0 || amount > c.maxShielded) revert IZetherToken.AmountOutOfRange(amount, c.maxShielded);
        if (recipient == 0) revert IZetherToken.ZeroRecipient();
        uint256 p = c.p;
        pp.from = ZetherTypes.toUA(payload[P_HEAD:P_HEAD + p]);
        _requireRegistered(c, pp.from);
        pp.beneficiary = beneficiary;
        pp.fee = _innerFee(c, beneficiary);
        (pp.sendCounter, pp.validUntil) = _checkSeqs(a, payload);
        pp.statement = bytes.concat(
            _header(c, OP_BURN, c.psid, a, pp, amount, recipient), payload[P_HEAD:P_HEAD + p], a.accC, a.accD
        );
    }

    /// @dev `header ‖ Y_f ‖ Y_a ‖ C_acc ‖ D_acc ‖ D_out ‖ C_deb ‖ be32(M) ‖ (Y_tj ‖ C_out_j ‖ C_aud_j ‖ D_aud_j)_j`; the
    ///      mode is in `opTag`.
    function _multiStatement(
        Ctx memory c,
        Acct memory a,
        bytes calldata payload,
        Prepared memory pp,
        ZetherTypes.TransferMode mode
    ) private view returns (bytes memory) {
        uint256 p = c.p;
        bytes32 op = mode == ZetherTypes.TransferMode.HASH ? OP_MULTI_HASH : OP_MULTI_BUNDLE;
        bytes memory ya = _auditorPoint(c, _audOff(payload, p, pp.to.length), pp.to.length);
        _noAuditorParty(ya, pp.from, pp.to);
        bytes memory head = bytes.concat(
            _header(c, op, c.ver.proofSystemIdMulti(), a, pp, 0, 0), payload[M_PTS:M_PTS + p], ya, a.accC, a.accD
        );
        head = bytes.concat(head, payload[M_PTS + p:M_PTS + 3 * p], payload[112:144]);
        return bytes.concat(head, payload[M_PTS + 3 * p:_leg(p, pp.to.length)]);
    }

    /// @dev Where leg `j` starts in a multi-recipient payload (and, for `j = M`, where the legs end).
    function _leg(uint256 p, uint256 j) private pure returns (uint256) {
        return M_PTS + 3 * p + 4 * p * j;
    }

    /// @dev The recipients: none the sender, pairwise distinct, registered.
    function _recipients(Ctx memory c, bytes calldata payload, ZetherTypes.UA from, uint256 m)
        private view returns (ZetherTypes.UA[] memory to)
    {
        uint256 p = c.p;
        to = new ZetherTypes.UA[](m);
        for (uint256 j; j < m; ++j) {
            uint256 o = _leg(p, j);
            to[j] = ZetherTypes.toUA(payload[o:o + p]);
            bytes32 t = ZetherTypes.UA.unwrap(to[j]);
            if (t == ZetherTypes.UA.unwrap(from)) revert IZetherToken.SelfTransfer();
            for (uint256 k; k < j; ++k) if (ZetherTypes.UA.unwrap(to[k]) == t) revert IZetherToken.DuplicateRecipient(to[j]);
            _requireRegistered(c, to[j]);
        }
    }

    /// @dev `accSeq`, `sendCounter` and `block.number ≤ validUntilBlock` (review C0-9, the PQZ header's rule; the word
    ///      is in the statement, so the proof binds it).
    function _checkSeqs(Acct memory a, bytes calldata payload) private view returns (uint64, uint256 validUntil) {
        uint256 provedAccSeq = uint256(bytes32(payload[0:32]));
        uint256 provedSend = uint256(bytes32(payload[32:64]));
        validUntil = uint256(bytes32(payload[64:P_HEAD]));
        if (block.number > validUntil) revert IZetherToken.TransferExpired(validUntil);
        if (provedAccSeq != a.accSeq) revert IZetherToken.StaleAccSeq(a.accSeq, provedAccSeq);
        if (provedSend != a.sendCounter) revert IZetherToken.StaleSendCounter(a.sendCounter, provedSend);
        return (a.sendCounter, validUntil);
    }

    /// @dev BUNDLE: the record `R` inline in state; HASH (commit-reveal): `R` by SSTORE2 (the slot holds the pointer), the
    ///      sender memo next to it, `R` also in `TransferBundles` (CTR-ZTH-38, CTR-ZTH-50, review C0-3). Every mode keeps
    ///      `R` in state.
    function _storeRecord(
        ZetherStorage storage s,
        uint256 p,
        bytes32 entryRef,
        bytes calldata payload,
        Prepared memory pp,
        ZetherTypes.TransferMode mode
    ) private {
        uint256 legsEnd = _leg(p, pp.to.length);
        bytes memory r = _record(pp.salt, payload[M_PTS + 3 * p:legsEnd], payload[M_PTS + p:M_PTS + 2 * p], p);
        if (mode == ZetherTypes.TransferMode.BUNDLE) {
            s.entries[entryRef] = r;
        } else {
            s.entryPtrs[entryRef] = SSTORE2.write(r);
            s.memos[entryRef] = payload[legsEnd:];
            emit IZetherToken.TransferBundles(entryRef, r);
        }
    }

    /// @dev `R = salt ‖ B_1 ‖ … ‖ B_M`, `B_j = Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j ‖ D_aud_j` (5 points, review C0-1; the
    ///      single format's `B` keeps 4, its auditor copy being under `s`).
    function _record(bytes16 salt, bytes calldata legs, bytes calldata dOut, uint256 p) private pure returns (bytes memory b) {
        b = abi.encodePacked(salt);
        for (uint256 o; o < legs.length; o += 4 * p) {
            b = bytes.concat(b, legs[o:o + 2 * p], dOut, legs[o + 2 * p:o + 4 * p]);
        }
    }

    /// @dev Number of the `m` legs with `C_aud_j = O` (the verifier then requires `D_aud_j = O` too).
    function _audOff(bytes calldata payload, uint256 p, uint256 m) private pure returns (uint256 n) {
        for (uint256 j; j < m; ++j) {
            uint256 o = _leg(p, j) + 2 * p;
            if (_isO(payload[o:o + p])) ++n;
        }
    }


// ------------------------------------------------------------------ ZetherLib: the owner digests

    /// @notice CTR-ZTH-16/17: `lastRolledPendingSeq < expectedPendingSeq ≤ pendingSeq`, signed by the account (a Schnorr
    ///         by `x` through `registry.requireAuthorized` under `zether-owner`, UA-6 U9) over `ZETHER_ROLLOVER_V1` with
    ///         `chainid`, `chainUid`, the token and `accSeq`.
    function rollOverSigned(
        ZetherTypes.UA ua,
        uint64 expectedPendingSeq,
        uint64 validUntilBlock,
        bytes calldata sig,
        Env memory e
    ) public {
        if (block.number > validUntilBlock) revert IZetherToken.RollOverExpired(validUntilBlock);
        if (!registeredOn(e.registry, ua)) revert IZetherToken.AccountNotRegistered(ua); // Zether UA only (2026-10-20)
        ZetherStorage storage s = $();
        Account storage a = s.acct[ua];
        if (a.pendingSeq < expectedPendingSeq || expectedPendingSeq <= a.lastRolledPendingSeq) {
            revert IZetherToken.PendingSeqMismatch(expectedPendingSeq, a.pendingSeq);
        }
        bytes32 digest = keccak256(abi.encode(
            TAG_ROLLOVER, block.chainid, e.chainUid, address(this), ua, a.accSeq, expectedPendingSeq, validUntilBlock
        ));
        _requireOwner(e, ua, digest, sig);
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
        if (!registeredOn(e.registry, ua)) revert IZetherToken.AccountNotRegistered(ua); // Zether UA only (2026-10-20)
        Account storage a = $().acct[ua];
        bytes32 digest = keccak256(abi.encode(
            TAG_SET_MODE, block.chainid, e.chainUid, address(this), ua, uint8(mode), a.modeNonce, validUntilBlock
        ));
        _requireOwner(e, ua, digest, sig);
        a.mode = mode;
        a.modeNonce += 1;
        emit IZetherToken.RollOverModeChanged(ua, mode);
    }


// ------------------------------------------------------------------ ZetherStatements

    /// @notice The multi-recipient statement by its stored form `mode`: BUNDLE (`mtxConfidentialTransfer` on a `BUNDLE` token), HASH
    ///         (`mtxConfidentialTransferCompact`, and `mtxConfidentialTransfer` on a `COMPACT` token; the payload ends with the memo).
    ///         `TransferEntryDisabled` for a form other than HASH on a `COMPACT` token, the
    ///         auditor errors by `auditorMode`.
    function transferStatement(
        address token,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        ZetherTypes.TransferMode mode,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.multiFrom(payload, c.p));
        return ZetherLib.prepareMulti(c, a, payload, beneficiary, mode).statement;
    }

    /// @notice The single-recipient statement (`mtxConfidentialTransferSingle`).
    function transferStatementSingle(
        address token,
        bytes calldata payload,
        ZetherTypes.UA beneficiary,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.singleFrom(payload, c.p));
        return ZetherLib.prepareSingle(c, a, payload, beneficiary).statement;
    }

    /// @notice The unshield statement (`mtxUnshield`; built: `burnStatement`).
    function unshieldStatement(
        address token,
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.tagOf(envelopeBinding), envelopeBinding);
    }

    /// @notice The statement of `mtxUnshieldUnwrap` on an `WRAPPED_ZETHER` token: relayed, the envelope binding;
    ///         direct, `ZTX_V1_DIRECT` with the leg and `minOut` bound (`unwrapBinding`).
    function unshieldUnwrapStatement(
        address token,
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary,
        address u,
        uint256 minOut,
        bytes32 envelopeBinding
    ) external view returns (bytes memory) {
        if (envelopeBinding != bytes32(0)) {
            return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_RELAYED, envelopeBinding);
        }
        return _unshield(token, payload, amount, recipient, beneficiary, ZetherLib.TAG_DIRECT, unwrapBinding(u, minOut));
    }

    /// @notice The binding word of a direct `mtxUnshieldUnwrap` (controller ruling, pending the owner).
    function unwrapBinding(address u, uint256 minOut) public pure returns (bytes32) {
        return ZetherLib.unwrapBinding(u, minOut);
    }

    function _unshield(
        address token,
        bytes calldata payload,
        uint256 amount,
        bytes32 recipient,
        ZetherTypes.UA beneficiary,
        bytes32 tag,
        bytes32 binding
    ) internal view returns (bytes memory) {
        ZetherLib.Ctx memory c = _ctx(token, tag, binding);
        ZetherLib.Acct memory a = _acct(token, ZetherLib.unshieldFrom(payload, c.p));
        return ZetherLib.prepareUnshield(c, a, payload, amount, recipient, beneficiary).statement;
    }


// ------------------------------------------------------------------ IConfidentialToken, the shared signatures

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
