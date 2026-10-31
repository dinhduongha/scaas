// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {PqzCore} from "./PqzCore.sol";
import {PqzBurnLib} from "./PqzBurnLib.sol";
import {PqzStateLib} from "./PqzStateLib.sol";
import {PqzTransferLib} from "./PqzTransferLib.sol";
import {PqzViewLib} from "./PqzViewLib.sol";
import {ENV_PQZ_VERIFIER} from "../factory/IFactoryToken.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title The PQZ layer of the kinds `NORMAL_PQZ` and `WRAPPED_PQZ` (CTR-PQZ-15, CTR-PQZ-22; P6g plan D1): the entry
///        points and views of pq-zero-knowledge.md §9.4; the state and the logic are the four libraries (`scaas.pqz`; D14).
/// @notice **UNAUDITED.** Any chain whose `PQZ` precompile passes the self-test (`PqzSafety`); never on Hedera.
///         A layer over the
///         public ERC-20 balance: `mtxShield` moves public units to `SHIELD_POOL` into a TRIVIAL pending entry (no
///         proof, any holder, free; plan 5h D18, D19), every debit may top up `shieldIn` from the signer's public
///         balance in the same call, `mtxUnshield` moves units out of the pool (to an address or a signing UA); fees
///         (txFee to the beneficiary, op 7's `decoyFee` to every leg) go from the pool to public UA-ledger balances. Nothing is minted or burnt by the
///         layer: `balanceOf(SHIELD_POOL) == totalShielded · shieldScale`. Ciphertexts, `acc` and the queue
///         live in state (plan 5h D1–D9): debits take an optional `accHint`, rollovers are `(ua, n)` by anyone. The verifier (precompile and proof system) is an
///         implementation immutable (CTR-ZTH-20 / CTR-PQZ-10), so the proof system is an attribute of the release; the
///         auditor UA and the two modes are fixed at creation. Every entry point is `nonReentrant`; the shared entry
///         points are `IConfidentialToken`'s (plan 5h D20), allowlisted on both relaying paths (fee class `ABSOLUTE`)
///         and never batched (CTR-PQZ-21); the rollover and `mtxPrepareAcc` are allowlisted too, never batched (Task R,
///         owner 2026-10-20). A holder is a signing UA: `auth` is that UA's own signature over the statement digest, and its PQZ key is a record attribute
///         (UA-6 U7); a UA without the key is refused as sender, leg, beneficiary, shield target and auditor. The shared
///         `beneficiary` must be the payload's (`BeneficiaryMismatch`).
abstract contract PqzLayer is MetaTokenBase, IPqzToken {
    /// @dev The `UAPqzVerifier` of this release; `init` takes the precompile and the proof system from it.
    address internal immutable PQZ_VERIFIER;

    /// @dev `env.deps = [UAPqzVerifier]` (`ENV_PQZ_VERIFIER`); never on Hedera.
    constructor(Env memory env) {
        if (env.deps.length != 1 || env.hedera || !SigCheck.isContract(env.deps[ENV_PQZ_VERIFIER])) revert BadInit();
        PQZ_VERIFIER = env.deps[ENV_PQZ_VERIFIER];
    }

    /// @notice CTR-PQZ-15: the token signs under `"SCaaS PqzToken"`.
    function _domainName() internal pure virtual override(ERC20MetaTx) returns (string memory) {
        return "SCaaS PqzToken";
    }

    // ------------------------------------------------------------------ views

    function verifier() external view returns (address) { return PQZ_VERIFIER; }
    function precompile() external view returns (address) { return PqzCore.$().pqz; }
    function proofSystemId() external view returns (bytes32) { return PqzCore.$().psid; }
    function shieldScale() external view returns (uint256) { return PqzCore.$().shieldScale; }
    function maxShielded() external view returns (uint256) { return PqzCore.$().maxShielded; }
    function confidentialFee() external view returns (uint256) { return PqzCore.$().confidentialFee; }
    function minDecoyFee() external view returns (uint256) { return PqzCore.$().minDecoyFee; }
    function auditorUA() external view returns (bytes32) { return PqzCore.$().auditorUA; }
    function auditorMode() external view returns (ZetherTypes.AuditorMode) { return PqzCore.$().auditorMode; }
    function disclosureMode() external view returns (ZetherTypes.DisclosureMode) { return PqzCore.$().disclosureMode; }
    function totalShielded() external view returns (uint256) { return PqzCore.$().totalShielded; }

    /// @notice The account (D13): counters, the `acc` reference, `accUnits`, flags, `sendCounter`, `accHash`.
    function pqzAccount(bytes32 ua) external view override returns (AccountState memory) {
        PqzCore.Account storage a = PqzCore.$().acct[ua];
        return AccountState(a.pendingCount, a.rolled, a.floor, a.cleared, a.accBlob, a.accUnits, a.flags,
            a.sendCounter, a.accHash);
    }

    /// @notice Pending slot `i` (plan 5h D2): `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`, `vOff = 0` a TRIVIAL
    ///         entry with its amount in the low 64 bits of the blob field; 0 once deleted.
    function pqzPending(bytes32 ua, uint64 i) external view override returns (uint256) {
        return PqzCore.$().acct[ua].pending[i];
    }

    /// @notice The `acc` ciphertext from state (restore from state, D13).
    function pqzAcc(bytes32 ua) external view override returns (bytes memory) {
        return PqzStateLib.accOf(ua);
    }

    /// @notice Entry `i` as a ciphertext from state (a TRIVIAL entry: `Trivial(digits(amount))`; D13).
    function pqzPendingCt(bytes32 ua, uint64 i) external view override returns (bytes memory) {
        return PqzStateLib.pendingCt(ua, i);
    }

    /// @notice The op blob of a transfer as stored, `R ‖ v_f` packed at `PACK_BITS` (P46; `v_f` the trailing
    ///         `PqzCt.VP` bytes; D1, D13; both storage modes), empty if unknown.
    function pqzEntryBlob(bytes32 entryRef) external view override returns (bytes memory) {
        address p = PqzCore.$().entryPtr[entryRef];
        return p == address(0) ? bytes("") : SSTORE2.read(p);
    }

    /// @notice `keccak256(R)` of the entry over the stored (packed, P46) `R`, read from its op blob (0 = unknown).
    function transferCiphertextHash(bytes32 entryRef) external view returns (bytes32) {
        return PqzCore.ciphertextHash(entryRef);
    }

    /// @notice The raw entry: `R` (BUNDLE), `keccak256(R) ‖ memo` (commit-reveal), empty (unknown).
    function transferEntry(bytes32 entryRef) external view returns (bytes memory) {
        PqzCore.PqzStorage storage s = PqzCore.$();
        address p = s.entryPtr[entryRef];
        if (p == address(0)) return "";
        bytes memory r = PqzCore.rOf(p);
        bytes memory m = s.memos[entryRef];
        return m.length == 0 ? r : abi.encodePacked(keccak256(r), m);
    }

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

    /// @notice The disclosure statement (§7.9) of leg `leg` of `entryRef` for `kind` (0 `SENDER_S`, 1 `RECEIVER_X`,
    ///         2 `AUDITOR`); a single-recipient entry is leg 0. `R` is read from the entry's op blob (D11).
    function disclosureStatement(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind)
        external view returns (bytes memory)
    {
        return PqzViewLib.disclosureStatementOf(entryRef, leg, amount, kind, _envOf(0));
    }

    /// @notice CTR-PQZ-14 / -26: the precompile's verdict on `proof` for `amount` in leg `leg` of `entryRef` (`R` from
    ///         the op blob, D11). A view; no attestation. An empty proof, an unknown entry, no leg `leg`, `kind > 2`
    ///         and `amount ≥ 2^64` are false; a precompile call that fails (out of gas) reverts (C2-6).
    function verifyTransferAmount(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, bytes calldata proof)
        external view returns (bool)
    {
        if (proof.length == 0) return false;
        // C2-6: only the statement's shape errors (custom errors) read false; an empty revert (out of gas in the
        // sub-call) is propagated, and a failed precompile call reverts in `verdict`
        try this.disclosureStatement(entryRef, leg, amount, kind) {} catch (bytes memory err) {
            if (err.length == 0) assembly ("memory-safe") { revert(0, 0) }
            return false;
        }
        return PqzViewLib.verifyAmountOf(entryRef, leg, amount, kind, proof, _envOf(0));
    }

    /// @notice CTR-PQZ-21: every envelope field except `data`, plus `chainUid` (address path).
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _envelopeBinding(m);
    }

    /// @notice The UA path's binding (tag `SCAAS-PQZ-UA-ENVELOPE-V1`, `from` as `bytes32`; P6g plan D4).
    function uaEnvelopeBinding(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32) {
        return _uaEnvelopeBinding(m);
    }

    // ------------------------------------------------------------------ shield (§7.3, P6g plan D1)

    /// @notice Moves `amount · shieldScale` public units of the signer to `SHIELD_POOL` (D19) into a TRIVIAL entry of
    ///         `toUA` (plan 5h D18); free, into any holder (owner 2026-10-20).
    function mtxShield(bytes32 toUA, uint256 amount) external nonReentrant {
        PqzStateLib.shield(toUA, amount, _msgSender(), _REGISTRY);
        _toPool(amount);
    }

    // ------------------------------------------------------------------ transfer (§7.4, CTR-PQZ-23, CTR-PQZ-25)

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

    // ------------------------------------------------------------------ rollover (§7.6, plan 5h D8)

    /// @notice Anyone: the next `min(n, K_MAX − 1 − accUnits)` entries of `ua` into its `acc`, in order, each at least
    ///         `ROLL_AGE` blocks old; `1 ≤ n ≤ ROLL_MAX`.
    function mtxRollOver(bytes32 ua, uint256 n) external nonReentrant {
        PqzStateLib.rollOver(ua, n);
    }

    /// @notice Anyone, once per account and half (0, 1) before its first rollover (idempotent).
    function mtxPrepareAcc(bytes32 ua, uint256 half) external nonReentrant {
        PqzStateLib.prepareAcc(ua, half, _REGISTRY);
    }

    // ------------------------------------------------------------------ internals

    function _env() internal view returns (PqzCore.Env memory) {
        return _envOf(_ticketBinding());
    }

    function _envOf(bytes32 binding) internal view returns (PqzCore.Env memory) {
        return PqzCore.Env(_REGISTRY, CHAIN_UID, binding, 0, 0, ZetherTypes.TransferMode.BUNDLE);
    }

    /// @dev `mtxConfidentialTransfer`'s form: BUNDLE on a BUNDLE token, commit-reveal (HASH) on a COMPACT one.
    function _defaultMode() internal view returns (ZetherTypes.TransferMode) {
        return PqzCore.$().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
            ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;
    }

    function _envTransfer(ZetherTypes.TransferMode mode) internal view returns (PqzCore.Env memory e) {
        e = _env();
        e.mode = mode;
    }

    /// @dev `units · shieldScale` public units of the signer (a derived UA signer: its UA-ledger balance) to
    ///      `SHIELD_POOL` (D19). The caller is read only when there is something to pull: with `units = 0` the
    ///      submitter is an open role, so a designator relayer is not refused (D3, CTR-UA-24).
    function _toPool(uint256 units) internal {
        if (units != 0) {
            address m = _msgSender();
            _poolMove(m == MetaTxLib.UA_POOL ? _ticketSubject() : MetaTxLib.pad(m), MetaTxLib.pad(MetaTxLib.SHIELD_POOL),
                units * PqzCore.$().shieldScale);
        }
    }

    /// @dev `units · shieldScale` public units from `SHIELD_POOL` to `to` (a UA: its public UA-ledger balance; D19).
    function _fromPool(bytes32 to, uint256 units) internal {
        if (units != 0) _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), to, units * PqzCore.$().shieldScale);
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

    function _envBurn(uint256 amount, bytes32 recipient) internal view returns (PqzCore.Env memory e) {
        e = _env();
        (e.amount, e.recipient) = (amount, recipient);
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m) internal view virtual override returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(PqzCore.TAG_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,
            m.nonce, m.validUntil, m.mode, r, m.fee, f));
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override returns (bytes32)
    {
        address r = (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER) != 0 ? m.relayer : address(0);
        address f = (m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
        return keccak256(abi.encode(PqzCore.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,
            m.nonce, m.validUntil, m.mode, r, m.fee, f));
    }

    /// @dev The PQZ ops of both kinds (CTR-PQZ-21): allowlisted `ABSOLUTE` on both paths, never batched; includes the
    ///      permissionless `mtxRollOver` / `mtxPrepareAcc` (relayed, owner 2026-10-20; the fee may be 0).
    function _isPqzOp(bytes4 sel) internal pure virtual returns (bool) {
        return sel == this.mtxShield.selector || sel == this.mtxConfidentialTransfer.selector
            || sel == this.mtxConfidentialTransferCompact.selector
            || sel == this.mtxConfidentialTransferSingle.selector
            || sel == this.mtxConfidentialTransferSingleCompact.selector || sel == this.mtxUnshield.selector
            || sel == this.mtxRollOver.selector || sel == this.mtxPrepareAcc.selector;
    }

    function _batchable(bytes4 sel) internal view virtual override returns (bool) {
        return !_isPqzOp(sel);
    }

    /// @dev `mtxShield`, `mtxRollOver`, `mtxPrepareAcc` have a static shape (68 bytes); the others carry `bytes`.
    function _pqzRule(bytes4 sel) internal pure returns (MtxRule memory) {
        return MtxRule(FEE_CLASS_ABSOLUTE, 0, (sel == this.mtxShield.selector || sel == this.mtxRollOver.selector || sel == this.mtxPrepareAcc.selector) ? 68 : 0);
    }
}
