// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {PqzLib} from "./PqzLib.sol";
import {PqzCt} from "./PqzCt.sol";

/// @title The PQZ layer of the kinds `NONE_PQZ` and `UNDERLYING_PQZ` (CTR-PQZ-15, CTR-PQZ-22; P6g plan D1): the entry
///        points and views of pq-zether.md §9.4; the state and the logic are `PqzLib` (`scaas.pqz`).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Chains 31337 / 1337 / 7622 only (`PqzSafety`). A layer over the
///         public ERC-20 balance: `pqzShield` burns public units into `plainPending`, `pqzUnshield` mints them; the
///         confidential layer keeps no underlying of its own. The verifier (precompile and proof system), the auditor
///         UA and the two modes are fixed at creation. Every entry point is `nonReentrant`; the PQZ selectors are
///         allowlisted on both relaying paths (fee class `ABSOLUTE`) and never batched (CTR-PQZ-21).
abstract contract PqzLayer is MetaTokenBase, IPqzToken {
    /// @notice CTR-PQZ-15: the token signs under `"SCaaS PqzToken"`.
    function _domainName() internal pure virtual override(ERC20MetaTx) returns (string memory) {
        return "SCaaS PqzToken";
    }

    // ------------------------------------------------------------------ views

    function verifier() external view returns (address) { return PqzLib.$().verifier; }
    function precompile() external view returns (address) { return PqzLib.$().pqz; }
    function proofSystemId() external view returns (bytes32) { return PqzLib.$().psid; }
    function shieldScale() external view returns (uint256) { return PqzLib.$().shieldScale; }
    function maxShielded() external view returns (uint256) { return PqzLib.$().maxShielded; }
    function confidentialFee() external view returns (uint256) { return PqzLib.$().confidentialFee; }
    function auditorUA() external view returns (bytes32) { return PqzLib.$().auditorUA; }
    function auditorMode() external view returns (ZetherTypes.AuditorMode) { return PqzLib.$().auditorMode; }
    function disclosureMode() external view returns (ZetherTypes.DisclosureMode) { return PqzLib.$().disclosureMode; }
    function totalShielded() external view returns (uint256) { return PqzLib.$().totalShielded; }

    function accountState(bytes32 ua) external view returns (AccountState memory) {
        PqzLib.Account storage a = PqzLib.$().acct[ua];
        return AccountState(PqzCt.stored(a.accHash), a.accUnits, a.pendingCount, a.rolled, a.floor, a.cleared,
            a.sendCounter, a.plainPending);
    }

    function pendingHash(bytes32 ua, uint64 i) external view returns (bytes32) {
        return PqzLib.$().acct[ua].pendingHash[i];
    }

    /// @notice `keccak256(R)` of the entry (0 = none: no-bundle or unknown).
    function transferCiphertextHash(bytes32 entryRef) external view returns (bytes32) {
        return PqzLib.ciphertextHash(entryRef);
    }

    /// @notice The raw entry: `R` (BUNDLE), `keccak256(R) ‖ memo` (commit-reveal), empty (none).
    function transferEntry(bytes32 entryRef) external view returns (bytes memory) {
        PqzLib.PqzStorage storage s = PqzLib.$();
        bytes32 h = s.entryHash[entryRef];
        if (h != 0) return abi.encodePacked(h, s.memos[entryRef]);
        address p = s.entryPtr[entryRef];
        if (p == address(0)) return "";
        bytes memory r = new bytes(p.code.length - 1);
        assembly ("memory-safe") { extcodecopy(p, add(r, 32), 1, mload(r)) }
        return r;
    }

    /// @notice The transfer statement the token builds for `payload` (direct: `binding` 0), after every cheap check.
    function transferStatement(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes32 binding)
        external view returns (bytes memory)
    {
        PqzLib.Env memory e = _envOf(binding);
        bool memo = payload.length == 208 + 16_768 + 57 || payload.length == 208 + 16_640 + 57;
        e.mode = memo ? ZetherTypes.TransferMode.HASH : _defaultMode();
        (, bytes memory buf) = PqzLib.prepareTransfer(e, payload, acc, inl, 0);
        return _stmt(buf);
    }

    /// @notice The burn (`amount > 0`) or refresh (`amount = 0`, `recipient = 0`) statement.
    function burnStatement(
        bytes calldata payload, bytes calldata acc, bytes[] calldata inl, uint256 amount, address recipient,
        bytes32 binding
    ) external view returns (bytes memory) {
        PqzLib.Env memory e = _envOf(binding);
        (e.amount, e.recipient) = (amount, recipient);
        (, bytes memory buf) = PqzLib.prepareBurn(e, payload, acc, inl, 0);
        return _stmt(buf);
    }

    /// @notice The disclosure statement (§7.9) of `entryRef` for `kind` (0 `SENDER_S`, 1 `RECEIVER_X`, 2 `AUDITOR`).
    function disclosureStatement(bytes32 entryRef, uint256 amount, uint8 kind, bytes calldata bundle)
        external view returns (bytes memory)
    {
        return _stmt(PqzLib.disclosureBuffer(entryRef, amount, kind, bundle, _envOf(0), 0));
    }

    /// @notice CTR-PQZ-14: the precompile's verdict on `opening = abi.encode(bytes bundle, bytes proof)` (canonical
    ///         only) for `amount` in `entryRef`. A view; no attestation. Any malformed input is false.
    function verifyTransferAmount(bytes32 entryRef, uint256 amount, uint8 kind, bytes calldata opening)
        external view returns (bool)
    {
        (bytes memory bundle, bytes memory proof) = abi.decode(opening, (bytes, bytes));
        if (keccak256(abi.encode(bundle, proof)) != keccak256(opening) || proof.length == 0) return false;
        try this.disclosureStatement(entryRef, amount, kind, bundle) {} catch { return false; }
        bytes memory buf = PqzLib.disclosureBuffer(entryRef, amount, kind, bundle, _envOf(0), proof.length);
        assembly ("memory-safe") { mcopy(add(add(buf, 37), 33184), add(proof, 32), mload(proof)) }
        return PqzLib.verdict(PqzLib.$().pqz, buf);
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

    /// @notice Burns `amount · shieldScale` public units of the signer; `plainPending[ua] += amount`.
    function pqzShield(bytes32 ua, uint256 amount) external nonReentrant {
        PqzLib.shield(ua, amount, _REGISTRY);
        _burn(_msgSender(), amount * PqzLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ transfer (§7.4, CTR-PQZ-23)

    /// @notice The token's default form: the bundle stored (BUNDLE token) or commit-reveal (COMPACT token).
    function pqzTransfer(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes calldata proof,
        bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzLib.transfer(_envTransfer(_defaultMode()), payload, acc, inl, proof, authSig);
    }

    function pqzTransferCompact(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes calldata proof,
        bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzLib.transfer(_envTransfer(ZetherTypes.TransferMode.HASH), payload, acc, inl, proof, authSig);
    }

    function pqzTransferNoBundle(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes calldata proof,
        bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzLib.transfer(_envTransfer(ZetherTypes.TransferMode.NONE), payload, acc, inl, proof, authSig);
    }

    // ------------------------------------------------------------------ burn and refresh (§7.5)

    /// @notice Burn `amount` into `amount · shieldScale` public units minted to `recipient`; `amount = 0` with
    ///         `recipient = 0` is a refresh.
    function pqzUnshield(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, uint256 amount,
        address recipient, bytes calldata proof, bytes calldata authSig) external nonReentrant
    {
        PqzLib.unshield(_envBurn(amount, recipient), payload, acc, inl, proof, authSig);
        if (amount != 0) _mint(recipient, amount * PqzLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ rollover (§7.6)

    function pqzRollOver(bytes32 ua, bytes calldata acc, bytes[] calldata cts) external nonReentrant {
        PqzLib.rollOver(ua, acc, cts);
    }

    // ------------------------------------------------------------------ internals

    function _env() internal view returns (PqzLib.Env memory) {
        return _envOf(_ticketBinding());
    }

    function _envOf(bytes32 binding) internal view returns (PqzLib.Env memory) {
        return PqzLib.Env(_REGISTRY, CHAIN_UID, binding, 0, address(0), ZetherTypes.TransferMode.BUNDLE);
    }

    /// @dev `pqzTransfer`'s form: BUNDLE on a BUNDLE token, commit-reveal (HASH) on a COMPACT one.
    function _defaultMode() internal view returns (ZetherTypes.TransferMode) {
        return PqzLib.$().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
            ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;
    }

    function _envTransfer(ZetherTypes.TransferMode mode) internal view returns (PqzLib.Env memory e) {
        e = _env();
        e.mode = mode;
    }

    function _envBurn(uint256 amount, address recipient) internal view returns (PqzLib.Env memory e) {
        e = _env();
        (e.amount, e.recipient) = (amount, recipient);
    }

    /// @dev The statement bytes of a precompile buffer (the 5-byte prefix and the empty proof dropped).
    function _stmt(bytes memory buf) internal pure returns (bytes memory st) {
        st = new bytes(buf.length - 5);
        assembly ("memory-safe") { mcopy(add(st, 32), add(buf, 37), mload(st)) }
    }

    function _envelopeBinding(MetaTxLib.MetaTransaction memory m) internal view virtual override returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(PqzLib.TAG_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,
            m.nonce, m.validUntil, m.mode, r, m.fee, f));
    }

    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override returns (bytes32)
    {
        address r = (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER) != 0 ? m.relayer : address(0);
        address f = (m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
        return keccak256(abi.encode(PqzLib.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,
            m.nonce, m.validUntil, m.mode, r, m.fee, f));
    }

    /// @dev The PQZ ops of both kinds (CTR-PQZ-21): allowlisted `ABSOLUTE` on both paths, never batched.
    function _isPqzOp(bytes4 sel) internal pure virtual returns (bool) {
        return sel == this.pqzShield.selector || sel == this.pqzTransfer.selector
            || sel == this.pqzTransferCompact.selector || sel == this.pqzTransferNoBundle.selector
            || sel == this.pqzUnshield.selector || sel == this.pqzRollOver.selector;
    }

    function _batchable(bytes4 sel) internal view virtual override returns (bool) {
        return !_isPqzOp(sel);
    }

    /// @dev `pqzShield` has a static shape (68 bytes); the others carry `bytes`.
    function _pqzRule(bytes4 sel) internal pure returns (MtxRule memory) {
        return MtxRule(FEE_CLASS_ABSOLUTE, 0, sel == this.pqzShield.selector ? 68 : 0);
    }
}
