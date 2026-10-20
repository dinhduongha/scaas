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
import {PqzCt} from "./PqzCt.sol";
import {ENV_PQZ_VERIFIER} from "../factory/IFactoryToken.sol";

/// @title The PQZ layer of the kinds `NONE_PQZ` and `UNDERLYING_PQZ` (CTR-PQZ-15, CTR-PQZ-22; P6g plan D1): the entry
///        points and views of pq-zero-knowledge.md §9.4; the state and the logic are the four libraries (`scaas.pqz`; D14).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Chains 31337 / 1337 / 7622 only (`PqzSafety`). A layer over the
///         public ERC-20 balance: `pqzShield` burns public units into `plainPending`, `pqzUnshield` mints them; the
///         confidential layer keeps no underlying of its own. The verifier (precompile and proof system) is an
///         implementation immutable (CTR-ZTH-20 / CTR-PQZ-10), so the proof system is an attribute of the release; the
///         auditor UA and the two modes are fixed at creation. Every entry point is `nonReentrant`; the PQZ selectors are
///         allowlisted on both relaying paths (fee class `ABSOLUTE`) and never batched (CTR-PQZ-21). A holder is a signing
///         UA: `authSig` is that UA's own signature over the statement digest, and its PQZ key is a record attribute
///         (UA-6 U7); a UA without the key is refused as sender, leg, beneficiary, shield target and auditor.
abstract contract PqzLayer is MetaTokenBase, IPqzToken {
    /// @dev The `UAPqzVerifier` of this release; `init` takes the precompile and the proof system from it.
    address internal immutable PQZ_VERIFIER;

    /// @dev `env.deps = [UAPqzVerifier]` (`ENV_PQZ_VERIFIER`); never on Hedera.
    constructor(Env memory env) {
        if (env.deps.length != 1 || env.hedera || env.deps[ENV_PQZ_VERIFIER].code.length == 0) revert BadInit();
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
    function multiLegFee() external view returns (uint256) { return PqzCore.$().multiLegFee; }
    function auditorUA() external view returns (bytes32) { return PqzCore.$().auditorUA; }
    function auditorMode() external view returns (ZetherTypes.AuditorMode) { return PqzCore.$().auditorMode; }
    function disclosureMode() external view returns (ZetherTypes.DisclosureMode) { return PqzCore.$().disclosureMode; }
    function totalShielded() external view returns (uint256) { return PqzCore.$().totalShielded; }

    function accountState(bytes32 ua) external view returns (AccountState memory) {
        PqzCore.Account storage a = PqzCore.$().acct[ua];
        return AccountState(PqzCt.stored(a.accHash), a.accUnits, a.pendingCount, a.rolled, a.floor, a.cleared,
            a.sendCounter, a.plainPending);
    }

    function pendingHash(bytes32 ua, uint64 i) external view returns (bytes32) {
        return PqzCore.$().acct[ua].pendingHash[i];
    }

    /// @notice `keccak256(R)` of the entry (0 = none: no-bundle or unknown).
    function transferCiphertextHash(bytes32 entryRef) external view returns (bytes32) {
        return PqzCore.ciphertextHash(entryRef);
    }

    /// @notice The raw entry: `R` (BUNDLE), `keccak256(R) ‖ memo` (commit-reveal), empty (none).
    function transferEntry(bytes32 entryRef) external view returns (bytes memory) {
        PqzCore.PqzStorage storage s = PqzCore.$();
        bytes32 h = s.entryHash[entryRef];
        if (h != 0) return abi.encodePacked(h, s.memos[entryRef]);
        address p = s.entryPtr[entryRef];
        if (p == address(0)) return "";
        bytes memory r = new bytes(p.code.length - 1);
        assembly ("memory-safe") { extcodecopy(p, add(r, 32), 1, mload(r)) }
        return r;
    }

    /// @notice The op 7 statement the token builds for a multi-recipient `payload`, after every cheap check; a payload
    ///         with the memo is read as commit-reveal. `binding` 0 = a direct call in that mode (`pqzTransfer`,
    ///         `…Compact`); a direct `…NoBundle` passes `keccak256(abi.encode(keccak256("SCAAS-PQZ-DIRECT-MODE-V1"),
    ///         uint8(2)))` (W-A); a relayed call its envelope binding.
    function transferStatement(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes32 binding)
        external view returns (bytes memory)
    {
        return PqzViewLib.statementOf(7, _envOf(binding), payload, acc, inl);
    }

    /// @notice The op 1 statement of a single-recipient `payload` (`pqzTransferSingle*`; `binding` as above).
    function transferSingleStatement(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes32 binding)
        external view returns (bytes memory)
    {
        return PqzViewLib.statementOf(1, _envOf(binding), payload, acc, inl);
    }

    /// @notice The burn (`amount > 0`) or refresh (`amount = 0`, `recipient = 0`) statement.
    function burnStatement(
        bytes calldata payload, bytes calldata acc, bytes[] calldata inl, uint256 amount, address recipient,
        bytes32 binding
    ) external view returns (bytes memory) {
        PqzCore.Env memory e = _envOf(binding);
        (e.amount, e.recipient) = (amount, recipient);
        return PqzViewLib.statementOf(2, e, payload, acc, inl);
    }

    /// @notice The disclosure statement (§7.9) of leg `leg` of `entryRef` for `kind` (0 `SENDER_S`, 1 `RECEIVER_X`,
    ///         2 `AUDITOR`); a single-recipient entry is leg 0.
    function disclosureStatement(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, bytes calldata bundle)
        external view returns (bytes memory)
    {
        return PqzViewLib.disclosureStatementOf(entryRef, leg, amount, kind, bundle, _envOf(0));
    }

    /// @notice CTR-PQZ-14 / -26: the precompile's verdict on `opening = abi.encode(bytes bundle, bytes proof)`
    ///         (canonical only) for `amount` in leg `leg` of `entryRef`. A view; no attestation. A non-canonical
    ///         opening, an empty proof, an unknown entry, a bundle that is not the stored one or has no leg `leg`,
    ///         `kind > 2` and `amount ≥ 2^64` are false; an `opening` that does not ABI-decode as `(bytes, bytes)`
    ///         reverts, as `ZetherDisclosure`'s `OpeningMalformed` (review W-I).
    function verifyTransferAmount(bytes32 entryRef, uint256 leg, uint256 amount, uint8 kind, bytes calldata opening)
        external view returns (bool)
    {
        (bytes memory bundle, bytes memory proof) = abi.decode(opening, (bytes, bytes));
        if (keccak256(abi.encode(bundle, proof)) != keccak256(opening) || proof.length == 0) return false;
        try this.disclosureStatement(entryRef, leg, amount, kind, bundle) {} catch { return false; }
        return PqzViewLib.verifyAmountOf(entryRef, leg, amount, kind, bundle, proof, _envOf(0));
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
        PqzStateLib.shield(ua, amount, _REGISTRY);
        _burn(_msgSender(), amount * PqzCore.$().shieldScale);
    }

    // ------------------------------------------------------------------ transfer (§7.4, CTR-PQZ-23, CTR-PQZ-25)

    /// @notice The multi-recipient transfer, op 7 `R_TXM` (`M` legs, decoys included; CTR-PQZ-26), in the token's
    ///         default form: the bundle stored (BUNDLE token) or commit-reveal (COMPACT token).
    function pqzTransfer(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes calldata proof,
        bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzTransferLib.transferMulti(_envTransfer(_defaultMode()), payload, acc, inl, proof, authSig);
    }

    function pqzTransferCompact(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes calldata proof,
        bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzTransferLib.transferMulti(_envTransfer(ZetherTypes.TransferMode.HASH), payload, acc, inl, proof, authSig);
    }

    function pqzTransferNoBundle(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes calldata proof,
        bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzTransferLib.transferMulti(_envTransfer(ZetherTypes.TransferMode.NONE), payload, acc, inl, proof, authSig);
    }

    /// @notice The single-recipient transfer, op 1 `R_TX` / `R_TX0` (§7.4), in the token's default form.
    function pqzTransferSingle(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, bytes calldata proof,
        bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzTransferLib.transfer(_envTransfer(_defaultMode()), payload, acc, inl, proof, authSig);
    }

    function pqzTransferSingleCompact(bytes calldata payload, bytes calldata acc, bytes[] calldata inl,
        bytes calldata proof, bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzTransferLib.transfer(_envTransfer(ZetherTypes.TransferMode.HASH), payload, acc, inl, proof, authSig);
    }

    function pqzTransferSingleNoBundle(bytes calldata payload, bytes calldata acc, bytes[] calldata inl,
        bytes calldata proof, bytes calldata authSig) external nonReentrant returns (bytes32)
    {
        return PqzTransferLib.transfer(_envTransfer(ZetherTypes.TransferMode.NONE), payload, acc, inl, proof, authSig);
    }

    // ------------------------------------------------------------------ burn and refresh (§7.5)

    /// @notice Burn `amount` into `amount · shieldScale` public units minted to `recipient`; `amount = 0` with
    ///         `recipient = 0` is a refresh.
    function pqzUnshield(bytes calldata payload, bytes calldata acc, bytes[] calldata inl, uint256 amount,
        address recipient, bytes calldata proof, bytes calldata authSig) external nonReentrant
    {
        PqzBurnLib.unshield(_envBurn(amount, recipient), payload, acc, inl, proof, authSig);
        if (amount != 0) _mint(recipient, amount * PqzCore.$().shieldScale);
    }

    // ------------------------------------------------------------------ rollover (§7.6)

    function pqzRollOver(bytes32 ua, bytes calldata acc, bytes[] calldata cts) external nonReentrant {
        PqzStateLib.rollOver(ua, acc, cts);
    }

    // ------------------------------------------------------------------ internals

    function _env() internal view returns (PqzCore.Env memory) {
        return _envOf(_ticketBinding());
    }

    function _envOf(bytes32 binding) internal view returns (PqzCore.Env memory) {
        return PqzCore.Env(_REGISTRY, CHAIN_UID, binding, 0, address(0), ZetherTypes.TransferMode.BUNDLE);
    }

    /// @dev `pqzTransfer`'s form: BUNDLE on a BUNDLE token, commit-reveal (HASH) on a COMPACT one.
    function _defaultMode() internal view returns (ZetherTypes.TransferMode) {
        return PqzCore.$().disclosureMode == ZetherTypes.DisclosureMode.COMPACT
            ? ZetherTypes.TransferMode.HASH
            : ZetherTypes.TransferMode.BUNDLE;
    }

    function _envTransfer(ZetherTypes.TransferMode mode) internal view returns (PqzCore.Env memory e) {
        e = _env();
        e.mode = mode;
    }

    function _envBurn(uint256 amount, address recipient) internal view returns (PqzCore.Env memory e) {
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

    /// @dev The PQZ ops of both kinds (CTR-PQZ-21): allowlisted `ABSOLUTE` on both paths, never batched.
    function _isPqzOp(bytes4 sel) internal pure virtual returns (bool) {
        return sel == this.pqzShield.selector || sel == this.pqzTransfer.selector
            || sel == this.pqzTransferCompact.selector || sel == this.pqzTransferNoBundle.selector
            || sel == this.pqzTransferSingle.selector || sel == this.pqzTransferSingleCompact.selector
            || sel == this.pqzTransferSingleNoBundle.selector
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
