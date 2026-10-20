// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "./IZetherVerifier.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {
    ENV_ZETHER_TRANSFER, ENV_ZETHER_BURN, ENV_ZETHER_INNER_PRODUCT, ENV_ZETHER_DISCLOSURE
} from "../factory/IFactoryToken.sol";

/// @dev What the layer reads from a transfer / burn verifier besides `IZetherVerifierCommon`.
interface IInnerProductBound {
    function innerProduct() external view returns (address);
}

/// @title The Zether layer of the kinds `NONE_ZETHER` and `UNDERLYING_ZETHER` (CTR-ZTH-44): the entry points of
///        CTR-ZTH-45 and the views; the state and the logic are `ZetherLib` (`scaas.zether`).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Dev chains only (`ZetherSafety`, CTR-ZTH-02). A layer over the
///         public ERC-20 balance: `mtxShield` moves public units to `SHIELD_POOL`, `mtxUnshield` moves them back (D19: no
///         burn, no mint; to an address or a signing UA, CTR-ZTH-51); the confidential layer
///         keeps no underlying of its own. The registry (the base's, `ERC20MetaTx`), the disclosure contract and the
///         curve's transfer and burn verifiers are implementation immutables (CTR-ZTH-20: `OpenFactory` registers an
///         implementation only on its canonical verifiers), so the curve is an attribute of the release (`curve()`); the
///         auditor key and the two modes (`disclosureMode`, `auditorMode`) are chosen at creation and never change.
///         Every entry point is `nonReentrant`. The shared entry points are `IConfidentialToken`'s (plan 5h D20): the
///         proof alone authorises, so `auth` and `accHint` must be empty (`AuthNotEmpty`, `AccHintNotEmpty`).
abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
    ITransferDisclosure private immutable _DISCLOSURE;
    /// @dev The transfer verifier (transfer proofs, the group operations; `init` copies it into `ZetherLib`'s storage,
    ///      the library cannot read immutables) and the burn verifier (unshield proofs, through `ZetherLib.Env`).
    IZetherVerifier internal immutable TRANSFER_VERIFIER;
    IZetherBurnVerifier internal immutable BURN_VERIFIER;

    /// @dev Runs after `MetaTokenBase`'s constructor, which set `_REGISTRY`: a Zether kind needs a registry. The release's
    ///      `Env.deps` (plan 5g-Z2): `ENV_ZETHER_TRANSFER`, `ENV_ZETHER_BURN`, `ENV_ZETHER_INNER_PRODUCT` (fixed inside the
    ///      two, checked here), `ENV_ZETHER_DISCLOSURE`; the two verifiers must be of one proof system (one curve), and
    ///      each in its role (review 5g-Z2 P2-2): two addresses, the transfer verifier answers `ringSize()` and the burn
    ///      verifier does not (a swapped or duplicated pair would accept shields and lock them).
    constructor(Env memory env) {
        address[] memory d = env.deps;
        if (d.length != 4 || env.hedera || _REGISTRY.code.length == 0) revert BadInit(); // never on Hedera
        IZetherVerifier t = IZetherVerifier(d[ENV_ZETHER_TRANSFER]);
        IZetherBurnVerifier b = IZetherBurnVerifier(d[ENV_ZETHER_BURN]);
        address ip = d[ENV_ZETHER_INNER_PRODUCT];
        if (address(t).code.length == 0 || address(b).code.length == 0 || d[ENV_ZETHER_DISCLOSURE].code.length == 0
            || t.proofSystemId() != b.proofSystemId() || ip == address(0)
            || IInnerProductBound(address(t)).innerProduct() != ip || IInnerProductBound(address(b)).innerProduct() != ip
            || address(t) == address(b) || !_answers(address(t), IZetherVerifier.ringSize.selector)
            || _answers(address(b), IZetherVerifier.ringSize.selector)) {
            revert BadInit();
        }
        _DISCLOSURE = ITransferDisclosure(d[ENV_ZETHER_DISCLOSURE]);
        TRANSFER_VERIFIER = t;
        BURN_VERIFIER = b;
    }

    /// @dev `target` answers `sel()` with one word (constructor only).
    function _answers(address target, bytes4 sel) private view returns (bool) {
        (bool ok, bytes memory r) = target.staticcall(abi.encodeWithSelector(sel));
        return ok && r.length == 32;
    }

    /// @notice CTR-MTX-02: confidential tokens sign under `"SCaaS ZetherToken"`.
    function _domainName() internal pure virtual override(ERC20MetaTx) returns (string memory) {
        return "SCaaS ZetherToken";
    }

    // ------------------------------------------------------------------ views

    function verifier() external view returns (IZetherVerifier) { return TRANSFER_VERIFIER; }
    function burnVerifier() external view returns (IZetherBurnVerifier) { return BURN_VERIFIER; }
    function curve() external view returns (string memory) { return TRANSFER_VERIFIER.curveName(); }
    function disclosure() external view returns (ITransferDisclosure) { return _DISCLOSURE; }
    function shieldScale() external view returns (uint256) { return ZetherLib.$().shieldScale; }
    function maxDecryptableShielded() external view returns (uint256) { return ZetherLib.$().maxShielded; }
    function confidentialFee() external view returns (uint256) { return ZetherLib.$().confidentialFee; }
    function minDecoyFee() external view returns (uint256) { return ZetherLib.$().minDecoyFee; }
    function auditorKey() external view returns (bytes memory) { return ZetherLib.$().auditorKey; }
    function auditorMode() external view returns (ZetherTypes.AuditorMode) { return ZetherLib.$().auditorMode; }
    function disclosureMode() external view returns (ZetherTypes.DisclosureMode) { return ZetherLib.$().disclosureMode; }
    function totalShielded() external view returns (uint256) { return ZetherLib.$().totalShielded; }
    /// @notice The raw record for `disclosure()`: `R` (BUNDLE, single), `keccak256(R) ‖ memo` (commit-reveal; the hash in
    ///         one slot), empty (NONE, unknown).
    function transferEntry(bytes32 entryRef) external view returns (bytes memory) {
        bytes32 h = ZetherLib.$().entryHashes[entryRef];
        return h != bytes32(0) ? abi.encodePacked(h, ZetherLib.$().memos[entryRef]) : ZetherLib.$().entries[entryRef];
    }
    function sendCounter(ZetherTypes.UA ua) external view returns (uint256) { return ZetherLib.$().acct[ua].sendCounter; }

    /// @notice Registered as this token's Zether kind (`registry.kindOf`, accounts.md §1.13).
    function registered(ZetherTypes.UA ua) external view returns (bool) {
        return ZetherLib.registeredOn(_REGISTRY, ua);
    }

    function accountState(ZetherTypes.UA ua) external view returns (AccountState memory) {
        ZetherLib.ZetherStorage storage s = ZetherLib.$();
        ZetherLib.Account storage a = s.acct[ua];
        uint256 p = s.p;
        return AccountState({
            accC: ZetherLib._pt(a.accC, p), accD: ZetherLib._pt(a.accD, p), pendingC: ZetherLib._pt(a.pendC, p),
            pendingD: ZetherLib._pt(a.pendD, p), accSeq: a.accSeq, pendingSeq: a.pendingSeq, sendCounter: a.sendCounter,
            modeNonce: a.modeNonce, mode: a.mode
        });
    }

    /// @notice CTR-ZTH-06: every envelope field except `data` (which carries the proof), plus `chainUid`.
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _zetherBinding(m);
    }

    /// @notice CTR-ZTH-51: the UA path's binding, tag `SCAAS-ZETHER-UA-ENVELOPE-V1` (distinct from the address path's).
    function uaEnvelopeBinding(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32) {
        return _uaEnvelopeBinding(m);
    }

    // ------------------------------------------------------------------ shield (CTR-ZTH-35)

    /// @notice Moves `amount · shieldScale` public units of the signer to `SHIELD_POOL` (D19: a transfer, not a burn);
    ///         `pending[toUA] += [amount]G`. The Zether key is the UA (CTR-UA-30): `toUA` must be registered as this
    ///         token's Zether kind. A derived UA signer pays from its UA-ledger balance.
    function mtxShield(bytes32 toUA, uint256 amount) external nonReentrant {
        address m = _msgSender();
        ZetherLib.shield(ZetherTypes.UA.wrap(toUA), amount, _REGISTRY, m);
        _poolMove(m == MetaTxLib.UA_POOL ? _ticketSubject() : MetaTxLib.pad(m), MetaTxLib.pad(MetaTxLib.SHIELD_POOL),
            amount * ZetherLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ transfer (CTR-ZTH-37, CTR-ZTH-38)

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

    function mtxConfidentialTransferNoBundle(bytes calldata payload, bytes calldata proof, bytes calldata auth,
        bytes32 beneficiary, bytes calldata accHint) external nonReentrant returns (bytes32)
    {
        return _multi(payload, proof, auth, beneficiary, accHint, ZetherTypes.TransferMode.NONE);
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

    // ------------------------------------------------------------------ roll-over (not allowlisted, CTR-ZTH-34)

    /// @notice The one aggregated pending of `ua` into `acc` for any `n ≥ 1` (`RollOverRange` for 0).
    function mtxRollOver(bytes32 ua, uint256 n) external nonReentrant {
        if (n == 0) revert RollOverRange(n);
        ZetherLib.rollOver(ZetherTypes.UA.wrap(ua));
    }

    function mtxRollOverBatch(ZetherTypes.UA[] calldata uas) external nonReentrant {
        ZetherLib.rollOverBatch(uas);
    }

    /// @dev Owner roll-over: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function mtxRollOverSigned(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external nonReentrant
    {
        ZetherLib.rollOverSigned(ua, expectedPendingSeq, validUntilBlock, sig, _env());
    }

    /// @dev Owner mode change: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function mtxSetRollOverMode(
        ZetherTypes.UA ua,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        bytes calldata sig
    ) external nonReentrant {
        ZetherLib.setRollOverMode(ua, mode, validUntilBlock, sig, _env());
    }

    // ------------------------------------------------------------------ internals

    /// @dev A public payee of an unshield: not `SHIELD_POOL`, not `UA_POOL`; the token is refused by the move and zero by
    ///      `prepareUnshield` (`ZeroRecipient`).
    function _requirePayee(address to) internal pure {
        if (to == MetaTxLib.SHIELD_POOL) revert ShieldPoolNotPayable();
        if (to == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
    }

    /// @dev The recipient id of `mtxUnshield` (CTR-ZTH-51): a padded address (`_requirePayee`) or a registered SIGNING
    ///      derived UA (`_requireDerivedReceiver`).
    function _requireRecipient(bytes32 to) internal view {
        if (UAKinds.inNativeSpace(to)) _requirePayee(address(uint160(uint256(to))));
        else _requireDerivedReceiver(to);
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

    /// @dev A fee the library took out of `totalShielded` (D19): `fee · shieldScale` public units (0: nothing) from the
    ///      pool to the Zether UA's public (UA-ledger) balance: the beneficiary's inner fee, a leg's `decoyFee`.
    function _fromPool(ZetherTypes.UA to, uint256 fee) internal {
        if (fee != 0) {
            _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), ZetherTypes.UA.unwrap(to), fee * ZetherLib.$().shieldScale);
        }
    }

    /// @dev The statement binding of this call (CTR-ZTH-34, CTR-ZTH-51): the envelope's inside `mtxExecute` or
    ///      `uaExecute` (`ZTX_V1_RELAYED`), else 0 (`ZTX_V1_DIRECT`), so a proof lifted out of a pending envelope fails
    ///      as a direct call, and one lifted between the two paths fails on the other's tag.
    function _env() internal view returns (ZetherLib.Env memory) {
        bytes32 b = _ticketBinding();
        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.tagOf(b), b, BURN_VERIFIER);
    }

    /// @dev The base stores it in the ticket for the self-call of every `mtxExecute` on this token.
    function _envelopeBinding(MetaTxLib.MetaTransaction memory m) internal view virtual override returns (bytes32) {
        return _zetherBinding(m);
    }

    /// @dev Likewise for every `uaExecute` (CTR-ZTH-51): `TAG_UA_ENVELOPE`, `from` as `bytes32`, never 0.
    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory m)
        internal view virtual override returns (bytes32)
    {
        address r = (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER) != 0 ? m.relayer : address(0);
        address f = (m.mode & MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT) != 0 ? m.feeRecipient : address(0);
        return keccak256(abi.encode(ZetherLib.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,
            m.nonce, m.validUntil, m.mode, r, m.fee, f));
    }

    /// @dev The allowlist entries of the layer (CTR-ZTH-34, CTR-MTX-19): every signer-authorised confidential op,
    ///      `ABSOLUTE` (no percentage of a hidden amount, CTR-ZTH-07), dynamic arguments; the roll-over functions are not
    ///      listed (they carry their own signature or none). The same set is on the UA allowlist (CTR-ZTH-51).
    function _isZetherOp(bytes4 sel) internal pure returns (bool) {
        return sel == this.mtxShield.selector || sel == this.mtxConfidentialTransfer.selector
            || sel == this.mtxConfidentialTransferCompact.selector
            || sel == this.mtxConfidentialTransferNoBundle.selector
            || sel == this.mtxConfidentialTransferSingle.selector || sel == this.mtxUnshield.selector;
    }

    function _zetherBinding(MetaTxLib.MetaTransaction memory m) internal view returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(
            ZetherLib.TAG_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch, m.nonce, m.validUntil,
            m.mode, r, m.fee, f
        ));
    }
}
