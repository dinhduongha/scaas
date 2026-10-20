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
///         public ERC-20 balance: `zetherShield` moves public units to `SHIELD_POOL`, `zetherUnshield` moves them back (D19: no burn, no mint); the confidential layer
///         keeps no underlying of its own. The registry (the base's, `ERC20MetaTx`), the disclosure contract and the
///         curve's transfer and burn verifiers are implementation immutables (CTR-ZTH-20: `OpenFactory` registers an
///         implementation only on its canonical verifiers), so the curve is an attribute of the release (`curve()`); the
///         auditor key and the two modes (`disclosureMode`, `auditorMode`) are chosen at creation and never change.
///         Every entry point is `nonReentrant`.
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

    // ------------------------------------------------------------------ shield (CTR-ZTH-35)

    /// @notice Moves `amount · shieldScale` public units of the signer to `SHIELD_POOL` (D19: a transfer, not a burn);
    ///         `pending[ua] += [amount]G`. A derived UA signer pays from its UA-ledger balance.
    function zetherShield(bytes calldata encodedY, uint256 amount) external nonReentrant {
        ZetherLib.shield(ZetherTypes.toUA(encodedY), amount, _REGISTRY);
        address m = _msgSender();
        _poolMove(m == MetaTxLib.UA_POOL ? _ticketSubject() : MetaTxLib.pad(m), MetaTxLib.pad(MetaTxLib.SHIELD_POOL),
            amount * ZetherLib.$().shieldScale);
    }

    // ------------------------------------------------------------------ transfer (CTR-ZTH-37, CTR-ZTH-38)

    /// @notice The token's default: the record stored (`BUNDLE` token) or commit-reveal (`COMPACT` token).
    function zetherTransfer(bytes calldata payload, bytes calldata proof, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        (bytes32 ref, uint256 fee) = ZetherLib.transferMulti(payload, proof, beneficiary, ZetherLib.defaultMode(), _env());
        _payBeneficiary(beneficiary, fee);
        return ref;
    }

    function zetherTransferCompact(bytes calldata payload, bytes calldata proof, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        (bytes32 ref, uint256 fee) = ZetherLib.transferMulti(payload, proof, beneficiary, ZetherTypes.TransferMode.HASH, _env());
        _payBeneficiary(beneficiary, fee);
        return ref;
    }

    function zetherTransferNoBundle(bytes calldata payload, bytes calldata proof, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        (bytes32 ref, uint256 fee) = ZetherLib.transferMulti(payload, proof, beneficiary, ZetherTypes.TransferMode.NONE, _env());
        _payBeneficiary(beneficiary, fee);
        return ref;
    }

    function zetherTransferSingle(bytes calldata payload, bytes calldata proof, ZetherTypes.UA beneficiary)
        external nonReentrant returns (bytes32)
    {
        (bytes32 ref, uint256 fee) = ZetherLib.transferSingle(payload, proof, beneficiary, _env());
        _payBeneficiary(beneficiary, fee);
        return ref;
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement binds `amount` and `to`; moves `amount · shieldScale` public units from
    ///         `SHIELD_POOL` to `to` (D19), then the fee to the beneficiary.
    function zetherUnshield(
        bytes calldata payload,
        bytes calldata proof,
        ZetherTypes.UA beneficiary,
        address to,
        uint256 amount
    ) external nonReentrant {
        _requirePayee(to);
        uint256 fee = ZetherLib.unshield(payload, proof, beneficiary, amount, to, _env());
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), MetaTxLib.pad(to), amount * ZetherLib.$().shieldScale);
        _payBeneficiary(beneficiary, fee);
    }

    // ------------------------------------------------------------------ roll-over (not allowlisted, CTR-ZTH-34)

    function zetherRollOver(ZetherTypes.UA ua) external nonReentrant {
        ZetherLib.rollOver(ua);
    }

    function zetherRollOverBatch(ZetherTypes.UA[] calldata uas) external nonReentrant {
        ZetherLib.rollOverBatch(uas);
    }

    /// @dev Owner roll-over: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function zetherRollOverSigned(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, bytes calldata sig)
        external nonReentrant
    {
        ZetherLib.rollOverSigned(ua, expectedPendingSeq, validUntilBlock, sig, _env());
    }

    /// @dev Owner mode change: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function zetherSetRollOverMode(
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

    /// @dev The beneficiary fee (D19): `fee · shieldScale` public units (`fee` from the library: 0 without a beneficiary)
    ///      from the pool to the beneficiary's public (UA-ledger) balance.
    function _payBeneficiary(ZetherTypes.UA beneficiary, uint256 fee) internal {
        if (fee != 0) {
            _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), ZetherTypes.UA.unwrap(beneficiary), fee * ZetherLib.$().shieldScale);
        }
    }

    /// @dev The statement binding of this call (CTR-ZTH-34): the envelope's inside `mtxExecute` (`ZTX_V1_RELAYED`),
    ///      else 0 (`ZTX_V1_DIRECT`), so a proof lifted out of a pending envelope fails as a direct call.
    function _env() internal view returns (ZetherLib.Env memory) {
        bytes32 b = _ticketBinding();
        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.tagOf(b), b, BURN_VERIFIER);
    }

    /// @dev The base stores it in the ticket for the self-call of every `mtxExecute` on this token.
    function _envelopeBinding(MetaTxLib.MetaTransaction memory m) internal view virtual override returns (bytes32) {
        return _zetherBinding(m);
    }

    /// @dev The allowlist entries of the layer (CTR-ZTH-34, CTR-MTX-19): every signer-authorised confidential op,
    ///      `ABSOLUTE` (no percentage of a hidden amount, CTR-ZTH-07), dynamic arguments; the roll-over functions are not
    ///      listed (they carry their own signature or none).
    function _isZetherOp(bytes4 sel) internal pure returns (bool) {
        return sel == this.zetherShield.selector || sel == this.zetherTransfer.selector
            || sel == this.zetherTransferCompact.selector || sel == this.zetherTransferNoBundle.selector
            || sel == this.zetherTransferSingle.selector || sel == this.zetherUnshield.selector;
    }

    function _zetherBinding(MetaTxLib.MetaTransaction memory m) internal view returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(
            ZetherLib.TAG_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch, m.nonce, m.validUntil,
            m.mode, r, m.fee, f
        ));
    }
}
