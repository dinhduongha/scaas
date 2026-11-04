// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20MetaTx} from "../metatx/ERC20MetaTx.sol";
import {MetaTokenBase} from "../metatx/MetaTokenBase.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {IZetherToken} from "./IZetherToken.sol";
import {IConfidentialToken} from "../confidential/IConfidentialToken.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "./IZetherVerifier.sol";
import {ITransferDisclosure} from "./ITransferDisclosure.sol";
import {ZetherTypes} from "./ZetherTypes.sol";
import {ZetherLib} from "./ZetherLib.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {
    ENV_ZETHER_TRANSFER, ENV_ZETHER_BURN, ENV_ZETHER_INNER_PRODUCT, ENV_ZETHER_DISCLOSURE
} from "../factory/IFactoryToken.sol";

/// @dev What the layer reads from a transfer / burn verifier besides `IZetherVerifierCommon`.
interface IInnerProductBound {
    function innerProduct() external view returns (address);
}

/// @title The Zether layer of the kinds `NORMAL_ZETHER` and `WRAPPED_ZETHER` (CTR-ZTH-44): the entry points of
///        CTR-ZTH-45 and the views; the state and the logic are `ZetherLib` (`scaas.zether`).
/// @notice **UNAUDITED.** Open on every chain (owner ruling 2026-10-31; the factory kind gate stays). A layer over the
///         public ERC-20 balance: `mtxShield` moves public units to `SHIELD_POOL`, `mtxUnshield` moves them back (D19: no
///         burn, no mint; to an address or a signing UA, CTR-ZTH-51); the confidential layer
///         keeps no underlying of its own. The registry (the base's, `ERC20MetaTx`), the disclosure contract and the
///         curve's transfer and burn verifiers are implementation immutables (CTR-ZTH-20: `OpenFactory` registers an
///         implementation only on its canonical verifiers), so the curve is an attribute of the release (`curve()`); the
///         auditor key and the two modes (`disclosureMode`, `auditorMode`) are chosen at creation and never change.
///         Every entry point is `nonReentrant`. The direct ops take explicit parameters and the proof, the only authority
///         (`IZetherToken`, TS-D17); each has a signed overload (`Envelope` first) and a `ua*` twin (TS-D14, TS-D16), which
///         run it through the ticket self-call, so the op's body and the statement's binding are the generic path's.
abstract contract ZetherLayer is MetaTokenBase, IZetherToken {
    bytes32 private constant ROLL_OVER_TYPEHASH = keccak256(
        "RollOver(address from,bytes32 ua,uint256 n,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_ROLL_OVER_TYPEHASH = keccak256(
        "UARollOver(bytes32 from,bytes32 ua,uint256 n,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant ROLL_OVER_BATCH_TYPEHASH = keccak256(
        "RollOverBatch(address from,bytes32[] uas,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_ROLL_OVER_BATCH_TYPEHASH = keccak256(
        "UARollOverBatch(bytes32 from,bytes32[] uas,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant ROLL_OVER_SIGNED_TYPEHASH = keccak256(
        "RollOverSigned(address from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_ROLL_OVER_SIGNED_TYPEHASH = keccak256(
        "UARollOverSigned(bytes32 from,bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant SET_MODE_TYPEHASH = keccak256(
        "SetRollOverMode(address from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    bytes32 private constant UA_SET_MODE_TYPEHASH = keccak256(
        "UASetRollOverMode(bytes32 from,bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );
    // The typehashes of the transfer and unshield entries are `ZetherLib`'s (CTR-ZTH-94).

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
        if (d.length != 4 || env.hedera || !SigCheck.isContract(_REGISTRY)) revert BadInit(); // never on Hedera
        IZetherVerifier t = IZetherVerifier(d[ENV_ZETHER_TRANSFER]);
        IZetherBurnVerifier b = IZetherBurnVerifier(d[ENV_ZETHER_BURN]);
        address ip = d[ENV_ZETHER_INNER_PRODUCT];
        if (!SigCheck.isContract(address(t)) || !SigCheck.isContract(address(b)) || !SigCheck.isContract(d[ENV_ZETHER_DISCLOSURE])
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
    /// @notice The record `R` for `disclosure()`, always from state: inline (BUNDLE, single) or read from its SSTORE2
    ///         pointer (commit-reveal); empty for an unknown ref.
    function transferEntry(bytes32 entryRef) external view returns (bytes memory) {
        address ptr = ZetherLib.$().entryPtrs[entryRef];
        return ptr != address(0) ? SSTORE2.read(ptr) : ZetherLib.$().entries[entryRef];
    }

    /// @notice The sender memo of a commit-reveal entry (CTR-ZTH-50), empty otherwise.
    function transferMemo(bytes32 entryRef) external view returns (bytes memory) { return ZetherLib.$().memos[entryRef]; }
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

    /// @notice The signed `mtxShield` (TS-D14, TS-D16).
    function mtxShield(MetaTxLib.Envelope calldata e, bytes32 toUA, uint256 amount, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(MetaTxLib.SHIELD_TYPEHASH, IConfidentialToken.mtxShield.selector, e, abi.encode(toUA, amount), sig);
    }

    /// @notice R47: an explicit `UASig` (ua-mtx-merge T1; the `bytes auth` form is in legacy/ua-mtx-merge/).
    function uaShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        return _namedUA(MetaTxLib.UA_SHIELD_TYPEHASH, IConfidentialToken.mtxShield.selector, e, abi.encode(toUA, amount), auth);
    }

    // ------------------------------------------------------------------ transfer (CTR-ZTH-37, CTR-ZTH-38)

    /// @notice The token's default: the record stored (`BUNDLE` token) or commit-reveal (`COMPACT` token). The body is
    ///         `ZetherLib`'s, which reads `t` and `proof` from this call's own arguments (CTR-ZTH-94).
    function mtxConfidentialTransfer(ZetherMulti calldata t, bytes calldata proof) external nonReentrant returns (bytes32) {
        proof;
        return _multi(t.beneficiaryUA, ZetherLib.defaultMode());
    }

    function mtxConfidentialTransferCompact(ZetherMulti calldata t, bytes calldata proof) external nonReentrant returns (bytes32) {
        proof;
        return _multi(t.beneficiaryUA, ZetherTypes.TransferMode.HASH);
    }

    function mtxConfidentialTransferSingle(ZetherSingle calldata t, bytes calldata proof) external nonReentrant returns (bytes32) {
        proof;
        (bytes32 ref, uint256 fee) = abi.decode(
            _lib(address(ZetherLib), ZetherLib.transferSingle.selector, abi.encode(_env())), (bytes32, uint256));
        _fromPool(ZetherTypes.UA.wrap(t.beneficiaryUA), fee);
        return ref;
    }

    /// @notice The signed forms (TS-D14, TS-D16): the struct's `args` and `proof` by hash, as a wallet shows them;
    ///         `ZetherLib` builds the struct's words and the op's call from this call's own arguments (CTR-ZTH-94).
    function mtxConfidentialTransfer(MetaTxLib.Envelope calldata e, ZetherMulti calldata t, bytes calldata proof, bytes calldata sig)
        external nonReentrant returns (bytes32)
    {
        (t, proof);
        return _ref(_namedZ(ZetherLib.multiCall.selector, false, e, sig));
    }

    function uaConfidentialTransfer(MetaTxLib.UAEnvelope calldata e, ZetherMulti calldata t, bytes calldata proof,
        IUARegistry.UASig calldata auth) external nonReentrant returns (bytes32)
    {
        (t, proof);
        return _ref(_namedZUA(ZetherLib.uaMultiCall.selector, false, e, auth));
    }

    function mtxConfidentialTransferCompact(MetaTxLib.Envelope calldata e, ZetherMulti calldata t, bytes calldata proof,
        bytes calldata sig) external nonReentrant returns (bytes32)
    {
        (t, proof);
        return _ref(_namedZ(ZetherLib.multiCall.selector, true, e, sig));
    }

    function uaConfidentialTransferCompact(MetaTxLib.UAEnvelope calldata e, ZetherMulti calldata t, bytes calldata proof,
        IUARegistry.UASig calldata auth) external nonReentrant returns (bytes32)
    {
        (t, proof);
        return _ref(_namedZUA(ZetherLib.uaMultiCall.selector, true, e, auth));
    }

    function mtxConfidentialTransferSingle(MetaTxLib.Envelope calldata e, ZetherSingle calldata t, bytes calldata proof,
        bytes calldata sig) external nonReentrant returns (bytes32)
    {
        (t, proof);
        return _ref(_namedZ(ZetherLib.singleCall.selector, false, e, sig));
    }

    function uaConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, ZetherSingle calldata t, bytes calldata proof,
        IUARegistry.UASig calldata auth) external nonReentrant returns (bytes32)
    {
        (t, proof);
        return _ref(_namedZUA(ZetherLib.uaSingleCall.selector, false, e, auth));
    }

    // ------------------------------------------------------------------ unshield

    /// @notice The unshield statement binds `amount` and `recipient`; moves `amount · shieldScale` public units from
    ///         `SHIELD_POOL` to `recipient` (D19): a padded address (not a pool) or a registered SIGNING UA, credited on
    ///         the UA ledger (CTR-ZTH-51); then the fee to the beneficiary. The proof part is `ZetherLib`'s (CTR-ZTH-94).
    function mtxUnshield(ZetherBurn calldata b, uint256 amount, bytes32 recipient, bytes calldata proof) external nonReentrant {
        proof;
        _requireRecipient(recipient);
        uint256 fee = abi.decode(_lib(address(ZetherLib), ZetherLib.unshield.selector, abi.encode(_env())), (uint256));
        _poolMove(MetaTxLib.pad(MetaTxLib.SHIELD_POOL), recipient, amount * ZetherLib.$().shieldScale);
        _fromPool(ZetherTypes.UA.wrap(b.beneficiaryUA), fee);
    }

    /// @notice The signed `mtxUnshield`: `amount` and `recipient` flat in the struct, as in the op.
    function mtxUnshield(MetaTxLib.Envelope calldata e, ZetherBurn calldata b, uint256 amount, bytes32 recipient,
        bytes calldata proof, bytes calldata sig) external nonReentrant returns (bytes memory)
    {
        (b, amount, recipient, proof);
        return _namedZ(ZetherLib.unshieldCall.selector, false, e, sig);
    }

    function uaUnshield(MetaTxLib.UAEnvelope calldata e, ZetherBurn calldata b, uint256 amount, bytes32 recipient,
        bytes calldata proof, IUARegistry.UASig calldata auth) external nonReentrant returns (bytes memory)
    {
        (b, amount, recipient, proof);
        return _namedZUA(ZetherLib.uaUnshieldCall.selector, false, e, auth);
    }

    // ------------------------------------------------------------------ roll-over (all four allowlisted, CTR-ZTH-34)

    /// @notice The one aggregated pending of `ua` into `acc` for any `n ≥ 1` (`RollOverRange` for 0).
    function mtxRollOver(bytes32 ua, uint256 n) external nonReentrant {
        if (n == 0) revert RollOverRange(n);
        ZetherLib.rollOver(ZetherTypes.UA.wrap(ua));
    }

    function mtxRollOverBatch(ZetherTypes.UA[] calldata uas) external nonReentrant {
        ZetherLib.rollOverBatch(uas);
    }

    /// @dev Owner roll-over: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function mtxRollOverSigned(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig)
        external nonReentrant
    {
        ZetherLib.rollOverSigned(ua, expectedPendingSeq, validUntilBlock, ownerSig, _env());
    }

    /// @dev Owner mode change: a registered Zether UA only (`AccountNotRegistered` otherwise).
    function mtxSetRollOverMode(
        ZetherTypes.UA ua,
        ZetherTypes.RollOverMode mode,
        uint64 validUntilBlock,
        IUARegistry.UASig calldata ownerSig
    ) external nonReentrant {
        ZetherLib.setRollOverMode(ua, mode, validUntilBlock, ownerSig, _env());
    }

    /// @notice The signed roll-overs; the owner's signature travels beside the struct, never in it (Appendix X.1).
    function mtxRollOver(MetaTxLib.Envelope calldata e, bytes32 ua, uint256 n, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(ROLL_OVER_TYPEHASH, IConfidentialToken.mtxRollOver.selector, e, abi.encode(ua, n), sig);
    }

    function uaRollOver(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 n, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        return _namedUA(UA_ROLL_OVER_TYPEHASH, IConfidentialToken.mtxRollOver.selector, e, abi.encode(ua, n), auth);
    }

    function mtxRollOverBatch(MetaTxLib.Envelope calldata e, ZetherTypes.UA[] calldata uas, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _batchCall(uas);
        return _namedCall(ROLL_OVER_BATCH_TYPEHASH, e, words, data, sig);
    }

    function uaRollOverBatch(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA[] calldata uas, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _batchCall(uas);
        return _namedCallUA(UA_ROLL_OVER_BATCH_TYPEHASH, e, words, data, auth);
    }

    function mtxRollOverSigned(MetaTxLib.Envelope calldata e, ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock,
        IUARegistry.UASig calldata ownerSig, bytes calldata sig) external nonReentrant returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _signedCall(ua, expectedPendingSeq, validUntilBlock, ownerSig);
        return _namedCall(ROLL_OVER_SIGNED_TYPEHASH, e, words, data, sig);
    }

    function uaRollOverSigned(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock,
        IUARegistry.UASig calldata ownerSig, IUARegistry.UASig calldata auth) external nonReentrant returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _signedCall(ua, expectedPendingSeq, validUntilBlock, ownerSig);
        return _namedCallUA(UA_ROLL_OVER_SIGNED_TYPEHASH, e, words, data, auth);
    }

    function mtxSetRollOverMode(MetaTxLib.Envelope calldata e, ZetherTypes.UA ua, ZetherTypes.RollOverMode rollOverMode,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, bytes calldata sig) external nonReentrant returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _modeCall(ua, rollOverMode, validUntilBlock, ownerSig);
        return _namedCall(SET_MODE_TYPEHASH, e, words, data, sig);
    }

    function uaSetRollOverMode(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, ZetherTypes.RollOverMode rollOverMode,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bytes memory)
    {
        (bytes memory words, bytes memory data) = _modeCall(ua, rollOverMode, validUntilBlock, ownerSig);
        return _namedCallUA(UA_SET_MODE_TYPEHASH, e, words, data, auth);
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

    /// @dev The multi-recipient entry points by stored form `mode`: the library's `txFee` to the beneficiary, then its
    ///      `decoyFee` to EVERY leg, the real recipient included (owner 2026-10-20: uniform, so it reveals no decoy).
    function _multi(bytes32 beneficiary, ZetherTypes.TransferMode mode) private returns (bytes32 ref) {
        ZetherLib.Paid memory f;
        (ref, f) = abi.decode(_lib(address(ZetherLib), ZetherLib.transferMulti.selector, abi.encode(mode, _env())),
            (bytes32, ZetherLib.Paid));
        _fromPool(ZetherTypes.UA.wrap(beneficiary), f.txFee);
        if (f.decoyFee != 0) for (uint256 j; j < f.legs.length; ++j) _fromPool(f.legs[j], f.decoyFee);
    }

    /// @dev CTR-ZTH-94: a DELEGATECALL into `lib` that hands it this call's own arguments as they arrived (`msg.data[4:]`,
    ///      decoded there, so no coder of a Zether struct stays in the token) under the library function `sel`, then
    ///      `tail` (what the library cannot read itself: the immutables of `_env()`); the library's revert bubbles.
    ///      Built in place, one copy of the arguments (a `bytes` argument to `delegatecall` would be copied once more).
    function _lib(address lib, bytes4 sel, bytes memory tail) internal returns (bytes memory r) {
        assembly ("memory-safe") {
            let p := mload(0x40)
            let n := calldatasize()
            mstore(p, sel)
            calldatacopy(add(p, 4), 4, sub(n, 4))
            let t := mload(tail)
            mcopy(add(p, n), add(tail, 32), t)
            let ok := delegatecall(gas(), lib, p, add(n, t), 0, 0)
            r := p // the request is spent: the reply takes its place
            mstore(r, returndatasize())
            returndatacopy(add(r, 32), 0, returndatasize())
            mstore(0x40, add(add(r, 32), and(add(returndatasize(), 31), not(31))))
            if iszero(ok) { revert(add(r, 32), returndatasize()) }
        }
    }

    /// @dev What a signed entry signs and runs, built by `lib` (`sel`) from this call's own arguments (`_lib`, `compact` the
    ///      tail word): its typehash, the words its struct hashes and the op's call. Read in place from the library's
    ///      return `(bytes32, bytes, bytes)`, the library's own encoding: no second copy of the op's call.
    function _built(address lib, bytes4 sel, bool compact)
        internal returns (bytes32 typehash, bytes memory words, bytes memory data)
    {
        bytes memory r = _lib(lib, sel, abi.encode(compact));
        assembly ("memory-safe") {
            let p := add(r, 32)
            typehash := mload(p)
            words := add(p, mload(add(p, 32)))
            data := add(p, mload(add(p, 64)))
        }
    }

    /// @dev A signed entry `ZetherLib` builds (`_built`), through the address path.
    function _namedZ(bytes4 sel, bool compact, MetaTxLib.Envelope calldata e, bytes calldata sig) private returns (bytes memory) {
        (bytes32 th, bytes memory words, bytes memory data) = _built(address(ZetherLib), sel, compact);
        return _namedCall(th, e, words, data, sig);
    }

    /// @dev Likewise through the UA path.
    function _namedZUA(bytes4 sel, bool compact, MetaTxLib.UAEnvelope calldata e, IUARegistry.UASig calldata auth)
        private returns (bytes memory)
    {
        (bytes32 th, bytes memory words, bytes memory data) = _built(address(ZetherLib), sel, compact);
        return _namedCallUA(th, e, words, data, auth);
    }

    // What a signed roll-over and its twin share: the words its struct hashes (TS-D17) and the op's call.

    function _batchCall(ZetherTypes.UA[] calldata uas) private pure returns (bytes memory, bytes memory) {
        return (abi.encode(keccak256(abi.encodePacked(uas))), abi.encodeCall(IZetherToken.mtxRollOverBatch, (uas)));
    }

    function _signedCall(ZetherTypes.UA ua, uint64 expectedPendingSeq, uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig)
        private pure returns (bytes memory, bytes memory)
    {
        return (abi.encode(ua, expectedPendingSeq, validUntilBlock),
            abi.encodeCall(IZetherToken.mtxRollOverSigned, (ua, expectedPendingSeq, validUntilBlock, ownerSig)));
    }

    function _modeCall(ZetherTypes.UA ua, ZetherTypes.RollOverMode rollOverMode, uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig)
        private pure returns (bytes memory, bytes memory)
    {
        return (abi.encode(ua, rollOverMode, validUntilBlock),
            abi.encodeCall(IZetherToken.mtxSetRollOverMode, (ua, rollOverMode, validUntilBlock, ownerSig)));
    }

    /// @dev The entry reference the self-call returned.
    function _ref(bytes memory ret) private pure returns (bytes32) {
        return abi.decode(ret, (bytes32));
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
        return ZetherLib.Env(_REGISTRY, CHAIN_UID, ZetherLib.tagOf(b), b, BURN_VERIFIER, _domainSeparatorV4());
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
    ///      `ABSOLUTE` (no percentage of a hidden amount, CTR-ZTH-07), dynamic arguments; every roll-over function is
    ///      listed too (owner 2026-10-20: every mtx* write is relayable; the fee may be 0); the signed ones keep
    ///      checking their own owner signature. The same set is on the UA allowlist (CTR-ZTH-51).
    function _isZetherOp(bytes4 sel) internal pure returns (bool) {
        return sel == IConfidentialToken.mtxShield.selector || sel == IZetherToken.mtxConfidentialTransfer.selector
            || sel == IZetherToken.mtxConfidentialTransferCompact.selector
            || sel == IZetherToken.mtxConfidentialTransferSingle.selector || sel == IZetherToken.mtxUnshield.selector
            || sel == IConfidentialToken.mtxRollOver.selector || sel == IZetherToken.mtxRollOverBatch.selector
            || sel == IZetherToken.mtxRollOverSigned.selector || sel == IZetherToken.mtxSetRollOverMode.selector;
    }

    function _zetherBinding(MetaTxLib.MetaTransaction memory m) internal view returns (bytes32) {
        (address r, address f) = MetaTxLib.canon(m);
        return keccak256(abi.encode(
            ZetherLib.TAG_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch, m.nonce, m.validUntil,
            m.mode, r, m.fee, f
        ));
    }
}
