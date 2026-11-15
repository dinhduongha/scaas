// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

import {MetaTxBase, MetaTxBaseCore} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IUALedger} from "./IUALedger.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The UA-signed call path on `MetaTxBase` (owner ruling 2026-11-01), for tokens and for contracts that are not.
/// @notice The one signed generic path of tokens, the router and the mandate wallets (ua-mtx-merge, CTR-MTX-30; Q6): `mtxExecute`, `mtxBatch`,
///         `mtxCancelNonce` on `bytes32` ids through `MtxPipelineLib` (CTR-MTX-17 on an id, CTR-UA-26). A native id signs
///         with its own key in `auth.signature` and reads `_mtxRule` (B); a derived UA is authorized by the registry and
///         reads `_uaAllowed` only, since inside the self-call it is `UA_POOL`; a registry is needed only for a derived
///         side (C). A contract without a ledger runs at fee mode `NONE` (`supportedModes()`), still relayable;
///         `ERC20MetaTx` overrides `_uaChargeFee` with its UA ledger. An op body reads `_subject()`. The address path
///         (`executeMetaTransaction`, R3) takes the same `Ctx` signature rule. `SmartKeyAccount` keeps the address entries
///         (`MetaTxAddressBase`).
abstract contract UAMetaTxBaseCore is MetaTxBaseCore {
    /// @custom:storage-location erc7201:scaas.ua.ledger
    /// @dev `balance` is the UA ledger's (`ERC20MetaTx`). `cancelUsed` served the unordered `uaCancelNonce`
    ///      (legacy/ua-mtx-merge/); unused since, kept because the layout is pinned (test/v2/layout/).
    struct UALedgerStorage {
        mapping(bytes32 ua => uint256) balance;
        mapping(bytes32 digest => bool) cancelUsed;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.ua.ledger")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _UA_STORAGE = 0x9e2def943e5a7ec3982e5d00524104579a6b98ce8b31343ac0092718cc04e900;

    /// @notice The UA registry of this chain (a constructor immutable; 0 = the UA path is off). A factory-made contract
    ///         passes 0 and reads its clone's code instead (`_registry`, `_hedera`, `_mtxCtx`; CTR-TOK-29).
    address private immutable _REGISTRY;
    /// @notice The EIP-1167 clone code hash of the chain's `SmartKeyAccount` implementation (0 = none): such a signer
    ///         gets 400k gas for ERC-1271, every other contract wallet 50k.
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    /// @notice Set on contracts deployed for Hedera (CTR-TOK-23): 64-byte signatures from accounts without code take the
    ///         HIP-632 path.
    bool private immutable _IS_HEDERA;

    constructor(string memory domainName, bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        MetaTxBaseCore(domainName, chainUid_)
    {
        _REGISTRY = registry_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        _IS_HEDERA = hedera_;
    }

    // ------------------------------------------------------------------ views

    function _registryBody() internal view virtual returns (address) {
        return _registry();
    }

    /// @notice CTR-TOK-23: the Hedera flag (the name of the immutable it was).
    function _IS_HEDERABody() internal view returns (bool) {
        return _hedera();
    }

    function _registry() internal view virtual returns (address) { return _REGISTRY; }

    function _hedera() internal view virtual returns (bool) { return _IS_HEDERA; }

    /// @notice The one nonce map (CTR-UA-26), keyed by id: a native address zero-padded, a derived UA as itself.
    function _mtxNonceBody(bytes32 from, uint256 batch) internal view virtual returns (uint256) {
        return _nonce(from, batch);
    }

    function _mtxDigestBody(MetaTxLib.UAMetaTransaction calldata m) internal view virtual returns (bytes32) {
        return _pipeCallDigest(_domainSeparatorV4(), MetaTxLib.UAMETATX_TYPEHASH, _uaEnvelopeOf(m));
    }

    // ------------------------------------------------------------------ entry points

    /// @notice The generic entry (R47: an explicit `UASig`, no packed `bytes auth`).
    function _mtxExecuteBody(MetaTxLib.UAMetaTransaction calldata m, IUARegistry.UASig calldata auth) internal virtual returns (bytes memory)
    {
        return _uaExecute(m, auth);
    }

    /// @notice Atomic: items run in order, each with a fresh ticket; any failure reverts all (CTR-MTX-11).
    function _mtxBatchBody(MetaTxLib.UAMetaTransaction[] calldata ms, IUARegistry.UASig[] calldata auths) internal virtual returns (bool)
    {
        uint256 n = ms.length;
        if (n == 0) revert IMetaTx.MtxBatchEmpty();
        if (n != auths.length) revert IMetaTx.MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) {
            _requireBatchable(bytes4(ms[i].data));
            _uaExecute(ms[i], auths[i]);
        }
        return true;
    }

    /// @notice The signed `cancelNonce(lane)` on ids (Q2, R19): `UACancelNonce(bytes32 from,uint256 lane,E)` run through
    ///         `preNamedUA` like every named op, so nonce-ordered on its own lane `e.batch`, relayer-bound by the mode,
    ///         fee 0 or more, native and derived alike, under the named op's purpose (MD-5). The body bumps `lane` for
    ///         `e.from` itself: no self-call of `cancelNonce`, which refuses a derived subject (`UA_POOL` there).
    function _mtxCancelNonceBody(MetaTxLib.UAEnvelope calldata e, uint256 lane, IUARegistry.UASig calldata auth) internal virtual returns (bytes memory)
    {
        MetaTxLib.UAMetaTransaction memory m = _uaMetaOf(e, abi.encodeCall(IMetaTx.cancelNonce, (lane)));
        _regPre(m.from, IMetaTx.cancelNonce.selector, m.mode);
        // the facts of `cancelNonce(lane)`, fixed: no self-call follows, so no allowlist is asked (a derived id too)
        MtxPipelineLib.Out memory o = _pipePreNamedUA(_mtxCtx(), MetaTxLib.UA_CANCEL_NONCE_TYPEHASH,
            _uaEnvelopeOf(m, 0), abi.encode(lane), MtxPipelineLib.CallFacts(IMetaTx.cancelNonce.selector, 36,
            FEE_CLASS_ABSOLUTE, 0, 36, 0, true, _supportedModesBody()), auth);
        _regFeeTo(MetaTxLib.pad(o.feeTo), o.fee);
        emit IUALedger.UANonceCancelled(e.from, lane, _bumpNonce(e.from, lane));
        if (o.fee != 0) _uaChargeFee(m, o.feeTo, o.fee);
        emit IUALedger.UAMetaTransactionExecuted(e.from, msg.sender, e.batch, e.nonce, o.digest, o.feeTo, o.fee);
        return "";
    }

    // ------------------------------------------------------------------ the pipeline hooks (T66b rule 4)

    /// @dev Every token-side call into `MtxPipelineLib`, each a hook whose default is the library call (the router,
    ///      the wallets, the token modules W, Z, Q). A token's module P overrides them with the library's internal
    ///      twins, T the trade authorisation, A the payment views (spec 2026-11-09-t66b-library-organisation.md §4.1
    ///      rule 4; generated by script/modules/gen_faces.py).
    function _pipePreCall(MtxPipelineLib.Ctx memory c, MtxPipelineLib.Envelope memory e,
        MtxPipelineLib.CallFacts memory f, bytes calldata sig)
        internal virtual returns (MtxPipelineLib.Out memory)
    {
        return MtxPipelineLib.preCall(c, e, f, sig);
    }

    function _pipePreCallUA(MtxPipelineLib.Ctx memory c, MtxPipelineLib.Envelope memory e,
        MtxPipelineLib.CallFacts memory f, IUARegistry.UASig calldata auth)
        internal virtual returns (MtxPipelineLib.Out memory)
    {
        return MtxPipelineLib.preCallUA(c, e, f, auth);
    }

    function _pipePreNamed(MtxPipelineLib.Ctx memory c, bytes32 typehash, MtxPipelineLib.Envelope memory e,
        bytes memory args, MtxPipelineLib.CallFacts memory f, bytes calldata sig)
        internal virtual returns (MtxPipelineLib.Out memory)
    {
        return MtxPipelineLib.preNamed(c, typehash, e, args, f, sig);
    }

    function _pipePreNamedUA(MtxPipelineLib.Ctx memory c, bytes32 typehash, MtxPipelineLib.Envelope memory e,
        bytes memory args, MtxPipelineLib.CallFacts memory f, IUARegistry.UASig calldata auth)
        internal virtual returns (MtxPipelineLib.Out memory)
    {
        return MtxPipelineLib.preNamedUA(c, typehash, e, args, f, auth);
    }

    function _pipePreTransferUA(MtxPipelineLib.Ctx memory c, MetaTxLib.UAMetaTransfer memory t, bytes32 signed,
        uint256 have, IUARegistry.UASig calldata auth)
        internal virtual returns (MtxPipelineLib.Out memory)
    {
        return MtxPipelineLib.preTransferUA(c, t, signed, have, auth);
    }

    function _pipeAuthorize(MtxPipelineLib.Ctx memory c, bytes32 from, bytes32 purpose, bytes32 digest,
        IUARegistry.UASig calldata auth)
        internal view virtual
    {
        MtxPipelineLib.authorize(c, from, purpose, digest, auth);
    }

    function _pipeCallDigest(bytes32 domainSeparator, bytes32 typehash, MtxPipelineLib.Envelope memory e)
        internal pure virtual returns (bytes32)
    {
        return MtxPipelineLib.callDigest(domainSeparator, typehash, e);
    }

    function _pipeTransferDigest(bytes32 domainSeparator, MetaTxLib.UAMetaTransfer calldata t)
        internal pure virtual returns (bytes32)
    {
        return MtxPipelineLib.transferDigest(domainSeparator, t);
    }

    function _pipePayeeFeeDigest(bytes32 domainSeparator, MetaTxLib.UAMetaTransfer calldata t, uint256 fee,
        address feeRecipient, uint256 validUntil)
        internal pure virtual returns (bytes32)
    {
        return MtxPipelineLib.payeeFeeDigest(domainSeparator, t, fee, feeRecipient, validUntil);
    }

    function _pipePayWithTaxHash(MetaTxLib.UAMetaTransfer calldata t, uint8 taxMode, uint256 tax)
        internal pure virtual returns (bytes32)
    {
        return MtxPipelineLib.payWithTaxHash(t, taxMode, tax);
    }

    function _pipeMetaPayId(MetaTxLib.PayMeta calldata m)
        internal pure virtual returns (bytes32)
    {
        return MtxPipelineLib.metaPayId(m);
    }

    function _pipePayMeta(bytes32 entryRef, MetaTxLib.PayMeta calldata m)
        internal virtual
    {
        MtxPipelineLib.payMeta(entryRef, m);
    }

    function _pipePayRecord(bytes32 payNo, bytes32 to, uint256 amount)
        internal virtual
    {
        MtxPipelineLib.payRecord(payNo, to, amount);
    }

    function _pipePaymentCount(bytes32 payNo)
        internal view virtual returns (uint256)
    {
        return MtxPipelineLib.paymentCount(payNo);
    }

    function _pipePaymentsOf(bytes32 payNo, uint256 offset, uint256 limit)
        internal view virtual returns (MetaTxLib.PayRecord[] memory)
    {
        return MtxPipelineLib.paymentsOf(payNo, offset, limit);
    }

    // ------------------------------------------------------------------ the pipeline on MtxPipelineLib

    /// @notice This contract's immutables for `MtxPipelineLib` (metatx split R2): the only place that builds a `Ctx`; a
    ///         factory-made contract reads its code's head once instead (`MetaTokenBase`).
    function _mtxCtx() internal view virtual returns (MtxPipelineLib.Ctx memory) {
        return MtxPipelineLib.Ctx(_domainSeparatorV4(), _REGISTRY, _SMART_KEY_CLONE_CODEHASH, _IS_HEDERA);
    }

    /// @dev What the library needs of `data` and of this kind's hooks: selector (zero-padded when shorter than 4),
    ///      length, the rule, the basis word when present (else 0) and, on the UA path, the UA verdict.
    function _callFacts(bytes memory data, bool ua) internal view returns (MtxPipelineLib.CallFacts memory f) {
        f.sel = bytes4(data);
        f.len = data.length;
        MtxRule memory r = _mtxRule(f.sel);
        (f.feeClass, f.amountArg, f.staticLen) = (r.feeClass, r.amountArg, r.staticLen);
        uint256 basisEnd = 36 + 32 * uint256(r.amountArg);
        if (r.feeClass == FEE_CLASS_AMOUNT && data.length >= basisEnd) {
            uint256 basis;
            assembly ("memory-safe") { basis := mload(add(data, basisEnd)) }
            f.basis = basis;
        }
        if (ua) f.uaAllowed = _uaAllowed(f.sel);
        f.supported = _supportedModesBody();
    }

    /// @notice The signer as an id: the subject of the live ticket, else the direct caller padded.
    function _subject() internal view returns (bytes32 s) {
        s = _ticketSubject();
        if (s == 0) s = MetaTxLib.pad(_msgSender());
    }

    /// @dev The generic pipeline on ids (CTR-MTX-17 on a `bytes32` signer) on the library: `preCallUA` runs 1 envelope,
    ///      2 authorization, 3 the allowlist (`_uaAllowed` for a derived id, `MetaTxUnknownOp`; `_mtxRule` for every id),
    ///      shape, fee class and the fee amount, 4 nonce; then 5 self-call under the id, 6 the fee hook, 7 event.
    function _uaExecute(MetaTxLib.UAMetaTransaction memory m, IUARegistry.UASig calldata auth)
        internal returns (bytes memory)
    {
        _regPre(m.from, bytes4(m.data), m.mode);
        return _uaSettle(m, _pipePreCallUA(_mtxCtx(), _uaEnvelopeOf(m), _callFacts(m.data, true), auth));
    }

    /// @dev `_uaExecute` of a named `ua*` entry (TS-D14), the twin of `_named`.
    function _namedUA(bytes32 typehash, bytes4 sel, MetaTxLib.UAEnvelope calldata e, bytes memory args,
        IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        return _namedCallUA(typehash, e, args, abi.encodePacked(sel, args), auth);
    }

    /// @dev `_namedUA` where the struct's words are not the call's arguments (`ERC20MetaTx._namedCall`).
    function _namedCallUA(bytes32 typehash, MetaTxLib.UAEnvelope calldata e, bytes memory words, bytes memory data,
        IUARegistry.UASig calldata auth) internal returns (bytes memory)
    {
        MetaTxLib.UAMetaTransaction memory m = _uaMetaOf(e, data);
        _regPre(m.from, bytes4(data), m.mode);
        return _uaSettle(m, _pipePreNamedUA(
            _mtxCtx(), typehash, _uaEnvelopeOf(m, 0), words, _callFacts(m.data, true), auth));
    }

    /// @dev The `UAMetaTransaction` a named entry runs as (the binding hooks and the fee read it).
    function _uaMetaOf(MetaTxLib.UAEnvelope calldata e, bytes memory data)
        private pure returns (MetaTxLib.UAMetaTransaction memory)
    {
        return MetaTxLib.UAMetaTransaction(e.from, data, e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee,
            e.feeRecipient);
    }

    /// @dev Steps 5-7 of the UA path.
    function _uaSettle(MetaTxLib.UAMetaTransaction memory m, MtxPipelineLib.Out memory o)
        private returns (bytes memory ret)
    {
        _regFeeTo(MetaTxLib.pad(o.feeTo), o.fee);
        ret = _selfCall(m.from, m.data, _uaEnvelopeBinding(m));                                         // 5
        if (o.fee != 0) _uaChargeFee(m, o.feeTo, o.fee);                                                // 6
        emit IUALedger.UAMetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, o.digest, o.feeTo, o.fee); // 7
    }

    /// @dev The envelope of `m` for the library: `data` as its hash (over this memory copy).
    function _uaEnvelopeOf(MetaTxLib.UAMetaTransaction memory m)
        internal pure returns (MtxPipelineLib.Envelope memory)
    {
        return _uaEnvelopeOf(m, keccak256(m.data));
    }

    function _uaEnvelopeOf(MetaTxLib.UAMetaTransaction memory m, bytes32 dataHash)
        internal pure returns (MtxPipelineLib.Envelope memory)
    {
        return MtxPipelineLib.Envelope(m.from, dataHash, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee,
            m.feeRecipient);
    }

    function _uaOn() internal view {
        if (_registry() == address(0)) revert IUALedger.UALedgerOff();
    }

    function _ua() internal pure returns (UALedgerStorage storage $) {
        assembly ("memory-safe") { $.slot := _UA_STORAGE }
    }

    // ------------------------------------------------------------------ hooks

    /// @notice The address path's signature under this contract's `Ctx`, as the UA path's (HIP-632, the clone's ERC-1271
    ///         cap). A token never reaches it: its `_execute` runs on the library.
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual override {
        MtxPipelineLib.requireSignature(_mtxCtx(), from, digest, sig);
    }

    /// @notice Step 6, fee ≠ 0 only: no ledger to charge => refused, as `_chargeFee` on the address path (CTR-MTX-22).
    ///         Reached only by a contract whose `supportedModes()` claims a fee mode.
    function _uaChargeFee(MetaTxLib.UAMetaTransaction memory m, address, uint256) internal virtual {
        revert IMetaTx.MetaTxUnknownMode(m.mode);
    }

    /// @notice The envelope binding a proof inside the UA path's self-call carries (CTR-PQZ-15, P6g plan D4,
    ///         CTR-ZTH-51): 0 by default; the confidential layers return their own (tags `SCAAS-PQZ-UA-ENVELOPE-V1`,
    ///         `SCAAS-ZETHER-UA-ENVELOPE-V1`), never 0, so step 5 writes it on every envelope of theirs (the address
    ///         path's `_envelopeBinding` rule).
    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory) internal view virtual returns (bytes32) {
        return bytes32(0);
    }

    /// @notice The UA allowlist (CTR-UA-26): selectors a `UAMetaTransaction` may call; none on the base, `NORMAL` adds
    ///         `burn`, the wrapper kinds their `unwrap`s and `unwrapToUA`. `approve`, `trade`, transfers and the dedicated
    ///         `…ToUA` functions are never on it (`MetaTxUnknownOp`).
    function _uaAllowed(bytes4) internal view virtual returns (bool) {
        return false;
    }

    // ------------------------------------------------------------------ regulated hooks (regulated-kinds spec §2.2)

    /// @notice Empty here, so a plain kind and the router read nothing more (CTR-GOV-11, "+0" pinned by
    ///         `test/governance/PlusZero.t.sol`); only a regulated kind overrides. Arguments are raw values the caller
    ///         already holds (F-10). Before `MtxPipelineLib.pre*` on `_uaExecute`, `_namedCallUA`, `mtxCancelNonce`,
    ///         `_execute`, `_namedCall` (`from` padded), `_uaExecuteTransfer` (`sel` 0): `sel` the inner op's selector,
    ///         `mode` the envelope's.
    function _regPre(bytes32 /* from */, bytes4 /* sel */, uint32 /* mode */) internal view virtual {}

    /// @notice Empty here (as `_regPre`). After `pre*` and before the self-call or move of the same seats, with the
    ///         pipeline's `feeTo` and `fee`; and the fee legs of `payWithFee`, `payWithFeeToUA`, `mtxPayWithPayeeFee`,
    ///         `mtxRelayFee`, `mtxWrapOrder`.
    function _regFeeTo(bytes32 /* feeTo */, uint256 /* fee */) internal view virtual {}
}

/// @notice `UAMetaTxBaseCore` with its external entries, each calling its body (T66b, spec 2026-11-09-t66b-library-organisation.md §4.4):
///         the form its non-token users inherit, ABI and modifiers unchanged. UNAUDITED.
abstract contract UAMetaTxBase is UAMetaTxBaseCore, IERC5267, IMetaTx {
    function registry() public view virtual returns (address) {
        return _registryBody();
    }

    function IS_HEDERA() external view returns (bool) {
        return _IS_HEDERABody();
    }

    function mtxNonce(bytes32 from, uint256 batch) public view virtual returns (uint256) {
        return _mtxNonceBody(from, batch);
    }

    function mtxDigest(MetaTxLib.UAMetaTransaction calldata m) public view virtual returns (bytes32) {
        return _mtxDigestBody(m);
    }

    function mtxExecute(MetaTxLib.UAMetaTransaction calldata m, IUARegistry.UASig calldata auth) public virtual nonReentrant returns (bytes memory) {
        return _mtxExecuteBody(m, auth);
    }

    function mtxBatch(MetaTxLib.UAMetaTransaction[] calldata ms, IUARegistry.UASig[] calldata auths) public virtual nonReentrant returns (bool) {
        return _mtxBatchBody(ms, auths);
    }

    function mtxCancelNonce(MetaTxLib.UAEnvelope calldata e, uint256 lane, IUARegistry.UASig calldata auth) public virtual nonReentrant returns (bytes memory) {
        return _mtxCancelNonceBody(e, lane, auth);
    }

    function chainUid() external view virtual override returns (bytes32) {
        return _chainUidBody();
    }

    function supportedModes() public view virtual override returns (uint32) {
        return _supportedModesBody();
    }

    function mtxSelectors() public view virtual override returns (bytes4[] memory selectors, uint8[] memory feeClass, uint8[] memory amountArg) {
        return _mtxSelectorsBody();
    }

    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature) external override nonReentrant returns (bool) {
        return _executeMetaTransactionBody(m, signature);
    }

    function cancelNonce(uint256 batch) external override nonReentrant {
        _cancelNonceBody(batch);
    }

    function eip712Domain() public view virtual override returns (
            bytes1 fields, string memory name, string memory version, uint256 chainId,
            address verifyingContract, bytes32 salt, uint256[] memory extensions
        ) {
        return _eip712DomainBody();
    }
}
