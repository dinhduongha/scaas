// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxBase} from "./MetaTxBase.sol";
import {IUALedger} from "./IUALedger.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title The UA-signed call path on `MetaTxBase` (owner ruling 2026-11-01), for tokens and for contracts that are not.
/// @notice `uaExecute` is a general entry: any contract on this base takes UA-signed calls of its `_uaAllowed` selectors
///         through `MtxPipelineLib` (CTR-MTX-17 on a `bytes32` signer, CTR-UA-26). A contract without a ledger runs at
///         fee mode `NONE` (`supportedModes()`, both paths), still relayable; `ERC20MetaTx` overrides `_uaChargeFee` with
///         its UA ledger. An op body reads `_subject()`, since `_msgSender()` is `UA_POOL` for every derived subject; a
///         derived signer cancels a lane with `uaCancelNonce`. The address path here takes the same `Ctx` signature rule.
///         `MetaTxBase` stays free of this code: `SmartKeyAccount` and `MandateWallet` have no registry.
abstract contract UAMetaTxBase is MetaTxBase {
    /// @custom:storage-location erc7201:scaas.ua.ledger
    /// @dev `balance` is the UA ledger's (`ERC20MetaTx`); `cancelUsed` is every contract's on this base.
    struct UALedgerStorage {
        mapping(bytes32 ua => uint256) balance;
        mapping(bytes32 digest => bool) cancelUsed;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.ua.ledger")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _UA_STORAGE = 0x9e2def943e5a7ec3982e5d00524104579a6b98ce8b31343ac0092718cc04e900;

    /// @notice The UA registry of this chain (an implementation immutable; 0 = the UA path is off).
    address internal immutable _REGISTRY;
    /// @notice The EIP-1167 clone code hash of the chain's `SmartKeyAccount` implementation (0 = none): such a signer
    ///         gets 400k gas for ERC-1271, every other contract wallet 50k.
    bytes32 internal immutable _SMART_KEY_CLONE_CODEHASH;

    /// @notice Set on implementations deployed for Hedera (CTR-TOK-23): 64-byte signatures from accounts without code
    ///         take the HIP-632 path.
    bool public immutable IS_HEDERA;

    constructor(string memory domainName, bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        MetaTxBase(domainName, chainUid_)
    {
        _REGISTRY = registry_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        IS_HEDERA = hedera_;
    }

    // ------------------------------------------------------------------ views

    function registry() public view virtual returns (address) {
        return _REGISTRY;
    }

    /// @notice The one nonce map (CTR-UA-26): `uaNonce(pad(a), b) == mtxNonce(a, b)`.
    function uaNonce(bytes32 ua, uint256 batch) public view virtual returns (uint256) {
        return _nonce(ua, batch);
    }

    function uaDigest(MetaTxLib.UAMetaTransaction calldata m) public view virtual returns (bytes32) {
        return MtxPipelineLib.callDigest(_domainSeparatorV4(), MetaTxLib.UAMETATX_TYPEHASH, _uaEnvelopeOf(m));
    }

    /// @notice The `metatx-cancel` digest (accounts.md §1.5): `CANCEL_TAG` is the purpose tag itself.
    function uaCancelDigest(bytes32 ua, uint256 batch, uint256 validUntil) public view virtual returns (bytes32) {
        return keccak256(abi.encode(
            UAKinds.PURPOSE_METATX_CANCEL, block.chainid, CHAIN_UID, address(this), ua, batch, validUntil
        ));
    }

    // ------------------------------------------------------------------ entry points

    function uaExecute(MetaTxLib.UAMetaTransaction calldata m, bytes calldata auth)
        public virtual nonReentrant returns (bytes memory)
    {
        return _uaExecute(m, auth);
    }

    /// @notice Atomic, items in order, each with a fresh ticket (as `mtxBatch`).
    function uaBatch(MetaTxLib.UAMetaTransaction[] calldata ms, bytes[] calldata auths)
        public virtual nonReentrant returns (bool)
    {
        uint256 n = ms.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != auths.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) {
            _requireBatchable(bytes4(ms[i].data));
            _uaExecute(ms[i], auths[i]);
        }
        return true;
    }

    /// @notice A derived UA's `cancelNonce`, signed under purpose `metatx-cancel`; each signature works once. Native ids
    ///         use `cancelNonce` (the same map, `pad(sender)`).
    function uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, bytes calldata auth)
        public virtual nonReentrant
    {
        _uaOn();
        if (UAKinds.inNativeSpace(ua)) revert IUALedger.UAKindNotAccepted(ua, 0);
        if (block.timestamp > validUntil) revert MetaTxExpired(validUntil, block.timestamp);
        bytes32 d = uaCancelDigest(ua, batch, validUntil);
        UALedgerStorage storage $ = _ua();
        if ($.cancelUsed[d]) revert IUALedger.UACancelUsed();
        IUARegistry(_REGISTRY).requireAuthorized(ua, UAKinds.PURPOSE_METATX_CANCEL, d, UAKinds.uaSig(ua, auth)); // R1 → C2
        $.cancelUsed[d] = true;
        emit IUALedger.UANonceCancelled(ua, batch, _bumpNonce(ua, batch));
    }

    // ------------------------------------------------------------------ the pipeline on MtxPipelineLib

    /// @notice This contract's immutables for `MtxPipelineLib` (metatx split R2): the only place that builds a `Ctx`.
    function _mtxCtx() internal view returns (MtxPipelineLib.Ctx memory) {
        return MtxPipelineLib.Ctx(_domainSeparatorV4(), _REGISTRY, _SMART_KEY_CLONE_CODEHASH, IS_HEDERA);
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
        f.supported = supportedModes();
    }

    /// @notice The signer as an id: the subject of the live ticket, else the direct caller padded.
    function _subject() internal view returns (bytes32 s) {
        s = _ticketSubject();
        if (s == 0) s = MetaTxLib.pad(_msgSender());
    }

    /// @dev The generic UA pipeline (CTR-MTX-17 on a `bytes32` signer) on the library: `preCall(ua = true)` runs the
    ///      ledger check, 1 envelope, 2 authorization, 3 the UA allowlist (`MetaTxUnknownOp`), the address path's shape
    ///      and fee class and the fee amount, 4 nonce; then 5 self-call under the id, 6 the fee hook, 7 event.
    function _uaExecute(MetaTxLib.UAMetaTransaction memory m, bytes calldata auth) internal returns (bytes memory) {
        return _uaSettle(m, MtxPipelineLib.preCall(_mtxCtx(), _uaEnvelopeOf(m), _callFacts(m.data, true), true, auth));
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
        return _uaSettle(m, MtxPipelineLib.preNamedUA(
            _mtxCtx(), typehash, _uaEnvelopeOf(m, 0), words, _callFacts(m.data, true), auth));
    }

    /// @dev The same for `uaShield`, which keeps `bytes auth` (owner table, 2026-11-01).
    function _namedUA(bytes32 typehash, bytes4 sel, MetaTxLib.UAEnvelope calldata e, bytes memory args, bytes calldata auth)
        internal returns (bytes memory)
    {
        MetaTxLib.UAMetaTransaction memory m = _uaMetaOf(e, abi.encodePacked(sel, args));
        return _uaSettle(m, MtxPipelineLib.preNamed(
            _mtxCtx(), typehash, _uaEnvelopeOf(m, 0), args, _callFacts(m.data, true), true, auth));
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
        if (_REGISTRY == address(0)) revert IUALedger.UALedgerOff();
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
        revert MetaTxUnknownMode(m.mode);
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
}
