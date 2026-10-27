// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {IUALedger} from "./IUALedger.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";

/// @title The token base of every SCaaS token (CTR-MTX-07): ERC-20 on `MetaTxBase`.
/// @notice Adds to the generic base: the fee in this token (`_chargeFee` by fee class, CTR-MTX-20), the typed
///         `MetaTransfer` path (`mtxExecuteTransfer`, `mtxBatchTransfer`, CTR-MTX-23/24) on the same lanes, the
///         allowance rule (CTR-TOK-01) and "no tokens at the token's own address" (CTR-MTX-18). Domain
///         `("SCaaS MetaToken", "1", chainId, clone, chain_uid)` for every kind (CTR-MTX-02). The sell side of a
///         `TradeOrder` (CTR-DEX-15) through `TradeLib`. The UA ledger (CTR-UA-18/19/26): `bytes32` balances of derived
///         UAs, shown as the holder `UA_POOL`, and the `ua*` pipelines on the same lanes; signatures of derived UAs
///         are checked by the UA registry (`requireAuthorized`), never here.
abstract contract ERC20MetaTx is ERC20, MetaTxBase, IERC20Payment, ITradeToken, IUALedger {
    using MetaTxLib for MetaTxLib.MetaTransfer;
    using MetaTxLib for MetaTxLib.UAMetaTransaction;
    using MetaTxLib for MetaTxLib.UAMetaTransfer;

    /// @notice The UA registry of this chain (an implementation immutable; 0 = the UA ledger is off).
    address internal immutable _REGISTRY;
    /// @notice The EIP-1167 clone code hash of the chain's `SmartKeyAccount` implementation (0 = none): such a signer
    ///         gets 400k gas for ERC-1271, every other contract wallet 50k.
    bytes32 internal immutable _SMART_KEY_CLONE_CODEHASH;

    /// @notice Set on implementations deployed for Hedera (CTR-TOK-23): 64-byte signatures from accounts without code
    ///         take the HIP-632 path.
    bool public immutable IS_HEDERA;

    /// @custom:storage-location erc7201:scaas.ua.ledger
    struct UALedgerStorage {
        mapping(bytes32 ua => uint256) balance;
        mapping(bytes32 digest => bool) cancelUsed;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.ua.ledger")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _UA_STORAGE = 0x9e2def943e5a7ec3982e5d00524104579a6b98ce8b31343ac0092718cc04e900;

    constructor(bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        ERC20("", "") MetaTxBase(_domainName(), chainUid_)
    {
        _REGISTRY = registry_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
        IS_HEDERA = hedera_;
    }

    /// @notice The EIP-712 domain name (CTR-MTX-02): `"SCaaS MetaToken"`; a confidential kind overrides it.
    function _domainName() internal pure virtual returns (string memory) {
        return "SCaaS MetaToken";
    }

    // ------------------------------------------------------------------ views

    /// @notice `0xF3`: both flags and every fee mode (a token holds the charged balance).
    function supportedModes() public pure override(IMetaTx, MetaTxBase) returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    function mtxDigest(MetaTxLib.MetaTransaction calldata m)
        external view override(IMetaTx, MetaTxBase) returns (bytes32)
    {
        return MtxPipelineLib.callDigest(_domainSeparatorV4(), MetaTxLib.METATX_TYPEHASH, _envelopeOf(m));
    }

    function mtxTransferDigest(MetaTxLib.MetaTransfer calldata t) external view returns (bytes32) {
        return MtxPipelineLib.transferDigest(_domainSeparatorV4(), false, _padded(t));
    }

    function registry() public view returns (address) {
        return _REGISTRY;
    }

    /// @notice A native id reads the ERC-20 balance of its address; a derived UA its UA-ledger balance.
    function balanceOfUA(bytes32 ua) public view returns (uint256) {
        return UAKinds.inNativeSpace(ua) ? balanceOf(address(uint160(uint256(ua)))) : _ua().balance[ua];
    }

    /// @notice The one nonce map (CTR-UA-26): `uaNonce(pad(a), b) == mtxNonce(a, b)`.
    function uaNonce(bytes32 ua, uint256 batch) external view returns (uint256) {
        return _nonce(ua, batch);
    }

    function uaDigest(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32) {
        return MtxPipelineLib.callDigest(_domainSeparatorV4(), MetaTxLib.UAMETATX_TYPEHASH, _uaEnvelopeOf(m));
    }

    function uaTransferDigest(MetaTxLib.UAMetaTransfer calldata t) external view returns (bytes32) {
        return MtxPipelineLib.transferDigest(_domainSeparatorV4(), true, t);
    }

    /// @notice The `metatx-cancel` digest (accounts.md §1.5): `CANCEL_TAG` is the purpose tag itself.
    function uaCancelDigest(bytes32 ua, uint256 batch, uint256 validUntil) public view returns (bytes32) {
        return keccak256(abi.encode(
            UAKinds.PURPOSE_METATX_CANCEL, block.chainid, CHAIN_UID, address(this), ua, batch, validUntil
        ));
    }

    // ------------------------------------------------------------------ trade orders (CTR-DEX-15, -25, -02)

    function tradeOrderDigest(TradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.hashStruct(o));
    }

    function uaTradeOrderDigest(UATradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.hashStructUA(o));
    }

    function cancelOrderDigest(bytes32 orderHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, orderHash)));
    }

    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
    }

    function uaInvalidateNoncesDigest(bytes32 from, uint256 batch, uint256 newMin) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.UA_INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
    }

    function pulled(bytes32 orderHash) external view returns (uint256) {
        return TradeLib.$().pulled[orderHash];
    }

    /// @notice One floor per id: `minNonce(a, b) == uaMinNonce(pad(a), b)`.
    function minNonce(address from, uint256 batch) external view returns (uint256) {
        return TradeLib.$().minNonce[TradeLib.pad(from)][batch];
    }

    function uaMinNonce(bytes32 from, uint256 batch) external view returns (uint256) {
        return TradeLib.$().minNonce[from][batch];
    }

    /// @notice Only `o.dex` calls (a direct read of the caller, CTR-MTX-18); never allowlisted. Moves the fill from
    ///         `o.from` to `o.dex` and nowhere else. The signature is checked once: a later fill of an order already
    ///         pulled (`pulled[h] ≠ 0`, `h` binds every field) skips it (CTR-DEX-15 step 4).
    function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external nonReentrant {
        bytes32 h = tradeOrderDigest(o);
        UATradeOrder memory c = TradeLib.core(o);
        TradeLib.precheck(c, f, h, msg.sender, address(this));
        if (TradeLib.$().pulled[h] == 0) _requireValidSignature(o.from, h, sig);
        _transfer(o.from, o.dex, TradeLib.record(c, f, h, false));
    }

    /// @notice CTR-DEX-25: `mtxTrade` for an id; the UA rule under purpose `trade` (a native id signs `h` itself); the
    ///         fill moves through the UA ledger (a derived seller: `Transfer(UA_POOL, dex)` + `UATransfer`).
    function uaTrade(UATradeOrder calldata o, bytes calldata auth, TradeFill calldata f) external nonReentrant {
        _uaOn();
        bytes32 h = uaTradeOrderDigest(o);
        UATradeOrder memory c = o;
        TradeLib.precheck(c, f, h, msg.sender, address(this));
        if (TradeLib.$().pulled[h] == 0) _uaAuthorize(o.from, UAKinds.PURPOSE_TRADE, h, auth);
        _uaMove(o.from, TradeLib.pad(o.dex), TradeLib.record(c, f, h, true));
    }

    /// @notice Cancel signatures never expire (CTR-DEX-02); anyone may submit one.
    function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external nonReentrant {
        bytes32 h = tradeOrderDigest(o);
        _requireValidSignature(o.from, cancelOrderDigest(h), sig);
        TradeLib.cancel(h, o.amount, TradeLib.pad(o.from), false);
    }

    function uaCancelOrder(UATradeOrder calldata o, bytes calldata auth) external nonReentrant {
        _uaOn();
        bytes32 h = uaTradeOrderDigest(o);
        _uaAuthorize(o.from, UAKinds.PURPOSE_TRADE, cancelOrderDigest(h), auth);
        TradeLib.cancel(h, o.amount, o.from, true);
    }

    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external nonReentrant {
        _requireValidSignature(from, invalidateNoncesDigest(from, batch, newMin), sig);
        TradeLib.invalidate(TradeLib.pad(from), batch, newMin, false);
    }

    function uaInvalidateNonces(bytes32 from, uint256 batch, uint256 newMin, bytes calldata auth) external nonReentrant {
        _uaOn();
        _uaAuthorize(from, UAKinds.PURPOSE_TRADE, uaInvalidateNoncesDigest(from, batch, newMin), auth);
        TradeLib.invalidate(from, batch, newMin, true);
    }

    // ------------------------------------------------------------------ typed path (CTR-MTX-23, CTR-MTX-24)

    function mtxExecuteTransfer(MetaTxLib.MetaTransfer calldata t, bytes calldata signature)
        external nonReentrant returns (bool)
    {
        _executeTransfer(t, signature);
        return true;
    }

    /// @notice Atomic, items in order; never mixed with `MetaTransaction`s (CTR-MTX-24).
    function mtxBatchTransfer(MetaTxLib.MetaTransfer[] calldata ts, bytes[] calldata signatures)
        external nonReentrant returns (bool)
    {
        uint256 n = ts.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != signatures.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) _executeTransfer(ts[i], signatures[i]);
        return true;
    }

    /// @dev Every typed entry (struct, batch, the named builders, receiver-pays) goes through here: steps 1-4 in
    ///      `MtxPipelineLib.preTransfer` (ids padded, `have` read here), so everything is checked before the nonce and
    ///      the transfers, which cannot fail afterwards. Returns the digest.
    function _executeTransfer(MetaTxLib.MetaTransfer memory t, bytes calldata signature) internal returns (bytes32) {
        MtxPipelineLib.Out memory o =
            MtxPipelineLib.preTransfer(_mtxCtx(), _padded(t), false, balanceOf(t.from), signature); // 1-4
        if (o.fee != 0) _transfer(t.from, o.feeTo, o.fee);                                         // 5
        _transfer(t.from, t.to, t.value);
        if (t.entryRef != 0) emit PaymentSettled(t.from, t.to, t.value, o.fee, o.feeTo, t.entryRef);
        emit MetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, o.digest, o.feeTo, o.fee); // 6
        return o.digest;
    }

    /// @dev A `MetaTransfer` in the `UAMetaTransfer` layout: `from` and `to` padded (the same struct hash, CTR-UA-26).
    function _padded(MetaTxLib.MetaTransfer memory t) internal pure returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer(MetaTxLib.pad(t.from), MetaTxLib.pad(t.to), t.value, t.entryRef, t.batch,
            t.nonce, t.validUntil, t.mode, t.relayer, t.fee, t.feeRecipient);
    }

    /// @dev Step 3: payee, fee on `value` (capped, CTR-MTX-13), the payee check (CTR-MTX-08), balance. Superseded by
    ///      `MtxPipelineLib._checkTransfer` (metatx split T3), no longer called; Task 4 moves it to legacy/metatx-v1/.
    function _checkTransfer(MetaTxLib.MetaTransfer memory t) private view returns (uint256 fee, address feeTo) {
        if (t.to == address(0)) revert PayToZero();
        if (t.to == address(this)) revert TransferToSelf();
        _notPool(t.to); // C5-3
        FeeMode fm = MetaTxLib.feeModeOf(t.mode);
        feeTo = t.feeRecipient == address(0) ? msg.sender : t.feeRecipient;
        fee = FeePolicy.compute(fm, t.value, t.fee);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0) {
            if (feeTo == t.to) revert FeeRecipientIsPayee();
            if (feeTo == address(this)) revert TransferToSelf();
            _notPool(feeTo);
        }
        uint256 need = t.value + fee;
        uint256 have = balanceOf(t.from);
        if (have < need) revert MetaTxInsufficientForFee(need, have);
    }

    // ------------------------------------------------------------------ the generic pipeline on MtxPipelineLib

    /// @notice The token's immutables for `MtxPipelineLib` (metatx split R2): the only place that builds a `Ctx`.
    function _mtxCtx() internal view returns (MtxPipelineLib.Ctx memory) {
        return MtxPipelineLib.Ctx(_domainSeparatorV4(), _REGISTRY, _SMART_KEY_CLONE_CODEHASH, IS_HEDERA);
    }

    /// @dev CTR-MTX-17 on the library: 1-4 and the fee amount in `preCall` (the fee is checked before the call, owner
    ///      2026-10-27), 5 the self-call, 6 the fee move, 7 the event. `data` stays here: the library gets its hash.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal override returns (bytes memory ret)
    {
        MtxPipelineLib.Out memory o =
            MtxPipelineLib.preCall(_mtxCtx(), _envelopeOf(m), _callFacts(m.data, false), false, signature); // 1-4
        ret = _selfCall(MetaTxLib.pad(m.from), m.data, _envelopeBinding(m));                                 // 5
        if (o.fee != 0) _transfer(m.from, o.feeTo, o.fee);                                                    // 6
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, o.digest, o.feeTo, o.fee);         // 7
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
    }

    // ------------------------------------------------------------------ fee of a self-call (CTR-MTX-20)
    // Superseded by `MtxPipelineLib._callFee`, now before the call (§3.8, owner 2026-10-27): `_chargeFee` / `_callFee`
    // are no longer reached on a token (its `_execute` overrides the base's); Task 4 moves them to `legacy/metatx-v1/`.

    /// @notice After the call: `ABSOLUTE` + `FIXED` = the signed amount, uncapped (step 3 refused `ABSOLUTE` +
    ///         `PERCENT`); anything else = `FeePolicy.compute` on the basis (≤ 1 %), so a `PERCENT` fee is never
    ///         taken as a raw amount whatever class the rule reports here. A failing transfer reverts the call.
    function _chargeFee(address from, uint256 basis, MetaTxLib.MetaTransaction memory m)
        internal override returns (uint256 fee)
    {
        address feeTo;
        (fee, feeTo) = _callFee(m.data, basis, m.mode, m.fee, _feeRecipientOf(m));
        if (fee != 0) _transfer(from, feeTo, fee);
    }

    /// @dev The fee of a self-call (both paths), after the call; a `UA_POOL` recipient would credit the pool's slot.
    function _callFee(bytes memory data, uint256 basis, uint32 mode, uint256 signed, address feeTo)
        private view returns (uint256 fee, address)
    {
        FeeMode fm = MetaTxLib.feeModeOf(mode);
        if (fm == FeeMode.NONE) return (0, feeTo);
        bool absoluteFixed = fm == FeeMode.FIXED && _mtxRule(bytes4(data)).feeClass == FEE_CLASS_ABSOLUTE;
        fee = absoluteFixed ? signed : FeePolicy.compute(fm, basis, signed);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0 && feeTo == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
        return (fee, feeTo);
    }

    // ------------------------------------------------------------------ allowance (CTR-TOK-01)

    /// @notice Caller and spender must both be contracts: no EOA grants or holds an allowance.
    function approve(address spender, uint256 value) public virtual override(ERC20, IERC20) returns (bool) {
        address caller = _msgSender();
        if (!SigCheck.isContract(caller)) revert CallerNotContract(caller);
        if (!SigCheck.isContract(spender)) revert SpenderNotContract(spender);
        return super.approve(spender, value);
    }

    /// @notice Only a contract spends an allowance; checked before the allowance.
    function transferFrom(address from, address to, uint256 value)
        public virtual override(ERC20, IERC20) returns (bool)
    {
        address caller = _msgSender();
        if (!SigCheck.isContract(caller)) revert CallerNotContract(caller);
        return super.transferFrom(from, to, value);
    }

    // ------------------------------------------------------------------ internals

    /// @dev The two pools are never a payee or a fee recipient (checked early so step 3 owns the refusal, C5-3).
    function _notPool(address a) internal pure {
        if (a == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
        if (a == MetaTxLib.SHIELD_POOL) revert ShieldPoolNotPayable();
    }

    /// @dev Tokens parked at the token's own address are what a spoofed self-call would spend (CTR-MTX-18). `UA_POOL`'s
    ///      slot is Σ of the UA balances and only `_uaMove` writes it (CTR-UA-18): no native move, mint or burn reaches
    ///      it, except a self-call under a derived UA (`uaExecute`), which spends that UA's own balance through it.
    function _update(address from, address to, uint256 value) internal virtual override {
        if (to == address(this)) revert TransferToSelf();
        if (to == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
        if (to == MetaTxLib.SHIELD_POOL || from == MetaTxLib.SHIELD_POOL) revert ShieldPoolNotPayable(); // D19
        if (from == MetaTxLib.UA_POOL) {
            bytes32 ua = _ticketSubject();
            if (UAKinds.inNativeSpace(ua)) revert UAPoolNotPayable();
            _uaDebit(ua, value);
            emit UATransfer(ua, MetaTxLib.pad(to), value);
        }
        super._update(from, to, value);
    }

    // ------------------------------------------------------------------ the UA ledger (CTR-UA-18, CTR-UA-19, CTR-UA-26)

    /// @notice Native `msg.sender` → a registered SIGNING UA: `Transfer(sender, UA_POOL)` and `UATransfer`.
    function transferToUA(bytes32 to, uint256 amount) external nonReentrant returns (bool) {
        _requireDerivedReceiver(to);
        _uaMove(MetaTxLib.pad(_msgSender()), to, amount);
        return true;
    }

    function uaExecute(MetaTxLib.UAMetaTransaction calldata m, bytes calldata auth)
        external nonReentrant returns (bytes memory)
    {
        return _uaExecute(m, auth);
    }

    /// @notice Atomic, items in order, each with a fresh ticket (as `mtxBatch`).
    function uaBatch(MetaTxLib.UAMetaTransaction[] calldata ms, bytes[] calldata auths)
        external nonReentrant returns (bool)
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

    function uaExecuteTransfer(MetaTxLib.UAMetaTransfer calldata t, bytes calldata auth)
        external nonReentrant returns (bool)
    {
        _uaExecuteTransfer(t, auth);
        return true;
    }

    /// @notice Atomic, items in order; never mixed with `UAMetaTransaction`s (as `mtxBatchTransfer`).
    function uaBatchTransfer(MetaTxLib.UAMetaTransfer[] calldata ts, bytes[] calldata auths)
        external nonReentrant returns (bool)
    {
        uint256 n = ts.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != auths.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) _uaExecuteTransfer(ts[i], auths[i]);
        return true;
    }

    /// @notice A derived UA's `cancelNonce`, signed under purpose `metatx-cancel`; each signature works once. Native ids
    ///         use `cancelNonce` (the same map, `pad(sender)`).
    function uaCancelNonce(bytes32 ua, uint256 batch, uint256 validUntil, bytes calldata auth) external nonReentrant {
        _uaOn();
        if (UAKinds.inNativeSpace(ua)) revert UAKindNotAccepted(ua, 0);
        if (block.timestamp > validUntil) revert MetaTxExpired(validUntil, block.timestamp);
        bytes32 d = uaCancelDigest(ua, batch, validUntil);
        UALedgerStorage storage $ = _ua();
        if ($.cancelUsed[d]) revert UACancelUsed();
        IUARegistry(_REGISTRY).requireAuthorized(ua, UAKinds.PURPOSE_METATX_CANCEL, d, auth);
        $.cancelUsed[d] = true;
        emit UANonceCancelled(ua, batch, _bumpNonce(ua, batch));
    }

    /// @dev The generic UA pipeline (CTR-MTX-17 on a `bytes32` signer) on the library: `preCall(ua = true)` runs the
    ///      ledger check, 1 envelope, 2 authorization, 3 the UA allowlist (`MetaTxUnknownOp`), the address path's shape
    ///      and fee class and the fee amount, 4 nonce; then 5 self-call under the id, 6 fee from the signer's ledger,
    ///      7 event.
    function _uaExecute(MetaTxLib.UAMetaTransaction memory m, bytes calldata auth) internal returns (bytes memory ret) {
        MtxPipelineLib.Out memory o =
            MtxPipelineLib.preCall(_mtxCtx(), _uaEnvelopeOf(m), _callFacts(m.data, true), true, auth); // 1-4
        ret = _selfCall(m.from, m.data, _uaEnvelopeBinding(m));                                         // 5
        if (o.fee != 0) _uaMove(m.from, MetaTxLib.pad(o.feeTo), o.fee);                                // 6
        emit UAMetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, o.digest, o.feeTo, o.fee); // 7
    }

    /// @dev The envelope of `m` for the library: `data` as its hash (over this memory copy).
    function _uaEnvelopeOf(MetaTxLib.UAMetaTransaction memory m)
        internal pure returns (MtxPipelineLib.Envelope memory)
    {
        return MtxPipelineLib.Envelope(m.from, keccak256(m.data), m.batch, m.nonce, m.validUntil, m.mode, m.relayer,
            m.fee, m.feeRecipient);
    }

    /// @notice The envelope binding a proof inside the UA path's self-call carries (CTR-PQZ-15, P6g plan D4,
    ///         CTR-ZTH-51): 0 by default; the confidential layers return their own (tags `SCAAS-PQZ-UA-ENVELOPE-V1`,
    ///         `SCAAS-ZETHER-UA-ENVELOPE-V1`), never 0, so step 5 writes it on every envelope of theirs (the address
    ///         path's `_envelopeBinding` rule).
    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory) internal view virtual returns (bytes32) {
        return bytes32(0);
    }

    /// @dev The typed UA pipeline (CTR-MTX-23 on ids): steps 1-4 in `MtxPipelineLib.preTransfer` (`have` read here),
    ///      everything checked before the nonce and the moves.
    function _uaExecuteTransfer(MetaTxLib.UAMetaTransfer memory t, bytes calldata auth) internal returns (bytes32) {
        MtxPipelineLib.Out memory o = MtxPipelineLib.preTransfer(_mtxCtx(), t, true, balanceOfUA(t.from), auth); // 1-4
        if (o.fee != 0) _uaMove(t.from, MetaTxLib.pad(o.feeTo), o.fee);                                // 5
        _uaMove(t.from, t.to, t.value);
        if (t.entryRef != 0) emit UAPaymentSettled(t.from, t.to, t.value, o.fee, o.feeTo, t.entryRef);
        emit UAMetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, o.digest, o.feeTo, o.fee); // 6
        return o.digest;
    }

    /// @dev Step 3 of the typed path: receiver, fee on `value` (capped), the payee check on the padded recipient,
    ///      balance. Superseded by `MtxPipelineLib._checkTransfer` (metatx split T3), no longer called; Task 4 moves
    ///      it to legacy/metatx-v1/.
    function _checkUATransfer(MetaTxLib.UAMetaTransfer memory t) private view returns (uint256 fee, address feeTo) {
        _checkTo(t.to);
        FeeMode fm = MetaTxLib.feeModeOf(t.mode);
        feeTo = t.feeRecipient == address(0) ? msg.sender : t.feeRecipient;
        fee = FeePolicy.compute(fm, t.value, t.fee);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0) {
            if (MetaTxLib.pad(feeTo) == t.to) revert FeeRecipientIsPayee();
            if (feeTo == address(this)) revert TransferToSelf();
            if (feeTo == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
            if (feeTo == MetaTxLib.SHIELD_POOL) revert ShieldPoolNotPayable();
        }
        uint256 need = t.value + fee;
        uint256 have = balanceOfUA(t.from);
        if (have < need) revert MetaTxInsufficientForFee(need, have);
    }

    /// @dev The receiver of every `…ToUA` function (CTR-UA-28): the ledger on and a registered SIGNING derived id; a
    ///      native id belongs to the address twin (`UANotRegistered`).
    function _requireDerivedReceiver(bytes32 to) internal view {
        _uaOn();
        if (UAKinds.inNativeSpace(to)) revert UANotRegistered(to);
        _checkTo(to);
    }

    /// @dev A mint into a derived UA (CTR-UA-28): a UA-ledger move from 0, `Transfer(0, UA_POOL)` and `UATransfer(0, to)`.
    function _uaMint(bytes32 to, uint256 v) internal {
        _requireDerivedReceiver(to);
        _uaMove(bytes32(0), to, v);
    }

    /// @dev A receiver: a native id other than 0, the token and `UA_POOL`; or a registered SIGNING UA (the Zether UA
    ///      included since UA-6, U8).
    function _checkTo(bytes32 to) private view {
        if (UAKinds.inNativeSpace(to)) {
            address a = address(uint160(uint256(to)));
            if (a == address(0)) revert PayToZero();
            if (a == address(this)) revert TransferToSelf();
            if (a == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
            if (a == MetaTxLib.SHIELD_POOL) revert ShieldPoolNotPayable();
            return;
        }
        uint16 kind = IUARegistry(_REGISTRY).kindOf(to);
        if (kind == 0) revert UANotRegistered(to);
        if (!UAKinds.isSigning(kind)) revert UAKindNotAccepted(to, kind);
    }

    /// @dev Step 2: a native id is checked here over the digest itself (CTR-UA-24: no code ⇒ ECDSA; an EIP-7702
    ///      designator ⇒ ECDSA, else ERC-1271 through the delegate; other code ⇒ ERC-1271; Hedera's HIP-632 as on the
    ///      address path), whatever the purpose; a derived one by the registry under `purpose` (`metatx`, or
    ///      `receiver-fee` for a payee's `ReceiverFee`).
    function _uaAuthorize(bytes32 from, bytes32 purpose, bytes32 digest, bytes calldata auth) internal view {
        if (!UAKinds.inNativeSpace(from)) {
            return IUARegistry(_REGISTRY).requireAuthorized(from, purpose, digest, auth);
        }
        address a = address(uint160(uint256(from)));
        if (a == address(0)) revert UANotRegistered(from); // C5-2: id 0 pays no fee (it would mint)
        if (a == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
        if (a == MetaTxLib.SHIELD_POOL) revert ShieldPoolNotPayable();
        _requireNativeUASignature(a, digest, auth);
    }

    /// @notice The native signature of the UA path; `MetaTokenBase` adds the Hedera HIP-632 branch.
    function _requireNativeUASignature(address from, bytes32 digest, bytes calldata sig) internal view virtual {
        if (!SigCheck.isValid7702(from, digest, sig, _erc1271Gas(from))) revert MetaTxBadSignature();
    }

    /// @notice The UA allowlist (CTR-UA-26): selectors a `UAMetaTransaction` may call; none on the base, `NONE` adds
    ///         `burn`, the wrapper kinds their `unwrap`s and `unwrapToUA`. `approve`, `trade`, transfers and the dedicated
    ///         `…ToUA` functions are never on it (`MetaTxUnknownOp`).
    function _uaAllowed(bytes4) internal view virtual returns (bool) {
        return false;
    }

    /// @dev Every UA-ledger move: derived sides in `balance`, native sides (or `UA_POOL` for a derived side) through
    ///      the ERC-20 core, so `Transfer` is emitted iff a native balance changes and `UATransfer` iff a side is derived.
    // ponytail: calls `ERC20._update` directly, skipping `_update`'s hooks and `_transfer`'s zero checks (callers
    // exclude 0); when the REGULATED features (FREEZE / PAUSE / ALLOWLIST, AdminLib) are built they must also hook
    // here, including the UA->UA branch.
    function _uaMove(bytes32 from, bytes32 to, uint256 value) internal {
        // D19: no UA-ledger caller reaches `SHIELD_POOL` (its moves bypass `_update`); only `_poolMove` does.
        if (from == MetaTxLib.pad(MetaTxLib.SHIELD_POOL) || to == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)) {
            revert ShieldPoolNotPayable();
        }
        _poolMove(from, to, value);
    }

    /// @dev `_uaMove` without the pool refusal: for a shielding layer's own moves into / out of `SHIELD_POOL` (D19).
    function _poolMove(bytes32 from, bytes32 to, uint256 value) internal {
        bool fromUA = !UAKinds.inNativeSpace(from);
        bool toUA = !UAKinds.inNativeSpace(to);
        if (!toUA && address(uint160(uint256(to))) == address(this)) revert TransferToSelf(); // CTR-MTX-18
        if (fromUA) _uaDebit(from, value);
        if (toUA) _ua().balance[to] += value;
        if (!(fromUA && toUA)) {
            ERC20._update(fromUA ? MetaTxLib.UA_POOL : address(uint160(uint256(from))),
                toUA ? MetaTxLib.UA_POOL : address(uint160(uint256(to))), value);
        }
        if (fromUA || toUA) emit UATransfer(from, to, value);
    }

    function _uaDebit(bytes32 ua, uint256 value) private {
        UALedgerStorage storage $ = _ua();
        uint256 b = $.balance[ua];
        if (b < value) revert UAInsufficientBalance(ua, b, value);
        unchecked { $.balance[ua] = b - value; }
    }

    function _uaOn() private view {
        if (_REGISTRY == address(0)) revert UALedgerOff();
    }

    function _ua() private pure returns (UALedgerStorage storage $) {
        assembly ("memory-safe") { $.slot := _UA_STORAGE }
    }

    function _isContract(address a) internal view returns (bool) {
        return SigCheck.isContract(a);
    }

    function _msgSender() internal view virtual override(Context, MetaTxBase) returns (address) {
        return MetaTxBase._msgSender();
    }
}
