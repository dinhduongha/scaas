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

    /// @custom:storage-location erc7201:scaas.ua.ledger
    struct UALedgerStorage {
        mapping(bytes32 ua => uint256) balance;
        mapping(bytes32 digest => bool) cancelUsed;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.ua.ledger")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _UA_STORAGE = 0x9e2def943e5a7ec3982e5d00524104579a6b98ce8b31343ac0092718cc04e900;

    constructor(bytes32 chainUid_, address registry_) ERC20("", "") MetaTxBase(_domainName(), chainUid_) {
        _REGISTRY = registry_;
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

    function mtxTransferDigest(MetaTxLib.MetaTransfer calldata t) external view returns (bytes32) {
        return _hashTypedDataV4(t.hashStruct());
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
        return _hashTypedDataV4(m.hashStruct());
    }

    function uaTransferDigest(MetaTxLib.UAMetaTransfer calldata t) external view returns (bytes32) {
        return _hashTypedDataV4(t.hashStruct());
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

    /// @dev Every typed entry (struct, batch, the named builders, receiver-pays) goes through here. Everything is
    ///      checked before the nonce and the transfers, which cannot fail afterwards. Returns the digest.
    function _executeTransfer(MetaTxLib.MetaTransfer memory t, bytes calldata signature)
        internal returns (bytes32 digest)
    {
        _checkEnvelope(MetaTxLib.pad(t.from), t.batch, t.nonce, t.validUntil, t.mode, t.relayer); // 1
        digest = _hashTypedDataV4(t.hashStruct());                                              // 2
        _requireValidSignature(t.from, digest, signature);
        (uint256 fee, address feeTo) = _checkTransfer(t);                                       // 3
        _useNonce(MetaTxLib.pad(t.from), t.batch);                                              // 4
        if (fee != 0) _transfer(t.from, feeTo, fee);                                            // 5
        _transfer(t.from, t.to, t.value);
        if (t.entryRef != 0) emit PaymentSettled(t.from, t.to, t.value, fee, feeTo, t.entryRef);
        emit MetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, digest, feeTo, fee); // 6
    }

    /// @dev Step 3: payee, fee on `value` (capped, CTR-MTX-13), the payee check (CTR-MTX-08), balance.
    function _checkTransfer(MetaTxLib.MetaTransfer memory t) private view returns (uint256 fee, address feeTo) {
        if (t.to == address(0)) revert PayToZero();
        if (t.to == address(this)) revert TransferToSelf();
        FeeMode fm = MetaTxLib.feeModeOf(t.mode);
        feeTo = t.feeRecipient == address(0) ? msg.sender : t.feeRecipient;
        fee = FeePolicy.compute(fm, t.value, t.fee);
        FeePolicy.validateRecipient(fm, feeTo);
        if (fee != 0) {
            if (feeTo == t.to) revert FeeRecipientIsPayee();
            if (feeTo == address(this)) revert TransferToSelf();
        }
        uint256 need = t.value + fee;
        uint256 have = balanceOf(t.from);
        if (have < need) revert MetaTxInsufficientForFee(need, have);
    }

    // ------------------------------------------------------------------ fee of a self-call (CTR-MTX-20)

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

    /// @dev Tokens parked at the token's own address are what a spoofed self-call would spend (CTR-MTX-18). `UA_POOL`'s
    ///      slot is Σ of the UA balances and only `_uaMove` writes it (CTR-UA-18): no native move, mint or burn reaches
    ///      it, except a self-call under a derived UA (`uaExecute`), which spends that UA's own balance through it.
    function _update(address from, address to, uint256 value) internal virtual override {
        if (to == address(this)) revert TransferToSelf();
        if (to == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
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

    /// @dev The generic UA pipeline (CTR-MTX-17 on a `bytes32` signer): 1 envelope, 2 authorization, 3 the UA allowlist
    ///      (`MetaTxUnknownOp`) then the address path's shape and fee class, 4 nonce, 5 self-call under the id, 6 fee
    ///      from the signer's ledger after the call, 7 event.
    function _uaExecute(MetaTxLib.UAMetaTransaction memory m, bytes calldata auth) internal returns (bytes memory ret) {
        _uaOn();
        _checkEnvelope(m.from, m.batch, m.nonce, m.validUntil, m.mode, m.relayer);                    // 1
        bytes32 digest = _hashTypedDataV4(m.hashStruct());                                             // 2
        _uaAuthorize(m.from, UAKinds.PURPOSE_METATX, digest, auth);
        bytes4 sel = bytes4(m.data);                                                                   // 3
        if (m.data.length < 4 || !_uaAllowed(sel)) revert MetaTxUnknownOp(sel);
        uint256 basis = _checkCall(m.data, m.mode);
        _useNonce(m.from, m.batch);                                                                    // 4
        ret = _selfCall(m.from, m.data, _uaEnvelopeBinding(m));                                        // 5
        (uint256 fee, address feeTo) =                                                                 // 6
            _callFee(m.data, basis, m.mode, m.fee, m.feeRecipient == address(0) ? msg.sender : m.feeRecipient);
        if (fee != 0) _uaMove(m.from, MetaTxLib.pad(feeTo), fee);
        emit UAMetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, feeTo, fee);      // 7
    }

    /// @notice The envelope binding a proof inside the UA path's self-call carries (CTR-PQZ-15, P6g plan D4): 0 by
    ///         default; the PQZ layer returns its own (tag `SCAAS-PQZ-UA-ENVELOPE-V1`), never 0, so step 5 writes it on
    ///         every PQZ envelope (the address path's `_envelopeBinding` rule).
    function _uaEnvelopeBinding(MetaTxLib.UAMetaTransaction memory) internal view virtual returns (bytes32) {
        return bytes32(0);
    }

    /// @dev The typed UA pipeline (CTR-MTX-23 on ids): everything is checked before the nonce and the moves.
    function _uaExecuteTransfer(MetaTxLib.UAMetaTransfer memory t, bytes calldata auth)
        internal returns (bytes32 digest)
    {
        _uaOn();
        _checkEnvelope(t.from, t.batch, t.nonce, t.validUntil, t.mode, t.relayer);                    // 1
        digest = _hashTypedDataV4(t.hashStruct());                                                     // 2
        _uaAuthorize(t.from, UAKinds.PURPOSE_METATX, digest, auth);
        (uint256 fee, address feeTo) = _checkUATransfer(t);                                           // 3
        _useNonce(t.from, t.batch);                                                                    // 4
        if (fee != 0) _uaMove(t.from, MetaTxLib.pad(feeTo), fee);                                     // 5
        _uaMove(t.from, t.to, t.value);
        if (t.entryRef != 0) emit UAPaymentSettled(t.from, t.to, t.value, fee, feeTo, t.entryRef);
        emit UAMetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, digest, feeTo, fee);      // 6
    }

    /// @dev Step 3 of the typed path: receiver, fee on `value` (capped), the payee check on the padded recipient,
    ///      balance.
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
        if (a == MetaTxLib.UA_POOL) revert UAPoolNotPayable();
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
