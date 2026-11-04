// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {MetaTxBase} from "./MetaTxBase.sol";
import {UAMetaTxBase} from "./UAMetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {IUALedger} from "./IUALedger.sol";
import {IUALedgerViews} from "./IUALedgerViews.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {MtxPipelineLib} from "./MtxPipelineLib.sol";

/// @title The token base of every SCaaS token (CTR-MTX-07): ERC-20 on `MetaTxBase`.
/// @notice Adds to the generic base: the fee in this token (amount by fee class checked in `MtxPipelineLib.preCall`
///         before the self-call, moved after it, CTR-MTX-20, owner 2026-10-27), the typed
///         `UAMetaTransfer` path (`mtxExecuteTransfer`, `mtxBatchTransfer`, CTR-MTX-23/24; ua-mtx-merge T2: one form for
///         native and derived ids, the address `MetaTransfer` path in legacy/ua-mtx-merge/) on the same lanes, the
///         allowance rule (CTR-TOK-01) and "no tokens at the token's own address" (CTR-MTX-18). Domain
///         `("SCaaS MetaToken", "1", chainId, clone, chain_uid)` for every kind (CTR-MTX-02). The sell side of a
///         `TradeOrder` (CTR-DEX-15) through `TradeLib`. The UA ledger (CTR-UA-18/19/26): `bytes32` balances of derived
///         UAs, shown as the holder `UA_POOL`, and the `ua*` pipelines on the same lanes. Every signature (the
///         relayed paths, trade, cancel, invalidate, receiver-fee) is checked in `MtxPipelineLib` (`requireSignature`
///         / `authorize`; a derived UA by the registry's `requireAuthorized`), never here (owner 2026-10-27).
abstract contract ERC20MetaTx is ERC20, UAMetaTxBase, IERC20Payment, ITradeToken, IUALedger, IUALedgerViews {
    using MetaTxLib for MetaTxLib.UAMetaTransaction;
    using MetaTxLib for MetaTxLib.UAMetaTransfer;

    constructor(bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        ERC20("", "") UAMetaTxBase(_domainName(), chainUid_, registry_, smartKeyAccountImpl_, hedera_)
    {}

    /// @notice The EIP-712 domain name (CTR-MTX-02): `"SCaaS MetaToken"`; a confidential kind overrides it.
    function _domainName() internal pure virtual returns (string memory) {
        return "SCaaS MetaToken";
    }

    // ------------------------------------------------------------------ views

    /// @notice `0xF3`: both flags and every fee mode (a token holds the charged balance).
    function supportedModes() public pure override(IMetaTx, MetaTxBase) returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    // `UAMetaTxBase` holds these three and `IUALedger` / `IUALedgerViews` name them too: the join spelled out.

    function registry() public view override(IUALedger, UAMetaTxBase) returns (address) {
        return UAMetaTxBase.registry();
    }

    function mtxNonce(bytes32 from, uint256 batch) public view override(IUALedgerViews, UAMetaTxBase) returns (uint256) {
        return UAMetaTxBase.mtxNonce(from, batch);
    }

    function mtxDigest(MetaTxLib.UAMetaTransaction calldata m)
        public view override(IUALedgerViews, UAMetaTxBase) returns (bytes32)
    {
        return UAMetaTxBase.mtxDigest(m);
    }

    /// @notice A native id reads the ERC-20 balance of its address; a derived UA its UA-ledger balance.
    function balanceOfUA(bytes32 ua) public view returns (uint256) {
        return UAKinds.inNativeSpace(ua) ? balanceOf(address(uint160(uint256(ua)))) : _ua().balance[ua];
    }

    function mtxTransferDigest(MetaTxLib.UAMetaTransfer calldata t) external view returns (bytes32) {
        return MtxPipelineLib.transferDigest(_domainSeparatorV4(), t);
    }

    // ------------------------------------------------------------------ trade orders (CTR-DEX-15, -25, -02)

    function tradeOrderDigest(TradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.orderHash(TradeLib.core(o), false));
    }

    function uaTradeOrderDigest(UATradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.orderHash(o, true));
    }

    function cancelOrderDigest(TradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.cancelHash(TradeLib.core(o), false));
    }

    function cancelUAOrderDigest(UATradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.cancelHash(o, true));
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
        if (TradeLib.$().pulled[h] == 0) MtxPipelineLib.requireSignature(_mtxCtx(), o.from, h, sig);
        _transfer(o.from, o.dex, TradeLib.record(c, f, h, false));
    }

    /// @notice CTR-DEX-25: `mtxTrade` for an id; the UA rule under purpose `trade` (a native id signs `h` itself); the
    ///         fill moves through the UA ledger (a derived seller: `Transfer(UA_POOL, dex)` + `UATransfer`). A registry
    ///         is needed only for a derived seller (C, R9: `authorize` refuses it `UALedgerOff` by name), so a native
    ///         holder's wrap order (`WrappedToken.mtxWrapOrder`, R39) runs on a token with no registry.
    function uaTrade(UATradeOrder calldata o, IUARegistry.UASig calldata auth, TradeFill calldata f) external nonReentrant {
        bytes32 h = uaTradeOrderDigest(o);
        UATradeOrder memory c = o;
        TradeLib.precheck(c, f, h, msg.sender, address(this));
        if (TradeLib.$().pulled[h] == 0) MtxPipelineLib.authorize(_mtxCtx(), o.from, UAKinds.PURPOSE_TRADE, h, auth);
        _uaMove(o.from, TradeLib.pad(o.dex), TradeLib.record(c, f, h, true));
    }

    /// @notice DX7: only `o.dex`, at most what it pulled for the order in this transaction (`TradeLib.restore`); a
    ///         direct read of the caller, never allowlisted.
    function restorePulled(TradeOrder calldata o, uint256 amount) external nonReentrant {
        TradeLib.restore(TradeLib.core(o), tradeOrderDigest(o), amount, msg.sender);
    }

    function restorePulled(UATradeOrder calldata o, uint256 amount) external nonReentrant {
        TradeLib.restore(o, uaTradeOrderDigest(o), amount, msg.sender);
    }

    /// @notice Cancel signatures never expire (CTR-DEX-02); anyone may submit one.
    function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external nonReentrant {
        MtxPipelineLib.requireSignature(_mtxCtx(), o.from, cancelOrderDigest(o), sig);
        TradeLib.cancel(tradeOrderDigest(o), o.amount, TradeLib.pad(o.from), false);
    }

    function uaCancelOrder(UATradeOrder calldata o, IUARegistry.UASig calldata auth) external nonReentrant {
        _uaOn();
        MtxPipelineLib.authorize(_mtxCtx(), o.from, UAKinds.PURPOSE_TRADE, cancelUAOrderDigest(o), auth);
        TradeLib.cancel(uaTradeOrderDigest(o), o.amount, o.from, true);
    }

    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external nonReentrant {
        MtxPipelineLib.requireSignature(_mtxCtx(), from, invalidateNoncesDigest(from, batch, newMin), sig);
        TradeLib.invalidate(TradeLib.pad(from), batch, newMin, false);
    }

    function uaInvalidateNonces(bytes32 from, uint256 batch, uint256 newMin, IUARegistry.UASig calldata auth)
        external nonReentrant
    {
        _uaOn();
        MtxPipelineLib.authorize(
            _mtxCtx(), from, UAKinds.PURPOSE_TRADE, uaInvalidateNoncesDigest(from, batch, newMin), auth);
        TradeLib.invalidate(from, batch, newMin, true);
    }

    // ------------------------------------------------------------------ the generic pipeline on MtxPipelineLib

    /// @dev CTR-MTX-17 on the library: 1-4 and the fee amount in `preCall` (the fee is checked before the call, owner
    ///      2026-10-27), 5 the self-call, 6 the fee move, 7 the event. `data` stays here: the library gets its hash.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal override returns (bytes memory)
    {
        return _settle(m, MtxPipelineLib.preCall(_mtxCtx(), _envelopeOf(m), _callFacts(m.data, false), signature));
    }

    /// @dev `_execute` of a named entry (TS-D14): 1-4 in `preNamed` over the entry's own struct, the rest shared.
    function _named(bytes32 typehash, bytes4 sel, MetaTxLib.Envelope calldata e, bytes memory args, bytes calldata sig)
        internal override returns (bytes memory)
    {
        return _namedCall(typehash, e, args, abi.encodePacked(sel, args), sig);
    }

    /// @dev `_named` where the struct's words are not the call's arguments: nested structs and `bytes` hash into `words`
    ///      (EIP-712), `data` is the op's call.
    function _namedCall(bytes32 typehash, MetaTxLib.Envelope calldata e, bytes memory words, bytes memory data, bytes calldata sig)
        internal returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m = _metaOf(e, data);
        return _settle(m, MtxPipelineLib.preNamed(
            _mtxCtx(), typehash, _envelopeOf(m, 0), words, _callFacts(m.data, false), sig));
    }

    /// @dev Steps 5-7 of the address path.
    function _settle(MetaTxLib.MetaTransaction memory m, MtxPipelineLib.Out memory o) private returns (bytes memory ret) {
        ret = _selfCall(MetaTxLib.pad(m.from), m.data, _envelopeBinding(m));                                 // 5
        if (o.fee != 0) _transfer(m.from, o.feeTo, o.fee);                                                    // 6
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, o.digest, o.feeTo, o.fee);         // 7
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
    ///      it, except a self-call under a derived UA (`mtxExecute`), which spends that UA's own balance through it.
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

    // ------------------------------------------------------------------ typed path (CTR-MTX-23, CTR-MTX-24)

    /// @notice The typed transfer or payment of any id (ua-mtx-merge T2: today's `uaExecuteTransfer` under this name): a
    ///         native `from` signs `UAMetaTransfer` with its own key and moves its ERC-20 balance, a derived one through
    ///         the registry and its UA-ledger balance.
    function mtxExecuteTransfer(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth)
        external nonReentrant returns (bool)
    {
        _uaExecuteTransfer(t, 0, auth);
        return true;
    }

    /// @notice Atomic, items in order; never mixed with `UAMetaTransaction`s (CTR-MTX-24).
    function mtxBatchTransfer(MetaTxLib.UAMetaTransfer[] calldata ts, IUARegistry.UASig[] calldata auths)
        external nonReentrant returns (bool)
    {
        uint256 n = ts.length;
        if (n == 0) revert MtxBatchEmpty();
        if (n != auths.length) revert MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) _uaExecuteTransfer(ts[i], 0, auths[i]);
        return true;
    }

    /// @dev Step 6 of the UA path: the fee from the signer's ledger.
    function _uaChargeFee(MetaTxLib.UAMetaTransaction memory m, address feeTo, uint256 fee) internal override {
        _uaMove(m.from, MetaTxLib.pad(feeTo), fee);
    }

    /// @dev Every typed entry (struct, batch, the named builders, receiver-pays, the relay fee) goes through here
    ///      (CTR-MTX-23 on ids): steps 1-4 in `MtxPipelineLib.preTransferUA` (`have` read here), everything checked
    ///      before the nonce and the moves, which cannot fail afterwards. `signed`: the struct the signer signed when it
    ///      is not `t` (`UARelayFee`), else 0. Returns the digest. A native side moves in the ERC-20 ledger and emits
    ///      `Transfer`; the events are the `UA…` ones for every subject (R18).
    function _uaExecuteTransfer(MetaTxLib.UAMetaTransfer memory t, bytes32 signed, IUARegistry.UASig calldata auth)
        internal returns (bytes32)
    {
        MtxPipelineLib.Out memory o = MtxPipelineLib.preTransferUA(_mtxCtx(), t, signed, balanceOfUA(t.from), auth); // 1-4
        if (o.fee != 0) _uaMove(t.from, MetaTxLib.pad(o.feeTo), o.fee);                                // 5
        _uaMove(t.from, t.to, t.value);
        if (t.entryRef != 0) emit UAPaymentSettled(t.from, t.to, t.value, o.fee, o.feeTo, t.entryRef);
        emit UAMetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, o.digest, o.feeTo, o.fee); // 6
        return o.digest;
    }

    /// @dev The receiver of every `…ToUA` function (CTR-UA-28): the ledger on and a registered SIGNING derived id; a
    ///      native id belongs to the address twin (`UANotRegistered`).
    function _requireDerivedReceiver(bytes32 to) internal view {
        _uaOn();
        if (UAKinds.inNativeSpace(to)) revert UANotRegistered(to);
        MtxPipelineLib._checkTo(_REGISTRY, to); // the one receiver rule (internal: inlined, no DELEGATECALL)
    }

    /// @dev A mint into a derived UA (CTR-UA-28): a UA-ledger move from 0, `Transfer(0, UA_POOL)` and `UATransfer(0, to)`.
    function _uaMint(bytes32 to, uint256 v) internal {
        _requireDerivedReceiver(to);
        _uaMove(bytes32(0), to, v);
    }

    /// @dev Every UA-ledger move: derived sides in `balance`, native sides (or `UA_POOL` for a derived side) through
    ///      the ERC-20 core, so `Transfer` is emitted iff a native balance changes and `UATransfer` iff a side is derived.
    // ponytail: calls `ERC20._update` directly, skipping `_update`'s hooks and `_transfer`'s zero checks (callers
    // exclude 0); when the REGULATED features (FREEZE / PAUSE / ALLOWLIST / DENYLIST, GovernanceLib) are built they must
    // also hook here, including the UA->UA branch. `_poolMove` carries no hook (governance spec §4.3: it moves the fees
    // and decoy fees that stay unchecked).
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

    function _msgSender() internal view virtual override(Context, MetaTxBase) returns (address) {
        return MetaTxBase._msgSender();
    }
}
