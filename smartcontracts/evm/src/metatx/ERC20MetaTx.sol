// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;
import {IERC20MetaTx} from "./IERC20MetaTx.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {MetaTxBase, MetaTxBaseCore} from "./MetaTxBase.sol";
import {UAMetaTxBase, UAMetaTxBaseCore} from "./UAMetaTxBase.sol";
import {IMetaTx} from "./IMetaTx.sol";
import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {ITradeToken, ILiquidityDex} from "../trade/ITradeToken.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {LiquidityLib} from "../trade/LiquidityLib.sol";
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
///         `UATradeOrder` (CTR-DEX-15, -25; T6: the token's only order form) through `TradeLib`. The UA ledger
///         (CTR-UA-18/19/26): `bytes32` balances of derived UAs, shown as the holder `UA_POOL`, and the `ua*`
///         pipelines on the same lanes. Every signature (the
///         relayed paths, trade, cancel, invalidate, receiver-fee) is checked in `MtxPipelineLib` (`requireSignature`
///         / `authorize`; a derived UA by the registry's `requireAuthorized`), never here (owner 2026-10-27).
abstract contract ERC20MetaTx is ERC20, UAMetaTxBaseCore {
    using MetaTxLib for MetaTxLib.UAMetaTransaction;
    using MetaTxLib for MetaTxLib.UAMetaTransfer;

    /// @dev A factory-made token (`MetaTokenBase`, CTR-TOK-29) passes 0s and reads its clone's code instead.
    constructor(bytes32 chainUid_, address registry_, address smartKeyAccountImpl_, bool hedera_)
        ERC20("", "") UAMetaTxBaseCore(_domainName(), chainUid_, registry_, smartKeyAccountImpl_, hedera_)
    {}

    /// @notice The EIP-712 domain name (CTR-MTX-02): `"SCaaS MetaToken"`; a confidential kind overrides it.
    function _domainName() internal pure virtual returns (string memory) {
        return "SCaaS MetaToken";
    }

    // ------------------------------------------------------------------ views

    /// @notice `0xF3`: both flags and every fee mode (a token holds the charged balance).
    function _supportedModesBody() internal pure override returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    // `UAMetaTxBase` holds these three and `IUALedger` / `IUALedgerViews` name them too: the join spelled out.

    function registry() public view  returns (address) {
        return UAMetaTxBaseCore._registryBody();
    }

    function _mtxNonceBody(bytes32 from, uint256 batch) internal view override returns (uint256) {
        return UAMetaTxBaseCore._mtxNonceBody(from, batch);
    }

    function _mtxDigestBody(MetaTxLib.UAMetaTransaction calldata m) internal view override returns (bytes32)
    {
        return UAMetaTxBaseCore._mtxDigestBody(m);
    }

    /// @notice A native id reads the ERC-20 balance of its address; a derived UA its UA-ledger balance.
    function balanceOfUA(bytes32 ua) public view returns (uint256) {
        return UAKinds.inNativeSpace(ua) ? balanceOf(address(uint160(uint256(ua)))) : _ua().balance[ua];
    }

    function _mtxTransferDigestBody(MetaTxLib.UAMetaTransfer calldata t) internal view returns (bytes32) {
        return _pipeTransferDigest(_domainSeparatorV4(), t);
    }

    // ------------------------------------------------------------------ trade orders (CTR-DEX-15, -25, -02)
    // ua-mtx-merge T6 (R12, R38): one form, `UATradeOrder`, for every subject; the address `TradeOrder` entries and
    // views (`mtxTrade(TradeOrder, bytes, …)`, `mtxCancelOrder(TradeOrder, bytes)`, `mtxInvalidateNonces(address, …)`,
    // `restorePulled(TradeOrder, …)`, the address digests and `minNonce(address, …)`) are in legacy/ua-mtx-merge/.

    function _tradeOrderDigestBody(ITradeToken.UATradeOrder calldata o) internal view returns (bytes32) {
        return _hashTypedDataV4(TradeLib.orderHash(o));
    }

    function _cancelOrderDigestBody(ITradeToken.UATradeOrder calldata o) internal view returns (bytes32) {
        return _hashTypedDataV4(TradeLib._cancelHash(o));
    }

    function _invalidateNoncesDigestBody(bytes32 from, uint256 batch, uint256 newMin) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.UA_INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
    }

    function _pulledBody(bytes32 orderHash) internal view returns (uint256) {
        return TradeLib.$().pulled[orderHash];
    }

    /// @notice One floor per id (a native address zero-padded); a store apart from the meta-tx nonces.
    function _minNonceBody(bytes32 from, uint256 batch) internal view returns (uint256) {
        return TradeLib.$().minNonce[from][batch];
    }

    /// @notice Only `o.dex` calls (a direct read of the caller, CTR-MTX-18); never allowlisted. Moves the fill from
    ///         `o.from` to `o.dex` and nowhere else; the UA rule under purpose `trade` (a native id signs `h` itself,
    ///         no registry call); the fill moves through the UA ledger (a derived seller: `Transfer(UA_POOL, dex)` +
    ///         `UATransfer`). A registry is needed only for a derived seller (C, R9: `authorize` refuses it
    ///         `UALedgerOff` by name). The signature is checked once: a later fill of an order already pulled
    ///         (`pulled[h] ≠ 0`, `h` binds every field) skips it (CTR-DEX-15 step 4).
    function _mtxTradeBody(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata auth, ITradeToken.TradeFill calldata f) internal {
        bytes32 h = _tradeOrderDigestBody(o);
        ITradeToken.UATradeOrder memory c = o;
        TradeLib._precheck(c, f, h, msg.sender, address(this));
        if (TradeLib.$().pulled[h] == 0) _pipeAuthorize(_mtxCtx(), o.from, UAKinds.PURPOSE_TRADE, h, auth);
        _uaMove(o.from, TradeLib.pad(o.dex), TradeLib._record(c, f, h, true));
    }

    /// @notice CTR-DEX-30, CTR-DEX-15 Change (spec 2026-11-10-dex-liquidity.md §5): a liquidity-capable DEX pulls exactly
    ///         `amount` of this token from `o.from` for the liquidity order `o`, once. Checks T1-T10 in order: the caller is
    ///         a contract and not this token, `o.from` not this token; `relayer`; expiry; this token's order lane; this
    ///         token is exactly one input, `0 < amount <= its maximum`; the caller answers `liquidityOrderDigest(o)` with the
    ///         digest this token computed under `verifyingContract = msg.sender` (T7, capped at `TOKEN_GAS`, its revert data
    ///         dropped, one word read); the UA rule under `trade` over that digest; one-shot (`pulled[h]`); the move.
    ///         A direct read of the caller, never allowlisted; no transient pull counter (`restorePulled` cannot name it).
    function _mtxLiquidityPullBody(ITradeToken.LiquidityOrder calldata o, IUARegistry.UASig calldata auth, uint256 amount,
        address submitter) internal
    {
        address dex = msg.sender;
        bytes32 h = LiquidityLib.digest(o, dex, _chainUid());
        if (dex == address(this) || !SigCheck.isContract(dex)) revert ITradeToken.DexNotContract(dex); // T1
        if (o.from == TradeLib.pad(address(this))) revert ITradeToken.SelfOrder(h);
        if (o.relayer != address(0) && o.relayer != submitter) revert ITradeToken.WrongRelayer(h, submitter); // T2
        if (block.timestamp > o.validUntil) revert ITradeToken.OrderExpired(h); // T3
        if (o.nonce >= TradeLib.MAX_MIN_NONCE) revert ITradeToken.NonceAboveCap(h); // T4
        if (o.nonce < TradeLib.$().minNonce[o.from][o.batch]) revert ITradeToken.NonceInvalidated(h);
        uint256 max; // T5: this token is exactly one input
        uint256 seen;
        for (uint256 i; i < o.inputs.length; ++i) {
            if (o.inputs[i].token == address(this)) (max, seen) = (o.inputs[i].amount, seen + 1);
        }
        if (seen != 1) revert ITradeToken.LiquidityShape(6);
        if (amount == 0) revert ITradeToken.ZeroFill(h); // T6
        if (amount > max) revert ITradeToken.Overfill(h);
        if (!_liquidityDex(dex, abi.encodeCall(ILiquidityDex.liquidityOrderDigest, (o)), h)) {
            revert ITradeToken.NotLiquidityDex(dex); // T7
        }
        _pipeAuthorize(_mtxCtx(), o.from, UAKinds.PURPOSE_TRADE, h, auth); // T8: always (the order is one-shot)
        TradeLib.TradeStorage storage t = TradeLib.$();
        if (t.pulled[h] != 0) revert ITradeToken.OrderClosed(h); // T9
        t.pulled[h] = amount;
        _uaMove(o.from, TradeLib.pad(dex), amount); // T10
        emit ITradeToken.LiquidityPulled(h, o.from, dex, amount);
    }

    /// @dev T7: a `staticcall` of `dex` capped at `TokenCall.TOKEN_GAS`, its revert data dropped, exactly one word read,
    ///      equal to `h`. A DEX release without the liquidity module has no such view; a starved call fails the same way
    ///      (the node retries a `NotLiquidityDex` from a DEX that carries the liquidity mark with more gas).
    function _liquidityDex(address dex, bytes memory data, bytes32 h) private view returns (bool good) {
        assembly ("memory-safe") {
            let g := gas()
            if gt(g, 500000) { g := 500000 } // C6-1: TokenCall.TOKEN_GAS
            let s := staticcall(g, dex, add(data, 0x20), mload(data), 0, 0x20)
            good := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), h))
        }
    }

    /// @notice DX7: only `o.dex`, at most what it pulled for the order in this transaction (`TradeLib.restore`); a
    ///         direct read of the caller, never allowlisted. The restore is the refund (Fable B P2-1, CTR-DEX-27 Change):
    ///         `amount` moves from `o.dex` back to `o.from` with the capacity, so a dex looping pull, restore, pull takes
    ///         at most the signed `amount` (CTR-DEX-19).
    function _restorePulledBody(ITradeToken.UATradeOrder calldata o, uint256 amount) internal {
        TradeLib._restore(o, _tradeOrderDigestBody(o), amount, msg.sender);
        _uaMove(TradeLib.pad(o.dex), o.from, amount);
    }

    /// @notice Cancel signatures never expire (CTR-DEX-02); anyone may submit one. A native id needs no registry (C).
    function _mtxCancelOrderBody(ITradeToken.UATradeOrder calldata o, IUARegistry.UASig calldata auth) internal {
        _pipeAuthorize(_mtxCtx(), o.from, UAKinds.PURPOSE_TRADE, _cancelOrderDigestBody(o), auth);
        TradeLib._cancel(_tradeOrderDigestBody(o), o.amount, o.from, true);
    }

    function _mtxInvalidateNoncesBody(bytes32 from, uint256 batch, uint256 newMin, IUARegistry.UASig calldata auth) internal {
        _pipeAuthorize(_mtxCtx(), from, UAKinds.PURPOSE_TRADE, _invalidateNoncesDigestBody(from, batch, newMin), auth);
        TradeLib._invalidate(from, batch, newMin, true);
    }

    // ------------------------------------------------------------------ the generic pipeline on MtxPipelineLib

    /// @dev CTR-MTX-17 on the library: 1-4 and the fee amount in `preCall` (the fee is checked before the call, owner
    ///      2026-10-27), 5 the self-call, 6 the fee move, 7 the event. `data` stays here: the library gets its hash.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature)
        internal override returns (bytes memory)
    {
        _regPre(MetaTxLib.pad(m.from), bytes4(m.data), m.mode);
        return _settle(m, _pipePreCall(_mtxCtx(), _envelopeOf(m), _callFacts(m.data, false), signature));
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
        _regPre(MetaTxLib.pad(m.from), bytes4(data), m.mode);
        return _settle(m, _pipePreNamed(
            _mtxCtx(), typehash, _envelopeOf(m, 0), words, _callFacts(m.data, false), sig));
    }

    /// @dev Steps 5-7 of the address path.
    function _settle(MetaTxLib.MetaTransaction memory m, MtxPipelineLib.Out memory o) private returns (bytes memory ret) {
        _regFeeTo(MetaTxLib.pad(o.feeTo), o.fee);
        ret = _selfCall(MetaTxLib.pad(m.from), m.data, _envelopeBinding(m));                                 // 5
        if (o.fee != 0) _transfer(m.from, o.feeTo, o.fee);                                                    // 6
        emit IMetaTx.MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, o.digest, o.feeTo, o.fee);         // 7
    }

    // ------------------------------------------------------------------ allowance (CTR-TOK-01)

    /// @notice Caller and spender must both be contracts: no EOA grants or holds an allowance.
    function approve(address spender, uint256 value) public virtual override returns (bool) {
        address caller = _msgSender();
        if (!SigCheck.isContract(caller)) revert IERC20MetaTx.CallerNotContract(caller);
        if (!SigCheck.isContract(spender)) revert IERC20MetaTx.SpenderNotContract(spender);
        _regPayer();
        return super.approve(spender, value);
    }

    /// @notice Only a contract spends an allowance; checked before the allowance.
    function transferFrom(address from, address to, uint256 value)
        public virtual override returns (bool)
    {
        address caller = _msgSender();
        if (!SigCheck.isContract(caller)) revert IERC20MetaTx.CallerNotContract(caller);
        return super.transferFrom(from, to, value);
    }

    // ------------------------------------------------------------------ internals

    /// @dev Tokens parked at the token's own address are what a spoofed self-call would spend (CTR-MTX-18). `UA_POOL`'s
    ///      slot is Σ of the UA balances and only `_uaMove` writes it (CTR-UA-18): no native move, mint or burn reaches
    ///      it, except a self-call under a derived UA (`mtxExecute`), which spends that UA's own balance through it.
    function _update(address from, address to, uint256 value) internal virtual override {
        if (to == address(this)) revert IERC20MetaTx.TransferToSelf();
        if (to == MetaTxLib.UA_POOL) revert IUALedger.UAPoolNotPayable();
        if (to == MetaTxLib.SHIELD_POOL || from == MetaTxLib.SHIELD_POOL) revert IUALedger.ShieldPoolNotPayable(); // D19
        bytes32 f = MetaTxLib.pad(from);
        if (from == MetaTxLib.UA_POOL) {
            bytes32 ua = _ticketSubject();
            if (UAKinds.inNativeSpace(ua)) revert IUALedger.UAPoolNotPayable();
            _uaDebit(ua, value);
            emit IUALedger.UATransfer(ua, MetaTxLib.pad(to), value);
            f = ua;
        }
        _regMove(f, MetaTxLib.pad(to), value);
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
    function _mtxExecuteTransferBody(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth) internal returns (bool)
    {
        _uaExecuteTransfer(t, 0, auth, 0, 0);
        return true;
    }

    /// @notice Atomic, items in order; never mixed with `UAMetaTransaction`s (CTR-MTX-24).
    function _mtxBatchTransferBody(MetaTxLib.UAMetaTransfer[] calldata ts, IUARegistry.UASig[] calldata auths) internal returns (bool)
    {
        uint256 n = ts.length;
        if (n == 0) revert IMetaTx.MtxBatchEmpty();
        if (n != auths.length) revert IMetaTx.MtxBatchLengthMismatch();
        for (uint256 i; i < n; ++i) _uaExecuteTransfer(ts[i], 0, auths[i], 0, 0);
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
    ///      `Transfer`; the events are the `UA…` ones for every subject (R18). `withheld` of `t.value` goes from the payer to
    ///      `withheldTo` instead of the payee (a tax, pay-meta-tax spec §5.3, O13); every other caller passes 0, 0.
    function _uaExecuteTransfer(MetaTxLib.UAMetaTransfer memory t, bytes32 signed, IUARegistry.UASig calldata auth,
        uint256 withheld, bytes32 withheldTo) internal returns (bytes32)
    {
        _regPre(t.from, 0, t.mode);
        MtxPipelineLib.Out memory o = _pipePreTransferUA(_mtxCtx(), t, signed, balanceOfUA(t.from), auth); // 1-4
        _regFeeTo(MetaTxLib.pad(o.feeTo), o.fee);
        if (o.fee != 0) _uaMove(t.from, MetaTxLib.pad(o.feeTo), o.fee);                                // 5
        _uaSplit(t.from, t.to, t.value, withheld, withheldTo);
        if (t.entryRef != 0) emit IUALedger.UAPaymentSettled(t.from, t.to, t.value, o.fee, o.feeTo, t.entryRef);
        emit IUALedger.UAMetaTransactionExecuted(t.from, msg.sender, t.batch, t.nonce, o.digest, o.feeTo, o.fee); // 6
        return o.digest;
    }

    /// @dev A payment of `value`: `value - withheld` to `to`, `withheld` to `withheldTo`, both from `from` (a tax,
    ///      pay-meta-tax spec §5.3 O13, lever 1: one split for `mtxPayWithTax` and `payWithTax`); both moves hooked.
    function _uaSplit(bytes32 from, bytes32 to, uint256 value, uint256 withheld, bytes32 withheldTo) internal {
        _uaMove(from, to, value - withheld);
        if (withheld != 0) _uaMove(from, withheldTo, withheld);
    }

    /// @dev The receiver of every `…ToUA` function (CTR-UA-28): the ledger on and a registered SIGNING derived id; a
    ///      native id belongs to the address twin (`UANotRegistered`).
    function _requireDerivedReceiver(bytes32 to) internal view {
        _uaOn();
        if (UAKinds.inNativeSpace(to)) revert IUALedger.UANotRegistered(to);
        MtxPipelineLib._checkTo(_registry(), to); // the one receiver rule (internal: inlined, no DELEGATECALL)
    }

    /// @dev A mint into a derived UA (CTR-UA-28): a UA-ledger move from 0, `Transfer(0, UA_POOL)` and `UATransfer(0, to)`.
    function _uaMint(bytes32 to, uint256 v) internal {
        _requireDerivedReceiver(to);
        _uaMove(bytes32(0), to, v);
    }

    /// @dev Every UA-ledger move: derived sides in `balance`, native sides (or `UA_POOL` for a derived side) through
    ///      the ERC-20 core, so `Transfer` is emitted iff a native balance changes and `UATransfer` iff a side is derived.
    // ponytail: calls `ERC20._update` directly, skipping `_update` and `_transfer`'s zero checks (callers exclude 0);
    // `_regMove` hooks here, the UA->UA branch included (regulated-kinds spec §2.2). `_poolMove` carries no hook
    // (governance spec §4.3: it moves the fees and decoy fees that stay unchecked).
    function _uaMove(bytes32 from, bytes32 to, uint256 value) internal {
        // D19: no UA-ledger caller reaches `SHIELD_POOL` (its moves bypass `_update`); only `_poolMove` does.
        if (from == MetaTxLib.pad(MetaTxLib.SHIELD_POOL) || to == MetaTxLib.pad(MetaTxLib.SHIELD_POOL)) {
            revert IUALedger.ShieldPoolNotPayable();
        }
        _regMove(from, to, value);
        _poolMove(from, to, value);
    }

    /// @dev `_uaMove` without the pool refusal: for a shielding layer's own moves into / out of `SHIELD_POOL` (D19).
    function _poolMove(bytes32 from, bytes32 to, uint256 value) internal {
        bool fromUA = !UAKinds.inNativeSpace(from);
        bool toUA = !UAKinds.inNativeSpace(to);
        if (!toUA && address(uint160(uint256(to))) == address(this)) revert IERC20MetaTx.TransferToSelf(); // CTR-MTX-18
        if (fromUA) _uaDebit(from, value);
        if (toUA) _ua().balance[to] += value;
        if (!(fromUA && toUA)) {
            ERC20._update(fromUA ? MetaTxLib.UA_POOL : address(uint160(uint256(from))),
                toUA ? MetaTxLib.UA_POOL : address(uint160(uint256(to))), value);
        }
        if (fromUA || toUA) emit IUALedger.UATransfer(from, to, value);
    }

    function _uaDebit(bytes32 ua, uint256 value) private {
        UALedgerStorage storage $ = _ua();
        uint256 b = $.balance[ua];
        if (b < value) revert IUALedger.UAInsufficientBalance(ua, b, value);
        unchecked { $.balance[ua] = b - value; }
    }

    function _msgSender() internal view virtual override(Context, MetaTxBaseCore) returns (address) {
        return MetaTxBaseCore._msgSender();
    }

    // ------------------------------------------------------------------ regulated hooks (regulated-kinds spec §2.2)
    // Empty here (CTR-GOV-11, "+0"): only a regulated kind overrides them; raw arguments the caller holds (F-10).

    /// @notice Every ledger move: `_update` (the sender resolved from `UA_POOL` to the ticket's UA) and `_uaMove`, the
    ///         UA -> UA branch included; never `_poolMove`. A mint has `from` 0, a burn `to` 0.
    function _regMove(bytes32 /* from */, bytes32 /* to */, uint256 /* value */) internal view virtual {}

    /// @notice A payer that is not the moved balance's own call: `approve`, a wrap into another id, the confidential
    ///         shields and wrap-shields, a PQZ `shieldIn`. The override resolves the payer itself.
    function _regPayer() internal view virtual {}

    /// @notice A named sender: `mtxWrapOrder`'s `o.from` when the destination is another id; PQZ `fromUA`.
    function _regSender(bytes32 /* a */) internal view virtual {}

    /// @notice A confidential op's public beneficiary.
    function _regName(bytes32 /* beneficiary */) internal view virtual {}

    /// @notice An unshield's public recipient, when the amount is not 0.
    function _regReceiver(bytes32 /* recipient */) internal view virtual {}
}
