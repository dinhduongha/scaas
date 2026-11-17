// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ITradeToken} from "./ITradeToken.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title The order checks of `UATradeOrder` (a SCaaS token's, CTR-DEX-15, CTR-DEX-25) and `TradeOrder` (the DEX's
///        outside legs, CTR-DEX-18), CTR-DEX-02, CTR-TOK-24, in the ERC-7201 namespace `scaas.trade`.
/// @notice External library: order checks and the per-order state (`pulled`, `minNonce`); the caller computes the
///         digest (its domain), checks the signature (the token: the UA rule, Hedera branch included; the DEX:
///         `SigCheck`) and moves the funds. Order of the checks is the spec's: caller and identities, relayer, shape,
///         [signature], closed, Path A / Path B, effects. Both structs run on one form, `UATradeOrder` (ids as `bytes32`,
///         a native address zero-padded; `core`), so `minNonce` is one floor per id. A token hashes only the UA structs
///         (ua-mtx-merge T6, R12: the address `TradeOrder` / `WrapOrder` side of the token and its typehashes are in
///         legacy/ua-mtx-merge/); `record`, `cancel`, `invalidate` keep `ua` for the DEX's outside legs (address events).
library TradeLib {
    bytes32 internal constant TRADE_ORDER_TYPEHASH = keccak256(
        "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,"
        "address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
    );
    bytes32 internal constant UA_WRAP_ORDER_TYPEHASH = keccak256(
        "UAWrapOrder(bytes32 from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,"
        "address relayer,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
    );
    // The cancel nests the struct the order was signed in (TS-D19); one string literal per typehash.
    bytes32 internal constant CANCEL_UA_ORDER_TYPEHASH = keccak256(
        "CancelUAOrder(UATradeOrder order)UATradeOrder(bytes32 from,address receiveToken,uint256 amount,"
        "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,bytes32 destination,uint8 flags,"
        "uint256 batch,uint256 nonce,uint256 validUntil)"
    );
    bytes32 internal constant CANCEL_UA_WRAP_ORDER_TYPEHASH = keccak256(
        "CancelUAWrapOrder(UAWrapOrder order)UAWrapOrder(bytes32 from,address wrappedToken,uint256 amount,"
        "uint256 minMinted,uint256 minFill,uint256 fee,address relayer,bytes32 destination,uint8 flags,uint256 batch,"
        "uint256 nonce,uint256 validUntil)"
    );
    /// @dev The DEX's outside-leg invalidate (CTR-DEX-18); a token signs `UAInvalidateNonces`.
    bytes32 internal constant INVALIDATE_NONCES_TYPEHASH =
        keccak256("InvalidateNonces(address from,uint256 batch,uint256 minNonce)");
    bytes32 internal constant UA_TRADE_ORDER_TYPEHASH = keccak256(
        "UATradeOrder(bytes32 from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,"
        "address relayer,address dex,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
    );
    bytes32 internal constant UA_INVALIDATE_NONCES_TYPEHASH =
        keccak256("UAInvalidateNonces(bytes32 from,uint256 batch,uint256 minNonce)");

    uint8 internal constant IOC = 1;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant LISTED_POOLS = 4;
    uint256 internal constant PPM = 1_000_000;
    uint256 internal constant MAX_FEE_PPM = 10_000;
    uint256 internal constant MAX_MIN_NONCE = 2 ** 128;

    /// @custom:storage-location erc7201:scaas.trade
    struct TradeStorage {
        mapping(bytes32 orderHash => uint256) pulled;
        // keyed by id: an address and its zero-padded id hash to the same slot (one floor for both structs)
        mapping(bytes32 from => mapping(uint256 batch => uint256)) minNonce;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.trade")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x2c9c6bfc4d8563261a812845f5cbef41fd06d0e8f173455fd0e077ab420e2f00;

    // keccak256("scaas.trade.pulledInTx"): the EIP-1153 base of the per-order amount pulled in this transaction (DX7)
    bytes32 private constant _PULLED_IN_TX = 0x2ca698c6c765bd574e7fcaf019f1f879dabafc254dbc4edea1a897c485aef9ea;

    function $() internal pure returns (TradeStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    /// @dev The transient slot of `h`'s amount pulled in this transaction (`record` adds, `restore` and `cancel` lower).
    function _inTx(bytes32 h) private pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0, h)
            mstore(0x20, _PULLED_IN_TX)
            slot := keccak256(0, 0x40)
        }
    }

    /// @dev EIP-712 struct hash of `o` as a `TradeOrder`: what a `DexOrder` nests, whatever its fields (CTR-DEX-18).
    function hashStruct(ITradeToken.TradeOrder memory o) internal pure returns (bytes32) {
        return _tradeHash(core(o), TRADE_ORDER_TYPEHASH);
    }

    /// @dev EIP-712 struct hash of a token's order (the token wraps it in its domain). An order with
    ///      `dex == receiveToken` is a wrap, the wrapped token pulling for itself (TS-D19): it is signed as `UAWrapOrder`,
    ///      which has no `dex`; every other order as `UATradeOrder`. One accepted form per order.
    function orderHash(ITradeToken.UATradeOrder memory c) internal pure returns (bytes32) {
        if (c.dex == c.receiveToken) return _wrapHash(c, UA_WRAP_ORDER_TYPEHASH);
        return _tradeHash(c, UA_TRADE_ORDER_TYPEHASH);
    }

    function _tradeHash(ITradeToken.UATradeOrder memory o, bytes32 typehash) private pure returns (bytes32) {
        return keccak256(abi.encode(
            typehash, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex,
            o.destination, o.flags, o.batch, o.nonce, o.validUntil));
    }

    function _wrapHash(ITradeToken.UATradeOrder memory o, bytes32 typehash) private pure returns (bytes32) {
        return keccak256(abi.encode(
            typehash, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.destination,
            o.flags, o.batch, o.nonce, o.validUntil));
    }

    /// @notice EIP-712 struct hash of the cancel of a token's order: the nested struct the order was signed in (TS-D19).
    ///         A library call: a rare path, and two type strings the tokens need not carry.
    function cancelHash(ITradeToken.UATradeOrder memory c) public pure returns (bytes32) {
        return _cancelHash(c);
    }

    /// @dev The body of `cancelHash` (T66b rule 4): a token's module T compiles it in; `cancelHash` is the DEX's library call.
    function _cancelHash(ITradeToken.UATradeOrder memory c) internal pure returns (bytes32) {
        bytes32 t = c.dex == c.receiveToken ? CANCEL_UA_WRAP_ORDER_TYPEHASH : CANCEL_UA_ORDER_TYPEHASH;
        return keccak256(abi.encode(t, orderHash(c)));
    }

    /// @dev The one form of both structs: the same 13 static ABI words in the same order, a native id being its address
    ///      zero-padded, so a `TradeOrder` in memory IS a `UATradeOrder` with padded ids (no field moves).
    function core(ITradeToken.TradeOrder memory o) internal pure returns (ITradeToken.UATradeOrder memory c) {
        assembly ("memory-safe") { c := o }
    }

    function pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    /// @dev The address of a native id (callers pass only ids of a `TradeOrder` or checked native ones).
    function addr(bytes32 id) internal pure returns (address) {
        return address(uint160(uint256(id)));
    }

    /// @notice Steps 1–3 (before the signature): caller and identities, relayer, shape. `token` is the sell token:
    ///         `address(this)` in a token; the leg's token in the DEX, which runs the same checks for outside tokens.
    function precheck(ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f, bytes32 h, address caller,
        address token) public view
    {
        _precheck(o, f, h, caller, token);
    }

    /// @dev The body of `precheck` (T66b rule 4): a token's module T compiles it in; `precheck` is the DEX's library call.
    function _precheck(ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f, bytes32 h, address caller,
        address token) internal view
    {
        if (caller != o.dex) revert ITradeToken.NotDex(caller);
        if (!SigCheck.isContract(o.dex)) revert ITradeToken.DexNotContract(o.dex);
        if (o.from == pad(token) || o.dex == token) revert ITradeToken.SelfOrder(h);
        if (o.relayer != address(0) && o.relayer != f.submitter) revert ITradeToken.WrongRelayer(h, f.submitter);
        if (block.timestamp > o.validUntil) revert ITradeToken.OrderExpired(h);
        if (o.nonce >= MAX_MIN_NONCE) revert ITradeToken.NonceAboveCap(h); // C6-5: no lane floor can reach it
        if (o.nonce < $().minNonce[o.from][o.batch]) revert ITradeToken.NonceInvalidated(h);
        if (o.flags & ~(IOC | ESCROW | LISTED_POOLS) != 0 || (o.flags & ESCROW != 0 && o.flags & IOC == 0)) {
            revert ITradeToken.BadFlags(h);
        }
        if (o.amount == 0 || o.receiveAmount == 0) revert ITradeToken.ZeroAmount(h);
        if (o.minFill > o.amount) revert ITradeToken.BadMinFill(h);
        if (o.fee > MAX_FEE_PPM) revert ITradeToken.FeeAboveCap(h);
    }

    /// @notice Steps 5–8 (after the signature): closed, Path A bounds or Path B shape, then `pulled` and the event.
    /// @return move the amount the token transfers from `o.from` to `o.dex`
    function record(ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f, bytes32 h, bool ua)
        public returns (uint256 move)
    {
        return _record(o, f, h, ua);
    }

    /// @dev The body of `record` (T66b rule 4): a token's module T compiles it in; `record` is the DEX's library call.
    function _record(ITradeToken.UATradeOrder memory o, ITradeToken.TradeFill memory f, bytes32 h, bool ua)
        internal returns (uint256 move)
    {
        TradeStorage storage s = $();
        uint256 p = s.pulled[h];
        if (p >= o.amount) revert ITradeToken.OrderClosed(h);
        if (o.flags & ESCROW == 0) {
            move = f.sellFill;
            if (move == 0) revert ITradeToken.ZeroFill(h);
            if (move > o.amount - p) revert ITradeToken.Overfill(h);
            // the signer's minFill is the only per-fill minimum (CTR-DEX-14); the remainder may close below it
            if (move != o.amount - p && move < o.minFill) revert ITradeToken.BelowMinFill(h);
            if (mulGt(move, o.receiveAmount, f.receiveFill, o.amount)) revert ITradeToken.PriceLimit(h);
            if (f.dexFee > Math.mulDiv(f.receiveFill, o.fee, PPM, Math.Rounding.Ceil)) revert ITradeToken.FeeAboveSigned(h);
        } else {
            move = o.amount;
            if (p != 0 || f.sellFill != move || f.receiveFill != 0 || f.dexFee != 0) {
                revert ITradeToken.EscrowFillShape(h);
            }
        }
        s.pulled[h] = o.flags & IOC != 0 ? o.amount : p + move;
        bytes32 t = _inTx(h);
        assembly ("memory-safe") { tstore(t, add(tload(t), move)) }
        if (ua) emit ITradeToken.UATradeFilled(h, o.from, move, f.receiveFill, f.dexFee);
        else emit ITradeToken.TradeFilled(h, addr(o.from), move, f.receiveFill, f.dexFee);
    }

    /// @notice `a·b > c·d` over 512 bits (SOL-02, review W-S): the price limit of any amounts, never an overflow panic.
    function mulGt(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (bool) {
        (uint256 h1, uint256 l1) = Math.mul512(a, b);
        (uint256 h2, uint256 l2) = Math.mul512(c, d);
        return h1 > h2 || (h1 == h2 && l1 > l2);
    }

    /// @notice DX7 (`restorePulled`, owner 2026-10-30): `o.dex` gives back `amount` of what it pulled for `h` in this
    ///         transaction (a hybrid's refunded leftover): `pulled[h]` is lower by it, fillable again. An IOC order stays
    ///         closed (`OrderClosed`).
    function restore(ITradeToken.UATradeOrder memory o, bytes32 h, uint256 amount, address caller) public {
        _restore(o, h, amount, caller);
    }

    /// @dev The body of `restore` (T66b rule 4): a token's module T compiles it in; `restore` is the DEX's library call.
    function _restore(ITradeToken.UATradeOrder memory o, bytes32 h, uint256 amount, address caller) internal {
        if (caller != o.dex) revert ITradeToken.NotDex(caller);
        if (o.flags & IOC != 0) revert ITradeToken.OrderClosed(h);
        bytes32 t = _inTx(h);
        uint256 inTx;
        assembly ("memory-safe") { inTx := tload(t) }
        if (amount > inTx) revert ITradeToken.RestoreExceedsPull(h);
        assembly ("memory-safe") { tstore(t, sub(inTx, amount)) }
        $().pulled[h] -= amount;
        emit ITradeToken.PullRestored(h, amount);
    }

    /// @notice After the cancel's signature: closed forever; an already closed order is a no-op. Either way this
    ///         transaction's pulls can no longer be restored (DX7).
    function cancel(bytes32 h, uint256 amount, bytes32 from, bool ua) public {
        _cancel(h, amount, from, ua);
    }

    /// @dev The body of `cancel` (T66b rule 4): a token's module T compiles it in; `cancel` is the DEX's library call.
    function _cancel(bytes32 h, uint256 amount, bytes32 from, bool ua) internal {
        bytes32 t = _inTx(h);
        assembly ("memory-safe") { tstore(t, 0) }
        TradeStorage storage s = $();
        if (s.pulled[h] >= amount) return;
        s.pulled[h] = amount;
        if (ua) emit ITradeToken.UAOrderCancelled(h, from);
        else emit ITradeToken.OrderCancelled(h, addr(from));
    }

    /// @notice After the `InvalidateNonces` / `UAInvalidateNonces` signature: strictly increasing, capped at `2^128`.
    function invalidate(bytes32 from, uint256 batch, uint256 newMin, bool ua) public {
        _invalidate(from, batch, newMin, ua);
    }

    /// @dev The body of `invalidate` (T66b rule 4): a token's module T compiles it in; `invalidate` is the DEX's library call.
    function _invalidate(bytes32 from, uint256 batch, uint256 newMin, bool ua) internal {
        TradeStorage storage s = $();
        uint256 cur = s.minNonce[from][batch];
        if (newMin <= cur) revert ITradeToken.MinNonceNotIncreasing(cur, newMin);
        if (newMin > MAX_MIN_NONCE) revert ITradeToken.MinNonceAboveCap(newMin);
        s.minNonce[from][batch] = newMin;
        if (ua) emit ITradeToken.UANoncesInvalidated(from, batch, newMin);
        else emit ITradeToken.NoncesInvalidated(addr(from), batch, newMin);
    }
}
