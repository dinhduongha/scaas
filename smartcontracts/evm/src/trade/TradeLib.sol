// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ITradeToken} from "./ITradeToken.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title The token side of `TradeOrder` and `UATradeOrder` (CTR-DEX-15, CTR-DEX-25, CTR-DEX-02, CTR-TOK-24), in the
///        ERC-7201 namespace `scaas.trade`.
/// @notice External library: order checks and the per-order state (`pulled`, `minNonce`); the token computes the
///         digest (its domain), checks the signature (its `_requireValidSignature` or the UA rule, Hedera branch
///         included) and moves the funds (ERC-20 stays inline). Order of the checks is the spec's: caller and
///         identities, relayer, shape, [token: signature], closed, Path A / Path B, effects. Both structs run on one
///         form, `UATradeOrder` (ids as `bytes32`, a native address zero-padded; `core`), so `minNonce` is one floor per
///         id; the events follow the entry point (`ua`).
library TradeLib {
    bytes32 internal constant TRADE_ORDER_TYPEHASH = keccak256(
        "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,"
        "address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
    );
    bytes32 internal constant CANCEL_ORDER_TYPEHASH = keccak256("CancelOrder(bytes32 orderHash)");
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

    function $() internal pure returns (TradeStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    /// @dev EIP-712 struct hash of `o` (the token wraps it in its domain).
    function hashStruct(ITradeToken.TradeOrder memory o) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex,
            o.destination, o.flags, o.batch, o.nonce, o.validUntil));
    }

    function hashStructUA(ITradeToken.UATradeOrder memory o) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            UA_TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer,
            o.dex, o.destination, o.flags, o.batch, o.nonce, o.validUntil));
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
        if (ua) emit ITradeToken.UATradeFilled(h, o.from, move, f.receiveFill, f.dexFee);
        else emit ITradeToken.TradeFilled(h, addr(o.from), move, f.receiveFill, f.dexFee);
    }

    /// @notice `a·b > c·d` over 512 bits (SOL-02, review W-S): the price limit of any amounts, never an overflow panic.
    function mulGt(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (bool) {
        (uint256 h1, uint256 l1) = Math.mul512(a, b);
        (uint256 h2, uint256 l2) = Math.mul512(c, d);
        return h1 > h2 || (h1 == h2 && l1 > l2);
    }

    /// @notice After the `CancelOrder` signature: closed forever; an already closed order is a no-op.
    function cancel(bytes32 h, uint256 amount, bytes32 from, bool ua) public {
        TradeStorage storage s = $();
        if (s.pulled[h] >= amount) return;
        s.pulled[h] = amount;
        if (ua) emit ITradeToken.UAOrderCancelled(h, from);
        else emit ITradeToken.OrderCancelled(h, addr(from));
    }

    /// @notice After the `InvalidateNonces` / `UAInvalidateNonces` signature: strictly increasing, capped at `2^128`.
    function invalidate(bytes32 from, uint256 batch, uint256 newMin, bool ua) public {
        TradeStorage storage s = $();
        uint256 cur = s.minNonce[from][batch];
        if (newMin <= cur) revert ITradeToken.MinNonceNotIncreasing(cur, newMin);
        if (newMin > MAX_MIN_NONCE) revert ITradeToken.MinNonceAboveCap(newMin);
        s.minNonce[from][batch] = newMin;
        if (ua) emit ITradeToken.UANoncesInvalidated(from, batch, newMin);
        else emit ITradeToken.NoncesInvalidated(addr(from), batch, newMin);
    }
}
