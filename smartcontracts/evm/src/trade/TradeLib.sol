// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {ITradeToken} from "./ITradeToken.sol";
import {SigCheck} from "../common/SigCheck.sol";

/// @title The token side of `TradeOrder` (CTR-DEX-15, CTR-DEX-02, CTR-TOK-24), in the ERC-7201 namespace `scaas.trade`.
/// @notice External library: order checks and the per-order state (`pulled`, `minNonce`); the token computes the
///         digest (its domain), checks the signature (its `_requireValidSignature`, Hedera branch included) and moves
///         the funds (ERC-20 stays inline). Order of the checks is the spec's: caller and identities, relayer, shape,
///         [token: signature], closed, Path A / Path B, effects.
library TradeLib {
    bytes32 internal constant TRADE_ORDER_TYPEHASH = keccak256(
        "TradeOrder(address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,"
        "address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)"
    );
    bytes32 internal constant CANCEL_ORDER_TYPEHASH = keccak256("CancelOrder(bytes32 orderHash)");
    bytes32 internal constant INVALIDATE_NONCES_TYPEHASH =
        keccak256("InvalidateNonces(address from,uint256 batch,uint256 minNonce)");

    uint8 internal constant IOC = 1;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant LISTED_POOLS = 4;
    uint256 internal constant PPM = 1_000_000;
    uint256 internal constant MIN_FILL_PPM = 500_000;
    uint256 internal constant MAX_FEE_PPM = 10_000;
    uint256 internal constant MAX_MIN_NONCE = 2 ** 128;

    /// @custom:storage-location erc7201:scaas.trade
    struct TradeStorage {
        mapping(bytes32 orderHash => uint256) pulled;
        mapping(address from => mapping(uint256 batch => uint256)) minNonce;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.trade")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x2c9c6bfc4d8563261a812845f5cbef41fd06d0e8f173455fd0e077ab420e2f00;

    function $() internal pure returns (TradeStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    /// @dev EIP-712 struct hash of `o` (the token wraps it in its domain).
    function hashStruct(ITradeToken.TradeOrder calldata o) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            TRADE_ORDER_TYPEHASH, o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex,
            o.destination, o.flags, o.batch, o.nonce, o.validUntil));
    }

    /// @notice Steps 1–3 (before the signature): caller and identities, relayer, shape.
    function precheck(ITradeToken.TradeOrder calldata o, ITradeToken.TradeFill calldata f, bytes32 h, address caller)
        public view
    {
        if (caller != o.dex) revert ITradeToken.NotDex(caller);
        if (!SigCheck.isContract(o.dex)) revert ITradeToken.DexNotContract(o.dex);
        if (o.from == address(this) || o.dex == address(this)) revert ITradeToken.SelfOrder(h);
        if (o.relayer != address(0) && o.relayer != f.submitter) revert ITradeToken.WrongRelayer(h, f.submitter);
        if (block.timestamp > o.validUntil) revert ITradeToken.OrderExpired(h);
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
    function record(ITradeToken.TradeOrder calldata o, ITradeToken.TradeFill calldata f, bytes32 h)
        public returns (uint256 move)
    {
        TradeStorage storage s = $();
        uint256 p = s.pulled[h];
        if (p >= o.amount) revert ITradeToken.OrderClosed(h);
        if (o.flags & ESCROW == 0) {
            move = f.sellFill;
            if (move == 0) revert ITradeToken.ZeroFill(h);
            if (move > o.amount - p) revert ITradeToken.Overfill(h);
            if (move != o.amount - p) {
                // effective minimum: max(minFill, ceil(amount/2)); received side: receiveFill >= ceil(receiveAmount/2).
                // Written as halves, not products, so a huge amount cannot overflow: equal to the MIN_FILL_PPM =
                // 500_000 form (ceil(x * 500_000 / 1e6) = x - x / 2); the halving encodes MIN_FILL_PPM = PPM / 2 (pinned by
                // test_minFillPpm_halvingEncodesIt). The received-side term is implied by the PriceLimit check below
                // (move >= ceil(amount/2) and move*R <= receiveFill*amount give receiveFill >= R/2, an integer, so
                // >= ceil(R/2)): it never binds on its own and is kept as a defensive floor.
                uint256 half = o.amount - o.amount / 2;
                uint256 m = o.minFill > half ? o.minFill : half;
                if (move < m || f.receiveFill < o.receiveAmount - o.receiveAmount / 2) {
                    revert ITradeToken.BelowMinFill(h);
                }
            }
            if (move * o.receiveAmount > f.receiveFill * o.amount) revert ITradeToken.PriceLimit(h);
            if (f.dexFee > (f.receiveFill * o.fee + PPM - 1) / PPM) revert ITradeToken.FeeAboveSigned(h);
        } else {
            move = o.amount;
            if (p != 0 || f.sellFill != move || f.receiveFill != 0 || f.dexFee != 0) {
                revert ITradeToken.EscrowFillShape(h);
            }
        }
        s.pulled[h] = o.flags & IOC != 0 ? o.amount : p + move;
        emit ITradeToken.TradeFilled(h, o.from, move, f.receiveFill, f.dexFee);
    }

    /// @notice After the `CancelOrder` signature: closed forever; an already closed order is a no-op.
    function cancel(ITradeToken.TradeOrder calldata o, bytes32 h) public {
        TradeStorage storage s = $();
        if (s.pulled[h] >= o.amount) return;
        s.pulled[h] = o.amount;
        emit ITradeToken.OrderCancelled(h, o.from);
    }

    /// @notice After the `InvalidateNonces` signature: strictly increasing, capped at `2^128`.
    function invalidate(address from, uint256 batch, uint256 newMin) public {
        TradeStorage storage s = $();
        uint256 cur = s.minNonce[from][batch];
        if (newMin <= cur) revert ITradeToken.MinNonceNotIncreasing(cur, newMin);
        if (newMin > MAX_MIN_NONCE) revert ITradeToken.MinNonceAboveCap(newMin);
        s.minNonce[from][batch] = newMin;
        emit ITradeToken.NoncesInvalidated(from, batch, newMin);
    }
}
