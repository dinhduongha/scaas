// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockRouter} from "./DexExchange.t.sol";
import {MockV2Pair, v2AmountOut} from "../helpers/MockUniswap.sol";

/// Matching modes 3 and 4 on the existing `mtxExchange` plans (spec §3.3, §3.4; DX2: no ABI change for these, DX3:
/// the clearing price is the planner's, applied through the floors). Fixture: the UA DEX base (A / B SCaaS with the UA
/// ledger on, C SCaaS without it, the outside `usdc`); a v2-style constant-product pair A / B with 100 000 A and
/// 200 000 B (marginal price 2 B per A); a v3-style router holding B and usdc; dave holds B, C and usdc, erin holds C.
///
/// The floor helper (`_ammPrice`, `_midPrice`, `_at`, `_buffered`, `_floor`) is DX3 as the planner would apply it: one
/// price P = num / den per pair (receive per sell) — the pool's reserves `rOut / rIn` when a pool exists, else the
/// midpoint of the two crossing limits `(r1·r2 + a1·a2) / (2·a1·r2)`; a leg's floor is `floor(internalFill · P)` plus
/// `floor(quote · (1 − 1 %))` for the part routed outside, and a leg whose floor is below its signed limit is left out
/// of the plan (the helper refuses it).
contract DexModesTest is UADexBase {
    uint256 constant ERIN_PK = 0xE41;
    uint256 constant BUFFER_BPS = 100; // 1 % off the outside quote
    address erin = vm.addr(ERIN_PK);
    MockV2Pair pool;
    MockRouter router;

    function setUp() public override {
        super.setUp();
        pool = new MockV2Pair(address(A), address(B));
        vm.prank(alice);
        A.transfer(address(pool), 100_000);
        router = new MockRouter();
        vm.startPrank(bob);
        B.transfer(address(pool), 200_000);
        B.transfer(address(router), 100_000);
        B.transfer(dave, 10_000);
        C.transfer(dave, 10_000);
        C.transfer(erin, 10_000);
        vm.stopPrank();
        pool.sync();
        usdc.mint(address(router), 100_000);
    }

    // ------------------------------------------------------------------ the floor helper (DX3)

    /// P of `sell` in the pool's other token: its marginal price `rOut / rIn`.
    function _ammPrice(address sell) internal view returns (uint256 num, uint256 den) {
        (uint256 r0, uint256 r1,) = pool.getReserves();
        return sell == pool.token0() ? (r1, r0) : (r0, r1);
    }

    /// P for `o1` (sells X for Y) against `o2` (sells Y for X), in Y per X: the midpoint of `o1`'s limit `r1 / a1` and
    /// `o2`'s `a2 / r2`. The limits must cross.
    function _midPrice(ITradeToken.TradeOrder memory o1, ITradeToken.TradeOrder memory o2)
        internal pure returns (uint256 num, uint256 den)
    {
        require(o1.receiveAmount * o2.receiveAmount <= o1.amount * o2.amount, "limits do not cross");
        return (o1.receiveAmount * o2.receiveAmount + o1.amount * o2.amount, 2 * o1.amount * o2.receiveAmount);
    }

    /// The internal part of a floor: `floor(fill · P)`.
    function _at(uint256 fill, uint256 num, uint256 den) internal pure returns (uint256) {
        return fill * num / den;
    }

    /// The outside part of a floor: the quote less the buffer.
    function _buffered(uint256 quote) internal pure returns (uint256) {
        return quote * (10_000 - BUFFER_BPS) / 10_000;
    }

    /// `floor` for a leg selling `sellFill`, or the leg is out of the plan: never below the signed limit.
    function _floor(ITradeToken.TradeOrder memory o, uint256 sellFill, uint256 floor) internal pure returns (uint256) {
        require(floor * o.amount >= sellFill * o.receiveAmount, "DX3: leg below its limit at P");
        return floor;
    }

    /// The pool's output for `amountIn` of `tokenIn` (Uniswap v2 `getAmountOut` on its reserves).
    function _quote(address tokenIn, uint256 amountIn) internal view returns (uint256) {
        (uint256 num, uint256 den) = _ammPrice(tokenIn);
        return v2AmountOut(amountIn, den, num);
    }

    // ------------------------------------------------------------------ legs, routes, calls

    function _h(address sell, ITradeToken.TradeOrder memory o) internal view returns (bytes32) {
        return sell == address(usdc) ? dex.dexOrderDigest(sell, o) : ITradeToken(sell).tradeOrderDigest(o);
    }

    /// A shape-0 exchange leg signed by `pk` (a `DexOrder` for usdc, a `TradeOrder` on the token otherwise).
    function _leg(uint256 pk, address sell, ITradeToken.TradeOrder memory o, uint256 sellFill, uint256 floor)
        internal view returns (ISCaaSDex.ExchangeLeg memory)
    {
        return ISCaaSDex.ExchangeLeg(sell, 0, abi.encode(o), _ecdsa(pk, _h(sell, o)), sellFill, floor);
    }

    /// A shape-1 exchange leg.
    function _uaXLeg(address sell, ITradeToken.UATradeOrder memory o, uint256 sellFill, uint256 floor)
        internal view returns (ISCaaSDex.ExchangeLeg memory)
    {
        return ISCaaSDex.ExchangeLeg(sell, 1, abi.encode(o), _uaLeg(sell, o, sellFill).sig, sellFill, floor);
    }

    /// A maker of a mode-3 plan: its floor is its own price `⌈fill · receiveAmount / amount⌉` (spec §3.3).
    function _maker(uint256 pk, address sell, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (ISCaaSDex.ExchangeLeg memory)
    {
        return _leg(pk, sell, o, fill, (fill * o.receiveAmount + o.amount - 1) / o.amount);
    }

    function _plan(bytes32 ref, ISCaaSDex.ExchangeLeg memory l0, ISCaaSDex.ExchangeLeg memory l1)
        internal pure returns (ISCaaSDex.ExchangePlan memory p)
    {
        p.ref = ref;
        p.legs = new ISCaaSDex.ExchangeLeg[](2);
        (p.legs[0], p.legs[1]) = (l0, l1);
    }

    function _plan(bytes32 ref, ISCaaSDex.ExchangeLeg memory l0, ISCaaSDex.ExchangeLeg memory l1,
        ISCaaSDex.ExchangeLeg memory l2) internal pure returns (ISCaaSDex.ExchangePlan memory p)
    {
        p.ref = ref;
        p.legs = new ISCaaSDex.ExchangeLeg[](3);
        (p.legs[0], p.legs[1], p.legs[2]) = (l0, l1, l2);
    }

    function _bobM() internal view returns (ITradeToken.TradeOrder memory) {
        return _nat(bob, address(A), 2000, 1000, 1_000);
    }

    function _daveM() internal view returns (ITradeToken.TradeOrder memory) {
        return _nat(dave, address(A), 1000, 600, 0);
    }

    /// Mode 3 as one plan: taker `t` (alice) sells 1000 A for B; makers bob (2000 B for 1000 A, fee 0.1 %) and dave
    /// (1000 B for 600 A) each sell 400 B at their own price (200 A, 240 A); the other 560 A go outside for at least
    /// `outsideFloor` B. The taker's floor: 800 B from the makers plus `outsideFloor`.
    function _m3(ITradeToken.TradeOrder memory t, uint256 outsideFloor)
        internal view returns (ISCaaSDex.ExchangePlan memory)
    {
        return _plan("m3", _leg(ALICE_PK, address(A), t, 1000, _floor(t, 1000, 800 + outsideFloor)),
            _maker(BOB_PK, address(B), _bobM(), 400), _maker(DAVE_PK, address(B), _daveM(), 400));
    }

    function _taker(uint256 nonce) internal view returns (ITradeToken.TradeOrder memory o) {
        o = _nat(alice, address(B), 1000, 1800, 3_000);
        o.nonce = nonce;
    }

    /// The v2 way: pay the pair by a transfer, then `swap` `amountOut` of the other token to the DEX.
    function _v2(address tokenIn, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(tokenIn, abi.encodeCall(IERC20.transfer, (address(pool), amountIn)));
        (uint256 o0, uint256 o1) = tokenIn == pool.token0() ? (uint256(0), amountOut) : (amountOut, uint256(0));
        xs[1] = ISCaaSDex.Interaction(address(pool), abi.encodeCall(MockV2Pair.swap, (o0, o1, address(dex), "")));
    }

    /// The v3-router way: `approve(router, amountIn)` on `tIn`, then the router swaps to the DEX.
    function _swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(tIn, abi.encodeCall(IERC20.approve, (address(router), amountIn)));
        xs[1] = ISCaaSDex.Interaction(address(router),
            abi.encodeCall(MockRouter.swap, (tIn, tOut, amountIn, amountOut, address(dex))));
    }

    function _cat(ISCaaSDex.Interaction[] memory x, ISCaaSDex.Interaction[] memory y)
        internal pure returns (ISCaaSDex.Interaction[] memory z)
    {
        z = new ISCaaSDex.Interaction[](x.length + y.length);
        for (uint256 i; i < x.length; ++i) z[i] = x[i];
        for (uint256 i; i < y.length; ++i) z[x.length + i] = y[i];
    }

    function _noIx() internal pure returns (ISCaaSDex.Interaction[] memory) {
        return new ISCaaSDex.Interaction[](0);
    }

    function _exchange(ISCaaSDex.ExchangePlan memory p, ISCaaSDex.Interaction[] memory xs) internal {
        vm.prank(RELAYER);
        dex.mtxExchange(p, xs);
    }

    function _expect(ISCaaSDex.ExchangePlan memory p, ISCaaSDex.Interaction[] memory xs, bytes memory err) internal {
        vm.prank(RELAYER);
        vm.expectRevert(err);
        dex.mtxExchange(p, xs);
    }

    function _err(bytes4 sel, bytes32 h) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, h);
    }

    function _empty() internal view {
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
        assertEq(C.balanceOf(address(dex)), 0);
        assertEq(usdc.balanceOf(address(dex)), 0);
    }

    // ------------------------------------------------------------------ mode 3 on an `mtxExchange` plan (spec §3.3)

    /// Taker + two makers + a v2 pair: the makers get exactly their price (bob 200 A less fee 1, dave 240 A, surplus
    /// 0), the pair's 1110 B above the 1098 outside floor (its quote less 1 %) is the taker's surplus (12).
    function test_mode3_exchangePlan_takerAndTwoMakers_viaMockV2() public {
        uint256 q = _quote(address(A), 560);
        assertEq(q, 1110);
        ITradeToken.TradeOrder memory t = _taker(1);
        ISCaaSDex.ExchangePlan memory p = _m3(t, _buffered(q));
        uint256 bob0 = B.balanceOf(bob);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("m3", _h(address(A), t), alice, alice, 1000, 1898, 12, 6, 0, 1800);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("m3", _h(address(B), _bobM()), bob, bob, 400, 200, 0, 1, 0, 200);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("m3", _h(address(B), _daveM()), dave, dave, 400, 240, 0, 0, 0, 240);
        _exchange(p, _v2(address(A), 560, q));
        assertEq(B.balanceOf(alice), 1898 - 6 + 12);
        assertEq(A.balanceOf(alice), 800_000 - 1000);
        assertEq(A.balanceOf(bob), 199);
        assertEq(A.balanceOf(dave), 240);
        assertEq(B.balanceOf(bob), bob0 - 400);
        assertEq(B.balanceOf(dave), 10_000 - 400);
        assertEq(A.balanceOf(TREASURY), 1);
        assertEq(B.balanceOf(RELAYER), 1);
        assertEq(B.balanceOf(TREASURY), 5);
        (uint256 rB, uint256 rA) = _ammPrice(address(A));
        assertEq(rA, 100_560);
        assertEq(rB, 200_000 - 1110);
        _empty();
    }

    /// The same plan through a v3-style router (approve + `swap`), which returns 1150: the 52 above the floor are the
    /// taker's; the makers still get exactly their price.
    function test_mode3_exchangePlan_viaMockV3Router() public {
        ITradeToken.TradeOrder memory t = _taker(1);
        _exchange(_m3(t, _buffered(_quote(address(A), 560))), _swap(address(A), address(B), 560, 1150));
        assertEq(B.balanceOf(alice), 1898 - 6 + 52);
        assertEq(A.balanceOf(bob), 199);
        assertEq(A.balanceOf(dave), 240);
        assertEq(A.balanceOf(address(router)), 560);
        assertEq(A.pulled(_h(address(A), t)), 1000);
        _empty();
    }

    /// An IOC taker (2000 A, 1000 filled) is closed at the pull; a FOK taker (`minFill == amount`) filled in part
    /// reverts with its hash, filled whole it settles.
    function test_mode3_exchangePlan_takerIocAndFok() public {
        uint256 oFloor = _buffered(_quote(address(A), 560));
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 2000, 3600, 3_000);
        t.flags = 1; // IOC
        _exchange(_m3(t, oFloor), _v2(address(A), 560, 1110));
        assertEq(A.pulled(_h(address(A), t)), 2000);
        assertEq(A.balanceOf(alice), 800_000 - 1000);

        oFloor = _buffered(_quote(address(A), 560));
        t = _nat(alice, address(B), 1200, 2160, 3_000);
        t.nonce = 2;
        t.minFill = 1200;
        ISCaaSDex.Interaction[] memory xs = _v2(address(A), 560, _quote(address(A), 560));
        _expect(_m3(t, oFloor), xs, _err(ITradeToken.BelowMinFill.selector, _h(address(A), t)));
        t = _nat(alice, address(B), 1000, 1800, 3_000);
        t.nonce = 3;
        t.minFill = 1000;
        _exchange(_m3(t, oFloor), xs);
        assertEq(A.pulled(_h(address(A), t)), 1000);
        assertEq(A.balanceOf(alice), 800_000 - 2000);
        assertEq(B.pulled(_h(address(B), _bobM())), 800);
        _empty();
    }

    /// A UA maker (shape 1, paid into its ledger, `UAExchangeLegSettled`) next to a native maker; then an outside-token
    /// maker (a `DexOrder` pulled through the puller) against a taker selling A for usdc.
    function test_mode3_exchangePlan_uaMaker_outsideMaker() public {
        ITradeToken.TradeOrder memory t = _taker(1);
        ITradeToken.UATradeOrder memory u = _ua(uaB, address(A), 2000, 1000, 1_000);
        uint256 q = _quote(address(A), 560);
        ISCaaSDex.ExchangePlan memory p = _plan("m3", _leg(ALICE_PK, address(A), t, 1000, 800 + _buffered(q)),
            _uaXLeg(address(B), u, 400, 200), _maker(DAVE_PK, address(B), _daveM(), 400));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.UAExchangeLegSettled("m3", B.uaTradeOrderDigest(u), uaB, uaB, 400, 200, 0, 1, 0, 200);
        _exchange(p, _v2(address(A), 560, q));
        assertEq(A.balanceOfUA(uaB), 199);
        assertEq(B.balanceOfUA(uaB), 100_000 - 400);
        assertEq(A.balanceOf(dave), 240);
        assertEq(B.balanceOf(alice), 1898 - 6 + 12);

        t = _nat(alice, address(usdc), 1000, 1800, 3_000);
        t.nonce = 2;
        ITradeToken.TradeOrder memory d = _nat(dave, address(A), 2000, 1000, 1_000);
        p = _plan("m3", _leg(ALICE_PK, address(A), t, 1000, 800 + 1080), _maker(DAVE_PK, address(usdc), d, 800));
        _exchange(p, _swap(address(A), address(usdc), 600, 1150));
        assertEq(A.balanceOf(dave), 240 + 399);
        assertEq(usdc.balanceOf(dave), 1e6 - 800);
        assertEq(usdc.balanceOf(alice), 1880 - 6 + 70);
        assertEq(dex.pulled(_h(address(usdc), d)), 800);
        _empty();
    }

    /// A maker cancelled between the plan and its inclusion reverts the whole plan with the maker's hash: on its token
    /// (a SCaaS maker) or on the DEX (an outside-token maker). Nothing moves.
    function test_mode3_exchangePlan_staleMaker_revertsWithItsHash() public {
        ITradeToken.TradeOrder memory t = _taker(1);
        bytes32 hb = _h(address(B), _bobM());
        vm.prank(bob);
        B.mtxCancelOrder(_bobM(), _ecdsa(BOB_PK, B.cancelOrderDigest(hb)));
        uint256 q = _quote(address(A), 560);
        _expect(_m3(t, _buffered(q)), _v2(address(A), 560, q), _err(ITradeToken.OrderClosed.selector, hb));

        ITradeToken.TradeOrder memory d = _nat(dave, address(A), 2000, 1000, 1_000);
        bytes32 hd = _h(address(usdc), d);
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](1);
        os[0] = ISCaaSDex.DexOrder(address(usdc), d);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _ecdsa(DAVE_PK, dex.cancelOrderDigest(hd));
        dex.mtxCancelOrders(os, sigs);
        t = _nat(alice, address(usdc), 1000, 1800, 3_000);
        ISCaaSDex.ExchangePlan memory p =
            _plan("m3", _leg(ALICE_PK, address(A), t, 1000, 1880), _maker(DAVE_PK, address(usdc), d, 800));
        _expect(p, _swap(address(A), address(usdc), 600, 1150), _err(ITradeToken.OrderClosed.selector, hd));

        assertEq(A.balanceOf(alice), 800_000);
        assertEq(B.balanceOf(alice), 0);
        assertEq(usdc.balanceOf(dave), 1e6);
    }

    /// The route spends 557 of the 560 A it was given: the 3 A left are excess of a receive token, paid to the makers
    /// pro rata of their floors (bob ⌊3 · 200 / 440⌋ = 1, dave the last receiver 2), not refunded to the taker (the
    /// `mtxHybrid` rule, DX7, is not this path's).
    function test_mode3_exchangePlan_excessAToMakersProRata() public {
        ITradeToken.TradeOrder memory t = _taker(1);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("m3", _h(address(A), t), alice, alice, 1000, 1898, 52, 6, 0, 1800);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("m3", _h(address(B), _bobM()), bob, bob, 400, 200, 1, 1, 0, 200);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("m3", _h(address(B), _daveM()), dave, dave, 400, 240, 2, 0, 0, 240);
        _exchange(_m3(t, _buffered(_quote(address(A), 560))), _swap(address(A), address(B), 557, 1150));
        assertEq(A.balanceOf(bob), 200 - 1 + 1);
        assertEq(A.balanceOf(dave), 242);
        assertEq(A.balanceOf(alice), 800_000 - 1000);
        assertEq(A.balanceOf(address(router)), 557);
        _empty();
    }

    // ------------------------------------------------------------------ mode 4: CoW / ring (spec §3.4)

    /// Partial CoW: alice sells 1000 A, bob 1200 B; at the pool's P = 2 bob's 1200 B meet 600 of alice's A inside the
    /// plan, the net 400 A go through the pair (quote 794, floor part 786). Floors: alice 1200 + 786 = 1986 B, bob
    /// 600 A; both orders filled, the pair's 8 B above the floor to alice.
    function test_mode4_partialCow_netThroughAmm_bothFilled() public {
        ITradeToken.TradeOrder memory oa = _nat(alice, address(B), 1000, 1900, 3_000);
        ITradeToken.TradeOrder memory ob = _nat(bob, address(A), 1200, 580, 1_000);
        (uint256 num, uint256 den) = _ammPrice(address(A));
        uint256 internalA = _at(1200, den, num);
        assertEq(internalA, 600);
        uint256 q = _quote(address(A), 1000 - internalA);
        assertEq(q, 794);
        uint256 fa = _floor(oa, 1000, _at(internalA, num, den) + _buffered(q));
        uint256 fb = _floor(ob, 1200, _at(1200, den, num));
        assertEq(fa, 1986);
        assertEq(fb, 600);
        uint256 bob0 = B.balanceOf(bob);
        _exchange(_plan("cow", _leg(ALICE_PK, address(A), oa, 1000, fa), _leg(BOB_PK, address(B), ob, 1200, fb)),
            _v2(address(A), 400, q));
        assertEq(A.pulled(_h(address(A), oa)), 1000);
        assertEq(B.pulled(_h(address(B), ob)), 1200);
        assertEq(B.balanceOf(alice), 1986 - 6 + 8);
        assertEq(A.balanceOf(bob), 600 - 1);
        assertEq(B.balanceOf(bob), bob0 - 1200);
        (uint256 rB, uint256 rA) = _ammPrice(address(A));
        assertEq(rA, 100_400);
        assertEq(rB, 200_000 - 794);
        _empty();
    }

    /// With a pool for the pair, P is its marginal price (2 B per A), not the midpoint of the limits (≈ 2.099): alice
    /// 1000 A for 2000 B, bob 2000 B for 1000 A, nothing routed, the pool untouched.
    function test_mode4_clearingPrice_ammMarginal() public {
        ITradeToken.TradeOrder memory oa = _nat(alice, address(B), 1000, 1900, 0);
        ITradeToken.TradeOrder memory ob = _nat(bob, address(A), 2000, 870, 0);
        (uint256 num, uint256 den) = _ammPrice(address(A));
        assertEq(num, 2 * den);
        (uint256 mn, uint256 md) = _midPrice(oa, ob);
        assertEq(_at(1000, mn, md), 2099); // what the midpoint would have given alice
        uint256 fa = _floor(oa, 1000, _at(1000, num, den));
        uint256 fb = _floor(ob, 2000, _at(2000, den, num));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("cow", _h(address(A), oa), alice, alice, 1000, 2000, 0, 0, 0, 1900);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("cow", _h(address(B), ob), bob, bob, 2000, 1000, 0, 0, 0, 870);
        _exchange(_plan("cow", _leg(ALICE_PK, address(A), oa, 1000, fa), _leg(BOB_PK, address(B), ob, 2000, fb)),
            _noIx());
        assertEq(B.balanceOf(alice), 2000);
        assertEq(A.balanceOf(bob), 1000);
        (uint256 rB, uint256 rA) = _ammPrice(address(A));
        assertEq(rA, 100_000);
        assertEq(rB, 200_000);
        _empty();
    }

    /// No pool for A / usdc: P is the midpoint of alice's 1.9 usdc per A and dave's 2.1 (= 2). Alice 1000 A for 2000
    /// usdc (limit 1900), dave 2000 of his 2100 usdc for 1000 A (limit ⌈952.4⌉ = 953): the improvement split between
    /// them, no excess, no interaction.
    function test_mode4_clearingPrice_midpointWithoutPool() public {
        ITradeToken.TradeOrder memory oa = _nat(alice, address(usdc), 1000, 1900, 0);
        ITradeToken.TradeOrder memory od = _nat(dave, address(A), 2100, 1000, 0);
        (uint256 num, uint256 den) = _midPrice(oa, od);
        assertEq(num, 2 * den);
        uint256 fa = _floor(oa, 1000, _at(1000, num, den));
        uint256 fd = _floor(od, 2000, _at(2000, den, num));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("cow", _h(address(A), oa), alice, alice, 1000, 2000, 0, 0, 0, 1900);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("cow", _h(address(usdc), od), dave, dave, 2000, 1000, 0, 0, 0, 953);
        _exchange(_plan("cow", _leg(ALICE_PK, address(A), oa, 1000, fa), _leg(DAVE_PK, address(usdc), od, 2000, fd)),
            _noIx());
        assertEq(usdc.balanceOf(alice), 2000);
        assertEq(A.balanceOf(dave), 1000);
        assertEq(dex.pulled(_h(address(usdc), od)), 2000);
        _empty();
    }

    /// A 3-token ring A → B → C → A with no interaction, at P(A→B) = 2, P(B→C) = 3/2, P(C→A) = 1/3; A is received by
    /// two legs. Floors: alice 2008 B, bob 3013 C, dave ⌊1505 / 3⌋ = 501 A, erin ⌊1508 / 3⌋ = 502 A. B's excess 1 goes
    /// to its only receiver (alice); A's rounding remainder 1 to its last receiver (erin), dave's share ⌊501 / 1003⌋ = 0.
    function test_mode4_ring3_noInteractions_remainderToLastReceiver() public {
        ITradeToken.TradeOrder memory oa = _nat(alice, address(B), 1004, 2000, 0);
        ITradeToken.TradeOrder memory ob = _nat(bob, address(C), 2009, 3000, 0);
        ITradeToken.TradeOrder memory od = _nat(dave, address(A), 1505, 500, 0);
        ITradeToken.TradeOrder memory oe = _nat(erin, address(A), 1508, 500, 0);
        ISCaaSDex.ExchangePlan memory p = _plan("ring", _leg(ALICE_PK, address(A), oa, 1004, _floor(oa, 1004, _at(1004, 2, 1))),
            _leg(BOB_PK, address(B), ob, 2009, _floor(ob, 2009, _at(2009, 3, 2))),
            _leg(DAVE_PK, address(C), od, 1505, _floor(od, 1505, _at(1505, 1, 3))));
        ISCaaSDex.ExchangeLeg[] memory legs = new ISCaaSDex.ExchangeLeg[](4);
        (legs[0], legs[1], legs[2]) = (p.legs[0], p.legs[1], p.legs[2]);
        legs[3] = _leg(ERIN_PK, address(C), oe, 1508, _floor(oe, 1508, _at(1508, 1, 3)));
        p.legs = legs;
        assertEq(abi.encode(p.legs[0].receiveFill, p.legs[1].receiveFill, p.legs[2].receiveFill, p.legs[3].receiveFill),
            abi.encode(2008, 3013, 501, 502));
        uint256 bobC = C.balanceOf(bob);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("ring", _h(address(C), od), dave, dave, 1505, 501, 0, 0, 0, 500);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("ring", _h(address(C), oe), erin, erin, 1508, 502, 1, 0, 0, 500);
        _exchange(p, _noIx());
        assertEq(B.balanceOf(alice), 2008 + 1);
        assertEq(C.balanceOf(bob), bobC + 3013);
        assertEq(A.balanceOf(dave), 501);
        assertEq(A.balanceOf(erin), 503);
        assertEq(C.balanceOf(erin), 10_000 - 1508);
        _empty();
    }

    /// A ring A → B → C → A short of B: the 750 C over bob's floor are routed C → usdc → B, usdc a declared hop token
    /// no leg receives. A route that leaves 1 usdc in the DEX fails conservation on usdc; the exact route settles.
    function test_mode4_ring_intermediateLeftover_conservationBroken() public {
        ITradeToken.TradeOrder memory oa = _nat(alice, address(B), 1000, 2000, 0);
        ITradeToken.TradeOrder memory ob = _nat(bob, address(C), 1500, 2250, 0);
        ITradeToken.TradeOrder memory od = _nat(dave, address(A), 3000, 1000, 0);
        ISCaaSDex.ExchangePlan memory p = _plan("ring", _leg(ALICE_PK, address(A), oa, 1000, _at(1000, 2, 1)),
            _leg(BOB_PK, address(B), ob, 1500, _at(1500, 3, 2)), _leg(DAVE_PK, address(C), od, 3000, _at(3000, 1, 3)));
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(usdc);
        ISCaaSDex.Interaction[] memory hop = _swap(address(C), address(usdc), 750, 501);
        _expect(p, _cat(hop, _swap(address(usdc), address(B), 500, 500)),
            abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(usdc)));
        _exchange(p, _cat(hop, _swap(address(usdc), address(B), 501, 500)));
        assertEq(B.balanceOf(alice), 2000);
        assertEq(A.balanceOf(dave), 1000);
        assertEq(C.balanceOf(address(router)), 750);
        _empty();
    }

    /// A leg filled at exactly its `minFill` (1000 of bob's 5000 B, 20 %: below the old half floor) in a CoW at the
    /// pool's P settles; one unit less is `BelowMinFill` with bob's hash. The remaining 4000 stay open.
    function test_mode4_legAtMinFillBelowHalf() public {
        ITradeToken.TradeOrder memory oa = _nat(alice, address(B), 500, 950, 0);
        ITradeToken.TradeOrder memory ob = _nat(bob, address(A), 5000, 2400, 0);
        ob.minFill = 1000;
        (uint256 num, uint256 den) = _ammPrice(address(A));
        bytes32 hb = _h(address(B), ob);
        ISCaaSDex.ExchangePlan memory p = _plan("cow", _leg(ALICE_PK, address(A), oa, 500, _floor(oa, 500, 999)),
            _leg(BOB_PK, address(B), ob, 999, _at(999, den, num)));
        _expect(p, _noIx(), _err(ITradeToken.BelowMinFill.selector, hb));
        p.legs[0] = _leg(ALICE_PK, address(A), oa, 500, _floor(oa, 500, _at(500, num, den)));
        p.legs[1] = _leg(BOB_PK, address(B), ob, 1000, _floor(ob, 1000, _at(1000, den, num)));
        _exchange(p, _noIx());
        assertEq(B.pulled(hb), 1000);
        assertEq(A.balanceOf(bob), 500);
        assertEq(B.balanceOf(alice), 1000);
        _empty();
    }

    /// Two independent CoW plans of one tick in one `mtxExchangeBatch` (spec §3.4, §5): alice / bob (shape 0) and
    /// uaP / uaB (shape 1), each at the pool's P = 2, no interaction; both settle.
    function test_mode4_twoCowPlansInOneBatch() public {
        ISCaaSDex.ExchangePlan[] memory ps = new ISCaaSDex.ExchangePlan[](2);
        (ps[0], ps[1]) = (_nativeCow(), _uaCow());
        ISCaaSDex.Interaction[][] memory xs = new ISCaaSDex.Interaction[][](2);
        (xs[0], xs[1]) = (_noIx(), _noIx());
        vm.prank(RELAYER);
        bool[] memory ok = dex.mtxExchangeBatch(ps, xs);
        assertEq(ok.length, 2);
        assertTrue(ok[0] && ok[1]);
        assertEq(B.balanceOf(alice), 2000);
        assertEq(A.balanceOf(bob), 1000);
        assertEq(B.balanceOfUA(uaP), 2000);
        assertEq(A.balanceOfUA(uaP), 100_000 - 1000);
        assertEq(A.balanceOfUA(uaB), 1000);
        assertEq(B.balanceOfUA(uaB), 100_000 - 2000);
        _empty();
    }

    function _nativeCow() internal view returns (ISCaaSDex.ExchangePlan memory) {
        ITradeToken.TradeOrder memory oa = _nat(alice, address(B), 1000, 1900, 0);
        ITradeToken.TradeOrder memory ob = _nat(bob, address(A), 2000, 950, 0);
        (uint256 num, uint256 den) = _ammPrice(address(A));
        return _plan("cow1", _leg(ALICE_PK, address(A), oa, 1000, _floor(oa, 1000, _at(1000, num, den))),
            _leg(BOB_PK, address(B), ob, 2000, _floor(ob, 2000, _at(2000, den, num))));
    }

    function _uaCow() internal view returns (ISCaaSDex.ExchangePlan memory) {
        (uint256 num, uint256 den) = _ammPrice(address(A));
        return _plan("cow2", _uaXLeg(address(A), _ua(uaP, address(B), 1000, 1900, 0), 1000, _at(1000, num, den)),
            _uaXLeg(address(B), _ua(uaB, address(A), 2000, 950, 0), 2000, _at(2000, den, num)));
    }
}
