// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockRouter, MockExecutor, Hostile} from "./DexExchange.t.sol";

/// `mtxHybrid` / `mtxHybridVia` (spec §4; DX2, DX5, DX6, DX8, DX9): one listed-market taker against 0..n makers at
/// the makers' own prices, the rest of its sell routed outside; the taker gets every unit above the outside floor.
/// Fixture: the UA DEX base (A / B SCaaS with the UA ledger on, the outside `usdc` against A); a v3-style router holding
/// B and usdc.
///
/// The base plan: alice sells 1000 A for at least 1800 B (fee 0.3 %); bob's resting order sells 2000 B for 1000 A
/// (fee 0.1 %), filled 800 B at his price ⌈800 · 1000 / 2000⌉ = 400 A; the other 600 A go to the router for at least
/// 1080 B. Floor 800 + 1080 = 1880 B, taker fee ⌈5.64⌉ = 6, the router returns 1150: surplus 70 to alice.
contract DexHybridTest is UADexBase {
    MockRouter router;

    function setUp() public override {
        super.setUp();
        router = new MockRouter();
        vm.prank(bob);
        B.transfer(address(router), 100_000);
        usdc.mint(address(router), 100_000);
    }

    // ------------------------------------------------------------------ helpers

    function _taker(ITradeToken.TradeOrder memory o, uint256 fill) internal view returns (ISCaaSDex.Leg memory) {
        return _natLeg(address(A), o, fill);
    }

    function _bob(uint256 fill) internal view returns (ISCaaSDex.Leg memory) {
        return _natLeg(address(B), _nat(bob, address(A), 2000, 1000, 1_000), fill);
    }

    function _ms(ISCaaSDex.Leg memory m) internal pure returns (ISCaaSDex.Leg[] memory ms) {
        ms = new ISCaaSDex.Leg[](1);
        ms[0] = m;
    }

    function _plan(ISCaaSDex.Leg memory taker, ISCaaSDex.Leg[] memory makers, uint256 sell, uint256 floor)
        internal pure returns (ISCaaSDex.HybridPlan memory p)
    {
        p.ref = "hy";
        p.taker = taker;
        p.makers = makers;
        p.outsideSell = sell;
        p.outsideFloor = floor;
    }

    /// The base plan (see the contract comment).
    function _base() internal view returns (ISCaaSDex.HybridPlan memory) {
        return _plan(_taker(_nat(alice, address(B), 1000, 1800, 3_000), 1000), _ms(_bob(800)), 600, 1080);
    }

    function _ix(address target, bytes memory data) internal pure returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](1);
        xs[0] = ISCaaSDex.Interaction(target, data);
    }

    function _cat(ISCaaSDex.Interaction[] memory x, ISCaaSDex.Interaction[] memory y)
        internal pure returns (ISCaaSDex.Interaction[] memory z)
    {
        z = new ISCaaSDex.Interaction[](x.length + y.length);
        for (uint256 i; i < x.length; ++i) z[i] = x[i];
        for (uint256 i; i < y.length; ++i) z[x.length + i] = y[i];
    }

    /// `approve(router, amountIn)` on `tIn`, then the router swaps `amountIn` for `amountOut` of `tOut` to the DEX.
    function _swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory)
    {
        return _cat(_ix(tIn, abi.encodeCall(IERC20.approve, (address(router), amountIn))),
            _ix(address(router), abi.encodeCall(MockRouter.swap, (tIn, tOut, amountIn, amountOut, address(dex)))));
    }

    function _route(uint256 amountIn, uint256 amountOut) internal view returns (ISCaaSDex.Interaction[] memory) {
        return _swap(address(A), address(B), amountIn, amountOut);
    }

    function _hybrid(ISCaaSDex.HybridPlan memory p, ISCaaSDex.Interaction[] memory xs) internal {
        vm.prank(RELAYER);
        dex.mtxHybrid(p, xs);
    }

    function _expect(ISCaaSDex.HybridPlan memory p, ISCaaSDex.Interaction[] memory xs, bytes memory err) internal {
        vm.prank(RELAYER);
        vm.expectRevert(err);
        dex.mtxHybrid(p, xs);
    }

    function _err(bytes4 sel, bytes32 h) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, h);
    }

    function _err(bytes4 sel, address x) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, x);
    }

    function _wrapped(uint256 index, address target, bytes memory reason) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(ISCaaSDex.InteractionFailed.selector, index, target, reason);
    }

    function _h(ISCaaSDex.Leg memory l) internal view returns (bytes32) {
        return ITradeToken(l.sellToken).tradeOrderDigest(abi.decode(l.order, (ITradeToken.TradeOrder)));
    }

    function _executor() internal returns (MockExecutor e) {
        e = new MockExecutor();
        vm.prank(bob);
        B.transfer(address(e), 100_000);
    }

    // ------------------------------------------------------------------ prices, events, fees

    /// The maker gets exactly its price (400 A less its fee 1) whatever the route returns; the taker gets the floor less
    /// its fee plus everything the route returned above `outsideFloor`; the DEX keeps nothing.
    function test_hybrid_makersAtTheirPrice_takerGetsAllAboveTheFloor() public {
        _hybrid(_base(), _route(600, 1150));
        assertEq(A.balanceOf(bob), 399);
        assertEq(A.balanceOf(TREASURY), 1);
        assertEq(B.balanceOf(bob), 800_000 - 800);
        assertEq(B.balanceOf(alice), 1880 - 6 + 70);
        assertEq(B.balanceOf(RELAYER), 1);
        assertEq(B.balanceOf(TREASURY), 5);
        assertEq(A.balanceOf(alice), 900_000 - 1000);
        assertEq(A.balanceOf(address(router)), 600);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
        // a richer route changes only the taker's surplus
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker = _natLeg(address(A), _withNonce(_nat(alice, address(B), 1000, 1800, 3_000), 2), 1000);
        _hybrid(p, _route(600, 1500));
        assertEq(A.balanceOf(bob), 2 * 399);
        assertEq(B.balanceOf(alice), 2 * (1880 - 6) + 70 + 420);
    }

    function _withNonce(ITradeToken.TradeOrder memory o, uint256 nonce)
        internal pure returns (ITradeToken.TradeOrder memory)
    {
        o.nonce = nonce;
        return o;
    }

    /// DX6: the maker `LegSettled` (paid first), the taker `ExchangeLegSettled` with `receivedFloor` = Σ maker sold +
    /// `outsideFloor`, `surplus` = output above `outsideFloor`, `limitReceive` on the taker's whole sell.
    function test_hybrid_events_makerLegSettled_takerExchangeLegSettled() public {
        ISCaaSDex.HybridPlan memory p = _base();
        vm.expectEmit(address(dex));
        emit ISCaaSDex.LegSettled("hy", _h(p.makers[0]), bob, bob, 800, 399, 1, 0, 0, 1);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 1000, 1880, 70, 6, 0, 1800);
        _hybrid(p, _route(600, 1150));
    }

    /// DX9: each maker pays `⌈recv · fee⌉` on its exact receive; the taker once on its floor (3800 B: ⌈19⌉), not on the
    /// 500 of surplus; the relayer gets 20 % of each fee (rounded down), the treasury the rest.
    function test_hybrid_fees_makersOnReceive_takerOnceOnFloor_surplusFeeFree() public {
        ISCaaSDex.Leg memory m = _natLeg(address(B), _nat(bob, address(A), 2000, 1000, 10_000), 2000);
        ISCaaSDex.HybridPlan memory p =
            _plan(_taker(_nat(alice, address(B), 2000, 3600, 5_000), 2000), _ms(m), 1000, 1800);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.LegSettled("hy", _h(m), bob, bob, 2000, 990, 10, 0, 2, 8);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 2000, 3800, 500, 19, 0, 3600);
        _hybrid(p, _route(1000, 2300));
        assertEq(A.balanceOf(bob), 990);
        assertEq(A.balanceOf(RELAYER), 2);
        assertEq(A.balanceOf(TREASURY), 8);
        assertEq(B.balanceOf(alice), 3800 - 19 + 500);
        assertEq(B.balanceOf(RELAYER), 3);
        assertEq(B.balanceOf(TREASURY), 16);
    }

    // ------------------------------------------------------------------ the check step (spec §4.2 step 1)

    function test_hybrid_outputBelowFloor_insufficientOutput() public {
        _expect(_base(), _route(600, 1079), _err(ISCaaSDex.InsufficientOutput.selector, address(B)));
        _hybrid(_base(), _route(600, 1080)); // exactly the floor settles, surplus 0
        assertEq(B.balanceOf(alice), 1880 - 6);
    }

    function test_hybrid_fillMismatch() public {
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker.fill = 999;
        _expect(p, _route(600, 1150), abi.encodeWithSelector(ISCaaSDex.FillMismatch.selector, 1000, 999));
        p = _base();
        p.outsideSell = 601;
        _expect(p, _route(600, 1150), abi.encodeWithSelector(ISCaaSDex.FillMismatch.selector, 1001, 1000));
    }

    function test_hybrid_marketNotListed() public {
        dex.setMarket(address(A), address(B), false);
        _expect(_base(), _route(600, 1150),
            abi.encodeWithSelector(ISCaaSDex.MarketNotListed.selector, address(A), address(B)));
    }

    /// DX8: `mtxSettle`'s rule — no maker's `from` equals the taker's.
    function test_hybrid_selfTrade_takerIsMaker() public {
        ISCaaSDex.HybridPlan memory p = _base();
        p.makers[0] = _natLeg(address(B), _nat(alice, address(A), 2000, 1000, 1_000), 800);
        _expect(p, _route(600, 1150), _err(ISCaaSDex.SelfTrade.selector, bytes32(uint256(uint160(alice)))));
    }

    /// Makers may share a signer (two of bob's orders), each at its own price.
    function test_hybrid_twoMakersOneSigner_settle() public {
        ISCaaSDex.Leg[] memory ms = new ISCaaSDex.Leg[](2);
        ms[0] = _bob(400);                                                                    // 200 A
        ms[1] = _natLeg(address(B), _withNonce(_nat(bob, address(A), 1000, 600, 0), 2), 400); // 240 A
        ISCaaSDex.HybridPlan memory p =
            _plan(_taker(_nat(alice, address(B), 1000, 1800, 0), 1000), ms, 560, 1008);
        _hybrid(p, _route(560, 1100));
        assertEq(A.balanceOf(bob), 200 - 1 + 240); // fee ⌈0.2⌉ on the first order only
        assertEq(B.balanceOf(alice), 800 + 1008 + 92);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
    }

    function test_hybrid_duplicateOrder() public {
        ISCaaSDex.Leg[] memory ms = new ISCaaSDex.Leg[](2);
        ms[0] = _bob(400);
        ms[1] = _bob(400);
        ISCaaSDex.HybridPlan memory p = _plan(_taker(_nat(alice, address(B), 1000, 1800, 0), 1000), ms, 600, 1080);
        _expect(p, _route(600, 1150), _err(ISCaaSDex.DuplicateOrder.selector, _h(ms[0])));
    }

    function test_hybrid_makerWrongRelayer() public {
        ITradeToken.TradeOrder memory o = _nat(bob, address(A), 2000, 1000, 1_000);
        o.relayer = address(0x1234);
        ISCaaSDex.HybridPlan memory p = _base();
        p.makers[0] = _natLeg(address(B), o, 800);
        _expect(p, _route(600, 1150), _err(ISCaaSDex.WrongRelayer.selector, RELAYER));
    }

    /// DX8: `LISTED_POOLS` is read from the taker only: on the taker an unlisted route is refused, on a maker it is
    /// ignored (the route cannot change what a maker gets).
    function test_hybrid_listedPools_takerFlag_makerFlagIgnored() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1800, 3_000);
        t.flags = 4;
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker = _taker(t, 1000);
        _expect(p, _route(600, 1150), _err(ISCaaSDex.TargetNotListed.selector, address(A)));
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 1_000);
        m.flags = 4;
        p = _base();
        p.makers[0] = _natLeg(address(B), m, 800);
        _hybrid(p, _route(600, 1150));
        assertEq(A.balanceOf(bob), 399);
    }

    /// DX5: no makers — a listed-market taker routed only outside.
    function test_hybrid_zeroMakers() public {
        ISCaaSDex.HybridPlan memory p =
            _plan(_taker(_nat(alice, address(B), 1000, 1800, 3_000), 600), new ISCaaSDex.Leg[](0), 600, 1080);
        _hybrid(p, _route(600, 1150));
        assertEq(B.balanceOf(alice), 1080 - 4 + 70);
        assertEq(A.pulled(_h(p.taker)), 600);
        assertEq(A.balanceOf(address(dex)), 0);
    }

    /// DX5: `outsideSell` 0 — book only, no interactions, surplus 0.
    function test_hybrid_zeroOutsideSell() public {
        ISCaaSDex.HybridPlan memory p =
            _plan(_taker(_nat(alice, address(B), 1000, 1800, 3_000), 400), _ms(_bob(800)), 0, 0);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 400, 800, 0, 3, 0, 720);
        _hybrid(p, new ISCaaSDex.Interaction[](0));
        assertEq(B.balanceOf(alice), 797);
        assertEq(A.balanceOf(bob), 399);
    }

    // ------------------------------------------------------------------ taker and maker shapes

    function test_hybrid_takerIoc_closedAtThePull() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 2000, 3600, 3_000);
        t.flags = 1;
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker = _taker(t, 1000);
        _hybrid(p, _route(600, 1150));
        assertEq(A.pulled(_h(p.taker)), 2000);
        assertEq(A.balanceOf(alice), 900_000 - 1000);
    }

    /// Fill-or-kill (`minFill == amount`): the whole amount settles, a part reverts at the pull with the taker's hash.
    function test_hybrid_takerFok() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1200, 2160, 3_000);
        t.minFill = 1200;
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker = _taker(t, 1000);
        _expect(p, _route(600, 1150), _err(ITradeToken.BelowMinFill.selector, _h(p.taker)));
        t.amount = 1000;
        t.receiveAmount = 1800;
        t.minFill = 1000;
        p.taker = _taker(t, 1000);
        _hybrid(p, _route(600, 1150));
        assertEq(A.pulled(_h(p.taker)), 1000);
    }

    /// A Path B taker: the token pulls 1500, 1000 is matched, 500 refunded to alice; the event's `refund` shows it.
    function test_hybrid_takerPathB_refundsTheRest() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1500, 2700, 3_000);
        t.flags = 3;
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker = _taker(t, 1000);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 1000, 1880, 70, 6, 500, 1800);
        _hybrid(p, _route(600, 1150));
        assertEq(A.balanceOf(alice), 900_000 - 1000);
        assertEq(B.balanceOf(alice), 1880 - 6 + 70);
        assertEq(A.balanceOf(address(dex)), 0);
    }

    /// A Path B maker: 2000 B pulled, 800 matched, 1200 back to bob.
    function test_hybrid_makerPathB() public {
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 1_000);
        m.flags = 3;
        ISCaaSDex.HybridPlan memory p = _base();
        p.makers[0] = _natLeg(address(B), m, 800);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.LegSettled("hy", _h(p.makers[0]), bob, bob, 800, 399, 1, 1200, 0, 1);
        _hybrid(p, _route(600, 1150));
        assertEq(B.balanceOf(bob), 800_000 - 800);
        assertEq(B.balanceOf(address(dex)), 0);
    }

    /// A UA maker (shape 1, paid into its ledger, `UALegSettled`) and an outside-token maker (`DexOrder` through the
    /// puller, on the A / usdc market).
    function test_hybrid_uaMaker_and_outsideMaker() public {
        ITradeToken.UATradeOrder memory u = _ua(uaB, address(A), 2000, 1000, 1_000);
        ISCaaSDex.HybridPlan memory p = _base();
        p.makers[0] = _uaLeg(address(B), u, 800);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.UALegSettled("hy", B.uaTradeOrderDigest(u), uaB, uaB, 800, 399, 1, 0, 0, 1);
        _hybrid(p, _route(600, 1150));
        assertEq(A.balanceOfUA(uaB), 399);
        assertEq(B.balanceOfUA(uaB), 100_000 - 800);
        assertEq(B.balanceOf(alice), 1880 - 6 + 70);

        ITradeToken.TradeOrder memory d = _nat(dave, address(A), 2000, 1000, 1_000);
        p = _plan(_taker(_withNonce(_nat(alice, address(usdc), 1000, 1800, 3_000), 2), 1000),
            _ms(_natLeg(address(usdc), d, 800)), 600, 1080);
        _hybrid(p, _swap(address(A), address(usdc), 600, 1150));
        assertEq(A.balanceOf(dave), 399);
        assertEq(usdc.balanceOf(dave), 1e6 - 800);
        assertEq(usdc.balanceOf(alice), 1880 - 6 + 70);
        assertEq(dex.pulled(dex.dexOrderDigest(address(usdc), d)), 800);
        assertEq(usdc.balanceOf(address(dex)), 0);
    }

    // ------------------------------------------------------------------ whole-plan reverts, hostile routes

    /// A maker whose order is already closed reverts the whole plan with the maker's order hash; nothing moves.
    function test_hybrid_staleMaker_revertsWholePlan() public {
        ISCaaSDex.Leg memory m = _natLeg(address(B), _nat(bob, address(A), 800, 400, 0), 800);
        _hybrid(_plan(_taker(_nat(alice, address(B), 1000, 1800, 0), 1000), _ms(m), 600, 1080), _route(600, 1150));
        uint256 aliceB = B.balanceOf(alice);
        ISCaaSDex.HybridPlan memory p =
            _plan(_taker(_withNonce(_nat(alice, address(B), 1000, 1800, 0), 2), 1000), _ms(m), 600, 1080);
        _expect(p, _route(600, 1150), _err(ITradeToken.OrderClosed.selector, _h(m)));
        assertEq(B.balanceOf(alice), aliceB);
        assertEq(A.balanceOf(alice), 900_000 - 1000);
    }

    function test_hybrid_reentry_refused() public {
        Hostile h = new Hostile();
        ISCaaSDex.Interaction[] memory xs =
            _cat(_ix(address(h), abi.encodeCall(Hostile.reenter, (ISCaaSDex(address(dex))))), _route(600, 1150));
        _expect(_base(), xs, _wrapped(0, address(h),
            abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector)));
        // an executor re-entering `mtxHybrid` hits the same guard
        MockExecutor e = _executor();
        ISCaaSDex.HybridPlan memory p = _base();
        e.setCall(address(dex), abi.encodeCall(ISCaaSDex.mtxHybrid, (p, new ISCaaSDex.Interaction[](0))));
        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector));
        dex.mtxHybridVia(p, address(e), abi.encode(int256(0)));
    }

    /// A reverting target is wrapped (DX11); a gas-burning one fails the plan with empty data, wrapped.
    function test_hybrid_gasBurningTarget() public {
        Hostile h = new Hostile();
        _expect(_base(), _ix(address(h), abi.encodeCall(Hostile.boom, ())),
            _wrapped(0, address(h), abi.encodeWithSelector(Hostile.Boom.selector, 42)));
        ISCaaSDex.HybridPlan memory p = _base();
        ISCaaSDex.Interaction[] memory xs = _ix(address(h), abi.encodeCall(Hostile.burn, ()));
        vm.prank(RELAYER);
        vm.expectRevert(_wrapped(0, address(h), ""));
        dex.mtxHybrid{gas: 1_500_000}(p, xs);
    }

    /// D3 (CTR-UA-24, DX18): the submitter and the order `relayer` binding are open roles — an EIP-7702 designator
    /// submits and is the bound relayer of both orders; it gets the relayer shares.
    function test_hybrid_designatorSubmitterAndRelayer_open() public {
        address d = address(0xD7702);
        vm.etch(d, abi.encodePacked(hex"ef0100", address(0x5EE9)));
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1800, 3_000);
        ITradeToken.TradeOrder memory m = _nat(bob, address(A), 2000, 1000, 1_000);
        t.relayer = d;
        m.relayer = d;
        ISCaaSDex.HybridPlan memory p = _plan(_taker(t, 1000), _ms(_natLeg(address(B), m, 800)), 600, 1080);
        vm.prank(d);
        dex.mtxHybrid(p, _route(600, 1150));
        assertEq(B.balanceOf(alice), 1880 - 6 + 70);
        assertEq(B.balanceOf(d), 1);
        // the same through the executor entry
        t.nonce = 2;
        m.nonce = 2;
        p = _plan(_taker(t, 1000), _ms(_natLeg(address(B), m, 800)), 600, 1080);
        MockExecutor e = _executor();
        vm.prank(d);
        dex.mtxHybridVia(p, address(e), abi.encode(int256(0)));
        assertEq(A.balanceOf(bob), 2 * 399);
    }

    // ------------------------------------------------------------------ path (b): the executor

    /// The executor is handed `outsideSell` of A and told the outside floor; one unit short fails.
    function test_hybridVia_executorPaysShort_insufficientOutput() public {
        MockExecutor e = _executor();
        ISCaaSDex.HybridPlan memory p = _base();
        vm.prank(RELAYER);
        vm.expectRevert(_err(ISCaaSDex.InsufficientOutput.selector, address(B)));
        dex.mtxHybridVia(p, address(e), abi.encode(int256(-1)));
    }

    function test_hybridVia_executorPaysMore_toTaker() public {
        MockExecutor e = _executor();
        ISCaaSDex.HybridPlan memory p = _base();
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 1000, 1880, 50, 6, 0, 1800);
        vm.prank(RELAYER);
        dex.mtxHybridVia(p, address(e), abi.encode(int256(50)));
        assertEq(B.balanceOf(alice), 1880 - 6 + 50);
        assertEq(A.balanceOf(bob), 399);
        assertEq(A.balanceOf(address(e)), 600);
        (address[] memory to, uint256[] memory ao, address[] memory ti, uint256[] memory ai) = e.got();
        assertEq(to.length, 1);
        assertEq(to[0], address(A));
        assertEq(ao[0], 600);
        assertEq(ti.length, 1);
        assertEq(ti[0], address(B));
        assertEq(ai[0], 1080);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
    }

    /// The taker's `LISTED_POOLS` (or the admin's listed-only) requires a listed executor.
    function test_hybridVia_executorNotListed() public {
        MockExecutor e = _executor();
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1800, 3_000);
        t.flags = 4;
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker = _taker(t, 1000);
        vm.prank(RELAYER);
        vm.expectRevert(_err(ISCaaSDex.TargetNotListed.selector, address(e)));
        dex.mtxHybridVia(p, address(e), abi.encode(int256(0)));
        dex.setListedOnly(true);
        ISCaaSDex.HybridPlan memory q = _base();
        vm.prank(RELAYER);
        vm.expectRevert(_err(ISCaaSDex.TargetNotListed.selector, address(e)));
        dex.mtxHybridVia(q, address(e), abi.encode(int256(0)));
        dex.setExchangeTarget(address(e), true);
        vm.prank(RELAYER);
        dex.mtxHybridVia(p, address(e), abi.encode(int256(0)));
        assertEq(A.balanceOf(bob), 399);
    }
}
