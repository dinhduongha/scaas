// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockRouter, MockExecutor, Hostile} from "./DexExchange.t.sol";
import {FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {HybridHarness} from "../helpers/HybridHarness.sol";
import {plainEnv} from "../helpers/Catalogue.sol";

/// A stand-in `o.dex` for `restorePulled` (DX7): pulls an order through the token's `mtxTrade` / `uaTrade` and gives
/// part of it back, in one call or in separate ones (each top-level call of a test is its own transaction).
contract PullRestorer {
    function pull(ITradeToken t, ITradeToken.TradeOrder calldata o, bytes calldata sig, uint256 fill, uint256 recv)
        public
    {
        t.mtxTrade(o, sig, ITradeToken.TradeFill(fill, recv, 0, msg.sender));
    }

    function restore(ITradeToken t, ITradeToken.TradeOrder calldata o, uint256 amount) public {
        t.restorePulled(o, amount);
    }

    function pullThenRestore(ITradeToken t, ITradeToken.TradeOrder calldata o, bytes calldata sig, uint256 fill,
        uint256 recv, uint256 amount) external
    {
        pull(t, o, sig, fill, recv);
        restore(t, o, amount);
    }

    /// The signer's cancel lands between the pull and the restore (anyone may submit a cancel).
    function pullCancelRestore(ITradeToken t, ITradeToken.TradeOrder calldata o, bytes calldata sig, uint256 fill,
        uint256 recv, bytes calldata cancelSig, uint256 amount) external
    {
        pull(t, o, sig, fill, recv);
        t.mtxCancelOrder(o, cancelSig);
        restore(t, o, amount);
    }

    function uaPullThenRestore(ITradeToken t, ITradeToken.UATradeOrder calldata o, bytes calldata auth, uint256 fill,
        uint256 recv, uint256 amount) external
    {
        t.uaTrade(o, auth, ITradeToken.TradeFill(fill, recv, 0, msg.sender));
        t.restorePulled(o, amount);
    }
}

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

    // ------------------------------------------------------------------ the taker's leftover (DX7, spec §4.2 step 5)

    address constant EVE = address(0xEEE);
    /// `restorePulled(TradeOrder,uint256)` and `restorePulled(UATradeOrder,uint256)`.
    bytes4 constant RESTORE = bytes4(keccak256("restorePulled((address,address,uint256,uint256,uint256,uint256,address,"
        "address,address,uint8,uint256,uint256,uint256),uint256)"));
    bytes4 constant UA_RESTORE = bytes4(keccak256("restorePulled((bytes32,address,uint256,uint256,uint256,uint256,"
        "address,address,bytes32,uint8,uint256,uint256,uint256),uint256)"));

    /// The refund plan: alice (1000 A for at least 1800 B, fee 0.3 %, `minFill` as given) fills 500: 400 A to bob for
    /// 800 B, 100 A outside for at least 180 B. Floor 980 B, fee ⌈2.94⌉ = 3. `_route(60, 200)` spends 60 of the 100:
    /// leftover 40, sold 460, surplus 20, `limitReceive` ⌈460 · 1800 / 1000⌉ = 828.
    function _refundPlan(uint256 minFill) internal view returns (ISCaaSDex.HybridPlan memory) {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1800, 3_000);
        t.minFill = minFill;
        return _plan(_taker(t, 500), _ms(_bob(800)), 100, 180);
    }

    /// A shape-0 `DexOrder` leg of an outside token (signed in the DEX's domain).
    function _dexLeg(address sell, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (ISCaaSDex.Leg memory)
    {
        return ISCaaSDex.Leg(sell, 0, abi.encode(o), _ecdsa(_pk(o.from), dex.dexOrderDigest(sell, o)), fill);
    }

    function test_hybrid_refund_soldAboveMinFill_settlesAndRefunds() public {
        ISCaaSDex.HybridPlan memory p = _refundPlan(400);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.LegSettled("hy", _h(p.makers[0]), bob, bob, 800, 399, 1, 0, 0, 1);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 460, 980, 20, 3, 40, 828);
        _hybrid(p, _route(60, 200));
        assertEq(A.balanceOf(alice), 900_000 - 460);
        assertEq(B.balanceOf(alice), 980 - 3 + 20);
        assertEq(A.balanceOf(address(router)), 60);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
    }

    /// The fee is on the floor only: with a refund, the same fee and shares as the same floor without one; no A fee
    /// beyond the maker's.
    function test_hybrid_refund_noFeeOnRefund() public {
        _hybrid(_refundPlan(0), _route(60, 200)); // 40 refunded
        assertEq(B.balanceOf(TREASURY), 3);
        assertEq(B.balanceOf(RELAYER), 0);
        assertEq(A.balanceOf(TREASURY), 1);
        assertEq(A.balanceOf(RELAYER), 0);
        ISCaaSDex.HybridPlan memory p = _refundPlan(0);
        p.taker = _taker(_withNonce(_nat(alice, address(B), 1000, 1800, 3_000), 2), 500);
        _hybrid(p, _route(100, 200)); // the same floor, nothing refunded
        assertEq(B.balanceOf(TREASURY), 2 * 3);
        assertEq(B.balanceOf(RELAYER), 0);
        assertEq(A.balanceOf(TREASURY), 2 * 1);
        assertEq(A.balanceOf(alice), 900_000 - 460 - 500);
    }

    /// The leftover goes to the taker only: the maker gets exactly its price (400 A = 399 + the fee 1).
    function test_hybrid_refund_makersNeverGetTheRemainder() public {
        _hybrid(_refundPlan(0), _route(60, 200));
        assertEq(A.balanceOf(bob), 399);
        assertEq(A.balanceOf(TREASURY) + A.balanceOf(RELAYER), 1);
        assertEq(B.balanceOf(bob), 800_000 - 800);
        assertEq(A.balanceOf(alice), 900_000 - 460);
    }

    /// Sold 460 below `minFill` 461 reverts the whole plan with the taker's hash (the fill 500 passed at the pull);
    /// `minFill` 460 settles.
    function test_hybrid_refund_soldBelowMinFill_reverts() public {
        ISCaaSDex.HybridPlan memory p = _refundPlan(461);
        _expect(p, _route(60, 200), _err(ISCaaSDex.BelowMinFill.selector, _h(p.taker)));
        _hybrid(_refundPlan(460), _route(60, 200));
        assertEq(A.balanceOf(alice), 900_000 - 460);
    }

    /// Fill-or-kill (`minFill == amount == fill`): any leftover makes the sold part fall below it.
    function test_hybrid_refund_fokTaker_reverts() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 500, 900, 3_000);
        t.minFill = 500;
        ISCaaSDex.HybridPlan memory p = _plan(_taker(t, 500), _ms(_bob(800)), 100, 180);
        _expect(p, _route(99, 200), _err(ISCaaSDex.BelowMinFill.selector, _h(p.taker)));
        _hybrid(p, _route(100, 200));
        assertEq(A.pulled(_h(p.taker)), 500);
    }

    /// No makers, the route spends nothing: the sold part is 0.
    function test_hybrid_refund_soldZero_zeroFill() public {
        ISCaaSDex.HybridPlan memory p =
            _plan(_taker(_nat(alice, address(B), 1000, 1800, 3_000), 100), new ISCaaSDex.Leg[](0), 100, 180);
        _expect(p, _route(0, 200), _err(ISCaaSDex.ZeroFill.selector, _h(p.taker)));
    }

    /// PD5: the price check on the sold part cannot be reached through the entry (the token checked the larger fill
    /// against the same floor); the harness runs `_takerSoldCheck` itself: 900 sold for a floor of 1600 is below the
    /// limit 1800 per 1000 (900 · 1800 > 1600 · 1000); 1620 is exactly at it.
    function test_hybrid_refund_worsePrice_priceLimit() public {
        HybridHarness hh = new HybridHarness(plainEnv(address(f), address(0), chainUidA, address(0), false));
        ITradeToken.UATradeOrder memory o = _ua(uaP, address(B), 1000, 1800, 0);
        o.minFill = 900;
        bytes32 h = keccak256("taker");
        vm.expectRevert(_err(ISCaaSDex.PriceLimit.selector, h));
        hh.takerSoldCheck(h, 1000, 1600, o, 100);
        hh.takerSoldCheck(h, 1000, 1620, o, 100);
        vm.expectRevert(_err(ISCaaSDex.BelowMinFill.selector, h));
        hh.takerSoldCheck(h, 1000, 1620, o, 101);
        o.minFill = 0;
        vm.expectRevert(_err(ISCaaSDex.ZeroFill.selector, h));
        hh.takerSoldCheck(h, 1000, 1620, o, 1000);
    }

    /// The route hands back more A than it was given (141 > 100): `ConservationBroken(A)`; exactly `outsideSell` back
    /// is a refund of all of it (sold = the makers' 400).
    function test_hybrid_refund_leftoverAboveOutsideSell_conservationBroken() public {
        vm.prank(alice);
        A.transfer(address(router), 1000);
        ISCaaSDex.Interaction[] memory xs = _cat(_route(60, 200), _ix(address(router),
            abi.encodeCall(MockRouter.swap, (address(usdc), address(A), 0, 101, address(dex)))));
        _expect(_refundPlan(0), xs, _err(ISCaaSDex.ConservationBroken.selector, address(A)));
        xs[2].data = abi.encodeCall(MockRouter.swap, (address(usdc), address(A), 0, 60, address(dex)));
        ISCaaSDex.HybridPlan memory p = _refundPlan(0);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 400, 980, 20, 3, 100, 720);
        _hybrid(p, xs);
        assertEq(A.pulled(_h(p.taker)), 400);
    }

    /// A Path B taker (`ESCROW | IOC`): the refund is the leftover plus the unmatched remainder; IOC: nothing restored.
    function test_hybrid_refund_pathBTaker_refundIsLeftoverPlusRemainder() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1500, 2700, 3_000);
        t.flags = 3;
        ISCaaSDex.HybridPlan memory p = _plan(_taker(t, 500), _ms(_bob(800)), 100, 180);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 460, 980, 20, 3, 1040, 828);
        _hybrid(p, _route(60, 200));
        assertEq(A.balanceOf(alice), 900_000 - 460);
        assertEq(A.pulled(_h(p.taker)), 1500);
        assertEq(A.balanceOf(address(dex)), 0);
    }

    /// An IOC taker on Path A is refunded too and stays closed (no `restorePulled`).
    function test_hybrid_refund_iocTaker_staysClosed() public {
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1800, 3_000);
        t.flags = 1;
        ISCaaSDex.HybridPlan memory p = _plan(_taker(t, 500), _ms(_bob(800)), 100, 180);
        _hybrid(p, _route(60, 200));
        assertEq(A.balanceOf(alice), 900_000 - 460);
        assertEq(A.pulled(_h(p.taker)), 1000);
    }

    /// Path (b): the executor sends 40 of its 100 A back to the DEX and pays the floor plus 20.
    function test_hybrid_refund_viaExecutor() public {
        MockExecutor e = _executor();
        e.setCall(address(A), abi.encodeCall(IERC20.transfer, (address(dex), 40)));
        ISCaaSDex.HybridPlan memory p = _refundPlan(400);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", _h(p.taker), alice, alice, 460, 980, 20, 3, 40, 828);
        vm.prank(RELAYER);
        dex.mtxHybridVia(p, address(e), abi.encode(int256(20)));
        assertEq(A.balanceOf(alice), 900_000 - 460);
        assertEq(A.balanceOf(address(e)), 60);
        assertEq(A.balanceOf(address(dex)), 0);
    }

    /// The token's `TradeFilled` shows the pulled fill 500; after the refund `pulled[h]` counts what the taker kept
    /// sold (460): the refunded 40 is restored (DX7, owner follow-up 2026-10-30).
    function test_hybrid_refund_gtcTakerPulledKeepsTheFill() public {
        ISCaaSDex.HybridPlan memory p = _refundPlan(0);
        bytes32 h = _h(p.taker);
        vm.expectEmit(address(A));
        emit ITradeToken.TradeFilled(h, alice, 500, 980, 3);
        vm.expectEmit(address(A));
        emit ITradeToken.PullRestored(h, 40);
        _hybrid(p, _route(60, 200));
        assertEq(A.pulled(h), 460);
    }

    /// The restored 40 is fillable again: a later 540 closes the order (without the restore it would `Overfill`).
    function test_hybrid_refund_restoresCapacity_gtcRefillsLater() public {
        ISCaaSDex.HybridPlan memory p = _refundPlan(0);
        bytes32 h = _h(p.taker);
        _hybrid(p, _route(60, 200));
        assertEq(A.pulled(h), 460);
        ISCaaSDex.HybridPlan memory q = _plan(_taker(_nat(alice, address(B), 1000, 1800, 3_000), 540),
            new ISCaaSDex.Leg[](0), 540, 972);
        _hybrid(q, _route(540, 1000));
        assertEq(A.pulled(h), 1000);
        assertEq(A.balanceOf(alice), 900_000 - 1000);
    }

    /// An outside-token taker (usdc through the puller): the DEX restores its own `pulled` and emits `PullRestored`.
    function test_hybrid_refund_outsideTaker_restoredOnTheDex() public {
        vm.prank(alice);
        A.transfer(address(router), 1000);
        ITradeToken.TradeOrder memory o = _nat(dave, address(A), 1000, 400, 0);
        bytes32 h = dex.dexOrderDigest(address(usdc), o);
        ISCaaSDex.HybridPlan memory p = _plan(_dexLeg(address(usdc), o, 100), new ISCaaSDex.Leg[](0), 100, 40);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.PullRestored(h, 40);
        _hybrid(p, _swap(address(usdc), address(A), 60, 50));
        assertEq(dex.pulled(h), 60);
        assertEq(usdc.balanceOf(dave), 1e6 - 60);
        assertEq(A.balanceOf(dave), 50);
        assertEq(usdc.balanceOf(address(dex)), 0);
    }

    // ------------------------------------------------------------------ restorePulled (DX7, owner 2026-10-30)

    function _restorer() internal returns (PullRestorer r, ITradeToken.TradeOrder memory o, bytes memory sig) {
        r = new PullRestorer();
        o = _nat(alice, address(B), 1000, 1800, 0);
        o.dex = address(r);
        sig = _ecdsa(ALICE_PK, A.tradeOrderDigest(o));
    }

    function test_restorePulled_onlyOrderDex() public {
        (PullRestorer r, ITradeToken.TradeOrder memory o,) = _restorer();
        vm.prank(EVE);
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, EVE));
        A.restorePulled(o, 0);
        // another DEX (the real one, not `o.dex`) cannot either
        vm.prank(address(dex));
        vm.expectRevert(abi.encodeWithSelector(ITradeToken.NotDex.selector, address(dex)));
        A.restorePulled(o, 0);
        r.restore(A, o, 0); // `o.dex` itself, nothing pulled: a zero restore is the only one allowed
    }

    function test_restorePulled_boundedByThisTxPull() public {
        (PullRestorer r, ITradeToken.TradeOrder memory o, bytes memory sig) = _restorer();
        bytes32 h = A.tradeOrderDigest(o);
        vm.expectRevert(_err(ITradeToken.RestoreExceedsPull.selector, h));
        r.pullThenRestore(A, o, sig, 500, 900, 501);
        vm.expectEmit(address(A));
        emit ITradeToken.PullRestored(h, 500);
        r.pullThenRestore(A, o, sig, 500, 900, 500);
        assertEq(A.pulled(h), 0);
        assertEq(A.balanceOf(address(r)), 500); // the restore moves no funds: the DEX refunds them itself
        // an IOC order stays closed
        o.flags = 1;
        sig = _ecdsa(ALICE_PK, A.tradeOrderDigest(o));
        vm.expectRevert(_err(ITradeToken.OrderClosed.selector, A.tradeOrderDigest(o)));
        r.pullThenRestore(A, o, sig, 500, 900, 1);
    }

    /// Each top-level call of a test is its own transaction (`isolate`): the counter does not carry over; a cancel in
    /// the same transaction clears it.
    function test_restorePulled_noCarryAcrossTx() public {
        (PullRestorer r, ITradeToken.TradeOrder memory o, bytes memory sig) = _restorer();
        bytes32 h = A.tradeOrderDigest(o);
        r.pull(A, o, sig, 500, 900);
        vm.expectRevert(_err(ITradeToken.RestoreExceedsPull.selector, h));
        r.restore(A, o, 1);
        assertEq(A.pulled(h), 500);
        bytes memory cancelSig = _ecdsa(ALICE_PK, A.cancelOrderDigest(h));
        vm.expectRevert(_err(ITradeToken.RestoreExceedsPull.selector, h));
        r.pullCancelRestore(A, o, sig, 100, 180, cancelSig, 1);
    }

    /// A UA taker (shape 1) through the DEX: refunded into its ledger, its `pulled` restored; and the `UATradeOrder`
    /// overload is bounded the same way.
    function test_restorePulled_uaOrder() public {
        ITradeToken.UATradeOrder memory u = _ua(uaP, address(B), 1000, 1800, 3_000);
        ISCaaSDex.HybridPlan memory p = _plan(_uaLeg(address(A), u, 500), _ms(_bob(800)), 100, 180);
        bytes32 h = A.uaTradeOrderDigest(u);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.UAExchangeLegSettled("hy", h, uaP, uaP, 460, 980, 20, 3, 40, 828);
        vm.expectEmit(address(A));
        emit ITradeToken.PullRestored(h, 40); // right after the refund
        _hybrid(p, _route(60, 200));
        assertEq(A.pulled(h), 460);
        assertEq(A.balanceOfUA(uaP), 100_000 - 460);
        assertEq(B.balanceOfUA(uaP), 980 - 3 + 20);

        PullRestorer r = new PullRestorer();
        ITradeToken.UATradeOrder memory v = _ua(uaP, address(B), 1000, 1800, 0);
        v.dex = address(r);
        bytes memory auth = _uaLeg(address(A), v, 0).sig;
        bytes32 hv = A.uaTradeOrderDigest(v);
        vm.expectRevert(_err(ITradeToken.RestoreExceedsPull.selector, hv));
        r.uaPullThenRestore(A, v, auth, 500, 900, 501);
        r.uaPullThenRestore(A, v, auth, 500, 900, 200);
        assertEq(A.pulled(hv), 300);
    }

    /// T4-sec: interactions run as the DEX, the orders' `dex`: `restorePulled` (both overloads) is refused, else a
    /// submitter could lower a pulled order's `pulled` in the same transaction and over-sell it.
    function test_hybrid_forbiddenSelector_restorePulled() public {
        ISCaaSDex.HybridPlan memory p = _base();
        bytes memory nat = abi.encodeWithSelector(RESTORE, abi.decode(p.makers[0].order, (ITradeToken.TradeOrder)), 800);
        _expect(p, _cat(_route(600, 1150), _ix(address(B), nat)),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(B), RESTORE));
        ITradeToken.UATradeOrder memory u = _ua(uaP, address(B), 1000, 1800, 3_000);
        p.taker = _uaLeg(address(A), u, 1000);
        bytes memory ua = abi.encodeWithSelector(UA_RESTORE, u, 1000);
        _expect(p, _cat(_route(600, 1150), _ix(address(A), ua)),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(A), UA_RESTORE));
        assertEq(RESTORE, bytes4(0x58c18f87));
        assertEq(UA_RESTORE, bytes4(0x8c4a5df6));
    }

    // ------------------------------------------------------------------ T3 review: m1-m4

    /// m3: the route spends more A than `outsideSell` (all 1000): A below its expected balance.
    function test_hybrid_routeOverspendsA_conservationBroken() public {
        _expect(_base(), _swap(address(A), address(B), 1000, 2000),
            _err(ISCaaSDex.ConservationBroken.selector, address(A)));
    }

    /// m3: an interaction moves the makers' A out of the DEX.
    function test_hybrid_interactionMovesAOut_conservationBroken() public {
        ISCaaSDex.Interaction[] memory xs =
            _cat(_route(600, 1150), _ix(address(A), abi.encodeCall(IERC20.transfer, (EVE, 400))));
        _expect(_base(), xs, _err(ISCaaSDex.ConservationBroken.selector, address(A)));
    }

    /// m3: the taker's limit holds on the floor: `outsideFloor` one below it (1799 < 1800) is refused at the pull.
    function test_hybrid_floorBelowTakerLimit_priceLimit() public {
        ISCaaSDex.HybridPlan memory p = _base();
        p.outsideFloor = 999;
        _expect(p, _route(600, 1150), _err(ITradeToken.PriceLimit.selector, _h(p.taker)));
    }

    /// m1: a hop A → usdc → B with usdc in `extraTokens`: a usdc leftover breaks conservation; the clean hop settles.
    function test_hybrid_extraTokensHop() public {
        ISCaaSDex.HybridPlan memory p = _base();
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(usdc);
        _expect(p, _cat(_swap(address(A), address(usdc), 600, 700), _swap(address(usdc), address(B), 699, 1150)),
            _err(ISCaaSDex.ConservationBroken.selector, address(usdc)));
        _hybrid(p, _cat(_swap(address(A), address(usdc), 600, 700), _swap(address(usdc), address(B), 700, 1150)));
        assertEq(B.balanceOf(alice), 1880 - 6 + 70);
        assertEq(usdc.balanceOf(address(dex)), 0);
    }

    /// m2: a UA taker (shape 1) sells A from uaP and receives the floor less its fee plus the surplus into its ledger.
    function test_hybrid_uaTaker() public {
        ITradeToken.UATradeOrder memory u = _ua(uaP, address(B), 1000, 1800, 3_000);
        ISCaaSDex.HybridPlan memory p = _base();
        p.taker = _uaLeg(address(A), u, 1000);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.UAExchangeLegSettled("hy", A.uaTradeOrderDigest(u), uaP, uaP, 1000, 1880, 70, 6, 0, 1800);
        _hybrid(p, _route(600, 1150));
        assertEq(B.balanceOfUA(uaP), 1880 - 6 + 70);
        assertEq(A.balanceOfUA(uaP), 100_000 - 1000);
        assertEq(A.balanceOf(bob), 399);
    }

    /// m4: a fee-on-transfer sell token, the taker's or a maker's (outside, through the puller): the DEX receives 1 %
    /// less than it pulled, `ConservationBroken(token)` at the pull check.
    function test_hybrid_feeOnTransferSellToken_conservationBroken() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        fot.mint(dave, 1e6);
        fot.mint(address(router), 1e6);
        address puller = dex.puller();
        vm.prank(dave);
        fot.approve(puller, type(uint256).max);
        dex.setMarket(address(A), address(fot), true);
        vm.prank(alice);
        A.transfer(address(router), 1000);
        // the taker sells it
        ISCaaSDex.HybridPlan memory p = _plan(_dexLeg(address(fot), _nat(dave, address(A), 1000, 400, 0), 500),
            new ISCaaSDex.Leg[](0), 500, 200);
        _expect(p, _swap(address(fot), address(A), 495, 250), _err(ISCaaSDex.ConservationBroken.selector, address(fot)));
        // a maker sells it
        p = _plan(_taker(_nat(alice, address(fot), 1000, 1800, 0), 1000),
            _ms(_dexLeg(address(fot), _nat(dave, address(A), 2000, 1000, 0), 800)), 600, 1080);
        _expect(p, _swap(address(A), address(fot), 600, 1150), _err(ISCaaSDex.ConservationBroken.selector, address(fot)));
    }
}
