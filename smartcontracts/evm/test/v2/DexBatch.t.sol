// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockRouter, Hostile} from "./DexExchange.t.sol";

/// An ERC-1271 signer that accepts every signature (cheap): only the DEX's gas check can fail it.
contract Any1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// An `approve` target that grants (`approve(x, n > 0)` returns true) but reverts the DEX's reset `approve(x, 0)` with
/// the bytes of `SigCheckGasStarved`.
contract ResetForger {
    function approve(address, uint256 v) external pure returns (bool) {
        if (v == 0) revert ISCaaSDex.SigCheckGasStarved(1, 2);
        return true;
    }
}

/// `mtxExchangeBatch` (spec §5; DX4, DX10, DX11; PD3): one self-call `exchangeOne` per path (a) plan; a failed plan
/// emits `ExchangeFailed(ref, reason ≤ 256 B)` and the others settle; the real starvation errors revert the whole call,
/// the same bytes from a target fail only its plan. Fixture: the UA DEX base (A / B SCaaS with the UA ledger on, the
/// outside `usdc` against A); a v3-style router holding A and B.
///
/// The base plan `_p(ref, nonce, out)`: alice sells 1000 A for at least 1800 B (fee 0.3 %), floor 1800; the router
/// swaps the 1000 A for `out` B (1900: settles, surplus 100; 1700: `InsufficientOutput(B)`).
contract DexBatchTest is UADexBase {
    address constant EVE = address(0xEEE);
    MockRouter router;

    function setUp() public override {
        super.setUp();
        router = new MockRouter();
        vm.prank(bob);
        B.transfer(address(router), 100_000);
        vm.prank(alice);
        A.transfer(address(router), 100_000);
    }

    // ------------------------------------------------------------------ helpers

    function _order(uint256 nonce) internal view returns (ITradeToken.TradeOrder memory o) {
        o = _nat(alice, address(B), 1000, 1800, 3_000);
        o.nonce = nonce;
    }

    /// A shape-0 exchange leg: a SCaaS token's `TradeOrder` or an outside token's `DexOrder`, ECDSA by its signer.
    function _leg(address sell, ITradeToken.TradeOrder memory o, uint256 sellFill, uint256 floor)
        internal view returns (ISCaaSDex.ExchangeLeg memory)
    {
        return ISCaaSDex.ExchangeLeg(sell, 0, abi.encode(o), _natLeg(sell, o, sellFill).sig, sellFill, floor);
    }

    function _plan(bytes32 ref, ISCaaSDex.ExchangeLeg memory l) internal pure returns (ISCaaSDex.ExchangePlan memory p) {
        p.ref = ref;
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = l;
    }

    function _ix(address target, bytes memory data) internal pure returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](1);
        xs[0] = ISCaaSDex.Interaction(target, data);
    }

    /// `approve(router, amountIn)` on `tIn`, then the router swaps `amountIn` for `amountOut` of `tOut` to the DEX.
    function _swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(tIn, abi.encodeCall(IERC20.approve, (address(router), amountIn)));
        xs[1] = ISCaaSDex.Interaction(address(router),
            abi.encodeCall(MockRouter.swap, (tIn, tOut, amountIn, amountOut, address(dex))));
    }

    /// The base plan (see the contract comment) and its route.
    function _p(bytes32 ref, uint256 nonce) internal view returns (ISCaaSDex.ExchangePlan memory) {
        return _plan(ref, _leg(address(A), _order(nonce), 1000, 1800));
    }

    function _r(uint256 out) internal view returns (ISCaaSDex.Interaction[] memory) {
        return _swap(address(A), address(B), 1000, out);
    }

    function _ps(ISCaaSDex.ExchangePlan memory a, ISCaaSDex.ExchangePlan memory b)
        internal pure returns (ISCaaSDex.ExchangePlan[] memory ps)
    {
        ps = new ISCaaSDex.ExchangePlan[](2);
        (ps[0], ps[1]) = (a, b);
    }

    function _xs(ISCaaSDex.Interaction[] memory a, ISCaaSDex.Interaction[] memory b)
        internal pure returns (ISCaaSDex.Interaction[][] memory xs)
    {
        xs = new ISCaaSDex.Interaction[][](2);
        (xs[0], xs[1]) = (a, b);
    }

    function _ps(ISCaaSDex.ExchangePlan memory a, ISCaaSDex.ExchangePlan memory b, ISCaaSDex.ExchangePlan memory c)
        internal pure returns (ISCaaSDex.ExchangePlan[] memory ps)
    {
        ps = new ISCaaSDex.ExchangePlan[](3);
        (ps[0], ps[1], ps[2]) = (a, b, c);
    }

    function _xs(ISCaaSDex.Interaction[] memory a, ISCaaSDex.Interaction[] memory b, ISCaaSDex.Interaction[] memory c)
        internal pure returns (ISCaaSDex.Interaction[][] memory xs)
    {
        xs = new ISCaaSDex.Interaction[][](3);
        (xs[0], xs[1], xs[2]) = (a, b, c);
    }

    function _batch(ISCaaSDex.ExchangePlan[] memory ps, ISCaaSDex.Interaction[][] memory xs)
        internal returns (bool[] memory)
    {
        vm.prank(RELAYER);
        return dex.mtxExchangeBatch(ps, xs);
    }

    function _wrapped(uint256 index, address target, bytes memory reason) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(ISCaaSDex.InteractionFailed.selector, index, target, reason);
    }

    /// The `ExchangeFailed` events of `logs`: their refs and reasons.
    function _failed(Vm.Log[] memory logs) internal view returns (bytes32[] memory refs, bytes[] memory reasons) {
        uint256 n;
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].emitter == address(dex) && logs[k].topics[0] == ISCaaSDex.ExchangeFailed.selector) ++n;
        }
        (refs, reasons) = (new bytes32[](n), new bytes[](n));
        n = 0;
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].emitter != address(dex) || logs[k].topics[0] != ISCaaSDex.ExchangeFailed.selector) continue;
            refs[n] = logs[k].topics[1];
            reasons[n++] = abi.decode(logs[k].data, (bytes));
        }
    }

    function _oks(bool[] memory ok) internal pure returns (bytes memory) {
        return abi.encode(ok);
    }

    function _bools(bool a, bool b, bool c) internal pure returns (bytes memory) {
        bool[] memory x = new bool[](3);
        (x[0], x[1], x[2]) = (a, b, c);
        return abi.encode(x);
    }

    function _bools(bool a, bool b) internal pure returns (bytes memory) {
        bool[] memory x = new bool[](2);
        (x[0], x[1]) = (a, b);
        return abi.encode(x);
    }

    /// The smallest call gas in [lo, hi] (step `step`) at which the batch reverts whole with `sel`; 0 if none.
    function _starvedAt(bytes memory cd, uint256 lo, uint256 hi, uint256 step, bytes4 sel) internal returns (uint256) {
        for (uint256 g = lo; g <= hi; g += step) {
            uint256 snap = vm.snapshotState();
            vm.prank(RELAYER);
            (bool done, bytes memory ret) = address(dex).call{gas: g}(cd);
            vm.revertToState(snap);
            if (!done && ret.length >= 4 && bytes4(ret) == sel) return g;
        }
        return 0;
    }

    // ------------------------------------------------------------------ per plan, not all-or-nothing

    /// Three plans, the second's route short: the first and third settle, one `ExchangeFailed(p2, …)` with the plan's
    /// own revert data, `ok = [true, false, true]`; the DEX keeps nothing.
    function test_batch_secondPlanFails_othersSettle() public {
        vm.recordLogs();
        bool[] memory ok = _batch(_ps(_p("p1", 1), _p("p2", 2), _p("p3", 3)), _xs(_r(1900), _r(1700), _r(1900)));
        assertEq(_oks(ok), _bools(true, false, true));
        (bytes32[] memory refs, bytes[] memory reasons) = _failed(vm.getRecordedLogs());
        assertEq(refs.length, 1);
        assertEq(refs[0], bytes32("p2"));
        assertEq(reasons[0], abi.encodeWithSelector(ISCaaSDex.InsufficientOutput.selector, address(B)));
        assertEq(B.balanceOf(alice), 2 * (1800 - 6 + 100));
        assertEq(A.pulled(A.tradeOrderDigest(_order(2))), 0);
        assertEq(A.pulled(A.tradeOrderDigest(_order(3))), 1000);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
    }

    function test_batch_allFail_nothingSettled() public {
        ISCaaSDex.ExchangePlan[] memory ps = _ps(_p("p1", 1), _p("p2", 2));
        ISCaaSDex.Interaction[][] memory xs = _xs(_r(1700), _r(1700));
        vm.prank(RELAYER);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxExchangeBatch(ps, xs);
        vm.prank(RELAYER);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxExchangeBatch(new ISCaaSDex.ExchangePlan[](0), new ISCaaSDex.Interaction[][](0));
    }

    function test_batch_lengthMismatch() public {
        ISCaaSDex.ExchangePlan[] memory ps = _ps(_p("p1", 1), _p("p2", 2));
        ISCaaSDex.Interaction[][] memory xs = new ISCaaSDex.Interaction[][](1);
        xs[0] = _r(1900);
        vm.prank(RELAYER);
        vm.expectRevert(ISCaaSDex.LengthMismatch.selector);
        dex.mtxExchangeBatch(ps, xs);
    }

    /// `exchangeOne` only from the DEX itself (`NotSelf`); a plan cannot reach it either: the DEX is a forbidden target.
    function test_batch_exchangeOneFromOutside_notSelf() public {
        ISCaaSDex.ExchangePlan memory p = _p("p1", 1);
        ISCaaSDex.Interaction[] memory xs = _r(1900);
        vm.prank(RELAYER);
        vm.expectRevert(ISCaaSDex.NotSelf.selector);
        dex.exchangeOne(p, xs, RELAYER);
        ISCaaSDex.Interaction[] memory into = _ix(address(dex), abi.encodeCall(dex.exchangeOne, (p, xs, RELAYER)));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeFailed("p2",
            abi.encodeWithSelector(ISCaaSDex.ForbiddenTarget.selector, address(dex)));
        assertEq(_oks(_batch(_ps(p, _p("p2", 2)), _xs(xs, into))), _bools(true, false));
    }

    /// `exchangeOne` runs `mtxExchange`'s interactions check: `restorePulled` stays refused inside a batch (DX7).
    function test_batch_restorePulledInteraction_forbidden() public {
        bytes4 restore = 0x58c18f87; // restorePulled(TradeOrder,uint256)
        ISCaaSDex.Interaction[] memory xs = _ix(address(A), abi.encodeWithSelector(restore, _order(1), 1));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeFailed("p2",
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(A), restore));
        _batch(_ps(_p("p1", 1), _p("p2", 2)), _xs(_r(1900), xs));
    }

    /// The order's `relayer` binding and the fee share follow the batch's caller (`submitter`), not the self-call's
    /// `msg.sender` (the DEX): bound to RELAYER, EVE's batch fails that plan; EVE gets the other plan's share (1 of 6).
    function test_batch_relayerBindingAndFeeShare_followTheCaller() public {
        ITradeToken.TradeOrder memory o = _order(1);
        o.relayer = RELAYER;
        ISCaaSDex.ExchangePlan memory bound = _plan("p1", _leg(address(A), o, 1000, 1800));
        ISCaaSDex.ExchangePlan[] memory ps = _ps(bound, _p("p2", 2));
        ISCaaSDex.Interaction[][] memory xs = _xs(_r(1900), _r(1900));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeFailed("p1", abi.encodeWithSelector(ISCaaSDex.WrongRelayer.selector, EVE));
        vm.prank(EVE);
        bool[] memory ok = dex.mtxExchangeBatch(ps, xs);
        assertEq(_oks(ok), _bools(false, true));
        assertEq(B.balanceOf(EVE), 1);
        assertEq(B.balanceOf(TREASURY), 5);
        assertEq(B.balanceOf(address(dex)), 0);
        ISCaaSDex.ExchangePlan[] memory one = new ISCaaSDex.ExchangePlan[](1);
        one[0] = bound;
        ISCaaSDex.Interaction[][] memory x1 = new ISCaaSDex.Interaction[][](1);
        x1[0] = _r(1900);
        assertTrue(_batch(one, x1)[0]);
        assertEq(B.balanceOf(RELAYER), 1);
    }

    /// A later plan sees what earlier ones left: alice's one order of 2000 A filled 1000 by each of the first two plans
    /// (`pulled` 2000), the third fails on the token's own fill accounting (`OrderClosed`).
    function test_batch_laterPlanSeesEarlierPulled() public {
        ITradeToken.TradeOrder memory o = _nat(alice, address(B), 2000, 3600, 3_000);
        ISCaaSDex.ExchangeLeg memory l = _leg(address(A), o, 1000, 1800);
        bytes32 h = A.tradeOrderDigest(o);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeFailed("p3", abi.encodeWithSelector(ITradeToken.OrderClosed.selector, h));
        bool[] memory ok = _batch(_ps(_plan("p1", l), _plan("p2", l), _plan("p3", l)), _xs(_r(1900), _r(1900), _r(1900)));
        assertEq(_oks(ok), _bools(true, true, false));
        assertEq(A.pulled(h), 2000);
        assertEq(A.balanceOf(address(dex)), 0);
    }

    // ------------------------------------------------------------------ starvation and hostile targets (DX11)

    /// A real `SigCheckGasStarved` (an outside leg's ERC-1271 check, cap 50 k, starved by the submitter's gas) reverts
    /// the whole batch even though the first plan settled; with the gas the same batch settles both.
    function test_batch_realSigCheckGasStarved_revertsWhole() public {
        address w = address(new Any1271());
        usdc.mint(w, 10_000);
        address pl = dex.puller();
        vm.prank(w);
        usdc.approve(pl, type(uint256).max);
        ISCaaSDex.ExchangeLeg memory l =
            ISCaaSDex.ExchangeLeg(address(usdc), 0, abi.encode(_nat(w, address(A), 1000, 400, 0)), hex"00", 1000, 400);
        ISCaaSDex.ExchangePlan[] memory ps = _ps(_p("p1", 1), _plan("p2", l));
        ISCaaSDex.Interaction[][] memory xs = _xs(_r(1900), _swap(address(usdc), address(A), 1000, 450));
        bytes memory cd = abi.encodeCall(dex.mtxExchangeBatch, (ps, xs));
        assertTrue(_starvedAt(cd, 200_000, 1_500_000, 2_000, ISCaaSDex.SigCheckGasStarved.selector) != 0,
            "a call gas starves the outside leg's check and reverts the whole batch");
        assertEq(_oks(_batch(ps, xs)), _bools(true, true));
        assertEq(A.balanceOf(w), 450);
    }

    /// A real `UAVerifyGas` (a p256 UA leg, verify cap 400 k) reverts the whole batch; with the gas both settle.
    function test_batch_realUAVerifyGas_revertsWhole() public {
        ITradeToken.UATradeOrder memory u = _ua(uaP, address(B), 1000, 1800, 0);
        ISCaaSDex.ExchangeLeg memory l =
            ISCaaSDex.ExchangeLeg(address(A), 1, abi.encode(u), _uaLeg(address(A), u, 1000).sig, 1000, 1800);
        ISCaaSDex.ExchangePlan[] memory ps = _ps(_p("p1", 1), _plan("p2", l));
        ISCaaSDex.Interaction[][] memory xs = _xs(_r(1900), _r(1900));
        bytes memory cd = abi.encodeCall(dex.mtxExchangeBatch, (ps, xs));
        assertTrue(_starvedAt(cd, 300_000, 2_000_000, 5_000, UAKinds.UAVerifyGas.selector) != 0,
            "a call gas starves the UA verify and reverts the whole batch");
        assertEq(_oks(_batch(ps, xs)), _bools(true, true));
        assertEq(B.balanceOfUA(uaP), 1900);
    }

    /// A target reverting with the bytes of `SigCheckGasStarved` fails only its plan: the outer selector is
    /// `InteractionFailed`, the forged bytes only its `reason`.
    function test_batch_forgedStarvationFromTarget_onlyThatPlan() public {
        Hostile h = new Hostile();
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeFailed("p2",
            _wrapped(0, address(h), abi.encodeWithSelector(ISCaaSDex.SigCheckGasStarved.selector, 1, 2)));
        bool[] memory ok =
            _batch(_ps(_p("p1", 1), _p("p2", 2)), _xs(_r(1900), _ix(address(h), abi.encodeCall(Hostile.forge, ()))));
        assertEq(_oks(ok), _bools(true, false));
    }

    /// The allowance reset after the route is a capped token call that drops the target's revert data (W-O): a target
    /// that reverts `approve(x, 0)` with the bytes of `SigCheckGasStarved` fails only its plan, with
    /// `SafeERC20FailedOperation(target)`; the first plan settles.
    function test_batch_resetForgesStarvation_onlyThatPlan() public {
        ResetForger f = new ResetForger();
        ISCaaSDex.Interaction[] memory r = _r(1900);
        ISCaaSDex.Interaction[] memory x2 = new ISCaaSDex.Interaction[](3);
        (x2[0], x2[1]) = (r[0], r[1]);
        x2[2] = ISCaaSDex.Interaction(address(f), abi.encodeCall(IERC20.approve, (address(1), 1)));
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeFailed("p2",
            abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(f)));
        bool[] memory ok = _batch(_ps(_p("p1", 1), _p("p2", 2)), _xs(_r(1900), x2));
        assertEq(_oks(ok), _bools(true, false));
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
    }

    /// A target reverting with 1 MB: its plan fails with a bounded reason (256 bytes of `InteractionFailed(…)`), the
    /// next plan settles.
    function test_batch_returnbombTarget_onlyThatPlan() public {
        Hostile h = new Hostile();
        vm.recordLogs();
        bool[] memory ok =
            _batch(_ps(_p("p1", 1), _p("p2", 2)), _xs(_ix(address(h), abi.encodeCall(Hostile.bomb, ())), _r(1900)));
        assertEq(_oks(ok), _bools(false, true));
        (bytes32[] memory refs, bytes[] memory reasons) = _failed(vm.getRecordedLogs());
        assertEq(refs.length, 1);
        assertEq(refs[0], bytes32("p1"));
        assertEq(reasons[0].length, 256);
        assertEq(bytes4(reasons[0]), ISCaaSDex.InteractionFailed.selector);
    }

    /// A gas-burning target exhausts its own plan (63/64 of the gas): it fails `InteractionFailed(0, target, "")` and
    /// the plan after it runs out of gas, `ExchangeFailed(p3, "")` (the node's `out_of_gas`); the first plan settled.
    /// The third plan is a CoW with no interaction (alice's 1000 A against bob's 2000 B), so its out-of-gas is in the
    /// DEX or a token call, never wrapped. Scanned over the call gas: the window moves with the gas schedule.
    function test_batch_gasBurningTarget_laterPlansFailEmpty() public {
        Hostile h = new Hostile();
        ISCaaSDex.ExchangePlan memory cow = _p("p3", 3);
        ISCaaSDex.ExchangeLeg[] memory legs = new ISCaaSDex.ExchangeLeg[](2);
        legs[0] = cow.legs[0];
        legs[1] = _leg(address(B), _nat(bob, address(A), 2000, 1000, 1_000), 2000, 1000);
        cow.legs = legs;
        ISCaaSDex.ExchangePlan[] memory ps = _ps(_p("p1", 1), _p("p2", 2), cow);
        ISCaaSDex.Interaction[][] memory xs =
            _xs(_r(1900), _ix(address(h), abi.encodeCall(Hostile.burn, ())), new ISCaaSDex.Interaction[](0));
        bytes memory cd = abi.encodeCall(dex.mtxExchangeBatch, (ps, xs));
        for (uint256 g = 2_000_000; g <= 30_000_000; g += 50_000) if (_burnedAt(cd, g, address(h))) return;
        revert("no call gas left the third plan out of gas while the batch returned");
    }

    /// At call gas `g`: false if the batch reverted or the third plan settled; else checks the outcome and returns true.
    function _burnedAt(bytes memory cd, uint256 g, address h) internal returns (bool) {
        uint256 snap = vm.snapshotState();
        vm.recordLogs();
        vm.prank(RELAYER);
        (bool done, bytes memory ret) = address(dex).call{gas: g}(cd);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        vm.revertToState(snap);
        if (!done || abi.decode(ret, (bool[]))[2]) return false;
        assertEq(ret, _bools(true, false, false));
        (bytes32[] memory refs, bytes[] memory reasons) = _failed(logs);
        assertEq(refs.length, 2);
        assertEq(refs[0], bytes32("p2"));
        assertEq(reasons[0], _wrapped(0, h, ""));
        assertEq(refs[1], bytes32("p3"));
        assertEq(reasons[1], "");
        return true;
    }
}
