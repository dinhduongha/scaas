// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockRouter} from "./DexExchange.t.sol";

/// Gas figures of the DEX entries (spec §13), measured on the UA DEX base with a v3-style mock router (the hop costs
/// what an `approve` and a `transferFrom` / `transfer` pair cost, no real pool). `isolate = true` runs each top-level
/// call as its own transaction, so the figure is `vm.lastCallGas()`: the transaction's REGULAR gas (intrinsic and
/// calldata floor included, as the spec's `mtxSettle` figure); the EIP-8037 state gas is logged apart. Each test logs
/// its figure; the assertions are upper bounds, 1.5 × the spec's estimate.
contract DexGasTest is UADexBase {
    MockRouter router;

    function setUp() public override {
        super.setUp();
        router = new MockRouter();
        vm.prank(bob);
        B.transfer(address(router), 100_000);
        vm.prank(alice);
        A.transfer(address(router), 100_000);
    }

    function _order(address from, address recv, uint256 amount, uint256 recvAmount, uint256 nonce)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o = _nat(from, recv, amount, recvAmount, 3_000);
        o.nonce = nonce;
    }

    /// `approve(router, amountIn)` on A, then the router swaps `amountIn` A for `amountOut` B to the DEX.
    function _route(uint256 amountIn, uint256 amountOut) internal view returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(address(A), abi.encodeCall(IERC20.approve, (address(router), amountIn)));
        xs[1] = ISCaaSDex.Interaction(address(router),
            abi.encodeCall(MockRouter.swap, (address(A), address(B), amountIn, amountOut, address(dex))));
    }

    /// Alice sells 1000 A for >= 1800 B; `n` makers (bob, 2000 B for 1000 A each, fills 800 / n B); the other 600 A go
    /// to the router for >= 1080 B (floor 800 + 1080 = 1880 B), which returns 1150.
    function _hybridPlan(uint256 n) internal view returns (ISCaaSDex.HybridPlan memory p) {
        p.ref = "gas";
        p.taker = _natLeg(address(A), _order(alice, address(B), 1000, 1800, 1), 1000);
        p.makers = new ISCaaSDex.Leg[](n);
        for (uint256 i; i < n; ++i) {
            p.makers[i] = _natLeg(address(B), _order(bob, address(A), 2000, 1000, i + 1), 800 / n);
        }
        p.outsideSell = 600;
        p.outsideFloor = 1080;
    }

    /// The last top-level call's regular gas (state gas logged).
    function _last(string memory what) internal returns (uint256 g) {
        Vm.Gas memory v = vm.lastCallGas();
        g = v.gasTotalUsed;
        emit log_named_uint(string.concat("GAS ", what, " (regular)"), g);
        emit log_named_uint(string.concat("GAS ", what, " (state)"), uint256(int256(v.gasStateUsed)));
    }

    function _hybridGas(uint256 n) internal returns (uint256 g) {
        ISCaaSDex.HybridPlan memory p = _hybridPlan(n);
        ISCaaSDex.Interaction[] memory xs = _route(600, 1150);
        vm.prank(RELAYER);
        dex.mtxHybrid(p, xs);
        g = _last(n == 1 ? "mtxHybrid 1x1 one hop" : "mtxHybrid 1x2 one hop");
    }

    /// Alice sells 1000 A for >= 1800 B, the router returns 1900.
    function _exchangePlan(bytes32 ref, uint256 nonce) internal view returns (ISCaaSDex.ExchangePlan memory p) {
        ITradeToken.TradeOrder memory o = _order(alice, address(B), 1000, 1800, nonce);
        p.ref = ref;
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = ISCaaSDex.ExchangeLeg(address(A), 0, abi.encode(o), _natLeg(address(A), o, 1000).sig, 1000, 1800);
    }

    /// Bound 1.5 x 0.60 M (one taker, one maker, one hop).
    function test_GAS_hybrid_1x1_oneHop() public {
        uint256 g = _hybridGas(1);
        assertLt(g, 900_000);
    }

    /// Bound 1.5 x (0.60 + 0.18) M (one further classical maker).
    function test_GAS_hybrid_1x2_oneHop() public {
        uint256 g = _hybridGas(2);
        assertLt(g, 1_170_000);
    }

    /// A one-plan `mtxExchangeBatch` over `mtxExchange` of the same plan, each its own transaction on the same state:
    /// the self-call, the plan's re-encoding, the result array, the longer calldata. Bound 1.5 x 30 k.
    function test_GAS_batch_overheadPerPlan() public {
        ISCaaSDex.ExchangePlan memory p1 = _exchangePlan("p1", 1);
        ISCaaSDex.Interaction[] memory r = _route(1000, 1900);
        uint256 snap = vm.snapshotState();
        vm.prank(RELAYER);
        dex.mtxExchange(p1, r);
        uint256 single = _last("mtxExchange 1 plan");
        vm.revertToState(snap);

        ISCaaSDex.ExchangePlan[] memory ps = new ISCaaSDex.ExchangePlan[](1);
        ps[0] = p1;
        ISCaaSDex.Interaction[][] memory xs = new ISCaaSDex.Interaction[][](1);
        xs[0] = r;
        vm.prank(RELAYER);
        dex.mtxExchangeBatch(ps, xs);
        uint256 batch = _last("mtxExchangeBatch 1 plan");
        emit log_named_uint("GAS mtxExchangeBatch overhead per plan", batch - single);
        assertLt(batch - single, 45_000);
    }

    /// Bound 1.5 x 354,530 (CTR-DEX-26, measured): alice sells 500 A for >= 1000 B, bob sells 1000 B for >= 500 A.
    function test_GAS_settle_1x1_unchanged() public {
        ISCaaSDex.Leg memory t = _natLeg(address(A), _order(alice, address(B), 500, 1000, 1), 500);
        ISCaaSDex.Leg memory m = _natLeg(address(B), _order(bob, address(A), 1000, 500, 1), 1000);
        ISCaaSDex.Settlement[] memory ss = _s(t, m);
        vm.prank(RELAYER);
        dex.mtxSettle(ss);
        uint256 g = _last("mtxSettle 1x1");
        assertLt(g, 531_795);
    }
}
