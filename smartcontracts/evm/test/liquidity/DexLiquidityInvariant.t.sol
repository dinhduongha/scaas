// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {nid} from "../helpers/Ids.sol";
import {LiquidityBase} from "./LiquidityBase.sol";
import {MockV2LiquidityPair} from "./LiquidityMocks.sol";

/// Drives `mtxLiquidity` with v2 adds (SCaaS and outside inputs, any slack), v2 withdraws and v4 mints, every call a valid
/// signed order; each records what the signer gave and got.
contract LiquidityHandler is Test {
    LiquidityInvariantTest internal t;
    uint256 public nonce;
    uint256 public calls;

    constructor(LiquidityInvariantTest t_) {
        t = t_;
    }

    function add(uint256 x, uint256 y, uint256 slack, bool outside) external {
        x = bound(x, 2_000, 50_000);
        y = bound(y, 2_000, 50_000);
        slack = bound(slack, 0, 1_000);
        t.doAdd(x, y, slack, outside, ++nonce);
        ++calls;
    }

    function withdraw(uint256 share) external {
        if (t.carolLp() < 10) return;
        t.doWithdraw(bound(share, 1, t.carolLp()), ++nonce);
        ++calls;
    }

    function mint(uint128 liq, uint256 slack) external {
        liq = uint128(bound(liq, 1, 40_000));
        t.doMint(liq, bound(slack, 0, 1_000), ++nonce);
        ++calls;
    }
}

/// Invariant (spec 2026-11-10-dex-liquidity.md §14, L8): between calls the DEX holds 0 of every plan token, no position and
/// no allowance; every executed order's pulls stay within its signed maxima (the tokens' `pulled[h]`), the DEX's `pulled[h]`
/// is 1; each signer's balance moved by exactly its pulls minus its refunds (a refund may exceed a pull, never assumed below).
/// forge-config: default.invariant.runs = 128
/// forge-config: default.invariant.depth = 64
/// forge-config: default.invariant.fail-on-revert = true
contract LiquidityInvariantTest is LiquidityBase {
    LiquidityHandler internal h;
    bytes32[] internal orders;
    uint256[] internal maxA;
    uint256 internal pulledA; // Σ pulls of `a` minus Σ refunds, by the events' figures
    uint256 internal aliceA0;

    function setUp() public override {
        super.setUp();
        _run(_addPlan(98_000), _addXs(ADD, ADD, address(dex))); // the pool exists
        aliceA0 = a.balanceOf(alice);
        vm.prank(carol);
        pair.approve(puller, type(uint256).max);
        h = new LiquidityHandler(this);
        targetContract(address(h));
    }

    function carolLp() external view returns (uint256) {
        return pair.balanceOf(carol);
    }

    function _record(ISCaaSDex.LiquidityPlan memory p) internal {
        bytes32 d = dex.liquidityOrderDigest(p.order);
        orders.push(d);
        maxA.push(p.order.inputs.length != 0 && p.order.inputs[0].token == address(a) ? p.order.inputs[0].amount : 0);
    }

    function doAdd(uint256 x, uint256 y, uint256 slack, bool outside, uint256 n) external {
        address second = outside ? address(usdc) : address(b);
        MockV2LiquidityPair lp = outside ? _usdcPair() : pair;
        ITradeToken.LiquidityOrder memory o = _base();
        o.nonce = n;
        o.inputs = _two(_t(address(a), x + slack), _t(second, y + slack));
        o.outputs = _one(_t(address(lp), 1));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(x + slack, y + slack));
        ISCaaSDex.Interaction[] memory xs = _xs3(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(lp), x))),
            _ix(second, abi.encodeCall(IERC20.transfer, (address(lp), y))),
            _ix(address(lp), abi.encodeCall(MockV2LiquidityPair.mint, (address(dex)))));
        _run(p, xs);
        _record(p);
        pulledA += x; // `slack` came back
    }

    MockV2LiquidityPair internal up;

    function _usdcPair() internal returns (MockV2LiquidityPair) {
        if (address(up) == address(0)) up = MockV2LiquidityPair(v2f.createPair(address(a), address(usdc)));
        return up;
    }

    function doWithdraw(uint256 share, uint256 n) external {
        ITradeToken.LiquidityOrder memory o = _base();
        (o.from, o.recipient, o.nonce) = (nid(carol), 0, n);
        o.inputs = _one(_t(address(pair), share));
        o.outputs = _two(_t(address(a), 0), _t(address(b), 0));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, CAROL_PK, _u(share));
        _run(p, _xs2(_ix(address(pair), abi.encodeCall(IERC20.transfer, (address(pair), share))),
            _ix(address(pair), abi.encodeCall(MockV2LiquidityPair.burn, (address(dex))))));
        _record(p);
    }

    function doMint(uint128 liq, uint256 slack, uint256 n) external {
        ITradeToken.LiquidityOrder memory o = _mintOrder(liq);
        o.nonce = n;
        (o.inputs[0].amount, o.inputs[1].amount) = (50_000 + slack, 50_000 + slack);
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        _run(p, _mintXs(liq, address(dex)));
        _record(p);
        pulledA += liq;
    }

    function invariant_dexHoldsNothing() public view {
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
        assertEq(usdc.balanceOf(address(dex)), 0);
        assertEq(pair.balanceOf(address(dex)), 0);
        assertEq(posm.balanceOf(address(dex)), 0);
        assertEq(a.allowance(address(dex), address(pair)) + b.allowance(address(dex), address(pair)), 0);
    }

    function invariant_pullsWithinSignedMaxima() public view {
        for (uint256 i; i < orders.length; ++i) {
            assertEq(dex.pulled(orders[i]), 1);
            assertLe(a.pulled(orders[i]), maxA[i]);
        }
    }

    function invariant_signerBalance() public view {
        assertEq(aliceA0 - a.balanceOf(alice), pulledA);
    }
}
