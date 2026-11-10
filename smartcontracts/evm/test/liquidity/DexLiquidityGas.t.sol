// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {LiquidityBase} from "./LiquidityBase.sol";
import {MockV2LiquidityPair} from "./LiquidityMocks.sol";

/// Gas of `mtxLiquidity` (spec 2026-11-10-dex-liquidity.md §13, L8): `isolate = true` runs each top-level call as its own
/// transaction, so the figure is `vm.lastCallGas()`, the regular gas (state gas logged apart). Upper bounds 1.5 × the spec's
/// estimate; each test logs its figure.
contract DexLiquidityGasTest is LiquidityBase {
    function _last(string memory what) internal returns (uint256 g) {
        Vm.Gas memory v = vm.lastCallGas();
        g = v.gasTotalUsed;
        emit log_named_uint(string.concat("GAS ", what, " (regular)"), g);
        emit log_named_uint(string.concat("GAS ", what, " (state)"), uint256(int256(v.gasStateUsed)));
    }

    /// v2-style add, two SCaaS inputs, native signer, LP output, fee > 0: estimate 390-535 k.
    function test_gas_v2AddTwoScaas() public {
        ISCaaSDex.LiquidityPlan memory p = _addPlan(98_000);
        ISCaaSDex.Interaction[] memory xs = _addXs(ADD, ADD, address(dex));
        vm.prank(relayer);
        dex.mtxLiquidity(p, xs);
        assertLe(_last("mtxLiquidity v2 add, two SCaaS inputs"), 802_500);
    }

    /// v2-style add, one SCaaS and one outside input (the DEX's verify and the puller): estimate 405-550 k.
    function test_gas_v2AddScaasOutside() public {
        MockV2LiquidityPair p2 = MockV2LiquidityPair(v2f.createPair(address(a), address(usdc)));
        ITradeToken.LiquidityOrder memory o = _base();
        o.inputs = _two(_t(address(a), ADD), _t(address(usdc), ADD));
        o.outputs = _one(_t(address(p2), 98_000));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, ALICE_PK, _u2(ADD, ADD));
        ISCaaSDex.Interaction[] memory xs = _xs3(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(p2), ADD))),
            _ix(address(usdc), abi.encodeCall(IERC20.transfer, (address(p2), ADD))),
            _ix(address(p2), abi.encodeCall(MockV2LiquidityPair.mint, (address(dex)))));
        vm.prank(relayer);
        dex.mtxLiquidity(p, xs);
        assertLe(_last("mtxLiquidity v2 add, SCaaS + outside"), 825_000);
    }

    /// v4 mock mint, two inputs, the reader check and the forward: estimate 510-815 k.
    function test_gas_v4Mint() public {
        ISCaaSDex.LiquidityPlan memory p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = posm.nextId();
        ISCaaSDex.Interaction[] memory xs = _mintXs(40_000, address(dex));
        vm.prank(relayer);
        dex.mtxLiquidity(p, xs);
        assertLe(_last("mtxLiquidity v4 mock mint"), 1_222_500);
    }
}
