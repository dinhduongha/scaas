// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UniswapExecutor} from "../../src/dex/UniswapExecutor.sol";
import {PoolKey} from "../../src/dex/uniswap/IUniswapV4.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockV3Factory, MockV3Pool, MockPoolManager, v2AmountOut} from "../helpers/MockUniswap.sol";

/// `UniswapExecutor` (spec §9, DX15) against mock v3 pools (CREATE2 by a mock factory with its own init-code hash) and
/// a mock v4 `PoolManager`. Fixture: the UA DEX base (A / B / C SCaaS tokens, the DEX); v3 pools A/B (100 000 A,
/// 200 000 B), A/C (100 000 each), C/B (100 000 C, 200 000 B), all fee 3000, and a v3 A/B pool at fee 500 priced 4 B
/// per A (50 000 A, 200 000 B); a v4 A/B pool in the manager (100 000 A, 200 000 B). The unit tests call
/// `exchangeCallback` as the DEX after handing the executor its input, as `mtxExchangeVia` does.
contract UniswapExecutorTest is UADexBase {
    MockV3Factory v3;
    MockPoolManager pm;
    UniswapExecutor ex;
    address pAB;
    address pAC;
    address pCB;
    address pAB500;
    PoolKey keyAB;

    function setUp() public override {
        super.setUp();
        v3 = new MockV3Factory();
        pAB = _pool(address(A), address(B), 3000, 100_000, 200_000);
        pAC = _pool(address(A), address(C), 3000, 100_000, 100_000);
        pCB = _pool(address(C), address(B), 3000, 100_000, 200_000);
        pAB500 = _pool(address(A), address(B), 500, 50_000, 200_000);
        pm = new MockPoolManager();
        keyAB = _key(address(A), address(B));
        (uint256 r0, uint256 r1) = address(A) < address(B) ? (100_000, 200_000) : (200_000, 100_000);
        pm.seed(keyAB, r0, r1);
        _fund(address(A), address(pm), 100_000);
        _fund(address(B), address(pm), 200_000);
        ex = new UniswapExecutor(address(dex), address(v3), v3.poolInitCodeHash(), address(pm));
    }

    // ------------------------------------------------------------------ helpers

    function _fund(address t, address to, uint256 amount) internal {
        vm.prank(t == address(A) ? alice : bob);
        IERC20(t).transfer(to, amount);
    }

    function _pool(address a, address b, uint24 fee, uint256 ra, uint256 rb) internal returns (address p) {
        p = v3.createPool(a, b, fee);
        _fund(a, p, ra);
        _fund(b, p, rb);
    }

    function _key(address a, address b) internal pure returns (PoolKey memory) {
        (address c0, address c1) = a < b ? (a, b) : (b, a);
        return PoolKey(c0, c1, 3000, 60, address(0));
    }

    function _v3(address tIn, address tOut, uint24 fee) internal pure returns (UniswapExecutor.Hop memory) {
        return UniswapExecutor.Hop(1, abi.encode(tIn, tOut, fee));
    }

    function _v3(address tIn, address tOut) internal pure returns (UniswapExecutor.Hop memory) {
        return _v3(tIn, tOut, 3000);
    }

    function _v4(PoolKey memory key, address tIn) internal pure returns (UniswapExecutor.Hop memory) {
        return UniswapExecutor.Hop(2, abi.encode(key, tIn == key.currency0));
    }

    function _hops(UniswapExecutor.Hop memory h) internal pure returns (bytes memory) {
        UniswapExecutor.Hop[] memory hs = new UniswapExecutor.Hop[](1);
        hs[0] = h;
        return abi.encode(hs);
    }

    function _hops(UniswapExecutor.Hop memory h0, UniswapExecutor.Hop memory h1) internal pure returns (bytes memory) {
        UniswapExecutor.Hop[] memory hs = new UniswapExecutor.Hop[](2);
        (hs[0], hs[1]) = (h0, h1);
        return abi.encode(hs);
    }

    function _one(address a) internal pure returns (address[] memory x) {
        x = new address[](1);
        x[0] = a;
    }

    /// As `mtxExchangeVia`: `amountIn` of `tIn` to the executor, then the callback from the DEX.
    function _run(UniswapExecutor e, address tIn, uint256 amountIn, address tOut, bytes memory data) internal {
        _fund(tIn, address(e), amountIn);
        vm.prank(address(dex));
        e.exchangeCallback("t", _one(tIn), new uint256[](1), _one(tOut), new uint256[](1), data);
    }

    function _expectRun(UniswapExecutor e, address tIn, uint256 amountIn, address tOut, bytes memory data,
        bytes memory err) internal
    {
        _fund(tIn, address(e), amountIn);
        vm.prank(address(dex));
        vm.expectRevert(err);
        e.exchangeCallback("t", _one(tIn), new uint256[](1), _one(tOut), new uint256[](1), data);
    }

    function _holdsNothing() internal view {
        assertEq(A.balanceOf(address(ex)), 0);
        assertEq(B.balanceOf(address(ex)), 0);
        assertEq(C.balanceOf(address(ex)), 0);
    }

    // ------------------------------------------------------------------ access

    function test_executor_onlyDex() public {
        bytes memory data = _hops(_v3(address(A), address(B)));
        vm.expectRevert(UniswapExecutor.NotDex.selector);
        ex.exchangeCallback("t", _one(address(A)), new uint256[](1), _one(address(B)), new uint256[](1), data);
        vm.prank(alice);
        vm.expectRevert(UniswapExecutor.NotDex.selector);
        ex.exchangeCallback("t", _one(address(A)), new uint256[](1), _one(address(B)), new uint256[](1), data);
    }

    /// Only the pool the executor derives from (V3_FACTORY, keccak(token0, token1, fee), V3_POOL_INIT_CODE_HASH) is
    /// paid: an EOA, a pool of the same code from another factory, and a real pool of this factory naming another pool's
    /// tokens are all refused, with a stray balance in the executor to steal.
    function test_executor_v3Callback_nonPool_refused() public {
        _fund(address(A), address(ex), 1000);
        bytes memory data = abi.encode(address(A), address(B), uint24(3000));
        vm.prank(alice);
        vm.expectRevert(UniswapExecutor.NotPool.selector);
        ex.uniswapV3SwapCallback(1000, -1, data);
        MockV3Factory other = new MockV3Factory();
        address fake = other.createPool(address(A), address(B), 3000);
        vm.prank(fake);
        vm.expectRevert(UniswapExecutor.NotPool.selector);
        ex.uniswapV3SwapCallback(1000, -1, data);
        vm.prank(pAC);
        vm.expectRevert(UniswapExecutor.NotPool.selector);
        ex.uniswapV3SwapCallback(1000, -1, data);
        vm.prank(pAB500); // same tokens, other fee: another pool
        vm.expectRevert(UniswapExecutor.NotPool.selector);
        ex.uniswapV3SwapCallback(1000, -1, data);
        UniswapExecutor off = new UniswapExecutor(address(dex), address(0), bytes32(0), address(0));
        vm.prank(pAB);
        vm.expectRevert(UniswapExecutor.NotPool.selector);
        off.uniswapV3SwapCallback(1000, -1, data);
        assertEq(A.balanceOf(address(ex)), 1000);
        assertEq(v3.getPool(address(A), address(B), 3000), pAB); // the derivation matches the factory
    }

    function test_executor_v4Callback_notPoolManager_refused() public {
        bytes memory data = _hops(_v4(keyAB, address(A)));
        vm.prank(alice);
        vm.expectRevert(UniswapExecutor.NotPoolManager.selector);
        ex.unlockCallback(data);
        vm.prank(address(pm)); // the manager, but not inside an unlock this executor started
        vm.expectRevert(UniswapExecutor.NotPoolManager.selector);
        ex.unlockCallback(data);
    }

    // ------------------------------------------------------------------ hops

    /// A → C → B on v3, each hop on the executor's whole balance: no intermediate amount is predicted; all of B goes
    /// to the DEX; the executor ends with 0 of every token.
    function test_executor_v3_twoHops_wholeBalance() public {
        uint256 c = v2AmountOut(1000, 100_000, 100_000);
        uint256 b = v2AmountOut(c, 100_000, 200_000);
        _run(ex, address(A), 1000, address(B), _hops(_v3(address(A), address(C)), _v3(address(C), address(B))));
        assertEq(B.balanceOf(address(dex)), b);
        assertEq(A.balanceOf(pAC), 101_000);
        assertEq(C.balanceOf(pCB), 100_000 + c);
        _holdsNothing();
    }

    /// One v4 hop inside one `unlock` (input settled by sync / transfer / settle, output taken); then a mixed route
    /// v4 A → B then v3 B → C in the same unlock. Every delta ends settled.
    function test_executor_v4_hop() public {
        uint256 b = v2AmountOut(1000, 100_000, 200_000);
        _run(ex, address(A), 1000, address(B), _hops(_v4(keyAB, address(A))));
        assertEq(B.balanceOf(address(dex)), b);
        assertEq(A.balanceOf(address(pm)), 101_000);
        _holdsNothing();
        uint256 b2 = v2AmountOut(500, 101_000, 200_000 - b);
        uint256 c = v2AmountOut(b2, 200_000, 100_000);
        _run(ex, address(A), 500, address(C), _hops(_v4(keyAB, address(A)), _v3(address(B), address(C))));
        assertEq(C.balanceOf(address(dex)), c);
        assertEq(pm.delta(address(A)), 0);
        assertEq(pm.delta(address(B)), 0);
        _holdsNothing();
    }

    function test_executor_v4_nativeCurrency_refused() public {
        PoolKey memory k = PoolKey(address(0), address(A), 3000, 60, address(0));
        _expectRun(ex, address(A), 1000, address(B), _hops(_v4(k, address(A))),
            abi.encodeWithSelector(UniswapExecutor.NativeCurrency.selector));
    }

    /// The C → B pool consumes only 500 of the C the first hop bought: the dust of C is refused, never kept.
    function test_executor_leftover_refused() public {
        MockV3Pool(pCB).setMaxIn(500);
        _expectRun(ex, address(A), 1000, address(B), _hops(_v3(address(A), address(C)), _v3(address(C), address(B))),
            abi.encodeWithSelector(UniswapExecutor.Leftover.selector, address(C)));
    }

    /// A stray balance sent to the executor is spent or forwarded at its next use: 100 A ride the hop, 50 B go to the
    /// DEX with the output (surplus for the signers there).
    function test_executor_strayBalance_becomesSurplus() public {
        _fund(address(A), address(ex), 100);
        _fund(address(B), address(ex), 50);
        _run(ex, address(A), 1000, address(B), _hops(_v3(address(A), address(B))));
        assertEq(B.balanceOf(address(dex)), v2AmountOut(1100, 100_000, 200_000) + 50);
        _holdsNothing();
    }

    function test_executor_hopKindOff() public {
        UniswapExecutor off = new UniswapExecutor(address(dex), address(0), bytes32(0), address(0));
        _expectRun(off, address(A), 10, address(B), _hops(_v3(address(A), address(B))),
            abi.encodeWithSelector(UniswapExecutor.HopKindOff.selector, uint8(1)));
        _expectRun(off, address(A), 10, address(B), _hops(_v4(keyAB, address(A))),
            abi.encodeWithSelector(UniswapExecutor.HopKindOff.selector, uint8(2)));
        _expectRun(ex, address(A), 10, address(B), _hops(UniswapExecutor.Hop(3, "")),
            abi.encodeWithSelector(UniswapExecutor.HopKindOff.selector, uint8(3)));
        _expectRun(ex, address(A), 10, address(B), _hops(UniswapExecutor.Hop(0, "")),
            abi.encodeWithSelector(UniswapExecutor.HopKindOff.selector, uint8(0)));
    }

    /// D5: the DEX, a v3 factory and a v4 pool manager must be contracts (an EOA or an EIP-7702 designator is not);
    /// 0 turns a hop kind off, never the DEX.
    function test_executor_constructor_dependenciesMustBeContracts() public {
        address eoa = address(0xE0A);
        address delegated = address(0x7702);
        vm.etch(delegated, abi.encodePacked(hex"ef0100", address(dex)));
        bytes32 h = v3.poolInitCodeHash();
        vm.expectRevert(abi.encodeWithSelector(UniswapExecutor.NotAContract.selector, eoa));
        new UniswapExecutor(eoa, address(v3), h, address(pm));
        vm.expectRevert(abi.encodeWithSelector(UniswapExecutor.NotAContract.selector, delegated));
        new UniswapExecutor(delegated, address(v3), h, address(pm));
        vm.expectRevert(abi.encodeWithSelector(UniswapExecutor.NotAContract.selector, address(0)));
        new UniswapExecutor(address(0), address(v3), h, address(pm));
        vm.expectRevert(abi.encodeWithSelector(UniswapExecutor.NotAContract.selector, eoa));
        new UniswapExecutor(address(dex), eoa, h, address(pm));
        vm.expectRevert(abi.encodeWithSelector(UniswapExecutor.NotAContract.selector, delegated));
        new UniswapExecutor(address(dex), address(v3), h, delegated);
        UniswapExecutor e = new UniswapExecutor(address(dex), address(0), bytes32(0), address(0));
        assertEq(e.DEX(), address(dex));
        assertEq(e.V3_FACTORY(), address(0));
        assertEq(e.V4_POOL_MANAGER(), address(0));
        assertEq(ex.V3_POOL_INIT_CODE_HASH(), h);
    }

    // ------------------------------------------------------------------ through the DEX

    /// `mtxExchangeVia`: alice sells 1000 A for at least 1900 B (fee 0.3 %) through A → C → B; she gets the floor less
    /// its fee ⌈5.7⌉ = 6 plus every B above the floor; the DEX and the executor end with nothing.
    function test_executor_viaDex_mtxExchangeVia_endToEnd() public {
        uint256 b = v2AmountOut(v2AmountOut(1000, 100_000, 100_000), 100_000, 200_000);
        ISCaaSDex.Leg memory l = _natLeg(address(A), _nat(alice, address(B), 1000, 1900, 3_000), 1000);
        ISCaaSDex.ExchangePlan memory p;
        p.ref = "x";
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = ISCaaSDex.ExchangeLeg(address(A), 0, l.order, l.sig, 1000, 1900);
        uint256 a0 = A.balanceOf(alice);
        vm.prank(RELAYER);
        dex.mtxExchangeVia(p, address(ex), _hops(_v3(address(A), address(C)), _v3(address(C), address(B))));
        assertGt(b, 1900);
        assertEq(B.balanceOf(alice), b - 6);
        assertEq(A.balanceOf(alice), a0 - 1000);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
        _holdsNothing();
    }

    /// `mtxHybridVia` with the DX7 refund: alice sells 500 A (minFill 400) for at least 1.8 B per A, 400 A to bob's
    /// order at his price (800 B), 100 A outside for at least 180 B. The fee-500 pool takes only 60 A and pays
    /// ⌊60 · 997 · 200 000 / (50 000 000 + 59 820)⌋ = 238 B; the executor returns the 40 A it could not sell, the DEX
    /// refunds them to alice (sold 460 ≥ minFill), she gets 980 − 3 + 58 B.
    function test_executor_viaDex_mtxHybridVia_withRefund() public {
        MockV3Pool(pAB500).setMaxIn(60);
        ITradeToken.TradeOrder memory t = _nat(alice, address(B), 1000, 1800, 3_000);
        t.minFill = 400;
        ISCaaSDex.HybridPlan memory p;
        p.ref = "hy";
        p.taker = _natLeg(address(A), t, 500);
        p.makers = new ISCaaSDex.Leg[](1);
        p.makers[0] = _natLeg(address(B), _nat(bob, address(A), 2000, 1000, 1_000), 800);
        p.outsideSell = 100;
        p.outsideFloor = 180;
        uint256 a0 = A.balanceOf(alice);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeLegSettled("hy", A.tradeOrderDigest(t), alice, alice, 460, 980, 58, 3, 40, 828);
        vm.prank(RELAYER);
        dex.mtxHybridVia(p, address(ex), _hops(_v3(address(A), address(B), 500)));
        assertEq(A.balanceOf(alice), a0 - 460);
        assertEq(B.balanceOf(alice), 980 - 3 + 58);
        assertEq(A.balanceOf(bob), 399);
        assertEq(A.balanceOf(pAB500), 50_060);
        assertEq(A.balanceOf(address(dex)), 0);
        assertEq(B.balanceOf(address(dex)), 0);
        _holdsNothing();
    }
}
