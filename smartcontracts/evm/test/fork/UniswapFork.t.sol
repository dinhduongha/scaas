// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UniswapExecutor} from "../../src/dex/UniswapExecutor.sol";
import {PoolKey} from "../../src/dex/uniswap/IUniswapV4.sol";
import {IUniswapV3Factory} from "../../src/dex/uniswap/IUniswapV3.sol";
import {UID_, normalInit} from "../v2/helpers/V2Fixture.sol";
import {Catalogue} from "../helpers/Catalogue.sol";

/// Minimal ABIs of the mainnet Uniswap contracts the fork test calls (written here, no Uniswap source).
interface ISwapRouter02 {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    function exactInputSingle(ExactInputSingleParams calldata p) external payable returns (uint256);
}

interface IV2Router {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to,
        uint256 deadline) external returns (uint256[] memory);
    function getAmountsOut(uint256 amountIn, address[] calldata path) external view returns (uint256[] memory);
}

interface IV2Factory {
    function createPair(address a, address b) external returns (address);
}

interface IV2Pair {
    function mint(address to) external returns (uint256);
}

interface IPermit2 {
    function approve(address token, address spender, uint160 amount, uint48 expiration) external;
    function allowance(address owner, address token, address spender) external view returns (uint160, uint48, uint48);
}

interface IUniversalRouter {
    function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external payable;
}

/// The DEX round against the real Uniswap on an Ethereum mainnet fork (spec §10, DX16, PD8). Opt-in: the RPC URL comes
/// only from `SCAAS_FORK_RPC_URL` (never committed, never logged); unset, every test skips (CI). The block is pinned,
/// so quotes and pool states are deterministic. Fixture: a fresh SCaaS stack (`OpenFactory`, a `NormalToken` TOK, an
/// `SCaaSDex` clone, `UniswapExecutor` on the real v3 factory and v4 `PoolManager`); markets WETH / USDC (outside legs
/// through the puller) and TOK / WETH; balances by `deal`. A quote is the route's real output, measured on a state
/// snapshot that is then reverted (`_quoteA` runs path (a)'s interactions as the DEX, `_quoteB` the executor); a floor
/// is that quote less 1 %, and every test asserts the exact payout (floor − fee + surplus = quote − fee). Each test
/// ends with the DEX and the executor holding 0 of every token and no allowance (`_clean`).
contract UniswapForkTest is Test {
    /// 2025-03-08 05:14:35 UTC, after Uniswap v4's mainnet launch (2025-01). Liquidity read at this block: v3 WETH /
    /// USDC 0.05 %, WETH / USDT 0.05 %, USDC / USDT 0.01 %, v2 WETH / USDC; v4 USDC / USDT (fee 100, tick spacing 1,
    /// no hooks) StateView `getLiquidity` = 3 417 756 898 041 992 (the v4 WETH / USDC ERC-20 pools are near empty).
    uint256 constant FORK_BLOCK = 22_000_000;

    // Uniswap's published Ethereum mainnet deployments (docs.uniswap.org: the v2, v3 and v4 deployment pages; Permit2
    // and the v4 UniversalRouter from the v4 page). Each has code at FORK_BLOCK; the v3 init-code hash is checked
    // against the factory's `getPool` in `test_fork_executor_v3TwoHops`.
    address constant V2_FACTORY = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;
    address constant V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D; // UniswapV2Router02
    address constant V3_FACTORY = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
    bytes32 constant V3_POOL_INIT_CODE_HASH = 0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54;
    address constant V3_ROUTER = 0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45; // SwapRouter02
    address constant POOL_MANAGER = 0x000000000004444c5dc75cB358380D2e3dE08A90; // v4 PoolManager
    address constant UNIVERSAL_ROUTER = 0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af; // v4 UniversalRouter
    address constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
    // Tokens: the canonical mainnet WETH9, Circle's USDC, Tether's USDT.
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    uint256 constant FEE = 3_000; // 0.3 % DEX fee on the WETH sellers' orders
    uint256 constant DAVE_PK = 0xDA7E;
    uint256 constant ERIN_PK = 0xE41;
    uint256 constant FRANK_PK = 0xF4A;
    uint256 constant ALICE_PK = 0xA11CE;
    address dave = vm.addr(DAVE_PK); // sells WETH
    address erin = vm.addr(ERIN_PK); // sells WETH or USDC
    address frank = vm.addr(FRANK_PK); // sells USDC
    address alice = vm.addr(ALICE_PK); // holds TOK
    address admin = address(0xAD);
    address treasury = address(0x7EA5);
    address relayer = address(0xBEEF);

    SCaaSDex dex;
    NormalToken tok;
    UniswapExecutor ex;

    function setUp() public {
        string memory url = vm.envOr("SCAAS_FORK_RPC_URL", string(""));
        if (bytes(url).length == 0) {
            vm.skip(true);
            return;
        }
        // The SCaaS stack is deployed before the fork, under foundry.toml's gas limit, and kept across it: on the fork
        // every call is capped at the block's 36 M gas, below what Amsterdam's code deposit charges for the 27-39 KiB
        // implementations (NormalToken, SCaaSDex).
        OpenFactory f = new OpenFactory(address(this), UID_, 0);
        address tokImpl = Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode,
            address(0), address(0), false);
        address dexImpl = Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        tok = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            abi.encode(normalInit("Tok", "TOK", 18, 1_000_000e18, alice, address(0))), "tok"));
        dex = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(admin, 0, treasury, false)), "dex"));
        address[] memory keep = new address[](6);
        (keep[0], keep[1], keep[2], keep[3], keep[4], keep[5]) =
            (address(f), tokImpl, dexImpl, address(tok), address(dex), dex.puller());
        vm.makePersistent(keep);
        vm.createSelectFork(url, FORK_BLOCK);
        // The fork takes the block's own rules (Prague) over foundry.toml; the stack is built for Amsterdam
        // (Glamsterdam, NET-EVM-06: a public chain gets it only after its fork), so the fork runs there.
        vm.setEvmVersion("amsterdam");
        assertEq(block.chainid, 1);
        ex = new UniswapExecutor(address(dex), V3_FACTORY, V3_POOL_INIT_CODE_HASH, POOL_MANAGER);
        vm.startPrank(admin);
        dex.setMarket(WETH, USDC, true);
        dex.setMarket(address(tok), WETH, true);
        vm.stopPrank();
        _fund(WETH, dave, 10 ether);
        _fund(WETH, erin, 10 ether);
        _fund(USDC, erin, 100_000e6);
        _fund(USDC, frank, 100_000e6);
    }

    // ------------------------------------------------------------------ helpers

    /// `who` holds `amount` of the outside `token` and approves the puller.
    function _fund(address token, address who, uint256 amount) internal {
        deal(token, who, amount);
        address p = dex.puller();
        vm.prank(who);
        IERC20(token).approve(p, type(uint256).max);
    }

    function _order(address from, address receiveToken, uint256 amount, uint256 receiveAmount, uint256 fee)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = receiveToken;
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.fee = fee;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    /// The signature of `o` selling `sell`: a `DexOrder` in the DEX's domain (outside token) or the token's own
    /// `TradeOrder` digest (TOK).
    function _sig(uint256 pk, address sell, ITradeToken.TradeOrder memory o) internal view returns (bytes memory) {
        bytes32 h = sell == address(tok) ? tok.tradeOrderDigest(o) : dex.dexOrderDigest(sell, o);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }

    function _leg(uint256 pk, address sell, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (ISCaaSDex.Leg memory)
    {
        return ISCaaSDex.Leg(sell, 0, abi.encode(o), _sig(pk, sell, o), fill);
    }

    function _xLeg(uint256 pk, address sell, ITradeToken.TradeOrder memory o, uint256 sellFill, uint256 floor)
        internal view returns (ISCaaSDex.ExchangeLeg memory)
    {
        return ISCaaSDex.ExchangeLeg(sell, 0, abi.encode(o), _sig(pk, sell, o), sellFill, floor);
    }

    function _plan(bytes32 ref, ISCaaSDex.ExchangeLeg memory l) internal pure returns (ISCaaSDex.ExchangePlan memory p) {
        p.ref = ref;
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = l;
    }

    function _plan(bytes32 ref, ISCaaSDex.ExchangeLeg memory l0, ISCaaSDex.ExchangeLeg memory l1)
        internal pure returns (ISCaaSDex.ExchangePlan memory p)
    {
        p.ref = ref;
        p.legs = new ISCaaSDex.ExchangeLeg[](2);
        (p.legs[0], p.legs[1]) = (l0, l1);
    }

    function _buffered(uint256 quote) internal pure returns (uint256) {
        return quote * 99 / 100;
    }

    function _fee(uint256 recv, uint256 fee) internal pure returns (uint256) {
        return (recv * fee + 999_999) / 1_000_000;
    }

    /// Path (a) through SwapRouter02: `approve(router, amountIn)` on `tIn`, then `exactInputSingle` to the DEX.
    function _v3Router(address tIn, address tOut, uint24 fee, uint256 amountIn, uint256 minOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(tIn, abi.encodeCall(IERC20.approve, (V3_ROUTER, amountIn)));
        xs[1] = ISCaaSDex.Interaction(V3_ROUTER, abi.encodeCall(ISwapRouter02.exactInputSingle,
            (ISwapRouter02.ExactInputSingleParams(tIn, tOut, fee, address(dex), amountIn, minOut, 0))));
    }

    /// Path (a) through Router02: `approve(router, amountIn)` on `tIn`, then `swapExactTokensForTokens` to the DEX.
    function _v2Router(address tIn, address tOut, uint256 amountIn, uint256 minOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(tIn, abi.encodeCall(IERC20.approve, (V2_ROUTER, amountIn)));
        xs[1] = ISCaaSDex.Interaction(V2_ROUTER, abi.encodeCall(IV2Router.swapExactTokensForTokens,
            (amountIn, minOut, _path(tIn, tOut), address(dex), type(uint256).max)));
    }

    function _path(address a, address b) internal pure returns (address[] memory p) {
        p = new address[](2);
        (p[0], p[1]) = (a, b);
    }

    function _v3Hop(address tIn, address tOut, uint24 fee) internal pure returns (UniswapExecutor.Hop memory) {
        return UniswapExecutor.Hop(1, abi.encode(tIn, tOut, fee));
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

    /// What path (a)'s interactions return to the DEX for `amountIn` of `tIn`: run as the DEX on a snapshot, reverted.
    function _quoteA(address tIn, uint256 amountIn, address tOut, ISCaaSDex.Interaction[] memory xs)
        internal returns (uint256 q)
    {
        uint256 id = vm.snapshotState();
        deal(tIn, address(dex), amountIn);
        for (uint256 i; i < xs.length; ++i) {
            vm.prank(address(dex));
            (bool ok,) = xs[i].target.call(xs[i].data);
            require(ok, "quote: interaction failed");
        }
        q = IERC20(tOut).balanceOf(address(dex));
        vm.revertToState(id);
    }

    /// What the executor returns to the DEX for `amountIn` of `tIn` on `data`: its callback as the DEX on a snapshot.
    function _quoteB(address tIn, uint256 amountIn, address tOut, bytes memory data) internal returns (uint256 q) {
        uint256 id = vm.snapshotState();
        deal(tIn, address(ex), amountIn);
        vm.prank(address(dex));
        ex.exchangeCallback("q", _one(tIn), new uint256[](1), _one(tOut), new uint256[](1), data);
        q = IERC20(tOut).balanceOf(address(dex));
        vm.revertToState(id);
    }

    /// (7) The DEX and the executor hold 0 of every token and grant no allowance (ERC-20 or Permit2) to any Uniswap
    /// contract or to each other.
    function _clean() internal view {
        address[4] memory tokens = [WETH, USDC, USDT, address(tok)];
        address[2] memory holders = [address(dex), address(ex)];
        address[7] memory spenders =
            [V2_ROUTER, V3_ROUTER, UNIVERSAL_ROUTER, PERMIT2, POOL_MANAGER, address(ex), address(dex)];
        for (uint256 i; i < tokens.length; ++i) {
            for (uint256 j; j < holders.length; ++j) {
                assertEq(IERC20(tokens[i]).balanceOf(holders[j]), 0, "holds a token");
                for (uint256 k; k < spenders.length; ++k) {
                    assertEq(IERC20(tokens[i]).allowance(holders[j], spenders[k]), 0, "ERC-20 allowance");
                    (uint160 amt,,) = IPermit2(PERMIT2).allowance(holders[j], tokens[i], spenders[k]);
                    assertEq(amt, 0, "Permit2 allowance");
                }
            }
        }
    }

    /// Mode 2, two WETH sellers in one plan, the route quoted at `q` for 1.5 WETH: floors 2/3 and 1/3 of the buffered
    /// quote; the excess split pro rata to the floors (the last leg takes the remainder), dave's fee once on his floor.
    function _twoSellers(bytes32 ref, uint256 q, ISCaaSDex.Interaction[] memory xs) internal {
        uint256 f0 = _buffered(q * 2 / 3);
        uint256 f1 = _buffered(q / 3);
        ITradeToken.TradeOrder memory od = _order(dave, USDC, 1 ether, f0 * 95 / 100, FEE);
        ITradeToken.TradeOrder memory oe = _order(erin, USDC, 0.5 ether, f1 * 95 / 100, 0);
        ISCaaSDex.ExchangePlan memory p =
            _plan(ref, _xLeg(DAVE_PK, WETH, od, 1 ether, f0), _xLeg(ERIN_PK, WETH, oe, 0.5 ether, f1));
        uint256 excess = q - f0 - f1;
        uint256 share0 = excess * f0 / (f0 + f1);
        vm.prank(relayer);
        dex.mtxExchange(p, xs);
        assertGt(excess, 0);
        assertEq(IERC20(USDC).balanceOf(dave), f0 - _fee(f0, FEE) + share0);
        assertEq(IERC20(USDC).balanceOf(erin), 100_000e6 + f1 + excess - share0);
        assertEq(IERC20(USDC).balanceOf(treasury), _fee(f0, FEE));
        assertEq(IERC20(WETH).balanceOf(dave), 9 ether);
        assertEq(IERC20(WETH).balanceOf(erin), 9.5 ether);
        _clean();
    }

    // ------------------------------------------------------------------ (1) mode 2, path (a)

    /// dave (1 WETH) and erin (0.5 WETH) sell for USDC through SwapRouter02 `exactInputSingle` (WETH / USDC 0.05 %,
    /// recipient the DEX); every USDC above the floors goes to the signers.
    function test_fork_v3RouterExactInput_outsideLegs() public {
        ISCaaSDex.Interaction[] memory xs = _v3Router(WETH, USDC, 500, 1.5 ether, 0);
        _twoSellers("v3", _quoteA(WETH, 1.5 ether, USDC, xs), xs);
    }

    /// The same two orders through Router02 `swapExactTokensForTokens` on the v2 WETH / USDC pair; the quote is the
    /// router's own `getAmountsOut`.
    function test_fork_v2Router_outsideLegs() public {
        uint256 q = IV2Router(V2_ROUTER).getAmountsOut(1.5 ether, _path(WETH, USDC))[1];
        ISCaaSDex.Interaction[] memory xs = _v2Router(WETH, USDC, 1.5 ether, 0);
        assertEq(_quoteA(WETH, 1.5 ether, USDC, xs), q);
        _twoSellers("v2", q, xs);
    }

    // ------------------------------------------------------------------ (2) mode 2, path (b)

    /// `mtxExchangeVia` through `UniswapExecutor`: dave's 1 WETH → USDT (v3 0.05 %) → USDC (v3 0.01 %), each hop on the
    /// executor's whole balance; he gets the floor less its fee plus every USDC above it. The executor's CREATE2
    /// derivation (factory, init-code hash) is the factory's own `getPool`.
    function test_fork_executor_v3TwoHops() public {
        (address t0, address t1) = WETH < USDC ? (WETH, USDC) : (USDC, WETH);
        address derived = address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", V3_FACTORY,
            keccak256(abi.encode(t0, t1, uint24(500))), V3_POOL_INIT_CODE_HASH)))));
        assertEq(IUniswapV3Factory(V3_FACTORY).getPool(WETH, USDC, 500), derived);
        _viaOne("v3x2", _hops(_v3Hop(WETH, USDT, 500), _v3Hop(USDT, USDC, 100)));
    }

    /// One v4 hop of a two-ERC-20 pool (USDC / USDT, fee 100, tick spacing 1, no hooks) after a v3 hop WETH → USDT: the
    /// whole route runs inside one `unlock`, the USDT owed settled by sync / transfer / settle, the USDC taken.
    function test_fork_executor_v4Hop() public {
        PoolKey memory key = PoolKey(USDC, USDT, 100, 1, address(0));
        _viaOne("v4", _hops(_v3Hop(WETH, USDT, 500), UniswapExecutor.Hop(2, abi.encode(key, false))));
    }

    function _viaOne(bytes32 ref, bytes memory data) internal {
        uint256 q = _quoteB(WETH, 1 ether, USDC, data);
        uint256 floor = _buffered(q);
        ITradeToken.TradeOrder memory o = _order(dave, USDC, 1 ether, floor * 95 / 100, FEE);
        vm.prank(relayer);
        dex.mtxExchangeVia(_plan(ref, _xLeg(DAVE_PK, WETH, o, 1 ether, floor)), address(ex), data);
        assertEq(IERC20(USDC).balanceOf(dave), q - _fee(floor, FEE));
        assertEq(IERC20(WETH).balanceOf(dave), 9 ether);
        assertEq(IERC20(USDC).balanceOf(treasury), _fee(floor, FEE));
        _clean();
    }

    // ------------------------------------------------------------------ (3) mode 3, hybrid

    /// dave sells WETH for USDC: erin and frank each sell 1000 USDC at their own price (the route's 1-WETH price, so
    /// 1000 USDC buy ⌈1000e6 · 1e18 / q1⌉ WETH), the other 1 WETH goes outside for at least the buffered quote. The
    /// makers get exactly their price; dave gets his floor (2000 USDC + outsideFloor) less its fee plus every USDC the
    /// route returns above `outsideFloor`.
    function _hybrid(bytes32 ref, uint256 q) internal view returns (ISCaaSDex.HybridPlan memory p, uint256 recv) {
        ITradeToken.TradeOrder memory me = _order(erin, WETH, 1000e6, 1000e6 * 1e18 / q, 0);
        ITradeToken.TradeOrder memory mf = _order(frank, WETH, 1000e6, 1000e6 * 1e18 / q, 0);
        recv = (1000e6 * me.receiveAmount + me.amount - 1) / me.amount;
        uint256 sell = 2 * recv + 1 ether;
        p.ref = ref;
        p.outsideSell = 1 ether;
        p.outsideFloor = _buffered(q);
        p.taker = _leg(DAVE_PK, WETH, _order(dave, USDC, sell, (2000e6 + p.outsideFloor) * 95 / 100, FEE), sell);
        p.makers = new ISCaaSDex.Leg[](2);
        p.makers[0] = _leg(ERIN_PK, USDC, me, 1000e6);
        p.makers[1] = _leg(FRANK_PK, USDC, mf, 1000e6);
    }

    function _checkHybrid(ISCaaSDex.HybridPlan memory p, uint256 recv, uint256 q) internal view {
        uint256 fee = _fee(2000e6 + p.outsideFloor, FEE);
        assertGt(q, p.outsideFloor);
        assertEq(IERC20(USDC).balanceOf(dave), 2000e6 + q - fee);
        assertEq(IERC20(WETH).balanceOf(dave), 10 ether - p.taker.fill);
        assertEq(IERC20(WETH).balanceOf(erin), 10 ether + recv);
        assertEq(IERC20(WETH).balanceOf(frank), recv);
        assertEq(IERC20(USDC).balanceOf(erin), 99_000e6);
        assertEq(IERC20(USDC).balanceOf(frank), 99_000e6);
        assertEq(IERC20(USDC).balanceOf(treasury), fee);
        _clean();
    }

    /// `mtxHybrid`, the remainder through SwapRouter02 (WETH / USDC 0.05 %).
    function test_fork_hybrid_twoMakers_v3Remainder() public {
        ISCaaSDex.Interaction[] memory xs = _v3Router(WETH, USDC, 500, 1 ether, 0);
        uint256 q = _quoteA(WETH, 1 ether, USDC, xs);
        (ISCaaSDex.HybridPlan memory p, uint256 recv) = _hybrid("hy", q);
        vm.prank(relayer);
        dex.mtxHybrid(p, xs);
        _checkHybrid(p, recv, q);
    }

    /// The same plan through `mtxHybridVia` and the executor (one v3 hop WETH → USDC 0.05 %).
    function test_fork_hybridVia_executor() public {
        bytes memory data = _hops(_v3Hop(WETH, USDC, 500));
        uint256 q = _quoteB(WETH, 1 ether, USDC, data);
        (ISCaaSDex.HybridPlan memory p, uint256 recv) = _hybrid("hyv", q);
        vm.prank(relayer);
        dex.mtxHybridVia(p, address(ex), data);
        _checkHybrid(p, recv, q);
    }

    // ------------------------------------------------------------------ (4) a SCaaS token into its real v2 pair

    /// A real v2 TOK / WETH pair created on the fork (100 000 TOK, 50 WETH); alice sells 1000 TOK for WETH through
    /// Router02. The DEX approves the router (both contracts, CTR-TOK-01); the allowance is 0 again after the route.
    function test_fork_scaasTokenIntoRealV2Pair() public {
        address pair = IV2Factory(V2_FACTORY).createPair(address(tok), WETH);
        vm.prank(alice);
        tok.transfer(pair, 100_000e18);
        deal(WETH, pair, 50 ether);
        IV2Pair(pair).mint(alice);
        uint256 q = IV2Router(V2_ROUTER).getAmountsOut(1000e18, _path(address(tok), WETH))[1];
        uint256 floor = _buffered(q);
        ITradeToken.TradeOrder memory o = _order(alice, WETH, 1000e18, floor * 95 / 100, FEE);
        vm.prank(relayer);
        dex.mtxExchange(_plan("tok", _xLeg(ALICE_PK, address(tok), o, 1000e18, floor)),
            _v2Router(address(tok), WETH, 1000e18, floor));
        assertEq(IERC20(WETH).balanceOf(alice), q - _fee(floor, FEE));
        assertEq(tok.balanceOf(alice), 1_000_000e18 - 101_000e18);
        assertEq(tok.balanceOf(pair), 101_000e18);
        _clean();
    }

    // ------------------------------------------------------------------ (5) mode 4, partial CoW

    /// dave sells 1 WETH for USDC, erin 1000 USDC for WETH. At the route's 1-WETH price q1 erin's USDC meet
    /// ⌊1000e6 · 1e18 / q1⌋ of dave's WETH inside the plan; only the net WETH goes through SwapRouter02. Floors: erin the
    /// matched WETH (excess 0), dave 1000 USDC + the net's buffered quote; dave gets every USDC above it.
    function test_fork_partialCow_netThroughV3() public {
        uint256 internalW = 1000e6 * 1e18 / _quoteA(WETH, 1 ether, USDC, _v3Router(WETH, USDC, 500, 1 ether, 0));
        ISCaaSDex.Interaction[] memory xs = _v3Router(WETH, USDC, 500, 1 ether - internalW, 0);
        uint256 qn = _quoteA(WETH, 1 ether - internalW, USDC, xs);
        uint256 fa = 1000e6 + _buffered(qn);
        ISCaaSDex.ExchangePlan memory p = _plan("cow",
            _xLeg(DAVE_PK, WETH, _order(dave, USDC, 1 ether, fa * 95 / 100, FEE), 1 ether, fa),
            _xLeg(ERIN_PK, USDC, _order(erin, WETH, 1000e6, internalW * 99 / 100, 0), 1000e6, internalW));
        vm.prank(relayer);
        dex.mtxExchange(p, xs);
        assertEq(IERC20(USDC).balanceOf(dave), 1000e6 + qn - _fee(fa, FEE));
        assertEq(IERC20(WETH).balanceOf(dave), 9 ether);
        assertEq(IERC20(WETH).balanceOf(erin), 10 ether + internalW);
        assertEq(IERC20(USDC).balanceOf(erin), 99_000e6);
        assertEq(dex.pulled(dex.dexOrderDigest(WETH, abi.decode(p.legs[0].order, (ITradeToken.TradeOrder)))), 1 ether);
        assertEq(dex.pulled(dex.dexOrderDigest(USDC, abi.decode(p.legs[1].order, (ITradeToken.TradeOrder)))), 1000e6);
        _clean();
    }

    // ------------------------------------------------------------------ (6) Universal Router via Permit2 refused

    /// The Universal Router pulls through Permit2, which needs a Permit2 `approve`: path (a) refuses that selector, so
    /// the plan reverts at that interaction and nothing moves.
    function test_fork_universalRouterPermit2_refused() public {
        ITradeToken.TradeOrder memory o = _order(dave, USDC, 1 ether, 1000e6, FEE);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](3);
        xs[0] = ISCaaSDex.Interaction(WETH, abi.encodeCall(IERC20.approve, (PERMIT2, 1 ether)));
        xs[1] = ISCaaSDex.Interaction(PERMIT2,
            abi.encodeCall(IPermit2.approve, (WETH, UNIVERSAL_ROUTER, uint160(1 ether), uint48(block.timestamp + 300))));
        bytes[] memory inputs = new bytes[](1); // V3_SWAP_EXACT_IN (command 0x00), payer the DEX through Permit2
        inputs[0] = abi.encode(address(dex), 1 ether, 0, abi.encodePacked(WETH, uint24(500), USDC), true);
        xs[2] = ISCaaSDex.Interaction(UNIVERSAL_ROUTER,
            abi.encodeCall(IUniversalRouter.execute, (hex"00", inputs, block.timestamp + 300)));
        ISCaaSDex.ExchangePlan memory p = _plan("ur", _xLeg(DAVE_PK, WETH, o, 1 ether, 2000e6));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, PERMIT2, IPermit2.approve.selector));
        dex.mtxExchange(p, xs);
        assertEq(IERC20(WETH).balanceOf(dave), 10 ether);
        assertEq(IERC20(USDC).balanceOf(dave), 0);
        assertEq(dex.pulled(dex.dexOrderDigest(WETH, o)), 0);
        _clean();
    }
}
