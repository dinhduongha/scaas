// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {V4PositionReader} from "../../src/dex/V4PositionReader.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {PoolKey} from "../../src/dex/uniswap/IUniswapV4.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, normalInit} from "../v2/helpers/V2Fixture.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {MockV2Factory, MockV2LiquidityPair, MockPositionManagerV4} from "./LiquidityMocks.sol";

/// The liquidity fixture (spec 2026-11-10-dex-liquidity.md §14): a factory with the `NORMAL` and DEX releases; SCaaS `a`
/// and `b` (alice 1e9 each, carol 1e9 each), the outside `usdc` (alice, approved to the puller); a v2-style pair of `a`
/// and `b` from its factory; a v4-style position manager with its reader, listed. Orders are native-signed by alice
/// unless a test says otherwise; carol receives.
abstract contract LiquidityBase is Test {
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant CAROL_PK = 0xCA401;
    address internal alice = vm.addr(ALICE_PK);
    address internal carol = vm.addr(CAROL_PK);
    address internal admin = address(0xAD);
    address internal treasury = address(0x7EA5);
    address internal relayer = address(0xBEEF);
    address internal attacker = address(0xBAD);

    OpenFactory internal f;
    SCaaSDex internal dex;
    address internal puller;
    NormalToken internal a;
    NormalToken internal b;
    MockERC20 internal usdc;
    MockV2Factory internal v2f;
    MockV2LiquidityPair internal pair;
    MockPositionManagerV4 internal posm;
    V4PositionReader internal reader;

    function setUp() public virtual {
        f = EnvKit.factory(address(this), UID_, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        a = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            abi.encode(normalInit("A", "A", 0, 2e9, alice, address(0))), "a"));
        b = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1,
            abi.encode(normalInit("B", "B", 0, 2e9, alice, address(0))), "b"));
        dex = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(admin), 200_000, treasury, false, 0, address(0))),
            "dex"));
        puller = dex.puller();
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdc.mint(alice, 1e9);
        vm.startPrank(alice);
        usdc.approve(puller, type(uint256).max);
        a.transfer(carol, 1e9);
        b.transfer(carol, 1e9);
        vm.stopPrank();
        vm.startPrank(admin);
        dex.setMarket(address(a), address(b), true);
        dex.setMarket(address(usdc), address(b), true);
        vm.stopPrank();
        v2f = new MockV2Factory();
        pair = MockV2LiquidityPair(v2f.createPair(address(a), address(b)));
        posm = new MockPositionManagerV4();
        reader = new V4PositionReader(address(posm));
        vm.prank(admin);
        dex.setExchangeTarget(address(reader), true);
    }

    // ------------------------------------------------------------------ orders

    function _t(address token, uint256 amount) internal pure returns (ITradeToken.LiquidityToken memory) {
        return ITradeToken.LiquidityToken(token, amount);
    }

    function _one(ITradeToken.LiquidityToken memory x) internal pure returns (ITradeToken.LiquidityToken[] memory r) {
        r = new ITradeToken.LiquidityToken[](1);
        r[0] = x;
    }

    function _two(ITradeToken.LiquidityToken memory x, ITradeToken.LiquidityToken memory y)
        internal pure returns (ITradeToken.LiquidityToken[] memory r)
    {
        r = new ITradeToken.LiquidityToken[](2);
        (r[0], r[1]) = (x, y);
    }

    function _u(uint256 x) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = x;
    }

    function _u2(uint256 x, uint256 y) internal pure returns (uint256[] memory r) {
        r = new uint256[](2);
        (r[0], r[1]) = (x, y);
    }

    /// From alice to carol, bound to `relayer`, lane 7, fee 0.3 %, five minutes.
    function _base() internal view returns (ITradeToken.LiquidityOrder memory o) {
        o.from = nid(alice);
        o.recipient = nid(carol);
        o.fee = 3_000;
        o.relayer = relayer;
        o.batch = 7;
        o.validUntil = block.timestamp + 300;
    }

    /// The digest written out from the spec (§4.2, §4.3), independent of `LiquidityLib`.
    function _hashOrder(ITradeToken.LiquidityOrder memory o) internal pure returns (bytes32) {
        bytes32 th = keccak256("LiquidityToken(address token,uint256 amount)");
        bytes32[2] memory arr;
        for (uint256 k; k < 2; ++k) {
            ITradeToken.LiquidityToken[] memory ts = k == 0 ? o.inputs : o.outputs;
            bytes memory packed;
            for (uint256 i; i < ts.length; ++i) {
                packed = bytes.concat(packed, keccak256(abi.encode(th, ts[i].token, ts[i].amount)));
            }
            arr[k] = keccak256(packed);
        }
        bytes32 ot = keccak256(bytes.concat("LiquidityOrder(bytes32 from,LiquidityToken[] inputs,LiquidityToken[] outputs,",
            "address positionManager,address positionReader,uint256 positionIn,bytes32 positionPool,int24 tickLower,",
            "int24 tickUpper,uint128 minLiquidity,bytes32 recipient,uint256 fee,address relayer,uint8 flags,uint256 batch,",
            "uint256 nonce,uint256 validUntil)LiquidityToken(address token,uint256 amount)"));
        return keccak256(bytes.concat(abi.encode(ot, o.from, arr[0], arr[1], o.positionManager, o.positionReader,
            o.positionIn, o.positionPool, o.tickLower), abi.encode(o.tickUpper, o.minLiquidity, o.recipient, o.fee,
            o.relayer, o.flags, o.batch, o.nonce, o.validUntil)));
    }

    /// `h` in the DEX domain of `verifyingContract` under this chain's `chain_uid`.
    function _digestFor(ITradeToken.LiquidityOrder memory o, address verifyingContract) internal view returns (bytes32) {
        bytes32 sep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS Dex"), keccak256("1"), block.chainid, verifyingContract, a.chainUid()));
        return keccak256(abi.encodePacked(hex"1901", sep, _hashOrder(o)));
    }

    function _sigFor(ITradeToken.LiquidityOrder memory o, uint256 pk, address verifyingContract)
        internal view returns (IUARegistry.UASig memory s)
    {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, _digestFor(o, verifyingContract));
        s.signature = abi.encodePacked(r, ss, v);
    }

    function _sig(ITradeToken.LiquidityOrder memory o, uint256 pk) internal view returns (IUARegistry.UASig memory s) {
        (uint8 v, bytes32 r, bytes32 ss) = vm.sign(pk, dex.liquidityOrderDigest(o));
        s.signature = abi.encodePacked(r, ss, v);
    }

    function _plan(ITradeToken.LiquidityOrder memory o, uint256 pk, uint256[] memory pull)
        internal view returns (ISCaaSDex.LiquidityPlan memory p)
    {
        p.ref = "liq";
        p.order = o;
        p.auth = _sig(o, pk);
        p.pull = pull;
    }

    function _ix(address target, bytes memory data) internal pure returns (ISCaaSDex.Interaction memory) {
        return ISCaaSDex.Interaction(target, data);
    }

    function _xs(ISCaaSDex.Interaction memory x) internal pure returns (ISCaaSDex.Interaction[] memory r) {
        r = new ISCaaSDex.Interaction[](1);
        r[0] = x;
    }

    function _xs2(ISCaaSDex.Interaction memory x, ISCaaSDex.Interaction memory y)
        internal pure returns (ISCaaSDex.Interaction[] memory r)
    {
        r = new ISCaaSDex.Interaction[](2);
        (r[0], r[1]) = (x, y);
    }

    function _xs3(ISCaaSDex.Interaction memory x, ISCaaSDex.Interaction memory y, ISCaaSDex.Interaction memory z)
        internal pure returns (ISCaaSDex.Interaction[] memory r)
    {
        r = new ISCaaSDex.Interaction[](3);
        (r[0], r[1], r[2]) = (x, y, z);
    }

    function _run(ISCaaSDex.LiquidityPlan memory p, ISCaaSDex.Interaction[] memory xs) internal {
        vm.prank(relayer);
        dex.mtxLiquidity(p, xs);
    }

    // ------------------------------------------------------------------ the standard v2 add

    uint256 internal constant ADD = 100_000; // of each side: first LP = sqrt(ADD²) − 1000 = 99 000
    uint256 internal constant LP_FIRST = 99_000;

    /// Alice gives up to `ADD` of `a` and `b`, carol receives at least `minLp` LP after the fee.
    function _addOrder(uint256 minLp) internal view returns (ITradeToken.LiquidityOrder memory o) {
        o = _base();
        o.inputs = _two(_t(address(a), ADD), _t(address(b), ADD));
        o.outputs = _one(_t(address(pair), minLp));
    }

    /// `a.transfer(pair, x)`, `b.transfer(pair, y)`, `pair.mint(to)`.
    function _addXs(uint256 x, uint256 y, address to) internal view returns (ISCaaSDex.Interaction[] memory) {
        return _xs3(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(pair), x))),
            _ix(address(b), abi.encodeCall(IERC20.transfer, (address(pair), y))),
            _ix(address(pair), abi.encodeCall(MockV2LiquidityPair.mint, (to))));
    }

    function _addPlan(uint256 minLp) internal view returns (ISCaaSDex.LiquidityPlan memory) {
        return _plan(_addOrder(minLp), ALICE_PK, _u2(ADD, ADD));
    }

    // ------------------------------------------------------------------ the v4-style position

    int24 internal constant LO = -600; // a negative tick (sign extension)
    int24 internal constant HI = 600;

    function _key() internal view returns (PoolKey memory) {
        return PoolKey(address(a), address(b), 3000, 60, address(0));
    }

    /// Alice deposits up to 50 k of each into a new position of `liq`, carol receives it (at least `minLiq`).
    function _mintOrder(uint128 minLiq) internal view returns (ITradeToken.LiquidityOrder memory o) {
        o = _base();
        o.inputs = _two(_t(address(a), 50_000), _t(address(b), 50_000));
        o.positionManager = address(posm);
        o.positionReader = address(reader);
        o.positionPool = posm.poolId(_key());
        (o.tickLower, o.tickUpper, o.minLiquidity) = (LO, HI, minLiq);
    }

    function _mintXs(uint128 liq, address owner) internal view returns (ISCaaSDex.Interaction[] memory) {
        return _xs3(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(posm), 50_000))),
            _ix(address(b), abi.encodeCall(IERC20.transfer, (address(posm), 50_000))),
            _ix(address(posm), abi.encodeCall(MockPositionManagerV4.mint, (_key(), LO, HI, liq, owner, address(dex)))));
    }

    /// Mints a 40 k position to carol through the DEX; returns its id.
    function _carolPosition() internal returns (uint256 id) {
        id = posm.nextId();
        ISCaaSDex.LiquidityPlan memory p = _plan(_mintOrder(40_000), ALICE_PK, _u2(50_000, 50_000));
        p.positionId = id;
        _run(p, _mintXs(40_000, address(dex)));
        vm.prank(carol);
        posm.approve(puller, id);
    }

    /// Carol gives position `id` and receives it back with at least `minLiq` and at least `out` of each token.
    function _returnOrder(uint256 id, uint128 minLiq, uint256 out) internal view returns (ISCaaSDex.LiquidityPlan memory p) {
        ITradeToken.LiquidityOrder memory o = _base();
        o.from = nid(carol);
        o.outputs = _two(_t(address(a), out), _t(address(b), out));
        o.positionManager = address(posm);
        o.positionReader = address(reader);
        o.positionIn = id;
        o.positionPool = posm.poolId(_key());
        (o.tickLower, o.tickUpper, o.minLiquidity) = (LO, HI, minLiq);
        p = _plan(o, CAROL_PK, new uint256[](0));
        p.positionId = id;
    }
}
