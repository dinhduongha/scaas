// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {console2} from "forge-std/console2.sol";
import {OnchainBase} from "./OnchainBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken, ILiquidityPullToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {V4PositionReader} from "../../src/dex/V4PositionReader.sol";
import {SCaaSDexLiquidityModule} from "../../src/dex/SCaaSDexLiquidityModule.sol";
import {PoolKey} from "../../src/dex/uniswap/IUniswapV4.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";
import {MockV2Factory, MockV2LiquidityPair, MockPositionManagerV4, MockOldDex} from "../../test/liquidity/LiquidityMocks.sol";

/// @notice Group `liquidity` (spec 2026-11-10-dex-liquidity.md §15; owner Step 5b rules 2026-11-10): a DEX created by the deployed
///         factory, two `NORMAL` tokens, an outside MockERC20, the TEST ONLY v2-style factory and v4-style position manager
///         with its reader (no Uniswap on a test chain), and the rows D-L1 (create a pair as the first interaction, then add
///         two SCaaS inputs; LP to a second address), D-L2 (SCaaS + outside, fee > 0 and the split), D-L4 (withdraw the LP),
///         D-L5 (v4 mock: mint a position through the reader, NFT to the recipient), D-L6 (a partial withdraw signed as the
///         received position, then a whole one that burns), D-L7 / D-L9 negatives (listed for `coverage.py neg`), D-L8 views
///         and wiring. D-L3 (a derived p256 UA) is not run here: it needs a registered p256 key on the target (the `misc`
///         group registers the vector UAs). Signed by k1 (alice) and k2 (carol), submitted by k3. Public addresses and hashes
///         only are printed. UNAUDITED.
contract Liquidity is OnchainBase {
    address constant TREASURY = address(0x7EA5);
    uint256 constant G = 3_000_000;
    int24 constant LO = -600;
    int24 constant HI = 600;

    OpenFactory f;
    ISCaaSDex dex;
    address A;
    address B;
    MockERC20 usdc;
    MockV2Factory v2f;
    MockPositionManagerV4 posm;
    V4PositionReader reader;
    address puller;
    uint256 n; // order nonce counter

    function run() external {
        _init("liquidity");
        f = OpenFactory(_dep("token_factory"));
        _book(address(f), "OpenFactory");
        _setup();
        console2.log(string.concat("liquidity: DEX ", vm.toString(address(dex)), ", tokens ", vm.toString(A), " ", vm.toString(B)));
        address pair = _addCreatePair();
        _addOutside();
        _withdraw(pair);
        _v4();
        _views(pair);
        _writeBook();
    }

    function _setup() internal {
        A = _normal("Onchain Liq A", "oLA");
        B = _normal("Onchain Liq B", "oLB");
        usdc = MockERC20(_create2(abi.encodePacked(type(MockERC20).creationCode, abi.encode("Onchain USD L", "oUSDL", uint8(6))), "usdc"));
        v2f = MockV2Factory(_create2(type(MockV2Factory).creationCode, "v2f"));
        posm = MockPositionManagerV4(_create2(type(MockPositionManagerV4).creationCode, "posm"));
        reader = V4PositionReader(_create2(abi.encodePacked(type(V4PositionReader).creationCode, abi.encode(address(posm))), "reader"));
        _book(address(usdc), "MockERC20");
        _book(address(v2f), "MockV2Factory");
        _book(address(posm), "MockPositionManagerV4");
        _book(address(reader), "V4PositionReader");
        bytes memory cfg = abi.encode(ISCaaSDex.DexConfig(_pad(a1), 200_000, TREASURY, false, 0, address(0)));
        vm.broadcast(k1);
        dex = ISCaaSDex(f.createDex(1, cfg, _salt("dex")));
        _book(address(dex), "SCaaSDex");
        puller = dex.puller();
        vm.startBroadcast(k1);
        dex.setMarket{gas: G}(A, B, true);
        dex.setMarket{gas: G}(A, address(usdc), true);
        dex.setExchangeTarget{gas: G}(address(reader), true);
        usdc.mint(a1, 1e12);
        usdc.approve{gas: G}(puller, type(uint256).max);
        vm.stopBroadcast();
    }

    function _normal(string memory name, string memory symbol) internal returns (address t) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals) = (name, symbol, 6);
        c.features = 1 << GovernanceBits.PAYABLE;
        c.admin = _pad(a1);
        (c.initialSupply, c.initialHolder) = (1e12, a1);
        vm.broadcast(k1);
        t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), _salt(symbol));
        _book(t, "NormalToken");
    }

    function _create2(bytes memory init, string memory what) internal returns (address a) {
        bytes32 s = _salt(what);
        a = vm.computeCreate2Address(s, keccak256(init), CREATE2_FACTORY);
        vm.broadcast(k1);
        // 30 M: the ERC-721 position manager's code deposit under Amsterdam ran out of 11 M (the first local run); within 60 M
        (bool ok,) = CREATE2_FACTORY.call{gas: 30_000_000}(abi.encodePacked(s, init));
        require(ok && a.code.length != 0, what);
    }

    // ------------------------------------------------------------------ orders

    function _order(address from, address to) internal returns (ITradeToken.LiquidityOrder memory o) {
        (o.from, o.recipient, o.fee, o.relayer, o.batch, o.nonce, o.validUntil) =
            (_pad(from), _pad(to), 3_000, a3, 11, ++n, vu);
    }

    function _tk(address t, uint256 amount) internal pure returns (ITradeToken.LiquidityToken memory) {
        return ITradeToken.LiquidityToken(t, amount);
    }

    function _plan(ITradeToken.LiquidityOrder memory o, uint256 pk, uint256[] memory pull)
        internal view returns (ISCaaSDex.LiquidityPlan memory p)
    {
        (p.ref, p.order, p.auth, p.pull) = (_salt(vm.toString(o.nonce)), o, _sig(pk, dex.liquidityOrderDigest(o)), pull);
    }

    function _ix(address t, bytes memory d) internal pure returns (ISCaaSDex.Interaction memory) {
        return ISCaaSDex.Interaction(t, d);
    }

    function _send(ISCaaSDex.LiquidityPlan memory p, ISCaaSDex.Interaction[] memory xs, string memory row) internal {
        vm.broadcast(k3);
        dex.mtxLiquidity{gas: 30_000_000}(p, xs); // D-L1 CREATEs a pair inside: its Amsterdam code deposit
        console2.log(string.concat("ok ", row, " h=", vm.toString(dex.liquidityOrderDigest(p.order))));
    }

    /// D-L1: `createPair` as the first interaction, then two SCaaS inputs; the LP to a2.
    function _addCreatePair() internal returns (address pair) {
        pair = vm.computeCreateAddress(address(v2f), vm.getNonce(address(v2f)));
        ITradeToken.LiquidityOrder memory o = _order(a1, a2);
        o.inputs = new ITradeToken.LiquidityToken[](2);
        (o.inputs[0], o.inputs[1]) = (_tk(A, 1e6), _tk(B, 1e6));
        o.outputs = new ITradeToken.LiquidityToken[](1);
        o.outputs[0] = _tk(pair, 9e5);
        uint256[] memory pull = new uint256[](2);
        (pull[0], pull[1]) = (1e6, 1e6);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](4);
        xs[0] = _ix(address(v2f), abi.encodeCall(MockV2Factory.createPair, (A, B)));
        xs[1] = _ix(A, abi.encodeCall(IERC20.transfer, (pair, 1e6)));
        xs[2] = _ix(B, abi.encodeCall(IERC20.transfer, (pair, 1e6)));
        xs[3] = _ix(pair, abi.encodeCall(MockV2LiquidityPair.mint, (address(dex))));
        _send(_plan(o, k1, pull), xs, "D-L1");
        _book(pair, "MockV2LiquidityPair");
        // D-L7: a replay of the same order is refused (OrderClosed), listed as a negative
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.mtxLiquidity, (_plan(o, k1, pull), xs)), ISCaaSDex.OrderClosed.selector,
            "liquidity: a replay of an executed order");
    }

    /// D-L2: one SCaaS and one outside input (the puller; the DEX verifies), fee 0.3 % split.
    function _addOutside() internal {
        vm.broadcast(k1);
        address p2 = v2f.createPair{gas: 30_000_000}(A, address(usdc));
        _book(p2, "MockV2LiquidityPair");
        ITradeToken.LiquidityOrder memory o = _order(a1, a2);
        o.inputs = new ITradeToken.LiquidityToken[](2);
        (o.inputs[0], o.inputs[1]) = (_tk(A, 1e6), _tk(address(usdc), 1e6));
        o.outputs = new ITradeToken.LiquidityToken[](1);
        o.outputs[0] = _tk(p2, 9e5);
        uint256[] memory pull = new uint256[](2);
        (pull[0], pull[1]) = (1e6, 1e6);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](3);
        xs[0] = _ix(A, abi.encodeCall(IERC20.transfer, (p2, 1e6)));
        xs[1] = _ix(address(usdc), abi.encodeCall(IERC20.transfer, (p2, 1e6)));
        xs[2] = _ix(p2, abi.encodeCall(MockV2LiquidityPair.mint, (address(dex))));
        _send(_plan(o, k1, pull), xs, "D-L2");
    }

    /// D-L4: a2 withdraws its LP of the A/B pair for both tokens (LP through the puller).
    function _withdraw(address pair) internal {
        uint256 lp = IERC20(pair).balanceOf(a2);
        vm.broadcast(k2);
        IERC20(pair).approve{gas: G}(puller, lp);
        ITradeToken.LiquidityOrder memory o = _order(a2, a2);
        o.inputs = new ITradeToken.LiquidityToken[](1);
        o.inputs[0] = _tk(pair, lp);
        o.outputs = new ITradeToken.LiquidityToken[](2);
        (o.outputs[0], o.outputs[1]) = (_tk(A, 1), _tk(B, 1));
        uint256[] memory pull = new uint256[](1);
        pull[0] = lp;
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](2);
        xs[0] = _ix(pair, abi.encodeCall(IERC20.transfer, (pair, lp)));
        xs[1] = _ix(pair, abi.encodeCall(MockV2LiquidityPair.burn, (address(dex))));
        _send(_plan(o, k2, pull), xs, "D-L4");
    }

    function _key() internal view returns (PoolKey memory) {
        return PoolKey(A, B, 3000, 60, address(0));
    }

    /// D-L5, D-L6: mint through the reader (NFT to a2), a partial withdraw signed as the received position, a whole one that burns.
    function _v4() internal {
        uint256 id = posm.nextId();
        ITradeToken.LiquidityOrder memory o = _order(a1, a2);
        o.inputs = new ITradeToken.LiquidityToken[](2);
        (o.inputs[0], o.inputs[1]) = (_tk(A, 5e5), _tk(B, 5e5));
        (o.positionManager, o.positionReader, o.positionPool) = (address(posm), address(reader), keccak256(abi.encode(_key())));
        (o.tickLower, o.tickUpper, o.minLiquidity) = (LO, HI, 4e5);
        uint256[] memory pull = new uint256[](2);
        (pull[0], pull[1]) = (5e5, 5e5);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](3);
        xs[0] = _ix(A, abi.encodeCall(IERC20.transfer, (address(posm), 5e5)));
        xs[1] = _ix(B, abi.encodeCall(IERC20.transfer, (address(posm), 5e5)));
        xs[2] = _ix(address(posm), abi.encodeCall(MockPositionManagerV4.mint, (_key(), LO, HI, 4e5, address(dex), address(dex))));
        ISCaaSDex.LiquidityPlan memory p = _plan(o, k1, pull);
        p.positionId = id;
        _send(p, xs, "D-L5");
        // D-L7: an unlisted reader is refused (listed as a negative against a fresh order)
        ITradeToken.LiquidityOrder memory bad = _order(a1, a2);
        bad.inputs = o.inputs;
        (bad.positionManager, bad.positionReader, bad.positionPool) = (address(posm), address(0xBEEF), o.positionPool);
        (bad.tickLower, bad.tickUpper, bad.minLiquidity) = (LO, HI, 4e5);
        ISCaaSDex.LiquidityPlan memory bp = _plan(bad, k1, pull);
        bp.positionId = posm.nextId();
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.mtxLiquidity, (bp, xs)), ISCaaSDex.PositionReaderNotListed.selector,
            "liquidity: an unlisted position reader");
        // D-L6: a2 gives the position and receives it back with at least 3e5 (a partial withdraw of 1e5)
        vm.broadcast(k2);
        posm.approve{gas: G}(puller, id);
        ITradeToken.LiquidityOrder memory w = _order(a2, a2);
        w.outputs = new ITradeToken.LiquidityToken[](2);
        (w.outputs[0], w.outputs[1]) = (_tk(A, 9e4), _tk(B, 9e4));
        (w.positionManager, w.positionReader, w.positionIn, w.positionPool) = (address(posm), address(reader), id, o.positionPool);
        (w.tickLower, w.tickUpper, w.minLiquidity) = (LO, HI, 3e5);
        ISCaaSDex.LiquidityPlan memory wp = _plan(w, k2, new uint256[](0));
        wp.positionId = id;
        ISCaaSDex.Interaction[] memory dx = new ISCaaSDex.Interaction[](1);
        dx[0] = _ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 1e5, address(dex))));
        _send(wp, dx, "D-L6 partial");
        // the whole rest, burnt: no position received, the given one spent whole
        vm.broadcast(k2);
        posm.approve{gas: G}(puller, id);
        ITradeToken.LiquidityOrder memory z = _order(a2, a2);
        z.outputs = w.outputs;
        (z.positionManager, z.positionIn) = (address(posm), id);
        ISCaaSDex.Interaction[] memory zx = new ISCaaSDex.Interaction[](2);
        zx[0] = _ix(address(posm), abi.encodeCall(MockPositionManagerV4.decrease, (id, 3e5, address(dex))));
        zx[1] = _ix(address(posm), abi.encodeCall(MockPositionManagerV4.burn, (id)));
        _send(_plan(z, k2, new uint256[](0)), zx, "D-L6 whole");
    }

    /// D-L8, D-L9: views and wiring; the negatives a contract without `liquidityOrderDigest` and an EOA meet on a token.
    function _views(address pair) internal {
        address[] memory ms = SCaaSDexLiquidityModuleLike(address(dex)).modules();
        require(ms.length == 2, "modules");
        _book(ms[1], "SCaaSDexLiquidityModule");
        require(ILiquidityPullTokenLike(A).supportsInterface(type(ILiquidityPullToken).interfaceId), "interface");
        ITradeToken.LiquidityOrder memory o = _order(a1, a2);
        o.inputs = new ITradeToken.LiquidityToken[](1);
        o.inputs[0] = _tk(A, 1);
        o.outputs = new ITradeToken.LiquidityToken[](1);
        o.outputs[0] = _tk(pair, 1);
        IUARegistry.UASig memory s = _sig(k1, dex.liquidityOrderDigest(o));
        _neg(a3, ms[1], abi.encodeCall(SCaaSDexLiquidityModule.liquidityOrderDigest, (o)),
            SCaaSDexLiquidityModule.NotDelegated.selector, "liquidity: the module called directly");
        _neg(a3, A, abi.encodeCall(ILiquidityPullToken.mtxLiquidityPull, (o, s, 1, a3)), ITradeToken.DexNotContract.selector,
            "liquidity: a token's mtxLiquidityPull called by an EOA");
        address old = _create2(type(MockOldDex).creationCode, "olddex");
        _book(old, "MockOldDex");
        _neg(a3, old, abi.encodeCall(MockOldDex.run, (A, o, s, 1, a3)), ITradeToken.NotLiquidityDex.selector,
            "liquidity: a contract without liquidityOrderDigest cannot make a token pull");
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](1);
        xs[0] = _ix(A, abi.encodeCall(ILiquidityPullToken.mtxLiquidityPull, (o, s, 1, a3)));
        uint256[] memory pull = new uint256[](1);
        pull[0] = 1;
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.mtxLiquidity, (_plan(o, k1, pull), xs)),
            ISCaaSDex.ForbiddenSelector.selector, "liquidity: mtxLiquidityPull inside an interaction");
    }
}

interface SCaaSDexLiquidityModuleLike {
    function modules() external view returns (address[] memory);
}

interface ILiquidityPullTokenLike {
    function supportsInterface(bytes4 id) external view returns (bool);
}
