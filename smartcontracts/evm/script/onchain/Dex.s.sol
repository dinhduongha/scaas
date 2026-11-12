// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {OnchainBase} from "./OnchainBase.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {ISCaaSDex, IExchangeExecutor} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";

/// @notice `SCaaSDex.settleOne`, the self-call entry `ISCaaSDex` does not declare (for its negative).
interface ISettleOne {
    function settleOne(ISCaaSDex.Settlement calldata s, address submitter) external;
}

/// @notice TEST ONLY fixture, never a product contract: a v3-style router for the exchange path (a). Pulls `amountIn` from
///         the caller under its allowance and pays `amountOut` of `tOut` to `to` from its own inventory (copied from
///         test/v2/DexExchange.t.sol `MockRouter`, without the quirks).
contract OnchainRouter {
    function swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut, address to) external returns (uint256) {
        IERC20(tIn).transferFrom(msg.sender, address(this), amountIn);
        IERC20(tOut).transfer(to, amountOut);
        return amountOut;
    }
}

/// @notice TEST ONLY fixture: an executor of the exchange path (b): pays each floor plus `abi.decode(data, (int256))` from its
///         own inventory (test/v2/DexExchange.t.sol `MockExecutor`, without the optional call).
contract OnchainExecutor is IExchangeExecutor {
    function exchangeCallback(bytes32, address[] calldata, uint256[] calldata, address[] calldata tokensIn,
        uint256[] calldata amountsIn, bytes calldata data) external
    {
        int256 bonus = abi.decode(data, (int256));
        for (uint256 i; i < tokensIn.length; ++i) IERC20(tokensIn[i]).transfer(msg.sender, uint256(int256(amountsIn[i]) + bonus));
    }
}

/// @notice T66b Step 5b, group `dex`: a DEX created by the Step 5 factory (`createDex`, its module D through the DEX's
///         governance stubs) and tokens created by `createToken` (kinds 0, 1 on a MockERC20 leg, 1 on a SCaaS leg, 8);
///         every DEX entry, the token trade entries (mtxTrade and restorePulled reached through the DEX, mtxCancelOrder,
///         mtxInvalidateNonces, mtxWrapOrder; then mtxTrade, restorePulled, mtxCancelOrder and mtxWrapOrder on a token of
///         each of the kinds 1, 2, 3, 8-11), negatives listed for `coverage.py neg`. Orders are signed by k1 (and k2, k3
///         for their own legs), submitted by k2 or k3. UNAUDITED.
contract Dex is OnchainBase {
    address constant TREASURY = address(0x7EA5);
    uint128 constant MAXW = type(uint128).max;
    /// @dev The gas limit of every trade, cancel, governance and fixture transaction, set by the call (forge sends it as
    ///      given): forge's estimate x 1.10 fell short on this Amsterdam chain in the first local runs (a top-level CREATE
    ///      out of gas, so fixtures go through the CREATE2 deployer; an mtxExchange whose `approve` interaction ran out of
    ///      gas at 436,790 asked; a cancelGrant whose SSTORE refund the estimate nets out, out of gas at 64,475). 3 M, 8 M
    ///      for a fixture: far within the 60 M asked of the rule and the block.
    uint256 constant G = 3_000_000;

    OpenFactory f;
    ISCaaSDex dex;
    ISCaaSDex dex2;
    address A; // NormalToken, a1
    address B; // NormalToken, a2
    address W; // WrappedToken over usdc, a1 wraps
    address W2; // WrappedToken over A (the wrap order)
    address R; // NormalRegulatedToken, a2
    MockERC20 usdc; // outside token, a1 and a3
    OnchainRouter router;
    OnchainRouter router2; // never listed
    OnchainExecutor exec;
    uint256 on; // order nonce counter
    ITradeToken.UATradeOrder cancelled;

    function run() external {
        _init("dex");
        f = OpenFactory(_dep("token_factory"));
        _book(address(f), "OpenFactory");
        string memory rel = _envBook("RELEASES_JSON", bookUid, "-releases.json");
        _book(vm.parseJsonAddress(rel, ".SCaaSDexGovernanceModule.address"), "SCaaSDexGovernanceModule");
        _book(vm.parseJsonAddress(rel, ".SCaaSDexLiquidityModule.address"), "SCaaSDexLiquidityModule");
        _setup();
        _admin();
        _settle();
        _exchange();
        _hybrid();
        _cancels();
        _wrapOrder();
        _kinds();
        _gov();
        _negatives();
        _writeBook();
    }

    // ------------------------------------------------------------------ setup

    function _setup() internal {
        A = _normal("Onchain Dex A", "oDA", a1);
        B = _normal("Onchain Dex B", "oDB", a2);
        usdc = MockERC20(_create2(abi.encodePacked(type(MockERC20).creationCode, abi.encode("Onchain USD", "oUSD", uint8(6))), "usdc"));
        _book(address(usdc), "MockERC20");
        vm.startBroadcast(k1);
        usdc.mint(a1, 1e12);
        usdc.mint(a3, 1e12);
        vm.stopBroadcast();
        W = _wrapped("Onchain Dex W", "oDW", address(usdc));
        W2 = _wrapped("Onchain Dex W2", "oDW2", A);
        R = _regulated();
        dex = _dex(0, "dex");
        dex2 = _dex(3600, "dex2");
        router = OnchainRouter(_create2(type(OnchainRouter).creationCode, "router"));
        router2 = OnchainRouter(_create2(type(OnchainRouter).creationCode, "router2"));
        exec = OnchainExecutor(_create2(type(OnchainExecutor).creationCode, "exec"));
        vm.startBroadcast(k1);
        usdc.approve(W, 1e9);
        IWrappedToken(W).wrap(1e9);
        IERC20(A).transfer(address(router), 1e8);
        IERC20(A).transfer(address(exec), 1e8);
        vm.stopBroadcast();
        vm.startBroadcast(k2);
        IERC20(B).transfer(address(router), 1e8);
        IERC20(B).transfer(address(exec), 1e8);
        vm.stopBroadcast();
        address puller = _puller();
        vm.broadcast(k3);
        usdc.approve(puller, type(uint256).max);
    }

    /// @dev A fixture through the deterministic CREATE2 deployer, not a top-level CREATE: forge's estimate of a top-level
    ///      CREATE on this Amsterdam chain falls short (the new-account state gas, about 184 k, is not in it: the first
    ///      run's OnchainRouter ran out of gas at the estimate x 1.10), a nested CREATE's estimate covers it.
    function _create2(bytes memory init, string memory what) internal returns (address a) {
        bytes32 s = _salt(what);
        a = vm.computeCreate2Address(s, keccak256(init), CREATE2_FACTORY);
        vm.broadcast(k1);
        (bool ok,) = CREATE2_FACTORY.call{gas: 2 * G + 2_000_000}(abi.encodePacked(s, init)); // MockERC20: 3.4 M
        require(ok && a.code.length != 0, what);
    }

    function _puller() internal view returns (address) {
        (bool ok, bytes memory r) = address(dex).staticcall(abi.encodeWithSignature("puller()"));
        require(ok, "puller");
        return abi.decode(r, (address));
    }

    function _base(string memory name, string memory symbol) internal pure returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals) = (name, symbol, 6);
        c.features = 1 << GovernanceBits.PAYABLE;
    }

    function _normal(string memory name, string memory symbol, address holder) internal returns (address t) {
        IFactoryToken.TokenConfig memory c = _base(name, symbol);
        c.admin = _pad(a1);
        (c.initialSupply, c.initialHolder) = (1e12, holder);
        vm.broadcast(k1);
        t = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), _salt(symbol));
        _book(t, "NormalToken");
    }

    function _wrapped(string memory name, string memory symbol, address leg) internal returns (address t) {
        IFactoryToken.TokenConfig memory c = _base(name, symbol);
        c.admin = _pad(a1);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        vm.broadcast(k1);
        t = f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), _salt(symbol));
        _book(t, "WrappedToken");
    }

    function _regulated() internal returns (address t) {
        IFactoryToken.TokenConfig memory c = _base("Onchain Dex R", "oDR");
        c.admin = _pad(a1);
        (c.initialSupply, c.initialHolder) = (1e12, a2);
        // no control set at creation; group 3s (CTR-GOV-24): a1's issuer seat holds the list bits 8, 9 (off, enableable), so
        // the token carries its terms (the `enableable` predicate); `_admin` lists the parties and switches the allow list on
        c.roles.issuer = _pad(a1);
        c.reg.termsHash = keccak256("onchain dex terms");
        vm.broadcast(k1);
        t = f.createToken(IOpenFactory.TokenKind.NORMAL_REGULATED, 1, abi.encode(c), _salt("oDR"));
        _book(t, "NormalRegulatedToken");
    }

    function _dex(uint64 grantDelay, string memory what) internal returns (ISCaaSDex d) {
        bytes memory cfg = abi.encode(ISCaaSDex.DexConfig(_pad(a1), 200_000, TREASURY, false, grantDelay, address(0), 0, 0));
        vm.broadcast(k1);
        d = ISCaaSDex(f.createDex(1, cfg, _salt(what)));
        _book(address(d), "SCaaSDex");
    }

    /// The DEX owner's own entries before the trades: markets, the fee split, listed targets (listed-only is set in `_gov`).
    function _admin() internal {
        vm.startBroadcast(k1);
        dex.setMarket{gas: G}(A, B, true);
        dex.setMarket{gas: G}(A, address(usdc), true);
        dex.setMarket{gas: G}(W, B, true);
        dex.setMarket{gas: G}(R, A, true);
        // group 3s (spec 2026-11-10-token-lists.md §4.4, §15 T8): R's allow list, written while off by a1's issuer seat: both
        // traders, the DEX and its puller listed like anyone else; then switched on at once (`FeatureEnabled(8)`)
        bytes32[] memory listed = new bytes32[](4);
        (listed[0], listed[1], listed[2], listed[3]) = (_pad(a1), _pad(a2), _pad(address(dex)), _pad(_puller()));
        IRegulatedToken(R).setAllowed{gas: G}(listed, true);
        IRegulatedToken(R).enableFeature{gas: G}(GovernanceBits.ALLOWLIST);
        dex.setFeeSplit{gas: G}(300_000, TREASURY);
        dex.setExchangeTarget{gas: G}(address(router), true);
        dex.setExchangeTarget{gas: G}(address(exec), true);
        vm.stopBroadcast();
    }

    // ------------------------------------------------------------------ orders and legs

    function _o(bytes32 from, address recv, uint256 amt, uint256 recvAmt, uint256 fee)
        internal returns (ITradeToken.UATradeOrder memory o)
    {
        (o.from, o.receiveToken, o.amount, o.receiveAmount, o.fee) = (from, recv, amt, recvAmt, fee);
        (o.dex, o.batch, o.nonce, o.validUntil) = (address(dex), 1, ++on, vu);
    }

    function _leg(address sell, ITradeToken.UATradeOrder memory o, uint256 pk, uint256 fill)
        internal view returns (ISCaaSDex.DexLeg memory l)
    {
        (l.sellToken, l.shape, l.uaOrder, l.fill) = (sell, 1, o, fill);
        l.auth.signature = _ecdsa(pk, ITradeToken(sell).tradeOrderDigest(o));
    }

    function _outside(address from, address recv, uint256 amt, uint256 recvAmt)
        internal returns (ITradeToken.TradeOrder memory o)
    {
        (o.from, o.receiveToken, o.amount, o.receiveAmount) = (from, recv, amt, recvAmt);
        (o.dex, o.batch, o.nonce, o.validUntil) = (address(dex), 1, ++on, vu);
    }

    function _leg0(ITradeToken.TradeOrder memory o, uint256 pk, uint256 fill) internal view returns (ISCaaSDex.DexLeg memory l) {
        (l.sellToken, l.order, l.fill) = (address(usdc), o, fill);
        l.sig = _ecdsa(pk, dex.dexOrderDigest(address(usdc), o));
    }

    function _x(ISCaaSDex.DexLeg memory l, uint256 sellFill, uint256 receiveFill)
        internal pure returns (ISCaaSDex.ExchangeLeg memory x)
    {
        (x.sellToken, x.shape, x.order, x.uaOrder, x.sig, x.auth) = (l.sellToken, l.shape, l.order, l.uaOrder, l.sig, l.auth);
        (x.sellFill, x.receiveFill) = (sellFill, receiveFill);
    }

    function _one(bytes32 ref, ISCaaSDex.DexLeg memory taker, ISCaaSDex.DexLeg memory maker)
        internal pure returns (ISCaaSDex.Settlement memory s)
    {
        (s.ref, s.taker) = (ref, taker);
        s.makers = new ISCaaSDex.DexLeg[](1);
        s.makers[0] = maker;
    }

    function _plan(bytes32 ref, ISCaaSDex.ExchangeLeg memory l) internal pure returns (ISCaaSDex.ExchangePlan memory p) {
        p.ref = ref;
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = l;
    }

    /// `approve(r, amountIn)` on `tIn`, then `r.swap(tIn, tOut, amountIn, amountOut, dex)`.
    function _swap(OnchainRouter r, address tIn, address tOut, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(tIn, abi.encodeCall(IERC20.approve, (address(r), amountIn)));
        xs[1] = ISCaaSDex.Interaction(address(r),
            abi.encodeCall(OnchainRouter.swap, (tIn, tOut, amountIn, amountOut, address(dex))));
    }

    /// a1 sells 1000 A for at least 1900 B at `fee` ppm, as an exchange leg with the floor 1900.
    function _aliceX(uint256 fee) internal returns (ISCaaSDex.ExchangeLeg memory) {
        return _x(_leg(A, _o(_pad(a1), B, 1000, 1900, fee), k1, 0), 1000, 1900);
    }

    // ------------------------------------------------------------------ settle (Path B, makers at their price)

    function _settle() internal {
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](2);
        // 1. a1 sells 1000 A for >= 1900 B (0.3 %), a2 sells 2000 B for 1000 A (0.1 %)
        ss[0] = _one("ab", _leg(A, _o(_pad(a1), B, 1000, 1900, 3_000), k1, 1000),
            _leg(B, _o(_pad(a2), A, 2000, 1000, 1_000), k2, 2000));
        // 2. the same with the taker's auth by the wrong key: MatchFailed, the batch still settles 1
        ss[1] = _one("bad", _leg(A, _o(_pad(a1), B, 1000, 1900, 0), k2, 1000),
            _leg(B, _o(_pad(a2), A, 2000, 1000, 0), k2, 2000));
        vm.broadcast(k3);
        bool[] memory ok = dex.mtxSettle{gas: G}(ss);
        require(ok[0] && !ok[1], "settle: 1 of 2");
        // an outside leg: a3 sells 1000 usdc (DexOrder, pulled by the puller) for 1000 A; a1 sells 1000 A for 1000 usdc
        ss = new ISCaaSDex.Settlement[](3);
        ss[0] = _one("usd", _leg0(_outside(a3, A, 1000, 1000), k3, 1000), _leg(A, _o(_pad(a1), address(usdc), 1000, 1000, 0), k1, 1000));
        // a wrapped leg: a1 sells 1000 W for 1000 B; a2 sells 1000 B for 1000 W
        ss[1] = _one("w", _leg(W, _o(_pad(a1), B, 1000, 1000, 2_000), k1, 1000), _leg(B, _o(_pad(a2), W, 1000, 1000, 0), k2, 1000));
        // a regulated leg: a2 sells 1000 R for 1000 A; a1 sells 1000 A for 1000 R
        ss[2] = _one("r", _leg(R, _o(_pad(a2), A, 1000, 1000, 0), k2, 1000), _leg(A, _o(_pad(a1), R, 1000, 1000, 0), k1, 1000));
        vm.broadcast(k2);
        ok = dex.mtxSettle{gas: G}(ss);
        require(ok[0] && ok[1] && ok[2], "settle: outside, wrapped, regulated");
    }

    // ------------------------------------------------------------------ exchange paths (a) and (b), batch

    function _exchange() internal {
        // (a): one router swap of 1000 A for 2000 B, floor 1900, surplus 100 to a1, fee 0.3 % on the floor
        ISCaaSDex.ExchangePlan memory p = _plan("xa", _aliceX(3_000));
        ISCaaSDex.Interaction[] memory xs = _swap(router, A, B, 1000, 2000);
        vm.broadcast(k3);
        dex.mtxExchange{gas: G}(p, xs);
        // (b): the executor gets 1000 A and pays the floor 1900 B, fee 0
        p = _plan("xb", _aliceX(0));
        vm.broadcast(k3);
        dex.mtxExchangeVia{gas: G}(p, address(exec), abi.encode(int256(0)));
        // batch: two plans of path (a), each its own self-call (exchangeOne)
        ISCaaSDex.ExchangePlan[] memory ps = new ISCaaSDex.ExchangePlan[](2);
        ISCaaSDex.Interaction[][] memory xss = new ISCaaSDex.Interaction[][](2);
        (ps[0], xss[0]) = (_plan("xc", _aliceX(1_000)), _swap(router, A, B, 1000, 1950));
        (ps[1], xss[1]) = (_plan("xd", _aliceX(0)), _swap(router, A, B, 1000, 1900));
        vm.broadcast(k2);
        bool[] memory ok = dex.mtxExchangeBatch{gas: G}(ps, xss);
        require(ok[0] && ok[1], "exchange batch");
    }

    // ------------------------------------------------------------------ hybrid (a) with a leftover, (b)

    function _hybridPlan(bytes32 ref) internal returns (ISCaaSDex.HybridPlan memory p) {
        // a1 sells 1000 A for >= 1000 B: 500 to a2's order (500 B for 500 A), 500 outside, floor 500 B
        p.ref = ref;
        p.taker = _leg(A, _o(_pad(a1), B, 1000, 1000, 0), k1, 1000);
        p.makers = new ISCaaSDex.DexLeg[](1);
        p.makers[0] = _leg(B, _o(_pad(a2), A, 500, 500, 0), k2, 500);
        (p.outsideSell, p.outsideFloor) = (500, 500);
    }

    function _hybrid() internal {
        // (a): the route sells only 400 of the 500 A: 100 refunded to a1 and restored on A (restorePulled, DX7)
        ISCaaSDex.HybridPlan memory p = _hybridPlan("ha");
        ISCaaSDex.Interaction[] memory xs = _swap(router, A, B, 400, 500);
        bytes32 h = ITradeToken(A).tradeOrderDigest(p.taker.uaOrder);
        vm.broadcast(k3);
        dex.mtxHybrid{gas: G}(p, xs);
        require(ITradeToken(A).pulled(h) == 900, "hybrid: restorePulled");
        // (b): the executor gets the 500 A, pays the 500 B floor
        p = _hybridPlan("hb");
        vm.broadcast(k3);
        dex.mtxHybridVia{gas: G}(p, address(exec), abi.encode(int256(0)));
    }

    // ------------------------------------------------------------------ cancels and nonce floors (token and DEX)

    function _cancels() internal {
        // token: a1 cancels a SCaaS order (CancelUAOrder), raises its order floor on lane 9 (UAInvalidateNonces)
        ITradeToken.UATradeOrder memory o = _o(_pad(a1), B, 1000, 1900, 0);
        cancelled = o;
        bytes memory s1 = _ecdsa(k1, ITradeToken(A).cancelOrderDigest(o));
        bytes memory s2 = _ecdsa(k1, ITradeToken(A).invalidateNoncesDigest(_pad(a1), 9, 5));
        vm.startBroadcast(k2);
        ITradeToken(A).mtxCancelOrder{gas: G}(o, _uaSig(s1));
        ITradeToken(A).mtxInvalidateNonces{gas: G}(_pad(a1), 9, 5, _uaSig(s2));
        vm.stopBroadcast();
        // DEX: a3 cancels an outside order (CancelDexOrder), raises its floor on lane 9
        ISCaaSDex.DexOrder[] memory os = new ISCaaSDex.DexOrder[](1);
        os[0] = ISCaaSDex.DexOrder(address(usdc), _outside(a3, A, 1000, 1000));
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _ecdsa(k3, dex.cancelDexOrderDigest(address(usdc), os[0].order));
        bytes memory s3 = _ecdsa(k3, dex.invalidateNoncesDigest(a3, 9, 5));
        vm.startBroadcast(k2);
        dex.mtxCancelOrders{gas: G}(os, sigs);
        dex.mtxInvalidateNonces{gas: G}(a3, 9, 5, s3);
        vm.stopBroadcast();
    }

    function _uaSig(bytes memory sig) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = sig;
    }

    // ------------------------------------------------------------------ wrap by signature (UAWrapOrder on a SCaaS leg)

    function _wrapOrder() internal {
        ITradeToken.UAWrapOrder memory o;
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill, o.fee) = (_pad(a1), W2, 1000, 1000, 1000, 1_000);
        (o.batch, o.nonce, o.validUntil) = (7, 1, vu);
        ITradeToken.UATradeOrder memory t = ITradeToken.UATradeOrder(o.from, W2, o.amount, o.minMinted, o.minFill, o.fee,
            o.relayer, W2, o.destination, o.flags, o.batch, o.nonce, o.validUntil);
        bytes memory sig = _ecdsa(k1, ITradeToken(A).tradeOrderDigest(t));
        vm.broadcast(k2);
        IWrappedToken(W2).mtxWrapOrder{gas: G}(A, o, _uaSig(sig));
    }

    // ------------------------------------------------------------------ the trade entries on every other kind

    uint256 wn = 1; // the wrap orders' nonce on A (lane 7; `_wrapOrder` took 1)

    /// @dev Kinds 1, 2, 3 and 8-11 (each its own release and trade module): a token X of the kind (Zether: BLS12-381
    ///      version 1, no auditor; regulated: no control set; wrapped: one leg, the SCaaS token A, X minted to a1 by its
    ///      signed `mtxWrapOrder`), then a settle of X against A (`mtxTrade` on X), a hybrid whose route sells 400 of the
    ///      500 X sent outside (100 back: `restorePulled` on X) and a cancelled order (`mtxCancelOrder` on X).
    function _kinds() internal {
        vm.broadcast(k1);
        IERC20(A).transfer(a2, 1e7); // a2's A for the makers below
        uint8[7] memory ks = [1, 2, 3, 8, 9, 10, 11];
        string[12] memory lb = ["NormalToken", "WrappedToken", "NormalZetherToken", "WrappedZetherToken", "", "", "", "",
            "NormalRegulatedToken", "WrappedRegulatedToken", "NormalZetherRegulatedToken", "WrappedZetherRegulatedToken"];
        for (uint256 i; i < 7; ++i) _kind(ks[i], lb[ks[i]]);
    }

    function _kind(uint8 n, string memory label) internal {
        address x = _kindToken(n, label);
        vm.startBroadcast(k1);
        dex.setMarket{gas: G}(x, A, true);
        dex.setMarket{gas: G}(x, B, true);
        vm.stopBroadcast();
        _kindSettle(x, n);
        _kindHybrid(x, n);
        ITradeToken.UATradeOrder memory o = _o(_pad(a1), B, 1000, 1900, 0);
        bytes memory sg = _ecdsa(k1, ITradeToken(x).cancelOrderDigest(o));
        vm.broadcast(k2);
        ITradeToken(x).mtxCancelOrder{gas: G}(o, _uaSig(sg));
    }

    function _kindToken(uint8 n, string memory label) internal returns (address x) {
        IFactoryToken.TokenConfig memory c = _base("Onchain Dex K", string.concat("oDK", vm.toString(n)));
        c.admin = _pad(a1);
        if (n == 2 || n == 3 || n == 10 || n == 11) {
            c.conf = IFactoryToken.ConfidentialConfig("", 1, 1 << 40, 0, 0, 0, 0, 0, bytes32(0), false, 0, 0, 0);
        }
        if (n % 2 == 1) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(A, 1, 1);
        } else {
            (c.initialSupply, c.initialHolder) = (1e12, a1);
        }
        // round 3s (token-lists spec §5.5): a regulated kind with an admin keeps its list bits enableable, so it carries terms
        if (n >= 8) c.reg.termsHash = keccak256("onchain dex terms");
        vm.broadcast(k1);
        x = f.createToken(IOpenFactory.TokenKind(n), 1, abi.encode(c), _salt(c.symbol));
        _book(x, label);
        if (n % 2 == 1) _wrapOrderOn(x, 10_000);
    }

    function _kindSettle(address x, uint8 n) internal {
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
        ss[0] = _one(keccak256(abi.encode("kind", n)), _leg(x, _o(_pad(a1), A, 1000, 1000, 0), k1, 1000),
            _leg(A, _o(_pad(a2), x, 1000, 1000, 0), k2, 1000));
        vm.broadcast(k2);
        require(dex.mtxSettle{gas: G}(ss)[0], string.concat("settle: kind ", vm.toString(n)));
    }

    function _kindHybrid(address x, uint8 n) internal {
        ISCaaSDex.HybridPlan memory p;
        p.ref = keccak256(abi.encode("hybrid", n));
        p.taker = _leg(x, _o(_pad(a1), B, 1000, 1000, 0), k1, 1000);
        p.makers = new ISCaaSDex.DexLeg[](1);
        p.makers[0] = _leg(B, _o(_pad(a2), x, 500, 500, 0), k2, 500);
        (p.outsideSell, p.outsideFloor) = (500, 500);
        bytes32 h = ITradeToken(x).tradeOrderDigest(p.taker.uaOrder);
        ISCaaSDex.Interaction[] memory xs = _swap(router, x, B, 400, 500);
        vm.broadcast(k3);
        dex.mtxHybrid{gas: G}(p, xs);
        require(ITradeToken(x).pulled(h) == 900, string.concat("restorePulled: kind ", vm.toString(n)));
    }

    /// @dev a1 wraps `amt` A into the wrapped token `wt` by a signed `UAWrapOrder` (A's trade-order digest), relayed by k2.
    function _wrapOrderOn(address wt, uint256 amt) internal {
        ITradeToken.UAWrapOrder memory o;
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill) = (_pad(a1), wt, amt, amt, amt);
        (o.batch, o.nonce, o.validUntil) = (7, ++wn, vu);
        ITradeToken.UATradeOrder memory t = ITradeToken.UATradeOrder(o.from, wt, o.amount, o.minMinted, o.minFill, o.fee,
            o.relayer, wt, o.destination, o.flags, o.batch, o.nonce, o.validUntil);
        bytes memory sig = _ecdsa(k1, ITradeToken(A).tradeOrderDigest(t));
        vm.broadcast(k2);
        IWrappedToken(wt).mtxWrapOrder{gas: G}(A, o, _uaSig(sig));
    }

    // ------------------------------------------------------------------ the DEX's governance (module D)

    function _gov() internal {
        IGovernance g = IGovernance(address(dex));
        IGovernance.GrantTerms memory t;
        (t.max, t.maxUses, t.validUntil) = (MAXW, 3, uint64(vu));
        vm.startBroadcast(k1);
        g.setGrant{gas: G}(GovernanceBits.FEE_ROUTING, _pad(a2), t); // a limited holder of FEE_ROUTING
        g.grantRole{gas: G}(GovernanceBits.LISTING, _pad(a2));
        vm.stopBroadcast();
        vm.startBroadcast(k2);
        dex.setFeeSplit{gas: G}(250_000, TREASURY); // a2 uses its grant
        g.renounceRole{gas: G}(GovernanceBits.FEE_ROUTING);
        vm.stopBroadcast();
        vm.startBroadcast(k1);
        g.revokeRole{gas: G}(GovernanceBits.LISTING, _pad(a2));
        dex.setListedOnly{gas: G}(true); // after the trades: with it every interaction target (the token of an approve too) is listed
        g.transferAdmin{gas: G}(_pad(a2), dex.chainUid());
        vm.stopBroadcast();
        vm.broadcast(k2);
        g.acceptAdmin{gas: G}();
        // dex2 (grantDelay 1 h): a grant proposed then cancelled, a feature off, the owner's roles and ownership renounced
        IGovernance g2 = IGovernance(address(dex2));
        vm.startBroadcast(k1);
        g2.grantRole{gas: G}(GovernanceBits.LISTING, _pad(a3));
        g2.cancelGrant{gas: G}(GovernanceBits.LISTING, _pad(a3));
        g2.disableFeature{gas: G}(GovernanceBits.LISTING);
        g2.renounceRole{gas: G}(GovernanceBits.FEE_ROUTING);
        g2.renounceAdmin{gas: G}(dex2.chainUid());
        vm.stopBroadcast();
    }

    // ------------------------------------------------------------------ negatives (eth_call on the final state)

    function _negatives() internal {
        // an order on an unlisted market, listed-only on: B / usdc has no market
        ISCaaSDex.HybridPlan memory hp;
        hp.ref = "neg";
        hp.taker = _leg(B, _o(_pad(a2), address(usdc), 1000, 1000, 0), k2, 1000);
        hp.makers = new ISCaaSDex.DexLeg[](0);
        (hp.outsideSell, hp.outsideFloor) = (1000, 1000);
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.mtxHybrid, (hp, new ISCaaSDex.Interaction[](0))),
            ISCaaSDex.MarketNotListed.selector, "mtxHybrid on an unlisted market (B / usdc), listed-only on");
        // the cancelled order filled again
        ITradeToken.UATradeOrder memory c = cancelled;
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.mtxExchange,
            (_plan("negc", _x(_leg(A, c, k1, 0), 1000, 1900)), _swap(router, A, B, 1000, 2000))),
            ITradeToken.OrderClosed.selector, "mtxExchange of a cancelled order");
        // an outside leg signed by the wrong key
        ITradeToken.TradeOrder memory u = _outside(a3, A, 1000, 1000);
        ISCaaSDex.DexLeg memory bad = _leg0(u, k2, 0);
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.mtxExchange,
            (_plan("negs", _x(bad, 1000, 1000)), _swap(router, address(usdc), A, 1000, 1000))),
            ISCaaSDex.BadSignature.selector, "mtxExchange of an outside order with a bad signature");
        // listed-only: an interaction on an unlisted router
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.mtxExchange, (_plan("negt", _aliceX(0)), _swap(router2, A, B, 1000, 2000))),
            ISCaaSDex.TargetNotListed.selector, "mtxExchange through an unlisted target, listed-only on");
        // the self-call entries and the factory's
        ISCaaSDex.Settlement memory s;
        _neg(a3, address(dex), abi.encodeCall(ISettleOne.settleOne, (s, a3)), ISCaaSDex.NotSelf.selector, "settleOne called directly");
        ISCaaSDex.ExchangePlan memory p;
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.exchangeOne, (p, new ISCaaSDex.Interaction[](0), a3)),
            ISCaaSDex.NotSelf.selector, "exchangeOne called directly");
        _neg(a3, address(dex), abi.encodeCall(ISCaaSDex.initialize, (bytes32(0), 1, "")), ISCaaSDex.NotFactory.selector,
            "initialize called directly");
        // a token's mtxTrade by anyone but the order's DEX
        ITradeToken.UATradeOrder memory o = _o(_pad(a1), B, 1000, 1900, 0);
        _neg(a2, A, abi.encodeCall(ITradeToken.mtxTrade, (o, _uaSig(""), ITradeToken.TradeFill(1000, 1900, 0, a2))),
            ITradeToken.NotDex.selector, "mtxTrade called by a non-DEX");
        // dex2's LISTING is off: a market cannot be set
        _neg(a1, address(dex2), abi.encodeCall(ISCaaSDex.setMarket, (A, B, true)), IGovernance.FeatureNotSet.selector,
            "setMarket on dex2 after disableFeature(LISTING)");
    }
}
