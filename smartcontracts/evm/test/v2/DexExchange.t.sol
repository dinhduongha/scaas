// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex, IExchangeExecutor} from "../../src/dex/ISCaaSDex.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {DexPuller} from "../../src/dex/DexPuller.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MockERC20, FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";
import {noVerifiers} from "../helpers/Canon.sol";

/// Router (v3 style): pulls `amountIn` (+ `extraIn`) from the caller under its allowance, pays `amountOut`
/// (- `shortOut`) to `to` and always claims `amountOut` (the DEX never reads it).
contract MockRouter {
    uint256 public extraIn;
    uint256 public shortOut;

    function setQuirks(uint256 extraIn_, uint256 shortOut_) external {
        (extraIn, shortOut) = (extraIn_, shortOut_);
    }

    function swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut, address to) external returns (uint256) {
        IERC20(tIn).transferFrom(msg.sender, address(this), amountIn + extraIn);
        IERC20(tOut).transfer(to, amountOut - shortOut);
        return amountOut;
    }
}

/// Pair (v2 style): paid first by a transfer, `swap` pays `(new input) · num / den` of `tokenOut` to `to`.
contract MockPair {
    IERC20 immutable tokenIn;
    IERC20 immutable tokenOut;
    uint256 immutable num;
    uint256 immutable den;
    uint256 reserveIn;

    constructor(address i, address o, uint256 n, uint256 d) {
        (tokenIn, tokenOut, num, den) = (IERC20(i), IERC20(o), n, d);
    }

    function swap(address to) external {
        uint256 bal = tokenIn.balanceOf(address(this));
        uint256 out = (bal - reserveIn) * num / den;
        reserveIn = bal;
        tokenOut.transfer(to, out);
    }
}

/// Executor of path (b): optionally makes one call (re-entry, `mtxTrade`, the puller), records what it was told, then
/// pays each floor plus `abi.decode(data, (int256))` from its own inventory.
contract MockExecutor is IExchangeExecutor {
    address public callTarget;
    bytes public callData;
    address[] outT;
    uint256[] outA;
    address[] inT;
    uint256[] inA;

    function setCall(address t, bytes calldata d) external {
        (callTarget, callData) = (t, d);
    }

    function exchangeCallback(bytes32, address[] calldata tokensOut, uint256[] calldata amountsOut,
        address[] calldata tokensIn, uint256[] calldata amountsIn, bytes calldata data) external
    {
        if (callTarget != address(0)) {
            (bool ok, bytes memory r) = callTarget.call(callData);
            if (!ok) assembly { revert(add(r, 32), mload(r)) }
        }
        outT = tokensOut;
        outA = amountsOut;
        inT = tokensIn;
        inA = amountsIn;
        int256 bonus = abi.decode(data, (int256));
        for (uint256 i; i < tokensIn.length; ++i) {
            IERC20(tokensIn[i]).transfer(msg.sender, uint256(int256(amountsIn[i]) + bonus));
        }
    }

    function got() external view returns (address[] memory, uint256[] memory, address[] memory, uint256[] memory) {
        return (outT, outA, inT, inA);
    }
}

/// Records the `ref` it is told and pays the floors back.
contract RefExecutor is IExchangeExecutor {
    bytes32 public ref;

    function exchangeCallback(bytes32 r, address[] calldata, uint256[] calldata, address[] calldata tokensIn,
        uint256[] calldata amountsIn, bytes calldata) external
    {
        ref = r;
        for (uint256 i; i < tokensIn.length; ++i) IERC20(tokensIn[i]).transfer(msg.sender, amountsIn[i]);
    }
}

/// Credits one unit more than it moves when the recipient is `sink` (a token that rebases up on arrival).
contract BonusERC20 is MockERC20 {
    address public sink;

    constructor() MockERC20("Bonus", "BON", 6) {}

    function setSink(address s) external { sink = s; }

    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (from != address(0) && to == sink) super._update(address(0), to, 1);
    }
}

/// Interaction targets that misbehave.
contract Hostile {
    error Boom(uint256 code);

    function boom() external pure { revert Boom(42); }
    function burn() external pure { while (true) {} }
    function reenter(ISCaaSDex d) external { d.mtxSettle(DexLegs.wire(new DexLegs.Settlement[](0))); }
}

/// The exchange path (CTR-DEX-20, -21, -23, -03): `TradeOrder`s executed against AMM routes at a floor, the surplus to
/// the signers, conservation over every token; what an interaction may call; listed targets; allowances reset.
contract DexExchangeTest is Test {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    uint256 constant CAROL_PK = 0xCA401;
    uint256 constant DAVE_PK = 0xDA7E;
    address alice = vm.addr(ALICE_PK);
    address bob = vm.addr(BOB_PK);
    address carol = vm.addr(CAROL_PK);
    address dave = vm.addr(DAVE_PK);
    address admin = address(0xAD);
    address treasury = address(0x7EA5);
    address relayer = address(0xBEEF);

    OpenFactory f;
    SCaaSDex dex;
    address puller;
    NoUnderlyingToken a;  // SCaaS: Alice 800 k, Carol 100 k, the router 100 k
    NoUnderlyingToken b;  // SCaaS: Bob 500 k, the router 500 k
    MockERC20 usdc;       // outside: Dave 1e6 (approved to the puller), the router 1e6
    MockERC20 c;          // an intermediate hop token, never listed
    MockRouter router;

    function setUp() public {
        f = new OpenFactory(address(this), UID_, noVerifiers());
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1,
            address(new NoUnderlyingToken(address(f), address(0), UID_, address(0), false)));
        f.registerDexImplementation(1, address(new SCaaSDex(address(f), UID_, address(0))));
        a = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1,
            noneInit("A", "A", 0, 1e6, alice, address(0)), "a"));
        b = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1,
            noneInit("B", "B", 0, 1e6, bob, address(0)), "b"));
        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(admin, 200_000, treasury, false), "dex"));
        puller = dex.puller();
        usdc = new MockERC20("USD Coin", "USDC", 6);
        c = new MockERC20("Hop", "C", 18);
        router = new MockRouter();
        usdc.mint(dave, 1e6);
        usdc.mint(address(router), 1e6);
        c.mint(address(router), 1e6);
        vm.prank(dave);
        usdc.approve(puller, type(uint256).max);
        vm.startPrank(alice);
        a.transfer(carol, 100_000);
        a.transfer(address(router), 100_000);
        vm.stopPrank();
        vm.prank(bob);
        b.transfer(address(router), 500_000);
        vm.startPrank(admin);
        dex.setMarket(address(a), address(b), true);
        dex.setMarket(address(usdc), address(b), true);
        vm.stopPrank();
    }

    // ------------------------------------------------------------------ helpers

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

    /// Signed on the token for a SCaaS sell token, as a `DexOrder` otherwise (the DEX's listing decides).
    function _leg(uint256 pk, address sellToken, ITradeToken.TradeOrder memory o, uint256 sellFill, uint256 floor)
        internal view returns (DexLegs.ExchangeLeg memory)
    {
        bytes32 d = dex.tokenKind(sellToken) == 1
            ? ITradeToken(sellToken).tradeOrderDigest(o) : dex.dexOrderDigest(sellToken, o);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return DexLegs.ExchangeLeg(sellToken, o, abi.encodePacked(r, s, v), sellFill, floor);
    }

    function _plan(DexLegs.ExchangeLeg memory l0) internal pure returns (DexLegs.ExchangePlan memory p) {
        p.ref = "x";
        p.legs = new DexLegs.ExchangeLeg[](1);
        p.legs[0] = l0;
    }

    function _plan2(DexLegs.ExchangeLeg memory l0, DexLegs.ExchangeLeg memory l1)
        internal pure returns (DexLegs.ExchangePlan memory p)
    {
        p.ref = "x";
        p.legs = new DexLegs.ExchangeLeg[](2);
        p.legs[0] = l0;
        p.legs[1] = l1;
    }

    /// Alice sells 1000 A for at least 1900 B (fee 0.3 %), floor 1900.
    function _alice() internal view returns (DexLegs.ExchangeLeg memory) {
        return _leg(ALICE_PK, address(a), _order(alice, address(b), 1000, 1900, 3_000), 1000, 1900);
    }

    /// Alice as above; Carol sells 1000 of 1999 A at 3597 B (limit ceil(1799.4) = 1800, fee 0.1 %), floor 1800.
    function _twoLegs() internal view returns (DexLegs.ExchangePlan memory) {
        return _plan2(_alice(), _leg(CAROL_PK, address(a), _order(carol, address(b), 1999, 3597, 1_000), 1000, 1800));
    }

    function _ix(address target, bytes memory data) internal pure returns (ISCaaSDex.Interaction[] memory xs) {
        xs = new ISCaaSDex.Interaction[](1);
        xs[0] = ISCaaSDex.Interaction(target, data);
    }

    /// `approve(router, amountIn)` on `tIn`, then `router.swap(tIn, tOut, amountIn, amountOut, dex)`.
    function _swap(address tIn, address tOut, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = _cat(_ix(tIn, abi.encodeCall(IERC20.approve, (address(router), amountIn))),
            _ix(address(router), abi.encodeCall(MockRouter.swap, (tIn, tOut, amountIn, amountOut, address(dex)))));
    }

    function _cat(ISCaaSDex.Interaction[] memory x, ISCaaSDex.Interaction[] memory y)
        internal pure returns (ISCaaSDex.Interaction[] memory z)
    {
        z = new ISCaaSDex.Interaction[](x.length + y.length);
        for (uint256 i; i < x.length; ++i) z[i] = x[i];
        for (uint256 i; i < y.length; ++i) z[x.length + i] = y[i];
    }

    function _exchange(DexLegs.ExchangePlan memory p, ISCaaSDex.Interaction[] memory xs) internal {
        vm.prank(relayer);
        dex.mtxExchange(DexLegs.wire(p), xs);
    }

    function _expectExchange(DexLegs.ExchangePlan memory p, ISCaaSDex.Interaction[] memory xs, bytes memory err)
        internal
    {
        vm.prank(relayer);
        vm.expectRevert(err);
        dex.mtxExchange(DexLegs.wire(p), xs);
    }

    function _err(bytes4 sel, address x) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, x);
    }

    function _executor() internal returns (MockExecutor e) {
        e = new MockExecutor();
        vm.prank(bob);
        b.transfer(address(e), 100_000);
    }

    /// The `ExchangeLegSettled` fields after the indexed ones, of the `i`-th such event.
    function _legEvent(Vm.Log[] memory logs, uint256 i) internal pure returns (bytes32 h, uint256[7] memory v) {
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].topics[0] != ISCaaSDex.ExchangeLegSettled.selector) continue;
            if (i != 0) {
                --i;
                continue;
            }
            address to;
            (to, v[1], v[2], v[3], v[4], v[5], v[6]) =
                abi.decode(logs[k].data, (address, uint256, uint256, uint256, uint256, uint256, uint256));
            v[0] = uint256(uint160(to));
            return (logs[k].topics[2], v);
        }
        revert("no such event");
    }

    // ------------------------------------------------------------------ path (a): routes, surplus, conservation

    /// Two legs, one router swap of 2000 A for 3800 B: floors 3700, surplus 100 split by floor (51, and 49 for the last
    /// leg with the remainder), fees on the floors only, the DEX left with nothing.
    function test_exchange_twoLegs_floorsPlusSurplus_feesOnTheFloor() public {
        DexLegs.ExchangePlan memory p = _twoLegs();
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        bytes32 ha = a.tradeOrderDigest(p.legs[0].o);
        bytes32 hc = a.tradeOrderDigest(p.legs[1].o);
        vm.recordLogs();
        _exchange(p, xs);
        assertEq(b.balanceOf(alice), 1900 - 6 + 51);
        assertEq(b.balanceOf(carol), 1800 - 2 + 49);
        assertEq(b.balanceOf(relayer), 1); // floor(6 · 20 %) + floor(2 · 20 %)
        assertEq(b.balanceOf(treasury), 7);
        assertEq(a.balanceOf(alice), 800_000 - 1000);
        assertEq(a.balanceOf(carol), 100_000 - 1000);
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
        assertEq(a.pulled(ha), 1000);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (bytes32 h, uint256[7] memory v) = _legEvent(logs, 0);
        assertEq(h, ha);
        assertEq(abi.encode(v), abi.encode([uint256(uint160(alice)), 1000, 1900, 51, 6, 0, 1900]));
        (h, v) = _legEvent(logs, 1);
        assertEq(h, hc);
        assertEq(abi.encode(v), abi.encode([uint256(uint160(carol)), 1000, 1800, 49, 2, 0, 1800]));
    }

    /// The signed `destination` (not the signer) gets the floor less the fee plus the surplus, and the event names it:
    /// floor 1900, fee 6, surplus 100.
    function test_exchange_destination_getsProceedsAndSurplus() public {
        address dest = address(0xD0D0);
        ITradeToken.TradeOrder memory o = _order(alice, address(b), 1000, 1900, 3_000);
        o.destination = dest;
        DexLegs.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1900));
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 1000, 2000);
        vm.recordLogs();
        _exchange(p, xs);
        assertEq(b.balanceOf(dest), 1900 - 6 + 100);
        assertEq(b.balanceOf(alice), 0);
        assertEq(b.balanceOf(address(dex)), 0);
        (, uint256[7] memory v) = _legEvent(vm.getRecordedLogs(), 0);
        assertEq(v[0], uint256(uint160(dest)));
    }

    /// A floor above the limit: `receivedFloor` is the committed floor (1950), `limitReceive` the signed price at the
    /// sold amount (1900); the surplus is measured over the floor (2000 - 1950).
    function test_exchange_floorAboveLimit_eventFields() public {
        DexLegs.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), _order(alice, address(b), 1000, 1900, 3_000), 1000, 1950));
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 1000, 2000);
        vm.recordLogs();
        _exchange(p, xs);
        assertEq(b.balanceOf(alice), 1950 - 6 + 50);
        (, uint256[7] memory v) = _legEvent(vm.getRecordedLogs(), 0);
        assertEq(abi.encode(v), abi.encode([uint256(uint160(alice)), 1000, 1950, 50, 6, 0, 1900]));
    }

    /// A cycle X→X (`receiveToken` = the sell token, accepted by the token): 1000 A → 2000 B → 1050 A, floor 1010, B a
    /// declared intermediate token back at its snapshot.
    function test_exchange_profitableCycle_xToX() public {
        ITradeToken.TradeOrder memory o = _order(alice, address(a), 1000, 1010, 0);
        DexLegs.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1010));
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(b);
        ISCaaSDex.Interaction[] memory xs =
            _cat(_swap(address(a), address(b), 1000, 2000), _swap(address(b), address(a), 2000, 1050));
        _exchange(p, xs);
        assertEq(a.balanceOf(alice), 800_000 + 50);
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
    }

    /// Multi-hop through two v2-style pairs, A → C → B, the hop token never touching the DEX.
    function test_exchange_multiHopThroughPairs() public {
        MockPair p1 = new MockPair(address(a), address(c), 2, 1);
        MockPair p2 = new MockPair(address(c), address(b), 1, 1);
        c.mint(address(p1), 1e6);
        vm.prank(bob);
        b.transfer(address(p2), 10_000);
        ISCaaSDex.Interaction[] memory xs = _cat(_ix(address(a), abi.encodeCall(IERC20.transfer, (address(p1), 1000))),
            _cat(_ix(address(p1), abi.encodeCall(MockPair.swap, (address(p2)))),
                _ix(address(p2), abi.encodeCall(MockPair.swap, (address(dex))))));
        _exchange(_plan(_alice()), xs);
        assertEq(b.balanceOf(alice), 1900 - 6 + 100);
        assertEq(a.balanceOf(address(p1)), 1000);
    }

    /// A → C → B through the DEX: C is declared, so a unit of C left behind fails conservation; the exact route passes.
    function test_exchange_intermediateLeftover_reverts() public {
        DexLegs.ExchangePlan memory p = _plan(_alice());
        p.extraTokens = new address[](1);
        p.extraTokens[0] = address(c);
        ISCaaSDex.Interaction[] memory first = _swap(address(a), address(c), 1000, 2000);
        _expectExchange(p, _cat(first, _swap(address(c), address(b), 1999, 2000)),
            _err(ISCaaSDex.ConservationBroken.selector, address(c)));
        _exchange(p, _cat(first, _swap(address(c), address(b), 2000, 2000)));
        assertEq(b.balanceOf(alice), 1900 - 6 + 100);
        assertEq(c.balanceOf(address(dex)), 0);
    }

    function test_exchange_soldOnlyLeftover_reverts() public {
        _expectExchange(_plan(_alice()), _swap(address(a), address(b), 999, 2000),
            _err(ISCaaSDex.ConservationBroken.selector, address(a)));
    }

    /// A router that pulls more than the route sells: under an exact approval the token refuses; under an unlimited
    /// one it takes a donation the DEX held, and conservation fails.
    function test_exchange_routerPullingMore_fails() public {
        vm.prank(alice);
        a.transfer(address(dex), 50);
        router.setQuirks(50, 0);
        DexLegs.ExchangePlan memory p = _plan(_alice());
        _expectExchange(p, _swap(address(a), address(b), 1000, 2000), abi.encodeWithSelector(
            IERC20Errors.ERC20InsufficientAllowance.selector, address(router), 1000, 1050));
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 1000, 2000);
        xs[0].data = abi.encodeCall(IERC20.approve, (address(router), type(uint256).max));
        _expectExchange(p, xs, _err(ISCaaSDex.ConservationBroken.selector, address(a)));
    }

    /// The router claims 3800 and pays 3699: below the floors (3700) ⇒ `InsufficientOutput`; at exactly the floors the
    /// plan settles with no surplus.
    function test_exchange_lyingRouter_insufficientOutput_exactFloorsSettle() public {
        DexLegs.ExchangePlan memory p = _twoLegs();
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        router.setQuirks(0, 101);
        _expectExchange(p, xs, _err(ISCaaSDex.InsufficientOutput.selector, address(b)));
        router.setQuirks(0, 100);
        _exchange(p, xs);
        assertEq(b.balanceOf(alice), 1900 - 6);
        assertEq(b.balanceOf(carol), 1800 - 2);
    }

    /// Path B on the exchange path: Carol's 2000 A are pulled whole, 1000 are routed, 1000 refunded.
    function test_exchange_pathBLeg_refundsTheRest() public {
        ITradeToken.TradeOrder memory o = _order(carol, address(b), 2000, 3600, 1_000);
        o.flags = 3; // IOC | ESCROW
        DexLegs.ExchangePlan memory p = _plan(_leg(CAROL_PK, address(a), o, 1000, 1800));
        vm.recordLogs();
        _exchange(p, _swap(address(a), address(b), 1000, 1850));
        assertEq(a.balanceOf(carol), 100_000 - 1000);
        assertEq(b.balanceOf(carol), 1800 - 2 + 50);
        (, uint256[7] memory v) = _legEvent(vm.getRecordedLogs(), 0);
        assertEq(v[5], 1000); // refund
    }

    /// Two signers trade with each other, no interaction at all (a coincidence of wants): each gets the other's excess.
    /// Bob's Path B leg holds 2000 B of refund in the token Alice receives.
    function test_exchange_coincidenceOfWants_noInteractions_refundNotDistributed() public {
        ITradeToken.TradeOrder memory ob = _order(bob, address(a), 4000, 1900, 1_000);
        ob.flags = 3;
        DexLegs.ExchangePlan memory p = _plan2(_alice(), _leg(BOB_PK, address(b), ob, 2000, 950));
        _exchange(p, new ISCaaSDex.Interaction[](0));
        assertEq(b.balanceOf(alice), 1900 - 6 + 100);
        assertEq(a.balanceOf(bob), 950 - 1 + 50);
        assertEq(b.balanceOf(bob), 500_000 - 2000);
        assertEq(b.balanceOf(address(dex)), 0);
        assertEq(a.balanceOf(address(dex)), 0);
    }

    /// An outside leg on the exchange path: a `DexOrder` pulled through the puller.
    function test_exchange_outsideLeg_throughThePuller() public {
        ITradeToken.TradeOrder memory o = _order(dave, address(b), 2000, 3800, 0);
        DexLegs.ExchangePlan memory p = _plan(_leg(DAVE_PK, address(usdc), o, 2000, 3800));
        bytes32 h = dex.dexOrderDigest(address(usdc), o);
        _exchange(p, _swap(address(usdc), address(b), 2000, 3900));
        assertEq(b.balanceOf(dave), 3900);
        assertEq(usdc.balanceOf(dave), 1e6 - 2000);
        assertEq(dex.pulled(h), 2000);
    }

    /// A fee-on-transfer sell token delivers 990 for 1000 pulled: refused at the pull, before any interaction, even
    /// though this route spends only what arrived.
    function test_exchange_feeOnTransferSellToken_failsAtThePull() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        fot.mint(dave, 1e6);
        vm.prank(dave);
        fot.approve(puller, type(uint256).max);
        vm.prank(admin);
        dex.setMarket(address(fot), address(b), true);
        DexLegs.ExchangePlan memory p =
            _plan(_leg(DAVE_PK, address(fot), _order(dave, address(b), 1000, 1000, 0), 1000, 1000));
        _expectExchange(p, _swap(address(fot), address(b), 990, 1000),
            _err(ISCaaSDex.ConservationBroken.selector, address(fot)));
    }

    /// A sell token that credits one unit more than the puller moved is refused at the pull too (the pull check is
    /// exact, not a lower bound), even though a route spending the extra unit would end at the snapshot.
    function test_exchange_excessCreditedSellToken_failsAtThePull() public {
        BonusERC20 bon = new BonusERC20();
        bon.mint(dave, 1e6);
        bon.mint(address(router), 1e6);
        bon.setSink(address(dex));
        vm.prank(dave);
        bon.approve(puller, type(uint256).max);
        vm.prank(admin);
        dex.setMarket(address(bon), address(b), true);
        DexLegs.ExchangePlan memory p =
            _plan(_leg(DAVE_PK, address(bon), _order(dave, address(b), 1000, 1900, 0), 1000, 1900));
        _expectExchange(p, _swap(address(bon), address(b), 1001, 2000),
            _err(ISCaaSDex.ConservationBroken.selector, address(bon)));
    }

    /// Every allowance an `approve` interaction grants (to the router, and to any other spender) is back to 0 after the
    /// plan: nothing the DEX approved outlives the route.
    function test_exchange_approvalsResetToZero() public {
        MockRouter spy = new MockRouter();
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        xs[0].data = abi.encodeCall(IERC20.approve, (address(router), type(uint256).max));
        xs = _cat(_ix(address(a), abi.encodeCall(IERC20.approve, (address(spy), 777))), xs);
        _exchange(_twoLegs(), xs);
        assertEq(a.allowance(address(dex), address(router)), 0);
        assertEq(a.allowance(address(dex), address(spy)), 0);
    }

    // ------------------------------------------------------------------ what an interaction may call (CTR-DEX-23)

    function test_exchange_forbiddenTargets_theDexAndThePuller() public {
        DexLegs.ExchangePlan memory p = _plan(_alice());
        _expectExchange(p, _ix(address(dex), abi.encodeCall(ISCaaSDex.setListedOnly, (true))),
            _err(ISCaaSDex.ForbiddenTarget.selector, address(dex)));
        _expectExchange(p, _ix(puller, abi.encodeCall(DexPuller.pull, (address(usdc), dave, 1))),
            _err(ISCaaSDex.ForbiddenTarget.selector, puller));
    }

    /// Without the selector block, this interaction pulls Bob's resting order (it names this DEX) with an invented
    /// `receiveFill` and the plan pays his 1000 B to Alice as surplus; conservation would balance.
    function test_exchange_forbiddenSelector_mtxTradeOfARestingOrder_andShortData() public {
        ITradeToken.TradeOrder memory ob = _order(bob, address(a), 1000, 500, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB_PK, b.tradeOrderDigest(ob));
        bytes memory steal = abi.encodeCall(ITradeToken.mtxTrade,
            (ob, abi.encodePacked(r, s, v), ITradeToken.TradeFill(1000, 1e9, 0, relayer)));
        DexLegs.ExchangePlan memory p = _plan(_alice());
        ISCaaSDex.Interaction[] memory route = _swap(address(a), address(b), 1000, 2000);
        _expectExchange(p, _cat(_ix(address(b), steal), route), abi.encodeWithSelector(
            ISCaaSDex.ForbiddenSelector.selector, address(b), ITradeToken.mtxTrade.selector));
        _expectExchange(p, _cat(_ix(address(router), ""), route),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(router), bytes4(0)));
        _expectExchange(p, _cat(_ix(address(router), hex"abcdef"), route),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(router), bytes4(0xabcdef00)));
    }

    /// `increaseAllowance` would raise an allowance the post-route reset (which only knows `approve`) never clears.
    function test_exchange_forbiddenSelector_increaseAllowance() public {
        assertEq(bytes4(keccak256("increaseAllowance(address,uint256)")), bytes4(0x39509351));
        bytes memory data = abi.encodeWithSelector(bytes4(0x39509351), address(router), 100);
        _expectExchange(_plan(_alice()), _cat(_ix(address(a), data), _swap(address(a), address(b), 1000, 2000)),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(a), bytes4(0x39509351)));
    }

    /// Permit2's `approve(token,spender,amount,expiration)` grants an allowance in Permit2, outside the reset.
    function test_exchange_forbiddenSelector_permit2Approve() public {
        assertEq(bytes4(keccak256("approve(address,address,uint160,uint48)")), bytes4(0x87517c45));
        bytes memory data = abi.encodeWithSelector(bytes4(0x87517c45), address(a), address(router), uint160(100), uint48(1));
        _expectExchange(_plan(_alice()), _cat(_ix(address(router), data), _swap(address(a), address(b), 1000, 2000)),
            abi.encodeWithSelector(ISCaaSDex.ForbiddenSelector.selector, address(router), bytes4(0x87517c45)));
    }

    /// The DEX holds no user allowance (holders approve the puller): `transferFrom(victim, …)` from an interaction fails.
    function test_exchange_transferFromAVictim_fails() public {
        ISCaaSDex.Interaction[] memory xs = _cat(
            _ix(address(usdc), abi.encodeCall(IERC20.transferFrom, (dave, address(0xBAD), 100))),
            _swap(address(a), address(b), 1000, 2000));
        _expectExchange(_plan(_alice()), xs,
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(dex), 0, 100));
    }

    function test_exchange_reenteringTarget_isRefused() public {
        Hostile h = new Hostile();
        ISCaaSDex.Interaction[] memory xs =
            _cat(_ix(address(h), abi.encodeCall(Hostile.reenter, (ISCaaSDex(address(dex))))),
                _swap(address(a), address(b), 1000, 2000));
        _expectExchange(_plan(_alice()), xs,
            abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector));
    }

    /// A failing interaction reverts the plan with its own data; a gas-burning one fails only this call.
    function test_exchange_revertingAndGasBurningTargets() public {
        Hostile h = new Hostile();
        DexLegs.ExchangePlan memory p = _plan(_alice());
        _expectExchange(p, _ix(address(h), abi.encodeCall(Hostile.boom, ())),
            abi.encodeWithSelector(Hostile.Boom.selector, 42));
        ISCaaSDex.Interaction[] memory xs = _ix(address(h), abi.encodeCall(Hostile.burn, ()));
        vm.prank(relayer);
        vm.expectRevert();
        dex.mtxExchange{gas: 1_000_000}(DexLegs.wire(p), xs);
    }

    // ------------------------------------------------------------------ listed targets: LISTED_POOLS × listed-only

    /// Four combinations on both entry points: an unlisted target or executor is refused iff a leg sets `LISTED_POOLS`
    /// or the admin's mode is on; once listed (the token's `approve` is an interaction too) the plan settles.
    function test_exchange_listedPoolsTimesListedOnly_bothEntryPoints() public {
        for (uint256 k; k < 8; ++k) {
            uint256 id = vm.snapshotState();
            bool flag = k & 1 != 0;
            bool mode = k & 2 != 0;
            bool via = k & 4 != 0;
            if (mode) {
                vm.prank(admin);
                dex.setListedOnly(true);
            }
            ITradeToken.TradeOrder memory o = _order(alice, address(b), 1000, 1900, 0);
            if (flag) o.flags = 4;
            DexLegs.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1900));
            if (via) _listedVia(p, flag || mode);
            else _listedDirect(p, flag || mode);
            assertEq(b.balanceOf(alice), 2000);
            vm.revertToState(id);
        }
    }

    function _listedDirect(DexLegs.ExchangePlan memory p, bool needsListing) internal {
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 1000, 2000);
        if (needsListing) {
            _expectExchange(p, xs, _err(ISCaaSDex.TargetNotListed.selector, address(a)));
            vm.prank(admin);
            dex.setExchangeTarget(address(a), true);
            _expectExchange(p, xs, _err(ISCaaSDex.TargetNotListed.selector, address(router)));
            vm.prank(admin);
            dex.setExchangeTarget(address(router), true);
        }
        _exchange(p, xs);
    }

    function _listedVia(DexLegs.ExchangePlan memory p, bool needsListing) internal {
        MockExecutor e = _executor();
        bytes memory data = abi.encode(int256(100));
        if (needsListing) {
            vm.prank(relayer);
            vm.expectRevert(_err(ISCaaSDex.TargetNotListed.selector, address(e)));
            dex.mtxExchangeVia(DexLegs.wire(p), address(e), data);
            vm.prank(admin);
            dex.setExchangeTarget(address(e), true);
        }
        vm.prank(relayer);
        dex.mtxExchangeVia(DexLegs.wire(p), address(e), data);
    }

    // ------------------------------------------------------------------ plan checks

    /// Known = a side of a listed market (counted per listed market, so a repeated listing is one): an unlisted token,
    /// or one whose last market was delisted, is refused on either side of a leg.
    function test_exchange_tokenNotKnown() public {
        DexLegs.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(c), _order(alice, address(b), 1000, 1900, 0),
            1000, 1900));
        _expectExchange(p, new ISCaaSDex.Interaction[](0), _err(ISCaaSDex.TokenNotKnown.selector, address(c)));
        p = _plan(_leg(ALICE_PK, address(a), _order(alice, address(c), 1000, 1900, 0), 1000, 1900));
        _expectExchange(p, new ISCaaSDex.Interaction[](0), _err(ISCaaSDex.TokenNotKnown.selector, address(c)));
        vm.startPrank(admin);
        dex.setMarket(address(a), address(b), true); // already listed: no second count
        dex.setMarket(address(a), address(b), false);
        vm.stopPrank();
        assertFalse(dex.tokenKnown(address(a)));
        assertTrue(dex.tokenKnown(address(b))); // still a side of USDC/B
        assertEq(dex.tokenKind(address(a)), 1); // the kind stays recorded
        _expectExchange(_plan(_alice()), new ISCaaSDex.Interaction[](0),
            _err(ISCaaSDex.TokenNotKnown.selector, address(a)));
        vm.prank(admin);
        dex.setMarket(address(a), address(b), true);
        assertTrue(dex.tokenKnown(address(a)));
    }

    function test_exchange_distinctSigners_noLegs_relayer_priceLimit() public {
        DexLegs.ExchangeLeg memory l2 = _alice();
        l2.o.nonce = 2;
        l2 = _leg(ALICE_PK, address(a), l2.o, 1000, 1900);
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 2000, 3800);
        _expectExchange(_plan2(_alice(), l2), xs, abi.encodeWithSelector(ISCaaSDex.SelfTrade.selector, bytes32(uint256(uint160(alice)))));
        _expectExchange(DexLegs.ExchangePlan("x", new DexLegs.ExchangeLeg[](0), new address[](0)),
            new ISCaaSDex.Interaction[](0), abi.encodeWithSelector(ISCaaSDex.NoLegs.selector));
        ITradeToken.TradeOrder memory o = _order(alice, address(b), 1000, 1900, 0);
        o.relayer = address(0x5EED);
        DexLegs.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1900));
        _expectExchange(p, xs, _err(ISCaaSDex.WrongRelayer.selector, relayer));
        // a floor below the signed limit: the token refuses it (Path A)
        p = _plan(_leg(ALICE_PK, address(a), _order(alice, address(b), 1000, 1900, 0), 1000, 1899));
        bytes32 h = a.tradeOrderDigest(p.legs[0].o);
        _expectExchange(p, _swap(address(a), address(b), 1000, 2000),
            abi.encodeWithSelector(ITradeToken.PriceLimit.selector, h));
    }

    // ------------------------------------------------------------------ path (b): the executor

    /// The executor is handed the sold fills (Path B remainder kept for the refund) and told the floors; it pays 1000
    /// more than the floors, which goes to the signers as on path (a) (513 and 487) and carries no fee.
    function test_exchangeVia_executorPaysMore_distributed() public {
        ITradeToken.TradeOrder memory oc = _order(carol, address(b), 2000, 3600, 1_000);
        oc.flags = 3;
        DexLegs.ExchangePlan memory p = _plan2(_alice(), _leg(CAROL_PK, address(a), oc, 1000, 1800));
        MockExecutor e = _executor();
        vm.prank(relayer);
        dex.mtxExchangeVia(DexLegs.wire(p), address(e), abi.encode(int256(1000)));
        assertEq(b.balanceOf(alice), 1900 - 6 + 513);
        assertEq(b.balanceOf(carol), 1800 - 2 + 487);
        assertEq(b.balanceOf(treasury), 7);
        assertEq(a.balanceOf(carol), 100_000 - 1000);
        assertEq(a.balanceOf(address(e)), 2000);
        (address[] memory to, uint256[] memory ao, address[] memory ti, uint256[] memory ai) = e.got();
        assertEq(to.length, 1);
        assertEq(to[0], address(a));
        assertEq(ao[0], 2000);
        assertEq(ti.length, 1);
        assertEq(ti[0], address(b));
        assertEq(ai[0], 3700);
    }

    function test_exchangeVia_executorPaysLess_reverts() public {
        DexLegs.ExchangePlan memory p = _twoLegs();
        MockExecutor e = _executor();
        vm.prank(relayer);
        vm.expectRevert(_err(ISCaaSDex.InsufficientOutput.selector, address(b)));
        dex.mtxExchangeVia(DexLegs.wire(p), address(e), abi.encode(int256(-1)));
    }

    /// An executor that re-enters the DEX, calls `mtxTrade` of a resting order or calls the puller fails.
    function test_exchangeVia_hostileExecutor_reenterTradePull_fail() public {
        DexLegs.ExchangePlan memory p = _plan(_alice());
        MockExecutor e = _executor();
        bytes memory data = abi.encode(int256(0));
        ITradeToken.TradeOrder memory ob = _order(bob, address(a), 1000, 500, 0);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BOB_PK, b.tradeOrderDigest(ob));
        bytes[3] memory calls = [
            abi.encodeCall(ISCaaSDex.mtxSettle, (DexLegs.wire(new DexLegs.Settlement[](0)))),
            abi.encodeCall(ITradeToken.mtxTrade, (ob, abi.encodePacked(r, s, v), ITradeToken.TradeFill(1000, 1e9, 0, relayer))),
            abi.encodeCall(DexPuller.pull, (address(usdc), dave, 1))
        ];
        address[3] memory targets = [address(dex), address(b), puller];
        bytes[3] memory errs = [
            abi.encodeWithSelector(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector),
            abi.encodeWithSelector(ITradeToken.NotDex.selector, address(e)),
            abi.encodeWithSelector(DexPuller.NotDex.selector, address(e))
        ];
        for (uint256 i; i < 3; ++i) {
            e.setCall(targets[i], calls[i]);
            vm.prank(relayer);
            vm.expectRevert(errs[i]);
            dex.mtxExchangeVia(DexLegs.wire(p), address(e), data);
        }
    }

    // ------------------------------------------------------------------ admin (CTR-DEX-03)

    function test_setExchangeTarget_setListedOnly_onlyAdmin() public {
        vm.expectRevert(_err(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setExchangeTarget(address(router), true);
        vm.expectRevert(_err(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setListedOnly(true);
        vm.startPrank(admin);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ExchangeTargetSet(address(router), true);
        dex.setExchangeTarget(address(router), true);
        vm.expectEmit(address(dex));
        emit ISCaaSDex.ListedOnlySet(true);
        dex.setListedOnly(true);
        vm.stopPrank();
        assertTrue(dex.exchangeTarget(address(router)));
        assertTrue(dex.listedOnly());
    }

    // ------------------------------------------------------------------ final-review pins

    /// Three legs receive B and the last B receiver (Dave) is not the last leg (Bob receives A): the
    /// split is pro rata over all floors and the remainder goes to the last receiver, not the last leg. Excess 250 B
    /// over floors 1900/1800/3800: 63, 60 and the remainder 127.
    function test_exchange_surplusSplit_threeReceivers_lastReceiverNotLastLeg() public {
        DexLegs.ExchangePlan memory p;
        p.ref = "x";
        p.legs = new DexLegs.ExchangeLeg[](4);
        DexLegs.ExchangePlan memory two = _twoLegs();
        p.legs[0] = two.legs[0];
        p.legs[1] = two.legs[1];
        p.legs[2] = _leg(DAVE_PK, address(usdc), _order(dave, address(b), 2000, 3800, 0), 2000, 3800);
        p.legs[3] = _leg(BOB_PK, address(b), _order(bob, address(a), 1000, 500, 0), 1000, 500);
        ISCaaSDex.Interaction[] memory xs =
            _cat(_swap(address(a), address(b), 1500, 2850), _swap(address(usdc), address(b), 2000, 3900));
        uint256 bobA = a.balanceOf(bob);
        _exchange(p, xs);
        assertEq(b.balanceOf(alice), 1900 - 6 + 63);
        assertEq(b.balanceOf(carol), 1800 - 2 + 60);
        assertEq(b.balanceOf(dave), 3800 + 127);
        assertEq(a.balanceOf(bob) - bobA, 500);
    }

    /// `LISTED_POOLS` on the second leg only still requires listed targets.
    function test_exchange_listedPools_onTheSecondLeg() public {
        ITradeToken.TradeOrder memory oc = _order(carol, address(b), 1999, 3597, 1_000);
        oc.flags = 4;
        DexLegs.ExchangePlan memory p = _plan2(_alice(), _leg(CAROL_PK, address(a), oc, 1000, 1800));
        _expectExchange(p, _swap(address(a), address(b), 2000, 3800), _err(ISCaaSDex.TargetNotListed.selector, address(a)));
    }

    /// Delisting every market of the quote token makes it unknown.
    function test_exchange_delistQuote_makesItUnknown() public {
        vm.startPrank(admin);
        dex.setMarket(address(a), address(b), false);
        dex.setMarket(address(usdc), address(b), false);
        vm.stopPrank();
        assertFalse(dex.tokenKnown(address(b)));
    }

    /// An `approve` with trailing calldata is reset too.
    function test_exchange_approveWithTrailingBytes_isReset() public {
        ISCaaSDex.Interaction[] memory xs = _swap(address(a), address(b), 1000, 2000);
        xs[0].data = abi.encodePacked(abi.encodeCall(IERC20.approve, (address(router), type(uint256).max)), bytes32(0));
        _exchange(_plan(_alice()), xs);
        assertEq(a.allowance(address(dex), address(router)), 0);
    }

    /// The event's `ref` and `from` topics.
    function test_exchange_legEvent_refAndFromTopics() public {
        ITradeToken.TradeOrder memory o = _order(alice, address(b), 1000, 1900, 3_000);
        o.destination = address(0xD0D0);
        DexLegs.ExchangePlan memory p = _plan(_leg(ALICE_PK, address(a), o, 1000, 1900));
        vm.recordLogs();
        _exchange(p, _swap(address(a), address(b), 1000, 2000));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 k; k < logs.length; ++k) {
            if (logs[k].topics[0] != ISCaaSDex.ExchangeLegSettled.selector) continue;
            assertEq(logs[k].topics[1], bytes32("x"));
            assertEq(logs[k].topics[3], bytes32(uint256(uint160(alice))));
            return;
        }
        revert("no event");
    }

    /// The executor is told the plan's `ref`.
    function test_exchange_executorGetsTheRef() public {
        RefExecutor e = new RefExecutor();
        vm.prank(bob);
        b.transfer(address(e), 10_000);
        vm.prank(relayer);
        dex.mtxExchangeVia(DexLegs.wire(_plan(_alice())), address(e), "");
        assertEq(e.ref(), bytes32("x"));
    }

    /// A relayer-bound order settles on the exchange path when its relayer submits.
    function test_exchange_relayerBoundOrder_settles() public {
        ITradeToken.TradeOrder memory o = _order(alice, address(b), 1000, 1900, 0);
        o.relayer = relayer;
        _exchange(_plan(_leg(ALICE_PK, address(a), o, 1000, 1900)), _swap(address(a), address(b), 1000, 2000));
        assertEq(b.balanceOf(alice), 2000);
    }
}
