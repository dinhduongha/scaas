// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UID_, noneInit} from "./helpers/V2Fixture.sol";

/// ERC-1271 makers that must not take other settlements down with them.
contract Burner1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4 r) { r = 0; while (true) {} }
}
contract Bomb1271 {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        assembly { return(0, 200000) }
    }
}

/// `SCaaSDex` as a factory clone (CTR-DEX-24) settling SCaaS legs (CTR-DEX-16, -17, -11): one taker against many makers,
/// every leg pulled through its token's `mtxTrade`, every party paid in the same call, the fee split, conservation.
contract DexTest is Test {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    uint256 constant CAROL_PK = 0xCA401;
    address alice = vm.addr(ALICE_PK);
    address bob = vm.addr(BOB_PK);
    address carol = vm.addr(CAROL_PK);
    address registrar = address(0xF00D);
    address admin = address(0xAD);
    address treasury = address(0x7EA5);
    address relayer = address(0xBEEF);

    OpenFactory f;
    SCaaSDex dexImpl;
    SCaaSDex dex;
    NoUnderlyingToken a; // the taker sells A
    NoUnderlyingToken b; // the makers sell B

    function setUp() public {
        f = new OpenFactory(registrar, UID_);
        address noneImpl = address(new NoUnderlyingToken(address(f), address(0), UID_, address(0), false));
        dexImpl = new SCaaSDex(address(f), UID_, address(0));
        vm.startPrank(registrar);
        f.registerImplementation(IOpenFactory.TokenKind.NONE, 1, noneImpl);
        f.registerDexImplementation(1, address(dexImpl));
        vm.stopPrank();
        a = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1, noneInit("A", "A", 0, 1e6, alice, address(0)), "a"));
        IFactoryToken.TokenConfig memory cb = noneInit("B", "B", 0, 1e6, bob, address(0));
        b = NoUnderlyingToken(f.createToken(IOpenFactory.TokenKind.NONE, 1, cb, "b"));
        vm.prank(bob);
        b.transfer(carol, 500_000);
        dex = SCaaSDex(f.createDex(1, ISCaaSDex.DexConfig(admin, 200_000, treasury, false), "dex"));
        vm.prank(admin);
        dex.setMarket(address(a), address(b), true);
    }

    // ------------------------------------------------------------------ helpers

    function _order(address from, NoUnderlyingToken receiveToken, uint256 amount, uint256 receiveAmount, uint256 fee)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        o.from = from;
        o.receiveToken = address(receiveToken);
        o.amount = amount;
        o.receiveAmount = receiveAmount;
        o.fee = fee;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = 1;
        o.validUntil = block.timestamp + 300;
    }

    function _leg(uint256 pk, NoUnderlyingToken sell, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (DexLegs.Leg memory l)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, sell.tradeOrderDigest(o));
        l = DexLegs.Leg(address(sell), o, abi.encodePacked(r, s, v), fill);
    }

    function _one(DexLegs.Settlement memory s) internal pure returns (DexLegs.Settlement[] memory ss) {
        ss = new DexLegs.Settlement[](1);
        ss[0] = s;
    }

    /// Alice sells 1000 A for at least 1900 B (fee 0.3 %); Bob sells 1000 B for 500 A, Carol 1000 B for 520 A (fee 0.1 %).
    function _book() internal view returns (DexLegs.Settlement memory s) {
        s.ref = "r1";
        s.makers = new DexLegs.Leg[](2);
        s.makers[0] = _leg(BOB_PK, b, _order(bob, a, 1000, 500, 1_000), 1000);
        s.makers[1] = _leg(CAROL_PK, b, _order(carol, a, 1000, 520, 1_000), 1000);
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 1020, 1900, 3_000), 1020); // 500 + 520 at the makers' prices
    }

    // ------------------------------------------------------------------ settle

    function test_settle_oneTakerTwoMakers_paysEveryone_splitsFees_conserves() public {
        DexLegs.Settlement[] memory ss = _one(_book()); // before the prank: _book makes external calls
        vm.recordLogs();
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(DexLegs.wire(ss));
        assertTrue(ok[0]);
        // taker: receives 2000 B gross, fee ceil(2000·0.3 %) = 6 → 1994; relayer share 20 % of 6 = 1, treasury 5
        assertEq(b.balanceOf(alice), 1994);
        assertEq(a.balanceOf(alice), 1e6 - 1020);
        // makers: 500 A and 520 A gross, fee ceil(0.5) = 1 each → 499 and 519; relayer floor(0.2) = 0
        assertEq(a.balanceOf(bob), 499);
        assertEq(a.balanceOf(carol), 519);
        assertEq(b.balanceOf(relayer), 1);
        assertEq(b.balanceOf(treasury), 5);
        assertEq(a.balanceOf(treasury), 2);
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
        uint256 legs;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) if (logs[i].topics[0] == ISCaaSDex.LegSettled.selector) ++legs;
        assertEq(legs, 3);
    }

    function test_makerPriceRoundsInTheMakersFavour() public {
        DexLegs.Settlement memory s;
        s.ref = "r";
        s.makers = new DexLegs.Leg[](1);
        s.makers[0] = _leg(BOB_PK, b, _order(bob, a, 1000, 333, 0), 1000); // 1000 B for 333 A
        // a 600 B fill would pay ceil(600·333/1000) = ceil(199.8) = 200 A, but 600 < half-of-1000 floor? 600 ≥ 500: ok
        s.makers[0] = _leg(BOB_PK, b, _order(bob, a, 1000, 333, 0), 600);
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 200, 600, 0), 200);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(_one(s)));
        assertEq(a.balanceOf(bob), 200);
        assertEq(b.balanceOf(alice), 600);
    }

    function test_takerFeeChargedOnceOnTheAggregate() public {
        // each maker leg alone would give the taker 1000 B → ceil(3) = 3 + 3 = 6; on the aggregate 2000 → 6: same here,
        // so use a rate where the per-maker ceilings exceed the aggregate: 0.15 % → per-maker ceil(1.5)=2+2=4, aggregate 3
        DexLegs.Settlement memory s = _book();
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 1020, 1900, 1_500), 1020);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(_one(s)));
        assertEq(b.balanceOf(alice), 1997);
    }

    function test_pathB_escrowMakerRefundsTheRest() public {
        DexLegs.Settlement memory s;
        s.ref = "r";
        s.makers = new DexLegs.Leg[](1);
        ITradeToken.TradeOrder memory mo = _order(bob, a, 1000, 500, 0);
        mo.flags = 3; // IOC | ESCROW
        s.makers[0] = _leg(BOB_PK, b, mo, 600);
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 300, 600, 0), 300);
        uint256 bobB = b.balanceOf(bob);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(_one(s)));
        assertEq(b.balanceOf(bob), bobB - 600); // pulled 1000, refunded 400
        assertEq(a.balanceOf(bob), 300);
        assertEq(b.balanceOf(address(dex)), 0);
    }

    function test_pathB_dexChecksTheMatchedPart() public {
        ITradeToken.TradeOrder memory mo = _order(bob, a, 1000, 500, 0);
        mo.flags = 3;
        DexLegs.Settlement memory s;
        s.ref = "r";
        s.makers = new DexLegs.Leg[](1);
        s.makers[0] = _leg(BOB_PK, b, mo, 400); // below the 50 % floor
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 200, 400, 0), 200);
        bytes32 h = b.tradeOrderDigest(mo);
        vm.prank(relayer);
        vm.expectRevert(ISCaaSDex.NothingSettled.selector);
        dex.mtxSettle(DexLegs.wire(_one(s)));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.BelowMinFill.selector, h));
        vm.prank(address(dex));
        dex.settleOne(DexLegs.wire(s), relayer);
    }

    function test_aFailingSettlementIsIsolated() public {
        DexLegs.Settlement[] memory ss = new DexLegs.Settlement[](2);
        ss[0] = _book();
        ss[0].makers[0].sig[0] = bytes1(uint8(ss[0].makers[0].sig[0]) ^ 1); // a bad maker signature
        ss[1] = _book();
        ss[1].ref = "r2";
        ss[1].makers[0].o.nonce = 2;
        ss[1].makers[0] = _leg(BOB_PK, b, ss[1].makers[0].o, 1000);
        ss[1].makers[1].o.nonce = 2;
        ss[1].makers[1] = _leg(CAROL_PK, b, ss[1].makers[1].o, 1000);
        ss[1].taker.o.nonce = 2;
        ss[1].taker = _leg(ALICE_PK, a, ss[1].taker.o, 1020);
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle(DexLegs.wire(ss));
        assertFalse(ok[0]);
        assertTrue(ok[1]);
        assertEq(b.balanceOf(alice), 1994);
    }

    function test_checks() public {
        DexLegs.Settlement memory s = _book();
        s.taker.fill = 1019;
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.FillMismatch.selector, 1020, 1019));
        s = _book();
        s.makers[1] = s.makers[0];
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.DuplicateOrder.selector, b.tradeOrderDigest(s.makers[0].o)));
        s = _book();
        s.makers[0] = _leg(ALICE_PK, b, _order(alice, a, 1000, 500, 1_000), 1000);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.SelfTrade.selector, bytes32(uint256(uint160(alice)))));
        s = _book();
        s.makers[0].sellToken = address(a);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.TokenMismatch.selector));
        s = _book();
        ITradeToken.TradeOrder memory o = _order(alice, b, 1020, 1900, 3_000);
        o.relayer = address(0x5E1);
        s.taker = _leg(ALICE_PK, a, o, 1020);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.WrongRelayer.selector, relayer));
        s = _book();
        s.makers = new DexLegs.Leg[](0);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.NoMakers.selector));
        vm.prank(admin);
        dex.setMarket(address(a), address(b), false);
        _expectOne(_book(), abi.encodeWithSelector(ISCaaSDex.MarketNotListed.selector, address(a), address(b)));
    }

    // ------------------------------------------------------------------ what only the DEX enforces

    function test_legSettled_receivedIsNetOfTheFee_everyField() public {
        DexLegs.Settlement[] memory ss = _one(_book());
        bytes32 hT = a.tradeOrderDigest(ss[0].taker.o);
        bytes32 hB = b.tradeOrderDigest(ss[0].makers[0].o);
        bytes32 hC = b.tradeOrderDigest(ss[0].makers[1].o);
        vm.recordLogs();
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 n;
        // taker, then the makers in order
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] != ISCaaSDex.LegSettled.selector) continue;
            if (n == 0) _checkLeg(logs[i], hT, alice, 1020, 2000, 6, 1);
            if (n == 1) _checkLeg(logs[i], hB, bob, 1000, 500, 1, 0);
            if (n == 2) _checkLeg(logs[i], hC, carol, 1000, 520, 1, 0);
            ++n;
        }
        assertEq(n, 3);
    }

    function _checkLeg(Vm.Log memory lg, bytes32 h, address from, uint256 sold, uint256 gross, uint256 fee, uint256 rel)
        internal view
    {
        assertEq(lg.emitter, address(dex));
        assertEq(lg.topics[1], "r1");
        assertEq(lg.topics[2], h);
        assertEq(address(uint160(uint256(lg.topics[3]))), from);
        (address dest, uint256 s_, uint256 recv, uint256 dexFee, uint256 refund, uint256 rs, uint256 ts) =
            abi.decode(lg.data, (address, uint256, uint256, uint256, uint256, uint256, uint256));
        assertEq(dest, from);
        assertEq(s_, sold);
        assertEq(dexFee, fee);
        assertEq(recv + dexFee, gross); // `received` is net
        assertEq(refund, 0);
        assertEq(rs, rel);
        assertEq(rs + ts, dexFee);
    }

    function test_pathB_takerBelowItsLimit_priceLimit() public {
        DexLegs.Settlement memory s;
        s.ref = "r";
        s.makers = new DexLegs.Leg[](1);
        s.makers[0] = _leg(BOB_PK, b, _order(bob, a, 1000, 500, 0), 1000);
        ITradeToken.TradeOrder memory o = _order(alice, b, 500, 1050, 0); // wants 2.1 B per A, the maker gives 2
        o.flags = 3;
        s.taker = _leg(ALICE_PK, a, o, 500);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.PriceLimit.selector, a.tradeOrderDigest(o)));
    }

    function test_pathB_takerPartialMatch_refundsInA() public {
        DexLegs.Settlement memory s = _book();
        ITradeToken.TradeOrder memory o = _order(alice, b, 1200, 2000, 3_000);
        o.flags = 3; // IOC | ESCROW: pulls 1200, matched 1020; fee 0.3 % on the 2000 B received
        s.taker = _leg(ALICE_PK, a, o, 1020);
        DexLegs.Settlement[] memory ss = _one(s);
        vm.recordLogs();
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(a.balanceOf(alice), 1e6 - 1020); // 180 came back
        assertEq(b.balanceOf(alice), 1994); // 2000 gross, fee 6
        assertEq(a.balanceOf(address(dex)), 0);
        assertEq(b.balanceOf(address(dex)), 0);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] != ISCaaSDex.LegSettled.selector || address(uint160(uint256(logs[i].topics[3]))) != alice) continue;
            (, uint256 sold,,, uint256 refund,,) = abi.decode(logs[i].data, (address, uint256, uint256, uint256, uint256, uint256, uint256));
            assertEq(sold, 1020);
            assertEq(refund, 180);
        }
    }

    // What only the DEX enforces on a Path B leg (the token sees `TradeFill(amount, 0, 0, submitter)`): the signed
    // minFill above 50 %, the signed fee rate, the refund recipient.

    function _escrowMaker(ITradeToken.TradeOrder memory mo, uint256 fill) internal view returns (DexLegs.Settlement memory s) {
        mo.flags = 3; // IOC | ESCROW
        s.ref = "r";
        s.makers = new DexLegs.Leg[](1);
        s.makers[0] = _leg(BOB_PK, b, mo, fill);
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 300, 600, 0), 300);
    }

    function test_pathB_signedMinFillAboveHalf_isEnforced() public {
        ITradeToken.TradeOrder memory mo = _order(bob, a, 1000, 500, 0);
        mo.minFill = 1000; // fill-or-kill
        DexLegs.Settlement memory s = _escrowMaker(mo, 600);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BelowMinFill.selector, b.tradeOrderDigest(mo)));
    }

    function test_pathB_makerFeeIsAtTheSignedRate() public {
        DexLegs.Settlement[] memory ss = _one(_escrowMaker(_order(bob, a, 1000, 500, 10_000), 600)); // 1 %
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(a.balanceOf(bob), 297); // 300 gross, fee ceil(3) = 3 (not 6, not on the signed 500)
        assertEq(a.balanceOf(relayer) + a.balanceOf(treasury), 3);
    }

    function test_pathB_refundGoesToFrom_proceedsToDestination() public {
        address dest = address(0xDE57);
        ITradeToken.TradeOrder memory mo = _order(bob, a, 1000, 500, 0);
        mo.destination = dest;
        DexLegs.Settlement[] memory ss = _one(_escrowMaker(mo, 600));
        uint256 bobB = b.balanceOf(bob);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(b.balanceOf(bob), bobB - 600); // the 400 refund came back to `from`
        assertEq(b.balanceOf(dest), 0);
        assertEq(a.balanceOf(dest), 300);
    }

    // Path A: the token checks price and fee against the figures the DEX hands it, so they must be what it pays.

    function test_pathA_takerLimitOneAboveTheFill_tokenRefuses() public {
        DexLegs.Settlement memory s = _book(); // the taker receives 2000 B for 1020 A
        ITradeToken.TradeOrder memory o = _order(alice, b, 1020, 2001, 3_000);
        s.taker = _leg(ALICE_PK, a, o, 1020);
        _expectOne(s, abi.encodeWithSelector(ITradeToken.PriceLimit.selector, a.tradeOrderDigest(o)));
    }

    function test_pathA_takerExactlyAtItsLimit_settles() public {
        DexLegs.Settlement memory s = _book();
        s.taker = _leg(ALICE_PK, a, _order(alice, b, 1020, 2000, 3_000), 1020);
        DexLegs.Settlement[] memory ss = _one(s);
        vm.prank(relayer);
        assertTrue(dex.mtxSettle(DexLegs.wire(ss))[0]);
        assertEq(b.balanceOf(alice), 1994);
    }

    function test_pathA_tokenSeesTheSettledFigures() public {
        DexLegs.Settlement[] memory ss = _one(_book());
        vm.recordLogs();
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 seen;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] != ITradeToken.TradeFilled.selector) continue;
            (, uint256 rf, uint256 fee) = abi.decode(logs[i].data, (uint256, uint256, uint256));
            if (logs[i].emitter == address(a)) {
                assertEq(rf, 2000); // the taker's gross receive and fee
                assertEq(fee, 6);
            } else {
                assertEq(rf, address(uint160(uint256(logs[i].topics[2]))) == bob ? 500 : 520);
                assertEq(fee, 1);
            }
            ++seen;
        }
        assertEq(seen, 3);
    }

    function test_reverseDirectionOfAListedMarket() public {
        assertTrue(dex.marketListed(address(a), address(b)));
        assertTrue(dex.marketListed(address(b), address(a)));
        // and it settles with the roles swapped: Bob (sells B) is the taker, Alice and a second A-seller the makers
        DexLegs.Settlement memory s;
        s.ref = "rv";
        s.makers = new DexLegs.Leg[](1);
        s.makers[0] = _leg(ALICE_PK, a, _order(alice, b, 500, 1000, 0), 500);
        s.taker = _leg(BOB_PK, b, _order(bob, a, 1000, 500, 0), 1000);
        DexLegs.Settlement[] memory ss = _one(s);
        vm.prank(relayer);
        assertTrue(dex.mtxSettle(DexLegs.wire(ss))[0]);
        assertEq(a.balanceOf(bob), 500);
        assertEq(b.balanceOf(alice), 1000);
        vm.prank(admin);
        dex.setMarket(address(b), address(a), false);
        assertFalse(dex.marketListed(address(a), address(b)));
    }

    function test_makerReceiveTokenIsNotTheTakersSellToken_tokenMismatch() public {
        DexLegs.Settlement memory s = _book();
        s.makers[0] = _leg(BOB_PK, b, _order(bob, b, 1000, 500, 1_000), 1000); // sells B for B; sellToken is right
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.TokenMismatch.selector));
    }

    function test_destination_proceedsGoThere_andNeverToTheDex() public {
        address dest = address(0xDE57);
        DexLegs.Settlement memory s = _book();
        ITradeToken.TradeOrder memory o = _order(alice, b, 1020, 1900, 3_000);
        o.destination = dest;
        s.taker = _leg(ALICE_PK, a, o, 1020);
        DexLegs.Settlement[] memory ss = _one(s);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(b.balanceOf(dest), 1994);
        assertEq(b.balanceOf(alice), 0);
        // to the DEX itself: the balance check refuses it
        o.destination = address(dex);
        o.nonce = 2;
        s.taker = _leg(ALICE_PK, a, o, 1020);
        s.makers[0].o.nonce = 2;
        s.makers[0] = _leg(BOB_PK, b, s.makers[0].o, 1000);
        s.makers[1].o.nonce = 2;
        s.makers[1] = _leg(CAROL_PK, b, s.makers[1].o, 1000);
        s.taker = _leg(ALICE_PK, a, o, 1020);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(b)));
    }

    function test_makerDestinationIsTheDex_conservationBroken() public {
        DexLegs.Settlement memory s = _book();
        ITradeToken.TradeOrder memory o = _order(bob, a, 1000, 500, 1_000);
        o.destination = address(dex);
        s.makers[0] = _leg(BOB_PK, b, o, 1000);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.ConservationBroken.selector, address(a)));
    }

    function test_classification_deprecatedAndUnregisteredAreOutside() public {
        address impl = address(new NoUnderlyingToken(address(f), address(0), UID_, address(0), false));
        address u = f.createTokenUnregistered(
            IOpenFactory.TokenKind.NONE, impl, noneInit("C", "C", 0, 1e6, alice, address(0)), "c");
        vm.startPrank(admin);
        dex.setMarket(address(a), u, true);
        assertEq(dex.tokenKind(u), 2);
        assertEq(dex.tokenKind(address(a)), 1);
        vm.stopPrank();
        vm.prank(registrar);
        f.deprecate(IOpenFactory.TokenKind.NONE, 1, "x");
        assertEq(dex.tokenKind(address(a)), 1); // a snapshot: unchanged until the market is listed again
        vm.prank(admin);
        dex.setMarket(address(a), address(b), true);
        assertEq(dex.tokenKind(address(a)), 2);
        assertEq(dex.tokenKind(address(b)), 2);
    }

    // ------------------------------------------------------------------ CTR-DEX-11: the fee rounds up

    /// Bob sells `n` B for `n` A at no fee; Alice sells `n` A at `fee` ppm and receives `n` B gross. Returns the fee.
    function _swap(uint256 n, uint256 fee, uint256 nonce) internal returns (uint256 dexFee) {
        DexLegs.Settlement memory s;
        s.ref = "r";
        s.makers = new DexLegs.Leg[](1);
        ITradeToken.TradeOrder memory mo = _order(bob, a, n, n, 0);
        mo.nonce = nonce;
        s.makers[0] = _leg(BOB_PK, b, mo, n);
        ITradeToken.TradeOrder memory to = _order(alice, b, n, n, fee);
        to.nonce = nonce;
        s.taker = _leg(ALICE_PK, a, to, n);
        DexLegs.Settlement[] memory ss = _one(s);
        uint256 before = b.balanceOf(alice);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        dexFee = n - (b.balanceOf(alice) - before);
    }

    function test_feeRoundsUp() public {
        assertEq(_swap(333, 3_000, 1), 1); // ceil(0.999)
        assertEq(b.balanceOf(alice), 332);
        assertEq(_swap(1, 3_000, 2), 1); // a 1-unit receive pays 1 and receives 0
        assertEq(b.balanceOf(alice), 332);
        assertEq(_swap(1_000, 3_000, 3), 3); // an exact multiple is unchanged
    }

    function test_feeRoundsUp_splittingNeverPaysLess() public {
        uint256 ten;
        for (uint256 i; i < 10; ++i) ten += _swap(100, 3_000, 10 + i);
        uint256 one = _swap(1_000, 3_000, 30);
        assertEq(one, 3);
        assertEq(ten, 10);
        assertGe(ten, one);
    }

    function testFuzz_feeRoundsUp(uint256 n, uint256 fee) public {
        n = bound(n, 1, 400_000);
        fee = bound(fee, 0, 10_000);
        uint256 dexFee = _swap(n, fee, 1);
        assertLe(dexFee, n);
        assertGe(dexFee * 1e6, n * fee);
        if (dexFee != 0) assertLt((dexFee - 1) * 1e6, n * fee); // and the smallest such
    }

    // ------------------------------------------------------------------ a hostile ERC-1271 maker costs only its own settlement

    function _hostileMaker(address w) internal {
        vm.prank(bob);
        b.transfer(w, 1000);
        DexLegs.Settlement[] memory ss = new DexLegs.Settlement[](2);
        ss[0] = _book();
        ss[0].makers[0] = DexLegs.Leg(address(b), _order(w, a, 1000, 500, 1_000), hex"00", 1000);
        ss[1] = _book();
        ss[1].ref = "r2";
        ss[1].makers[0].o.nonce = 2;
        ss[1].makers[0] = _leg(BOB_PK, b, ss[1].makers[0].o, 1000);
        ss[1].makers[1].o.nonce = 2;
        ss[1].makers[1] = _leg(CAROL_PK, b, ss[1].makers[1].o, 1000);
        ss[1].taker.o.nonce = 2;
        ss[1].taker = _leg(ALICE_PK, a, ss[1].taker.o, 1020);
        vm.prank(relayer);
        bool[] memory ok = dex.mtxSettle{gas: 3_000_000}(DexLegs.wire(ss));
        assertFalse(ok[0]);
        assertTrue(ok[1]);
        assertEq(b.balanceOf(alice), 1994);
    }

    function test_gasBurning1271Maker_othersStillSettle() public { _hostileMaker(address(new Burner1271())); }
    function test_returndataBomb1271Maker_othersStillSettle() public { _hostileMaker(address(new Bomb1271())); }

    /// The kind is the DEX's listing, never the leg's: once the version is deprecated and the market listed again, `a`
    /// and `b` are outside, a leg signed on the token is checked against its `DexOrder` digest, and the fill is pulled
    /// through the puller (EOAs cannot approve a SCaaS token, CTR-TOK-01, so it fails on the allowance).
    function test_deprecatedTokenListedAsOutside_isADexOrderPulledByThePuller() public {
        vm.prank(registrar);
        f.deprecate(IOpenFactory.TokenKind.NONE, 1, "x");
        vm.prank(admin);
        dex.setMarket(address(a), address(b), true);
        DexLegs.Settlement memory s = _book();
        bytes32 h = dex.dexOrderDigest(address(a), s.taker.o);
        _expectOne(s, abi.encodeWithSelector(ISCaaSDex.BadSignature.selector, h));
        s.taker = _dexLeg(ALICE_PK, address(a), s.taker.o, 1020);
        // the puller drops the token's revert data (W-O): a fixed error names the token
        _expectOne(s, abi.encodeWithSelector(SafeERC20.SafeERC20FailedOperation.selector, address(a)));
    }

    /// Alice sells 1020 of an outside token (a `DexOrder`, pulled by the puller) against the SCaaS makers of `_book`.
    function test_takerSellsAnOutsideToken_settles() public {
        MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);
        usdc.mint(alice, 5000);
        vm.prank(admin);
        dex.setMarket(address(usdc), address(b), true);
        assertEq(dex.tokenKind(address(usdc)), 2);
        assertEq(dex.tokenKind(address(b)), 1);
        address p = dex.puller();
        vm.prank(alice);
        usdc.approve(p, 1020);
        DexLegs.Settlement memory s = _book();
        for (uint256 i; i < 2; ++i) {
            ITradeToken.TradeOrder memory mo = s.makers[i].o;
            mo.receiveToken = address(usdc);
            s.makers[i] = _leg(i == 0 ? BOB_PK : CAROL_PK, b, mo, 1000);
        }
        s.taker = _dexLeg(ALICE_PK, address(usdc), s.taker.o, 1020);
        bytes32 h = dex.dexOrderDigest(address(usdc), s.taker.o);
        DexLegs.Settlement[] memory ss = _one(s);
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(b.balanceOf(alice), 1994);
        assertEq(usdc.balanceOf(alice), 5000 - 1020);
        assertEq(usdc.balanceOf(bob), 499); // 500 less ceil(0.5) fee
        assertEq(usdc.balanceOf(carol), 519);
        assertEq(usdc.balanceOf(address(dex)), 0);
        assertEq(dex.pulled(h), 1020);
    }

    function _dexLeg(uint256 pk, address sellToken, ITradeToken.TradeOrder memory o, uint256 fill)
        internal view returns (DexLegs.Leg memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, dex.dexOrderDigest(sellToken, o));
        return DexLegs.Leg(sellToken, o, abi.encodePacked(r, s, v), fill);
    }

    function test_settleOneOnlyThroughSettle() public {
        DexLegs.Settlement memory s = _book();
        vm.expectRevert(ISCaaSDex.NotSelf.selector);
        dex.settleOne(DexLegs.wire(s), relayer);
    }

    function _expectOne(DexLegs.Settlement memory s, bytes memory err) internal {
        vm.prank(address(dex));
        vm.expectRevert(err);
        dex.settleOne(DexLegs.wire(s), relayer);
    }

    // ------------------------------------------------------------------ factory and admin (CTR-DEX-24, CTR-DEX-03)

    function test_createDex_registry_andInitializeOnce() public {
        assertTrue(f.isDex(address(dex)));
        assertEq(f.dexVersionOf(address(dex)), 1);
        assertFalse(f.isDex(address(dexImpl)));
        assertEq(dex.admin(), admin);
        assertEq(dex.treasury(), treasury);
        assertEq(dex.relayerSharePpm(), 200_000);
        vm.expectRevert(ISCaaSDex.NotFactory.selector);
        dex.initialize(address(this), 1, ISCaaSDex.DexConfig(admin, 0, treasury, false));
        vm.prank(address(f));
        vm.expectRevert(ISCaaSDex.AlreadyInitialized.selector);
        dex.initialize(address(this), 1, ISCaaSDex.DexConfig(admin, 0, treasury, false));
        vm.prank(address(f));
        vm.expectRevert(ISCaaSDex.AlreadyInitialized.selector);
        dexImpl.initialize(address(this), 1, ISCaaSDex.DexConfig(admin, 0, treasury, false));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.DexVersionUnknown.selector, 2));
        f.createDex(2, ISCaaSDex.DexConfig(admin, 0, treasury, false), "x");
    }

    function test_dexCatalogue_versionZeroRefused_latestTracksTheHighest() public {
        assertEq(f.latestDexVersion(), 1);
        SCaaSDex v5 = new SCaaSDex(address(f), UID_, address(0));
        SCaaSDex v2 = new SCaaSDex(address(f), UID_, address(0));
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.DexVersionUnknown.selector, 0));
        f.registerDexImplementation(0, address(v2));
        f.registerDexImplementation(5, address(v5));
        assertEq(f.latestDexVersion(), 5);
        f.registerDexImplementation(2, address(v2)); // an older version does not lower it
        vm.stopPrank();
        assertEq(f.latestDexVersion(), 5);
        assertEq(f.dexImplementationOf(2), address(v2));
        assertEq(f.dexImplementationOf(5), address(v5));
        address d = f.createDex(2, ISCaaSDex.DexConfig(admin, 0, treasury, false), "v2");
        assertEq(f.dexVersionOf(d), 2); // the requested version, not the latest
        assertEq(f.dexVersionOf(address(dex)), 1);
    }

    function test_createDex_saltScopedByCreator_andNotReusable() public {
        ISCaaSDex.DexConfig memory cfg = ISCaaSDex.DexConfig(admin, 0, treasury, false);
        vm.prank(address(0xA1));
        address d1 = f.createDex(1, cfg, "same");
        vm.prank(address(0xA2));
        address d2 = f.createDex(1, cfg, "same");
        assertTrue(d1 != d2);
        vm.prank(address(0xA1));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.SaltAlreadyUsed.selector, d1));
        f.createDex(1, cfg, "same");
    }

    function test_createDex_emitsDexCreated() public {
        address creator = address(0xA1);
        vm.expectEmit(false, true, false, true, address(f)); // the clone address is derived, not asserted
        emit IOpenFactory.DexCreated(address(0), creator, 1, address(dexImpl), address(0xADD));
        vm.prank(creator);
        address d = f.createDex(1, ISCaaSDex.DexConfig(address(0xADD), 0, treasury, false), "ev");
        assertEq(SCaaSDex(d).admin(), address(0xADD));
    }

    function test_registerDex_checksFactoryAndChain() public {
        SCaaSDex other = new SCaaSDex(address(0xFAC), UID_, address(0));
        vm.startPrank(registrar);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ImplementationFactoryMismatch.selector, address(other)));
        f.registerDexImplementation(2, address(other));
        SCaaSDex wrongChain = new SCaaSDex(address(f), keccak256("x"), address(0));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ChainUidMismatch.selector, UID_, keccak256("x")));
        f.registerDexImplementation(2, address(wrongChain));
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.DexVersionAlreadyRegistered.selector, 1, address(dexImpl)));
        f.registerDexImplementation(1, address(dexImpl));
        vm.stopPrank();
        vm.expectRevert(IOpenFactory.NotRegistrar.selector);
        f.registerDexImplementation(3, address(dexImpl));
    }

    function test_adminOnly_feeSplitBounds() public {
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setMarket(address(a), address(b), false);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.NotAdmin.selector, address(this)));
        dex.setFeeSplit(0, treasury);
        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.FeeSplitInvalid.selector, 1, address(0)));
        dex.setFeeSplit(1, address(0));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.FeeSplitInvalid.selector, 1, address(dex)));
        dex.setFeeSplit(1, address(dex));
        vm.expectRevert(abi.encodeWithSelector(ISCaaSDex.FeeSplitInvalid.selector, 1_000_001, treasury));
        dex.setFeeSplit(1_000_001, treasury);
        dex.setFeeSplit(1_000_000, address(0)); // all to the relayer: no treasury needed
        vm.stopPrank();
        DexLegs.Settlement[] memory ss = _one(_book());
        vm.prank(relayer);
        dex.mtxSettle(DexLegs.wire(ss));
        assertEq(b.balanceOf(relayer), 6);
    }

    function test_domainIsTheClone_saltedWithTheChain() public view {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) = dex.eip712Domain();
        assertEq(name, "SCaaS Dex");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(vc, address(dex));
        assertEq(salt, UID_);
        assertEq(dex.chainUid(), UID_);
        assertEq(dex.factory(), address(f));
    }
}
