// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Vm} from "forge-std/Vm.sol";
import {Fixtures} from "./helpers/Fixtures.sol";
import {Mock1271Wallet} from "./helpers/WalletMocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {FeePolicy} from "../src/common/FeePolicy.sol";
import {SCaaSDexV1} from "../src/dex/SCaaSDexV1.sol";

contract SCaaSDexTest is Fixtures {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    uint256 constant CAROL_PK = 0xCA401;
    address alice;
    address bob;
    address carol;
    address admin = address(0xAD);
    address feeTo = address(0xFEE);
    MetaToken tA; // base
    MetaToken tB; // quote
    MetaToken tF; // separate relayer-fee token
    SCaaSDexV1 dex;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(ALICE_PK);
        bob = vm.addr(BOB_PK);
        carol = vm.addr(CAROL_PK);
        _deployFactory();
        dex = new SCaaSDexV1(admin);
        tA = _standalone(address(this), "AAA", 18, 3_000 ether, address(0));
        tB = _standalone(address(this), "BBB", 18, 3_000 ether, address(0));
        tF = _standalone(address(this), "FEE", 18, 3_000 ether, address(0));
        tA.transfer(alice, 1_000 ether);
        tB.transfer(bob, 1_000 ether);
        tB.transfer(carol, 1_000 ether);
        tF.transfer(alice, 1_000 ether);
        _approveAll(alice);
        _approveAll(bob);
        _approveAll(carol);
        _list(false, 0, 0);
    }

    // ------------------------------------------------------------------ helpers

    function _approveAll(address who) internal {
        vm.startPrank(who);
        tA.approve(address(dex), type(uint256).max);
        tB.approve(address(dex), type(uint256).max);
        tF.approve(address(dex), type(uint256).max);
        vm.stopPrank();
    }

    function _list(bool feeOn, uint32 makerPpm, uint32 takerPpm) internal {
        vm.prank(admin);
        dex.setMarket(address(tA), address(tB), SCaaSDexV1.Market(true, feeOn, makerPpm, takerPpm, feeTo));
    }

    function _order(address maker, MetaToken sell, uint256 sellAmt, MetaToken buy, uint256 buyAmt)
        internal view returns (SCaaSDexV1.Order memory o)
    {
        o.maker = maker;
        o.sellToken = address(sell);
        o.buyToken = address(buy);
        o.sellAmount = sellAmt;
        o.buyAmount = buyAmt;
        o.nonce = uint256(keccak256(abi.encode(maker, sellAmt, buyAmt))) >> 160;
        o.expiry = block.timestamp + 300;
        o.maxFeePpm = 10_000;
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signOrder(uint256 pk, SCaaSDexV1.Order memory o) internal view returns (bytes memory) {
        return _sig(pk, dex.orderHash(o));
    }

    function _match(
        SCaaSDexV1.Order memory m, uint256 mpk, SCaaSDexV1.Order memory t, uint256 tpk,
        uint256 makerFill, uint256 takerFill
    ) internal view returns (SCaaSDexV1.Match memory x) {
        x = SCaaSDexV1.Match({
            ref: keccak256(abi.encode(m, t, makerFill)), maker: m, makerSig: _signOrder(mpk, m),
            taker: t, takerSig: _signOrder(tpk, t), makerFill: makerFill, takerFill: takerFill
        });
    }

    function _one(SCaaSDexV1.Match memory x) internal pure returns (SCaaSDexV1.Match[] memory ms) {
        ms = new SCaaSDexV1.Match[](1);
        ms[0] = x;
    }

    function _settle(SCaaSDexV1.Match memory x) internal returns (bool) {
        vm.prank(relayer);
        return dex.settle(_one(x))[0];
    }

    /// Một cặp duy nhất fail ⇒ cả batch revert NothingSettled; lý do thật nằm trong MatchFailed.
    function _expectMatchFails(SCaaSDexV1.Match memory x, bytes memory reason) internal {
        vm.prank(relayer);
        try dex.settle(_one(x)) {
            fail();
        } catch (bytes memory err) {
            assertEq(bytes4(err), SCaaSDexV1.NothingSettled.selector);
        }
        // the inner reason, through a batch that has one good match so the tx survives
        SCaaSDexV1.Order memory gm = _order(carol, tB, 1 ether, tA, 1);
        gm.nonce = ++_goodNonce;
        SCaaSDexV1.Order memory gt = _order(alice, tA, 1, tB, 1 ether);
        gt.nonce = _goodNonce;
        SCaaSDexV1.Match[] memory ms = new SCaaSDexV1.Match[](2);
        ms[0] = x;
        ms[1] = _match(gm, CAROL_PK, gt, ALICE_PK, 1 ether, 1);
        vm.expectEmit(address(dex));
        emit SCaaSDexV1.MatchFailed(x.ref, reason);
        vm.prank(relayer);
        bool[] memory ok = dex.settle(ms);
        assertFalse(ok[0]);
        assertTrue(ok[1]);
    }

    uint256 private _goodNonce = 1 << 100;

    function _dexHoldsNothing() internal view {
        assertEq(tA.balanceOf(address(dex)), 0);
        assertEq(tB.balanceOf(address(dex)), 0);
        assertEq(tF.balanceOf(address(dex)), 0);
    }

    // ------------------------------------------------------------------ full + partial fills

    function test_fullMatchSwapsDirectlyBetweenUsers() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether)));
        assertEq(tA.balanceOf(bob), 100 ether);
        assertEq(tB.balanceOf(alice), 200 ether);
        assertEq(dex.filled(dex.orderHash(ask)), 100 ether);
        assertEq(dex.filled(dex.orderHash(bid)), 200 ether);
        _dexHoldsNothing();
    }

    function test_partialFillsAccumulateAndNeverOverfill() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory b1 = _order(bob, tB, 80 ether, tA, 40 ether);
        SCaaSDexV1.Order memory b2 = _order(carol, tB, 120 ether, tA, 60 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, b1, BOB_PK, 40 ether, 80 ether)));
        assertTrue(_settle(_match(ask, ALICE_PK, b2, CAROL_PK, 60 ether, 120 ether)));
        bytes32 h = dex.orderHash(ask);
        assertEq(dex.filled(h), 100 ether);
        SCaaSDexV1.Order memory b3 = _order(bob, tB, 2 ether, tA, 1 ether);
        _expectMatchFails(
            _match(ask, ALICE_PK, b3, BOB_PK, 1 ether, 2 ether),
            abi.encodeWithSelector(SCaaSDexV1.Overfill.selector, h, 100 ether, 1 ether, 100 ether));
        assertEq(dex.filled(h), 100 ether);
    }

    function test_fillAboveSellAmountInOneMatchFails() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 10 ether, tB, 20 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 40 ether, tA, 20 ether);
        bytes32 h = dex.orderHash(ask);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 20 ether, 40 ether),
            abi.encodeWithSelector(SCaaSDexV1.Overfill.selector, h, 0, 20 ether, 10 ether));
    }

    function test_makerPriceLimitIsEnforced() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether); // >= 2 B per A
        SCaaSDexV1.Order memory bid = _order(bob, tB, 190 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 190 ether),
            abi.encodeWithSelector(SCaaSDexV1.PriceLimit.selector, dex.orderHash(ask)));
    }

    function test_takerPriceLimitIsEnforced() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether); // <= 2 B per A
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 90 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.PriceLimit.selector, dex.orderHash(bid)));
    }

    function test_priceImprovementGoesWhereTheRelayerPutsItWithinBothLimits() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether); // 2.0
        SCaaSDexV1.Order memory bid = _order(bob, tB, 250 ether, tA, 100 ether);   // up to 2.5
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether))); // maker's price
        assertEq(tB.balanceOf(bob), 800 ether);
        assertEq(dex.filled(dex.orderHash(bid)), 200 ether);
    }

    // ------------------------------------------------------------------ flags

    function test_fokRefusesAPartialFill() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.flags = dex.FLAG_FOK();
        SCaaSDexV1.Order memory bid = _order(bob, tB, 100 ether, tA, 50 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 50 ether, 100 ether),
            abi.encodeWithSelector(SCaaSDexV1.FillOrKill.selector, dex.orderHash(ask)));
    }

    function test_fokFillsWhole() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.flags = dex.FLAG_FOK();
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether)));
    }

    function test_iocRemainderIsClosedAtTheEndOfTheTx() public {
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        bid.flags = dex.FLAG_IOC();
        SCaaSDexV1.Order memory ask = _order(alice, tA, 40 ether, tB, 80 ether);
        bytes32 hb = dex.orderHash(bid);
        vm.expectEmit(address(dex));
        emit SCaaSDexV1.OrderCancelled(hb, bob);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 40 ether, 80 ether)));
        assertEq(dex.filled(hb), 200 ether);
        assertEq(tB.balanceOf(bob), 920 ether);           // only 80 moved
    }

    function test_iocFillsAgainstSeveralMakersInOneTx() public {
        tA.transfer(carol, 100 ether);
        _approveAll(carol);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        bid.flags = dex.FLAG_IOC();
        SCaaSDexV1.Order memory a1 = _order(alice, tA, 30 ether, tB, 60 ether);
        SCaaSDexV1.Order memory a2 = _order(carol, tA, 30 ether, tB, 60 ether);
        SCaaSDexV1.Match[] memory ms = new SCaaSDexV1.Match[](2);
        ms[0] = _match(a1, ALICE_PK, bid, BOB_PK, 30 ether, 60 ether);
        ms[1] = _match(a2, CAROL_PK, bid, BOB_PK, 30 ether, 60 ether);
        vm.prank(relayer);
        bool[] memory ok = dex.settle(ms);
        assertTrue(ok[0] && ok[1]);
        assertEq(tA.balanceOf(bob), 60 ether);
        assertEq(dex.filled(dex.orderHash(bid)), 200 ether);
    }

    function test_conflictingOrUnknownFlagsAreRefused() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        ask.flags = 3;
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.BadFlags.selector, dex.orderHash(ask)));
        ask.flags = 4;
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.BadFlags.selector, dex.orderHash(ask)));
    }

    // ------------------------------------------------------------------ validity

    function test_expiredOrderFails() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.expiry = block.timestamp - 1;
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.OrderExpired.selector, dex.orderHash(ask)));
    }

    function test_wrongSignerFails() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        SCaaSDexV1.Match memory x = _match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether);
        x.makerSig = _signOrder(BOB_PK, ask);
        _expectMatchFails(x, abi.encodeWithSelector(SCaaSDexV1.BadSignature.selector, dex.orderHash(ask)));
    }

    function test_relayerRestrictionBindsTheSubmitter() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.relayer = address(0xD1);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.WrongRelayer.selector, dex.orderHash(ask)));
        ask.relayer = relayer;
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether)));
    }

    function test_takerRestriction() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.taker = carol;
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.WrongTaker.selector, dex.orderHash(ask)));
    }

    function test_selfTradeAndTokenMismatchAndZeroFill() public {
        tB.transfer(alice, 300 ether);
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory own = _order(alice, tB, 200 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, own, ALICE_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.SelfTrade.selector));
        SCaaSDexV1.Order memory wrong = _order(bob, tB, 200 ether, tB, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, wrong, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.TokenMismatch.selector));
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 0, 0),
            abi.encodeWithSelector(SCaaSDexV1.ZeroFill.selector));
    }

    function test_unlistedMarketFails() public {
        tF.transfer(bob, 200 ether);
        vm.prank(admin);
        dex.setMarket(address(tA), address(tF), SCaaSDexV1.Market(false, false, 0, 0, address(0)));
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tF, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tF, 200 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.MarketNotListed.selector));
    }

    function test_settleOneIsSelfOnly() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        SCaaSDexV1.Match memory x = _match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether);
        vm.expectRevert(SCaaSDexV1.OnlySelf.selector);
        dex.settleOne(x, relayer);
    }

    // ------------------------------------------------------------------ batch

    function test_batchIsAtomicPerMatch() public {
        tA.transfer(carol, 100 ether);
        _approveAll(carol);
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        SCaaSDexV1.Order memory stale = _order(carol, tA, 10 ether, tB, 20 ether);
        stale.expiry = block.timestamp - 1;
        SCaaSDexV1.Order memory bid2 = _order(bob, tB, 20 ether, tA, 10 ether);
        SCaaSDexV1.Match[] memory ms = new SCaaSDexV1.Match[](2);
        ms[0] = _match(stale, CAROL_PK, bid2, BOB_PK, 10 ether, 20 ether);
        ms[1] = _match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether);
        vm.prank(relayer);
        bool[] memory ok = dex.settle(ms);
        assertFalse(ok[0]);
        assertTrue(ok[1]);
        assertEq(dex.filled(dex.orderHash(bid2)), 0, "failed match left no trace");
        assertEq(tA.balanceOf(carol), 100 ether);
        assertEq(tA.balanceOf(bob), 100 ether);
        _dexHoldsNothing();
    }

    function test_batchWithNothingSettledReverts() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.expiry = 1;
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        SCaaSDexV1.Match[] memory ms = _one(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether));
        vm.prank(relayer);
        vm.expectRevert(SCaaSDexV1.NothingSettled.selector);
        dex.settle(ms);
    }

    // ------------------------------------------------------------------ cancel

    function _cancelReq(uint256 pk, SCaaSDexV1.Order memory o)
        internal view returns (SCaaSDexV1.CancelReq[] memory r)
    {
        r = new SCaaSDexV1.CancelReq[](1);
        r[0] = SCaaSDexV1.CancelReq(o, _sig(pk, dex.cancelDigest(dex.orderHash(o))));
    }

    function test_cancelledOrderCanNeverSettle() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.CancelReq[] memory r = _cancelReq(ALICE_PK, ask);
        bytes32 h = dex.orderHash(ask);
        vm.expectEmit(address(dex));
        emit SCaaSDexV1.OrderCancelled(h, alice);
        vm.prank(relayer);
        dex.cancel(r);
        assertEq(dex.filled(h), 100 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 2 ether, tA, 1 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 1 ether, 2 ether),
            abi.encodeWithSelector(SCaaSDexV1.Overfill.selector, h, 100 ether, 1 ether, 100 ether));
        vm.recordLogs();
        dex.cancel(r);                                   // replay: no-op, no event
        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_cancelBySomeoneElseIsSkipped() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        dex.cancel(_cancelReq(BOB_PK, ask));
        assertEq(dex.filled(dex.orderHash(ask)), 0);
    }

    function test_cancelAfterPartialFillClosesTheRest() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 80 ether, tA, 40 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 40 ether, 80 ether)));
        dex.cancel(_cancelReq(ALICE_PK, ask));
        assertEq(dex.filled(dex.orderHash(ask)), 100 ether);
        assertEq(tA.balanceOf(alice), 960 ether);
    }

    function test_invalidateNoncesKillsOlderOrdersAndCannotReplay() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.nonce = 5;
        bytes memory sig = _sig(ALICE_PK, dex.invalidateDigest(alice, 6));
        vm.expectEmit(address(dex));
        emit SCaaSDexV1.NoncesInvalidated(alice, 6);
        dex.invalidateNonces(alice, 6, sig);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.NonceInvalidated.selector, dex.orderHash(ask)));
        vm.expectRevert(SCaaSDexV1.NonceNotIncreasing.selector);
        dex.invalidateNonces(alice, 6, sig);
        ask.nonce = 6;
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether)));
    }

    function test_invalidateNoncesIsBoundedAndSigned() public {
        uint256 tooBig = uint256(type(uint128).max) + 1;
        bytes memory sig = _sig(ALICE_PK, dex.invalidateDigest(alice, tooBig));
        vm.expectRevert(SCaaSDexV1.NonceNotIncreasing.selector);
        dex.invalidateNonces(alice, tooBig, sig);
        sig = _sig(BOB_PK, dex.invalidateDigest(alice, 7));
        vm.expectRevert(abi.encodeWithSelector(SCaaSDexV1.BadSignature.selector, bytes32(0)));
        dex.invalidateNonces(alice, 7, sig);
    }

    // ------------------------------------------------------------------ DEX fee

    function test_feeOffMovesExactlyTheFillsAndNothingToTheFeeRecipient() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        ask.maxFeePpm = 0;
        bid.maxFeePpm = 0;
        vm.recordLogs();
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether)));
        assertEq(tA.balanceOf(feeTo) + tB.balanceOf(feeTo), 0);
        assertEq(tA.balanceOf(bob), 100 ether);
        assertEq(tB.balanceOf(alice), 200 ether);
        // exactly two Transfer events: no zero-value fee transfer
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 transfers;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == keccak256("Transfer(address,address,uint256)")) ++transfers;
        }
        assertEq(transfers, 2);
    }

    function test_feeOnSplitsReceivedAmountsWithoutDust() public {
        _list(true, 1_000, 2_500);                       // 0.1 % maker, 0.25 % taker
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether + 7, tB, 200 ether + 14);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether + 14, tA, 100 ether + 7);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether + 7, 200 ether + 14)));
        uint256 fillB = 200 ether + 14;
        uint256 fillA = 100 ether + 7;
        uint256 makerFee = fillB * 1_000 / 1e6;
        uint256 takerFee = fillA * 2_500 / 1e6;
        assertEq(tB.balanceOf(alice) + tB.balanceOf(feeTo), 200 ether + 14);
        assertEq(tB.balanceOf(feeTo), makerFee);
        assertEq(tA.balanceOf(bob) + tA.balanceOf(feeTo), 100 ether + 7);
        assertEq(tA.balanceOf(feeTo), takerFee);
        assertEq(tA.totalSupply(), 3_000 ether);
        _dexHoldsNothing();
    }

    function test_feeAboveWhatTheOrderSignedFails() public {
        _list(true, 1_000, 2_500);
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        bid.maxFeePpm = 2_000;                           // taker fee is 2 500
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.FeeAboveSigned.selector, dex.orderHash(bid)));
        bid.maxFeePpm = 2_500;
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether)));
    }

    function test_setMarketGuards() public {
        SCaaSDexV1.Market memory m = SCaaSDexV1.Market(true, true, 1, 1, feeTo);
        vm.expectRevert(SCaaSDexV1.NotAdmin.selector);
        dex.setMarket(address(tA), address(tB), m);
        vm.startPrank(admin);
        m.makerFeePpm = uint32(FeePolicy.MAX_FEE_PPM + 1);
        vm.expectRevert(SCaaSDexV1.BadMarket.selector);
        dex.setMarket(address(tA), address(tB), m);
        m.makerFeePpm = 1;
        m.feeRecipient = address(dex);
        vm.expectRevert(SCaaSDexV1.FeeWouldStick.selector);
        dex.setMarket(address(tA), address(tB), m);
        m.feeRecipient = address(0);
        vm.expectRevert(SCaaSDexV1.FeeWouldStick.selector);
        dex.setMarket(address(tA), address(tB), m);
        vm.expectRevert(SCaaSDexV1.BadMarket.selector);
        dex.setMarket(address(tA), address(tA), m);
        vm.stopPrank();
        assertEq(dex.marketKey(address(tA), address(tB)), dex.marketKey(address(tB), address(tA)));
    }

    // ------------------------------------------------------------------ relayer fee

    function test_relayerPercentFeeInSellTokenGoesToTheSubmitter() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.feeMode = 1;                                 // PERCENT
        ask.fee = 5_000;                                 // 0.5 %
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 40 ether, 80 ether)));
        assertEq(tA.balanceOf(relayer), 0.2 ether);
        assertEq(tA.balanceOf(alice), 1_000 ether - 40 ether - 0.2 ether);
        _dexHoldsNothing();
    }

    function test_relayerFixedFeeInAFeeTokenIsProRata() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.feeMode = 2;                                 // FIXED
        ask.fee = 3 ether;
        ask.feeToken = address(tF);
        ask.feeRecipient = address(0x5E1);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 40 ether, 80 ether)));
        assertEq(tF.balanceOf(address(0x5E1)), 1.2 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 60 ether, 120 ether)));
        assertEq(tF.balanceOf(address(0x5E1)), 3 ether);
    }

    /// review agy F1: `fee * sold` tràn 256 bit dù kết quả vừa — node tính 512 bit, contract phải khớp.
    function test_relayerFixedFeeProRataDoesNotOverflow() public {
        MetaToken big = _standalone(address(this), "BIG", 18, 1 << 200, address(0));
        big.transfer(alice, 1 << 200);
        vm.prank(alice);
        big.approve(address(dex), type(uint256).max);
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.feeMode = 2;                                 // FIXED, separate token: no 1 % cap
        ask.fee = 1 << 199;
        ask.feeToken = address(big);
        ask.feeRecipient = address(0x5E1);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 40 ether, 80 ether)));
        assertEq(big.balanceOf(address(0x5E1)), (uint256(1) << 199) * 2 / 5);
    }

    function test_relayerFeeGuards() public {
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.feeMode = 1;
        ask.fee = 1;
        ask.feeToken = address(tF);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.PercentFeeNeedsSellToken.selector, dex.orderHash(ask)));
        ask = _order(alice, tA, 100 ether, tB, 200 ether);
        ask.feeMode = 2;
        ask.fee = 2 ether;                               // > 1 % of 100
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 2 ether, 1 ether));
        ask.fee = 1 ether;
        ask.feeRecipient = address(dex);
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.FeeWouldStick.selector));
        ask.feeRecipient = address(0);
        ask.feeMode = 3;
        _expectMatchFails(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether),
            abi.encodeWithSelector(SCaaSDexV1.FeeModeInvalid.selector, dex.orderHash(ask)));
    }

    // ------------------------------------------------------------------ ERC-1271 maker (passkey/seed account)

    function test_contractAccountMakerSignsWithErc1271AndApprovesGasless() public {
        Mock1271Wallet w = new Mock1271Wallet(carol);
        tA.transfer(address(w), 100 ether);
        // gasless approve via the MetaToken op, signed by the wallet owner, checked through 1271
        MetaTxLib.LegacyMetaTransaction memory m = _mt(address(w), address(dex), 0,
            abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), address(dex), 100 ether),
            uint256(keccak256("scaas.dex.approve")), MetaTxLib.MODE_RESTRICT_RELAYER);
        bytes memory asig = _sign(CAROL_PK, tA, m);
        vm.prank(relayer);
        tA.executeMetaTransaction(m, asig);
        assertEq(tA.allowance(address(w), address(dex)), 100 ether);

        SCaaSDexV1.Order memory ask = _order(address(w), tA, 100 ether, tB, 200 ether);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        SCaaSDexV1.Match memory x = _match(ask, CAROL_PK, bid, BOB_PK, 100 ether, 200 ether);
        assertTrue(_settle(x));
        assertEq(tB.balanceOf(address(w)), 200 ether);
        w.setMode(Mock1271Wallet.Mode.WrongMagic);
        SCaaSDexV1.Order memory ask2 = _order(address(w), tA, 1, tB, 2);
        SCaaSDexV1.Order memory bid2 = _order(bob, tB, 2, tA, 1);
        _expectMatchFails(_match(ask2, CAROL_PK, bid2, BOB_PK, 1, 2),
            abi.encodeWithSelector(SCaaSDexV1.BadSignature.selector, dex.orderHash(ask2)));
    }

    // ------------------------------------------------------------------ R30: DEX and payments never block each other

    function test_dexActivityNeverBlocksPaymentsAndViceVersa() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        // a resting DEX order and a DEX nonce invalidation ...
        dex.invalidateNonces(alice, 1, _sig(ALICE_PK, dex.invalidateDigest(alice, 1)));
        // ... leave every token lane untouched: a payment on lane 7 still runs at nonce 0
        MetaTxLib.LegacyMetaTransaction memory pay = _mt(alice, address(0x5409), 1 ether,
            _payData(bytes32("order-1")), 7, MetaTxLib.MODE_RESTRICT_RELAYER);
        bytes memory psig = _sign(ALICE_PK, tA, pay);
        vm.prank(relayer);
        tA.executeMetaTransaction(pay, psig);
        // and token-side nonce activity (payment + cancelMetaNonce) never invalidates the DEX order
        vm.prank(alice);
        tA.cancelMetaNonce(7);
        assertEq(tA.metaNonce(alice, 7), 2);
        SCaaSDexV1.Order memory bid = _order(bob, tB, 200 ether, tA, 100 ether);
        assertTrue(_settle(_match(ask, ALICE_PK, bid, BOB_PK, 100 ether, 200 ether)));
        assertEq(tA.metaNonce(alice, 7), 2, "settlement never touches token nonces");
    }

    // ------------------------------------------------------------------ intake view

    function test_checkOrderReportsStatusAndFundable() public {
        SCaaSDexV1.Order memory ask = _order(alice, tA, 100 ether, tB, 200 ether);
        bytes memory sig = _signOrder(ALICE_PK, ask);
        (bytes32 h, uint8 st, uint256 rem, uint256 fundable,) = dex.checkOrder(ask, sig);
        assertEq(h, dex.orderHash(ask));
        assertEq(st, dex.ST_OK());
        assertEq(rem, 100 ether);
        assertEq(fundable, 1_000 ether);
        vm.prank(alice);
        tA.approve(address(dex), 5 ether);
        (,,, fundable,) = dex.checkOrder(ask, sig);
        assertEq(fundable, 5 ether);
        (, st,,,) = dex.checkOrder(ask, _signOrder(BOB_PK, ask));
        assertEq(st, dex.ST_BAD_SIG());
        dex.cancel(_cancelReq(ALICE_PK, ask));
        (, st, rem,,) = dex.checkOrder(ask, sig);
        assertEq(st, dex.ST_CLOSED());
        assertEq(rem, 0);
        ask.expiry = 1;
        (, st,,,) = dex.checkOrder(ask, _signOrder(ALICE_PK, ask));
        assertEq(st, dex.ST_EXPIRED());
        SCaaSDexV1.Order memory other = _order(alice, tA, 1, tF, 1);
        (, st,,,) = dex.checkOrder(other, _signOrder(ALICE_PK, other));
        assertEq(st, dex.ST_NOT_LISTED());
        SCaaSDexV1.Order memory feeBad = _order(alice, tA, 100 ether, tB, 1);
        feeBad.feeMode = 2;
        feeBad.fee = 2 ether;
        (, st,,,) = dex.checkOrder(feeBad, _signOrder(ALICE_PK, feeBad));
        assertEq(st, dex.ST_BAD_FEE());
    }

    // ------------------------------------------------------------------ fuzz

    function testFuzz_neverOverfillsConservesAndHoldsNothing(
        uint96 sellA, uint96 buyA, uint96 sellB, uint96 buyB, uint96 fillA, uint96 fillB, bool feeOn
    ) public {
        sellA = uint96(bound(sellA, 1, 500 ether));
        sellB = uint96(bound(sellB, 1, 500 ether));
        buyA = uint96(bound(buyA, 1, 500 ether));
        buyB = uint96(bound(buyB, 1, 500 ether));
        fillA = uint96(bound(fillA, 1, 600 ether));
        fillB = uint96(bound(fillB, 1, 600 ether));
        if (feeOn) _list(true, 3_000, 7_000);
        SCaaSDexV1.Order memory ask = _order(alice, tA, sellA, tB, buyA);
        SCaaSDexV1.Order memory bid = _order(bob, tB, sellB, tA, buyB);
        uint256 supplyA = tA.totalSupply();
        vm.prank(relayer);
        try dex.settle(_one(_match(ask, ALICE_PK, bid, BOB_PK, fillA, fillB))) {
            assertLe(uint256(fillA) * buyA, uint256(fillB) * sellA, "maker limit");
            assertLe(uint256(fillB) * buyB, uint256(fillA) * sellB, "taker limit");
            assertLe(dex.filled(dex.orderHash(ask)), sellA);
            assertLe(dex.filled(dex.orderHash(bid)), sellB);
            assertEq(tA.balanceOf(bob) + tA.balanceOf(feeTo), fillA);
            assertEq(tB.balanceOf(alice) + tB.balanceOf(feeTo), fillB);
        } catch {
            assertEq(tA.balanceOf(alice), 1_000 ether);
            assertEq(tB.balanceOf(bob), 1_000 ether);
        }
        assertEq(tA.totalSupply(), supplyA);
        _dexHoldsNothing();
    }

    // ------------------------------------------------------------------ KAT for Rust/clients

    function test_writeDexKat() public {
        vm.chainId(7622);
        SCaaSDexV1 d = new SCaaSDexV1(admin);
        SCaaSDexV1.Order memory o = SCaaSDexV1.Order({
            maker: alice, taker: address(0), sellToken: address(0xA0), buyToken: address(0xB0),
            sellAmount: 100e18, buyAmount: 250e6, nonce: 1_800_000_000_000 << 20, expiry: 1_800_000_300,
            maxFeePpm: 2_500, flags: 2, relayer: relayer, feeMode: 1, fee: 1_000,
            feeToken: address(0), feeRecipient: address(0)
        });
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("SCaaS Dex"), keccak256("1"), uint256(7622), address(d)));
        bytes32 h = keccak256(abi.encodePacked(hex"1901", domainSep, keccak256(abi.encode(d.ORDER_TYPEHASH(), o))));
        assertEq(h, d.orderHash(o));
        string memory k = "dexkat";
        vm.serializeString(k, "chain_id", "7622");
        vm.serializeString(k, "dex", vm.toString(address(d)));
        vm.serializeString(k, "maker", vm.toString(o.maker));
        vm.serializeString(k, "sell_token", vm.toString(o.sellToken));
        vm.serializeString(k, "buy_token", vm.toString(o.buyToken));
        vm.serializeString(k, "sell_amount", vm.toString(o.sellAmount));
        vm.serializeString(k, "buy_amount", vm.toString(o.buyAmount));
        vm.serializeString(k, "nonce", vm.toString(o.nonce));
        vm.serializeString(k, "expiry", vm.toString(o.expiry));
        vm.serializeString(k, "max_fee_ppm", vm.toString(uint256(o.maxFeePpm)));
        vm.serializeString(k, "flags", vm.toString(uint256(o.flags)));
        vm.serializeString(k, "relayer", vm.toString(o.relayer));
        vm.serializeString(k, "fee_mode", vm.toString(uint256(o.feeMode)));
        vm.serializeString(k, "fee", vm.toString(o.fee));
        vm.serializeString(k, "order_hash", vm.toString(h));
        vm.serializeString(k, "cancel_digest", vm.toString(d.cancelDigest(h)));
        string memory out = vm.serializeString(k, "invalidate_digest", vm.toString(d.invalidateDigest(alice, 42)));
        vm.writeJson(out, "./test/vectors/dex_kat.json");
    }
}
