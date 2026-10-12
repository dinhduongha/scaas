// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {MetaTxDex} from "../src/dex/MetaTxDex.sol";
import {MetaTxLib} from "../src/common/MetaTxLib.sol";
import {IERC20MetaTxV1} from "../src/metatx/IERC20MetaTxV1.sol";

contract MetaTxDexTest is Fixtures {
    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant BOB_PK = 0xB0B;
    address alice;
    address bob;
    MetaToken tA;
    MetaToken tB;
    MetaTxDex dex;
    uint32 constant R = MetaTxLib.MODE_RESTRICT_RELAYER;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(ALICE_PK);
        bob = vm.addr(BOB_PK);
        _deployFactory();
        dex = new MetaTxDex();
        tA = _standalone(address(this), "AAA", 18, 1_000 ether, address(0));
        tB = _standalone(address(this), "BBB", 18, 1_000 ether, address(0));
        tA.transfer(alice, 500 ether);
        tB.transfer(bob, 500 ether);
    }

    function _leg(uint256 pk, MetaToken sell, uint256 value, MetaToken buy, uint256 minBuy, address cp)
        internal view returns (MetaTxDex.Leg memory l)
    {
        MetaTxLib.LegacyMetaTransaction memory m = MetaTxLib.LegacyMetaTransaction({
            from: vm.addr(pk), to: address(dex), value: value,
            data: _tradeData(address(buy), minBuy, cp), batch: uint256(keccak256(abi.encode(pk, value))),
            nonce: 0, validUntil: block.timestamp + 300, mode: R, relayer: address(dex),
            fee: 0, feeRecipient: address(0)
        });
        l = MetaTxDex.Leg({token: IERC20MetaTxV1(address(sell)), m: m, sig: ""});
        l.sig = _signLeg(pk, sell, m);
    }

    function _signLeg(uint256 pk, MetaToken t, MetaTxLib.LegacyMetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, t.metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    function test_settleSwapsAtomically() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectEmit(address(dex));
        emit MetaTxDex.TradeSettled(alice, bob, address(tA), address(tB), 100 ether, 60 ether);
        vm.prank(relayer);
        dex.settle(a, b);
        assertEq(tB.balanceOf(alice), 60 ether);
        assertEq(tA.balanceOf(bob), 100 ether);
        assertEq(tA.balanceOf(address(dex)), 0);
        assertEq(tB.balanceOf(address(dex)), 0);
    }

    function test_priceNotMetReverts() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 70 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(abi.encodeWithSelector(MetaTxDex.PriceNotMet.selector, 60 ether, 70 ether));
        dex.settle(a, b);
    }

    function test_counterpartyIsEnforced() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0xCAFE));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.CounterpartyMismatch.selector);
        dex.settle(a, b);
    }

    function test_counterTokenMustMatch() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tA, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.CounterTokenMismatch.selector);
        dex.settle(a, b);
    }

    function test_sameTokenRefused() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tA, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tA, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.SameToken.selector);
        dex.settle(a, b);
    }

    function test_samePartyRefused() public {
        tB.transfer(alice, 100 ether);
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(ALICE_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.SameParty.selector);
        dex.settle(a, b);
    }

    function test_secondLegFailureMovesNothing() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        b.sig = a.sig;                                   // wrong signer for b
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        dex.settle(a, b);
        assertEq(tA.metaNonce(alice, a.m.batch), 0);
        assertEq(tA.balanceOf(alice), 500 ether);
    }

    function test_legMustBeRoutedThroughThisDex() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.relayer = address(0xD1);
        a.sig = _signLeg(ALICE_PK, tA, a.m);
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.LegNotRoutedHere.selector);
        dex.settle(a, b);
    }

    function test_leakedLegCannotRunOutsideTheDex() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxUnauthorizedRelayer.selector, address(dex), relayer));
        tA.executeMetaTransaction(a.m, a.sig);
    }

    function test_feeThatWouldStickInTheDexIsRefused() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.mode = R | MetaTxLib.MODE_FEE_FIXED;
        a.m.fee = 0.1 ether;                             // feeRecipient stays 0 -> would go to DEX
        a.sig = _signLeg(ALICE_PK, tA, a.m);
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.FeeWouldStick.selector);
        dex.settle(a, b);
    }

    function test_relayerFillsFeeRecipientAndIsPaid() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.mode = R | MetaTxLib.MODE_FEE_FIXED;
        a.m.fee = 0.1 ether;
        a.sig = _signLeg(ALICE_PK, tA, a.m);
        a.m.feeRecipient = relayer;                      // not restricted: outside the digest
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.prank(relayer);
        dex.settle(a, b);
        assertEq(tA.balanceOf(relayer), 0.1 ether);
        assertEq(tA.balanceOf(alice), 399.9 ether);
    }

    function test_nonTradeLegRefused() public {
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, 100 ether, tB, 50 ether, address(0));
        a.m.data = _payData(bytes32("x"));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, 60 ether, tA, 100 ether, address(0));
        vm.expectRevert(MetaTxDex.NotATradeLeg.selector);
        dex.settle(a, b);
    }

    function testFuzz_settleConservesOrReverts(uint96 va, uint96 vb, uint96 minA, uint96 minB) public {
        va = uint96(bound(va, 1, 500 ether));
        vb = uint96(bound(vb, 1, 500 ether));
        MetaTxDex.Leg memory a = _leg(ALICE_PK, tA, va, tB, minB, address(0));
        MetaTxDex.Leg memory b = _leg(BOB_PK, tB, vb, tA, minA, address(0));
        bool crosses = vb >= minB && va >= minA;
        if (!crosses) vm.expectRevert();
        dex.settle(a, b);
        if (crosses) {
            assertEq(tA.balanceOf(bob), va);
            assertEq(tB.balanceOf(alice), vb);
        }
        assertEq(tA.totalSupply(), 1_000 ether);
        assertEq(tA.balanceOf(address(dex)) + tB.balanceOf(address(dex)), 0);
    }
}
