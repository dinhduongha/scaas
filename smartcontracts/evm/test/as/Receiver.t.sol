// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IComplianceRegistry} from "../../src/regulated/IComplianceRegistry.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {nid} from "../helpers/Ids.sol";

/// Plan T29 (regulated-kinds spec §3.1 `canReceive`, §3.2 the receiver rows, §5 the call budget; CTR-AS-07): `canReceive`'s
/// reasons 1-4 agree with `hasFlags`; each receiver row checks its receiver (transfer, mint, wrap, a fee leg's recipient,
/// the forced transfer's beneficiary) and no sender; the registry calls per path stay within spec §5's budget. Kinds 8 and 9.
contract ReceiverTest is RegFixture {
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;
    uint32 constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint64 constant ACCR = 2;
    uint64 constant MAX = type(uint64).max;
    address feeTo = address(0xFEE);
    bytes32 internal PAYREF = PayMetaKit.ref("request-1"); // pay-meta-tax T37: the commitment of its `PayMeta`
    bytes4 constant HAS_FLAGS = IComplianceRegistry.hasFlags.selector;

    function _reason(address t, bytes32 a, bool ok, uint8 reason, uint64 req, uint64 den, string memory what) internal view {
        (bool o, uint8 r) = IRegulatedToken(t).canReceive(a);
        assertEq(o, ok, what);
        assertEq(r, reason, what);
        assertEq(o, creg.hasFlags(a, req, den), string.concat(what, ": agrees with hasFlags"));
    }

    /// Reasons (spec §3.1): 1 not attested or flags missing, 2 expired, 3 attester disabled, 4 denied; 0 when it may
    /// receive. Both lists, `DENYLIST` alone, both off (no call).
    function test_canReceiveReasons() public {
        for (uint256 i; i < 2; ++i) {
            _clearBob();
            address t = _listed(i, KYC, SANCTIONED, bytes32(i));
            bytes32 b = nid(bob);
            _reason(t, b, false, 1, KYC, SANCTIONED, "not attested");
            _attest(b, ACCR, MAX);
            _reason(t, b, false, 1, KYC, SANCTIONED, "flags missing");
            _attest(b, KYC, MAX);
            _reason(t, b, true, 0, KYC, SANCTIONED, "attested");
            _attest(b, KYC, uint64(block.timestamp));
            _reason(t, b, true, 0, KYC, SANCTIONED, "validUntil == now");
            _attest(b, KYC, uint64(block.timestamp) - 1);
            _reason(t, b, false, 2, KYC, SANCTIONED, "expired");
            _attest(b, KYC, MAX);
            vm.prank(cadmin);
            creg.setAttester(attester, false);
            _reason(t, b, false, 3, KYC, SANCTIONED, "attester disabled");
            vm.prank(cadmin);
            creg.setAttester(attester, true);
            _attest(b, KYC | SANCTIONED, MAX);
            _reason(t, b, false, 4, KYC, SANCTIONED, "denied");
            _attestAs(cadmin, b, ELIGIBLE, MAX);
            _reason(t, b, true, 0, KYC, SANCTIONED, "ELIGIBLE_CONTRACT");

            address d = _listed(i, 0, SANCTIONED, bytes32(i + 10));
            _attestAs(cadmin, b, 0, MAX); // an admin row: only the admin clears it (owner 2026-11-06)
            _attest(b, KYC, MAX);
            _reason(d, b, true, 0, 0, SANCTIONED, "denylist: not denied");
            _reason(d, nid(address(0x5EED)), true, 0, 0, SANCTIONED, "denylist: unattested");
            _attest(b, SANCTIONED, MAX);
            _reason(d, b, false, 4, 0, SANCTIONED, "denylist: denied");
            _attest(b, SANCTIONED, uint64(block.timestamp) - 1);
            _reason(d, b, true, 0, 0, SANCTIONED, "denylist: denial lapsed");

            _countStart();
            (bool ok, uint8 r) = IRegulatedToken(_ks()[i]).canReceive(nid(address(0x5EED)));
            assertEq(_countEnd(0), 0, "lists off: no call");
            assertTrue(ok, "lists off");
            assertEq(r, 0, "lists off");
            _countStart();
            IRegulatedToken(t).canReceive(nid(bob));
            assertEq(_countEnd(0), 2, "two bounded calls (spec 3.1)");
        }
    }

    /// The receiver rows (spec §3.2): a mint (kind 8's minter) and a wrap (kind 9) to an unattested receiver refused; a
    /// fee leg's recipient (`payWithFee`) refused at the seat before any move; the forced transfer's beneficiary refused
    /// (`R` before `_poolMove`). Senders are never checked: an unattested holder still sends and burns.
    function test_receiverRows() public {
        for (uint256 i; i < 2; ++i) {
            _clearBob();
            _attestAs(cadmin, nid(feeTo), 0, 0);
            _attestAs(cadmin, nid(address(0xBE11)), 0, 0);
            address t = _listed(i, KYC, 0, bytes32(i));
            bytes memory neBob = abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(bob), uint8(0));
            if (i == 0) {
                vm.expectRevert(neBob);
                NormalToken(t).mint(bob, 1);
            } else {
                usd.mint(bob, 5);
                vm.startPrank(bob);
                usd.approve(t, 5);
                vm.expectRevert(neBob);
                WrappedToken(payable(t)).wrap(5);
                vm.stopPrank();
            }
            _attest(nid(bob), KYC, MAX);
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(feeTo), uint8(0)));
            NormalToken(t).payWithFee(bob, 100, FeeMode.FIXED, 1, feeTo, PAYREF, PayMetaKit.meta("request-1"));
            _attest(nid(feeTo), KYC, MAX);
            vm.prank(alice);
            NormalToken(t).payWithFee(bob, 100, FeeMode.FIXED, 1, feeTo, PAYREF, PayMetaKit.meta("request-1"));

            bytes32 rid = _order(t, keccak256("o"), nid(alice), nid(address(0xBE11)), 10, 0);
            _freeze(t, nid(alice));
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, nid(address(0xBE11)), uint8(0)));
            IRegulatedToken(t).forceTransfer(rid, 5);
            _attest(nid(address(0xBE11)), KYC, MAX);
            vm.prank(issuer);
            IRegulatedToken(t).forceTransfer(rid, 5);
            assertEq(IERC20(t).balanceOf(address(0xBE11)), 5);
            _unfreeze(t, nid(alice));

            _attest(nid(alice), 0, MAX); // alice no longer attested: she still sends to bob and burns
            vm.startPrank(alice);
            IERC20(t).transfer(bob, 1);
            if (i == 0) NormalToken(t).burn(1);
            else WrappedToken(payable(t)).unwrap(1, alice);
            vm.stopPrank();
        }
    }

    // ------------------------------------------------------------------ the call budget (spec §5)

    function _budget(uint256 n, string memory what) internal {
        assertEq(_countEnd(HAS_FLAGS), n, what);
    }

    /// A listed token with every party of these paths attested.
    function _ready(uint256 i, bytes32 salt) internal returns (address t) {
        t = _listed(i, KYC, SANCTIONED, salt);
        address[5] memory who = [bob, relayer, feeTo, address(0xBE11), alice];
        for (uint256 j; j < who.length; ++j) _attest(nid(who[j]), KYC, MAX);
        _attest(UA_X, KYC, MAX);
    }

    /// Direct transfer, mint (kind 8) or wrap (kind 9), forced transfer: one call each; burn and unwrap none.
    function test_callBudgetDirect() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ready(i, bytes32(i));
            _countStart();
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            _budget(1, "direct transfer");
            if (i == 0) {
                _countStart();
                NormalToken(t).mint(bob, 1);
                _budget(1, "mint");
            } else {
                usd.mint(bob, 5);
                vm.prank(bob);
                usd.approve(t, 5);
                _countStart();
                vm.prank(bob);
                WrappedToken(payable(t)).wrap(5);
                _budget(1, "wrap");
            }
            bytes32 rid = _order(t, keccak256("o"), nid(alice), nid(address(0xBE11)), 10, 0);
            _freeze(t, nid(alice));
            _countStart();
            vm.prank(issuer);
            IRegulatedToken(t).forceTransfer(rid, 5);
            _budget(1, "forceTransfer");
            _unfreeze(t, nid(alice));
            _countStart();
            vm.prank(bob);
            if (i == 0) NormalToken(t).burn(1);
            else WrappedToken(payable(t)).unwrap(1, bob);
            _budget(0, "burn, unwrap");
        }
    }

    /// A relayed typed transfer at a `FIXED` fee, `payWithFee`, `payWithFeeToUA`, `mtxPayReceiverFee`: three calls each
    /// (the receiver; the fee recipient at its seat and at its move).
    function test_callBudgetFeePaths() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ready(i, bytes32(i));
            MetaTxLib.UAMetaTransfer memory x;
            (x.from, x.to, x.value, x.batch, x.validUntil, x.mode, x.fee) =
                (nid(alice), nid(bob), 100, 1, block.timestamp + 60, FIX, 1);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, NormalToken(t).mtxTransferDigest(x));
            IUARegistry.UASig memory sig;
            sig.signature = abi.encodePacked(r, s, v);
            _countStart();
            vm.prank(relayer);
            NormalToken(t).mtxExecuteTransfer(x, sig);
            _budget(3, "relayed transfer with a fee");

            _countStart();
            vm.prank(alice);
            NormalToken(t).payWithFee(bob, 100, FeeMode.FIXED, 1, feeTo, PAYREF, PayMetaKit.meta("request-1"));
            _budget(3, "payWithFee");
            _countStart();
            vm.prank(alice);
            NormalToken(t).payWithFeeToUA(UA_X, 100, FeeMode.FIXED, 1, feeTo, PayMetaKit.ref(keccak256("request-2")), PayMetaKit.meta(keccak256("request-2")));
            _budget(3, "payWithFeeToUA");

            MetaTxLib.UAMetaTransfer memory p = MetaTxLib.UAMetaTransfer({from: nid(alice), to: nid(bob), value: 100,
                entryRef: PayMetaKit.ref("request-3"), batch: NormalToken(t).payLane(PayMetaKit.ref("request-3")), nonce: 0,
                validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)});
            IUARegistry.UASig memory ps;
            IUARegistry.UASig memory rs;
            (v, r, s) = vm.sign(ALICE_PK, NormalToken(t).mtxTransferDigest(p));
            ps.signature = abi.encodePacked(r, s, v);
            (v, r, s) = vm.sign(BOB_PK, NormalToken(t).receiverFeeDigest(p, 3, feeTo, block.timestamp + 300));
            rs.signature = abi.encodePacked(r, s, v);
            _countStart();
            vm.prank(relayer);
            NormalToken(t).mtxPayReceiverFee(p, ps, 3, feeTo, block.timestamp + 300, rs, PayMetaKit.meta("request-3"));
            _budget(3, "mtxPayReceiverFee");
        }
    }

    /// `mtxWrapOrder` with a fee (kind 9 over a kind-0 underlying, `ALLOWLIST` on): three calls (the destination's mint, the
    /// submitter at the seat and at its mint).
    function test_callBudgetWrapOrder() public {
        address u = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("U", "U", 0, SUPPLY, alice,
            address(0))), "u");
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.FREEZE) | (1 << GovernanceBits.ALLOWLIST);
        (c.roles.compliance, c.reg.complianceRegistry, c.reg.requiredFlags) = (0, address(creg), KYC);
        c.legs[0] = IFactoryToken.Leg(u, 3, 1);
        address w = f.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), "w");
        _attest(nid(alice), KYC, MAX);
        _attest(nid(relayer), KYC, MAX);
        ITradeToken.UAWrapOrder memory o;
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill, o.fee) = (nid(alice), w, 1000, 3000, 1000, 1_000);
        (o.batch, o.nonce, o.validUntil) = (7, 1, block.timestamp + 300);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, NormalToken(u).tradeOrderDigest(DexLegs.asTrade(o)));
        IUARegistry.UASig memory a;
        a.signature = abi.encodePacked(r, s, v);
        _countStart();
        vm.prank(relayer);
        WrappedToken(payable(w)).mtxWrapOrder(u, o, a);
        _budget(3, "mtxWrapOrder with a fee");
        assertEq(IERC20(w).balanceOf(relayer), 3);
    }
}
