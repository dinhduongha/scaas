// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {nid} from "../helpers/Ids.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {RelayFeeRouter} from "../../src/metatx/RelayFeeRouter.sol";

/// A relay target with code (pay-meta-tax T38): its call runs every time.
contract RelayPing {
    uint256 public n;

    function ping() external {
        ++n;
    }
}

/// A stand-in for a venue paying a relayer its share out of its own balance by an ordinary `transfer`
/// (`SCaaSDex._payLeg`'s `_send`): the token cannot tell it from any payout.
contract Venue {
    function pay(address t, address to, uint256 v) external {
        IERC20(t).transfer(to, v);
    }
}

/// Plan T28 (regulated-kinds spec §3.2 fee rows, RK-6, Codex 1, F-15): every fee leg of the token checks its recipient
/// before effects (`F` ⇒ `FeeRecipientFrozen`): the envelope fee (a typed transfer, `mtxCancelNonce`), `payWithFee`,
/// `payWithFeeToUA`, `mtxPayReceiverFee` (and its payee, whose fee leg is its own send), `mtxRelayFee`, `mtxWrapOrder`;
/// the DEX relayer share is an ordinary credit. Kinds 8 and 9, each with its control.
contract FeeLegsTest is RegFixture {
    uint32 constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    uint32 constant FIX = MetaTxLib.MODE_FEE_FIXED;
    address feeTo = address(0xFEE);
    bytes32 internal PAYREF = PayMetaKit.ref("request-1"); // pay-meta-tax T37: the commitment of its `PayMeta`

    /// The envelope's fee leg (`_regFeeTo` after `pre*`): a typed transfer at a `FIXED` fee to its relayer, refused
    /// `FeeRecipientFrozen(relayer)` when the relayer is frozen; the same signed transfer runs once it is not.
    function test_envelopeFeeLeg() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            MetaTxLib.UAMetaTransfer memory x;
            (x.from, x.to, x.value, x.batch, x.validUntil, x.mode, x.fee) =
                (nid(alice), nid(bob), 100, 1, block.timestamp + 60, FIX, 1); // FIXED: at most 1 %
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, MetaTokenBase(t).mtxTransferDigest(x));
            IUARegistry.UASig memory sig;
            sig.signature = abi.encodePacked(r, s, v);
            _freeze(t, nid(relayer));
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(relayer)));
            MetaTokenBase(t).mtxExecuteTransfer(x, sig);
            _unfreeze(t, nid(relayer));
            vm.prank(relayer);
            MetaTokenBase(t).mtxExecuteTransfer(x, sig);
            assertEq(IERC20(t).balanceOf(relayer), 1);
        }
    }

    /// RK-8: `mtxCancelNonce` takes the fee-leg row too.
    function test_cancelNonceFeeLeg() public {
        string memory ty = "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            MetaTxLib.UAEnvelope memory e = _env(alice, FIX, 1);
            IUARegistry.UASig memory s = _namedSig(ALICE_PK, t, ty, e, abi.encode(uint256(9)));
            _freeze(t, nid(relayer));
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(relayer)));
            UAMetaTxBase(t).mtxCancelNonce(e, 9, s);
            _unfreeze(t, nid(relayer));
            vm.prank(relayer);
            UAMetaTxBase(t).mtxCancelNonce(e, 9, s);
            assertEq(IERC20(t).balanceOf(relayer), 1);
        }
    }

    /// CTR-AS-08: `payWithFee` and `payWithFeeToUA` with a frozen fee recipient, refused before any move; the control pays.
    function test_payWithFeeFrozenFeeRecipient() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            _freeze(t, nid(feeTo));
            vm.startPrank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(feeTo)));
            MetaTokenBase(t).payWithFee(bob, 100, FeeMode.FIXED, 1, feeTo, PAYREF, PayMetaKit.meta("request-1"));
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(feeTo)));
            MetaTokenBase(t).payWithFeeToUA(UA_X, 100, FeeMode.FIXED, 1, feeTo, PAYREF, PayMetaKit.meta("request-1"));
            vm.stopPrank();
            _unfreeze(t, nid(feeTo));
            vm.startPrank(alice);
            MetaTokenBase(t).payWithFee(bob, 100, FeeMode.FIXED, 1, feeTo, PAYREF, PayMetaKit.meta("request-1"));
            MetaTokenBase(t).payWithFeeToUA(UA_X, 100, FeeMode.FIXED, 1, feeTo, PAYREF, PayMetaKit.meta("request-1"));
            vm.stopPrank();
            assertEq(IERC20(t).balanceOf(feeTo), 2);
        }
    }

    function _payTr(address t) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer({from: nid(alice), to: nid(bob), value: 100, entryRef: PAYREF,
            batch: MetaTokenBase(t).payLane(PAYREF), nonce: 0, validUntil: block.timestamp + 300, mode: RR,
            relayer: relayer, fee: 0, feeRecipient: address(0)});
    }

    function _rfSigs(address t, MetaTxLib.UAMetaTransfer memory x)
        internal view returns (IUARegistry.UASig memory ps, IUARegistry.UASig memory rs)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, MetaTokenBase(t).mtxTransferDigest(x));
        ps.signature = abi.encodePacked(r, s, v);
        (v, r, s) = vm.sign(BOB_PK, MetaTokenBase(t).receiverFeeDigest(x, 3, feeTo, block.timestamp + 300));
        rs.signature = abi.encodePacked(r, s, v);
    }

    /// `mtxPayReceiverFee`: a frozen fee recipient is refused before the payment (`FeeRecipientFrozen`); a frozen payee
    /// cannot pay the receiver fee, which is its own send (`Frozen(payee)`, owner 2026-11-05 call 2); unfrozen, both
    /// signatures run (the control).
    function test_payReceiverFeeFrozen() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            MetaTxLib.UAMetaTransfer memory x = _payTr(t);
            (IUARegistry.UASig memory ps, IUARegistry.UASig memory rs) = _rfSigs(t, x);
            uint256 until = block.timestamp + 300;
            _freeze(t, nid(feeTo));
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(feeTo)));
            MetaTokenBase(t).mtxPayReceiverFee(x, ps, 3, feeTo, until, rs, PayMetaKit.meta("request-1"));
            _unfreeze(t, nid(feeTo));
            _freeze(t, nid(bob));
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(bob)));
            MetaTokenBase(t).mtxPayReceiverFee(x, ps, 3, feeTo, until, rs, PayMetaKit.meta("request-1"));
            _unfreeze(t, nid(bob));
            vm.prank(relayer);
            MetaTokenBase(t).mtxPayReceiverFee(x, ps, 3, feeTo, until, rs, PayMetaKit.meta("request-1"));
            assertEq(IERC20(t).balanceOf(bob), 97);
            assertEq(IERC20(t).balanceOf(feeTo), 3);
        }
    }

    /// `mtxRelayFee`: the relay's payee is a relayer-fee recipient, refused `FeeRecipientFrozen(payee)` before the
    /// signature; unfrozen, the same garbage-signed call fails in the pipeline (the control).
    function test_relayFeeFrozenPayee() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes memory cd = abi.encodeCall(MetaTokenBase.mtxRelayFee,
                (nid(alice), address(0x7A), keccak256("call"), nid(feeTo), 5, 2, 0, block.timestamp + 60, _bad()));
            bytes4 ctl = _try(t, cd);
            assertTrue(ctl != 0 && ctl != IRegulatedToken.FeeRecipientFrozen.selector, "control");
            _freeze(t, nid(feeTo));
            assertEq(_try(t, cd), IRegulatedToken.FeeRecipientFrozen.selector);
        }
    }

    /// The DEX relayer share (decided, spec §3.2): a venue pays it from its own balance by an ordinary transfer, which a
    /// freeze never refuses (credits are never refused, CTR-AS-05); the frozen relayer's own send stays refused.
    function test_dexRelayerShareIsOrdinaryCredit() public {
        Venue venue = new Venue();
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(alice);
            IERC20(t).transfer(address(venue), 10);
            _freeze(t, nid(relayer));
            venue.pay(t, relayer, 4);
            assertEq(IERC20(t).balanceOf(relayer), 4);
            vm.prank(relayer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(relayer)));
            IERC20(t).transfer(bob, 1);
        }
    }

    // ------------------------------------------------------------------ mtxWrapOrder (kind 9)

    /// Kind 9 over a SCaaS underlying (a kind-0 token alice holds), `FREEZE` only.
    function _wrapOrderPair() internal returns (address u, address w) {
        u = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(normalInit("U", "U", 0, SUPPLY, alice, address(0))), "u");
        IFactoryToken.TokenConfig memory c = _cfg9();
        c.features = (1 << GovernanceBits.PAYABLE) | (1 << GovernanceBits.FREEZE);
        c.roles.compliance = 0;
        c.legs[0] = IFactoryToken.Leg(u, 3, 1);
        w = f.createToken(IOpenFactory.TokenKind.WRAPPED_REGULATED, 1, abi.encode(c), "w");
    }

    function _wrapOrder(address w, uint256 fee, bytes32 destination) internal view returns (ITradeToken.UAWrapOrder memory o) {
        (o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill, o.fee) = (nid(alice), w, 1000, 3000, 1000, fee);
        (o.destination, o.batch, o.nonce, o.validUntil) = (destination, 7, 1, block.timestamp + 300);
    }

    function _wrapSig(address u, ITradeToken.UAWrapOrder memory o) internal view returns (IUARegistry.UASig memory a) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, MetaTokenBase(u).tradeOrderDigest(DexLegs.asTrade(o)));
        a.signature = abi.encodePacked(r, s, v);
    }

    /// The submitter's fee (`fee != 0`, minted to `msg.sender`) with a frozen submitter: `FeeRecipientFrozen`, before the
    /// mints; unfrozen, the order wraps and pays it (the control).
    function test_wrapOrderFrozenSubmitter() public {
        (address u, address w) = _wrapOrderPair();
        ITradeToken.UAWrapOrder memory o = _wrapOrder(w, 1_000, 0);
        IUARegistry.UASig memory sig = _wrapSig(u, o);
        _freeze(w, nid(relayer));
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, nid(relayer)));
        WrappedToken(payable(w)).mtxWrapOrder(u, o, sig);
        _unfreeze(w, nid(relayer));
        vm.prank(relayer);
        WrappedToken(payable(w)).mtxWrapOrder(u, o, sig);
        assertEq(IERC20(w).balanceOf(relayer), 3);
        assertEq(IERC20(w).balanceOf(alice), 2997);
    }

    /// C10, F-28: an order whose destination is another id moves `o.from`'s value: a frozen `o.from` is refused `Frozen`
    /// before the signature; to `o.from` itself it is a credit, not checked (a wrap of her own units).
    function test_wrapOrderFrozenFromOtherDestination() public {
        (address u, address w) = _wrapOrderPair();
        _freeze(w, nid(alice));
        ITradeToken.UAWrapOrder memory o = _wrapOrder(w, 0, nid(bob));
        IUARegistry.UASig memory none;
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(alice)));
        WrappedToken(payable(w)).mtxWrapOrder(u, o, none);
        o = _wrapOrder(w, 0, 0);
        IUARegistry.UASig memory sig = _wrapSig(u, o);
        vm.prank(relayer);
        WrappedToken(payable(w)).mtxWrapOrder(u, o, sig);
        assertEq(IERC20(w).balanceOf(alice), 3000);
    }

    /// alice's signed `UARelayFee` of 5 to the router (open mode) on lane 2, nonce 0, for `cd` on `target` (helpers: the
    /// test's stack).
    function _relaySig(address t, address target, bytes memory cd, address router, uint256 vu)
        internal view returns (IUARegistry.UASig memory a)
    {
        bytes32 h = keccak256(abi.encode(keccak256(
            "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer)"),
            nid(alice), target, keccak256(cd), nid(router), uint256(5), uint256(2), uint256(0), vu, router));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_PK, MtxDigest.typed(t, h));
        a.signature = abi.encodePacked(r, s, v);
    }

    /// pay-meta-tax T38, O14 (spec §4.1): router open mode stays on the regulated kinds; its limitation pinned: a frozen
    /// submitter is still paid, because RK-6 checks the signed payee (the router), not the one the router forwards to.
    function test_relayFee_openModeFrozenSubmitterPaid() public {
        RelayFeeRouter router = new RelayFeeRouter();
        RelayPing target = new RelayPing();
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            _freeze(t, nid(relayer));
            uint256 b0 = IERC20(t).balanceOf(relayer);
            _openRelay(router, address(target), t);
            assertEq(IERC20(t).balanceOf(relayer), b0 + 5, "O14: the frozen submitter is paid in open mode");
        }
    }

    /// `relayer` submits alice's open-mode relay fee of 5 for `ping()` on `target`.
    function _openRelay(RelayFeeRouter router, address target, address t) internal {
        bytes memory cd = abi.encodeCall(RelayPing.ping, ());
        uint256 vu = block.timestamp + 300;
        IUARegistry.UASig memory a = _relaySig(t, target, cd, address(router), vu);
        vm.prank(relayer);
        router.relay(target, cd, t, nid(alice), nid(address(router)), 5, 2, 0, vu, a);
    }

}
