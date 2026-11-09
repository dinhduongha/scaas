// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";

import {Vm} from "forge-std/Test.sol";
import {UACall} from "../ua/UACall.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {PayRigBase} from "./PayMeta.t.sol";
import {PayMetaKit} from "../helpers/PayMetaKit.sol";

/// @notice Pay-meta-tax spec §2.2, §2.3, §2.5 (T37; O3, O12): every pay entry consumes `(t.from, t.batch, t.nonce)` like
///         `mtxExecuteTransfer`, on any lane; one `entryRef` takes several payments; `payLane(entryRef)` at nonce 0 is a
///         client convention that still works; the receiver-fee shape lost its lane terms; the generic path lands a pay
///         signature without `PaymentMeta` (O12, pinned). Every kind of the parity rigs.
contract PayLanesTest is PayRigBase {
    uint256 internal constant PAYEE_PK = 0xB0B0B;
    address internal constant RF_TO = address(0xFEE6);

    function test_mtxPay_freeLane() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(10 + i);
            _pay(t, _ut(PayMetaKit.id(m), 7, 0), m);
            MetaTxLib.PayMeta memory m2 = _meta(20 + i);
            _pay(t, _ut(PayMetaKit.id(m2), 7, 1), m2);
            assertEq(NormalToken(t).mtxNonce(MetaTxLib.pad(signer), 7), 2, kinds[i]);
            assertEq(NormalToken(t).balanceOf(PAYEE), 2 * AMOUNT, kinds[i]);
        }
    }

    function test_mtxPay_payLaneConventionStillWorks() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(30 + i);
            bytes32 ref = PayMetaKit.id(m);
            uint256 lane = NormalToken(t).payLane(ref);
            assertEq(lane, uint256(keccak256(abi.encodePacked("scaas.pay.lane", ref))), kinds[i]);
            _pay(t, _ut(ref, lane, 0), m);
            assertEq(NormalToken(t).mtxNonce(MetaTxLib.pad(signer), lane), 1, kinds[i]);
        }
    }

    /// O3: two partial payments of one `entryRef` both land, each with its `PaymentMeta` (F-16).
    function test_mtxPay_twoPartialsSameRef() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(40 + i);
            bytes32 ref = PayMetaKit.id(m);
            vm.recordLogs();
            _pay(t, _ut(ref, 3, 0), m);
            _pay(t, _ut(ref, 5, 0), m);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(_count(logs, t, IMetaTokenV2.PaymentMeta.selector), 2, kinds[i]);
            assertEq(_count(logs, t, IUALedger.UAPaymentSettled.selector), 2, kinds[i]);
            assertEq(NormalToken(t).balanceOf(PAYEE), 2 * AMOUNT, kinds[i]);
        }
    }

    /// `mtxPayMeta` and the flat `mtxPay` are gone (legacy): their selectors reach no function.
    function test_mtxPayMeta_selectorAbsent() public {
        bytes4 meta = bytes4(keccak256(
            "mtxPayMeta(bytes32,bytes32,uint256,bytes32,bytes,uint256,uint32,address,uint256,address,(bytes32,bytes32,bytes,bytes))"));
        bytes4 flat = bytes4(keccak256(
            "mtxPay(bytes32,bytes32,uint256,bytes32,uint256,uint32,address,uint256,address,(bytes32,bytes32,bytes,bytes))"));
        bytes4 metaId = bytes4(keccak256("metaPayId(bytes32,bytes)"));
        for (uint256 i; i < toks.length; ++i) {
            (bool ok,) = toks[i].call(abi.encodeWithSelector(meta));
            assertFalse(ok, kinds[i]);
            (ok,) = toks[i].call(abi.encodeWithSelector(flat));
            assertFalse(ok, kinds[i]);
            (ok,) = toks[i].call(abi.encodeWithSelector(metaId, bytes32(uint256(1)), ""));
            assertFalse(ok, kinds[i]);
        }
        assertTrue(meta != NormalToken.mtxPay.selector && flat != NormalToken.mtxPay.selector);
    }

    /// O12 pinned: the `UAMetaTransfer` signed for `mtxPay` lands through `mtxExecuteTransfer` without `PaymentMeta`; its
    /// nonce then refuses `mtxPay`.
    function test_genericPath_landsWithoutPaymentMeta() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(50 + i);
            MetaTxLib.UAMetaTransfer memory x = _ut(PayMetaKit.id(m), 7, 0);
            IUARegistry.UASig memory s = _sigOf(t, x);
            vm.recordLogs();
            vm.prank(REL);
            NormalToken(t).mtxExecuteTransfer(x, s);
            Vm.Log[] memory logs = vm.getRecordedLogs();
            assertEq(_count(logs, t, IMetaTokenV2.PaymentMeta.selector), 0, kinds[i]);
            assertEq(_count(logs, t, IUALedger.UAPaymentSettled.selector), 1, kinds[i]);
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
            NormalToken(t).mtxPay(x, s, m);
        }
    }

    // ------------------------------------------------------------------ receiver-pays (spec §2.5)

    /// The payer's payment for receiver-pays: fee `NONE`, `RESTRICT_RELAYER`, the payee `vm.addr(PAYEE_PK)`.
    function _rfX(bytes32 ref, uint256 batch, uint256 nonce) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer(MetaTxLib.pad(signer), MetaTxLib.pad(vm.addr(PAYEE_PK)), AMOUNT, ref, batch, nonce,
            block.timestamp + 300, MetaTxLib.MODE_RESTRICT_RELAYER, REL, 0, address(0));
    }

    function _rf(address t, MetaTxLib.UAMetaTransfer memory x, MetaTxLib.PayMeta memory m) internal {
        IUARegistry.UASig memory pa = _sigOf(t, x);
        bytes32 rd = NormalToken(t).receiverFeeDigest(x, 10, RF_TO, block.timestamp + 300);
        IUARegistry.UASig memory qa = UACall.auth(x.to, _ecdsa(PAYEE_PK, rd));
        uint256 vu = block.timestamp + 300;
        vm.prank(REL);
        NormalToken(t).mtxPayReceiverFee(x, pa, 10, RF_TO, vu, qa, m);
    }

    /// A receiver fee on a free lane (lane 7, nonces 0 and 1): no `payLane` / nonce-0 term.
    function test_receiverFee_freeLane() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(60 + i);
            _rf(t, _rfX(PayMetaKit.id(m), 7, 0), m);
            _rf(t, _rfX(PayMetaKit.id(m), 7, 1), m);
            assertEq(NormalToken(t).balanceOf(vm.addr(PAYEE_PK)), 2 * (AMOUNT - 10), kinds[i]);
            assertEq(NormalToken(t).balanceOf(RF_TO), 20, kinds[i]);
        }
    }

    /// RP2: the payee's co-signature is dead once the payer's nonce was used elsewhere.
    function test_receiverFee_coSignDeadAfterNonceUsed() public {
        for (uint256 i; i < toks.length; ++i) {
            address t = toks[i];
            MetaTxLib.PayMeta memory m = _meta(70 + i);
            MetaTxLib.UAMetaTransfer memory x = _rfX(PayMetaKit.id(m), 7, 0);
            IUARegistry.UASig memory pa = _sigOf(t, x);
            IUARegistry.UASig memory qa = UACall.auth(x.to,
                _ecdsa(PAYEE_PK, NormalToken(t).receiverFeeDigest(x, 10, RF_TO, block.timestamp + 300)));
            uint256 snap = vm.snapshotState();
            vm.prank(REL);
            NormalToken(t).mtxPayReceiverFee(x, pa, 10, RF_TO, block.timestamp + 300, qa, m); // control
            vm.revertToState(snap);
            vm.prank(REL);
            NormalToken(t).mtxPay(x, pa, m); // the payer's nonce, used by a plain pay
            vm.prank(REL);
            vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
            NormalToken(t).mtxPayReceiverFee(x, pa, 10, RF_TO, block.timestamp + 300, qa, m);
        }
    }

    /// The receiver-fee entry checks `PayMeta` like every pay entry: a mismatched one is refused by name.
    function test_receiverFee_metaMismatch() public {
        address t = toks[0];
        MetaTxLib.PayMeta memory m = _meta(80);
        MetaTxLib.PayMeta memory other = _meta(81);
        MetaTxLib.UAMetaTransfer memory x = _rfX(PayMetaKit.id(m), 7, 0);
        IUARegistry.UASig memory pa = _sigOf(t, x);
        IUARegistry.UASig memory qa = UACall.auth(x.to,
            _ecdsa(PAYEE_PK, NormalToken(t).receiverFeeDigest(x, 10, RF_TO, block.timestamp + 300)));
        vm.prank(REL);
        vm.expectRevert(abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, x.entryRef, PayMetaKit.id(other)));
        NormalToken(t).mtxPayReceiverFee(x, pa, 10, RF_TO, block.timestamp + 300, qa, other);
    }
}
