// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {kindArgs} from "../../script/KindModules.sol";

import {PayMetaKit} from "../helpers/PayMetaKit.sol";
import {OrderJson} from "../helpers/OrderJson.sol";
import {Erc7739Kit} from "../helpers/Erc7739Kit.sol";
import {domainOf, h, n, a as a_} from "../metatx/NamedEntry.t.sol";
import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {normalInit} from "./helpers/V2Fixture.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// Payee fee (CTR-MTX-05, CTR-MTX-06): the payer's `UAMetaTransfer` runs untouched, the payee's co-signed
/// `UAPayeeFee` moves `fee` from the payee in the same transaction. ua-mtx-merge T2: the one `mtxPayWithPayeeFee`
/// (today's `uaPayReceiverFee`), here with native payer and payee (EOAs signing with their own keys, ids padded); the
/// address `MetaTransfer` / `ReceiverFee` form and this file as it stood are in legacy/ua-mtx-merge/.
contract PayeeFeeTest is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant PAYER_PK = 0xA11CE;
    uint256 internal constant PAYEE_PK = 0xB0B;
    address internal payer = vm.addr(PAYER_PK);
    address internal payee = vm.addr(PAYEE_PK);
    address internal relayer = address(0xBEEF);
    address internal feeTo = address(0xFEE);
    /// pay-meta-tax T37: the request's `entryRef` is the commitment of its `PayMeta` (`PayMetaKit.meta("request-1")`).
    bytes32 internal REF = PayMetaKit.ref("request-1");
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    NormalToken internal t;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        address impl = address(new NormalToken(address(this), kindArgs(0, address(this), "")));
        t = NormalToken(EnvKit.clone(impl, EnvKit.env(UID, address(0), address(0), false)));
        t.initialize(nid(address(this)), 1, abi.encode(normalInit("Points", "PTS", 6, 0, address(this), address(this))));
        t.mint(payer, 1_000e6);
    }

    function _pay(address to, uint256 value) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer({
            from: MetaTxLib.pad(payer), to: MetaTxLib.pad(to), value: value, entryRef: REF, batch: t.payLane(REF), nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// A native id's `UASig`: its own signature only (R17).
    function _n(bytes memory sig) internal pure returns (IUARegistry.UASig memory u) {
        u.signature = sig;
    }

    function _run(MetaTxLib.UAMetaTransfer memory x, uint256 fee, address to, uint256 rfUntil) internal {
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        IUARegistry.UASig memory rs = _n(_sig(PAYEE_PK, t.payeeFeeDigest(x, fee, to, rfUntil)));
        vm.prank(relayer);
        t.mtxPayWithPayeeFee(x, ps, fee, to, rfUntil, rs, PayMetaKit.meta("request-1"));
    }

    function _runRevert(MetaTxLib.UAMetaTransfer memory x, uint256 fee, address to, uint256 rfUntil, bytes memory err)
        internal
    {
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        IUARegistry.UASig memory rs = _n(_sig(PAYEE_PK, t.payeeFeeDigest(x, fee, to, rfUntil)));
        vm.prank(relayer);
        vm.expectRevert(err);
        t.mtxPayWithPayeeFee(x, ps, fee, to, rfUntil, rs, PayMetaKit.meta("request-1"));
    }

    /// C5-3: a `UA_POOL` fee recipient is refused before the payer's payment runs (the payee signature is not even
    /// read). ua-mtx-merge T2, meaning: the merged body (today's `uaPayReceiverFee`) refuses `SHIELD_POOL` at the fee's
    /// move (D19, `_uaMove`), after both signatures: the call reverts whole and nothing moves; the address body's early
    /// `_notPool` is in legacy/ua-mtx-merge/.
    function test_C5_3_poolFeeRecipientRefusedFirst() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 100e6);
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        vm.prank(relayer);
        vm.expectRevert(IUALedger.UAPoolNotPayable.selector);
        t.mtxPayWithPayeeFee(x, ps, 3e6, MetaTxLib.UA_POOL, block.timestamp + 60, _n(hex"00"), PayMetaKit.meta("request-1"));
        _runRevert(x, 3e6, MetaTxLib.SHIELD_POOL, block.timestamp + 60,
            abi.encodeWithSelector(IUALedger.ShieldPoolNotPayable.selector));
        assertEq(t.balanceOf(payer), 1_000e6);
        assertEq(t.balanceOf(MetaTxLib.SHIELD_POOL), 0);
    }

    /// ua-mtx-merge T2 (R18, R20), meaning: the `UA…` events with padded ids, not the address ones.
    function test_payeePaysTheFee_eventsAndBalances() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 100e6);
        bytes32 d = t.mtxTransferDigest(x);
        vm.expectEmit(address(t));
        emit IUALedger.UAPaymentSettled(MetaTxLib.pad(payer), MetaTxLib.pad(payee), 100e6, 0, relayer, REF);
        vm.expectEmit(address(t));
        emit IUALedger.UAMetaTransactionExecuted(MetaTxLib.pad(payer), relayer, t.payLane(REF), 0, d, relayer, 0);
        vm.expectEmit(address(t));
        emit IMetaTokenV2.UAPayeeFeePaid(d, MetaTxLib.pad(payee), feeTo, 3e6);
        _run(x, 3e6, feeTo, block.timestamp + 60);
        assertEq(t.balanceOf(payer), 900e6);                 // RP1: payer −N
        assertEq(t.balanceOf(payee), 97e6);                  // payee N − fee
        assertEq(t.balanceOf(feeTo), 3e6);
    }

    function test_feeEqualToValue_and_unboundPayerFeeRecipientIgnored() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 10e6);
        x.feeRecipient = address(0xDEAD);                    // not checked (canon zeroes it)
        _run(x, 10e6, feeTo, block.timestamp);
        assertEq(t.balanceOf(payee), 0);
        assertEq(t.balanceOf(feeTo), 10e6);
    }

    function test_shapeErrors() public {
        bytes memory shape = abi.encodeWithSelector(IMetaTokenV2.PayeeFeeShape.selector);
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 10e6);
        x.entryRef = 0; // pay-meta-tax T37, meaning: `_payMeta` refuses it first, by name
        _runRevert(x, 1, feeTo, block.timestamp,
            abi.encodeWithSelector(IMetaTokenV2.PayMetaMismatch.selector, bytes32(0), REF));
        x = _pay(payee, 10e6);
        x.mode = RR | MetaTxLib.MODE_FEE_FIXED;
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        x = _pay(payee, 10e6);
        x.fee = 1;
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        x = _pay(payee, 10e6);
        x.mode = 0;                                          // payer relayer unbound
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        // pay-meta-tax T37 (O3, spec §2.5): `batch == payLane(entryRef)` and `nonce == 0` are no longer part of the shape
        // (test/metatx/PayLanes.t.sol `test_payeeFee_freeLane`)
        _runRevert(_pay(payee, 10e6), 1, address(0), block.timestamp, shape);
    }

    function test_amountExpiryAndPayeeCheck() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 10e6);
        _runRevert(x, 0, feeTo, block.timestamp,
            abi.encodeWithSelector(IMetaTokenV2.PayeeFeeAmount.selector, 0, 10e6));
        _runRevert(x, 10e6 + 1, feeTo, block.timestamp,
            abi.encodeWithSelector(IMetaTokenV2.PayeeFeeAmount.selector, 10e6 + 1, 10e6));
        _runRevert(x, 1, feeTo, block.timestamp - 1,
            abi.encodeWithSelector(IMetaTokenV2.PayeeFeeExpired.selector, block.timestamp - 1, block.timestamp));
        _runRevert(x, 1, payee, block.timestamp, abi.encodeWithSelector(IERC20MetaTx.FeeRecipientIsPayee.selector));
        _runRevert(x, 1, address(t), block.timestamp, abi.encodeWithSelector(IERC20MetaTx.TransferToSelf.selector));
    }

    function test_coSignatureOverAnotherDigest_refused() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 10e6);
        MetaTxLib.UAMetaTransfer memory other = _pay(payee, 11e6);
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        IUARegistry.UASig memory rs = _n(_sig(PAYEE_PK, t.payeeFeeDigest(other, 1, feeTo, block.timestamp)));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxPayWithPayeeFee(x, ps, 1, feeTo, block.timestamp, rs, PayMetaKit.meta("request-1"));
        assertEq(t.balanceOf(payee), 0);                     // RP4: no fee without the payment, and vice versa
    }

    function test_payerIntentLandedElsewhere_coSignatureDead() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 10e6);
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        IUARegistry.UASig memory rs = _n(_sig(PAYEE_PK, t.payeeFeeDigest(x, 1, feeTo, block.timestamp)));
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, ps);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        t.mtxPayWithPayeeFee(x, ps, 1, feeTo, block.timestamp, rs, PayMetaKit.meta("request-1"));
        assertEq(t.balanceOf(feeTo), 0);
    }

    function test_erc1271Payee() public {
        Mock1271Wallet w = new Mock1271Wallet(payee);
        MetaTxLib.UAMetaTransfer memory x = _pay(address(w), 10e6);
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        IUARegistry.UASig memory rs = _n(_sig(PAYEE_PK, t.payeeFeeDigest(x, 2e6, feeTo, block.timestamp)));
        vm.prank(relayer);
        t.mtxPayWithPayeeFee(x, ps, 2e6, feeTo, block.timestamp, rs, PayMetaKit.meta("request-1"));
        assertEq(t.balanceOf(address(w)), 8e6);
        assertEq(t.balanceOf(feeTo), 2e6);
    }

    /// RP1 under fuzz: payee nets `N − fee ≥ 0`, payer `−N`, fee recipient `+fee`.
    function testFuzz_rp1(uint256 n, uint256 fee) public {
        n = bound(n, 1, 1_000e6);
        fee = bound(fee, 1, n);
        _run(_pay(payee, n), fee, feeTo, block.timestamp);
        assertEq(t.balanceOf(payer), 1_000e6 - n);
        assertEq(t.balanceOf(payee), n - fee);
        assertEq(t.balanceOf(feeTo), fee);
    }

    function _walletFee(MetaTxLib.UAMetaTransfer memory x, uint256 fee, uint256 until) internal view returns (bytes32) {
        string memory m = string.concat('{"payment":{"from":', h(x.from), ',"to":', h(x.to), ',"value":', n(x.value), ',"entryRef":', h(x.entryRef),
            ',"batch":', n(x.batch), ',"nonce":', n(x.nonce), ',"validUntil":', n(x.validUntil));
        return OrderJson.digest(address(t), "UAPayeeFee", string.concat(
            '"UAPayeeFee":[{"name":"payment","type":"UAMetaTransfer"},{"name":"fee","type":"uint256"},{"name":"feeRecipient","type":"address"},',
            '{"name":"validUntil","type":"uint256"}],"UAMetaTransfer":[{"name":"from","type":"bytes32"},{"name":"to","type":"bytes32"},',
            '{"name":"value","type":"uint256"},{"name":"entryRef","type":"bytes32"},{"name":"batch","type":"uint256"},{"name":"nonce","type":"uint256"},',
            '{"name":"validUntil","type":"uint256"},{"name":"mode","type":"uint32"},{"name":"relayer","type":"address"},{"name":"fee","type":"uint256"},',
            '{"name":"feeRecipient","type":"address"}]'), string.concat(m, ',"mode":', n(x.mode), ',"relayer":', a_(x.relayer), ',"fee":', n(x.fee),
            ',"feeRecipient":', a_(x.feeRecipient), '},"fee":', n(fee), ',"feeRecipient":', a_(feeTo), ',"validUntil":', n(until), '}'));
    }

    /// `UAPayeeFee` nests the payment (TS-D19): the wallet's JSON is the digest the payee signs. The pre-C6 form over the
    /// payment digest, the only change, is `MetaTxBadSignature` and nothing moves; a co-signature for another payment too;
    /// the wallet's runs.
    function test_payeeFeeNested() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 100e6);
        uint256 until = block.timestamp + 60;
        bytes32 wallet = _walletFee(x, 3e6, until);
        assertEq(t.payeeFeeDigest(x, 3e6, feeTo, until), wallet);
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        {
            bytes32 flat = keccak256(abi.encodePacked(hex"1901", domainOf(address(t)), keccak256(abi.encode(
                keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)"),
                t.mtxTransferDigest(x), uint256(3e6), feeTo, until))));
            IUARegistry.UASig memory old = _n(_sig(PAYEE_PK, flat));
            vm.prank(relayer);
            vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
            t.mtxPayWithPayeeFee(x, ps, 3e6, feeTo, until, old, PayMetaKit.meta("request-1"));
        }
        {
            MetaTxLib.UAMetaTransfer memory y = _pay(payee, 100e6 + 1);
            IUARegistry.UASig memory forOther = _n(_sig(PAYEE_PK, t.payeeFeeDigest(y, 3e6, feeTo, until)));
            vm.prank(relayer);
            vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
            t.mtxPayWithPayeeFee(x, ps, 3e6, feeTo, until, forOther, PayMetaKit.meta("request-1"));
        }
        assertEq(t.balanceOf(payee), 0);
        vm.prank(relayer);
        t.mtxPayWithPayeeFee(x, ps, 3e6, feeTo, until, _n(_sig(PAYEE_PK, wallet)), PayMetaKit.meta("request-1"));
        assertEq(t.balanceOf(feeTo), 3e6);
    }

    function _paymentHash(MetaTxLib.UAMetaTransfer memory x) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,"
                "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
            x.from, x.to, x.value, x.entryRef, x.batch, x.nonce, x.validUntil, x.mode, x.relayer, x.fee, x.feeRecipient));
    }

    /// The `UAPayeeFee` typehash and domain are pinned independently of the contract. ua-mtx-merge T2, meaning: the
    /// token's payee-fee struct is `UAPayeeFee` (R21); the address `ReceiverFee` pin stays
    /// (legacy, no entry), and so does `UAReceiverFee`'s, the name before the payee-fee rename (CTR-MTX-86).
    function test_payeeFeeDigestIsPinned() public view {
        assertEq(keccak256("ReceiverFee(MetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)"
            "MetaTransfer(address from,address to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,"
            "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
            0x7c08a6ca283c642a92e66bc1b0a04aaf10abca26906244a63d8a5e3c28232305);
        assertEq(keccak256("UAReceiverFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)"
            "UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,"
            "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
            0xb12d2a080dcf6d9edea1a63b0fd3a59ebffa656c929d21f676d1f1507c75021a);
        // owner 2026-11-12 (CTR-MTX-86): the struct is `UAPayeeFee`, the same members
        assertEq(keccak256("UAPayeeFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)"
            "UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,"
            "uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
            0x8a3955a6c3529266f588d56c7bfd28bdd0b5ad194fc9ca4428e159686a16c7ca);
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(t), UID));
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 100e6);
        bytes32 expected = keccak256(abi.encodePacked(hex"1901", domainSep, keccak256(abi.encode(
            bytes32(0x8a3955a6c3529266f588d56c7bfd28bdd0b5ad194fc9ca4428e159686a16c7ca), _paymentHash(x), uint256(3e6), feeTo,
            uint256(1_800_000_060)))));
        assertEq(t.payeeFeeDigest(x, 3e6, feeTo, 1_800_000_060), expected);
    }

    /// Owner 2026-11-12 (CTR-MTX-86): the names before the payee-fee rename have no entry. The same calldata under the old
    /// selectors finds no function (`mtxPayReceiverFee` 0x0de1ca2d, `receiverFeeDigest` 0x7c4fa261); under the new ones
    /// it runs (positive control); a payee signature under the old struct name is refused.
    function test_oldReceiverFeeNamesHaveNoEntry() public {
        MetaTxLib.UAMetaTransfer memory x = _pay(payee, 100e6);
        uint256 until = block.timestamp + 60;
        bytes memory args = abi.encode(x, 3e6, feeTo, until);
        (bool ok,) = address(t).staticcall(abi.encodePacked(bytes4(0x7c4fa261), args));
        assertFalse(ok, "receiverFeeDigest");
        bytes memory ret;
        (ok, ret) = address(t).staticcall(abi.encodePacked(IMetaTokenV2.payeeFeeDigest.selector, args));
        assertTrue(ok, "payeeFeeDigest");
        assertEq(abi.decode(ret, (bytes32)), t.payeeFeeDigest(x, 3e6, feeTo, until));
        bytes32 oldTyped = keccak256(abi.encodePacked(hex"1901", Erc7739Kit.separator(address(t)), keccak256(abi.encode(
            bytes32(0xb12d2a080dcf6d9edea1a63b0fd3a59ebffa656c929d21f676d1f1507c75021a), _paymentHash(x), uint256(3e6), feeTo,
            until))));
        IUARegistry.UASig memory ps = _n(_sig(PAYER_PK, t.mtxTransferDigest(x)));
        IUARegistry.UASig memory rs = _n(_sig(PAYEE_PK, t.payeeFeeDigest(x, 3e6, feeTo, until)));
        bytes memory tail = abi.encode(x, ps, 3e6, feeTo, until, rs, PayMetaKit.meta("request-1"));
        vm.prank(relayer);
        (ok,) = address(t).call(abi.encodePacked(bytes4(0x0de1ca2d), tail));
        assertFalse(ok, "mtxPayReceiverFee");
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxPayWithPayeeFee(x, ps, 3e6, feeTo, until, _n(_sig(PAYEE_PK, oldTyped)), PayMetaKit.meta("request-1"));
        vm.prank(relayer);
        (ok,) = address(t).call(abi.encodePacked(IMetaTokenV2.mtxPayWithPayeeFee.selector, tail));
        assertTrue(ok, "mtxPayWithPayeeFee");
        assertEq(t.balanceOf(feeTo), 3e6);
    }
}
