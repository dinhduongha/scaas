// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Mock1271Wallet} from "../helpers/WalletMocks.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {IMetaTokenV2} from "../../src/metatx/IMetaTokenV2.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {noneInit} from "./helpers/V2Fixture.sol";

/// Receiver-pays (CTR-MTX-05, CTR-MTX-06): the payer's `MetaTransfer` runs untouched, the payee's co-signed
/// `ReceiverFee` moves `fee` from the payee in the same transaction.
contract ReceiverPaysTest is Test {
    bytes32 internal constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 internal constant PAYER_PK = 0xA11CE;
    uint256 internal constant PAYEE_PK = 0xB0B;
    address internal payer = vm.addr(PAYER_PK);
    address internal payee = vm.addr(PAYEE_PK);
    address internal relayer = address(0xBEEF);
    address internal feeTo = address(0xFEE);
    bytes32 internal constant REF = keccak256("request-1");
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    NoUnderlyingToken internal t;

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        address impl = address(new NoUnderlyingToken(address(this), address(0), UID, false));
        t = NoUnderlyingToken(Clones.clone(impl));
        t.initialize(address(this), new address[](0), 1,
            abi.encode(noneInit("Points", "PTS", 6, 0, address(this), address(this))));
        t.mint(payer, 1_000e6);
    }

    function _pay(address to, uint256 value) internal view returns (MetaTxLib.MetaTransfer memory) {
        return MetaTxLib.MetaTransfer({
            from: payer, to: to, value: value, entryRef: REF, batch: t.payLane(REF), nonce: 0,
            validUntil: block.timestamp + 300, mode: RR, relayer: relayer, fee: 0, feeRecipient: address(0)
        });
    }

    function _sig(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function _run(MetaTxLib.MetaTransfer memory x, uint256 fee, address to, uint256 rfUntil) internal {
        bytes memory ps = _sig(PAYER_PK, t.mtxTransferDigest(x));
        bytes memory rs = _sig(PAYEE_PK, t.receiverFeeDigest(t.mtxTransferDigest(x), fee, to, rfUntil));
        vm.prank(relayer);
        t.mtxPayReceiverFee(x, ps, fee, to, rfUntil, rs);
    }

    function _runRevert(MetaTxLib.MetaTransfer memory x, uint256 fee, address to, uint256 rfUntil, bytes memory err)
        internal
    {
        bytes memory ps = _sig(PAYER_PK, t.mtxTransferDigest(x));
        bytes memory rs = _sig(PAYEE_PK, t.receiverFeeDigest(t.mtxTransferDigest(x), fee, to, rfUntil));
        vm.prank(relayer);
        vm.expectRevert(err);
        t.mtxPayReceiverFee(x, ps, fee, to, rfUntil, rs);
    }

    function test_payeePaysTheFee_eventsAndBalances() public {
        MetaTxLib.MetaTransfer memory x = _pay(payee, 100e6);
        bytes32 d = t.mtxTransferDigest(x);
        vm.expectEmit(address(t));
        emit IERC20Payment.PaymentSettled(payer, payee, 100e6, 0, relayer, REF);
        vm.expectEmit(address(t));
        emit IMetaTx.MetaTransactionExecuted(payer, relayer, t.payLane(REF), 0, d, relayer, 0);
        vm.expectEmit(address(t));
        emit IMetaTokenV2.ReceiverFeePaid(d, payee, feeTo, 3e6);
        _run(x, 3e6, feeTo, block.timestamp + 60);
        assertEq(t.balanceOf(payer), 900e6);                 // RP1: payer −N
        assertEq(t.balanceOf(payee), 97e6);                  // payee N − fee
        assertEq(t.balanceOf(feeTo), 3e6);
    }

    function test_feeEqualToValue_and_unboundPayerFeeRecipientIgnored() public {
        MetaTxLib.MetaTransfer memory x = _pay(payee, 10e6);
        x.feeRecipient = address(0xDEAD);                    // not checked (canon zeroes it)
        _run(x, 10e6, feeTo, block.timestamp);
        assertEq(t.balanceOf(payee), 0);
        assertEq(t.balanceOf(feeTo), 10e6);
    }

    function test_shapeErrors() public {
        bytes memory shape = abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeShape.selector);
        MetaTxLib.MetaTransfer memory x = _pay(payee, 10e6);
        x.entryRef = 0;
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        x = _pay(payee, 10e6);
        x.mode = RR | MetaTxLib.MODE_FEE_FIXED;
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        x = _pay(payee, 10e6);
        x.fee = 1;
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        x = _pay(payee, 10e6);
        x.mode = 0;                                          // payer relayer unbound
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        x = _pay(payee, 10e6);
        x.batch = 1;                                         // not payLane(entryRef)
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        x = _pay(payee, 10e6);
        x.nonce = 1;
        _runRevert(x, 1, feeTo, block.timestamp, shape);
        _runRevert(_pay(payee, 10e6), 1, address(0), block.timestamp, shape);
    }

    function test_amountExpiryAndPayeeCheck() public {
        MetaTxLib.MetaTransfer memory x = _pay(payee, 10e6);
        _runRevert(x, 0, feeTo, block.timestamp,
            abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeAmount.selector, 0, 10e6));
        _runRevert(x, 10e6 + 1, feeTo, block.timestamp,
            abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeAmount.selector, 10e6 + 1, 10e6));
        _runRevert(x, 1, feeTo, block.timestamp - 1,
            abi.encodeWithSelector(IMetaTokenV2.ReceiverFeeExpired.selector, block.timestamp - 1, block.timestamp));
        _runRevert(x, 1, payee, block.timestamp, abi.encodeWithSelector(IERC20MetaTx.FeeRecipientIsPayee.selector));
        _runRevert(x, 1, address(t), block.timestamp, abi.encodeWithSelector(IERC20MetaTx.TransferToSelf.selector));
    }

    function test_coSignatureOverAnotherDigest_refused() public {
        MetaTxLib.MetaTransfer memory x = _pay(payee, 10e6);
        MetaTxLib.MetaTransfer memory other = _pay(payee, 11e6);
        bytes memory ps = _sig(PAYER_PK, t.mtxTransferDigest(x));
        bytes memory rs = _sig(PAYEE_PK, t.receiverFeeDigest(t.mtxTransferDigest(other), 1, feeTo, block.timestamp));
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxPayReceiverFee(x, ps, 1, feeTo, block.timestamp, rs);
        assertEq(t.balanceOf(payee), 0);                     // RP4: no fee without the payment, and vice versa
    }

    function test_payerIntentLandedElsewhere_coSignatureDead() public {
        MetaTxLib.MetaTransfer memory x = _pay(payee, 10e6);
        bytes memory ps = _sig(PAYER_PK, t.mtxTransferDigest(x));
        bytes memory rs = _sig(PAYEE_PK, t.receiverFeeDigest(t.mtxTransferDigest(x), 1, feeTo, block.timestamp));
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, ps);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        t.mtxPayReceiverFee(x, ps, 1, feeTo, block.timestamp, rs);
        assertEq(t.balanceOf(feeTo), 0);
    }

    function test_erc1271Payee() public {
        Mock1271Wallet w = new Mock1271Wallet(payee);
        MetaTxLib.MetaTransfer memory x = _pay(address(w), 10e6);
        bytes memory ps = _sig(PAYER_PK, t.mtxTransferDigest(x));
        bytes memory rs = _sig(PAYEE_PK, t.receiverFeeDigest(t.mtxTransferDigest(x), 2e6, feeTo, block.timestamp));
        vm.prank(relayer);
        t.mtxPayReceiverFee(x, ps, 2e6, feeTo, block.timestamp, rs);
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

    /// The `ReceiverFee` typehash and domain are pinned independently of the contract.
    function test_receiverFeeDigestIsPinned() public view {
        assertEq(keccak256("ReceiverFee(bytes32 paymentDigest,uint256 fee,address feeRecipient,uint256 validUntil)"),
            0x0128f09c9f096f23f7540465cf85cf756ab725cb552bf61e040433a9b20a9bdf);
        bytes32 domainSep = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256("SCaaS MetaToken"), keccak256("1"), uint256(7622), address(t), UID));
        bytes32 d = keccak256("payment");
        bytes32 expected = keccak256(abi.encodePacked(hex"1901", domainSep, keccak256(abi.encode(
            bytes32(0x0128f09c9f096f23f7540465cf85cf756ab725cb552bf61e040433a9b20a9bdf), d, uint256(3e6), feeTo,
            uint256(1_800_000_060)))));
        assertEq(t.receiverFeeDigest(d, 3e6, feeTo, 1_800_000_060), expected);
    }
}
