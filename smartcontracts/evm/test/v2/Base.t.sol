// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {V2Fixture, BaseHarness, GasBurner1271, UID_} from "./helpers/V2Fixture.sol";
import {Puller} from "../helpers/WalletMocks.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IERC20Payment} from "../../src/metatx/IERC20Payment.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../../src/common/FeePolicy.sol";

/// T1: `ERC20MetaTx` + `MetaTokenBase` (TW2 §3, §7) trên một tầng giả tối thiểu.
contract BaseTest is V2Fixture {
    BaseHarness t;
    uint256 constant PK = 0xA11CE;
    address alice;
    address shop = address(0x5409);
    address feeTaker = address(0xFEE);

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(PK);
        t = _harness(address(this), 0);
        t.mint(alice, 1_000e6);
    }

    function _exec(MetaTxLib.MetaTransfer memory x) internal {
        _xfer(PK, address(t), x);
    }

    function _expectExecRevert(MetaTxLib.MetaTransfer memory x, bytes memory err) internal {
        bytes memory s = _signTr(PK, address(t), x);
        vm.prank(relayer);
        vm.expectRevert(err);
        t.mtxExecuteTransfer(x, s);
    }

    function _expectCallRevert(MetaTxLib.MetaTransaction memory m, bytes memory err) internal {
        bytes memory s = _signCall(PK, address(t), m);
        vm.prank(relayer);
        vm.expectRevert(err);
        t.mtxExecute(m, s);
    }

    // ------------------------------------------------------------------ domain, init

    function test_domainIsSaltedV1AndTheClone() public {
        vm.chainId(7622);
        (bytes1 f, string memory n, string memory v, uint256 cid, address vc, bytes32 salt,) = t.eip712Domain();
        assertEq(f, hex"1f");
        assertEq(n, "SCaaS MetaToken");
        assertEq(v, "1");
        assertEq(cid, 7622);
        assertEq(vc, address(t));
        assertEq(salt, UID_);
        assertEq(t.name(), "Harness");
        assertEq(t.decimals(), 6);
        assertEq(t.creator(), address(this));
        assertEq(t.version(), 1);
    }

    function test_implementationIsLockedAndCloneInitializesOnce() public {
        address impl = t.implementation();
        IFactoryToken.TokenConfig memory cfg;
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        MetaTokenBase(impl).initialize(address(this), 1, cfg);
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        t.initialize(address(this), 1, cfg);
        address c = Clones.clone(impl);
        vm.prank(address(0xBAD));
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        MetaTokenBase(c).initialize(address(0xBAD), 1, cfg);
    }

    // ------------------------------------------------------------------ pipeline

    function test_transferThroughTheTypedPath() public {
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 100e6, 0, 7, RR);
        bytes32 d = t.mtxTransferDigest(x);
        vm.expectEmit(address(t));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 7, 0, d, relayer, 0);
        _exec(x);
        assertEq(t.balanceOf(shop), 100e6);
        assertEq(t.mtxNonce(alice, 7), 1);
        _expectExecRevert(x, abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
    }

    function test_cancelNonceEmits() public {
        vm.expectEmit(address(t));
        emit IMetaTx.MetaNonceCancelled(alice, 5, 1);
        vm.prank(alice);
        t.cancelNonce(5);
        vm.expectEmit(address(t));
        emit IMetaTx.MetaNonceCancelled(alice, 5, 2);
        vm.prank(alice);
        t.cancelNonce(5);
        assertEq(t.mtxNonce(alice, 5), 2);
        // signed on another lane: a subject without gas cancels
        vm.expectEmit(address(t));
        emit IMetaTx.MetaNonceCancelled(alice, 5, 3);
        _execCall(PK, address(t), _call(alice, abi.encodeCall(t.cancelNonce, (5)), 9, RR));
        assertEq(t.mtxNonce(alice, 5), 3);
        assertEq(t.mtxNonce(alice, 9), 1);
    }

    // ------------------------------------------------------------------ R26, CTR-TOK-01

    /// Caller and spender must both be contracts (the holder here is this test contract).
    function test_allowanceOnlyBetweenContracts() public {
        t.mint(address(this), 10);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, shop));
        t.approve(shop, 1);
        Puller p = new Puller();
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, alice));
        t.approve(address(p), 5);
        t.approve(address(p), 5);
        p.pull(address(t), address(this), shop, 5);
        assertEq(t.balanceOf(shop), 5);
        vm.prank(shop);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, shop));
        t.transferFrom(address(this), shop, 0);
    }

    function test_approveIsNeverASelfCall() public {
        Puller p = new Puller();
        _expectCallRevert(_call(alice, abi.encodeCall(t.approve, (address(p), 77)), 1, RR),
            abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, t.approve.selector));
        assertEq(t.allowance(alice, address(p)), 0);
    }

    function test_erc1271Gets400kOnlyAsSmartKeyAccountClone() public {
        GasBurner1271 burner = new GasBurner1271();
        BaseHarness impl = new BaseHarness(address(this), address(burner));
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.initialHolder) = ("H", "H", address(this)); // the harness mints `initialSupply` (0)
        BaseHarness tk = BaseHarness(_clone(address(impl), address(this), new address[](0), abi.encode(c)));
        address clone = Clones.clone(address(burner));
        tk.mint(clone, 10);
        tk.mint(address(burner), 10);
        MetaTxLib.MetaTransfer memory x = _tr(clone, shop, 1, 0, 1, RR);
        vm.prank(relayer);
        tk.mtxExecuteTransfer(x, hex"00");
        assertEq(tk.balanceOf(shop), 1);
        x.from = address(burner);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tk.mtxExecuteTransfer(x, hex"00");
    }

    function test_shortAndUnlistedData() public {
        _expectCallRevert(_call(alice, hex"0102", 1, RR),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, bytes4(0x01020000)));
        _expectCallRevert(_call(alice, hex"deadbeef", 1, RR),
            abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, bytes4(0xdeadbeef)));
        bytes memory longCancel = abi.encodePacked(abi.encodeCall(t.cancelNonce, (1)), uint8(0));
        _expectCallRevert(_call(alice, longCancel, 1, RR),
            abi.encodeWithSelector(IMetaTx.MtxDataShape.selector, t.cancelNonce.selector));
        _expectCallRevert(_call(alice, abi.encodeCall(t.transfer, (shop, 1)), 1, RR),
            abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, t.transfer.selector));
    }

    /// Review L2: a transfer to 0 fails at step 3 (before the nonce), never after the fee.
    function test_transferToZeroFailsAtStepThree() public {
        _expectExecRevert(_tr(alice, address(0), 1, 0, 1, RR), abi.encodeWithSelector(IERC20MetaTx.PayToZero.selector));
        assertEq(t.mtxNonce(alice, 1), 0);
    }

    /// Review L1: STATICCALL tới một selector lạ (ví dụ `nonces(address)` của ai đó dò EIP-2612) revert rẻ, không
    /// đốt hết gas vì TSTORE của guard trong frame tĩnh.
    function test_unknownSelectorStaticcallRevertsCheaply() public view {
        uint256 g0 = gasleft();
        (bool ok,) = address(t).staticcall{gas: 200_000}(abi.encodeWithSignature("nonces(address)", alice));
        assertFalse(ok);
        assertLt(g0 - gasleft(), 20_000);
    }

    // ------------------------------------------------------------------ phí, R132

    function test_percentFeeOnValueChargedOnTop() public {
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 100e6, 0, 1, RR | RF | PCT);
        x.fee = 5_000; // 0,5 %
        x.feeRecipient = feeTaker;
        _exec(x);
        assertEq(t.balanceOf(shop), 100e6);
        assertEq(t.balanceOf(feeTaker), 0.5e6);
        assertEq(t.balanceOf(alice), 1_000e6 - 100.5e6);
    }

    function test_feeCapOnePercentBothModes() public {
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 100e6, 0, 1, PCT);
        x.fee = 10_001;
        _expectExecRevert(x, abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 10_001, 10_000));
        x.mode = FIX;
        x.fee = 1e6 + 1;
        _expectExecRevert(x, abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 1e6 + 1, 1e6));
        x.fee = 1e6;
        _exec(x);
        assertEq(t.balanceOf(relayer), 1e6);
    }

    function test_feeNeverGoesToThePayee() public {
        bytes memory err = abi.encodeWithSelector(IERC20MetaTx.FeeRecipientIsPayee.selector);
        // bound recipient == to, transfer
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 100e6, 0, 1, RR | RF | PCT);
        x.fee = 1_000;
        x.feeRecipient = shop;
        _expectExecRevert(x, err);
        // payment (entryRef)
        x.entryRef = bytes32(uint256(9));
        _expectExecRevert(x, err);
        // relayer-default: the payee self-relays with a fee
        x = _tr(alice, relayer, 100e6, 0, 1, RR | PCT);
        x.fee = 1_000;
        _expectExecRevert(x, err);
        // unbound feeRecipient raw == to (relayer-filled, flag off) resolves to it as in v1
        x = _tr(alice, shop, 100e6, 0, 1, PCT);
        x.fee = 1_000;
        x.feeRecipient = shop;
        _expectExecRevert(x, err);
        // a fee that computes to 0 never trips it
        x.value = 999;
        _exec(x);
        // payWithFee
        vm.prank(alice);
        vm.expectRevert(err);
        t.payWithFee(shop, 100e6, FeeMode.PERCENT, 1_000, shop, bytes32(0));
    }

    function testFuzz_feeConservesSupply(uint96 value, uint16 feePpm) public {
        uint256 v = bound(value, 0, 900e6);
        uint256 f = bound(feePpm, 0, 10_000);
        uint256 supply = t.totalSupply();
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, v, bytes32(uint256(1)), 1, RR | RF | PCT);
        x.fee = f;
        x.feeRecipient = feeTaker;
        _exec(x);
        assertEq(t.totalSupply(), supply);
        assertEq(t.balanceOf(alice) + t.balanceOf(shop) + t.balanceOf(feeTaker), supply);
        assertEq(t.balanceOf(feeTaker), v * f / 1e6);
    }

    // ------------------------------------------------------------------ hàm có tên (§7)

    /// The named builders consume the signature of `mtxExecuteTransfer` on the struct they build: checked through
    /// the event (same digest) and the lane.
    function testFuzz_namedDigestEqualsGeneric(
        uint8 which, uint256 amount, uint256 batch, uint64 ttl, bool restrict, uint16 feePpm, bytes32 payId
    ) public {
        which = uint8(bound(which, 0, 3));
        amount = bound(amount, 0, 900e6);
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, amount, 0, batch, restrict ? RR : 0);
        x.validUntil = block.timestamp + ttl;
        if (which == 1 || which == 2) {
            x.mode |= RF | PCT;
            x.fee = bound(feePpm, 0, 10_000);
            x.feeRecipient = feeTaker;
        }
        if (which == 2) x.entryRef = payId;
        if (which == 3) {
            x.entryRef = payId;
            x.batch = t.payLane(payId);
        }
        bytes32 d = t.mtxTransferDigest(x);
        bytes memory s = _signTr(PK, address(t), x);
        vm.expectEmit(address(t));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, x.batch, 0, d,
            x.feeRecipient == address(0) ? relayer : x.feeRecipient, x.value * x.fee / 1e6);
        vm.prank(relayer);
        if (which == 0) t.mtxTransfer(alice, shop, amount, x.batch, 0, x.validUntil, x.mode, relayer, s);
        else if (which == 1) {
            t.mtxTransferWithFee(alice, shop, amount, x.batch, 0, x.validUntil, x.mode, relayer, x.fee, feeTaker, s);
        } else if (which == 2) t.mtxExecuteTransfer(x, s);
        else t.mtxPay(alice, shop, amount, payId, x.validUntil, x.mode, relayer, 0, address(0), s);
        assertEq(t.mtxNonce(alice, x.batch), 1);
    }

    function test_oneSignatureOneLaneAcrossPaths() public {
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 1e6, 0, 3, RR);
        bytes memory s = _signTr(PK, address(t), x);
        vm.prank(relayer);
        t.mtxTransfer(alice, shop, 1e6, 3, 0, x.validUntil, RR, relayer, s);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        t.mtxExecuteTransfer(x, s);
        // the other way round
        x.batch = 4;
        s = _signTr(PK, address(t), x);
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, s);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        t.mtxTransfer(alice, shop, 1e6, 4, 0, x.validUntil, RR, relayer, s);
    }

    function test_everyModeShapeCase() public {
        uint256 vu = block.timestamp + 1;
        bytes4 e = MetaTokenBase.MtxModeShape.selector;
        uint32[3] memory badPlain = [RR | PCT, RF, RR | FIX];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(abi.encodeWithSelector(e, badPlain[i]));
            t.mtxTransfer(alice, shop, 1, 1, 0, vu, badPlain[i], relayer, "");
        }
        uint32[3] memory badFee = [RR | RF, PCT, uint32(0x30) | RF];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(abi.encodeWithSelector(e, badFee[i]));
            t.mtxTransferWithFee(alice, shop, 1, 1, 0, vu, badFee[i], relayer, 1, feeTaker, "");
        }
        vm.expectRevert(abi.encodeWithSelector(e, RF | PCT));
        t.mtxTransferWithFee(alice, shop, 1, 1, 0, vu, RF | PCT, relayer, 1, address(0), "");
        MetaTxLib.MetaTransaction memory m = _call(alice, abi.encodeCall(t.cancelNonce, (1)), 1, RR | RF);
        vm.expectRevert(abi.encodeWithSelector(e, RR | RF));
        t.mtxExecuteWithFee(m, "");
        // with a fee nibble it runs: `cancelNonce` is ABSOLUTE, the signed fee is charged after the call
        m = _call(alice, abi.encodeCall(t.cancelNonce, (1)), 2, RR | RF | FIX);
        m.fee = 3;
        m.feeRecipient = feeTaker;
        bytes memory s = _signCall(PK, address(t), m);
        vm.prank(relayer);
        t.mtxExecuteWithFee(m, s);
        assertEq(t.mtxNonce(alice, 1), 1);
        assertEq(t.balanceOf(feeTaker), 3);
    }

    /// L5: `fee` không bị canonical-zero hoá dưới `NONE`. Đường chung nhận; `mtxTransfer` đặt `fee = 0` nên
    /// chữ ký không khớp.
    function test_leftoverFeeUnderNoneFailsTheNamedPath() public {
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 1e6, 0, 1, RR);
        x.fee = 5;
        bytes memory s = _signTr(PK, address(t), x);
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxTransfer(alice, shop, 1e6, 1, 0, x.validUntil, RR, relayer, s);
        vm.prank(relayer);
        t.mtxExecuteTransfer(x, s);
        assertEq(t.balanceOf(shop), 1e6);
    }

    function test_mtxPayDerivesTheLaneAndPaysOnce() public {
        bytes32 p = keccak256("invoice-1");
        assertEq(t.payLane(p), uint256(keccak256(abi.encodePacked("scaas.pay.lane", p))));
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 25e6, p, t.payLane(p), RR);
        bytes memory s = _signTr(PK, address(t), x);
        vm.expectEmit(address(t));
        emit IERC20Payment.PaymentSettled(alice, shop, 25e6, 0, relayer, p);
        vm.prank(relayer);
        t.mtxPay(alice, shop, 25e6, p, x.validUntil, RR, relayer, 0, address(0), s);
        assertEq(t.mtxNonce(alice, t.payLane(p)), 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        t.mtxPay(alice, shop, 25e6, p, x.validUntil, RR, relayer, 0, address(0), s);
    }

    /// R139 (review M2): "một lần" là theo ĐƯỜNG `mtxPay`. Cùng `entryRef` qua `payWithFee` vẫn phát event —
    /// reconciler coi lần hai là ngoại lệ, không phải khoản thứ hai.
    function test_payWithFeeSameEntryRefStillSettles() public {
        bytes32 p = keccak256("invoice-1");
        MetaTxLib.MetaTransfer memory x = _tr(alice, shop, 1e6, p, t.payLane(p), RR);
        bytes memory s = _signTr(PK, address(t), x);
        vm.prank(relayer);
        t.mtxPay(alice, shop, 1e6, p, x.validUntil, RR, relayer, 0, address(0), s);
        vm.expectEmit(address(t));
        emit IERC20Payment.PaymentSettled(alice, shop, 1e6, 0, address(0), p);
        vm.prank(alice);
        t.payWithFee(shop, 1e6, FeeMode.NONE, 0, address(0), p);
    }

    function _batchItems(uint256 n) internal view returns (MetaTxLib.MetaTransfer[] memory xs, bytes[] memory ss) {
        xs = new MetaTxLib.MetaTransfer[](n);
        ss = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            xs[i] = _tr(alice, shop, 1e6, bytes32(i), 100 + i, RR);
            ss[i] = _signTr(PK, address(t), xs[i]);
        }
    }

    function test_mtxBatchRunsEveryItem() public {
        (MetaTxLib.MetaTransfer[] memory xs, bytes[] memory ss) = _batchItems(3);
        vm.prank(relayer);
        t.mtxBatchTransfer(xs, ss);
        assertEq(t.balanceOf(shop), 3e6);
    }

    function test_mtxBatchIsAtomic() public {
        (MetaTxLib.MetaTransfer[] memory xs, bytes[] memory ss) = _batchItems(3);
        ss[2] = ss[0];
        vm.prank(relayer);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        t.mtxBatchTransfer(xs, ss);
        assertEq(t.balanceOf(shop), 0);
        assertEq(t.mtxNonce(alice, 100), 0);
    }

    function test_mtxBatchShape() public {
        (MetaTxLib.MetaTransfer[] memory xs, bytes[] memory ss) = _batchItems(2);
        vm.expectRevert(IMetaTx.MtxBatchLengthMismatch.selector);
        t.mtxBatchTransfer(xs, new bytes[](1));
        vm.expectRevert(IMetaTx.MtxBatchEmpty.selector);
        t.mtxBatchTransfer(new MetaTxLib.MetaTransfer[](0), ss);
    }
}
