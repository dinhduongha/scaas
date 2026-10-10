// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {V2Fixture, BaseHarness, GasBurner1271} from "./helpers/V2Fixture.sol";
import {Puller} from "../helpers/WalletMocks.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {MetaTxCore} from "../../src/metatx/MetaTxCore.sol";
import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
import {IERC20PaymentV1} from "../../src/metatx/IERC20PaymentV1.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../../src/common/FeePolicy.sol";

/// T1: `MetaTxCore` + `MetaTokenBase` (TW2 §3, §7) trên một tầng giả tối thiểu.
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

    function _exec(MetaTxLib.LegacyMetaTransaction memory m) internal {
        bytes memory s = _sig(PK, address(t), m);
        vm.prank(relayer);
        t.executeMetaTransaction(m, s);
    }

    function _expectExecRevert(MetaTxLib.LegacyMetaTransaction memory m, bytes memory err) internal {
        bytes memory s = _sig(PK, address(t), m);
        vm.prank(relayer);
        vm.expectRevert(err);
        t.executeMetaTransaction(m, s);
    }

    // ------------------------------------------------------------------ domain, init

    function test_domainIsV2AndTheClone() public view {
        (, string memory n, string memory v, uint256 cid, address vc,,) = t.eip712Domain();
        assertEq(n, "SCaaS MetaToken");
        assertEq(v, "2");
        assertEq(cid, block.chainid);
        assertEq(vc, address(t));
        assertEq(t.name(), "Harness");
        assertEq(t.decimals(), 6);
        assertEq(t.creator(), address(this));
        assertEq(t.version(), 1);
    }

    function test_implementationIsLockedAndCloneInitializesOnce() public {
        address impl = t.implementation();
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        MetaTokenBase(impl).initialize(address(this), new address[](0), 1, "");
        vm.expectRevert(MetaTokenBase.AlreadyInitialized.selector);
        t.initialize(address(this), new address[](0), 1, "");
        address c = Clones.clone(impl);
        vm.prank(address(0xBAD));
        vm.expectRevert(MetaTokenBase.NotFactory.selector);
        MetaTokenBase(c).initialize(address(0xBAD), new address[](0), 1, "");
    }

    // ------------------------------------------------------------------ pipeline

    function test_transferThroughTheGenericPath() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 100e6, "", 7, RR);
        bytes32 d = t.metaTxDigest(m);
        vm.expectEmit(address(t));
        emit IERC20MetaTxV1.MetaTransactionExecuted(alice, relayer, 7, 0, d, relayer, 0);
        _exec(m);
        assertEq(t.balanceOf(shop), 100e6);
        assertEq(t.metaNonce(alice, 7), 1);
        _expectExecRevert(m, abi.encodeWithSelector(IERC20MetaTxV1.MetaTxBadNonce.selector, 1, 0));
    }

    function test_cancelMetaNonceEmits() public {
        vm.expectEmit(address(t));
        emit MetaTxCore.MetaNonceCancelled(alice, 5, 1);
        vm.prank(alice);
        t.cancelMetaNonce(5);
        vm.expectEmit(address(t));
        emit MetaTxCore.MetaNonceCancelled(alice, 5, 2);
        vm.prank(alice);
        t.cancelMetaNonce(5);
        assertEq(t.metaNonce(alice, 5), 2);
    }

    // ------------------------------------------------------------------ R26

    function test_allowanceOnlyBetweenContracts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.SpenderNotContract.selector, shop));
        t.approve(shop, 1);
        Puller p = new Puller();
        vm.prank(alice);
        t.approve(address(p), 5);
        p.pull(address(t), alice, shop, 5);
        assertEq(t.balanceOf(shop), 5);
        vm.prank(shop);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.CallerNotContract.selector, shop));
        t.transferFrom(alice, shop, 0);
        // approve op: spender EOA refused at step 6
        bytes memory a = abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), shop, 1);
        _expectExecRevert(_mt(alice, shop, 0, a, 1, RR),
            abi.encodeWithSelector(IERC20MetaTxV1.SpenderNotContract.selector, shop));
    }

    function test_approveOpSetsAllowance() public {
        Puller p = new Puller();
        bytes memory a = abi.encodeWithSelector(bytes4(keccak256("approve(address,uint256)")), address(p), 77);
        _exec(_mt(alice, address(p), 0, a, 1, RR));
        assertEq(t.allowance(alice, address(p)), 77);
    }

    function test_erc1271Gets400kOnlyAsSubjectAccountClone() public {
        GasBurner1271 burner = new GasBurner1271();
        BaseHarness impl = new BaseHarness(address(this), address(burner));
        BaseHarness tk = BaseHarness(_clone(address(impl), address(this), new address[](0),
            abi.encode("H", "H", uint8(0), uint256(0))));
        address clone = Clones.clone(address(burner));
        tk.mint(clone, 10);
        tk.mint(address(burner), 10);
        MetaTxLib.LegacyMetaTransaction memory m = _mt(clone, shop, 1, "", 1, RR);
        vm.prank(relayer);
        tk.executeMetaTransaction(m, hex"00");
        assertEq(tk.balanceOf(shop), 1);
        m.from = address(burner);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        tk.executeMetaTransaction(m, hex"00");
    }

    /// L6: một op có đúng một encoding. Bit cao bẩn trong word địa chỉ ⇒ op lạ, không phải địa chỉ cắt ngắn.
    function test_dirtyAddressWordIsUnknownOp() public {
        Puller p = new Puller();
        bytes4 ap = bytes4(keccak256("approve(address,uint256)"));
        bytes memory a = abi.encodePacked(ap, uint256(uint160(address(p))) | (uint256(1) << 200), uint256(1));
        _expectExecRevert(_mt(alice, address(p), 0, a, 1, RR),
            abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, ap));
        bytes4 tr = bytes4(keccak256("trade(address,uint256,address)"));
        bytes memory d = abi.encodePacked(tr, uint256(1) << 255, uint256(1), uint256(0));
        _expectExecRevert(_mt(alice, relayer, 1, d, 1, RR),
            abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, tr));
        d = abi.encodePacked(tr, uint256(0), uint256(1), uint256(1) << 160);
        _expectExecRevert(_mt(alice, relayer, 1, d, 1, RR),
            abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, tr));
    }

    function test_unknownAndShortOps() public {
        _expectExecRevert(_mt(alice, shop, 1, hex"0102", 1, RR),
            abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, bytes4(0)));
        _expectExecRevert(_mt(alice, shop, 1, hex"deadbeef", 1, RR),
            abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, bytes4(0xdeadbeef)));
        _expectExecRevert(_mt(alice, address(0), 1, _payData(bytes32(uint256(1))), 1, RR),
            abi.encodeWithSelector(MetaTokenBase.PayToZero.selector));
        bytes memory longPay = abi.encodePacked(_payData(bytes32(uint256(1))), uint8(0));
        _expectExecRevert(_mt(alice, shop, 1, longPay, 1, RR),
            abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, bytes4(keccak256("pay(bytes32)"))));
    }

    /// Review L2: transfer tới 0 fail ở bước 6 (như v1 fail ở bước 8, cùng lỗi), không bao giờ sau khi thu phí.
    function test_transferToZeroFailsAtStepSix() public {
        _expectExecRevert(_mt(alice, address(0), 1, "", 1, RR),
            abi.encodeWithSignature("ERC20InvalidReceiver(address)", address(0)));
    }

    /// Review L1: STATICCALL tới một selector lạ (ví dụ `nonces(address)` của ai đó dò EIP-2612) revert rẻ, không
    /// đốt hết gas vì TSTORE của guard trong frame tĩnh.
    function test_unknownSelectorStaticcallRevertsCheaply() public view {
        uint256 g0 = gasleft();
        (bool ok,) = address(t).staticcall{gas: 200_000}(abi.encodeWithSignature("nonces(address)", alice));
        assertFalse(ok);
        assertLt(g0 - gasleft(), 20_000);
    }

    function test_tradeLegNeedsRestrictedRelayerAndGoesToIt() public {
        bytes memory d = abi.encodeWithSelector(bytes4(keccak256("trade(address,uint256,address)")),
            address(1), uint256(1), address(0));
        _expectExecRevert(_mt(alice, relayer, 5, d, 1, 0), abi.encodeWithSelector(MetaTokenBase.TradeLegNotRestricted.selector));
        _expectExecRevert(_mt(alice, shop, 5, d, 1, RR), abi.encodeWithSelector(MetaTokenBase.TradeLegNotRestricted.selector));
        _exec(_mt(alice, relayer, 5, d, 1, RR));
        assertEq(t.balanceOf(relayer), 5);
    }

    /// Op unwrap không tồn tại trên tầng không có underlying.
    function test_unwrapOpIsUnknownWithoutUnderlying() public {
        bytes4 op = bytes4(keccak256("unwrap(address,address,uint256)"));
        _expectExecRevert(_mt(alice, shop, 1, _unwrapData(address(1), shop, 0), 1, RR),
            abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, op));
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1, _unwrapData(address(1), shop, 0), 1, RR);
        bytes memory s = _sig(PK, address(t), m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, op));
        t.mtxUnwrap(alice, address(1), 1, shop, 0, 1, 0, m.validUntil, RR, relayer, s);
    }

    // ------------------------------------------------------------------ phí, R132

    function test_percentFeeOnValueChargedOnTop() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 100e6, "", 1, RR | RF | PCT);
        m.fee = 5_000; // 0,5 %
        m.feeRecipient = feeTaker;
        _exec(m);
        assertEq(t.balanceOf(shop), 100e6);
        assertEq(t.balanceOf(feeTaker), 0.5e6);
        assertEq(t.balanceOf(alice), 1_000e6 - 100.5e6);
    }

    function test_feeCapOnePercentBothModes() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 100e6, "", 1, PCT);
        m.fee = 10_001;
        _expectExecRevert(m, abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 10_001, 10_000));
        m.mode = FIX;
        m.fee = 1e6 + 1;
        _expectExecRevert(m, abi.encodeWithSelector(FeePolicy.FeeExceedsCap.selector, 1e6 + 1, 1e6));
        m.fee = 1e6;
        _exec(m);
        assertEq(t.balanceOf(relayer), 1e6);
    }

    function test_feeNeverGoesToThePayee() public {
        bytes memory err = abi.encodeWithSelector(MetaTxCore.FeeRecipientIsPayee.selector);
        // bound recipient == to, transfer
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 100e6, "", 1, RR | RF | PCT);
        m.fee = 1_000;
        m.feeRecipient = shop;
        _expectExecRevert(m, err);
        // pay op
        m.data = _payData(bytes32(uint256(9)));
        _expectExecRevert(m, err);
        // relayer-default: the payee self-relays with a fee
        m = _mt(alice, relayer, 100e6, "", 1, RR | PCT);
        m.fee = 1_000;
        _expectExecRevert(m, err);
        // unbound feeRecipient raw == to (relayer-filled, flag off) resolves to it as in v1
        m = _mt(alice, shop, 100e6, "", 1, PCT);
        m.fee = 1_000;
        m.feeRecipient = shop;
        _expectExecRevert(m, err);
        // a fee that computes to 0 never trips it
        m.value = 999;
        _exec(m);
        // payWithFee
        vm.prank(alice);
        vm.expectRevert(err);
        t.payWithFee(shop, 100e6, FeeMode.PERCENT, 1_000, shop, bytes32(0));
    }

    /// `trade`: `to` là contract khớp lệnh (relayer); phí cho relayer không phải "phí cho người nhận".
    function test_payeeCheckDoesNotApplyToTrade() public {
        bytes memory d = abi.encodeWithSelector(bytes4(keccak256("trade(address,uint256,address)")),
            address(1), uint256(1), address(0));
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, relayer, 100e6, d, 1, RR | PCT);
        m.fee = 1_000;
        _exec(m);
        assertEq(t.balanceOf(relayer), 100.1e6);
    }

    function testFuzz_feeConservesSupply(uint96 value, uint16 feePpm) public {
        uint256 v = bound(value, 0, 900e6);
        uint256 f = bound(feePpm, 0, 10_000);
        uint256 supply = t.totalSupply();
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, v, _payData(bytes32(uint256(1))), 1, RR | RF | PCT);
        m.fee = f;
        m.feeRecipient = feeTaker;
        _exec(m);
        assertEq(t.totalSupply(), supply);
        assertEq(t.balanceOf(alice) + t.balanceOf(shop) + t.balanceOf(feeTaker), supply);
        assertEq(t.balanceOf(feeTaker), v * f / 1e6);
    }

    // ------------------------------------------------------------------ hàm có tên (§7)

    /// Digest của lời gọi có tên == digest của `executeMetaTransaction` với cùng struct: kiểm qua event, vì
    /// chữ ký ký trên digest generic phải chạy được qua tên.
    function testFuzz_namedDigestEqualsGeneric(
        uint8 which, uint256 amount, uint256 batch, uint64 ttl, bool restrict, uint16 feePpm, bytes32 payId
    ) public {
        which = uint8(bound(which, 0, 3));
        amount = bound(amount, 0, 900e6);
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, amount, "", batch, restrict ? RR : 0);
        m.validUntil = block.timestamp + ttl;
        if (which == 1 || which == 2) {
            m.mode |= RF | PCT;
            m.fee = bound(feePpm, 0, 10_000);
            m.feeRecipient = feeTaker;
        }
        if (which == 2) m.data = _payData(payId);
        if (which == 3) {
            m.data = _payData(payId);
            m.batch = t.payLane(payId);
        }
        bytes32 d = t.metaTxDigest(m);
        bytes memory s = _sig(PK, address(t), m);
        vm.expectEmit(address(t));
        emit IERC20MetaTxV1.MetaTransactionExecuted(alice, relayer, m.batch, 0, d,
            m.feeRecipient == address(0) ? relayer : m.feeRecipient, m.value * m.fee / 1e6);
        vm.prank(relayer);
        if (which == 0) t.mtxTransfer(alice, shop, amount, m.batch, 0, m.validUntil, m.mode, relayer, s);
        else if (which == 1) {
            t.mtxTransferWithFee(alice, shop, amount, m.batch, 0, m.validUntil, m.mode, relayer, m.fee, feeTaker, s);
        } else if (which == 2) t.executeMetaTransactionWithFee(m, s);
        else t.mtxPay(alice, shop, amount, payId, m.validUntil, m.mode, relayer, 0, address(0), s);
        assertEq(t.metaNonce(alice, m.batch), 1);
    }

    function test_oneSignatureOneLaneAcrossPaths() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1e6, "", 3, RR);
        bytes memory s = _sig(PK, address(t), m);
        vm.prank(relayer);
        t.mtxTransfer(alice, shop, 1e6, 3, 0, m.validUntil, RR, relayer, s);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxBadNonce.selector, 1, 0));
        t.executeMetaTransaction(m, s);
        // the other way round
        m.batch = 4;
        s = _sig(PK, address(t), m);
        vm.prank(relayer);
        t.executeMetaTransaction(m, s);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxBadNonce.selector, 1, 0));
        t.mtxTransfer(alice, shop, 1e6, 4, 0, m.validUntil, RR, relayer, s);
    }

    function test_everyModeShapeCase() public {
        uint256 vu = block.timestamp + 1;
        bytes4 e = MetaTokenBase.MtxModeShape.selector;
        uint32[3] memory badPlain = [RR | PCT, RF, RR | FIX];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(abi.encodeWithSelector(e, badPlain[i]));
            t.mtxTransfer(alice, shop, 1, 1, 0, vu, badPlain[i], relayer, "");
            vm.expectRevert(abi.encodeWithSelector(e, badPlain[i]));
            t.mtxUnwrap(alice, address(1), 1, shop, 0, 1, 0, vu, badPlain[i], relayer, "");
        }
        uint32[3] memory badFee = [RR | RF, PCT, uint32(0x30) | RF];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(abi.encodeWithSelector(e, badFee[i]));
            t.mtxTransferWithFee(alice, shop, 1, 1, 0, vu, badFee[i], relayer, 1, feeTaker, "");
            MetaTxLib.LegacyMetaTransaction memory u = _mt(alice, shop, 1, "", 1, badFee[i]);
            u.fee = 1;
            u.feeRecipient = feeTaker;
            vm.expectRevert(abi.encodeWithSelector(e, badFee[i]));
            _mtxUnwrapWithFee(address(t), u, address(1), 0, "");
        }
        vm.expectRevert(abi.encodeWithSelector(e, RF | PCT));
        t.mtxTransferWithFee(alice, shop, 1, 1, 0, vu, RF | PCT, relayer, 1, address(0), "");
        MetaTxLib.LegacyMetaTransaction memory u0 = _mt(alice, shop, 1, "", 1, RF | FIX);
        u0.fee = 1;
        vm.expectRevert(abi.encodeWithSelector(e, RF | FIX));
        _mtxUnwrapWithFee(address(t), u0, address(1), 0, "");
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1, "", 1, RR | RF);
        vm.expectRevert(abi.encodeWithSelector(e, RR | RF));
        t.executeMetaTransactionWithFee(m, "");
    }

    /// L5: `fee` không bị canonical-zero hoá dưới `NONE`. Đường chung nhận; `mtxTransfer` đặt `fee = 0` nên
    /// chữ ký không khớp.
    function test_leftoverFeeUnderNoneFailsTheNamedPath() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1e6, "", 1, RR);
        m.fee = 5;
        bytes memory s = _sig(PK, address(t), m);
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        t.mtxTransfer(alice, shop, 1e6, 1, 0, m.validUntil, RR, relayer, s);
        vm.prank(relayer);
        t.executeMetaTransaction(m, s);
        assertEq(t.balanceOf(shop), 1e6);
    }

    function test_mtxPayDerivesTheLaneAndPaysOnce() public {
        bytes32 p = keccak256("invoice-1");
        assertEq(t.payLane(p), uint256(keccak256(abi.encodePacked("scaas.pay.lane", p))));
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 25e6, _payData(p), t.payLane(p), RR);
        bytes memory s = _sig(PK, address(t), m);
        vm.expectEmit(address(t));
        emit IERC20PaymentV1.PaymentSettled(alice, shop, 25e6, 0, relayer, p);
        vm.prank(relayer);
        t.mtxPay(alice, shop, 25e6, p, m.validUntil, RR, relayer, 0, address(0), s);
        assertEq(t.metaNonce(alice, t.payLane(p)), 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxBadNonce.selector, 1, 0));
        t.mtxPay(alice, shop, 25e6, p, m.validUntil, RR, relayer, 0, address(0), s);
    }

    /// R139 (review M2): "một lần" là theo ĐƯỜNG `mtxPay`. Cùng `entryRef` qua `payWithFee` vẫn phát event —
    /// reconciler coi lần hai là ngoại lệ, không phải khoản thứ hai.
    function test_payWithFeeSameEntryRefStillSettles() public {
        bytes32 p = keccak256("invoice-1");
        MetaTxLib.LegacyMetaTransaction memory m = _mt(alice, shop, 1e6, _payData(p), t.payLane(p), RR);
        bytes memory s = _sig(PK, address(t), m);
        vm.prank(relayer);
        t.mtxPay(alice, shop, 1e6, p, m.validUntil, RR, relayer, 0, address(0), s);
        vm.expectEmit(address(t));
        emit IERC20PaymentV1.PaymentSettled(alice, shop, 1e6, 0, address(0), p);
        vm.prank(alice);
        t.payWithFee(shop, 1e6, FeeMode.NONE, 0, address(0), p);
    }

    function _batchItems(uint256 n) internal view returns (MetaTxLib.LegacyMetaTransaction[] memory ms, bytes[] memory ss) {
        ms = new MetaTxLib.LegacyMetaTransaction[](n);
        ss = new bytes[](n);
        for (uint256 i; i < n; ++i) {
            ms[i] = _mt(alice, shop, 1e6, _payData(bytes32(i)), 100 + i, RR);
            ss[i] = _sig(PK, address(t), ms[i]);
        }
    }

    function test_mtxBatchRunsEveryItem() public {
        (MetaTxLib.LegacyMetaTransaction[] memory ms, bytes[] memory ss) = _batchItems(3);
        vm.prank(relayer);
        t.mtxBatch(ms, ss);
        assertEq(t.balanceOf(shop), 3e6);
    }

    function test_mtxBatchIsAtomic() public {
        (MetaTxLib.LegacyMetaTransaction[] memory ms, bytes[] memory ss) = _batchItems(3);
        ss[2] = ss[0];
        vm.prank(relayer);
        vm.expectRevert(IERC20MetaTxV1.MetaTxBadSignature.selector);
        t.mtxBatch(ms, ss);
        assertEq(t.balanceOf(shop), 0);
        assertEq(t.metaNonce(alice, 100), 0);
    }

    function test_mtxBatchShape() public {
        (MetaTxLib.LegacyMetaTransaction[] memory ms, bytes[] memory ss) = _batchItems(2);
        vm.expectRevert(MetaTokenBase.MtxBatchLengthMismatch.selector);
        t.mtxBatch(ms, new bytes[](1));
        vm.expectRevert(MetaTokenBase.MtxBatchEmpty.selector);
        t.mtxBatch(new MetaTxLib.LegacyMetaTransaction[](0), ss);
    }
}
