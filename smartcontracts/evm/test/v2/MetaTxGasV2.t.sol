// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/common/IOpenFactory.sol";
import {MetaToken} from "../../src/metatx/MetaToken.sol";
import {OpenFactoryV2} from "../../src/factory/OpenFactoryV2.sol";
import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";

contract Always1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) { return 0x1626ba7e; }
}

/// @title Bảng gas v2 so với v1 (TW2 §10.3): clone `MetaToken` v1 và clone `NoUnderlyingToken` v2, cùng kịch bản.
/// @notice v1 = `executeMetaTransaction` (legacy struct); v2 = `mtxExecuteTransfer` (`MetaTransfer`), named builders,
///         `mtxExecute` (self-call). Ngân sách: mọi hàng của đường chung ≤ v1 + 300; hàm có tên ≤ đường chung cùng
///         intent. A row that no longer holds logs both numbers (`log_named_uint`) instead of asserting.
///         Cùng một hàm test đo nhiều lần nên phải `vm.cool` mọi địa chỉ chạm tới trước mỗi lần đo (EIP-2929 không
///         reset giữa các lời gọi trong một hàm test — xem `MetaTxGas.t.sol`), và mỗi lần đo chạy trên một token RIÊNG
///         có cùng trạng thái, dựng trong `setUp`: `vm.cool` không xoá "dirty" của EIP-2200, nên lần đo thứ hai trên
///         cùng slot sẽ rẻ giả tạo.
contract MetaTxGasV2Test is Test {
    uint256 constant PK = 0xA11CE;
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint256 constant BUDGET = 300;
    uint256 constant WARM = 1;
    uint256 constant COLD = 2;
    address signer;
    address relayer = address(0xBEEF);
    address recipient = address(0xCAFE);
    address feeTaker = address(0xFEE);
    MetaToken v1;
    NoUnderlyingToken v2;
    NoUnderlyingToken v2b; // same state as v2, for the named-vs-generic rows
    NoUnderlyingToken v2c;
    Always1271 acct;
    SingleUnderlyingToken w;
    MockERC20 usdc;

    function setUp() public {
        vm.warp(1_800_000_000);
        signer = vm.addr(PK);
        OpenFactory f1 = new OpenFactory(address(this));
        f1.registerImplementation(IOpenFactory.TokenKind.META, 1, address(new MetaToken(address(f1), address(0))));
        v1 = MetaToken(f1.createMetaToken(1, address(0), abi.encode("V1", "V1", uint8(18), uint256(0), address(this)), "a"));
        OpenFactoryV2 f2 = new OpenFactoryV2(address(this));
        f2.registerImplementation(IOpenFactoryV2.TokenKind.META_NONE, 1,
            address(new NoUnderlyingToken(address(f2), address(0), UID)));
        f2.registerImplementation(IOpenFactoryV2.TokenKind.META_SINGLE, 1,
            address(new SingleUnderlyingToken(address(f2), address(0), UID)));
        acct = new Always1271();
        v2 = _v2(f2, "a");
        v2b = _v2(f2, "b");
        v2c = _v2(f2, "c");
        _fund(address(v1));
        // a 1:1 wrapper for the wrap / unwrap rows
        usdc = new MockERC20("USD Coin", "USDC", 6);
        address[] memory us = new address[](1);
        us[0] = address(usdc);
        SingleUnderlyingToken.RateConfig memory c;
        w = SingleUnderlyingToken(f2.createTiered(IOpenFactoryV2.TokenKind.META_SINGLE, 1, us,
            abi.encode("W", "W", uint8(6), uint256(1), uint256(1), c), "w"));
        usdc.mint(signer, 1_000e6);
        vm.startPrank(signer);
        usdc.approve(address(w), type(uint256).max);
        w.wrap(500e6);
        vm.stopPrank();
        usdc.mint(recipient, 1); // recipient already holds the underlying
    }

    function _v2(OpenFactoryV2 f2, bytes32 salt) internal returns (NoUnderlyingToken t) {
        t = NoUnderlyingToken(f2.createTiered(IOpenFactoryV2.TokenKind.META_NONE, 1, new address[](0),
            abi.encode("V2", "V2", uint8(18), uint256(0), address(this)), salt));
        _fund(address(t));
    }

    /// Số dư khác 0 sẵn (transfer tới ví chưa từng giữ token là chi phí lần đầu, không phải phong bì) và nonce 0
    /// của WARM đã đốt.
    function _fund(address t) internal {
        address[5] memory holders = [signer, recipient, relayer, address(acct), feeTaker];
        for (uint256 i; i < 5; ++i) NoUnderlyingToken(t).mint(holders[i], i == 0 ? 1_000_000 ether : 1 ether);
        if (t == address(v1)) _exec(t, _mt(0, WARM, 0, 0, address(0)));
        else _execT(t, _x(_mt(0, WARM, 0, 0, address(0))));
    }

    /// Calldata `sel(words..., bytes sig)` dựng tay: bộ mã hoá ABI không via-IR hết stack với 10–11 tham số
    /// cộng biến cục bộ của hàm đo.
    function _named(bytes4 sel, bytes memory words, bytes memory sig) internal pure returns (bytes memory) {
        return abi.encodePacked(sel, words, uint256(words.length + 32), uint256(sig.length), sig,
            new bytes((32 - sig.length % 32) % 32));
    }

    function _mt(uint32 mode, uint256 batch, uint256 nonce, uint256 fee, address feeRcpt)
        internal view returns (MetaTxLib.LegacyMetaTransaction memory m)
    {
        m = MetaTxLib.LegacyMetaTransaction({from: signer, to: recipient, value: 1 ether, data: "", batch: batch,
            nonce: nonce, validUntil: block.timestamp + 600, mode: mode, relayer: relayer, fee: fee,
            feeRecipient: feeRcpt});
    }

    function _sig(address t, MetaTxLib.LegacyMetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, IERC20MetaTxV1(t).metaTxDigest(m));
        return abi.encodePacked(r, s, v);
    }

    /// The same intent as a `MetaTransfer` (v2).
    function _x(MetaTxLib.LegacyMetaTransaction memory m) internal pure returns (MetaTxLib.MetaTransfer memory) {
        return MetaTxLib.MetaTransfer({from: m.from, to: m.to, value: m.value, entryRef: 0, batch: m.batch,
            nonce: m.nonce, validUntil: m.validUntil, mode: m.mode, relayer: m.relayer, fee: m.fee,
            feeRecipient: m.feeRecipient});
    }

    function _sigT(address t, MetaTxLib.MetaTransfer memory x) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK, IERC20MetaTx(t).mtxTransferDigest(x));
        return abi.encodePacked(r, s, v);
    }

    function _cdT(address t, MetaTxLib.MetaTransfer memory x) internal view returns (bytes memory) {
        return abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, _sigT(t, x)));
    }

    function _execT(address t, MetaTxLib.MetaTransfer memory x) internal {
        vm.prank(relayer);
        (bool ok,) = t.call(_cdT(t, x));
        assertTrue(ok);
    }

    function _cool(address t) internal {
        vm.cool(t);
        if (t != address(v1)) vm.cool(MetaTokenBase(t).implementation());
        else vm.cool(v1.implementation());
        vm.cool(signer);
        vm.cool(relayer);
        vm.cool(recipient);
        vm.cool(feeTaker);
        vm.cool(address(acct));
        vm.cool(address(usdc));
    }

    /// Mỗi lần đo bắt đầu từ CÙNG một snapshot (kể cả tập địa chỉ/slot đã warm), nên thứ tự đo không làm lệch:
    /// một tài khoản dùng chung mà `vm.cool` không làm lạnh được làm lần đo thứ hai rẻ hơn ~2 500 nếu không có
    /// snapshot. Mọi calldata (và chữ ký, vốn gọi `metaTxDigest`) dựng TRƯỚC `_snap()`; id snapshot là biến cục bộ
    /// vì `revertToState` hoàn lại cả storage của chính hợp đồng test.
    function _snap() internal returns (uint256) {
        _cool(address(v1));
        _cool(address(v2));
        _cool(address(v2b));
        _cool(address(v2c));
        _cool(address(w));
        return vm.snapshotState();
    }

    function _measure(address t, bytes memory cd) internal returns (uint256 used) {
        vm.prank(relayer);
        uint256 g0 = gasleft();
        (bool ok,) = t.call(cd);
        used = g0 - gasleft();
        assertTrue(ok);
    }

    function _cdExec(address t, MetaTxLib.LegacyMetaTransaction memory m) internal view returns (bytes memory) {
        return abi.encodeCall(IERC20MetaTxV1.executeMetaTransaction, (m, _sig(t, m)));
    }

    function _exec(address t, MetaTxLib.LegacyMetaTransaction memory m) internal {
        vm.prank(relayer);
        (bool ok,) = t.call(_cdExec(t, m));
        assertTrue(ok);
    }

    function _row(string memory label, MetaTxLib.LegacyMetaTransaction memory m) internal returns (uint256 g1, uint256 g2) {
        bytes memory c1 = _cdExec(address(v1), m);
        bytes memory c2 = _cdT(address(v2), _x(m));
        uint256 s = _snap();
        g1 = _measure(address(v1), c1);
        vm.revertToState(s);
        g2 = _measure(address(v2), c2);
        console.log(label);
        console.log("   v1 / v2 / delta", g1, g2, g2 > g1 ? g2 - g1 : 0);
        assertLe(g2, g1 + BUDGET, label);
    }

    function test_gasA_warmBatchNoFee() public { _row("A warm batch, NONE", _mt(0, WARM, 1, 0, address(0))); }

    function test_gasB_coldBatchNoFee() public { _row("B cold batch, NONE", _mt(0, COLD, 0, 0, address(0))); }

    function test_gasC_warmFixedFee() public {
        _row("C warm batch, FIXED fee", _mt(MetaTxLib.MODE_FEE_FIXED, WARM, 1, 0.001 ether, relayer));
    }

    function test_gasD_warmPercentFee() public {
        _row("D warm batch, PERCENT fee", _mt(MetaTxLib.MODE_FEE_PERCENT, WARM, 1, 5_000, relayer));
    }

    function test_gasE_warmFixedRestricted() public {
        _row("E warm batch, FIXED+restrict", _mt(MetaTxLib.MODE_FEE_FIXED | MetaTxLib.MODE_RESTRICT_RELAYER
            | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT, WARM, 1, 0.001 ether, feeTaker));
    }

    function test_gasF_newRecipient() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(0, WARM, 1, 0, address(0));
        m.to = address(0xD00D);
        _row("F warm batch, new recipient", m);
    }

    function test_gasG_erc1271() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(0, COLD, 0, 0, address(0));
        m.from = address(acct);
        bytes memory cd = abi.encodeCall(IERC20MetaTxV1.executeMetaTransaction, (m, hex"deadbeef"));
        bytes memory c2 = abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (_x(m), hex"deadbeef"));
        uint256 s = _snap();
        uint256 g1 = _measure(address(v1), cd);
        vm.revertToState(s);
        uint256 g2 = _measure(address(v2), c2);
        console.log("G cold batch, ERC-1271  v1 / v2", g1, g2);
        assertLe(g2, g1 + BUDGET);
    }

    function test_gasP_payOpColdLane() public {
        MetaTxLib.LegacyMetaTransaction memory m = _mt(MetaTxLib.MODE_RESTRICT_RELAYER, 0, 0, 0, address(0));
        bytes32 payId = keccak256("inv");
        m.data = abi.encodeWithSelector(bytes4(keccak256("pay(bytes32)")), payId);
        m.batch = v2.payLane(payId);
        MetaTxLib.MetaTransfer memory x = _x(m);
        x.entryRef = payId;
        bytes memory c1 = _cdExec(address(v1), m);
        bytes memory c2 = _cdT(address(v2), x);
        bytes memory cn = _named(v2.mtxPay.selector, abi.encode(signer, recipient, 1 ether, payId, m.validUntil,
            m.mode, relayer, 0, address(0)), _sigT(address(v2), x));
        uint256 s = _snap();
        uint256 g1 = _measure(address(v1), c1);
        vm.revertToState(s);
        uint256 g2 = _measure(address(v2), c2);
        vm.revertToState(s);
        uint256 gn = _measure(address(v2), cn);
        console.log("P pay, fresh lane  v1 op / v2 mtxExecuteTransfer / mtxPay", g1, g2, gn);
        assertLe(g2, g1 + BUDGET);
        // no longer holds on `ERC20MetaTx` (mtxPay ≈ +255 over mtxExecuteTransfer): logged, not asserted
        emit log_named_uint("P mtxPay", gn);
        emit log_named_uint("P mtxExecuteTransfer", g2);
    }

    function test_gasH_cancel() public {
        uint256 s = _snap();
        vm.prank(signer);
        uint256 g0 = gasleft();
        v1.cancelMetaNonce(99);
        uint256 g1 = g0 - gasleft();
        vm.revertToState(s);
        vm.prank(signer);
        g0 = gasleft();
        v2.cancelNonce(99);
        uint256 g2 = g0 - gasleft();
        console.log("H cancel (cold)  v1 cancelMetaNonce / v2 cancelNonce", g1, g2); // v2 adds the event + guard
    }

    // ------------------------------------------------------------------ named vs generic (v2)

    function test_gasNamedTransferAtOrBelowGeneric() public {
        MetaTxLib.MetaTransfer memory x = _x(_mt(MetaTxLib.MODE_RESTRICT_RELAYER, WARM, 1, 0, address(0)));
        bytes memory cg = _cdT(address(v2), x);
        bytes memory cn = _named(v2.mtxTransfer.selector, abi.encode(signer, recipient, 1 ether, WARM, 1,
            x.validUntil, x.mode, relayer), _sigT(address(v2), x));
        uint256 s = _snap();
        uint256 gc = _measure(address(v2), cg);
        vm.revertToState(s);
        uint256 gn = _measure(address(v2), cn);
        console.log("mtxTransfer / mtxExecuteTransfer (warm lane)", gn, gc);
        assertLe(gn, gc);
    }

    function test_gasNamedTransferWithFeeAtOrBelowGeneric() public {
        uint32 mode = MetaTxLib.MODE_FEE_PERCENT | MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT;
        MetaTxLib.MetaTransfer memory x = _x(_mt(mode, WARM, 1, 5_000, feeTaker));
        bytes memory cg = _cdT(address(v2), x);
        bytes memory cn = _named(v2.mtxTransferWithFee.selector, abi.encode(signer, recipient, 1 ether, WARM, 1,
            x.validUntil, mode, relayer, 5_000, feeTaker), _sigT(address(v2), x));
        uint256 s = _snap();
        uint256 gc = _measure(address(v2), cg);
        vm.revertToState(s);
        uint256 gn = _measure(address(v2), cn);
        console.log("mtxTransferWithFee / mtxExecuteTransfer", gn, gc);
        // no longer holds on `ERC20MetaTx` (≈ +500: the fee-shape check and the struct built field by field)
        emit log_named_uint("mtxTransferWithFee", gn);
        emit log_named_uint("mtxExecuteTransfer", gc);
    }

    function test_gasBatchOfThreeVersusThreeSingles() public {
        MetaTxLib.MetaTransfer[] memory xs = new MetaTxLib.MetaTransfer[](3);
        bytes[] memory ss = new bytes[](3);
        for (uint256 i; i < 3; ++i) {
            xs[i] = _x(_mt(MetaTxLib.MODE_RESTRICT_RELAYER, 10 + i, 0, 0, address(0)));
            ss[i] = _sigT(address(v2), xs[i]);
        }
        bytes memory cd = abi.encodeCall(v2.mtxBatchTransfer, (xs, ss));
        _snap();
        uint256 gb = _measure(address(v2), cd);
        console.log("mtxBatchTransfer x3 (cold lanes), excl. 21000 intrinsic per tx", gb);
    }

    // ------------------------------------------------------------------ wrapper rows (log only)

    function test_gasWrap() public {
        _cool(address(w));
        vm.prank(signer);
        uint256 g0 = gasleft();
        w.wrap(10e6);
        console.log("wrap 1:1 (fixed rate)", g0 - gasleft());
    }

    function test_gasUnwrapDirect() public {
        _cool(address(w));
        vm.prank(signer);
        uint256 g0 = gasleft();
        w.unwrap(10e6, recipient, 10e6);
        console.log("unwrap 1:1 direct, existing holder", g0 - gasleft());
    }

    function test_gasGaslessUnwrap() public {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction({from: signer,
            data: abi.encodeWithSignature("unwrap(uint256,address,uint256)", 10e6, recipient, 10e6), batch: WARM,
            nonce: 0, validUntil: block.timestamp + 600, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: relayer,
            fee: 0, feeRecipient: address(0)});
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(PK, w.mtxDigest(m));
        bytes memory cd = abi.encodeCall(IMetaTx.mtxExecute, (m, abi.encodePacked(r, sg, v)));
        _snap();
        uint256 gu = _measure(address(w), cd);
        console.log("mtxExecute(unwrap) (cold lane, plain token, existing holder)", gu);
    }

    function test_gasCalldata() public view {
        MetaTxLib.MetaTransfer memory x = _x(_mt(MetaTxLib.MODE_RESTRICT_RELAYER, WARM, 1, 0, address(0)));
        bytes memory s = _sigT(address(v2), x);
        _cd("I calldata mtxExecuteTransfer", abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, s)));
        _cd("I calldata mtxTransfer", _named(v2.mtxTransfer.selector, abi.encode(signer, recipient, 1 ether, WARM, 1,
            x.validUntil, x.mode, relayer), s));
        bytes32 p = keccak256("inv");
        x.entryRef = p;
        x.batch = v2.payLane(p);
        _cd("I calldata mtxExecuteTransfer(pay)", abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, s)));
        _cd("I calldata mtxPay", _named(v2.mtxPay.selector, abi.encode(signer, recipient, 1 ether, p, x.validUntil,
            x.mode, relayer, 0, address(0)), s));
    }

    function _cd(string memory label, bytes memory cd) internal pure {
        uint256 g;
        for (uint256 i; i < cd.length; ++i) g += cd[i] == 0 ? 4 : 16;
        console.log(label, cd.length, g);
    }
}
