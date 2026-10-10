// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {BlacklistERC20, SenderPaysFeeERC20, HookERC20, ITokensReceived, RateAdminForwarder}
    from "./helpers/V2Mocks.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {MetaTxCore} from "../../src/metatx/MetaTxCore.sol";
import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Người nhận có hook (ERC-777): trong lúc unwrap op đang chạy, đọc nonce của người ký, gọi `cancelMetaNonce`
/// và `transfer` của wrapper (không có guard), hoặc thử vào lại một hàm có guard.
contract HookRecipient is ITokensReceived {
    SingleUnderlyingToken public w;
    address public watched;
    uint256 public watchedBatch;
    uint256 public seenNonce;
    bool public reenterGuarded;

    constructor(SingleUnderlyingToken w_) { w = w_; }

    function arm(address who, uint256 batch, bool guarded) external {
        watched = who;
        watchedBatch = batch;
        reenterGuarded = guarded;
    }

    function tokensReceived(address, uint256) external {
        if (msg.sender != w.underlying()) return;
        seenNonce = w.metaNonce(watched, watchedBatch);
        if (reenterGuarded) {
            w.unwrap(1, address(this)); // contract-wide guard: reverts, and with it the whole unwrap
        } else {
            w.cancelMetaNonce(42);
            w.transfer(address(0xD00D), 1);
        }
    }
}

/// T2: op unwrap không gas (TW2 §5.3, R148) và `mtxUnwrap`/`mtxUnwrapWithFee`.
contract UnwrapOpTest is V2Fixture {
    uint256 constant PK = 0xA11CE;
    address alice;
    address shop = address(0x5409);
    address feeTaker = address(0xFEE);
    MockERC20 usdc;
    SingleUnderlyingToken t;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(PK);
        usdc = new MockERC20("USD Coin", "USDC", 6);
        t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _wrapFor(t, MockERC20(address(usdc)), alice, 1_000e6);
    }

    function _wrapFor(SingleUnderlyingToken w, MockERC20 u, address who, uint256 v) internal {
        u.mint(who, v);
        vm.startPrank(who);
        u.approve(address(w), v);
        w.wrap(v);
        vm.stopPrank();
    }

    function _op(address u, uint256 wrapped, address recipient, uint256 minOut)
        internal view returns (MetaTxLib.LegacyMetaTransaction memory m)
    {
        m = _mt(alice, recipient, wrapped, _unwrapData(u, recipient, minOut), 9, RR);
    }

    function _run(SingleUnderlyingToken w, MetaTxLib.LegacyMetaTransaction memory m) internal {
        bytes memory s = _sig(PK, address(w), m);
        vm.prank(relayer);
        w.executeMetaTransaction(m, s);
    }

    function _runRevert(SingleUnderlyingToken w, MetaTxLib.LegacyMetaTransaction memory m, bytes memory err) internal {
        bytes memory s = _sig(PK, address(w), m);
        vm.prank(relayer);
        vm.expectRevert(err);
        w.executeMetaTransaction(m, s);
        assertEq(w.metaNonce(alice, m.batch), 0);
    }

    function test_unwrapOpPaysTheRecipientInUnderlying() public {
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(usdc), 100e6, shop, 100e6);
        bytes32 d = t.metaTxDigest(m);
        vm.expectEmit(address(t));
        emit SingleUnderlyingToken.Unwrapped(alice, address(usdc), shop, 100e6, 100e6);
        vm.expectEmit(address(t));
        emit IERC20MetaTxV1.MetaTransactionExecuted(alice, relayer, 9, 0, d, relayer, 0);
        _run(t, m);
        assertEq(usdc.balanceOf(shop), 100e6);
        assertEq(t.balanceOf(alice), 900e6);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 900e6);
    }

    /// Phí lấy bằng đơn vị wrapped TRƯỚC khi đốt; người giữ trả phí trên `value`, giữ phần dư làm tròn.
    function test_feeInWrappedUnitsBeforeTheBurn() public {
        SingleUnderlyingToken q = _single(address(usdc), 18, 1e12, 1, _fixedRate());
        _wrapFor(q, usdc, alice, 10e6);
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(usdc), 2e18 + 5, shop, 2e6);
        m.mode = RR | RF | PCT;
        m.fee = 10_000; // 1 %
        m.feeRecipient = feeTaker;
        bytes memory s = _sig(PK, address(q), m);
        vm.prank(relayer);
        _mtxUnwrapWithFee(address(q), m, address(usdc), 2e6, s);
        uint256 fee = m.value / 100;
        assertEq(q.balanceOf(feeTaker), fee);
        assertEq(q.balanceOf(alice), 10e18 - fee - 2e18); // burned 2e18, keeps the 5 of dust
        assertEq(usdc.balanceOf(shop), 2e6);
    }

    function test_stepSixRefusals() public {
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(usdc), 10e6, shop, 0);
        m.to = address(0xCAFE);
        _runRevert(t, m, abi.encodeWithSelector(MetaTokenBase.UnwrapRecipientMismatch.selector));
        m = _op(address(usdc), 10e6, address(0), 0);
        _runRevert(t, m, abi.encodeWithSelector(SingleUnderlyingToken.UnwrapRecipientInvalid.selector, address(0)));
        m = _op(address(usdc), 10e6, address(t), 0);
        _runRevert(t, m, abi.encodeWithSelector(SingleUnderlyingToken.UnwrapRecipientInvalid.selector, address(t)));
        m = _op(address(usdc), 10e6, shop, 10e6 + 1);
        _runRevert(t, m, abi.encodeWithSelector(SingleUnderlyingToken.UnwrapBelowMin.selector, 10e6, 10e6 + 1));
        m = _op(address(0x1234), 10e6, shop, 0);
        _runRevert(t, m, abi.encodeWithSelector(SingleUnderlyingToken.UnknownUnderlying.selector, address(0x1234)));
        m = _op(address(usdc), 0, shop, 0);
        _runRevert(t, m, abi.encodeWithSelector(SingleUnderlyingToken.UnwrapTooSmall.selector));
        m = _op(address(usdc), 2_000e6, shop, 0);
        _runRevert(t, m, abi.encodeWithSelector(IERC20MetaTxV1.MetaTxInsufficientForFee.selector, 2_000e6, 1_000e6));
        bytes4 op = t.OP_UNWRAP();
        m.data = abi.encodePacked(op, uint256(uint160(address(usdc))) | (1 << 170), uint256(uint160(shop)), uint256(0));
        m.value = 1;
        _runRevert(t, m, abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, op));
        m.data = abi.encodePacked(op, uint256(uint160(address(usdc))), uint256(uint160(shop)) | (1 << 200), uint256(0));
        _runRevert(t, m, abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, op));
    }

    /// R132 không áp cho unwrap: không có người được trả.
    function test_noPayeeCheckOnUnwrap() public {
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(usdc), 10e6, relayer, 0);
        m.mode = RR | PCT;
        m.fee = 1_000;
        _run(t, m);
        assertEq(usdc.balanceOf(relayer), 10e6);
        assertEq(t.balanceOf(relayer), 0.01e6);
    }

    /// Chuyển underlying là thứ DUY NHẤT được fail sau bước 7; nó revert cả tx, kể cả phí và nonce.
    function test_underlyingRevertUndoesFeeAndNonce() public {
        BlacklistERC20 bl = new BlacklistERC20();
        SingleUnderlyingToken b = _single(address(bl), 6, 1, 1, _fixedRate());
        _wrapFor(b, MockERC20(address(bl)), alice, 100e6);
        bl.setBlocked(shop, true);
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(bl), 50e6, shop, 0);
        m.mode = RR | FIX;
        m.fee = 1e5;
        _runRevert(b, m, abi.encodeWithSelector(BlacklistERC20.Blocked.selector, shop));
        assertEq(b.balanceOf(alice), 100e6);
        assertEq(b.balanceOf(relayer), 0);
    }

    function test_senderPaysFeeUnderlyingRevertsTheOp() public {
        SenderPaysFeeERC20 sp = new SenderPaysFeeERC20();
        SingleUnderlyingToken b = _single(address(sp), 18, 1, 1, _fixedRate());
        sp.mint(alice, 1 ether); // the sender-side fee of the wrap itself
        _wrapFor(b, MockERC20(address(sp)), alice, 100 ether);
        sp.mint(address(b), 1 ether);
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(sp), 10 ether, shop, 0);
        _runRevert(b, m, abi.encodeWithSelector(
            SingleUnderlyingToken.UnderlyingTransferMismatch.selector, address(sp), 10 ether, 10.1 ether));
    }

    /// Hook ERC-777 giữa unwrap: nonce đã ghi (bước 7), hàm không guard chạy được và trạng thái vẫn nhất quán.
    function test_erc777HookSeesTheNonceSpentAndConsistentState() public {
        HookERC20 hk = new HookERC20();
        SingleUnderlyingToken h = _single(address(hk), 18, 1, 1, _fixedRate());
        HookRecipient r = new HookRecipient(h);
        hk.setHooked(address(r));
        _wrapFor(h, MockERC20(address(hk)), alice, 10 ether);
        _wrapFor(h, MockERC20(address(hk)), address(r), 1 ether);
        r.arm(alice, 9, false);
        _run(h, _op(address(hk), 3 ether, address(r), 0));
        assertEq(r.seenNonce(), 1);
        assertEq(h.metaNonce(address(r), 42), 1);
        assertEq(h.balanceOf(address(0xD00D)), 1);
        assertEq(hk.balanceOf(address(r)), 3 ether);
        assertGe(h.collateralValue(), h.totalSupply());
        assertEq(hk.balanceOf(address(h)), 8 ether);
    }

    function test_erc777HookCannotReenterAGuardedFunction() public {
        HookERC20 hk = new HookERC20();
        SingleUnderlyingToken h = _single(address(hk), 18, 1, 1, _fixedRate());
        HookRecipient r = new HookRecipient(h);
        hk.setHooked(address(r));
        _wrapFor(h, MockERC20(address(hk)), alice, 10 ether);
        _wrapFor(h, MockERC20(address(hk)), address(r), 1 ether);
        r.arm(alice, 9, true);
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(hk), 3 ether, address(r), 0);
        bytes memory s = _sig(PK, address(h), m);
        vm.prank(relayer);
        vm.expectRevert();
        h.executeMetaTransaction(m, s);
        assertEq(h.metaNonce(alice, 9), 0);
        assertEq(h.balanceOf(alice), 10 ether);
    }

    /// Đổi tỉ lệ đang chờ: unwrap op vẫn chạy ở tỉ lệ hiện tại, `minOut` bảo vệ người ký.
    function test_unwrapOpWorksDuringAPendingRateChange() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        SingleUnderlyingToken a = _single(address(usdc), 6, 1, 1, _adjustable(address(adm)));
        _wrapFor(a, usdc, alice, 100);
        adm.exec(address(a), abi.encodeCall(SingleUnderlyingToken.proposeRate, (address(usdc), 101, 100)));
        _run(a, _op(address(usdc), 50, shop, 50));
        assertEq(usdc.balanceOf(shop), 50);
        vm.warp(block.timestamp + 7 days);
        adm.exec(address(a), abi.encodeCall(SingleUnderlyingToken.executeRate, ()));
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(usdc), 50, shop, 50);
        m.batch = 10;
        _runRevert(a, m, abi.encodeWithSelector(SingleUnderlyingToken.UnwrapBelowMin.selector, 49, 50));
    }

    /// Mọi hàm unwrap có tên ≡ op chung: cùng digest, cùng lane.
    function testFuzz_namedUnwrapDigestEqualsGeneric(uint256 wrapped, uint256 batch, bool withFee, uint16 feePpm)
        public
    {
        wrapped = bound(wrapped, 1, 900e6);
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(usdc), wrapped, shop, wrapped);
        m.batch = batch;
        if (withFee) {
            m.mode = RR | RF | FIX;
            m.fee = bound(feePpm, 0, wrapped / 100);
            m.feeRecipient = feeTaker;
        }
        bytes32 d = t.metaTxDigest(m);
        bytes memory s = _sig(PK, address(t), m);
        vm.expectEmit(address(t));
        emit IERC20MetaTxV1.MetaTransactionExecuted(alice, relayer, batch, 0, d, withFee ? feeTaker : relayer, m.fee);
        vm.prank(relayer);
        if (withFee) _mtxUnwrapWithFee(address(t), m, address(usdc), wrapped, s);
        else t.mtxUnwrap(alice, address(usdc), wrapped, shop, wrapped, batch, 0, m.validUntil, RR, relayer, s);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.MetaTxBadNonce.selector, 1, 0));
        t.executeMetaTransaction(m, s);
    }

    function test_mtxUnwrapWithFeeDecodesLikeTheAbi() public {
        MetaTxLib.LegacyMetaTransaction memory m = _op(address(usdc), 10e6, shop, 0);
        m.mode = RR | RF | FIX;
        m.fee = 1;
        m.feeRecipient = feeTaker;
        bytes memory s = _sig(PK, address(t), m);
        bytes memory cd = _unwrapFeeCalldata(m, address(usdc), 0, s);
        // dirty address word (from) ⇒ empty revert, like the ABI decoder
        bytes memory bad = _slice(cd, cd.length);
        bad[4] = 0x01;
        vm.prank(relayer);
        (bool ok,) = address(t).call(bad);
        assertFalse(ok);
        // truncated
        vm.prank(relayer);
        (ok,) = address(t).call(_slice(cd, cd.length - 40));
        assertFalse(ok);
        // unknown selector still reverts empty
        (ok,) = address(t).call(hex"12345678");
        assertFalse(ok);
        vm.prank(relayer);
        (bool ok2, bytes memory ret) = address(t).call(cd);
        assertTrue(ok2);
        assertEq(abi.decode(ret, (bool)), true);
    }

    function _slice(bytes memory b, uint256 n) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; ++i) out[i] = b[i];
    }
}
