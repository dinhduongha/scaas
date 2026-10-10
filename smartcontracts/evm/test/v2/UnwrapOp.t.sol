// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {BlacklistERC20, SenderPaysFeeERC20, HookERC20, ITokensReceived, RateAdminForwarder}
    from "./helpers/V2Mocks.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Người nhận có hook (ERC-777): trong lúc unwrap không gas đang chạy, đọc nonce, số dư của người ký và của người
/// nhận phí, gọi `transfer` của wrapper (không có guard), hoặc thử vào lại một hàm có guard.
contract HookRecipient is ITokensReceived {
    UnderlyingToken public w;
    address public watched;
    uint256 public watchedBatch;
    address public watchedFeeTo;
    uint256 public seenNonce;
    uint256 public seenBalance;
    uint256 public seenFeeBalance;
    bool public reenterGuarded;

    constructor(UnderlyingToken w_) { w = w_; }

    function arm(address who, uint256 batch, address feeTo, bool guarded) external {
        watched = who;
        watchedBatch = batch;
        watchedFeeTo = feeTo;
        reenterGuarded = guarded;
    }

    function tokensReceived(address, uint256) external {
        if (msg.sender != w.underlying()) return;
        seenNonce = w.mtxNonce(watched, watchedBatch);
        seenBalance = w.balanceOf(watched);
        seenFeeBalance = w.balanceOf(watchedFeeTo);
        if (reenterGuarded) {
            w.unwrap(1, address(this)); // contract-wide guard: reverts, and with it the whole unwrap
        } else {
            w.transfer(address(0xD00D), 1);
        }
    }
}

/// T2: unwrap không gas = `mtxExecute(unwrap(uint256,address,uint256))`, allowlisted `AMOUNT(0)` (CTR-MTX-12).
contract UnwrapOpTest is V2Fixture {
    uint256 constant PK = 0xA11CE;
    address alice;
    address shop = address(0x5409);
    address feeTaker = address(0xFEE);
    MockERC20 usdc;
    UnderlyingToken t;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(PK);
        usdc = new MockERC20("USD Coin", "USDC", 6);
        t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _wrapFor(t, MockERC20(address(usdc)), alice, 1_000e6);
    }

    function _wrapFor(UnderlyingToken w, MockERC20 u, address who, uint256 v) internal {
        u.mint(who, v);
        vm.startPrank(who);
        u.approve(address(w), v);
        w.wrap(v);
        vm.stopPrank();
    }

    /// Gasless single-asset unwrap on lane 9.
    function _op(uint256 wrapped, address recipient, uint256 minOut)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = _call(alice, abi.encodeWithSignature("unwrap(uint256,address,uint256)", wrapped, recipient, minOut), 9, RR);
    }

    function _run(address w, MetaTxLib.MetaTransaction memory m) internal {
        _execCall(PK, w, m);
    }

    function _runRevert(address w, MetaTxLib.MetaTransaction memory m, bytes memory err) internal {
        bytes memory s = _signCall(PK, w, m);
        vm.prank(relayer);
        vm.expectRevert(err);
        MetaTokenBase(w).mtxExecute(m, s);
        assertEq(MetaTokenBase(w).mtxNonce(alice, m.batch), 0);
    }

    function test_gaslessUnwrapPaysTheRecipient() public {
        MetaTxLib.MetaTransaction memory m = _op(100e6, shop, 100e6);
        bytes32 d = t.mtxDigest(m);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.Unwrapped(alice, address(usdc), shop, 100e6, 100e6);
        vm.expectEmit(address(t));
        emit IMetaTx.MetaTransactionExecuted(alice, relayer, 9, 0, d, relayer, 0);
        _run(address(t), m);
        assertEq(usdc.balanceOf(shop), 100e6);
        assertEq(t.balanceOf(alice), 900e6);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 900e6);
    }

    /// Phí bằng đơn vị wrapped, cơ sở = `wrapped` (`AMOUNT(0)`), lấy SAU khi đốt; người giữ giữ phần dư làm tròn.
    function test_feeInWrappedUnitsAfterTheCall() public {
        UnderlyingToken q = _single(address(usdc), 18, 1e12, 1, _fixedRate());
        _wrapFor(q, usdc, alice, 10e6);
        MetaTxLib.MetaTransaction memory m = _op(2e18 + 5, shop, 2e6);
        m.mode = RR | RF | PCT;
        m.fee = 10_000; // 1 %
        m.feeRecipient = feeTaker;
        uint256 fee = uint256(2e18 + 5) / 100;
        vm.expectEmit(address(q));
        emit IUnderlyingToken.Unwrapped(alice, address(usdc), shop, 2e18, 2e6);
        vm.expectEmit(address(q));
        emit IERC20.Transfer(alice, feeTaker, fee);
        _run(address(q), m);
        assertEq(q.balanceOf(feeTaker), fee);
        assertEq(q.balanceOf(alice), 10e18 - fee - 2e18); // burned 2e18, keeps the 5 of dust
        assertEq(usdc.balanceOf(shop), 2e6);
        // the whole balance with a fee: the burn leaves nothing for the fee, so the call reverts with it
        uint256 bal = q.balanceOf(alice);
        (,, uint256 reserve,,) = q.legOf(address(usdc));
        m = _op(bal, shop, 0);
        m.batch = 10;
        m.mode = RR | RF | PCT;
        m.fee = 10_000;
        m.feeRecipient = feeTaker;
        _runRevert(address(q), m,
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientBalance.selector, alice, 0, bal / 100));
        assertEq(q.balanceOf(alice), bal);
        (,, uint256 reserveAfter,,) = q.legOf(address(usdc));
        assertEq(reserveAfter, reserve);
        assertEq(usdc.balanceOf(shop), 2e6);
    }

    function test_innerRefusalsBubble() public {
        _runRevert(address(t), _op(10e6, address(0), 0),
            abi.encodeWithSelector(IUnderlyingToken.UnwrapRecipientInvalid.selector, address(0)));
        _runRevert(address(t), _op(10e6, address(t), 0),
            abi.encodeWithSelector(IUnderlyingToken.UnwrapRecipientInvalid.selector, address(t)));
        _runRevert(address(t), _op(10e6, shop, 10e6 + 1),
            abi.encodeWithSelector(IUnderlyingToken.UnwrapBelowMin.selector, 10e6, 10e6 + 1));
        _runRevert(address(t), _op(0, shop, 0), abi.encodeWithSelector(IUnderlyingToken.UnwrapTooSmall.selector));
        _runRevert(address(t), _op(2_000e6, shop, 0),
            abi.encodeWithSelector(IUnderlyingToken.InsufficientReserve.selector, address(usdc), 2_000e6, 1_000e6));
        // Multi: an underlying that is not a leg
        address[] memory us = new address[](2);
        (us[0], us[1]) = (address(usdc), address(new MockERC20("Tether", "USDT", 6)));
        uint256[] memory ones = new uint256[](2);
        (ones[0], ones[1]) = (1, 1);
        UnderlyingToken mu = _multi(us, ones, ones, _fixedRate(), address(0));
        bytes memory d = abi.encodeWithSignature(
            "unwrap(address,uint256,address,uint256)", address(0x1234), 10e6, shop, 0);
        _runRevert(address(mu), _call(alice, d, 9, RR),
            abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, address(0x1234)));
    }

    /// R132 không áp cho unwrap: không có người được trả.
    function test_noPayeeCheckOnUnwrap() public {
        MetaTxLib.MetaTransaction memory m = _op(10e6, relayer, 0);
        m.mode = RR | PCT;
        m.fee = 1_000;
        _run(address(t), m);
        assertEq(usdc.balanceOf(relayer), 10e6);
        assertEq(t.balanceOf(relayer), 0.01e6);
    }

    /// Chuyển underlying fail trong lời gọi; nó revert cả tx, kể cả phí và nonce.
    function test_underlyingRevertUndoesFeeAndNonce() public {
        BlacklistERC20 bl = new BlacklistERC20();
        UnderlyingToken b = _single(address(bl), 6, 1, 1, _fixedRate());
        _wrapFor(b, MockERC20(address(bl)), alice, 100e6);
        bl.setBlocked(shop, true);
        MetaTxLib.MetaTransaction memory m = _op(50e6, shop, 0);
        m.mode = RR | FIX;
        m.fee = 1e5;
        _runRevert(address(b), m, abi.encodeWithSelector(BlacklistERC20.Blocked.selector, shop));
        assertEq(b.balanceOf(alice), 100e6);
        assertEq(b.balanceOf(relayer), 0);
    }

    function test_senderPaysFeeUnderlyingRevertsTheGaslessUnwrap() public {
        SenderPaysFeeERC20 sp = new SenderPaysFeeERC20();
        UnderlyingToken b = _single(address(sp), 18, 1, 1, _fixedRate());
        sp.mint(alice, 1 ether); // the sender-side fee of the wrap itself
        _wrapFor(b, MockERC20(address(sp)), alice, 100 ether);
        sp.mint(address(b), 1 ether);
        _runRevert(address(b), _op(10 ether, shop, 0), abi.encodeWithSelector(
            IUnderlyingToken.UnderlyingTransferMismatch.selector, address(sp), 10 ether, 10.1 ether));
    }

    /// Hook ERC-777 giữa unwrap: nonce đã ghi (bước 4), đã đốt, CHƯA thu phí (phí sau lời gọi); hàm không guard
    /// chạy được và trạng thái vẫn nhất quán.
    function test_erc777HookSeesTheNonceSpentAndConsistentState() public {
        HookERC20 hk = new HookERC20();
        UnderlyingToken h = _single(address(hk), 18, 1, 1, _fixedRate());
        HookRecipient r = new HookRecipient(h);
        hk.setHooked(address(r));
        _wrapFor(h, MockERC20(address(hk)), alice, 10 ether);
        _wrapFor(h, MockERC20(address(hk)), address(r), 1 ether);
        r.arm(alice, 9, feeTaker, false);
        MetaTxLib.MetaTransaction memory m = _op(3 ether, address(r), 0);
        m.mode = RR | RF | PCT;
        m.fee = 10_000; // 1 %
        m.feeRecipient = feeTaker;
        _run(address(h), m);
        assertEq(r.seenNonce(), 1);
        assertEq(r.seenBalance(), 7 ether);
        assertEq(r.seenFeeBalance(), 0);
        assertEq(h.balanceOf(feeTaker), 0.03 ether);
        assertEq(h.balanceOf(alice), 7 ether - 0.03 ether);
        assertEq(h.balanceOf(address(0xD00D)), 1);
        assertEq(hk.balanceOf(address(r)), 3 ether);
        assertGe(h.collateralValue(), h.totalSupply());
        assertEq(hk.balanceOf(address(h)), 8 ether);
    }

    function test_erc777HookCannotReenterAGuardedFunction() public {
        HookERC20 hk = new HookERC20();
        UnderlyingToken h = _single(address(hk), 18, 1, 1, _fixedRate());
        HookRecipient r = new HookRecipient(h);
        hk.setHooked(address(r));
        _wrapFor(h, MockERC20(address(hk)), alice, 10 ether);
        _wrapFor(h, MockERC20(address(hk)), address(r), 1 ether);
        r.arm(alice, 9, feeTaker, true);
        MetaTxLib.MetaTransaction memory m = _op(3 ether, address(r), 0);
        bytes memory s = _signCall(PK, address(h), m);
        vm.prank(relayer);
        vm.expectRevert();
        h.mtxExecute(m, s);
        assertEq(h.mtxNonce(alice, 9), 0);
        assertEq(h.balanceOf(alice), 10 ether);
    }

    /// Đổi tỉ lệ đang chờ: unwrap không gas vẫn chạy ở tỉ lệ hiện tại, `minOut` bảo vệ người ký.
    function test_gaslessUnwrapWorksDuringAPendingRateChange() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken a = _single(address(usdc), 6, 1, 1, _adjustable(address(adm)));
        _wrapFor(a, usdc, alice, 100);
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.proposeRate, (address(usdc), 101, 100)));
        _run(address(a), _op(50, shop, 50));
        assertEq(usdc.balanceOf(shop), 50);
        vm.warp(block.timestamp + 7 days);
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.executeRate, ()));
        MetaTxLib.MetaTransaction memory m = _op(50, shop, 50);
        m.batch = 10;
        _runRevert(address(a), m, abi.encodeWithSelector(IUnderlyingToken.UnwrapBelowMin.selector, 49, 50));
    }

    /// No named unwrap any more (R10): both selectors hit no function and revert empty.
    function test_oldUnwrapEntryPointsAreGone() public {
        bytes4[2] memory sels = [
            bytes4(keccak256(
                "mtxUnwrap(address,address,uint256,address,uint256,uint256,uint256,uint256,uint32,address,bytes)")),
            bytes4(keccak256(
                "mtxUnwrapWithFee(address,address,uint256,address,uint256,uint256,uint256,uint256,uint32,address,uint256,address,bytes)"))
        ];
        for (uint256 i; i < 2; ++i) {
            vm.prank(relayer);
            (bool ok, bytes memory ret) = address(t).call(abi.encodePacked(sels[i], new bytes(14 * 32)));
            assertFalse(ok);
            assertEq(ret.length, 0);
        }
    }
}
