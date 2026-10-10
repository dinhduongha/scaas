// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {V2Fixture} from "./helpers/V2Fixture.sol";
import {MockERC20, FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {SenderPaysFeeERC20, SlashableERC20, NoDecimals, BadDecimals, RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {SingleUnderlyingToken} from "../../src/metatx/SingleUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";

/// T2: tầng 2 `SingleUnderlyingToken` — wrap/unwrap/reserve, tỉ lệ, làm tròn (TW2 §5, R133, R134, R137, R143).
contract Tier2Test is V2Fixture {
    MockERC20 usdc;
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        vm.warp(1_800_000_000);
        usdc = new MockERC20("USD Coin", "USDC", 6);
    }

    function _fund(MockERC20 u, address who, uint256 v, address spender) internal {
        u.mint(who, v);
        vm.prank(who);
        u.approve(spender, v);
    }

    function _wrap(SingleUnderlyingToken t, MockERC20 u, address who, uint256 v) internal returns (uint256) {
        _fund(u, who, v, address(t));
        vm.prank(who);
        return t.wrap(v);
    }

    function test_oneToOneIsV1Behaviour() public {
        SingleUnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        assertEq(uint8(t.tokenKind()), uint8(IOpenFactoryV2.TokenKind.META_SINGLE));
        assertEq(t.underlying(), address(usdc));
        assertEq(t.underlyings().length, 1);
        _fund(usdc, alice, 100e6, address(t));
        vm.expectEmit(address(t));
        emit SingleUnderlyingToken.Wrapped(alice, address(usdc), 100e6, 100e6);
        vm.prank(alice);
        assertEq(t.wrap(100e6), 100e6);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 100e6);
        vm.expectEmit(address(t));
        emit SingleUnderlyingToken.Unwrapped(alice, address(usdc), bob, 40e6, 40e6);
        vm.prank(alice);
        assertEq(t.unwrap(40e6, bob), 40e6); // v1 selector: minOut 0
        assertEq(usdc.balanceOf(bob), 40e6);
        assertEq(t.balanceOf(alice), 60e6);
        assertEq(t.collateralValue(), 60e6);
    }

    /// 10¹²:1 (USDC → 18 decimals): wrap không làm tròn; unwrap trả ⌊w/10¹²⌋, đốt bội của 10¹², người giữ giữ dư.
    function test_integerRateKeepsDustWithTheHolder() public {
        SingleUnderlyingToken t = _single(address(usdc), 18, 1e12, 1, _fixedRate());
        assertEq(_wrap(t, usdc, alice, 2e6), 2e18);
        vm.prank(alice);
        uint256 out = t.unwrap(1.5e12 + 7, bob, 1);
        assertEq(out, 1);
        assertEq(t.balanceOf(alice), 2e18 - 1e12);
        (uint256 o, uint256 b) = t.previewUnwrap(address(usdc), 1.5e12 + 7);
        assertEq(o, 1);
        assertEq(b, 1e12);
    }

    /// 3:7: wrap ⌊in·3/7⌋, unwrap ⌊w·7/3⌋, đốt ⌈out·3/7⌉ ≤ w.
    function test_roundingAlwaysDown() public {
        SingleUnderlyingToken t = _single(address(usdc), 6, 3, 7, _fixedRate());
        (uint256 minted, uint256 used) = t.previewWrap(address(usdc), 10);
        assertEq(minted, 4);
        assertEq(used, 10);
        assertEq(_wrap(t, usdc, alice, 10), 4);
        (uint256 out, uint256 burned) = t.previewUnwrap(address(usdc), 4);
        assertEq(out, 9);
        assertEq(burned, 4);
        vm.prank(alice);
        t.unwrap(4, bob, 9);
        assertEq(usdc.balanceOf(bob), 9);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 1); // the contract keeps the rounding
        assertEq(t.totalSupply(), 0);
    }

    /// 1 USDC → 100 điểm (`D = 0`): 1:10⁴. 15 000 raw mint 1 điểm và để 5 000 trong reserve (review L2).
    function test_previewWrapUsedAndDustInReserve() public {
        SingleUnderlyingToken t = _single(address(usdc), 0, 1, 1e4, _fixedRate());
        (uint256 minted, uint256 used) = t.previewWrap(address(usdc), 15_000);
        assertEq(minted, 1);
        assertEq(used, 10_000);
        assertEq(_wrap(t, usdc, alice, 15_000), 1);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 15_000);
    }

    function test_zeroOutputsRevert() public {
        SingleUnderlyingToken t = _single(address(usdc), 0, 1, 1e4, _fixedRate());
        _fund(usdc, alice, 9_999, address(t));
        vm.prank(alice);
        vm.expectRevert(SingleUnderlyingToken.WrapTooSmall.selector);
        t.wrap(9_999);
        SingleUnderlyingToken t2 = _single(address(usdc), 18, 1e12, 1, _fixedRate());
        _wrap(t2, usdc, alice, 1);
        vm.prank(alice);
        vm.expectRevert(SingleUnderlyingToken.UnwrapTooSmall.selector);
        t2.unwrap(1e12 - 1, bob);
    }

    function test_unwrapBelowMinAndBadRecipient() public {
        SingleUnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _wrap(t, usdc, alice, 10);
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(SingleUnderlyingToken.UnwrapBelowMin.selector, 5, 6));
        t.unwrap(5, bob, 6);
        vm.expectRevert(abi.encodeWithSelector(SingleUnderlyingToken.UnwrapRecipientInvalid.selector, address(0)));
        t.unwrap(5, address(0));
        vm.expectRevert(abi.encodeWithSelector(SingleUnderlyingToken.UnwrapRecipientInvalid.selector, address(t)));
        t.unwrap(5, address(t));
        vm.stopPrank();
    }

    function test_feeOnTransferInboundMintsWhatArrived() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        SingleUnderlyingToken t = _single(address(fot), 18, 1, 1, _fixedRate());
        fot.mint(alice, 100 ether);
        vm.prank(alice);
        fot.approve(address(t), 100 ether);
        vm.prank(alice);
        assertEq(t.wrap(100 ether), 99 ether);
        (,, uint256 reserve,,) = t.legOf(address(fot));
        assertEq(reserve, 99 ether);
        vm.prank(alice);
        t.unwrap(10 ether, bob); // fee from the amount: bob gets 9.9, the wrapper loses exactly 10
        assertEq(fot.balanceOf(bob), 9.9 ether);
    }

    function test_senderPaysFeeUnderlyingCannotLeave() public {
        SenderPaysFeeERC20 sp = new SenderPaysFeeERC20();
        SingleUnderlyingToken t = _single(address(sp), 18, 1, 1, _fixedRate());
        sp.mint(alice, 100 ether);
        vm.prank(alice);
        sp.approve(address(t), 50 ether);
        vm.prank(alice);
        assertEq(t.wrap(50 ether), 50 ether);
        sp.mint(address(t), 1 ether); // so the wrapper can pay the extra fee at all
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            SingleUnderlyingToken.UnderlyingTransferMismatch.selector, address(sp), 10 ether, 10.1 ether));
        t.unwrap(10 ether, bob);
    }

    function test_donationIsNotCountedAndStaysLocked() public {
        SingleUnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _wrap(t, usdc, alice, 100);
        usdc.mint(address(t), 1_000);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 100);
        assertEq(t.collateralValue(), 100);
        (uint256 out,) = t.previewUnwrap(address(usdc), 100);
        assertEq(out, 100);
    }

    function test_negativeRebaseStopsWrapNotUnwrap() public {
        SlashableERC20 sl = new SlashableERC20(6);
        SingleUnderlyingToken t = _single(address(sl), 6, 1, 1, _fixedRate());
        sl.mint(alice, 200);
        vm.prank(alice);
        sl.approve(address(t), 200);
        vm.prank(alice);
        t.wrap(100);
        sl.slash(address(t), 30);
        bytes memory err = abi.encodeWithSelector(SingleUnderlyingToken.ReserveShortfall.selector, address(sl), 70, 100);
        vm.prank(alice);
        vm.expectRevert(err);
        t.wrap(10);
        vm.prank(alice);
        vm.expectRevert(err);
        t.addReserve(address(sl), 10);
        vm.prank(alice);
        t.unwrap(60, alice); // first come, first served
        assertEq(sl.balanceOf(address(t)), 10);
    }

    function test_addReserveRaisesBackingNotSupply() public {
        SingleUnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _wrap(t, usdc, alice, 100);
        _fund(usdc, bob, 50, address(t));
        vm.expectEmit(address(t));
        emit SingleUnderlyingToken.ReserveAdded(bob, address(usdc), 50);
        vm.prank(bob);
        t.addReserve(address(usdc), 50);
        assertEq(t.totalSupply(), 100);
        assertEq(t.collateralValue(), 150);
        vm.expectRevert(abi.encodeWithSelector(SingleUnderlyingToken.UnknownUnderlying.selector, bob));
        t.addReserve(bob, 1);
    }

    function test_decimalsAreTheIssuersChoiceAndLegSnapshot() public {
        SingleUnderlyingToken t = _single(address(usdc), 18, 1e12, 1, _fixedRate());
        assertEq(t.decimals(), 18);
        (uint96 num, uint96 den,, uint8 d, bool enabled) = t.legOf(address(usdc));
        assertEq(num, 1e12);
        assertEq(den, 1);
        assertEq(d, 6);
        assertTrue(enabled);
        assertFalse(t.rateAdjustable());
    }

    function test_allowanceOnlyBetweenContracts() public {
        SingleUnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
    }

    // ------------------------------------------------------------------ init refusals

    function initExt(address[] memory us, bytes memory d) external returns (address) {
        if (singleImpl == address(0)) singleImpl = address(new SingleUnderlyingToken(address(this), address(0)));
        return _clone(singleImpl, address(this), us, d);
    }

    function _refuse(address u, bytes memory d, bytes memory err) internal {
        address[] memory us = new address[](1);
        us[0] = u;
        vm.expectRevert(err);
        this.initExt(us, d);
    }

    function test_initRefusals() public {
        bytes memory ok = _singleInit(6, 1, 1, _fixedRate());
        bytes4 inv = SingleUnderlyingToken.UnderlyingInvalid.selector;
        _refuse(address(0), ok, abi.encodeWithSelector(inv, address(0)));
        _refuse(address(0xDEAD), ok, abi.encodeWithSelector(inv, address(0xDEAD)));
        address nd = address(new NoDecimals());
        _refuse(nd, ok, abi.encodeWithSelector(SingleUnderlyingToken.DecimalsUnreadable.selector, nd));
        address bd = address(new BadDecimals());
        _refuse(bd, ok, abi.encodeWithSelector(SingleUnderlyingToken.DecimalsUnreadable.selector, bd));
        bytes4 ri = SingleUnderlyingToken.RateInvalid.selector;
        _refuse(address(usdc), _singleInit(6, 0, 1, _fixedRate()), abi.encodeWithSelector(ri, 0, 1));
        _refuse(address(usdc), _singleInit(6, 1, 0, _fixedRate()), abi.encodeWithSelector(ri, 1, 0));
        _refuse(address(usdc), _singleInit(6, 1 << 96, 1, _fixedRate()), abi.encodeWithSelector(ri, 1 << 96, 1));
        _refuse(address(usdc), _singleInit(6, 1, 1 << 96, _fixedRate()), abi.encodeWithSelector(ri, 1, 1 << 96));
        // fixed with leftovers
        SingleUnderlyingToken.RateConfig memory c = _fixedRate();
        c.rateDelay = 7 days;
        bytes memory cfgErr = abi.encodeWithSelector(SingleUnderlyingToken.RateConfigInvalid.selector);
        _refuse(address(usdc), _singleInit(6, 1, 1, c), cfgErr);
        // adjustable: admin must have code, delay [2d, 30d], step [1, 1000]
        _refuse(address(usdc), _singleInit(6, 1, 1, _adjustable(bob)),
            abi.encodeWithSelector(SingleUnderlyingToken.RateAdminNotContract.selector, bob));
        address adm = address(new RateAdminForwarder());
        c = _adjustable(adm);
        c.rateDelay = 2 days - 1;
        _refuse(address(usdc), _singleInit(6, 1, 1, c), cfgErr);
        c.rateDelay = 30 days + 1;
        _refuse(address(usdc), _singleInit(6, 1, 1, c), cfgErr);
        c = _adjustable(adm);
        c.maxRateStepBps = 0;
        _refuse(address(usdc), _singleInit(6, 1, 1, c), cfgErr);
        c.maxRateStepBps = 1001;
        _refuse(address(usdc), _singleInit(6, 1, 1, c), cfgErr);
        // count
        address[] memory two = new address[](2);
        two[0] = address(usdc);
        two[1] = address(usdc);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 2));
        this.initExt(two, ok);
    }

    function test_initRefusesItselfAsUnderlying() public {
        singleImpl = address(new SingleUnderlyingToken(address(this), address(0)));
        address predicted = Clones.predictDeterministicAddress(singleImpl, bytes32("self"));
        address c = Clones.cloneDeterministic(singleImpl, bytes32("self"));
        assertEq(c, predicted);
        address[] memory us = new address[](1);
        us[0] = c;
        vm.expectRevert(abi.encodeWithSelector(SingleUnderlyingToken.UnderlyingInvalid.selector, c));
        MetaTokenBase(c).initialize(address(this), us, 1, _singleInit(6, 1, 1, _fixedRate()));
    }

    function test_boundsAreInclusive() public {
        address adm = address(new RateAdminForwarder());
        SingleUnderlyingToken.RateConfig memory c = _adjustable(adm);
        c.rateDelay = 2 days;
        c.maxRateStepBps = 1;
        _single(address(usdc), 6, type(uint96).max, type(uint96).max, c);
        c.rateDelay = 30 days;
        c.maxRateStepBps = 1000;
        SingleUnderlyingToken t = _single(address(usdc), 6, 1, 1, c);
        assertTrue(t.rateAdjustable());
        assertEq(t.rateAdmin(), adm);
        assertEq(t.rateDelay(), 30 days);
        assertEq(t.maxRateStepBps(), 1000);
    }

    // ------------------------------------------------------------------ fuzz

    /// R133 + §6.3 mục 6: một vòng wrap→unwrap không bao giờ trả ra nhiều underlying hơn đã vào, ở mọi tỉ lệ.
    function testFuzz_wrapUnwrapNeverProfits(uint256 amount, uint96 num, uint96 den) public {
        num = uint96(bound(num, 1, type(uint96).max));
        den = uint96(bound(den, 1, type(uint96).max));
        amount = bound(amount, 1, 1e30);
        SingleUnderlyingToken t = _single(address(usdc), 6, num, den, _fixedRate());
        (uint256 minted,) = t.previewWrap(address(usdc), amount);
        vm.assume(minted > 0);
        _wrap(t, usdc, alice, amount);
        (uint256 out,) = t.previewUnwrap(address(usdc), minted);
        if (out == 0) return;
        vm.prank(alice);
        t.unwrap(minted, alice);
        assertLe(usdc.balanceOf(alice), amount);
        assertGe(t.collateralValue(), t.totalSupply());
    }
}
