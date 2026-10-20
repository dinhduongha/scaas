// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {V2Fixture, Rate} from "./helpers/V2Fixture.sol";
import {MockERC20, FeeOnTransferERC20} from "../helpers/Mocks.sol";
import {SenderPaysFeeERC20, SlashableERC20, NoDecimals, BadDecimals, RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// T2: tầng 2 `UnderlyingToken` — wrap/unwrap/reserve, tỉ lệ, làm tròn (TW2 §5, R133, R134, R137, R143).
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

    function _wrap(UnderlyingToken t, MockERC20 u, address who, uint256 v) internal returns (uint256) {
        _fund(u, who, v, address(t));
        vm.prank(who);
        return t.wrap(v);
    }

    function test_oneToOneIsV1Behaviour() public {
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        assertEq(t.kind(), AdminLib.KIND_UNDERLYING);
        assertEq(t.underlying(), address(usdc));
        assertEq(t.underlyings().length, 1);
        _fund(usdc, alice, 100e6, address(t));
        vm.expectEmit(address(t));
        emit IUnderlyingToken.Wrapped(alice, address(usdc), 100e6, 100e6);
        vm.prank(alice);
        assertEq(t.wrap(100e6), 100e6);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 100e6);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.Unwrapped(alice, address(usdc), bob, 40e6, 40e6);
        vm.prank(alice);
        assertEq(t.unwrap(40e6, bob), 40e6); // v1 selector: minOut 0
        assertEq(usdc.balanceOf(bob), 40e6);
        assertEq(t.balanceOf(alice), 60e6);
        assertEq(t.collateralValue(), 60e6);
    }

    /// 10¹²:1 (USDC → 18 decimals): wrap không làm tròn; unwrap trả ⌊w/10¹²⌋, đốt bội của 10¹², người giữ giữ dư.
    function test_integerRateKeepsDustWithTheHolder() public {
        UnderlyingToken t = _single(address(usdc), 18, 1e12, 1, _fixedRate());
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
        UnderlyingToken t = _single(address(usdc), 6, 3, 7, _fixedRate());
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
        UnderlyingToken t = _single(address(usdc), 0, 1, 1e4, _fixedRate());
        (uint256 minted, uint256 used) = t.previewWrap(address(usdc), 15_000);
        assertEq(minted, 1);
        assertEq(used, 10_000);
        assertEq(_wrap(t, usdc, alice, 15_000), 1);
        (,, uint256 reserve,,) = t.legOf(address(usdc));
        assertEq(reserve, 15_000);
    }

    function test_zeroOutputsRevert() public {
        UnderlyingToken t = _single(address(usdc), 0, 1, 1e4, _fixedRate());
        _fund(usdc, alice, 9_999, address(t));
        vm.prank(alice);
        vm.expectRevert(IUnderlyingToken.WrapTooSmall.selector);
        t.wrap(9_999);
        UnderlyingToken t2 = _single(address(usdc), 18, 1e12, 1, _fixedRate());
        _wrap(t2, usdc, alice, 1);
        vm.prank(alice);
        vm.expectRevert(IUnderlyingToken.UnwrapTooSmall.selector);
        t2.unwrap(1e12 - 1, bob);
    }

    function test_unwrapBelowMinAndBadRecipient() public {
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _wrap(t, usdc, alice, 10);
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapBelowMin.selector, 5, 6));
        t.unwrap(5, bob, 6);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapRecipientInvalid.selector, address(0)));
        t.unwrap(5, address(0));
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnwrapRecipientInvalid.selector, address(t)));
        t.unwrap(5, address(t));
        vm.stopPrank();
    }

    function test_feeOnTransferInboundMintsWhatArrived() public {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        UnderlyingToken t = _single(address(fot), 18, 1, 1, _fixedRate());
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
        UnderlyingToken t = _single(address(sp), 18, 1, 1, _fixedRate());
        sp.mint(alice, 100 ether);
        vm.prank(alice);
        sp.approve(address(t), 50 ether);
        vm.prank(alice);
        assertEq(t.wrap(50 ether), 50 ether);
        sp.mint(address(t), 1 ether); // so the wrapper can pay the extra fee at all
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(
            IUnderlyingToken.UnderlyingTransferMismatch.selector, address(sp), 10 ether, 10.1 ether));
        t.unwrap(10 ether, bob);
    }

    function test_donationIsNotCountedAndStaysLocked() public {
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
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
        UnderlyingToken t = _single(address(sl), 6, 1, 1, _fixedRate());
        sl.mint(alice, 200);
        vm.prank(alice);
        sl.approve(address(t), 200);
        vm.prank(alice);
        t.wrap(100);
        sl.slash(address(t), 30);
        bytes memory err = abi.encodeWithSelector(IUnderlyingToken.ReserveShortfall.selector, address(sl), 70, 100);
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

    /// `wrap(uint256)` is allowlisted `ABSOLUTE`: pulls from and mints to the signer, the signed fee comes out of the
    /// minted units after the call.
    function test_gaslessWrapPaysAbsoluteFeeFromMinted() public {
        uint256 pk = 0xA11CE;
        address signer = vm.addr(pk);
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _fund(usdc, signer, 100e6, address(t));
        MetaTxLib.MetaTransaction memory m = _call(signer, abi.encodeWithSignature("wrap(uint256)", 100e6), 1, RR | FIX);
        m.fee = 2e6; // ABSOLUTE: uncapped
        _execCall(pk, address(t), m);
        assertEq(t.balanceOf(signer), 98e6);
        assertEq(t.balanceOf(relayer), 2e6);
        assertEq(usdc.balanceOf(signer), 0);
        assertEq(t.collateralValue(), t.totalSupply());
    }

    function test_addReserveRaisesBackingNotSupply() public {
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        _wrap(t, usdc, alice, 100);
        _fund(usdc, bob, 50, address(t));
        vm.expectEmit(address(t));
        emit IUnderlyingToken.ReserveAdded(bob, address(usdc), 50);
        vm.prank(bob);
        t.addReserve(address(usdc), 50);
        assertEq(t.totalSupply(), 100);
        assertEq(t.collateralValue(), 150);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, bob));
        t.addReserve(bob, 1);
    }

    function test_decimalsAreTheIssuersChoiceAndLegSnapshot() public {
        UnderlyingToken t = _single(address(usdc), 18, 1e12, 1, _fixedRate());
        assertEq(t.decimals(), 18);
        (uint96 num, uint96 den,, uint8 d, bool enabled) = t.legOf(address(usdc));
        assertEq(num, 1e12);
        assertEq(den, 1);
        assertEq(d, 6);
        assertTrue(enabled);
        assertFalse(t.rateAdjustable());
    }

    function test_allowanceOnlyBetweenContracts() public {
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, _fixedRate());
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.approve(address(this), 1);
    }

    // ------------------------------------------------------------------ init refusals

    function initExt(address[] memory us, bytes memory d) external returns (address) {
        return _clone(_underlyingImpl(), address(this), us, d);
    }

    /// Init of one leg `u` at `num/den` with `cfg`, expected to revert `err`.
    function _refuse(address u, uint256 num, uint256 den, Rate memory cfg, bytes memory err) internal {
        bytes memory d = _singleInit(u, 6, num, den, cfg);
        vm.expectRevert(err);
        this.initExt(_one(u), d);
    }

    function test_initRefusals() public {
        Rate memory f = _fixedRate();
        bytes4 inv = IUnderlyingToken.UnderlyingInvalid.selector;
        _refuse(address(0xDEAD), 1, 1, f, abi.encodeWithSelector(inv, address(0xDEAD)));
        address nd = address(new NoDecimals());
        _refuse(nd, 1, 1, f, abi.encodeWithSelector(IUnderlyingToken.DecimalsUnreadable.selector, nd));
        address bd = address(new BadDecimals());
        _refuse(bd, 1, 1, f, abi.encodeWithSelector(IUnderlyingToken.DecimalsUnreadable.selector, bd));
        bytes4 ri = IUnderlyingToken.RateInvalid.selector;
        _refuse(address(usdc), 0, 1, f, abi.encodeWithSelector(ri, 0, 1));
        _refuse(address(usdc), 1, 0, f, abi.encodeWithSelector(ri, 1, 0));
        _refuse(address(usdc), 1 << 96, 1, f, abi.encodeWithSelector(ri, 1 << 96, 1));
        _refuse(address(usdc), 1, 1 << 96, f, abi.encodeWithSelector(ri, 1, 1 << 96));
        // fixed with leftovers
        Rate memory c = _fixedRate();
        c.rateDelay = 7 days;
        bytes memory cfgErr = abi.encodeWithSelector(IUnderlyingToken.RateConfigInvalid.selector);
        _refuse(address(usdc), 1, 1, c, cfgErr);
        // adjustable: admin must have code, delay [2d, 30d], step [1, 1000]
        _refuse(address(usdc), 1, 1, _adjustable(bob),
            abi.encodeWithSelector(ITokenAdmin.RoleNotContract.selector, uint8(3), bob));
        address adm = address(new RateAdminForwarder());
        c = _adjustable(adm);
        c.rateDelay = 2 days - 1;
        _refuse(address(usdc), 1, 1, c, cfgErr);
        c.rateDelay = 30 days + 1;
        _refuse(address(usdc), 1, 1, c, cfgErr);
        c = _adjustable(adm);
        c.maxRateStepBps = 0;
        _refuse(address(usdc), 1, 1, c, cfgErr);
        c.maxRateStepBps = 1001;
        _refuse(address(usdc), 1, 1, c, cfgErr);
    }

    /// D9: one implementation takes 1–8 legs; with two the single-asset ABI refuses (`UnderlyingRequired`).
    function test_twoLegsAreAValidToken_singleAssetAbiRefuses() public {
        address[] memory two = new address[](2);
        two[0] = address(usdc);
        two[1] = address(new MockERC20("Tether", "USDT", 6));
        uint256[] memory one = new uint256[](2);
        one[0] = one[1] = 1;
        UnderlyingToken t = UnderlyingToken(this.initExt(two, _multiInit(two, one, one, _fixedRate(), address(0))));
        assertEq(t.kind(), AdminLib.KIND_UNDERLYING);
        assertEq(t.underlying(), address(0));
        assertEq(t.underlyings().length, 2);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        t.wrap(1);
        vm.expectRevert(IUnderlyingToken.UnderlyingRequired.selector);
        t.unwrap(1, bob);
    }

    function test_initRefusesItselfAsUnderlying() public {
        address impl = _underlyingImpl();
        address predicted = Clones.predictDeterministicAddress(impl, bytes32("self"));
        address c = Clones.cloneDeterministic(impl, bytes32("self"));
        assertEq(c, predicted);
        IFactoryToken.TokenConfig memory cfg =
            abi.decode(_singleInit(c, 6, 1, 1, _fixedRate()), (IFactoryToken.TokenConfig));
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnderlyingInvalid.selector, c));
        MetaTokenBase(c).initialize(address(this), 1, abi.encode(cfg));
    }

    function test_boundsAreInclusive() public {
        address adm = address(new RateAdminForwarder());
        Rate memory c = _adjustable(adm);
        c.rateDelay = 2 days;
        c.maxRateStepBps = 1;
        _single(address(usdc), 6, type(uint96).max, type(uint96).max, c);
        c.rateDelay = 30 days;
        c.maxRateStepBps = 1000;
        UnderlyingToken t = _single(address(usdc), 6, 1, 1, c);
        assertTrue(t.rateAdjustable());
        assertTrue(t.hasRole(3, adm));
        assertEq(t.rateDelay(), 30 days);
        assertEq(t.maxRateStepBps(), 1000);
    }

    // ------------------------------------------------------------------ fuzz

    /// R133 + §6.3 mục 6: một vòng wrap→unwrap không bao giờ trả ra nhiều underlying hơn đã vào, ở mọi tỉ lệ.
    function testFuzz_wrapUnwrapNeverProfits(uint256 amount, uint96 num, uint96 den) public {
        num = uint96(bound(num, 1, type(uint96).max));
        den = uint96(bound(den, 1, type(uint96).max));
        amount = bound(amount, 1, 1e30);
        UnderlyingToken t = _single(address(usdc), 6, num, den, _fixedRate());
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
