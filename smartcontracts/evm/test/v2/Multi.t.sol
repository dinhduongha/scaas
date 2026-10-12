// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {V2Fixture, UID_, Rate} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {AdminLib} from "../../src/metatx/AdminLib.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// T3: tầng 3 `UnderlyingToken` — any-of, reserve theo chân, guardian chỉ tắt wrap (TW2 §8, R136, R147).
contract MultiTest is V2Fixture {
    uint256 constant PK = 0xA11CE;
    address alice;
    address bob = address(0xB0B);
    address guardian = address(0x6A2D);
    MockERC20 usdc;
    MockERC20 usdt;
    MockERC20 dai;
    UnderlyingToken t;
    RateAdminForwarder adm;

    function setUp() public {
        vm.warp(1_800_000_000);
        alice = vm.addr(PK);
        usdc = new MockERC20("USD Coin", "USDC", 6);
        usdt = new MockERC20("Tether", "USDT", 6);
        dai = new MockERC20("Dai", "DAI", 18);
        adm = new RateAdminForwarder();
        t = _three(_fixedRate());
    }

    function _three(Rate memory cfg) internal returns (UnderlyingToken) {
        address[] memory us = new address[](3);
        (us[0], us[1], us[2]) = (address(usdc), address(usdt), address(dai));
        uint256[] memory nums = new uint256[](3);
        (nums[0], nums[1], nums[2]) = (1e12, 1e12, 1);
        uint256[] memory dens = new uint256[](3);
        (dens[0], dens[1], dens[2]) = (1, 1, 1);
        return _multi(us, nums, dens, cfg, guardian);
    }

    function _wrap(UnderlyingToken m, MockERC20 u, address who, uint256 v) internal returns (uint256 minted) {
        u.mint(who, v);
        vm.startPrank(who);
        u.approve(address(m), v);
        minted = m.wrap(address(u), v);
        vm.stopPrank();
    }

    function test_kindAndLegs() public view {
        assertEq(t.kind(), AdminLib.KIND_UNDERLYING); // D9: every leg count
        assertEq(t.underlying(), address(0));
        address[] memory us = t.underlyings();
        assertEq(us.length, 3);
        assertEq(us[1], address(usdt));
        assertTrue(t.hasRole(4, guardian));
        (uint96 num,,, uint8 d,) = t.legOf(address(usdc));
        assertEq(num, 1e12);
        assertEq(d, 6);
    }

    function test_anyOfWrapOneUnwrapAnother() public {
        assertEq(_wrap(t, usdc, alice, 100e6), 100e18);
        assertEq(_wrap(t, dai, bob, 50e18), 50e18);
        vm.prank(alice);
        (uint256 out, uint256 burned) = t.unwrap(address(dai), 30e18, alice, 30e18);
        assertEq(out, 30e18);
        assertEq(burned, 30e18);
        assertEq(dai.balanceOf(alice), 30e18);
        (,, uint256 rc,,) = t.legOf(address(usdc));
        (,, uint256 rd,,) = t.legOf(address(dai));
        assertEq(rc, 100e6);
        assertEq(rd, 20e18);
        assertEq(t.collateralValue(), 120e18);
        assertEq(t.totalSupply(), 120e18);
    }

    function test_unwrapBoundedByTheLegReserve() public {
        _wrap(t, usdc, alice, 100e6);
        _wrap(t, usdt, alice, 10e6);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.InsufficientReserve.selector,
            address(usdt), 11e6, 10e6));
        t.unwrap(address(usdt), 11e18, alice, 0);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.UnknownUnderlying.selector, bob));
        t.unwrap(bob, 1, alice, 0);
    }

    function test_initRefusals() public {
        address[] memory one = new address[](1);
        one[0] = address(usdc);
        uint256[] memory n1 = new uint256[](1);
        n1[0] = 1;
        // D9: one leg is a valid token (the single-asset ABI works)
        assertEq(UnderlyingToken(this.multiExt(one, n1, n1)).underlying(), address(usdc));
        address[] memory nine = new address[](9);
        uint256[] memory n9 = new uint256[](9);
        for (uint256 i; i < 9; ++i) {
            nine[i] = address(new MockERC20("X", "X", 6));
            n9[i] = 1;
        }
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 9));
        this.multiExt(nine, n9, n9);
        address[] memory eight = new address[](8);
        uint256[] memory n8 = new uint256[](8);
        for (uint256 i; i < 8; ++i) (eight[i], n8[i]) = (nine[i], 1);
        assertEq(UnderlyingToken(this.multiExt(eight, n8, n8)).underlyings().length, 8);
        address[] memory dup = new address[](2);
        (dup[0], dup[1]) = (address(usdc), address(usdc));
        uint256[] memory n2 = new uint256[](2);
        (n2[0], n2[1]) = (1, 1);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.DuplicateUnderlying.selector, address(usdc)));
        this.multiExt(dup, n2, n2);
        dup[1] = address(usdt);
        n2[1] = 0;
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.RateInvalid.selector, 0, 1));
        this.multiExt(dup, n2, _ones(2));
    }

    function _ones(uint256 n) internal pure returns (uint256[] memory a) {
        a = new uint256[](n);
        for (uint256 i; i < n; ++i) a[i] = 1;
    }

    function multiExt(address[] memory us, uint256[] memory nums, uint256[] memory dens) external returns (address) {
        return address(_multi(us, nums, dens, _fixedRate(), address(0)));
    }

    function test_inheritedSingleAssetAbiReverts() public {
        bytes4 e = IUnderlyingToken.UnderlyingRequired.selector;
        vm.expectRevert(e);
        t.wrap(1);
        vm.expectRevert(e);
        t.unwrap(1, alice);
        vm.expectRevert(e);
        t.unwrap(1, alice, 0);
    }

    // ------------------------------------------------------------------ guardian

    function test_guardianDisablesWrapOneWay() public {
        _wrap(t, usdt, alice, 10e6);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdt), "depeg");
        vm.expectEmit(address(t));
        emit IUnderlyingToken.WrapDisabled(address(usdt), guardian, "depeg");
        vm.prank(guardian);
        t.disableWrap(address(usdt), "depeg");
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(usdt)));
        t.disableWrap(address(usdt), "again");
        (,,,, bool enabled) = t.legOf(address(usdt));
        assertFalse(enabled);
        // inflow refused, exit open
        usdt.mint(alice, 1e6);
        vm.startPrank(alice);
        usdt.approve(address(t), 1e6);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(usdt)));
        t.wrap(address(usdt), 1e6);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapDisabledFor.selector, address(usdt)));
        t.addReserve(address(usdt), 1e6);
        t.unwrap(address(usdt), 4e18, alice, 4e6);
        vm.stopPrank();
        assertEq(usdt.balanceOf(alice), 5e6);
    }

    function test_gaslessUnwrapWorksOnADisabledLeg() public {
        _wrap(t, usdt, alice, 10e6);
        vm.prank(guardian);
        t.disableWrap(address(usdt), "depeg");
        bytes memory d = abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(usdt), 3e18, bob, 3e6);
        _execCall(PK, address(t), _call(alice, d, 1, RR));
        assertEq(usdt.balanceOf(bob), 3e6);
    }

    function test_renounceGuardian() public {
        vm.expectEmit(address(t));
        emit ITokenAdmin.RoleRevoked(4, guardian, guardian);
        vm.prank(guardian);
        t.renounceRole(4);
        assertFalse(t.hasRole(4, guardian));
        vm.prank(guardian);
        vm.expectRevert(IUnderlyingToken.NotGuardian.selector);
        t.disableWrap(address(usdc), "x");
        vm.prank(guardian);
        vm.expectRevert(abi.encodeWithSelector(ITokenAdmin.MissingRole.selector, uint8(4), guardian));
        t.renounceRole(4);
    }

    // ------------------------------------------------------------------ rates (R147)

    function test_rateDecreaseRefusedWhileAnyLegIsDisabled() public {
        UnderlyingToken a = _three(_adjustable(address(adm)));
        _wrap(a, usdc, alice, 100e6);
        _wrap(a, dai, alice, 100e18);
        usdc.mint(address(this), 10e6);
        usdc.approve(address(a), 10e6);
        a.addReserve(address(usdc), 10e6); // collateral for the decrease
        vm.prank(guardian);
        a.disableWrap(address(usdt), "depeg");
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.proposeRate, (address(usdc), 99e10, 1)));
        vm.warp(block.timestamp + 7 days);
        vm.expectRevert(IUnderlyingToken.RateDecreaseWithDisabledLeg.selector);
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.executeRate, ()));
        // a raise is fine
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.cancelRate, ()));
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.proposeRate, (address(usdc), 101e10, 1)));
        vm.warp(block.timestamp + 7 days);
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.executeRate, ()));
    }

    /// Review H1: thay đổi đang chờ (hạ leg i) ⇒ flash-wrap leg j bị dừng; bên thứ ba không thực thi được.
    function test_h1PendingChangePausesEveryLegAndOnlyTheAdminExecutes() public {
        UnderlyingToken a = _three(_adjustable(address(adm)));
        _wrap(a, usdc, alice, 100e6);
        _wrap(a, dai, alice, 100e18);
        adm.exec(address(a), abi.encodeCall(UnderlyingToken.proposeRate, (address(usdc), 99e10, 1)));
        dai.mint(bob, 1_000e18);
        vm.startPrank(bob);
        dai.approve(address(a), 1_000e18);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapPausedForRateChange.selector, address(dai)));
        a.wrap(address(dai), 1_000e18);
        vm.stopPrank();
        vm.warp(block.timestamp + 7 days);
        vm.prank(bob);
        vm.expectRevert(IUnderlyingToken.NotRateAdmin.selector);
        a.executeRate();
        // unwrap stays open on every leg during the change
        vm.prank(alice);
        a.unwrap(address(usdc), 1e18, alice, 1e6);
    }

    function test_allowanceOnlyBetweenContracts() public {
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.approve(address(this), 1);
    }

    MockERC20 fa;
    MockERC20 fb;

    function _pair(uint256[4] memory r) internal returns (UnderlyingToken m) {
        fa = new MockERC20("A", "A", 6);
        fb = new MockERC20("B", "B", 6);
        address[] memory us = new address[](2);
        (us[0], us[1]) = (address(fa), address(fb));
        uint256[] memory nums = new uint256[](2);
        (nums[0], nums[1]) = (r[0], r[1]);
        uint256[] memory dens = new uint256[](2);
        (dens[0], dens[1]) = (r[2], r[3]);
        m = _multi(us, nums, dens, _fixedRate(), address(0));
        // deep reserve on leg j from someone else
        _wrap(m, fb, bob, 1e60);
    }

    /// Ở tỉ lệ danh nghĩa (par), wrap chân i rồi unwrap chân j không bao giờ lời: `out_j·q_j ≤ in_i·q_i`.
    function testFuzz_wrapIUnwrapJNeverProfitsAtPar(uint256 amount, uint96 qi, uint96 qj, uint96 di, uint96 dj)
        public
    {
        uint256[4] memory r = [bound(qi, 1, 1e12), bound(qj, 1, 1e12), bound(di, 1, 1e12), bound(dj, 1, 1e12)];
        UnderlyingToken m = _pair(r);
        amount = bound(amount, 1, 1e24);
        (uint256 minted,) = m.previewWrap(address(fa), amount);
        vm.assume(minted > 0);
        _wrap(m, fa, alice, amount);
        (uint256 out,) = m.previewUnwrap(address(fb), minted);
        vm.assume(out > 0 && out <= 1e60);
        vm.prank(alice);
        m.unwrap(address(fb), minted, alice, 0);
        // value in wrapped units, cross-multiplied: out·num_j/den_j ≤ amount·num_i/den_i
        assertLe(out * r[1] * r[2], amount * r[0] * r[3]);
        assertGe(m.collateralValue(), m.totalSupply());
    }
}
