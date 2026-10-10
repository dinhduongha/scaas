// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {V2Fixture, Rate} from "./helpers/V2Fixture.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {SlashableERC20, RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {ITokenAdmin} from "../../src/metatx/ITokenAdmin.sol";

/// T2: tỉ lệ cố định / điều chỉnh được, timelock, chỉ admin thực thi, tạm dừng wrap (TW2 §6, R135, R147).
contract RatesTest is V2Fixture {
    SlashableERC20 usdc;
    RateAdminForwarder adm;
    UnderlyingToken t;
    address alice = address(0xA11CE);

    function setUp() public {
        vm.warp(1_800_000_000);
        usdc = new SlashableERC20(6);
        adm = new RateAdminForwarder();
        t = _single(address(usdc), 6, 1, 1, _adjustable(address(adm)));
        _wrap(alice, 100);
    }

    function _wrap(address who, uint256 v) internal {
        usdc.mint(who, v);
        vm.startPrank(who);
        usdc.approve(address(t), v);
        t.wrap(v);
        vm.stopPrank();
    }

    function _admin(bytes memory call) internal {
        adm.exec(address(t), call);
    }

    function _propose(uint96 num, uint96 den) internal {
        _admin(abi.encodeCall(UnderlyingToken.proposeRate, (address(usdc), num, den)));
    }

    function _execute() internal {
        _admin(abi.encodeCall(UnderlyingToken.executeRate, ()));
    }

    function test_fixedRateHasNoSetters() public {
        UnderlyingToken f = _single(address(usdc), 6, 1, 1, _fixedRate());
        bytes4 e = IUnderlyingToken.RateFixed.selector;
        vm.expectRevert(e);
        f.proposeRate(address(usdc), 1, 1);
        vm.expectRevert(e);
        f.cancelRate();
        vm.expectRevert(e);
        f.executeRate();
    }

    function test_proposeExecuteLifecycle() public {
        uint64 eta = uint64(block.timestamp + 7 days);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.RateChangeProposed(address(usdc), 1, 1, 101, 100, eta);
        _propose(101, 100);
        (address u, uint96 n, uint96 d, uint64 e) = t.pendingRate();
        assertEq(u, address(usdc));
        assertEq(n, 101);
        assertEq(d, 100);
        assertEq(e, eta);
        vm.warp(eta);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.RateChanged(address(usdc), 1, 1, 101, 100);
        _execute();
        (uint96 num, uint96 den,,,) = t.legOf(address(usdc));
        assertEq(num, 101);
        assertEq(den, 100);
        (u,,, e) = t.pendingRate();
        assertEq(u, address(0));
        assertEq(e, 0);
        assertEq(t.balanceOf(alice), 100); // balances never change
    }

    function test_onlyTheAdminProposesCancelsExecutes() public {
        bytes4 e = IUnderlyingToken.NotRateAdmin.selector;
        vm.expectRevert(e);
        t.proposeRate(address(usdc), 101, 100);
        _propose(101, 100);
        vm.warp(block.timestamp + 7 days);
        vm.prank(alice);
        vm.expectRevert(e);
        t.executeRate();
        vm.expectRevert(e);
        t.cancelRate();
    }

    function test_onePendingChangeAndCancel() public {
        _propose(101, 100);
        vm.expectRevert(IUnderlyingToken.RateChangePending.selector);
        _propose(100, 101);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.RateChangeCancelled(address(usdc));
        _admin(abi.encodeCall(UnderlyingToken.cancelRate, ()));
        vm.expectRevert(IUnderlyingToken.NoRateChangePending.selector);
        _admin(abi.encodeCall(UnderlyingToken.cancelRate, ()));
        vm.expectRevert(IUnderlyingToken.NoRateChangePending.selector);
        _execute();
        _propose(100, 101);
    }

    function test_delayAndWindowBounds() public {
        _propose(101, 100);
        (,,, uint64 eta) = t.pendingRate();
        vm.warp(eta - 1);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.RateChangeNotReady.selector, eta));
        _execute();
        vm.warp(eta + 7 days + 1);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.RateChangeExpired.selector, eta));
        _execute();
        vm.warp(eta + 7 days); // window is inclusive
        _execute();
    }

    function test_expiredChangeCountsAsNone() public {
        _propose(101, 100);
        (,,, uint64 eta) = t.pendingRate();
        vm.warp(eta + 7 days + 1);
        (address u,,, uint64 e) = t.pendingRate();
        assertEq(u, address(0));
        assertEq(e, 0);
        _wrap(alice, 1); // not paused
        vm.expectRevert(IUnderlyingToken.NoRateChangePending.selector);
        _admin(abi.encodeCall(UnderlyingToken.cancelRate, ()));
        _propose(100, 101); // a new one is allowed
    }

    function test_stepBoundExactEdgeBothDirections() public {
        // 1 % at 1:1. |num'·den − num·den'|·10⁴ ≤ num·den'·bps
        vm.expectRevert(IUnderlyingToken.RateStepTooLarge.selector);
        _propose(10_101, 10_000);
        vm.expectRevert(IUnderlyingToken.RateStepTooLarge.selector);
        _propose(9_899, 10_000);
        _propose(101, 100);
        _admin(abi.encodeCall(UnderlyingToken.cancelRate, ()));
        _propose(99, 100);
        _admin(abi.encodeCall(UnderlyingToken.cancelRate, ()));
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.RateInvalid.selector, 0, 1));
        _propose(0, 1);
    }

    function test_decreaseNeedsCollateral() public {
        // lower q: each unit redeems more; C' = ⌊100·99/100⌋ = 99 < 100
        _propose(99, 100);
        vm.warp(block.timestamp + 7 days);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.RateChangeUndercollateralized.selector, 99, 100));
        _execute();
        usdc.mint(address(this), 2);
        usdc.approve(address(t), 2);
        t.addReserve(address(usdc), 2); // open while pending
        _execute();
        assertGe(t.collateralValue(), t.totalSupply());
    }

    /// M1: phantom reserve. Sốc âm trước, rồi một lần hạ tỉ lệ đã được "cấp vốn" trên sổ — bị từ chối.
    function test_executeRefusesShortfallOnAnyLeg() public {
        usdc.mint(address(this), 10);
        usdc.approve(address(t), 10);
        t.addReserve(address(usdc), 10);
        _propose(99, 100);
        usdc.slash(address(t), 5);
        vm.warp(block.timestamp + 7 days);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.ReserveShortfall.selector, address(usdc), 105, 110));
        _execute();
    }

    /// L1: `collateralValue` bão hoà thay vì tràn; `executeRate` không bị DoS bởi một chân khổng lồ.
    function test_collateralValueSaturatesAndExecuteSurvives() public {
        UnderlyingToken big = _single(address(usdc), 6, type(uint96).max, 1, _adjustable(address(adm)));
        usdc.mint(address(this), 1 << 200);
        usdc.approve(address(big), 1 << 200);
        big.addReserve(address(usdc), 1 << 200);
        assertEq(big.collateralValue(), type(uint256).max);
        usdc.mint(address(this), 1);
        usdc.approve(address(big), 1);
        big.wrap(1); // supply > 0, so execute must evaluate the huge leg
        adm.exec(address(big), abi.encodeCall(UnderlyingToken.proposeRate,
            (address(usdc), type(uint96).max - 1, 1)));
        vm.warp(block.timestamp + 7 days);
        adm.exec(address(big), abi.encodeCall(UnderlyingToken.executeRate, ()));
    }

    /// D4/D5 (CTR-TOK-06): renouncing the role leaves the rate and the pending change; `disableFeature` cancels it.
    function test_renounceRoleKeepsThePendingChange_disableFeatureCancelsIt() public {
        _propose(101, 100);
        vm.expectEmit(address(t));
        emit ITokenAdmin.RoleRevoked(3, address(adm), address(adm));
        _admin(abi.encodeCall(ITokenAdmin.renounceRole, (3)));
        assertFalse(t.hasRole(3, address(adm)));
        assertTrue(t.rateAdjustable());
        (address u,,,) = t.pendingRate();
        assertEq(u, address(usdc));
        vm.expectRevert(IUnderlyingToken.NotRateAdmin.selector);
        _propose(100, 101);
        vm.prank(wrapperOwner);
        t.disableFeature(3);
        (address u2, uint96 n, uint96 d, uint64 eta) = t.pendingRate();
        assertEq(u2, address(0));
        assertEq(n, 0);
        assertEq(d, 0);
        assertEq(eta, 0);
        assertFalse(t.rateAdjustable());
        _wrap(alice, 1);
    }

    /// R135/R147: không ai wrap được ở một tỉ lệ sắp đổi; unwrap và addReserve vẫn mở.
    function test_wrapPausedWhilePendingReopensAfter() public {
        _propose(101, 100);
        usdc.mint(alice, 10);
        vm.prank(alice);
        usdc.approve(address(t), 10);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.WrapPausedForRateChange.selector, address(usdc)));
        t.wrap(10);
        vm.prank(alice);
        t.unwrap(10, alice, 10);
        usdc.mint(address(this), 1);
        usdc.approve(address(t), 1);
        t.addReserve(address(usdc), 1);
        // cancel reopens
        _admin(abi.encodeCall(UnderlyingToken.cancelRate, ()));
        _wrap(alice, 1);
        // execute reopens
        _propose(101, 100);
        vm.warp(block.timestamp + 7 days);
        _execute();
        _wrap(alice, 1);
    }

    /// Biên bước, so với tham chiếu 512 bit (`Math.mul512`).
    function testFuzz_stepBoundExact(uint96 n0, uint96 d0, uint96 n1, uint96 d1, uint16 bps) public {
        uint256 m = type(uint96).max;
        uint256[5] memory v = [bound(n0, 1, m), bound(d0, 1, m), bound(n1, 1, m), bound(d1, 1, m), bound(bps, 1, 1000)];
        Rate memory c = _adjustable(address(adm));
        c.maxRateStepBps = uint16(v[4]);
        UnderlyingToken s = _single(address(usdc), 6, v[0], v[1], c);
        if (!_withinRef(v[0], v[1], v[2], v[3], v[4])) vm.expectRevert(IUnderlyingToken.RateStepTooLarge.selector);
        adm.exec(address(s), abi.encodeCall(UnderlyingToken.proposeRate, (address(usdc), uint96(v[2]), uint96(v[3]))));
    }

    function _withinRef(uint256 n0, uint256 d0, uint256 n1, uint256 d1, uint256 bps) internal pure returns (bool) {
        (uint256 aHi, uint256 aLo) = Math.mul512(n1, d0);
        (uint256 bHi, uint256 bLo) = Math.mul512(n0, d1);
        assertTrue(aHi == 0 && bHi == 0); // uint96 inputs: both products < 2^192
        uint256 diff = aLo > bLo ? aLo - bLo : bLo - aLo;
        (uint256 lHi, uint256 lLo) = Math.mul512(diff, 10_000);
        (aHi, aLo) = Math.mul512(bLo, bps);
        return lHi < aHi || (lHi == aHi && lLo <= aLo);
    }
}
