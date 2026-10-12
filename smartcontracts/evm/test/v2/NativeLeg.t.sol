// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Errors} from "@openzeppelin/contracts/utils/Errors.sol";
import {V2Fixture, UID_, Rate, underlyingInit} from "./helpers/V2Fixture.sol";
import {RateAdminForwarder} from "./helpers/V2Mocks.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {IUnderlyingToken} from "../../src/metatx/IUnderlyingToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// Has no `receive`: refuses the native coin.
contract CoinRefuser {}

/// Re-enters the token from `receive` (unwrap to itself again).
contract CoinReenterer {
    UnderlyingToken public t;
    function arm(UnderlyingToken t_) external { t = t_; }
    receive() external payable {
        t.unwrap(1, address(this), 0);
    }
}

/// The native-coin leg (CTR-TOK-26): `address(0)`, payable wrap with `msg.value == amount`, CEI payout with all gas,
/// balance mechanics on `address(this).balance`, forced coin is not reserve, no gasless native wrap.
contract NativeLegTest is V2Fixture {
    uint256 constant ALICE_PK = 0xA11CE;
    address alice = vm.addr(ALICE_PK);
    address bob = address(0xB0B);
    MockERC20 usdc = new MockERC20("USD Coin", "USDC", 6);

    function initExt(address[] memory us, bytes memory d) external returns (address) {
        return _clone(_underlyingImpl(), address(this), us, d);
    }

    /// One native leg at 1:1, 18 decimals, rates fixed.
    function _native() internal returns (UnderlyingToken) {
        return _single(address(0), 18, 1, 1, _fixedRate());
    }

    function _wrapNative(UnderlyingToken t, address who, uint256 v) internal {
        vm.deal(who, v);
        vm.prank(who);
        t.wrap{value: v}(v);
    }

    function test_native_wrapAndUnwrap() public {
        UnderlyingToken t = _native();
        assertEq(t.underlying(), address(0));
        (,,, uint8 dec,) = t.legOf(address(0));
        assertEq(dec, 18);
        vm.deal(alice, 3 ether);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.Wrapped(alice, address(0), 3 ether, 3 ether);
        vm.prank(alice);
        assertEq(t.wrap{value: 3 ether}(3 ether), 3 ether);
        assertEq(t.balanceOf(alice), 3 ether);
        assertEq(address(t).balance, 3 ether);
        assertEq(t.collateralValue(), 3 ether);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.Unwrapped(alice, address(0), bob, 1 ether, 1 ether);
        vm.prank(alice);
        assertEq(t.unwrap(1 ether, bob, 1 ether), 1 ether);
        assertEq(bob.balance, 1 ether);
        (,, uint256 reserve,,) = t.legOf(address(0));
        assertEq(reserve, 2 ether);
        assertEq(t.totalSupply(), 2 ether);
    }

    function test_native_valueMustMatch() public {
        UnderlyingToken t = _native();
        vm.deal(alice, 2 ether);
        vm.startPrank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 1 ether, 2 ether));
        t.wrap{value: 1 ether}(2 ether);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 0, 1 ether));
        t.addReserve(address(0), 1 ether);
        vm.stopPrank();
    }

    function test_native_erc20LegRefusesValue() public {
        address[] memory us = new address[](2);
        (us[0], us[1]) = (address(usdc), address(0));
        uint256[] memory one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
        UnderlyingToken t = _multi(us, one, one, _fixedRate(), address(0));
        usdc.mint(alice, 5);
        vm.deal(alice, 1);
        vm.startPrank(alice);
        usdc.approve(address(t), 5);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 1, 0));
        t.wrap{value: 1}(address(usdc), 5);
        t.wrap(address(usdc), 5);
        t.wrap{value: 1}(address(0), 1);
        vm.stopPrank();
        assertEq(t.collateralValue(), 6);
    }

    function test_native_atMostOneLeg() public {
        address[] memory us = new address[](2);
        uint256[] memory one = new uint256[](2);
        (one[0], one[1]) = (1, 1);
        Rate memory fixedRate;
        bytes memory d = abi.encode(underlyingInit(us, one, one, 18, fixedRate, address(0), address(0)));
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.DuplicateUnderlying.selector, address(0)));
        this.initExt(us, d);
    }

    function test_native_forcedCoinIsNotReserve() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 1 ether);
        vm.deal(address(t), 5 ether); // selfdestruct / block reward
        (,, uint256 reserve,,) = t.legOf(address(0));
        assertEq(reserve, 1 ether);
        assertEq(t.collateralValue(), 1 ether);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.InsufficientReserve.selector, address(0), 2 ether,
            1 ether));
        t.unwrap(2 ether, alice, 0);
        _wrapNative(t, bob, 1 ether); // the surplus does not stop a wrap
        assertEq(t.balanceOf(bob), 1 ether);
    }

    function test_native_shortfallStopsWrapNotUnwrap() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 2 ether);
        vm.deal(address(t), 1 ether); // the balance fell below the reserve
        vm.deal(bob, 1 ether);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.ReserveShortfall.selector, address(0), 1 ether,
            2 ether));
        t.wrap{value: 1 ether}(1 ether);
        vm.prank(alice);
        t.unwrap(1 ether, alice, 0);
        assertEq(alice.balance, 1 ether);
    }

    function test_native_addReserveIsPayable() public {
        UnderlyingToken t = _native();
        vm.deal(bob, 1 ether);
        vm.expectEmit(address(t));
        emit IUnderlyingToken.ReserveAdded(bob, address(0), 1 ether);
        vm.prank(bob);
        t.addReserve{value: 1 ether}(address(0), 1 ether);
        assertEq(t.collateralValue(), 1 ether);
        assertEq(t.totalSupply(), 0);
    }

    function test_native_refusingRecipientRevertsTheUnwrap() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 1 ether);
        address r = address(new CoinRefuser());
        vm.prank(alice);
        vm.expectRevert(Errors.FailedCall.selector);
        t.unwrap(1 ether, r, 0);
        assertEq(t.balanceOf(alice), 1 ether); // nothing burned
    }

    function test_native_reentrantRecipientIsBlocked() public {
        UnderlyingToken t = _native();
        CoinReenterer r = new CoinReenterer();
        r.arm(t);
        _wrapNative(t, address(r), 2 ether);
        vm.prank(address(r));
        vm.expectRevert(IMetaTx.Reentrancy.selector);
        t.unwrap(1 ether, address(r), 0);
    }

    function test_native_contractRecipientGetsAllGas() public {
        UnderlyingToken t = _native();
        _wrapNative(t, alice, 1 ether);
        GasHungry g = new GasHungry();
        vm.prank(alice);
        t.unwrap(1 ether, address(g), 0);
        assertEq(address(g).balance, 1 ether);
    }

    function test_native_noGaslessWrap_gaslessUnwrapWorks() public {
        UnderlyingToken t = _native();
        MetaTxLib.MetaTransaction memory m = _call(alice, abi.encodeWithSignature("wrap(uint256)", 1 ether), 1, RR);
        bytes memory sig = _signCall(ALICE_PK, address(t), m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.NativeValueMismatch.selector, 0, 1 ether));
        t.mtxExecute(m, sig);
        _wrapNative(t, alice, 1 ether);
        m = _call(alice, abi.encodeWithSignature("unwrap(uint256,address,uint256)", 1 ether, bob, 1 ether), 1, RR);
        _execCall(ALICE_PK, address(t), m);
        assertEq(bob.balance, 1 ether);
    }

    function test_native_executeRateChecksTheCoinBalance() public {
        RateAdminForwarder adm = new RateAdminForwarder();
        UnderlyingToken t = _single(address(0), 18, 1, 1, _adjustable(address(adm)));
        _wrapNative(t, alice, 1 ether);
        adm.exec(address(t), abi.encodeCall(t.proposeRate, (address(0), 101, 100)));
        vm.warp(block.timestamp + 7 days);
        vm.deal(address(t), 0.5 ether);
        vm.expectRevert(abi.encodeWithSelector(IUnderlyingToken.ReserveShortfall.selector, address(0), 0.5 ether,
            1 ether));
        adm.exec(address(t), abi.encodeCall(t.executeRate, ()));
        vm.deal(address(t), 1 ether);
        adm.exec(address(t), abi.encodeCall(t.executeRate, ()));
        (uint96 n, uint96 d,,,) = t.legOf(address(0));
        assertEq(abi.encode(n, d), abi.encode(uint96(101), uint96(100)));
    }

    function test_native_decimalsOnHederaAre8() public {
        UnderlyingToken h = UnderlyingToken(_clone(address(new UnderlyingToken(address(this), address(0), UID_, true)),
            address(this), _one(address(0)), _singleInit(address(0), 8, 1, 1, _fixedRate())));
        (,,, uint8 dec,) = h.legOf(address(0));
        assertEq(dec, 8);
    }
}

/// Burns 100k gas on receipt: more than a 2,300 stipend.
contract GasHungry {
    receive() external payable {
        uint256 g = gasleft();
        while (g - gasleft() < 100_000) {}
    }
}
