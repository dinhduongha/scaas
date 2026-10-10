// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {V2Fixture, UID_} from "./helpers/V2Fixture.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IOpenFactoryV2} from "../../src/common/IOpenFactoryV2.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";

/// T2: tầng 1 `NoUnderlyingToken` (TW2 §4, R141).
contract Tier1Test is V2Fixture {
    address minter = address(0x111);
    address bob = address(0xB0B);

    function setUp() public {
        vm.warp(1_800_000_000);
    }

    function test_initMintsToCreatorAndStoresMinter() public {
        NoUnderlyingToken t = _none(address(this), 500, minter);
        assertEq(t.balanceOf(address(this)), 500);
        assertEq(t.totalSupply(), 500);
        assertEq(t.minter(), minter);
        assertEq(t.decimals(), 0);
        assertEq(uint8(t.tokenKind()), uint8(IOpenFactoryV2.TokenKind.META_NONE));
    }

    function test_onlyMinterMints() public {
        NoUnderlyingToken t = _none(address(this), 0, minter);
        vm.prank(minter);
        t.mint(bob, 7);
        assertEq(t.balanceOf(bob), 7);
        vm.prank(bob);
        vm.expectRevert(NoUnderlyingToken.NotMinter.selector);
        t.mint(bob, 1);
    }

    function test_zeroMinterMeansFixedSupply() public {
        NoUnderlyingToken t = _none(address(this), 100, address(0));
        vm.prank(address(0));
        vm.expectRevert(NoUnderlyingToken.NotMinter.selector);
        t.mint(bob, 1);
        vm.expectRevert(NoUnderlyingToken.NotMinter.selector);
        t.renounceMinter();
    }

    function test_renounceMinterIsOneWay() public {
        NoUnderlyingToken t = _none(address(this), 0, minter);
        vm.expectEmit(address(t));
        emit NoUnderlyingToken.MinterRenounced();
        vm.prank(minter);
        t.renounceMinter();
        assertEq(t.minter(), address(0));
        vm.prank(minter);
        vm.expectRevert(NoUnderlyingToken.NotMinter.selector);
        t.mint(bob, 1);
    }

    function test_holderBurnsOwnBalance() public {
        NoUnderlyingToken t = _none(address(this), 100, address(0));
        vm.expectEmit(address(t));
        emit IERC20.Transfer(address(this), address(0), 40);
        t.burn(40);
        assertEq(t.totalSupply(), 60);
        assertEq(t.balanceOf(address(this)), 60);
    }

    /// `burn(uint256)` is allowlisted `AMOUNT(0)`: the fee is on the burned amount, taken after the burn.
    function test_gaslessBurnPaysAmountFee() public {
        uint256 pk = 0xA11CE;
        address alice = vm.addr(pk);
        address feeTaker = address(0xFEE);
        NoUnderlyingToken t = _none(alice, 1_000e6, address(0));
        MetaTxLib.MetaTransaction memory m = _call(alice, abi.encodeCall(t.burn, (100e6)), 1, RR | RF | PCT);
        m.fee = 10_000; // 1 %
        m.feeRecipient = feeTaker;
        vm.expectEmit(address(t));
        emit IERC20.Transfer(alice, address(0), 100e6);
        vm.expectEmit(address(t));
        emit IERC20.Transfer(alice, feeTaker, 1e6);
        _execCall(pk, address(t), m);
        assertEq(t.totalSupply(), 900e6);
        assertEq(t.balanceOf(alice), 899e6);
        assertEq(t.balanceOf(feeTaker), 1e6);
        assertEq(t.mtxNonce(alice, 1), 1);
    }

    function test_initRefusesUnderlyings() public {
        noneImpl = address(new NoUnderlyingToken(address(this), address(0), UID_));
        address[] memory us = new address[](1);
        us[0] = address(0x1234);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.UnderlyingCountInvalid.selector, 1));
        this.cloneExt(noneImpl, us, abi.encode("P", "P", uint8(0), uint256(0), address(0)));
    }

    function cloneExt(address impl, address[] memory us, bytes memory d) external returns (address) {
        return _clone(impl, address(this), us, d);
    }

    function test_allowanceOnlyBetweenContracts() public {
        NoUnderlyingToken t = _none(address(this), 100, address(0));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.approve(address(this), 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.transferFrom(address(this), bob, 0);
    }

    /// An EOA with an EIP-7702 designator (`0xef0100 ‖ addr`) has code but is not a contract here (CTR-TOK-01).
    function test_allowance_7702DelegatedEoaRefused() public {
        NoUnderlyingToken t = _none(address(this), 100, address(0));
        vm.etch(bob, abi.encodePacked(hex"ef0100", address(this)));
        assertEq(bob.code.length, 23);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.approve(address(this), 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.transferFrom(address(this), bob, 0);
    }

    function test_unwrapIsNotListedOnTier1() public {
        uint256 pk = 0xA11CE;
        NoUnderlyingToken t = _none(vm.addr(pk), 100, address(0));
        bytes4 sel = bytes4(keccak256("unwrap(uint256,address,uint256)"));
        MetaTxLib.MetaTransaction memory m = _call(vm.addr(pk), abi.encodeWithSelector(sel, 1, bob, 0), 1, RR);
        bytes memory s = _signCall(pk, address(t), m);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxSelectorNotAllowed.selector, sel));
        t.mtxExecute(m, s);
    }
}
