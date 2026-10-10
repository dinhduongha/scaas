// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {V2Fixture} from "./helpers/V2Fixture.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IERC20MetaTxV1} from "../../src/metatx/IERC20MetaTxV1.sol";
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

    function test_initRefusesUnderlyings() public {
        noneImpl = address(new NoUnderlyingToken(address(this), address(0)));
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
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTxV1.CallerNotContract.selector, bob));
        t.transferFrom(address(this), bob, 0);
    }

    function test_unwrapOpIsUnknownOnTier1() public {
        uint256 pk = 0xA11CE;
        NoUnderlyingToken t = _none(vm.addr(pk), 100, address(0));
        MetaTxLib.LegacyMetaTransaction memory m = _mt(vm.addr(pk), bob, 1, _unwrapData(address(1), bob, 0), 1, RR);
        bytes memory s = _sig(pk, address(t), m);
        bytes4 op = t.OP_UNWRAP();
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(MetaTokenBase.MetaTxUnknownOp.selector, op));
        t.executeMetaTransaction(m, s);
    }
}
