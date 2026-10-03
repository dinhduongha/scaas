// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Fixtures} from "./helpers/Fixtures.sol";
import {Puller, ConstructorPuller} from "./helpers/WalletMocks.sol";
import {MetaToken} from "../src/metatx/MetaToken.sol";
import {IERC20MetaTx} from "../src/metatx/IERC20MetaTx.sol";

/// R26: allowance chỉ tồn tại giữa hợp đồng. EOA không bao giờ là spender, và chỉ hợp đồng
/// gọi được `transferFrom`. EOA đã uỷ quyền EIP-7702 vẫn là EOA; hợp đồng đang chạy
/// constructor bị coi là EOA (code rỗng) — đó là hệ quả được chấp nhận, không phải lỗi.
contract ContractOnlyAllowanceTest is Fixtures {
    MetaToken internal t;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    Puller internal puller;

    function setUp() public {
        _deployFactory();
        t = _standalone(address(this), "ZVND", 0, 1_000_000, address(this));
        t.transfer(alice, 1000);
        puller = new Puller();
    }

    function test_approve_to_eoa_reverts() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
    }

    function test_approve_to_counterfactual_address_reverts() public {
        address future = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, future));
        t.approve(future, 1);
    }

    function test_contract_spender_pulls() public {
        vm.prank(alice);
        assertTrue(t.approve(address(puller), 300));
        puller.pull(address(t), alice, bob, 300);
        assertEq(t.balanceOf(bob), 300);
        assertEq(t.allowance(alice, address(puller)), 0);
    }

    function test_contract_can_approve_contract() public {
        t.transfer(address(puller), 50);
        Puller other = new Puller();
        puller.approveOn(address(t), address(other), 50);
        other.pull(address(t), address(puller), bob, 50);
        assertEq(t.balanceOf(bob), 50);
    }

    function test_eoa_cannot_call_transferFrom() public {
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.transferFrom(alice, bob, 0);
    }

    function test_7702_delegated_eoa_is_an_eoa() public {
        // Designator EIP-7702: 0xef0100 ‖ địa chỉ delegate (23 byte).
        vm.etch(bob, abi.encodePacked(hex"ef0100", address(puller)));
        assertEq(bob.code.length, 23);
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.SpenderNotContract.selector, bob));
        t.approve(bob, 1);
        vm.prank(bob);
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, bob));
        t.transferFrom(alice, bob, 0);
    }

    function test_23_byte_contract_that_is_not_a_designator_is_a_contract() public {
        address c = address(0xC0DE);
        vm.etch(c, abi.encodePacked(hex"ef0200", address(puller)));
        vm.prank(alice);
        assertTrue(t.approve(c, 1));
    }

    function test_constructor_cannot_spend() public {
        address future = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectRevert(abi.encodeWithSelector(IERC20MetaTx.CallerNotContract.selector, future));
        new ConstructorPuller(address(t), alice, 1);
    }
}
