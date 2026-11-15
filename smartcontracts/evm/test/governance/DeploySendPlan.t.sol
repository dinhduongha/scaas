// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeploySend} from "../../script/DeploySend.s.sol";

/// `DeploySend.plan` (NET-EVM-11): the send plan's four arrays read in four calls; a CREATE (zero `to`), another sender,
/// a value or arrays that do not line up refused by index.
contract DeploySendPlanTest is Test {
    DeploySend ds;
    address constant S = 0x85528c7E75Ab86B58A166E263A49449927b15b02;
    string constant F = '"0x85528c7e75ab86b58a166e263a49449927b15b02"';
    string constant A = '"0x4e59b44847b379578588920ca78fbf26c0b4956c"';
    string constant B = '"0x00000000000000000000000000000000000000b0"';
    string constant Z = '"0x0000000000000000000000000000000000000000"';

    function setUp() public {
        ds = new DeploySend();
    }

    function _p(string memory from, string memory to, string memory value, string memory input)
        internal
        pure
        returns (string memory)
    {
        return string.concat('{"from":[', from, '],"to":[', to, '],"value":[', value, '],"input":[', input, "]}");
    }

    function _three(string memory a, string memory b, string memory c) internal pure returns (string memory) {
        return string.concat(a, ",", b, ",", c);
    }

    function test_plan_parsesEveryField() public view {
        (address[] memory to, bytes[] memory input) = ds.plan(
            _p(_three(F, F, F), _three(A, B, A), '"0x0","0x0","0x0"', '"0x01","0x0203","0x"'), S
        );
        assertEq(to.length, 3);
        assertEq(to[0], 0x4e59b44847b379578588920cA78FbF26c0B4956C);
        assertEq(to[1], address(0xb0));
        assertEq(input[0], hex"01");
        assertEq(input[1], hex"0203");
        assertEq(input[2], hex"");
    }

    function test_plan_empty() public view {
        (address[] memory to,) = ds.plan(_p("", "", "", ""), S);
        assertEq(to.length, 0);
    }

    function test_plan_refusesACreateByIndex() public {
        vm.expectRevert(abi.encodeWithSelector(DeploySend.PlanTxNotSendable.selector, 1, "a CREATE (no `to`)"));
        ds.plan(_p(_three(F, F, F), _three(A, Z, A), '"0x0","0x0","0x0"', '"0x01","0x02","0x03"'), S);
    }

    function test_plan_refusesAnotherSenderByIndex() public {
        vm.expectRevert(abi.encodeWithSelector(DeploySend.PlanTxNotSendable.selector, 2, "another sender"));
        ds.plan(_p(_three(F, F, B), _three(A, B, A), '"0x0","0x0","0x0"', '"0x01","0x02","0x03"'), S);
    }

    function test_plan_refusesAValueByIndex() public {
        vm.expectRevert(abi.encodeWithSelector(DeploySend.PlanTxNotSendable.selector, 2, "a value"));
        ds.plan(_p(_three(F, F, F), _three(A, B, A), '"0x0","0x0","0x5"', '"0x01","0x02","0x03"'), S);
    }

    function test_plan_refusesArraysThatDoNotLineUp() public {
        vm.expectRevert(
            abi.encodeWithSelector(DeploySend.PlanTxNotSendable.selector, type(uint256).max, "the plan's fields do not line up")
        );
        ds.plan(_p(_three(F, F, F), _three(A, B, A), '"0x0","0x0"', '"0x01","0x02","0x03"'), S);
    }
}
