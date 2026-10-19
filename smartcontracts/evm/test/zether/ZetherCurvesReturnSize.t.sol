// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {G1Bn254} from "../../src/zether/ZetherCurves.sol";

contract Bn254Harness {
    function add(bytes memory a, bytes memory b) external view returns (bytes memory) { return G1Bn254.add(a, b); }
    function mul(bytes memory a, uint256 k) external view returns (bytes memory) { return G1Bn254.mul(a, k); }
    function msm(bytes memory p, uint256[] memory s) external view returns (bytes memory) { return G1Bn254.msm(p, s); }
    function isValid(bytes memory a) external view returns (bool) { return G1Bn254.isValid(a); }
    function mapToG1(bytes memory p) external view returns (bytes memory) { return G1Bn254.mapToG1(p); }
}

/// Review W-I (2026-10-19): the bn254 wrappers require the exact return size. A chain without 0x05 / 0x06 / 0x07 answers
/// "success, empty"; on the success flag alone the zeros left in memory would read as a result (every MSM `O`).
contract ZetherCurvesReturnSizeTest is Test {
    Bn254Harness h;
    bytes g;

    function setUp() public {
        h = new Bn254Harness();
        g = G1Bn254.generator();
    }

    function test_realPrecompilesStillAnswer() public view {
        assertEq(h.add(g, g), h.mul(g, 2));
        assertTrue(h.isValid(g));
        uint256[] memory s = new uint256[](1);
        s[0] = 3;
        assertEq(h.msm(g, s), h.mul(g, 3));
    }

    function test_emptyReturnIsRefused() public {
        uint256[] memory s = new uint256[](1);
        s[0] = 3;
        vm.mockCall(address(6), bytes(""), bytes(""));
        vm.expectRevert(G1Bn254.BadPoint.selector);
        h.add(g, g);
        assertFalse(h.isValid(g));
        vm.expectRevert(G1Bn254.BadPoint.selector);
        h.msm(g, s);
        vm.clearMockedCalls();
        vm.mockCall(address(7), bytes(""), bytes(""));
        vm.expectRevert(G1Bn254.BadPoint.selector);
        h.mul(g, 2);
        vm.expectRevert(G1Bn254.BadPoint.selector);
        h.msm(g, s);
        vm.clearMockedCalls();
        vm.mockCall(address(5), bytes(""), bytes(""));
        vm.expectRevert(G1Bn254.ModexpFailed.selector);
        h.mapToG1("x");
    }
}
