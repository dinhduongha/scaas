// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MultiSig} from "../src/common/MultiSig.sol";

contract MultiSigTest is Test {
    function _owners(uint256 n) private pure returns (address[] memory o, uint256[] memory k) {
        o = new address[](n); k = new uint256[](n);
        for (uint256 i; i < n; ++i) { k[i] = i + 1; o[i] = vm.addr(k[i]); }
        // sap tang dan theo dia chi
        for (uint256 i; i < n; ++i)
            for (uint256 j = i + 1; j < n; ++j)
                if (o[j] < o[i]) { (o[i],o[j])=(o[j],o[i]); (k[i],k[j])=(k[j],k[i]); }
    }

    function _sign(uint256 pk, bytes32 d) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    function test_quorumAccepts2of3() public pure {
        (address[] memory o, uint256[] memory k) = _owners(3);
        bytes32 d = keccak256("x");
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(k[0], d);
        sigs[1] = _sign(k[1], d);
        MultiSig.requireQuorum(o, 2, d, sigs);
    }

    /// Cái bẫy chính: nộp CÙNG một chữ ký hai lần. Không ép thứ tự thì nó qua.
    function test_theSameSignatureTwiceIsRefused() public {
        (address[] memory o, uint256[] memory k) = _owners(3);
        bytes32 d = keccak256("x");
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(k[0], d);
        sigs[1] = _sign(k[0], d);   // trung
        vm.expectRevert(abi.encodeWithSelector(MultiSig.DuplicateOrUnsorted.selector, o[0]));
        this.callQuorum(o, 2, d, sigs);
    }

    function test_zeroThresholdIsRefused() public {
        (address[] memory o,) = _owners(3);
        vm.expectRevert(abi.encodeWithSelector(MultiSig.BadThreshold.selector, uint256(0), uint256(3)));
        this.callQuorum(o, 0, keccak256("x"), new bytes[](0));
    }

    function test_aNonOwnerIsRefused() public {
        (address[] memory o, uint256[] memory k) = _owners(3);
        bytes32 d = keccak256("x");
        bytes[] memory sigs = new bytes[](2);
        uint256 outsider = 99;
        address a = vm.addr(outsider);
        // xep tang dan de qua duoc check thu tu, roi phai bi chan boi check chu so huu
        if (a < o[0]) { sigs[0] = _sign(outsider, d); sigs[1] = _sign(k[0], d); }
        else          { sigs[0] = _sign(k[0], d);     sigs[1] = _sign(outsider, d); }
        vm.expectRevert(abi.encodeWithSelector(MultiSig.NotAnOwner.selector, a));
        this.callQuorum(o, 2, d, sigs);
    }

    function callQuorum(address[] memory o, uint256 t, bytes32 d, bytes[] memory s) external pure {
        MultiSig.requireQuorum(o, t, d, s);
    }
}
