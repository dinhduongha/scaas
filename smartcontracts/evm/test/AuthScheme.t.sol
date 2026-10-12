// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AuthScheme, AuthSchemeLib} from "../src/common/AuthScheme.sol";
import {MultiSig} from "../src/common/MultiSig.sol";
import {Bls12381} from "../src/common/Bls12381.sol";

contract AuthSchemeTest is Test {
    /// FROST và MuSig2 là giao thức off-chain sinh ra MỘT chữ ký Schnorr. Contract không
    /// phân biệt được, và test này ghim điều đó: hai sơ đồ, một đường code. Nếu ai đó tách
    /// chúng ra thành hai verifier, test này fail và buộc họ giải thích tại sao.
    function test_mpcSchemesShareOneVerifierPath() public pure {
        assertEq(
            AuthSchemeLib.verifierPath(AuthScheme.FROST_BN254),
            AuthSchemeLib.verifierPath(AuthScheme.MUSIG2_BN254)
        );
    }

    /// SELF_SCHNORR là sơ đồ duy nhất mà lộ encKey đồng nghĩa mất tiền (§02.4.2).
    function test_onlySelfSchnorrDiesWithEncKey() public pure {
        assertFalse(AuthSchemeLib.survivesEncKeyLeak(AuthScheme.SELF_SCHNORR));
        assertTrue(AuthSchemeLib.survivesEncKeyLeak(AuthScheme.ECDSA_MULTISIG));
        assertTrue(AuthSchemeLib.survivesEncKeyLeak(AuthScheme.FROST_BN254));
        assertTrue(AuthSchemeLib.survivesEncKeyLeak(AuthScheme.BLS_12381));
    }

    /// Số enum nằm trong storage đã ghi và trong digest đã ký. Ghim chúng.
    function test_enumNumbersAreFrozen() public pure {
        assertEq(uint8(AuthScheme.SELF_SCHNORR),   0);
        assertEq(uint8(AuthScheme.ECDSA_MULTISIG), 1);
        assertEq(uint8(AuthScheme.FROST_BN254),    2);
        assertEq(uint8(AuthScheme.MUSIG2_BN254),   3);
        assertEq(uint8(AuthScheme.BLS_BN254),          4);
        assertEq(uint8(AuthScheme.BLS_12381),          5);
        assertEq(uint8(AuthScheme.PQ_COMMITMENT),      6);
        assertEq(uint8(AuthScheme.SMART_ACCOUNT_1271), 7);
    }

    /// Địa chỉ precompile EIP-2537 — bản cuối đánh số lại so với draft. Sai một số là gọi
    /// trúng precompile khác, và với input toàn 0 nó vẫn trả byte: sai IM LẶNG.
    function test_eip2537AddressesMatchFinalSpec() public pure {
        assertEq(Bls12381.G1ADD,         address(0x0b));
        assertEq(Bls12381.G1MSM,         address(0x0c));
        assertEq(Bls12381.G2ADD,         address(0x0d));  // KHÔNG phải 0x0e
        assertEq(Bls12381.G2MSM,         address(0x0e));
        assertEq(Bls12381.PAIRING_CHECK, address(0x0f));
        assertEq(Bls12381.MAP_FP_TO_G1,  address(0x10));  // KHÔNG phải 0x11
        assertEq(Bls12381.MAP_FP2_TO_G2, address(0x11));
    }

    // --- MultiSig ---

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
