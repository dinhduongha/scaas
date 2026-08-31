// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {HashToCurve} from "../src/common/HashToCurve.sol";
import {Bls12381} from "../src/common/Bls12381.sol";

/// @notice `expand_message_xmd` là loại code mà một byte sai vẫn chạy, vẫn trả ra 32 byte
///         trông rất ngẫu nhiên, và chỉ lộ ra khi cố verify một chữ ký do thư viện khác tạo.
///         Nên nó phải bị ghim bằng known-answer test, không bằng đọc lại code.
contract HashToCurveTest is Test {
    /// DST của RFC 9380 Appendix K.1. Vector dưới đây khớp CẢ HAI: (a) một bản cài đặt
    /// Python độc lập viết thẳng từ văn bản RFC, và (b) vector in trong chính RFC.
    bytes constant RFC_DST = "QUUX-V01-CS02-with-expander-SHA256-128";

    function test_xmdMatchesRfc9380EmptyMessage() public pure {
        assertEq(
            HashToCurve.expandMessageXmd("", RFC_DST, 32),
            hex"68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
        );
    }

    function test_xmdMatchesRfc9380Abc() public pure {
        assertEq(
            HashToCurve.expandMessageXmd("abc", RFC_DST, 32),
            hex"d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615"
        );
    }

    /// 128 byte = 4 khối SHA-256, nên vector này ghim luôn vòng lặp `b_i = H(b0 ^ b_{i-1} …)`.
    /// Vector 32 byte ở trên chỉ chạm `b_1`, không bao giờ chạm vòng lặp.
    bytes constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    function test_xmdFourBlocksEmpty() public pure {
        assertEq(
            HashToCurve.expandMessageXmd("", DST, 128),
            hex"f9f9e1a5da5e2f2ecc0799921ee0b64858c9f1619623160c7ee022862e4077f6"
            hex"d3bee3887e216a3dc507d3a2a586ca3cea9b173a9d436303dc99c5135bdc8714"
            hex"db4802a53afd372fd219c50d047db9312305949ab38a0cc3d2830d6e44992fa0"
            hex"ef158ddb5fd2328a564e6933fbb5ac96a8c4ba77e0daf035aa5eea8866abbb75"
        );
    }

    function test_xmdFourBlocksAbc() public pure {
        assertEq(
            HashToCurve.expandMessageXmd("abc", DST, 128),
            hex"d2266f5f37de39e5eb24984eccd4767aea7ccd75122c647900c46a2b5845bb8b"
            hex"837292a5727a464efc9ba4d12f615cb63c5d3f4d6b39657af8606402f2c0688b"
            hex"a7bc70b54c485008ee4255569e0ed3438e983366ff4fa9aeb46678bfd41331d1"
            hex"2e5f82dfb778ca33fc4209bbc14d035ab0a041df27d9a291a9195c032d574367"
        );
    }

    function test_xmdDependsOnDst() public pure {
        assertTrue(
            keccak256(HashToCurve.expandMessageXmd("abc", DST, 32))
                != keccak256(HashToCurve.expandMessageXmd("abc", RFC_DST, 32))
        );
    }

    /// `lenInBytes` đi vào `b_0` dưới dạng 2 byte, nên xin 32 byte rồi cắt KHÁC với xin 128
    /// byte rồi lấy 32 byte đầu. Ai đó "tối ưu" bằng cách cache một lần expand rồi cắt sẽ
    /// làm hỏng domain separation, và test này bắt được.
    function test_lengthIsBoundIntoTheHash() public pure {
        bytes memory short_ = HashToCurve.expandMessageXmd("abc", DST, 32);
        bytes memory long_  = HashToCurve.expandMessageXmd("abc", DST, 128);
        bytes memory prefix = new bytes(32);
        for (uint256 i; i < 32; ++i) prefix[i] = long_[i];
        assertTrue(keccak256(short_) != keccak256(prefix));
    }

    function test_dstLongerThan255Reverts() public {
        bytes memory big = new bytes(256);
        vm.expectRevert(abi.encodeWithSelector(HashToCurve.DstTooLong.selector, uint256(256)));
        this.callXmd("abc", big, 32);
    }

    function callXmd(bytes memory m, bytes memory d, uint256 n) external pure returns (bytes memory) {
        return HashToCurve.expandMessageXmd(m, d, n);
    }

    /// Modulus trường cơ sở: 48 byte, và giá trị của nó đã được CHÍNH precompile EIP-2537
    /// trên chain 9000 xác nhận — `MAP_FP_TO_G1(p-1)` trả 128 byte, `MAP_FP_TO_G1(p)` revert.
    /// Ở đây chỉ ghim độ dài và byte đầu/cuối để một lần sửa nhầm không đi lọt.
    function test_fieldModulusShape() public pure {
        assertEq(HashToCurve.P.length, 48);
        assertEq(uint8(HashToCurve.P[0]),  0x1a);
        assertEq(uint8(HashToCurve.P[47]), 0xab);
    }
}
