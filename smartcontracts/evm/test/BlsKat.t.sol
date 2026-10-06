// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Bls12381} from "../src/common/Bls12381.sol";
import {HashToCurve} from "../src/common/HashToCurve.sol";

/// @notice KAT cho BLS12-381 min-signature-size, sinh bằng `py_ecc` và **đã xác nhận trên
///         chain 9000**: `PAIRING_CHECK` trả 1 cho bộ dưới đây, trả 0 khi đổi thông điệp,
///         và revert khi sửa một bit của chữ ký (điểm rời khỏi đường cong).
///
/// Các test cần precompile EIP-2537 sẽ **tự bỏ qua** nếu chain đang chạy không có nó —
/// `forge test` mặc định chạy trên EVM cục bộ. Chạy đầy đủ bằng:
///
///     forge test --fork-url http://127.0.0.1:8545 --match-contract BlsKat
contract BlsKatTest is Test {
    bytes constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    bytes constant MSG = "bamboo"; // message of the external py_ecc KAT (verified on chain 9000), not a tag

    bytes constant HM =
        hex"000000000000000000000000000000000a8420a64f75971be4bccf69a1adcec1"
        hex"b4ea93950ed374ca9c2a507652a85c2fb43dc69e073d0f1154eb2a76242ba01c"
        hex"000000000000000000000000000000001908f9979abcce991413bed5427be350"
        hex"17c2df468ea509ce53a0eb96d7a1b280c789d40836eb369ab4bbb48762c111cb";
    bytes constant PK =
        hex"000000000000000000000000000000000dbc474120cea5caa2db02317ed526b0"
        hex"ed38fc0125a744152ef14fe150276f33e16c5c77a970133623a56f1bfd4d75de"
        hex"0000000000000000000000000000000007b3eeb42b85620997c97be990474d7c"
        hex"0d3633a18f65b17e4a9e099d0e4aff0a53e96ca4b6a8c115cae7616f47b24db1"
        hex"000000000000000000000000000000000d82b99034a83660dd6836f3920644ca"
        hex"c2e3b0f3a10440927123d3547bc05121dbf4a7bcfb5ae03a327fcb42bd443547"
        hex"000000000000000000000000000000000c8d230abb5492b20107d5ddd01ecb2a"
        hex"6b70d242958d37fbbc52da22c6d0b38fb9be19e363b6836dada0415f5f16f2ee";
    bytes constant SIG =
        hex"0000000000000000000000000000000018fda64dabe2222133fb2ee16080d9be"
        hex"1ffe8b76ca2acc36c2c0d7e8b3252b5b9451f2116351a588915dd0a080495d4e"
        hex"00000000000000000000000000000000161955658b4d1b4374de8dda63509e4a"
        hex"7eb4d89e35085937ce891ab030f48f946dd03663a313deecf2fb306193f0e258";

    modifier onlyWithEip2537() {
        if (!Bls12381.isSupported()) {
            emit log("bo qua: chain khong co EIP-2537");
            return;
        }
        _;
    }

    /// Bản cài đặt Solidity phải cho ra ĐÚNG điểm mà pipeline tham chiếu cho ra. Đây là
    /// test quan trọng nhất của `HashToCurve`: nó nối RFC 9380 với precompile.
    function test_hashToG1MatchesReference() public onlyWithEip2537 {
        assertEq(HashToCurve.hashToG1(MSG, DST), HM);
    }

    function test_validSignatureVerifies() public onlyWithEip2537 {
        assertTrue(Bls12381.verifyMinSig(HM, PK, SIG));
    }

    /// Thông điệp khác ⇒ H(m) khác ⇒ pairing ra 0. Không revert — trả về false.
    function test_wrongMessageFails() public onlyWithEip2537 {
        bytes memory other = HashToCurve.hashToG1("bamboo2", DST);
        assertFalse(Bls12381.verifyMinSig(other, PK, SIG));
    }

    /// DST khác cũng phải ra H(m) khác — domain separation là thật, không phải trang trí.
    function test_differentDstGivesDifferentPoint() public onlyWithEip2537 {
        bytes memory other = HashToCurve.hashToG1(MSG, "SOME_OTHER_DST_");
        assertTrue(keccak256(other) != keccak256(HM));
    }

    /// Điểm sinh G2 lấy đối: ghim hình dạng. Giá trị đã được chính pairing check xác nhận.
    function test_negG2GeneratorShape() public pure {
        assertEq(Bls12381.NEG_G2_GENERATOR.length, 256);
    }
}
