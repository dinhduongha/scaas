// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Transcript Fiat-Shamir và hash-to-scalar (đặc tả §4).
/// @notice **UNAUDITED.** Một transcript duy nhất cho Σ và cả hai
///         Bulletproof. Mỗi absorb có tiền tố độ dài nhãn và độ dài dữ liệu ⇒ không có hai chuỗi
///         thông điệp khác nhau cho cùng một trạng thái (`"AB"‖"C"` ≠ `"A"‖"BC"`).
library ZetherTranscript {
    function init() internal pure returns (bytes32) {
        return keccak256("SCAAS-ZETHER-TRANSCRIPT-V1");
    }

    function absorb(bytes32 st, string memory label, bytes memory data) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(st, uint8(0), uint8(bytes(label).length), label, uint32(data.length), data)
        );
    }

    /// @return st2 trạng thái mới; c challenge trong `[0, r)` (0 ⇒ người gọi phải từ chối proof).
    function challenge(bytes32 st, string memory label, uint256 r) internal pure returns (bytes32 st2, uint256 c) {
        st2 = keccak256(abi.encodePacked(st, uint8(1), uint8(bytes(label).length), label));
        c = hashToScalar(st2, r);
    }

    /// @notice `(keccak(seed‖0x02)·2^256 + keccak(seed‖0x03)) mod r` — rút gọn 512 bit, độ lệch < 2^-250.
    function hashToScalar(bytes32 seed, uint256 r) internal pure returns (uint256) {
        uint256 hi = uint256(keccak256(abi.encodePacked(seed, uint8(2))));
        uint256 lo = uint256(keccak256(abi.encodePacked(seed, uint8(3))));
        uint256 twoTo256 = (type(uint256).max % r) + 1; // 2^256 mod r (r > 2^255 không xảy ra: r < 2^255)
        return addmod(mulmod(hi, twoTo256, r), lo, r);
    }
}
