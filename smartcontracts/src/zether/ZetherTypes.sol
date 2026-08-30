// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Kiểu dùng chung của tầng bảo mật.
/// @dev Curve là `bn254` (D1 chốt lại 2026-08-30 sau spike S7 — BLS12-381 KHÔNG rẻ
///      hơn, ở k=277 nó đắt hơn ~2%, và không tồn tại trên chain private 9000).
///      Nhưng KHÔNG hằng số hoá curve ở đây: verifier được inject bằng địa chỉ lúc
///      `initialize()`, nên đổi curve = deploy verifier khác, không sửa token.
library ZetherTypes {
    /// Điểm trên G1. Với bn254 thì đây là toạ độ affine mod p.
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// Ciphertext ElGamal dạng exponential (lifted):
    ///     C = g^b · y^r
    ///     D = g^r
    /// Giải mã bằng `x` cho ra `g^b`, KHÔNG phải `b`. Đi từ `g^b` về `b` là discrete
    /// log — khoá bí mật không giúp gì. Đây là lý do tồn tại trần giải mã
    /// `MAX_DECRYPTABLE_SHIELDED`, và lý do contract không bao giờ "giải mã" được.
    struct Ciphertext {
        G1Point c;
        G1Point d;
    }

    /// Universal Account: `keccak256(abi.encode(y))`. Một tên duy nhất cho thứ mà
    /// code hiện tại gọi lẫn lộn là `yHash`, `bytes32 account`, `schnorrAddress`.
    type UA is bytes32;

    function toUA(G1Point memory y) internal pure returns (UA) {
        return UA.wrap(keccak256(abi.encode(y)));
    }

    function unwrap(UA a) internal pure returns (bytes32) {
        return UA.unwrap(a);
    }
}
