// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Kiểu dùng chung của tầng bảo mật — CURVE-AGNOSTIC.
///
/// @notice Factory mở cho toàn thế giới, nên **không có curve nào là "curve của hệ
///         thống"**. Người tạo token chọn verifier, thị trường chọn token. Hệ quả
///         trực tiếp lên kiểu dữ liệu, và nó không tránh được:
///
///         | | bn254 | BLS12-381 |
///         |---|---|---|
///         | Fp | 254 bit, vừa 1 uint256 | 381 bit, EIP-2537 pad thành **64 byte** |
///         | G1 point on-chain | **64 byte** | **128 byte** (đã đo trên Gnosis) |
///         | Scalar field r | 254 bit | 255 bit |
///         | Precompile | 0x06/0x07/0x08, có từ Byzantium 2017 | 0x0b…0x10, cần Prague |
///
///         Nên `struct G1Point { uint256 x; uint256 y; }` **KHÔNG dùng làm kiểu chung
///         được** — nó là kiểu của bn254, không phải kiểu của "một điểm". Interface
///         chung phải nhận điểm dạng `bytes`, mã hoá theo `proofSystemId()`.
///
///         Điều này còn RẺ HƠN dạng có kiểu: gói cả bó điểm vào một `bytes` bỏ được
///         toàn bộ ABI offset của mảng động, nên calldata nhỏ hơn chứ không lớn hơn.
library ZetherTypes {
    /// Universal Account. `keccak256(<mã hoá chính tắc của y>)`.
    ///
    /// **Curve-dependent, và phải nhớ điều đó.** Cùng một con người trên bn254 và
    /// trên BLS12-381 có HAI UA khác nhau — hai keypair khác nhau trên hai nhóm khác
    /// nhau, không phải một danh tính hai cách viết. Ví tuyệt đối không được gộp
    /// chúng lại thành một dòng.
    type UA is bytes32;

    function unwrap(UA a) internal pure returns (bytes32) {
        return UA.unwrap(a);
    }

    function wrap(bytes32 b) internal pure returns (UA) {
        return UA.wrap(b);
    }

    /// @notice UA từ mã hoá chính tắc của public key.
    /// @dev Nhận `bytes` chứ không nhận điểm có kiểu, nên hàm này đúng cho mọi curve.
    function toUA(bytes memory encodedY) internal pure returns (UA) {
        return UA.wrap(keccak256(encodedY));
    }
}

/// @title Kiểu điểm CỦA RIÊNG bn254. Không phải kiểu chung.
/// @dev Nằm ở đây để implementation bn254 và test dùng. Implementation BLS12-381 có
///      kiểu riêng của nó (mỗi toạ độ 2 word). Không cố hợp nhất hai cái — chúng là
///      hai nhóm khác nhau, và một kiểu "chung" chỉ tạo ảo giác thay thế được cho nhau.
library Bn254 {
    struct G1Point {
        uint256 x;
        uint256 y;
    }

    /// Ciphertext ElGamal dạng exponential (lifted):
    ///     C = g^b · y^r ,  D = g^r
    /// Giải mã bằng `x` cho ra `g^b`, KHÔNG phải `b`. Đi từ `g^b` về `b` là discrete
    /// log — khoá bí mật không giúp gì. Đó là lý do tồn tại trần giải mã, và lý do
    /// contract không bao giờ "giải mã" được số dư của ai.
    struct Ciphertext {
        G1Point c;
        G1Point d;
    }

    uint256 internal constant G1_ENCODED_BYTES = 64;
}

/// @title Hằng số mã hoá của BLS12-381 theo EIP-2537.
library Bls12381 {
    /// Mỗi Fp là 64 byte (16 byte zero pad + 48 byte giá trị), nên G1 là 128 byte.
    /// Đã xác nhận bằng `eth_call` vào 0x0b (G1ADD) trên Gnosis: output đúng 128 byte.
    uint256 internal constant G1_ENCODED_BYTES = 128;
    uint256 internal constant G2_ENCODED_BYTES = 256;
}
