// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Kiểu dùng chung của tầng bảo mật — CURVE-AGNOSTIC.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
///
///         Factory mở cho toàn thế giới, nên **không có curve nào là "curve của hệ thống"**. Điểm G1 của
///         bn254 là 64 byte, của BLS12-381 là 128 byte (EIP-2537), nên mọi interface chung nhận điểm dạng
///         `bytes` mã hoá theo `IZetherVerifier.proofSystemId()` — gói một bó điểm vào một `bytes` còn bỏ
///         được toàn bộ ABI offset của mảng động. Phép toán theo từng curve: `ZetherCurves.sol`.
library ZetherTypes {
    /// Universal Account. `keccak256(<mã hoá chính tắc của y>)`.
    ///
    /// **Curve-dependent.** Cùng một người trên bn254 và trên BLS12-381 có HAI UA khác nhau — hai keypair
    /// trên hai nhóm khác nhau. Ví tuyệt đối không được gộp chúng.
    type UA is bytes32;

    /// Ai được gộp `pending → acc` (SRS §7.6, canon C5 bản 5). Cờ per (UA, token), chỉ chủ đổi được.
    enum RollOverMode {
        PUBLIC,     // mặc định: ai cũng gọi được rollOverPublic/rollOverBatch; no-op khi pending rỗng
        OWNER_ONLY  // treasury / B2B R3–R4: chỉ rollOverSigned
    }

    function toUA(bytes memory encodedY) internal pure returns (UA) {
        return UA.wrap(keccak256(encodedY));
    }
}
