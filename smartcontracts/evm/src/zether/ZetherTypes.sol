// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
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

    /// Nơi giữ bundle tiết lộ của một transfer nhiều người nhận (nằm trong opTag, relayer không đổi được).
    enum TransferMode {
        HASH,   // commit-reveal (`zetherTransferCompact`; `zetherTransfer` trên token COMPACT): keccak256(R) một slot +
                // memo người gửi, R = salt ‖ B_1 ‖ … ‖ B_M phát trong event
        BUNDLE, // `zetherTransfer` trên token BUNDLE: lưu R
        NONE    // `zetherTransferNoBundle`: không lưu, tiết lộ off-chain từ calldata
    }

    /// Cách lưu bundle của token, cố định từ `initialize` (CTR-ZTH-38).
    enum DisclosureMode {
        BUNDLE, // mặc định: `zetherTransfer` lưu R, `…Compact` / `…NoBundle` tiết kiệm gas; single lưu R
        COMPACT // mọi transfer là commit-reveal (`zetherTransfer` = `…Compact`); `…NoBundle` và single bị từ chối
    }

    /// Auditor của token, cố định từ `initialize` (CTR-ZTH-09, CTR-ZTH-42).
    enum AuditorMode {
        NONE,    // không khoá auditor: mọi C_aud = O
        FULL,    // có khoá: mọi transfer phải có auditor (mọi C_aud ≠ O)
        OPTIONAL // có khoá: người gửi được bỏ auditor theo transfer (mọi C_aud = O hoặc không cái nào)
    }

    function toUA(bytes memory encodedY) internal pure returns (UA) {
        return UA.wrap(keccak256(encodedY));
    }
}
