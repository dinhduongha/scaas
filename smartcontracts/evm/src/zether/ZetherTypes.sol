// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Kiểu dùng chung của tầng bảo mật.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
///
///         Classical Zether runs on BLS12-381 only since UA-6 (CTR-ZTH-32; the bn254 line is in `legacy/ua6/`). Points
///         stay `bytes` (128 bytes, EIP-2537) encoded per `IZetherVerifier.proofSystemId()` — gói một bó điểm vào một
///         `bytes` còn bỏ được toàn bộ ABI offset của mảng động. Phép toán: `ZetherCurves.sol`.
library ZetherTypes {
    /// Universal Account of a Zether key (accounts.md CTR-UA-16): `keccak256(TAG(zether-bls12381) ‖ Y)`, kind 0x0141.
    type UA is bytes32;

    uint16 internal constant KIND_ZETHER_BLS12381 = 0x0141;
    /// `TAG(kind) = keccak256("scaas.ua.<name>.v1")` (accounts.md §1.6).
    bytes32 internal constant TAG_ZETHER_BLS12381 = keccak256("scaas.ua.zether-bls12381.v1");

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

    /// `UA = keccak256(TAG_ZETHER_BLS12381 ‖ encodedY)` (CTR-UA-22). A length other than 128 gives an id no registry
    /// can hold (`UAKeyData` at registration), so the token finds it unregistered.
    function toUA(bytes memory encodedY) internal pure returns (UA) {
        return UA.wrap(keccak256(abi.encodePacked(TAG_ZETHER_BLS12381, encodedY)));
    }
}
