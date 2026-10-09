// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Sơ đồ uỷ quyền cho một tài khoản Zether.
/// @notice Giá trị 0–4 giữ nguyên số của `02-account-registry.md` §2.4.1 — chúng nằm
///         trong storage đã ghi và trong digest đã ký, **không đổi số được**. `BLS12381`
///         là giá trị mới: chain 7622 (formerly 9000) đã bật EIP-2537 (2026-08-31) nên biến thể này
///         chạy được, và nó là đường cong mạnh hơn hẳn `BLS_BN254`.
///
/// **Bất biến an ninh #1 (§02.4.2):** `transferConfidential` và `withdraw` phải xác thực
/// HAI thứ độc lập — ZK proof chứng minh biết `x`, VÀ chữ ký theo `authScheme` trên một
/// digest bao trùm toàn bộ giao dịch. Bỏ vế thứ hai thì lộ `encKey` = mất tiền, thay vì
/// chỉ là read-only breach.
enum AuthScheme {
    SELF_SCHNORR,        // 0 — KHÔNG có chữ ký riêng. ZK proof CHÍNH LÀ uỷ quyền
    ECDSA_MULTISIG,      // 1 — N-of-M ECDSA thô, xem MultiSig.sol
    FROST_BN254,         // 2 — threshold Schnorr t-of-n (KHÔNG phải MuSig2)
    MUSIG2_BN254,        // 3 — n-of-n
    BLS_BN254,           // 4 — chỉ private chain, ~100 bit
    BLS_12381,           // 5 — cần EIP-2537. ~126 bit. Xem Bls12381.sol + HashToCurve.sol
    PQ_COMMITMENT,       // 6 — verify off-chain
    SMART_ACCOUNT_1271   // 7
}

/// @title Ánh xạ sơ đồ -> đường xác minh. TÁM giá trị, nhưng chỉ SÁU đường code.
library AuthSchemeLib {
    /// @notice MPC KHÔNG cần một đường xác minh riêng, và đây là điều dễ thiết kế thừa nhất.
    ///
    /// FROST (t-of-n) và MuSig2 (n-of-n) đều là **giao thức off-chain** để nhiều bên cùng
    /// tạo ra **MỘT chữ ký Schnorr duy nhất**. Chữ ký đó `(R, z)` verify bằng đúng phương
    /// trình của chữ ký một-người: `z·G == R + c·P`. Contract **không phân biệt được**, và
    /// không cần phân biệt.
    ///
    /// Nên: `FROST_BN254` và `MUSIG2_BN254` dùng **chung một đường code** với nhau, và cùng
    /// đường đó phục vụ luôn một người ký Schnorr đơn lẻ. Viết hai verifier là viết hai lần
    /// cùng một phép toán.
    ///
    /// Hai giá trị enum vẫn tách ra vì chúng khác nhau ở chỗ **khác**: registry ghi lại
    /// *cơ chế quản trị nào đang bảo vệ tài khoản* — t-of-n hay n-of-n — và đó là thông tin
    /// kiểm toán, thông tin chính sách, không phải thông tin xác minh.
    ///
    /// Điều DUY NHẤT mà MPC đòi hỏi ở tầng contract: khoá công khai đăng ký phải là **khoá
    /// TỔNG HỢP** của nhóm, không phải share của ai. Đó là ràng buộc lúc đăng ký (§02.2 PoP),
    /// không phải lúc verify.
    function verifierPath(AuthScheme s) internal pure returns (uint8) {
        if (s == AuthScheme.SELF_SCHNORR)        return 0;  // không chữ ký nào để kiểm
        if (s == AuthScheme.ECDSA_MULTISIG)      return 1;  // MultiSig.sol
        if (s == AuthScheme.BLS_BN254)           return 3;  // pairing bn254, precompile 0x08
        if (s == AuthScheme.BLS_12381)           return 4;  // Bls12381.sol + HashToCurve.sol
        if (s == AuthScheme.PQ_COMMITMENT)       return 5;  // verify off-chain, on-chain chỉ giữ cam kết
        if (s == AuthScheme.SMART_ACCOUNT_1271)  return 6;  // SigCheck.isValid -> ERC-1271
        return 2;                                           // FROST + MUSIG2 -> CÙNG Schnorr bn254
    }

    /// @notice Sơ đồ này có chống được compromise `encKey` không.
    /// @dev `SELF_SCHNORR` là sơ đồ DUY NHẤT mà lộ `encKey` đồng nghĩa mất tiền — vì không
    ///      có vế thứ hai nào để chặn. Hợp lệ, nhưng phải nhìn thấy được (§02.4.2).
    function survivesEncKeyLeak(AuthScheme s) internal pure returns (bool) {
        return s != AuthScheme.SELF_SCHNORR;
    }
}
