// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Xác thực tài khoản Hedera qua HIP-632 (`IHederaAccountService` tại 0x16a) — R63, R6-2.
/// @notice `isAuthorizedRaw(account, messageHash, signature) returns (bool)`:
///         - 64 byte ⇒ ed25519 RFC 8032 trên ĐÚNG `messageHash` (32 byte), tài khoản phải có khoá ED25519 đơn;
///         - 65–72 byte ⇒ ECDSA, tài khoản phải có alias EVM (không long-zero).
///         Precompile REVERT (không trả false) khi tài khoản không tồn tại, khoá phức hợp hay sai kiểu khoá
///         (`IsAuthorizedRawCall.java`). Ở đây mọi revert, mọi câu trả lời không đúng 32 byte, và mọi giá trị
///         khác `1` đều là "không được uỷ quyền" — fail closed, kể cả trên chain không có precompile.
///
///         Phải gọi bằng CALL, không STATICCALL: `IsAuthorizedRawCall` không cài `allowsStaticFrame()` (mặc định
///         false) nên system contract HALT trong frame tĩnh (`AbstractNativeSystemContract`). Đã thử trên testnet
///         2026-10-03: cùng lời gọi, STATICCALL ⇒ `ok = false`, CALL ⇒ `ok = true` + kết quả.
library HederaAccountAuth {
    address internal constant HAS = address(0x16a);
    bytes4 internal constant IS_AUTHORIZED_RAW = 0xb2a31da4; // isAuthorizedRaw(address,bytes,bytes)
    /// @dev Phí thật = phí `ecrecover` (3 000). Khi từ chối (tài khoản lạ, khoá phức hợp) system contract trả về
    ///      với TOÀN BỘ gas còn lại của frame bị tính (`reversionWith(rce, frame.getRemainingGas())`): trần này giữ
    ///      cho một chữ ký xấu lọt qua mô phỏng (đua đổi khoá) không đốt hết gas của tx relayer.
    uint256 internal constant HAS_GAS = 100_000;

    function isAuthorizedRaw(address account, bytes32 digest, bytes calldata sig) internal returns (bool) {
        (bool ok, bytes memory ret) =
            HAS.call{gas: HAS_GAS}(abi.encodeWithSelector(IS_AUTHORIZED_RAW, account, abi.encodePacked(digest), sig));
        return ok && ret.length == 32 && uint256(bytes32(ret)) == 1;
    }

    /// @notice Cùng hàm, kiểu `view`, cho chỗ gọi bị ràng `view` (`ERC20MetaTx._requireValidSignature`). An toàn vì
    ///         chỗ gọi duy nhất là `executeMetaTransaction` (không phải view, frame không tĩnh) và 0x16a không ghi
    ///         state, không gọi ngược. ponytail: bỏ khi `_requireValidSignature` của lớp cha thôi là `view`.
    function asView()
        internal pure returns (function (address, bytes32, bytes calldata) internal view returns (bool) f)
    {
        function (address, bytes32, bytes calldata) internal returns (bool) g = isAuthorizedRaw;
        assembly ("memory-safe") { f := g }
    }
}
