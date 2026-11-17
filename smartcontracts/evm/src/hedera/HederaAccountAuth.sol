// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
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

    /// @notice The same function as `view`, for the `view` signature checks of `MtxPipelineLib` (`_authorizeNative` on
    ///         the merged entries, `_requireSignature` on `executeMetaTransaction`), through `HederaLib.requireValid`.
    ///         Safe because every call site is a non-view entry point, so the frame is never static: the merged
    ///         `mtx<Op>(UAEnvelope, …, UASig)` / `mtxExecuteTransfer` / `mtxBatchTransfer` / `mtxPay*` / `mtxExecute` /
    ///         `mtxBatch` / `mtxCancelNonce` entries, `executeMetaTransaction` (ua-mtx-merge T8, R42), and the no-twin
    ///         `mtxWrap*` / `mtxAddReserve` entries; 0x16a writes no state and calls nothing back. ponytail: drop it when
    ///         those checks stop being `view`.
    function asView()
        internal pure returns (function (address, bytes32, bytes calldata) internal view returns (bool) f)
    {
        function (address, bytes32, bytes calldata) internal returns (bool) g = isAuthorizedRaw;
        assembly ("memory-safe") { f := g }
    }
}
