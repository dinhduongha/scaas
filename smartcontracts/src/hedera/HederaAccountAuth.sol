// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Xác thực tài khoản Hedera qua HIP-632 (`IHederaAccountService` tại 0x16a) — R63, R6-2.
/// @notice `isAuthorizedRaw(account, messageHash, signature) returns (bool)`:
///         - 64 byte ⇒ ed25519 RFC 8032 trên ĐÚNG `messageHash` (32 byte), tài khoản phải có khoá ED25519 đơn;
///         - 65–72 byte ⇒ ECDSA, tài khoản phải có alias EVM (không long-zero).
///         Precompile REVERT (không trả false) khi tài khoản không tồn tại, khoá phức hợp hay sai kiểu khoá
///         (`IsAuthorizedRawCall.java`). Ở đây mọi revert, mọi câu trả lời không đúng 32 byte, và mọi giá trị
///         khác `1` đều là "không được uỷ quyền" — fail closed, kể cả trên chain không có precompile.
library HederaAccountAuth {
    address internal constant HAS = address(0x16a);
    bytes4 internal constant IS_AUTHORIZED_RAW = 0xb2a31da4; // isAuthorizedRaw(address,bytes,bytes)

    function isAuthorizedRaw(address account, bytes32 digest, bytes calldata sig) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            HAS.staticcall(abi.encodeWithSelector(IS_AUTHORIZED_RAW, account, abi.encodePacked(digest), sig));
        return ok && ret.length == 32 && uint256(bytes32(ret)) == 1;
    }
}
