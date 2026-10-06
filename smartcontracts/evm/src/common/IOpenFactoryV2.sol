// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Factory v2 (TW2 §9, R130). Đọc `IOpenFactory` trước: mô hình y hệt, chỉ thêm ba kind.
/// @notice `IOpenFactory.sol` đóng băng cùng `OpenFactory.sol` v1: thêm giá trị vào enum ở đó là đổi bytecode
///         của factory v1 đã deploy (ABI decoder kiểm biên enum), nên nó không còn source-verify được. Enum ở
///         đây là bản NỐI DÀI của enum v1 — `META = 0`, `ZETHER = 1` giữ nguyên số, không giá trị nào dùng lại.
interface IOpenFactoryV2 {
    enum TokenKind {
        META,        // v1 MetaToken gộp hai tầng
        ZETHER,      // số dư bí mật
        META_NONE,   // v2 tầng 1: không underlying
        META_SINGLE, // v2 tầng 2: một underlying
        META_MULTI   // v2 tầng 3: 2–8 underlying, any-of
    }
}
