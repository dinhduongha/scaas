// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Factory v2 (TW2 §9, R130). Đọc `IOpenFactory` trước: mô hình y hệt (catalogue append-only, clone
///        EIP-1167, không quyền nào trên token đã deploy), chỉ thêm ba kind và hai hàm tạo theo tầng.
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

    event ImplementationRegistered(
        TokenKind indexed kind, uint64 indexed version, address indexed implementation, address registrar);
    event ImplementationDeprecated(TokenKind indexed kind, uint64 indexed version, string reason);
    /// @notice Chỉ cho kind v1 (`META`, `ZETHER`), như factory v1.
    event TokenDeployed(
        address indexed token, address indexed creator, address indexed underlying, TokenKind kind,
        uint64 version, address implementation, address verifier);
    /// @notice Kind v2: event DUY NHẤT của một lần tạo (không kèm `TokenDeployed`, review L13).
    event TieredTokenDeployed(
        address indexed token, address indexed creator, TokenKind kind, uint64 version,
        address implementation, address[] underlyings);

    error VersionAlreadyRegistered(TokenKind kind, uint64 version, address existing);
    error VersionUnknown(TokenKind kind, uint64 version);
    /// @notice Lúc đăng ký / tạo không đăng ký: `tokenKind()` của implementation khác `expected` (`got = META` khi nó
    ///         không trả lời). Ở đường vào sai kind: `expected = META` (đường v1) hoặc `META_NONE` (đường theo tầng).
    error VersionKindMismatch(TokenKind expected, TokenKind got);
    error ImplementationNotAContract(address implementation);
    error VerifierUnsupportedOnThisChain(address verifier, string curveName);
    error VerifierRequiredForZether();
    error SaltAlreadyUsed(address existing);

    /// @notice `META_NONE` 0, `META_SINGLE` 1, `META_MULTI` 2–8 (token kiểm lại; factory kiểm để chỉ mục có nghĩa).
    function createTiered(
        TokenKind kind, uint64 version, address[] calldata underlyings, bytes calldata initData, bytes32 salt
    ) external returns (address token);

    /// @notice Như `createTiered` với implementation ngoài catalogue: `version == 0`, vẫn kiểm `tokenKind()`.
    function createTieredUnregistered(
        TokenKind kind, address implementation, address[] calldata underlyings, bytes calldata initData, bytes32 salt
    ) external returns (address token);
}
