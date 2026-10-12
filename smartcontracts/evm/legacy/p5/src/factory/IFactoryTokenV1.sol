// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

/// @title Hợp đồng giữa `OpenFactoryV1` và MỌI implementation, kể cả kind ZETHER.
/// @notice Một hàm. Factory gọi nó trong CÙNG lời gọi với `CREATE2` (01-token-factory
///         §1.4.3 lớp 1), và implementation phải từ chối mọi người gọi khác factory
///         (lớp 2). Tham số per-token chỉ có đúng một đường đến: ở đây.
interface IFactoryTokenV1 {
    function initialize(
        address creator,
        address underlying,
        address verifier,
        uint64 version,
        bytes calldata initData
    ) external;
}
