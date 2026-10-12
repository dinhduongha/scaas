// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";

/// @title Hợp đồng giữa `OpenFactoryV2` và implementation v2 (ba tầng, TW2 §9).
/// @notice Khác `IFactoryToken` v1 ở hai điểm: `underlyings` là một mảng (tầng 3 có 2–8 chân) và không có
///         `verifier` (không token v2 nào là Zether). `tokenKind()` cho factory kiểm lúc đăng ký và lúc tạo
///         không đăng ký, để một version không bao giờ nằm sai kind (R130).
interface IFactoryTokenV2 {
    function tokenKind() external pure returns (IOpenFactoryV2.TokenKind);

    function initialize(
        address creator,
        address[] calldata underlyings,
        uint64 version,
        bytes calldata initData
    ) external;
}
