// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Cổng an toàn của owner (R34, ruling RS2-1): Zether chỉ sống trên chain dev.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Allowlist cứng, không cấu hình được: một danh sách
///         truyền vào constructor sẽ cho người deploy ghi chain id mainnet vào. Thêm một chain = sửa
///         file này + deploy version mới, tức là một quyết định có review, không phải một tham số.
library ZetherSafety {
    error ZetherNotDevChain(uint256 chainId);

    function isDevChain() internal view returns (bool) {
        return block.chainid == 31337   // anvil / hardhat
            || block.chainid == 1337;   // geth --dev
    }

    function requireDevChain() internal view {
        if (!isDevChain()) revert ZetherNotDevChain(block.chainid);
    }
}
