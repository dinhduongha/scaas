// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The ML-DSA expanded-key cache's part transactions, measured (round 3zh, owner 2026-11-15; spec MD-5 / F-5)
/// @notice Per kind (rows 0, 1, 2 = `mldsa44`, `mldsa65`, `mldsa87`) and part (`PqUA.mldsaParts`): the least working gas limit
///         of the `cacheExpandedKey` call, its regular share (forge charges a nested call's EIP-8037 state gas to its limit: the
///         least working limit less the state gas), plus 100,000 for the transaction's intrinsic gas and calldata, rounded up
///         to 10,000 (`regular`), and its EIP-8037 state gas (`state`, exact), as `test/ua/UARegistryPq.t.sol`
///         `test_mldsaCache_partLeastWorkingGas` measures and pins them (2026-11-15, forge 1.8.5, Amsterdam).
///         `DeployBase._cacheFits` checks them against 2^24 and the chain's block gas limit at deploy time (MD-5). UNAUDITED.
library DeployGas {
    function regular() internal pure returns (uint64[3][3] memory r) {
        // measured least working regular share: 9,630,460 | 7,190,993, 10,125,976 | 10,082,105, 10,081,942, 10,621,914
        r = [
            [uint64(9_740_000), 0, 0], [uint64(7_300_000), 10_230_000, 0], [uint64(10_190_000), 10_190_000, 10_730_000]
        ];
    }

    function state() internal pure returns (uint64[3][3] memory s) {
        s = [
            [uint64(31_715_370), 0, 0],
            [uint64(23_783_850), 33_282_090, 0],
            [uint64(33_184_170), 33_184_170, 34_848_810]
        ];
    }
}
