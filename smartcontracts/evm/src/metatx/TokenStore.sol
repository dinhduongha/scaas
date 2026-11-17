// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Identity and metadata of a token (ERC-7201 `scaas.token`), split from the governance fields (CTR-GOV-01).
library TokenStore {
    // ------------------------------------------------------------------ kinds (CTR-TOK-21, fresh enum)
    uint8 internal constant KIND_NORMAL = 0;
    uint8 internal constant KIND_WRAPPED = 1;
    uint8 internal constant KIND_NORMAL_ZETHER = 2;
    uint8 internal constant KIND_WRAPPED_ZETHER = 3;
    uint8 internal constant KIND_NORMAL_PQZ = 4;
    uint8 internal constant KIND_WRAPPED_PQZ = 5;
    // 6 and 7 retired (the dropped `*_ZETHER_PQZ`); the regulated kinds, each its base kind plus the regulated hooks
    // (CTR-GOV-16, regulated-kinds spec §2.1)
    uint8 internal constant KIND_NORMAL_REGULATED = 8;
    uint8 internal constant KIND_WRAPPED_REGULATED = 9;
    uint8 internal constant KIND_NORMAL_ZETHER_REGULATED = 10;
    uint8 internal constant KIND_WRAPPED_ZETHER_REGULATED = 11;
    uint8 internal constant KIND_NORMAL_PQZ_REGULATED = 12;
    uint8 internal constant KIND_WRAPPED_PQZ_REGULATED = 13;

    /// @custom:storage-location erc7201:scaas.token
    struct TokenStorage {
        address creator;
        uint64 version;
        uint8 kind;
        uint8 decimals;
        bool initialized;
        string name;
        string symbol;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.token")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0x83083067f3d1caf66741d4eeefa9d3f4f0e5b0793677731d6fee7e67b774ac00;

    function $() internal pure returns (TokenStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }
}
