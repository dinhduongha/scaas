// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// F185: a write to a fresh slot costs 22,100 (cold) on Osaka and well over 40,000 under Amsterdam (EIP-8037 state gas,
/// EIP-8038), so the active EVM is told apart by what it charges. For tests whose bound differs per EVM (the `zether`
/// profile and the public-chain profiles stay Osaka).
contract SlotWriteProbe {
    uint256 internal s;

    function write() external returns (uint256 g) {
        g = gasleft();
        s = 1;
        g -= gasleft();
    }
}

function isAmsterdam() returns (bool) {
    return new SlotWriteProbe().write() > 40_000;
}
