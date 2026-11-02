// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The global table of bits 0–63 (owner 2026-11-02, CTR-GOV-10): one meaning on every SCaaS contract, allocated once,
///        never renumbered. Bits 64–127 belong to each application contract, bits 128 and above are refused. Prototype.
library GovernanceBits {
    uint8 internal constant PAYABLE = 0;
    uint8 internal constant MINTABLE = 1;
    uint8 internal constant BURNABLE = 2;
    uint8 internal constant RATE_ADJUSTABLE = 3;
    uint8 internal constant WRAP_DISABLEABLE = 4;
    uint8 internal constant FREEZE = 5;
    uint8 internal constant FORCE = 6;
    uint8 internal constant PAUSE = 7;
    uint8 internal constant ALLOWLIST = 8;
    uint8 internal constant MODERATE = 9;
    uint8 internal constant RECORD = 10;
    uint8 internal constant LISTING = 11;
    uint8 internal constant FEE_ROUTING = 12;
    uint8 internal constant RESCUABLE = 17;

    /// @dev Flags 5–8 (CTR-AS-17): refused while the controls are not built.
    uint256 internal constant REGULATED = (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << ALLOWLIST);
    uint256 internal constant ALWAYS_LOCKED = (1 << PAYABLE) | (1 << BURNABLE) | (1 << RESCUABLE);

    // Per kind (CTR-TOK-22). The confidential kinds' refusal of flags 5–8 is today's built state (CTR-AS-17), not a
    // permanent rule: their regulated versions are open, owner, not designed (CTR-GOV-03).
    uint256 internal constant NORMAL_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE);
    uint256 internal constant WRAPPED_BITS = (1 << PAYABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
    /// @dev Every token kind: the bits with a holder, and those whose holder must have code.
    uint256 internal constant TOKEN_ROLES = (1 << MINTABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
    uint256 internal constant TOKEN_CONTRACT_ONLY = 1 << RATE_ADJUSTABLE;

    uint256 internal constant DEX_BITS = (1 << LISTING) | (1 << FEE_ROUTING);
}
