// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The global table of bits 0-127 (owner 2026-11-02, CTR-GOV-10 and its Change of 2026-11-04): one meaning on every
///        SCaaS contract, allocated once, never renumbered. Bits 128-255 belong to each application contract, labelled by
///        `bitLabel`; no band is refused.
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
    uint8 internal constant DENYLIST = 9;
    uint8 internal constant RECORD = 10;
    uint8 internal constant LISTING = 11;
    uint8 internal constant FEE_ROUTING = 12;
    uint8 internal constant RESCUABLE = 17;
    uint8 internal constant MODERATE = 21;

    /// @dev Flags 5–9 (CTR-AS-17, CTR-GOV-18): refused while the controls are not built.
    uint256 internal constant REGULATED = (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << ALLOWLIST) | (1 << DENYLIST);
    uint256 internal constant ALWAYS_LOCKED = (1 << PAYABLE) | (1 << BURNABLE) | (1 << RESCUABLE);

    // Per kind (CTR-TOK-22, spec §1.2). No kind of this release takes a bit of 5-9: `NORMAL` and `WRAPPED` refuse them as not
    // built, the confidential kinds as invalid; that is today's built state (CTR-AS-17, CTR-GOV-03), not a permanent rule.
    uint256 internal constant NORMAL_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE);
    uint256 internal constant WRAPPED_BITS = (1 << PAYABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
    /// @dev The masks of each kind (spec §1.2): the bits with a holder, those whose holder must have code, those whose power
    ///      passes the number it acts on (B-09), those whose power reads `use`'s scope (B-10). Every token kind: scalar bit 1,
    ///      no scope.
    uint256 internal constant NORMAL_ROLES = 1 << MINTABLE;
    uint256 internal constant WRAPPED_ROLES = (1 << MINTABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE);
    uint256 internal constant WRAPPED_CONTRACT_ONLY = 1 << RATE_ADJUSTABLE;
    uint256 internal constant TOKEN_SCALAR = 1 << MINTABLE;

    uint256 internal constant DEX_BITS = (1 << LISTING) | (1 << FEE_ROUTING);
}
