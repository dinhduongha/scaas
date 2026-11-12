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
    /// @dev A holder moves units out of an account to another, public balances only, with no record (CTR-GOV-20, owner
    ///      2026-11-05): any holder (never contract-only), `WHOLE` or `LIMITED`, on the regulated kinds 8-13 only; a plain
    ///      kind refuses it. Its entry is plan T32.
    uint8 internal constant OPERATOR_TRANSFER = 22;
    /// @dev The tax recipient and the one token-wide PERCENT rate of the regulated kinds 8-13 (pay-meta-tax spec §6, O9,
    ///      O10): a power, no scalar, no scope; any holder (an EOA, an `msig`, a contract), never contract-only; granted
    ///      with the issuer seat; never delay-relaxed (Q5).
    uint8 internal constant TAX = 23;
    /// @dev The PQZ kinds' proof storage mode (group 3h, PQZ proof path spec §5, O10): `setProofStore`, `NONE` (the proof in
    ///      calldata only) or `LOG` (each later debit's proof as an event); a power, no scalar, no scope; on kinds 4, 5, 12,
    ///      13 only; any holder (an EOA, a single-key UA, an `msig`, a contract), never contract-only; granted with the
    ///      issuer seat; never delay-relaxed. Disabling it freezes the current mode.
    uint8 internal constant PQZ_PROOF = 24;
    /// @dev Group 3l (wrap limits spec 2026-11-10-wrap-limits.md §2, R12): on the hybrids (`maxSupply != 0`) of the
    ///      wrapped kinds 1, 3, 5, 9, 11, 13 only (`WrapControlNeedsHybrid` on a pure-wrap token). 25 a capability: the owner
    ///      sets the four limits per leg, their token-wide caps, the net rule and the decay; 26 a power: the owner turns the
    ///      wrapper and unwrapper lists on and off, a holder writes members; 27 a power: a holder unwraps beyond its
    ///      entitlement. 26 and 27: any holder, never contract-only, never delay-relaxed.
    uint8 internal constant WRAP_LIMIT = 25;
    uint8 internal constant WRAP_LIST = 26;
    uint8 internal constant REDEEMER = 27;
    uint256 internal constant WRAP_CONTROLS = (1 << WRAP_LIMIT) | (1 << WRAP_LIST) | (1 << REDEEMER);
    /// @dev Round 3s (spec 2026-11-10-token-lists.md §3, CTR-GOV-24, owner 2026-11-10): the compliance registry check of the
    ///      regulated kinds 8-13, under one bit (what bits 8 and 9 did before): a capability, no holder; set at creation or
    ///      by `enableFeature`, at once; disabled by `disableFeature` after `grantDelay` (in the regulated delayed set).
    ///      Bits 8 and 9 are the token's own lists (`setAllowed`, `setDenied`): powers, any holder.
    uint8 internal constant KYC = 28;
    /// @dev The DEX's closed markets (owner 2026-11-12): on, `mtxSettle` and the hybrids take only a listed pair and the
    ///      exchange path only known tokens (`setMarket`); off, any pair and any token. A capability, no holder; off by
    ///      default, set and locked at creation only (`DexConfig.features` / `lockedFeatures`), never enabled later; the
    ///      admin's `disableFeature` opens the markets for good unless locked.
    uint8 internal constant CLOSED_MARKETS = 29;
    /// @dev The bits `enableFeature` may switch on (spec §5.2): 8, 9, 28, each only where the kind's mask holds it and not
    ///      locked. 8 and 9 are never disabled (`FeatureNotDisableable`). No plain kind's mask holds them.
    uint256 internal constant ENABLEABLE = (1 << ALLOWLIST) | (1 << DENYLIST) | (1 << KYC);
    uint256 internal constant NOT_DISABLEABLE = (1 << ALLOWLIST) | (1 << DENYLIST);

    /// @dev Flags 5–9 and 28 (CTR-AS-17, CTR-GOV-18, CTR-GOV-24): the controls of the regulated kinds 8–13; no plain kind's
    ///      valid mask holds them, so a plain kind refuses each with `FeatureInvalidForKind` (regulated-kinds spec Q3).
    uint256 internal constant REGULATED =
        (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << ALLOWLIST) | (1 << DENYLIST) | (1 << KYC);
    /// @dev `Roles.issuer`'s bits: `init` grants it each one that is set (regulated-kinds spec §2.4; bit 23, pay-meta-tax
    ///      spec §6.1, F-19; bit 24, PQZ proof path spec §5, which a plain PQZ kind's issuer seat takes alone), and each list
    ///      bit 8, 9 that is valid and not locked off, set or not (round 3s, spec §6.3, Fable P1-1, R-7: `enableable`).
    uint256 internal constant ISSUER_BITS = (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << ALLOWLIST) | (1 << DENYLIST)
        | (1 << TAX) | (1 << PQZ_PROOF);
    /// @dev What the PQZ kinds 4, 5, 12, 13 add to their base kind's valid and role masks (bit 24).
    uint256 internal constant PQZ_KIND_BITS = 1 << PQZ_PROOF;
    /// @dev The contract-only bits a threshold (`msig`) UA may hold as a contract (RK-1, CTR-AS-03 Change, owner
    ///      2026-11-05); any other contract-only bit (`RATE_ADJUSTABLE`) still takes a native id with code.
    uint256 internal constant REGULATED_ROLES =
        (1 << FREEZE) | (1 << FORCE) | (1 << PAUSE) | (1 << RECORD) | (1 << MODERATE);
    uint256 internal constant ALWAYS_LOCKED = (1 << PAYABLE) | (1 << BURNABLE) | (1 << RESCUABLE);

    // Per kind (CTR-TOK-22, spec §1.2). No plain kind takes a bit of 5-9 or 28: each refuses them as invalid for the kind;
    // the regulated kinds 8-13 hold them (CTR-AS-17, CTR-GOV-03, CTR-GOV-24), and bit 22 (CTR-GOV-20).
    /// @dev `RESCUABLE` on every token kind (spec §6.2, CTR-GOV-06): set at creation, always locked;
    ///      `rescueTo` comes only with it, and 0 there stores `SCAAS_DEV_RESCUE` (CTR-GOV-25).
    uint256 internal constant NORMAL_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE) | (1 << RESCUABLE);
    /// @dev `MINTABLE` makes a hybrid (spec §5.2, CTR-GOV-12): set at creation iff `maxSupply != 0`.
    uint256 internal constant WRAPPED_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE)
        | (1 << RESCUABLE) | WRAP_CONTROLS;
    /// @dev The masks of each kind (spec §1.2): the bits with a holder, those whose holder must have code, those whose power
    ///      passes the number it acts on (B-09), those whose power reads `use`'s scope (B-10). Every token kind: scalar bit 1,
    ///      no scope.
    uint256 internal constant NORMAL_ROLES = 1 << MINTABLE;
    uint256 internal constant WRAPPED_ROLES =
        (1 << MINTABLE) | (1 << RATE_ADJUSTABLE) | (1 << WRAP_DISABLEABLE) | (1 << WRAP_LIST) | (1 << REDEEMER);
    uint256 internal constant WRAPPED_CONTRACT_ONLY = 1 << RATE_ADJUSTABLE;
    uint256 internal constant TOKEN_SCALAR = 1 << MINTABLE;

    uint256 internal constant DEX_BITS = (1 << LISTING) | (1 << FEE_ROUTING);
    /// @dev The DEX's valid bits: its two powers and the capability `CLOSED_MARKETS`.
    uint256 internal constant DEX_VALID = DEX_BITS | (1 << CLOSED_MARKETS);

    /// @notice Round 3s, spec §5.5 (Fable P2-2): the bits of 8, 9, 28 that can still be switched on: valid for the kind, not
    ///         set, not locked (off), the admin not 0, and for 28 a compliance registry (it cannot be set after creation).
    ///         One predicate for the `termsHash` rule at init, the issuer seat's list bits, and every client's warning.
    function enableable(uint256 features, uint256 locked, uint256 valid, bytes32 admin, bool registry)
        internal pure returns (uint256 e)
    {
        if (admin == 0) return 0;
        e = ENABLEABLE & valid & ~features & ~locked;
        if (!registry) e &= ~(uint256(1) << KYC);
    }
}
