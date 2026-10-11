// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AdminLib} from "../metatx/AdminLib.sol";

/// @title What `OpenFactory` needs from every token implementation (CTR-TOK-25): the creation config, one
///        `initialize` the factory calls in the SAME call as `CREATE2`, and `kind()`. The factory also reads
///        `factory()` and `chainUid()` (`IMetaTx`) at registration.
interface IFactoryToken {
    /// @notice One leg of an `UNDERLYING*` kind: `underlying` (`address(0)` = the native coin, CTR-TOK-26), rate
    ///         `num/den` (CTR-TOK-04). `uint256` so a value `≥ 2^96` reverts `RateInvalid` instead of failing to decode.
    struct Leg {
        address underlying;
        uint256 num;
        uint256 den;
    }

    /// @notice With `RATE_ADJUSTABLE`: `2 days ≤ rateDelay ≤ 30 days`, `1 ≤ maxRateStepBps ≤ 1000`; without: both 0.
    struct RateConfig {
        uint32 rateDelay;
        uint16 maxRateStepBps;
    }

    /// @notice `*_ZETHER` kinds only; every other kind requires it empty. `maxShielded` (the total cap, `≤ 2^54`) and
    ///         `confidentialFee` (the inner fee, `< 2^64` and `< maxShielded`) are per token (CTR-ZTH-04, CTR-ZTH-05).
    ///         The two modes are fixed for the token's life (CTR-ZTH-38, CTR-ZTH-42): `disclosureMode` 0 `BUNDLE` (the
    ///         default: every transfer entry, `zetherTransfer` stores the record) or 1 `COMPACT` (commit-reveal only);
    ///         `auditorMode` 0 `NONE` (no key, every `C_aud = O`), 1 `FULL` (key, every transfer includes the auditor)
    ///         or 2 `OPTIONAL` (key, the sender may leave the auditor out per transfer). `ZetherTypes` names the values.
    struct ConfidentialConfig {
        address verifier;
        bytes auditorKey;
        uint256 shieldScale;
        uint256 maxShielded;
        uint256 confidentialFee;
        uint8 disclosureMode;
        uint8 auditorMode;
    }

    /// @notice CTR-TOK-25. Fields of another kind must be empty (`ConfigFieldForOtherKind`), so a token never carries a
    ///         setting it ignores and the factory's underlying index never lies.
    struct TokenConfig {
        string name;
        string symbol;
        uint8 decimals;
        uint256 features;
        uint256 lockedFeatures;
        address owner;               // 0 = no administration ever
        AdminLib.Roles roles;        // initial holders, each only for a set flag
        uint256 initialSupply;       // NONE* only
        address initialHolder;       // NONE* only
        Leg[] legs;                  // UNDERLYING* only, 1..8
        RateConfig rate;             // UNDERLYING* only, with RATE_ADJUSTABLE
        ConfidentialConfig conf;     // *_ZETHER only
    }

    /// @notice A field set for another kind (`field`: 1 initialSupply/initialHolder, 2 legs, 3 rate, 4 conf).
    error ConfigFieldForOtherKind(uint8 field);

    /// @notice Called by the factory only, in the same call as the clone's `CREATE2`.
    function initialize(address creator, uint64 version, TokenConfig calldata cfg) external;

    /// @notice CTR-TOK-21 kind of the implementation (and of every clone).
    function kind() external view returns (uint8);
}
