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

    /// @notice `*_ZETHER` kinds only (P3); every other kind requires it empty.
    struct ConfidentialConfig {
        address verifier;
        bytes auditorKey;
        uint256 shieldScale;
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
