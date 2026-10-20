// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {AdminLib} from "../metatx/AdminLib.sol";

// Positions in `IFactoryToken.Env.deps` (plan 5g-Z2): the `*_ZETHER` kinds' transfer, burn and inner-product verifiers
// and `ZetherDisclosure` of one curve (CTR-ZTH-20); the `*_PQZ` kinds' `UAPqzVerifier`.
uint256 constant ENV_ZETHER_TRANSFER = 0;
uint256 constant ENV_ZETHER_BURN = 1;
uint256 constant ENV_ZETHER_INNER_PRODUCT = 2;
uint256 constant ENV_ZETHER_DISCLOSURE = 3;
uint256 constant ENV_PQZ_VERIFIER = 0;

/// @title What `OpenFactory` needs from every token implementation (CTR-TOK-25, plan 5g-Z2): the release's deployment
///        environment `Env`, one generic `initialize(creator, version, initArgs)` the factory calls in the SAME call as
///        the clone's `CREATE2`, and `kind()`. The factory also reads `factory()`, `chainUid()` (`IMetaTx`) at deployment
///        and `features()`, `lockedFeatures()`, `owner()`, `underlyings()` after `initialize` (provenance, the index).
///        The kinds of this repository take `initArgs = abi.encode(TokenConfig)`; a later version may take another
///        encoding without a factory change.
interface IFactoryToken {
    /// @notice The deployment environment of a release (owner 2026-10-20, CTR-ZTH-20): the system dependencies the
    ///         factory publishes per kind and version (`OpenFactory.publishEnv`) and appends to every implementation's
    ///         init code as `abi.encode(envVersion, env, implArgs)`, so they are constructor immutables of the code by
    ///         construction. `factory` and `chainUid` are the factory's own; `registry` the UA registry (0 = none);
    ///         `deps` the kind's dependencies by position (`*_ZETHER`: `ENV_ZETHER_*`; `*_PQZ`: `ENV_PQZ_VERIFIER`; plain
    ///         kinds and the DEX: none); `libs` the linked libraries of the code, each checked against
    ///         `libCodeHashes` (`extcodehash`) when a release is deployed. Generic on purpose: a dependency is an
    ///         address with a documented position, not a named verifier field.
    struct Env {
        address factory;
        bytes32 chainUid;
        address registry;
        address smartKeyAccountImpl;
        bool hedera;
        address[] deps;
        address[] libs;
        bytes32[] libCodeHashes;
    }


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
    ///         The verifiers are not in it: they are the release's (`Env.deps`, CTR-ZTH-20); the creator picks them by
    ///         picking the version.
    struct ConfidentialConfig {
        bytes auditorKey;
        uint256 shieldScale;
        uint256 maxShielded;
        uint256 confidentialFee;
        uint8 disclosureMode;
        uint8 auditorMode;
        /// PQZ only (op 7, CTR-PQZ-25): a public amount credited to every listed leg of a multi-recipient transfer,
        /// paid by the sender with the fee; 0 = none. Zether kinds: must be 0.
        uint256 multiLegFee;
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

    /// @notice Called by the factory only, in the same call as the clone's `CREATE2`; `initArgs` is the creator's,
    ///         opaque to the factory (here `abi.encode(TokenConfig)`), decoded and validated by the implementation.
    function initialize(address creator, uint64 version, bytes calldata initArgs) external;

    /// @notice The token's underlyings in leg order, empty for the `NONE*` kinds: the factory's index reads it after
    ///         `initialize`.
    function underlyings() external view returns (address[] memory);

    /// @notice CTR-TOK-21 kind of the implementation (and of every clone).
    function kind() external view returns (uint8);
}
