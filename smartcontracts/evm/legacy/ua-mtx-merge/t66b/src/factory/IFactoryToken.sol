// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {TokenStore} from "../metatx/TokenStore.sol";

// Positions in `IFactoryToken.Env.deps` (plan 5g-Z2): the `*_ZETHER` kinds' transfer, burn and inner-product verifiers
// and `ZetherDisclosure` of one curve (CTR-ZTH-20); the `*_PQZ` kinds' `UAPqzVerifier`.
uint256 constant ENV_ZETHER_TRANSFER = 0;
uint256 constant ENV_ZETHER_BURN = 1;
uint256 constant ENV_ZETHER_INNER_PRODUCT = 2;
uint256 constant ENV_ZETHER_DISCLOSURE = 3;
uint256 constant ENV_PQZ_VERIFIER = 0;

/// @title What `OpenFactory` needs from every token implementation (CTR-TOK-25, CTR-TOK-29; plan 5g-Z2, chain-neutral spec
///        §2): chain-neutral code (`constructor(address factory_, bytes implArgs)`: the same bytes and address on every
///        chain), the instance's chain values in its own code (`ChainEnv`, appended to the clone by the factory and exposed
///        by `chainEnv()`), one generic `initialize(creatorId, version, initArgs)` the factory calls in the SAME call as
///        the clone's creation, `kind()` and `validateEnv`. The factory also reads `factory()` at deployment and
///        `chainUid()`, `features()`, `lockedFeatures()`, `owner()`, `underlyings()` after `initialize` (the post-check,
///        provenance, the index). The kinds of this repository take `initArgs = abi.encode(TokenConfig)`; a later version
///        may take another encoding without a factory change.
interface IFactoryToken {
    /// @notice The registrar's deployment environment of a release (owner 2026-10-20, CTR-ZTH-20; chain-neutral spec §2.1):
    ///         the chain values the factory publishes per kind and version (`OpenFactory.publishEnv`), never changed.
    ///         `registry` the UA registry (0 = none; its `chainUid()` must be the factory's); `deps` the kind's dependencies
    ///         by position (`*_ZETHER`: `ENV_ZETHER_*`; `*_PQZ`: `ENV_PQZ_VERIFIER`; plain kinds and the DEX: none; at most
    ///         4); `params` a generic class's chain values by documented position (at most 2); `libs` the linked
    ///         libraries of the code, each checked against `libCodeHashes` (`extcodehash`) when a release is deployed.
    ///         The factory's own values (`chainUid`, the router, its address) are not in it: it fills them.
    struct Env {
        address registry;
        address smartKeyAccountImpl;
        bool hedera;
        address[] deps;
        bytes32[] params;
        address[] libs;
        bytes32[] libCodeHashes;
    }

    /// @notice The chain values of one instance (CTR-TOK-29): the factory composes it from its own `chainUid` and
    ///         `govRouter` and the release's `Env`, and appends it to the clone's runtime code (`ChainEnvCode`); never a
    ///         parameter of an entry a caller reaches. `govRouter` this chain's `GovernanceRouter` (0 = none): a call
    ///         from it acts for the UA it authenticated.
    struct ChainEnv {
        bytes32 chainUid;
        address registry;
        address govRouter;
        address smartKeyAccountImpl;
        bool hedera;
        address[] deps;
        bytes32[] params;
    }

    /// @notice `initialize` on code that is not a clone with a well-formed env (counts within the bounds, the length
    ///         exact, `chainUid` not 0): the implementation, or a clone made outside the factory (Fable P3-4).
    error EnvMissing();

    /// @notice One leg of an `WRAPPED*` kind: `underlying` (`address(0)` = the native coin, CTR-TOK-26), rate
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

    /// @notice The confidential kinds (`*_ZETHER`, `*_PQZ`) only; every other kind requires it empty. `maxShielded` (the total cap, `≤ 2^54`) and
    ///         `confidentialFee` (the inner fee, `< 2^64` and `< maxShielded`) are per token (CTR-ZTH-04, CTR-ZTH-05).
    ///         The two modes are fixed for the token's life (CTR-ZTH-38, CTR-ZTH-42): `disclosureMode` 0 `BUNDLE` (the
    ///         default: every transfer entry, `mtxConfidentialTransfer` stores the record) or 1 `COMPACT` (commit-reveal only);
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
        /// Both layers (owner 2026-10-20): the least per-leg `decoyFee` a sender may put in a multi-recipient payload
        /// (PQZ op 7, CTR-PQZ-25; Zether `mtxConfidentialTransfer*` multi); the sender's `decoyFee` goes to every leg's
        /// public balance. Immutable; 0 allowed (the default).
        uint256 minDecoyFee;
        /// `*_PQZ` kinds only (group 3f, PQZ verifier mode spec §3, AV-2; every other kind requires the three empty):
        /// `pqzVerifyMode` 0 `PRECOMPILE` (the default, the precompile's verdict) or 1 `OFFCHAIN` (a verdict signed by
        /// `pqzVerifierUA`), any other value `PqzVerifyModeInvalid`; `pqzVerifierUA` 0 in `PRECOMPILE`, the verifier UA in
        /// `OFFCHAIN`; `pqzVerifierFixed` false in `PRECOMPILE`, in `OFFCHAIN` true = fixed for ever, false = transferable
        /// with the factory's notice. A field set against the mode: `PqzVerifyConfigInvalid`. Immutable mode.
        uint8 pqzVerifyMode;
        bytes32 pqzVerifierUA;
        bool pqzVerifierFixed;
        /// `*_PQZ` kinds only (group 3h, pqz-proof-path spec §4.1, PP-4, C8; every other kind requires 0): where each debit's
        /// proof and its 640-byte header live besides the transaction's calldata: 0 `NONE` (the default, calldata only) or 1
        /// `LOG` (a `PqzDebitProof` event of the token); any other value `ProofStoreInvalid`. Changed later only through bit
        /// 24 `PQZ_PROOF` (`setProofStore`), effective at the next debit.
        uint8 proofStore;
    }

    /// @notice Regulated-kinds spec §2.4: the regulated kinds' (8-13) only; a plain kind (0-5) refuses any set field
    ///         (`ConfigFieldForOtherKind(6)`). `complianceRegistry` ≠ 0 iff `ALLOWLIST` or `DENYLIST` (its code pinned by
    ///         the release); `requiredFlags` ≠ 0 iff `ALLOWLIST`; `deniedFlags` ≠ 0 iff `DENYLIST`; `termsHash` ≠ 0 iff
    ///         any of bits 5-10, 21. The regulated kinds check it at init.
    struct RegulatedParams {
        address complianceRegistry;
        uint64 requiredFlags;
        uint64 deniedFlags;
        bytes32 termsHash;
        bytes32 taxRecipient; // pay-meta-tax spec §6.2: != 0 iff bit 23 `TAX`
    }

    /// @notice CTR-TOK-25. Fields of another kind must be empty (`ConfigFieldForOtherKind`), so a token never carries a
    ///         setting it ignores and the factory's underlying index never lies.
    struct TokenConfig {
        string name;
        string symbol;
        uint8 decimals;
        uint256 features;
        uint256 lockedFeatures;
        bytes32 owner;               // a UA id (a native account: its padded address); 0 = no administration ever
        GovernanceLib.Roles roles;        // initial holders, each only for a set flag
        uint256 initialSupply;       // NORMAL* only
        address initialHolder;       // NORMAL* only
        Leg[] legs;                  // WRAPPED* only, 1..8
        RateConfig rate;             // WRAPPED* only, with RATE_ADJUSTABLE
        ConfidentialConfig conf;     // *_ZETHER only
        uint64 grantDelay;           // spec §1.6: the owner's two calls, at most 30 days; 0 = one call
        address rescueTo;            // spec §6.2: with `RESCUABLE` only, immutable; never the token or a pool
        uint256 maxSupply;           // WRAPPED* only, spec §5.2: the hybrid's cap, with `MINTABLE` only; 0 = no hybrid
        RegulatedParams reg;         // *_REGULATED (8-13) only
    }

    /// @notice A field set for another kind (`field`: 1 initialSupply/initialHolder, 2 legs, 3 rate, 4 conf, 5 maxSupply,
    ///         6 reg).
    error ConfigFieldForOtherKind(uint8 field);

    /// @notice Called by the factory only, in the same call as the clone's creation, on a clone carrying its env
    ///         (`EnvMissing`); `creatorId` the creator's UA id (S3); `initArgs` is the creator's, opaque to the factory
    ///         (here `abi.encode(TokenConfig)`), decoded and validated by the implementation.
    function initialize(bytes32 creatorId, uint64 version, bytes calldata initArgs) external;

    /// @notice The token's underlyings in leg order, empty for the `NORMAL*` kinds: the factory's index reads it after
    ///         `initialize`.
    function underlyings() external view returns (address[] memory);

    /// @notice CTR-TOK-21 kind of the implementation (and of every clone).
    function kind() external view returns (uint8);

    /// @notice This instance's env, decoded from its code; all zero on the implementation.
    function chainEnv() external view returns (ChainEnv memory);

    /// @notice The kind's checks of an env (the constructor checks before chain-neutral releases): reverts (`BadInit`)
    ///         unless this code can run on `env`. The factory calls it by `staticcall` once per release and chain.
    function validateEnv(ChainEnv calldata env) external view;
}

/// @dev Regulated-kinds spec §2.4: a plain kind (0-5) refuses a set `reg` with `ConfigFieldForOtherKind(6)`; a regulated kind
///      (8-13) reads it. Every init path of the kinds calls it with the token's own `kind()`.
function requireRegOfKind(uint8 kind, IFactoryToken.RegulatedParams memory r) pure {
    if (kind < TokenStore.KIND_NORMAL_REGULATED && (r.complianceRegistry != address(0) || r.requiredFlags != 0
        || r.deniedFlags != 0 || r.termsHash != 0)) revert IFactoryToken.ConfigFieldForOtherKind(6);
}
