// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "./IFactoryToken.sol";

/// @title The one token factory of a chain (CTR-TOK-03, CTR-TOK-25; plan 5g-Z2): an append-only catalogue of releases
///        per kind and of DEX releases, each the factory's own `CREATE2` of the registrar's init code with a published,
///        versioned deployment environment (`IFactoryToken.Env`) appended; EIP-1167 clones initialised in the same call
///        with the creator's opaque `initArgs`; no power over any token or DEX it created.
interface IOpenFactory {
    /// @notice CTR-TOK-21, a fresh enum (nothing deployed): the value equals the implementation's `kind()`.
    ///         `NONE_PQZ` / `UNDERLYING_PQZ` are built (P6g); ids 6 and 7 (the dropped
    ///         `*_ZETHER_PQZ` kinds) are never reused: an out-of-range kind fails ABI decoding.
    enum TokenKind {
        NONE,
        UNDERLYING,
        NONE_ZETHER,
        UNDERLYING_ZETHER,
        NONE_PQZ,
        UNDERLYING_PQZ
    }

    /// @notice A release: the factory-deployed code, the env version it was deployed with (its `keccak256(abi.encode(env))`
    ///         as `envHash`), the time from which `createToken` / `createDex` accept it (`usableFrom = deployment +
    ///         noticePeriod`), and whether it is deprecated (immediate, never undone).
    struct Release {
        address implementation;
        uint16 envVersion;
        bytes32 envHash;
        uint64 usableFrom;
        bool deprecated;
    }

    /// @notice An env domain: a `TokenKind` value, or `DEX_DOMAIN` for the DEX.
    event EnvPublished(uint8 indexed domain, uint16 indexed envVersion, bytes32 envHash);
    /// @notice The release hashes (owner 2026-10-20): the env's, the init code's (without the appended arguments, a
    ///         reproducible-build check) and the deployed code's.
    event ImplementationDeployed(
        TokenKind indexed kind, uint64 indexed version, address indexed implementation, uint16 envVersion, bytes32 envHash,
        bytes32 initcodeHash, bytes32 codeHash, uint64 usableFrom);
    event ImplementationDeprecated(TokenKind indexed kind, uint64 indexed version, string reason);
    event KindEnabled(TokenKind indexed kind, bool enabled);
    /// @notice The one event of a creation; `features`, `lockedFeatures`, `owner`, `underlyings` read from the token after
    ///         `initialize`.
    event TokenCreated(
        address indexed token, address indexed creator, TokenKind indexed kind, uint64 version, address implementation,
        uint256 features, uint256 lockedFeatures, address owner, address[] underlyings);
    event DexImplementationDeployed(
        uint64 indexed version, address indexed implementation, uint16 envVersion, bytes32 envHash, bytes32 initcodeHash,
        bytes32 codeHash, uint64 usableFrom);
    event DexImplementationDeprecated(uint64 indexed version, string reason);
    event DexCreated(address indexed dex, address indexed creator, uint64 version, address implementation, address admin);

    error NotRegistrar();
    error ChainUidZero();
    /// @notice The constructor's notice period exceeds `MAX_NOTICE_PERIOD` (30 days).
    error NoticePeriodTooLong(uint64 noticePeriod);
    /// @notice Creation of a kind the registrar has not enabled (plain kinds on from the start, confidential ones off).
    error KindDisabled(TokenKind kind);
    error VersionAlreadyRegistered(TokenKind kind, uint64 version, address existing);
    error VersionUnknown(TokenKind kind, uint64 version);
    /// @notice The implementation's `kind()` differs (`got = type(uint256).max` when it does not answer).
    error VersionKindMismatch(TokenKind expected, uint256 got);
    error ImplementationNotAContract(address implementation);
    error ImplementationFactoryMismatch(address implementation);
    error ChainUidMismatch(bytes32 expected, bytes32 got);
    /// @notice The factory's index takes at most 8 legs (`underlyings()` after `initialize`).
    error UnderlyingCountInvalid(uint256 n);
    error SaltAlreadyUsed(address existing);
    error DexVersionUnknown(uint64 version);
    error DexVersionAlreadyRegistered(uint64 version, address existing);
    /// @notice `createToken` / `createDex` refuse a deprecated version (owner 2026-10-20); existing tokens are untouched.
    error VersionDeprecated(TokenKind kind, uint64 version);
    error DexVersionDeprecated(uint64 version);
    /// @notice Before `usableFrom` (the notice period, owner 2026-10-20).
    error VersionNotYetUsable(TokenKind kind, uint64 version, uint64 usableFrom);
    error DexVersionNotYetUsable(uint64 version, uint64 usableFrom);
    /// @notice `createTokenUnregistered` is for the plain kinds only (owner 2026-10-19).
    error UnregisteredConfidentialKind(TokenKind kind);
    /// @notice No env `envVersion` published for the domain (version 0 included).
    error EnvUnknown(uint8 domain, uint16 envVersion);
    error EnvAlreadyPublished(uint8 domain, uint16 envVersion);
    /// @notice `factory` / `chainUid` not the factory's, `libs` and `libCodeHashes` of different lengths, or a library
    ///         code hash that pins nothing (`0` or `keccak256("")`).
    error EnvInvalid();
    /// @notice A linked library of the env does not have its published code hash (checked at each release deployment).
    error LibraryCodeHashMismatch(address library_, bytes32 expected, bytes32 got);
    /// @notice The `CREATE2` of a release failed without revert data (a constructor's revert is bubbled), e.g. a
    ///         runtime over the chain's code-size limit. Init code over the chain's init-code limit (EIP-3860) is an
    ///         exceptional halt of the factory's call frame instead: the registrar's call consumes all its gas and
    ///         fails without `DeployFailed`.
    error DeployFailed();

    function registrar() external view returns (address);
    function chainUid() external view returns (bytes32);
    /// @notice Seconds between a release's deployment and its first use (chain-configured: minutes on 7622, days on
    ///         22776; 0 on the dev chains and in tests).
    function noticePeriod() external view returns (uint64);
    /// @notice The env domain of the DEX (`type(uint8).max`).
    function DEX_DOMAIN() external view returns (uint8);

    /// @notice Registrar only: publishes env `envVersion` (from 1, append-only, never changed) of a kind's releases.
    ///         `env.factory` / `env.chainUid` must be this factory's (`EnvInvalid`).
    function publishEnv(TokenKind kind, uint16 envVersion, IFactoryToken.Env calldata env) external;
    function publishDexEnv(uint16 envVersion, IFactoryToken.Env calldata env) external;
    function envOf(TokenKind kind, uint16 envVersion) external view returns (IFactoryToken.Env memory);
    function dexEnvOf(uint16 envVersion) external view returns (IFactoryToken.Env memory);
    function latestEnvVersion(TokenKind kind) external view returns (uint16);
    function latestDexEnvVersion() external view returns (uint16);

    /// @notice Registrar only: on the kind's published env `envVersion` (named explicitly, `EnvUnknown` otherwise —
    ///         interim rule, controller proposal 2026-10-20, until the governance-matrix spec), checks each
    ///         `env.libs[i].codehash`, `CREATE2`s (salt `keccak256(abi.encode(kind, version))`)
    ///         `initcode ‖ abi.encode(envVersion, env, implArgs)`, checks `kind()`, `factory()`, `chainUid()`, records
    ///         the release with its env version and hash (usable after `noticePeriod`). Append-only, version 0 refused;
    ///         the same init code may be deployed again as a later version on another env.
    function deployImplementation(
        TokenKind kind,
        uint64 version,
        uint16 envVersion,
        bytes calldata initcode,
        bytes calldata implArgs
    ) external returns (address implementation);
    function deprecate(TokenKind kind, uint64 version, string calldata reason) external;
    /// @notice Registrar only; a confidential kind starts off.
    function setKindEnabled(TokenKind kind, bool on) external;
    function kindEnabled(TokenKind kind) external view returns (bool);
    function releaseOf(TokenKind kind, uint64 version) external view returns (Release memory);
    function implementationOf(TokenKind kind, uint64 version) external view returns (address);
    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool);
    /// @notice May name a deprecated or not yet usable release: clients pick the newest usable one.
    function latestVersion(TokenKind kind) external view returns (uint64);

    /// @notice Any usable, non-deprecated release of an enabled kind; `initArgs` opaque to the factory (for the kinds of
    ///         this repository `abi.encode(IFactoryToken.TokenConfig)`), validated by the implementation.
    function createToken(TokenKind kind, uint64 version, bytes calldata initArgs, bytes32 salt)
        external returns (address token);
    /// @notice Plain kinds only (`UnregisteredConfidentialKind`): any implementation of `kind` for this factory and chain,
    ///         recorded with `version == 0` — unvetted code: clients and the gateway trust `isRegisteredToken` only.
    function createTokenUnregistered(TokenKind kind, address implementation, bytes calldata initArgs, bytes32 salt)
        external returns (address token);

    function predictAddress(address implementation, address creator, bytes32 salt) external view returns (address);
    function isToken(address token) external view returns (bool);
    /// @notice Made by this factory from a release (`version ≠ 0`).
    function isRegisteredToken(address token) external view returns (bool);
    function creatorOf(address token) external view returns (address);
    function versionOf(address token) external view returns (TokenKind kind, uint64 version);
    /// @notice First token `creator` made over `underlying`; it may have several legs: read `underlyings()`.
    function getWrapper(address creator, address underlying) external view returns (address);
    function getWrapperCount(address creator, address underlying) external view returns (uint256);
    function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address);
    function deployCountFor(address underlying) external view returns (uint256);
    function deployedFor(address underlying, uint256 index) external view returns (address);

    /// @notice Registrar only: as `deployImplementation` for the DEX (salt `keccak256(abi.encode("dex", version))`, DEX
    ///         env `envVersion`); the release must answer `factory()` and `chainUid()`.
    function deployDexImplementation(uint64 version, uint16 envVersion, bytes calldata initcode, bytes calldata implArgs)
        external returns (address implementation);
    function dexReleaseOf(uint64 version) external view returns (Release memory);
    function dexImplementationOf(uint64 version) external view returns (address);
    /// @notice Registrar only: marks a DEX version deprecated; `createDex` then refuses it (existing DEXes untouched).
    function deprecateDex(uint64 version, string calldata reason) external;
    function isDexDeprecated(uint64 version) external view returns (bool);
    function latestDexVersion() external view returns (uint64);
    /// @notice An `SCaaSDex` clone of a usable, non-deprecated DEX release, `initialize(initArgs)` in the same call
    ///         (`initArgs = abi.encode(ISCaaSDex.DexConfig)`, CTR-DEX-24).
    function createDex(uint64 version, bytes calldata initArgs, bytes32 salt) external returns (address dex);
    /// @notice Advisory (clients and the node); tokens never consult it (CTR-DEX-19).
    function isDex(address dex) external view returns (bool);
    function dexVersionOf(address dex) external view returns (uint64);
}
