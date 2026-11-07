// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "./IFactoryToken.sol";

/// @title The one token factory of a chain (CTR-TOK-03, CTR-TOK-25, CTR-TOK-29; plan 5g-Z2): an append-only catalogue of
///        releases per kind and of DEX releases, each the factory's own `CREATE2` of the registrar's chain-neutral init
///        code, under a published, versioned deployment environment (`IFactoryToken.Env`); CREATE3 instances (EIP-1167
///        clones with the instance's `ChainEnv` appended) initialised in the same call with the creator's opaque
///        `initArgs`; no power over any token or DEX it created. Chain-neutral spec: the factory, every release and every
///        instance have the same address on every chain; the chain's values are written once (`configureChain`).
interface IOpenFactory {
    /// @notice CTR-TOK-21, a fresh enum (nothing deployed): the value equals the implementation's `kind()`.
    ///         `NORMAL_PQZ` / `WRAPPED_PQZ` are built (P6g); ids 6 and 7 (the dropped
    ///         `*_ZETHER_PQZ` kinds) are never reused: an out-of-range kind fails ABI decoding.
    /// @notice CTR-GOV-16, spec §4.1: every id is a real member before the factory freezes. 6 and 7 are the dropped
    ///         `*_ZETHER_PQZ` ids, never reused: `deployImplementation` refuses them (`KindRetired`). 8-13, the regulated
    ///         kinds, are off until a release is published and the kind enabled.
    enum TokenKind {
        NORMAL,                   // 0
        WRAPPED,                  // 1
        NORMAL_ZETHER,            // 2
        WRAPPED_ZETHER,           // 3
        NORMAL_PQZ,               // 4
        WRAPPED_PQZ,              // 5
        RETIRED_6,                // 6, the dropped NORMAL_ZETHER_PQZ, never reused
        RETIRED_7,                // 7, the dropped WRAPPED_ZETHER_PQZ, never reused
        NORMAL_REGULATED,         // 8
        WRAPPED_REGULATED,        // 9
        NORMAL_ZETHER_REGULATED,  // 10
        WRAPPED_ZETHER_REGULATED, // 11
        NORMAL_PQZ_REGULATED,     // 12
        WRAPPED_PQZ_REGULATED     // 13
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

    /// @notice Factory index spec §2.1 (CTR-TOK-27, owner 2026-11-07): one record per contract this factory created, in
    ///         its own state, never changed or deleted. `creatorId` the creator's UA id (a direct call: `pad(msg.sender)`);
    ///         `ownerUA` the contract's `owner()` right after `initialize` (a claim, 0 = no administration ever);
    ///         (a signed creation through the router: the signing UA, S3);
    ///         `contractClass` `CLASS_TOKEN` (`kind` a `TokenKind`) or `CLASS_DEX` (`kind` 0), 0 = not made here; `version`
    ///         the release (0 = `createTokenUnregistered`); `createdBlock` / `createdAt` the chain's `block.number` /
    ///         `block.timestamp`.
    struct Created {
        address addr;
        bytes32 creatorId;
        bytes32 ownerUA;
        uint16 contractClass;
        uint16 kind;
        uint64 version;
        uint64 createdBlock;
        uint64 createdAt;
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
    ///         `creatorId` the creator's UA id (S3; a native creator's topic is its padded address).
    event TokenCreated(
        address indexed token, bytes32 indexed creatorId, TokenKind indexed kind, uint64 version, address implementation,
        uint256 features, uint256 lockedFeatures, bytes32 owner, address[] underlyings);
    event DexImplementationDeployed(
        uint64 indexed version, address indexed implementation, uint16 envVersion, bytes32 envHash, bytes32 initcodeHash,
        bytes32 codeHash, uint64 usableFrom);
    event DexImplementationDeprecated(uint64 indexed version, string reason);
    event DexCreated(address indexed dex, bytes32 indexed creatorId, uint64 version, address implementation, bytes32 owner);
    /// @notice The chain's one-time values (chain-neutral spec §3.1).
    event ChainConfigured(bytes32 indexed chainUid, uint64 noticePeriod, address govRouter);

    error NotRegistrar();
    error ChainUidZero();
    /// @notice `configureChain`'s notice period exceeds `MAX_NOTICE_PERIOD` (30 days).
    error NoticePeriodTooLong(uint64 noticePeriod);
    /// @notice Every creation, publish and deploy entry before `configureChain`.
    error ChainNotConfigured();
    error ChainAlreadyConfigured();
    /// @notice The chain can prove its genesis hash (`BLOCKHASH(0)`, EIP-2935) and `given` is not it.
    error ChainUidNotGenesis(bytes32 given, bytes32 provable);
    /// @notice The reference block's hash on this chain is not `given` (`actual` 0: the chain cannot answer).
    error RefBlockMismatch(uint256 refBlock, bytes32 given, bytes32 actual);
    /// @notice The CREATE3 proxy's `CREATE` of the instance failed (it answers success there, Fable P2-5).
    error InstanceNotCreated();
    /// @notice A release's `validateEnv` reverted without data (it has none, or it failed without a reason).
    error EnvRefused(address implementation);
    /// @notice Creation of a kind the registrar has not enabled (plain kinds on from the start, confidential ones off).
    error KindDisabled(TokenKind kind);
    error VersionAlreadyRegistered(TokenKind kind, uint64 version, address existing);
    error VersionUnknown(TokenKind kind, uint64 version);
    /// @notice 6 and 7 are retired ids: no release of them is ever deployed (CTR-GOV-16).
    error KindRetired(TokenKind kind);
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
    /// @notice `libs` and `libCodeHashes` of different lengths, a library code hash that pins nothing (`0` or
    ///         `keccak256("")`), more than 4 `deps` or 2 `params`.
    error EnvInvalid();
    /// @notice A linked library of the env does not have its published code hash (checked at each release deployment).
    error LibraryCodeHashMismatch(address library_, bytes32 expected, bytes32 got);
    /// @notice The `CREATE2` of a release failed without revert data (a constructor's revert is bubbled), e.g. a
    ///         runtime over the chain's code-size limit. Init code over the chain's init-code limit (EIP-3860) is an
    ///         exceptional halt of the factory's call frame instead: the registrar's call consumes all its gas and
    ///         fails without `DeployFailed`.
    error DeployFailed();
    /// @notice A list view of class 0 or of a class this factory does not make.
    error ClassUnknown(uint16 contractClass);
    /// @notice A page of more than `MAX_PAGE` records.
    error PageTooLarge(uint256 n);

    function registrar() external view returns (address);
    /// @notice Registrar only, once (chain-neutral spec §3.1): this chain's `chain_uid` (≠ 0; its genesis hash whenever the
    ///         EVM can prove it: `ChainUidNotGenesis`), the notice period (≤ `MAX_NOTICE_PERIOD`), the router (0 = none;
    ///         its `chainUid()` must be `chainUid_`) and a reference block (`refBlock ≠ 0`: its hash on this chain must be
    ///         `refHash`, `RefBlockMismatch`; 0 on a chain whose `BLOCKHASH` is not its own block hash).
    function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_, uint256 refBlock, bytes32 refHash)
        external;
    /// @notice 0 until `configureChain`.
    function chainUid() external view returns (bytes32);
    /// @notice Seconds between a release's deployment and its first use (chain-configured: minutes on 7622, days on
    ///         22776; 0 on the dev chains and in tests).
    function noticePeriod() external view returns (uint64);
    /// @notice This chain's `GovernanceRouter` (0 = none): every instance's `ChainEnv.govRouter`.
    function govRouter() external view returns (address);
    /// @notice The env domain of the DEX (`type(uint8).max`).
    function DEX_DOMAIN() external view returns (uint8);

    /// @notice Registrar only: publishes env `envVersion` (from 1, append-only, never changed) of a kind's releases. A
    ///         `registry ≠ 0` must name this factory's `chainUid` (`ChainUidMismatch`).
    function publishEnv(TokenKind kind, uint16 envVersion, IFactoryToken.Env calldata env) external;
    function publishDexEnv(uint16 envVersion, IFactoryToken.Env calldata env) external;
    function envOf(TokenKind kind, uint16 envVersion) external view returns (IFactoryToken.Env memory);
    function dexEnvOf(uint16 envVersion) external view returns (IFactoryToken.Env memory);
    function latestEnvVersion(TokenKind kind) external view returns (uint16);
    function latestDexEnvVersion() external view returns (uint16);

    /// @notice Registrar only: on the kind's published env `envVersion` (named explicitly, `EnvUnknown` otherwise —
    ///         interim rule, controller proposal 2026-10-20, until the governance-matrix spec), checks each
    ///         `env.libs[i].codehash`, `CREATE2`s (salt `keccak256(abi.encode(kind, version))`) the chain-neutral
    ///         `initcode ‖ abi.encode(address(this), implArgs)` (the same address on every chain), checks `kind()`,
    ///         `factory()` and the release's `validateEnv` of the instance env, records the release with its env version
    ///         and hash (usable after `noticePeriod`). Append-only, version 0 refused; the same init code may be deployed
    ///         again as a later version on another env.
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
    /// @notice Plain kinds only (`UnregisteredConfidentialKind`): any implementation of `kind` for this factory, on the
    ///         kind's latest env, recorded with `version == 0` — unvetted code: clients and the gateway trust
    ///         `isRegisteredToken` only.
    function createTokenUnregistered(TokenKind kind, address implementation, bytes calldata initArgs, bytes32 salt)
        external returns (address token);

    /// @notice CREATE3 (chain-neutral spec §4.2): one view for every path; the address says nothing about the version,
    ///         the code or the configuration on a chain (read `infoOf` and the instance per chain).
    function predictAddress(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt)
        external view returns (address);
    function isToken(address token) external view returns (bool);
    /// @notice Made by this factory from a release (`version ≠ 0`).
    function isRegisteredToken(address token) external view returns (bool);
    /// @notice The creator's address for a native `creatorId`, 0 for a derived one (`infoOf`) or a non-token.
    function creatorOf(address token) external view returns (address);
    function versionOf(address token) external view returns (TokenKind kind, uint64 version);
    /// @notice First token `creatorId` made over `underlying`; it may have several legs: read `underlyings()`.
    function getWrapper(bytes32 creatorId, address underlying) external view returns (address);
    function getWrapperCount(bytes32 creatorId, address underlying) external view returns (uint256);
    function getWrapperAt(bytes32 creatorId, address underlying, uint256 index) external view returns (address);
    function deployCountFor(address underlying) external view returns (uint256);
    function deployedFor(address underlying, uint256 index) external view returns (address);

    /// @notice Registrar only: as `deployImplementation` for the DEX (salt `keccak256(abi.encode("dex", version))`, DEX
    ///         env `envVersion`); the release must answer `factory()` and accept the env (`validateEnv`).
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

    // ------------------------------------------------------------------ the index (factory index spec §2, CTR-TOK-27)

    function CLASS_TOKEN() external view returns (uint16);
    function CLASS_DEX() external view returns (uint16);
    function MAX_PAGE() external view returns (uint256);
    /// @notice The record of `c`; `contractClass == 0` when this factory did not create it.
    function infoOf(address c) external view returns (Created memory);
    /// @notice Every contract of `contractClass`, in creation order (oldest first), `n` (≤ `MAX_PAGE`) records from
    ///         `from`, and the list's length. `from ≥ total` is an empty page; `n = 0` answers only `total`.
    function contractsPage(uint16 contractClass, uint256 from, uint256 n)
        external view returns (Created[] memory page, uint256 total);
    /// @notice The contracts that named `ownerUA` as owner at their creation (a claim; never for `ownerUA` 0).
    function contractsOfOwner(bytes32 ownerUA, uint16 contractClass, uint256 from, uint256 n)
        external view returns (Created[] memory page, uint256 total);
    /// @notice The contracts `creatorId` created (authenticated: the direct caller).
    function contractsOfCreator(bytes32 creatorId, uint16 contractClass, uint256 from, uint256 n)
        external view returns (Created[] memory page, uint256 total);
}
