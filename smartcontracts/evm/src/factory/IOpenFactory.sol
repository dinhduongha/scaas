// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "./IFactoryToken.sol";
import {IAdmin} from "../governance/IAdmin.sol";

/// @title The one token factory of a chain (CTR-TOK-03, CTR-TOK-25, CTR-TOK-29; plan 5g-Z2): an append-only catalogue of
///        releases per kind and of DEX releases, each the factory's own `CREATE2` of chain-neutral init code the admin
///        approved, under a published, versioned deployment environment (`IFactoryToken.Env`); CREATE3 instances (EIP-1167
///        clones with the instance's `ChainEnv` appended) initialised in the same call with the creator's opaque
///        `initArgs`; no power over any token or DEX it created. Chain-neutral spec: the factory, every release and every
///        instance have the same address on every chain; the chain's values are written once (`configureChain`).
///        Round 3r (CTR-GOV-23, spec 2026-11-10-admin-not-owner.md §5.2, §5.6): one UA admin (`IAdmin`, a native first
///        admin from the constructor, a two-step transfer, a renounce), every admin op `onlyAdmin`; a release is approved
///        by hash and deployed by anyone, the native admin's own deploy its own approval. **UNAUDITED.**
interface IOpenFactory is IAdmin {
    /// @notice CTR-TOK-21, a fresh enum (nothing deployed): the value equals the implementation's `kind()`.
    ///         `NORMAL_PQZ` / `WRAPPED_PQZ` are built (P6g); ids 6 and 7 (the dropped
    ///         `*_ZETHER_PQZ` kinds) are never reused: an out-of-range kind fails ABI decoding.
    /// @notice CTR-GOV-16, spec §4.1: every id is a real member before the factory freezes. 6 and 7 are the dropped
    ///         `*_ZETHER_PQZ` ids, never reused: `deployTokenImplementation` refuses them (`KindRetired`). 8-13, the regulated
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
    ///         its own state, never changed or deleted. `creatorId` the creator's UA id (a direct call: `pad(msg.sender)`;
    ///         a signed creation through the router: the signing UA, S3); no owner (round 3r R1, CTR-GOV-23: an admin
    ///         moves, so the current one is the contract's own `admin()`, its history the contract's own events);
    ///         `contractClass` `CLASS_TOKEN` (`kind` a `TokenKind`) or `CLASS_DEX` (`kind` 0), 0 = not made here; `version`
    ///         the release (0 = `createTokenUnregistered`); `createdBlock` / `createdAt` the chain's `block.number` /
    ///         `block.timestamp`.
    struct Created {
        address addr;
        bytes32 creatorId;
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
    event TokenImplementationDeprecated(TokenKind indexed kind, uint64 indexed version, string reason);
    event TokenKindEnabled(TokenKind indexed kind, bool enabled);
    /// @notice The one event of a creation; `features`, `lockedFeatures`, `underlyings` read from the token after
    ///         `initialize` (no owner, 3r R1).
    ///         `creatorId` the creator's UA id (S3; a native creator's topic is its padded address).
    event TokenCreated(
        address indexed token, bytes32 indexed creatorId, TokenKind indexed kind, uint64 version, address implementation,
        uint256 features, uint256 lockedFeatures, address[] underlyings);
    event DexImplementationDeployed(
        uint64 indexed version, address indexed implementation, uint16 envVersion, bytes32 envHash, bytes32 initcodeHash,
        bytes32 codeHash, uint64 usableFrom);
    event DexImplementationDeprecated(uint64 indexed version, string reason);
    event DexCreated(address indexed dex, bytes32 indexed creatorId, uint64 version, address implementation);
    /// @notice The chain's one-time values (chain-neutral spec §3.1).
    event ChainConfigured(bytes32 indexed chainUid, uint64 noticePeriod, address govRouter);

    /// @notice The constructor's first admin is 0 or a derived id (high 96 bits not 0): it must be a native id, the same
    ///         on every chain, since `configureChain` is its direct call (spec §5.2).
    error AdminNotNative(bytes32 admin);
    error ChainUidZero();
    /// @notice `configureChain`'s notice period exceeds `MAX_NOTICE_PERIOD` (30 days).
    error NoticePeriodTooLong(uint64 noticePeriod);
    /// @notice Every creation, publish and deploy entry before `configureChain`.
    error ChainNotConfigured();
    error ChainAlreadyConfigured();
    /// @notice A creation by the chain's router (S3) whose `subject()` is 0: the router names no signer.
    error RouterSubjectZero();
    /// @notice The chain can prove its genesis hash (`BLOCKHASH(0)`, EIP-2935) and `given` is not it.
    error ChainUidNotGenesis(bytes32 given, bytes32 provable);
    /// @notice The reference block's hash on this chain is not `given` (`actual` 0: the chain cannot answer).
    error RefBlockMismatch(uint256 refBlock, bytes32 given, bytes32 actual);
    /// @notice The CREATE3 proxy's `CREATE` of the instance failed (it answers success there, Fable P2-5).
    error InstanceNotCreated();
    /// @notice A release's `validateEnv` reverted without data (it has none, or it failed without a reason).
    error EnvRefused(address implementation);
    /// @notice Creation of a kind the admin has not enabled (plain kinds on from the start, confidential ones off).
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
    /// @notice No env `envVersion` published for the domain (version 0 included): a `TokenKind`, `DEX_DOMAIN`, or a
    ///         generic `class << 16 | kind` (T70: `uint32`).
    error EnvUnknown(uint32 domain, uint16 envVersion);
    error EnvAlreadyPublished(uint32 domain, uint16 envVersion);
    /// @notice `libs` and `libCodeHashes` of different lengths, a library code hash that pins nothing (`0` or
    ///         `keccak256("")`), more than 4 `deps`, 2 `params` or 32 `libs` (`MAX_LIBS`, the node's decode bound).
    error EnvInvalid();
    /// @notice A linked library of the env does not have its published code hash (checked at each release deployment).
    error LibraryCodeHashMismatch(address library_, bytes32 expected, bytes32 got);
    /// @notice A body module the release names in `modules()` is not one of its env's `libs` (T66b §4.5), so its code hash
    ///         is pinned by no env.
    error ModuleNotPinned(address module);
    /// @notice The release does not answer `modules()` with one well-formed `address[]` (T66b §4.5; fail closed).
    error ModulesUnreadable(address implementation);
    /// @notice The `CREATE2` of a release failed without revert data (a constructor's revert is bubbled), e.g. a
    ///         runtime over the chain's code-size limit. Init code over the chain's init-code limit (EIP-3860) is an
    ///         exceptional halt of the factory's call frame instead: the deploy call consumes all its gas and fails
    ///         without `DeployFailed`.
    error DeployFailed();
    /// @notice A list view of class 0 or of a class this factory does not make.
    error ClassUnknown(uint16 contractClass);
    /// @notice A page of more than `MAX_PAGE` records.
    error PageTooLarge(uint256 n);

    // ------------------------------------------------------------------ the admin (spec §5.1, §5.2) and the approvals (§5.6)

    /// @notice An approval's state: `LIVE` from `approve*` until a deploy consumes it (`CONSUMED`) or `revokeApproval`
    ///         deletes it (`NONE`). Live means `LIVE`, the current `adminGeneration` and `block.timestamp <= until`.
    enum ApprovalState { NONE, LIVE, CONSUMED }

    /// @notice The field of an approval that is not the factory's own (`ApprovalFieldMismatch`).
    enum ApprovalField { CHAIN_UID, FACTORY, ADMIN_GENERATION }

    /// @notice One slot: the state, the admin term that approved, the last second it may be used.
    struct Approval {
        ApprovalState state;
        uint32 adminGeneration;
        uint64 until;
    }

    /// @notice `key` approved by the admin of term `adminGeneration`, usable once until `until` (spec §5.6 item 1).
    event ReleaseApproved(bytes32 indexed key, uint32 adminGeneration, uint64 until);
    event ReleaseApprovalRevoked(bytes32 indexed key);

    /// @notice An approval naming another `chainUid`, another factory or another admin term than this factory's own.
    error ApprovalFieldMismatch(ApprovalField field);
    /// @notice `until` not in the future, or more than `MAX_NOTICE_PERIOD` (30 days) ahead.
    error ApprovalTooLong(uint64 until);
    /// @notice A live approval of the same key exists (a not-live one is overwritten).
    error ApprovalLive(bytes32 key);
    /// @notice `revokeApproval` of a key never approved, revoked already or consumed.
    error ApprovalNotRevocable(bytes32 key);
    /// @notice A deploy without a live approval of its key, by a sender that is not the native admin (a designator is
    ///         not, D2); checked before the version.
    error ReleaseNotApproved(bytes32 key);
    /// @notice An ERC-165 probe of a release's checks without the gas for its full 30,000 stipend (EIP-150 64/63 and a
    ///         margin): the probe's answer must be the release's, never the sender's gas (spec §5.6 item 3).
    error ProbeGasLow(uint256 gasLeft);

    /// @notice Admin only, after `configureChain` (spec §5.2; `transferAdmin` likewise): the admin becomes 0 for good, the pending with it; every
    ///         admin op ends on this factory, deprecation included (owner, Q1). `chainUid_` this factory's
    ///         (`ChainUidMismatch`, Fable recheck-2 P3-1): a native admin's direct call is void on a sibling with the same chain id.
    function renounceAdmin(bytes32 chainUid_) external;
    /// @notice Completed changes of admin (accepts and the renounce): an approval lives only in the term that made it.
    function adminGeneration() external view returns (uint32);
    /// @notice Admin only, after `configureChain`: approves the release `deployTokenImplementation(kind, version,
    ///         envVersion, initcode, implArgs)` with `keccak256(initcode) == initcodeHash`, `keccak256(implArgs) ==
    ///         implArgsHash`, once, until `until` (≤ 30 days ahead); `chainUid`, `factory` and `adminGeneration` must be
    ///         this factory's own. The key: `keccak256(abi.encode(keccak256("scaas.factory.release.token"), chainUid,
    ///         factory, kind, version, envVersion, initcodeHash, implArgsHash))`.
    function approveTokenRelease(TokenKind kind, uint64 version, uint16 envVersion, bytes32 initcodeHash,
        bytes32 implArgsHash, bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until) external;
    /// @notice As `approveTokenRelease` for `deployDexImplementation`; key tag `"scaas.factory.release.dex"`, fields
    ///         `version, envVersion, initcodeHash, implArgsHash`.
    function approveDexRelease(uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash,
        bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until) external;
    /// @notice As `approveTokenRelease` for `deployImplementation`; key tag `"scaas.factory.release.class"`, fields
    ///         `contractClass, kind, version, envVersion, initSelector, interfaceId, initcodeHash, implArgsHash`.
    function approveRelease(ReleaseId calldata id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId,
        bytes32 initcodeHash, bytes32 implArgsHash, bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until)
        external;
    /// @notice Admin only, after `configureChain`: deletes a stored approval not consumed, live or not.
    function revokeApproval(bytes32 key) external;
    function approvalOf(bytes32 key) external view returns (Approval memory);

    /// @notice Admin only, direct only (before it the factory has no router), once (chain-neutral spec §3.1): this chain's `chain_uid` (≠ 0; its genesis hash whenever the
    ///         EVM can prove it: `ChainUidNotGenesis`), the notice period (≤ `MAX_NOTICE_PERIOD`), the router (0 with
    ///         `govRouterCodeHash` 0 = none; else its code hash must be `govRouterCodeHash`, `CodeHashMismatch`; its
    ///         `chainUid()` must be `chainUid_`; its `registry()` an account with code, `RouterRegistryInvalid`; its
    ///         `smartKeyCloneHash()` its registry's, `SmartKeyCloneHashMismatch`: spec §13.3, §13.4) and a reference block
    ///         (`refBlock ≠ 0`: its hash on this chain must be `refHash`, `RefBlockMismatch`; 0 on a chain whose
    ///         `BLOCKHASH` is not its own block hash).
    function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_, bytes32 govRouterCodeHash,
        uint256 refBlock, bytes32 refHash) external;
    /// @notice 0 until `configureChain`.
    function chainUid() external view returns (bytes32);
    /// @notice Seconds between a release's deployment and its first use (chain-configured: minutes on 7622, days on
    ///         22776; 0 on the dev chains and in tests).
    function noticePeriod() external view returns (uint64);
    /// @notice This chain's `GovernanceRouter` (0 = none): every instance's `ChainEnv.govRouter`.
    function govRouter() external view returns (address);
    /// @notice The env domain of the DEX (`type(uint8).max`).
    function DEX_DOMAIN() external view returns (uint8);

    // ------------------------------------------------------------------ the chain's directory (spec §13, owner 2026-11-10)

    /// @notice The chain's fixed shared contracts, as the named views answer them (spec §13.6).
    struct Directory {
        address uaRegistry;
        address govRouter;
        address relayFeeRouter;
        address relayFeeExecutor;
        address complianceRegistry;
        address smartKeyAccountFactory;
        address zetherStatements;
    }

    /// @notice A write-once entry written (`view_` the selector of its view), with the code hash the admin gave.
    event ChainEntrySet(bytes4 indexed view_, address at_, bytes32 codeHash);

    /// @notice A write-once entry written already (`view_` the selector of its view).
    error EntryAlreadySet(bytes4 view_);
    /// @notice `at_`'s code hash is not `expected`, or `expected` pins nothing (0, `keccak256("")`).
    error CodeHashMismatch(address at_, bytes32 expected, bytes32 got);
    /// @notice An entry's own view (the executor's `ROUTER()`, the compliance registry's `govRouter()`, …) answers another
    ///         value than the factory's, or no word (`view_` the selector of the entry's view).
    error EntryMismatch(bytes4 view_);
    /// @notice `configureChain`: the router's `registry()` is no account with code (0 included), or no answer.
    error RouterRegistryInvalid(address registry);
    /// @notice A `SmartKeyAccount` clone code hash that is not the router's (`expected`): its registry's at
    ///         `configureChain`, the account factory's `IMPLEMENTATION()` clone at `setChainEntries`.
    error SmartKeyCloneHashMismatch(bytes32 expected, bytes32 got);
    /// @notice An env's `registry` is neither 0 nor the router's (`uaRegistry()`, spec §13.4).
    error EnvRegistryMismatch(address expected, address got);
    /// @notice An env's `smartKeyAccountImpl` is neither 0 nor an implementation of the router's clone code hash.
    error EnvSmartKeyAccountMismatch(bytes32 cloneHash, address got);

    /// @notice Admin only, after `configureChain` (spec §13.3): each non-zero address written once into its zero slot
    ///         (`EntryAlreadySet`), 0 leaves the entry open for a later call; each code hash its argument (`CodeHashMismatch`,
    ///         0 and `keccak256("")` pin nothing). The relay router's `EXECUTOR()` has `relayFeeExecutorCodeHash` and answers
    ///         `ROUTER()` with the relay router; the compliance registry's `govRouter()` is the factory's; the account
    ///         factory's `chainUid()` is the factory's and, with a router, its `IMPLEMENTATION()`'s clone code hash the
    ///         router's. Every view call fails closed. `ChainEntrySet` per entry written, the relay executor's too (`view_` =
    ///         `relayFeeExecutor.selector`, Fable 3r3s3t P3-10).
    function setChainEntries(address relayFeeRouter_, bytes32 relayFeeRouterCodeHash, bytes32 relayFeeExecutorCodeHash,
        address complianceRegistry_, bytes32 complianceRegistryCodeHash, address smartKeyAccountFactory_,
        bytes32 smartKeyAccountFactoryCodeHash, address zetherStatements_, bytes32 zetherStatementsCodeHash) external;
    /// @notice Every entry by its view (spec §13.6).
    function directory() external view returns (Directory memory);
    /// @notice The router's `registry()`, stored nowhere; 0 without a router.
    function uaRegistry() external view returns (address);
    /// @notice 0 until written.
    function relayFeeRouter() external view returns (address);
    /// @notice The written relay router's `EXECUTOR()`; 0 until written.
    function relayFeeExecutor() external view returns (address);
    /// @notice The SCaaS deploy's own `ComplianceRegistry` (discovery only, spec §13.1); 0 until written.
    function complianceRegistry() external view returns (address);
    /// @notice 0 until written.
    function smartKeyAccountFactory() external view returns (address);
    /// @notice 0 until written.
    function zetherStatements() external view returns (address);

    /// @notice Admin only: publishes env `envVersion` (from 1, append-only, never changed) of a kind's releases. A
    ///         `registry ≠ 0` must name this factory's `chainUid` (`ChainUidMismatch`); with a router, a `registry ≠ 0`
    ///         must be `uaRegistry()` (`EnvRegistryMismatch`) and a `smartKeyAccountImpl ≠ 0` an implementation of the
    ///         router's `smartKeyCloneHash()` (`EnvSmartKeyAccountMismatch`, spec §13.4). At most `MAX_LIBS` (32) libraries.
    function publishTokenEnv(TokenKind kind, uint16 envVersion, IFactoryToken.Env calldata env) external;
    function publishDexEnv(uint16 envVersion, IFactoryToken.Env calldata env) external;
    function tokenEnvOf(TokenKind kind, uint16 envVersion) external view returns (IFactoryToken.Env memory);
    function dexEnvOf(uint16 envVersion) external view returns (IFactoryToken.Env memory);
    function latestTokenEnvVersion(TokenKind kind) external view returns (uint16);
    function latestDexEnvVersion() external view returns (uint16);

    /// @notice Open to anyone against a live approval of its key (`approveTokenRelease`; consumed here; the native admin's
    ///         own call is its own approval, `ReleaseNotApproved` before anything else): on the kind's published env
    ///         `envVersion` (named explicitly, `EnvUnknown` otherwise), checks each
    ///         `env.libs[i].codehash`, `CREATE2`s (salt `keccak256(abi.encode(kind, version))`) the chain-neutral
    ///         `initcode ‖ abi.encode(address(this), implArgs)` (the same address on every chain), checks `kind()`,
    ///         `factory()`, the release's `validateEnv` of the instance env and its body modules (`modules()`, each in the
    ///         env's `libs`: `ModuleNotPinned`, CTR-TOK-30), records the release with its env version
    ///         and hash (usable after `noticePeriod`). Append-only, version 0 refused; the same init code may be deployed
    ///         again as a later version on another env. `chainUid_` as `deprecateToken` (the native admin's own call
    ///         carries no approval key, Fable recheck-2 P3-1), on every deploy.
    function deployTokenImplementation(
        TokenKind kind,
        uint64 version,
        uint16 envVersion,
        bytes calldata initcode,
        bytes calldata implArgs,
        bytes32 chainUid_
    ) external returns (address implementation);
    /// @notice Admin only, after `configureChain`; `chainUid_` this factory's (`ChainUidMismatch`): a native admin's direct
    ///         call is void on a sibling with the same chain id (Fable D P3-2). The same word on every deprecation and switch.
    function deprecateToken(TokenKind kind, uint64 version, bytes32 chainUid_, string calldata reason) external;
    /// @notice Admin only; a confidential kind starts off. `chainUid_` as `deprecateToken`.
    function setTokenKindEnabled(TokenKind kind, bool on, bytes32 chainUid_) external;
    function tokenKindEnabled(TokenKind kind) external view returns (bool);
    function releaseOf(TokenKind kind, uint64 version) external view returns (Release memory);
    function implementationOf(TokenKind kind, uint64 version) external view returns (address);
    function isTokenDeprecated(TokenKind kind, uint64 version) external view returns (bool);
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

    /// @notice As `deployTokenImplementation` for the DEX (approved by `approveDexRelease`) (salt `keccak256(abi.encode("dex", version))`, DEX
    ///         env `envVersion`); the release must answer `factory()` and accept the env (`validateEnv`). `chainUid_` as there.
    function deployDexImplementation(uint64 version, uint16 envVersion, bytes calldata initcode, bytes calldata implArgs,
        bytes32 chainUid_) external returns (address implementation);
    function dexReleaseOf(uint64 version) external view returns (Release memory);
    function dexImplementationOf(uint64 version) external view returns (address);
    /// @notice Admin only: marks a DEX version deprecated; `createDex` then refuses it (existing DEXes untouched).
    ///         `chainUid_` as `deprecateToken`.
    function deprecateDex(uint64 version, bytes32 chainUid_, string calldata reason) external;
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
    /// @notice The contracts `creatorId` created (authenticated: the direct caller).
    function contractsOfCreator(bytes32 creatorId, uint16 contractClass, uint256 from, uint256 n)
        external view returns (Created[] memory page, uint256 total);

    // ------------------------------------------------------------------ the generic catalogue (factory index spec §8, CTR-TOK-28)

    /// @notice A generic release's id: class (3..65535, the admin's), kind (per class), version (from 1).
    struct ReleaseId {
        uint16 contractClass;
        uint16 kind;
        uint64 version;
    }

    /// @notice A generic release: as `Release`, with the one initializer `createInstance` may call on a fresh clone and the
    ///         class's ERC-165 interface id the implementation answers true.
    struct ClassRelease {
        address implementation;
        uint16 envVersion;
        bytes32 envHash;
        uint64 usableFrom;
        bool deprecated;
        bytes4 initSelector;
        bytes4 interfaceId;
    }

    /// @notice What every generic release and each of its clones answers (`factoryInfo()`), six static words (192 B):
    ///         the factory, the instance's `chain_uid` (0 on the implementation: chain-neutral releases), its release id,
    ///         and whether it is initialized (true on the implementation, locked by its constructor); no owner (3r R1, Q4).
    struct FactoryInfo {
        address factory;
        bytes32 chainUid;
        uint16 contractClass;
        uint16 kind;
        uint64 version;
        bool initialized;
    }

    event ClassEnvPublished(uint16 indexed contractClass, uint16 indexed kind, uint16 indexed envVersion, bytes32 envHash);
    event ReleaseDeployed(uint16 indexed contractClass, uint16 indexed kind, uint64 indexed version, address implementation,
        uint16 envVersion, bytes32 envHash, bytes32 initcodeHash, bytes32 codeHash, bytes4 initSelector, bytes4 interfaceId,
        uint64 usableFrom);
    event ReleaseDeprecated(uint16 indexed contractClass, uint16 indexed kind, uint64 indexed version, string reason);
    event ClassKindEnabled(uint16 indexed contractClass, uint16 indexed kind, bool enabled);
    event InstanceCreated(address indexed instance, bytes32 indexed creatorId, uint16 indexed contractClass, uint16 kind,
        uint64 version, address implementation);

    /// @notice A generic entry for class 0 (not made here), 1 (`TOKEN`) or 2 (`DEX`): those keep their typed paths.
    error ClassReserved(uint16 contractClass);
    error ReleaseUnknown(uint16 contractClass, uint16 kind, uint64 version);
    error ReleaseAlreadyRegistered(uint16 contractClass, uint16 kind, uint64 version, address existing);
    /// @notice `createInstance` of a deprecated release (the event of the deprecation is `ReleaseDeprecated`; an error
    ///         cannot share its name).
    error ReleaseIsDeprecated(uint16 contractClass, uint16 kind, uint64 version);
    error ReleaseNotYetUsable(uint16 contractClass, uint16 kind, uint64 version, uint64 usableFrom);
    error ClassKindDisabled(uint16 contractClass, uint16 kind);
    error InitSelectorZero();
    error InitSelectorMismatch(bytes4 expected, bytes4 got);
    /// @notice The release's `factoryInfo()` is not 192 B naming this factory, its own id, initialized.
    error ReleaseInfoMismatch(address implementation);
    error InterfaceNotSupported(address implementation, bytes4 interfaceId);
    /// @notice After `initCall`, the clone's `factoryInfo()` is not 192 B naming this factory, the release's id,
    ///         initialized.
    error InstanceInfoMismatch(address instance);

    /// @notice Admin only: env `envVersion` of a generic `(contractClass, kind)` (`ClassReserved` for 0-2), as
    ///         `publishTokenEnv`.
    function publishClassEnv(uint16 contractClass, uint16 kind, uint16 envVersion, IFactoryToken.Env calldata env) external;
    /// @notice As `deployTokenImplementation` (approved by `approveRelease`, which also binds `initSelector` and
    ///         `interfaceId`): the release `id` from chain-neutral init code, `initcode ‖ abi.encode(id, factory, implArgs)`
    ///         `CREATE2`d (salt `keccak256(abi.encode("release", id))`) on env `envVersion`; checked: code, `factoryInfo()`,
    ///         ERC-165 (`0x01ffc9a7`, `interfaceId`, not `0xffffffff`), `validateEnv`, its body modules (`modules()`, each
    ///         in the env's `libs`: `ModuleNotPinned`, CTR-TOK-30; owner 2026-11-10). The first release of a class lists it in
    ///         `classes()`, the first of a kind in `kindsOf`. Usable after `noticePeriod`; a new `(class, kind)` starts off.
    ///         `chainUid_` as `deployTokenImplementation`.
    function deployImplementation(ReleaseId calldata id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId,
        bytes calldata initcode, bytes calldata implArgs, bytes32 chainUid_) external returns (address implementation);
    /// @notice Admin only: immediate, never undone; existing instances untouched. `chainUid_` as `deprecateToken`.
    function deprecateRelease(ReleaseId calldata id, bytes32 chainUid_, string calldata reason) external;
    /// @notice Admin only: the reversible stop of every version of a `(class, kind)`. `chainUid_` as `deprecateToken`.
    function setClassKindEnabled(uint16 contractClass, uint16 kind, bool on, bytes32 chainUid_) external;
    function classEnvOf(uint16 contractClass, uint16 kind, uint16 envVersion) external view returns (IFactoryToken.Env memory);
    function latestClassEnvVersion(uint16 contractClass, uint16 kind) external view returns (uint16);
    function classReleaseOf(ReleaseId calldata id) external view returns (ClassRelease memory);
    /// @notice May name a deprecated or not yet usable release.
    function latestClassVersion(uint16 contractClass, uint16 kind) external view returns (uint64);
    function classKindEnabled(uint16 contractClass, uint16 kind) external view returns (bool);
    /// @notice The generic classes with a release, in the order of their first release.
    function classes() external view returns (uint16[] memory);
    /// @notice The kinds of `contractClass` with a release, in the order of their first release.
    function kindsOf(uint16 contractClass) external view returns (uint16[] memory);

    /// @notice A CREATE3 instance of the usable, non-deprecated release `id` of an enabled `(class, kind)`, its env appended,
    ///         and one call: `initCall`, the release's catalogued initializer (`initSelector`, its own typed arguments), value
    ///         0, to the fresh clone only; then `factoryInfo()` must name this factory, the release and `initialized`, its
    ///         `chainUid` this factory's; the record and the lists. The submitter is the creator.
    function createInstance(ReleaseId calldata id, bytes32 salt, bytes calldata initCall) external returns (address instance);
    /// @notice The creator of the creation in progress (EIP-1153), 0 outside one; a nested creation sees its own.
    function creating() external view returns (bytes32 creatorId);
}
