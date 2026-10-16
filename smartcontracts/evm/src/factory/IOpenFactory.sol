// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "./IFactoryToken.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";

/// @title The one token factory of a chain (CTR-TOK-03, CTR-TOK-25): an append-only catalogue of implementations per
///        kind, EIP-1167 clones by `CREATE2` initialised in the same call, no power over any token it created.
interface IOpenFactory {
    /// @notice CTR-TOK-21, a fresh enum (nothing deployed): the value equals the implementation's `kind()`. The `*_PQZ`
    ///         kinds are reserved (no implementation can be registered for them yet).
    enum TokenKind {
        NONE,
        UNDERLYING,
        NONE_ZETHER,
        UNDERLYING_ZETHER,
        NONE_PQZ,
        UNDERLYING_PQZ,
        NONE_ZETHER_PQZ,
        UNDERLYING_ZETHER_PQZ
    }

    event ImplementationRegistered(
        TokenKind indexed kind, uint64 indexed version, address indexed implementation, address registrar);
    event ImplementationDeprecated(TokenKind indexed kind, uint64 indexed version, string reason);
    /// @notice The one event of a creation.
    event TokenCreated(
        address indexed token, address indexed creator, TokenKind indexed kind, uint64 version, address implementation,
        uint256 features, uint256 lockedFeatures, address owner, address[] underlyings);

    error NotRegistrar();
    error ChainUidZero();
    error KindReserved(TokenKind kind);
    error VersionAlreadyRegistered(TokenKind kind, uint64 version, address existing);
    error VersionUnknown(TokenKind kind, uint64 version);
    /// @notice The implementation's `kind()` differs (`got = type(uint256).max` when it does not answer).
    error VersionKindMismatch(TokenKind expected, uint256 got);
    error ImplementationNotAContract(address implementation);
    error ImplementationFactoryMismatch(address implementation);
    error ChainUidMismatch(bytes32 expected, bytes32 got);
    /// @notice `NONE*` 0 legs, `UNDERLYING*` 1–8.
    error UnderlyingCountInvalid(uint256 n);
    error SaltAlreadyUsed(address existing);
    error DexVersionUnknown(uint64 version);
    error DexVersionAlreadyRegistered(uint64 version, address existing);

    /// @notice The Zether gate (CTR-ZTH-02, CTR-TOK-03): off by default, switched by the registrar, on only on a dev
    ///         chain (`ZetherSafety`); creating a `*_ZETHER` token needs it on, a dev chain, and a verifier this chain
    ///         can run (`isSupportedOnThisChain()`).
    event ZetherEnabled(bool enabled);
    error ZetherDisabled();
    /// @notice The PQZ gate (CTR-PQZ-01, P6g plan D1/D2): off by default; on only on a `PqzSafety` chain whose `PQZ`
    ///         precompile passes its self-test; a `*_PQZ` creation needs it on and a `UAPqzVerifier` this chain runs.
    event PqzEnabled(bool enabled);
    error PqzDisabled();
    error VerifierRequiredForPqz();
    error PqzVerifierUnsupported(address verifier);
    error VerifierRequiredForZether();
    /// @notice `curve` is the verifier's `curveName()`, empty when it has no code or no answer.
    error VerifierUnsupportedOnThisChain(address verifier, string curve);

    function zetherEnabled() external view returns (bool);
    /// @notice Registrar only; `true` reverts `ZetherNotDevChain` outside chain ids 31337/1337, `false` always works.
    function setZetherEnabled(bool on) external;

    /// @notice Registrar only; `true` needs `PqzSafety`'s chain and the precompile's self-test, `false` always works.
    function setPqzEnabled(bool on) external;

    function pqzEnabled() external view returns (bool);

    /// @notice DEX catalogue (CTR-DEX-24): append-only, versions from 1; the implementation must answer
    ///         `factory() == this` and `chainUid() == chainUid`.
    event DexImplementationRegistered(uint64 indexed version, address indexed implementation, address registrar);
    event DexCreated(address indexed dex, address indexed creator, uint64 version, address implementation, address admin);

    function registrar() external view returns (address);
    function chainUid() external view returns (bytes32);

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external;
    function deprecate(TokenKind kind, uint64 version, string calldata reason) external;
    function implementationOf(TokenKind kind, uint64 version) external view returns (address);
    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool);
    function latestVersion(TokenKind kind) external view returns (uint64);

    function createToken(TokenKind kind, uint64 version, IFactoryToken.TokenConfig calldata cfg, bytes32 salt)
        external returns (address token);
    /// @notice Any implementation of `kind` for this factory and chain; recorded with `version == 0`.
    function createTokenUnregistered(
        TokenKind kind, address implementation, IFactoryToken.TokenConfig calldata cfg, bytes32 salt
    ) external returns (address token);

    function predictAddress(address implementation, address creator, bytes32 salt) external view returns (address);
    function isToken(address token) external view returns (bool);
    function creatorOf(address token) external view returns (address);
    function versionOf(address token) external view returns (TokenKind kind, uint64 version);
    /// @notice First token `creator` made over `underlying`; it may have several legs: read `underlyings()`.
    function getWrapper(address creator, address underlying) external view returns (address);
    function getWrapperCount(address creator, address underlying) external view returns (uint256);
    function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address);
    function deployCountFor(address underlying) external view returns (uint256);
    function deployedFor(address underlying, uint256 index) external view returns (address);

    function registerDexImplementation(uint64 version, address implementation) external;
    function dexImplementationOf(uint64 version) external view returns (address);
    function latestDexVersion() external view returns (uint64);
    /// @notice An `SCaaSDex` clone, `initialize(cfg)` in the same call (CTR-DEX-24).
    function createDex(uint64 version, ISCaaSDex.DexConfig calldata cfg, bytes32 salt) external returns (address dex);
    /// @notice Advisory (clients and the node); tokens never consult it (CTR-DEX-19).
    function isDex(address dex) external view returns (bool);
    function dexVersionOf(address dex) external view returns (uint64);
}
