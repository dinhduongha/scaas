// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "./IFactoryToken.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";

/// @title The one token factory of a chain (CTR-TOK-03, CTR-TOK-25): an append-only catalogue of implementations per
///        kind, EIP-1167 clones by `CREATE2` initialised in the same call, no power over any token it created.
interface IOpenFactory {
    /// @notice CTR-TOK-21, a fresh enum (nothing deployed): the value equals the implementation's `kind()`.
    ///         `NONE_PQZ` / `UNDERLYING_PQZ` are built (P6g, behind the PQZ gate); the `*_ZETHER_PQZ` kinds are
    ///         reserved (`KindReserved`: no implementation can be registered for them yet).
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

    /// @notice The canonical confidential verifiers of the chain, fixed at the factory's deployment (owner 2026-10-19,
    ///         CTR-ZTH-20; no setter, a new set is a new factory): Zether per curve (0 bn254, 1 BLS12-381) the transfer
    ///         verifier, the burn verifier and `ZetherDisclosure` (the inner-product verifier is fixed inside the two
    ///         verifiers); PQZ per proof system (0 PQZL, 1 PQZH) the `UAPqzVerifier`. 0 = not on this chain.
    struct Canonical {
        address[2] zetherVerifier;
        address[2] zetherBurnVerifier;
        address[2] zetherDisclosure;
        address[2] pqzVerifier;
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
    /// @notice `createToken` / `createDex` refuse a deprecated version (owner 2026-10-20); existing tokens are untouched.
    error VersionDeprecated(TokenKind kind, uint64 version);
    error DexVersionDeprecated(uint64 version);
    /// @notice A confidential implementation whose verifiers (Zether: `verifier()`, `burnVerifier()`, `disclosure()`;
    ///         PQZ: `verifier()`) are not one of the factory's canonical sets (CTR-ZTH-20).
    error NotCanonicalVerifiers(address implementation);
    /// @notice `createTokenUnregistered` is for the plain kinds only (owner 2026-10-19).
    error UnregisteredConfidentialKind(TokenKind kind);

    /// @notice The Zether gate (CTR-ZTH-02, CTR-TOK-03): off by default, switched by the registrar, on only on a dev
    ///         chain (`ZetherSafety`); creating a `*_ZETHER` token needs it on, a dev chain, and a verifier this chain
    ///         can run (`isSupportedOnThisChain()`).
    event ZetherEnabled(bool enabled);
    error ZetherDisabled();
    /// @notice The PQZ gate (CTR-PQZ-01, P6g plan D1/D2): off by default; on only on a `PqzSafety` chain whose `PQZ`
    ///         precompile passes its self-test; a `*_PQZ` creation needs it on and a `UAPqzVerifier` this chain runs.
    event PqzEnabled(bool enabled);
    error PqzDisabled();
    error PqzVerifierUnsupported(address verifier);
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
    event DexImplementationDeprecated(uint64 indexed version, string reason);
    event DexCreated(address indexed dex, address indexed creator, uint64 version, address implementation, address admin);

    function registrar() external view returns (address);
    function chainUid() external view returns (bytes32);
    /// @notice The canonical Zether set of `curve` (0 bn254, 1 BLS12-381); zeros when absent.
    function zetherVerifiers(uint8 curve) external view returns (address verifier, address burnVerifier, address disclosure);
    /// @notice The canonical `UAPqzVerifier` of `proofSystem` (0 PQZL, 1 PQZH); 0 when absent.
    function pqzVerifier(uint8 proofSystem) external view returns (address);

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external;
    function deprecate(TokenKind kind, uint64 version, string calldata reason) external;
    function implementationOf(TokenKind kind, uint64 version) external view returns (address);
    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool);
    function latestVersion(TokenKind kind) external view returns (uint64);

    function createToken(TokenKind kind, uint64 version, IFactoryToken.TokenConfig calldata cfg, bytes32 salt)
        external returns (address token);
    /// @notice Plain kinds only (`UnregisteredConfidentialKind`): any implementation of `kind` for this factory and chain,
    ///         recorded with `version == 0` — unvetted code: clients and the gateway trust `isRegisteredToken` only.
    function createTokenUnregistered(
        TokenKind kind, address implementation, IFactoryToken.TokenConfig calldata cfg, bytes32 salt
    ) external returns (address token);

    function predictAddress(address implementation, address creator, bytes32 salt) external view returns (address);
    function isToken(address token) external view returns (bool);
    /// @notice Made by this factory from a registered implementation version (`version ≠ 0`).
    function isRegisteredToken(address token) external view returns (bool);
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
    /// @notice Registrar only: marks a DEX version deprecated; `createDex` then refuses it (existing DEXes untouched).
    function deprecateDex(uint64 version, string calldata reason) external;
    function isDexDeprecated(uint64 version) external view returns (bool);
    function latestDexVersion() external view returns (uint64);
    /// @notice An `SCaaSDex` clone, `initialize(cfg)` in the same call (CTR-DEX-24).
    function createDex(uint64 version, ISCaaSDex.DexConfig calldata cfg, bytes32 salt) external returns (address dex);
    /// @notice Advisory (clients and the node); tokens never consult it (CTR-DEX-19).
    function isDex(address dex) external view returns (bool);
    function dexVersionOf(address dex) external view returns (uint64);
}
