// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "./IOpenFactory.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
import {ITokenAdmin} from "../metatx/ITokenAdmin.sol";

/// @title `OpenFactory` (CTR-TOK-03, CTR-TOK-25): the one token factory of a chain (plan 5g-Z2).
/// @notice Anyone creates tokens and DEXes; the registrar publishes deployment environments (`publishEnv`, versioned
///         per kind, never changed), deploys releases from init code (`deployImplementation`, `deployDexImplementation`:
///         the factory's own `CREATE2`, the env version the registrar names appended as constructor arguments, so the
///         dependencies — Zether and PQZ verifiers included, CTR-ZTH-20 — are immutables of the code by construction;
///         each linked library checked by code hash), enables kinds and deprecates releases: it has no power over any
///         token or DEX.
///         A release must answer `kind()`, `factory() == this` and `chainUid() == chainUid` (CTR-GEN-05); the catalogue
///         is append-only; a release is usable `noticePeriod` seconds after its deployment, and a deprecated one is no
///         longer creatable (owner 2026-10-20). Creation clones by `CREATE2` with the salt scoped by the creator and
///         calls `initialize(creator, version, initArgs)` in the same call; `initArgs` and every kind-specific check
///         (flags, legs, the Zether / PQZ verifier and chain gates) are the implementation's. The registrar's key is the
///         trust root for code (a multisig / UA msig before mainnet). **Zether is UNAUDITED — NOT FOR PRODUCTION FUNDS.**
contract OpenFactory is IOpenFactory {
    struct Info {
        address creator;
        TokenKind kind;
        uint64 version;
        bool exists;
    }

    uint256 internal constant MAX_LEGS = 8;
    uint8 public constant DEX_DOMAIN = type(uint8).max;
    /// @dev The longest notice period (review 5g-Z2 P2-4): the period is immutable, and near `2^64` every
    ///      `deployImplementation` would overflow `usableFrom` and brick the catalogue.
    uint64 public constant MAX_NOTICE_PERIOD = 30 days;

    address public immutable registrar;
    bytes32 public immutable chainUid;
    uint64 public immutable noticePeriod;

    mapping(uint8 => mapping(uint16 => IFactoryToken.Env)) private _envs;
    mapping(uint8 => mapping(uint16 => bytes32)) private _envHash;
    mapping(uint8 => uint16) private _latestEnv;
    mapping(TokenKind => mapping(uint64 => Release)) private _releases;
    mapping(TokenKind => uint64) private _latest;
    mapping(uint64 => Release) private _dexReleases;
    uint64 private _latestDex;
    /// @dev Bit `kind` set = creation enabled; the plain kinds start on.
    uint256 private _enabled = 3;
    mapping(address => Info) private _info;
    mapping(address => mapping(address => address[])) private _wrappers;
    mapping(address => address[]) private _byUnderlying;
    mapping(address => uint64) private _dexVersion; // 0 = not a DEX made here

    /// @param noticePeriod_ seconds between a release's deployment and its first use (7622: minutes, 22776: days).
    constructor(address registrar_, bytes32 chainUid_, uint64 noticePeriod_) {
        if (chainUid_ == bytes32(0)) revert ChainUidZero();
        if (noticePeriod_ > MAX_NOTICE_PERIOD) revert NoticePeriodTooLong(noticePeriod_);
        registrar = registrar_;
        chainUid = chainUid_;
        noticePeriod = noticePeriod_;
    }

    modifier onlyRegistrar() {
        if (msg.sender != registrar) revert NotRegistrar();
        _;
    }

    // ------------------------------------------------------------------ environments

    function publishEnv(TokenKind kind, uint16 envVersion, IFactoryToken.Env calldata env) external onlyRegistrar {
        _publish(uint8(kind), envVersion, env);
    }

    function publishDexEnv(uint16 envVersion, IFactoryToken.Env calldata env) external onlyRegistrar {
        _publish(DEX_DOMAIN, envVersion, env);
    }

    function envOf(TokenKind kind, uint16 envVersion) external view returns (IFactoryToken.Env memory) {
        return _envs[uint8(kind)][envVersion];
    }

    function dexEnvOf(uint16 envVersion) external view returns (IFactoryToken.Env memory) {
        return _envs[DEX_DOMAIN][envVersion];
    }

    function latestEnvVersion(TokenKind kind) external view returns (uint16) { return _latestEnv[uint8(kind)]; }

    function latestDexEnvVersion() external view returns (uint16) { return _latestEnv[DEX_DOMAIN]; }

    // ------------------------------------------------------------------ releases

    function deployImplementation(
        TokenKind kind,
        uint64 version,
        uint16 envVersion,
        bytes calldata initcode,
        bytes calldata implArgs
    ) external onlyRegistrar returns (address implementation) {
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _releases[kind][version].implementation;
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        Release memory r;
        (implementation, r) =
            _deploy(uint8(kind), envVersion, keccak256(abi.encode(kind, version)), initcode, implArgs);
        _checkImplementation(kind, implementation);
        _releases[kind][version] = r;
        if (version > _latest[kind]) _latest[kind] = version;
        emit ImplementationDeployed(kind, version, implementation, r.envVersion, r.envHash, keccak256(initcode),
            implementation.codehash, r.usableFrom);
    }

    function deprecate(TokenKind kind, uint64 version, string calldata reason) external onlyRegistrar {
        if (_releases[kind][version].implementation == address(0)) revert VersionUnknown(kind, version);
        _releases[kind][version].deprecated = true;
        emit ImplementationDeprecated(kind, version, reason);
    }

    function setKindEnabled(TokenKind kind, bool on) external onlyRegistrar {
        uint256 bit = 1 << uint8(kind);
        _enabled = on ? _enabled | bit : _enabled & ~bit;
        emit KindEnabled(kind, on);
    }

    function kindEnabled(TokenKind kind) public view returns (bool) { return _enabled & (1 << uint8(kind)) != 0; }

    function releaseOf(TokenKind kind, uint64 version) external view returns (Release memory) {
        return _releases[kind][version];
    }

    function implementationOf(TokenKind kind, uint64 version) external view returns (address) {
        return _releases[kind][version].implementation;
    }

    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool) {
        return _releases[kind][version].deprecated;
    }

    function latestVersion(TokenKind kind) external view returns (uint64) { return _latest[kind]; }

    // ------------------------------------------------------------------ create

    function createToken(TokenKind kind, uint64 version, bytes calldata initArgs, bytes32 salt)
        external returns (address)
    {
        Release storage r = _releases[kind][version];
        address impl = r.implementation;
        if (impl == address(0)) revert VersionUnknown(kind, version);
        if (r.deprecated) revert VersionDeprecated(kind, version);
        if (block.timestamp < r.usableFrom) revert VersionNotYetUsable(kind, version, r.usableFrom);
        return _create(kind, version, impl, initArgs, salt);
    }

    function createTokenUnregistered(TokenKind kind, address implementation, bytes calldata initArgs, bytes32 salt)
        external returns (address)
    {
        if (uint8(kind) >= uint8(TokenKind.NONE_ZETHER)) revert UnregisteredConfidentialKind(kind);
        _checkImplementation(kind, implementation);
        return _create(kind, 0, implementation, initArgs, salt);
    }

    function predictAddress(address implementation, address creator, bytes32 salt) public view returns (address) {
        return Clones.predictDeterministicAddress(implementation, _salt(creator, salt));
    }

    // ------------------------------------------------------------------ provenance

    function isToken(address token) external view returns (bool) { return _info[token].exists; }

    function isRegisteredToken(address token) external view returns (bool) {
        return _info[token].exists && _info[token].version != 0;
    }

    function creatorOf(address token) external view returns (address) { return _info[token].creator; }

    function versionOf(address token) external view returns (TokenKind kind, uint64 version) {
        Info storage i = _info[token];
        return (i.kind, i.version);
    }

    function getWrapper(address creator, address underlying) external view returns (address) {
        address[] storage w = _wrappers[creator][underlying];
        return w.length == 0 ? address(0) : w[0];
    }

    function getWrapperCount(address creator, address underlying) external view returns (uint256) {
        return _wrappers[creator][underlying].length;
    }

    function getWrapperAt(address creator, address underlying, uint256 index) external view returns (address) {
        return _wrappers[creator][underlying][index];
    }

    function deployCountFor(address underlying) external view returns (uint256) {
        return _byUnderlying[underlying].length;
    }

    function deployedFor(address underlying, uint256 index) external view returns (address) {
        return _byUnderlying[underlying][index];
    }

    // ------------------------------------------------------------------ DEX (CTR-DEX-24)

    function deployDexImplementation(uint64 version, uint16 envVersion, bytes calldata initcode, bytes calldata implArgs)
        external onlyRegistrar returns (address implementation)
    {
        if (version == 0) revert DexVersionUnknown(0);
        address existing = _dexReleases[version].implementation;
        if (existing != address(0)) revert DexVersionAlreadyRegistered(version, existing);
        Release memory r;
        (implementation, r) =
            _deploy(DEX_DOMAIN, envVersion, keccak256(abi.encode("dex", version)), initcode, implArgs);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        (bool ok, uint256 got) = _word(implementation, bytes4(keccak256("factory()")));
        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
        (ok, got) = _word(implementation, bytes4(keccak256("chainUid()")));
        if (!ok || bytes32(got) != chainUid) revert ChainUidMismatch(chainUid, ok ? bytes32(got) : bytes32(0));
        _dexReleases[version] = r;
        if (version > _latestDex) _latestDex = version;
        emit DexImplementationDeployed(version, implementation, r.envVersion, r.envHash, keccak256(initcode),
            implementation.codehash, r.usableFrom);
    }

    function dexReleaseOf(uint64 version) external view returns (Release memory) { return _dexReleases[version]; }

    function dexImplementationOf(uint64 version) external view returns (address) {
        return _dexReleases[version].implementation;
    }

    function deprecateDex(uint64 version, string calldata reason) external onlyRegistrar {
        if (_dexReleases[version].implementation == address(0)) revert DexVersionUnknown(version);
        _dexReleases[version].deprecated = true;
        emit DexImplementationDeprecated(version, reason);
    }

    function isDexDeprecated(uint64 version) external view returns (bool) { return _dexReleases[version].deprecated; }

    function latestDexVersion() external view returns (uint64) { return _latestDex; }

    function createDex(uint64 version, bytes calldata initArgs, bytes32 salt) external returns (address dex) {
        Release storage r = _dexReleases[version];
        address impl = r.implementation;
        if (impl == address(0)) revert DexVersionUnknown(version);
        if (r.deprecated) revert DexVersionDeprecated(version);
        if (block.timestamp < r.usableFrom) revert DexVersionNotYetUsable(version, r.usableFrom);
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        if (predicted.code.length != 0 || _dexVersion[predicted] != 0) revert SaltAlreadyUsed(predicted);
        dex = Clones.cloneDeterministic(impl, s);
        ISCaaSDex(dex).initialize(msg.sender, version, initArgs);
        _dexVersion[dex] = version;
        emit DexCreated(dex, msg.sender, version, impl, ISCaaSDex(dex).admin());
    }

    function isDex(address dex) external view returns (bool) { return _dexVersion[dex] != 0; }

    function dexVersionOf(address dex) external view returns (uint64) { return _dexVersion[dex]; }

    // ------------------------------------------------------------------ internal

    function _publish(uint8 domain, uint16 envVersion, IFactoryToken.Env calldata env) private {
        if (envVersion == 0) revert EnvUnknown(domain, 0);
        if (_envHash[domain][envVersion] != bytes32(0)) revert EnvAlreadyPublished(domain, envVersion);
        if (env.factory != address(this) || env.chainUid != chainUid || env.libs.length != env.libCodeHashes.length) {
            revert EnvInvalid();
        }
        // An empty pin (0: no account; keccak256(""): no code) checks nothing (review 5g-Z2 P2-1).
        for (uint256 i; i < env.libCodeHashes.length; ++i) {
            bytes32 h = env.libCodeHashes[i];
            if (h == bytes32(0) || h == keccak256("")) revert EnvInvalid();
        }
        _envs[domain][envVersion] = env;
        bytes32 envHash = keccak256(abi.encode(env));
        _envHash[domain][envVersion] = envHash;
        if (envVersion > _latestEnv[domain]) _latestEnv[domain] = envVersion;
        emit EnvPublished(domain, envVersion, envHash);
    }

    /// @dev The domain's env `v` (named by the registrar): every linked library's code hash, then `CREATE2` of
    ///      `initcode ‖ abi.encode(v, env, implArgs)`; a constructor's revert is bubbled, an empty failure is `DeployFailed`.
    function _deploy(uint8 domain, uint16 v, bytes32 salt, bytes calldata initcode, bytes calldata implArgs)
        private returns (address at, Release memory r)
    {
        if (_envHash[domain][v] == bytes32(0)) revert EnvUnknown(domain, v);
        IFactoryToken.Env storage env = _envs[domain][v];
        for (uint256 i; i < env.libs.length; ++i) {
            bytes32 got = env.libs[i].codehash;
            if (got != env.libCodeHashes[i]) revert LibraryCodeHashMismatch(env.libs[i], env.libCodeHashes[i], got);
        }
        bytes memory code = bytes.concat(initcode, abi.encode(v, env, implArgs));
        assembly ("memory-safe") {
            at := create2(0, add(code, 32), mload(code), salt)
            if iszero(at) {
                if returndatasize() {
                    let m := mload(0x40)
                    returndatacopy(m, 0, returndatasize())
                    revert(m, returndatasize())
                }
            }
        }
        if (at == address(0)) revert DeployFailed();
        r = Release(at, v, _envHash[domain][v], uint64(block.timestamp) + noticePeriod, false);
    }

    /// @dev Code, `kind()`, `factory()`, `chainUid()`: each read by staticcall, a missing or short answer refused.
    function _checkImplementation(TokenKind kind, address implementation) private view {
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        (bool ok, uint256 got) = _word(implementation, IFactoryToken.kind.selector);
        if (!ok) got = type(uint256).max;
        if (got != uint256(kind)) revert VersionKindMismatch(kind, got);
        (ok, got) = _word(implementation, bytes4(keccak256("factory()")));
        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
        (ok, got) = _word(implementation, bytes4(keccak256("chainUid()")));
        if (!ok || bytes32(got) != chainUid) revert ChainUidMismatch(chainUid, ok ? bytes32(got) : bytes32(0));
    }

    function _word(address target, bytes4 sel) private view returns (bool ok, uint256 w) {
        bytes memory ret;
        (ok, ret) = target.staticcall(abi.encodeWithSelector(sel));
        ok = ok && ret.length == 32;
        if (ok) w = abi.decode(ret, (uint256));
    }

    function _salt(address creator, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(creator, salt));
    }

    /// @dev The generic gate (the kind enabled), the clone, `initialize` with the creator's `initArgs`, then the index
    ///      and the event from the token's own views.
    function _create(TokenKind kind, uint64 version, address impl, bytes calldata initArgs, bytes32 salt)
        private returns (address token)
    {
        if (!kindEnabled(kind)) revert KindDisabled(kind);
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        // a registered clone is never deleted; an unregistered implementation could self-destruct its clone in `initialize`
        if (_info[predicted].exists || predicted.code.length != 0) revert SaltAlreadyUsed(predicted);
        token = Clones.cloneDeterministic(impl, s);
        IFactoryToken(token).initialize(msg.sender, version, initArgs);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        address[] memory us = IFactoryToken(token).underlyings();
        if (us.length > MAX_LEGS) revert UnderlyingCountInvalid(us.length);
        for (uint256 i; i < us.length; ++i) {
            _wrappers[msg.sender][us[i]].push(token);
            _byUnderlying[us[i]].push(token);
        }
        ITokenAdmin t = ITokenAdmin(token);
        emit TokenCreated(token, msg.sender, kind, version, impl, t.features(), t.lockedFeatures(), t.owner(), us);
    }
}
