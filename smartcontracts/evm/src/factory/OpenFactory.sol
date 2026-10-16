// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "./IOpenFactory.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
import {ITokenAdmin} from "../metatx/ITokenAdmin.sol";
import {IZetherVerifier} from "../zether/IZetherVerifier.sol";
import {ZetherSafety} from "../zether/ZetherSafety.sol";
import {PqzSafety} from "../pqz/PqzSafety.sol";

/// @title `OpenFactory` (CTR-TOK-03, CTR-TOK-25): the one token factory of a chain.
/// @notice Anyone creates tokens; the registrar only appends implementations to the catalogue (and marks versions
///         deprecated): it has no power over any token. A registered implementation must answer `kind()`,
///         `factory() == this` and `chainUid() == chainUid` (so a clone's domain salt has one source, CTR-GEN-05);
///         the catalogue is append-only, so a wrong entry would be dead forever. Creation clones by `CREATE2` with
///         the salt scoped by the creator and calls `initialize` in the same call; flag validation is the token's.
///         Kinds `NONE`, `UNDERLYING`, `NONE_ZETHER`, `UNDERLYING_ZETHER`; a `*_ZETHER` creation passes the Zether gate
///         (`zetherEnabled`, a dev chain, a verifier this chain runs). **Zether is UNAUDITED — NOT FOR PRODUCTION FUNDS.**
contract OpenFactory is IOpenFactory {
    struct Info {
        address creator;
        TokenKind kind;
        uint64 version;
        bool exists;
    }

    uint256 internal constant MAX_LEGS = 8;

    address public immutable registrar;
    bytes32 public immutable chainUid;

    mapping(TokenKind => mapping(uint64 => address)) private _impl;
    mapping(TokenKind => mapping(uint64 => bool)) private _deprecated;
    mapping(TokenKind => uint64) private _latest;
    mapping(address => Info) private _info;
    mapping(address => mapping(address => address[])) private _wrappers;
    mapping(address => address[]) private _byUnderlying;
    mapping(uint64 => address) private _dexImpl;
    uint64 private _latestDex;
    mapping(address => uint64) private _dexVersion; // 0 = not a DEX made here
    bool public zetherEnabled;
    bool public pqzEnabled;

    constructor(address registrar_, bytes32 chainUid_) {
        if (chainUid_ == bytes32(0)) revert ChainUidZero();
        registrar = registrar_;
        chainUid = chainUid_;
    }

    // ------------------------------------------------------------------ catalogue

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _impl[kind][version];
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        _checkImplementation(kind, implementation);
        _impl[kind][version] = implementation;
        if (version > _latest[kind]) _latest[kind] = version;
        emit ImplementationRegistered(kind, version, implementation, msg.sender);
    }

    function deprecate(TokenKind kind, uint64 version, string calldata reason) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (_impl[kind][version] == address(0)) revert VersionUnknown(kind, version);
        _deprecated[kind][version] = true;
        emit ImplementationDeprecated(kind, version, reason);
    }

    function implementationOf(TokenKind kind, uint64 version) external view returns (address) {
        return _impl[kind][version];
    }

    function isDeprecated(TokenKind kind, uint64 version) external view returns (bool) {
        return _deprecated[kind][version];
    }

    function latestVersion(TokenKind kind) external view returns (uint64) {
        return _latest[kind];
    }

    function setZetherEnabled(bool on) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (on) ZetherSafety.requireDevChain();
        zetherEnabled = on;
        emit ZetherEnabled(on);
    }

    function setPqzEnabled(bool on) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (on) {
            PqzSafety.requireAllowedChain();
            PqzSafety.requireSelfTest(PqzSafety.PQZ);
        }
        pqzEnabled = on;
        emit PqzEnabled(on);
    }

    // ------------------------------------------------------------------ create

    function createToken(TokenKind kind, uint64 version, IFactoryToken.TokenConfig calldata cfg, bytes32 salt)
        external returns (address)
    {
        address impl = _impl[kind][version];
        if (impl == address(0)) revert VersionUnknown(kind, version);
        return _create(kind, version, impl, cfg, salt);
    }

    function createTokenUnregistered(
        TokenKind kind, address implementation, IFactoryToken.TokenConfig calldata cfg, bytes32 salt
    ) external returns (address) {
        _checkImplementation(kind, implementation);
        return _create(kind, 0, implementation, cfg, salt);
    }

    function predictAddress(address implementation, address creator, bytes32 salt) public view returns (address) {
        return Clones.predictDeterministicAddress(implementation, _salt(creator, salt));
    }

    // ------------------------------------------------------------------ provenance

    function isToken(address token) external view returns (bool) { return _info[token].exists; }

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

    function registerDexImplementation(uint64 version, address implementation) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (version == 0) revert DexVersionUnknown(0);
        address existing = _dexImpl[version];
        if (existing != address(0)) revert DexVersionAlreadyRegistered(version, existing);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        (bool ok, uint256 got) = _word(implementation, bytes4(keccak256("factory()")));
        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
        (ok, got) = _word(implementation, bytes4(keccak256("chainUid()")));
        if (!ok || bytes32(got) != chainUid) revert ChainUidMismatch(chainUid, ok ? bytes32(got) : bytes32(0));
        _dexImpl[version] = implementation;
        if (version > _latestDex) _latestDex = version;
        emit DexImplementationRegistered(version, implementation, msg.sender);
    }

    function dexImplementationOf(uint64 version) external view returns (address) { return _dexImpl[version]; }

    function latestDexVersion() external view returns (uint64) { return _latestDex; }

    function createDex(uint64 version, ISCaaSDex.DexConfig calldata cfg, bytes32 salt) external returns (address dex) {
        address impl = _dexImpl[version];
        if (impl == address(0)) revert DexVersionUnknown(version);
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        if (predicted.code.length != 0 || _dexVersion[predicted] != 0) revert SaltAlreadyUsed(predicted);
        dex = Clones.cloneDeterministic(impl, s);
        ISCaaSDex(dex).initialize(msg.sender, version, cfg);
        _dexVersion[dex] = version;
        emit DexCreated(dex, msg.sender, version, impl, cfg.admin);
    }

    function isDex(address dex) external view returns (bool) { return _dexVersion[dex] != 0; }

    function dexVersionOf(address dex) external view returns (uint64) { return _dexVersion[dex]; }

    // ------------------------------------------------------------------ internal

    /// @dev Code, `kind()`, `factory()`, `chainUid()`: each read by staticcall, a missing or short answer refused.
    function _checkImplementation(TokenKind kind, address implementation) private view {
        if (uint8(kind) > uint8(TokenKind.UNDERLYING_PQZ)) revert KindReserved(kind);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        (bool ok, uint256 got) = _word(implementation, IFactoryToken.kind.selector);
        if (!ok) got = type(uint256).max;
        if (got != uint256(kind)) revert VersionKindMismatch(kind, got);
        (ok, got) = _word(implementation, bytes4(keccak256("factory()")));
        if (!ok || got != uint256(uint160(address(this)))) revert ImplementationFactoryMismatch(implementation);
        (ok, got) = _word(implementation, bytes4(keccak256("chainUid()")));
        if (!ok || bytes32(got) != chainUid) revert ChainUidMismatch(chainUid, ok ? bytes32(got) : bytes32(0));
    }

    /// @dev The gate, then the verifier: an absent precompile does not revert, it returns success with empty output,
    ///      so a verifier this chain cannot run is refused before anyone deposits (CTR-TOK-03).
    function _checkZether(address verifier) private view {
        if (!zetherEnabled) revert ZetherDisabled();
        ZetherSafety.requireDevChain(); // a flag set on a dev chain does not survive a chain id change (fork)
        if (verifier == address(0)) revert VerifierRequiredForZether();
        // low level: no code, or a fallback answering with empty data, fails typed rather than with a decode revert
        (bool answered, uint256 w) = _word(verifier, IZetherVerifier.isSupportedOnThisChain.selector);
        if (answered && w == 1) return;
        string memory curve;
        if (answered) try IZetherVerifier(verifier).curveName() returns (string memory c) { curve = c; } catch {}
        revert VerifierUnsupportedOnThisChain(verifier, curve);
    }

    /// @dev The PQZ gate, the chain, then the verifier's own check (chain and the precompile's self-test, now).
    function _checkPqz(address verifier) private view {
        if (!pqzEnabled) revert PqzDisabled();
        PqzSafety.requireAllowedChain();
        if (verifier == address(0)) revert VerifierRequiredForPqz();
        (bool answered, uint256 w) = _word(verifier, IZetherVerifier.isSupportedOnThisChain.selector);
        if (!answered || w != 1) revert PqzVerifierUnsupported(verifier);
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

    function _create(TokenKind kind, uint64 version, address impl, IFactoryToken.TokenConfig calldata cfg,
        bytes32 salt) private returns (address token)
    {
        if (kind == TokenKind.NONE_ZETHER || kind == TokenKind.UNDERLYING_ZETHER) _checkZether(cfg.conf.verifier);
        if (kind == TokenKind.NONE_PQZ || kind == TokenKind.UNDERLYING_PQZ) _checkPqz(cfg.conf.verifier);
        uint256 n = cfg.legs.length;
        bool wrapper = kind == TokenKind.UNDERLYING || kind == TokenKind.UNDERLYING_ZETHER
            || kind == TokenKind.UNDERLYING_PQZ;
        if (wrapper ? n == 0 || n > MAX_LEGS : n != 0) revert UnderlyingCountInvalid(n);
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        // a registered clone is never deleted; an unregistered implementation could self-destruct its clone in `initialize`
        if (_info[predicted].exists || predicted.code.length != 0) revert SaltAlreadyUsed(predicted);
        token = Clones.cloneDeterministic(impl, s);
        IFactoryToken(token).initialize(msg.sender, version, cfg);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        address[] memory us = new address[](n);
        for (uint256 i; i < n; ++i) {
            address u = cfg.legs[i].underlying;
            us[i] = u;
            _wrappers[msg.sender][u].push(token);
            _byUnderlying[u].push(token);
        }
        emit TokenCreated(token, msg.sender, kind, version, impl, cfg.features,
            ITokenAdmin(token).lockedFeatures(), cfg.owner, us);
    }
}
