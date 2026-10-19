// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "./IOpenFactory.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {ISCaaSDex} from "../dex/ISCaaSDex.sol";
import {ITokenAdmin} from "../metatx/ITokenAdmin.sol";
import {IZetherVerifierCommon} from "../zether/IZetherVerifier.sol";
import {IZetherToken} from "../zether/IZetherToken.sol";
import {ZetherSafety} from "../zether/ZetherSafety.sol";
import {PqzSafety} from "../pqz/PqzSafety.sol";

/// @title `OpenFactory` (CTR-TOK-03, CTR-TOK-25): the one token factory of a chain.
/// @notice Anyone creates tokens; the registrar only appends implementations to the catalogue (and marks versions
///         deprecated): it has no power over any token. A registered implementation must answer `kind()`,
///         `factory() == this` and `chainUid() == chainUid` (so a clone's domain salt has one source, CTR-GEN-05);
///         the catalogue is append-only, so a wrong entry would be dead forever. Creation clones by `CREATE2` with
///         the salt scoped by the creator and calls `initialize` in the same call; flag validation is the token's.
///         Kinds `NONE`, `UNDERLYING`, `NONE_ZETHER`, `UNDERLYING_ZETHER`; a `*_ZETHER` creation passes the Zether gate
///         (`zetherEnabled`, a dev chain, a verifier this chain runs), a `*_PQZ` one the PQZ gate. The confidential
///         verifiers are canonical (owner 2026-10-19, CTR-ZTH-20): fixed in the constructor (`Canonical`), and a
///         confidential implementation is registered only when its verifier immutables are one of those sets; the
///         creator never names a verifier and cannot use an unregistered confidential implementation. A deprecated
///         version is no longer creatable (owner 2026-10-20). The registrar's key remains the trust root for code.
///         **Zether is UNAUDITED — NOT FOR PRODUCTION FUNDS.**
contract OpenFactory is IOpenFactory {
    struct Info {
        address creator;
        TokenKind kind;
        uint64 version;
        bool exists;
    }

    uint256 internal constant MAX_LEGS = 8;
    bytes4 private constant _VERIFIER_SEL = bytes4(keccak256("verifier()"));

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
    mapping(uint64 => bool) private _dexDeprecated;
    bool public zetherEnabled;
    bool public pqzEnabled;

    address private immutable _ZV0;
    address private immutable _ZV1;
    address private immutable _ZB0;
    address private immutable _ZB1;
    address private immutable _ZD0;
    address private immutable _ZD1;
    address private immutable _PQ0;
    address private immutable _PQ1;

    constructor(address registrar_, bytes32 chainUid_, Canonical memory c) {
        if (chainUid_ == bytes32(0)) revert ChainUidZero();
        registrar = registrar_;
        chainUid = chainUid_;
        (_ZV0, _ZV1, _ZB0, _ZB1) = (c.zetherVerifier[0], c.zetherVerifier[1], c.zetherBurnVerifier[0], c.zetherBurnVerifier[1]);
        (_ZD0, _ZD1, _PQ0, _PQ1) = (c.zetherDisclosure[0], c.zetherDisclosure[1], c.pqzVerifier[0], c.pqzVerifier[1]);
    }

    function zetherVerifiers(uint8 curve) public view returns (address verifier, address burnVerifier, address disclosure) {
        if (curve == 0) return (_ZV0, _ZB0, _ZD0);
        if (curve == 1) return (_ZV1, _ZB1, _ZD1);
    }

    function pqzVerifier(uint8 proofSystem) public view returns (address) {
        return proofSystem == 0 ? _PQ0 : proofSystem == 1 ? _PQ1 : address(0);
    }

    // ------------------------------------------------------------------ catalogue

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _impl[kind][version];
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        _checkImplementation(kind, implementation);
        _checkCanonical(kind, implementation);
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
        if (_deprecated[kind][version]) revert VersionDeprecated(kind, version);
        return _create(kind, version, impl, cfg, salt);
    }

    function createTokenUnregistered(
        TokenKind kind, address implementation, IFactoryToken.TokenConfig calldata cfg, bytes32 salt
    ) external returns (address) {
        if (uint8(kind) >= uint8(TokenKind.NONE_ZETHER)) revert UnregisteredConfidentialKind(kind);
        _checkImplementation(kind, implementation);
        return _create(kind, 0, implementation, cfg, salt);
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

    function deprecateDex(uint64 version, string calldata reason) external {
        if (msg.sender != registrar) revert NotRegistrar();
        if (_dexImpl[version] == address(0)) revert DexVersionUnknown(version);
        _dexDeprecated[version] = true;
        emit DexImplementationDeprecated(version, reason);
    }

    function isDexDeprecated(uint64 version) external view returns (bool) { return _dexDeprecated[version]; }

    function latestDexVersion() external view returns (uint64) { return _latestDex; }

    function createDex(uint64 version, ISCaaSDex.DexConfig calldata cfg, bytes32 salt) external returns (address dex) {
        address impl = _dexImpl[version];
        if (impl == address(0)) revert DexVersionUnknown(version);
        if (_dexDeprecated[version]) revert DexVersionDeprecated(version);
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

    /// @dev A confidential implementation's verifier immutables must be one canonical set (CTR-ZTH-20): Zether
    ///      `(verifier(), burnVerifier(), disclosure())` equal to curve 0's or curve 1's, PQZ `verifier()` equal to PQZL's
    ///      or PQZH's. No answer reads as 0, and 0 never matches.
    function _checkCanonical(TokenKind kind, address impl) private view {
        bool ok = true;
        if (_isZether(kind)) {
            address v = _addr(impl, IZetherToken.verifier.selector);
            address b = _addr(impl, IZetherToken.burnVerifier.selector);
            address d = _addr(impl, IZetherToken.disclosure.selector);
            ok = v != address(0) && ((v == _ZV0 && b == _ZB0 && d == _ZD0) || (v == _ZV1 && b == _ZB1 && d == _ZD1));
        } else if (_isPqz(kind)) {
            address v = _addr(impl, _VERIFIER_SEL);
            ok = v != address(0) && (v == _PQ0 || v == _PQ1);
        }
        if (!ok) revert NotCanonicalVerifiers(impl);
    }

    function _isZether(TokenKind kind) private pure returns (bool) {
        return kind == TokenKind.NONE_ZETHER || kind == TokenKind.UNDERLYING_ZETHER;
    }

    function _isPqz(TokenKind kind) private pure returns (bool) {
        return kind == TokenKind.NONE_PQZ || kind == TokenKind.UNDERLYING_PQZ;
    }

    /// @dev An address-sized answer of `impl`, else 0.
    function _addr(address impl, bytes4 sel) private view returns (address) {
        (bool ok, uint256 w) = _word(impl, sel);
        return ok && w == uint160(w) ? address(uint160(w)) : address(0);
    }

    /// @dev The gate, then the verifier: an absent precompile does not revert, it returns success with empty output,
    ///      so a verifier this chain cannot run is refused before anyone deposits (CTR-TOK-03).
    function _checkZether(address verifier) private view {
        if (!zetherEnabled) revert ZetherDisabled();
        ZetherSafety.requireDevChain(); // a flag set on a dev chain does not survive a chain id change (fork)
        // low level: no code, or a fallback answering with empty data, fails typed rather than with a decode revert
        (bool answered, uint256 w) = _word(verifier, IZetherVerifierCommon.isSupportedOnThisChain.selector);
        if (answered && w == 1) return;
        string memory curve;
        if (answered) try IZetherVerifierCommon(verifier).curveName() returns (string memory c) { curve = c; } catch {}
        revert VerifierUnsupportedOnThisChain(verifier, curve);
    }

    /// @dev The PQZ gate, the chain, then the verifier's own check (chain and the precompile's self-test, now).
    function _checkPqz(address verifier) private view {
        if (!pqzEnabled) revert PqzDisabled();
        PqzSafety.requireAllowedChain();
        (bool answered, uint256 w) = _word(verifier, IZetherVerifierCommon.isSupportedOnThisChain.selector);
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
        // the release's own verifier (an immutable checked at registration, CTR-ZTH-20)
        if (_isZether(kind)) _checkZether(_addr(impl, _VERIFIER_SEL));
        if (_isPqz(kind)) _checkPqz(_addr(impl, _VERIFIER_SEL));
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
