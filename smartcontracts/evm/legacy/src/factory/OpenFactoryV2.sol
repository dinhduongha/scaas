// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactoryV2} from "../common/IOpenFactoryV2.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {IFactoryTokenV2} from "./IFactoryTokenV2.sol";
import {IZetherVerifier} from "../zether/IZetherVerifier.sol";
import {ZetherSafety} from "../zether/ZetherSafety.sol";

/// @title Factory mở v2 (TW2 §9, R130) — một deployment MỚI; `OpenFactory.sol` v1 đóng băng.
/// @notice Mọi hàm v1 giữ nguyên ngữ nghĩa (kind `META`/`ZETHER`, `IFactoryToken`, `TokenDeployed`); thêm ba
///         kind `META_NONE`/`META_SINGLE`/`META_MULTI` qua `createTiered*` (`IFactoryTokenV2`, `TieredTokenDeployed`).
///         Kind ⇔ đường vào: đường v1 từ chối kind mới, đường theo tầng từ chối kind v1 — không ai đi vòng được
///         kiểm số underlying hay `tokenKind()`. Registrar không có quyền nào trên token.
contract OpenFactoryV2 is IOpenFactoryV2 {
    struct Info {
        address creator;
        TokenKind kind;
        uint64 version;
        bool exists;
    }

    uint256 internal constant MAX_LEGS = 8;

    address public immutable registrar;

    mapping(TokenKind => mapping(uint64 => address)) private _impl;
    mapping(TokenKind => mapping(uint64 => bool)) private _deprecated;
    mapping(TokenKind => uint64) private _latest;
    mapping(address => Info) private _info;
    mapping(address => mapping(address => address[])) private _wrappers;
    mapping(address => address[]) private _byUnderlying;

    /// @notice Cổng Zether như v1: **UNAUDITED — NOT FOR PRODUCTION FUNDS**, chỉ bật trên chain dev.
    bool public zetherEnabled;

    event ZetherEnabled(bool enabled);

    error NotRegistrar();
    error ZetherDisabled();
    error UnderlyingCountInvalid(uint256 n);
    /// @notice Catalogue append-only: một implementation trỏ factory khác sẽ chết vĩnh viễn ở đây.
    error ImplementationFactoryMismatch(address implementation);

    constructor(address registrar_) {
        registrar = registrar_;
    }

    modifier onlyRegistrar() {
        if (msg.sender != registrar) revert NotRegistrar();
        _;
    }

    // ------------------------------------------------------------------ catalogue

    function registerImplementation(TokenKind kind, uint64 version, address implementation) external onlyRegistrar {
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _impl[kind][version];
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        if (_isTiered(kind)) {
            _checkKind(kind, implementation);
            (bool ok, bytes memory ret) = implementation.staticcall(abi.encodeWithSignature("factory()"));
            if (!ok || ret.length != 32 || abi.decode(ret, (uint256)) != uint160(address(this))) {
                revert ImplementationFactoryMismatch(implementation);
            }
        }
        _impl[kind][version] = implementation;
        if (version > _latest[kind]) _latest[kind] = version;
        emit ImplementationRegistered(kind, version, implementation, msg.sender);
    }

    function setZetherEnabled(bool on) external onlyRegistrar {
        if (on) ZetherSafety.requireDevChain();
        zetherEnabled = on;
        emit ZetherEnabled(on);
    }

    function deprecate(TokenKind kind, uint64 version, string calldata reason) external onlyRegistrar {
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

    // ------------------------------------------------------------------ create: v1 kinds

    function createMetaToken(uint64 version, address underlying, bytes calldata initData, bytes32 salt)
        external returns (address)
    {
        return _create(TokenKind.META, version, _registered(TokenKind.META, version),
                       underlying, address(0), initData, salt);
    }

    function createZetherToken(uint64 version, address underlying, address verifier, bytes calldata initData,
        bytes32 salt) external returns (address)
    {
        _requireZether();
        address impl = _registered(TokenKind.ZETHER, version);
        _checkVerifier(verifier);
        return _create(TokenKind.ZETHER, version, impl, underlying, verifier, initData, salt);
    }

    function createUnregistered(TokenKind kind, address implementation, address underlying, address verifier,
        bytes calldata initData, bytes32 salt) external returns (address)
    {
        if (_isTiered(kind)) revert VersionKindMismatch(TokenKind.META, kind);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        if (kind == TokenKind.ZETHER) {
            _requireZether();
            _checkVerifier(verifier);
        }
        return _create(kind, 0, implementation, underlying, verifier, initData, salt);
    }

    // ------------------------------------------------------------------ create: tiered kinds

    function createTiered(TokenKind kind, uint64 version, address[] calldata underlyings, bytes calldata initData,
        bytes32 salt) external returns (address)
    {
        if (!_isTiered(kind)) revert VersionKindMismatch(TokenKind.META_NONE, kind);
        return _createTiered(kind, version, _registered(kind, version), underlyings, initData, salt);
    }

    function createTieredUnregistered(TokenKind kind, address implementation, address[] calldata underlyings,
        bytes calldata initData, bytes32 salt) external returns (address)
    {
        if (!_isTiered(kind)) revert VersionKindMismatch(TokenKind.META_NONE, kind);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        _checkKind(kind, implementation);
        return _createTiered(kind, 0, implementation, underlyings, initData, salt);
    }

    function predictAddress(address implementation, address creator, bytes32 salt) public view returns (address) {
        return Clones.predictDeterministicAddress(implementation, _salt(creator, salt));
    }

    // ------------------------------------------------------------------ provenance

    function isDeployedHere(address token) external view returns (bool) { return _info[token].exists; }

    function creatorOf(address token) external view returns (address) { return _info[token].creator; }

    function versionOf(address token) external view returns (TokenKind kind, uint64 version) {
        Info storage i = _info[token];
        return (i.kind, i.version);
    }

    /// @notice Có thể trả một token Multi (ABI một tài sản của nó revert): client đọc `versionOf(token).kind` trước.
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

    // ------------------------------------------------------------------ internal

    function _isTiered(TokenKind kind) private pure returns (bool) {
        return kind >= TokenKind.META_NONE;
    }

    /// @dev `tokenKind()` qua staticcall: không trả lời, trả sai độ dài hay ngoài enum đều là `got = META`.
    function _checkKind(TokenKind kind, address implementation) private view {
        (bool ok, bytes memory ret) = implementation.staticcall(abi.encodeCall(IFactoryTokenV2.tokenKind, ()));
        uint256 got = ok && ret.length == 32 ? abi.decode(ret, (uint256)) : 0;
        if (got != uint256(kind)) {
            revert VersionKindMismatch(kind, got <= uint256(type(TokenKind).max) ? TokenKind(got) : TokenKind.META);
        }
    }

    function _registered(TokenKind kind, uint64 version) private view returns (address impl) {
        impl = _impl[kind][version];
        if (impl == address(0)) revert VersionUnknown(kind, version);
    }

    function _requireZether() private view {
        if (!zetherEnabled) revert ZetherDisabled();
        ZetherSafety.requireDevChain();
    }

    /// @dev Như v1: precompile vắng mặt không revert, nên hỏi verifier trước khi ai nạp tiền.
    function _checkVerifier(address verifier) private view {
        if (verifier == address(0)) revert VerifierRequiredForZether();
        if (verifier.code.length == 0) revert VerifierUnsupportedOnThisChain(verifier, "");
        bool ok;
        try IZetherVerifier(verifier).isSupportedOnThisChain() returns (bool s) { ok = s; } catch {}
        if (ok) return;
        string memory curve;
        try IZetherVerifier(verifier).curveName() returns (string memory c) { curve = c; } catch {}
        revert VerifierUnsupportedOnThisChain(verifier, curve);
    }

    function _salt(address creator, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(creator, salt));
    }

    function _clone(address impl, bytes32 salt) private returns (address token) {
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        if (predicted.code.length != 0) revert SaltAlreadyUsed(predicted);
        token = Clones.cloneDeterministic(impl, s);
    }

    function _create(TokenKind kind, uint64 version, address impl, address underlying, address verifier,
        bytes calldata initData, bytes32 salt) private returns (address token)
    {
        token = _clone(impl, salt);
        IFactoryToken(token).initialize(msg.sender, underlying, verifier, version, initData);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        if (underlying != address(0)) {
            _wrappers[msg.sender][underlying].push(token);
            _byUnderlying[underlying].push(token);
        }
        emit TokenDeployed(token, msg.sender, underlying, kind, version, impl, verifier);
    }

    function _createTiered(TokenKind kind, uint64 version, address impl, address[] calldata underlyings,
        bytes calldata initData, bytes32 salt) private returns (address token)
    {
        uint256 n = underlyings.length;
        if (kind == TokenKind.META_NONE ? n != 0 : kind == TokenKind.META_SINGLE ? n != 1 : n < 2 || n > MAX_LEGS) {
            revert UnderlyingCountInvalid(n);
        }
        token = _clone(impl, salt);
        IFactoryTokenV2(token).initialize(msg.sender, underlyings, version, initData);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        for (uint256 i; i < n; ++i) {
            _wrappers[msg.sender][underlyings[i]].push(token);
            _byUnderlying[underlyings[i]].push(token);
        }
        emit TieredTokenDeployed(token, msg.sender, kind, version, impl, underlyings);
    }
}
