// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactory} from "../common/IOpenFactory.sol";
import {IFactoryToken} from "./IFactoryToken.sol";
import {IZetherVerifier} from "../zether/IZetherVerifier.sol";

/// @title Factory mở — hiện thực `IOpenFactory`. Đọc docstring của interface trước.
/// @notice Catalogue là DANH MỤC, không phải cổng: `registrar` chỉ thêm được version
///         mới, không sửa được version cũ, và `createUnregistered` đi vòng hoàn toàn.
///         Không có quyền nào ở đây chạm được một token đã deploy.
contract OpenFactory is IOpenFactory {
    struct Info {
        address creator;
        TokenKind kind;
        uint64 version;
        bool exists;
    }

    address public immutable registrar;

    mapping(TokenKind => mapping(uint64 => address)) private _impl;
    mapping(TokenKind => mapping(uint64 => bool)) private _deprecated;
    mapping(TokenKind => uint64) private _latest;
    mapping(address => Info) private _info;
    mapping(address => mapping(address => address[])) private _wrappers;
    mapping(address => address[]) private _byUnderlying;

    error NotRegistrar();

    constructor(address registrar_) {
        registrar = registrar_;
    }

    modifier onlyRegistrar() {
        if (msg.sender != registrar) revert NotRegistrar();
        _;
    }

    // ------------------------------------------------------------------ catalogue

    function registerImplementation(TokenKind kind, uint64 version, address implementation)
        external onlyRegistrar
    {
        // version 0 là dấu của `createUnregistered`; cho đăng ký thì nó mất nghĩa.
        if (version == 0) revert VersionUnknown(kind, 0);
        address existing = _impl[kind][version];
        if (existing != address(0)) revert VersionAlreadyRegistered(kind, version, existing);
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        _impl[kind][version] = implementation;
        if (version > _latest[kind]) _latest[kind] = version;
        emit ImplementationRegistered(kind, version, implementation, msg.sender);
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

    // ------------------------------------------------------------------ create

    function createMetaToken(uint64 version, address underlying, bytes calldata initData, bytes32 salt)
        external returns (address)
    {
        return _create(TokenKind.META, version, _registered(TokenKind.META, version),
                       underlying, address(0), initData, salt);
    }

    function createZetherToken(
        uint64 version,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address) {
        address impl = _registered(TokenKind.ZETHER, version);
        _checkVerifier(verifier);
        return _create(TokenKind.ZETHER, version, impl, underlying, verifier, initData, salt);
    }

    function createUnregistered(
        TokenKind kind,
        address implementation,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) external returns (address) {
        if (implementation.code.length == 0) revert ImplementationNotAContract(implementation);
        if (kind == TokenKind.ZETHER) _checkVerifier(verifier);
        return _create(kind, 0, implementation, underlying, verifier, initData, salt);
    }

    function predictAddress(address implementation, address creator, bytes32 salt)
        public view returns (address)
    {
        return Clones.predictDeterministicAddress(implementation, _salt(creator, salt));
    }

    // ------------------------------------------------------------------ provenance

    function isDeployedHere(address token) external view returns (bool) { return _info[token].exists; }

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

    // ------------------------------------------------------------------ internal

    function _registered(TokenKind kind, uint64 version) private view returns (address impl) {
        impl = _impl[kind][version];
        if (impl == address(0)) revert VersionUnknown(kind, version);
    }

    /// @dev Precompile vắng mặt không revert — nó trả rỗng. Hỏi verifier trước khi có
    ///      ai nạp tiền vào một token bất biến không bao giờ verify được (IOpenFactory).
    function _checkVerifier(address verifier) private view {
        if (verifier == address(0)) revert VerifierRequiredForZether();
        bool ok;
        try IZetherVerifier(verifier).isSupportedOnThisChain() returns (bool s) { ok = s; } catch {}
        if (ok) return;
        string memory curve;
        try IZetherVerifier(verifier).curveName() returns (string memory c) { curve = c; } catch {}
        revert VerifierUnsupportedOnThisChain(verifier, curve);
    }

    /// @dev `creator` là `msg.sender` trong salt: không ai chiếm được địa chỉ của người khác.
    function _salt(address creator, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(creator, salt));
    }

    function _create(
        TokenKind kind,
        uint64 version,
        address impl,
        address underlying,
        address verifier,
        bytes calldata initData,
        bytes32 salt
    ) private returns (address token) {
        bytes32 s = _salt(msg.sender, salt);
        address predicted = Clones.predictDeterministicAddress(impl, s);
        if (predicted.code.length != 0) revert SaltAlreadyUsed(predicted);
        token = Clones.cloneDeterministic(impl, s);
        // CÙNG hàm với CREATE2: không có khe nào để front-run initialize().
        IFactoryToken(token).initialize(msg.sender, underlying, verifier, version, initData);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        _wrappers[msg.sender][underlying].push(token);
        _byUnderlying[underlying].push(token);
        emit TokenDeployed(token, msg.sender, underlying, kind, version, impl, verifier);
    }
}
