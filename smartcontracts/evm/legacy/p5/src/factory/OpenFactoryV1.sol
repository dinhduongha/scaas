// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IOpenFactoryV1} from "../common/IOpenFactoryV1.sol";
import {IFactoryTokenV1} from "./IFactoryTokenV1.sol";
import {IZetherVerifier} from "../zether/IZetherVerifier.sol";
import {ZetherSafety} from "../zether/ZetherSafety.sol";

/// @title Factory mở — hiện thực `IOpenFactoryV1`. Đọc docstring của interface trước.
/// @notice Catalogue là DANH MỤC, không phải cổng: `registrar` chỉ thêm được version
///         mới, không sửa được version cũ, và `createUnregistered` đi vòng hoàn toàn.
///         Không có quyền nào ở đây chạm được một token đã deploy.
contract OpenFactoryV1 is IOpenFactoryV1 {
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

    /// @notice Cổng Zether của owner (R34, RS2-1): **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Mặc định tắt;
    ///         chỉ bật được trên chain dev (`ZetherSafety`), và tạo token Zether kiểm lại cả hai mỗi lần.
    bool public zetherEnabled;

    event ZetherEnabled(bool enabled);

    error NotRegistrar();
    error ZetherDisabled();

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

    /// @notice Bật/tắt tạo token Zether. Bật revert `ZetherNotDevChain` ngoài allowlist dev; tắt luôn được.
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
        _requireZether();
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
        if (kind == TokenKind.ZETHER) {
            _requireZether();
            _checkVerifier(verifier);
        }
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

    function _requireZether() private view {
        if (!zetherEnabled) revert ZetherDisabled();
        ZetherSafety.requireDevChain(); // cờ bật trên một chain dev rồi chain đổi id (fork) vẫn không lọt
    }

    /// @dev Precompile vắng mặt không revert — nó trả rỗng. Hỏi verifier trước khi có
    ///      ai nạp tiền vào một token bất biến không bao giờ verify được (IOpenFactoryV1).
    function _checkVerifier(address verifier) private view {
        if (verifier == address(0)) revert VerifierRequiredForZether();
        // Không code ⇒ lời gọi "thành công" với returndata rỗng, và lỗi giải mã nổ ở
        // frame NÀY — ngoài tầm `catch`. Phải chặn trước.
        if (verifier.code.length == 0) revert VerifierUnsupportedOnThisChain(verifier, "");
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
        IFactoryTokenV1(token).initialize(msg.sender, underlying, verifier, version, initData);
        _info[token] = Info({creator: msg.sender, kind: kind, version: version, exists: true});
        // Tầng 1 (underlying 0) không phải wrapper của gì cả: không vào sổ wrapper.
        if (underlying != address(0)) {
            _wrappers[msg.sender][underlying].push(token);
            _byUnderlying[underlying].push(token);
        }
        emit TokenDeployed(token, msg.sender, underlying, kind, version, impl, verifier);
    }
}
