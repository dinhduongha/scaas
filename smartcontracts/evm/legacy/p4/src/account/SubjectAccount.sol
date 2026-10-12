// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";

enum KeyKind {
    NONE,           // 0 — slot trống / đã xoá
    P256_WEBAUTHN,  // 1 — passkey: (x, y) P-256 + rpIdHash + originHash
    SECP256K1       // 2 — khoá dẫn xuất từ seed: x = địa chỉ (căn phải), còn lại 0
}

/// @dev Một khoá được uỷ quyền. `keyId = keccak256(abi.encode(key))`.
struct SubjectKey {
    KeyKind kind;
    bytes32 x;
    bytes32 y;
    bytes32 rpIdHash;    // sha256(rpId) — 32 byte đầu của authenticatorData
    bytes32 originHash;  // keccak256(origin) — giá trị "origin" trong clientDataJSON
}

/// @title Account của MỘT chủ thể trên một mạng EVM, nhiều khoá (R31 + R32, §C.3).
/// @notice ERC-1271 (`AuthScheme.SMART_ACCOUNT_1271 = 7`): token gọi `isValidSignature` với
///         digest EIP-712 của meta-tx (digest đã mang `from` = account này, nên chữ ký của một
///         khoá dùng chung cho hai account không chuyển được sang account kia).
///
///         Chữ ký = `abi.encode(uint256 keyIndex, bytes32[] proof, bytes sig)` (RS4-3):
///         - `proof` rỗng ⇒ thông điệp = digest; khác rỗng ⇒ thông điệp = gốc Merkle của lô,
///           lá `batchLeaf(digest)` băm kép có miền 0x00 (review S26).
///         - P-256: `sig = abi.encode(bytes authenticatorData, bytes clientDataJSON, bytes32 r, bytes32 s)`,
///           challenge = base64url(thông điệp).
///         - secp256k1: `sig` 65 byte ECDSA (low-s) trên thông điệp thô.
///
///         Vòng đời khoá chỉ qua `executeAsOwner` (một khoá hiện có ký, nonce riêng) hoặc
///         guardian sau `RECOVERY_DELAY` (huỷ được bởi một khoá). Không bao giờ còn 0 khoá.
///         Không owner/admin nào khác: factory chỉ khởi tạo, không giữ quyền gì.
contract SubjectAccount is EIP712, IERC1271 {
    bytes32 public constant OWNER_CALL_TYPEHASH =
        keccak256("OwnerCall(bytes data,uint256 nonce,uint256 validUntil)");
    uint256 public constant RECOVERY_DELAY = 2 days;
    bytes4 private constant _INVALID = 0xffffffff;
    uint8 private constant _FLAG_UP = 0x01;
    uint8 private constant _FLAG_UV = 0x04;

    address public immutable FACTORY;

    bool private _initialized;
    mapping(uint256 index => SubjectKey) private _keys;
    mapping(bytes32 keyId => bool) public hasKey;
    uint256 public keyCount;
    uint256 public nextKeyIndex;
    uint256 public ownerNonce;
    address public guardian;
    bytes32 public pendingRecovery;   // keyId của khoá guardian muốn thêm
    uint256 public recoveryReadyAt;

    event KeyAdded(uint256 indexed index, KeyKind kind, bytes32 indexed keyId);
    event KeyRemoved(uint256 indexed index, bytes32 indexed keyId);
    event GuardianSet(address indexed guardian);
    event RecoveryInitiated(bytes32 indexed keyId, uint256 readyAt);
    event RecoveryCancelled(bytes32 indexed keyId);
    event OwnerCallExecuted(uint256 indexed nonce);

    error NotFactory();
    error AlreadyInitialized();
    error NotSelf();
    error NotGuardian();
    error BadKey();
    error DuplicateKey();
    error NoSuchKey(uint256 index);
    error LastKey();
    error SignatureExpired();
    error BadNonce();
    error BadSignature();
    error CallFailed(bytes reason);
    error NoRecovery();
    error RecoveryNotReady(uint256 readyAt);

    modifier onlySelf() {
        if (msg.sender != address(this)) revert NotSelf();
        _;
    }

    /// @dev Chạy MỘT lần trên implementation (do factory deploy). Khoá luôn implementation.
    constructor() EIP712("SCaaS SubjectAccount", "1") {
        FACTORY = msg.sender;
        _initialized = true;
    }

    /// @notice Chỉ factory, trong cùng tx với clone (RS4-1): không có cửa sổ front-run.
    function initialize(SubjectKey calldata firstKey, address guardian_) external {
        if (msg.sender != FACTORY) revert NotFactory();
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;
        _addKey(firstKey);
        if (guardian_ != address(0)) {
            guardian = guardian_;
            emit GuardianSet(guardian_);
        }
    }

    receive() external payable {}

    // ------------------------------------------------------------------ ERC-1271

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _isValid(hash, signature) ? IERC1271.isValidSignature.selector : _INVALID;
    }

    // ------------------------------------------------------------------ owner (một khoá ký)

    /// @notice Gasless cho chủ thể: một khoá hiện có ký `OwnerCall`, relayer nộp. Mọi hàm
    ///         `onlySelf` chạy qua đây với `msg.sender == address(this)`.
    function executeAsOwner(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata signature)
        external returns (bytes memory)
    {
        if (block.timestamp > validUntil) revert SignatureExpired();
        if (nonce != ownerNonce) revert BadNonce();
        if (!_isValid(ownerCallDigest(data, nonce, validUntil), signature)) revert BadSignature();
        ownerNonce = nonce + 1;
        emit OwnerCallExecuted(nonce);
        (bool ok, bytes memory ret) = address(this).call(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    function addKey(SubjectKey calldata key) external onlySelf returns (uint256) {
        return _addKey(key);
    }

    function removeKey(uint256 index) external onlySelf {
        _removeKey(index);
    }

    /// @notice Xoay = thêm khoá mới rồi xoá khoá cũ, nguyên tử.
    function rotateKey(uint256 index, SubjectKey calldata key) external onlySelf returns (uint256 added) {
        added = _addKey(key);
        _removeKey(index);
    }

    /// @notice Đổi guardian huỷ luôn recovery đang chờ của guardian cũ.
    function setGuardian(address guardian_) external onlySelf {
        guardian = guardian_;
        _clearRecovery();
        emit GuardianSet(guardian_);
    }

    function cancelRecovery() external onlySelf {
        if (pendingRecovery == bytes32(0)) revert NoRecovery();
        _clearRecovery();
    }

    /// @notice Chủ thể làm gì cũng được với tài sản của mình (rút, chuyển). Token vẫn tự áp R26
    ///         (allowance chỉ cho hợp đồng).
    function execute(address target, uint256 value, bytes calldata data) external onlySelf returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    // ------------------------------------------------------------------ guardian

    /// @notice Gọi lại khi đang chờ ⇒ đặt lại khoá và đồng hồ.
    function initiateRecovery(SubjectKey calldata key) external {
        if (msg.sender != guardian || guardian == address(0)) revert NotGuardian();
        _checkKey(key);
        bytes32 id = keyIdOf(key);
        pendingRecovery = id;
        recoveryReadyAt = block.timestamp + RECOVERY_DELAY;
        emit RecoveryInitiated(id, recoveryReadyAt);
    }

    /// @notice Ai cũng nộp được sau trễ. THÊM khoá (RS4-4): khoá cũ không bị xoá — chủ thể
    ///         xoá khoá đã mất bằng chính khoá mới.
    function completeRecovery(SubjectKey calldata key) external returns (uint256 index) {
        bytes32 id = pendingRecovery;
        if (id == bytes32(0) || keyIdOf(key) != id) revert NoRecovery();
        if (block.timestamp < recoveryReadyAt) revert RecoveryNotReady(recoveryReadyAt);
        pendingRecovery = bytes32(0);
        recoveryReadyAt = 0;
        index = _addKey(key);
    }

    // ------------------------------------------------------------------ views

    function keyAt(uint256 index) external view returns (SubjectKey memory) {
        return _keys[index];
    }

    function keyIdOf(SubjectKey calldata key) public pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }

    function ownerCallDigest(bytes calldata data, uint256 nonce, uint256 validUntil) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(OWNER_CALL_TYPEHASH, keccak256(data), nonce, validUntil)));
    }

    /// @notice Lá Merkle của một digest trong lô: `keccak256(keccak256(0x00 ‖ digest))`.
    function batchLeaf(bytes32 digest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes1(0x00), digest))));
    }

    // ------------------------------------------------------------------ private

    function _addKey(SubjectKey calldata key) private returns (uint256 index) {
        _checkKey(key);
        bytes32 id = keyIdOf(key);
        if (hasKey[id]) revert DuplicateKey();
        hasKey[id] = true;
        index = nextKeyIndex++;
        _keys[index] = key;
        keyCount += 1;
        emit KeyAdded(index, key.kind, id);
    }

    function _removeKey(uint256 index) private {
        SubjectKey storage k = _keys[index];
        if (k.kind == KeyKind.NONE) revert NoSuchKey(index);
        if (keyCount == 1) revert LastKey();
        bytes32 id = keccak256(abi.encode(k));
        delete hasKey[id];
        delete _keys[index];
        keyCount -= 1;
        emit KeyRemoved(index, id);
    }

    function _clearRecovery() private {
        bytes32 id = pendingRecovery;
        if (id != bytes32(0)) {
            pendingRecovery = bytes32(0);
            recoveryReadyAt = 0;
            emit RecoveryCancelled(id);
        }
    }

    function _checkKey(SubjectKey calldata k) private pure {
        if (k.kind == KeyKind.P256_WEBAUTHN) {
            if (!P256.isValidPublicKey(k.x, k.y) || k.rpIdHash == 0 || k.originHash == 0) revert BadKey();
        } else if (k.kind == KeyKind.SECP256K1) {
            if (k.x == 0 || uint256(k.x) >> 160 != 0 || k.y != 0 || k.rpIdHash != 0 || k.originHash != 0) {
                revert BadKey();
            }
        } else {
            revert BadKey();
        }
    }

    function _isValid(bytes32 digest, bytes calldata signature) private view returns (bool) {
        (uint256 index, bytes32[] memory proof, bytes memory sig) =
            abi.decode(signature, (uint256, bytes32[], bytes));
        SubjectKey storage k = _keys[index];
        bytes32 message = proof.length == 0 ? digest : MerkleProof.processProof(proof, batchLeaf(digest));
        KeyKind kind = k.kind;
        if (kind == KeyKind.SECP256K1) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(message, sig);
            return err == ECDSA.RecoverError.NoError && rec == address(uint160(uint256(k.x)));
        }
        if (kind == KeyKind.P256_WEBAUTHN) return _verifyWebAuthn(k, message, sig);
        return false;
    }

    /// @dev WebAuthn assertion (§C.1): rpIdHash, cờ UP+UV, clientDataJSON (RS4-2), rồi P-256 trên
    ///      `sha256(authenticatorData ‖ sha256(clientDataJSON))`. `P256.verify` từ chối s > n/2 —
    ///      client chuẩn hoá `s := n − s` sau khi giải DER (review S5).
    function _verifyWebAuthn(SubjectKey storage k, bytes32 message, bytes memory sig) private view returns (bool) {
        (bytes memory authData, bytes memory clientData, bytes32 r, bytes32 s) =
            abi.decode(sig, (bytes, bytes, bytes32, bytes32));
        if (authData.length < 37) return false;
        bytes32 rpIdHash;
        assembly ("memory-safe") { rpIdHash := mload(add(authData, 32)) }
        if (rpIdHash != k.rpIdHash) return false;
        if (uint8(authData[32]) & (_FLAG_UP | _FLAG_UV) != (_FLAG_UP | _FLAG_UV)) return false;
        if (!_clientDataOk(clientData, message, k.originHash)) return false;
        bytes32 h = sha256(abi.encodePacked(authData, sha256(clientData)));
        return P256.verify(h, r, s, k.x, k.y);
    }

    /// @dev Kiểm giới hạn của WebAuthn L3 §5.8.1.2 (RS4-2): tiền tố cố định gồm type +
    ///      challenge, origin tới dấu `"` kế tiếp, rồi đúng một trong hai: `}` là ký tự cuối
    ///      (Safari, L2), hoặc `,"crossOrigin":false` theo sau bởi `}`/`,` (Chrome, Firefox, L3).
    ///      Mọi thứ khác — `crossOrigin:true` (iframe của site khác), khoá lạ chen trước
    ///      crossOrigin, khoảng trắng — đều từ chối (review SEC-01): fail-closed.
    function _clientDataOk(bytes memory cd, bytes32 challenge, bytes32 originHash) private pure returns (bool) {
        bytes memory prefix = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '","origin":"');
        uint256 p = prefix.length;
        uint256 n = cd.length;
        if (n < p + 2 || _hashSlice(cd, 0, p) != keccak256(prefix)) return false;
        uint256 end = p;
        while (end < n && cd[end] != '"') ++end;
        if (end + 1 >= n || _hashSlice(cd, p, end - p) != originHash) return false;
        if (cd[end + 1] == "}") return end + 2 == n;
        bytes memory crossFalse = ',"crossOrigin":false';
        uint256 after_ = end + 1 + crossFalse.length;
        if (after_ >= n || _hashSlice(cd, end + 1, crossFalse.length) != keccak256(crossFalse)) return false;
        if (cd[after_] == "}") return after_ + 1 == n;
        return cd[after_] == ",";
    }

    function _hashSlice(bytes memory b, uint256 start, uint256 len) private pure returns (bytes32 h) {
        assembly ("memory-safe") { h := keccak256(add(add(b, 32), start), len) }
    }
}
