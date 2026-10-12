// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MetaTxBase} from "../metatx/MetaTxBase.sol";
import {IMetaTx} from "../metatx/IMetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {WebAuthnClientData} from "../common/WebAuthnClientData.sol";

enum KeyKind {
    NONE,           // 0: empty or removed slot
    P256_WEBAUTHN,  // 1: passkey: (x, y) P-256 + rpIdHash + originHash
    SECP256K1       // 2: seed-derived key: x = address (right-aligned), the rest 0
}

/// @dev One authorised key of the subject. `keyId = keccak256(abi.encode(key))`.
struct SubjectKey {
    KeyKind kind;
    bytes32 x;
    bytes32 y;
    bytes32 rpIdHash;    // sha256(rpId): the first 32 bytes of authenticatorData
    bytes32 originHash;  // keccak256(origin): the "origin" value of clientDataJSON
}

/// @title The multi-key ERC-1271 account of one subject on one EVM chain (CTR-ACC-09…11), on `MetaTxBase`.
/// @notice ERC-1271 for tokens and the DEX: `isValidSignature(digest, abi.encode(uint256 keyIndex, bytes32[] proof,
///         bytes sig))` (CTR-ACC-02): an empty `proof` signs the digest, a non-empty one a Merkle root whose leaf is
///         `batchLeaf(digest)`; P-256 `sig = abi.encode(authenticatorData, clientDataJSON, r, s)` with challenge =
///         base64url(message), secp256k1 `sig` = 65-byte ECDSA (low-s) over the raw message.
///
///         Key management is a `MetaTransaction` signed by the account itself (CTR-ACC-10): `from = address(this)`
///         (its passkeys have no address), checked against its own key set, domain `("SCaaS SmartKeyAccount", "1",
///         chainId, account, chain_uid)`, the 2D lane nonce, fee mode `NONE`. `addKey`, `removeKey`, `rotateKey`,
///         `setGuardian`, `cancelRecovery` and `execute` are allowlisted self-calls, `onlySelf`. `mtxExecuteAsOwner` is
///         the named builder of that `MetaTransaction` on lane 0. Guardian recovery adds a key after `RECOVERY_DELAY`
///         (CTR-ACC-03); the account never has zero keys. No owner or admin: the factory only initialises.
contract SmartKeyAccount is MetaTxBase, IERC1271 {
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
    address public guardian;
    bytes32 public pendingRecovery;   // keyId of the key the guardian wants to add
    uint256 public recoveryReadyAt;

    event KeyAdded(uint256 indexed index, KeyKind kind, bytes32 indexed keyId);
    event KeyRemoved(uint256 indexed index, bytes32 indexed keyId);
    event GuardianSet(address indexed guardian);
    event RecoveryInitiated(bytes32 indexed keyId, uint256 readyAt);
    event RecoveryCancelled(bytes32 indexed keyId);

    error NotFactory();
    error AlreadyInitialized();
    error NotSelf();
    error NotGuardian();
    error BadKey();
    error DuplicateKey();
    error NoSuchKey(uint256 index);
    error LastKey();
    error CallFailed(bytes reason);
    error NoRecovery();
    error RecoveryNotReady(uint256 readyAt);

    /// @dev Inside the one self-call of `mtxExecute` the sender is the signer; only the account itself passes.
    modifier onlySelf() {
        if (_msgSender() != address(this)) revert NotSelf();
        _;
    }

    /// @dev Runs once, on the implementation, deployed by the factory; locks the implementation.
    constructor(bytes32 chainUid_) MetaTxBase("SCaaS SmartKeyAccount", chainUid_) {
        FACTORY = msg.sender;
        _initialized = true;
    }

    /// @notice Factory only, in the same transaction as the clone (CTR-ACC-01): no front-run window.
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

    // ------------------------------------------------------------------ signed by the account (CTR-ACC-10)

    /// @notice Named builder (CTR-MTX-21): the `MetaTransaction{from: this, data, batch: 0, nonce, validUntil}`, no
    ///         relayer or fee binding, run through the base pipeline. Same digest and lane as `mtxExecute`.
    function mtxExecuteAsOwner(bytes calldata data, uint256 nonce, uint256 validUntil, bytes calldata signature)
        external nonReentrant returns (bytes memory)
    {
        MetaTxLib.MetaTransaction memory m;
        m.from = address(this);
        m.data = data;
        m.nonce = nonce;
        m.validUntil = validUntil;
        return _execute(m, signature);
    }

    function addKey(SubjectKey calldata key) external nonReentrant onlySelf returns (uint256) {
        return _addKey(key);
    }

    function removeKey(uint256 index) external nonReentrant onlySelf {
        _removeKey(index);
    }

    /// @notice Add the new key, then remove the old one, atomically.
    function rotateKey(uint256 index, SubjectKey calldata key) external nonReentrant onlySelf returns (uint256 added) {
        added = _addKey(key);
        _removeKey(index);
    }

    /// @notice A new guardian also cancels the old guardian's pending recovery.
    function setGuardian(address guardian_) external nonReentrant onlySelf {
        guardian = guardian_;
        _clearRecovery();
        emit GuardianSet(guardian_);
    }

    function cancelRecovery() external nonReentrant onlySelf {
        if (pendingRecovery == bytes32(0)) revert NoRecovery();
        _clearRecovery();
    }

    /// @notice The subject does what it wants with its own assets; tokens still apply their own rules (no EOA
    ///         approve). Runs under the guard, so the target cannot re-enter the account.
    function execute(address target, uint256 value, bytes calldata data)
        external nonReentrant onlySelf returns (bytes memory)
    {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
        return ret;
    }

    // ------------------------------------------------------------------ guardian (CTR-ACC-03)

    /// @notice Called again while pending: replaces the key and restarts the clock.
    function initiateRecovery(SubjectKey calldata key) external {
        if (msg.sender != guardian || guardian == address(0)) revert NotGuardian();
        _checkKey(key);
        bytes32 id = keyIdOf(key);
        pendingRecovery = id;
        recoveryReadyAt = block.timestamp + RECOVERY_DELAY;
        emit RecoveryInitiated(id, recoveryReadyAt);
    }

    /// @notice Anyone, after the delay. ADDS the key; no key is removed (the subject removes the lost key with the
    ///         new one).
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

    /// @notice Merkle leaf of one digest of a batch: `keccak256(keccak256(0x00 ‖ digest))`.
    function batchLeaf(bytes32 digest) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(bytes1(0x00), digest))));
    }

    /// @notice The allowlist (CTR-MTX-19): the base `cancelNonce`, then the six self-only functions; fee `NONE` only.
    function mtxSelectors()
        public pure override returns (bytes4[] memory s, uint8[] memory c, uint8[] memory a)
    {
        s = new bytes4[](7);
        c = new uint8[](7);
        a = new uint8[](7);
        s[0] = IMetaTx.cancelNonce.selector;
        s[1] = SmartKeyAccount.addKey.selector;
        s[2] = SmartKeyAccount.removeKey.selector;
        s[3] = SmartKeyAccount.rotateKey.selector;
        s[4] = SmartKeyAccount.setGuardian.selector;
        s[5] = SmartKeyAccount.cancelRecovery.selector;
        s[6] = SmartKeyAccount.execute.selector;
        for (uint256 i; i < 7; ++i) c[i] = FEE_CLASS_ABSOLUTE;
    }

    // ------------------------------------------------------------------ MetaTxBase hooks

    /// @dev Static lengths: a key is five words; `execute` has dynamic `data`.
    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == SmartKeyAccount.addKey.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 164);
        if (sel == SmartKeyAccount.removeKey.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == SmartKeyAccount.rotateKey.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 196);
        if (sel == SmartKeyAccount.setGuardian.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 36);
        if (sel == SmartKeyAccount.cancelRecovery.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 4);
        if (sel == SmartKeyAccount.execute.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 0);
        return super._mtxRule(sel);
    }

    /// @dev The account is the signer of its own key management (CTR-ACC-10).
    function _selfSender() internal pure override {}

    /// @dev `from == this`: one of the account's keys, through its own `isValidSignature` as a static self-call with
    ///      uncapped gas (`SigCheck` caps ERC-1271 at 50k; the Solidity P-256 verifier needs about 280k on a chain
    ///      without the P256VERIFY precompile); anyone else (only `cancelNonce` on their own lane runs for them): EOA or
    ///      ERC-1271 through `SigCheck`.
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view override {
        if (from != address(this)) return super._requireValidSignature(from, digest, sig);
        (bool ok, bytes memory ret) =
            address(this).staticcall(abi.encodeCall(IERC1271.isValidSignature, (digest, sig)));
        if (!ok || ret.length != 32 || bytes4(ret) != IERC1271.isValidSignature.selector) revert MetaTxBadSignature();
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

    /// @dev WebAuthn assertion (CTR-ACC-08): rpIdHash, flags UP and UV, clientDataJSON, then P-256 over
    ///      `sha256(authenticatorData ‖ sha256(clientDataJSON))`. `P256.verify` refuses s > n/2 (clients normalise).
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

    /// @dev The strict clientDataJSON grammar (`WebAuthnClientData.parse`) with the key's origin.
    function _clientDataOk(bytes memory cd, bytes32 challenge, bytes32 originHash) private pure returns (bool) {
        (bool ok, uint256 o, uint256 len) = WebAuthnClientData.parse(cd, challenge);
        return ok && WebAuthnClientData.hashSlice(cd, o, len) == originHash;
    }
}
