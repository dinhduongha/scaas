// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Nền meta-tx v2 (TW2 §3, R131). Cùng struct, typehash, `canon` và thứ tự chín bước với
///        `ERC20MetaTx` v1 — file v1 đóng băng, đây là file mới.
/// @notice Khác v1:
///         - pipeline chạy trên struct trong MEMORY (`_execute`), để hàm có tên dựng được một struct (§7.1);
///         - bước 6 thêm R132: phí không bao giờ tới người nhận của transfer/`pay`;
///         - nonce ghi ở bước 7 cùng phí, nên không lời gọi ra ngoài nào (unwrap op, R148) chạy khi nonce còn
///           chưa tiêu; event vẫn ở bước 9;
///         - `cancelMetaNonce` phát `MetaNonceCancelled`;
///         - slot guard `scaas.metatx.reentrancy.v2`.
abstract contract MetaTxCore is ERC20, EIP712, IERC20MetaTx {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    /// @dev `(from, batch) -> nonce kế tiếp`. 2D: batch nào kẹt thì chỉ kẹt batch đó. Slot 7 (TW2 §10.1).
    mapping(address => mapping(uint256 => uint256)) private _metaNonce;

    /// @dev Guard theo CONTRACT (transient): phủ meta-tx, `mtxBatch`, wrap, unwrap, `addReserve`.
    ///      keccak256("scaas.metatx.reentrancy.v2") — viết thẳng số: assembly không nhận constant keccak256().
    bytes32 private constant _REENTRANCY_SLOT =
        0xebf67dd58a1980d104bb27934008f54c575cc277a284209434090c31d27a7106;

    event MetaNonceCancelled(address indexed from, uint256 indexed batch, uint256 newNonce);

    /// @notice R132: phí khác 0 mà người nhận phí (đã resolve) chính là người được trả.
    error FeeRecipientIsPayee();

    modifier nonReentrant() {
        assembly ("memory-safe") {
            if tload(_REENTRANCY_SLOT) { revert(0, 0) }
            tstore(_REENTRANCY_SLOT, 1)
        }
        _;
        assembly ("memory-safe") { tstore(_REENTRANCY_SLOT, 0) }
    }

    function metaNonce(address from, uint256 batch) public view returns (uint256) {
        return _metaNonce[from][batch];
    }

    function supportedModes() external pure returns (uint32) {
        return MetaTxLib.MODE_KNOWN_MASK;
    }

    function metaTxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32) {
        return _hashTypedDataV4(m.hashStruct());
    }

    function cancelMetaNonce(uint256 batch) external {
        uint256 n;
        unchecked { n = ++_metaNonce[msg.sender][batch]; }
        emit MetaNonceCancelled(msg.sender, batch, n);
    }

    function executeMetaTransaction(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external nonReentrant returns (bool)
    {
        _execute(m, signature);
        return true;
    }

    /// @dev Chín bước (TW2 §3.2). Mọi đường vào (generic, có tên, batch) đi qua đây và chỉ qua đây.
    function _execute(MetaTxLib.MetaTransaction memory m, bytes calldata signature) internal {
        // --- 1. relayer ---
        if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 && m.relayer != msg.sender) {
            revert MetaTxUnauthorizedRelayer(m.relayer, msg.sender);
        }
        // --- 2. validUntil ---
        if (block.timestamp > m.validUntil) revert MetaTxExpired(m.validUntil, block.timestamp);
        // --- 3. mode ---
        MetaTxLib.validateMode(m.mode);
        FeeMode feeMode = MetaTxLib.feeModeOf(m.mode);
        // --- 4. nonce ---
        uint256 expected = _metaNonce[m.from][m.batch];
        if (expected != m.nonce) revert MetaTxBadNonce(expected, m.nonce);
        // --- 5. chữ ký ---
        bytes32 digest = _hashTypedDataV4(m.hashStruct());
        _requireValidSignature(m.from, digest, signature);
        // --- 6. KIỂM ĐỦ. Sau bước này chỉ chuyển underlying của unwrap op (R148) được phép fail ---
        address feeRecipient = m.feeRecipient == address(0) ? msg.sender : m.feeRecipient;
        uint256 feeAmount = FeePolicy.compute(feeMode, m.value, m.fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        if (feeAmount != 0 && feeRecipient == m.to && _hasPayee(m)) revert FeeRecipientIsPayee();
        uint256 need = m.value + feeAmount;
        uint256 have = balanceOf(m.from);
        if (have < need) revert MetaTxInsufficientForFee(need, have);
        _checkOp(m);
        // --- 7. thu phí, tiêu nonce ---
        if (feeAmount != 0) _transfer(m.from, feeRecipient, feeAmount);
        unchecked { _metaNonce[m.from][m.batch] = expected + 1; }
        // --- 8. thực thi ---
        _executeOp(m, feeAmount, feeRecipient);
        // --- 9. emit ---
        emit MetaTransactionExecuted(m.from, msg.sender, m.batch, m.nonce, digest, feeRecipient, feeAmount);
    }

    // ------------------------------------------------------------------ allowance (R26)

    /// @notice Spender phải là hợp đồng (R26): không EOA nào giữ được allowance.
    function approve(address spender, uint256 value) public virtual override(ERC20, IERC20) returns (bool) {
        if (!_isContract(spender)) revert SpenderNotContract(spender);
        return super.approve(spender, value);
    }

    /// @notice Chỉ hợp đồng tiêu được allowance; kiểm TRƯỚC allowance.
    function transferFrom(address from, address to, uint256 value)
        public virtual override(ERC20, IERC20) returns (bool)
    {
        if (!_isContract(msg.sender)) revert CallerNotContract(msg.sender);
        return super.transferFrom(from, to, value);
    }

    /// @dev Như v1: code rỗng (EOA, hoặc hợp đồng đang chạy constructor) hay designator EIP-7702
    ///      `0xef0100‖address` (23 byte) đều không phải hợp đồng.
    function _isContract(address a) internal view returns (bool) {
        uint256 len = a.code.length;
        if (len == 0) return false;
        if (len == 23) {
            bytes memory c = a.code;
            if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false;
        }
        return true;
    }

    /// @dev EOA (65 byte, low-s) hoặc ERC-1271, phân biệt bằng `_isContract(from)` (như v1). `virtual`: Hedera
    ///      thêm HIP-632 (R63, R144).
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig) internal view virtual {
        if (!_isContract(from)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            if (err != ECDSA.RecoverError.NoError || rec != from) revert MetaTxBadSignature();
        } else {
            (bool ok, bytes memory ret) = from.staticcall{gas: _erc1271Gas(from)}(
                abi.encodeCall(IERC1271.isValidSignature, (digest, sig))
            );
            if (!ok || ret.length != 32 || abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector) {
                revert MetaTxBadSignature();
            }
        }
    }

    /// @dev 50k cho mọi ví hợp đồng; implementation nào biết một loại ví cần hơn thì ghi đè.
    function _erc1271Gas(address) internal view virtual returns (uint256) {
        return 50_000;
    }

    /// @dev R132: op này có người được trả là `m.to` không. Mặc định: chỉ transfer (`data` rỗng).
    function _hasPayee(MetaTxLib.MetaTransaction memory m) internal pure virtual returns (bool) {
        return m.data.length == 0;
    }

    /// @dev Bước 6 riêng của op. Mặc định: chỉ transfer.
    function _checkOp(MetaTxLib.MetaTransaction memory m) internal view virtual {
        if (m.data.length != 0) revert MetaTxUnknownMode(m.mode);
    }

    /// @dev Bước 8. Không được fail, trừ chuyển underlying của unwrap op (R148), vốn revert cả tx.
    function _executeOp(MetaTxLib.MetaTransaction memory m, uint256, address) internal virtual {
        _transfer(m.from, m.to, m.value);
    }
}
