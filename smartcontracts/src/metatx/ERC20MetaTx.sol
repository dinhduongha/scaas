// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC20MetaTx} from "./IERC20MetaTx.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeePolicy, FeeMode} from "../common/FeePolicy.sol";

/// @title Mixin meta-transaction cho mọi token trong hệ.
/// @notice Đây là bản cài đặt tham chiếu của thứ tự chín bước ở §04.6.1, và nó tồn
///         tại vì một lý do cụ thể: **đo gas**. `00-CANON.md` §C7 dẫn số phong bì
///         bằng phép tính tay quanh một `innerGasLimit` không còn tồn tại; số đúng
///         phải đo, và không đo được nếu không có contract để đo.
///
/// Không có `CALL` tới contract lạ ở bất kỳ đâu trong file này — đó là toàn bộ luận
/// điểm của §04.1. Thao tác nằm trong chính contract, nên bước 6 kiểm được đủ điều
/// kiện và sau bước 7 không gì fail được nữa.
abstract contract ERC20MetaTx is ERC20, EIP712, IERC20MetaTx {
    using MetaTxLib for MetaTxLib.MetaTransaction;

    /// @dev `(from, batch) -> nonce kế tiếp`. 2D: batch nào kẹt thì chỉ kẹt batch đó.
    mapping(address => mapping(uint256 => uint256)) private _metaNonce;

    /// @dev Guard theo CONTRACT, không theo hàm (§04.6.3). Transient storage: chain
    ///      9000 đã có Cancun/Prague sau khi sửa chainspec, Gnosis và Celo cũng vậy.
    /// keccak256("bamboo.metatx.reentrancy.v1") — hằng số phải viết thẳng số:
    /// inline assembly của solc 0.8 không nhận một constant tính bằng keccak256().
    bytes32 private constant _REENTRANCY_SLOT =
        0xfadfe27b5cbfdbb32eee3737cf0fe576eeec89aee56cef334a86b4e2c362b8b6;

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

    function metaTxDigest(MetaTxLib.MetaTransaction calldata m)
        external view returns (bytes32)
    {
        return _hashTypedDataV4(m.hashStruct());
    }

    function cancelMetaNonce(uint256 batch) external {
        unchecked { _metaNonce[msg.sender][batch] += 1; }
    }

    function executeMetaTransaction(
        MetaTxLib.MetaTransaction calldata m,
        bytes calldata signature
    ) external nonReentrant returns (bool) {
        // --- 1. relayer (0 gas) ---
        if (m.mode & MetaTxLib.MODE_RESTRICT_RELAYER != 0 && m.relayer != msg.sender) {
            revert MetaTxUnauthorizedRelayer(m.relayer, msg.sender);
        }
        // --- 2. validUntil (0 gas) ---
        if (block.timestamp > m.validUntil) {
            revert MetaTxExpired(m.validUntil, block.timestamp);
        }
        // --- 3. mode (0 gas) ---
        MetaTxLib.validateMode(m.mode);
        FeeMode feeMode = MetaTxLib.feeModeOf(m.mode);

        // --- 4. nonce (1 sload) ---
        uint256 expected = _metaNonce[m.from][m.batch];
        if (expected != m.nonce) revert MetaTxBadNonce(expected, m.nonce);

        // --- 5. chữ ký ---
        bytes32 digest = _hashTypedDataV4(m.hashStruct());
        _requireValidSignature(m.from, digest, signature);

        // --- 6. KIỂM ĐỦ. Sau bước này không gì được phép fail ---
        address feeRecipient = m.feeRecipient == address(0) ? msg.sender : m.feeRecipient;
        uint256 feeAmount = FeePolicy.compute(feeMode, m.value, m.fee);
        FeePolicy.validateRecipient(feeMode, feeRecipient);
        uint256 need = m.value + feeAmount;
        uint256 have = balanceOf(m.from);
        if (have < need) revert MetaTxInsufficientForFee(need, have);
        _checkOp(m);

        // --- 7. thu phí ---
        if (feeAmount != 0) _transfer(m.from, feeRecipient, feeAmount);

        // --- 8. thực thi ---
        _executeOp(m, feeAmount, feeRecipient);

        // --- 9. nonce++ và emit ---
        unchecked { _metaNonce[m.from][m.batch] = expected + 1; }
        emit MetaTransactionExecuted(
            m.from, msg.sender, m.batch, m.nonce, digest, feeRecipient, feeAmount
        );
        return true;
    }

    // ------------------------------------------------------------------ allowance (R26)

    /// @notice Spender phải là hợp đồng. Phishing kiểu "approve vô hạn cho một ví lạ" không
    ///         còn đường: không EOA nào giữ được allowance (SRS kiến trúc §3.2).
    function approve(address spender, uint256 value) public virtual override(ERC20, IERC20) returns (bool) {
        if (!_isContract(spender)) revert SpenderNotContract(spender);
        return super.approve(spender, value);
    }

    /// @notice Chỉ hợp đồng tiêu được allowance. Kiểm TRƯỚC allowance, nên một EOA nhận lỗi
    ///         này kể cả khi `value == 0`.
    function transferFrom(address from, address to, uint256 value)
        public virtual override(ERC20, IERC20) returns (bool)
    {
        if (!_isContract(msg.sender)) revert CallerNotContract(msg.sender);
        return super.transferFrom(from, to, value);
    }

    /// @dev Không phải hợp đồng nếu: code rỗng (EOA — hoặc hợp đồng ĐANG chạy constructor:
    ///      nó không được approve hay tiêu allowance từ constructor của chính mình), hoặc code
    ///      đúng là designator EIP-7702 `0xef0100‖address` (23 byte): khoá riêng của EOA vẫn ký
    ///      được mọi thứ, nên nó vẫn là EOA.
    function _isContract(address a) internal view returns (bool) {
        uint256 len = a.code.length;
        if (len == 0) return false;
        if (len == 23) {
            bytes memory c = a.code;
            if (c[0] == 0xef && c[1] == 0x01 && c[2] == 0x00) return false;
        }
        return true;
    }

    /// @dev Hai đường: EOA (65 byte, low-s) và ERC-1271. Phân biệt bằng `_isContract(from)`
    ///      chứ không bằng độ dài chữ ký — một smart account hoàn toàn có thể trả về một
    ///      blob 65 byte, và đoán theo độ dài thì nó bị verify nhầm bằng `ecrecover`. EOA uỷ
    ///      quyền EIP-7702 đi đường ECDSA: khoá của nó vẫn ký được (R26, review W3).
    /// @dev `virtual`: một mạng có cách xác thực tài khoản riêng (Hedera HIP-632 cho khoá ED25519 —
    ///      R63) ghi đè ở implementation của mạng đó; thứ tự 9 bước không đổi.
    function _requireValidSignature(address from, bytes32 digest, bytes calldata sig)
        internal view virtual
    {
        if (!_isContract(from)) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, sig);
            if (err != ECDSA.RecoverError.NoError || rec != from) revert MetaTxBadSignature();
        } else {
            (bool ok, bytes memory ret) = from.staticcall{gas: 50_000}(
                abi.encodeCall(IERC1271.isValidSignature, (digest, sig))
            );
            if (!ok || ret.length != 32 ||
                abi.decode(ret, (bytes4)) != IERC1271.isValidSignature.selector) {
                revert MetaTxBadSignature();
            }
        }
    }

    /// @dev Bước 6 riêng của thao tác. Mặc định: `data` rỗng ⇒ chuyển token thường, và
    ///      số dư đã được kiểm ở trên nên không còn gì để kiểm.
    function _checkOp(MetaTxLib.MetaTransaction calldata m) internal view virtual {
        if (m.data.length != 0) revert MetaTxUnknownMode(m.mode);
    }

    /// @dev Bước 8. Không được fail — mọi điều kiện đã kiểm ở `_checkOp`. Nhận phí đã
    ///      thu để op nào cần báo phí trong event (`pay`) không phải tính lại.
    function _executeOp(MetaTxLib.MetaTransaction calldata m, uint256, address) internal virtual {
        _transfer(m.from, m.to, m.value);
    }
}
