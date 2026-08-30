// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Tầng nền: mọi token trong hệ đều gasless được.
/// @notice Cây kế thừa (quyết định của user — "Zether là child của MetaTransaction"):
///
///     IERC20
///      └── IERC20MetaTx          <- ĐÂY. Tầng nền.
///           ├── IERC20Payment    <- token thanh toán công khai
///           └── IZetherToken     <- token bảo mật, kế thừa TOÀN BỘ meta-tx
///
/// Không phải hai nhánh song song. Hệ quả trực tiếp: một Zether token tự động có
/// meta-transaction, nên `transferConfidential` gọi được cả hai đường — EOA có
/// native gas gọi thẳng, hoặc bọc trong MetaTransaction qua relayer.
interface IERC20MetaTx is IERC20 {
    event MetaTransactionExecuted(
        address indexed from,
        address indexed relayer,
        uint256 indexed batch,
        uint256 nonce,
        bytes32 digest,
        bool success
    );

    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error MetaTxSelfCallForbidden();

    /// @notice Nonce kế tiếp của `(from, batch)`. Client đọc cái này để ký.
    /// @dev 2D: batch nào kẹt thì chỉ kẹt batch đó.
    function metaNonce(address from, uint256 batch) external view returns (uint256);

    /// @notice Digest EIP-712 mà `from` phải ký. Public để SDK và relayer kiểm
    ///         chéo được trước khi gửi — mesh cần validate-before-gossip.
    function metaTxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);

    /// @notice Thực thi một meta-transaction đã ký.
    /// @param m         intent
    /// @param signature chữ ký EIP-712 của `m.from`, TÁCH KHỎI struct
    /// @dev Thứ tự kiểm BẮT BUỘC, rẻ trước đắt, để spam bị chặn ở chi phí thấp nhất:
    ///      relayer (0 gas) -> expiry (0 gas) -> nonce (1 sload) -> chữ ký (~3k) ->
    ///      thu phí -> inner call.
    ///      Phí được thu TRƯỚC inner call. Bất biến: "phí đã trả ⟺ transaction không
    ///      revert" — inner call revert vẫn thu phí, vì relayer đã bỏ gas thật.
    function executeMetaTransaction(
        MetaTxLib.MetaTransaction calldata m,
        bytes calldata signature
    ) external payable returns (bool success, bytes memory returnData);

    /// @notice Huỷ một nonce chưa dùng mà không cần thực thi gì.
    /// @dev Người ký phải rút lại được một intent đã phát lên mesh. Không có hàm này
    ///      thì cách duy nhất là tự gửi một giao dịch rác cùng nonce.
    function cancelMetaNonce(uint256 batch) external;
}
