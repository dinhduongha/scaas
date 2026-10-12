// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Tầng nền: mọi token trong hệ đều gasless được.
/// @notice Cây kế thừa (quyết định của user — "Zether là child của MetaTransaction"):
///
///     IERC20
///      └── IERC20MetaTxV1          <- ĐÂY. Tầng nền.
///           ├── IERC20PaymentV1    <- token thanh toán công khai
///           └── IZetherToken     <- token bảo mật, kế thừa TOÀN BỘ meta-tx
///
/// Không phải hai nhánh song song. Hệ quả trực tiếp: một Zether token tự động có
/// meta-transaction, nên `transferConfidential` gọi được cả hai đường — EOA có
/// native gas gọi thẳng, hoặc bọc trong MetaTransaction qua relayer.
interface IERC20MetaTxV1 is IERC20 {
    /// @dev `relayer` và `feeRecipient` phát ra đây là giá trị ĐÃ RESOLVE tại runtime
    ///      (`msg.sender` và địa chỉ thực nhận phí), KHÔNG phải `m.relayer`/`m.feeRecipient`
    ///      thô — trong MODE_OPEN hai ô đó là rác do relayer điền.
    event MetaTransactionExecuted(
        address indexed from,
        address indexed relayer,
        uint256 indexed batch,
        uint256 nonce,
        bytes32 digest,
        address feeRecipient,
        uint256 fee
    );

    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error MetaTxUnknownMode(uint32 mode);
    error MetaTxInsufficientForFee(uint256 needed, uint256 available);
    /// @notice R26: allowance chỉ giữa hợp đồng. `approve` cho một spender không phải hợp
    ///         đồng (EOA, EOA uỷ quyền EIP-7702, hợp đồng chưa deploy xong) bị từ chối.
    error SpenderNotContract(address spender);
    /// @notice R26: chỉ hợp đồng gọi được `transferFrom`.
    error CallerNotContract(address caller);

    /// @notice Nonce kế tiếp của `(from, batch)`. Client đọc cái này để ký.
    /// @dev 2D: batch nào kẹt thì chỉ kẹt batch đó.
    function metaNonce(address from, uint256 batch) external view returns (uint256);

    /// @notice Digest EIP-712 mà `from` phải ký. Public để SDK và relayer kiểm
    ///         chéo được trước khi gửi — mesh cần validate-before-gossip.
    function metaTxDigest(MetaTxLib.LegacyMetaTransaction calldata m) external view returns (bytes32);

    /// @notice Thực thi một meta-transaction đã ký.
    /// @param m         intent
    /// @param signature chữ ký EIP-712 của `m.from`, TÁCH KHỎI struct
    /// @dev Thứ tự BẮT BUỘC, rẻ trước đắt, để spam bị chặn ở chi phí thấp nhất:
    ///
    ///        1. relayer      (0 gas)   — wildcard hoặc khớp msg.sender
    ///        2. validUntil   (0 gas)
    ///        3. mode hợp lệ  (0 gas)   — `mode & ~MODE_KNOWN_MASK == 0`
    ///        4. nonce        (1 sload)
    ///        5. chữ ký       (~3k)   — trên digest đã canonical-zero hoá (MetaTxLib.canon)
    ///        6. KIỂM TRA ĐỦ điều kiện (số dư, đã đăng ký, proof hợp lệ...) —
    ///           mọi thứ có thể fail đều fail ở đây
    ///        7. thu phí
    ///        8. thực thi thao tác
    ///
    ///      Bước 6 đứng trước bước 7 là điều một forwarder generic không làm được, vì
    ///      nó không biết lời gọi ra ngoài sẽ fail vì gì. Ở đây thao tác nằm trong
    ///      chính contract này nên nó kiểm hết được, và sau bước 7 không thể fail.
    ///
    ///      Bất biến: **phí đã thu ⟺ thao tác đã xảy ra.** Không swallow mode, không
    ///      `MODE_REQUIRE_SUCCESS`, không try/catch. Op fail ⇒ toàn bộ tx revert ⇒
    ///      nonce không tiêu, phí không thu, relayer mất gas. Relayer tự bảo vệ bằng
    ///      simulation gate; kẻ cố tình làm fail bị chấm `origin_grief_score` (§05.5).
    ///
    ///      KHÔNG `payable`: token này không nhận native coin. Trả gas là việc của
    ///      relayer ở tầng vỏ tx.
    function executeMetaTransaction(
        MetaTxLib.LegacyMetaTransaction calldata m,
        bytes calldata signature
    ) external returns (bool success);

    /// @notice Bitmask các `mode` mà token này hiểu.
    /// @dev Node mesh gọi một lần lúc onboard một contract để dựng bảng năng lực
    ///      §22.4, thay vì đoán từ ABI.
    function supportedModes() external view returns (uint32);

    /// @notice Huỷ một nonce chưa dùng mà không cần thực thi gì.
    /// @dev Người ký phải rút lại được một intent đã phát lên mesh. Không có hàm này
    ///      thì cách duy nhất là tự gửi một giao dịch rác cùng nonce.
    function cancelMetaNonce(uint256 batch) external;
}
