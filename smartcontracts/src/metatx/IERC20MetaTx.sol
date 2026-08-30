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
    /// @dev `success` biến mất so với bản trước: sau §24 một meta-tx đã lên chuỗi thì
    ///      thao tác **đã xảy ra**, không có nhánh "thành công một nửa" để mà báo.
    ///      `op` được index để indexer lọc theo loại thao tác không cần decode args.
    event MetaTransactionExecuted(
        address indexed from,
        address indexed relayer,
        uint256 indexed batch,
        uint256 nonce,
        uint8   op,
        bytes32 digest
    );

    error MetaTxExpired(uint256 validUntil, uint256 nowTs);
    error MetaTxBadNonce(uint256 expected, uint256 got);
    error MetaTxBadSignature();
    error MetaTxUnauthorizedRelayer(address allowed, address caller);
    error MetaTxUnknownOp(uint8 op);
    error MetaTxBadArgs(uint8 op);
    error MetaTxInsufficientForFee(uint256 needed, uint256 available);

    /// @notice Nonce kế tiếp của `(from, batch)`. Client đọc cái này để ký.
    /// @dev 2D: batch nào kẹt thì chỉ kẹt batch đó.
    function metaNonce(address from, uint256 batch) external view returns (uint256);

    /// @notice Digest EIP-712 mà `from` phải ký. Public để SDK và relayer kiểm
    ///         chéo được trước khi gửi — mesh cần validate-before-gossip.
    function metaTxDigest(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);

    /// @notice Thực thi một meta-transaction đã ký.
    /// @param m         intent — `m.op` là thao tác của CHÍNH token này (§24)
    /// @param signature chữ ký EIP-712 của `m.from`, TÁCH KHỎI struct
    /// @dev Thứ tự BẮT BUỘC, rẻ trước đắt, để spam bị chặn ở chi phí thấp nhất:
    ///
    ///        1. relayer      (0 gas)   — wildcard hoặc khớp msg.sender
    ///        2. validUntil   (0 gas)
    ///        3. op hợp lệ    (0 gas)   — không nằm trong bảng thì revert ngay
    ///        4. nonce        (1 sload)
    ///        5. chữ ký       (~3k)
    ///        6. decode args, KIỂM TRA ĐỦ điều kiện của op (số dư, đã đăng ký,
    ///           proof hợp lệ...) — mọi thứ có thể fail đều fail ở đây
    ///        7. thu phí
    ///        8. thực thi op bằng INTERNAL call
    ///
    ///      Bước 6 đứng trước bước 7 là điều generic forwarder không làm được, vì nó
    ///      không biết inner call sẽ fail vì gì. Ở đây op có kiểu nên contract kiểm
    ///      hết được, và sau bước 7 thao tác **không thể** fail.
    ///
    ///      Bất biến: **phí đã thu ⟺ thao tác đã xảy ra.** Không swallow mode, không
    ///      `MODE_REQUIRE_SUCCESS`, không try/catch. Op fail ⇒ toàn bộ tx revert ⇒
    ///      nonce không tiêu, phí không thu, relayer mất gas. Relayer tự bảo vệ bằng
    ///      simulation gate; kẻ cố tình làm fail bị chấm `origin_grief_score` (§05.5).
    ///
    ///      KHÔNG `payable`: token này không nhận native coin. Trả gas là việc của
    ///      relayer ở tầng vỏ tx.
    function executeMetaTransaction(
        MetaTxLib.MetaTransaction calldata m,
        bytes calldata signature
    ) external returns (bool success);

    /// @notice `op` này có được token này hỗ trợ không.
    /// @dev Node mesh gọi hàm này một lần lúc onboard một contract để dựng bảng năng
    ///      lực §22.4, thay vì đoán từ ABI. Rẻ hơn và không sai được.
    function supportsMetaOp(uint8 op) external view returns (bool);

    /// @notice Huỷ một nonce chưa dùng mà không cần thực thi gì.
    /// @dev Người ký phải rút lại được một intent đã phát lên mesh. Không có hàm này
    ///      thì cách duy nhất là tự gửi một giao dịch rác cùng nonce.
    function cancelMetaNonce(uint256 batch) external;
}
