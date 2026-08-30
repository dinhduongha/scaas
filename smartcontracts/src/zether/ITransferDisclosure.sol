// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title Selective disclosure: chứng minh "tôi đã gửi ĐÚNG số tiền này, trong ĐÚNG
///        giao dịch này" mà không công khai gì khác.
///
/// @notice Yêu cầu gốc của user: *"Kèm thêm thông tin để nếu cần, có thể chứng minh:
///         Tôi đã gửi đúng số tiền amount, và đây là bằng chứng."*
///
/// **Không dùng `hash(amount ‖ random)`.** Nó là một cam kết TÁCH RỜI khỏi giao dịch:
/// nó chứng minh "tồn tại một cam kết vào X", không chứng minh "GIAO DỊCH NÀY trị giá
/// X". Người gửi có thể phát nhiều hash và chọn cái có lợi lúc tranh chấp. Nó cũng tốn
/// 32 byte on-chain mỗi giao dịch, mãi mãi.
///
/// Cách đúng: **mở chính ciphertext**. Nó vốn đã là một cam kết Pedersen-like vào `v`:
///
///     C_transfer = g^v · y_to^s
///     D_transfer = g^s
///
/// nên mở nó là chứng minh số tiền, và nó ràng buộc TUYỆT ĐỐI vào đúng giao dịch đó.
/// **Chi phí thêm lúc chuyển: bằng không.** Không thêm trường, không thêm gas.
interface ITransferDisclosure {
    /// Ba đường mở, ba chủ thể khác nhau. Giữ cả ba — mỗi cái giải một tình huống
    /// tranh chấp mà hai cái kia không giải được.
    enum OpeningKind {
        /// Người GỬI mở, biết `s`. Verifier kiểm `C · g^{-v} == y_to^s`.
        /// Rẻ nhất: hai scalar mult, một so sánh, không ZK.
        SENDER_S,
        /// Người NHẬN mở, biết `x_to`. Kiểm `C · g^{-v} == D^{x_to}` kèm
        /// Chaum-Pedersen chứng minh đã dùng đúng `x_to` ứng với `y_to`.
        /// Quan trọng vì nó cho người nhận chứng minh mà KHÔNG CẦN người gửi hợp tác —
        /// tình huống tranh chấp thực tế thường đúng là vậy.
        RECEIVER_X,
        /// Auditor được chỉ định mở `C_aud` (biến thể shared-`s`).
        AUDITOR
    }

    event AmountAttested(
        bytes32 indexed entryRef,
        uint256 amount,
        OpeningKind kind,
        address indexed attestedBy,
        uint256 timestamp
    );

    error UnknownEntry(bytes32 entryRef);
    error OpeningMalformed();

    /// @notice Kiểm một lời khai số tiền. **View — gọi FREE qua `eth_call`.**
    /// @param entryRef BẮT BUỘC. Thiếu nó thì chỉ chứng minh được "có một giao dịch
    ///        trị giá X", không phải "giao dịch NÀY trị giá X".
    /// @param amount   số tiền được tuyên bố, đơn vị che giấu
    /// @param kind     đường mở nào
    /// @param opening  `s` cho SENDER_S; `(proof Chaum-Pedersen)` cho RECEIVER_X;
    ///                 khoá/proof auditor cho AUDITOR
    ///
    /// @dev Phần lớn nhu cầu — kiểm toán, đối soát ERP, trả lời cơ quan thuế — chỉ
    ///      cần hàm này: miễn phí, không giới hạn số lần, KHÔNG để lại vết on-chain.
    ///      Đó là điểm thiết kế, không phải tối ưu: một lượt đối soát hàng tháng
    ///      không nên tự nó trở thành dữ liệu công khai.
    function verifyTransferAmount(
        bytes32 entryRef,
        uint256 amount,
        OpeningKind kind,
        bytes calldata opening
    ) external view returns (bool);

    /// @notice Ghi một attestation BẤT BIẾN, có dấu thời gian on-chain. Tốn gas.
    /// @dev KHÔNG bắt buộc, và không phải đường mặc định. Chỉ gọi khi cần bằng chứng
    ///      có dấu thời gian không chối được — nộp toà, hoặc chốt một tranh chấp.
    ///      Tách khỏi `verifyTransferAmount` vì gộp lại sẽ biến mọi lần kiểm tra
    ///      thường lệ thành một giao dịch đổi trạng thái.
    function attestTransferAmount(
        bytes32 entryRef,
        uint256 amount,
        OpeningKind kind,
        bytes calldata opening
    ) external returns (bool);

    /// @notice Ciphertext gốc của một giao dịch, để bên thứ ba verify ĐỘC LẬP.
    /// @dev Toà án không nên phải tin `verifyTransferAmount` của chính contract bị
    ///      tranh chấp. Hàm này xuất dữ liệu thô để một verifier ngoài chuỗi
    ///      (CLI độc lập, mã nguồn mở) kiểm lại từ đầu.
    function transferCiphertext(bytes32 entryRef)
        external
        view
        returns (bytes memory encodedCiphertext, bytes memory encodedYTo);
}
