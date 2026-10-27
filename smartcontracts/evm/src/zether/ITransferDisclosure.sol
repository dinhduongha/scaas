// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

/// @title Selective disclosure: chứng minh "tôi đã gửi ĐÚNG số tiền này, trong ĐÚNG
///        giao dịch này" mà không công khai gì khác.
///
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Hiện thực: `ZetherDisclosure` — contract RIÊNG, không
///         state, một bản phục vụ mọi Zether token trên mọi đường cong (owner Z13); token chỉ xuất bundle thô
///         (`transferEntry`) và địa chỉ `disclosure()`. Định dạng `opening` và challenge Chaum-Pedersen:
///         `2026-10-03-zether-design.md` §12, spec multi-recipient §5.1.
///
///         Yêu cầu gốc của user: *"Kèm thêm thông tin để nếu cần, có thể chứng minh:
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
/// Chi phí lúc chuyển: token lưu bản ghi để mở on-chain — `R = salt ‖ B_1 ‖ … ‖ B_M` đầy đủ (định dạng một người nhận:
/// 4 điểm; mode BUNDLE: 5 điểm mỗi leg, `D_aud_j` từ review C0-1), hoặc `R` bằng SSTORE2 cộng memo người gửi (commit-reveal,
/// CTR-ZTH-50). Mọi mode đều giữ `R` trong state (review C0-3; mode NONE đã bị bỏ), CTR-ZTH-14/38.
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
        /// Auditor được chỉ định mở `C_aud`: DLEQ trên `D_aud_j = [t_j]G` của leg `j` (nhiều người nhận, `t_j` riêng mỗi leg,
        /// review C0-1), trên `D_out` ở định dạng một người nhận. Sai khi `C_aud = O` (người gửi bỏ auditor, Z12).
        AUDITOR,
        /// Người GỬI mở MỘT leg mà không giao `s`: Chaum-Pedersen `log_G D_out == log_{Y_t}(C − [v]G)` (Z10).
        /// `s` mở mọi leg của transfer (Z3); opening này chỉ mở leg `index`.
        SENDER_CP
    }

    error UnknownEntry(bytes32 entryRef);
    error OpeningMalformed();
    /// @notice Bản ghi token trả không phải định dạng `R` (độ dài không phải `16 + 4P` hay `16 + 5P·M`).
    error RecordMalformed(bytes32 entryRef);
    error BadRecipientIndex(uint256 index);

    /// @notice Kiểm một lời khai số tiền. **View — gọi FREE qua `eth_call`**, hoặc on-chain từ contract bất kỳ.
    /// @param token    Zether token giữ `entryRef`. Người gọi chọn token mình tin: một "token" giả trả gì cũng được.
    ///        Challenge ràng địa chỉ token (không phải contract này).
    /// @param entryRef BẮT BUỘC. Thiếu nó thì chỉ chứng minh được "có một giao dịch
    ///        trị giá X", không phải "giao dịch NÀY trị giá X".
    /// @param index    người nhận thứ mấy của giao dịch (transfer một người nhận: 0)
    /// @param amount   số tiền được tuyên bố, đơn vị che giấu
    /// @param kind     đường mở nào
    /// @param opening  `s` cho SENDER_S; `abi.encode(A1, A2, z)` (Chaum-Pedersen) cho RECEIVER_X, AUDITOR, SENDER_CP
    ///        Bản ghi `R` luôn đọc từ state của token (`transferEntry`), không nhận từ người gọi.
    ///
    /// @dev Phần lớn nhu cầu — kiểm toán, đối soát ERP, trả lời cơ quan thuế — chỉ
    ///      cần hàm này: miễn phí, không giới hạn số lần, KHÔNG để lại vết on-chain.
    ///      Đó là điểm thiết kế, không phải tối ưu: một lượt đối soát hàng tháng
    ///      không nên tự nó trở thành dữ liệu công khai.
    function verifyTransferAmount(
        address token,
        bytes32 entryRef,
        uint256 index,
        uint256 amount,
        OpeningKind kind,
        bytes calldata opening
    ) external view returns (bool);

    /// @notice Ciphertext gốc của một giao dịch, để bên thứ ba verify ĐỘC LẬP.
    /// @dev Toà án không nên phải tin `verifyTransferAmount` của chính contract bị
    ///      tranh chấp. Hàm này xuất dữ liệu thô để một verifier ngoài chuỗi
    ///      (CLI độc lập, mã nguồn mở) kiểm lại từ đầu.
    function transferCiphertext(address token, bytes32 entryRef, uint256 index)
        external
        view
        returns (bytes memory encodedCiphertext, bytes memory encodedYTo);
}
