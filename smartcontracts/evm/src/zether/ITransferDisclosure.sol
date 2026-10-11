// SPDX-License-Identifier: Apache-2.0
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
/// Chi phí lúc chuyển: token lưu bản ghi để mở on-chain — `R = salt ‖ B_1 ‖ … ‖ B_M` đầy đủ (định dạng một người nhận,
/// mode BUNDLE, 4 điểm mỗi leg), một slot hash cộng memo người gửi (commit-reveal, CTR-ZTH-50), hoặc không gì (mode
/// NONE: chỉ off-chain), CTR-ZTH-14/38.
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
        /// Auditor được chỉ định mở `C_aud` (biến thể shared-`s`). Sai khi `C_aud = O` (người gửi bỏ auditor, Z12).
        AUDITOR,
        /// Người GỬI mở MỘT leg mà không giao `s`: Chaum-Pedersen `log_G D_out == log_{Y_t}(C − [v]G)` (Z10).
        /// `s` mở mọi leg của transfer (Z3); opening này chỉ mở leg `index`.
        SENDER_CP
    }

    error UnknownEntry(bytes32 entryRef);
    error OpeningMalformed();
    /// @notice Mode HASH: `bundles` không khớp hash đã lưu.
    error BundlesMismatch(bytes32 entryRef);
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
    /// @param bundles  commit-reveal: `R = salt ‖ B_1 ‖ … ‖ B_M` (từ event `TransferBundles`, calldata, hoặc người gửi
    ///                 dựng lại từ memo), khớp hash đã lưu;
    ///                 bỏ qua khi bundle nằm trong storage. Mode NONE: không có gì để kiểm (`UnknownEntry`).
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
        bytes calldata opening,
        bytes calldata bundles
    ) external view returns (bool);

    /// @notice Ciphertext gốc của một giao dịch, để bên thứ ba verify ĐỘC LẬP.
    /// @dev Toà án không nên phải tin `verifyTransferAmount` của chính contract bị
    ///      tranh chấp. Hàm này xuất dữ liệu thô để một verifier ngoài chuỗi
    ///      (CLI độc lập, mã nguồn mở) kiểm lại từ đầu.
    function transferCiphertext(address token, bytes32 entryRef, uint256 index, bytes calldata bundles)
        external
        view
        returns (bytes memory encodedCiphertext, bytes memory encodedYTo);
}
