// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

/// @notice Ba chế độ phí. Mẫu số THỐNG NHẤT là ppm (1e6); `perMille` (1e3) đã bị
/// loại vì không biểu diễn được 0,05%.
enum FeeMode {
    NONE,    // feeAmount == 0 và feeRecipient == address(0)
    PERCENT, // feeAmount == amount * feePpm / 1e6
    FIXED    // feeAmount tuyệt đối theo đơn vị token
}

/// @title Tính và kiểm tra phí cho tầng MetaTransaction.
/// @dev Chỉ dùng cho tầng NGOÀI (ERC-20 công khai). Tầng TRONG (Zether) có ràng
///      buộc riêng và nghiêm ngặt hơn — xem `FeePolicy.requireConfidentialSafe`.
library FeePolicy {
    uint256 internal constant PPM_DENOMINATOR = 1_000_000;

    /// Trần cứng 1%. Không phải tham số quản trị: nó là bất biến bảo vệ người ký,
    /// vì người ký nhìn phí trong ví EIP-712 nhưng không tự tính lại được.
    uint256 internal constant MAX_FEE_PPM = 10_000;

    error FeeModeInvalid();
    error FeeExceedsCap(uint256 feeAmount, uint256 cap);
    error FeeRecipientRequired();
    error PercentFeeForbiddenOnConfidential();

    /// @notice Phí phải trả, theo mode.
    /// @dev PERCENT cũng chịu đúng cái trần 1% như FIXED — nếu không thì `feePpm`
    ///      tuỳ ý sẽ vượt mặt trần và biến FIXED thành nhánh duy nhất được bảo vệ.
    function compute(FeeMode mode, uint256 amount, uint256 feePpmOrFixed)
        internal
        pure
        returns (uint256 feeAmount)
    {
        if (mode == FeeMode.NONE) {
            return 0;
        }
        if (mode == FeeMode.PERCENT) {
            if (feePpmOrFixed > MAX_FEE_PPM) {
                revert FeeExceedsCap(feePpmOrFixed, MAX_FEE_PPM);
            }
            return (amount * feePpmOrFixed) / PPM_DENOMINATOR;
        }
        // FIXED
        uint256 cap = (amount * MAX_FEE_PPM) / PPM_DENOMINATOR;
        if (feePpmOrFixed > cap) {
            revert FeeExceedsCap(feePpmOrFixed, cap);
        }
        return feePpmOrFixed;
    }

    function validateRecipient(FeeMode mode, address feeRecipient) internal pure {
        if (mode == FeeMode.NONE) {
            // Không ép feeRecipient == address(0): người ký có thể để lại địa chỉ
            // cũ khi hạ phí về 0, và revert ở đó chỉ gây khó chịu, không tăng an toàn.
            return;
        }
        if (feeRecipient == address(0)) revert FeeRecipientRequired();
    }

    /// @notice Ràng buộc bảo mật cho MỌI thao tác chạm số dư bí mật.
    /// @dev `fee = v * p` với `fee` và `p` công khai ⇒ `v = fee / p` ⇒ số tiền bí
    ///      mật lộ hoàn toàn. Đây là lý do PERCENT bị cấm ở TẦNG CONTRACT chứ không
    ///      chỉ khuyến nghị. Áp cho cả tầng ngoài khi nó bọc một lệnh Zether: một
    ///      `amount = 0` công khai làm phí phần trăm ra 0 (vô nghĩa), còn tính theo
    ///      giá trị thật thì lại rò rỉ.
    ///
    ///      Bậc thang phí cũng bị cấm, nhưng contract không nhìn thấy được điều đó —
    ///      nó nằm ở governance đặt bảng giá: một hằng số cho mỗi cặp (token, chain),
    ///      không bao giờ là hàm của `v`.
    function requireConfidentialSafe(FeeMode mode) internal pure {
        if (mode == FeeMode.PERCENT) revert PercentFeeForbiddenOnConfidential();
    }
}
