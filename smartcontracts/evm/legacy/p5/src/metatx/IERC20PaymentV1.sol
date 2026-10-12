// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {IERC20MetaTxV1} from "./IERC20MetaTxV1.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title Token thanh toán CÔNG KHAI. Số dư nhìn thấy được, cả ba mode phí đều dùng được.
interface IERC20PaymentV1 is IERC20MetaTxV1 {
    event PaymentSettled(
        address indexed from,
        address indexed to,
        uint256 amount,
        uint256 feeAmount,
        address feeRecipient,
        bytes32 indexed entryRef
    );

    /// @notice Chuyển kèm phí, một giao dịch.
    /// @param entryRef khoá đối soát của ERP. Đây là thứ nối on-chain với
    ///        `account.move` bên Odoo; thiếu nó thì đối soát phải đoán theo số tiền.
    /// @dev `amount` chuyển NGUYÊN VẸN cho `to`; phí thu THÊM từ `from`, không trừ
    ///      vào `amount`. Trừ vào amount thì người nhận nhận thiếu so với hoá đơn và
    ///      mọi đối soát ERP lệch.
    function payWithFee(
        address to,
        uint256 amount,
        FeeMode feeMode,
        uint256 fee,
        address feeRecipient,
        bytes32 entryRef
    ) external returns (bool);
}
