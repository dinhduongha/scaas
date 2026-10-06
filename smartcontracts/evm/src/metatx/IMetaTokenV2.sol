// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Hàm meta-tx có tên (TW2 §7, R138–R140). Chỉ là đường vào mỏng: mỗi hàm DỰNG một
///        `MetaTransaction` rồi chạy đúng pipeline chín bước của `executeMetaTransaction`.
/// @notice Cùng struct, cùng typehash, cùng digest: một chữ ký chạy được trên cả hai đường và một lane chỉ
///         tiêu một lần. Mỗi hàm chỉ thêm một kiểm tra hình dạng `mode` (`MtxModeShape`), không gì khác — nên
///         một hàm có tên không bao giờ nhận một intent mà đường chung từ chối.
///
///         Client PHẢI ký `fee = 0` và `feeRecipient = 0` cho mọi intent không phí: `fee` không bị
///         canonical-zero hoá dưới fee `NONE`, và `mtxTransfer`/`mtxUnwrap` đặt `fee = 0` (review L5).
interface IMetaTokenV2 is IERC20Payment {
    /// @notice ≡ `executeMetaTransaction({from,to,amount,"",batch,nonce,validUntil,mode,relayer,0,0})`.
    ///         `mode`: chỉ `MODE_RESTRICT_RELAYER` được bật (fee `NONE`).
    function mtxTransfer(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, bytes calldata signature
    ) external returns (bool);

    /// @notice ≡ `executeMetaTransaction({from,to,amount,"",batch,nonce,validUntil,mode,relayer,fee,feeRecipient})`.
    ///         `mode`: fee `PERCENT` hoặc `FIXED`, `MODE_RESTRICT_FEE_RECIPIENT` bật, `feeRecipient ≠ 0` — người
    ///         gửi tự nêu ai được trả phí. Phí không bao giờ tới người nhận (R132).
    function mtxTransferWithFee(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external returns (bool);

    /// @notice ≡ `executeMetaTransaction(m, signature)` cho mọi op, thêm điều kiện fee nibble ≠ `NONE`.
    function executeMetaTransactionWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external returns (bool);

    /// @notice ≡ `executeMetaTransaction({from,to,amount,pay(payId),payLane(payId),0,validUntil,mode,relayer,fee,
    ///         feeRecipient})`. Lane suy ra ON CHAIN: một `(payer, payId)` trả tối đa một lần QUA `mtxPay` (R139).
    function mtxPay(
        address from, address to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external returns (bool);

    /// @notice ≡ `executeMetaTransaction({from,recipient,wrapped,unwrap(underlying,recipient,minOut),batch,nonce,
    ///         validUntil,mode,relayer,0,0})` (R148). Tầng 1 revert `MetaTxUnknownOp`.
    function mtxUnwrap(
        address from, address underlying, uint256 wrapped, address recipient, uint256 minOut,
        uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer, bytes calldata signature
    ) external returns (bool);

    /// @notice Nhiều intent trong một tx ngoài, NGUYÊN TỬ: một item revert thì cả lô revert (R140).
    function mtxBatch(MetaTxLib.MetaTransaction[] calldata ms, bytes[] calldata signatures) external returns (bool);

    /// @notice Lane mà client phải dùng cho `payId` trên token này:
    ///         `uint256(keccak256(abi.encodePacked("scaas.pay.lane", payId)))` — cùng giá trị client v1 tự suy
    ///         ra off-chain (R9), nên lane của một khoản thanh toán không phụ thuộc version token.
    function payLane(bytes32 payId) external pure returns (uint256);
}

/// @title `mtxUnwrapWithFee` (R148) — tách khỏi `IMetaTokenV2` vì token cài nó trong `fallback`.
/// @notice 13 tham số vượt sức chứa của decoder ABI solc không via-IR ("dataEnd too deep"), nên `MetaTokenBase`
///         tự giải mã calldata. Selector, ABI và ngữ nghĩa đúng như khai báo dưới đây; client gọi qua interface này.
///         Bộ mã hoá ABI của một caller Solidity không via-IR cũng không chứa nổi 13 giá trị: dựng calldata bằng tay.
interface IMetaTokenV2UnwrapWithFee {
    /// @notice Như `mtxUnwrap`, phí (đơn vị wrapped) từ tham số; hình dạng `mode` như `mtxTransferWithFee`.
    function mtxUnwrapWithFee(
        address from, address underlying, uint256 wrapped, address recipient, uint256 minOut,
        uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer,
        uint256 fee, address feeRecipient, bytes calldata signature
    ) external returns (bool);
}
