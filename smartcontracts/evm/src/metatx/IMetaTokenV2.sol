// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title Named functions of every v2 tier (`MetaTokenBase`, metatx.md Interfaces; CTR-MTX-09, CTR-MTX-05).
interface IMetaTokenV2 is IERC20Payment {
    event ReceiverFeePaid(bytes32 indexed paymentDigest, address indexed payee, address indexed feeRecipient,
                          uint256 fee);

    error ReceiverFeeShape();
    error ReceiverFeeExpired(uint256 validUntil, uint256 nowTs);
    error ReceiverFeeAmount(uint256 fee, uint256 value);

    function mtxTransfer(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, bytes calldata signature
    ) external returns (bool);

    function mtxTransferWithFee(
        address from, address to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external returns (bool);

    function mtxExecuteWithFee(MetaTxLib.MetaTransaction calldata m, bytes calldata signature)
        external returns (bytes memory);

    function mtxPay(
        address from, address to, uint256 amount, bytes32 payId, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external returns (bool);

    function mtxPayReceiverFee(
        MetaTxLib.MetaTransfer calldata t, bytes calldata payerSig,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig
    ) external returns (bool);

    function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
        external view returns (bytes32);

    function payLane(bytes32 payId) external pure returns (uint256);
}
