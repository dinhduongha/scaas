// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeeMode} from "../common/FeePolicy.sol";

/// @title Named functions of every v2 tier (`MetaTokenBase`, metatx.md Interfaces; CTR-MTX-09, CTR-MTX-05), and those of
///        the UA ledger (accounts.md CTR-UA-26: each builds its `UAMetaTransfer` / `UAMetaTransaction`).
interface IMetaTokenV2 is IERC20Payment {
    event ReceiverFeePaid(bytes32 indexed paymentDigest, address indexed payee, address indexed feeRecipient,
                          uint256 fee);
    /// @notice `uaPayReceiverFee` (CTR-MTX-05 on ids): the payee is an id.
    event UAReceiverFeePaid(bytes32 indexed paymentDigest, bytes32 indexed payee, address indexed feeRecipient,
                            uint256 fee);

    /// @notice `mtxPayMeta` / `uaPayMeta` (CTR-MTX-26), before `PaymentSettled` / `UAPaymentSettled`; `meta` is never
    ///         parsed.
    event PaymentMeta(bytes32 indexed payId, bytes meta);

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

    /// @notice CTR-MTX-26: `keccak256(abi.encodePacked("scaas.pay.meta", salt, keccak256(meta)))`.
    function metaPayId(bytes32 salt, bytes calldata meta) external pure returns (bytes32);

    /// @notice `mtxPay` with `payId = metaPayId(salt, meta)` (CTR-MTX-26): the same digest, lane and nonce.
    function mtxPayMeta(
        address from, address to, uint256 amount, bytes32 salt, bytes calldata meta, uint256 validUntil,
        uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata signature
    ) external returns (bool);

    function mtxPayReceiverFee(
        MetaTxLib.MetaTransfer calldata t, bytes calldata payerSig,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeSig
    ) external returns (bool);

    function receiverFeeDigest(bytes32 paymentDigest, uint256 fee, address feeRecipient, uint256 validUntil)
        external view returns (bytes32);

    /// @notice Receiver-pays on the UA path: payer and payee are ids; a derived payee co-signs under `receiver-fee`.
    function uaPayReceiverFee(
        MetaTxLib.UAMetaTransfer calldata t, bytes calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, bytes calldata payeeAuth
    ) external returns (bool);

    function payLane(bytes32 payId) external pure returns (uint256);

    /// @notice `payWithFee` to the registered SIGNING UA `to` (accounts.md CTR-UA-28); emits `UAPaymentSettled`.
    function payWithFeeToUA(bytes32 to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient,
                            bytes32 entryRef) external returns (bool);

    function uaTransfer(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
                        uint32 mode, address relayer, bytes calldata auth) external returns (bool);
    function uaTransferWithFee(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce,
                               uint256 validUntil, uint32 mode, address relayer, uint256 fee, address feeRecipient,
                               bytes calldata auth) external returns (bool);
    function uaPay(bytes32 from, bytes32 to, uint256 amount, bytes32 payId, uint256 validUntil, uint32 mode,
                   address relayer, uint256 fee, address feeRecipient, bytes calldata auth) external returns (bool);
    /// @notice `uaPay` with `payId = metaPayId(salt, meta)` (CTR-MTX-26).
    function uaPayMeta(bytes32 from, bytes32 to, uint256 amount, bytes32 salt, bytes calldata meta, uint256 validUntil,
                       uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes calldata auth)
        external returns (bool);
    function uaUnwrap(bytes32 from, address underlying, uint256 wrapped, address recipient, uint256 minOut,
                      uint256 batch, uint256 nonce, uint256 validUntil, uint32 mode, address relayer,
                      bytes calldata auth) external returns (bytes memory);
}
