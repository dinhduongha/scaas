// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20Payment} from "./IERC20Payment.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";
import {FeeMode} from "../common/FeePolicy.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title Named functions of every v2 tier (`MetaTokenBase`, metatx.md Interfaces; CTR-MTX-09, CTR-MTX-05) on ids
///        (accounts.md CTR-UA-26; ua-mtx-merge T2: each builds its `UAMetaTransfer`, one form for native and derived ids;
///        the address forms and `ReceiverFee` are in legacy/ua-mtx-merge/).
interface IMetaTokenV2 is IERC20Payment {
    /// @notice `mtxPayReceiverFee` (CTR-MTX-05 on ids): the payee is an id.
    event UAReceiverFeePaid(bytes32 indexed paymentDigest, bytes32 indexed payee, address indexed feeRecipient,
                            uint256 fee);

    /// @notice `mtxPayMeta` (CTR-MTX-26), before `UAPaymentSettled`; `meta` is never parsed.
    event PaymentMeta(bytes32 indexed payId, bytes meta);

    error ReceiverFeeShape();
    error ReceiverFeeExpired(uint256 validUntil, uint256 nowTs);
    error ReceiverFeeAmount(uint256 fee, uint256 value);

    /// @notice CTR-MTX-26: `keccak256(abi.encodePacked("scaas.pay.meta", salt, keccak256(meta)))`.
    function metaPayId(bytes32 salt, bytes calldata meta) external pure returns (bytes32);

    function receiverFeeDigest(MetaTxLib.UAMetaTransfer calldata t, uint256 fee, address feeRecipient, uint256 validUntil)
        external view returns (bytes32);

    /// @notice Receiver-pays: payer and payee are ids; a derived payee co-signs under `receiver-fee`.
    function mtxPayReceiverFee(
        MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth
    ) external returns (bool);

    function payLane(bytes32 payId) external pure returns (uint256);

    /// @notice `payWithFee` to the registered SIGNING UA `to` (accounts.md CTR-UA-28); emits `UAPaymentSettled`.
    function payWithFeeToUA(bytes32 to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient,
                            bytes32 entryRef) external returns (bool);

    function mtxTransfer(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
                         uint32 mode, address relayer, IUARegistry.UASig calldata auth) external returns (bool);
    function mtxTransferWithFee(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce,
                                uint256 validUntil, uint32 mode, address relayer, uint256 fee, address feeRecipient,
                                IUARegistry.UASig calldata auth) external returns (bool);
    /// @notice Payment `payId` on its own lane `payLane(payId)`, nonce 0 (CTR-MTX-10).
    function mtxPay(bytes32 from, bytes32 to, uint256 amount, bytes32 payId, uint256 validUntil, uint32 mode,
                    address relayer, uint256 fee, address feeRecipient, IUARegistry.UASig calldata auth)
        external returns (bool);
    /// @notice `mtxPay` with `payId = metaPayId(salt, meta)` (CTR-MTX-26): the same digest, lane and nonce.
    function mtxPayMeta(bytes32 from, bytes32 to, uint256 amount, bytes32 salt, bytes calldata meta, uint256 validUntil,
                        uint32 mode, address relayer, uint256 fee, address feeRecipient, IUARegistry.UASig calldata auth)
        external returns (bool);
}
