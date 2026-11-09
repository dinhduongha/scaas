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

    /// @notice Every pay entry (CTR-MTX-26, pay-meta-tax spec §3.2), before the payment's events; never parsed.
    event PaymentMeta(bytes32 indexed payId, string payNo, uint16 schema, bytes body);

    /// @notice A zero `salt`, or `schema == 0` and a non-empty `body` disagree.
    error PayMetaShape();
    error PayNoTooLong(uint256 length);
    error PayMetaMismatch(bytes32 entryRef, bytes32 payId);
    error ReceiverFeeShape();
    error ReceiverFeeExpired(uint256 validUntil, uint256 nowTs);
    error ReceiverFeeAmount(uint256 fee, uint256 value);

    /// @notice CTR-MTX-26: `keccak256(abi.encodePacked("scaas.pay.meta.v2", salt, keccak256(abi.encode(payNo, schema,
    ///         body))))`.
    function metaPayId(MetaTxLib.PayMeta calldata meta) external pure returns (bytes32);

    function receiverFeeDigest(MetaTxLib.UAMetaTransfer calldata t, uint256 fee, address feeRecipient, uint256 validUntil)
        external view returns (bytes32);

    /// @notice Receiver-pays: payer and payee are ids; a derived payee co-signs under `receiver-fee`.
    function mtxPayReceiverFee(
        MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth,
        uint256 fee, address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth,
        MetaTxLib.PayMeta calldata meta
    ) external returns (bool);

    /// @notice A client convention, not enforced (O3): a client that wants one payment per request signs on this lane
    ///         at nonce 0.
    function payLane(bytes32 payId) external pure returns (uint256);

    /// @notice `payWithFee` to the registered SIGNING UA `to` (accounts.md CTR-UA-28); emits `UAPaymentSettled`.
    function payWithFeeToUA(bytes32 to, uint256 amount, FeeMode feeMode, uint256 fee, address feeRecipient,
                            bytes32 entryRef, MetaTxLib.PayMeta calldata meta) external returns (bool);

    function mtxTransfer(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce, uint256 validUntil,
                         uint32 mode, address relayer, IUARegistry.UASig calldata auth) external returns (bool);
    function mtxTransferWithFee(bytes32 from, bytes32 to, uint256 amount, uint256 batch, uint256 nonce,
                                uint256 validUntil, uint32 mode, address relayer, uint256 fee, address feeRecipient,
                                IUARegistry.UASig calldata auth) external returns (bool);
    /// @notice The payment `t` (`entryRef == metaPayId(meta)`, any lane, CTR-MTX-10, O3) with its metadata.
    function mtxPay(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata auth,
                    MetaTxLib.PayMeta calldata meta) external returns (bool);
}
