// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MetaTxLib} from "../../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../../src/ua/IUARegistry.sol";

/// @title The receiver-fee names, as they stood at 202a05a9 (renamed by the owner 2026-11-12, CTR-MTX-86: "payee fee",
///        "payee" consistently): the entry `mtxPayReceiverFee` (now `mtxPayWithPayeeFee`), the view `receiverFeeDigest`
///        (now `payeeFeeDigest`), the event `UAReceiverFeePaid` (now `UAPayeeFeePaid`), the errors `ReceiverFee*` (now
///        `PayeeFee*`), the typed struct `UAReceiverFee` (now `UAPayeeFee`, the same members) and the UA purpose
///        `receiver-fee` (now `payee-fee`). Their bodies are `MetaTokenBase._mtxPayWithPayeeFeeBody` / `_payeeFee` under
///        the old names, unchanged. On every `PAYABLE` kind (the twelve token kinds). Not built. UNAUDITED.
interface IReceiverFeeV1 {
    /// `0xff4d76ed`
    event UAReceiverFeePaid(bytes32 indexed paymentDigest, bytes32 indexed payee, address indexed feeRecipient,
        uint256 fee);

    /// `0x7402dad8`
    error ReceiverFeeShape();
    /// `0x05d8c0a0`
    error ReceiverFeeExpired(uint256 validUntil, uint256 nowTs);
    /// `0xb00c2e22`
    error ReceiverFeeAmount(uint256 fee, uint256 value);

    /// `0x7c4fa261`
    function receiverFeeDigest(MetaTxLib.UAMetaTransfer calldata t, uint256 fee, address feeRecipient, uint256 validUntil)
        external view returns (bytes32);

    /// `0x0de1ca2d`
    function mtxPayReceiverFee(MetaTxLib.UAMetaTransfer calldata t, IUARegistry.UASig calldata payerAuth, uint256 fee,
        address feeRecipient, uint256 rfValidUntil, IUARegistry.UASig calldata payeeAuth, MetaTxLib.PayMeta calldata meta)
        external returns (bool);
}

library ReceiverFeeV1 {
    /// `0xb12d2a080dcf6d9edea1a63b0fd3a59ebffa656c929d21f676d1f1507c75021a`
    bytes32 internal constant UA_RECEIVER_FEE_TYPEHASH = keccak256(
        "UAReceiverFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)UAMetaTransfer(bytes32 from,"
        "bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,"
        "uint256 fee,address feeRecipient)");
    /// `0x37eb8dc32cfd77c0119dbff5dfdf055cc19cfc0ee77d3fba5121eb83350f9a8e` (`UAKinds.PURPOSE_RECEIVER_FEE`)
    bytes32 internal constant PURPOSE_RECEIVER_FEE = keccak256("scaas.ua.purpose.receiver-fee.v1");
}
