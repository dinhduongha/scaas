// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `UAReceiverFee` row of `src/typed.rs` as it stood at 202a05a9, before the payee-fee rename (owner 2026-11-12,
//! CTR-MTX-86; now `UAPayeeFee`, the same members, typehash 0xb12d2a08… -> 0x8a3955a6…); `src/api.rs` named the UA
//! purpose `receiver-fee` (now `payee-fee`). Reference only; not built.
pub const UA_RECEIVER_FEE_V1: (&str, &str) =
    ("UAReceiverFee", "UAReceiverFee(UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil)UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)");
