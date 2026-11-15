// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The receiver-fee names of the node as they stood at 202a05a9, before the payee-fee rename (owner 2026-11-12,
//! CTR-MTX-86): the CALL_TABLE row `UAReceiverFee` on `mtxPayReceiverFee` (`src/typed.rs`; now `UAPayeeFee` on
//! `mtxPayWithPayeeFee`, the same fields) and the refused job field `receiver_fee` (`src/odoo.rs` `Job`; now
//! `payee_fee`, refused the same way; a job still carrying `receiver_fee` is refused by name, `RECEIVER_FEE_REFUSED`).
//! (`"T"`: the table's token domain.) Reference only; not built.
pub const UA_RECEIVER_FEE_V1: (&str, &str, &str, &str, &str) =
    ("UAReceiverFee", "mtxPayReceiverFee", "T", "UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil", "payment payerSig:UASig fee feeRecipient validUntil @ meta:PayMeta");
