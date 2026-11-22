// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The hand-off's blob (spec §27.5 (c)), one form for every family: the signer's operation by its named fields as signed, its
//! signature, the signer. EVM (`op::Op::hand_off`, plan T41.evm): `family` `evm`, the typed struct's `message` and `extra`, the
//! signature in the entry's form. Soroban (`wallet::Wallet::soroban_hand_off`, plan T41.soroban): `family` `soroban`, `struct`
//! `signed_op`, `kind` `token`, `message` the node's named `payload` (`{nonce, expiry, invocation}`), `extra` null, the 64-byte
//! signature as `0x` hex, `signer_kind` 0 (a native key), `ids` false. It holds no secret. UNAUDITED.
use crate::SdkError;
use serde_json::Value;

/// A blob's largest JSON text (spec §27.5 (c)): the vectors' largest signed operation, an `msig` of three PQ members, is
/// 14,722 B of signature (its blob 15,800 B) (`tests/handoff.rs` `the_cap_holds_the_largest_signed_operation`).
pub const HANDOFF_MAX: usize = 256 * 1024;
/// A blob's deepest nesting.
const HANDOFF_DEPTH: usize = 8;
/// A signed operation handed off (spec §27.5 (c)): the operation's named fields as signed (canonical), its signature in the
/// entry's form, the signer's subject id and kind. It holds no secret; who holds it can land it, never redirect it.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
#[cfg_attr(frb_expand, doc = frb_hint!(opaque))]
pub struct SignedOpBlob {
    /// 1
    pub v: u32,
    /// the profile's `chain_uid` (`0x` + 64 hex)
    pub chain_uid: String,
    /// `evm`, `soroban`
    pub family: String,
    /// the domain's contract, the token (`0x` + 40 hex; a `C…` on Soroban)
    pub contract: String,
    /// the contract function (`mtxPay`, `mtxCancelNonce`, …; `pay`, `transfer`, `burn` on Soroban)
    pub entry: String,
    /// the signed struct
    #[serde(rename = "struct")]
    pub name: String,
    /// the domain kind (`token`)
    pub kind: String,
    /// the struct's fields, canonical (an unbound `relayer` and `feeRecipient` 0)
    pub message: Value,
    /// what the entry takes unsigned beside them (a pay's `meta`, …)
    pub extra: Value,
    /// the signature in the entry's form (`bytes`, a `UASig`)
    pub signature: Value,
    /// the signer's subject id (the lane's `from`)
    pub signer: String,
    /// the signer's kind (a UA kind, 0 a native EVM key)
    pub signer_kind: u16,
    /// the transfer on ids (`mtxExecuteTransfer`)
    pub ids: bool,
}

impl SignedOpBlob {
    /// The blob from its JSON text: `Argument` above [`HANDOFF_MAX`] bytes, deeper than 8, with an unknown or missing field.
    pub fn from_json(text: &str) -> Result<SignedOpBlob, SdkError> {
        if text.len() > HANDOFF_MAX
            || scaas_ua::json::depth_within(text.as_bytes(), HANDOFF_DEPTH).is_err()
        {
            return Err(SdkError::Argument);
        }
        serde_json::from_str(text).map_err(|_| SdkError::Argument)
    }

    /// Its JSON text.
    pub fn to_json(&self) -> Result<String, SdkError> {
        serde_json::to_string(self).map_err(|_| SdkError::Internal)
    }
}
