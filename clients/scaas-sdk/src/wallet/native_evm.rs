// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The EVM native send (spec §8.5): a transaction of type 0, 1 or 2 (owner 2026-11-18, ruling 3: 3 (blob) and 4 (EIP-7702)
//! `TxTypeRefused`; by default 2 where the chain's head has a base fee, else 0; chain id 0 refused), its nonce and fees read
//! and capped by `Limits` before review (`FeeAboveCap`), signed by `scaas-ua` `sign_transaction`, written ahead, sent by
//! `broadcast(raw, Fanout::All)`, followed by `tx_state`. The only way an EVM key signs a transaction. No EIP-7702
//! authorization is built; a delegated sender may send, its review carrying the mark (ruling 5).
use super::Wallet;
use crate::op::quote::{check_caps, delegated, payer_address, self_relay};
use crate::op::state::{self, Row};
use crate::op::submit::{detach, send, sign_tx};
use crate::op::{addr20, evm, hex, sim, unhex, KeyRef, SubmitPath, SubmitQuote};
use crate::SdkError;
use alloy::primitives::{Bytes, U256};

/// `prepare_native_send`'s request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeSend {
    /// a native `evm` key
    pub key: KeyRef,
    pub chain: String,
    /// `0x` + 40 hex
    pub to: String,
    /// wei, decimal
    pub value: String,
    /// `0x` hex calldata, or none
    pub data: Option<String>,
    /// the EIP-2718 type asked: 0, 1 or 2 (2 only where the chain has a base fee); `None`: 2 where it has one, else 0.
    /// `TxTypeRefused` otherwise (3 and 4 never)
    pub tx_type: Option<u8>,
}

/// A native send as the user reviews it: the transaction's fields and the quote; `submit_native_send` signs exactly these.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct NativeQuote {
    pub key: KeyRef,
    pub chain: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub data: String,
    pub quote: SubmitQuote,
    /// the sender's code is an EIP-7702 designator (`0xef0100…`, the account's delegation mark, T9): the send is the EOA's own
    /// transaction and stays allowed; the app can warn (owner 2026-11-18, ruling 5)
    pub delegated: bool,
}

impl Wallet {
    /// Quotes a native send (spec §8.5): `TxTypeRefused` (a type other than 0, 1, 2; 2 on a chain without a base fee),
    /// `Argument` (chain id 0, a bad address, value or data, a key other than a native `evm` one), `GasAboveTxCap`,
    /// `FeeAboveCap`.
    pub async fn prepare_native_send(&self, req: NativeSend) -> Result<NativeQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if req.tx_type.is_some_and(|t| t > 2) {
                    return Err(SdkError::TxTypeRefused);
                }
                let (_, chain_id, pool) = evm(&sdk, &req.chain)?;
                if chain_id == 0 {
                    return Err(SdkError::Argument);
                }
                let to = addr20(&req.to.to_ascii_lowercase())?;
                let value = U256::from_str_radix(&req.value, 10).map_err(|_| SdkError::Argument)?;
                let data = match &req.data {
                    Some(d) => unhex(d)?,
                    None => vec![],
                };
                if data.len() > 128 * 1024 {
                    return Err(SdkError::Argument);
                }
                let from = payer_address(&sdk, &req.key)?;
                let mut quote = self_relay(
                    &sdk,
                    &req.chain,
                    &req.key,
                    to.into(),
                    value,
                    Bytes::from(data.clone()),
                    "0".into(),
                    false,
                    None,
                )
                .await?;
                quote.tx_type = match req.tx_type {
                    None => quote.tx_type,
                    Some(2) if quote.tx_type != 2 => return Err(SdkError::TxTypeRefused),
                    Some(t) => t,
                };
                let delegated = delegated(&pool.code(from).await.map_err(sim)?);
                Ok(NativeQuote {
                    key: req.key,
                    chain: req.chain,
                    from: format!("{from:#x}"),
                    to: hex(&to),
                    value: value.to_string(),
                    data: hex(&data),
                    quote,
                    delegated,
                })
            })
            .await
    }

    /// Signs exactly `q`, writes the operation's row, returns its id; the send runs on and reports as `Event::OpState`, the
    /// state follows `tx_state` (`Op::state`).
    pub async fn submit_native_send(&self, q: NativeQuote) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let fee = q
                    .quote
                    .max_fee_per_gas
                    .parse::<u128>()
                    .map_err(|_| SdkError::Argument)?;
                check_caps(&sdk, q.quote.gas_limit, fee)?;
                // the key that signs is the quote's payer: it must be the reviewed key and `from` (closing review P3)
                let signs_with_key =
                    matches!(&q.quote.path, SubmitPath::SelfRelay { payer } if *payer == q.key);
                if !signs_with_key || format!("{:#x}", payer_address(&sdk, &q.key)?) != q.from {
                    return Err(SdkError::Argument);
                }
                let (_, chain_id, _) = evm(&sdk, &q.chain)?;
                let value = U256::from_str_radix(&q.value, 10).map_err(|_| SdkError::Argument)?;
                let (raw, id) = sign_tx(
                    &sdk,
                    chain_id,
                    &q.quote,
                    addr20(&q.to)?,
                    value,
                    unhex(&q.data)?,
                )?;
                let row = Row {
                    op: crate::vault::uuid4()?,
                    chain: q.chain.clone(),
                    entry: "transfer".into(),
                    name: "EvmTx".into(),
                    kind: "native".into(),
                    contract: q.to.clone(),
                    from: String::new(),
                    batch: String::new(),
                    nonce: String::new(),
                    valid_until: u64::MAX,
                    digest: id.clone(),
                    op_json: serde_json::Value::Null,
                    calldata: q.data.clone(),
                    raw: Some(hex(&raw)),
                    tx_id: Some(id),
                    tx_nonce: Some(q.quote.tx_nonce),
                    path: "self".into(),
                    payer: Some(q.from.clone()),
                    from_block: 0,
                    state: "signed".into(),
                    detail: "Signed".into(),
                    landed: None,
                    relayer_bound: false,
                    extra: serde_json::Value::Null,
                    gas_limit: Some(q.quote.gas_limit),
                    signer_kind: None,
                    unsigned_len: None,
                    ended_at: None,
                    fact: None,
                    message: serde_json::Value::Null,
                };
                state::put(&sdk, &row).await?;
                let (s2, op) = (sdk.clone(), row.op.clone());
                detach(&sdk, async move { send(&s2, row).await });
                Ok(op)
            })
            .await
    }
}
