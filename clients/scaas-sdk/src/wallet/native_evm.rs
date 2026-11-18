// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The EVM native send (spec §8.5): an EIP-1559 transaction (type 2 only: type 4 has no shape here, `TxTypeRefused`; chain id
//! 0 refused), its nonce and fees read and capped by `Limits` before review (`FeeAboveCap`), signed by `scaas-ua`
//! `sign_transaction`, written ahead, sent by `broadcast(raw, Fanout::All)`, followed by `tx_state`. The only way an EVM key
//! signs a transaction. No EIP-7702 authorization is built.
use super::Wallet;
use crate::op::quote::{check_caps, payer_address, self_relay};
use crate::op::state::{self, Row};
use crate::op::submit::{detach, send, sign_tx};
use crate::op::{addr20, evm, hex, unhex, KeyRef, SubmitQuote};
use crate::SdkError;
use alloy::primitives::{Bytes, U256};

/// `prepare_native_send`'s request.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// the EIP-2718 type asked: 2 only (`TxTypeRefused` otherwise; type 4 never)
    pub tx_type: u8,
}

/// A native send as the user reviews it: the transaction's fields and the quote; `submit_native_send` signs exactly these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeQuote {
    pub key: KeyRef,
    pub chain: String,
    pub from: String,
    pub to: String,
    pub value: String,
    pub data: String,
    pub quote: SubmitQuote,
}

impl Wallet {
    /// Quotes a native send (spec §8.5): `TxTypeRefused` (a type other than 2), `Argument` (chain id 0, a bad address, value
    /// or data, a key other than a native `evm` one), `GasAboveTxCap`, `FeeAboveCap`.
    pub async fn prepare_native_send(&self, req: NativeSend) -> Result<NativeQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if req.tx_type != 2 {
                    return Err(SdkError::TxTypeRefused);
                }
                let (_, chain_id, _) = evm(&sdk, &req.chain)?;
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
                let quote = self_relay(
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
                Ok(NativeQuote {
                    key: req.key,
                    chain: req.chain,
                    from: format!("{from:#x}"),
                    to: hex(&to),
                    value: value.to_string(),
                    data: hex(&data),
                    quote,
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
                if format!("{:#x}", payer_address(&sdk, &q.key)?) != q.from {
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
                };
                state::put(&sdk, &row).await?;
                let (s2, op) = (sdk.clone(), row.op.clone());
                detach(&sdk, async move { send(&s2, row).await });
                Ok(op)
            })
            .await
    }
}
