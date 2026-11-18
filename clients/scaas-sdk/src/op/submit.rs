// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sign, write ahead, send (spec §13.4, CLI-SDK-09): sign → write the row (state `signed`) → send → state `sent`. `submit`
//! returns once the row is written; the send runs on as a task and reports as `Event::OpState`, never as `submit`'s error. A row
//! still `signed` after a restart is sent by `resume`; a row `sent` is sent again only by the user's `resend`, the same bytes.
use super::prepared::{envelope, Prepared};
use super::quote::{check_caps, payer_address, SubmitPath, SubmitQuote};
use super::state::{self, Row};
use super::{dec, evm, hex, key, lane_nonce, unhex, InFlight, Op, OpState};
use crate::events::Event;
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, U256};
use scaas_rpc::evm::BroadcastOutcome;
use scaas_rpc::node::{NodeClient, SubmitOutcome, UaMetaTxReq};
use scaas_rpc::Fanout;
use scaas_ua::wallet::entries::{entry, entry_rows, transfer_on_ids, Built};
use scaas_ua::wallet::{sign_scaas, EvmTx};
use serde_json::{json, Value};
use std::sync::{Arc, PoisonError};

/// `PreparedStale`: past its `validUntil` on the chain's clock, or its lane's nonce moved.
pub(crate) async fn fresh(sdk: &Sdk, p: &Prepared) -> Result<(), SdkError> {
    let (_, _, pool) = evm(sdk, &p.chain())?;
    let (_, now) = super::head(&pool).await?;
    if now >= p.expires_at() {
        return Err(SdkError::PreparedStale);
    }
    if let Some((from, batch, nonce)) = &p.t.lane {
        let at = lane_nonce(&pool, Address::from(p.t.contract), p.t.kind, from, *batch).await?;
        if at != *nonce {
            return Err(SdkError::PreparedStale);
        }
    }
    Ok(())
}

/// A signature in the entry's form (`scaas-ua`'s rows): `bytes` for `@bytes` and the address entries, a `UASig` for `@ua` and
/// the `UA*` / `CancelUA*` structs, `SmartKeyAccount`'s own an `AccountSig{keyIndex, proof, signature}` (plan T13 adds the key
/// tree's proof).
fn sig_json(p: &Prepared, key_data: &[u8], signature: &[u8]) -> Result<Value, SdkError> {
    let plan = entry_rows()
        .into_iter()
        .find(|r| r.name == p.t.name && r.kinds.contains(&p.t.kind))
        .map(|r| r.plan)
        .ok_or(SdkError::Argument)?;
    let name = p.t.name;
    let ua = plan.contains("@ua") || name.starts_with("UA") || name.starts_with("CancelUA");
    Ok(if plan.contains("@bytes") {
        json!(hex(signature))
    } else if ua {
        json!({"keyData": hex(key_data), "signature": hex(signature), "members": []})
    } else if p.t.kind == "account" {
        json!({"keyIndex": "0", "proof": [], "signature": hex(signature)})
    } else {
        json!(hex(signature))
    })
}

fn build(p: &Prepared, sig: &Value) -> Result<Built, SdkError> {
    if p.t.ids {
        return Ok(transfer_on_ids(p.t.kind, &p.t.contract, &p.t.message, sig)?);
    }
    Ok(entry(
        p.t.name,
        p.t.kind,
        &p.t.contract,
        &p.t.message,
        &p.t.extra,
        sig,
    )?)
}

/// The entry of `p` with an empty signature: the unsigned form a quote estimates (owner 2026-11-18, ruling 1).
pub(crate) fn unsigned(p: &Prepared) -> Result<Built, SdkError> {
    build(p, &sig_json(p, &[], &[])?)
}

/// The signature of `p` under its check, and the entry built with it (calldata and job op from one parse).
pub(crate) fn sign(sdk: &Sdk, p: &Prepared) -> Result<Built, SdkError> {
    let k = key(sdk, &p.signer())?;
    #[cfg(test)]
    sdk.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let s = sign_scaas(k.signer(), &p.t.td, p.t.expect.clone())?;
    if !s.members.is_empty() {
        return Err(SdkError::Argument);
    }
    build(p, &sig_json(p, &s.key_data, &s.signature)?)
}

/// An EIP-1559 transaction of `quote` from its payer to `to` with `data`, signed by `scaas-ua`: the raw bytes and the id.
pub(crate) fn sign_tx(
    sdk: &Sdk,
    chain_id: u64,
    quote: &SubmitQuote,
    to: [u8; 20],
    value: U256,
    data: Vec<u8>,
) -> Result<(Vec<u8>, String), SdkError> {
    let SubmitPath::SelfRelay { payer } = &quote.path else {
        return Err(SdkError::Argument);
    };
    let super::Key::Native(_, k) = key(sdk, payer)? else {
        return Err(SdkError::Argument);
    };
    let word = |s: &str| -> Result<[u8; 32], SdkError> {
        Ok(U256::from_str_radix(s, 10)
            .map_err(|_| SdkError::Argument)?
            .to_be_bytes::<32>())
    };
    let (nonce, gas_limit, to, value) = (
        quote.tx_nonce,
        quote.gas_limit,
        Some(to),
        value.to_be_bytes::<32>(),
    );
    // types 0, 1, 2 (owner 2026-11-18, ruling 3); a legacy price is the quote's maximum fee per gas
    let tx = match quote.tx_type {
        0 => EvmTx::Legacy {
            chain_id,
            nonce,
            gas_price: word(&quote.max_fee_per_gas)?,
            gas_limit,
            to,
            value,
            data,
        },
        1 => EvmTx::Eip2930 {
            chain_id,
            nonce,
            gas_price: word(&quote.max_fee_per_gas)?,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![],
        },
        2 => EvmTx::Eip1559 {
            chain_id,
            nonce,
            max_priority_fee_per_gas: word(&quote.max_priority_fee_per_gas)?,
            max_fee_per_gas: word(&quote.max_fee_per_gas)?,
            gas_limit,
            to,
            value,
            data,
            access_list: vec![],
        },
        _ => return Err(SdkError::TxTypeRefused),
    };
    let signed = k.sign_transaction(&tx)?;
    let id = hex(&scaas_ua::keccak256(&signed.raw));
    Ok((signed.raw, id))
}

/// `submit`'s re-check of the quote it takes: a resolved path and the SDK's caps.
fn check_quote(sdk: &Sdk, q: &SubmitQuote) -> Result<(), SdkError> {
    match &q.path {
        SubmitPath::Gateway => Ok(()),
        SubmitPath::SelfRelay { .. } => {
            let fee = q
                .max_fee_per_gas
                .parse::<u128>()
                .map_err(|_| SdkError::Argument)?;
            check_caps(sdk, q.gas_limit, fee).map(|_| ())
        }
        SubmitPath::Auto { .. } => Err(SdkError::Argument),
    }
}

impl Op {
    /// Signs `prepared` under its check, writes the operation's row (state `signed`) and returns its id (spec §13.4, R17); the
    /// send runs on and reports as `Event::OpState`. An `Err` means nothing was signed or written: `PreparedUnknown`,
    /// `PreparedStale`, `PolicyRefused`, `FeeAboveCap`, a store failure.
    pub async fn submit(
        &self,
        prepared: Arc<Prepared>,
        quote: SubmitQuote,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                Op::known(&sdk, &prepared)?;
                check_quote(&sdk, &quote)?;
                fresh(&sdk, &prepared).await?;
                let (_, chain_id, pool) = evm(&sdk, &prepared.chain())?;
                let (from_block, _) = super::head(&pool).await?;
                let built = sign(&sdk, &prepared)?;
                let (raw, tx_id, payer) = match &quote.path {
                    SubmitPath::SelfRelay { payer } => {
                        // the signed calldata simulated once (ruling 1): a revert or more gas than the confirmed quote
                        // ends here, nothing written or sent
                        let from = payer_address(&sdk, payer)?;
                        let to = Address::from(prepared.t.contract);
                        let data = alloy::primitives::Bytes::from(built.calldata.clone());
                        if pool
                            .simulate_from(from, to, data)
                            .await
                            .map_err(super::sim)?
                            > quote.gas_limit
                        {
                            return Err(SdkError::GasUnquoted);
                        }
                        let (raw, id) = sign_tx(
                            &sdk,
                            chain_id,
                            &quote,
                            prepared.t.contract,
                            U256::ZERO,
                            built.calldata.clone(),
                        )?;
                        (
                            Some(hex(&raw)),
                            Some(id),
                            Some(format!("{:#x}", payer_address(&sdk, payer)?)),
                        )
                    }
                    _ => (None, None, None),
                };
                let (from, batch, nonce) = prepared
                    .t
                    .lane
                    .as_ref()
                    .map(|(f, b, n)| (hex(f), b.to_string(), n.to_string()))
                    .unwrap_or_default();
                let row = Row {
                    op: crate::vault::uuid4()?,
                    chain: prepared.chain(),
                    entry: prepared.entry(),
                    name: prepared.t.name.into(),
                    kind: prepared.t.kind.into(),
                    contract: hex(&prepared.t.contract),
                    from,
                    batch,
                    nonce,
                    valid_until: prepared.expires_at(),
                    digest: prepared.id(),
                    op_json: built.op.clone().unwrap_or(Value::Null),
                    calldata: hex(&built.calldata),
                    raw,
                    tx_id,
                    tx_nonce: payer.as_ref().map(|_| quote.tx_nonce),
                    path: if payer.is_some() { "self" } else { "gateway" }.into(),
                    payer,
                    from_block,
                    state: "signed".into(),
                    detail: "Signed".into(),
                    landed: None,
                    relayer_bound: envelope(&prepared.t.message)
                        .and_then(|e| e.get("mode"))
                        .map(dec)
                        .transpose()?
                        .is_some_and(|m| m.bit(0)),
                };
                state::put(&sdk, &row).await?;
                sdk.prepared
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&prepared.id());
                let op = row.op.clone();
                let s2 = sdk.clone();
                detach(&sdk, async move { send(&s2, row).await });
                Ok(op)
            })
            .await
    }

    /// Sends every row still `signed` (a send cut by a restart), its first send, the same bytes; a row `sent` is not sent
    /// again (spec §13.4). Returns how many were sent.
    pub async fn resume(&self) -> Result<u32, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let mut n = 0;
                for row in state::rows(&sdk).await? {
                    if row.state == "signed" {
                        send(&sdk, row).await;
                        n += 1;
                    }
                }
                Ok(n)
            })
            .await
    }

    /// The same signed bytes again, at the user's request only (spec §13.3): on its own path, or a gateway's operation
    /// self-relayed by a payer when its `relayer` is unbound (`Argument` otherwise), or a self-relayed one posted to the
    /// gateways. Never re-signed (a self-relay's transaction by a new payer quote is the payer's own new transaction).
    pub async fn resend(&self, op: String, quote: SubmitQuote) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let mut row = state::row(&sdk, &op).await?;
                if row.state != "signed" && row.state != "sent" {
                    return Err(SdkError::Argument);
                }
                check_quote(&sdk, &quote)?;
                match (&quote.path, row.path.as_str()) {
                    (SubmitPath::Gateway, _) if !row.op_json.is_null() => {
                        row.path = "gateway".into()
                    }
                    (SubmitPath::SelfRelay { .. }, "self") => {}
                    (SubmitPath::SelfRelay { payer }, _) => {
                        if row.relayer_bound {
                            return Err(SdkError::Argument);
                        }
                        let (_, chain_id, _) = evm(&sdk, &row.chain)?;
                        let to = super::addr20(&row.contract)?;
                        let (raw, id) = sign_tx(
                            &sdk,
                            chain_id,
                            &quote,
                            to,
                            U256::ZERO,
                            unhex(&row.calldata)?,
                        )?;
                        row.raw = Some(hex(&raw));
                        row.tx_id = Some(id);
                        row.tx_nonce = Some(quote.tx_nonce);
                        row.payer = Some(format!("{:#x}", payer_address(&sdk, payer)?));
                        row.path = "self".into();
                    }
                    _ => return Err(SdkError::Argument),
                }
                state::put(&sdk, &row).await?;
                send(&sdk, row).await;
                Ok(())
            })
            .await
    }
}

/// Runs `f` on as a task of the SDK's runtime, whatever happens to the caller (spec §13.4); on wasm32, where it is awaited.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn detach(sdk: &Arc<Sdk>, f: impl std::future::Future<Output = ()> + Send + 'static) {
    match &sdk.rt {
        Some(rt) => drop(rt.handle.spawn(f)),
        None => drop(tokio::spawn(f)),
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn detach(_: &Arc<Sdk>, f: impl std::future::Future<Output = ()> + 'static) {
    drop(tokio::task::spawn_local(f));
}

/// One send of `row`'s bytes on its path; the row then `sent` with the outcome's detail, and the event.
pub(crate) async fn send(sdk: &Arc<Sdk>, mut row: Row) {
    let detail = match send_once(sdk, &row).await {
        Ok(d) => d,
        Err(_) => InFlight::GivenUpByEveryNode,
    };
    row.state = "sent".into();
    row.detail = format!("{detail:?}");
    if state::put(sdk, &row).await.is_ok() {
        sdk.emit(Event::OpState {
            op: row.op.clone(),
            state: OpState::InFlight { detail },
        });
    }
}

async fn send_once(sdk: &Sdk, row: &Row) -> Result<InFlight, SdkError> {
    let (_, chain_id, pool) = evm(sdk, &row.chain)?;
    if let Some(raw) = &row.raw {
        return Ok(match pool.broadcast(&unhex(raw)?, Fanout::All).await? {
            BroadcastOutcome::Sent { .. } => InFlight::Sent,
            BroadcastOutcome::Rejected { .. } => InFlight::BroadcastRejected,
        });
    }
    let gateways = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == row.chain)
        .and_then(|c| c.gateways.clone())
        .ok_or(SdkError::SubmitPathNone)?;
    let node = NodeClient::new(gateways)?;
    let outcome = if row.entry == "mtxExecuteTransfer" {
        // the transfer on ids: `POST /v1/ua-metatx` (owner 2026-11-18, ruling 6)
        let o = &row.op_json;
        let s = |k: &str| o.get(k).and_then(Value::as_str).map(String::from);
        let req = UaMetaTxReq {
            chain: chain_id,
            token: s("token").ok_or(SdkError::Internal)?,
            contract: s("contract"),
            struct_: s("struct"),
            m: o.get("m").cloned().unwrap_or_default(),
            auth: o.get("auth").cloned().unwrap_or_default(),
        };
        node.submit_ua_metatx(&req, Fanout::All).await?
    } else {
        node.submit_op(chain_id, &row.op_json, Fanout::All).await?
    };
    Ok(match outcome {
        SubmitOutcome::Queued { .. } => InFlight::Queued,
        SubmitOutcome::NotQueued { .. } => InFlight::GivenUpByEveryNode,
    })
}
