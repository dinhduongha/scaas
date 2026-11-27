// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sign, write ahead, send (spec §13.4, CLI-SDK-09; owner 2026-11-19, ruling A): sign → write the row (state `signed`) →
//! simulate a self-relay's signed calldata → send → state `sent`. Nothing signed leaves the SDK before its row is written (the
//! simulation sends the signed calldata to an endpoint). `submit` returns once the row is written; the simulation and the send
//! run on as a task and report as `Event::OpState`, never as `submit`'s error: a refused simulation is `InFlight { SimRefused }`,
//! the operation tracked to a chain fact like any other. A row still `signed` after a restart is sent by `resume` (unless its
//! simulation was refused); a row `sent` is sent again only by the user's `resend`, the same bytes.
use super::prepared::{envelope, Prepared};
use super::quote::{
    check_caps, check_gateways, door_a, fee_of, figure, kept_gateways, payer_address, signed_quote,
    signer_kind, SubmitPath, SubmitQuote,
};
use super::state::{self, Row};
use super::{dec, evm, hex, key, lane_nonce, unhex, InFlight, Op, OpState};
use crate::events::Event;
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, U256};
use scaas_rpc::evm::BroadcastOutcome;
use scaas_rpc::node::{SubmitOutcome, UaMetaTxReq};
use scaas_rpc::Fanout;
use scaas_ua::wallet::entries::{entry, entry_rows, relay_fee_op, transfer_on_ids, Built};
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
        let at = lane_nonce(
            &pool,
            Address::from(p.t.contract),
            p.t.kind,
            from,
            *batch,
            super::gov_target(&p.t.message),
        )
        .await?;
        if at != *nonce {
            return Err(SdkError::PreparedStale);
        }
    }
    Ok(())
}

/// A signature in the entry's form (`scaas-ua`'s rows): `bytes` for `@bytes` and the address entries, a `UASig` for `@ua` and
/// the `UA*` / `CancelUA*` structs, `SmartKeyAccount`'s own an `AccountSig{keyIndex, proof, signature}` (plan T13 adds the key
/// tree's proof).
pub(crate) fn sig_json(p: &Prepared, key_data: &[u8], signature: &[u8]) -> Result<Value, SdkError> {
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
        json!({"keyIndex": p.t.key_index.to_string(), "proof": [], "signature": hex(signature)})
    } else {
        json!(hex(signature))
    })
}

pub(crate) fn build(p: &Prepared, sig: &Value, extra: &Value) -> Result<Built, SdkError> {
    if p.t.ids {
        return Ok(transfer_on_ids(p.t.kind, &p.t.contract, &p.t.message, sig)?);
    }
    let mut b = entry(
        p.t.name,
        p.t.kind,
        &p.t.entry_contract(),
        &p.t.message,
        extra,
        sig,
    )?;
    // a relay fee's job carries the call it pays for (job-api's relay-fee job; owner 2026-11-19, ruling F)
    if let Some((op, calldata)) = &p.t.relay_call {
        let call = Built {
            calldata: calldata.clone(),
            op: Some(op.clone()),
            message: Value::Null,
        };
        b.op = Some(relay_fee_op(&b, &call)?);
    }
    Ok(b)
}

/// The entry of `p` with an empty signature: the unsigned form a quote estimates (owner 2026-11-18, ruling 1).
pub(crate) fn unsigned(p: &Prepared) -> Result<Built, SdkError> {
    build(p, &sig_json(p, &[], &[])?, &p.t.extra)
}

/// The signature of `p` under its check, and the entry built with it (calldata and job op from one parse). A stored key row
/// (a passkey, a secure-element key) signs through the platform's authenticator (`external`).
pub(crate) async fn sign(sdk: &Sdk, p: &Prepared) -> Result<Built, SdkError> {
    let (sig, extra) = signature(sdk, p).await?;
    build(p, &sig, &extra)
}

/// The signature of `p` in the entry's form and the entry's unsigned arguments with any statement signed first (`ownerSig`);
/// an imported operation's own, made elsewhere (spec §27.5 (c)).
pub(crate) async fn signature(sdk: &Sdk, p: &Prepared) -> Result<(Value, Value), SdkError> {
    if let Some((sig, _)) = &p.t.signed {
        return Ok((sig.clone(), p.t.extra.clone()));
    }
    if let super::KeyRef::Msig { ua, slots } = p.signer() {
        return Ok((sign_msig(sdk, p, &ua, &slots).await?, p.t.extra.clone()));
    }
    if let super::KeyRef::BlsMulti { .. } = p.signer() {
        return Err(SdkError::Argument); // a group signs by its members' aggregate: `Op::submit_bls_multi`
    }
    let k = super::key_opened(sdk, &p.signer()).await?;
    #[cfg(test)]
    sdk.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // the statement of the named slot first (`ownerSig`, owner 2026-11-19 C3; a PQZ debit's `pqzAuth`), then the entry: each
    // digest approved, then signed under its check
    let mut extra = p.t.extra.clone();
    if let Some((td, ex, slot)) = &p.t.owner {
        let o = sign_one(sdk, &k, td, ex).await?;
        extra.as_object_mut().ok_or(SdkError::Internal)?.insert(
            (*slot).into(),
            json!({"keyData": hex(&o.key_data), "signature": hex(&o.signature), "members": []}),
        );
    }
    let s = sign_one(sdk, &k, &p.t.td, &p.t.expect).await?;
    Ok((sig_json(p, &s.key_data, &s.signature)?, extra))
}

/// An `msig` signer (`KeyRef::Msig`): its `UASig{"", "", members}` by `account::msig` under the entry's check, for a `UA*` entry
/// only (an `msig` has no native or account form, no owner statement).
#[cfg(feature = "account")]
async fn sign_msig(
    sdk: &Sdk,
    p: &Prepared,
    ua: &str,
    slots: &[super::MsigSlot],
) -> Result<Value, SdkError> {
    let plan = entry_rows()
        .into_iter()
        .find(|r| r.name == p.t.name && r.kinds.contains(&p.t.kind))
        .map(|r| r.plan)
        .ok_or(SdkError::Argument)?;
    let ua_form =
        plan.contains("@ua") || p.t.name.starts_with("UA") || p.t.name.starts_with("CancelUA");
    if !ua_form || plan.contains("@bytes") || p.t.owner.is_some() {
        return Err(SdkError::Argument);
    }
    #[cfg(test)]
    sdk.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let s =
        crate::account::msig::sign_typed(sdk, &p.chain(), ua, slots, &p.t.td, &p.t.expect).await?;
    serde_json::from_str(&scaas_ua::json::uasig_json(&s)).map_err(|_| SdkError::Internal)
}

#[cfg(not(feature = "account"))]
async fn sign_msig(
    _: &Sdk,
    _: &Prepared,
    _: &str,
    _: &[super::MsigSlot],
) -> Result<Value, SdkError> {
    Err(SdkError::FeatureMissing)
}

pub(crate) async fn sign_one(
    sdk: &Sdk,
    k: &super::Key,
    td: &scaas_ua::wallet::TypedData,
    ex: &scaas_ua::wallet::Expect,
) -> Result<scaas_ua::ua_portable::UASig, SdkError> {
    #[cfg(feature = "zether")]
    if let super::Key::Zether(_, z) = k {
        z.approve(td.digest()?);
    }
    let s = match k {
        super::Key::External(row, _) => super::external::sign(sdk, row, td, ex).await?,
        _ => sign_scaas(k.signer(), td, ex.clone())?,
    };
    if !s.members.is_empty() {
        return Err(SdkError::Argument);
    }
    Ok(s)
}

/// The transaction of `quote` to `to` with `value` and `data`, unsigned (its type, nonce, gas and fees; the L1 data fee's
/// input, plan T38).
pub(crate) fn evm_tx(
    chain_id: u64,
    quote: &SubmitQuote,
    to: [u8; 20],
    value: U256,
    data: Vec<u8>,
) -> Result<EvmTx, SdkError> {
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
    Ok(match quote.tx_type {
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
    })
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
    let nonce = quote.tx_nonce;
    let tx = evm_tx(chain_id, quote, to, value, data)?;
    let signed = k.sign_transaction(&tx)?;
    let id = hex(&scaas_ua::keccak256(&signed.raw));
    // the payer's next nonce after this one, the floor of its next quote in this session
    if let (Some(c), Ok(from)) = (
        sdk.chain_where(|c| c.profile.chain_id == Some(chain_id))
            .ok(),
        payer_address(sdk, payer),
    ) {
        let mut n = sdk
            .sent_nonces
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let e = n
            .entry((c.profile.key.clone(), format!("{from:#x}")))
            .or_insert(0);
        *e = (*e).max(nonce.saturating_add(1));
    }
    Ok((signed.raw, id))
}

/// `submit`'s re-check of the quote it takes: a resolved path and the SDK's caps. A gateway quote, built by `quote` or by hand,
/// is checked as `quote` checks it: a door-A entry and gateways that announce the profile's `chain_uid`.
async fn check_quote(sdk: &Sdk, p: Option<&Prepared>, q: &SubmitQuote) -> Result<(), SdkError> {
    match &q.path {
        SubmitPath::Gateway => {
            if p.is_some_and(|p| !door_a(p)) {
                return Err(SdkError::SubmitPathNone);
            }
            Ok(())
        }
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

/// Takes `p` out of the SDK's table (one `submit` of a `Prepared`: a second, concurrent or later, is `PreparedUnknown`).
pub(crate) fn take(sdk: &Sdk, p: &Arc<Prepared>) -> Result<(), SdkError> {
    let mut t = sdk.prepared.lock().unwrap_or_else(PoisonError::into_inner);
    match t.get(&p.id()) {
        Some(q) if Arc::ptr_eq(q, p) => {
            t.remove(&p.id());
            Ok(())
        }
        _ => Err(SdkError::PreparedUnknown),
    }
}

/// The message without its `validUntil` (the envelope's, or its `payment`'s): what a retry repeats.
fn retried(m: &Value) -> Value {
    let mut m = m.clone();
    if let Some(o) = m.as_object_mut() {
        o.remove("validUntil");
        if let Some(p) = o.get_mut("payment").and_then(Value::as_object_mut) {
            p.remove("validUntil");
        }
    }
    m
}

/// An earlier operation of this SDK that `p` retries (the same struct and message on the same lane and nonce, another
/// `validUntil`) and that is not over (owner 2026-11-19, T13b ruling 7): a retry after its `validUntil` lapsed signs again on
/// the same lane only once it is `Expired` by a chain fact; before that the retry is that operation. Its id, after following
/// it once; `None`: none, or the earlier one `Expired`.
async fn earlier_on_lane(sdk: &Arc<Sdk>, p: &Prepared) -> Result<Option<String>, SdkError> {
    let Some((from, batch, nonce)) = &p.t.lane else {
        return Ok(None);
    };
    let (from, batch, nonce) = (hex(from), batch.to_string(), nonce.to_string());
    let contract = hex(&p.t.contract);
    let mine = retried(&p.t.message);
    for row in state::rows(sdk).await? {
        let same = row.chain == p.chain()
            && row.name == p.t.name
            && row.contract.eq_ignore_ascii_case(&contract)
            && row.from.eq_ignore_ascii_case(&from)
            && row.batch == batch
            && row.nonce == nonce
            && retried(&row.message) == mine;
        if !same || row.state == "expired" {
            continue;
        }
        let op = Op { sdk: sdk.clone() };
        if !matches!(op.state(row.op.clone()).await?, OpState::Expired { .. }) {
            return Ok(Some(row.op));
        }
    }
    Ok(None)
}

/// How `submit` signs: the signer's own key, or a `bls12381-multi` group's aggregate of its members' partials (plan Task 17:
/// the parts, `surplus`).
pub(crate) enum Signing {
    Key,
    BlsMulti(Vec<super::BlsMultiPart>, bool),
}

/// Puts `p` back after a failure before anything was signed or written.
pub(crate) fn put_back(sdk: &Sdk, p: &Arc<Prepared>) {
    sdk.prepared
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(p.id())
        .or_insert_with(|| p.clone());
}

impl Op {
    /// Signs `prepared` under its check, writes the operation's row (state `signed`) and returns its id (spec §13.4, R17;
    /// owner 2026-11-19, ruling A); the simulation of a self-relay and the send run on and report as `Event::OpState`. An `Err`
    /// means nothing was written or sent (a signature made before a failed write never leaves the SDK): `PreparedUnknown`,
    /// `PreparedStale`, `PolicyRefused`, `FeeAboveCap`, `SubmitPathNone`, `ProfileMismatch`, a store failure; a self-relay's
    /// gas recomputed from the signed calldata (owner 2026-11-19, G3: never below the quote's, its transaction sent with it)
    /// above `Limits::max_gas` `SignedGasAboveCap`, above the chain's per-transaction cap `GasAboveTxCap`.
    pub async fn submit(
        &self,
        prepared: Arc<Prepared>,
        quote: SubmitQuote,
    ) -> Result<String, SdkError> {
        self.submit_with(prepared, quote, Signing::Key).await
    }

    /// [`Op::submit`] signed as `how` says.
    pub(crate) async fn submit_with(
        &self,
        prepared: Arc<Prepared>,
        quote: SubmitQuote,
        how: Signing,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                Op::known(&sdk, &prepared)?;
                check_quote(&sdk, Some(&prepared), &quote).await?;
                fresh(&sdk, &prepared).await?;
                let (profile, chain_id, pool) = evm(&sdk, &prepared.chain())?;
                if quote.path == SubmitPath::Gateway {
                    check_gateways(&sdk, &prepared.chain()).await?;
                }
                // the first block the operation may land in: the final block now, before it is signed (P2-5)
                let from_block = super::final_number(&pool, &profile).await?;
                // a retry on the lane of an operation not yet `Expired` by a chain fact is that operation (T13b ruling 7)
                if let Some(op) = earlier_on_lane(&sdk, &prepared).await? {
                    return Ok(op);
                }
                take(&sdk, &prepared)?;
                let signed = match &how {
                    Signing::Key => sign(&sdk, &prepared).await,
                    Signing::BlsMulti(parts, surplus) => {
                        super::bls_multi::sign(&prepared, parts, *surplus)
                    }
                }
                .and_then(|b| {
                    if quote.path == SubmitPath::Gateway && b.op.is_none() {
                        return Err(SdkError::SubmitPathNone);
                    }
                    Ok(b)
                });
                let built = match signed {
                    Ok(b) => b,
                    Err(e) => {
                        put_back(&sdk, &prepared);
                        return Err(e);
                    }
                };
                // G3: a self-relay's gas recomputed from the signed calldata, before anything is written or sent; the signer's
                // kind and the unsigned calldata's length kept on the row for a later self-relay `resend` (Q5)
                let kind = signer_kind(&sdk, &prepared).await;
                let (signer, unsigned_len) =
                    match unsigned(&prepared).and_then(|u| Ok((kind?, u.calldata.len()))) {
                        Ok(v) => v,
                        Err(e) => {
                            put_back(&sdk, &prepared);
                            return Err(e);
                        }
                    };
                let quote = match &quote.path {
                    SubmitPath::SelfRelay { .. } => {
                        match signed_quote(
                            &sdk,
                            &prepared.chain(),
                            signer,
                            unsigned_len,
                            &quote,
                            Address::from(prepared.t.entry_contract()),
                            &built.calldata,
                            None,
                        )
                        .await
                        {
                            Ok(q) => q,
                            Err(e) => {
                                put_back(&sdk, &prepared);
                                return Err(e);
                            }
                        }
                    }
                    _ => quote,
                };
                let (raw, tx_id, payer) = match &quote.path {
                    SubmitPath::SelfRelay { payer } => {
                        let (raw, id) = sign_tx(
                            &sdk,
                            chain_id,
                            &quote,
                            prepared.t.entry_contract(),
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
                    contract: hex(&prepared.t.entry_contract()),
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
                    gas_limit: payer.as_ref().map(|_| quote.gas_limit),
                    signer_kind: Some(signer),
                    unsigned_len: Some(unsigned_len as u64),
                    members: super::bls_multi::members(&prepared.signer()),
                    ended_at: None,
                    fact: prepared
                        .t
                        .fact
                        .as_ref()
                        .map(|(c, e, h)| (hex(c), (*e).to_string(), hex(h))),
                    message: prepared.t.message.clone(),
                    extra: prepared.t.extra.clone(),
                    basis: None,
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
                // the write ahead: nothing signed has left the SDK yet (ruling A)
                state::put(&sdk, &row).await?;
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
                    // a refused simulation is sent again only by the user's `resend`; a row of another family is its own
                    // module's (review T26 B-8)
                    if row.state == "signed"
                        && row.detail != "SimRefused"
                        && evm(&sdk, &row.chain).is_ok()
                    {
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
    /// gateways. Never re-signed (a self-relay's transaction by a new payer quote is the payer's own new transaction). A
    /// gateway's operation self-relayed: its gas recomputed from the row's stored signed calldata as `submit` does (owner
    /// 2026-11-19, Q5, G3's rule): never below `quote`'s, above `Limits::max_gas` `SignedGasAboveCap`, above the chain's
    /// per-transaction cap `GasAboveTxCap`, a cost above the caps `FeeAboveCap`, nothing written or sent; a row without the
    /// signer's kind and unsigned length (written before Q5): `Argument`.
    pub async fn resend(&self, op: String, quote: SubmitQuote) -> Result<(), SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let mut row = state::row(&sdk, &op).await?;
                if row.state != "signed" && row.state != "sent" {
                    return Err(SdkError::Argument);
                }
                check_quote(&sdk, None, &quote).await?;
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
                        let (Some(signer), Some(unsigned_len)) =
                            (row.signer_kind, row.unsigned_len)
                        else {
                            return Err(SdkError::Argument);
                        };
                        let unsigned_len =
                            usize::try_from(unsigned_len).map_err(|_| SdkError::Argument)?;
                        // PR A review, finding 2: the row's own figure (its entry, kind, signer kind and lane state, from
                        // its stored message and arguments), so a payer's quote of another operation never lowers it
                        let own = {
                            let c = sdk.chain(&row.chain)?;
                            let profile = &c.profile;
                            figure(
                                &sdk,
                                profile,
                                (&row.entry, &row.kind, signer, row.nonce == "0"),
                                &row.extra,
                                &row.message,
                                &fee_of(&row.name, &row.message)?,
                                None,
                                unsigned_len,
                                row.members,
                            )?
                        };
                        // Q5: the gas from the stored signed calldata, before anything is written or sent
                        let quote = signed_quote(
                            &sdk,
                            &row.chain,
                            signer,
                            unsigned_len,
                            &quote,
                            Address::from(to),
                            &unhex(&row.calldata)?,
                            own,
                        )
                        .await?;
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
                        row.gas_limit = Some(quote.gas_limit);
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

/// Runs `f` on as a task of the SDK's runtime, whatever happens to the caller (spec §13.4); on wasm32 a task of the page's event
/// loop (`wasm_bindgen_futures::spawn_local`: no tokio `LocalSet` there; closing review P2-9). After `Sdk::close` nothing
/// starts; a close aborts one in flight and waits for it, natively (on wasm32 it runs to its end: user-profiles review C-8).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn detach(sdk: &Arc<Sdk>, f: impl std::future::Future<Output = ()> + Send + 'static) {
    let _ = sdk.task(f);
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn detach(sdk: &Arc<Sdk>, f: impl std::future::Future<Output = ()> + 'static) {
    if sdk.live().is_ok() {
        wasm_bindgen_futures::spawn_local(f);
    }
}

/// One send of `row`'s bytes on its path; the row then `sent` with the outcome's detail, and the event. A refused simulation
/// sends nothing and leaves the state as it was, with the detail `SimRefused`. A send nothing accepted (review T26 B-6: an
/// error before any post, a simulation that failed in transport, every gateway unreachable) leaves it `signed` with the
/// detail `Signed`, so `resume` sends it again.
pub(crate) async fn send(sdk: &Arc<Sdk>, mut row: Row) {
    let detail = send_once(sdk, &row).await.unwrap_or(InFlight::Signed);
    if detail != InFlight::SimRefused && detail != InFlight::Signed {
        row.state = "sent".into();
    }
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
    // the row's path decides (review T26 B-5): a self-relayed row `resend` moved to the gateways keeps its old transaction
    if let (Some(raw), false) = (&row.raw, row.path == "gateway") {
        // a relayed operation's signed calldata simulated from the payer (ruling 1, after the write ahead: ruling A): a revert,
        // a failed simulation or more gas than the confirmed quote sends nothing
        if row.kind != "native" {
            let from: Address = row
                .payer
                .as_deref()
                .and_then(|p| p.parse().ok())
                .ok_or(SdkError::Internal)?;
            let to = Address::from(super::addr20(&row.contract)?);
            let data = alloy::primitives::Bytes::from(unhex(&row.calldata)?);
            match pool.simulate_from(from, to, data).await {
                Ok(g) if row.gas_limit.is_some_and(|l| g <= l) => {}
                Ok(_) | Err(scaas_rpc::evm::SimError::Revert(_)) => {
                    return Ok(InFlight::SimRefused)
                }
                // review T26 B-6: no answer is no refusal
                Err(e) => return Err(super::sim(e)),
            }
        }
        return Ok(match pool.broadcast(&unhex(raw)?, Fanout::All).await? {
            BroadcastOutcome::Sent { .. } => InFlight::Sent,
            BroadcastOutcome::Rejected { .. } => InFlight::BroadcastRejected,
        });
    }
    let node = kept_gateways(sdk, &row.chain).await?;
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
        // review T26 B-6 (CLI-RPC-09): an unreachable gateway may not have it; every gateway refusing has given it up
        SubmitOutcome::NotQueued { outcomes }
            if outcomes
                .iter()
                .any(|(_, o)| matches!(o, scaas_rpc::node::NodeOutcome::Unreachable(_))) =>
        {
            InFlight::Signed
        }
        SubmitOutcome::NotQueued { .. } => InFlight::GivenUpByEveryNode,
    })
}
