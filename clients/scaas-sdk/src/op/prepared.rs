// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Prepare and review (spec §13.1, CLI-SDK-08): the typed data and its check built by `scaas-ua` from a module's named fields,
//! kept in the SDK's table as an opaque [`Prepared`]; nothing is signed here.
use super::{dec, evm, hex, lane_nonce, KeyRef, Op};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, U256};
use scaas_ua::wallet::entries::entry_rows;
use scaas_ua::wallet::{scaas_typed_data, Expect, TypedData};
use serde_json::{Map, Value};
use std::sync::{Arc, PoisonError};

/// Where a reviewed value comes from (spec §13.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// a field of the signed struct (or committed to by it, as a pay's `PayMeta`), decoded
    Signed,
    /// what the request named and the signed struct holds only in encrypted form (a confidential amount, recipient)
    Request,
    /// what the SDK chose or read: the contract, every token or market touched with its mark
    Derived,
}

/// One reviewed value: its name (a path for a nested field, `payment.value`), the value as signed, its display form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewField {
    pub name: String,
    pub value: String,
    pub display: String,
    pub source: Source,
}

/// A module's check builder: the chain's time and the canonical message give the `scaas-ua` check of what the user confirmed.
pub(crate) type ExpectFn = Box<dyn Fn(u64, &Value) -> Result<Expect, SdkError> + Send + Sync>;

/// What a module's `prepare_<op>` hands to [`Op::prepare`]: one `(struct, domain kind)` row with its named fields.
pub(crate) struct Draft {
    pub chain: String,
    pub name: &'static str,
    pub kind: &'static str,
    pub contract: [u8; 20],
    /// the signed struct by field name; an envelope without `nonce` takes the lane's next nonce, read here
    pub message: Value,
    /// what the entry takes unsigned (`meta`, …)
    pub extra: Value,
    pub signer: KeyRef,
    /// the module's own check (a payment's); `None`: `Expect::Op` over the message, its fee the cap
    pub expect: Option<ExpectFn>,
    /// decoded and request fields the module adds to the review
    pub review: Vec<ReviewField>,
    /// tokens and markets the operation touches besides a token domain's own contract
    pub touched: Vec<[u8; 20]>,
    pub opaque: bool,
    /// the transfer on ids (`mtxExecuteTransfer`, `POST /v1/ua-metatx`; owner 2026-11-18, ruling 6) instead of the row's entry
    pub ids: bool,
    /// a relay fee's paid call: its job `op` and signed calldata (owner 2026-11-19, ruling F)
    pub relay_call: Option<(Value, Vec<u8>)>,
}

/// The parts `submit` needs; never in a record a caller could rebuild.
pub(crate) struct Typed {
    pub name: &'static str,
    pub kind: &'static str,
    pub contract: [u8; 20],
    pub td: TypedData,
    pub expect: Expect,
    /// the canonical message (unbound `relayer` / `feeRecipient` 0)
    pub message: Value,
    pub extra: Value,
    /// the lane: the subject's id bytes, its batch and nonce (`None`: a struct without an envelope)
    pub lane: Option<(Vec<u8>, U256, U256)>,
    /// the transfer on ids
    pub ids: bool,
    /// a relay fee's paid call (job `op`, signed calldata)
    pub relay_call: Option<(Value, Vec<u8>)>,
}

/// A prepared operation (spec §13.1): opaque, kept in the SDK's table; it holds no secret and nothing signed.
pub struct Prepared {
    id: String,
    chain: String,
    entry: String,
    review: Vec<ReviewField>,
    opaque: bool,
    signer: KeyRef,
    expires_at: u64,
    pub(crate) t: Typed,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared").field("id", &self.id).finish()
    }
}

impl Prepared {
    /// The typed digest (`scaas-ua`'s), the node's in-flight key too.
    pub fn id(&self) -> String {
        self.id.clone()
    }
    pub fn chain(&self) -> String {
        self.chain.clone()
    }
    /// The contract function: `mtxPay`, `mtxCancelNonce`, …
    pub fn entry(&self) -> String {
        self.entry.clone()
    }
    pub fn review(&self) -> Vec<ReviewField> {
        self.review.clone()
    }
    /// An undecoded call under `AllowOpaqueCall` (§13.2).
    pub fn opaque(&self) -> bool {
        self.opaque
    }
    pub fn signer(&self) -> KeyRef {
        self.signer.clone()
    }
    /// The operation's `validUntil` (`u64::MAX`: none).
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// The EIP-712 domain's name of a domain kind (`typed_ops.json`'s `domains`).
pub(crate) fn domain_name(kind: &str) -> Result<&'static str, SdkError> {
    Ok(match kind {
        "token" => "SCaaS MetaToken",
        "zether" => "SCaaS ZetherToken",
        "pqz" => "SCaaS PqzToken",
        "wallet" => "SCaaS MandateWallet",
        "account" => "SCaaS SmartKeyAccount",
        "dex" => "SCaaS Dex",
        "gov_router" => "SCaaS GovernanceRouter",
        _ => return Err(SdkError::Argument),
    })
}

/// The envelope's object: the message itself, or its `payment` (`UAPayeeFee`, `UAPayWithTax`).
pub(crate) fn envelope(m: &Value) -> Option<&Map<String, Value>> {
    let has = |o: &Map<String, Value>| {
        o.contains_key("from") && o.contains_key("batch") && o.contains_key("validUntil")
    };
    match m.as_object() {
        Some(o) if has(o) => Some(o),
        Some(o) => o
            .get("payment")
            .and_then(Value::as_object)
            .filter(|p| has(p)),
        None => None,
    }
}

fn envelope_mut(m: &mut Value) -> Option<&mut Map<String, Value>> {
    if m.get("payment").is_some() && m.get("batch").is_none() {
        m.get_mut("payment").and_then(Value::as_object_mut)
    } else {
        m.as_object_mut()
    }
}

/// Every leaf of the signed message, by path.
fn flatten(prefix: &str, v: &Value, out: &mut Vec<ReviewField>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&p, x, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                flatten(&format!("{prefix}[{i}]"), x, out);
            }
        }
        Value::String(s) => out.push(field(prefix, s, s, Source::Signed)),
        other => {
            let s = other.to_string();
            out.push(field(prefix, &s, &s, Source::Signed));
        }
    }
}

pub(crate) fn field(name: &str, value: &str, display: &str, source: Source) -> ReviewField {
    ReviewField {
        name: name.into(),
        value: value.into(),
        display: display.into(),
        source,
    }
}

fn address_of(m: &Map<String, Value>, k: &str) -> Option<[u8; 20]> {
    m.get(k)
        .and_then(Value::as_str)
        .and_then(|s| super::addr20(s).ok())
        .filter(|a| *a != [0; 20])
}

impl Op {
    /// Builds and keeps a [`Prepared`] (spec §13.1): the lane's nonce and the chain's time read, the typed data and its check
    /// built by `scaas-ua`, every field listed for review. `WalletLocked`: the signer's seed is locked; `Argument`: a field the
    /// struct refuses.
    pub(crate) async fn prepare(sdk: &Arc<Sdk>, d: Draft) -> Result<Arc<Prepared>, SdkError> {
        let (profile, chain_id, pool) = evm(sdk, &d.chain)?;
        drop(super::key_opened(sdk, &d.signer).await?); // a locked seed refuses before any read
        let uid: [u8; 32] = super::unhex(&profile.chain_uid)?
            .try_into()
            .map_err(|_| SdkError::Argument)?;
        let mut message = d.message;
        let mut lane = None;
        if let Some(e) = envelope(&message) {
            let from = super::unhex(
                e.get("from")
                    .and_then(Value::as_str)
                    .ok_or(SdkError::Argument)?,
            )?;
            let batch = dec(e.get("batch").ok_or(SdkError::Argument)?)?;
            let nonce = match e.get("nonce") {
                Some(n) => dec(n)?,
                None => lane_nonce(&pool, Address::from(d.contract), d.kind, &from, batch).await?,
            };
            if let Some(e) = envelope_mut(&mut message) {
                e.insert("nonce".into(), Value::String(nonce.to_string()));
            }
            lane = Some((from, batch, nonce));
        }
        let (_, now) = super::head(&pool).await?;
        let td = scaas_typed_data(
            d.name,
            Some(domain_name(d.kind)?),
            &d.contract,
            chain_id,
            &uid,
            &message,
        )?;
        let canonical = td
            .to_value()
            .get("message")
            .cloned()
            .ok_or(SdkError::Internal)?;
        let id = hex(&td.digest()?);
        let env = envelope(&canonical).cloned().unwrap_or_default();
        let mode = env.get("mode").map(dec).transpose()?.unwrap_or_default();
        // the fee the relayer takes, as the check computes it: a PERCENT envelope's `fee` is a rate in millionths of the amount
        // (closing review P2-4); the check's cap and the review's line are this amount
        let due = if env.is_empty() {
            "0".to_string()
        } else {
            scaas_ua::wallet::fee_due(d.name, &canonical)?
        };
        let expect = match &d.expect {
            Some(f) => f(now, &canonical)?,
            None => Expect::Op {
                op: d.name.into(),
                contract: d.contract,
                chain_id,
                chain_uid: uid,
                message: canonical.clone(),
                max_fee: due.clone(),
                fee_recipient: (mode.bit(1))
                    .then(|| address_of(&env, "feeRecipient"))
                    .flatten(),
                relayer: (mode.bit(0)).then(|| address_of(&env, "relayer")).flatten(),
                now,
                max_window: sdk.window(&d.chain),
            },
        };
        let mut review = Vec::new();
        flatten("", &canonical, &mut review);
        review.extend(d.review);
        if !env.is_empty() {
            review.push(field("fee.due", &due, &due, Source::Derived));
        }
        review.push(field(
            "contract",
            &hex(&d.contract),
            &hex(&d.contract),
            Source::Derived,
        ));
        let mut touched = d.touched;
        if matches!(d.kind, "token" | "zether" | "pqz") {
            touched.insert(0, d.contract);
        }
        for t in &touched {
            let a = hex(t);
            let listed = profile
                .tokens
                .iter()
                .find(|l| l.address.eq_ignore_ascii_case(&a));
            let display = listed.map_or("unlisted".to_string(), |l| format!("listed {}", l.symbol));
            review.push(field("token", &a, &display, Source::Derived));
        }
        let entry = match d.ids {
            true if d.name == "UAMetaTransfer" => "mtxExecuteTransfer".to_string(),
            true => return Err(SdkError::Argument),
            false => entry_rows()
                .into_iter()
                .find(|r| r.name == d.name && r.kinds.contains(&d.kind))
                .map(|r| r.entry.to_string())
                .ok_or(SdkError::Argument)?,
        };
        let expires_at = env
            .get("validUntil")
            .map(dec)
            .transpose()?
            .map_or(u64::MAX, |v| u64::try_from(v).unwrap_or(u64::MAX));
        // the signing window on the SDK's clock (T13b ruling 1): not already past, not further than the chain's window, so an
        // endpoint's clock cannot stretch a signature's life
        if env.contains_key("validUntil") {
            let wall = sdk.now();
            if expires_at <= wall || expires_at > wall.saturating_add(sdk.window(&d.chain)) {
                return Err(SdkError::ValidUntilRefused);
            }
        }
        let p = Arc::new(Prepared {
            id: id.clone(),
            chain: d.chain,
            entry,
            review,
            opaque: d.opaque,
            signer: d.signer,
            expires_at,
            t: Typed {
                name: d.name,
                kind: d.kind,
                contract: d.contract,
                td,
                expect,
                message: canonical,
                extra: d.extra,
                lane,
                ids: d.ids,
                relay_call: d.relay_call,
            },
        });
        let mut table = sdk.prepared.lock().unwrap_or_else(PoisonError::into_inner);
        // the table holds what can still be submitted: one past its `validUntil` on the chain's clock is `PreparedStale` anyway
        // (closing review P3: the table no longer grows without bound)
        table.retain(|_, q| q.expires_at > now);
        table.insert(id, p.clone());
        Ok(p)
    }

    /// `p` if it is the one this SDK keeps under its id (`PreparedUnknown` otherwise).
    pub(crate) fn known(sdk: &Sdk, p: &Arc<Prepared>) -> Result<(), SdkError> {
        let t = sdk.prepared.lock().unwrap_or_else(PoisonError::into_inner);
        match t.get(&p.id) {
            Some(q) if Arc::ptr_eq(q, p) => Ok(()),
            _ => Err(SdkError::PreparedUnknown),
        }
    }
}
