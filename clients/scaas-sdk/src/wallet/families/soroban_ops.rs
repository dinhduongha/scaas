// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Soroban's operations and its Native column (plan 2026-11-17-scaas-sdk T41.soroban, with T29.soroban and T30.soroban; spec
//! §27.3 (d), §27.5; docs/networks/soroban.md NET-SOR-01, NET-SOR-02, NET-SOR-09, NET-SOR-12, NET-SOR-15). A `G…` subject's
//! host authorization of a token entry (`transfer`, `pay`, `burn`) is prepared from named fields, reviewed, signed once by
//! `scaas-ua`'s own builder (`families::soroban::check_terms`), written ahead, and sent either through the gateways' `/v1/ops`
//! or as a self-relay: the payer's own `G…` sends the native transaction (`wallet::soroban_tx`), simulated first (the record
//! mode for an op not yet signed, the enforcing mode once it is), its fee under `Limits::max_native_cost`. A hand-off gives the
//! signed op to its payee, who imports it with every check in its order and self-relays it. The Native column: a `Payment` of
//! XLM on the same builder. Following is by chain facts: the payer's transaction by its local id, the op by its host nonce
//! (and a pay's `pay_ref`) entries. Every read goes through the profile's list (failover; `strict_majority` compares the
//! others). The SDK builds ledger keys (an encoding) and hashes nothing (CLI-SDK-01). UNAUDITED.
use super::read_set;
use super::soroban::{account_key, failed, holder, Holder, ACCOUNT_MAX};
use crate::op::state::{self, Row};
use crate::vault::OpenSeed;
use crate::wallet::native::{derive, NativeKeyRef};
use crate::wallet::Wallet;
use crate::{Chain, FamilyParams, Sdk, SdkError};
use scaas_rpc::pool::ReadError;
use scaas_rpc::soroban::{Broadcast, Simulation, Soroban, TxStatus};
use scaas_rpc::{EndpointFailure, FailureKind, RpcError};
use scaas_ua::families::soroban::{
    check_terms, network_id, pay_nonce, signed_op, Checked, OpFields, OpKind, Shown, Terms,
};
use scaas_ua::wallet::soroban_tx::{SorobanData, SorobanTx, TxOp};
use scaas_ua::wallet::NativeKey;
use serde_json::{json, Value};
use std::sync::Arc;

/// The node's margin on a simulation's resource fee (`RESOURCE_FEE_MARGIN_PCT`), kept here.
const MARGIN_PCT: u64 = 15;
/// The node's 120 s: an imported op must stay valid at least this long (spec §27.5 (c)); on Soroban a ledger closes at most
/// once a second, so as many ledgers bound the auth entry's expiry.
const IMPORT_MARGIN_SECS: u64 = 120;
/// A native transaction's time bound at most this far ahead (NET-SOR-15's hour): a lost one holds its source's sequence.
const TX_WINDOW_SECS: u64 = 3_600;
/// A hand-off blob's bounds (spec §27.5 (c)).
pub const BLOB_MAX: usize = 256 << 10;
pub const BLOB_DEPTH: usize = 8;

/// A Soroban op's entry and its own fields (amounts: canonical decimals of the token's units).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SorobanOpKind {
    Transfer {
        to: String,
        amount: String,
    },
    /// `pay_ref`: `0x` + 64 hex, once per `(from, pay_ref)` (NET-SOR-09)
    Pay {
        to: String,
        amount: String,
        pay_ref: String,
    },
    Burn {
        amount: String,
    },
}

/// A request to prepare an op of the `G…` `subject` (a `stellar` key) on the listed token `contract`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorobanOpRequest {
    pub chain: String,
    pub subject: NativeKeyRef,
    pub contract: String,
    pub kind: SorobanOpKind,
    /// unix seconds: a pay's signed `valid_until`, every kind's auth expiry
    pub valid_until: u64,
}

/// A prepared op as the user reviews it: every signed field named. `signature` is set once it is signed (an import, a resend):
/// then nothing is signed again for it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorobanPrepared {
    pub chain: String,
    pub contract: String,
    /// `transfer`, `pay`, `burn`
    pub entry: String,
    pub from: String,
    pub to: Option<String>,
    pub amount: String,
    pub pay_ref: Option<String>,
    pub valid_until: u64,
    /// the host nonce (an `i64`, decimal) and the auth entry's expiry ledger
    pub nonce: String,
    pub expiry: u32,
    /// the key that signs it; `None` for an imported op
    pub subject: Option<NativeKeyRef>,
    /// `0x` + 128 hex
    pub signature: Option<String>,
    /// unbound on Soroban (the host does not bind the transaction's source, spec §27.5 (f) 1): whoever holds a signed op can land
    /// it, to its named payee, until `valid_until`
    pub relayer_bound: bool,
    /// the row this op continues (a resend), else `None`
    pub op: Option<String>,
}

/// How a Soroban op reaches the chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SorobanPath {
    /// the profile's gateways (`POST /v1/ops`), the same body to each
    Gateway,
    /// the payer's own `G…` (a `stellar` key) sends the native transaction and pays its fee
    SelfRelay { payer: NativeKeyRef },
}

/// A native transaction's cost (spec §27.5 (e)), decimal strings of the chain's smallest unit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCost {
    /// `stroop`
    pub unit: String,
    /// the inclusion fee and the resource fee with the margin (Soroban's rent of new entries is inside the resource fee, its
    /// refundable part back to the payer)
    pub fee: String,
    pub storage: String,
    /// where storage goes back: `in-fee` on Soroban
    pub storage_refund: String,
    pub forward: String,
    pub max_cost: String,
    /// the transaction's own bound: its `max_time` (unix seconds)
    pub expires: String,
}

/// A quote the user confirms; `soroban_submit` takes exactly it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorobanQuote {
    pub path: SorobanPath,
    /// the payer's `G…` (a self-relay): linked on chain to the op
    pub payer: Option<String>,
    pub native: Option<NativeCost>,
    /// the gateways the body goes to
    pub gateways: Vec<u32>,
    /// the payer's sequence + 1 (decimal), the inclusion fee per operation, the transaction's `max_time`
    pub seq: Option<String>,
    pub inclusion_fee: u64,
    pub max_time: u64,
}

/// A signed op handed to its payee (spec §27.5 (c)): named fields only, no secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOpBlob {
    pub v: u32,
    pub chain_uid: String,
    pub family: String,
    pub contract: String,
    pub entry: String,
    /// the `signed_op`'s named `payload` (`{nonce, expiry, invocation}`)
    pub op: OpPayload,
    /// `0x` + 128 hex
    pub signature: String,
    /// the subject (`G…`)
    pub signer: String,
}

/// A `signed_op` payload by name (docs/node/job-api.md#soroban-signed-op).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpPayload {
    pub nonce: String,
    pub expiry: u32,
    pub invocation: Invocation,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub contract: String,
    pub function: String,
    pub args: Vec<Arg>,
    pub sub_invocations: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arg {
    #[serde(rename = "type")]
    pub ty: String,
    pub value: Value,
}

impl SignedOpBlob {
    /// A blob from its JSON: at most [`BLOB_MAX`] bytes and [`BLOB_DEPTH`] deep, every field known (`Argument`).
    pub fn from_json(text: &str) -> Result<SignedOpBlob, SdkError> {
        if text.len() > BLOB_MAX {
            return Err(SdkError::Argument);
        }
        scaas_ua::json::depth_within(text.as_bytes(), BLOB_DEPTH)
            .map_err(|_| SdkError::Argument)?;
        serde_json::from_str(text).map_err(|_| SdkError::Argument)
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A hand-off: the signer's row (followed by [`Wallet::soroban_follow`]) and the blob for the payee.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandOff {
    pub op: String,
    pub blob: SignedOpBlob,
}

/// What the importer expects: its chain and its own ids (`G…`), one of which a payment's `to` must be.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportExpect {
    pub chain: String,
    pub payee: Vec<String>,
}

/// A native XLM send (the Native column): `amount` stroops from `key`'s `G…` to the existing account `to`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorobanNativeSend {
    pub chain: String,
    pub key: NativeKeyRef,
    pub to: String,
    pub amount: String,
}

/// A native send as reviewed and quoted; `soroban_submit_native_send` signs exactly these.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SorobanNativeQuote {
    pub chain: String,
    pub key: NativeKeyRef,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub seq: String,
    pub fee: u64,
    pub max_time: u64,
    pub native: NativeCost,
}

// ---------------------------------------------------------------- the chain, the reads

/// The profile's Soroban client, its network id and passphrase (`Argument`: not a Soroban profile).
fn soroban(c: &Chain) -> Result<(&Soroban, [u8; 32], &str), SdkError> {
    let (sor, _) = c.soroban.as_ref().ok_or(SdkError::Argument)?;
    let Some(FamilyParams::Soroban { passphrase, .. }) = &c.profile.family_params else {
        return Err(SdkError::Argument);
    };
    Ok((sor.as_ref(), network_id(passphrase), passphrase))
}

fn malformed(i: usize, why: &str) -> ReadError {
    ReadError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
}

/// The latest ledger, failed over.
async fn latest(sor: &Soroban) -> Result<u64, SdkError> {
    let a = sor
        .client
        .failover(sor, |i| async move {
            sor.latest_ledger(i)
                .await
                .map(|l| l.sequence)
                .map_err(|e| failed(i, e))
        })
        .await?;
    Ok(a.value)
}

/// `keys`' entries at one ledger (read by [`read_set`]): the ledger and each entry's XDR, `None` where absent. An archived entry
/// (`liveUntilLedgerSeq` below the ledger) is the endpoint's failure (NET-SOR-22).
async fn entries(sor: &Soroban, keys: &[Vec<u8>]) -> Result<(u64, Vec<Option<Vec<u8>>>), SdkError> {
    let at = |i: usize, floor: u64| async move {
        let (l, e) = sor.entries_at(i, keys).await.map_err(|e| failed(i, e))?;
        if l < floor {
            return Err(malformed(i, "a ledger behind the set's"));
        }
        if e.iter()
            .flatten()
            .any(|x| x.live_until.is_some_and(|t| t < l))
        {
            return Err(malformed(i, "an archived entry"));
        }
        Ok((
            l,
            e.into_iter().map(|x| x.map(|x| x.xdr)).collect::<Vec<_>>(),
        ))
    };
    read_set(
        &sor.client,
        sor,
        |i| at(i, 0),
        |j, l| async move { at(j, l).await.map(|(_, v)| v) },
    )
    .await
}

/// A `G…`'s balance and sequence from its account entry: the key's 40 bytes, then `balance` and `seqNum` (`i64` each);
/// `Argument` for an account that does not exist.
async fn account(sor: &Soroban, g: &[u8; 32]) -> Result<(i64, i64), SdkError> {
    let key = account_key(g);
    let (_, e) = entries(sor, std::slice::from_ref(&key)).await?;
    let x = e.into_iter().next().flatten().ok_or(SdkError::Argument)?;
    let num = |r: std::ops::Range<usize>| {
        x.get(r)
            .and_then(|b| b.try_into().ok())
            .map(i64::from_be_bytes)
    };
    match (
        x.len() <= ACCOUNT_MAX && x.get(..40) == Some(key.as_slice()),
        num(40..48),
        num(48..56),
    ) {
        (true, Some(b), Some(s)) if b >= 0 && s >= 0 => Ok((b, s)),
        _ => Err(SdkError::Rpc(RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        })),
    }
}

/// The inclusion fee per operation: Soroban's (`soroban`) or the others' (`getFeeStats`' 90th percentile).
async fn inclusion_fee(sor: &Soroban, soroban: bool) -> Result<u64, SdkError> {
    let at = |i: usize| async move {
        let (s, c) = sor.fee_stats_at(i).await.map_err(|e| failed(i, e))?;
        Ok(if soroban { s } else { c })
    };
    let (_, f) = read_set(
        &sor.client,
        sor,
        |i| async move { at(i).await.map(|f| (0, f)) },
        |j, _| at(j),
    )
    .await?;
    Ok(f)
}

/// The simulation of `envelope` (read by [`read_set`]; under `strict_majority` the others must give the same answer).
async fn simulate(sor: &Soroban, envelope: &[u8]) -> Result<Simulation, SdkError> {
    let at = |i: usize| async move { sor.simulate_at(i, envelope).await.map_err(|e| failed(i, e)) };
    let (_, s) = read_set(&sor.client, sor, at, |j, _| async move {
        at(j).await.map(|(_, s)| s)
    })
    .await?;
    Ok(s)
}

/// The host nonce key of the op (NET-SOR-12) and, for a pay, its `PayRef(from, pay_ref)` key (NET-SOR-09): `LedgerKey`s.
pub(crate) fn spent_keys(c: &Checked) -> Vec<Vec<u8>> {
    let from = Holder::Account(account_holder(&c.from()));
    let mut nonce = vec![0, 0, 0, 6];
    sc_address(&mut nonce, &from);
    nonce.extend_from_slice(&[0, 0, 0, 21]);
    nonce.extend_from_slice(&c.nonce().to_be_bytes());
    nonce.extend_from_slice(&[0, 0, 0, 0]); // temporary
    let mut keys = vec![nonce];
    if let Some(r) = c.pay_ref() {
        let mut k = vec![0, 0, 0, 6];
        sc_address(&mut k, &Holder::Contract(contract_id(&c.contract())));
        k.extend_from_slice(&[0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 3]); // Vec of three
        k.extend_from_slice(&[0, 0, 0, 15, 0, 0, 0, 6]);
        k.extend_from_slice(b"PayRef\0\0");
        k.extend_from_slice(&[0, 0, 0, 18]);
        sc_address(&mut k, &from);
        k.extend_from_slice(&[0, 0, 0, 13, 0, 0, 0, 32]);
        k.extend_from_slice(&r);
        k.extend_from_slice(&[0, 0, 0, 1]); // persistent
        keys.push(k);
    }
    keys
}

fn sc_address(v: &mut Vec<u8>, h: &Holder) {
    match h {
        Holder::Account(k) => {
            v.extend_from_slice(&[0; 8]);
            v.extend_from_slice(k);
        }
        Holder::Contract(k) | Holder::Ua(k) => {
            v.extend_from_slice(&[0, 0, 0, 1]);
            v.extend_from_slice(k);
        }
    }
}

fn account_holder(g: &str) -> [u8; 32] {
    match holder(g) {
        Some(Holder::Account(k)) => k,
        _ => [0; 32],
    }
}

fn contract_id(c: &str) -> [u8; 32] {
    match holder(c) {
        Some(Holder::Contract(k)) => k,
        _ => [0; 32],
    }
}

/// The op is spent at the latest ledger: its nonce or its pay's `pay_ref` entry exists.
async fn spent(sor: &Soroban, c: &Checked) -> Result<bool, SdkError> {
    let (_, e) = entries(sor, &spent_keys(c)).await?;
    Ok(e.iter().any(Option::is_some))
}

/// `chain`'s native cost cap (`FeeAboveCap` without one: no native spend).
fn cap(sdk: &Sdk, chain: &str) -> Result<u64, SdkError> {
    let c = sdk
        .limits
        .max_native_cost
        .iter()
        .find(|c| c.chain == chain)
        .ok_or(SdkError::FeeAboveCap)?;
    c.max.parse().map_err(|_| SdkError::Argument)
}

fn cost(fee: u64, max_time: u64) -> NativeCost {
    NativeCost {
        unit: "stroop".into(),
        fee: fee.to_string(),
        storage: "0".into(),
        storage_refund: "in-fee".into(),
        forward: "0".into(),
        max_cost: fee.to_string(),
        expires: max_time.to_string(),
    }
}

/// A `stellar` key of the seed (kept beside its open seed) and its `G…`.
fn stellar(sdk: &Sdk, k: &NativeKeyRef) -> Result<(Arc<OpenSeed>, NativeKey, [u8; 32]), SdkError> {
    if k.network != "stellar" {
        return Err(SdkError::Argument);
    }
    let (s, key) = derive(sdk, k)?;
    let pk: [u8; 32] = key
        .public_key()
        .try_into()
        .map_err(|_| SdkError::Argument)?;
    Ok((s, key, pk))
}

fn g_of(pk: &[u8; 32]) -> String {
    scaas_ua::families::soroban::Address::Account(*pk).text()
}

/// A row's `extra` field (`Null` when absent).
fn ex<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}

fn put(v: &mut Value, k: &str, x: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(k.into(), x);
    }
}

fn hex(b: &[u8]) -> String {
    crate::text::hex(b)
}

// ---------------------------------------------------------------- the checked op

/// The op's terms and what is shown, from a prepared op on its chain's passphrase.
fn checked(
    p: &SorobanPrepared,
    passphrase: &str,
    ledger: u32,
    window: u32,
) -> Result<Checked, SdkError> {
    let pay_ref = p.pay_ref.as_deref().map(crate::text::unhex).transpose()?;
    let terms = Terms {
        network_id: network_id(passphrase),
        contract: p.contract.clone(),
        kind: p.entry.clone(),
        fields: OpFields {
            from: p.from.clone(),
            to: p.to.clone(),
            amount: p.amount.clone(),
            pay_ref,
            valid_until: (p.entry == "pay").then_some(p.valid_until),
            extra: vec![],
        },
        nonce: p.nonce.parse::<i128>().map_err(|_| SdkError::Argument)?,
        expiry: i64::from(p.expiry),
        ledger,
        window,
    };
    let shown = Shown {
        passphrase: passphrase.into(),
        contract: p.contract.clone(),
        kind: p.entry.clone(),
        from: p.from.clone(),
        to: p.to.clone(),
        amount: p.amount.clone(),
    };
    Ok(check_terms(&terms, &shown)?)
}

/// [`checked`] of an op whose window was checked when it was prepared or imported: its own expiry the ledger, no window.
fn rebuilt(p: &SorobanPrepared, passphrase: &str) -> Result<Checked, SdkError> {
    checked(p, passphrase, p.expiry, 0)
}

fn listed(c: &Chain, contract: &str) -> Result<(), SdkError> {
    if c.profile.tokens.iter().any(|t| t.address == contract) {
        Ok(())
    } else {
        Err(SdkError::ProfileMismatch)
    }
}

fn signature(p: &SorobanPrepared) -> Result<Option<[u8; 64]>, SdkError> {
    p.signature
        .as_deref()
        .map(|s| {
            crate::text::unhex(s)?
                .try_into()
                .map_err(|_| SdkError::Argument)
        })
        .transpose()
}

fn new_id() -> Result<String, SdkError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| SdkError::Internal)?;
    Ok(format!("sor-{}", hex(&b).trim_start_matches("0x")))
}

fn row_of(p: &SorobanPrepared, c: &Checked, id: &str, path: &str, state: &str) -> Row {
    Row {
        op: id.into(),
        chain: p.chain.clone(),
        entry: p.entry.clone(),
        name: "soroban".into(),
        kind: "token".into(),
        contract: p.contract.clone(),
        from: p.from.clone(),
        batch: String::new(),
        nonce: p.nonce.clone(),
        valid_until: p.valid_until,
        digest: hex(&c.digest()),
        op_json: Value::Null,
        calldata: String::new(),
        raw: None,
        tx_id: None,
        tx_nonce: None,
        path: path.into(),
        payer: None,
        from_block: 0,
        state: state.into(),
        detail: String::new(),
        landed: None,
        relayer_bound: false,
        gas_limit: None,
        signer_kind: None,
        unsigned_len: None,
        members: None,
        ended_at: None,
        message: c.payload_json(),
        extra: json!({"expiry": p.expiry, "pay_ref": p.pay_ref, "to": p.to, "amount": p.amount}),
        fact: None,
    }
}

/// The transaction of a self-relay of `c` (signed by `sig` when given; `data` its simulation's).
fn invoke(
    payer: &[u8; 32],
    fee: u64,
    seq: i64,
    max_time: u64,
    c: &Checked,
    sig: Option<[u8; 64]>,
    data: Option<SorobanData>,
) -> SorobanTx {
    SorobanTx {
        source: g_of(payer),
        fee,
        seq: i128::from(seq),
        min_time: 0,
        max_time,
        op: TxOp::Invoke {
            op: Some(c.clone()),
            signature: sig,
            data,
        },
    }
}

/// A simulation's data with the node's margin, and the transaction's whole fee: `inclusion + resource × 1.15` (`FeeAboveCap`
/// past a `u32`). The recorded auth must be the subject's one entry.
fn priced(
    sim: Simulation,
    c: &Checked,
    inclusion: u64,
    imported: bool,
) -> Result<(SorobanData, u64), SdkError> {
    let refused = |reason: String| {
        if imported {
            SdkError::ImportedOpRefused
        } else {
            SdkError::Rpc(RpcError::Revert {
                endpoint: 0,
                data: vec![],
                reason,
            })
        }
    };
    let (d, auth) = match sim {
        Simulation::Refused { reason } => return Err(refused(reason)),
        Simulation::Restore => return Err(refused("archived entries need a restore first".into())),
        Simulation::Ok { data, auth, .. } => (data, auth),
    };
    let mut want = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    want.extend_from_slice(&account_holder(&c.from()));
    if auth.len() != 1
        || auth
            .first()
            .and_then(|a| scaas_rpc::soroban::auth_signer(a))
            != Some(want.as_slice())
    {
        return Err(refused(
            "the call needs a signer other than the op's subject".into(),
        ));
    }
    let fee = u64::try_from(d.resource_fee).map_err(|_| SdkError::Argument)?;
    let resource = fee
        .checked_add(fee.saturating_mul(MARGIN_PCT) / 100)
        .ok_or(SdkError::FeeAboveCap)?;
    let total = resource
        .checked_add(inclusion)
        .filter(|t| *t <= u64::from(u32::MAX))
        .ok_or(SdkError::FeeAboveCap)?;
    let data = SorobanData {
        read_only: d.read_only,
        read_write: d.read_write,
        instructions: d.instructions,
        disk_read_bytes: d.disk_read_bytes,
        write_bytes: d.write_bytes,
        resource_fee: i64::try_from(resource).map_err(|_| SdkError::FeeAboveCap)?,
        archived: d.archived,
    };
    Ok((data, total))
}

// ---------------------------------------------------------------- the calls

impl Wallet {
    /// Prepares a `G…` subject's op (T29.soroban): the token listed (`ProfileMismatch`), `valid_until` within the chain's window
    /// (`ValidUntilRefused`), the subject a `stellar` key; the expiry ledger read now (`latest + (valid_until − now)`: a ledger
    /// closes at most once a second, so it never expires first); the nonce NET-SOR-02's for a pay, else from the OS. The fields
    /// pass `scaas-ua`'s `check_terms` before anything is returned.
    pub async fn soroban_prepare(
        &self,
        req: SorobanOpRequest,
    ) -> Result<SorobanPrepared, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&req.chain)?;
                let (sor, _, passphrase) = soroban(c)?;
                listed(c, &req.contract)?;
                let now = sdk.now();
                let window = c
                    .profile
                    .max_valid_secs
                    .unwrap_or(sdk.limits.max_valid_secs);
                if req.valid_until <= now || req.valid_until - now > window {
                    return Err(SdkError::ValidUntilRefused);
                }
                let (_, _, pk) = stellar(&sdk, &req.subject)?;
                let (entry, to, amount, pay_ref) = match &req.kind {
                    SorobanOpKind::Transfer { to, amount } => {
                        ("transfer", Some(to.clone()), amount.clone(), None)
                    }
                    SorobanOpKind::Pay {
                        to,
                        amount,
                        pay_ref,
                    } => (
                        "pay",
                        Some(to.clone()),
                        amount.clone(),
                        Some(pay_ref.clone()),
                    ),
                    SorobanOpKind::Burn { amount } => ("burn", None, amount.clone(), None),
                };
                let nonce = match &pay_ref {
                    Some(r) => {
                        let r: [u8; 32] = crate::text::unhex(r)?
                            .try_into()
                            .map_err(|_| SdkError::Argument)?;
                        pay_nonce(&r, req.valid_until)
                    }
                    None => {
                        let mut b = [0u8; 8];
                        getrandom::getrandom(&mut b).map_err(|_| SdkError::Internal)?;
                        i64::from_be_bytes(b)
                    }
                };
                let ledger = u32::try_from(latest(sor).await?).map_err(|_| SdkError::Argument)?;
                let ahead = u32::try_from(req.valid_until - now)
                    .map_err(|_| SdkError::ValidUntilRefused)?;
                let p = SorobanPrepared {
                    chain: req.chain,
                    contract: req.contract,
                    entry: entry.into(),
                    from: g_of(&pk),
                    to,
                    amount,
                    pay_ref,
                    valid_until: req.valid_until,
                    nonce: nonce.to_string(),
                    expiry: ledger
                        .checked_add(ahead)
                        .ok_or(SdkError::ValidUntilRefused)?,
                    subject: Some(req.subject),
                    signature: None,
                    relayer_bound: false,
                    op: None,
                };
                checked(&p, passphrase, ledger, ahead)?;
                Ok(p)
            })
            .await
    }

    /// The quote of `p` on `path`: the gateways (none: `SubmitPathNone`), or a self-relay by `payer`: its sequence + 1, the
    /// inclusion fee, and the simulation of the transaction (the record mode for an op not yet signed: no signature at quote
    /// time; the enforcing mode for a signed one: an imported op's refusal is `ImportedOpRefused`), its fee with the margin under
    /// `Limits::max_native_cost` (`FeeAboveCap`).
    pub async fn soroban_quote(
        &self,
        p: SorobanPrepared,
        path: SorobanPath,
    ) -> Result<SorobanQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&p.chain)?;
                let (sor, _, passphrase) = soroban(c)?;
                let op = rebuilt(&p, passphrase)?;
                let max_time = p.valid_until.min(sdk.now().saturating_add(TX_WINDOW_SECS));
                let SorobanPath::SelfRelay { payer } = &path else {
                    let n = c.profile.gateways.len();
                    if n == 0 {
                        return Err(SdkError::SubmitPathNone);
                    }
                    return Ok(SorobanQuote {
                        path,
                        payer: None,
                        native: None,
                        gateways: (0..n as u32).collect(),
                        seq: None,
                        inclusion_fee: 0,
                        max_time,
                    });
                };
                let (_, _, pk) = stellar(&sdk, payer)?;
                let (_, seq) = account(sor, &pk).await?;
                let seq = seq.checked_add(1).ok_or(SdkError::Argument)?;
                let inclusion = inclusion_fee(sor, true).await?;
                let sig = signature(&p)?;
                let env = invoke(&pk, 0, seq, max_time, &op, sig, None).unsigned_envelope()?;
                let (_, fee) = priced(simulate(sor, &env).await?, &op, inclusion, sig.is_some())?;
                if fee > cap(&sdk, &p.chain)? {
                    return Err(SdkError::FeeAboveCap);
                }
                Ok(SorobanQuote {
                    path,
                    payer: Some(g_of(&pk)),
                    native: Some(cost(fee, max_time)),
                    gateways: vec![],
                    seq: Some(seq.to_string()),
                    inclusion_fee: inclusion,
                    max_time,
                })
            })
            .await
    }

    /// Submits `p` as quoted in `q`: the op signed once (an op signed already is never signed again), the row written ahead, then
    /// sent: through the gateways (`/v1/ops`, every gateway), or as the payer's transaction, simulated again with the signed
    /// entry (its fee at most the quote's, else `FeeAboveCap`), signed by the payer, broadcast to every endpoint. Returns the
    /// row's id; following is [`Wallet::soroban_follow`]'s.
    pub async fn soroban_submit(
        &self,
        p: SorobanPrepared,
        q: SorobanQuote,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&p.chain)?;
                let (sor, nid, passphrase) = soroban(c)?;
                let op = rebuilt(&p, passphrase)?;
                let sig = match signature(&p)? {
                    Some(s) => s,
                    None => {
                        let k = p.subject.as_ref().ok_or(SdkError::Argument)?;
                        stellar(&sdk, k)?.1.sign_soroban_auth(&op)?
                    }
                };
                let id = match &p.op {
                    Some(id) => id.clone(),
                    None => new_id()?,
                };
                let mut row = match &p.op {
                    Some(id) => state::row(&sdk, id).await?,
                    None => row_of(&p, &op, &id, "gateway", "signed"),
                };
                put(&mut row.extra, "signature", json!(hex(&sig)));
                put(&mut row.extra, "subject", json!(p.subject));
                match &q.path {
                    SorobanPath::Gateway => {
                        let list = c.gateways.clone().ok_or(SdkError::SubmitPathNone)?;
                        let body = signed_op(&op, &sig, q.max_time);
                        row.op_json = body.clone();
                        row.path = "gateway".into();
                        state::put(&sdk, &row).await?;
                        let nodes = scaas_rpc::node::NodeClient::new(list)?;
                        let out = nodes
                            .submit_ops(&c.profile.key, &body, scaas_rpc::endpoint::Fanout::All)
                            .await?;
                        row.state = "sent".into();
                        row.detail = match out {
                            scaas_rpc::node::SubmitOutcome::Queued { .. } => "queued".into(),
                            scaas_rpc::node::SubmitOutcome::NotQueued { .. } => "not_queued".into(),
                        };
                    }
                    SorobanPath::SelfRelay { payer } => {
                        let (_seed, key, pk) = stellar(&sdk, payer)?;
                        if q.payer.as_deref() != Some(g_of(&pk).as_str()) {
                            return Err(SdkError::Argument);
                        }
                        let seq: i64 = q
                            .seq
                            .as_deref()
                            .ok_or(SdkError::Argument)?
                            .parse()
                            .map_err(|_| SdkError::Argument)?;
                        let quoted: u64 = q
                            .native
                            .as_ref()
                            .ok_or(SdkError::Argument)?
                            .fee
                            .parse()
                            .map_err(|_| SdkError::Argument)?;
                        let env = invoke(&pk, 0, seq, q.max_time, &op, Some(sig), None)
                            .unsigned_envelope()?;
                        let (data, fee) = priced(
                            simulate(sor, &env).await?,
                            &op,
                            q.inclusion_fee,
                            p.signature.is_some(),
                        )?;
                        if fee > quoted || fee > cap(&sdk, &p.chain)? {
                            return Err(SdkError::FeeAboveCap);
                        }
                        let tx = invoke(&pk, fee, seq, q.max_time, &op, Some(sig), Some(data));
                        let signed = key.sign_soroban_tx(&nid, &tx)?;
                        row.path = "self".into();
                        row.payer = Some(g_of(&pk));
                        row.raw = Some(hex(&signed.envelope));
                        row.tx_id = Some(hex(&signed.hash));
                        row.tx_nonce = u64::try_from(seq).ok();
                        put(&mut row.extra, "max_time", json!(q.max_time));
                        row.state = "signed".into();
                        state::put(&sdk, &row).await?;
                        let b = sor
                            .send(
                                &nid,
                                &signed.tx,
                                &[(signed.hint, signed.signature)],
                                scaas_rpc::endpoint::Fanout::All,
                            )
                            .await?;
                        row.state = "sent".into();
                        row.detail = match b {
                            Broadcast::Sent { .. } => "accepted".into(),
                            Broadcast::Rejected { .. } => "rejected".into(),
                        };
                    }
                }
                state::put(&sdk, &row).await?;
                Ok(id)
            })
            .await
    }

    /// The signer's hand-off (spec §27.5 (c)): signs `p` once, writes its row ahead (`handed_off`), returns the blob; nothing is
    /// sent; its row's id beside it. On Soroban the blob is unbound (`relayer_bound` false): whoever holds it can land it, to its named payee only.
    pub async fn soroban_hand_off(&self, p: SorobanPrepared) -> Result<HandOff, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&p.chain)?;
                let (_, _, passphrase) = soroban(c)?;
                if p.signature.is_some() || p.op.is_some() {
                    return Err(SdkError::Argument);
                }
                let op = rebuilt(&p, passphrase)?;
                let k = p.subject.as_ref().ok_or(SdkError::Argument)?;
                let sig = stellar(&sdk, k)?.1.sign_soroban_auth(&op)?;
                let id = new_id()?;
                let mut row = row_of(&p, &op, &id, "handed_off", "handed_off");
                put(&mut row.extra, "signature", json!(hex(&sig)));
                state::put(&sdk, &row).await?;
                let payload: OpPayload =
                    serde_json::from_value(op.payload_json()).map_err(|_| SdkError::Internal)?;
                let blob = SignedOpBlob {
                    v: 1,
                    chain_uid: c.profile.chain_uid.clone(),
                    family: "soroban".into(),
                    contract: p.contract,
                    entry: p.entry,
                    op: payload,
                    signature: hex(&sig),
                    signer: p.from,
                };
                Ok(HandOff { op: id, blob })
            })
            .await
    }

    /// The payee's import (spec §27.5 (c)), each check in its order: the blob's chain and family the profile's
    /// (`ProfileMismatch`); the contract a listed token, the invocation's own (`ProfileMismatch`); the entry one this SDK can
    /// show and simulate (`ImportKindRefused`); a payment's `to` one of `expect.payee` (`ImportNotPayee`); no relayer field
    /// (Soroban binds none) and no fee field (Soroban's ops carry none); the expiry at least 120 s ahead (`ImportExpired`); the
    /// nonce and a pay's `pay_ref` unspent (`ImportConsumed`); then `scaas-ua` rebuilds the signed bytes from the named fields.
    /// The signature is the chain's to judge: the quote's simulation (`ImportedOpRefused`).
    pub async fn soroban_import(
        &self,
        blob: SignedOpBlob,
        expect: ImportExpect,
    ) -> Result<SorobanPrepared, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&expect.chain)?;
                let (sor, _, passphrase) = soroban(c)?;
                if blob.v != 1 || blob.family != "soroban" || blob.chain_uid != c.profile.chain_uid
                {
                    return Err(SdkError::ProfileMismatch);
                }
                let inv = &blob.op.invocation;
                listed(c, &blob.contract)?;
                if inv.contract != blob.contract {
                    return Err(SdkError::ProfileMismatch);
                }
                let kind = OpKind::from_name(&inv.function)
                    .filter(|_| inv.function == blob.entry && inv.sub_invocations.is_empty());
                let Some(kind) = kind else {
                    return Err(SdkError::ImportKindRefused);
                };
                let want: &[&str] = match kind {
                    OpKind::Transfer => &["Address", "Address", "i128"],
                    OpKind::Pay => &["Address", "Address", "i128", "BytesN<32>", "u64"],
                    OpKind::Burn => &["Address", "i128"],
                };
                if inv
                    .args
                    .iter()
                    .map(|a| a.ty.as_str())
                    .ne(want.iter().copied())
                {
                    return Err(SdkError::Argument);
                }
                let text = |n: usize| {
                    inv.args
                        .get(n)
                        .and_then(|a| a.value.as_str())
                        .map(str::to_string)
                        .ok_or(SdkError::Argument)
                };
                let from = text(0)?;
                if from != blob.signer {
                    return Err(SdkError::Argument);
                }
                let (to, amount) = if kind.has_payee() {
                    (Some(text(1)?), text(2)?)
                } else {
                    (None, text(1)?)
                };
                if let Some(t) = &to {
                    if !expect.payee.iter().any(|p| p == t) {
                        return Err(SdkError::ImportNotPayee);
                    }
                }
                let (pay_ref, valid_until) = if kind == OpKind::Pay {
                    let v = inv
                        .args
                        .get(4)
                        .and_then(|a| a.value.as_u64())
                        .ok_or(SdkError::Argument)?;
                    (Some(text(3)?), v)
                } else {
                    (None, 0)
                };
                let now = sdk.now();
                let ledger = latest(sor).await?;
                if u64::from(blob.op.expiry) < ledger.saturating_add(IMPORT_MARGIN_SECS)
                    || (kind == OpKind::Pay && valid_until < now.saturating_add(IMPORT_MARGIN_SECS))
                {
                    return Err(SdkError::ImportExpired);
                }
                // a transfer's or burn's own bound is its expiry ledger: at most one ledger a second from now on
                let valid_until = if kind == OpKind::Pay {
                    valid_until
                } else {
                    now.saturating_add(u64::from(blob.op.expiry).saturating_sub(ledger))
                };
                let p = SorobanPrepared {
                    chain: expect.chain,
                    contract: blob.contract,
                    entry: inv.function.clone(),
                    from,
                    to,
                    amount,
                    pay_ref,
                    valid_until,
                    nonce: blob.op.nonce,
                    expiry: blob.op.expiry,
                    subject: None,
                    signature: Some(blob.signature),
                    relayer_bound: false,
                    op: None,
                };
                signature(&p)?.ok_or(SdkError::Argument)?;
                let op = rebuilt(&p, passphrase)?;
                if spent(sor, &op).await? {
                    return Err(SdkError::ImportConsumed);
                }
                Ok(p)
            })
            .await
    }

    /// A self-relayed op whose transaction expired or failed, again (spec §27.5 (e), at the user's request): the row's signed op
    /// as a prepared op with its signature, for a new quote and submit around it. The op is never signed again; the row goes on.
    pub async fn soroban_resend(&self, op: String) -> Result<SorobanPrepared, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let r = state::row(&sdk, &op).await?;
                if r.terminal() || r.name != "soroban" || ex(&r.extra, "signature").is_null() {
                    return Err(SdkError::Argument);
                }
                let s = |k: &str| ex(&r.extra, k).as_str().map(str::to_string);
                Ok(SorobanPrepared {
                    chain: r.chain,
                    contract: r.contract,
                    entry: r.entry,
                    from: r.from,
                    to: s("to"),
                    amount: s("amount").ok_or(SdkError::Argument)?,
                    pay_ref: s("pay_ref"),
                    valid_until: r.valid_until,
                    nonce: r.nonce,
                    expiry: ex(&r.extra, "expiry")
                        .as_u64()
                        .and_then(|e| u32::try_from(e).ok())
                        .ok_or(SdkError::Argument)?,
                    subject: serde_json::from_value(ex(&r.extra, "subject").clone())
                        .ok()
                        .flatten(),
                    signature: s("signature"),
                    relayer_bound: false,
                    op: Some(op),
                })
            })
            .await
    }

    /// One step of following row `op` by chain facts (spec §13.5, §27.5 (c)), its state after: `landed` when this row's own
    /// transaction (or its gateway, or for a handed-off op whoever holds it) landed the op; `consumed` when the op is spent and
    /// this row's own transaction did not land it; `expired` past its bound and unspent; a native send's billed failure
    /// `reverted`. A self-relay whose transaction failed or expired stays `sent` (`detail` names why): the op may still land.
    pub async fn soroban_follow(&self, op: String) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let mut r = state::row(&sdk, &op).await?;
                if r.terminal() {
                    return Ok(r.state);
                }
                let c = sdk.chain(&r.chain)?;
                let (sor, _, passphrase) = soroban(c)?;
                let now = sdk.now();
                let status = match &r.tx_id {
                    Some(t) => {
                        let h: [u8; 32] = crate::text::unhex(t)?
                            .try_into()
                            .map_err(|_| SdkError::Argument)?;
                        let a = sor
                            .client
                            .failover(sor, |i| async move {
                                sor.transaction_at(i, &h).await.map_err(|e| failed(i, e))
                            })
                            .await?;
                        Some(a.value)
                    }
                    None => None,
                };
                let max_time = ex(&r.extra, "max_time").as_u64().unwrap_or(0);
                fn end(r: &mut Row, s: &str, detail: &str) {
                    r.state = s.into();
                    r.detail = detail.into();
                }
                if let Some(TxStatus::Success { ledger }) = status {
                    r.landed = Some((ledger, r.tx_id.clone().unwrap_or_default()));
                }
                if r.path == "native" {
                    match status {
                        Some(TxStatus::Success { .. }) => end(&mut r, "landed", "success"),
                        Some(TxStatus::Failed { .. }) => end(&mut r, "reverted", "failed"),
                        Some(TxStatus::NotFound { .. }) if now > max_time => {
                            end(&mut r, "expired", "not found past max_time")
                        }
                        _ => {}
                    }
                } else {
                    let p = SorobanPrepared {
                        chain: r.chain.clone(),
                        contract: r.contract.clone(),
                        entry: r.entry.clone(),
                        from: r.from.clone(),
                        to: ex(&r.extra, "to").as_str().map(str::to_string),
                        amount: ex(&r.extra, "amount").as_str().unwrap_or_default().into(),
                        pay_ref: ex(&r.extra, "pay_ref").as_str().map(str::to_string),
                        valid_until: r.valid_until,
                        nonce: r.nonce.clone(),
                        expiry: ex(&r.extra, "expiry")
                            .as_u64()
                            .and_then(|e| u32::try_from(e).ok())
                            .unwrap_or(0),
                        subject: None,
                        signature: None,
                        relayer_bound: false,
                        op: None,
                    };
                    let checked = rebuilt(&p, passphrase)?;
                    let gone = spent(sor, &checked).await?;
                    match status {
                        Some(TxStatus::Success { .. }) => end(&mut r, "landed", "success"),
                        _ if gone && r.tx_id.is_none() => end(&mut r, "landed", "spent"),
                        _ if gone => end(&mut r, "consumed", "spent by another transaction"),
                        _ if now > r.valid_until || latest(sor).await? > u64::from(p.expiry) => {
                            end(&mut r, "expired", "unspent past its bound")
                        }
                        Some(TxStatus::Failed { .. }) => r.detail = "tx_failed".into(),
                        Some(TxStatus::NotFound { .. }) if now > max_time => {
                            r.detail = "tx_expired".into()
                        }
                        _ => {}
                    }
                }
                if r.terminal() {
                    r.ended_at = Some(now);
                }
                state::put(&sdk, &r).await?;
                Ok(r.state)
            })
            .await
    }

    /// A native XLM send (the Native column, spec §27.5 (d) "Native sends"): `to` an existing account (`Argument` otherwise:
    /// a `Payment` to none fails), `amount` a positive `i64` of stroops, the source's sequence + 1, the inclusion fee under
    /// `Limits::max_native_cost` (`FeeAboveCap`). Nothing is signed.
    pub async fn soroban_prepare_native_send(
        &self,
        req: SorobanNativeSend,
    ) -> Result<SorobanNativeQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&req.chain)?;
                let (sor, _, _) = soroban(c)?;
                let (_, _, pk) = stellar(&sdk, &req.key)?;
                let to = match holder(&req.to) {
                    Some(Holder::Account(k)) => k,
                    _ => return Err(SdkError::Argument),
                };
                match req.amount.parse::<i64>() {
                    Ok(a) if a > 0 && a.to_string() == req.amount => {}
                    _ => return Err(SdkError::Argument),
                }
                let (_, seq) = account(sor, &pk).await?;
                account(sor, &to).await?;
                let fee = inclusion_fee(sor, false).await?;
                if fee > cap(&sdk, &req.chain)? {
                    return Err(SdkError::FeeAboveCap);
                }
                let max_time = sdk.now().saturating_add(TX_WINDOW_SECS);
                Ok(SorobanNativeQuote {
                    chain: req.chain,
                    key: req.key,
                    from: g_of(&pk),
                    to: req.to,
                    amount: req.amount,
                    seq: seq.checked_add(1).ok_or(SdkError::Argument)?.to_string(),
                    fee,
                    max_time,
                    native: cost(fee, max_time),
                })
            })
            .await
    }

    /// Signs exactly `q` once (the key `q.key`, whose `G…` is `q.from`), writes the row ahead, broadcasts it to every endpoint;
    /// returns the row's id ([`Wallet::soroban_follow`] follows it to its ledger).
    pub async fn soroban_submit_native_send(
        &self,
        q: SorobanNativeQuote,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = sdk.chain(&q.chain)?;
                let (sor, nid, _) = soroban(c)?;
                let (_seed, key, pk) = stellar(&sdk, &q.key)?;
                if g_of(&pk) != q.from || q.fee > cap(&sdk, &q.chain)? {
                    return Err(SdkError::Argument);
                }
                let tx = SorobanTx {
                    source: q.from.clone(),
                    fee: q.fee,
                    seq: q.seq.parse().map_err(|_| SdkError::Argument)?,
                    min_time: 0,
                    max_time: q.max_time,
                    op: TxOp::Payment {
                        destination: q.to.clone(),
                        amount: q.amount.parse().map_err(|_| SdkError::Argument)?,
                    },
                };
                let signed = key.sign_soroban_tx(&nid, &tx)?;
                let id = new_id()?;
                let mut row = Row {
                    op: id.clone(),
                    chain: q.chain.clone(),
                    entry: "payment".into(),
                    name: "soroban".into(),
                    kind: "native".into(),
                    contract: String::new(),
                    from: q.from.clone(),
                    batch: String::new(),
                    nonce: q.seq.clone(),
                    valid_until: q.max_time,
                    digest: hex(&signed.hash),
                    op_json: Value::Null,
                    calldata: String::new(),
                    raw: Some(hex(&signed.envelope)),
                    tx_id: Some(hex(&signed.hash)),
                    tx_nonce: q.seq.parse().ok(),
                    path: "native".into(),
                    payer: Some(q.from.clone()),
                    from_block: 0,
                    state: "signed".into(),
                    detail: String::new(),
                    landed: None,
                    relayer_bound: false,
                    gas_limit: None,
                    signer_kind: None,
                    unsigned_len: None,
                    members: None,
                    ended_at: None,
                    message: Value::Null,
                    extra: json!({"max_time": q.max_time, "to": q.to, "amount": q.amount}),
                    fact: None,
                };
                state::put(&sdk, &row).await?;
                let b = sor
                    .send(
                        &nid,
                        &signed.tx,
                        &[(signed.hint, signed.signature)],
                        scaas_rpc::endpoint::Fanout::All,
                    )
                    .await?;
                row.state = "sent".into();
                row.detail = match b {
                    Broadcast::Sent { .. } => "accepted".into(),
                    Broadcast::Rejected { .. } => "rejected".into(),
                };
                state::put(&sdk, &row).await?;
                Ok(id)
            })
            .await
    }
}
