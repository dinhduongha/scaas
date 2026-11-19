// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Registration (spec §7 "Registration"; plan T13): a UA key's registry write built by `scaas-ua` (`registration_args`, the
//! PoP by `sign_ua` under `pop` v2, role Pop, CLI-UAL-17; the calldata by `entries::registry_call`), self-relayed by the
//! user's payer while the gateway's `POST /v1/ua/register` is not served (§13.3). The node's split (gateway.md): a
//! registration carrying a `pqzPop` whose full call's gas is above min(the chain's per-transaction cap, its block gas
//! limit, `Limits::max_gas`), or whose estimate fails, is sent as the registration without `pqzPop`, then `storePqzPop`; a part
//! still above the cap is `GasAboveTxCap`. A KEM key in its hash-commit form is filled by `setKemKey(ua, 0, kem, UASig())`.
//! A registry write is an opaque [`RegistryWrite`] kept in the SDK's table, quoted (the payer's estimate) and submitted like a
//! native send (sign → write ahead → simulate → send); it lands **by its record** (`isRegistered`, `pqzKeyAt(…).proven`,
//! `kemKeyAt(…)`), whoever sent it: a registration is portable, its PoP binds no caller (CTR-UA-07). UNAUDITED.
use super::Account;
use crate::op::quote::{check_caps, payer_address, self_relay};
use crate::op::state::{self, Row};
use crate::op::submit::{detach, send, sign_tx};
use crate::op::{
    evm, field, hex, key, sim, unhex, Key, KeyRef, ReviewField, Source, SubmitPath, SubmitQuote,
};
use crate::{Sdk, SdkError};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::rpc::types::TransactionRequest;
use scaas_rpc::evm::EvmPool;
use scaas_ua::wallet::entries::registry_call;
use serde_json::{json, Value};
use std::sync::{Arc, PoisonError};

/// What a registration carries besides the key (spec §7): the PQZ key with its `R_REG` proof, the KEM key (version 0).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RegisterAttrs {
    pub pqz_key: bool,
    pub kem: bool,
}

/// `prepare_register`: the UA key `key` (a seed's `KeyRef::Ua`) registered on `chain`, its writes self-relayed by `payer` (a
/// native `evm` key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub key: KeyRef,
    pub chain: String,
    pub attrs: RegisterAttrs,
    pub payer: KeyRef,
}

/// The record that shows a registry write landed (read at the profile's final block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Landed {
    /// `isRegistered(ua)`
    Registered,
    /// `pqzKeyAt(ua, v).proven`
    PqzPop(u64),
    /// `kemKeyAt(ua, v).kem.scheme != 0`
    Kem(u64),
}

impl Landed {
    fn name(self) -> String {
        match self {
            Landed::Registered => "registered".into(),
            Landed::PqzPop(v) => format!("pqzPop:{v}"),
            Landed::Kem(v) => format!("kem:{v}"),
        }
    }
    pub(crate) fn parse(s: &str) -> Option<Landed> {
        match s.split_once(':') {
            None if s == "registered" => Some(Landed::Registered),
            Some(("pqzPop", v)) => v.parse().ok().map(Landed::PqzPop),
            Some(("kem", v)) => v.parse().ok().map(Landed::Kem),
            _ => None,
        }
    }
}

/// A registry write as the user reviews it (spec §7, §13.1): opaque, kept in the SDK's table; it holds public data only
/// (the PoP binds no caller). `submit_registry_write` sends exactly its calldata to the profile's registry.
pub struct RegistryWrite {
    id: String,
    chain: String,
    entry: String,
    ua: [u8; 32],
    review: Vec<ReviewField>,
    payer: KeyRef,
    pub(crate) calldata: Vec<u8>,
    pub(crate) landed: Landed,
}

impl std::fmt::Debug for RegistryWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryWrite")
            .field("id", &self.id)
            .field("entry", &self.entry)
            .finish()
    }
}

impl RegistryWrite {
    pub fn id(&self) -> String {
        self.id.clone()
    }
    pub fn chain(&self) -> String {
        self.chain.clone()
    }
    /// The registry function: `register`, `registerWebAuthn`, …, `storePqzPop`, `setKemKey`.
    pub fn entry(&self) -> String {
        self.entry.clone()
    }
    /// The UA it registers (`0x` + 64 hex).
    pub fn ua(&self) -> String {
        hex(&self.ua)
    }
    pub fn review(&self) -> Vec<ReviewField> {
        self.review.clone()
    }
    /// The calldata the payer's transaction carries to the registry (`0x` hex; public data).
    pub fn calldata(&self) -> String {
        hex(&self.calldata)
    }
    /// The payer whose transaction sends it (linked on chain to the UA's registration).
    pub fn payer(&self) -> KeyRef {
        self.payer.clone()
    }
}

/// A registration as the registry holds it (`registration_of`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrationState {
    pub registered: bool,
    /// the hash commit of the KEM key (`attrs.kemPkHash`, `0x` + 64 hex; all zero: none)
    pub kem_pk_hash: String,
    /// the KEM key of version 0 is stored (a commit filled, or the full key given at `register`)
    pub kem_stored: bool,
    /// the PQZ key of version 0 has its stored proof
    pub pqz_proven: bool,
}

pub(crate) fn registry_of(sdk: &Sdk, chain: &str) -> Result<Address, SdkError> {
    let (profile, _, _) = evm(sdk, chain)?;
    profile
        .registry
        .as_deref()
        .and_then(|r| r.parse().ok())
        .ok_or(SdkError::Argument)
}

fn selector(sig: &str) -> Vec<u8> {
    scaas_ua::keccak256(sig.as_bytes())
        .get(..4)
        .unwrap_or_default()
        .to_vec()
}

fn word_u64(v: u64) -> [u8; 32] {
    U256::from(v).to_be_bytes::<32>()
}

/// The view call of `landed` on `ua`.
pub(crate) fn record_call(landed: Landed, ua: &[u8; 32]) -> Bytes {
    let mut d = match landed {
        Landed::Registered => selector("isRegistered(bytes32)"),
        Landed::PqzPop(_) => selector("pqzKeyAt(bytes32,uint64)"),
        Landed::Kem(_) => selector("kemKeyAt(bytes32,uint64)"),
    };
    d.extend_from_slice(ua);
    match landed {
        Landed::PqzPop(v) | Landed::Kem(v) => d.extend_from_slice(&word_u64(v)),
        Landed::Registered => {}
    }
    Bytes::from(d)
}

fn word(out: &[u8], i: usize) -> Option<U256> {
    out.get(i * 32..i * 32 + 32).map(U256::from_be_slice)
}

/// The record's answer: present or not; `None` for an answer of another shape.
pub(crate) fn record_holds(landed: Landed, out: &[u8]) -> Option<bool> {
    match landed {
        // one ABI `bool`, exactly 0 or 1
        Landed::Registered => match (out.len(), word(out, 0)?) {
            (32, w) if w <= U256::from(1) => Some(w == U256::from(1)),
            _ => None,
        },
        // `(address ptr, bytes32 pqzPopHash, bool proven)`
        Landed::PqzPop(_) => Some(word(out, 2)? == U256::from(1)),
        // `(KemKey kem, bytes sig)`: the tuple's offset, then its first word the scheme
        Landed::Kem(_) => {
            let off = usize::try_from(word(out, 0)?).ok()?;
            Some(!out.get(off..off + 32)?.iter().all(|b| *b == 0))
        }
    }
}

async fn read_record(
    pool: &EvmPool,
    registry: Address,
    landed: Landed,
    ua: &[u8; 32],
) -> Result<bool, SdkError> {
    let tx = TransactionRequest::default()
        .with_to(registry)
        .with_input(record_call(landed, ua));
    let out = pool.call_tx(tx).await.map_err(sim)?;
    record_holds(landed, &out).ok_or(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
        last: None,
        failover_revert: None,
    }))
}

/// `registrationOf(ua)`'s `attrs.kemPkHash` (zero for an unregistered UA).
async fn kem_pk_hash(pool: &EvmPool, registry: Address, ua: &[u8; 32]) -> Result<[u8; 32], SdkError> {
    let mut d = selector("registrationOf(bytes32)");
    d.extend_from_slice(ua);
    let tx = TransactionRequest::default()
        .with_to(registry)
        .with_input(Bytes::from(d));
    let out = pool.call_tx(tx).await.map_err(sim)?;
    let bad = || {
        SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        })
    };
    // `(uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop)`: `attrs` by its offset, `kemPkHash` its fourth word
    let off = word(&out, 2)
        .and_then(|w| usize::try_from(w).ok())
        .ok_or_else(bad)?;
    out.get(off + 96..off + 128)
        .and_then(|w| w.try_into().ok())
        .ok_or_else(bad)
}

/// The gas cap a registry write must fit: min(the chain's per-transaction cap, its block gas limit, `Limits::max_gas`).
async fn gas_cap(sdk: &Sdk, chain: &str, pool: &EvmPool) -> Result<u64, SdkError> {
    let (profile, _, _) = evm(sdk, chain)?;
    let block = pool.block_gas().await.map_err(sim)?;
    Ok(profile
        .tx_gas_cap
        .unwrap_or(u64::MAX)
        .min(block.limit)
        .min(sdk.limits.max_gas))
}

fn flatten(prefix: &str, v: &Value, out: &mut Vec<ReviewField>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                flatten(&format!("{prefix}.{k}"), x, out);
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

/// One write kept in the table.
fn keep(
    sdk: &Sdk,
    chain: &str,
    entry: &str,
    ua: [u8; 32],
    args: &Value,
    payer: &KeyRef,
    landed: Landed,
) -> Result<Arc<RegistryWrite>, SdkError> {
    let registry = registry_of(sdk, chain)?;
    let calldata = registry_call(entry, args)?;
    let mut review = vec![
        field("entry", entry, entry, Source::Derived),
        field("ua", &hex(&ua), &hex(&ua), Source::Derived),
        field(
            "registry",
            &format!("{registry:#x}"),
            &format!("{registry:#x}"),
            Source::Derived,
        ),
    ];
    flatten("args", args, &mut review);
    let w = Arc::new(RegistryWrite {
        id: crate::vault::uuid4()?,
        chain: chain.into(),
        entry: entry.into(),
        ua,
        review,
        payer: payer.clone(),
        calldata,
        landed,
    });
    sdk.registry_writes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(w.id.clone(), w.clone());
    Ok(w)
}

/// The writes of a registration with its arguments `args` (named fields, `entry` among them, as `scaas-ua`'s
/// `registration_args_json` gives them) and `kem_fill` (the `setKemKey` of a hash-committed KEM key): skipped when `ua` is
/// registered already (its KEM fill added when the commit is unfilled); split as the node's rule when it carries a `pqzPop`
/// and does not fit (module doc). `GasAboveTxCap`: a part above the cap.
pub(crate) async fn writes(
    sdk: &Arc<Sdk>,
    chain: &str,
    payer: &KeyRef,
    ua: [u8; 32],
    args: &Value,
    kem_fill: Option<&Value>,
) -> Result<Vec<Arc<RegistryWrite>>, SdkError> {
    let (_, _, pool) = evm(sdk, chain)?;
    let registry = registry_of(sdk, chain)?;
    let entry = args
        .get("entry")
        .and_then(Value::as_str)
        .ok_or(SdkError::Argument)?
        .to_string();
    let from = payer_address(sdk, payer)?;
    let mut out = Vec::new();
    let registered = read_record(&pool, registry, Landed::Registered, &ua).await?;
    if !registered {
        let full = registry_call(&entry, args)?;
        let pqz_pop = args.get("pqzPop").and_then(Value::as_str).unwrap_or("0x");
        let cap = gas_cap(sdk, chain, &pool).await?;
        let fits = |g: Result<u64, _>| matches!(g, Ok(g) if g <= cap);
        let split = pqz_pop != "0x"
            && !fits(pool.simulate_from(from, registry, Bytes::from(full)).await);
        if split {
            let mut first = args.clone();
            first
                .as_object_mut()
                .ok_or(SdkError::Argument)?
                .insert("pqzPop".into(), json!("0x"));
            let part = registry_call(&entry, &first)?;
            if !fits(pool.simulate_from(from, registry, Bytes::from(part)).await) {
                return Err(SdkError::GasAboveTxCap);
            }
            out.push(keep(sdk, chain, &entry, ua, &first, payer, Landed::Registered)?);
            let store = json!({"ua": hex(&ua), "version": 0, "pqzPop": pqz_pop});
            out.push(keep(sdk, chain, "storePqzPop", ua, &store, payer, Landed::PqzPop(0))?);
        } else {
            out.push(keep(sdk, chain, &entry, ua, args, payer, Landed::Registered)?);
        }
    }
    if let Some(fill) = kem_fill {
        let filled = registered && read_record(&pool, registry, Landed::Kem(0), &ua).await?;
        if !filled {
            out.push(keep(sdk, chain, "setKemKey", ua, fill, payer, Landed::Kem(0))?);
        }
    }
    Ok(out)
}

/// `submit_registry_write`'s re-check of what it takes: one of this SDK's writes (`PreparedUnknown`).
fn known(sdk: &Sdk, w: &Arc<RegistryWrite>) -> Result<(), SdkError> {
    match sdk
        .registry_writes
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&w.id)
    {
        Some(x) if Arc::ptr_eq(x, w) => Ok(()),
        _ => Err(SdkError::PreparedUnknown),
    }
}

/// Takes `w` out of the table (one submit: a second, concurrent or later, is `PreparedUnknown`).
fn take(sdk: &Sdk, w: &Arc<RegistryWrite>) -> Result<(), SdkError> {
    let mut t = sdk.registry_writes.lock().unwrap_or_else(PoisonError::into_inner);
    match t.get(&w.id) {
        Some(x) if Arc::ptr_eq(x, w) => {
            t.remove(&w.id);
            Ok(())
        }
        _ => Err(SdkError::PreparedUnknown),
    }
}

/// A seed key's registration by `scaas-ua` (`registration_args_json`; the PoP by `sign_ua` under `pop` v2, the Zether UA's by
/// its facade): the UA and `{args, kemFill, …}`.
pub(crate) fn build(sdk: &Sdk, key_ref: &KeyRef, attrs: RegisterAttrs) -> Result<([u8; 32], Value), SdkError> {
    if attrs.pqz_key {
        return Err(SdkError::FeatureMissing);
    }
    let (kind, key_data, ua, pop, kem_pk) = match key(sdk, key_ref)? {
        Key::Ua(_, k) => {
            let ua = k.ua().ok_or(SdkError::Argument)?;
            let kem_pk = if attrs.kem {
                k.kem_key(0)?.kem_pk()
            } else {
                vec![]
            };
            let hp = scaas_ua::holder_pop_message(
                k.kind(),
                &ua,
                &k.key_data(),
                None,
                None,
                None,
                Some(&kem_pk),
            )
            .map_err(|_| SdkError::Argument)?;
            let pop = k.sign_ua(
                &scaas_ua::ua_portable::pop_v2_tag(),
                &hp.registration_digest,
            )?;
            (k.kind(), k.key_data(), ua, pop, kem_pk)
        }
        #[cfg(feature = "zether")]
        Key::Zether(_, z) => {
            if attrs.kem {
                return Err(SdkError::Argument); // a Zether UA holds no KEM key
            }
            let (y, pop) = z.pop()?;
            (crate::confidential::ZETHER_KIND, y, z.ua(), pop, vec![])
        }
        Key::Native(..) => return Err(SdkError::Argument),
    };
    let input = json!({
        "kind": kind, "keyData": hex(&key_data), "pqzKey": "0x", "pqzPopHash": "0x", "pqzPop": "0x",
        "kemPk": hex(&kem_pk), "pop": hex(&pop),
    });
    let r: Value = serde_json::from_str(
        &scaas_ua::json::registration_args_json(&input.to_string())
            .map_err(|_| SdkError::Argument)?,
    )
    .map_err(|_| SdkError::Internal)?;
    Ok((ua, r))
}

/// `ReceiverUnregistered` (spec §7.1): `to` a derived UA (not a native id: its top 12 bytes not all zero) that the profile's
/// registry does not hold, or on a profile naming no registry (fail closed: owner 2026-11-19, R3); a native id passes.
pub(crate) async fn receiver_registered(sdk: &Sdk, chain: &str, to: &[u8; 32]) -> Result<(), SdkError> {
    if to.get(..12).is_some_and(|h| h.iter().all(|b| *b == 0)) {
        return Ok(());
    }
    let (profile, _, pool) = evm(sdk, chain)?;
    let Some(registry) = profile.registry.as_deref() else {
        return Err(SdkError::ReceiverUnregistered);
    };
    let registry: Address = registry.parse().map_err(|_| SdkError::Argument)?;
    match read_record(&pool, registry, Landed::Registered, to).await? {
        true => Ok(()),
        false => Err(SdkError::ReceiverUnregistered),
    }
}

impl Account {
    /// Prepares the registration of `req.key` (spec §7): the arguments and the PoP by `scaas-ua`, then the writes (the
    /// registration, `storePqzPop` when split, `setKemKey` for a hash-committed KEM key), in the order they must land; an
    /// already registered UA gives only what it misses. `WalletLocked`; `Argument` (a key other than a seed's UA key, a KEM
    /// key on a kind that holds none, a profile without a registry); `FeatureMissing` (`attrs.pqz_key`: the PQZ key's
    /// `R_REG` proof is not built in this SDK yet); `GasAboveTxCap`.
    pub async fn prepare_register(&self, req: Register) -> Result<Vec<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (ua, r) = build(&sdk, &req.key, req.attrs)?;
                let args = r.get("args").ok_or(SdkError::Internal)?;
                let fill = r.get("kemFill").filter(|f| !f.is_null());
                writes(&sdk, &req.chain, &req.payer, ua, args, fill).await
            })
            .await
    }

    /// The quote of `write` by its payer (spec §13.3): the estimate of its calldata, the chain's and the SDK's caps, the
    /// payer's nonce. Quote a later part only after the one before it landed (its estimate reverts before).
    /// `PreparedUnknown`, `GasAboveTxCap`, `FeeAboveCap`.
    pub async fn quote_registry_write(&self, write: Arc<RegistryWrite>) -> Result<SubmitQuote, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                known(&sdk, &write)?;
                let registry = registry_of(&sdk, &write.chain)?;
                self_relay(
                    &sdk,
                    &write.chain,
                    &write.payer,
                    registry,
                    U256::ZERO,
                    Bytes::from(write.calldata.clone()),
                    "0".into(),
                    false,
                    None,
                )
                .await
            })
            .await
    }

    /// Signs the payer's transaction carrying exactly `write`, writes the operation's row, returns its id; the send runs on
    /// and reports as `Event::OpState`; `Op::state` follows it to `Landed` by the record. `PreparedUnknown` (a write not of
    /// this SDK, or submitted already), `Argument` (a quote of another payer), `FeeAboveCap`; a failed signing of the payer's
    /// transaction (`WalletLocked`, …) leaves the write in the table, submittable again.
    pub async fn submit_registry_write(
        &self,
        write: Arc<RegistryWrite>,
        quote: SubmitQuote,
    ) -> Result<String, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                known(&sdk, &write)?;
                let fee = quote
                    .max_fee_per_gas
                    .parse::<u128>()
                    .map_err(|_| SdkError::Argument)?;
                check_caps(&sdk, quote.gas_limit, fee)?;
                if !matches!(&quote.path, SubmitPath::SelfRelay { payer } if *payer == write.payer) {
                    return Err(SdkError::Argument);
                }
                let (profile, chain_id, pool) = evm(&sdk, &write.chain)?;
                let registry = registry_of(&sdk, &write.chain)?;
                let from_block = crate::op::final_number(&pool, &profile).await?;
                // one submit of a write: taken out of the table before it is signed, put back when the signing fails (owner
                // 2026-11-19, R4: as `Op::submit`)
                take(&sdk, &write)?;
                let (raw, id) = match sign_tx(
                    &sdk,
                    chain_id,
                    &quote,
                    registry.into_array(),
                    U256::ZERO,
                    write.calldata.clone(),
                ) {
                    Ok(x) => x,
                    Err(e) => {
                        sdk.registry_writes
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .entry(write.id.clone())
                            .or_insert_with(|| write.clone());
                        return Err(e);
                    }
                };
                let row = Row {
                    op: crate::vault::uuid4()?,
                    chain: write.chain.clone(),
                    entry: write.entry.clone(),
                    name: write.entry.clone(),
                    kind: "registry".into(),
                    contract: format!("{registry:#x}"),
                    from: hex(&write.ua),
                    batch: write.landed.name(),
                    nonce: String::new(),
                    valid_until: u64::MAX,
                    digest: id.clone(),
                    op_json: Value::Null,
                    calldata: hex(&write.calldata),
                    raw: Some(hex(&raw)),
                    tx_id: Some(id),
                    tx_nonce: Some(quote.tx_nonce),
                    path: "self".into(),
                    payer: Some(format!("{:#x}", payer_address(&sdk, &write.payer)?)),
                    from_block,
                    state: "signed".into(),
                    detail: "Signed".into(),
                    landed: None,
                    relayer_bound: false,
                    gas_limit: Some(quote.gas_limit),
                    ended_at: None,
                    message: Value::Null,
                };
                state::put(&sdk, &row).await?;
                let (s2, op) = (sdk.clone(), row.op.clone());
                detach(&sdk, async move { send(&s2, row).await });
                Ok(op)
            })
            .await
    }

    /// The registration of `ua` (`0x` + 64 hex) on `chain` as the registry holds it now.
    pub async fn registration_of(&self, chain: String, ua: String) -> Result<RegistrationState, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let ua: [u8; 32] = unhex(&ua)?.try_into().map_err(|_| SdkError::Argument)?;
                let (_, _, pool) = evm(&sdk, &chain)?;
                let registry = registry_of(&sdk, &chain)?;
                let registered = read_record(&pool, registry, Landed::Registered, &ua).await?;
                if !registered {
                    return Ok(RegistrationState {
                        kem_pk_hash: hex(&[0; 32]),
                        ..Default::default()
                    });
                }
                Ok(RegistrationState {
                    registered,
                    kem_pk_hash: hex(&kem_pk_hash(&pool, registry, &ua).await?),
                    kem_stored: read_record(&pool, registry, Landed::Kem(0), &ua).await?,
                    pqz_proven: read_record(&pool, registry, Landed::PqzPop(0), &ua).await?,
                })
            })
            .await
    }

    /// The KEM repair (CTR-UA-07, `scaas-ua` `kem_repair`): after a registration in the hash-commit form, or one landed by
    /// someone else in that form, the `setKemKey(ua, 0, kem, UASig())` that stores `key`'s KEM key (version 0) when the commit
    /// is unfilled; `None` when nothing is to repair (no commit, or filled). `WalletLocked`; `Argument` as `prepare_register`.
    pub async fn prepare_kem_repair(
        &self,
        key: KeyRef,
        chain: String,
        payer: KeyRef,
    ) -> Result<Option<Arc<RegistryWrite>>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let Key::Ua(_, k) = crate::op::key(&sdk, &key)? else {
                    return Err(SdkError::Argument);
                };
                let ua = k.ua().ok_or(SdkError::Argument)?;
                let kem_pk = k.kem_key(0)?.kem_pk();
                let (_, _, pool) = evm(&sdk, &chain)?;
                let registry = registry_of(&sdk, &chain)?;
                if !read_record(&pool, registry, Landed::Registered, &ua).await? {
                    return Ok(None);
                }
                let hash = kem_pk_hash(&pool, registry, &ua).await?;
                let stored = if read_record(&pool, registry, Landed::Kem(0), &ua).await? {
                    // any non-empty stored key: `kem_repair` only asks whether one is stored
                    scaas_ua::ua_portable::KemKey {
                        scheme: 1,
                        ..Default::default()
                    }
                } else {
                    scaas_ua::ua_portable::KemKey::default()
                };
                let Some(fix) = scaas_ua::ua_portable::kem_repair(&ua, &hash, &stored, &kem_pk)
                    .map_err(|_| SdkError::Argument)?
                else {
                    return Ok(None);
                };
                // the fill carries no signature: the PoP signed the same `UAKemRecord` (CTR-UA-07)
                let args = json!({
                    "ua": hex(&fix.ua), "version": fix.version,
                    "kem": {"scheme": fix.kem.scheme, "mlkemEk": hex(&fix.kem.mlkem_ek), "x25519": hex(&fix.kem.x25519)},
                    "sig": {"keyData": "0x", "signature": "0x", "members": []},
                });
                Ok(Some(keep(&sdk, &chain, "setKemKey", ua, &args, &payer, Landed::Kem(0))?))
            })
            .await
    }
}

#[cfg(test)]
#[path = "register_tests.rs"]
mod tests;
