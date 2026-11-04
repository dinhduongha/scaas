//! Stellar Soroban (R65). Meta-tx cấp contract = authorization gốc: chủ thể đã ký
//! `HashIdPreimage::SorobanAuthorization` (Odoo dựng); adapter đặt chữ ký vào `SorobanAuthorizationEntry` của một tx
//! mà **lane account** là source (sequence riêng của lane, trả phí) — chủ thể không có sequence trong đường đi (R30).
//! Nonce auth là ngẫu nhiên (host ghi cặp (địa chỉ, nonce) đã dùng) ⇒ không head-of-line (R62).
//! Tuỳ chọn fee-bump (CAP-15): `params.fee_bump_lane = i` ⇒ account của lane `i` trả phí cho mọi lane.
//! Thiết kế: `docs/history/specs/2026-10-03-net-soroban.md`.
//! UA-Soroban (spec `2026-10-30-ua-soroban-design.md` §8, §9): `ua_metatx` jobs (`ua_metatx_job`, named fields, `UA_FNS`, `accept_membership` on the registry among them), the lane-authority
//! rule (`check_recorded_auth`), Protocol 23 auto-restore within `params.max_deposit_per_job` (`sim_data`), UA events.
//! UA-8 (UA8-D23): `call` jobs for the registry writes (`ua8_call_job`), the off-chain check before a relayer's attestation
//! (`ua8_precheck`). Every job names its fields and the node builds the XDR (owner 2026-10-31, 2026-11-02): a blob where a field
//! belongs is `HEX_ARGS_REFUSED`; what stays hex is signature bytes.
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use scaas_ua::ua8::{self, FrostKey, FrostMember, KemKey, MemberSig, MsigMember, MsigStructure, MuSig2Key, RegisterArgs, SetKemKeyArgs, UAAttrs, UASig, WebAuthnKey};
use scaas_ua::UAError;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, ConfigSettingEntry, ConfigSettingId, ContractDataDurability, ContractDataEntry, ContractExecutable, DecoratedSignature, FeeBumpTransaction,
    FeeBumpTransactionEnvelope, FeeBumpTransactionExt, FeeBumpTransactionInnerTx, Hash, HostFunction, Int128Parts, Int256Parts, InvokeContractArgs,
    InvokeHostFunctionOp, LedgerEntry, LedgerEntryData, LedgerKey, LedgerKeyAccount, LedgerKeyConfigSetting, LedgerKeyContractData, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    ReadXdr, ScAddress, ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SequenceNumber, Signature, SignatureHint,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    SorobanTransactionData, SorobanTransactionDataExt, TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
    InnerTransactionResultResult, TransactionResult, TransactionResultResult, TransactionV1Envelope, UInt128Parts, UInt256Parts, Uint256, WriteXdr,
};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Refused, Rejected, Signed, TxStatus};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{stellar_account_strkey, LocalSigner, Signer};

const DEFAULT_BASE_FEE: u32 = 100;
/// Biên cho resource fee mô phỏng (trạng thái có thể đổi giữa mô phỏng và thực thi).
const RESOURCE_FEE_MARGIN_PCT: i64 = 15;
/// `getEvents`: tối đa 5 contract mỗi bộ lọc.
const CONTRACTS_PER_FILTER: usize = 5;
/// How deep XDR a job puts in may nest (`xdr_limits` allows twice that around it). `Limits::len` alone leaves the depth open, about 2,700 levels in 64 KiB of hex, and a stack
/// overflow aborts the whole node. A `Vec` level costs four, so this holds 15 (`deep_xdr_is_refused_not_a_stack_overflow`); a contract's own
/// shapes need far fewer.
const XDR_DEPTH: u32 = 64;
const EVENT_PAGE: u64 = 1000;

pub struct SorobanAdapter {
    key: String,
    rpc: Vec<String>,
    http: reqwest::Client,
    network_id: [u8; 32],
    signers: Vec<LocalSigner>,
    lanes: Vec<Lane>,
    fee_bump: Option<usize>,
    base_fee: u32,
    quorum: usize,
    relay_fee: RelayFeePolicy,
    /// `params.max_deposit_per_job` (stroops; absent = 0): the most resource fee a job that restores archived entries
    /// may declare (NODE-LANE-18, spec §7).
    max_deposit: u64,
    /// `params.max_resource_fee_per_job` (stroops; absent = 0, every job refused, and a chain with lanes does not start): the most
    /// resource fee, margin included, any job may declare (NET-SOR-22).
    max_resource_fee: u64,
    hashes: Mutex<HashMap<u64, String>>,
    /// The last `tx_max_size_bytes` the network answered, used while a later read fails.
    tx_limit: Mutex<Option<usize>>,
    /// The same for `contract_data_entry_size_bytes`.
    entry_limit: Mutex<Option<usize>>,
}

fn hex(b: &[u8]) -> String {
    alloy::hex::encode(b)
}

pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

fn lane_pk(s: &LocalSigner) -> Result<[u8; 32]> {
    s.public_key().try_into().map_err(|_| anyhow!("soroban lanes are ed25519"))
}

/// Chữ ký trong credentials: account `G…` ⇒ `Vec[Map{public_key, signature}]` (định dạng account gốc của host);
/// account contract `C…` ⇒ ScVal XDR mà `__check_auth` của nó đọc, chèn nguyên văn. `0x…` hex, as every byte value of a job.
pub fn credential_signature(from: &ScAddress, signature: &Value) -> Result<ScVal> {
    let sig = hex_of(signature)?;
    match from {
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk)))) => {
            if sig.len() != 64 {
                bail!("account signature is 64 bytes");
            }
            let entry = |k: &str, v: Vec<u8>| -> Result<ScMapEntry> {
                Ok(ScMapEntry { key: ScVal::Symbol(ScSymbol(k.try_into()?)), val: ScVal::Bytes(v.try_into()?) })
            };
            let map = ScMap(vec![entry("public_key", pk.to_vec())?, entry("signature", sig)?].try_into()?);
            Ok(ScVal::Vec(Some(vec![ScVal::Map(Some(map))].try_into()?)))
        }
        ScAddress::Contract(_) => Ok(ScVal::from_xdr(&sig, Limits { depth: XDR_DEPTH, len: 8192 })?),
        _ => bail!("unsupported signer address"),
    }
}

/// `{contract, function, args: [{type, value}], sub_invocations: [invocation]}`, a contract call and what it calls under the same
/// signature. A host function (`CreateContract…`) has no form: nothing the node relays signs one.
fn invocation_of(v: &Value) -> Result<SorobanAuthorizedInvocation> {
    let [contract, function, args, subs] = named(v, "invocation", ["contract", "function", "args", "sub_invocations"])?;
    let args: Vec<ScVal> = list_of(args, relayed_of)?;
    let call = InvokeContractArgs { contract_address: address_of(contract)?, function_name: symbol_of(function)?, args: args.try_into()? };
    let subs: Vec<SorobanAuthorizedInvocation> = list_of(subs, invocation_of)?;
    Ok(SorobanAuthorizedInvocation { function: SorobanAuthorizedFunction::ContractFn(call), sub_invocations: subs.try_into()? })
}

/// One subject's authorization, of a `signed_op`, `op.auth[]` or `extra.auth[]` (owner 2026-11-02): `{payload: {nonce, expiry,
/// invocation}, from, signature}`. The node builds the entry from the named fields and the host checks `signature` over it, on this
/// chain's network id, so a signature for another network or other values fails there. `signature` stays hex: it is one crypto
/// object. The credentials are always `Address`: a `SourceAccount` entry is the node's own.
pub fn auth_entry(x: &Value) -> Result<(SorobanAuthorizationEntry, InvokeContractArgs)> {
    let [nonce, expiry, invocation] = named(&x["payload"], "payload", ["nonce", "expiry", "invocation"])?;
    let root = invocation_of(invocation)?;
    let SorobanAuthorizedFunction::ContractFn(call) = &root.function else { bail!("a payload invokes a contract function") };
    let from = x["from"].as_str().ok_or_else(|| anyhow!("op.from missing"))?;
    let address = ScAddress::from_str(from).map_err(|_| anyhow!("bad subject address {from}"))?;
    let ScVal::I64(nonce) = ua_value("i64", nonce)? else { bail!("payload.nonce is an i64") };
    let signature = credential_signature(&address, &x["signature"]).context("op.signature")?;
    let call = call.clone();
    Ok((
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials { address, nonce, signature_expiration_ledger: num_of(expiry)?, signature }),
            root_invocation: root,
        },
        call,
    ))
}

/// `op.auth` or `extra.auth`: absent, or a list of `{payload, from, signature}`.
fn auth_entries(v: &Value) -> Result<Vec<SorobanAuthorizationEntry>> {
    match v {
        Value::Null => Ok(vec![]),
        _ => list_of(v, |x| Ok(auth_entry(x)?.0)),
    }
}

/// The host call and auth entries of a `signed_op`: the call is the invocation the subject signed; `extra.auth` adds
/// co-signers' entries (NET-SOR-07). The call never comes from the job (`HEX_ARGS_REFUSED`, `job_tx`).
pub fn host_call(op: &Value) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let (main, call) = auth_entry(op)?;
    let contract = op["contract"].as_str().and_then(|c| ScAddress::from_str(c).ok()).ok_or_else(|| anyhow!("bad contract"))?;
    let mut auth = vec![main];
    auth.extend(auth_entries(&op["extra"]["auth"])?);
    if call.contract_address != contract {
        bail!("op targets {} but its call is to {}", op["contract"], call.contract_address);
    }
    Ok((call, auth))
}

fn scval_str(v: &ScVal) -> Option<String> {
    match v {
        ScVal::Symbol(s) => Some(String::from_utf8_lossy(s.0.as_slice()).into_owned()),
        _ => None,
    }
}

fn scval_addr(v: &ScVal) -> Option<String> {
    match v {
        ScVal::Address(a) => Some(a.to_string()),
        _ => None,
    }
}

fn scval_b32(v: &ScVal) -> Option<String> {
    match v {
        ScVal::Bytes(b) if b.len() == 32 => Some(format!("0x{}", hex(b.as_slice()))),
        _ => None,
    }
}

fn scval_i128(v: &ScVal) -> Option<i128> {
    match v {
        ScVal::I128(p) => Some(((p.hi as i128) << 64) | p.lo as i128),
        _ => None,
    }
}

/// A `Holder::Addr(a)` as the contracts encode it (`Vec[Symbol("Addr"), Address]`).
pub fn holder_addr(a: &ScAddress) -> ScVal {
    let pair = vec![ScVal::Symbol(ScSymbol("Addr".try_into().expect("symbol"))), ScVal::Address(a.clone())];
    ScVal::Vec(Some(ScVec(pair.try_into().expect("pair"))))
}

enum Holder<'a> {
    Addr(&'a ScAddress),
    Ua(&'a [u8]),
}

/// A contracttype `Holder`: `Vec[Symbol("Addr"), Address]` or `Vec[Symbol("Ua"), BytesN<32>]`.
fn holder(v: &ScVal) -> Option<Holder<'_>> {
    let ScVal::Vec(Some(v)) = v else { return None };
    match v.as_slice() {
        [ScVal::Symbol(s), ScVal::Address(a)] if s.0.as_slice() == b"Addr" => Some(Holder::Addr(a)),
        [ScVal::Symbol(s), ScVal::Bytes(b)] if s.0.as_slice() == b"Ua" && b.len() == 32 => Some(Holder::Ua(b.as_slice())),
        _ => None,
    }
}

/// A holder in its event form, as NEAR and Algorand (`indexer::join_pay_events` compares these strings): the strkey of
/// an address, `0x` ‖ 64 hex of a UA id.
fn scval_holder(v: &ScVal) -> Option<String> {
    Some(match holder(v)? {
        Holder::Addr(a) => a.to_string(),
        Holder::Ua(u) => format!("0x{}", hex(u)),
    })
}

/// Một event `getEvents` ⇒ event chuẩn hoá (thiếu `block_hash`); `None` = không phải event của ta / sai dạng.
pub fn decode_event(ev: &Value) -> Option<Value> {
    let topics: Vec<ScVal> = ev["topic"]
        .as_array()?
        .iter()
        .map(|t| ScVal::from_xdr_base64(t.as_str()?, xdr_limits(4096)).ok())
        .collect::<Option<_>>()?;
    let value = ScVal::from_xdr_base64(ev["value"].as_str()?, xdr_limits(4096)).ok()?;
    let ledger = ev["ledger"].as_u64()?;
    let tx = ev["txHash"].as_str()?;
    if tx.len() != 64 || !tx.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let log_index: u64 = ev["id"].as_str()?.rsplit_once('-')?.1.parse().ok()?;
    let mut out = json!({
        "contract": ev["contractId"].as_str()?, "block_number": ledger,
        "tx_hash": format!("0x{}", tx.to_lowercase()), "log_index": log_index,
    });
    let amount = |v: &ScVal| scval_i128(v).filter(|a| *a >= 0).map(|a| a.to_string());
    match scval_str(topics.first()?)?.as_str() {
        "PaymentSettled" => {
            let ScVal::Vec(Some(data)) = &value else { return None };
            out["event"] = json!("PaymentSettled");
            out["from"] = json!(scval_addr(topics.get(1)?)?);
            out["to"] = json!(scval_addr(topics.get(2)?)?);
            out["amount"] = json!(amount(data.first()?)?);
            out["entry_ref"] = json!(scval_b32(data.get(1)?)?);
        }
        "MetaTransactionExecuted" => {
            out["event"] = json!("MetaTransactionExecuted");
            out["from"] = json!(scval_addr(topics.get(1)?)?);
            out["digest"] = json!(scval_b32(&value)?);
        }
        // CTR-MTX-26 / -27: joined to their `PaymentSettled` (`indexer::join_pay_events`), never sent alone
        "PaymentMeta" => {
            let ScVal::Bytes(meta) = &value else { return None };
            out["event"] = json!("PaymentMeta");
            out["entry_ref"] = json!(scval_b32(topics.get(1)?)?);
            out["meta"] = json!(format!("0x{}", hex(meta.as_slice())));
        }
        "RelayFeePaid" => {
            let ScVal::Vec(Some(data)) = &value else { return None };
            out["event"] = json!("RelayFeePaid");
            out["entry_ref"] = json!(scval_b32(topics.get(1)?)?);
            out["target"] = json!(scval_addr(topics.get(2)?)?);
            out["token"] = json!(scval_addr(topics.get(3)?)?);
            // T8: payer / payee are `Holder`s (a UA payer of `ua_relay`, a UA bound payee)
            out["from"] = json!(scval_holder(data.first()?)?);
            out["to"] = json!(scval_holder(data.get(1)?)?);
            out["amount"] = json!(amount(data.get(2)?)?);
        }
        // The UA ledger (spec §9.6) as the cross-family rows: a UA move is a `Transfer`, a UA payment a
        // `PaymentSettled`, a UA-signed entry a `MetaTransactionExecuted` (ids, as NEAR and Algorand).
        "UaTransfer" => {
            out["event"] = json!("Transfer");
            out["from"] = json!(scval_holder(topics.get(1)?)?);
            out["to"] = json!(scval_holder(topics.get(2)?)?);
            out["amount"] = json!(amount(&value)?);
        }
        "UaPaymentSettled" => {
            let ScVal::Vec(Some(data)) = &value else { return None };
            out["event"] = json!("PaymentSettled");
            out["from"] = json!(scval_holder(topics.get(1)?)?);
            out["to"] = json!(scval_holder(topics.get(2)?)?);
            out["amount"] = json!(amount(data.first()?)?);
            out["entry_ref"] = json!(scval_b32(data.get(1)?)?);
        }
        "UaMetaTransactionExecuted" => {
            out["event"] = json!("MetaTransactionExecuted");
            out["from"] = json!(scval_b32(topics.get(1)?)?);
            out["digest"] = json!(scval_b32(&value)?);
        }
        "UaNonceCancelled" => {
            let ScVal::U64(n) = value else { return None };
            out["event"] = json!("UaNonceCancelled");
            out["ua"] = json!(scval_b32(topics.get(1)?)?);
            out["lane"] = json!(scval_b32(topics.get(2)?)?);
            out["nonce"] = json!(n.to_string());
        }
        "UaRegistered" => {
            let ScVal::U32(kind) = topics.get(2)? else { return None };
            out["event"] = json!("UaRegistered");
            out["ua"] = json!(scval_b32(topics.get(1)?)?);
            out["kind"] = json!(kind);
        }
        _ => return None,
    }
    Some(out)
}

impl SorobanAdapter {
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        let p = &cfg.params;
        let passphrase = p
            .get("network_passphrase")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("chain {}: params.network_passphrase is required", cfg.chain_key()))?;
        let mut lanes = Vec::new();
        for (s, &i) in signers.iter().zip(&cfg.lanes) {
            lanes.push(Lane { index: i, address: stellar_account_strkey(&lane_pk(s)?) });
        }
        let fee_bump = match p.get("fee_bump_lane").and_then(|v| v.as_integer()) {
            Some(i) => Some(cfg.lanes.iter().position(|&l| l as i64 == i).ok_or_else(|| anyhow!("fee_bump_lane {i} is not a lane"))?),
            None => None,
        };
        Ok(Self {
            key: cfg.chain_key(),
            rpc: cfg.rpc_urls.clone(),
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build()?,
            network_id: network_id(passphrase),
            signers: signers.iter().map(clone_signer).collect::<Result<_>>()?,
            lanes,
            fee_bump,
            base_fee: p.get("base_fee").and_then(|v| v.as_integer()).map(|v| v as u32).unwrap_or(DEFAULT_BASE_FEE),
            quorum: cfg.finality.quorum.max(1),
            relay_fee: RelayFeePolicy::from_cfg(cfg).with_context(|| format!("chain {}", cfg.chain_key()))?,
            max_deposit: stroops(cfg, "max_deposit_per_job")?,
            max_resource_fee: stroops(cfg, "max_resource_fee_per_job")?,
            hashes: Mutex::new(HashMap::new()),
            tx_limit: Mutex::new(None),
            entry_limit: Mutex::new(None),
        })
    }

    async fn call(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let r: Value = self.http.post(url).json(&body).send().await?.json().await.with_context(|| format!("{method}: decode"))?;
        if let Some(e) = r.get("error") {
            bail!("{method}: {e}");
        }
        Ok(r["result"].clone())
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.call(&self.rpc[0], method, params).await
    }

    async fn ledger_hash(&self, url: &str, seq: u64) -> Result<String> {
        let r = self.call(url, "getLedgers", json!({"startLedger": seq, "pagination": {"limit": 1}})).await?;
        let l = &r["ledgers"][0];
        if l["sequence"].as_u64() != Some(seq) {
            bail!("ledger {seq} not available");
        }
        let h = l["hash"].as_str().ok_or_else(|| anyhow!("ledger {seq} without hash"))?;
        Ok(format!("0x{}", h.to_lowercase()))
    }

    fn signer(&self, lane: usize) -> Result<&LocalSigner> {
        self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))
    }

    fn tx(&self, lane: usize, seq: i64, valid_until: u64, call: InvokeContractArgs, auth: Vec<SorobanAuthorizationEntry>) -> Result<Transaction> {
        Ok(Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(lane_pk(self.signer(lane)?)?)),
            fee: self.base_fee,
            seq_num: SequenceNumber(seq),
            // Tx chưa vào hết hạn cùng payload ⇒ sequence của lane không treo (review S14).
            cond: Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(valid_until) }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: HostFunction::InvokeContract(call),
                    auth: auth.try_into()?,
                }),
            }]
            .try_into()?,
            ext: TransactionExt::V0,
        })
    }

    fn decorated(signer: &LocalSigner, hash: &[u8; 32]) -> Result<DecoratedSignature> {
        let pk = lane_pk(signer)?;
        Ok(DecoratedSignature {
            hint: SignatureHint(pk[28..].try_into()?),
            signature: Signature(signer.sign(hash)?.try_into()?),
        })
    }

    /// The bytes `tx_max_size_bytes` counts for `tx`, known with no key used: its V1 envelope with a blank signature of ed25519's
    /// length. A fee bump around it is not counted (measured, `e2e_ua8_tx_size_limit`).
    fn envelope_size(tx: &Transaction) -> Result<usize> {
        let blank = DecoratedSignature { hint: SignatureHint([0; 4]), signature: Signature(vec![0; 64].try_into()?) };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope { tx: tx.clone(), signatures: vec![blank].try_into()? });
        Ok(env.to_xdr(Limits::none())?.len())
    }

    /// A read-only call by simulation from lane 0; `None` = it needs a restore (an archived entry): unknown, never a
    /// default value. A simulation error is an `Err` (fail closed): `SimRefused` when the host refused the call or its answer is
    /// over what the node reads, which a retry never changes.
    async fn view(&self, contract: &ScAddress, f: &str, args: Vec<ScVal>) -> Result<Option<ScVal>> {
        let (value, restore) = self.sim_view(contract, f, args).await?;
        Ok(value.filter(|_| !restore))
    }

    /// `view` for `op_consumed`: a view the host refuses says nothing about the op, so the answer is unknown. As a failed read the job
    /// would go back to the queue on every claim, and the queue is per chain.
    async fn view_or_unknown(&self, contract: &ScAddress, f: &str, args: Vec<ScVal>) -> Result<Option<ScVal>> {
        match self.view(contract, f, args).await {
            Err(e) if e.is::<SimRefused>() => Ok(None),
            r => r,
        }
    }

    /// A read-only call by simulation: its value, and whether the simulation needs a restore (it may still have read the
    /// archived entry, so the value can come with `true`, and only with `true` can it be absent).
    async fn sim_view(&self, contract: &ScAddress, f: &str, args: Vec<ScVal>) -> Result<(Option<ScVal>, bool)> {
        let call = InvokeContractArgs { contract_address: contract.clone(), function_name: ScSymbol(f.try_into()?), args: args.try_into()? };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope { tx: self.tx(0, 0, 0, call, vec![])?, signatures: Default::default() });
        let sim = self.rpc("simulateTransaction", json!({"transaction": env.to_xdr_base64(Limits::none())?})).await?;
        if let Some(e) = sim.get("error").and_then(|e| e.as_str()) {
            return Err(SimRefused(format!("{f}: {e}")).into());
        }
        let mut restore = sim.get("restorePreamble").is_some_and(|r| !r.is_null());
        if let Some(d) = sim["transactionData"].as_str() {
            restore |= restores(&SorobanTransactionData::from_xdr_base64(d, xdr_limits(1 << 20))?);
        }
        match sim["results"][0]["xdr"].as_str() {
            Some(x) => Ok((Some(ScVal::from_xdr_base64(x, Limits { depth: XDR_DEPTH, len: 1 << 16 }).map_err(|e| SimRefused(format!("{f}: answer over the read bound: {e}")))?), restore)),
            None if restore => Ok((None, true)),
            None => bail!("{f}: simulation without a result"),
        }
    }

    /// Decision (D): the router's executor, read once from `router.executor()` (the router names it at construction,
    /// immutable); a plain pay, a pay-meta or a relay fee to it is refused like one to the router.
    /// A router without `executor()` (an old stateless router, not the relay-fee contract) is a config error: the
    /// job fails with it (`Revert`), never requeued forever; a transport failure or a needed restore stays `Transport`.
    async fn load_executor(&self) -> std::result::Result<(), SimError> {
        let (Some(router), None) = (&self.relay_fee.router, self.relay_fee.executor.get()) else { return Ok(()) };
        let config = |why: String| SimError::Revert(format!(
            "config: params.relay_fee.router {router} {why}; deploy the router with its executor (deploy.sh soroban <net> relay_fee)"));
        match self.view(router, "executor", vec![]).await {
            Ok(Some(ScVal::Address(x))) => {
                let _ = self.relay_fee.executor.set(x);
                Ok(())
            }
            Ok(Some(v)) => Err(config(format!("executor() is not an address: {v:?}"))),
            Ok(None) => Err(SimError::Transport("router executor(): its state needs a restore".into())),
            Err(e) if e.is::<SimRefused>() => Err(config(format!("has no executor(): {e:#}"))),
            Err(e) => Err(SimError::Transport(format!("router executor(): {e:#}"))),
        }
    }

    /// The registry's `relayers()`, read until it answers and then kept: the list is immutable, so a lane not listed stays
    /// refused whatever a later read says. Only a job that names a relayer needs it: an RPC failure is `Transport`, a needed
    /// restore or a registry that does not answer `Revert`, so an idle registry costs that job and no other.
    async fn load_relayers(&self) -> std::result::Result<(), SimError> {
        let (Some(registry), None) = (&self.relay_fee.ua_registry, self.relay_fee.relayers.get()) else { return Ok(()) };
        let config = |why: String| SimError::Revert(format!("config: params.ua_registry {registry} {why}"));
        match self.view(registry, "relayers", vec![]).await {
            Ok(Some(ScVal::Vec(Some(v)))) => {
                let list: Option<Vec<ScAddress>> = v.iter().map(|a| match a {
                    ScVal::Address(a) => Some(a.clone()),
                    _ => None,
                }).collect();
                let _ = self.relay_fee.relayers.set(list.ok_or_else(|| config(format!("relayers() is not a list of addresses: {v:?}")))?);
                Ok(())
            }
            Ok(Some(v)) => Err(config(format!("relayers() is not a list: {v:?}"))),
            Ok(None) => Err(SimError::Revert("registry relayers(): its state needs a restore".into())),
            Err(e) if e.is::<SimRefused>() => Err(config(format!("has no relayers(): {e:#}"))),
            Err(e) => Err(SimError::Transport(format!("registry relayers(): {e:#}"))),
        }
    }

    /// The network's `tx_max_size_bytes`, read for each job: a setting the validators vote, so a change is seen on the next good
    /// read, with no restart. A read that fails uses the last good answer, so this limit never stops a chain simulation still
    /// serves; only the first read, with no answer yet, is `Transport`, as a failed simulation.
    async fn tx_max_size(&self) -> std::result::Result<usize, SimError> {
        let read = self.read_tx_max_size().await;
        let mut last = self.tx_limit.lock().unwrap_or_else(|e| e.into_inner());
        match read {
            Ok(limit) => {
                *last = Some(limit);
                Ok(limit)
            }
            Err(why) => (*last).inspect(|l| tracing::warn!(chain = %self.key, "tx_max_size_bytes: {why}; using the last answer, {l}"))
                .ok_or_else(|| SimError::Transport(format!("tx_max_size_bytes: {why}"))),
        }
    }

    async fn read_tx_max_size(&self) -> std::result::Result<usize, String> {
        match self.read_setting(ConfigSettingId::ContractBandwidthV0).await? {
            ConfigSettingEntry::ContractBandwidthV0(b) => Ok(b.tx_max_size_bytes as usize),
            other => Err(format!("not the bandwidth setting: {other:?}")),
        }
    }

    async fn read_setting(&self, id: ConfigSettingId) -> std::result::Result<ConfigSettingEntry, String> {
        let k = LedgerKey::ConfigSetting(LedgerKeyConfigSetting { config_setting_id: id });
        let k = k.to_xdr_base64(Limits::none()).map_err(|e| e.to_string())?;
        let r = self.rpc("getLedgerEntries", json!({"keys": [k]})).await.map_err(|e| format!("{e:#}"))?;
        let x = r["entries"][0]["xdr"].as_str().ok_or("no entry")?;
        match LedgerEntryData::from_xdr_base64(x, xdr_limits(1 << 16)) {
            Ok(LedgerEntryData::ConfigSetting(c)) => Ok(c),
            other => Err(format!("not a setting: {other:?}")),
        }
    }

    /// The network's `contract_data_entry_size_bytes`, read as `tx_max_size`; a failed read uses the last answer. `None`: never
    /// answered, so the check cannot run. That job goes on: the chain still refuses an entry over the limit.
    async fn entry_max_size(&self) -> Option<usize> {
        let read = match self.read_setting(ConfigSettingId::ContractDataEntrySizeBytes).await {
            Ok(ConfigSettingEntry::ContractDataEntrySizeBytes(n)) => Ok(n as usize),
            Ok(other) => Err(format!("not the entry setting: {other:?}")),
            Err(why) => Err(why),
        };
        let mut last = self.entry_limit.lock().unwrap_or_else(|e| e.into_inner());
        match read {
            Ok(limit) => *last = Some(limit),
            Err(why) => tracing::warn!(chain = %self.key, "contract_data_entry_size_bytes: {why}; using the last answer, {:?}", *last),
        }
        *last
    }

    /// `getLedgerEntries` key of `lane`'s account.
    fn account_key(&self, lane: usize) -> Result<String> {
        let account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(lane_pk(self.signer(lane)?)?)));
        Ok(LedgerKey::Account(LedgerKeyAccount { account_id: account }).to_xdr_base64(Limits::none())?)
    }

    /// Owner 2026-11-02: a `ua_metatx` is free to the client and outside the `call` share, so on a mandate it runs only code the operator
    /// listed: the contract's instance entry, read through the host, names a Wasm of `params.mandate_wasm_hashes`. A failed read is
    /// `Transport`; no instance, an executable that is no Wasm, or a hash not listed is `Revert`, `MANDATE_WASM_REFUSED`, unset refusing all.
    async fn mandate_wasm_ok(&self, c: &ScAddress) -> std::result::Result<(), SimError> {
        let refused = |why: String| SimError::Revert(format!("{MANDATE_WASM_REFUSED}: {c} {why}"));
        let k = LedgerKey::ContractData(LedgerKeyContractData { contract: c.clone(), key: ScVal::LedgerKeyContractInstance, durability: ContractDataDurability::Persistent });
        let k = k.to_xdr_base64(Limits::none()).map_err(|e| refused(e.to_string()))?;
        let r = self.rpc("getLedgerEntries", json!({"keys": [k]})).await.map_err(|e| SimError::Transport(format!("{e:#}")))?;
        if r.get("latestLedger").is_none() {
            return Err(SimError::Transport(format!("getLedgerEntries without latestLedger: {r}")));
        }
        let Some(x) = r["entries"][0]["xdr"].as_str() else { return Err(refused("has no contract instance".into())) };
        let data = LedgerEntryData::from_xdr_base64(x, xdr_limits(1 << 20)).map_err(|e| refused(format!("instance unreadable: {e}")))?;
        let LedgerEntryData::ContractData(ContractDataEntry { val: ScVal::ContractInstance(i), .. }) = data else { return Err(refused("has no contract instance".into())) };
        match i.executable {
            ContractExecutable::Wasm(Hash(h)) if self.relay_fee.mandate_wasms.contains(&h) => Ok(()),
            ContractExecutable::Wasm(Hash(h)) => Err(refused(format!("runs Wasm {}, not in params.mandate_wasm_hashes", hex(&h)))),
            e => Err(refused(format!("runs {e:?}, no Wasm"))),
        }
    }

    /// CTR-ACC-07: a delegate's `mtx_revoke` / `mtx_mandate_pay` refused `StaleEpoch` (the mandate's error #13): the
    /// reason names `epoch(token)`, re-read now, so the client re-signs (EVM: the revert names `StaleEpoch(current,
    /// signed)`). `None` = not that refusal.
    async fn stale_epoch(&self, call: &InvokeContractArgs, err: &str) -> Option<String> {
        let i = match call.function_name.0.as_slice() {
            b"mtx_revoke" => 2,
            b"mtx_mandate_pay" => 4,
            _ => return None,
        };
        if !err.contains("Error(Contract, #13)") {
            return None;
        }
        let ScVal::U64(signed) = call.args.get(i)? else { return None };
        let token = call.args.first()?.clone();
        let Some(ScVal::U64(current)) = self.view(&call.contract_address, "epoch", vec![token]).await.ok().flatten() else { return None };
        (current != *signed).then(|| format!("StaleEpoch: signed {signed}, epoch(token) {current}; re-read epoch(token) and re-sign (CTR-ACC-07)"))
    }
}

/// `txSOROBAN_INVALID`, plain or inside a fee bump's `txFEE_BUMP_INNER_FAILED`. Bytes that do not decode are not it.
fn soroban_invalid(error_result: &Value) -> bool {
    let Some(r) = error_result.as_str().and_then(|x| TransactionResult::from_xdr_base64(x, xdr_limits(1 << 16)).ok()) else { return false };
    match r.result {
        TransactionResultResult::TxSorobanInvalid => true,
        TransactionResultResult::TxFeeBumpInnerFailed(p) => matches!(p.result.result, InnerTransactionResultResult::TxSorobanInvalid),
        _ => false,
    }
}

/// `simulateTransaction` answered `error`: the host refused the call (not a transport failure).
#[derive(Debug)]
struct SimRefused(String);

impl std::fmt::Display for SimRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SimRefused {}

/// XDR an RPC answers, or the node built around what a job put in, inside a transaction's own levels: bounded by length and depth,
/// as `Limits::len` alone is not. A stack overflow aborts the whole node.
fn xdr_limits(len: usize) -> Limits {
    Limits { depth: 2 * XDR_DEPTH, len }
}

/// `params.<key>`, a non-negative integer of stroops; absent = 0.
fn stroops(cfg: &ChainCfg, key: &str) -> Result<u64> {
    match cfg.params.get(key) {
        None => Ok(0),
        Some(v) => v.as_integer().and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| anyhow!("chain {}: params.{key} must be a non-negative integer (stroops), not {v}", cfg.chain_key())),
    }
}

fn clone_signer(s: &LocalSigner) -> Result<LocalSigner> {
    match s {
        LocalSigner::Ed(k) => Ok(LocalSigner::Ed(k.clone())),
        LocalSigner::Secp(_) => bail!("soroban lanes are ed25519 (m/44'/148'/i')"),
    }
}

#[async_trait]
impl ChainAdapter for SorobanAdapter {
    fn family(&self) -> Family {
        Family::Soroban
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let op = job.op.clone().ok_or_else(|| SimError::Revert("job without op".into()))?;
        let rv = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let pk = lane_pk(self.signer(lane).map_err(rv)?).map_err(rv)?;
        let lane_addr = ScAddress::from_str(&stellar_account_strkey(&pk)).map_err(|e| SimError::Revert(e.to_string()))?;
        self.load_executor().await?;
        let registry_write = job.kind.as_deref() == Some("call") || is_accept(job);
        if registry_write && !op["args"]["relayer"].is_null() {
            self.load_relayers().await?;
        }
        let (call, auth, valid_until) = job_tx(&self.network_id, job.kind.as_deref(), &op, &lane_addr, &self.relay_fee).map_err(rv)?;
        let valid_until = tx_deadline(valid_until).map_err(rv)?;
        if job.kind.as_deref() == Some("ua_metatx") && UA_FNS.iter().any(|f| f.class == Class::Mandate && f.name.as_bytes() == call.function_name.0.as_slice()) {
            self.mandate_wasm_ok(&call.contract_address).await?;
        }
        if registry_write {
            self.ua8_precheck(&op).await?;
        }
        let tx = self.tx(lane, 0, valid_until, call.clone(), auth.clone()).map_err(rv)?;
        let env = TransactionEnvelope::Tx(TransactionV1Envelope { tx: tx.clone(), signatures: Default::default() });
        let b64 = env.to_xdr_base64(Limits::none()).map_err(|e| SimError::Revert(e.to_string()))?;
        let sim = self
            .rpc("simulateTransaction", json!({"transaction": b64}))
            .await
            .map_err(|e| SimError::Transport(format!("{e:#}")))?;
        if let Some(err) = sim.get("error").and_then(|e| e.as_str()) {
            if let Some(stale) = self.stale_epoch(&call, err).await {
                return Err(SimError::Revert(stale));
            }
        }
        let data = sim_data(&sim, self.max_deposit)?;
        if u64::try_from(data.resource_fee).map_or(true, |f| f > self.max_resource_fee) {
            return Err(SimError::Revert(format!("{RESOURCE_FEE_OVER_CAP}: {} stroops declared, params.max_resource_fee_per_job {}", data.resource_fee, self.max_resource_fee)));
        }
        check_recorded_auth(&sim, &call, &auth).map_err(rv)?;
        if !auth.iter().any(|e| matches!(e.credentials, SorobanCredentials::Address(_))) {
            check_no_other_signer(&sim).map_err(rv)?;
        }
        let mut tx = tx;
        tx.fee = u32::try_from(self.base_fee as i64 + data.resource_fee).map_err(|_| SimError::Revert("fee overflow".into()))?;
        tx.ext = TransactionExt::V1(data);
        // simulation does not see this limit, and `sendTransaction` would refuse it: this job's own state, named here
        let size = Self::envelope_size(&tx).map_err(rv)?;
        let limit = self.tx_max_size().await?;
        if size > limit {
            return Err(SimError::Revert(format!("transaction of {size} B over the network's tx_max_size_bytes ({limit})")));
        }
        // simulation does not refuse this write, and on chain it fails on the lane's fee: this job's own state
        if let Some(size) = largest_data_write(&sim) {
            if let Some(limit) = self.entry_max_size().await.filter(|l| size > *l) {
                return Err(SimError::Revert(format!("entry of {size} B over the network's contract_data_entry_size_bytes ({limit})")));
            }
        }
        let body = tx.to_xdr(Limits::none()).map_err(|e| SimError::Revert(e.to_string()))?;
        Ok(Built { job_id: job.id, body, valid_until, meta: json!({}) })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let mut tx = Transaction::from_xdr(&built.body, xdr_limits(built.body.len()))?;
        tx.seq_num = SequenceNumber(sequence as i64 + 1);
        let inner_hash = tx.hash(self.network_id)?;
        let inner = TransactionV1Envelope { signatures: vec![Self::decorated(self.signer(lane)?, &inner_hash)?].try_into()?, tx };
        let (env, hash) = match self.fee_bump {
            None => (TransactionEnvelope::Tx(inner), inner_hash),
            Some(f) => {
                let payer = self.signer(f)?;
                let fb = FeeBumpTransaction {
                    fee_source: MuxedAccount::Ed25519(Uint256(lane_pk(payer)?)),
                    // Phí bao gồm một "op" nữa của chính fee-bump (CAP-15).
                    fee: inner.tx.fee as i64 + self.base_fee as i64,
                    inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                    ext: FeeBumpTransactionExt::V0,
                };
                let h = fb.hash(self.network_id)?;
                let sig = Self::decorated(payer, &h)?;
                (TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope { tx: fb, signatures: vec![sig].try_into()? }), h)
            }
        };
        Ok(Signed {
            job_id: built.job_id,
            tx_id: format!("0x{}", hex(&hash)),
            raw: env.to_xdr(Limits::none())?,
            valid_until: built.valid_until,
            sequence,
        })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        let env = TransactionEnvelope::from_xdr(&signed.raw, xdr_limits(signed.raw.len()))?;
        let r = self.rpc("sendTransaction", json!({"transaction": env.to_xdr_base64(Limits::none())?})).await?;
        match r["status"].as_str() {
            Some("PENDING") | Some("DUPLICATE") => Ok(()),
            // ERROR = CheckTx-equivalent refusal (bad seq/auth/fee/malformed): the same bytes never pass ⇒ rebuild, except
            // `txSOROBAN_INVALID`, which a rebuild never passes either. TRY_AGAIN_LATER (queue full) and transport errors stay retryable.
            Some("ERROR") if soroban_invalid(&r["errorResultXdr"]) => Err(Refused(format!("sendTransaction ERROR: {}", r["errorResultXdr"])).into()),
            Some("ERROR") => Err(Rejected(format!("sendTransaction ERROR: {}", r["errorResultXdr"])).into()),
            other => bail!("sendTransaction {}: {}", other.unwrap_or("?"), r["errorResultXdr"]),
        }
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let r = self.rpc("getTransaction", json!({"hash": tx_id.trim_start_matches("0x")})).await?;
        Ok(match r["status"].as_str() {
            Some("SUCCESS") => TxStatus::Mined { height: r["ledger"].as_u64().unwrap_or_default(), tx_hash: None },
            Some("FAILED") => TxStatus::Reverted { reason: format!("tx failed: {}", r["resultXdr"].as_str().unwrap_or("")) },
            _ => TxStatus::Unknown,
        })
    }

    /// NET-SOR-14: `feeCharged` of a transaction that landed, `SUCCESS` or `FAILED`. Under a fee bump the outer result, the fee
    /// that left the fee account (`e2e_ua8_spend_stop` compares both with the balances). What this cannot read is an `Err`, never 0.
    async fn tx_fee(&self, tx_id: &str) -> Result<Option<u128>> {
        let r = self.rpc("getTransaction", json!({"hash": tx_id.trim_start_matches("0x")})).await?;
        if !matches!(r["status"].as_str(), Some("SUCCESS" | "FAILED")) {
            bail!("getTransaction {tx_id}: {}, not landed", r["status"]);
        }
        let x = r["resultXdr"].as_str().ok_or_else(|| anyhow!("getTransaction {tx_id} without resultXdr"))?;
        let fee = TransactionResult::from_xdr_base64(x, xdr_limits(1 << 16))?.fee_charged;
        Ok(Some(u128::try_from(fee).with_context(|| format!("feeCharged {fee}"))?))
    }

    /// NET-SOR-14 (owner ruling I-1): the native balance of the account that pays, the lane's own or under a fee bump the fee
    /// account alone. An account that does not exist holds 0, which is an answer (the RPC still names its `latestLedger`); a failed
    /// read is an `Err`, and the last balance stands.
    async fn lane_balance(&self, lane: usize) -> Result<Option<u128>> {
        let k = self.account_key(self.fee_bump.unwrap_or(lane))?;
        let r = self.rpc("getLedgerEntries", json!({"keys": [k]})).await?;
        if r.get("latestLedger").is_none() {
            bail!("getLedgerEntries without latestLedger: {r}");
        }
        let Some(e) = r["entries"].get(0) else { return Ok(Some(0)) };
        let x = e["xdr"].as_str().ok_or_else(|| anyhow!("account entry without xdr"))?;
        match LedgerEntryData::from_xdr_base64(x, xdr_limits(1 << 16))? {
            LedgerEntryData::Account(a) => Ok(Some(u128::try_from(a.balance)?)),
            _ => bail!("not an account entry"),
        }
    }

    async fn sequence(&self, lane: usize) -> Result<u64> {
        let k = self.account_key(lane)?;
        let r = self.rpc("getLedgerEntries", json!({"keys": [k]})).await?;
        let x = r["entries"][0]["xdr"].as_str().ok_or_else(|| anyhow!("lane {} account does not exist", self.lanes[lane].address))?;
        match LedgerEntryData::from_xdr_base64(x, xdr_limits(1 << 16))? {
            LedgerEntryData::Account(a) => Ok(a.seq_num.0 as u64),
            _ => bail!("not an account entry"),
        }
    }

    /// SCP: ledger đã đóng là final; quorum = các endpoint khác trả cùng hash cho ledger đó.
    async fn final_head(&self) -> Result<Option<Head>> {
        let r = self.rpc("getLatestLedger", json!({})).await?;
        let height = r["sequence"].as_u64().ok_or_else(|| anyhow!("getLatestLedger without sequence"))?;
        let hash = format!("0x{}", r["id"].as_str().ok_or_else(|| anyhow!("getLatestLedger without id"))?.to_lowercase());
        let mut agree = 1;
        for url in &self.rpc[1..] {
            if self.ledger_hash(url, height).await.ok().as_deref() == Some(hash.as_str()) {
                agree += 1;
            }
        }
        Ok((agree >= self.quorum).then_some(Head { height, hash }))
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        if let Some(h) = self.hashes.lock().ok().and_then(|m| m.get(&height).cloned()) {
            return Ok(h);
        }
        let h = self.ledger_hash(&self.rpc[0], height).await?;
        if let Ok(mut m) = self.hashes.lock() {
            if m.len() > 4096 {
                m.clear();
            }
            m.insert(height, h.clone());
        }
        Ok(h)
    }

    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        // the tokens' events, and the router's `RelayFeePaid` (`RelayFeePaid` only from it, a token event never)
        let router = self.relay_fee.router.as_ref().map(|r| r.to_string());
        let contracts: Vec<String> = contracts.iter().cloned().chain(router.clone()).collect();
        for chunk in contracts.chunks(CONTRACTS_PER_FILTER) {
            let filter = json!([{"type": "contract", "contractIds": chunk}]);
            let mut cursor: Option<String> = None;
            'pages: loop {
                let r = self.rpc("getEvents", events_params(&filter, from, to, cursor.as_deref())).await?;
                let evs = r["events"].as_array().cloned().unwrap_or_default();
                for ev in &evs {
                    // Thứ tự ledger tăng dần; trang theo cursor chạy tới đỉnh ⇒ qua `to` là hết phần của ta.
                    if ev["ledger"].as_u64().is_some_and(|l| l > to) {
                        break 'pages;
                    }
                    if let Some(mut e) = decode_event(ev).filter(|e| (e["event"] == "RelayFeePaid") == (e["contract"].as_str() == router.as_deref())) {
                        e["block_hash"] = json!(self.block_hash(e["block_number"].as_u64().unwrap_or_default()).await?);
                        out.push(e);
                    }
                }
                match r["cursor"].as_str() {
                    Some(c) if evs.len() as u64 == EVENT_PAGE => cursor = Some(c.to_owned()),
                    _ => break,
                }
            }
        }
        out.sort_by_key(|e| (e["block_number"].as_u64(), e["tx_hash"].as_str().map(str::to_owned), e["log_index"].as_u64()));
        Ok(crate::indexer::join_pay_events(out))
    }

    /// Owner 2026-11-02: the client's list, as EVM's, so a token registered after the start is served without a restart.
    fn refresh_tokens(&self, nc: &crate::odoo::NodeConfig) {
        if let Ok(mut t) = self.relay_fee.tokens.write() {
            *t = nc.tokens.iter().filter_map(|t| ScAddress::from_str(&t.address).ok()).collect();
        }
    }

    /// Reads `relayers()` early and only logs a failure: the list concerns relayer-mode jobs alone, and `build` reads it for them.
    async fn start_check(&self) -> Result<()> {
        if let Err(e) = self.load_relayers().await {
            tracing::warn!(chain = %self.key, "registry relayers() not read at start, relayer-mode jobs read it again: {e}");
        }
        Ok(())
    }

    /// R80 for `ua_metatx` jobs (spec §9.3, NET-SOR-12): a pay ref spent (`ua_ref_used(ua, pay_ref)` on the token; the
    /// mandate's `paid(pay_ref)`), or the UA's lane past the job's nonce (`ua_nonce(ua, lane) > nonce`; a mandate owner
    /// entry reads `owner()` first), or a slot accepted (`member_accepted`). A view that needs a restore or that the host refuses, a
    /// native signer, or a job without a lane is unknown.
    /// `signed_op` jobs keep the host's random nonces: unknown.
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        if job.kind.as_deref() != Some("ua_metatx") {
            return Ok(None);
        }
        let Some(Ok((call, f))) = job.op.as_ref().map(ua_call) else { return Ok(None) };
        // the guard's allow-list: a job it refuses is never reported consumed by a contract it would not serve
        if !listed(&call, f, &self.relay_fee) {
            return Ok(None);
        }
        let (a, c) = (call.args.as_slice(), &call.contract_address);
        if f.class == Class::Mandate {
            match self.mandate_wasm_ok(c).await {
                Ok(()) => {}
                Err(SimError::Revert(_)) => return Ok(None),
                Err(SimError::Transport(e)) => bail!("{e}"),
            }
        }
        let b32 = |b: [u8; 32]| -> Result<ScVal> { Ok(ScVal::Bytes(b.to_vec().try_into()?)) };
        let by_ref = match f.name {
            "ua_pay" => Some((c.clone(), "ua_ref_used", vec![a[0].clone(), a[3].clone()])),
            "ua_pay_meta" => {
                let (Some(salt), Some(meta)) = (bytes_arg(&a[3]), bytes_arg(&a[4])) else { return Ok(None) };
                Some((c.clone(), "ua_ref_used", vec![a[0].clone(), b32(meta_pay_id(salt, meta))?]))
            }
            "ua_relay" => {
                let ScVal::Address(token) = &a[5] else { return Ok(None) };
                if !self.relay_fee.token(token) {
                    return Ok(None);
                }
                Some((token.clone(), "ua_ref_used", vec![a[0].clone(), b32(ua_relay_ref(&self.network_id, a)?)?]))
            }
            "mtx_mandate_pay" => Some((c.clone(), "paid", vec![a[3].clone()])),
            ACCEPT => {
                let Some(index) = field(&a[1], "index") else { return Ok(None) };
                Some((c.clone(), "member_accepted", vec![a[0].clone(), index.clone()]))
            }
            _ => None,
        };
        if let Some((contract, view, args)) = by_ref {
            return Ok(match self.view_or_unknown(&contract, view, args).await? {
                Some(ScVal::Bool(b)) => Some(b),
                _ => None,
            });
        }
        let Some(l) = f.lane else { return Ok(None) };
        let ScVal::U64(nonce) = a[l + 1] else { return Ok(None) };
        let signer = match f.from {
            Some(i) => a[i].clone(),
            None => match self.view_or_unknown(c, "owner", vec![]).await? {
                Some(o) => o,
                None => return Ok(None),
            },
        };
        let ua = match (&signer, holder(&signer)) {
            (ScVal::Bytes(b), _) if b.len() == 32 => signer.clone(),
            (_, Some(Holder::Ua(u))) => ScVal::Bytes(u.to_vec().try_into()?),
            _ => return Ok(None), // a native signer: host authorisation, no lane
        };
        Ok(match self.view_or_unknown(c, "ua_nonce", vec![ua, a[l].clone()]).await? {
            Some(ScVal::U64(next)) => Some(next > nonce),
            _ => None,
        })
    }

    /// A `ua_metatx` names its deadline in its arguments, so a job picked up after a restart reads it from the built call, bounded as `build` bounds it.
    fn job_valid_until(&self, job: &Job) -> u64 {
        let built = (job.kind.as_deref() == Some("ua_metatx")).then_some(job.op.as_ref()).flatten().and_then(|op| ua_call(op).ok());
        let signed = built.and_then(|(call, _)| ua_valid_until(&call).ok()).unwrap_or_else(|| job.op.as_ref().and_then(|o| o["valid_until"].as_u64()).unwrap_or(0));
        // what `tx_deadline` gave the transaction before the restart is no later than this
        signed.min(crate::submit::now().saturating_add(max_valid_for()))
    }

    /// By kind, less a plain `signed_op` whose root is a token payment. Anything `token_payment` cannot read stays in the share. A member's
    /// acceptance is a registry write free to the client, so it counts as a `call` job.
    fn in_call_share(&self, job: &Job) -> bool {
        let payment = matches!(job.kind.as_deref(), None | Some("signed_op")) && job.op.as_ref().is_some_and(|op| token_payment(op, &self.relay_fee).is_some());
        (crate::adapter::call_share_by_kind(job) || is_accept(job)) && !payment
    }

    /// Spec §9.1: a `ua_metatx` job's id is its op digest, recomputed from its arguments (`settle`: none, the job's own).
    async fn digest(&self, job: &Job) -> std::result::Result<Option<alloy::primitives::B256>, SimError> {
        if job.kind.as_deref() == Some("ua_metatx") {
            if let Some(Ok((call, f))) = job.op.as_ref().map(ua_call) {
                if let Ok(Some(d)) = ua_digest(&self.network_id, &call, f) {
                    return Ok(Some(d.into()));
                }
            }
        }
        Ok(crate::submit::job_digest(job))
    }
}

/// Trang `getEvents`: trang sau chỉ mang cursor — stellar-rpc từ chối khoảng ledger kèm cursor
/// (`GetEventsRequest.Valid`: "ledger ranges and cursor cannot both be set").
fn events_params(filter: &Value, from: u64, to: u64, cursor: Option<&str>) -> Value {
    match cursor {
        None => json!({"startLedger": from, "endLedger": to + 1, "filters": filter, "pagination": {"limit": EVENT_PAGE}}),
        Some(c) => json!({"filters": filter, "pagination": {"cursor": c, "limit": EVENT_PAGE}}),
    }
}

/// CTR-MTX-26: `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`, the token's `meta_pay_id`.
pub fn meta_pay_id(salt: &[u8], meta: &[u8]) -> [u8; 32] {
    let mut b = b"scaas.pay.meta".to_vec();
    b.extend_from_slice(salt);
    b.extend_from_slice(alloy::primitives::keccak256(meta).as_slice());
    alloy::primitives::keccak256(b).0
}

/// CTR-MTX-27 `ref` (the router's `relay_ref`): `keccak256("scaas.relayfee" ‖ network id ‖ xdr(target) ‖
/// keccak256(xdr((func, args))) ‖ salt)`, `xdr((func, args))` the ScVal `Vec[Symbol(func), Vec(args)]`. The
/// function symbol is hashed as received (any bytes), never re-encoded.
pub fn relay_ref(network: &[u8; 32], target: &ScAddress, func: &ScSymbol, args: &[ScVal], salt: &[u8; 32]) -> [u8; 32] {
    let pair = vec![ScVal::Symbol(func.clone()), ScVal::Vec(Some(ScVec(args.to_vec().try_into().expect("args"))))];
    let call = ScVal::Vec(Some(ScVec(pair.try_into().expect("pair"))));
    let mut b = b"scaas.relayfee".to_vec();
    b.extend_from_slice(network);
    b.extend_from_slice(&ScVal::Address(target.clone()).to_xdr(Limits::none()).expect("xdr"));
    b.extend_from_slice(alloy::primitives::keccak256(call.to_xdr(Limits::none()).expect("xdr")).as_slice());
    b.extend_from_slice(salt);
    alloy::primitives::keccak256(b).0
}

fn bytes_arg(v: &ScVal) -> Option<&[u8]> {
    match v {
        ScVal::Bytes(b) => Some(b.as_slice()),
        _ => None,
    }
}

fn op_bytes(op: &Value, k: &str) -> Result<Vec<u8>> {
    hex_of(&op[k]).with_context(|| format!("op.{k}"))
}

/// Pay-meta job: the signed invocation is the token's `pay_meta`; `op.salt` / `op.meta` must be the signed
/// arguments (the auth entry covers them), `op.pay_ref` (when given) the commitment, `meta` within the cap.
pub fn pay_meta_job(op: &Value, max_meta: usize) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let (call, auth) = host_call(op)?;
    if call.function_name.0.as_slice() != b"pay_meta" || call.args.len() != 6 {
        bail!("pay-meta job must sign pay_meta(from, to, amount, salt, meta, valid_until)");
    }
    let (salt, meta) = (op_bytes(op, "salt")?, op_bytes(op, "meta")?);
    if meta.len() > max_meta {
        bail!("meta is {} B, above max_pay_meta_bytes {max_meta}", meta.len());
    }
    if bytes_arg(&call.args[3]) != Some(&salt[..]) || bytes_arg(&call.args[4]) != Some(&meta[..]) {
        bail!("op.salt / op.meta differ from the signed pay_meta arguments");
    }
    if !op["pay_ref"].is_null() && op_bytes(op, "pay_ref")? != meta_pay_id(&salt, &meta) {
        bail!("pay_ref != metaPayId(salt, meta)");
    }
    Ok((call, auth))
}

/// What the node accepts as a relay-fee job (controller call 2026-10-27, owner may override): the configured
/// router, a registered token, and a fee that reaches this lane and is at least `min_amount` (`relay_fee_ours`).
pub struct RelayFeePolicy {
    pub router: Option<ScAddress>,
    /// The chain's registered tokens: the config's until the client's `node_config` answers (`refresh_tokens`), as EVM's.
    pub tokens: std::sync::RwLock<Vec<ScAddress>>,
    pub params: crate::config::RelayParams,
    /// `params.dex` (`C…`): the DEX whose `settle` / `ua_cancel` `ua_metatx` jobs serve; `None` = none.
    pub dex: Option<ScAddress>,
    /// The router's executor (decision (D)), read once from `router.executor()` (`SorobanAdapter::load_executor`).
    pub executor: OnceLock<ScAddress>,
    /// `params.ua_registry` (`C…`): the only target of `call` jobs, never of a `signed_op`; `None` = none are relayed.
    pub ua_registry: Option<ScAddress>,
    /// `params.mandates` (`C…`): the mandates a `signed_op` may call.
    pub mandates: Vec<ScAddress>,
    /// `params.mandate_wasm_hashes` (64 hex each): the code a `ua_metatx` on a mandate may run (`mandate_wasm_ok`); none = no such job.
    pub mandate_wasms: Vec<[u8; 32]>,
    /// The registry's `relayers()`, kept from the first read that answers (`load_relayers`): unset, nobody is listed.
    pub relayers: OnceLock<Vec<ScAddress>>,
}

impl RelayFeePolicy {
    fn token(&self, c: &ScAddress) -> bool {
        self.tokens.read().is_ok_and(|t| t.contains(c))
    }

    /// `params.relay_fee = { router = "C…", min_amount = N, relay_bound_payee }`, `params.max_pay_meta_bytes`
    /// (`ChainCfg::relay_params`) and the chain's registered `tokens`. A `router` that is set but is not a contract
    /// strkey is a startup error, never a silently disabled router.
    pub fn from_cfg(cfg: &ChainCfg) -> Result<Self> {
        let params = cfg.relay_params()?;
        let router = match params.router.as_deref() {
            None => None,
            Some(r) => match ScAddress::from_str(r) {
                Ok(a @ ScAddress::Contract(_)) => Some(a),
                _ => bail!("params.relay_fee.router {r:?} is not a Soroban contract address (C…)"),
            },
        };
        let tokens: Vec<ScAddress> = cfg.tokens.iter()
            .map(|t| ScAddress::from_str(&t.address).map_err(|e| anyhow!("tokens: {} is not a Soroban address: {e}", t.address)))
            .collect::<Result<_>>()?;
        let contract = |k: &str| match cfg.params.get(k) {
            None => Ok(None),
            Some(v) => match v.as_str().map(ScAddress::from_str) {
                Some(Ok(a @ ScAddress::Contract(_))) => Ok(Some(a)),
                _ => Err(anyhow!("params.{k} {v} is not a Soroban contract address (C…)")),
            },
        };
        let mandates = match cfg.params.get("mandates") {
            None => &[][..],
            Some(m) => m.as_array().ok_or_else(|| anyhow!("params.mandates {m} is not a list"))?.as_slice(),
        };
        let mandates = mandates.iter()
            .map(|m| match m.as_str().map(ScAddress::from_str) {
                Some(Ok(a @ ScAddress::Contract(_))) => Ok(a),
                _ => Err(anyhow!("params.mandates: {m} is not a Soroban contract address (C…)")),
            })
            .collect::<Result<_>>()?;
        let mandate_wasms = match cfg.params.get("mandate_wasm_hashes") {
            None => &[][..],
            Some(m) => m.as_array().ok_or_else(|| anyhow!("params.mandate_wasm_hashes {m} is not a list"))?.as_slice(),
        };
        let mandate_wasms = mandate_wasms.iter()
            .map(|h| h.as_str().and_then(|h| alloy::hex::decode(h).ok()).and_then(|h| h.try_into().ok()).ok_or_else(|| anyhow!("params.mandate_wasm_hashes: {h} is not 32 bytes of hex")))
            .collect::<Result<_>>()?;
        Ok(Self { router, tokens: tokens.into(), params, dex: contract("dex")?, executor: OnceLock::new(), ua_registry: contract("ua_registry")?, relayers: OnceLock::new(), mandates, mandate_wasms })
    }
}

/// The job's invocation, checked before simulation (fail closed): `op.kind` by the one rule (`adapter::op_kind`):
/// `"pay_meta"` (`pay_meta_job`), `"relay_fee"` (`relay_fee_job`), none = the signed invocation as it is, on a known contract
/// (`known_contract`); outside a relay, never a pay to the router.
pub fn job_call(network: &[u8; 32], op: &Value, lane: &ScAddress, policy: &RelayFeePolicy)
    -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)>
{
    let kind = crate::adapter::op_kind(op, &crate::adapter::PAY_KINDS)?;
    let (call, auth) = match kind {
        Some("pay_meta") => pay_meta_job(op, policy.params.max_pay_meta_bytes)?,
        Some(_) => {
            let (c, a, _) = relay_fee_job(network, op, lane, policy)?;
            return Ok((c, a));
        }
        None => host_call(op)?,
    };
    known_contract(&call.contract_address, policy)?;
    if pays_router(&call, policy) {
        bail!("a pay or approval to the relay-fee router or its executor is refused (CTR-MTX-27: never pay the router)");
    }
    Ok((call, auth))
}

/// Owner ruling 2026-11-02: a `signed_op` is no open host call. It runs on a token, a mandate, the DEX or the router the chain's
/// `params` name, and never on the registry, whatever else lists it: a registry write is a `call` job (a `G…` member that must sign one
/// submits it itself), or the one `ua_metatx` of `Class::Registry`, by name.
fn known_contract(c: &ScAddress, policy: &RelayFeePolicy) -> Result<()> {
    if policy.ua_registry.as_ref() == Some(c) {
        bail!("{CALL_TARGET_REFUSED}: a signed_op never runs on the registry; a registry write is a call job");
    }
    if policy.token(c) || policy.mandates.contains(c) || policy.dex.as_ref() == Some(c) || policy.router.as_ref() == Some(c) {
        return Ok(());
    }
    bail!("{CALL_TARGET_REFUSED}: {c} is not a token, mandate, DEX or router of this chain's params")
}

/// The owner's refinement of 2026-11-02: a plain `signed_op` whose root is a token payment, `pay`, `pay_meta` or `transfer` on a contract
/// of `policy.tokens`, read from the job's named JSON. The host call is exactly that root, so a client cannot mislabel it. `None`: any
/// other call, another `op.kind`, or a job that does not parse.
fn token_payment(op: &Value, policy: &RelayFeePolicy) -> Option<InvokeContractArgs> {
    if !matches!(crate::adapter::op_kind(op, &crate::adapter::PAY_KINDS), Ok(None)) {
        return None;
    }
    let (call, _) = host_call(op).ok()?;
    let pays = matches!(call.function_name.0.as_slice(), b"pay" | b"pay_meta" | b"transfer");
    (pays && policy.token(&call.contract_address)).then_some(call)
}

/// What the budget gate read is what runs: a job read as a token payment that builds any other host call is refused.
fn runs_as_read(op: &Value, call: &InvokeContractArgs, policy: &RelayFeePolicy) -> Result<()> {
    match token_payment(op, policy) {
        Some(read) if read != *call => bail!("{CALL_TARGET_REFUSED}: read as a token payment on {}, but the job builds another call", read.contract_address),
        _ => Ok(()),
    }
}

/// CTR-MTX-27: a call that pays (or approves for later pays) the router or its executor: a token `pay` / `pay_meta` /
/// `transfer` to either (argument 1), `approve` to either as spender (argument 1; an amount 0 withdraws, allowed),
/// `transfer_from` with either as spender or `to` (arguments 0, 2), a `Holder::Addr` of either as the `to` / payee
/// (argument 1) of `ua_pay` / `ua_pay_meta` / `ua_transfer` (outside `ua_relay`), `mtx_mandate_pay`, `mtx_withdraw`,
/// `mtx_set_payee` (unless it withdraws the approval), the delegate (argument 1) of `mtx_set_mandate` (an executor
/// delegate is anyone's: `relay` runs `mtx_mandate_pay` as it), or as either order's `destination` of `settle`; for `relay` /
/// `ua_relay`, the relayed target call by the same rule. Coins on the router are stranded; the executor runs targets as
/// itself, so the next relay could take whatever it holds or is approved.
pub fn pays_router(call: &InvokeContractArgs, policy: &RelayFeePolicy) -> bool {
    let (a, f) = (call.args.as_slice(), call.function_name.0.as_slice());
    if let (b"relay" | b"ua_relay", Some(ScVal::Address(t)), Some(ScVal::Symbol(func)), Some(ScVal::Vec(Some(inner)))) = (f, a.get(1), a.get(2), a.get(3)) {
        let target = InvokeContractArgs { contract_address: t.clone(), function_name: func.clone(), args: inner.0.clone() };
        if pays_router(&target, policy) {
            return true;
        }
    }
    let to = a.get(1);
    policy.router.iter().chain(policy.executor.get()).any(|x| match f {
        b"pay" | b"pay_meta" | b"transfer" => to == Some(&ScVal::Address(x.clone())),
        b"approve" => to == Some(&ScVal::Address(x.clone())) && a.get(2).and_then(scval_i128) != Some(0),
        b"transfer_from" => [0, 2].iter().any(|&i| a.get(i) == Some(&ScVal::Address(x.clone()))),
        b"ua_pay" | b"ua_pay_meta" | b"ua_transfer" | b"mtx_mandate_pay" | b"mtx_withdraw" | b"mtx_set_mandate" => to == Some(&holder_addr(x)),
        b"mtx_set_payee" => to == Some(&holder_addr(x)) && a.get(2) != Some(&ScVal::Bool(false)),
        b"settle" => a.iter().take(2).any(|o| field(o, "destination") == Some(&holder_addr(x))),
        _ => false,
    })
}

/// Relay-fee job: the payer's signed root is the router's `relay` with the eight `require_auth_for_args` arguments (`target, func,
/// args, salt, token, to, amount, valid_until`) and the token's `pay` (carrying `ref`) as sub-invocation. The node builds the
/// call from that root: `relay(payer, …, relayer)`, `payer` the signer and `relayer` this lane (the transaction source), so no
/// second copy of the call exists to differ from the signed one. Checks the policy, `ref` against the call bytes and the signed
/// tree against the call. Soroban does not satisfy `relayer.require_auth()` from the transaction source alone: the returned
/// auth carries an explicit `SourceAccount` entry rooted at the same call.
pub fn relay_fee_job(
    network: &[u8; 32],
    op: &Value,
    lane: &ScAddress,
    policy: &RelayFeePolicy,
) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, [u8; 32])> {
    let (signed, mut auth) = host_call(op)?;
    let SorobanCredentials::Address(cred) = &auth[0].credentials else { bail!("payer entry has no address credentials") };
    if signed.function_name.0.as_slice() != b"relay" || signed.args.len() != 8 {
        bail!("relay-fee job must sign relay(target, func, args, salt, token, to, amount, valid_until)");
    }
    if policy.router.as_ref() != Some(&signed.contract_address) {
        bail!("relay target is not the configured router");
    }
    let mut args = vec![ScVal::Address(cred.address.clone())];
    args.extend(signed.args.iter().cloned());
    args.push(ScVal::Address(lane.clone()));
    let call = InvokeContractArgs { args: args.try_into()?, ..signed };
    if pays_router(&call, policy) {
        bail!("the relayed call pays or approves the relay-fee router or its executor (CTR-MTX-27)");
    }
    let (ScVal::Address(target), ScVal::Symbol(func), ScVal::Vec(Some(inner))) = (&call.args[1], &call.args[2], &call.args[3]) else {
        bail!("relay target / func / args malformed");
    };
    let salt: [u8; 32] = bytes_arg(&call.args[4]).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("salt is 32 bytes"))?;
    let ScVal::Address(token) = &call.args[5] else { bail!("token argument malformed") };
    if !policy.token(token) {
        bail!("token is not registered on this chain");
    }
    let amount = scval_i128(&call.args[7]).and_then(|a| u128::try_from(a).ok()).ok_or_else(|| anyhow!("amount argument malformed or negative"))?;
    // open mode: `to` is the router (it forwards to the relayer, this lane); a bound payee is `to` itself
    let to = &call.args[6];
    if policy.executor.get().is_some_and(|x| *to == ScVal::Address(x.clone())) {
        bail!("the fee is bound to the router's executor (BadPayee)");
    }
    crate::adapter::relay_fee_ours(*to == ScVal::Address(call.contract_address.clone()), *to == ScVal::Address(lane.clone()), amount, &policy.params)?;
    let rf = relay_ref(network, target, func, inner.as_slice(), &salt);
    if op_bytes(op, "ref")? != rf {
        bail!("op.ref != relay_ref(target, func, args, salt)");
    }
    // The signed tree must contain exactly the payment that commits to `ref`.
    let pays = auth[0].root_invocation.sub_invocations.iter().filter(|s| match &s.function {
        SorobanAuthorizedFunction::ContractFn(f) => {
            f.contract_address == *token
                && f.function_name.0.as_slice() == b"pay"
                && f.args.len() == 5
                && f.args[0] == call.args[0]
                && f.args[1] == call.args[6]
                && f.args[2] == call.args[7]
                && bytes_arg(&f.args[3]) == Some(&rf[..])
                && f.args[4] == call.args[8]
        }
        _ => false,
    });
    if pays.count() != 1 {
        bail!("the payer's signature does not carry token.pay(payer, to, amount, ref, valid_until)");
    }
    auth.push(source_entry(&call));
    Ok((call, auth, rf))
}

/// The lane's explicit authority for exactly `call` (spec §8): a `SourceAccount` entry rooted at the call, nothing below.
fn source_entry(call: &InvokeContractArgs) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation { function: SorobanAuthorizedFunction::ContractFn(call.clone()), sub_invocations: Default::default() },
    }
}

/// The job's call, auth and `valid_until` by `job.kind` (S15): `ua_metatx` ⇒ `ua_metatx_job` (`valid_until` from the
/// signed arguments), `call` ⇒ `ua8_call_job` (`op.valid_until`), none / `signed_op` ⇒ `job_call` (`op.valid_until`); any
/// other kind is refused. No kind takes its call as a blob: `op.args` is named fields and `op.extra.call` is gone.
pub fn job_tx(network: &[u8; 32], kind: Option<&str>, op: &Value, lane: &ScAddress, policy: &RelayFeePolicy)
    -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, u64)>
{
    if op["args"].is_string() {
        return Err(hex_refused("op.args"));
    }
    if !op["extra"]["call"].is_null() {
        return Err(hex_refused("op.extra.call"));
    }
    let (call, auth, valid_until) = match kind {
        Some("ua_metatx") => {
            let (call, auth, _) = ua_metatx_job(network, op, lane, policy)?;
            let valid_until = if op["function"] == ACCEPT { bounded_deadline(op)? } else { ua_valid_until(&call)? };
            (call, auth, valid_until)
        }
        None | Some("signed_op") => {
            let valid_until = bounded_deadline(op)?;
            let (call, auth) = job_call(network, op, lane, policy)?;
            runs_as_read(op, &call, policy)?;
            (call, auth, valid_until)
        }
        Some("call") => {
            let registry = policy.ua_registry.as_ref().ok_or_else(|| anyhow!("a call job needs params.ua_registry (the chain's UaRegistry)"))?;
            let valid_until = bounded_deadline(op)?;
            let listed = policy.relayers.get().is_some_and(|l| l.contains(lane));
            let (call, auth) = ua8_call_job(network, op, lane, registry, listed)?;
            (call, auth, valid_until)
        }
        Some(k) => bail!("unknown job kind {k:?} (signed_op | ua_metatx | call)"),
    };
    within_depth(&call)?;
    auth.iter().try_for_each(within_depth)?;
    Ok((call, auth, valid_until))
}

/// `op.valid_until` of a job whose deadline nothing the node reads signs, so the node bounds it: on chain `0` is no `max_time`, the
/// transaction good for ever, while `follow` reads it as long past and reports `dead` at its first poll.
fn bounded_deadline(op: &Value) -> Result<u64> {
    let valid_until = op["valid_until"].as_u64().ok_or_else(|| anyhow!("op.valid_until missing"))?;
    let (now, max) = (crate::submit::now(), max_valid_for());
    if valid_until <= now || valid_until > now.saturating_add(max) {
        bail!("op.valid_until {valid_until} is not within {max} s after now ({now})");
    }
    Ok(valid_until)
}

fn max_valid_for() -> u64 {
    crate::mesh::accept::MeshParams::default().max_valid_for_secs
}

/// The transaction's `max_time` (NET-SOR-15): never past, or `txTOO_LATE` puts the job back in the queue on every claim, and at most
/// `max_valid_for()` from now whatever the client signed, since a lost transaction holds its lane to this deadline. NODE-LANE-16 lets
/// the bound narrow; a later claim builds a new transaction while the signed deadline lasts.
fn tx_deadline(signed: u64) -> Result<u64> {
    let now = crate::submit::now();
    if signed <= now {
        bail!("expired before inclusion: valid_until {signed}, now {now}");
    }
    Ok(signed.min(now.saturating_add(max_valid_for())))
}

/// The named path's `XDR_DEPTH`: what a job built must read back as any XDR a job puts in does.
fn within_depth<T: ReadXdr + WriteXdr>(v: &T) -> Result<()> {
    let b = v.to_xdr(Limits::none())?;
    T::from_xdr(&b, Limits { depth: XDR_DEPTH, len: b.len() }).map(|_| ()).map_err(|e| anyhow!("a job value nested past the limit: {e}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Token,
    Router,
    Dex,
    Mandate,
    Registry,
}

/// One allow-listed `ua_metatx` function (spec §9.1): its contract class, its arguments in the contract's order, name and
/// type (`ua_value`), `auth` last (`settle` has two order auths), and the indexes of `valid_until` (`None`: the orders' `expiry`),
/// `relayer` (`Option<Address>`; `ua_relay`'s an `Address`), the UA signer `from` (`BytesN<32>`, `mtx_revoke`'s `by` a `Holder`;
/// `None` with a lane = the mandate's owner) and its `lane` (the nonce follows it).
struct UaFn {
    name: &'static str,
    class: Class,
    args: &'static [(&'static str, &'static str)],
    valid_until: Option<usize>,
    relayer: Option<usize>,
    from: Option<usize>,
    lane: Option<usize>,
}

const fn uf(name: &'static str, class: Class, args: &'static [(&'static str, &'static str)], valid_until: Option<usize>, relayer: Option<usize>,
            from: Option<usize>, lane: Option<usize>) -> UaFn {
    UaFn { name, class, args, valid_until, relayer, from, lane }
}

const ID: &str = "BytesN<32>";
const OPT: &str = "Option<Address>";
/// CTR-UA-37: a member's acceptance, the one `ua_metatx` of `Class::Registry`: its signature is the member's and over no call, so it carries
/// no deadline, no op digest and no `auth` argument.
const ACCEPT: &str = "accept_membership";

/// The contracts' signatures (T5–T8, T6b's `epoch` in the delegate entries): the one table of the `ua_metatx` job API.
const UA_FNS: [UaFn; 14] = [
    uf(ACCEPT, Class::Registry, &[("ua", ID), ("member_sig", "MemberSig"), ("relayer", OPT)], None, Some(2), None, None),
    uf("ua_transfer", Class::Token, &[("from", ID), ("to", "Holder"), ("amount", "i128"), ("lane", ID), ("nonce", "u64"), ("valid_until", "u64"), ("relayer", OPT),
                                      ("auth", "UaSig")], Some(5), Some(6), Some(0), Some(3)),
    uf("ua_pay", Class::Token, &[("from", ID), ("to", "Holder"), ("amount", "i128"), ("pay_ref", ID), ("valid_until", "u64"), ("relayer", OPT), ("auth", "UaSig")],
       Some(4), Some(5), Some(0), None),
    uf("ua_pay_meta", Class::Token, &[("from", ID), ("to", "Holder"), ("amount", "i128"), ("salt", ID), ("meta", "Bytes"), ("valid_until", "u64"), ("relayer", OPT),
                                      ("auth", "UaSig")], Some(5), Some(6), Some(0), None),
    uf("ua_burn", Class::Token, &[("from", ID), ("amount", "i128"), ("lane", ID), ("nonce", "u64"), ("valid_until", "u64"), ("relayer", OPT), ("auth", "UaSig")],
       Some(4), Some(5), Some(0), Some(2)),
    uf("ua_cancel_nonce", Class::Token, &[("ua", ID), ("lane", ID), ("valid_until", "u64"), ("auth", "UaSig")], Some(2), None, Some(0), None),
    uf("ua_relay", Class::Router, &[("payer", ID), ("target", "Address"), ("func", "Symbol"), ("args", "Vec<Val>"), ("salt", ID), ("token", "Address"), ("to", "Holder"),
                                    ("amount", "i128"), ("valid_until", "u64"), ("relayer", "Address"), ("auth", "UaSig")], Some(8), Some(9), Some(0), None),
    uf("settle", Class::Dex, &[("maker", "Order"), ("taker", "Order"), ("maker_fill", "i128"), ("maker_auth", "UaSig"), ("taker_auth", "UaSig")], None, None, None, None),
    uf("ua_cancel", Class::Dex, &[("order", "Order"), ("auth", "UaSig")], None, None, None, None),
    uf("mtx_set_mandate", Class::Mandate, &[("token", "Address"), ("delegate", "Holder"), ("max_per_payment", "i128"), ("max_per_period", "i128"), ("period_seconds", "u64"),
                                            ("expiry", "u64"), ("lane", ID), ("nonce", "u64"), ("valid_until", "u64"), ("relayer", OPT), ("auth", "UaSig")],
       Some(8), Some(9), None, Some(6)),
    uf("mtx_set_payee", Class::Mandate, &[("token", "Address"), ("payee", "Holder"), ("allowed", "bool"), ("lane", ID), ("nonce", "u64"), ("valid_until", "u64"),
                                          ("relayer", OPT), ("auth", "UaSig")], Some(5), Some(6), None, Some(3)),
    uf("mtx_revoke", Class::Mandate, &[("token", "Address"), ("by", "Holder"), ("epoch", "u64"), ("lane", ID), ("nonce", "u64"), ("valid_until", "u64"), ("relayer", OPT),
                                       ("auth", "UaSig")], Some(5), Some(6), Some(1), Some(3)),
    uf("mtx_withdraw", Class::Mandate, &[("token", "Address"), ("to", "Holder"), ("amount", "i128"), ("lane", ID), ("nonce", "u64"), ("valid_until", "u64"), ("relayer", OPT),
                                         ("auth", "UaSig")], Some(5), Some(6), None, Some(3)),
    uf("mtx_mandate_pay", Class::Mandate, &[("token", "Address"), ("payee", "Holder"), ("amount", "i128"), ("pay_ref", ID), ("epoch", "u64"), ("valid_until", "u64"),
                                            ("relayer", OPT), ("auth", "UaSig")], Some(5), Some(6), None, None),
];

/// `ua-common`'s `Order`.
const ORDER: [(&str, &str); 10] = [("maker", "Holder"), ("destination", "Holder"), ("relayer", "Address"), ("sell_token", "Address"), ("sell_amount", "i128"),
                                   ("buy_token", "Address"), ("buy_amount", "i128"), ("max_fee_ppm", "u32"), ("expiry", "u64"), ("salt", "u64")];

/// The `ua_metatx` op (SOR-D14, the explicit parameters of owner 2026-10-31): `{contract, function, args, auth?: [{payload, from,
/// signature}], valid_until?}`, `args` every argument by name, `auth` included, any other field refused ⇒ the call and its table
/// row. The digest and the XDR both come from this one call.
fn ua_call(op: &Value) -> Result<(InvokeContractArgs, &'static UaFn)> {
    let s = |k: &str| op[k].as_str().ok_or_else(|| anyhow!("op.{k} missing"));
    // decision (C): the kind is `job.kind`; an `op.kind` here is a misrouted job, never ignored
    if op.get("kind").is_some_and(|k| !k.is_null()) {
        bail!("a ua_metatx op carries no op.kind (got {})", op["kind"]);
    }
    if let Some(k) = op.as_object().and_then(|o| o.keys().find(|k| !["contract", "function", "args", "auth", "valid_until", "kind"].contains(&k.as_str()))) {
        bail!("op: unknown field {k}");
    }
    let function = s("function")?;
    let f = UA_FNS.iter().find(|f| f.name == function).ok_or_else(|| anyhow!("{function:?} is not a ua_metatx function"))?;
    let contract = match ScAddress::from_str(s("contract")?) {
        Ok(a @ ScAddress::Contract(_)) => a,
        _ => bail!("op.contract is not a Soroban contract address (C…)"),
    };
    let args = args_of(function, f.args, &op["args"])?;
    Ok((InvokeContractArgs { contract_address: contract, function_name: ScSymbol(function.try_into()?), args: args.try_into()? }, f))
}

fn field<'a>(v: &'a ScVal, k: &str) -> Option<&'a ScVal> {
    let ScVal::Map(Some(m)) = v else { return None };
    m.iter().find(|e| matches!(&e.key, ScVal::Symbol(s) if s.0.as_slice() == k.as_bytes())).map(|e| &e.val)
}

/// A `ua_metatx` call's deadline from its signed arguments (NET-SOR-15): `valid_until`, or the orders' earliest
/// `expiry` (`settle`, `ua_cancel`).
pub fn ua_valid_until(call: &InvokeContractArgs) -> Result<u64> {
    let f = UA_FNS.iter().find(|f| f.name.as_bytes() == call.function_name.0.as_slice()).ok_or_else(|| anyhow!("not a ua_metatx call"))?;
    let u = |v: Option<&ScVal>| match v {
        Some(ScVal::U64(x)) => Ok(*x),
        _ => Err(anyhow!("{}: valid_until / order expiry malformed", f.name)),
    };
    match f.valid_until {
        Some(i) => u(call.args.get(i)),
        None => {
            let orders = if f.name == "settle" { 2 } else { 1 };
            (0..orders).map(|i| u(call.args.get(i).and_then(|o| field(o, "expiry")))).try_fold(u64::MAX, |m, e| Ok(m.min(e?)))
        }
    }
}

/// NET-SOR-16's op digest (`scaas_ua_common::op_digest`): `sha256(xdr(Vec[Symbol("scaas_metaop_v1"), Bytes(network id),
/// Address(contract), Symbol(fn), Vec(args)]))`, the arguments without `auth`.
pub fn op_digest(network: &[u8; 32], contract: &ScAddress, function: &ScSymbol, args: &[ScVal]) -> Result<[u8; 32]> {
    call_digest("scaas_metaop_v1", network, contract, function, args)
}

/// `scaas_ua_common::attest_digest`: what a relayer's auth covers, every argument of a registry write under a tag of its own.
pub fn attest_digest(network: &[u8; 32], contract: &ScAddress, function: &ScSymbol, args: &[ScVal]) -> Result<[u8; 32]> {
    call_digest("scaas_attest_v1", network, contract, function, args)
}

fn call_digest(tag: &str, network: &[u8; 32], contract: &ScAddress, function: &ScSymbol, args: &[ScVal]) -> Result<[u8; 32]> {
    let v = vec![
        ScVal::Symbol(ScSymbol(tag.try_into()?)),
        ScVal::Bytes(network.to_vec().try_into()?),
        ScVal::Address(contract.clone()),
        ScVal::Symbol(function.clone()),
        ScVal::Vec(Some(ScVec(args.to_vec().try_into()?))),
    ];
    Ok(Sha256::digest(ScVal::Vec(Some(ScVec(v.try_into()?))).to_xdr(Limits::none())?).into())
}

/// `ua_relay(payer, target, func, args, salt, …)`'s `ref` (CTR-MTX-27), the inner `ua_pay`'s `pay_ref`.
fn ua_relay_ref(network: &[u8; 32], a: &[ScVal]) -> Result<[u8; 32]> {
    let (Some(ScVal::Address(target)), Some(ScVal::Symbol(func)), Some(ScVal::Vec(Some(inner)))) = (a.get(1), a.get(2), a.get(3)) else {
        bail!("ua_relay target / func / args malformed");
    };
    let salt: [u8; 32] = a.get(4).and_then(bytes_arg).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("salt is 32 bytes"))?;
    Ok(relay_ref(network, target, func, inner.as_slice(), &salt))
}

/// The digest the UA signed (the job id): `op_digest` over the arguments without `auth`; `ua_relay`'s is the inner
/// `token.ua_pay(payer, to, amount, ref, valid_until, Some(router))` (`ua-ops.json`); `settle` has none (its UA legs
/// sign orders, not the call).
fn ua_digest(network: &[u8; 32], call: &InvokeContractArgs, f: &UaFn) -> Result<Option<[u8; 32]>> {
    let a = call.args.as_slice();
    match f.name {
        "settle" | ACCEPT => Ok(None),
        "ua_relay" => {
            let ScVal::Address(token) = &a[5] else { bail!("ua_relay token malformed") };
            let rf = ScVal::Bytes(ua_relay_ref(network, a)?.to_vec().try_into()?);
            let inner = [a[0].clone(), a[6].clone(), a[7].clone(), rf, a[8].clone(), ScVal::Address(call.contract_address.clone())];
            Ok(Some(op_digest(network, token, &ScSymbol("ua_pay".try_into()?), &inner)?))
        }
        _ => Ok(Some(op_digest(network, &call.contract_address, &call.function_name, &a[..a.len() - 1])?)),
    }
}

/// `ua_relay`'s policy, as `relay_fee_job`'s: a registered token, a payee that is not the executor, and a fee that
/// reaches this lane (open mode `to == Holder::Addr(router)`, or bound to it) unless `relay_bound_payee`.
fn ua_relay_policy(call: &InvokeContractArgs, lane: &ScAddress, policy: &RelayFeePolicy) -> Result<()> {
    let a = call.args.as_slice();
    let ScVal::Address(token) = &a[5] else { bail!("ua_relay token malformed") };
    if !policy.token(token) {
        bail!("token is not registered on this chain");
    }
    let to = &a[6];
    if policy.executor.get().is_some_and(|x| *to == holder_addr(x)) {
        bail!("the fee is bound to the router's executor (BadPayee)");
    }
    let amount = scval_i128(&a[7]).and_then(|v| u128::try_from(v).ok()).ok_or_else(|| anyhow!("amount argument malformed or negative"))?;
    crate::adapter::relay_fee_ours(*to == holder_addr(&call.contract_address), *to == holder_addr(lane), amount, &policy.params)
}

/// The allow-list by contract class: a token ∈ `policy.tokens`, the router, `policy.dex`, `params.ua_registry`. A mandate is any contract
/// here, this being pure: `build` and `op_consumed` read its code (`mandate_wasm_ok`); its job names a `token` ∈ `policy.tokens` (argument
/// 0 of every `mtx_*`), which the mandate calls (owner 2026-11-03).
fn listed(call: &InvokeContractArgs, f: &UaFn, policy: &RelayFeePolicy) -> bool {
    let c = &call.contract_address;
    match f.class {
        Class::Token => policy.token(c),
        Class::Router => policy.router.as_ref() == Some(c),
        Class::Dex => policy.dex.as_ref() == Some(c),
        Class::Mandate => matches!(call.args.first(), Some(ScVal::Address(t)) if policy.token(t)),
        Class::Registry => policy.ua_registry.as_ref() == Some(c),
    }
}

/// A `ua_metatx` job (spec §9.1, SOR-D14): the allow-list (token ∈ `policy.tokens`: `ua_transfer`, `ua_pay`,
/// `ua_pay_meta`, `ua_burn`, `ua_cancel_nonce`; router = `policy.router`: `ua_relay`; DEX = `policy.dex`: `settle`,
/// `ua_cancel`; a listed Wasm, checked in `build`, naming a token ∈ `policy.tokens`: the mandate's `mtx_*`; `params.ua_registry`: `accept_membership`), `relayer` `None` or this lane
/// (`ua_relay`, and each `settle` order: this lane), `valid_until` from the signed arguments, never a UA pay to the router or its executor
/// outside `ua_relay`. Auth: `op.auth` entries for native legs only (as `host_call`), and when the relayer is this lane one
/// `SourceAccount` entry rooted at exactly the call (S8, §8), or, on the registry, the listed lane's one word (`attest_entry`). Returns the
/// call, its auth and the op digest (zero for `settle`, `accept_membership`).
pub fn ua_metatx_job(network: &[u8; 32], op: &Value, lane: &ScAddress, policy: &RelayFeePolicy)
    -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, [u8; 32])>
{
    let (call, f) = ua_call(op)?;
    if !listed(&call, f, policy) {
        if f.class == Class::Mandate {
            bail!("{TOKEN_NOT_SERVED}: {} on {} names a token this chain does not register", f.name, call.contract_address);
        }
        bail!("{} is not allowed on {} (not this chain's {:?} contract)", f.name, call.contract_address, f.class);
    }
    let (a, me) = (call.args.as_slice(), ScVal::Address(lane.clone()));
    let lane_bound = match f.name {
        "settle" => {
            if a[..2].iter().any(|o| field(o, "relayer") != Some(&me)) {
                bail!("settle: each order's relayer must be this lane");
            }
            true
        }
        "ua_relay" => {
            if a[9] != me {
                bail!("ua_relay: the relayer must be this lane");
            }
            true
        }
        _ => match f.relayer.map(|i| &a[i]) {
            None | Some(ScVal::Void) => false,
            Some(r) if *r == me => true,
            Some(_) => bail!("{}: the relayer must be None or this lane", f.name),
        },
    };
    if f.class == Class::Registry {
        if lane_bound && !policy.relayers.get().is_some_and(|l| l.contains(lane)) {
            bail!("this lane is not in the registry's relayers(): no relayer-mode job");
        }
    } else {
        ua_valid_until(&call)?;
    }
    if pays_router(&call, policy) {
        bail!("a pay or approval to the relay-fee router or its executor is refused (outside ua_relay's own fee; CTR-MTX-27)");
    }
    if f.name == "ua_relay" {
        ua_relay_policy(&call, lane, policy)?;
    }
    let digest = ua_digest(network, &call, f)?.unwrap_or_default();
    let mut auth = auth_entries(&op["auth"])?;
    if lane_bound {
        auth.push(if f.class == Class::Registry { attest_entry(network, &call)? } else { source_entry(&call) });
    }
    Ok((call, auth, digest))
}

/// S14 / spec §8: a simulation (recording mode records every `require_auth`) whose auth holds a `SourceAccount` entry
/// that is not rooted at exactly `call` (with nothing below), or at another `SourceAccount` entry of the job's `own`, fails the job
/// before submission: the node never lends a lane's authority to another call. Only `own`'s `SourceAccount` entries count: a
/// subject's `Address` entry has a root the client chose. Unreadable entries fail closed. The RPC records only for a transaction with no auth
/// entry; with one it enforces (`e2e_ua8_simulation_auth_mode`), so for a job carrying the lane's entry this reads back that
/// entry alone, and the refusal of anything else is the host's, at simulation.
fn check_recorded_auth(sim: &Value, call: &InvokeContractArgs, own: &[SorobanAuthorizationEntry]) -> Result<()> {
    let ours = source_entry(call).root_invocation;
    for e in recorded_auth(sim)? {
        let known = e.root_invocation == ours || own.iter().any(|o| matches!(o.credentials, SorobanCredentials::SourceAccount) && o.root_invocation == e.root_invocation);
        if matches!(e.credentials, SorobanCredentials::SourceAccount) && !known {
            bail!("the call asks for this lane's authority outside the job's own call (S14: a lane's authority is never lent)");
        }
    }
    Ok(())
}

/// Any job with no subject's entry: a call that records someone else's (the slot of a `G…` member, a native mandate owner, host-authorised)
/// wants a signature this transaction will not have: it could only fail on chain, on the lane's fee.
fn check_no_other_signer(sim: &Value) -> Result<()> {
    if recorded_auth(sim)?.iter().any(|e| !matches!(e.credentials, SorobanCredentials::SourceAccount)) {
        bail!("the call needs another account's signature, which this job does not carry");
    }
    Ok(())
}

/// The auth entries a simulation recorded; an unreadable one fails closed.
fn recorded_auth(sim: &Value) -> Result<Vec<SorobanAuthorizationEntry>> {
    let mut out = Vec::new();
    for r in sim["results"].as_array().into_iter().flatten() {
        for e in r["auth"].as_array().into_iter().flatten() {
            let x = e.as_str().ok_or_else(|| anyhow!("simulation auth entry is not base64 XDR"))?;
            out.push(SorobanAuthorizationEntry::from_xdr_base64(x, xdr_limits(1 << 20))?);
        }
    }
    Ok(out)
}

/// Protocol 23 (CAP-0066): the transaction data lists archived entries the transaction restores itself.
fn restores(data: &SorobanTransactionData) -> bool {
    matches!(&data.ext, SorobanTransactionDataExt::V1(x) if !x.archived_soroban_entries.is_empty())
}

/// The largest `ContractData` entry a simulation would write: its whole `LedgerEntry`, `stateChanges[].after`, the size the host
/// compares (measured, `e2e_ua8_spend_stop`: 65,536 B lands, 65,540 B fails). `None` = it names none it can read: the job goes on.
fn largest_data_write(sim: &Value) -> Option<usize> {
    sim["stateChanges"].as_array()?.iter()
        .filter_map(|c| LedgerEntry::from_xdr_base64(c["after"].as_str()?, xdr_limits(1 << 21)).ok())
        .filter(|e| matches!(e.data, LedgerEntryData::ContractData(_)))
        .filter_map(|e| e.to_xdr(Limits::none()).ok())
        .map(|b| b.len())
        .max()
}

/// The simulation's transaction data, resource fee plus the margin. An archived footprint (Protocol 23 auto-restore,
/// NET-SOR-11) is accepted only when that declared fee is ≤ `max_deposit` stroops (`params.max_deposit_per_job`;
/// absent = 0 = none); a legacy `restorePreamble` stays a revert.
fn sim_data(sim: &Value, max_deposit: u64) -> std::result::Result<SorobanTransactionData, SimError> {
    if let Some(err) = sim.get("error").and_then(|e| e.as_str()) {
        return Err(SimError::Revert(err.chars().take(300).collect()));
    }
    if sim.get("restorePreamble").is_some_and(|r| !r.is_null()) {
        return Err(SimError::Revert("contract state is archived; restore it first".into()));
    }
    let data = sim["transactionData"].as_str().ok_or_else(|| SimError::Transport("no transactionData".into()))?;
    let mut data = SorobanTransactionData::from_xdr_base64(data, xdr_limits(1 << 20)).map_err(|e| SimError::Transport(e.to_string()))?;
    data.resource_fee = data.resource_fee.saturating_add(data.resource_fee.saturating_mul(RESOURCE_FEE_MARGIN_PCT) / 100);
    if restores(&data) && u64::try_from(data.resource_fee).map_or(true, |f| f > max_deposit) {
        return Err(SimError::Revert(format!("restore over max_deposit_per_job ({} > {max_deposit} stroops)", data.resource_fee)));
    }
    Ok(data)
}


/// The `msig` kind.
const MSIG: u16 = 0x0120;

/// U8S-D8's `Chain` kinds. Every other kind goes through `check_*`, so a kind this table does not know fails closed.
fn chain_kind(kind: u16) -> bool {
    matches!(kind, 0x0100 | 0x0101 | 0x0102 | 0x0108 | MSIG | 0x0130 | 0x0131)
}

/// One registry write of a `call` job, in `scaas_ua`'s types: the XDR and the off-chain check read the same values. `Accept` is the
/// `ua_metatx` on the registry, here for its off-chain check alone: its XDR comes from `UA_FNS`, as every `ua_metatx`.
enum Ua8Write {
    Register(RegisterArgs),
    SetKem(SetKemKeyArgs),
    SetPqz { ua: [u8; 32], pqz_key: Vec<u8>, pqz_pop_hash: [u8; 32], sig: UASig },
    StorePop { ua: [u8; 32], pqz_pop: Vec<u8> },
    Accept { ua: [u8; 32], slot: MemberSig },
}

/// A `ua_metatx` job on `accept_membership`.
fn is_accept(job: &Job) -> bool {
    job.kind.as_deref() == Some("ua_metatx") && job.op.as_ref().is_some_and(|op| op["function"] == ACCEPT)
}

/// `accept_membership`'s arguments for `ua8_precheck`; `ua_call` has refused any other shape before it.
fn accept_write(op: &Value) -> Result<(Ua8Write, Option<ScAddress>)> {
    let [ua, member_sig, relayer] = named(&op["args"], ACCEPT, ["ua", "member_sig", "relayer"])?;
    Ok((Ua8Write::Accept { ua: b32_of(ua)?, slot: member_sig_of(member_sig)? }, relayer_of(relayer)?))
}

/// A blob where a job has named fields, on any job kind and at any level (explicit parameters, owner 2026-10-31).
const HEX_ARGS_REFUSED: &str = "HEX_ARGS_REFUSED";
/// A `signed_op` on a contract the chain's `params` do not name, or on the registry (owner ruling 2026-11-02).
const CALL_TARGET_REFUSED: &str = "CALL_TARGET_REFUSED";
/// `ua_metatx` on a mandate whose code is not in `params.mandate_wasm_hashes` (`mandate_wasm_ok`).
const MANDATE_WASM_REFUSED: &str = "MANDATE_WASM_REFUSED";
/// A `ua_metatx` on a mandate names a `token` not in `policy.tokens` (owner 2026-11-03): the name the EVM guard gives an unregistered token.
const TOKEN_NOT_SERVED: &str = "TOKEN_NOT_SERVED";
/// A simulation declares more resource fee than `params.max_resource_fee_per_job`.
const RESOURCE_FEE_OVER_CAP: &str = "RESOURCE_FEE_OVER_CAP";

fn hex_refused(what: &str) -> anyhow::Error {
    anyhow!("{HEX_ARGS_REFUSED}: {what} takes named fields, not a hex blob")
}

/// `v`'s named fields in `names`' order, every one required, no other (explicit parameters, owner 2026-10-31).
fn fields<'a>(v: &'a Value, what: &str, names: &[&str]) -> Result<Vec<&'a Value>> {
    if v.is_string() {
        return Err(hex_refused(what));
    }
    let o = v.as_object().ok_or_else(|| anyhow!("{what} is an object of named fields"))?;
    if let Some(k) = o.keys().find(|k| !names.contains(&k.as_str())) {
        bail!("{what}: unknown field {k}");
    }
    names.iter().map(|n| o.get(*n).ok_or_else(|| anyhow!("{what}: {n} missing"))).collect()
}

fn named<'a, const N: usize>(v: &'a Value, what: &str, names: [&str; N]) -> Result<[&'a Value; N]> {
    fields(v, what, &names)?.try_into().map_err(|_| anyhow!("{what}: one value per name"))
}

fn hex_of(v: &Value) -> Result<Vec<u8>> {
    let h = v.as_str().and_then(|s| s.strip_prefix("0x")).ok_or_else(|| anyhow!("bytes are 0x… hex, not {v}"))?;
    Ok(alloy::hex::decode(h)?)
}

fn b32_of(v: &Value) -> Result<[u8; 32]> {
    hex_of(v)?.try_into().map_err(|_| anyhow!("{v} is not 32 bytes"))
}

fn num_of<T: TryFrom<u64>>(v: &Value) -> Result<T> {
    v.as_u64().and_then(|n| T::try_from(n).ok()).ok_or_else(|| anyhow!("{v} is not a number in range"))
}

fn list_of<T>(v: &Value, one: impl Fn(&Value) -> Result<T>) -> Result<Vec<T>> {
    if v.is_string() {
        return Err(hex_refused("a list"));
    }
    v.as_array().ok_or_else(|| anyhow!("{v} is not a list"))?.iter().map(one).collect()
}

fn kem_of(v: &Value) -> Result<KemKey> {
    let [scheme, mlkem_ek, x25519] = named(v, "kem", ["scheme", "mlkem_ek", "x25519"])?;
    Ok(KemKey { scheme: num_of(scheme)?, mlkem_ek: hex_of(mlkem_ek)?, x25519: b32_of(x25519)? })
}

fn attrs_of(v: &Value) -> Result<UAAttrs> {
    let [pqz_key, pqz_pop_hash, kem, kem_pk_hash] = named(v, "attrs", ["pqz_key", "pqz_pop_hash", "kem", "kem_pk_hash"])?;
    Ok(UAAttrs { pqz_key: hex_of(pqz_key)?, pqz_pop_hash: b32_of(pqz_pop_hash)?, kem: kem_of(kem)?, kem_pk_hash: b32_of(kem_pk_hash)? })
}

/// Soroban's `MemberSig{index, key_data, sig}`, flat until its round: `key_data` is always empty (CTR-UA-33), so a job that fills it is
/// refused here, as the contract refuses it; there is no list, the registry refuses an `msig` member (NET-SOR-18).
fn member_sig_of(v: &Value) -> Result<MemberSig> {
    let [index, key_data, sig] = named(v, "member signature", ["index", "key_data", "sig"])?;
    if !hex_of(key_data)?.is_empty() {
        bail!("a member signature carries no key_data");
    }
    Ok(MemberSig { index: num_of(index)?, members: vec![], sig: hex_of(sig)? })
}

fn sig_of(v: &Value) -> Result<UASig> {
    let [key_data, signature, members] = named(v, "sig", ["key_data", "signature", "members"])?;
    Ok(UASig { key_data: hex_of(key_data)?, signature: hex_of(signature)?, members: list_of(members, member_sig_of)? })
}

fn structure_of(v: &Value) -> Result<MsigStructure> {
    let [threshold, members] = named(v, "structure", ["threshold", "members"])?;
    let member = |m: &Value| {
        let [kind, id, weight] = named(m, "member", ["kind", "id", "weight"])?;
        Ok(MsigMember { kind: num_of(kind)?, id: b32_of(id)?, weight: num_of(weight)? })
    };
    Ok(MsigStructure { threshold: num_of(threshold)?, members: list_of(members, member)? })
}

fn webauthn_of(v: &Value) -> Result<WebAuthnKey> {
    let [x, y, rp_id_hash] = named(v, "key", ["x", "y", "rp_id_hash"])?;
    Ok(WebAuthnKey { x: b32_of(x)?, y: b32_of(y)?, rp_id_hash: b32_of(rp_id_hash)? })
}

fn musig2_of(v: &Value) -> Result<MuSig2Key> {
    let [agg_key, member_keys] = named(v, "key", ["agg_key", "member_keys"])?;
    Ok(MuSig2Key { agg_key: hex_of(agg_key)?, member_keys: list_of(member_keys, hex_of)? })
}

fn frost_of(v: &Value) -> Result<FrostKey> {
    let [group_key, threshold, members] = named(v, "key", ["group_key", "threshold", "members"])?;
    let member = |m: &Value| {
        let [commitments, r, z] = named(m, "member", ["commitments", "r", "z"])?;
        Ok(FrostMember { commitments: list_of(commitments, hex_of)?, r: hex_of(r)?, z: b32_of(z)? })
    };
    Ok(FrostKey { group_key: hex_of(group_key)?, threshold: num_of(threshold)?, members: list_of(members, member)? })
}

fn relayer_of(v: &Value) -> Result<Option<ScAddress>> {
    match v {
        Value::Null => Ok(None),
        _ => address_of(v).map(Some).with_context(|| format!("relayer {v} is null or an address")),
    }
}

fn address_of(v: &Value) -> Result<ScAddress> {
    v.as_str().and_then(|s| ScAddress::from_str(s).ok()).ok_or_else(|| anyhow!("{v} is not an address"))
}

/// `Holder::Addr` or `Holder::Ua`, named as the contract's variants.
fn holder_of(v: &Value) -> Result<ScVal> {
    if v.is_string() {
        return Err(hex_refused("a holder"));
    }
    match v.as_object().filter(|o| o.len() == 1).map(|o| (o.get("Addr"), o.get("Ua"))) {
        Some((Some(a), _)) => Ok(holder_addr(&address_of(a)?)),
        Some((_, Some(u))) => sc_vec(vec![ScVal::Symbol(ScSymbol("Ua".try_into()?)), sc_bytes(&b32_of(u)?)?]),
        _ => bail!("a holder is {{\"Addr\": \"G…\"}} or {{\"Ua\": \"0x…\"}}, not {v}"),
    }
}

/// A decimal string: the form of every integer a JSON number cannot hold. Digits only: alloy's `U256` also parses `0x…`.
fn decimal_of<T: FromStr>(v: &Value, ty: &str) -> Result<T> {
    let digits = |s: &&str| s.strip_prefix('-').unwrap_or(s).bytes().all(|b| b.is_ascii_digit());
    v.as_str().filter(digits).and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("{v} is not a {ty} as a decimal string"))
}

/// A 64-bit integer: a number or, for a client that cannot write one past 2^53, a decimal string.
fn int64_of<T: FromStr + TryFrom<i128>>(v: &Value, ty: &str) -> Result<T> {
    if v.is_string() {
        return decimal_of(v, ty);
    }
    v.as_i64().map(i128::from).or(v.as_u64().map(i128::from)).and_then(|n| T::try_from(n).ok()).ok_or_else(|| anyhow!("{v} is not a {ty}"))
}

fn symbol_of(v: &Value) -> Result<ScSymbol> {
    Ok(ScSymbol(v.as_str().ok_or_else(|| anyhow!("{v} is not a symbol"))?.try_into()?))
}

/// One value of a contract type, spelled as the contract and `ua-ops.json` spell it. `i128`, `u128`, `u256` and `i256` are decimal
/// strings, as every amount the node reports; `u64`, `i64`, `Timepoint` and `Duration` as `int64_of`; `Map` a list of `{key, val}`, any
/// key type, any order, sorted here. `Void` and `Map` serve the arguments a contract does not type: a relayed call's, a signed
/// invocation's. `Error` and the host's ledger-key values are no argument a job can name.
fn ua_value(ty: &str, v: &Value) -> Result<ScVal> {
    Ok(match ty {
        ID => sc_bytes(&b32_of(v)?)?,
        "Bytes" => sc_bytes(&hex_of(v)?)?,
        "i128" => {
            let n: i128 = decimal_of(v, ty)?;
            ScVal::I128(Int128Parts { hi: (n >> 64) as i64, lo: n as u64 })
        }
        "u128" => {
            let n: u128 = decimal_of(v, ty)?;
            ScVal::U128(UInt128Parts { hi: (n >> 64) as u64, lo: n as u64 })
        }
        "u256" => {
            let n: alloy::primitives::U256 = decimal_of(v, ty)?;
            let [hi_hi, hi_lo, lo_hi, lo_lo] = limbs(n.to_be_bytes());
            ScVal::U256(UInt256Parts { hi_hi, hi_lo, lo_hi, lo_lo })
        }
        "i256" => {
            let n: alloy::primitives::I256 = decimal_of(v, ty)?;
            let [hi_hi, hi_lo, lo_hi, lo_lo] = limbs(n.to_be_bytes());
            ScVal::I256(Int256Parts { hi_hi: hi_hi as i64, hi_lo, lo_hi, lo_lo })
        }
        "i32" => ScVal::I32(v.as_i64().and_then(|n| i32::try_from(n).ok()).ok_or_else(|| anyhow!("{v} is not an i32"))?),
        "u32" => ScVal::U32(num_of(v)?),
        "u64" => ScVal::U64(int64_of(v, ty)?),
        "i64" => ScVal::I64(int64_of(v, ty)?),
        "Timepoint" => ScVal::Timepoint(TimePoint(int64_of(v, ty)?)),
        "Duration" => ScVal::Duration(stellar_xdr::Duration(int64_of(v, ty)?)),
        "bool" => ScVal::Bool(v.as_bool().ok_or_else(|| anyhow!("{v} is not a bool"))?),
        "Address" => ScVal::Address(address_of(v)?),
        OPT => relayer_of(v)?.map_or(ScVal::Void, ScVal::Address),
        "Symbol" => ScVal::Symbol(symbol_of(v)?),
        "String" => ScVal::String(ScString(v.as_str().ok_or_else(|| anyhow!("{v} is not a string"))?.try_into()?)),
        "Holder" => holder_of(v)?,
        "UaSig" => sc_sig(&sig_of(v)?)?,
        "MemberSig" => sc_member_sig(&member_sig_of(v)?)?,
        "Order" => sc_struct_of(ORDER.iter().map(|f| f.0).zip(args_of("order", &ORDER, v)?).collect())?,
        "Vec<Val>" => sc_vec(list_of(v, relayed_of)?)?,
        "Void" if v.is_null() => ScVal::Void,
        "Map" => {
            let entry = |e: &Value| {
                let [key, val] = named(e, "map entry", ["key", "val"])?;
                Ok((relayed_of(key)?, relayed_of(val)?))
            };
            sc_map(list_of(v, entry)?)?
        }
        _ => bail!("{ty} value {v}: unknown type or value"),
    })
}

/// A 256-bit integer's four big-endian limbs.
fn limbs(b: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_be_bytes(b[i * 8..i * 8 + 8].try_into().expect("8 bytes")))
}

/// One argument of a relayed call (`Vec<Val>`): it names its own type, `{type, value}`.
fn relayed_of(v: &Value) -> Result<ScVal> {
    let [ty, value] = named(v, "relayed argument", ["type", "value"])?;
    ua_value(ty.as_str().ok_or_else(|| anyhow!("a relayed argument's type is a string, not {ty}"))?, value)
}

/// `table`'s values from `v`'s named fields, in `table`'s order: an entry's arguments, a struct's fields.
fn args_of(what: &str, table: &[(&str, &str)], v: &Value) -> Result<Vec<ScVal>> {
    let names: Vec<&str> = table.iter().map(|f| f.0).collect();
    let values = fields(v, what, &names)?;
    table.iter().zip(values).map(|((name, ty), x)| ua_value(ty, x).with_context(|| format!("{what}.{name}"))).collect()
}

/// UA8-D23, S15, the explicit parameters of owner 2026-10-31: `op = {contract, function, args, valid_until}`, `args` the
/// contract's own arguments by name, bytes `0x…` hex, a `#[contracttype]` struct an object of its fields, `relayer` null or a
/// `G…` (`store_pqz_pop` has none). The write, and its `relayer`.
fn ua8_write(op: &Value) -> Result<(Ua8Write, Option<ScAddress>)> {
    let [_, function, a, _] = named(op, "op", ["contract", "function", "args", "valid_until"])?;
    let f = function.as_str().ok_or_else(|| anyhow!("op.function is a string"))?;
    let reg = |w| Ua8Write::Register(w);
    Ok(match f {
        "register" => {
            let [kind, key_data, attrs, pop, pqz_pop, relayer] = named(a, f, ["kind", "key_data", "attrs", "pop", "pqz_pop", "relayer"])?;
            let (kind, key_data, attrs) = (num_of(kind)?, hex_of(key_data)?, attrs_of(attrs)?);
            (reg(RegisterArgs::Register { kind, key_data, attrs, pop: hex_of(pop)?, pqz_pop: hex_of(pqz_pop)? }), relayer_of(relayer)?)
        }
        "register_msig" => {
            let [structure, attrs, pop, pqz_pop, relayer] = named(a, f, ["structure", "attrs", "pop", "pqz_pop", "relayer"])?;
            let (structure, attrs) = (structure_of(structure)?, attrs_of(attrs)?);
            (reg(RegisterArgs::RegisterMsig { structure, attrs, pop: list_of(pop, member_sig_of)?, pqz_pop: hex_of(pqz_pop)? }), relayer_of(relayer)?)
        }
        "register_webauthn" => {
            let [key, attrs, pop, pqz_pop, relayer] = named(a, f, ["key", "attrs", "pop", "pqz_pop", "relayer"])?;
            let (key, attrs) = (webauthn_of(key)?, attrs_of(attrs)?);
            (reg(RegisterArgs::RegisterWebAuthn { key, attrs, pop: hex_of(pop)?, pqz_pop: hex_of(pqz_pop)? }), relayer_of(relayer)?)
        }
        "register_musig2" => {
            let [kind, key, attrs, pop, pqz_pop, relayer] = named(a, f, ["kind", "key", "attrs", "pop", "pqz_pop", "relayer"])?;
            let (kind, key, attrs) = (num_of(kind)?, musig2_of(key)?, attrs_of(attrs)?);
            (reg(RegisterArgs::RegisterMuSig2 { kind, key, attrs, pop: hex_of(pop)?, pqz_pop: hex_of(pqz_pop)? }), relayer_of(relayer)?)
        }
        "register_frost" => {
            let [kind, key, attrs, pop, pqz_pop, relayer] = named(a, f, ["kind", "key", "attrs", "pop", "pqz_pop", "relayer"])?;
            let (kind, key, attrs) = (num_of(kind)?, frost_of(key)?, attrs_of(attrs)?);
            (reg(RegisterArgs::RegisterFrost { kind, key, attrs, pop: hex_of(pop)?, pqz_pop: hex_of(pqz_pop)? }), relayer_of(relayer)?)
        }
        "set_kem_key" => {
            let [ua, version, kem, sig, relayer] = named(a, f, ["ua", "version", "kem", "sig", "relayer"])?;
            (Ua8Write::SetKem(SetKemKeyArgs { ua: b32_of(ua)?, version: int64_of(version, "u64")?, kem: kem_of(kem)?, sig: sig_of(sig)? }), relayer_of(relayer)?)
        }
        "set_pqz_key" => {
            let [ua, pqz_key, pqz_pop_hash, sig, relayer] = named(a, f, ["ua", "pqz_key", "pqz_pop_hash", "sig", "relayer"])?;
            (Ua8Write::SetPqz { ua: b32_of(ua)?, pqz_key: hex_of(pqz_key)?, pqz_pop_hash: b32_of(pqz_pop_hash)?, sig: sig_of(sig)? }, relayer_of(relayer)?)
        }
        "store_pqz_pop" => {
            let [ua, pqz_pop] = named(a, f, ["ua", "pqz_pop"])?;
            (Ua8Write::StorePop { ua: b32_of(ua)?, pqz_pop: hex_of(pqz_pop)? }, None)
        }
        _ => bail!("{f:?} is not a registry write"),
    })
}

fn sc_bytes(b: &[u8]) -> Result<ScVal> {
    Ok(ScVal::Bytes(b.to_vec().try_into()?))
}

fn sc_vec(v: Vec<ScVal>) -> Result<ScVal> {
    Ok(ScVal::Vec(Some(ScVec(v.try_into()?))))
}

fn sc_list(l: &[Vec<u8>]) -> Result<ScVal> {
    sc_vec(l.iter().map(|b| sc_bytes(b)).collect::<Result<_>>()?)
}

fn sc_struct<const N: usize>(fields: [(&str, ScVal); N]) -> Result<ScVal> {
    sc_struct_of(fields.into())
}

/// A `#[contracttype]` struct: a map of its field names.
fn sc_struct_of(fields: Vec<(&str, ScVal)>) -> Result<ScVal> {
    sc_map(fields.into_iter().map(|(k, v)| Ok((ScVal::Symbol(ScSymbol(k.try_into()?)), v))).collect::<Result<_>>()?)
}

/// A map, its keys sorted: the host refuses any other.
fn sc_map(mut entries: Vec<(ScVal, ScVal)>) -> Result<ScVal> {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let e: Vec<ScMapEntry> = entries.into_iter().map(|(key, val)| ScMapEntry { key, val }).collect();
    Ok(ScVal::Map(Some(ScMap(e.try_into()?))))
}

fn sc_kem(k: &KemKey) -> Result<ScVal> {
    sc_struct([("scheme", ScVal::U32(k.scheme.into())), ("mlkem_ek", sc_bytes(&k.mlkem_ek)?), ("x25519", sc_bytes(&k.x25519)?)])
}

fn sc_attrs(a: &UAAttrs) -> Result<ScVal> {
    sc_struct([("pqz_key", sc_bytes(&a.pqz_key)?), ("pqz_pop_hash", sc_bytes(&a.pqz_pop_hash)?), ("kem", sc_kem(&a.kem)?), ("kem_pk_hash", sc_bytes(&a.kem_pk_hash)?)])
}

fn sc_member_sig(s: &MemberSig) -> Result<ScVal> {
    sc_struct([("index", ScVal::U32(s.index.into())), ("key_data", sc_bytes(&[])?), ("sig", sc_bytes(&s.sig)?)])
}

fn sc_member_sigs(m: &[MemberSig]) -> Result<ScVal> {
    sc_vec(m.iter().map(sc_member_sig).collect::<Result<_>>()?)
}

fn sc_sig(s: &UASig) -> Result<ScVal> {
    sc_struct([("key_data", sc_bytes(&s.key_data)?), ("signature", sc_bytes(&s.signature)?), ("members", sc_member_sigs(&s.members)?)])
}

fn sc_structure(s: &MsigStructure) -> Result<ScVal> {
    let one = |m: &MsigMember| sc_struct([("kind", ScVal::U32(m.kind.into())), ("id", sc_bytes(&m.id)?), ("weight", ScVal::U32(m.weight.into()))]);
    sc_struct([("threshold", ScVal::U32(s.threshold.into())), ("members", sc_vec(s.members.iter().map(one).collect::<Result<_>>()?)?)])
}

fn sc_frost(k: &FrostKey) -> Result<ScVal> {
    let one = |m: &FrostMember| sc_struct([("commitments", sc_list(&m.commitments)?), ("r", sc_bytes(&m.r)?), ("z", sc_bytes(&m.z)?)]);
    sc_struct([("group_key", sc_bytes(&k.group_key)?), ("threshold", ScVal::U32(k.threshold.into())), ("members", sc_vec(k.members.iter().map(one).collect::<Result<_>>()?)?)])
}

/// The write's function and arguments as the registry declares them.
fn ua8_args(w: &Ua8Write, relayer: ScVal) -> Result<(&'static str, Vec<ScVal>)> {
    Ok(match w {
        Ua8Write::Register(RegisterArgs::Register { kind, key_data, attrs, pop, pqz_pop }) => {
            ("register", vec![ScVal::U32((*kind).into()), sc_bytes(key_data)?, sc_attrs(attrs)?, sc_bytes(pop)?, sc_bytes(pqz_pop)?, relayer])
        }
        Ua8Write::Register(RegisterArgs::RegisterMsig { structure, attrs, pop, pqz_pop }) => {
            ("register_msig", vec![sc_structure(structure)?, sc_attrs(attrs)?, sc_member_sigs(pop)?, sc_bytes(pqz_pop)?, relayer])
        }
        Ua8Write::Register(RegisterArgs::RegisterWebAuthn { key, attrs, pop, pqz_pop }) => {
            let k = sc_struct([("x", sc_bytes(&key.x)?), ("y", sc_bytes(&key.y)?), ("rp_id_hash", sc_bytes(&key.rp_id_hash)?)])?;
            ("register_webauthn", vec![k, sc_attrs(attrs)?, sc_bytes(pop)?, sc_bytes(pqz_pop)?, relayer])
        }
        Ua8Write::Register(RegisterArgs::RegisterMuSig2 { kind, key, attrs, pop, pqz_pop }) => {
            let k = sc_struct([("agg_key", sc_bytes(&key.agg_key)?), ("member_keys", sc_list(&key.member_keys)?)])?;
            ("register_musig2", vec![ScVal::U32((*kind).into()), k, sc_attrs(attrs)?, sc_bytes(pop)?, sc_bytes(pqz_pop)?, relayer])
        }
        Ua8Write::Register(RegisterArgs::RegisterFrost { kind, key, attrs, pop, pqz_pop }) => {
            ("register_frost", vec![ScVal::U32((*kind).into()), sc_frost(key)?, sc_attrs(attrs)?, sc_bytes(pop)?, sc_bytes(pqz_pop)?, relayer])
        }
        Ua8Write::SetKem(a) => ("set_kem_key", vec![sc_bytes(&a.ua)?, ScVal::U64(a.version), sc_kem(&a.kem)?, sc_sig(&a.sig)?, relayer]),
        Ua8Write::SetPqz { ua, pqz_key, pqz_pop_hash, sig } => {
            ("set_pqz_key", vec![sc_bytes(ua)?, sc_bytes(pqz_key)?, sc_bytes(pqz_pop_hash)?, sc_sig(sig)?, relayer])
        }
        Ua8Write::StorePop { ua, pqz_pop } => ("store_pqz_pop", vec![sc_bytes(ua)?, sc_bytes(pqz_pop)?]),
        Ua8Write::Accept { .. } => bail!("{ACCEPT} is a ua_metatx job"),
    })
}

/// A `call` job (S15, UA8-D23): one registry write, built here from its named fields, on `params.ua_registry` only. No auth
/// entry comes from the job. `relayer` is `None` or this lane, and this lane only when `listed` in `relayers()`; `Some(lane)`
/// adds exactly one `SourceAccount` entry on the function, over the one word `attest` asks for: `attest_digest` of the call's own
/// arguments, so what is hashed is what is sent (owner 2026-11-01).
pub fn ua8_call_job(network: &[u8; 32], op: &Value, lane: &ScAddress, registry: &ScAddress, listed: bool) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let (w, relayer) = ua8_write(op)?;
    if op["contract"].as_str().and_then(|c| ScAddress::from_str(c).ok()).as_ref() != Some(registry) {
        bail!("a call job targets params.ua_registry only, not {}", op["contract"]);
    }
    match &relayer {
        Some(r) if r != lane => bail!("the relayer must be None or this lane"),
        Some(_) if !listed => bail!("this lane is not in the registry's relayers(): no relayer-mode job"),
        _ => {}
    }
    let (f, args) = ua8_args(&w, relayer.as_ref().map_or(ScVal::Void, |r| ScVal::Address(r.clone())))?;
    let call = InvokeContractArgs { contract_address: registry.clone(), function_name: ScSymbol(f.try_into()?), args: args.try_into()? };
    if relayer.is_none() {
        return Ok((call, vec![]));
    }
    let auth = vec![attest_entry(network, &call)?];
    Ok((call, auth))
}

/// The lane's `SourceAccount` entry on a registry write it attests: the entry's function, over the one word `attest_digest` of the arguments.
fn attest_entry(network: &[u8; 32], call: &InvokeContractArgs) -> Result<SorobanAuthorizationEntry> {
    let d = attest_digest(network, &call.contract_address, &call.function_name, &call.args)?;
    Ok(source_entry(&InvokeContractArgs { contract_address: call.contract_address.clone(), function_name: call.function_name.clone(), args: vec![sc_bytes(&d)?].try_into()? }))
}

/// The contract's `attest`, as a superset: this write has a part the chain cannot verify, a signature of a kind outside
/// `chain_kind` or an `msig` slot of a member outside it, `evm-eoa` and `G…` being the chain's. `kind` and `key_data` are the record's.
fn ua8_marked(w: &Ua8Write, kind: u16, key_data: &[u8]) -> Result<bool> {
    if kind != MSIG {
        return Ok(!chain_kind(kind));
    }
    let slots: &[MemberSig] = match w {
        Ua8Write::Register(RegisterArgs::RegisterMsig { pop, .. }) => pop,
        Ua8Write::SetKem(a) => &a.sig.members,
        Ua8Write::SetPqz { sig, .. } => &sig.members,
        Ua8Write::Accept { slot, .. } => std::slice::from_ref(slot),
        _ => return Ok(false),
    };
    let members = MsigStructure::from_key_data(key_data)?.members;
    Ok(slots.iter().any(|s| members.get(s.index as usize).is_none_or(|m| !chain_kind(m.kind) && !matches!(m.kind, 0x0001 | 0x0011))))
}

/// The `UaSig` as the bytes `check_*` take: a single key's `signature`, an `msig`'s stored `abi.encode(MemberSig[])`; any
/// other field set is `Unauthorized` (the contract's `sig_fields_ok`).
fn ua_sig_bytes(kind: u16, s: &UASig) -> std::result::Result<Vec<u8>, UAError> {
    let ok = s.key_data.is_empty() && if kind == MSIG { s.signature.is_empty() } else { s.members.is_empty() };
    ok.then(|| if kind == MSIG { ua8::encode_member_sigs(&s.members) } else { s.signature.clone() }).ok_or(UAError::Unauthorized)
}

/// `scaas_ua::ua8::check_*` on the write, `kind` and `key_data` being its record's.
fn ua8_check(w: &Ua8Write, kind: u16, key_data: &[u8], members: &ua8::Members) -> std::result::Result<(), UAError> {
    match w {
        Ua8Write::Register(a) => {
            let (pop, pqz_pop) = match a {
                RegisterArgs::RegisterMsig { pop, pqz_pop, .. } => (ua8::encode_member_sigs(pop), pqz_pop),
                RegisterArgs::Register { pop, pqz_pop, .. }
                | RegisterArgs::RegisterWebAuthn { pop, pqz_pop, .. }
                | RegisterArgs::RegisterMuSig2 { pop, pqz_pop, .. }
                | RegisterArgs::RegisterFrost { pop, pqz_pop, .. } => (pop.clone(), pqz_pop),
            };
            ua8::check_registration(kind, key_data, a.attrs(), &pop, pqz_pop, members)
        }
        Ua8Write::SetKem(a) => ua8::check_kem_record(kind, key_data, &a.ua, a.version, &a.kem.kem_pk(), &ua_sig_bytes(kind, &a.sig)?, members),
        Ua8Write::SetPqz { ua, pqz_key, pqz_pop_hash, sig } => {
            ua8::check_pqz_key_record(kind, key_data, ua, pqz_key, pqz_pop_hash, &ua_sig_bytes(kind, sig)?, members)
        }
        Ua8Write::StorePop { .. } => Ok(()),
        Ua8Write::Accept { ua, slot } if kind == MSIG => ua8::check_membership(key_data, ua, slot, members),
        Ua8Write::Accept { .. } => Err(UAError::Unauthorized),
    }
}

/// The kind a `register…` names.
fn register_kind(a: &RegisterArgs) -> u16 {
    match a {
        RegisterArgs::Register { kind, .. } | RegisterArgs::RegisterMuSig2 { kind, .. } | RegisterArgs::RegisterFrost { kind, .. } => *kind,
        RegisterArgs::RegisterMsig { .. } => MSIG,
        RegisterArgs::RegisterWebAuthn { .. } => 0x0100,
    }
}

impl SorobanAdapter {
    /// `record_of(ua)` by simulation: `(kind, key_data, signable)`, `None` for an unregistered id. An archived record's value
    /// is taken: every reader binds it to its id (`ua_of` here, `derive_ua` in `check_*`), and the write's `sim_data` applies the
    /// restore cap. An RPC failure alone is `Transport`, never "unregistered"; what this job's state answers is `Revert`, since
    /// a requeued job is claimed again first and would starve the chain's queue.
    async fn ua8_record(&self, registry: &ScAddress, ua: &[u8; 32]) -> std::result::Result<Option<(u16, Vec<u8>, bool)>, SimError> {
        let id = sc_bytes(ua).map_err(|e| SimError::Revert(e.to_string()))?;
        let v = match self.sim_view(registry, "record_of", vec![id]).await {
            Ok((Some(v), _)) => v,
            Ok((None, _)) => return Err(SimError::Revert("record_of: its state needs a restore, and no value came back".into())),
            Err(e) if e.is::<SimRefused>() => return Err(SimError::Revert(format!("record_of: {e:#}"))),
            Err(e) => return Err(SimError::Transport(format!("record_of: {e:#}"))),
        };
        if v == ScVal::Void {
            return Ok(None);
        }
        match (field(&v, "kind"), field(&v, "key_data"), field(&v, "signable")) {
            (Some(ScVal::U32(k)), Some(ScVal::Bytes(d)), Some(ScVal::Bool(s))) if *k <= 0xFFFF => Ok(Some((*k as u16, d.to_vec(), *s))),
            _ => Err(SimError::Revert(format!("record_of is not a record: {v:?}"))),
        }
    }

    /// An acceptance of a slot that holds one is a no-op on chain: free to the client, on the lane's fee and in `call_budget_pct`, so it
    /// is refused here, unsent. As `ua8_record`: a failed RPC is `Transport`, what the state answers `Revert`.
    async fn not_yet_accepted(&self, registry: &ScAddress, ua: &[u8; 32], index: u16) -> std::result::Result<(), SimError> {
        let id = sc_bytes(ua).map_err(|e| SimError::Revert(e.to_string()))?;
        match self.sim_view(registry, "member_accepted", vec![id, ScVal::U32(index.into())]).await {
            Ok((Some(ScVal::Bool(false)), _)) => Ok(()),
            Ok((Some(ScVal::Bool(true)), _)) => Err(SimError::Revert(format!("slot {index} is already accepted: nothing to send"))),
            Ok((v, _)) => Err(SimError::Revert(format!("member_accepted answered {v:?}"))),
            Err(e) if e.is::<SimRefused>() => Err(SimError::Revert(format!("member_accepted: {e:#}"))),
            Err(e) => Err(SimError::Transport(format!("member_accepted: {e:#}"))),
        }
    }

    /// `store_pqz_pop` over stored bytes is a no-op on chain, on the lane's fee in `call_budget_pct`: refused here, as `not_yet_accepted`. This
    /// check saves a fee and decides nothing else, so any other answer leaves the job to its simulation.
    async fn pop_not_stored(&self, registry: &ScAddress, ua: &[u8; 32]) -> std::result::Result<(), SimError> {
        let id = sc_bytes(ua).map_err(|e| SimError::Revert(e.to_string()))?;
        match self.sim_view(registry, "pqz_pop_of", vec![id]).await {
            Ok((Some(ScVal::Bytes(b)), _)) if !b.is_empty() => Err(SimError::Revert("the PQZ proof is already stored: nothing to send".into())),
            Err(e) if !e.is::<SimRefused>() => Err(SimError::Transport(format!("pqz_pop_of: {e:#}"))),
            _ => Ok(()),
        }
    }

    /// An `msig`'s derived members as the contract reads them (`check_members`): a `Chain` kind's `Signer`, whose bytes
    /// `record_of` returns when `signable`, a marked kind's `Ua`. What is absent `check_*` refuses as `MemberUnknown`.
    async fn ua8_members(&self, registry: &ScAddress, key_data: &[u8]) -> std::result::Result<HashMap<[u8; 32], (u16, Vec<u8>)>, SimError> {
        let structure = MsigStructure::from_key_data(key_data).map_err(|e| SimError::Revert(e.to_string()))?;
        let mut known = HashMap::new();
        for m in structure.members.iter().filter(|m| !scaas_ua::is_native(m.kind)) {
            if let Some((kind, key, signable)) = self.ua8_record(registry, &m.id).await? {
                if signable || !chain_kind(kind) {
                    known.insert(m.id, (kind, key));
                }
            }
        }
        Ok(known)
    }

    /// UA8-D23, the gate behind `Checked::Relayer`: a write with a part the chain cannot verify passes `check_*` here, before
    /// it is simulated, or the job fails with no submit. A part the chain verifies is not checked: `check_*` refuses a valid
    /// `G…` member, and the chain is that part's check. A fill of a hash commit (version 0) and `store_pqz_pop` attest nothing; a stored proof is
    /// refused unsent (`pop_not_stored`).
    async fn ua8_precheck(&self, op: &Value) -> std::result::Result<(), SimError> {
        let rv = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let registry = self.relay_fee.ua_registry.as_ref().ok_or_else(|| SimError::Revert("params.ua_registry is not set".into()))?;
        let (w, relayer) = if op["function"] == ACCEPT { accept_write(op) } else { ua8_write(op) }.map_err(rv)?;
        let (kind, key_data) = match &w {
            Ua8Write::Register(a) => (register_kind(a), a.key_data()),
            Ua8Write::SetKem(a) if a.version == 0 => return Ok(()),
            Ua8Write::StorePop { ua, .. } => return self.pop_not_stored(registry, ua).await,
            Ua8Write::SetKem(SetKemKeyArgs { ua, .. }) | Ua8Write::SetPqz { ua, .. } | Ua8Write::Accept { ua, .. } => {
                let (kind, key, _) = self.ua8_record(registry, ua).await?.ok_or_else(|| SimError::Revert("the UA is not registered".into()))?;
                // the answer decides whether anything is checked, so it must be this id's, as `Members` is
                if scaas_ua::ua_of(kind, &key) != Ok(*ua) {
                    return Err(SimError::Revert(format!("record_of answered another record for {}", hex(ua))));
                }
                (kind, key)
            }
        };
        if let Ua8Write::Accept { ua, slot } = &w {
            self.not_yet_accepted(registry, ua, slot.index).await?;
        }
        if !ua8_marked(&w, kind, &key_data).map_err(|e| rv(e.context("key data")))? {
            return Ok(());
        }
        if relayer.is_none() {
            return Err(SimError::Revert(format!("a part of kind {kind:#06x} needs a relayer (NotVerifiable): this job names none")));
        }
        let refused = |e: UAError| SimError::Revert(format!("off-chain check refused the record: {}", e.code()));
        // the contract's layout first, 16 members among it: one job costs at most 16 reads
        scaas_ua::derive_ua(kind, &key_data, false).map_err(refused)?;
        let known = if kind == MSIG { self.ua8_members(registry, &key_data).await? } else { HashMap::new() };
        ua8_check(&w, kind, &key_data, &|id| known.get(&id).cloned()).map_err(refused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const NETWORK: &str = "Standalone Network ; February 2017";
    const CONTRACT: &str = "CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO";
    const FROM: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
    /// `smartcontracts/soroban/contracts/token/src/test.rs::cross_implementation_vector` (= Python `test_fam_soroban`).
    const PREIMAGE: &str = "00000009baefd734b8d3e48472cff83912375fedbc7573701912fe308af730180f97d74a000000000000002a000003e800000000000000012222222222222222222222222222222222222222222222222222222222222222000000037061790000000005000000120000000000000000e3726830a0b60cb5f52c844cffcd4eed65eba5c155e89b26411562724e71e54400000012000000000000000033333333333333333333333333333333333333333333333333333333333333330000000a000000000000000000000000000030390000000d00000020111111111111111111111111111111111111111111111111111111111111111100000005000000006b49d32c00000000";

    fn unhex(s: &str) -> Result<Vec<u8>> {
        Ok(alloy::hex::decode(s)?)
    }

    /// U8S-D8's `Chain` kinds are the Soroban registry's own register gate (`ua-registry` `register_record`), both directions;
    /// `mldsa87` (0x0134, CTR-UA-39 Q5) stays out until its Soroban round, so its records fail closed through `check_*`.
    #[test]
    fn chain_kind_is_the_registry_gate_without_mldsa87() {
        let registry = [0x0100, 0x0101, 0x0102, 0x0108, MSIG, 0x0130, 0x0131];
        for kind in 0x0001..=0x0150u16 {
            assert_eq!(chain_kind(kind), registry.contains(&kind), "{kind:#06x}");
        }
        assert!(!chain_kind(0x0134));
    }

    /// `fndsa1024` (0x0135, CTR-UA-40) stays out of the Soroban gate too until its Soroban round (EVM first): a record of it fails
    /// closed through `check_*`, while `fndsa512`'s neighbours keep their verdicts.
    #[test]
    fn chain_kind_is_the_registry_gate_without_fndsa1024() {
        assert!(!chain_kind(0x0135) && !chain_kind(0x0132) && chain_kind(0x0131));
    }

    fn op(payload: Value, sig: &str) -> Value {
        json!({"payload": payload, "from": FROM, "signature": sig, "contract": CONTRACT, "valid_until": 1_800_000_300u64, "extra": {}})
    }

    #[test]
    fn cross_implementation_vector_decodes_into_the_call() {
        assert_eq!(hex(&Sha256::digest(unhex(PREIMAGE).unwrap())), "0a2127bfdc94f6062f0ec27f6db966ae719dafaca90bc537666eab606b901103");
        let (call, auth) = host_call(&op(cross_payload(), &sig())).unwrap();
        assert_eq!(call.contract_address.to_string(), CONTRACT);
        assert_eq!(call.function_name.0.as_slice(), b"pay");
        assert_eq!(call.args.len(), 5);
        let SorobanCredentials::Address(c) = &auth[0].credentials else { panic!() };
        assert_eq!((c.nonce, c.signature_expiration_ledger, c.address.to_string()), (42, 1000, FROM.to_string()));
        // Host account signature format: Vec[Map{public_key, signature}].
        let ScVal::Vec(Some(v)) = &c.signature else { panic!() };
        let ScVal::Map(Some(m)) = &v[0] else { panic!() };
        assert_eq!(m.0.len(), 2);
    }

    /// Owner ruling 2026-11-02: from the named fields alone the node rebuilds the exact bytes the subject signed, a sub-invocation
    /// included: the cross vector's `HashIdPreimage`, on this chain's network id, from the entry the job became.
    #[test]
    fn named_payload_rebuilds_the_signed_bytes() {
        let preimage = |e: &SorobanAuthorizationEntry| {
            let SorobanCredentials::Address(c) = &e.credentials else { panic!() };
            HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                network_id: Hash(network_id(NETWORK)), nonce: c.nonce, signature_expiration_ledger: c.signature_expiration_ledger, invocation: e.root_invocation.clone(),
            }).to_xdr(Limits::none()).unwrap()
        };
        let (_, auth) = host_call(&op(cross_payload(), &sig())).unwrap();
        assert_eq!(hex(&preimage(&auth[0])), PREIMAGE);
        let HashIdPreimage::SorobanAuthorization(mut p) = HashIdPreimage::from_xdr(unhex(PREIMAGE).unwrap(), Limits::none()).unwrap() else { panic!() };
        p.nonce = i64::MIN;
        p.invocation.sub_invocations = vec![inv(CONTRACT, "pay", vec![addr(FROM), i128v(7)], vec![inv(WALLET, "deep", vec![], vec![])])].try_into().unwrap();
        let named = json!({"nonce": p.nonce.to_string(), "expiry": p.signature_expiration_ledger, "invocation": invocation(&p.invocation)});
        let (call, auth) = host_call(&op(named, &sig())).unwrap();
        assert_eq!(hex(&preimage(&auth[0])), hex(&HashIdPreimage::SorobanAuthorization(p).to_xdr(Limits::none()).unwrap()));
        assert_eq!(call.function_name.0.as_slice(), b"pay", "the host call is the root, not what it calls");
    }

    #[test]
    fn wrong_contract_and_bad_signatures_are_refused() {
        let mut o = op(cross_payload(), &sig());
        o["contract"] = json!("CBCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEJ5HZ");
        assert!(host_call(&o).is_err());
        assert!(host_call(&op(cross_payload(), "0xabcd")).is_err(), "account signatures are 64 bytes");
        assert!(format!("{:#}", host_call(&op(cross_payload(), &"ab".repeat(64))).unwrap_err()).contains("0x"), "bytes are 0x… hex, as every leaf");
        assert!(format!("{:#}", host_call(&op(json!("00000001"), &sig())).unwrap_err()).contains(HEX_ARGS_REFUSED));
        // one change each
        for (k, bad) in [("nonce", json!(1.5)), ("expiry", json!(-1)), ("invocation", json!(null)), ("memo", json!(1))] {
            let mut p = cross_payload();
            p[k] = bad;
            assert!(host_call(&op(p, &sig())).is_err(), "{k}");
        }
        let mut p = cross_payload();
        p["invocation"]["sub_invocations"] = json!("0x00");
        assert!(format!("{:#}", host_call(&op(p, &sig())).unwrap_err()).contains(HEX_ARGS_REFUSED), "a hex tree");
        let mut p = cross_payload();
        p["invocation"].as_object_mut().unwrap().remove("function");
        assert!(host_call(&op(p, &sig())).is_err());
    }

    #[test]
    fn decodes_payment_and_executed_events() {
        let addr = |s: &str| ScVal::Address(ScAddress::from_str(s).unwrap()).to_xdr_base64(Limits::none()).unwrap();
        let sym = |s: &str| ScVal::Symbol(ScSymbol(s.try_into().unwrap())).to_xdr_base64(Limits::none()).unwrap();
        let b32 = ScVal::Bytes(vec![0x11u8; 32].try_into().unwrap());
        let amt = ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: 12_345 });
        let data = ScVal::Vec(Some(vec![amt, b32.clone()].try_into().unwrap())).to_xdr_base64(Limits::none()).unwrap();
        let ev = json!({"ledger": 7, "contractId": CONTRACT, "txHash": "AB".repeat(32), "id": "0000000030064775168-0000000001",
                        "topic": [sym("PaymentSettled"), addr(FROM), addr(CONTRACT)], "value": data});
        let e = decode_event(&ev).unwrap();
        assert_eq!((e["event"].as_str(), e["amount"].as_str(), e["log_index"].as_u64()), (Some("PaymentSettled"), Some("12345"), Some(1)));
        assert_eq!(e["entry_ref"], json!(format!("0x{}", "11".repeat(32))));
        assert_eq!(e["tx_hash"], json!(format!("0x{}", "ab".repeat(32))));
        assert_eq!(e["to"], json!(CONTRACT));
        let ev = json!({"ledger": 7, "contractId": CONTRACT, "txHash": "ab".repeat(32), "id": "1-2",
                        "topic": [sym("MetaTransactionExecuted"), addr(FROM)], "value": b32.to_xdr_base64(Limits::none()).unwrap()});
        assert_eq!(decode_event(&ev).unwrap()["digest"], json!(format!("0x{}", "11".repeat(32))));
        let ev = json!({"ledger": 7, "contractId": CONTRACT, "txHash": "ab".repeat(32), "id": "1-2",
                        "topic": [sym("transfer"), addr(FROM)], "value": b32.to_xdr_base64(Limits::none()).unwrap()});
        assert!(decode_event(&ev).is_none(), "SEP-41 transfer events are not ours");
    }

    /// T17 (G): `PaymentMeta` and the router's `RelayFeePaid` decode and join the expected token's `PaymentSettled`
    /// of the same transaction (`indexer::join_pay_events`); a fee in another token joins nothing; neither is a row.
    #[test]
    fn soroban_indexer_joins_pay_meta_and_relay_fee() {
        const ROUTER: &str = "CBCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEJ5HZ";
        let x = |v: ScVal| v.to_xdr_base64(Limits::none()).unwrap();
        let addr = |s: &str| x(ScVal::Address(ScAddress::from_str(s).unwrap()));
        let sym = |s: &str| x(ScVal::Symbol(ScSymbol(s.try_into().unwrap())));
        let b = |v: &[u8]| ScVal::Bytes(v.to_vec().try_into().unwrap());
        let amt = |n: u64| ScVal::I128(stellar_xdr::Int128Parts { hi: 0, lo: n });
        let vecv = |v: Vec<ScVal>| x(ScVal::Vec(Some(v.try_into().unwrap())));
        let ev = |contract: &str, i: u32, topic: Vec<String>, value: String| json!({"ledger": 7, "contractId": contract,
            "txHash": "ab".repeat(32), "id": format!("1-{i}"), "topic": topic, "value": value});
        let (pid, rf) = ([4u8; 32], [5u8; 32]);
        let evs = [
            ev(CONTRACT, 1, vec![sym("PaymentMeta"), x(b(&pid))], x(b(&[0xab, 0xcd]))),
            ev(CONTRACT, 2, vec![sym("PaymentSettled"), addr(FROM), addr(WALLET)], vecv(vec![amt(100), b(&pid)])),
            ev(CONTRACT, 3, vec![sym("PaymentSettled"), addr(FROM), addr(ROUTER)], vecv(vec![amt(5), b(&rf)])),
            ev(ROUTER, 4, vec![sym("RelayFeePaid"), x(b(&rf)), addr(WALLET), addr(CONTRACT)],
               vecv(vec![h_addr(FROM), h_addr(FROM), amt(5)])),
            ev(ROUTER, 5, vec![sym("RelayFeePaid"), x(b(&rf)), addr(WALLET), addr(WALLET)],
               vecv(vec![h_addr(FROM), h_addr(FROM), amt(5)])),
        ];
        let out = crate::indexer::join_pay_events(evs.iter().filter_map(decode_event).collect());
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|e| e["event"] == "PaymentSettled"));
        assert_eq!((out[0]["meta"].as_str(), out[1]["meta"].as_str()), (Some("0xabcd"), None));
        assert_eq!((out[1]["relay_target"].as_str(), out[1]["relay_payee"].as_str()), (Some(WALLET), Some(FROM)), "open mode: paid to the router");
        assert!(out[0]["relay_payee"].is_null());
    }

    // ------------------------------------------------------------ metatx-split T10 (CTR-MTX-26 / 27)

    use stellar_xdr::{HashIdPreimage, HashIdPreimageSorobanAuthorization, Hash};

    const WALLET: &str = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH";
    const OWNER: &str = FROM;
    /// `smartcontracts/soroban/contracts/relay-fee/src/test.rs::VEC_REF` (network id 0x07 x 32, salt 0x09 x 32).
    const VEC_REF: &str = "ce0e8797ad9aa168b64b32821f51bea8a931dbb5e8e15e0044cb94ca9dd4f106";
    const SALT: [u8; 32] = [9; 32];
    const NET7: [u8; 32] = [7; 32];

    fn addr(s: &str) -> ScVal {
        ScVal::Address(ScAddress::from_str(s).unwrap())
    }
    fn sym(s: &str) -> ScVal {
        ScVal::Symbol(ScSymbol(s.try_into().unwrap()))
    }
    fn byt(b: &[u8]) -> ScVal {
        ScVal::Bytes(b.to_vec().try_into().unwrap())
    }
    fn vecv(v: Vec<ScVal>) -> ScVal {
        ScVal::Vec(Some(ScVec(v.try_into().unwrap())))
    }
    fn i128v(x: u64) -> ScVal {
        ScVal::I128(Int128Parts { hi: 0, lo: x })
    }
    fn inv(contract: &str, f: &str, args: Vec<ScVal>, subs: Vec<SorobanAuthorizedInvocation>) -> SorobanAuthorizedInvocation {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::from_str(contract).unwrap(),
                function_name: ScSymbol(f.try_into().unwrap()),
                args: args.try_into().unwrap(),
            }),
            sub_invocations: subs.try_into().unwrap(),
        }
    }
    /// A signed invocation as a job names it.
    fn invocation(i: &SorobanAuthorizedInvocation) -> Value {
        let SorobanAuthorizedFunction::ContractFn(c) = &i.function else { panic!("a contract call") };
        json!({"contract": c.contract_address.to_string(), "function": String::from_utf8_lossy(c.function_name.0.as_slice()),
               "args": c.args.iter().map(relayed).collect::<Vec<_>>(), "sub_invocations": i.sub_invocations.iter().map(invocation).collect::<Vec<_>>()})
    }
    fn payload(root: SorobanAuthorizedInvocation) -> Value {
        json!({"nonce": 42, "expiry": 1000, "invocation": invocation(&root)})
    }
    /// `PREIMAGE`'s named fields.
    fn cross_payload() -> Value {
        let HashIdPreimage::SorobanAuthorization(p) = HashIdPreimage::from_xdr(unhex(PREIMAGE).unwrap(), Limits::none()).unwrap() else { panic!() };
        json!({"nonce": p.nonce, "expiry": p.signature_expiration_ledger, "invocation": invocation(&p.invocation)})
    }
    fn sig() -> String {
        format!("0x{}", "ab".repeat(64))
    }
    fn meta_row() -> Value {
        let rows: Vec<Value> = serde_json::from_str(include_str!("../../../smartcontracts/vectors/metatx/paymeta.json")).unwrap();
        rows[0].clone()
    }
    fn strip(s: &Value) -> Vec<u8> {
        unhex(s.as_str().unwrap().trim_start_matches("0x")).unwrap()
    }
    fn pay_meta_op(salt: &[u8], meta: &[u8], op_salt: &[u8], op_meta: &[u8]) -> Value {
        let args = vec![addr(FROM), addr(WALLET), i128v(40), byt(salt), byt(meta), ScVal::U64(1_800_000_300)];
        json!({"payload": payload(inv(CONTRACT, "pay_meta", args, vec![])), "from": FROM, "signature": sig(),
               "contract": CONTRACT, "valid_until": 1_800_000_300u64,
               "salt": format!("0x{}", hex(op_salt)), "meta": format!("0x{}", hex(op_meta)), "extra": {}})
    }

    #[test]
    fn soroban_pay_meta_job_builds_pay_meta() {
        let r = meta_row();
        let (salt, meta, id) = (strip(&r["salt"]), strip(&r["meta"]), strip(&r["payId"]));
        // The shared vector: payId = keccak256("scaas.pay.meta" || salt || keccak256(meta)).
        assert_eq!(meta_pay_id(&salt, &meta).to_vec(), id);
        let mut op = pay_meta_op(&salt, &meta, &salt, &meta);
        let (call, auth) = pay_meta_job(&op, 2048).unwrap();
        assert_eq!((call.function_name.0.as_slice(), call.args.len(), auth.len()), (&b"pay_meta"[..], 6, 1));
        // pay_ref given by the job must equal the commitment.
        op["pay_ref"] = json!(format!("0x{}", hex(&id)));
        assert!(pay_meta_job(&op, 2048).is_ok());
        op["pay_ref"] = json!(format!("0x{}", "00".repeat(32)));
        assert!(pay_meta_job(&op, 2048).is_err(), "pay_ref != metaPayId");
        // The unsigned salt / meta must be the signed ones (the auth entry covers them).
        assert!(pay_meta_job(&pay_meta_op(&salt, &meta, &[1; 32], &meta), 2048).is_err());
        assert!(pay_meta_job(&pay_meta_op(&salt, &meta, &salt, b"other"), 2048).is_err());
        // Wrong function, over the cap.
        let mut plain = pay_meta_op(&salt, &meta, &salt, &meta);
        plain["payload"] = json!(payload(inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&id), ScVal::U64(1)], vec![])));
        assert!(pay_meta_job(&plain, 2048).is_err());
        let big = vec![7u8; 2049];
        assert!(pay_meta_job(&pay_meta_op(&salt, &big, &salt, &big), 2048).unwrap_err().to_string().contains("max_pay_meta_bytes"));
        assert!(pay_meta_job(&pay_meta_op(&salt, &big, &salt, &big), 4096).is_ok(), "params.max_pay_meta_bytes raises it");
    }

    fn relay_job(token_pay_ref: &[u8], op_ref: &[u8]) -> Value {
        relay_job_with(token_pay_ref, op_ref, sym("revoke"))
    }

    fn relay_job_with(token_pay_ref: &[u8], op_ref: &[u8], func: ScVal) -> Value {
        relay_job_to(token_pay_ref, op_ref, func, WALLET2)
    }

    /// `to` = the payee: the router (open mode, the default), the lane, or anyone else (bound).
    fn relay_job_to(token_pay_ref: &[u8], op_ref: &[u8], func: ScVal, payee: &str) -> Value {
        relay_job_args(token_pay_ref, op_ref, func, payee, vec![addr(CONTRACT), addr(OWNER)])
    }

    /// `relay_job_to` with the target call's arguments given: the signed root and the job's `ref`, nothing else names the call.
    fn relay_job_args(token_pay_ref: &[u8], op_ref: &[u8], func: ScVal, payee: &str, args: Vec<ScVal>) -> Value {
        let (token, to) = (CONTRACT, addr(payee));
        let signed = vec![addr(WALLET), func, vecv(args), byt(&SALT), addr(token), to.clone(), i128v(7), ScVal::U64(1_800_000_300)];
        let pay = inv(token, "pay", vec![addr(OWNER), to, i128v(7), byt(token_pay_ref), ScVal::U64(1_800_000_300)], vec![]);
        json!({"kind": "relay_fee", "payload": payload(inv(WALLET2, "relay", signed, vec![pay])), "from": OWNER, "signature": sig(), "contract": WALLET2,
               "valid_until": 1_800_000_300u64, "ref": format!("0x{}", hex(op_ref)), "extra": {}})
    }
    const WALLET2: &str = "CBCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEJ5HZ"; // the router
    const LANE: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";

    fn policy() -> RelayFeePolicy {
        RelayFeePolicy { router: Some(ScAddress::from_str(WALLET2).unwrap()), tokens: vec![ScAddress::from_str(CONTRACT).unwrap()].into(),
                         params: rp(5), dex: Some(ScAddress::from_str(DEX).unwrap()), executor: OnceLock::new(),
                         ua_registry: None, relayers: OnceLock::new(), mandates: vec![], mandate_wasms: vec![] }
    }

    fn rp(min_amount: u128) -> crate::config::RelayParams {
        crate::config::RelayParams { min_amount, ..Default::default() }
    }

    /// T17 (every adapter): the one `op.kind` rule, never a pay to the router outside a relay, a relay fee that
    /// reaches this lane (open or bound to it) else refused unless `relay_bound_payee`, and a router that is set but
    /// not a contract address is a startup error.
    #[test]
    fn soroban_kind_router_and_payee_rules() {
        let lane = ScAddress::from_str(LANE).unwrap();
        let pay = |to: &str| json!({"payload": payload(inv(CONTRACT, "pay", vec![addr(FROM), addr(to), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": 1_800_000_300u64, "extra": {}});
        assert!(job_call(&NET7, &pay(WALLET), &lane, &policy()).is_ok());
        for k in [json!(7), json!(true), json!({}), json!("pay")] {
            let mut o = pay(WALLET);
            o["kind"] = k.clone();
            assert!(job_call(&NET7, &o, &lane, &policy()).unwrap_err().to_string().contains("unknown op.kind"), "{k}");
        }
        let mut o = pay(WALLET);
        o["meta"] = json!("0x00");
        assert!(job_call(&NET7, &o, &lane, &policy()).is_err(), "kind-less meta");
        assert!(job_call(&NET7, &pay(WALLET2), &lane, &policy()).unwrap_err().to_string().contains("router"), "never pay the router");
        assert!(job_call(&NET7, &pay(WALLET2), &lane, &RelayFeePolicy { router: None, ..policy() }).is_ok(), "no router configured");
        // the payee rule
        let args = vec![addr(CONTRACT), addr(OWNER)];
        let rf = relay_ref(&NET7, &ScAddress::from_str(WALLET).unwrap(), &ScSymbol("revoke".try_into().unwrap()), &args, &SALT);
        let to = |payee: &str| relay_job_to(&rf, &rf, sym("revoke"), payee);
        assert!(relay_fee_job(&NET7, &to(LANE), &lane, &policy()).is_ok(), "bound to this lane");
        let e = relay_fee_job(&NET7, &to(WALLET), &lane, &policy()).err().unwrap().to_string();
        assert!(e.contains("relay_bound_payee"), "{e}");
        let sponsored = RelayFeePolicy { params: crate::config::RelayParams { relay_bound_payee: true, min_amount: 1_000, ..Default::default() }, ..policy() };
        assert!(relay_fee_job(&NET7, &to(WALLET), &lane, &sponsored).is_ok(), "sponsored: no min_amount");
        assert!(relay_fee_job(&NET7, &to(LANE), &lane, &sponsored).is_err(), "ours: min_amount");
        // config
        let cfg = |router: toml::Value| {
            let mut t = toml::Table::new();
            t.insert("router".into(), router);
            let mut c = ChainCfg::default();
            c.params.insert("relay_fee".into(), toml::Value::Table(t));
            c
        };
        assert!(RelayFeePolicy::from_cfg(&cfg(WALLET2.into())).unwrap().router.is_some());
        for bad in [toml::Value::from("CNOTANADDRESS"), toml::Value::from(FROM), toml::Value::from(7)] {
            assert!(RelayFeePolicy::from_cfg(&cfg(bad.clone())).is_err(), "{bad}");
        }
        let mut c = cfg(WALLET2.into());
        c.params["relay_fee"].as_table_mut().unwrap().insert("min_amount".into(), (-1).into());
        assert!(RelayFeePolicy::from_cfg(&c).is_err(), "a negative min_amount is an error, never the default");
        let mut c = cfg(WALLET2.into());
        c.tokens = vec![crate::config::TokenCfg { address: "CNOTANADDRESS".into(), decimals: 7 }];
        assert!(format!("{:#}", RelayFeePolicy::from_cfg(&c).err().expect("bad token accepted")).contains("tokens"), "T17 fix 1");
    }

    #[test]
    fn soroban_relay_fee_job_checks_ref() {
        let args = vec![addr(CONTRACT), addr(OWNER)];
        let revoke = ScSymbol("revoke".try_into().unwrap());
        let rf = relay_ref(&NET7, &ScAddress::from_str(WALLET).unwrap(), &revoke, &args, &SALT);
        assert_eq!(hex(&rf), VEC_REF, "same ref as the contract's test");
        assert_ne!(rf, relay_ref(&NET7, &ScAddress::from_str(WALLET).unwrap(), &revoke, &args, &[8; 32]), "salt is in the ref");
        let lane = ScAddress::from_str(LANE).unwrap();
        let ok = relay_job(&rf, &rf);
        let (call, auth, got) = relay_fee_job(&NET7, &ok, &lane, &policy()).unwrap();
        assert_eq!((call.function_name.0.as_slice(), call.args.len(), got), (&b"relay"[..], 10, rf));
        // N2: built from the signed root, the call a job used to send as `extra.call`: the payer the signer, the relayer this lane
        assert_eq!(call.args.as_slice(), [addr(OWNER), addr(WALLET), sym("revoke"), vecv(args.clone()), byt(&SALT), addr(CONTRACT), addr(WALLET2), i128v(7),
                                          ScVal::U64(1_800_000_300), addr(LANE)]);
        // The payer's entry plus the explicit source-account entry (source auth is not implicit), rooted at the call.
        assert_eq!(auth.len(), 2);
        assert!(matches!(auth[0].credentials, SorobanCredentials::Address(_)));
        assert!(matches!(auth[1].credentials, SorobanCredentials::SourceAccount));
        assert_eq!(auth[1].root_invocation.function, SorobanAuthorizedFunction::ContractFn(call.clone()));
        assert!(auth[1].root_invocation.sub_invocations.is_empty());
        let bad = |o: Value| relay_fee_job(&NET7, &o, &lane, &policy()).is_err();
        // The payment's ref is not the call's; the job's declared ref is not the call's.
        assert!(bad(relay_job(&[9; 32], &rf)));
        assert!(bad(relay_job(&rf, &[9; 32])));
        let mut bare = ok.clone();
        bare["ref"] = json!(hex(&rf));
        assert!(bad(bare), "bytes are 0x… hex, as every leaf");
        // A signed root that is not the eight arguments of `relay`.
        let mut short = ok.clone();
        short["payload"] = json!(payload(inv(WALLET2, "relay", vec![addr(WALLET)], vec![])));
        assert!(bad(short));
        // Policy: other router, unregistered token, fee below the minimum.
        let other = RelayFeePolicy { router: Some(ScAddress::from_str(WALLET).unwrap()), ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &other).is_err());
        let none = RelayFeePolicy { router: None, ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &none).is_err());
        let no_token = RelayFeePolicy { tokens: vec![].into(), ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &no_token).is_err());
        let dear = RelayFeePolicy { params: rp(8), ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &dear).is_err());
        assert!(relay_fee_job(&NET7, &ok, &lane, &RelayFeePolicy { params: rp(7), ..policy() }).is_ok());
    }

    /// A symbol over 32 bytes: refused, no panic.
    #[test]
    fn relay_fee_job_survives_a_long_symbol() {
        let mut o = relay_job(&[1; 32], &[2; 32]);
        o["payload"]["invocation"]["args"][1]["value"] = json!("x".repeat(33));
        assert!(relay_fee_job(&NET7, &o, &lane(), &policy()).is_err());
    }

    // ------------------------------------------------------------ UA-Soroban T9 (spec §8, §9; SOR-D14)

    const DEX: &str = "CBTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGM2VL";
    const MANDATE: &str = "CBKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVLO6Q";
    const VU: u64 = 1_800_000_300;
    /// The Wasm the test chains' params list and their mandates run.
    const MANDATE_WASM: [u8; 32] = [9; 32];
    const UA: [u8; 32] = [0x77; 32];

    fn executor() -> ScAddress {
        ScAddress::Contract(stellar_xdr::ContractId(Hash([0x5a; 32])))
    }
    fn sc(s: &str) -> ScAddress {
        ScAddress::from_str(s).unwrap()
    }
    fn lane() -> ScAddress {
        sc(LANE)
    }
    pub(super) fn h_addr(s: &str) -> ScVal {
        holder_addr(&sc(s))
    }
    fn h_ua(u: [u8; 32]) -> ScVal {
        vecv(vec![sym("Ua"), byt(&u)])
    }
    fn u64v(x: u64) -> ScVal {
        ScVal::U64(x)
    }
    /// A DEX `Order` as its contracttype map (fields sorted).
    fn order(maker: ScVal, relayer: &str, expiry: u64) -> ScVal {
        let e = |k: &str, v: ScVal| ScMapEntry { key: sym(k), val: v };
        ScVal::Map(Some(ScMap(vec![
            e("buy_amount", i128v(5)), e("buy_token", addr(WALLET)), e("destination", maker.clone()), e("expiry", u64v(expiry)),
            e("maker", maker), e("max_fee_ppm", ScVal::U32(0)), e("relayer", addr(relayer)), e("salt", u64v(1)),
            e("sell_amount", i128v(5)), e("sell_token", addr(CONTRACT)),
        ].try_into().unwrap())))
    }
    /// A `ua_metatx` op as a client writes it: each argument by its name in `UA_FNS`. One of the wrong type, or none, is `null` or
    /// missing, which the parser refuses.
    fn ua_op(contract: &str, function: &str, args: Vec<ScVal>) -> Value {
        let table = UA_FNS.iter().find(|f| f.name == function).map_or(&[][..], |f| f.args);
        let named: serde_json::Map<String, Value> = table.iter().zip(&args).map(|((k, t), v)| (k.to_string(), job_value(t, v))).collect();
        json!({"contract": contract, "function": function, "args": named})
    }
    fn ua_sig(signature: &[u8]) -> ScVal {
        sc_struct([("key_data", byt(&[])), ("members", vecv(vec![])), ("signature", byt(signature))]).unwrap()
    }
    fn auth_arg() -> ScVal {
        ua_sig(&[0xaa; 8])
    }
    /// One well-formed op per allow-listed function, `relayer` as given (`Void` = None).
    fn ua_ops(relayer: ScVal) -> Vec<(&'static str, &'static str, Vec<ScVal>)> {
        let (ua, l, r, a) = (byt(&UA), byt(&[1; 32]), relayer, auth_arg());
        let rf = byt(&[3; 32]);
        vec![
            (CONTRACT, "ua_transfer", vec![ua.clone(), h_addr(WALLET), i128v(5), l.clone(), u64v(0), u64v(VU), r.clone(), a.clone()]),
            (CONTRACT, "ua_pay", vec![ua.clone(), h_addr(WALLET), i128v(5), rf.clone(), u64v(VU), r.clone(), a.clone()]),
            (CONTRACT, "ua_pay_meta", vec![ua.clone(), h_addr(WALLET), i128v(5), byt(&[4; 32]), byt(b"m"), u64v(VU), r.clone(), a.clone()]),
            (CONTRACT, "ua_burn", vec![ua.clone(), i128v(5), l.clone(), u64v(0), u64v(VU), r.clone(), a.clone()]),
            (CONTRACT, "ua_cancel_nonce", vec![ua.clone(), l.clone(), u64v(VU), a.clone()]),
            (MANDATE, "mtx_set_mandate", vec![addr(CONTRACT), h_ua(UA), i128v(5), i128v(9), u64v(60), u64v(VU), l.clone(), u64v(0), u64v(VU), r.clone(), a.clone()]),
            (MANDATE, "mtx_set_payee", vec![addr(CONTRACT), h_addr(WALLET), ScVal::Bool(true), l.clone(), u64v(0), u64v(VU), r.clone(), a.clone()]),
            (MANDATE, "mtx_revoke", vec![addr(CONTRACT), h_ua(UA), u64v(1), l.clone(), u64v(0), u64v(VU), r.clone(), a.clone()]),
            (MANDATE, "mtx_withdraw", vec![addr(CONTRACT), h_ua(UA), i128v(5), l.clone(), u64v(0), u64v(VU), r.clone(), a.clone()]),
            (MANDATE, "mtx_mandate_pay", vec![addr(CONTRACT), h_addr(WALLET), i128v(5), rf.clone(), u64v(1), u64v(VU), r, a.clone()]),
            (DEX, "ua_cancel", vec![order(h_ua(UA), LANE, VU), a.clone()]),
            (DEX, "settle", vec![order(h_ua(UA), LANE, VU), order(h_addr(FROM), LANE, VU + 9), i128v(5), a, ua_sig(&[])]),
        ]
    }
    /// `router.ua_relay(payer, target, func, args, salt, token, to, amount, valid_until, relayer, auth)`.
    fn ua_relay_args(to: ScVal, relayer: &str) -> Vec<ScVal> {
        vec![byt(&UA), addr(WALLET), sym("revoke"), vecv(vec![addr(CONTRACT)]), byt(&SALT), addr(CONTRACT), to, i128v(7), u64v(VU),
             addr(relayer), auth_arg()]
    }
    fn source_entries(auth: &[SorobanAuthorizationEntry]) -> Vec<&SorobanAuthorizationEntry> {
        auth.iter().filter(|e| matches!(e.credentials, SorobanCredentials::SourceAccount)).collect()
    }

    /// One value of a job in its JSON, `ty` the contract's type name as `UA_FNS` and `ua-ops.json` spell it: what a client writes.
    /// A value of another type comes out `null`, which the parser refuses.
    fn job_value(ty: &str, v: &ScVal) -> Value {
        let h0 = |b: &[u8]| json!(format!("0x{}", hex(b)));
        let of = |k: &str, t: &str| field(v, k).map_or(Value::Null, |x| job_value(t, x));
        match (ty, v) {
            ("Address" | "Option<Address>", ScVal::Address(a)) => json!(a.to_string()),
            ("BytesN<32>" | "Bytes", ScVal::Bytes(b)) => h0(b.as_slice()),
            ("i128", ScVal::I128(_)) => json!(scval_i128(v).unwrap().to_string()),
            ("u64", ScVal::U64(n)) => json!(n),
            ("u32", ScVal::U32(n)) => json!(n),
            ("bool", ScVal::Bool(b)) => json!(b),
            ("Symbol", ScVal::Symbol(_)) => json!(scval_str(v).unwrap()),
            ("Holder", _) => match holder(v) {
                Some(Holder::Addr(a)) => json!({"Addr": a.to_string()}),
                Some(Holder::Ua(u)) => json!({"Ua": format!("0x{}", hex(u))}),
                None => Value::Null,
            },
            ("Order", ScVal::Map(_)) => Value::Object(ORDER.iter().map(|(k, t)| (k.to_string(), of(k, t))).collect()),
            ("UaSig", ScVal::Map(_)) => {
                let slots: Vec<ScVal> = match field(v, "members") {
                    Some(ScVal::Vec(Some(m))) => m.to_vec(),
                    _ => vec![],
                };
                let slot = |m: &ScVal| json!({"index": field(m, "index").map(|i| job_value("u32", i)), "key_data": field(m, "key_data").map(|b| job_value("Bytes", b)), "sig": field(m, "sig").map(|b| job_value("Bytes", b))});
                json!({"key_data": of("key_data", "Bytes"), "signature": of("signature", "Bytes"), "members": slots.iter().map(slot).collect::<Vec<_>>()})
            }
            ("Vec<Val>", ScVal::Vec(Some(l))) => Value::Array(l.iter().map(relayed).collect()),
            ("Map", ScVal::Map(Some(m))) => json!(m.iter().map(|e| json!({"key": relayed(&e.key), "val": relayed(&e.val)})).collect::<Vec<_>>()),
            _ => Value::Null,
        }
    }
    /// One argument of a relayed call in its JSON: no declared type, so it names its own.
    fn relayed(v: &ScVal) -> Value {
        let ty = match v {
            ScVal::Address(_) => "Address",
            ScVal::Bytes(_) => "Bytes",
            ScVal::I128(_) => "i128",
            ScVal::U64(_) => "u64",
            ScVal::U32(_) => "u32",
            ScVal::Bool(_) => "bool",
            ScVal::Symbol(_) => "Symbol",
            ScVal::Vec(_) => "Vec<Val>",
            ScVal::Map(_) => "Map",
            ScVal::Void => return json!({"type": "Void", "value": null}),
            other => panic!("not a relayed value in these tests: {other:?}"),
        };
        json!({"type": ty, "value": job_value(ty, v)})
    }

    /// N2: every row of `ua-ops.json` as a job: each value read from the row, written as JSON by the row's own name and type, and
    /// that JSON alone reaches the node. The XDR the node builds is the row's, argument by argument in the row's order, and its digest
    /// the row's, which the contract tests reproduce. `ua_relay`'s digest is the inner `token.ua_pay`, with `pay_ref = ref` and
    /// `relayer = Some(router)`.
    #[test]
    fn ua_metatx_digest_matches_ua_ops_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../smartcontracts/soroban/vectors/ua-ops.json")).unwrap();
        let net = network_id(v["network"]["passphrase"].as_str().unwrap());
        let c = &v["contracts"];
        let at = |k: &str| sc(c[k].as_str().unwrap());
        let policy = RelayFeePolicy { router: Some(at("router")), tokens: vec![at("token")].into(), params: rp(5), dex: Some(at("dex")),
                                      executor: OnceLock::new(), ua_registry: None, relayers: OnceLock::new(), mandates: vec![], mandate_wasms: vec![] };
        let xdr = |s: &Value| ScVal::from_xdr(strip(s), Limits::none()).unwrap();
        let mut n = 0;
        for e in v["entries"].as_array().unwrap() {
            if e["name"] == "ua_order" {
                continue; // `ua_trade`'s order digest: signed by the maker, run by the DEX, never a job
            }
            for row in e["perKind"].as_array().unwrap() {
                let list = row["args"].as_array().unwrap();
                let mut want: Vec<ScVal> = list.iter().map(|a| xdr(&a["xdr"])).collect();
                let mut fields: serde_json::Map<String, Value> =
                    list.iter().map(|a| (a["name"].as_str().unwrap().to_string(), job_value(a["type"].as_str().unwrap(), &xdr(&a["xdr"])))).collect();
                let auth = xdr(&row["authXdr"]);
                let (contract, function) = if e["name"] == "ua_relay" {
                    let r = &e["relay"];
                    assert_eq!(want[3], byt(&strip(&r["ref"])), "the vector's pay_ref is its relay ref");
                    let inner: Vec<ScVal> = r["args"].as_array().unwrap().iter().map(|a| xdr(&a["xdr"])).collect();
                    let outer = json!({"payer": fields["from"], "target": r["target"], "func": r["func"], "args": inner.iter().map(relayed).collect::<Vec<_>>(),
                                       "salt": r["salt"], "token": e["contract"], "to": fields["to"], "amount": fields["amount"],
                                       "valid_until": fields["valid_until"], "relayer": LANE});
                    fields = outer.as_object().unwrap().clone();
                    want = vec![want[0].clone(), addr(r["target"].as_str().unwrap()), sym(r["func"].as_str().unwrap()), vecv(inner),
                                byt(&strip(&r["salt"])), addr(e["contract"].as_str().unwrap()), want[1].clone(), want[2].clone(),
                                want[4].clone(), addr(LANE)];
                    (c["router"].as_str().unwrap(), "ua_relay")
                } else {
                    (e["contract"].as_str().unwrap(), e["fn"].as_str().unwrap())
                };
                fields.insert("auth".into(), job_value("UaSig", &auth));
                want.push(auth);
                let op = json!({"contract": contract, "function": function, "args": fields});
                // a row bound to one lane runs on that lane
                let me = op["args"]["relayer"].as_str().map_or_else(lane, sc);
                let (call, _, digest) = ua_metatx_job(&net, &op, &me, &policy).unwrap_or_else(|x| panic!("{} {}: {x:#}", e["name"], row["kind"]));
                assert_eq!(call.contract_address.to_string(), contract);
                assert_eq!(call.function_name.0.as_slice(), function.as_bytes());
                assert_eq!(call.args.as_slice(), want.as_slice(), "{} {}: the node's XDR is the row's", e["name"], row["kind"]);
                assert_eq!(format!("0x{}", hex(&digest)), row["digest"].as_str().unwrap(), "{} {}", e["name"], row["kind"]);
                n += 1;
            }
        }
        assert_eq!(n, 13 * 7, "every job row of the vector file");
    }

    /// N2: a job as a client writes it, by hand: the node builds the XDR from the named fields, in the contract's order, a struct's
    /// fields sorted, whatever order the job writes them in; `valid_until` comes from those same fields.
    #[test]
    fn soroban_job_explicit_args_build_xdr() {
        let (p, ua, zero) = (policy(), format!("0x{}", hex(&UA)), format!("0x{}", hex(&[1; 32])));
        let build = |op: Value| job_tx(&NET7, Some("ua_metatx"), &op, &lane(), &p).unwrap();
        let slot = sc_struct([("index", ScVal::U32(1)), ("key_data", byt(&[])), ("sig", byt(&[0xcc]))]).unwrap();
        let sig = json!({"signature": "0xaabb", "members": [{"sig": "0xcc", "index": 1, "key_data": "0x"}], "key_data": "0x"});
        let want_sig = sc_struct([("key_data", byt(&[])), ("members", vecv(vec![slot])), ("signature", byt(&[0xaa, 0xbb]))]).unwrap();

        // the widest i128, a u64 past 2^53 as a decimal string, a UA holder, the relayer null
        let max = i128::MAX.to_string();
        let (call, auth, vu) = build(json!({"contract": CONTRACT, "function": "ua_transfer", "args": {
            "auth": sig, "relayer": null, "valid_until": VU, "nonce": "18446744073709551615", "lane": zero, "amount": max, "to": {"Ua": ua}, "from": ua}}));
        let big = ScVal::I128(stellar_xdr::Int128Parts { hi: i64::MAX, lo: u64::MAX });
        assert_eq!(call.args.as_slice(), [byt(&UA), h_ua(UA), big, byt(&[1; 32]), u64v(u64::MAX), u64v(VU), ScVal::Void, want_sig.clone()]);
        assert_eq!(call.function_name.0.as_slice(), b"ua_transfer");
        assert_eq!((auth.len(), vu), (0, VU));

        // a relayed call of any shape: each argument names its type
        let target = [addr(LANE), byt(&[3]), i128v(5), u64v(1), ScVal::U32(2), ScVal::Bool(true), sym("x"), ScVal::Void, vecv(vec![addr(OWNER)]), h_ua(UA), want_sig.clone(),
                      sc_struct([("a", ScVal::U32(1)), ("b", byt(&[2]))]).unwrap()];
        let typed = json!([{"type": "Address", "value": LANE}, {"type": "Bytes", "value": "0x03"}, {"type": "i128", "value": "5"}, {"type": "u64", "value": 1},
                           {"type": "u32", "value": 2}, {"type": "bool", "value": true}, {"type": "Symbol", "value": "x"}, {"type": "Void", "value": null},
                           {"type": "Vec<Val>", "value": [{"type": "Address", "value": OWNER}]}, {"type": "Holder", "value": {"Ua": ua}}, {"type": "UaSig", "value": sig},
                           {"type": "Map", "value": [{"key": {"type": "Symbol", "value": "b"}, "val": {"type": "Bytes", "value": "0x02"}},
                                                     {"key": {"type": "Symbol", "value": "a"}, "val": {"type": "u32", "value": 1}}]}]);
        let (call, auth, _) = build(json!({"contract": WALLET2, "function": "ua_relay", "args": {
            "payer": ua, "target": WALLET, "func": "revoke", "args": typed, "salt": zero, "token": CONTRACT, "to": {"Addr": WALLET2}, "amount": "7",
            "valid_until": VU, "relayer": LANE, "auth": sig}}));
        assert_eq!(call.args.as_slice(), [byt(&UA), addr(WALLET), sym("revoke"), vecv(target.to_vec()), byt(&[1; 32]), addr(CONTRACT), h_addr(WALLET2), i128v(7),
                                          u64v(VU), addr(LANE), want_sig.clone()]);
        assert_eq!(auth.len(), 1, "the lane's own entry");

        // two orders, one UA and one native, with their signatures: the earlier expiry bounds the job
        let leg = |maker: Value, expiry: u64| json!({"salt": 1, "expiry": expiry, "max_fee_ppm": 0, "buy_amount": "5", "buy_token": WALLET, "sell_amount": "5",
                                                     "sell_token": CONTRACT, "relayer": LANE, "destination": maker, "maker": maker});
        let none = json!({"key_data": "0x", "signature": "0x", "members": []});
        let (call, _, vu) = build(json!({"contract": DEX, "function": "settle", "args": {
            "maker": leg(json!({"Ua": ua}), VU + 9), "taker": leg(json!({"Addr": FROM}), VU), "maker_fill": "5", "maker_auth": sig, "taker_auth": none}}));
        let empty = sc_struct([("key_data", byt(&[])), ("members", vecv(vec![])), ("signature", byt(&[]))]).unwrap();
        assert_eq!(call.args.as_slice(), [order(h_ua(UA), LANE, VU + 9), order(h_addr(FROM), LANE, VU), i128v(5), want_sig.clone(), empty]);
        assert_eq!(vu, VU);

        // a bool and a Holder::Addr; the digest is over what was built, `auth` left out
        let op = json!({"contract": MANDATE, "function": "mtx_set_payee", "args": {
            "token": CONTRACT, "payee": {"Addr": WALLET}, "allowed": true, "lane": zero, "nonce": 3, "valid_until": VU, "relayer": null, "auth": sig}});
        let (call, _, d) = ua_metatx_job(&NET7, &op, &lane(), &p).unwrap();
        let signed = [addr(CONTRACT), h_addr(WALLET), ScVal::Bool(true), byt(&[1; 32]), u64v(3), u64v(VU), ScVal::Void];
        assert_eq!(call.args.as_slice()[..7], signed);
        assert_eq!(d, op_digest(&NET7, &sc(MANDATE), &call.function_name, &signed).unwrap());
    }

    /// One `lane_step` of `job`: what it sent, its last state and error.
    async fn job_step(a: &SorobanAdapter, calls: &Arc<Mutex<Vec<String>>>, job: Value) -> (usize, String, String) {
        use crate::adapter::tests::{fake_odoo, Fake};
        let before = sends(calls);
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job], tokens: json!([]), ..Default::default() }).await;
        crate::adapter::lane_step(a, &odoo, 0, "n#0").await.unwrap();
        let f = o.lock().unwrap();
        let last = f.reports.last().unwrap();
        (sends(calls) - before, last["chain_state"].as_str().unwrap().to_string(), last["error"].as_str().unwrap_or_default().to_string())
    }

    /// N2, the owner's explicit parameters: a blob where a job has named fields is `HEX_ARGS_REFUSED` on every Soroban job kind, at
    /// every level. Each case is a job that passes, with one thing changed: the job goes `dead` on its one claim and nothing is sent.
    #[tokio::test]
    async fn soroban_hex_args_refused() {
        let hexed = |args: Vec<ScVal>| json!(format!("0x{}", hex(&ScVec(args.try_into().unwrap()).to_xdr(Limits::none()).unwrap())));
        let call_xdr = json!(hex(&InvokeContractArgs { contract_address: sc(CONTRACT), function_name: ScSymbol("pay".try_into().unwrap()), args: Default::default() }
            .to_xdr(Limits::none()).unwrap()));
        let answer: Answer = Arc::new(|c| match c.function_name.0.as_slice() {
            b"executor" => view_ok(ScVal::Address(executor())),
            b"ua_ref_used" => view_ok(ScVal::Bool(false)),
            _ => view_ok(ScVal::Void),
        });
        let net = network_id("x");
        let (a, calls) = stub_adapter(answer, true).await;
        let refused = async |job: Value, what: &str| {
            let (sent, state, error) = job_step(&a, &calls, job).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "{what}: {error}");
            assert!(error.contains(HEX_ARGS_REFUSED), "{what}: {error}");
        };

        // ua_metatx: `ua_pay`, relayer None
        let (c, f, args) = ua_ops(ScVal::Void).remove(1);
        let ua = ua_op(c, f, args.clone());
        let job = |op: &Value| json!({"id": 7, "kind": "ua_metatx", "op": op});
        assert_eq!(job_step(&a, &calls, job(&ua)).await.0, 1, "the passing job");
        let mut o = ua.clone();
        o["args"] = hexed(args);
        refused(job(&o), "op.args").await;
        for (k, v) in [("auth", hexed(vec![auth_arg()])), ("to", hexed(vec![h_ua(UA)]))] {
            let mut o = ua.clone();
            o["args"][k] = v;
            refused(job(&o), k).await;
        }
        let mut o = ua.clone();
        o["extra"] = json!({"call": call_xdr});
        refused(job(&o), "extra.call on a ua_metatx").await;
        let mut o = ua.clone();
        o["auth"] = json!([{"payload": PREIMAGE, "from": FROM, "signature": sig()}]);
        refused(job(&o), "a hex op.auth payload").await;
        o["auth"] = json!(PREIMAGE);
        refused(job(&o), "op.auth as a blob").await;
        let mut o = ua.clone();
        o["auth"] = json!([{"payload": payload(inv(CONTRACT, "pay", vec![], vec![])), "from": FROM, "signature": sig()}]);
        assert_eq!(job_step(&a, &calls, job(&o)).await.0, 1, "a named op.auth payload");
        // a relayed call's arguments
        let lane0 = stub_lane();
        let relay = ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), &lane0));
        assert_eq!(job_step(&a, &calls, job(&relay)).await.0, 1, "the passing ua_relay");
        let mut o = relay.clone();
        o["args"]["args"] = hexed(vec![addr(OWNER)]);
        refused(job(&o), "a relayed call's args").await;

        // signed_op: a plain pay, and the relay fee
        let pay = json!({"payload": payload(inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
                         "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": crate::submit::now() + 60, "extra": {}});
        let signed = |op: &Value| json!({"id": 7, "kind": "signed_op", "op": op});
        assert_eq!(job_step(&a, &calls, signed(&pay)).await.0, 1, "the passing signed_op");
        let mut o = pay.clone();
        o["extra"]["call"] = call_xdr.clone();
        refused(signed(&o), "extra.call on a signed_op").await;
        let mut o = pay.clone();
        o["args"] = hexed(vec![]);
        refused(signed(&o), "op.args on a signed_op").await;
        let mut o = pay.clone();
        o["payload"] = json!(PREIMAGE);
        refused(signed(&o), "a hex payload").await;
        let mut o = pay.clone();
        o["extra"]["auth"] = json!([{"payload": PREIMAGE, "from": FROM, "signature": sig()}]);
        refused(signed(&o), "a hex extra.auth payload").await;
        o["extra"]["auth"] = json!(PREIMAGE);
        refused(signed(&o), "extra.auth as a blob").await;
        let mut o = pay.clone();
        o["extra"]["auth"] = json!([{"payload": payload(inv(WALLET, "co", vec![], vec![])), "from": FROM, "signature": sig()}]);
        assert_eq!(job_step(&a, &calls, signed(&o)).await.0, 1, "a named extra.auth payload");
        let rf = relay_ref(&net, &sc(WALLET), &ScSymbol("revoke".try_into().unwrap()), &[addr(CONTRACT), addr(OWNER)], &SALT);
        let mut fee = relay_job_args(&rf, &rf, sym("revoke"), &stub_lane(), vec![addr(CONTRACT), addr(OWNER)]);
        fee["valid_until"] = json!(crate::submit::now() + 60);
        assert_eq!(job_step(&a, &calls, signed(&fee)).await.0, 1, "the passing relay fee");
        fee["extra"]["call"] = call_xdr.clone();
        refused(signed(&fee), "extra.call on a relay fee").await;

        // an order: `ua_cancel` needs `params.dex`
        let (ad, callsd) = allow_adapter().await;
        let cancel = ua_op(DEX, "ua_cancel", vec![order(h_ua(UA), LANE, VU), auth_arg()]);
        assert_eq!(job_step(&ad, &callsd, job(&cancel)).await.0, 1, "the passing ua_cancel");
        let mut o = cancel.clone();
        o["args"]["order"] = hexed(vec![]);
        let (sent, state, error) = job_step(&ad, &callsd, job(&o)).await;
        assert_eq!((sent, state.as_str()), (0, "dead"), "an order: {error}");
        assert!(error.contains(HEX_ARGS_REFUSED), "an order: {error}");

        // call: `store_pqz_pop`
        let (a8, calls8) = ua8_adapter(Arc::new(|_| view_ok(ScVal::Void))).await;
        let mut write = ops(&NONE).remove(7);
        write["valid_until"] = json!(crate::submit::now() + 60);
        let job8 = |op: &Value| json!({"id": 7, "kind": "call", "op": op});
        assert_eq!(job_step(&a8, &calls8, job8(&write)).await.0, 1, "the passing call job");
        for (k, v) in [("args", hexed(vec![byt(&UA), byt(&[1])])), ("extra", json!({"call": call_xdr}))] {
            let mut o = write.clone();
            o[k] = v;
            let (sent, state, error) = job_step(&a8, &calls8, job8(&o)).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "{k}: {error}");
            assert!(error.contains(HEX_ARGS_REFUSED), "{k}: {error}");
        }
    }

    type Change = fn(&mut Value);

    /// N2: the parser's own refusals, one change from a passing job each: dead on its one claim, nothing sent.
    #[tokio::test]
    async fn soroban_job_bad_fields_refused() {
        let (a, calls) = stub_adapter(Arc::new(|_| view_ok(ScVal::Void)), false).await;
        let (c, f, args) = ua_ops(ScVal::Void).remove(0);
        let ok = ua_op(c, f, args);
        let job = |op: &Value| json!({"id": 7, "kind": "ua_metatx", "op": op});
        assert_eq!(job_step(&a, &calls, job(&ok)).await.0, 1, "the passing job");
        let cases: &[(Change, &str)] = &[
            (|o| o["extra"] = json!({}), "unknown field"),
            (|o| o["args"]["memo"] = json!(1), "unknown field"),
            (|o| { o["args"].as_object_mut().unwrap().remove("nonce"); }, "nonce missing"),
            (|o| o["args"]["amount"] = json!(5), "i128"),
            (|o| o["args"]["amount"] = json!("5.5"), "i128"),
            (|o| o["args"]["amount"] = json!("170141183460469231731687303715884105728"), "i128"),
            (|o| o["args"]["to"] = json!({"Addr": WALLET, "Ua": "0x00"}), "holder"),
            (|o| o["args"]["to"] = json!({"Id": WALLET}), "holder"),
            (|o| o["args"]["to"] = json!({"Addr": "not a strkey"}), "address"),
            (|o| o["args"]["from"] = json!("0x77"), "not 32 bytes"),
            (|o| o["args"]["from"] = json!("77"), "0x"),
            (|o| o["args"]["nonce"] = json!(-1), "u64"),
            (|o| o["args"]["auth"]["members"] = json!([{"index": 70000, "key_data": "0x", "sig": "0x"}]), "number"),
        ];
        for (i, (change, why)) in cases.iter().enumerate() {
            let mut o = ok.clone();
            change(&mut o);
            let (sent, state, error) = job_step(&a, &calls, job(&o)).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "case {i}: {error}");
            assert!(error.contains(why), "case {i}: {error}");
        }
    }

    /// N2 review: every type a relayed call or a signed invocation may name that the contract table does not, against its XDR written
    /// by hand (Stellar-contract.x; `clientkeys` reads this table too). A `Map` is written in any order and sorted by key.
    const TYPED_KAT: &str = r#"[
        {"type": "String", "value": "hi", "xdr": "0000000e0000000268690000"},
        {"type": "u128", "value": "18446744073709551616", "xdr": "0000000900000000000000010000000000000000"},
        {"type": "i64", "value": -2, "xdr": "00000006fffffffffffffffe"},
        {"type": "i64", "value": "-9223372036854775808", "xdr": "000000068000000000000000"},
        {"type": "i32", "value": -2, "xdr": "00000004fffffffe"},
        {"type": "u256", "value": "6277101735386680763835789423207666416102355444464034512896", "xdr": "0000000b0000000000000001000000000000000000000000000000000000000000000000"},
        {"type": "i256", "value": "-1", "xdr": "0000000cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
        {"type": "Timepoint", "value": 5, "xdr": "000000070000000000000005"},
        {"type": "Duration", "value": "6", "xdr": "000000080000000000000006"},
        {"type": "Map", "value": [{"key": {"type": "u32", "value": 2}, "val": {"type": "bool", "value": true}}, {"key": {"type": "u32", "value": 1}, "val": {"type": "bool", "value": false}}],
         "xdr": "0000001100000001000000020000000300000001000000000000000000000003000000020000000000000001"},
        {"type": "MemberSig", "value": {"index": 3, "key_data": "0x", "sig": "0xab"},
         "xdr": "0000001100000001000000030000000f00000005696e64657800000000000003000000030000000f000000086b65795f646174610000000d000000000000000f00000003736967000000000d00000001ab000000"}
    ]"#;

    #[test]
    fn typed_values_against_their_xdr() {
        let rows: Vec<Value> = serde_json::from_str(TYPED_KAT).unwrap();
        for r in &rows {
            let v = relayed_of(&json!({"type": r["type"], "value": r["value"]})).unwrap_or_else(|e| panic!("{}: {e:#}", r["type"]));
            assert_eq!(hex(&v.to_xdr(Limits::none()).unwrap()), r["xdr"].as_str().unwrap(), "{}", r["type"]);
        }
        assert_eq!(rows.len(), 11, "every row, each type at least once");
        for (ty, bad) in [("u128", json!("-1")), ("u128", json!(1)), ("i32", json!(2_147_483_648u64)), ("i64", json!("9223372036854775808")), ("String", json!(1)),
                          ("u256", json!(format!("1{}", "0".repeat(78)))), ("i256", json!(format!("1{}", "0".repeat(77)))), ("Timepoint", json!(-1)), ("Duration", json!("x")),
                          ("u256", json!("0x10")), ("i256", json!("0x10")), ("u128", json!("")), ("i128", json!("-")),
                          ("Map", json!({"a": {"type": "u32", "value": 1}})), ("Error", json!(1))] {
            assert!(relayed_of(&json!({"type": ty, "value": bad})).is_err(), "{ty} {bad}");
        }
    }

    /// N2 review: `n` levels of `ScVal::Vec(Some([…]))` around a `Void`, in XDR.
    fn deep_xdr(n: usize) -> Vec<u8> {
        let mut b = [0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1].repeat(n);
        b.extend([0, 0, 0, 1]);
        b
    }

    /// XDR nested past the bound is refused by depth, where `Limits::len` alone would recurse about 2,700 levels in 64 KiB of hex and a
    /// stack overflow would abort the whole node. A `C…` subject's `signature` is the one job XDR left.
    #[test]
    fn deep_xdr_is_refused_not_a_stack_overflow() {
        let c = sc(CONTRACT);
        let xdr = |n: usize| json!(format!("0x{}", hex(&deep_xdr(n))));
        assert!(credential_signature(&c, &xdr(15)).is_ok());
        for n in [16, 64, 680] {
            assert!(format!("{:#}", credential_signature(&c, &xdr(n)).unwrap_err()).to_lowercase().contains("depth"), "{n} levels");
        }
    }

    /// The named path has the same bound: a job nested past it is refused, the deepest job within it goes through `sign` and `submit`.
    #[tokio::test]
    async fn a_nested_job_stops_at_the_depth_bound() {
        let nest = |n: usize| (0..n).fold(ScVal::U32(1), |v, _| vecv(vec![v]));
        let lane0 = stub_lane();
        let op = |n: usize| {
            let mut args = ua_relay_args(h_addr(WALLET2), &lane0);
            args[3] = vecv(vec![nest(n)]);
            ua_op(WALLET2, "ua_relay", args)
        };
        let p = RelayFeePolicy { executor: OnceLock::new(), ..policy() };
        let me = sc(&lane0);
        let deepest = (1..64).take_while(|n| job_tx(&network_id("x"), Some("ua_metatx"), &op(*n), &me, &p).is_ok()).last().unwrap();
        assert!((4..64).contains(&deepest), "{deepest}");
        let e = job_tx(&network_id("x"), Some("ua_metatx"), &op(deepest + 1), &me, &p).unwrap_err();
        assert!(format!("{e:#}").contains("nested"), "{e:#}");
        // an `op.auth` entry is in no call: it has the bound of its own
        let with_auth = |n: usize| {
            let mut o = op(1);
            o["auth"] = json!([{"payload": payload(inv(CONTRACT, "pay", vec![nest(n)], vec![])), "from": FROM, "signature": sig()}]);
            o
        };
        assert!(job_tx(&network_id("x"), Some("ua_metatx"), &with_auth(1), &me, &p).is_ok());
        let e = job_tx(&network_id("x"), Some("ua_metatx"), &with_auth(16), &me, &p).unwrap_err();
        assert!(format!("{e:#}").contains("nested"), "{e:#}");
        let answer: Answer = Arc::new(|c| match c.function_name.0.as_slice() {
            b"executor" => view_ok(ScVal::Address(executor())),
            _ => view_ok(ScVal::Void),
        });
        let (a, calls) = stub_adapter(answer, true).await;
        assert_eq!(job_step(&a, &calls, json!({"id": 7, "kind": "ua_metatx", "op": op(deepest)})).await.0, 1);
    }

    /// N2 review, the allow-list adapter: the registry listed as a token too, so that only the registry's own refusal can stop it.
    async fn allow_adapter() -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let answer: Answer = Arc::new(|c| match c.function_name.0.as_slice() {
            b"executor" => view_ok(ScVal::Address(executor())),
            _ => view_ok(ScVal::Void),
        });
        let url = rpc_stub(answer, calls.clone()).await;
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec![url], lanes: vec![0], ..Default::default() };
        c.tokens = [CONTRACT, REGISTRY].iter().map(|t| crate::config::TokenCfg { address: t.to_string(), decimals: 7 }).collect();
        c.params.insert("network_passphrase".into(), "x".into());
        c.params.insert("max_resource_fee_per_job".into(), 1_000_000_000.into());
        c.params.insert("mandate_wasm_hashes".into(), toml::Value::Array(vec![hex(&MANDATE_WASM).into()]));
        c.params.insert("ua_registry".into(), REGISTRY.into());
        c.params.insert("dex".into(), DEX.into());
        c.params.insert("mandates".into(), toml::Value::Array(vec![WALLET.into()]));
        let mut t = toml::Table::new();
        t.insert("router".into(), WALLET2.into());
        c.params.insert("relay_fee".into(), toml::Value::Table(t));
        let s = LocalSigner::Ed(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        (SorobanAdapter::new(&c, &[s]).unwrap(), calls)
    }

    /// Owner ruling 2026-11-02: a `signed_op` runs only on a known contract, never on the registry, whatever else lists it.
    #[tokio::test]
    async fn signed_op_allow_list() {
        let (a, calls) = allow_adapter().await;
        let job = |c: &str| json!({"id": 7, "kind": "signed_op", "op": {"payload": payload(inv(c, "work", vec![addr(FROM)], vec![])), "from": FROM, "signature": sig(),
                                   "contract": c, "valid_until": crate::submit::now() + 60, "extra": {}}});
        for c in [CONTRACT, WALLET, DEX, WALLET2] {
            let (sent, state, error) = job_step(&a, &calls, job(c)).await;
            assert_eq!((sent, state.as_str()), (1, "mined"), "{c}: {error}");
        }
        let unknown = executor().to_string();
        for (c, why) in [(unknown.as_str(), "unlisted"), (REGISTRY, "the registry")] {
            let (sent, state, error) = job_step(&a, &calls, job(c)).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "{why}: {error}");
            assert!(error.contains(CALL_TARGET_REFUSED), "{why}: {error}");
        }
        for bad in [toml::Value::Array(vec![FROM.into()]), WALLET.into()] {
            let mut c = ChainCfg::default();
            c.params.insert("mandates".into(), bad.clone());
            assert!(RelayFeePolicy::from_cfg(&c).is_err(), "{bad}: a list of contracts");
        }
    }

    /// Owner ruling 2026-11-02: a plain `signed_op` that is no token payment counts in the `call` share. At 50 % it is not claimed and
    /// the payment behind it runs; one with `op.kind` is a payment.
    #[tokio::test]
    async fn a_plain_signed_op_stops_at_the_call_share() {
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        let plain = |id: i64| signed_on(id, CONTRACT, "approve");
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2 - 1, 50), vec![plain(7), pay_of(&a, 8)]).await, (vec![7], 1), "one stroop under the share");
        assert_eq!(sends(&calls), 1);
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), vec![plain(7), pay_of(&a, 8)]).await, (vec![8], 1), "at the share: held, the payment runs");
        assert_eq!(sends(&calls), 2);
        let mut kindless = plain(9);
        kindless.as_object_mut().unwrap().remove("kind");
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), vec![kindless, pay_of(&a, 8)]).await, (vec![8], 1), "no job kind is a signed_op");
        let args = vec![addr(FROM), addr(WALLET), i128v(40), byt(&[1; 32]), byt(b"m"), ScVal::U64(VU)];
        let meta = json!({"id": 10, "kind": "signed_op", "op": {"kind": "pay_meta", "payload": payload(inv(CONTRACT, "pay_meta", args, vec![])), "from": FROM,
                          "signature": sig(), "contract": CONTRACT, "valid_until": VU, "salt": format!("0x{}", hex(&[1; 32])), "meta": "0x6d", "extra": {}}});
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), vec![meta]).await, (vec![10], 1), "a pay-meta is a payment");
    }

    /// A plain `signed_op`, `function` on `contract`, its deadline `VU`.
    fn signed_on(id: i64, contract: &str, function: &str) -> Value {
        json!({"id": id, "kind": "signed_op", "op": {"payload": payload(inv(contract, function, vec![addr(FROM), addr(WALLET), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": contract, "valid_until": crate::submit::now() + 600, "extra": {}}})
    }

    /// The owner's refinement of 2026-11-02: a plain `signed_op` whose root is a token payment runs to the whole budget. Its name on any
    /// other contract, any other function on a token, a job that does not parse, and a `call` job stay in the share.
    #[tokio::test]
    async fn a_token_payment_runs_to_the_budget() {
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        let held = || spent_lane(BUDGET / 2, 50);
        assert_eq!(budget_step(&a, &held(), vec![signed_on(7, CONTRACT, "approve"), signed_on(8, CONTRACT, "pay")]).await, (vec![8], 1), "the native pay runs, the other is held");
        assert_eq!(sends(&calls), 1);
        for (id, f) in [(9, "transfer"), (10, "pay_meta")] {
            assert_eq!(budget_step(&a, &held(), vec![signed_on(id, CONTRACT, f)]).await, (vec![id], 1), "{f}");
            assert_eq!(sends(&calls), id as usize - 7, "{f}");
        }
        assert_eq!(budget_step(&a, &spent_lane(BUDGET - 1, 50), vec![signed_on(11, CONTRACT, "pay")]).await, (vec![11], 1), "to the last stroop");
        assert_eq!(budget_step(&a, &spent_lane(BUDGET, 50), vec![signed_on(12, CONTRACT, "pay")]).await, (vec![], 0), "not past the budget");
        let sent = sends(&calls);

        let unlisted = executor().to_string();
        for (c, why) in [(unlisted.as_str(), "an unlisted contract"), (WALLET, "the mandate"), (DEX, "the DEX")] {
            assert_eq!(budget_step(&a, &held(), vec![signed_on(20, c, "pay")]).await, (vec![], 0), "a pay name on {why}");
        }
        for f in ["approve", "burn", "payment"] {
            assert_eq!(budget_step(&a, &held(), vec![signed_on(21, CONTRACT, f)]).await, (vec![], 0), "{f} on a token");
        }
        let mut broken = signed_on(22, CONTRACT, "pay");
        broken["op"]["signature"] = json!("zz");
        let mut no_args = signed_on(23, CONTRACT, "pay");
        no_args["op"]["payload"]["invocation"].as_object_mut().unwrap().remove("args");
        let mut hexed = signed_on(24, CONTRACT, "pay");
        hexed["op"]["payload"] = json!(PREIMAGE);
        let mut salted = signed_on(25, CONTRACT, "pay");
        salted["op"]["salt"] = json!("0x00");
        let call = json!({"id": 26, "kind": "call", "op": signed_on(26, CONTRACT, "pay")["op"]});
        for j in [broken, no_args, hexed, salted, call] {
            assert_eq!(budget_step(&a, &held(), vec![j.clone()]).await, (vec![], 0), "unparsable, or no plain signed_op: {j}");
        }
        // positive control: under the share each of the known ones goes on
        for (i, (id, c, f)) in [(30, WALLET, "pay"), (31, DEX, "pay"), (32, CONTRACT, "approve")].into_iter().enumerate() {
            assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2 - 1, 50), vec![signed_on(id, c, f)]).await, (vec![id], 1), "{c} {f}");
            assert_eq!(sends(&calls), sent + i + 1, "{c} {f}");
        }
    }

    /// `op.contract` naming another contract than the signed root: the read refuses it, so at the share it is held, and under the share
    /// `build` refuses it, `dead`, nothing sent. A job read as a payment that builds any other call is refused by name.
    #[tokio::test]
    async fn a_job_whose_root_and_built_call_differ_is_refused() {
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        let mut other = signed_on(7, CONTRACT, "pay");
        other["op"]["contract"] = json!(DEX);
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), vec![other.clone()]).await, (vec![], 0), "held: not read as a payment");
        let (sent, state, error) = job_step(&a, &calls, other).await;
        assert_eq!((sent, state.as_str()), (0, "dead"), "{error}");
        assert!(error.contains("its call is to"), "{error}");

        let (p, op) = (&a.relay_fee, signed_on(8, CONTRACT, "pay")["op"].clone());
        let (call, _) = host_call(&op).unwrap();
        assert!(runs_as_read(&op, &call, p).is_ok(), "the job's own root");
        for built in [InvokeContractArgs { function_name: ScSymbol("approve".try_into().unwrap()), ..call.clone() },
                      InvokeContractArgs { contract_address: sc(DEX), ..call.clone() },
                      InvokeContractArgs { args: vec![addr(FROM)].try_into().unwrap(), ..call.clone() }] {
            let e = runs_as_read(&op, &built, p).unwrap_err().to_string();
            assert!(e.contains(CALL_TARGET_REFUSED), "{e}");
        }
    }

    /// A `ua_metatx` needs no `op.valid_until`, so `recover_lane` reads the deadline from the built call: a job in flight across a
    /// restart is not `dead` at the first `Unknown` while its transaction may still land. The widest deadline a job can sign counts too.
    #[tokio::test]
    async fn restart_takes_a_ua_metatx_deadline_from_the_built_call() {
        use crate::adapter::tests::{fake_odoo, Fake};
        let (a, _, _) = spend_adapter(registry(vec![], vec![]), Net { tx: json!({"status": "NOT_FOUND"}), ..Net::default() }, false).await;
        for deadline in [crate::submit::now() + 600, u64::MAX] {
            let (c, f, mut args) = ua_ops(ScVal::Void).remove(1);
            args[4] = u64v(deadline);
            let inflight = json!([{"job_id": 8, "state": "signed", "tx_hash": "0x0a", "nonce": 123456, "payload": {"id": 8, "kind": "ua_metatx", "op": ua_op(c, f, args)}}]);
            let (odoo, o) = fake_odoo(Fake { inflight, tokens: json!([]), ..Default::default() }).await;
            tokio::time::timeout(std::time::Duration::from_secs(10), crate::adapter::recover_lane(a.as_ref(), &odoo, 0, "n#0")).await.expect("recovery hung").unwrap();
            let f = o.lock().unwrap();
            assert_eq!(f.reports.last().unwrap()["chain_state"], "queued", "{deadline}: {:?}", f.reports);
        }
    }

    /// Spec §9.1: token functions on a registered token, `ua_relay` on the router, `settle` / `ua_cancel` on
    /// `params.dex`, the mandate's `mtx_*` on any contract, naming a registered token; anything else, or the wrong arity, is refused.
    #[test]
    fn ua_metatx_allowlist() {
        let p = policy();
        for (contract, f, args) in ua_ops(ScVal::Void) {
            let ok = ua_metatx_job(&NET7, &ua_op(contract, f, args.clone()), &lane(), &p);
            assert!(ok.is_ok(), "{f}: {:#}", ok.err().unwrap());
            if contract != MANDATE {
                let e = ua_metatx_job(&NET7, &ua_op(WALLET, f, args.clone()), &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("not allowed"), "{f} on an unlisted contract: {e}");
            } else {
                assert!(ua_metatx_job(&NET7, &ua_op(WALLET, f, args.clone()), &lane(), &p).is_ok(), "{f}: any mandate");
            }
            let mut short = args.clone();
            short.pop();
            assert!(ua_metatx_job(&NET7, &ua_op(contract, f, short), &lane(), &p).is_err(), "{f}: arity");
        }
        assert!(ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)), &lane(), &p).is_ok());
        assert!(ua_metatx_job(&NET7, &ua_op(CONTRACT, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)), &lane(), &p).is_err());
        let no_dex = RelayFeePolicy { dex: None, ..policy() };
        let (_, _, settle) = ua_ops(ScVal::Void).pop().unwrap();
        assert!(ua_metatx_job(&NET7, &ua_op(DEX, "settle", settle), &lane(), &no_dex).is_err(), "no params.dex");
        for f in ["transfer", "pay", "ua_trade", "mint_to_ua", "transfer_to_ua", "mtx_execute", "relay", "cancel"] {
            let e = ua_metatx_job(&NET7, &ua_op(CONTRACT, f, vec![auth_arg()]), &lane(), &p).unwrap_err().to_string();
            assert!(e.contains("not a ua_metatx function"), "{f}: {e}");
        }
        // the 8-argument delegate forms with `epoch` (T6b); the old 7-argument mtx_mandate_pay is refused
        let pay = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == "mtx_mandate_pay").unwrap().2;
        assert_eq!(pay.len(), 8);
        let old: Vec<ScVal> = pay.iter().enumerate().filter(|(i, _)| *i != 4).map(|(_, v)| v.clone()).collect();
        assert!(ua_metatx_job(&NET7, &ua_op(MANDATE, "mtx_mandate_pay", old), &lane(), &p).is_err());
        // decision (C): the job kind is `job.kind`; a ua_metatx op carrying any `op.kind` is refused
        let (c, f, args) = ua_ops(ScVal::Void).remove(0);
        for k in [json!("relay_fee"), json!("pay_meta"), json!("ua_metatx"), json!(7), json!({})] {
            let mut o = ua_op(c, f, args.clone());
            o["kind"] = k.clone();
            assert!(ua_metatx_job(&NET7, &o, &lane(), &p).unwrap_err().to_string().contains("op.kind"), "{k}");
        }
        let mut o = ua_op(c, f, args);
        o["kind"] = Value::Null;
        assert!(ua_metatx_job(&NET7, &o, &lane(), &p).is_ok(), "null = absent");
    }

    /// S8 / §8: `relayer` is `None` (no lane authority) or this lane (one `SourceAccount` entry rooted at exactly the
    /// call); `ua_relay` and `settle` need this lane; anyone else is refused.
    #[test]
    fn ua_metatx_relayer_must_be_lane() {
        let p = policy();
        for (contract, f, args) in ua_ops(ScVal::Void) {
            let (call, auth, _) = ua_metatx_job(&NET7, &ua_op(contract, f, args), &lane(), &p).unwrap();
            let src = source_entries(&auth);
            if f == "settle" {
                assert_eq!(src.len(), 1, "both orders name this lane: one entry");
            } else {
                assert!(src.is_empty(), "{f}: relayer None lends nothing");
            }
            assert!(auth.len() == src.len(), "{f}: no subject entries without op.auth");
            let _ = call;
        }
        for (contract, f, args) in ua_ops(addr(LANE)) {
            if matches!(f, "ua_cancel_nonce" | "ua_cancel" | "settle") {
                continue; // no relayer argument
            }
            let (call, auth, _) = ua_metatx_job(&NET7, &ua_op(contract, f, args), &lane(), &p).unwrap();
            let src = source_entries(&auth);
            assert_eq!(src.len(), 1, "{f}");
            assert_eq!(src[0].root_invocation.function, SorobanAuthorizedFunction::ContractFn(call));
            assert!(src[0].root_invocation.sub_invocations.is_empty());
        }
        for other in [FROM, WALLET2, CONTRACT] {
            for (contract, f, args) in ua_ops(addr(other)) {
                if matches!(f, "ua_cancel_nonce" | "ua_cancel" | "settle") {
                    continue;
                }
                let e = ua_metatx_job(&NET7, &ua_op(contract, f, args), &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("relayer"), "{f} relayer {other}: {e}");
            }
        }
        let (call, auth, _) = ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)), &lane(), &p).unwrap();
        assert_eq!(source_entries(&auth).len(), 1);
        assert_eq!(auth[0].root_invocation.function, SorobanAuthorizedFunction::ContractFn(call));
        assert!(ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), FROM)), &lane(), &p).is_err());
        let foreign = vec![order(h_ua(UA), LANE, VU), order(h_addr(FROM), FROM, VU), i128v(5), auth_arg(), ua_sig(&[])];
        assert!(ua_metatx_job(&NET7, &ua_op(DEX, "settle", foreign), &lane(), &p).unwrap_err().to_string().contains("relayer"));
        // valid_until comes from the signed arguments (NET-SOR-15): settle's earlier order expiry
        let (_, _, settle) = ua_ops(ScVal::Void).pop().unwrap();
        let (call, _, _) = ua_metatx_job(&NET7, &ua_op(DEX, "settle", settle), &lane(), &p).unwrap();
        assert_eq!(ua_valid_until(&call).unwrap(), VU);
        // native legs: op.auth entries decoded as host_call does, nothing else
        let mut o = ua_op(CONTRACT, "ua_transfer", ua_ops(ScVal::Void).remove(0).2);
        o["auth"] = json!([{"payload": cross_payload(), "from": FROM, "signature": sig()}]);
        let (_, auth, _) = ua_metatx_job(&NET7, &o, &lane(), &p).unwrap();
        assert!(matches!(auth.as_slice(), [SorobanAuthorizationEntry { credentials: SorobanCredentials::Address(_), .. }]));
    }

    /// S14 / spec §8: a recorded `SourceAccount` entry not rooted at exactly the job's call fails the job before
    /// submission; the lane's own entry for the call, and subject entries, pass.
    #[test]
    fn ua_metatx_refuses_extra_source_account_auth() {
        let (call, auth, _) = ua_metatx_job(&NET7, &ua_op(CONTRACT, "ua_transfer", ua_ops(addr(LANE)).remove(0).2), &lane(), &policy()).unwrap();
        let b64 = |e: &SorobanAuthorizationEntry| json!(e.to_xdr_base64(Limits::none()).unwrap());
        let sim = |entries: Vec<Value>| json!({"results": [{"xdr": "AAAAAQ==", "auth": entries}]});
        assert!(check_recorded_auth(&sim(vec![b64(&auth[0])]), &call, &auth).is_ok(), "the lane's entry for the call");
        let subject = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials { address: sc(FROM), nonce: 1, signature_expiration_ledger: 9, signature: ScVal::Void }),
            root_invocation: inv(WALLET, "anything", vec![], vec![]),
        };
        assert!(check_recorded_auth(&sim(vec![b64(&auth[0]), b64(&subject)]), &call, &auth).is_ok(), "a subject entry is not the lane's");
        let elsewhere = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: inv(CONTRACT, "transfer", vec![addr(LANE), addr(FROM), i128v(1)], vec![]),
        };
        let e = check_recorded_auth(&sim(vec![b64(&auth[0]), b64(&elsewhere)]), &call, &auth).unwrap_err().to_string();
        assert!(e.contains("lane"), "{e}");
        let deeper = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call.clone()),
                sub_invocations: vec![inv(CONTRACT, "transfer", vec![addr(LANE)], vec![])].try_into().unwrap(),
            },
        };
        assert!(check_recorded_auth(&sim(vec![b64(&deeper)]), &call, &auth).is_err(), "the call plus a lent sub-invocation");
        assert!(check_recorded_auth(&sim(vec![json!("not xdr")]), &call, &auth).is_err(), "unreadable: fail closed");
        assert!(check_recorded_auth(&json!({"results": [{"xdr": "AAAAAQ=="}]}), &call, &auth).is_ok(), "nothing recorded");
    }

    /// `own` names only the lane's entries. A subject's `Address` entry has a root the client chose: it never makes a `SourceAccount`
    /// entry at that root the job's own, or a client could lend the lane's authority by placing the root. The word a relayer-mode
    /// job carries is the one `SourceAccount` root this widens to.
    #[test]
    fn recorded_auth_own_means_the_lanes_own() {
        let call = InvokeContractArgs { contract_address: sc(MANDATE), function_name: ScSymbol("register".try_into().unwrap()), args: vec![ScVal::U32(1), ScVal::U32(2)].try_into().unwrap() };
        let b64 = |e: &SorobanAuthorizationEntry| json!(e.to_xdr_base64(Limits::none()).unwrap());
        let sim = |e: &SorobanAuthorizationEntry| json!({"results": [{"xdr": "AAAAAQ==", "auth": [b64(e)]}]});
        let root = inv(WALLET, "anything", vec![], vec![]);
        let subject = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials { address: sc(FROM), nonce: 1, signature_expiration_ledger: 9, signature: ScVal::Void }),
            root_invocation: root.clone(),
        };
        let lent = SorobanAuthorizationEntry { credentials: SorobanCredentials::SourceAccount, root_invocation: root };
        let e = check_recorded_auth(&sim(&lent), &call, std::slice::from_ref(&subject)).unwrap_err().to_string();
        assert!(e.contains("lane"), "a subject's root is no lane entry: {e}");
        let d = attest_digest(&NET7, &call.contract_address, &call.function_name, &call.args).unwrap();
        let word = source_entry(&InvokeContractArgs { args: vec![byt(&d)].try_into().unwrap(), ..call.clone() });
        check_recorded_auth(&sim(&word), &call, std::slice::from_ref(&word)).unwrap();
        assert!(check_recorded_auth(&sim(&word), &call, &[]).is_err(), "only when it is this job's");
    }

    /// Final review A-I1 note (spec §8): a lane that is a `G…` member of an `msig` never lends that membership to a job.
    /// The entry the node attaches for `relayer = this lane` is root-only (the host, simulating in enforcing mode, then
    /// refuses the registry's nested `lane.require_auth_for_args((ua, purpose, digest))`), and a recorded lane entry
    /// carrying a `registry.require_authorized` sub-invocation fails the job before signing.
    #[test]
    fn ua_metatx_lane_entry_root_only_no_member_auth() {
        let p = policy();
        for (contract, f, args) in ua_ops(addr(LANE)) {
            if matches!(f, "ua_cancel_nonce" | "ua_cancel") {
                continue; // no relayer argument
            }
            let (call, auth, _) = ua_metatx_job(&NET7, &ua_op(contract, f, args), &lane(), &p).unwrap();
            let src = source_entries(&auth);
            assert_eq!(src.len(), 1, "{f}");
            assert!(src[0].root_invocation.sub_invocations.is_empty(), "{f}: root only");
            let member = SorobanAuthorizationEntry {
                credentials: SorobanCredentials::SourceAccount,
                root_invocation: SorobanAuthorizedInvocation {
                    function: SorobanAuthorizedFunction::ContractFn(call.clone()),
                    sub_invocations: vec![inv(CONTRACT, "require_authorized", vec![byt(&UA), byt(&[0x51; 32]), byt(&[0x52; 32])], vec![])]
                        .try_into()
                        .unwrap(),
                },
            };
            let sim = json!({"results": [{"xdr": "AAAAAQ==", "auth": [json!(member.to_xdr_base64(Limits::none()).unwrap())]}]});
            let e = check_recorded_auth(&sim, &call, &auth).unwrap_err().to_string();
            assert!(e.contains("lane"), "{f}: {e}");
        }
    }

    /// CTR-MTX-27: outside `ua_relay`, a UA pay to the router (or its executor) strands the coins: refused.
    #[test]
    fn pays_router_covers_ua_pay() {
        let p = policy();
        p.executor.set(executor()).unwrap();
        let ex = executor().to_string();
        for f in ["ua_pay", "ua_pay_meta", "ua_transfer"] {
            for to in [WALLET2, ex.as_str()] {
                let (contract, _, mut args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == f).unwrap();
                args[1] = h_addr(to);
                let call = InvokeContractArgs { contract_address: sc(contract), function_name: ScSymbol(f.try_into().unwrap()),
                                                args: args.clone().try_into().unwrap() };
                assert!(pays_router(&call, &p), "{f} to {to}");
                let e = ua_metatx_job(&NET7, &ua_op(contract, f, args), &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("router"), "{f} to {to}: {e}");
            }
        }
        // every other entry that pays or approves a holder: the mandate's payee / withdrawal `to` / delegate (final review
        // B-I1: a delegate equal to the executor lets anyone run `mtx_mandate_pay` through `relay`), settle's destinations
        for f in ["mtx_mandate_pay", "mtx_withdraw", "mtx_set_payee", "mtx_set_mandate"] {
            for to in [WALLET2, ex.as_str()] {
                let (contract, _, mut args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == f).unwrap();
                args[1] = h_addr(to);
                let e = ua_metatx_job(&NET7, &ua_op(contract, f, args.clone()), &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("router"), "{f} to {to}: {e}");
                if f == "mtx_set_payee" {
                    args[2] = ScVal::Bool(false);
                    assert!(ua_metatx_job(&NET7, &ua_op(contract, f, args), &lane(), &p).is_ok(), "withdrawing an approval");
                }
            }
        }
        let (contract, _, mut args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == "mtx_set_mandate").unwrap();
        args[1] = h_addr(LANE);
        assert!(ua_metatx_job(&NET7, &ua_op(contract, "mtx_set_mandate", args), &lane(), &p).is_ok(), "an ordinary delegate");
        for to in [WALLET2, ex.as_str()] {
            for i in 0..2 {
                let (_, _, mut args) = ua_ops(ScVal::Void).pop().unwrap();
                let ScVal::Map(Some(m)) = &mut args[i] else { panic!() };
                let mut v = m.0.to_vec();
                v.iter_mut().find(|e| e.key == sym("destination")).unwrap().val = h_addr(to);
                args[i] = ScVal::Map(Some(ScMap(v.try_into().unwrap())));
                let e = ua_metatx_job(&NET7, &ua_op(DEX, "settle", args), &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("router"), "settle order {i} to {to}: {e}");
            }
        }
        // ua_relay's open mode names the router as `to`: that is the relay, not a pay to it
        assert!(ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)), &lane(), &p).is_ok());
        assert!(ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(LANE), LANE)), &lane(), &p).is_ok(), "bound to the lane");
        let e = ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(&ex), LANE)), &lane(), &p).unwrap_err().to_string();
        assert!(e.contains("executor"), "{e}");
        let e = ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_ua(UA), LANE)), &lane(), &p).unwrap_err().to_string();
        assert!(e.contains("relay_bound_payee"), "a UA payee is bound to someone else: {e}");
        let e = ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)), &lane(), &RelayFeePolicy { tokens: vec![].into(), ..policy() })
            .unwrap_err().to_string();
        assert!(e.contains("token"), "{e}");
    }

    /// Router-fix review (carried to ua-soroban): anything approved to the executor is spendable by anyone through
    /// `relay` (the executor runs targets as itself), and an approval to the router strands like a pay. The node refuses
    /// `approve` naming either as spender (an `approve(…, 0, …)` withdraws: allowed) and `transfer_from` naming either
    /// as spender or `to`; for `relay` / `ua_relay` jobs it checks the relayed target call the same way.
    #[test]
    fn node_refuses_approvals_to_router_or_executor() {
        let p = policy();
        p.executor.set(executor()).unwrap();
        let ex = executor().to_string();
        let host = |f: &str, args: Vec<ScVal>| json!({"payload": payload(inv(CONTRACT, f, args, vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": crate::submit::now() + 600, "extra": {}});
        let approve = |x: &str, n: u64| vec![addr(FROM), addr(x), i128v(n), ScVal::U32(100)];
        let tf_spender = |x: &str| vec![addr(x), addr(FROM), addr(LANE), i128v(5)];
        let tf_to = |x: &str| vec![addr(LANE), addr(FROM), addr(x), i128v(5)];
        assert!(job_call(&NET7, &host("approve", approve(LANE, 5)), &lane(), &p).is_ok());
        assert!(job_call(&NET7, &host("transfer_from", tf_to(OWNER)), &lane(), &p).is_ok());
        for x in [WALLET2, ex.as_str()] {
            for (f, args) in [("approve", approve(x, 5)), ("transfer_from", tf_spender(x)), ("transfer_from", tf_to(x))] {
                let e = job_call(&NET7, &host(f, args.clone()), &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("router"), "{f} {x}: {e}");
                // relay_fee: the relayed target call
                let rf = relay_ref(&NET7, &sc(WALLET), &ScSymbol(f.try_into().unwrap()), &args, &SALT);
                let job = relay_job_args(&rf, &rf, sym(f), LANE, args.clone());
                let e = relay_fee_job(&NET7, &job, &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("router"), "relay {f} {x}: {e}");
                // ua_relay: the same
                let mut ua = ua_relay_args(h_addr(WALLET2), LANE);
                (ua[2], ua[3]) = (sym(f), vecv(args));
                let e = ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua), &lane(), &p).unwrap_err().to_string();
                assert!(e.contains("router"), "ua_relay {f} {x}: {e}");
            }
            assert!(job_call(&NET7, &host("approve", approve(x, 0)), &lane(), &p).is_ok(), "withdrawing an approval to {x}");
        }
        // the relayed target paying the router is refused too (the T8 attack shape: a victim's pay to the router)
        let args = vec![addr(FROM), addr(WALLET2), i128v(5), byt(&[3; 32]), u64v(VU)];
        let rf = relay_ref(&NET7, &sc(WALLET), &ScSymbol("pay".try_into().unwrap()), &args, &SALT);
        assert!(relay_fee_job(&NET7, &relay_job_args(&rf, &rf, sym("pay"), LANE, args), &lane(), &p).is_err());
        // an ordinary relayed call still passes
        let args = vec![addr(CONTRACT), addr(OWNER)];
        let rf = relay_ref(&NET7, &sc(WALLET), &ScSymbol("revoke".try_into().unwrap()), &args, &SALT);
        assert!(relay_fee_job(&NET7, &relay_job_args(&rf, &rf, sym("revoke"), LANE, args), &lane(), &p).is_ok());
    }

    /// Router-fix review (carried): a configured router without `executor()` (an old stateless router, or not the
    /// relay-fee contract at all) is a config error: the chain's Soroban jobs fail with it (`Revert`, the job goes
    /// `dead` with the reason), never `Transport` (requeued forever).
    #[tokio::test]
    async fn missing_executor_is_a_config_error() {
        let answers: [Answer; 2] = [
            Arc::new(|c| match c.function_name.0.as_slice() {
                b"executor" => json!({"error": "HostError: Error(WasmVm, MissingValue)\ntrying to invoke non-existent contract function"}),
                _ => json!({"error": "stop here"}),
            }),
            Arc::new(|c| match c.function_name.0.as_slice() {
                b"executor" => view_ok(ScVal::U32(7)),
                _ => json!({"error": "stop here"}),
            }),
        ];
        for answer in answers {
            let (a, _) = stub_adapter(answer, true).await;
            let (c, f, args) = ua_ops(ScVal::Void).remove(0);
            let e = a.build(&ua_job(c, f, args), 0).await.err().unwrap();
            assert!(matches!(&e, SimError::Revert(r) if r.contains("config") && r.contains("executor")), "{e:?}");
            assert!(a.relay_fee.executor.get().is_none());
        }
    }

    /// Decision (D): the router's executor is never a payee: plain `pay` / `pay_meta` and relay-fee jobs refuse it.
    #[test]
    fn relay_jobs_refuse_the_executor_as_payee() {
        let p = policy();
        p.executor.set(executor()).unwrap();
        let ex = executor().to_string();
        let pay = |to: &str| json!({"payload": payload(inv(CONTRACT, "pay", vec![addr(FROM), addr(to), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": crate::submit::now() + 600, "extra": {}});
        assert!(job_call(&NET7, &pay(WALLET), &lane(), &p).is_ok());
        assert!(job_call(&NET7, &pay(&ex), &lane(), &p).unwrap_err().to_string().contains("executor"));
        let r = meta_row();
        let (salt, meta) = (strip(&r["salt"]), strip(&r["meta"]));
        let mut pm = pay_meta_op(&salt, &meta, &salt, &meta);
        pm["kind"] = json!("pay_meta");
        assert!(job_call(&NET7, &pm, &lane(), &p).is_ok());
        let args = vec![addr(FROM), addr(&ex), i128v(40), byt(&salt), byt(&meta), ScVal::U64(VU)];
        pm["payload"] = json!(payload(inv(CONTRACT, "pay_meta", args, vec![])));
        assert!(job_call(&NET7, &pm, &lane(), &p).unwrap_err().to_string().contains("executor"));
        let a = vec![addr(CONTRACT), addr(OWNER)];
        let rf = relay_ref(&NET7, &sc(WALLET), &ScSymbol("revoke".try_into().unwrap()), &a, &SALT);
        let sponsored = RelayFeePolicy { params: crate::config::RelayParams { relay_bound_payee: true, ..rp(5) }, ..policy() };
        sponsored.executor.set(executor()).unwrap();
        assert!(relay_fee_job(&NET7, &relay_job_to(&rf, &rf, sym("revoke"), WALLET), &lane(), &sponsored).is_ok());
        let e = relay_fee_job(&NET7, &relay_job_to(&rf, &rf, sym("revoke"), &ex), &lane(), &sponsored).unwrap_err().to_string();
        assert!(e.contains("executor"), "{e}");
    }

    /// The node's job kinds (S15): `ua_metatx`, `call`, and `signed_op` / none for the native jobs; anything else is refused.
    #[test]
    fn soroban_unknown_job_kind_refused() {
        let p = policy();
        let pay = json!({"payload": payload(inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": crate::submit::now() + 600, "extra": {}});
        for k in [None, Some("signed_op")] {
            assert_eq!(Some(job_tx(&NET7, k, &pay, &lane(), &p).unwrap().2), pay["valid_until"].as_u64(), "{k:?}");
        }
        let (c, f, args) = ua_ops(ScVal::Void).remove(0);
        assert_eq!(job_tx(&NET7, Some("ua_metatx"), &ua_op(c, f, args), &lane(), &p).unwrap().2, VU);
        assert!(job_tx(&NET7, Some("ua_metatx"), &pay, &lane(), &p).is_err(), "a signed_op is not a ua_metatx");
        for k in ["metatx", "pay", "", "UA_METATX", "CALL"] {
            let e = job_tx(&NET7, Some(k), &pay, &lane(), &p).unwrap_err().to_string();
            assert!(e.contains("unknown job kind") && e.contains("call"), "{k}: {e}");
        }
        // `call` is a kind now, and a signed_op is not one
        let e = job_tx(&NET7, Some("call"), &pay, &lane(), &p).unwrap_err().to_string();
        assert!(!e.contains("unknown job kind"), "{e}");
    }

    fn data(resource_fee: i64, archived: &[u32]) -> String {
        let footprint = stellar_xdr::LedgerFootprint { read_only: Default::default(), read_write: Default::default() };
        let ext = if archived.is_empty() {
            stellar_xdr::SorobanTransactionDataExt::V0
        } else {
            stellar_xdr::SorobanTransactionDataExt::V1(stellar_xdr::SorobanResourcesExtV0 { archived_soroban_entries: archived.to_vec().try_into().unwrap() })
        };
        let d = SorobanTransactionData {
            ext,
            resources: stellar_xdr::SorobanResources { footprint, instructions: 1, disk_read_bytes: 0, write_bytes: 0 },
            resource_fee,
        };
        d.to_xdr_base64(Limits::none()).unwrap()
    }

    /// NET-SOR-11 (node half): a Protocol 23 simulation that restores archived entries is paid within
    /// `params.max_deposit_per_job` (stroops, the declared resource fee with its margin); over it, or with the cap absent
    /// (0), refused; a simulation without archived entries never needs the cap.
    #[test]
    fn auto_restore_within_deposit_cap() {
        let sim = |fee: i64, archived: &[u32]| json!({"transactionData": data(fee, archived), "results": [{"xdr": "AAAAAQ==", "auth": []}]});
        let d = sim_data(&sim(1_000, &[0, 2]), 1_150).unwrap();
        assert_eq!(d.resource_fee, 1_150, "15 % margin");
        let e = sim_data(&sim(1_000, &[0]), 1_149).unwrap_err();
        assert!(matches!(&e, SimError::Revert(r) if r.contains("restore over max_deposit_per_job")), "{e:?}");
        assert!(matches!(sim_data(&sim(1, &[0]), 0), Err(SimError::Revert(_))), "cap absent = no restore accepted");
        assert_eq!(sim_data(&sim(1_000, &[]), 0).unwrap().resource_fee, 1_150, "no archived entries");
        assert!(matches!(sim_data(&json!({"results": []}), 0), Err(SimError::Transport(_))), "no transactionData");
    }

    /// A legacy `restorePreamble` (an RPC before Protocol 23 auto-restore) stays a revert, whatever the cap.
    #[test]
    fn restore_preamble_still_reverts() {
        let sim = json!({"transactionData": data(10, &[]), "restorePreamble": {"transactionData": data(5, &[]), "minResourceFee": "5"}});
        assert!(matches!(sim_data(&sim, u64::MAX), Err(SimError::Revert(r)) if r.contains("archived")));
        let sim = json!({"transactionData": data(10, &[]), "restorePreamble": null});
        assert!(sim_data(&sim, 0).is_ok(), "a null preamble is none");
    }

    fn ev_of(contract: &str, topic: Vec<ScVal>, value: ScVal) -> Value {
        let x = |v: &ScVal| v.to_xdr_base64(Limits::none()).unwrap();
        json!({"ledger": 7, "contractId": contract, "txHash": "ab".repeat(32), "id": "1-3",
               "topic": topic.iter().map(x).collect::<Vec<_>>(), "value": x(&value)})
    }

    /// Spec §9.6: the UA ledger's events as the cross-family rows (a holder is its `G…` / `C…` strkey or the UA id
    /// `0x…`, as NEAR and Algorand): `UaTransfer` ⇒ `Transfer`, `UaPaymentSettled` ⇒ `PaymentSettled`,
    /// `UaMetaTransactionExecuted` ⇒ `MetaTransactionExecuted`; `UaNonceCancelled`, `UaRegistered` as themselves.
    #[test]
    fn decode_ua_events() {
        let ua = format!("0x{}", "77".repeat(32));
        let e = decode_event(&ev_of(CONTRACT, vec![sym("UaTransfer"), h_ua(UA), h_addr(FROM)], i128v(9))).unwrap();
        assert_eq!((e["event"].as_str(), e["from"].as_str(), e["to"].as_str(), e["amount"].as_str()), (Some("Transfer"), Some(ua.as_str()), Some(FROM), Some("9")));
        let e = decode_event(&ev_of(CONTRACT, vec![sym("UaPaymentSettled"), h_ua(UA), h_addr(WALLET)], vecv(vec![i128v(4), byt(&[5; 32])]))).unwrap();
        assert_eq!((e["event"].as_str(), e["from"].as_str(), e["to"].as_str(), e["amount"].as_str()), (Some("PaymentSettled"), Some(ua.as_str()), Some(WALLET), Some("4")));
        assert_eq!(e["entry_ref"], json!(format!("0x{}", "05".repeat(32))));
        let e = decode_event(&ev_of(CONTRACT, vec![sym("UaMetaTransactionExecuted"), byt(&UA)], byt(&[6; 32]))).unwrap();
        assert_eq!((e["event"].as_str(), e["from"].as_str()), (Some("MetaTransactionExecuted"), Some(ua.as_str())));
        assert_eq!(e["digest"], json!(format!("0x{}", "06".repeat(32))));
        let e = decode_event(&ev_of(CONTRACT, vec![sym("UaNonceCancelled"), byt(&UA), byt(&[1; 32])], u64v(3))).unwrap();
        assert_eq!((e["event"].as_str(), e["ua"].as_str(), e["nonce"].as_str()), (Some("UaNonceCancelled"), Some(ua.as_str()), Some("3")));
        assert_eq!(e["lane"], json!(format!("0x{}", "01".repeat(32))));
        let e = decode_event(&ev_of(CONTRACT, vec![sym("UaRegistered"), byt(&UA), ScVal::U32(0x0102)], vecv(vec![ScVal::Void, ScVal::Void]))).unwrap();
        assert_eq!((e["event"].as_str(), e["ua"].as_str(), e["kind"].as_u64()), (Some("UaRegistered"), Some(ua.as_str()), Some(0x0102)));
        // CTR-UA-33.A on Soroban: `key_data` empty when too large is the same row, the id being the topic
        let record = |d: &[u8]| vecv(vec![ScVal::Map(Some(ScMap(vec![ScMapEntry { key: sym("key_data"), val: byt(d) }].try_into().unwrap()))), ScVal::Void]);
        let [whole, emptied] = [record(&[7; 64]), record(&[])].map(|d| decode_event(&ev_of(CONTRACT, vec![sym("UaRegistered"), byt(&UA), ScVal::U32(0x0113)], d)).unwrap());
        assert_eq!(whole, emptied);
        // malformed holders and negative amounts decode to nothing
        assert!(decode_event(&ev_of(CONTRACT, vec![sym("UaTransfer"), vecv(vec![sym("Ua"), byt(&[1; 31])]), h_addr(FROM)], i128v(9))).is_none());
        assert!(decode_event(&ev_of(CONTRACT, vec![sym("UaTransfer"), vecv(vec![sym("Nope"), addr(FROM)]), h_addr(FROM)], i128v(9))).is_none());
        let neg = ScVal::I128(Int128Parts { hi: -1, lo: u64::MAX });
        assert!(decode_event(&ev_of(CONTRACT, vec![sym("UaTransfer"), h_ua(UA), h_addr(FROM)], neg)).is_none());
    }

    /// T8 made `RelayFeePaid`'s payer / payee `Holder`s: decoded as ids, a UA payer's fee joins its UA payment row.
    #[test]
    fn decode_relay_fee_paid_holder() {
        let ua = format!("0x{}", "77".repeat(32));
        let rf = [5u8; 32];
        let fee = ev_of(WALLET2, vec![sym("RelayFeePaid"), byt(&rf), addr(WALLET), addr(CONTRACT)], vecv(vec![h_ua(UA), h_addr(LANE), i128v(5)]));
        let e = decode_event(&fee).unwrap();
        assert_eq!((e["event"].as_str(), e["from"].as_str(), e["to"].as_str(), e["amount"].as_str()), (Some("RelayFeePaid"), Some(ua.as_str()), Some(LANE), Some("5")));
        assert_eq!((e["target"].as_str(), e["token"].as_str()), (Some(WALLET), Some(CONTRACT)));
        let old = ev_of(WALLET2, vec![sym("RelayFeePaid"), byt(&rf), addr(WALLET), addr(CONTRACT)], vecv(vec![addr(FROM), addr(LANE), i128v(5)]));
        assert!(decode_event(&old).is_none(), "the pre-T8 Address shape is not this router's");
        // open mode: the UA paid the router, which forwarded to the lane
        let mut paid = ev_of(CONTRACT, vec![sym("UaPaymentSettled"), h_ua(UA), h_addr(WALLET2)], vecv(vec![i128v(5), byt(&rf)]));
        paid["id"] = json!("1-2");
        let out = crate::indexer::join_pay_events([paid, fee].iter().filter_map(decode_event).collect());
        assert_eq!(out.len(), 1);
        assert_eq!((out[0]["relay_target"].as_str(), out[0]["relay_payee"].as_str()), (Some(WALLET), Some(LANE)));
    }

    // ---- a stub Soroban RPC: `simulateTransaction` answered per invoked function

    type Answer = Arc<dyn Fn(&InvokeContractArgs) -> Value + Send + Sync>;
    use std::sync::Arc;

    /// The quickstart's `tx_max_size_bytes`.
    const TX_MAX: u32 = 132_096;
    /// `errorResultXdr` as the real host answers a transaction over that limit (`e2e_ua8_tx_size_limit`, `EDGE`): `txSOROBAN_INVALID`,
    /// and under a fee bump `txFEE_BUMP_INNER_FAILED` around it.
    const ERROR_SOROBAN_INVALID: &str = "AAAAAAALbzj////vAAAAAA==";
    const ERROR_BUMP_SOROBAN_INVALID: &str = "AAAAAAALb5z////zWRfjyUlWVTv+F87wskTRYnPObfe1KCBhWRpVN3xSsFoAAAAAAAAAAP///+8AAAAAAAAAAA==";
    /// The quickstart's `contract_data_entry_size_bytes`.
    const ENTRY_MAX: u32 = 65_536;

    async fn rpc_stub(answer: Answer, calls: Arc<Mutex<Vec<String>>>) -> String {
        rpc_stub_limit(answer, calls, Arc::new(Mutex::new(Some(TX_MAX)))).await
    }

    /// `limit`: the bandwidth setting's `tx_max_size_bytes`, which `sendTransaction` also enforces; `None` = the RPC has no such
    /// entry. Shared, so a test can change the network's answer.
    async fn rpc_stub_limit(answer: Answer, calls: Arc<Mutex<Vec<String>>>, limit: Arc<Mutex<Option<u32>>>) -> String {
        rpc_stub_net(answer, calls, limit, Arc::new(Mutex::new(Net::default()))).await
    }

    /// The stub chain's answers beyond simulation.
    struct Net {
        /// `getTransaction`.
        tx: Value,
        /// `contract_data_entry_size_bytes`; `None` = the RPC has no such entry.
        entry_limit: Option<u32>,
        /// The accounts that exist, each `(public key, balance)`; `None` = every account, with no balance.
        accounts: Option<Vec<([u8; 32], i64)>>,
        /// `sendTransaction` answers `ERROR` with this `errorResultXdr`.
        refuses: Option<String>,
        /// `getLedgerEntries` answers a JSON body with no result.
        no_entries_result: bool,
        /// `getLedgerEntries` answers an entry with no `xdr`.
        bare_entry: bool,
        /// Every contract's executable; `None` = no instance entry.
        executable: Option<ContractExecutable>,
    }

    impl Default for Net {
        fn default() -> Self {
            Self { tx: json!({"status": "SUCCESS", "ledger": 5}), entry_limit: Some(ENTRY_MAX), accounts: None, refuses: None, no_entries_result: false, bare_entry: false, executable: Some(ContractExecutable::Wasm(Hash(MANDATE_WASM))) }
        }
    }

    async fn rpc_stub_net(answer: Answer, calls: Arc<Mutex<Vec<String>>>, limit: Arc<Mutex<Option<u32>>>, net: Arc<Mutex<Net>>) -> String {
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(b): axum::Json<Value>| {
            let (answer, calls, limit, net) = (answer.clone(), calls.clone(), limit.clone(), net.clone());
            async move {
                let limit = *limit.lock().unwrap();
                let lane_rpc = match b["method"].as_str() {
                    Some("sendTransaction") => {
                        calls.lock().unwrap().push("SEND".to_string());
                        // what core counts: the inner envelope of a fee bump
                        let env = match TransactionEnvelope::from_xdr_base64(b["params"]["transaction"].as_str().unwrap(), Limits::none()).unwrap() {
                            TransactionEnvelope::TxFeeBump(f) => {
                                let FeeBumpTransactionInnerTx::Tx(i) = f.tx.inner_tx;
                                TransactionEnvelope::Tx(i)
                            }
                            e => e,
                        };
                        let over = env.to_xdr(Limits::none()).unwrap().len() > limit.unwrap_or(TX_MAX) as usize;
                        let refused = net.lock().unwrap().refuses.clone().or(over.then(|| ERROR_SOROBAN_INVALID.to_string()));
                        Some(match refused {
                            Some(x) => json!({"status": "ERROR", "errorResultXdr": x}),
                            None => json!({"status": "PENDING"}),
                        })
                    }
                    Some("getLedgerEntries") => {
                        let net = net.lock().unwrap();
                        let mut entries = vec![];
                        for k in b["params"]["keys"].as_array().unwrap() {
                            match (LedgerKey::from_xdr_base64(k.as_str().unwrap(), Limits::none()).unwrap(), limit) {
                                (LedgerKey::ConfigSetting(c), _) if c.config_setting_id == ConfigSettingId::ContractDataEntrySizeBytes => {
                                    let e = net.entry_limit.map(|l| LedgerEntryData::ConfigSetting(ConfigSettingEntry::ContractDataEntrySizeBytes(l)));
                                    entries.extend(e.map(|e| e.to_xdr_base64(Limits::none()).unwrap()));
                                }
                                (LedgerKey::ConfigSetting(_), l) => entries.extend(l.map(bandwidth)),
                                (LedgerKey::ContractData(k), _) => entries.extend(net.executable.clone().map(|e| instance(&k.contract, e))),
                                (LedgerKey::Account(k), _) => {
                                    let AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk))) = k.account_id;
                                    match &net.accounts {
                                        None => entries.push(lane_account(0)),
                                        Some(l) => entries.extend(l.iter().find(|a| a.0 == pk).map(|a| lane_account(a.1))),
                                    }
                                }
                                _ => entries.push(lane_account(0)),
                            }
                        }
                        Some(if net.no_entries_result {
                            Value::Null
                        } else if net.bare_entry {
                            json!({"entries": [{}], "latestLedger": 5})
                        } else {
                            json!({"entries": entries.iter().map(|x| json!({"xdr": x})).collect::<Vec<_>>(), "latestLedger": 5})
                        })
                    }
                    Some("getTransaction") => Some(net.lock().unwrap().tx.clone()),
                    _ => None,
                };
                if let Some(r) = lane_rpc {
                    return axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": r}));
                }
                let env = TransactionEnvelope::from_xdr_base64(b["params"]["transaction"].as_str().unwrap(), Limits::none()).unwrap();
                let TransactionEnvelope::Tx(t) = env else { panic!() };
                let OperationBody::InvokeHostFunction(op) = &t.tx.operations[0].body else { panic!() };
                let HostFunction::InvokeContract(c) = &op.host_function else { panic!() };
                calls.lock().unwrap().push(String::from_utf8_lossy(c.function_name.0.as_slice()).into_owned());
                axum::Json(json!({"jsonrpc": "2.0", "id": 1, "result": answer(c)}))
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    /// A contract's instance entry, as `getLedgerEntries` answers it.
    fn instance(contract: &ScAddress, executable: ContractExecutable) -> String {
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: stellar_xdr::ExtensionPoint::V0,
            contract: contract.clone(),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(stellar_xdr::ScContractInstance { executable, storage: None }),
        }).to_xdr_base64(Limits::none()).unwrap()
    }

    /// `tx_max_size_bytes`'s answer.
    fn bandwidth(tx_max_size_bytes: u32) -> String {
        let b = stellar_xdr::ConfigSettingContractBandwidthV0 { ledger_max_txs_size_bytes: 1 << 20, tx_max_size_bytes, fee_tx_size1_kb: 1 };
        LedgerEntryData::ConfigSetting(stellar_xdr::ConfigSettingEntry::ContractBandwidthV0(b)).to_xdr_base64(Limits::none()).unwrap()
    }

    /// `adapter.sequence`'s answer.
    fn lane_account(balance: i64) -> String {
        LedgerEntryData::Account(stellar_xdr::AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1; 32]))),
            balance,
            seq_num: SequenceNumber(4),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: Default::default(),
            thresholds: stellar_xdr::Thresholds([1, 0, 0, 0]),
            signers: Default::default(),
            ext: stellar_xdr::AccountEntryExt::V0,
        }).to_xdr_base64(Limits::none()).unwrap()
    }

    fn view_ok(v: ScVal) -> Value {
        json!({"results": [{"xdr": v.to_xdr_base64(Limits::none()).unwrap(), "auth": []}], "transactionData": data(100, &[])})
    }
    fn view_archived(v: ScVal) -> Value {
        json!({"results": [{"xdr": v.to_xdr_base64(Limits::none()).unwrap(), "auth": []}], "transactionData": data(100, &[1])})
    }

    async fn stub_adapter(answer: Answer, router: bool) -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        stub_adapter_limit(answer, router, Arc::new(Mutex::new(Some(TX_MAX)))).await
    }

    async fn stub_adapter_limit(answer: Answer, router: bool, limit: Arc<Mutex<Option<u32>>>) -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let url = rpc_stub_limit(answer, calls.clone(), limit).await;
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec![url], lanes: vec![0], ..Default::default() };
        c.tokens = vec![crate::config::TokenCfg { address: CONTRACT.into(), decimals: 7 }];
        c.params.insert("network_passphrase".into(), "x".into());
        c.params.insert("max_resource_fee_per_job".into(), 1_000_000_000.into());
        c.params.insert("mandate_wasm_hashes".into(), toml::Value::Array(vec![hex(&MANDATE_WASM).into()]));
        if router {
            let mut t = toml::Table::new();
            t.insert("router".into(), WALLET2.into());
            c.params.insert("relay_fee".into(), toml::Value::Table(t));
        }
        let s = LocalSigner::Ed(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        (SorobanAdapter::new(&c, &[s]).unwrap(), calls)
    }

    fn ua_job(contract: &str, f: &str, args: Vec<ScVal>) -> Job {
        serde_json::from_value(json!({"id": 7, "kind": "ua_metatx", "op": ua_op(contract, f, args)})).unwrap()
    }

    /// R80 for lane entries: `ua_nonce(ua, lane) > nonce` on the token (or on the mandate, for the mandate's UA
    /// owner read by `owner()`); a view that needs a restore is unknown, never "not consumed"; no lane = unknown.
    #[tokio::test]
    async fn op_consumed_ua_lane() {
        let next = Arc::new(Mutex::new(3u64));
        let n2 = next.clone();
        let answer: Answer = Arc::new(move |c| {
            let at_mandate = c.contract_address == sc(MANDATE);
            match c.function_name.0.as_slice() {
                b"ua_nonce" => {
                    assert_eq!((c.args[0].clone(), c.args[1].clone()), (byt(&UA), byt(&[1; 32])));
                    let n = *n2.lock().unwrap();
                    if n == 99 { view_archived(u64v(0)) } else { view_ok(u64v(n + at_mandate as u64)) }
                }
                b"owner" => view_ok(h_ua(UA)),
                f => panic!("{}", String::from_utf8_lossy(f)),
            }
        });
        let (a, calls) = stub_adapter(answer, false).await;
        let ops = ua_ops(ScVal::Void);
        let job = |f: &str, nonce: u64| {
            let (c, f, mut args) = ops.iter().find(|o| o.1 == f).cloned().unwrap();
            let i = args.iter().position(|v| *v == byt(&[1; 32])).unwrap() + 1;
            args[i] = u64v(nonce);
            ua_job(c, f, args)
        };
        for f in ["ua_transfer", "ua_burn"] {
            assert_eq!(a.op_consumed(&job(f, 3)).await.unwrap(), Some(false), "{f}: next nonce 3");
            assert_eq!(a.op_consumed(&job(f, 2)).await.unwrap(), Some(true), "{f}: 2 spent");
        }
        assert_eq!(a.op_consumed(&job("mtx_revoke", 3)).await.unwrap(), Some(true), "mandate lane at 4, by = the UA");
        assert_eq!(a.op_consumed(&job("mtx_set_payee", 4)).await.unwrap(), Some(false), "owner() is the UA");
        *next.lock().unwrap() = 99;
        assert_eq!(a.op_consumed(&job("ua_transfer", 0)).await.unwrap(), None, "archived lane: unknown");
        // no lane of the UA: a native `by`, cancels, DEX legs, signed_op
        let (c, f, mut args) = ops.iter().find(|o| o.1 == "mtx_revoke").cloned().unwrap();
        args[1] = h_addr(FROM);
        assert_eq!(a.op_consumed(&ua_job(c, f, args)).await.unwrap(), None);
        for f in ["ua_cancel_nonce", "ua_cancel", "settle"] {
            let (c, f, args) = ops.iter().find(|o| o.1 == f).cloned().unwrap();
            assert_eq!(a.op_consumed(&ua_job(c, f, args)).await.unwrap(), None, "{f}");
        }
        let signed: Job = serde_json::from_value(json!({"id": 7, "kind": "signed_op", "op": {}})).unwrap();
        assert_eq!(a.op_consumed(&signed).await.unwrap(), None);
        assert!(!calls.lock().unwrap().is_empty());
    }

    /// R80 for pay refs: `ua_ref_used(ua, pay_ref)` (`ua_pay_meta`: `metaPayId(salt, meta)`; `ua_relay`: the relay
    /// `ref` on the fee token) and the mandate's `paid(pay_ref)` for `mtx_mandate_pay`.
    #[tokio::test]
    async fn op_consumed_ua_pay_ref() {
        let used = Arc::new(Mutex::new(Vec::<(String, ScVal)>::new()));
        let u2 = used.clone();
        let answer: Answer = Arc::new(move |c| {
            let f = String::from_utf8_lossy(c.function_name.0.as_slice()).into_owned();
            let r = match f.as_str() {
                "ua_ref_used" => {
                    assert_eq!(c.args[0], byt(&UA));
                    c.args[1].clone()
                }
                "paid" => c.args[0].clone(),
                _ => panic!("{f}"),
            };
            let hit = u2.lock().unwrap().iter().any(|(g, x)| *g == f && *x == r);
            view_ok(ScVal::Bool(hit))
        });
        let (a, _) = stub_adapter(answer, true).await;
        let ops = ua_ops(ScVal::Void);
        let job = |f: &str| {
            let (c, f, args) = ops.iter().find(|o| o.1 == f).cloned().unwrap();
            ua_job(c, f, args)
        };
        let relay = ua_job(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE));
        for j in [job("ua_pay"), job("ua_pay_meta"), job("mtx_mandate_pay"), relay.clone()] {
            assert_eq!(a.op_consumed(&j).await.unwrap(), Some(false));
        }
        let rf = relay_ref(&a.network_id, &sc(WALLET), &ScSymbol("revoke".try_into().unwrap()), &[addr(CONTRACT)], &SALT);
        used.lock().unwrap().extend([
            ("ua_ref_used".to_string(), byt(&[3; 32])),
            ("ua_ref_used".to_string(), byt(&meta_pay_id(&[4; 32], b"m"))),
            ("paid".to_string(), byt(&[3; 32])),
            ("ua_ref_used".to_string(), byt(&rf)),
        ]);
        for j in [job("ua_pay"), job("ua_pay_meta"), job("mtx_mandate_pay"), relay] {
            assert_eq!(a.op_consumed(&j).await.unwrap(), Some(true), "{:?}", j.op);
        }
        // the guard's allow-list: a job it refuses is never reported consumed
        let (_, _, pay) = ops.iter().find(|o| o.1 == "ua_pay").cloned().unwrap();
        assert_eq!(a.op_consumed(&ua_job(WALLET, "ua_pay", pay)).await.unwrap(), None, "unlisted token");
        let mut other_token = ua_relay_args(h_addr(WALLET2), LANE);
        other_token[5] = addr(WALLET);
        assert_eq!(a.op_consumed(&ua_job(WALLET2, "ua_relay", other_token)).await.unwrap(), None, "unregistered fee token");
        assert_eq!(a.op_consumed(&ua_job(CONTRACT, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE))).await.unwrap(), None, "not the router");
    }

    /// CTR-ACC-07: a delegate job refused `StaleEpoch` (mandate error #13) names the current `epoch(token)`, re-read
    /// by the node, so the client re-signs; another #13-free error stays as the RPC gave it.
    #[tokio::test]
    async fn stale_epoch_names_the_current_epoch() {
        let answer: Answer = Arc::new(|c| match c.function_name.0.as_slice() {
            b"epoch" => view_ok(u64v(2)),
            b"mtx_mandate_pay" | b"mtx_revoke" => json!({"error": "HostError: Error(Contract, #13)"}),
            _ => json!({"error": "HostError: Error(Contract, #6)"}),
        });
        let (a, calls) = stub_adapter(answer, false).await;
        for f in ["mtx_mandate_pay", "mtx_revoke"] {
            let (c, f, args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == f).unwrap();
            let e = a.build(&ua_job(c, f, args), 0).await.err().unwrap();
            assert!(matches!(&e, SimError::Revert(r) if r.contains("StaleEpoch") && r.contains("signed 1") && r.contains("epoch(token) 2")), "{f}: {e:?}");
        }
        let (c, f, args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == "mtx_withdraw").unwrap();
        let e = a.build(&ua_job(c, f, args), 0).await.err().unwrap();
        assert!(matches!(&e, SimError::Revert(r) if r.contains("#6") && !r.contains("StaleEpoch")), "{e:?}");
        assert_eq!(calls.lock().unwrap().iter().filter(|c| *c == "epoch").count(), 2);
    }

    /// Decision (D): the router's `executor()` is read once (first build), then every job is checked against it.
    #[tokio::test]
    async fn executor_is_read_once() {
        let answer: Answer = Arc::new(|c| match c.function_name.0.as_slice() {
            b"executor" => view_ok(ScVal::Address(executor())),
            _ => json!({"error": "stop here"}),
        });
        let (a, calls) = stub_adapter(answer, true).await;
        let (c, f, args) = ua_ops(ScVal::Void).remove(0);
        for _ in 0..2 {
            assert!(a.build(&ua_job(c, f, args.clone()), 0).await.is_err());
        }
        assert_eq!(a.relay_fee.executor.get(), Some(&executor()));
        assert_eq!(calls.lock().unwrap().iter().filter(|c| *c == "executor").count(), 1);
        let mut to_ex = args.clone();
        to_ex[1] = holder_addr(&executor());
        let e = a.build(&ua_job(c, f, to_ex), 0).await.err().unwrap();
        assert!(matches!(&e, SimError::Revert(r) if r.contains("router")), "{e:?}");
    }

    // ---- ua8-soroban B6: `call` jobs for the registry writes, the relayer pre-check (UA8-D23)

    use pqcrypto_falcon::falconpadded512 as falcon;
    use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
    use scaas_ua::{encode_msig, UAError};

    const REGISTRY: &str = MANDATE;
    const NONE: Value = Value::Null;

    fn h(b: &[u8]) -> String {
        format!("0x{}", hex(b))
    }
    fn portable() -> &'static Value {
        static P: OnceLock<Value> = OnceLock::new();
        P.get_or_init(|| serde_json::from_str(include_str!("../../../smartcontracts/vectors/ua/portable.json")).unwrap())
    }
    fn row(list: &str, name: &str) -> &'static Value {
        portable()[list].as_array().unwrap().iter().find(|r| r["name"] == name || r["id"] == name).unwrap()
    }
    /// portable.json's `args` (camelCase, with `entry`) as the job's named fields; a slot `{index, members, sig}` in this family's flat form.
    fn snake(v: &Value) -> Value {
        match v {
            Value::Object(m) if m.contains_key("index") && m.contains_key("sig") => json!({"index": m["index"], "key_data": "0x", "sig": m["sig"]}),
            Value::Object(m) => {
                let name = |k: &str| k.chars().flat_map(|c| if c.is_ascii_uppercase() { vec!['_', c.to_ascii_lowercase()] } else { vec![c] }).collect();
                Value::Object(m.iter().filter(|(k, _)| *k != "entry").map(|(k, x)| (name(k), snake(x))).collect())
            }
            Value::Array(a) => a.iter().map(snake).collect(),
            x => x.clone(),
        }
    }
    fn call_op(function: &str, args: Value) -> Value {
        json!({"contract": REGISTRY, "function": function, "args": args, "valid_until": crate::submit::now() + 600})
    }
    /// A `kemRecords` / `pqzKeyRecords` row as its job.
    fn rec_op(f: &str, r: &Value, relayer: &Value) -> Value {
        let mut a = snake(&r["args"]);
        a["relayer"] = relayer.clone();
        call_op(f, a)
    }
    fn reg_op(r: &Value, relayer: &Value) -> Value {
        let f = if r["args"]["entry"] == "registerMsig" { "register_msig" } else { "register" };
        rec_op(f, r, relayer)
    }
    /// One byte of a `0x…` field flipped.
    fn flip(v: &mut Value) {
        let mut b = strip(v);
        let i = b.len() / 2;
        b[i] ^= 1;
        *v = json!(h(&b));
    }
    /// One well-formed job per allow-listed function (S15, UA8-D23), `relayer` as given (`store_pqz_pop` has none).
    fn ops(relayer: &Value) -> Vec<Value> {
        let z = h(&[0; 32]);
        let attrs = json!({"pqz_key": "0x", "pqz_pop_hash": z, "kem": {"scheme": 0, "mlkem_ek": "0x", "x25519": z}, "kem_pk_hash": z});
        let sig = json!({"key_data": "0x", "signature": "0xab", "members": [{"index": 0, "key_data": "0x", "sig": "0xcd"}]});
        let msig = json!({"threshold": 1, "members": [{"kind": 0x0102, "id": h(&[2; 32]), "weight": 1}]});
        let web = json!({"x": h(&[1; 32]), "y": h(&[2; 32]), "rp_id_hash": h(&[3; 32])});
        let musig = json!({"agg_key": h(&[2; 33]), "member_keys": [h(&[3; 33]), h(&[4; 33])]});
        let frost = json!({"group_key": h(&[2; 33]), "threshold": 2, "members": [{"commitments": [h(&[3; 33]), h(&[4; 33])], "r": h(&[5; 33]), "z": h(&[6; 32])}]});
        let kem = json!({"scheme": 1, "mlkem_ek": h(&[7; 1568]), "x25519": h(&[8; 32])});
        vec![
            call_op("register", json!({"kind": 0x0102, "key_data": h(&[1; 32]), "attrs": attrs, "pop": "0xab", "pqz_pop": "0x", "relayer": relayer})),
            call_op("register_msig", json!({"structure": msig, "attrs": attrs, "pop": sig["members"], "pqz_pop": "0x", "relayer": relayer})),
            call_op("register_webauthn", json!({"key": web, "attrs": attrs, "pop": "0xab", "pqz_pop": "0x", "relayer": relayer})),
            call_op("register_musig2", json!({"kind": 0x0110, "key": musig, "attrs": attrs, "pop": "0xab", "pqz_pop": "0x", "relayer": relayer})),
            call_op("register_frost", json!({"kind": 0x0111, "key": frost, "attrs": attrs, "pop": "0xab", "pqz_pop": "0x", "relayer": relayer})),
            call_op("set_kem_key", json!({"ua": h(&UA), "version": 1, "kem": kem, "sig": sig, "relayer": relayer})),
            call_op("set_pqz_key", json!({"ua": h(&UA), "pqz_key": h(&[9; 16_384]), "pqz_pop_hash": h(&[1; 32]), "sig": sig, "relayer": relayer})),
            call_op("store_pqz_pop", json!({"ua": h(&UA), "pqz_pop": "0xab"})),
        ]
    }
    fn job_of(op: &Value) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
        ua8_call_job(&NET7, op, &lane(), &sc(REGISTRY), true)
    }

    /// The registry only: the job's `contract` is `params.ua_registry`; one field from a passing job.
    #[test]
    fn soroban_call_job_registry_only() {
        let op = ops(&NONE).remove(7);
        assert_eq!(job_of(&op).unwrap().0.contract_address, sc(REGISTRY));
        for other in [CONTRACT, WALLET, DEX, FROM, "nope"] {
            let mut o = op.clone();
            o["contract"] = json!(other);
            let e = job_of(&o).unwrap_err().to_string();
            assert!(e.contains("ua_registry"), "{other}: {e}");
        }
    }

    /// The eight functions and nothing else; every field of each is required, no other is taken.
    #[test]
    fn soroban_call_job_function_allowlist() {
        let names = ["register", "register_msig", "register_webauthn", "register_musig2", "register_frost", "set_kem_key", "set_pqz_key", "store_pqz_pop"];
        let good = ops(&NONE);
        assert_eq!(good.iter().map(|o| job_of(o).unwrap().0.function_name.0.to_string()).collect::<Vec<_>>(), names);
        for f in ["relay", "ua_transfer", "require_authorized", "transfer", "__constructor", "registerMsig", ""] {
            let mut o = good[0].clone();
            o["function"] = json!(f);
            let e = job_of(&o).unwrap_err().to_string();
            assert!(e.contains("not a registry write"), "{f}: {e}");
        }
        for o in &good {
            let f = o["function"].clone();
            for k in o["args"].as_object().unwrap().keys() {
                let mut gone = o.clone();
                gone["args"].as_object_mut().unwrap().remove(k);
                let e = job_of(&gone).unwrap_err().to_string();
                assert!(e.contains("missing"), "{f} without {k}: {e}");
            }
            let mut more = o.clone();
            more["args"]["signature"] = json!("0xab");
            let e = job_of(&more).unwrap_err().to_string();
            assert!(e.contains("unknown field"), "{f}: {e}");
        }
        for (path, k) in [(&["args", "attrs"][..], "kem_commit"), (&["args", "attrs", "kem"][..], "pk"), (&["args", "structure"][..], "t")] {
            let mut o = good[1].clone();
            path.iter().fold(&mut o, |v, p| &mut v[*p])[k] = json!(1);
            let e = job_of(&o).unwrap_err().to_string();
            assert!(e.contains("unknown field"), "{k}: {e}");
        }
        // an opaque blob is not a field: `args` stays named, and a number stays in the contract's range
        let mut o = good[0].clone();
        o["args"] = json!("0xab");
        assert!(job_of(&o).is_err());
        o = good[0].clone();
        o["args"]["kind"] = json!(0x1_0000);
        assert!(job_of(&o).is_err(), "kind is a u16 in the key's id");
    }

    /// The contract's typed shapes, field for field: a `#[contracttype]` struct is a map sorted by field name.
    #[test]
    fn soroban_call_job_builds_the_contract_shapes() {
        fn keys(v: &ScVal) -> Vec<String> {
            let ScVal::Map(Some(m)) = v else { panic!("{v:?}") };
            m.iter().map(|e| scval_str(&e.key).unwrap()).collect()
        }
        fn seq(v: &ScVal) -> &[ScVal] {
            let ScVal::Vec(Some(s)) = v else { panic!("{v:?}") };
            s.as_slice()
        }
        let got: Vec<Vec<ScVal>> = ops(&NONE).iter().map(|o| job_of(o).unwrap().0.args.to_vec()).collect();
        assert_eq!(got.iter().map(Vec::len).collect::<Vec<_>>(), [6, 5, 5, 6, 6, 5, 5, 2], "the contract's arities");
        let attrs = field(&got[0][2], "kem").unwrap();
        assert_eq!(keys(&got[0][2]), ["kem", "kem_pk_hash", "pqz_key", "pqz_pop_hash"]);
        assert_eq!(keys(attrs), ["mlkem_ek", "scheme", "x25519"]);
        assert_eq!(field(attrs, "scheme"), Some(&ScVal::U32(0)));
        assert_eq!(got[0][0], ScVal::U32(0x0102));
        assert_eq!(got[0][1], byt(&[1; 32]));
        assert_eq!((&got[0][3], &got[0][4], &got[0][5]), (&byt(&[0xab]), &byt(&[]), &ScVal::Void));
        assert_eq!(keys(&got[1][0]), ["members", "threshold"]);
        assert_eq!(keys(&seq(field(&got[1][0], "members").unwrap())[0]), ["id", "kind", "weight"]);
        assert_eq!(keys(&seq(&got[1][2])[0]), ["index", "key_data", "sig"]);
        assert_eq!(field(&seq(&got[1][2])[0], "index"), Some(&ScVal::U32(0)));
        assert_eq!(keys(&got[2][0]), ["rp_id_hash", "x", "y"]);
        assert_eq!(got[3][0], ScVal::U32(0x0110));
        assert_eq!(keys(&got[3][1]), ["agg_key", "member_keys"]);
        assert_eq!(seq(field(&got[3][1], "member_keys").unwrap()), [byt(&[3; 33]), byt(&[4; 33])]);
        assert_eq!(keys(&got[4][1]), ["group_key", "members", "threshold"]);
        assert_eq!(keys(&seq(field(&got[4][1], "members").unwrap())[0]), ["commitments", "r", "z"]);
        assert_eq!((&got[5][0], &got[5][1]), (&byt(&UA), &u64v(1)));
        assert_eq!(keys(&got[5][3]), ["key_data", "members", "signature"]);
        assert_eq!((&got[6][1], &got[6][2]), (&byt(&[9; 16_384]), &byt(&[1; 32])));
        assert_eq!(got[7], [byt(&UA), byt(&[0xab])]);
    }

    /// No auth entries from the job: a job naming any is refused, one without has none but the lane's own.
    #[test]
    fn soroban_call_job_has_no_job_auth_entries() {
        for o in ops(&NONE) {
            assert_eq!(job_of(&o).unwrap().1.len(), 0, "{}", o["function"]);
            for (k, v) in [("auth", json!([{"payload": PREIMAGE, "from": FROM, "signature": sig()}])), ("extra", json!({"auth": []})), ("payload", json!(PREIMAGE))] {
                let mut bad = o.clone();
                bad[k] = v;
                let e = job_of(&bad).unwrap_err().to_string();
                assert!(e.contains("unknown field"), "{k}: {e}");
            }
        }
    }

    /// `ua8_attest_digest_vector`'s bytes, built outside Rust (`scripts/attest-digest-vector.py`): what the contract and the
    /// node must both answer.
    #[test]
    fn attest_digest_vector() {
        let (net, c, sym) = ([0x11; 32], sc(CONTRACT), |s: &str| ScSymbol(s.try_into().unwrap()));
        let args = [ScVal::U32(7), byt(&[1, 2]), ScVal::Void];
        assert_eq!(hex(&attest_digest(&net, &c, &sym("register"), &args).unwrap()), "10c27d0f11b12ccc54ceeff725eea285795a0ea2d18bb5320b95c1c9e6e95b92");
        assert_eq!(hex(&attest_digest(&net, &c, &sym("set_kem_key"), &args).unwrap()), "2da85a452358a70d013d2dbe4fd4136bec2234b25380f7f222fcfff6c712aa53");
    }

    /// `relayer` is `None` or this lane; `Some(lane)` adds exactly one `SourceAccount` entry, on the call's function, over the
    /// one word `attest` asks for.
    #[test]
    fn relayer_arg_is_the_lane() {
        for o in ops(&json!(LANE)) {
            let (call, auth) = job_of(&o).unwrap();
            if call.function_name.0.as_slice() == b"store_pqz_pop" {
                assert!(auth.is_empty(), "no relayer argument");
                continue;
            }
            assert_eq!(auth.len(), 1, "{}", o["function"]);
            assert!(matches!(auth[0].credentials, SorobanCredentials::SourceAccount));
            let SorobanAuthorizedFunction::ContractFn(f) = &auth[0].root_invocation.function else { panic!() };
            assert_eq!((&f.contract_address, &f.function_name), (&call.contract_address, &call.function_name));
            let d = attest_digest(&NET7, &call.contract_address, &call.function_name, &call.args).unwrap();
            assert_eq!(f.args.as_slice(), [byt(&d)], "one word, not the arguments again");
            assert!(auth[0].root_invocation.sub_invocations.is_empty());
            assert_eq!(call.args.last(), Some(&addr(LANE)));
        }
        for other in [FROM, WALLET] {
            for o in ops(&json!(other)).into_iter().take(7) {
                let e = job_of(&o).unwrap_err().to_string();
                assert!(e.contains("None or this lane"), "{}: {e}", o["function"]);
            }
        }
        let mut bad = ops(&json!(LANE)).remove(0);
        bad["args"]["relayer"] = json!(7);
        assert!(job_of(&bad).is_err(), "a relayer is an address or null");
    }

    /// `call` needs `params.ua_registry` (a contract), and a deadline; unset, nothing is relayed.
    #[test]
    fn ua_registry_param_required_for_call() {
        let op = ops(&NONE).remove(7);
        let e = job_tx(&NET7, Some("call"), &op, &lane(), &policy()).unwrap_err().to_string();
        assert!(e.contains("ua_registry"), "{e}");
        let p = RelayFeePolicy { ua_registry: Some(sc(REGISTRY)), ..policy() };
        assert_eq!(Some(job_tx(&NET7, Some("call"), &op, &lane(), &p).unwrap().2), op["valid_until"].as_u64());
        let mut late = op.clone();
        late.as_object_mut().unwrap().remove("valid_until");
        assert!(job_tx(&NET7, Some("call"), &late, &lane(), &p).unwrap_err().to_string().contains("valid_until"));
        let cfg = |v: Option<&str>| {
            let mut c = ChainCfg { family: "soroban".into(), ..Default::default() };
            if let Some(v) = v {
                c.params.insert("ua_registry".into(), v.into());
            }
            RelayFeePolicy::from_cfg(&c)
        };
        assert!(cfg(None).unwrap().ua_registry.is_none());
        assert_eq!(cfg(Some(REGISTRY)).unwrap().ua_registry, Some(sc(REGISTRY)));
        for bad in [FROM, "nope"] {
            assert!(format!("{:#}", cfg(Some(bad)).err().unwrap()).contains("params.ua_registry"), "{bad}");
        }
    }

    // A real msig row's typed signatures are the bytes `check_*` takes, on `register` and on a KEM record.
    #[test]
    fn msig_row_converts_to_the_stored_bytes() {
        let r = row("registrations", "msig-pq/n2048-kmax1024");
        let key_data = strip(&r["keyData"]);
        let keys: HashMap<[u8; 32], (u16, Vec<u8>)> = portable()["registrations"].as_array().unwrap().iter()
            .map(|m| (strip(&m["ua"]).try_into().unwrap(), (m["kind"].as_u64().unwrap() as u16, strip(&m["keyData"]))))
            .collect();
        let members = |id| keys.get(&id).cloned();
        let write = |o: &Value| ua8_write(o).unwrap().0;
        let w = write(&reg_op(r, &NONE));
        let Ua8Write::Register(RegisterArgs::RegisterMsig { pop, .. }) = &w else { panic!() };
        assert_eq!(ua8::encode_member_sigs(pop), strip(&r["pop"]), "the stored abi.encode(MemberSig[])");
        ua8_check(&w, 0x0120, &key_data, &members).unwrap();
        let mut bad = reg_op(r, &NONE);
        flip(&mut bad["args"]["pop"][1]["sig"]);
        assert_eq!(ua8_check(&write(&bad), 0x0120, &key_data, &members), Err(UAError::Pop));

        let k = row("kemRecords", "msig-pq/v1");
        ua8_check(&write(&rec_op("set_kem_key", k, &NONE)), 0x0120, &key_data, &members).unwrap();
        let mut bad = rec_op("set_kem_key", k, &NONE);
        flip(&mut bad["args"]["sig"]["members"][0]["sig"]);
        assert_eq!(ua8_check(&write(&bad), 0x0120, &key_data, &members), Err(UAError::Unauthorized));
        // the contract's `sig_fields_ok`: an msig only `members`
        let mut bad = rec_op("set_kem_key", k, &NONE);
        bad["args"]["sig"]["signature"] = json!("0xab");
        assert_eq!(ua8_check(&write(&bad), 0x0120, &key_data, &members), Err(UAError::Unauthorized));

        // an evm-eoa slot, by its typed digest; a single key's `signature`; the same shape rule the other way
        let n = row("registrations", "msig-pq-native");
        ua8_check(&write(&reg_op(n, &NONE)), 0x0120, &strip(&n["keyData"]), &members).unwrap();
        let s = row("registrations", "fndsa512");
        let (d, p) = (strip(&s["keyData"]), row("pqzKeyRecords", "fndsa512/n2048-kmax1024"));
        ua8_check(&write(&rec_op("set_pqz_key", p, &NONE)), 0x0132, &d, &members).unwrap();
        let mut bad = rec_op("set_pqz_key", p, &NONE);
        bad["args"]["sig"]["key_data"] = json!("0xab");
        assert_eq!(ua8_check(&write(&bad), 0x0132, &d, &members), Err(UAError::Unauthorized));
    }

    // -- the adapter against a stub registry: `calls` is every simulation, by function, and `SEND` every submit

    fn stub_lane() -> String {
        stellar_account_strkey(&ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes())
    }
    fn rec(kind: u16, key: &[u8], signable: bool) -> ScVal {
        let e = |k: &str, v: ScVal| ScMapEntry { key: sym(k), val: v };
        ScVal::Map(Some(ScMap(vec![e("key_data", byt(key)), e("kind", ScVal::U32(kind as u32)), e("signable", ScVal::Bool(signable))].try_into().unwrap())))
    }
    fn row_rec(r: &Value, signable: bool) -> ([u8; 32], ScVal) {
        (strip(&r["ua"]).try_into().unwrap(), rec(r["kind"].as_u64().unwrap() as u16, &strip(&r["keyData"]), signable))
    }
    /// `relayers()`, `record_of(id)` from `records`, and a passing simulation of anything else.
    fn registry(relayers: Vec<ScVal>, records: Vec<([u8; 32], ScVal)>) -> Answer {
        Arc::new(move |c| match c.function_name.0.as_slice() {
            b"relayers" => view_ok(vecv(relayers.clone())),
            b"record_of" => view_ok(records.iter().find(|r| c.args[0] == byt(&r.0)).map_or(ScVal::Void, |r| r.1.clone())),
            b"member_accepted" => view_ok(ScVal::Bool(false)),
            _ => view_ok(ScVal::Void),
        })
    }
    async fn ua8_adapter(answer: Answer) -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        ua8_adapter_cap(answer, 0).await
    }
    async fn ua8_adapter_cap(answer: Answer, max_deposit: i64) -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let url = rpc_stub(answer, calls.clone()).await;
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec![url], lanes: vec![0], ..Default::default() };
        c.tokens = vec![crate::config::TokenCfg { address: CONTRACT.into(), decimals: 7 }];
        c.params.insert("network_passphrase".into(), "x".into());
        c.params.insert("max_resource_fee_per_job".into(), 1_000_000_000.into());
        c.params.insert("mandate_wasm_hashes".into(), toml::Value::Array(vec![hex(&MANDATE_WASM).into()]));
        c.params.insert("ua_registry".into(), REGISTRY.into());
        c.params.insert("max_deposit_per_job".into(), max_deposit.into());
        let s = LocalSigner::Ed(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        (SorobanAdapter::new(&c, &[s]).unwrap(), calls)
    }
    /// An adapter past `start_check`, its lane listed, its call log empty.
    async fn listed(records: Vec<([u8; 32], ScVal)>) -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        let (a, calls) = ua8_adapter(registry(vec![addr(&stub_lane())], records)).await;
        a.start_check().await.unwrap();
        assert_eq!(*calls.lock().unwrap(), ["relayers"]);
        calls.lock().unwrap().clear();
        (a, calls)
    }
    /// What the lane does with a job: build, and only after it sign and send.
    async fn run(a: &SorobanAdapter, op: &Value) -> std::result::Result<(), SimError> {
        run_kind(a, "call", op).await
    }
    async fn run_kind(a: &SorobanAdapter, kind: &str, op: &Value) -> std::result::Result<(), SimError> {
        let job: Job = serde_json::from_value(json!({"id": 7, "kind": kind, "op": op})).unwrap();
        let built = a.build(&job, 0).await?;
        let signed = a.sign(built, 0, 1).await.unwrap();
        a.submit(&signed).await.unwrap();
        Ok(())
    }
    fn logged(c: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        std::mem::take(&mut *c.lock().unwrap())
    }
    fn refused(r: std::result::Result<(), SimError>, why: &str) {
        assert!(matches!(&r, Err(SimError::Revert(e)) if e.contains(why)), "{why}: {r:?}");
    }

    /// `fndsa512` is relayer-checked: a valid row passes `check_*` and only then is simulated and sent.
    #[tokio::test]
    async fn relayer_mode_prechecks_off_chain() {
        let r = row("registrations", "fndsa512");
        let (a, calls) = listed(vec![row_rec(r, false)]).await;
        let me = json!(stub_lane());
        run(&a, &reg_op(r, &me)).await.unwrap();
        assert_eq!(logged(&calls), ["register", "SEND"]);
        run(&a, &rec_op("set_kem_key", row("kemRecords", "fndsa512/v1"), &me)).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "set_kem_key", "SEND"], "the record's kind and key are read first");
        run(&a, &rec_op("set_pqz_key", row("pqzKeyRecords", "fndsa512/n2048-kmax1024"), &me)).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "set_pqz_key", "SEND"]);
        // the one change: no `relayer`, so the part would be `NotVerifiable`
        refused(run(&a, &reg_op(r, &NONE)).await, "needs a relayer");
        refused(run(&a, &rec_op("set_kem_key", row("kemRecords", "fndsa512/v1"), &NONE)).await, "needs a relayer");
        assert_eq!(logged(&calls), ["record_of"], "never simulated, never sent");
    }

    /// A flipped byte: refused, and the fake RPC proves the write was never simulated or sent.
    #[tokio::test]
    async fn relayer_mode_refuses_failing_record() {
        let r = row("registrations", "fndsa512");
        let (k, q) = (row("kemRecords", "fndsa512/v1"), row("pqzKeyRecords", "fndsa512/n2048-kmax1024"));
        let (a, calls) = listed(vec![row_rec(r, false)]).await;
        let me = json!(stub_lane());
        let mut pop = reg_op(r, &me);
        flip(&mut pop["args"]["pop"]);
        let e = run(&a, &pop).await;
        refused(e, "UAPoP");
        assert_eq!(logged(&calls), Vec::<String>::new(), "not one RPC call");
        let mut kem = rec_op("set_kem_key", k, &me);
        flip(&mut kem["args"]["sig"]["signature"]);
        refused(run(&a, &kem).await, "UAUnauthorized");
        assert_eq!(logged(&calls), ["record_of"], "only the record read");
        let mut pqz = rec_op("set_pqz_key", q, &me);
        flip(&mut pqz["args"]["sig"]["signature"]);
        refused(run(&a, &pqz).await, "UAUnauthorized");
        assert_eq!(logged(&calls), ["record_of"]);
        // the control of all three: the same jobs unflipped, on the same adapter
        for o in [reg_op(r, &me), rec_op("set_kem_key", k, &me), rec_op("set_pqz_key", q, &me)] {
            run(&a, &o).await.unwrap();
            assert_eq!(logged(&calls).last().unwrap(), "SEND");
        }
    }

    // -- an msig slot of a kind the chain cannot verify: no vector row has one, so a fresh `fndsa512` member signs

    struct Member {
        key: Vec<u8>,
        id: [u8; 32],
        sk: falcon::SecretKey,
    }
    fn member() -> Member {
        let (pk, sk) = falcon::keypair();
        let key = pk.as_bytes().to_vec();
        Member { id: scaas_ua::derive_ua(0x0132, &key, false).unwrap(), key, sk }
    }
    /// `m`'s slot of the `pop` of the msig `key_data`, no attributes: over the `member` digest of its registration.
    fn slot(key_data: &[u8], m: &Member) -> Vec<u8> {
        let (ua, none) = (scaas_ua::ua_of(0x0120, key_data).unwrap(), [0; 32]);
        let digest = ua8::registration_digest(&ua, 0x0120, &none, &ua8::kem_record_hash(&ua, 0, &[]).unwrap(), &none);
        let md = scaas_ua::member_digest(&ua, &scaas_ua::ua_message(0x0120, &ua8::pop_v2_tag(), &digest).unwrap());
        let msg = scaas_ua::ua_message(0x0132, &scaas_ua::purpose_tag("member").unwrap(), &md).unwrap();
        falcon::detached_sign(&msg, &m.sk).as_bytes().to_vec()
    }
    /// `register_msig` of `threshold` and `members` in id order, `slots` = member index ⇒ signature.
    fn msig_op(threshold: u16, members: &[(u16, [u8; 32], u16)], slots: &[(u16, Vec<u8>)], relayer: &Value) -> Value {
        let z = h(&[0; 32]);
        let m: Vec<Value> = members.iter().map(|(k, id, w)| json!({"kind": k, "id": h(id), "weight": w})).collect();
        let s: Vec<Value> = slots.iter().map(|(i, b)| json!({"index": i, "key_data": "0x", "sig": h(b)})).collect();
        call_op("register_msig", json!({"structure": {"threshold": threshold, "members": m}, "pop": s, "pqz_pop": "0x", "relayer": relayer,
            "attrs": {"pqz_key": "0x", "pqz_pop_hash": z, "kem": {"scheme": 0, "mlkem_ek": "0x", "x25519": z}, "kem_pk_hash": z}}))
    }
    fn by_id(mut m: Vec<(u16, [u8; 32], u16)>) -> Vec<(u16, [u8; 32], u16)> {
        m.sort_by_key(|x| x.1);
        m
    }

    /// A marked slot reads its member through `record_of`; every other job differs from the passing one by one thing.
    #[tokio::test]
    async fn relayer_mode_checks_a_marked_msig_slot() {
        let m = member();
        let ms = vec![(0x0132, m.id, 1)];
        let kd = encode_msig(1, &ms);
        let (a, calls) = listed(vec![(m.id, rec(0x0132, &m.key, false))]).await;
        let me = json!(stub_lane());
        let good = msig_op(1, &ms, &[(0, slot(&kd, &m))], &me);
        run(&a, &good).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "register_msig", "SEND"]);

        let mut bad = good.clone();
        flip(&mut bad["args"]["pop"][0]["sig"]);
        refused(run(&a, &bad).await, "UAPoP");
        assert_eq!(logged(&calls), ["record_of"], "the write is never simulated");
        let mut none = good.clone();
        none["args"]["relayer"] = NONE;
        refused(run(&a, &none).await, "needs a relayer");
        assert_eq!(logged(&calls), Vec::<String>::new());

        // the member is not registered: `MemberUnknown`
        let (b, calls) = listed(vec![]).await;
        refused(run(&b, &good).await, "UAMemberUnknown");
        assert_eq!(logged(&calls), ["record_of"]);
        // an RPC failure is no answer: retried, never a pass; a host refusal is this job's own: dead, not requeued
        let answering = |answer: Value| {
            let m = Arc::new(move |f: &InvokeContractArgs| match f.function_name.0.as_slice() {
                b"relayers" => view_ok(vecv(vec![addr(&stub_lane())])),
                b"record_of" => answer.clone(),
                _ => view_ok(ScVal::Void),
            });
            async move {
                let (c, calls) = ua8_adapter(m).await;
                c.start_check().await.unwrap();
                logged(&calls);
                (c, calls)
            }
        };
        let (c, calls) = answering(json!({})).await;
        let e = run(&c, &good).await;
        assert!(matches!(&e, Err(SimError::Transport(_))), "{e:?}");
        assert_eq!(logged(&calls), ["record_of"]);
        let (c, calls) = answering(json!({"error": "boom"})).await;
        refused(run(&c, &good).await, "boom");
        assert_eq!(logged(&calls), ["record_of"]);
        // an archived member's value is bound to its id by `check_*`: it is used, and the restore is the write's
        let (c, calls) = answering(view_archived(rec(0x0132, &m.key, false))).await;
        run(&c, &good).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "register_msig", "SEND"]);
        refused(run(&c, &bad).await, "UAPoP");
        assert_eq!(logged(&calls), ["record_of"], "a restore skips no check");
    }

    /// An archived record (review): its value is used where its id binds it, the write's `sim_data` applies the cap, and a
    /// restore with no value is this job's own refusal.
    #[tokio::test]
    async fn archived_record_restores_within_the_cap() {
        let (r, k) = (row("registrations", "fndsa512"), row("kemRecords", "fndsa512/v1"));
        let (ua, record) = row_rec(r, false);
        let answer = |x: Option<Value>| -> Answer {
            let record = record.clone();
            Arc::new(move |c| match c.function_name.0.as_slice() {
                b"relayers" => view_ok(vecv(vec![addr(&stub_lane())])),
                b"record_of" => x.clone().unwrap_or_else(|| view_archived(record.clone())),
                _ => view_archived(ScVal::Void),
            })
        };
        assert_eq!(strip(&k["ua"]), ua);
        let me = json!(stub_lane());
        let job = rec_op("set_kem_key", k, &me);
        let (a, calls) = ua8_adapter_cap(answer(None), 115).await;
        a.start_check().await.unwrap();
        logged(&calls);
        run(&a, &job).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "set_kem_key", "SEND"], "100 + 15 % within the cap");
        let mut bad = job.clone();
        flip(&mut bad["args"]["sig"]["signature"]);
        refused(run(&a, &bad).await, "UAUnauthorized");
        assert_eq!(logged(&calls), ["record_of"], "a restore skips no check");
        let (a, calls) = ua8_adapter_cap(answer(None), 114).await;
        a.start_check().await.unwrap();
        logged(&calls);
        refused(run(&a, &job).await, "restore over max_deposit_per_job");
        assert_eq!(logged(&calls), ["record_of", "set_kem_key"], "the write's cap, never sent");
        let (a, calls) = ua8_adapter_cap(answer(Some(json!({"restorePreamble": {"minResourceFee": "5"}}))), 115).await;
        a.start_check().await.unwrap();
        logged(&calls);
        refused(run(&a, &job).await, "needs a restore");
        assert_eq!(logged(&calls), ["record_of"]);
    }

    /// Review: a job naming an archived record, with a garbage `sig`, leaves the queue at once and the next job runs:
    /// `relay_poll` is oldest first, so a requeued job would be claimed again every round.
    #[tokio::test]
    async fn archived_record_job_does_not_hold_the_queue() {
        use crate::adapter::tests::{fake_odoo, Fake};
        let record = row_rec(row("registrations", "mldsa65/n2048-kmax1024"), true).1;
        let (a, calls) = ua8_adapter(Arc::new(move |c| match c.function_name.0.as_slice() {
            b"relayers" => view_ok(vecv(vec![])),
            b"record_of" => view_archived(record.clone()),
            b"set_kem_key" => view_archived(ScVal::Void),
            _ => view_ok(ScVal::Void),
        })).await;
        let mut garbage = rec_op("set_kem_key", row("kemRecords", "mldsa65/v1"), &NONE);
        garbage["args"]["sig"]["signature"] = json!("0xdead");
        let jobs = vec![json!({"id": 7, "kind": "call", "op": garbage}), json!({"id": 8, "kind": "call", "op": ops(&NONE)[7]})];
        let (odoo, o) = fake_odoo(Fake { jobs, repeat: true, ..Default::default() }).await;
        for _ in 0..4 {
            crate::adapter::lane_step(&a, &odoo, 0, "n#0").await.unwrap();
            let mut f = o.lock().unwrap();
            let last = f.reports.last().unwrap().clone();
            if last["chain_state"] != "queued" {
                f.jobs.retain(|j| j["id"] != last["job_id"]);
            }
            if f.jobs.is_empty() {
                break;
            }
        }
        let f = o.lock().unwrap();
        let states = |id: i64| f.reports.iter().filter(|r| r["job_id"] == id).map(|r| r["chain_state"].as_str().unwrap()).collect::<Vec<_>>();
        assert_eq!(states(7), ["dead"], "{:?}", f.reports);
        assert_eq!(states(8).last(), Some(&"mined"), "{:?}", f.reports);
        assert_eq!(f.claims, 2, "each job once");
        assert!(f.jobs.is_empty());
        assert_eq!(logged(&calls).iter().filter(|c| *c == "SEND").count(), 1);
    }

    // -- a transaction over the network's `tx_max_size_bytes`: simulation passes it, `sendTransaction` never will

    /// A `store_pqz_pop` job with `pad` bytes of proof: it reads no state, so only its size is under test.
    fn sized_op(pad: usize) -> Value {
        let mut o = ops(&NONE)[7].clone();
        assert_eq!(o["function"], "store_pqz_pop");
        o["args"]["pqz_pop"] = json!(h(&vec![7; pad]));
        o
    }
    async fn sized_adapter(fee_bump: bool, limit: Option<u32>) -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let url = rpc_stub_limit(registry(vec![], vec![]), calls.clone(), Arc::new(Mutex::new(limit))).await;
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec![url], lanes: vec![0], ..Default::default() };
        c.params.insert("network_passphrase".into(), "x".into());
        c.params.insert("max_resource_fee_per_job".into(), 1_000_000_000.into());
        c.params.insert("mandate_wasm_hashes".into(), toml::Value::Array(vec![hex(&MANDATE_WASM).into()]));
        c.params.insert("ua_registry".into(), REGISTRY.into());
        if fee_bump {
            c.params.insert("fee_bump_lane".into(), 0.into());
        }
        let s = LocalSigner::Ed(ed25519_dalek::SigningKey::from_bytes(&[1; 32]));
        (SorobanAdapter::new(&c, &[s]).unwrap(), calls)
    }

    /// As `archived_record_job_does_not_hold_the_queue`: over the limit is this job's own state, `dead` on one claim with nothing
    /// signed, and the next job goes.
    #[tokio::test]
    async fn oversized_job_does_not_hold_the_queue() {
        use crate::adapter::tests::{fake_odoo, Fake};
        let (a, calls) = sized_adapter(false, Some(TX_MAX)).await;
        let jobs = vec![json!({"id": 7, "kind": "call", "op": sized_op(TX_MAX as usize)}), json!({"id": 8, "kind": "call", "op": sized_op(8)})];
        let (odoo, o) = fake_odoo(Fake { jobs, repeat: true, ..Default::default() }).await;
        for _ in 0..4 {
            crate::adapter::lane_step(&a, &odoo, 0, "n#0").await.unwrap();
            let mut f = o.lock().unwrap();
            let last = f.reports.last().unwrap().clone();
            if last["chain_state"] != "queued" {
                f.jobs.retain(|j| j["id"] != last["job_id"]);
            }
            if f.jobs.is_empty() {
                break;
            }
        }
        let f = o.lock().unwrap();
        let states = |id: i64| f.reports.iter().filter(|r| r["job_id"] == id).map(|r| r["chain_state"].as_str().unwrap()).collect::<Vec<_>>();
        assert_eq!(states(7), ["dead"], "{:?}", f.reports);
        assert!(f.reports[0]["error"].as_str().unwrap().contains("tx_max_size_bytes"), "{:?}", f.reports[0]);
        assert_eq!(states(8).last(), Some(&"mined"), "{:?}", f.reports);
        assert_eq!(f.claims, 2, "each job once");
        assert!(f.jobs.is_empty());
        assert_eq!(logged(&calls).iter().filter(|c| *c == "SEND").count(), 1, "the oversized job is never sent");
    }

    /// The compared size is what `sign` sends, less a fee bump's 128 B: exactly the limit is sent, 4 B more (XDR's step) is refused
    /// here. Core's reading of both edges is `e2e_ua8_tx_size_limit`.
    #[tokio::test]
    async fn transaction_of_exactly_the_limit_passes() {
        for (fee_bump, wrap) in [(false, 0), (true, 128)] {
            let (a, calls) = sized_adapter(fee_bump, Some(TX_MAX)).await;
            let signed_len = |pad: usize| {
                let a = &a;
                async move {
                    let job: Job = serde_json::from_value(json!({"id": 7, "kind": "call", "op": sized_op(pad)})).unwrap();
                    a.sign(a.build(&job, 0).await.unwrap(), 0, 1).await.unwrap().raw.len()
                }
            };
            let pad = TX_MAX as usize + wrap - signed_len(4).await + 4;
            assert_eq!(signed_len(pad).await, TX_MAX as usize + wrap, "fee_bump {fee_bump}");
            logged(&calls);
            run(&a, &sized_op(pad)).await.unwrap();
            assert_eq!(logged(&calls).last().unwrap(), "SEND", "fee_bump {fee_bump}");
            refused(run(&a, &sized_op(pad + 4)).await, "tx_max_size_bytes");
            assert!(!logged(&calls).contains(&"SEND".to_string()), "fee_bump {fee_bump}");
        }
    }

    /// One exit for every job kind: a `ua_metatx` too.
    #[tokio::test]
    async fn oversized_ua_metatx_refused_at_build() {
        let (a, calls) = stub_adapter(Arc::new(|_| view_ok(ScVal::Void)), false).await;
        let (contract, f, mut args) = ua_ops(ScVal::Void).remove(2);
        assert_eq!(f, "ua_pay_meta");
        args[4] = byt(&vec![7; TX_MAX as usize]);
        let e = a.build(&ua_job(contract, f, args), 0).await.err().unwrap();
        assert!(matches!(&e, SimError::Revert(r) if r.contains("tx_max_size_bytes")), "{e:?}");
        assert!(!logged(&calls).contains(&"SEND".to_string()));
    }

    /// The limit never stops payments simulation still serves: a read that fails uses the last answer, and a voted change is seen
    /// on the next good read, with no restart.
    #[tokio::test]
    async fn failed_limit_read_uses_the_last_answer() {
        let limit = Arc::new(Mutex::new(Some(TX_MAX)));
        let (a, calls) = stub_adapter_limit(Arc::new(|_| view_ok(ScVal::Void)), false, limit.clone()).await;
        let (contract, f, args) = ua_ops(ScVal::Void).remove(1);
        assert_eq!(f, "ua_pay");
        let pay = ua_job(contract, f, args);
        assert!(a.build(&pay, 0).await.is_ok(), "a good read");
        *limit.lock().unwrap() = None;
        assert!(a.build(&pay, 0).await.is_ok(), "the read fails, the last answer holds, the payment builds");
        *limit.lock().unwrap() = Some(100);
        let e = a.build(&pay, 0).await.err().unwrap();
        assert!(matches!(&e, SimError::Revert(r) if r.contains("(100)")), "a voted change, on the next good read: {e:?}");
        *limit.lock().unwrap() = None;
        assert!(a.build(&pay, 0).await.is_err(), "the last answer is the newest one");
        assert!(!logged(&calls).contains(&"SEND".to_string()));
    }

    /// The limit is the network's: with no answer yet, the first read is no refusal of this job, as a failed simulation is not.
    #[tokio::test]
    async fn unread_limit_is_transport() {
        let (a, calls) = sized_adapter(false, None).await;
        let r = run(&a, &sized_op(8)).await;
        assert!(matches!(&r, Err(SimError::Transport(e)) if e.contains("tx_max_size_bytes")), "{r:?}");
        assert!(!logged(&calls).contains(&"SEND".to_string()));
    }

    /// `evm-contract`: no off-chain check exists (C14). Signing nothing it passes; with a slot it is `NotVerifiable`.
    #[tokio::test]
    async fn relayer_mode_refuses_evm_contract_slot() {
        let m = member();
        let mut contract = [0u8; 32];
        contract[31] = 9;
        let ms = by_id(vec![(0x0132, m.id, 2), (0x0002, contract, 1)]);
        let (a, calls) = listed(vec![(m.id, rec(0x0132, &m.key, false))]).await;
        let me = json!(stub_lane());
        let at = ms.iter().position(|x| x.1 == m.id).unwrap() as u16;
        let good = msig_op(2, &ms, &[(at, slot(&encode_msig(2, &ms), &m))], &me);
        run(&a, &good).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "register_msig", "SEND"]);
        // threshold 3: both slots are needed, and the fndsa512 one is valid, so only the `evm-contract` slot refuses
        let mut slots = vec![(1 - at, vec![0xab; 65]), (at, slot(&encode_msig(3, &ms), &m))];
        slots.sort_by_key(|s| s.0);
        refused(run(&a, &msig_op(3, &ms, &slots, &me)).await, "UANotVerifiable");
        assert_eq!(logged(&calls), ["record_of"], "the write is never simulated");
        // no relayer changes nothing: an `evm-contract` slot is never submitted
        refused(run(&a, &msig_op(3, &ms, &slots, &NONE)).await, "needs a relayer");
        assert_eq!(logged(&calls), Vec::<String>::new());
        // beside a Chain slot alone it is still the part that needs a relayer: its slot comes first and refuses
        let ml = row("registrations", "mldsa65#1");
        let (b, calls) = listed(vec![row_rec(ml, true)]).await;
        let ms = by_id(vec![(0x0131, strip(&ml["ua"]).try_into().unwrap(), 2), (0x0002, contract, 1)]);
        let chain = msig_op(3, &ms, &[(0, vec![0xab; 65]), (1, vec![0xcd; 3309])], &me);
        refused(run(&b, &chain).await, "UANotVerifiable");
        assert_eq!(logged(&calls), ["record_of"], "the write is never simulated");
    }

    /// A `G…` member with only Chain parts needs no relayer, so `check_*`, which refuses it, is not asked; a `G…` member
    /// next to a slot that needs a relayer stays refused (the owner's question, fail closed).
    #[tokio::test]
    async fn g_member_msig_is_checked_only_for_a_marked_slot() {
        let (m, g) = (member(), [0xee; 32]);
        let ed = row("registrations", "ed25519");
        let ed_id: [u8; 32] = strip(&ed["ua"]).try_into().unwrap();
        let (a, calls) = listed(vec![row_rec(ed, true), (m.id, rec(0x0132, &m.key, false))]).await;
        // classical-dominant: no `pop` (U8S-D2), `Chain`, whatever its members
        let classical = by_id(vec![(0x0011, g, 1), (0x0102, ed_id, 1)]);
        assert!(scaas_ua::derive_ua(0x0120, &encode_msig(2, &classical), false).is_err(), "check_* refuses it off chain");
        run(&a, &msig_op(2, &classical, &[], &NONE)).await.unwrap();
        assert_eq!(logged(&calls), ["register_msig", "SEND"], "not checked, not refused");
        // the fndsa512 member's slot, valid for this very structure: only the `G…` member beside it refuses
        let marked = by_id(vec![(0x0011, g, 1), (0x0132, m.id, 2)]);
        let at = marked.iter().position(|x| x.1 == m.id).unwrap() as u16;
        let job = msig_op(2, &marked, &[(at, slot(&encode_msig(2, &marked), &m))], &json!(stub_lane()));
        refused(run(&a, &job).await, "UAKeyData");
        assert_eq!(logged(&calls), Vec::<String>::new(), "no read, no simulation");
        // the control: the same weights with a native member `check_*` knows
        let mut eoa = [0u8; 32];
        eoa[31] = 1;
        let known = by_id(vec![(0x0001, eoa, 1), (0x0132, m.id, 2)]);
        let at = known.iter().position(|x| x.1 == m.id).unwrap() as u16;
        run(&a, &msig_op(2, &known, &[(at, slot(&encode_msig(2, &known), &m))], &json!(stub_lane()))).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "register_msig", "SEND"]);
    }

    /// Review: one job costs at most the contract's 16 member reads; 17 are refused with no simulation at all.
    #[tokio::test]
    async fn msig_member_list_is_bounded_before_any_read() {
        let (a, calls) = listed(vec![]).await;
        let job = |n: u8| {
            let ms: Vec<(u16, [u8; 32], u16)> = (1..=n).map(|i| (0x0132, [i; 32], 1)).collect();
            msig_op(n.into(), &ms, &[(0, vec![0xab; 666])], &json!(stub_lane()))
        };
        refused(run(&a, &job(16)).await, "UAMemberUnknown");
        assert_eq!(logged(&calls), vec!["record_of".to_string(); 16], "the control: the same job at the limit");
        refused(run(&a, &job(17)).await, "UAKeyData");
        assert_eq!(logged(&calls), Vec::<String>::new(), "no read, no simulation");
    }

    /// Review: a `call` job's deadline is the node's to bound, nobody signed it: `0` is no `max_time`, a far one holds the
    /// lane in `follow`, `u64::MAX` overflows `valid_until + EXPIRY_GRACE`.
    #[tokio::test]
    async fn call_job_valid_until_is_bounded() {
        let (a, calls) = listed(vec![]).await;
        let (now, max) = (crate::submit::now(), crate::mesh::accept::MeshParams::default().max_valid_for_secs);
        let mut o = ops(&NONE).remove(7);
        for v in [0, now - 1, now + max + 60, u64::MAX] {
            o["valid_until"] = json!(v);
            refused(run(&a, &o).await, "valid_until");
            assert_eq!(logged(&calls), Vec::<String>::new(), "{v}");
        }
        for v in [now + 60, now + max - 60] {
            o["valid_until"] = json!(v);
            run(&a, &o).await.unwrap();
            assert_eq!(logged(&calls), ["pqz_pop_of", "store_pqz_pop", "SEND"], "{v}");
        }
    }

    /// `check_*` only where a part needs `relayer`: a Chain row is the chain's to refuse, a commit's fill compares a hash,
    /// and `store_pqz_pop` has no `relayer`.
    #[tokio::test]
    async fn chain_parts_are_not_prechecked() {
        let (ml, f) = (row("registrations", "mldsa65/n2048-kmax1024"), row("registrations", "fndsa512"));
        let (a, calls) = listed(vec![row_rec(ml, true), row_rec(f, false)]).await;
        // a wrong signature the node never reads: it reaches the simulation, which is the chain's check
        let mut chain = reg_op(row("registrations", "ed25519"), &NONE);
        flip(&mut chain["args"]["pop"]);
        run(&a, &chain).await.unwrap();
        assert_eq!(logged(&calls), ["register", "SEND"]);
        run(&a, &rec_op("set_kem_key", row("kemRecords", "mldsa65/v1"), &NONE)).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "set_kem_key", "SEND"]);
        let mut fill = rec_op("set_kem_key", row("kemRecords", "fndsa512/v1"), &NONE);
        fill["args"]["version"] = json!(0);
        fill["args"]["sig"] = json!({"key_data": "0x", "signature": "0x", "members": []});
        run(&a, &fill).await.unwrap();
        assert_eq!(logged(&calls), ["set_kem_key", "SEND"], "a marked kind's fill needs no relayer");
        run(&a, &ops(&NONE)[7]).await.unwrap();
        assert_eq!(logged(&calls), ["pqz_pop_of", "store_pqz_pop", "SEND"]);
        // an unregistered id: nothing to check, refused before its write
        let mut lost = rec_op("set_kem_key", row("kemRecords", "fndsa512/v1"), &NONE);
        lost["args"]["ua"] = json!(h(&[0x77; 32]));
        refused(run(&a, &lost).await, "not registered");
        assert_eq!(logged(&calls), ["record_of"]);
        // an answer that is not this id's cannot turn a marked record into a Chain one: the job above with its record swapped
        let (b, calls) = listed(vec![(strip(&f["ua"]).try_into().unwrap(), row_rec(ml, true).1)]).await;
        let job = rec_op("set_kem_key", row("kemRecords", "fndsa512/v1"), &json!(stub_lane()));
        refused(run(&b, &job).await, "another record");
        assert_eq!(logged(&calls), ["record_of"]);
    }

    /// `relayers()` answers once: not listed stays refused even if a later read would pass, and the one difference from the
    /// passing job is that answer.
    #[tokio::test]
    async fn relayer_mode_refused_on_unlisted_lane() {
        let r = row("registrations", "fndsa512");
        let job = reg_op(r, &json!(stub_lane()));
        let list = Arc::new(Mutex::new(vec![addr(FROM)]));
        let l2 = list.clone();
        let (a, calls) = ua8_adapter(Arc::new(move |c| match c.function_name.0.as_slice() {
            b"relayers" => view_ok(vecv(l2.lock().unwrap().clone())),
            _ => view_ok(ScVal::Void),
        })).await;
        a.start_check().await.unwrap();
        list.lock().unwrap().push(addr(&stub_lane()));
        a.start_check().await.unwrap();
        assert_eq!(logged(&calls), ["relayers"], "read once");
        refused(run(&a, &job).await, "not in the registry's relayers()");
        assert_eq!(logged(&calls), Vec::<String>::new(), "never simulated, never sent");
        // relayer-mode names the job: `Some(lane)` is refused on a part the chain verifies too; `None` there is untouched
        refused(run(&a, &reg_op(row("registrations", "ed25519"), &json!(stub_lane()))).await, "not in the registry's relayers()");
        run(&a, &reg_op(row("registrations", "ed25519"), &NONE)).await.unwrap();
        assert_eq!(logged(&calls), ["register", "SEND"]);

        let (b, calls) = listed(vec![]).await;
        run(&b, &job).await.unwrap();
        assert_eq!(logged(&calls), ["register", "SEND"], "the control: listed at start");
    }

    /// Review: a failed `relayers()` read holds only what needs the list. `start_check` passes, payments and Chain parts run,
    /// a relayer-mode job fails closed until a read answers, and the answer is kept.
    #[tokio::test]
    async fn failed_relayers_read_stops_only_relayer_mode() {
        let list = view_ok(vecv(vec![addr(&stub_lane())]));
        let answer = Arc::new(Mutex::new(json!({})));
        let shared = answer.clone();
        let (a, calls) = ua8_adapter(Arc::new(move |c| match c.function_name.0.as_slice() {
            b"relayers" => shared.lock().unwrap().clone(),
            _ => view_ok(ScVal::Void),
        })).await;
        a.start_check().await.unwrap();
        assert_eq!(logged(&calls), ["relayers"], "logged, the lane starts");

        let pay = json!({"payload": payload(inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": crate::submit::now() + 600, "extra": {}});
        run_kind(&a, "signed_op", &pay).await.unwrap();
        assert_eq!(logged(&calls), ["pay", "SEND"]);
        run(&a, &reg_op(row("registrations", "ed25519"), &NONE)).await.unwrap();
        assert_eq!(logged(&calls), ["register", "SEND"], "no relayer named, no read");

        let job = reg_op(row("registrations", "fndsa512"), &json!(stub_lane()));
        let e = run(&a, &job).await;
        assert!(matches!(&e, Err(SimError::Transport(_))), "an RPC failure is retried: {e:?}");
        assert_eq!(logged(&calls), ["relayers"], "never simulated, never sent");
        for (bad, why) in [(view_archived(vecv(vec![])), "needs a restore"), (json!({"error": "boom"}), "config"), (view_ok(u64v(1)), "config")] {
            *answer.lock().unwrap() = bad;
            refused(run(&a, &job).await, why);
            assert_eq!(logged(&calls), ["relayers"], "{why}");
        }
        *answer.lock().unwrap() = list;
        run(&a, &job).await.unwrap();
        assert_eq!(logged(&calls), ["relayers", "register", "SEND"], "the read answers, the job runs");
        *answer.lock().unwrap() = json!({});
        run(&a, &job).await.unwrap();
        assert_eq!(logged(&calls), ["register", "SEND"], "read once");
    }

    // -- CTR-UA-37: `accept_membership`, a `ua_metatx` job on the registry

    /// A `portable.json` `memberships` row as a job names it.
    fn accept_op(r: &Value, relayer: &Value) -> Value {
        let vu = crate::submit::now() + 600;
        json!({"contract": REGISTRY, "function": "accept_membership", "valid_until": vu,
               "args": {"ua": r["ua"], "member_sig": {"index": r["index"], "key_data": "0x", "sig": r["sig"]}, "relayer": relayer}})
    }
    fn membership(name: &str) -> &'static Value {
        portable()["memberships"].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap()
    }
    /// `msig-classical` and its members, as the registry answers them.
    fn classical() -> Vec<([u8; 32], ScVal)> {
        let mut r = ["msig-classical", "bls-bn254-minsig", "schnorr-bn254"].map(|n| row_rec(row("registrations", n), false)).to_vec();
        r.push(row_rec(row("registrations", "p256"), true));
        r
    }
    fn registry_policy() -> RelayFeePolicy {
        RelayFeePolicy { ua_registry: Some(sc(REGISTRY)), ..policy() }
    }

    /// The allow-list: this function on `params.ua_registry` alone, as a `ua_metatx`; `known_contract` holds, a `signed_op` never runs on
    /// the registry, a `call` job stays the eight writes; nothing signed names the deadline, so the node bounds it.
    #[test]
    fn accept_job_runs_on_the_registry_alone() {
        let (p, op) = (registry_policy(), accept_op(membership("msig-classical/0"), &NONE));
        let tx = |k: &str, o: &Value, p: &RelayFeePolicy| job_tx(&NET7, Some(k), o, &lane(), p);
        let (call, auth, vu) = tx("ua_metatx", &op, &p).unwrap();
        assert_eq!((call.contract_address.clone(), call.function_name.0.as_slice(), call.args.len()), (sc(REGISTRY), &b"accept_membership"[..], 3));
        assert_eq!((auth.len(), Some(vu)), (0, op["valid_until"].as_u64()));
        assert_eq!(ua_digest(&NET7, &call, UA_FNS.iter().find(|f| f.name == "accept_membership").unwrap()).unwrap(), None, "nothing signs a digest of the call");
        let mut other = op.clone();
        other["contract"] = json!(WALLET);
        assert!(tx("ua_metatx", &other, &p).unwrap_err().to_string().contains("not allowed"));
        assert!(tx("ua_metatx", &op, &policy()).unwrap_err().to_string().contains("not allowed"), "no params.ua_registry");
        let e = tx("call", &op, &p).unwrap_err().to_string();
        assert!(e.contains("auth") || e.contains("not a registry write"), "{e}");
        let mut plain = op.clone();
        plain.as_object_mut().unwrap().remove("auth");
        assert!(format!("{:#}", tx("call", &plain, &p).unwrap_err()).contains("not a registry write"));
        // `known_contract`: the same call as the subject's own signed invocation
        let subject = json!({"payload": {"nonce": "1", "expiry": 9, "invocation": {"contract": REGISTRY, "function": "accept_membership", "args": [], "sub_invocations": []}},
                             "from": FROM, "signature": sig(), "contract": REGISTRY, "valid_until": op["valid_until"], "extra": {}});
        assert!(format!("{:#}", tx("signed_op", &subject, &p).unwrap_err()).contains(CALL_TARGET_REFUSED));
        // the deadline, one change each
        for (vu, why) in [(json!(null), "op.valid_until missing"), (json!(1), "not within"), (json!(crate::submit::now() + 7_200), "not within")] {
            let mut o = op.clone();
            o["valid_until"] = vu;
            assert!(format!("{:#}", tx("ua_metatx", &o, &p).unwrap_err()).contains(why), "{why}");
        }
        // named parameters: a blob or an unknown field is refused at every level
        let mut blob = op.clone();
        blob["args"]["member_sig"] = json!("0xab");
        assert!(format!("{:#}", tx("ua_metatx", &blob, &p).unwrap_err()).contains(HEX_ARGS_REFUSED));
        let mut extra = op.clone();
        extra["args"]["member_sig"]["memo"] = json!(1);
        assert!(tx("ua_metatx", &extra, &p).is_err());
        let mut past = op.clone();
        past["args"]["member_sig"]["index"] = json!(70_000);
        assert!(tx("ua_metatx", &past, &p).is_err(), "an index its u16 cannot hold");
    }

    /// `relayer` is this lane and a listed one, and then the job carries the registry's one word, `attest_digest` of its three arguments,
    /// in the registry's own form, never the lane's authority over the call. A subject's `op.auth` entry goes through as on any `ua_metatx`.
    #[test]
    fn accept_job_attests_one_word() {
        let (p, me) = (registry_policy(), json!(lane().to_string()));
        let op = accept_op(membership("msig-classical/1"), &me);
        assert!(job_tx(&NET7, Some("ua_metatx"), &op, &lane(), &p).unwrap_err().to_string().contains("relayers()"), "a lane the list does not hold");
        p.relayers.set(vec![lane()]).unwrap();
        let (call, auth, _) = job_tx(&NET7, Some("ua_metatx"), &op, &lane(), &p).unwrap();
        let d = attest_digest(&NET7, &sc(REGISTRY), &call.function_name, &call.args).unwrap();
        assert_eq!(auth.len(), 1);
        assert!(matches!(auth[0].credentials, SorobanCredentials::SourceAccount));
        let SorobanAuthorizedFunction::ContractFn(root) = &auth[0].root_invocation.function else { panic!() };
        assert_eq!((root.contract_address.clone(), root.function_name.clone(), root.args.as_slice()), (sc(REGISTRY), call.function_name.clone(), &[byt(&d)][..]));
        let mut other = op.clone();
        other["args"]["relayer"] = json!(FROM);
        assert!(job_tx(&NET7, Some("ua_metatx"), &other, &lane(), &p).unwrap_err().to_string().contains("this lane"));
        let mut signed = accept_op(membership("msig-classical/0"), &NONE);
        signed["auth"] = json!([{"payload": cross_payload(), "from": FROM, "signature": sig()}]);
        let (_, auth, _) = job_tx(&NET7, Some("ua_metatx"), &signed, &lane(), &p).unwrap();
        assert!(matches!(auth.as_slice(), [e] if matches!(e.credentials, SorobanCredentials::Address(_))));
    }

    /// A slot the chain verifies is simulated with no relayer; a relayer-checked one passes `check_membership` first or nothing is
    /// simulated: every row, unchanged, and one flipped byte.
    #[tokio::test]
    async fn accept_job_prechecks_a_marked_slot() {
        let f = row("registrations", "fndsa512");
        let mut records = classical();
        records.push(row_rec(f, false));
        let (a, calls) = listed(records).await;
        let me = json!(stub_lane());
        let mut single = accept_op(membership("msig-classical/1"), &me);
        single["args"]["ua"] = f["ua"].clone();
        refused(run_kind(&a, "ua_metatx", &single).await, "UAUnauthorized");
        assert_eq!(logged(&calls), ["record_of", "member_accepted"], "a single key has no slot: never simulated");
        for n in ["msig-classical/0", "msig-classical/3"] {
            run_kind(&a, "ua_metatx", &accept_op(membership(n), &NONE)).await.unwrap();
            assert_eq!(logged(&calls), ["record_of", "member_accepted", "accept_membership", "SEND"], "{n}");
        }
        for n in ["msig-classical/1", "msig-classical/2"] {
            refused(run_kind(&a, "ua_metatx", &accept_op(membership(n), &NONE)).await, "needs a relayer");
            assert_eq!(logged(&calls), ["record_of", "member_accepted"], "{n}: never simulated");
            let mut bad = accept_op(membership(n), &me);
            flip(&mut bad["args"]["member_sig"]["sig"]);
            refused(run_kind(&a, "ua_metatx", &bad).await, "UAUnauthorized");
            assert_eq!(logged(&calls).last().unwrap(), "record_of", "{n}: never simulated");
            run_kind(&a, "ua_metatx", &accept_op(membership(n), &me)).await.unwrap();
            assert_eq!(logged(&calls).last().unwrap(), "SEND", "{n}");
        }
        let mut past = accept_op(membership("msig-classical/1"), &me);
        past["args"]["member_sig"]["index"] = json!(4);
        refused(run_kind(&a, "ua_metatx", &past).await, "UAUnauthorized");
        let mut gone = accept_op(membership("msig-classical/1"), &me);
        gone["args"]["ua"] = json!(h(&[0x66; 32]));
        refused(run_kind(&a, "ua_metatx", &gone).await, "not registered");
    }

    /// A slot already accepted: a no-op on chain, on the lane's fee, so nothing is simulated or sent (`a_re_run_acceptance_is_consumed`: its report); the same job on a slot not yet accepted
    /// goes. A `member_accepted` that answers no bool, or no RPC, sends nothing either.
    #[tokio::test]
    async fn accept_job_on_an_accepted_slot_is_refused_unsent() {
        let (records, answer) = (classical(), Arc::new(Mutex::new(ScVal::Bool(true))));
        let base = registry(vec![addr(&stub_lane())], records);
        let a2 = answer.clone();
        let reply: Answer = Arc::new(move |c| if c.function_name.0.as_slice() == b"member_accepted" { view_ok(a2.lock().unwrap().clone()) } else { base(c) });
        let (a, calls) = ua8_adapter(reply).await;
        let op = accept_op(membership("msig-classical/0"), &NONE);
        refused(run_kind(&a, "ua_metatx", &op).await, "already accepted");
        assert_eq!(logged(&calls), ["record_of", "member_accepted"], "never simulated, never sent");
        *answer.lock().unwrap() = ScVal::Void;
        refused(run_kind(&a, "ua_metatx", &op).await, "member_accepted answered");
        assert_eq!(logged(&calls), ["record_of", "member_accepted"]);
        *answer.lock().unwrap() = ScVal::Bool(false);
        run_kind(&a, "ua_metatx", &op).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "member_accepted", "accept_membership", "SEND"]);
    }

    /// CTR-UA-34's open item, on this job: `derive_ua` refuses an `msig` with a `G…` member, so a relayer-checked slot beside one fails closed
    /// here, before simulation; the `G…` slot of the same structure, which the chain checks, needs no off-chain check and goes on.
    #[tokio::test]
    async fn accept_job_a_marked_slot_beside_a_g_member_fails_closed() {
        let f = row("registrations", "fndsa512");
        let (fid, g) = (<[u8; 32]>::try_from(strip(&f["ua"])).unwrap(), [0x22u8; 32]);
        let mut list = [(0x0011u16, g, 1u16), (0x0132, fid, 1)];
        list.sort_by_key(|m| m.1);
        let d = encode_msig(1, &list);
        let ua = scaas_ua::ua_of(0x0120, &d).unwrap();
        let (a, calls) = listed(vec![(ua, rec(0x0120, &d, true)), row_rec(f, false)]).await;
        let at = |id: &[u8; 32]| list.iter().position(|m| m.1 == *id).unwrap();
        let slot = |id: &[u8; 32]| json!({"ua": h(&ua), "index": at(id), "sig": "0x"});
        refused(run_kind(&a, "ua_metatx", &accept_op(&slot(&fid), &json!(stub_lane()))).await, "UAKeyData");
        assert_eq!(logged(&calls), ["record_of", "member_accepted"], "never simulated");
        run_kind(&a, "ua_metatx", &accept_op(&slot(&g), &NONE)).await.unwrap();
        assert_eq!(logged(&calls).last().unwrap(), "SEND");
    }

    /// An `evm-contract` slot: nothing here can run ERC-1271, so `check_membership` is `NotVerifiable` and the job dies before simulation.
    #[tokio::test]
    async fn accept_job_refuses_an_evm_contract_slot() {
        let r = row("registrations", "msig-classical");
        let d = strip(&r["keyData"]);
        let contract = [&d[..4], &[0, 2], &d[6..]].concat();
        let ua = scaas_ua::ua_of(0x0120, &contract).unwrap();
        let (a, calls) = listed(vec![(ua, rec(0x0120, &contract, false)), row_rec(row("registrations", "bls-bn254-minsig"), false),
                                     row_rec(row("registrations", "schnorr-bn254"), false), row_rec(row("registrations", "p256"), true)]).await;
        let mut op = accept_op(membership("msig-classical/0"), &json!(stub_lane()));
        op["args"]["ua"] = json!(h(&ua));
        refused(run_kind(&a, "ua_metatx", &op).await, "NotVerifiable");
        assert_eq!(logged(&calls).last().unwrap(), "record_of", "never simulated");
    }

    /// A `G…` member's acceptance is the member's auth entry: with none the simulation records its signature and the job fails unsent;
    /// `op.auth` carries it, and the job goes.
    #[tokio::test]
    async fn accept_job_needs_a_g_members_entry() {
        let signer = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials { address: sc(FROM), nonce: 1, signature_expiration_ledger: 1, signature: ScVal::Void }),
            root_invocation: source_entry(&InvokeContractArgs { contract_address: sc(REGISTRY), function_name: ScSymbol("accept_membership".try_into().unwrap()), args: Default::default() }).root_invocation,
        };
        let recorded = signer.to_xdr_base64(Limits::none()).unwrap();
        let answer: Answer = Arc::new(move |_| json!({"results": [{"xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(), "auth": [recorded.clone()]}], "transactionData": data(100, &[])}));
        let d = encode_msig(1, &[(0x0011, [0x22; 32], 1)]);
        let ua = scaas_ua::ua_of(0x0120, &d).unwrap();
        let records = registry(vec![], vec![(ua, rec(0x0120, &d, true))]);
        let both: Answer = Arc::new(move |c| if matches!(c.function_name.0.as_slice(), b"record_of" | b"member_accepted") { records(c) } else { answer(c) });
        let (a, calls) = ua8_adapter(both).await;
        let slot = json!({"name": "g", "ua": h(&ua), "index": 0, "sig": "0x"});
        refused(run_kind(&a, "ua_metatx", &accept_op(&slot, &NONE)).await, "does not carry");
        assert_eq!(logged(&calls), ["record_of", "member_accepted", "accept_membership"], "simulated, never sent");
        let mut op = accept_op(&slot, &NONE);
        op["auth"] = json!([{"payload": cross_payload(), "from": FROM, "signature": sig()}]);
        run_kind(&a, "ua_metatx", &op).await.unwrap();
        assert_eq!(logged(&calls), ["record_of", "member_accepted", "accept_membership", "SEND"]);
    }

    /// Free to the client, as a `call` job: in the call share, and no other `ua_metatx` joins it.
    #[tokio::test]
    async fn accept_job_is_in_the_call_share() {
        let (a, _) = ua8_adapter(Arc::new(|_| json!({}))).await;
        let job = |kind: &str, op: Value| -> Job { serde_json::from_value(json!({"id": 7, "kind": kind, "op": op})).unwrap() };
        let op = accept_op(membership("msig-classical/0"), &NONE);
        assert!(a.in_call_share(&job("ua_metatx", op.clone())));
        assert_eq!(Some(a.job_valid_until(&job("ua_metatx", op.clone()))), op["valid_until"].as_u64(), "after a restart, the job's own deadline");
        let (c, f, args) = ua_ops(ScVal::Void).remove(0);
        assert!(!a.in_call_share(&job("ua_metatx", ua_op(c, f, args))));
        assert!(a.in_call_share(&job("call", json!({}))));
    }

    /// `check_recorded_auth` applies, and a call that wants anyone else's authority cannot land: the job carries no entry.
    #[tokio::test]
    async fn call_job_refuses_recorded_authority() {
        let stolen = source_entry(&InvokeContractArgs { contract_address: sc(WALLET), function_name: ScSymbol("pay".try_into().unwrap()), args: Default::default() });
        let signer = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials { address: sc(FROM), nonce: 1, signature_expiration_ledger: 1, signature: ScVal::Void }),
            root_invocation: stolen.root_invocation.clone(),
        };
        let at = |e: &SorobanAuthorizationEntry| e.to_xdr_base64(Limits::none()).unwrap();
        let sim = |auth: Vec<String>| json!({"results": [{"xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(), "auth": auth}], "transactionData": data(100, &[])});
        let job = reg_op(row("registrations", "ed25519"), &NONE);
        for (entry, why) in [(at(&stolen), "lent"), (at(&signer), "signature")] {
            let a2 = sim(vec![entry]);
            let (a, calls) = ua8_adapter(Arc::new(move |_| a2.clone())).await;
            refused(run(&a, &job).await, why);
            assert_eq!(logged(&calls), ["register"], "simulated, never sent");
        }
        // the control: the lane's own entry for exactly this call
        let (a, calls) = ua8_adapter(Arc::new(move |c| sim(vec![source_entry(c).to_xdr_base64(Limits::none()).unwrap()]))).await;
        run(&a, &job).await.unwrap();
        assert_eq!(logged(&calls), ["register", "SEND"]);
    }

    /// The contract reads `Signer` for a Chain kind and `Ua` for a marked one (`check_members`); natives have no record.
    #[tokio::test]
    async fn members_read_as_the_contract_reads_them() {
        let (signer, unsigned, marked, gone) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        let mut native = [0u8; 32];
        native[31] = 1;
        let (a, calls) = listed(vec![(signer, rec(0x0131, b"s", true)), (unsigned, rec(0x0131, b"u", false)), (marked, rec(0x0132, b"m", false))]).await;
        let d = encode_msig(1, &[(0x0001, native, 1), (0x0131, signer, 1), (0x0131, unsigned, 1), (0x0132, marked, 1), (0x0131, gone, 1)]);
        let m = a.ua8_members(&sc(REGISTRY), &d).await.unwrap();
        assert_eq!(m.len(), 2, "{m:?}");
        assert_eq!((&m[&signer], &m[&marked]), (&(0x0131, b"s".to_vec()), &(0x0132, b"m".to_vec())));
        assert_eq!(logged(&calls).len(), 4, "every derived member, no native");
    }

    proptest! {
        #[test]
        fn payload_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512), sig in "[0-9a-f]{0,200}") {
            let _ = host_call(&op(json!(hex(&bytes)), &sig));
        }

        #[test]
        fn jobs_never_panic_on_untrusted_input(bytes in proptest::collection::vec(any::<u8>(), 0..512), sig in "[0-9a-f]{0,200}",
                                               call in "[0-9a-f]{0,400}", i in any::<usize>(), b in any::<u8>()) {
            let net = network_id(NETWORK);
            let lane = ScAddress::from_str(LANE).unwrap();
            let mut o = op(json!(hex(&bytes)), &sig);
            o["extra"] = json!({"call": call});
            o["salt"] = json!(sig);
            o["meta"] = json!(sig);
            let _ = pay_meta_job(&o, 2048);
            let _ = relay_fee_job(&net, &o, &lane, &policy());
            // A well-formed job with one byte of its JSON mutated.
            let rf = [1u8; 32];
            let mut c = serde_json::to_vec(&relay_job(&rf, &rf)).unwrap();
            let n = c.len();
            c[i % n] = b;
            if let Ok(v) = serde_json::from_slice::<Value>(&c) {
                let _ = relay_fee_job(&NET7, &v, &lane, &policy());
                let _ = job_tx(&NET7, None, &v, &lane, &policy());
            }
        }

        /// A well-formed `ua_metatx` op with one byte of its JSON mutated: refused or built, never a panic.
        #[test]
        fn ua_metatx_job_never_panics(k in 0usize..13, i in any::<usize>(), b in any::<u8>()) {
            let mut ops = ua_ops(addr(LANE));
            ops.push((WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)));
            let (c, f, args) = ops.swap_remove(k % ops.len());
            let mut a = serde_json::to_vec(&ua_op(c, f, args)).unwrap();
            let n = a.len();
            a[i % n] = b;
            if let Ok(o) = serde_json::from_slice::<Value>(&a) {
                let _ = ua_metatx_job(&NET7, &o, &lane(), &policy());
                let _ = job_tx(&NET7, Some("ua_metatx"), &o, &lane(), &policy());
            }
        }

        /// A registry write's untrusted bytes: refused or checked, never a panic.
        #[test]
        fn ua8_check_never_panics(kind in any::<u16>(), key in proptest::collection::vec(any::<u8>(), 0..1024), pop in proptest::collection::vec(any::<u8>(), 0..1024), index in any::<u16>()) {
            let mut o = ops(&NONE).remove(0);
            (o["args"]["kind"], o["args"]["key_data"], o["args"]["pop"]) = (json!(kind), json!(h(&key)), json!(h(&pop)));
            let (w, _) = ua8_write(&o).unwrap();
            let _ = ua8_marked(&w, kind, &key);
            let _ = ua8_check(&w, kind, &key, &|_| None);
            let mut o = ops(&NONE).remove(1);
            o["args"]["pop"][0] = json!({"index": index, "key_data": "0x", "sig": h(&pop)});
            let (w, _) = ua8_write(&o).unwrap();
            let _ = ua8_marked(&w, MSIG, &key);
            let _ = ua8_check(&w, MSIG, &key, &|_| None);
        }

        #[test]
        fn event_decoder_never_panics(t0 in ".{0,80}", t1 in ".{0,80}", v in ".{0,200}", id in ".{0,30}", tx in ".{0,70}") {
            let _ = decode_event(&json!({"ledger": 1, "contractId": CONTRACT, "txHash": tx, "id": id, "topic": [t0, t1], "value": v}));
        }

        #[test]
        fn mutated_payload_never_panics(i in any::<usize>(), b in any::<u8>()) {
            let mut p = serde_json::to_vec(&cross_payload()).unwrap();
            let n = p.len();
            p[i % n] = b;
            if let Ok(v) = serde_json::from_slice::<Value>(&p) {
                let _ = host_call(&op(v, &sig()));
            }
        }
    }

    #[test]
    fn event_pages_after_the_first_carry_only_the_cursor() {
        let f = json!([{"type": "contract", "contractIds": [CONTRACT]}]);
        let first = events_params(&f, 10, 20, None);
        assert_eq!((first["startLedger"].as_u64(), first["endLedger"].as_u64()), (Some(10), Some(21)));
        // stellar-rpc GetEventsRequest.Valid: "ledger ranges and cursor cannot both be set".
        let next = events_params(&f, 10, 20, Some("0000000042-0000000001"));
        assert_eq!(next["pagination"]["cursor"], "0000000042-0000000001");
        assert!(next.get("startLedger").is_none() && next.get("endLedger").is_none(), "{next}");
    }

    // ---- the spend stop (NET-SOR-14)

    /// `resultXdr` as the real host answers it (Protocol 30 quickstart, `e2e_ua8_spend_stop`, whose `FEE` lines compare each
    /// `feeCharged` with what left the payer's balance): SUCCESS, FAILED, and both under a fee bump.
    const RESULT_SUCCESS: &str = "AAAAAAAOmaUAAAAAAAAAAQAAAAAAAAAYAAAAAFAt8yW35C2zFXeWHaVy2MCn80yeTkoeh6LYx/OWZwfwAAAAAA==";
    const RESULT_FAILED: &str = "AAAAAAAFwhH/////AAAAAQAAAAAAAAAY/////QAAAAA=";
    const RESULT_BUMP_SUCCESS: &str = "AAAAAAAOmgkAAAABxhCeKITm331T+c813d/vgsvT1jdeC/Fvf+SEMZPVqDMAAAAAAAAAAAAAAAAAAAABAAAAAAAAABgAAAAAulj84l+7Ptgk7kgYNYbiVWZP327QkxLiQOm8rCevr8gAAAAAAAAAAA==";
    const RESULT_BUMP_FAILED: &str = "AAAAAAAFwnX////zSG1s3vM5/nZVp4irv7Llnmfod1hIgycQrJ1HV1i3kqoAAAAAAAAAAP////8AAAABAAAAAAAAABj////9AAAAAAAAAAA=";
    const FAILED_FEE: u128 = 377_361;

    fn lane_key(seed: u8) -> LocalSigner {
        LocalSigner::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
    }

    fn lane_pk_of(seed: u8) -> [u8; 32] {
        lane_key(seed).public_key().try_into().unwrap()
    }

    /// A real adapter on the stub chain: lanes `[1; 32]` and `[2; 32]`, the first the fee account when `fee_bump`.
    async fn spend_adapter(answer: Answer, net: Net, fee_bump: bool) -> (Arc<SorobanAdapter>, Arc<Mutex<Vec<String>>>, Arc<Mutex<Net>>) {
        let (calls, net) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(net)));
        let url = rpc_stub_net(answer, calls.clone(), Arc::new(Mutex::new(Some(TX_MAX))), net.clone()).await;
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec![url], lanes: vec![0, 1], ..Default::default() };
        c.tokens = vec![crate::config::TokenCfg { address: CONTRACT.into(), decimals: 7 }];
        c.params.insert("network_passphrase".into(), "x".into());
        c.params.insert("max_resource_fee_per_job".into(), 1_000_000_000.into());
        c.params.insert("mandate_wasm_hashes".into(), toml::Value::Array(vec![hex(&MANDATE_WASM).into()]));
        c.params.insert("ua_registry".into(), REGISTRY.into());
        c.params.insert("dex".into(), DEX.into());
        c.params.insert("mandates".into(), toml::Value::Array(vec![WALLET.into()]));
        if fee_bump {
            c.params.insert("fee_bump_lane".into(), 0.into());
        }
        (Arc::new(SorobanAdapter::new(&c, &[lane_key(1), lane_key(2)]).unwrap()), calls, net)
    }

    fn sends(c: &Arc<Mutex<Vec<String>>>) -> usize {
        c.lock().unwrap().iter().filter(|c| *c == "SEND").count()
    }

    /// `feeCharged`, of a SUCCESS and of a FAILED, the outer result under a fee bump. Each refusal is one change from a passing answer.
    #[tokio::test]
    async fn tx_fee_is_the_fee_charged() {
        let (a, _, net) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        for (status, xdr, want) in [("SUCCESS", RESULT_SUCCESS, 956_837), ("FAILED", RESULT_FAILED, 377_361), ("SUCCESS", RESULT_BUMP_SUCCESS, 956_937), ("FAILED", RESULT_BUMP_FAILED, 377_461)] {
            net.lock().unwrap().tx = json!({"status": status, "ledger": 5, "resultXdr": xdr});
            assert_eq!(a.tx_fee("0xab").await.unwrap(), Some(want), "{status} {xdr}");
        }
        let mut negative = stellar_xdr::TransactionResult::from_xdr_base64(RESULT_FAILED, Limits::none()).unwrap();
        negative.fee_charged = -1;
        for bad in [json!({"status": "NOT_FOUND", "resultXdr": RESULT_FAILED}), json!({"status": "FAILED", "resultXdr": "AAAA"}), json!({"status": "FAILED"}),
                    json!({"status": "FAILED", "resultXdr": negative.to_xdr_base64(Limits::none()).unwrap()})] {
            net.lock().unwrap().tx = bad.clone();
            assert!(a.tx_fee("0xab").await.is_err(), "{bad}: an unread fee is never a zero one");
        }
    }

    /// The account that pays and no other (owner ruling I-1): the lane's own, or under a fee bump the fee account alone. An account
    /// that does not exist holds nothing; a failed read, or an answer with no result, is an `Err`, never a zero that opens the floor.
    #[tokio::test]
    async fn lane_balance_is_the_account_that_pays() {
        let (one, two) = (lane_pk_of(1), lane_pk_of(2));
        let answer = registry(vec![], vec![]);
        let (a, _, net) = spend_adapter(answer.clone(), Net { accounts: Some(vec![(two, 70)]), ..Net::default() }, false).await;
        assert_eq!(a.lane_balance(1).await.unwrap(), Some(70), "funded");
        assert_eq!(a.lane_balance(0).await.unwrap(), Some(0), "unfunded");
        net.lock().unwrap().accounts = Some(vec![(one, 1_000), (two, 70)]);
        assert_eq!(a.lane_balance(1).await.unwrap(), Some(70), "no fee bump: the other account pays nothing here");
        net.lock().unwrap().no_entries_result = true;
        assert!(a.lane_balance(1).await.is_err(), "no result is no answer");
        net.lock().unwrap().no_entries_result = false;
        net.lock().unwrap().bare_entry = true;
        assert!(a.lane_balance(1).await.is_err(), "an entry with no xdr is no answer");
        let (a, _, net) = spend_adapter(answer, Net { accounts: Some(vec![(one, 1_000), (two, 70)]), ..Net::default() }, true).await;
        assert_eq!(a.lane_balance(1).await.unwrap(), Some(1_000), "the fee account alone");
        assert_eq!(a.lane_balance(0).await.unwrap(), Some(1_000), "the fee account's own lane");
        net.lock().unwrap().accounts = Some(vec![(two, 70)]);
        assert_eq!(a.lane_balance(1).await.unwrap(), Some(0), "the fee account does not exist");
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec!["http://127.0.0.1:1".into()], lanes: vec![0], ..Default::default() };
        c.params.insert("network_passphrase".into(), "x".into());
        c.params.insert("max_resource_fee_per_job".into(), 1_000_000_000.into());
        c.params.insert("mandate_wasm_hashes".into(), toml::Value::Array(vec![hex(&MANDATE_WASM).into()]));
        assert!(SorobanAdapter::new(&c, &[lane_key(1)]).unwrap().lane_balance(0).await.is_err());
    }

    /// I-1: a funded lane behind an empty fee account takes no job, and sends nothing. The one difference, a funded fee account:
    /// the lane runs.
    #[tokio::test]
    async fn an_empty_fee_account_opens_the_floor_behind_a_funded_lane() {
        let (one, two) = (lane_pk_of(1), lane_pk_of(2));
        let floor = crate::config::BreakerCfg { min_relayer_balance: Some(100), ..Default::default() };
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), Net { accounts: Some(vec![(one, 0), (two, 1_000_000)]), ..Net::default() }, true).await;
        assert_eq!(lane_run(a, 1, floor.clone(), &calls, 300).await, (0, vec![], 0));
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), Net { accounts: Some(vec![(one, 100), (two, 1_000_000)]), ..Net::default() }, true).await;
        assert!(lane_run(a, 1, floor, &calls, 300).await.0 > 0);
    }

    /// The `errorResultXdr` of a refusal.
    fn refusal(result: stellar_xdr::TransactionResultResult) -> String {
        stellar_xdr::TransactionResult { fee_charged: 100, result, ext: stellar_xdr::TransactionResultExt::V0 }.to_xdr_base64(Limits::none()).unwrap()
    }

    /// `txSOROBAN_INVALID` never passes, and the queue is per chain and oldest first: a job back in it would hold every lane. So the
    /// head job goes `dead` on its one claim and the next job runs.
    #[tokio::test]
    async fn soroban_invalid_ends_the_head_job_and_the_next_runs() {
        use crate::adapter::tests::{fake_odoo, Fake};
        for error in [ERROR_SOROBAN_INVALID, ERROR_BUMP_SOROBAN_INVALID] {
            let net = Net { refuses: Some(error.to_string()), tx: json!({"status": "NOT_FOUND"}), ..Net::default() };
            let (a, calls, net) = spend_adapter(registry(vec![], vec![]), net, false).await;
            let jobs = vec![call_of(7), call_of(8)];
            let (odoo, o) = fake_odoo(Fake { jobs, repeat: true, tokens: json!([]), ..Default::default() }).await;
            crate::adapter::lane_step(a.as_ref(), &odoo, 0, "n#0").await.unwrap();
            {
                let mut f = o.lock().unwrap();
                let last = f.reports.last().unwrap();
                assert_eq!((&last["job_id"], &last["chain_state"], f.claims), (&json!(7), &json!("dead"), 1), "{:?}", f.reports);
                assert!(last["error"].as_str().unwrap().contains("sendTransaction ERROR"), "{last}");
                f.jobs.retain(|j| j["id"] != 7);
            }
            *net.lock().unwrap() = Net::default();
            crate::adapter::lane_step(a.as_ref(), &odoo, 0, "n#0").await.unwrap();
            let f = o.lock().unwrap();
            assert_eq!((&f.reports.last().unwrap()["job_id"], &f.reports.last().unwrap()["chain_state"]), (&json!(8), &json!("mined")));
            assert_eq!(sends(&calls), 2);
        }
    }

    /// The one change, another code: what a rebuilt transaction can pass stays `Rejected`, back to the queue, the lane backing off.
    #[tokio::test]
    async fn only_soroban_invalid_is_for_good() {
        use stellar_xdr::TransactionResultResult as R;
        for result in [R::TxBadSeq, R::TxInsufficientFee] {
            let net = Net { refuses: Some(refusal(result)), tx: json!({"status": "NOT_FOUND"}), ..Net::default() };
            let (a, _, _) = spend_adapter(registry(vec![], vec![]), net, false).await;
            let job: Job = serde_json::from_value(call_of(7)).unwrap();
            let signed = a.sign(a.build(&job, 0).await.unwrap(), 0, 1).await.unwrap();
            let e = a.submit(&signed).await.unwrap_err();
            assert!(e.downcast_ref::<Rejected>().is_some() && e.downcast_ref::<crate::adapter::Refused>().is_none(), "{e:#}");
        }
    }

    /// `sendTransaction` answers `ERROR` to every send (`Rejected`, back to the queue, oldest first, so the same job again): the lane
    /// backs off instead of looping at RPC speed, whatever the cause.
    #[tokio::test]
    async fn rejected_send_backs_off() {
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), Net { refuses: Some(refusal(stellar_xdr::TransactionResultResult::TxBadSeq)), tx: json!({"status": "NOT_FOUND"}), ..Net::default() }, false).await;
        let (sent, states, _) = lane_run(a, 0, Default::default(), &calls, 2_500).await;
        assert!((1..=3).contains(&sent), "{sent} sends in 2.5 s");
        assert!(states.contains(&"queued".to_string()), "{states:?}");
    }

    /// The real lane loop on `store_pqz_pop` jobs for `ms`, one job id over and over: what it sent, the states it reported and the claims.
    async fn lane_run(a: Arc<SorobanAdapter>, lane: usize, cfg: crate::config::BreakerCfg, calls: &Arc<Mutex<Vec<String>>>, ms: u64) -> (usize, Vec<String>, u32) {
        use crate::adapter::tests::{fake_odoo, Fake};
        let jobs = vec![json!({"id": 7, "kind": "call", "op": sized_op(8)})];
        let (odoo, o) = fake_odoo(Fake { jobs, repeat: true, tokens: json!([]), ..Default::default() }).await;
        let k = Arc::new(Mutex::new(crate::breaker::Breaker::new(cfg)));
        let run = crate::adapter::lane_runner(a, odoo, lane, "n#0".into(), std::time::Duration::from_millis(10), k, Default::default());
        let _ = tokio::time::timeout(std::time::Duration::from_millis(ms), run).await;
        let f = o.lock().unwrap();
        (sends(calls), f.reports.iter().map(|r| r["chain_state"].as_str().unwrap().to_string()).collect(), f.claims)
    }

    /// The ruling: a lane burned by failing jobs stops. Three FAILED transactions are the budget, with the whole of it open to
    /// `call` jobs here, so the fourth job is never claimed, and each of the three is followed to its report. At the default share
    /// the same `call` jobs stop at two, half the budget being reached. The one difference, no budget: the lane keeps sending.
    #[tokio::test]
    async fn failing_jobs_open_the_budget_and_later_jobs_do_not_send() {
        let failing = || Net { tx: json!({"status": "FAILED", "ledger": 5, "resultXdr": RESULT_FAILED}), ..Net::default() };
        let budget = crate::config::BreakerCfg { gas_budget_per_hour: Some(3 * FAILED_FEE), ..Default::default() };
        let whole = crate::config::BreakerCfg { call_budget_pct: 100, ..budget.clone() };
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), failing(), false).await;
        let (sent, states, claims) = lane_run(a, 0, whole, &calls, 800).await;
        assert_eq!((sent, claims), (3, 3), "{states:?}");
        assert_eq!(states.iter().filter(|s| *s == "reverted").count(), 3, "the jobs in flight end in their reports: {states:?}");

        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), failing(), false).await;
        let (sent, states, claims) = lane_run(a, 0, budget, &calls, 800).await;
        assert_eq!((sent, claims), (2, 2), "{states:?}");

        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), failing(), false).await;
        let (sent, ..) = lane_run(a, 0, Default::default(), &calls, 800).await;
        assert!(sent > 3, "no budget: {sent}");
    }

    /// Under the floor the lane takes no job at all; at the floor it runs, the one difference.
    #[tokio::test]
    async fn balance_floor_stops_the_lane_before_it_sends() {
        let funded = || Net { accounts: Some(vec![(lane_pk_of(1), 100)]), ..Net::default() };
        let floor = |f: u128| crate::config::BreakerCfg { min_relayer_balance: Some(f), ..Default::default() };
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), funded(), false).await;
        assert_eq!(lane_run(a, 0, floor(101), &calls, 300).await, (0, vec![], 0));
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), funded(), false).await;
        let (sent, states, _) = lane_run(a, 0, floor(100), &calls, 300).await;
        assert!(sent > 0 && states.contains(&"mined".to_string()), "{sent} {states:?}");
    }

    /// A `LedgerEntry` of exactly `size` B, as `stateChanges[].after` carries it.
    fn contract_data_after(size: usize) -> String {
        let entry = |n: usize| stellar_xdr::LedgerEntry {
            last_modified_ledger_seq: 7,
            data: LedgerEntryData::ContractData(stellar_xdr::ContractDataEntry {
                ext: stellar_xdr::ExtensionPoint::V0,
                contract: ScAddress::from_str(REGISTRY).unwrap(),
                key: ScVal::Void,
                durability: stellar_xdr::ContractDataDurability::Persistent,
                val: byt(&vec![7; n]),
            }),
            ext: stellar_xdr::LedgerEntryExt::V0,
        };
        let frame = entry(0).to_xdr(Limits::none()).unwrap().len();
        let x = entry(size - frame).to_xdr_base64(Limits::none()).unwrap();
        assert_eq!(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &x).unwrap().len(), size);
        x
    }

    /// A contract's code of `size` B or so: the limit is not code's.
    fn contract_code_after(size: usize) -> String {
        stellar_xdr::LedgerEntry {
            last_modified_ledger_seq: 7,
            data: LedgerEntryData::ContractCode(stellar_xdr::ContractCodeEntry {
                ext: stellar_xdr::ContractCodeEntryExt::V0,
                hash: stellar_xdr::Hash([7; 32]),
                code: vec![7; size].try_into().unwrap(),
            }),
            ext: stellar_xdr::LedgerEntryExt::V0,
        }.to_xdr_base64(Limits::none()).unwrap()
    }

    /// The registry's answers, the write's simulation carrying `changes` (`Null` = a simulation without `stateChanges`).
    fn writes(changes: Value) -> Answer {
        Arc::new(move |c| {
            let mut a = view_ok(if c.function_name.0.as_slice() == b"relayers" { vecv(vec![]) } else { ScVal::Void });
            if !changes.is_null() {
                a["stateChanges"] = changes.clone();
            }
            a
        })
    }

    fn after(entries: &[String]) -> Value {
        entries.iter().map(|x| json!({"type": "updated", "key": "AAAA", "before": null, "after": x})).collect()
    }

    /// One `lane_step` of a `store_pqz_pop` job: what it sent, the states it reported, the claims and the last error.
    async fn entry_step(a: &SorobanAdapter, calls: &Arc<Mutex<Vec<String>>>) -> (usize, Vec<String>, u32, String) {
        use crate::adapter::tests::{fake_odoo, Fake};
        let jobs = vec![json!({"id": 7, "kind": "call", "op": sized_op(8)})];
        let (odoo, o) = fake_odoo(Fake { jobs, tokens: json!([]), ..Default::default() }).await;
        crate::adapter::lane_step(a, &odoo, 0, "n#0").await.unwrap();
        let f = o.lock().unwrap();
        let states: Vec<String> = f.reports.iter().map(|r| r["chain_state"].as_str().unwrap().to_string()).collect();
        (sends(calls), states, f.claims, f.reports.last().unwrap()["error"].as_str().unwrap_or_default().to_string())
    }

    /// Measured on the real host (`e2e_ua8_spend_stop`, `BOUNDARY`): an `after` of the limit lands, 4 B more (XDR's step) fails on
    /// chain, on the lane's fee. So over it is refused here, `dead` on the one claim, nothing sent, and a smaller entry beside it
    /// does not hide it.
    #[tokio::test]
    async fn entry_over_the_limit_is_refused_at_build() {
        let (limit, small) = (ENTRY_MAX as usize, contract_data_after(200));
        let (a, calls, _) = spend_adapter(writes(after(&[small.clone(), contract_data_after(limit + 4)])), Net::default(), false).await;
        let (sent, states, claims, error) = entry_step(&a, &calls).await;
        assert_eq!((sent, states.join(" ").as_str(), claims), (0, "dead", 1));
        assert!(error.contains("contract_data_entry_size_bytes") && error.contains(&format!("({limit})")), "{error}");

        let (a, calls, _) = spend_adapter(writes(after(&[small, contract_data_after(limit)])), Net::default(), false).await;
        let (sent, states, ..) = entry_step(&a, &calls).await;
        assert_eq!((sent, states.last().map(String::as_str)), (1, Some("mined")), "exactly the limit runs");
    }

    /// The check only saves a fee, and the chain still refuses: what it cannot read lets the job through, never stops it.
    #[tokio::test]
    async fn entry_check_never_stops_a_job_on_what_it_cannot_read() {
        let over = contract_data_after(ENTRY_MAX as usize + 4);
        for (changes, net, why) in [
            (Value::Null, Net::default(), "no stateChanges"),
            (json!([{"type": "deleted", "key": "AAAA", "before": "AAAA", "after": null}]), Net::default(), "no after"),
            (after(&["not xdr".to_string()]), Net::default(), "an after that does not decode"),
            (after(&[contract_code_after(ENTRY_MAX as usize + 4)]), Net::default(), "code, not data"),
            (after(std::slice::from_ref(&over)), Net { entry_limit: None, ..Net::default() }, "the limit never read"),
        ] {
            let (a, calls, _) = spend_adapter(writes(changes), net, false).await;
            let (sent, states, ..) = entry_step(&a, &calls).await;
            assert_eq!((sent, states.last().map(String::as_str)), (1, Some("mined")), "{why}");
        }
        // as `tx_max_size_bytes`: a failed read keeps the last answer, a voted change is seen on the next good read
        let (a, calls, net) = spend_adapter(writes(after(&[over])), Net { entry_limit: Some(70_000), ..Net::default() }, false).await;
        assert_eq!(entry_step(&a, &calls).await.0, 1, "under this limit");
        net.lock().unwrap().entry_limit = Some(ENTRY_MAX);
        let (sent, states, ..) = entry_step(&a, &calls).await;
        assert_eq!((sent, states.join(" ").as_str()), (1, "dead"), "the voted limit");
        net.lock().unwrap().entry_limit = None;
        let (sent, states, ..) = entry_step(&a, &calls).await;
        assert_eq!((sent, states.join(" ").as_str()), (1, "dead"), "the read fails, the last answer holds");
    }

    /// B6's rule through the real step: a `relayers()` read that fails stops no payment.
    #[tokio::test]
    async fn a_payment_runs_while_relayers_read_fails() {
        use crate::adapter::tests::{fake_odoo, Fake};
        let (a, calls) = ua8_adapter(Arc::new(|c| match c.function_name.0.as_slice() {
            b"relayers" => json!({}),
            _ => view_ok(ScVal::Void),
        })).await;
        a.start_check().await.unwrap();
        let pay = json!({"payload": payload(inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": crate::submit::now() + 600, "extra": {}});
        let (odoo, o) = fake_odoo(Fake { jobs: vec![json!({"id": 7, "kind": "signed_op", "op": pay})], tokens: json!([]), ..Default::default() }).await;
        crate::adapter::lane_step(&a, &odoo, 0, "n#0").await.unwrap();
        let states: Vec<String> = o.lock().unwrap().reports.iter().map(|r| r["chain_state"].as_str().unwrap().to_string()).collect();
        assert_eq!(states, ["signed", "broadcast", "mined"]);
        assert_eq!(sends(&calls), 1);
    }

    // ---- the `call` share of the budget (owner ruling I-2)

    const BUDGET: u128 = 1_000_000_000;

    fn call_of(id: i64) -> Value {
        json!({"id": id, "kind": "call", "op": sized_op(8)})
    }

    /// A payment: a UA pay, which runs to the whole budget.
    fn pay_of(_: &SorobanAdapter, id: i64) -> Value {
        let (c, f, args) = ua_ops(ScVal::Void).remove(1);
        json!({"id": id, "kind": "ua_metatx", "op": ua_op(c, f, args)})
    }

    fn spent_lane(spent: u128, pct: u8) -> Mutex<crate::breaker::Breaker> {
        let mut k = crate::breaker::Breaker::new(crate::config::BreakerCfg { gas_budget_per_hour: Some(BUDGET), call_budget_pct: pct, ..Default::default() });
        k.spend(crate::submit::now(), spent);
        Mutex::new(k)
    }

    /// One real `lane_step` over `jobs` in queue order: the jobs it reported and how many it claimed.
    async fn budget_step(a: &SorobanAdapter, k: &Mutex<crate::breaker::Breaker>, jobs: Vec<Value>) -> (Vec<i64>, u32) {
        use crate::adapter::tests::{fake_odoo, Fake};
        let (odoo, o) = fake_odoo(Fake { jobs, repeat: true, tokens: json!([]), ..Default::default() }).await;
        crate::adapter::lane_step_metered(a, &odoo, 0, "n#0", Some(k)).await.unwrap();
        let f = o.lock().unwrap();
        let mut ids: Vec<i64> = f.reports.iter().map(|r| r["job_id"].as_i64().unwrap()).collect();
        ids.dedup();
        (ids, f.claims)
    }

    /// Under the share a `call` job at the head runs; at it the `call` job is not claimed and the payment behind it runs; at the
    /// whole budget neither runs; the next window reopens both.
    #[tokio::test]
    async fn call_jobs_stop_at_their_share_and_payments_run_to_the_budget() {
        let (a, calls, _) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        let jobs = vec![call_of(7), pay_of(&a, 8)];
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2 - 1, 50), jobs.clone()).await, (vec![7], 1), "one stroop under the share");
        assert_eq!(sends(&calls), 1);
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), jobs.clone()).await, (vec![8], 1), "at the share");
        assert_eq!(sends(&calls), 2);
        assert_eq!(budget_step(&a, &spent_lane(BUDGET - 1, 50), jobs.clone()).await, (vec![8], 1), "a payment runs to the budget");
        assert_eq!(sends(&calls), 3);
        let spent = spent_lane(BUDGET, 50);
        assert_eq!(budget_step(&a, &spent, jobs.clone()).await, (vec![], 0), "at the budget neither runs");
        assert_eq!(sends(&calls), 3);
        spent.lock().unwrap().rewind();
        assert_eq!(budget_step(&a, &spent, jobs).await, (vec![7], 1), "the next window reopens both");
        assert_eq!(sends(&calls), 4);
    }

    /// The share is the named value, not a constant.
    #[tokio::test]
    async fn the_call_share_is_configured() {
        let (a, _, _) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        let jobs = vec![call_of(7), pay_of(&a, 8)];
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 4, 25), jobs.clone()).await.0, [8]);
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 4, 26), jobs).await.0, [7]);
    }

    /// `relay_poll` is oldest first: a payment behind a queue of stopped `call` jobs must still be seen.
    #[tokio::test]
    async fn stopped_calls_at_the_head_do_not_hide_a_payment() {
        let (a, _, _) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        let mut jobs: Vec<Value> = (0..20).map(call_of).collect();
        jobs.push(pay_of(&a, 99));
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), jobs).await, (vec![99], 1));
    }

    /// The limit of the legacy pull path, pinned: the client clamps `relay_poll` at 50, so a payment behind 50 stopped `call` jobs is
    /// not seen on this path, across windows while the backlog lasts. The node's own queue claims by kind (NODE-JOB-21).
    #[tokio::test]
    async fn a_backlog_over_the_read_hides_a_payment_on_the_pull_path() {
        let (a, _, _) = spend_adapter(registry(vec![], vec![]), Net::default(), false).await;
        let mut jobs: Vec<Value> = (0..49).map(call_of).collect();
        jobs.push(pay_of(&a, 99));
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), jobs.clone()).await, (vec![99], 1), "the 50th job is read");
        jobs.insert(0, call_of(100));
        assert_eq!(budget_step(&a, &spent_lane(BUDGET / 2, 50), jobs).await, (vec![], 0), "the 51st is not");
    }

    // ---- RV, the whole-branch review: each proof of a defect, turned into the rule it broke

    fn void_answer() -> Answer {
        Arc::new(|_| json!({"transactionData": data(100, &[]), "results": [{"xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(), "auth": []}]}))
    }

    /// The row of `f` in `ua_ops`, its relayer `None`, on `contract`.
    fn ua_row(contract: &str, f: &str) -> Value {
        let (_, f, args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == f).unwrap();
        json!({"id": 7, "kind": "ua_metatx", "op": ua_op(contract, f, args)})
    }

    fn as_job(j: &Value) -> Job {
        serde_json::from_value(j.clone()).unwrap()
    }

    /// A `signed_op`'s deadline nothing the node reads signs: `0` is no `max_time` on chain, while `follow` would read it as long past and
    /// report `dead` with the transaction in flight. Refused before anything is sent, with the past and the over-long; the same job
    /// with a deadline in the bound goes.
    #[tokio::test]
    async fn a_signed_op_deadline_is_bounded() {
        let (a, calls, _) = spend_adapter(void_answer(), Net::default(), false).await;
        for v in [json!(0), json!(1), json!(crate::submit::now() + max_valid_for() + 60)] {
            let mut j = signed_on(7, CONTRACT, "pay");
            j["op"]["valid_until"] = v.clone();
            let (sent, state, why) = job_step(&a, &calls, j).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "{v}: {why}");
            assert!(why.contains("not within"), "{v}: {why}");
        }
        assert_eq!(job_step(&a, &calls, signed_on(7, CONTRACT, "pay")).await.1, "mined");
    }

    /// A signed deadline already past is refused at `build`: on one claim `dead`, unsent. Sent, `txTOO_LATE` is `Rejected`, and the job
    /// came back to the queue on every claim, holding the chain's queue.
    #[tokio::test]
    async fn a_past_deadline_ends_on_one_claim() {
        let net = Net { refuses: Some(refusal(stellar_xdr::TransactionResultResult::TxTooLate)), ..Net::default() };
        let (a, calls, _) = spend_adapter(void_answer(), net, false).await;
        let (c, f, mut args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == "ua_transfer").unwrap();
        args[5] = u64v(crate::submit::now() - 1);
        let (sent, state, why) = job_step(&a, &calls, json!({"id": 7, "kind": "ua_metatx", "op": ua_op(c, f, args)})).await;
        assert_eq!((sent, state.as_str()), (0, "dead"), "{why}");
        assert!(why.contains("expired before inclusion"), "{why}");
    }

    /// A lost transaction holds its lane to `max_time`, so a client's deadline only narrows the bound: `max_time` is the shorter of the two,
    /// `follow` reads the same value, and after a restart the bound holds too.
    #[tokio::test]
    async fn a_lost_transaction_holds_the_lane_for_the_bound_at_most() {
        let (a, _, _) = spend_adapter(void_answer(), Net::default(), false).await;
        let (c, f, mut args) = ua_ops(ScVal::Void).into_iter().find(|o| o.1 == "ua_transfer").unwrap();
        let (now, max) = (crate::submit::now(), max_valid_for());
        for signed in [now + 60, now + max + 60, u64::MAX] {
            args[5] = u64v(signed);
            let job = ua_job(c, f, args.clone());
            let built = a.build(&job, 0).await.unwrap();
            let Preconditions::Time(t) = Transaction::from_xdr(&built.body, Limits::none()).unwrap().cond else { panic!("no time bounds") };
            assert_eq!(t.max_time.0, built.valid_until);
            assert!(built.valid_until == signed.min(built.valid_until) && built.valid_until <= crate::submit::now() + max, "{signed}");
            assert!(signed > now + max || built.valid_until == signed, "{signed}: a deadline in the bound stays");
            assert!(a.job_valid_until(&job) <= crate::submit::now() + max && a.job_valid_until(&job) >= built.valid_until, "{signed}");
        }
    }

    /// A contract that answers none of the views: not a failed read, so `dead` on one claim, not `queued` for ever at the head of the chain's
    /// queue. All four views of `op_consumed`, by ref, `owner()`, `ua_nonce` and the token's.
    #[tokio::test]
    async fn a_view_the_host_refuses_is_unknown() {
        let answer: Answer = Arc::new(|_| json!({"error": "HostError: Error(Storage, MissingValue)"}));
        let (a, calls, _) = spend_adapter(answer, Net::default(), false).await;
        for (c, f) in [(WALLET2, "mtx_mandate_pay"), (WALLET2, "mtx_set_payee"), (CONTRACT, "ua_transfer"), (CONTRACT, "ua_pay")] {
            let job = ua_row(c, f);
            assert_eq!(a.op_consumed(&as_job(&job)).await.unwrap(), None, "{f}");
            let (sent, state, why) = job_step(&a, &calls, job).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "{f}: {why}");
        }
    }

    /// A failed read stays a failed read, a job back in the queue: only the host's refusal is an answer.
    #[tokio::test]
    async fn a_failed_view_read_is_not_unknown() {
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec!["http://127.0.0.1:1".into()], lanes: vec![0], ..Default::default() };
        c.params.insert("network_passphrase".into(), "x".into());
        let down = SorobanAdapter::new(&c, &[lane_key(1)]).unwrap();
        assert!(down.view_or_unknown(&sc(CONTRACT), "paid", vec![]).await.is_err());
    }

    /// The lane account gone after the claim: `queued` and a retry, as a transport failure in `build`. The job never stays claimed with no report.
    #[tokio::test]
    async fn a_failed_sequence_read_puts_the_claimed_job_back() {
        use crate::adapter::tests::{fake_odoo, Fake};
        let (a, calls, _) = spend_adapter(void_answer(), Net { accounts: Some(vec![]), ..Net::default() }, false).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![signed_on(7, CONTRACT, "pay")], tokens: json!([]), ..Default::default() }).await;
        let step = crate::adapter::step_once(a.as_ref(), &odoo, 0, "n#0", None, &Default::default()).await.unwrap();
        assert!(matches!(step, crate::adapter::Step::Retry(ref why) if why.contains("does not exist")));
        let f = o.lock().unwrap();
        assert_eq!((f.claims, sends(&calls)), (1, 0));
        assert_eq!(f.reports.iter().map(|r| r["chain_state"].as_str().unwrap()).collect::<Vec<_>>(), ["queued"]);
    }

    /// `ua_metatx` with no `op.auth` whose simulation records a native holder's authority: the transaction can only fail on chain, on the
    /// lane's fee, so it is refused unsent, as a registry write. The same job with the holder's entry in `op.auth` goes.
    #[tokio::test]
    async fn a_ua_metatx_missing_a_native_signer_is_refused_unsent() {
        let root = inv(WALLET, "mtx_set_payee", vec![], vec![]);
        let signer = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials { address: sc(FROM), nonce: 1, signature_expiration_ledger: 1, signature: ScVal::Void }),
            root_invocation: root,
        };
        let e = signer.to_xdr_base64(Limits::none()).unwrap();
        let answer: Answer = Arc::new(move |_| json!({"results": [{"xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(), "auth": [e]}], "transactionData": data(100, &[])}));
        let (a, calls, _) = spend_adapter(answer, Net::default(), false).await;
        let job = ua_row(WALLET, "mtx_set_payee");
        let (sent, state, why) = job_step(&a, &calls, job.clone()).await;
        assert_eq!((sent, state.as_str()), (0, "dead"), "{why}");
        assert!(why.contains("another account's signature"), "{why}");
        let mut signed = job;
        signed["op"]["auth"] = json!([{"payload": payload(inv(WALLET, "mtx_set_payee", vec![], vec![])), "from": FROM, "signature": sig()}]);
        assert_eq!(job_step(&a, &calls, signed).await.0, 1, "its entry carried");
    }

    /// Owner 2026-11-02: a free `mtx_*` job runs past the `call` share, so it runs only listed code, read from the instance through the host.
    /// Another Wasm, no instance and a built-in contract are `MANDATE_WASM_REFUSED`, `dead`, nothing simulated. A failed read goes back to
    /// the queue. The listed Wasm goes.
    #[tokio::test]
    async fn a_ua_metatx_runs_only_a_listed_mandate_wasm() {
        let (a, calls, net) = spend_adapter(void_answer(), Net::default(), false).await;
        assert!(!a.in_call_share(&as_job(&ua_row(WALLET2, "mtx_set_payee"))), "past the share: why this list exists");
        for e in [Some(ContractExecutable::Wasm(Hash([8; 32]))), None, Some(ContractExecutable::StellarAsset)] {
            net.lock().unwrap().executable = e.clone();
            let (sent, state, why) = job_step(&a, &calls, ua_row(WALLET2, "mtx_set_payee")).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "{e:?}: {why}");
            assert!(why.contains(MANDATE_WASM_REFUSED), "{e:?}: {why}");
        }
        assert_eq!(logged(&calls), Vec::<String>::new(), "nothing simulated");
        net.lock().unwrap().executable = Some(ContractExecutable::Wasm(Hash(MANDATE_WASM)));
        net.lock().unwrap().no_entries_result = true;
        assert_eq!(job_step(&a, &calls, ua_row(WALLET2, "mtx_set_payee")).await.1, "queued", "a failed read is no refusal");
        net.lock().unwrap().no_entries_result = false;
        assert_eq!(job_step(&a, &calls, ua_row(WALLET2, "mtx_set_payee")).await.0, 1);
    }

    /// A contract with code nobody listed answers what it likes: its `paid` is never `consumed`, the job's own answer stays unknown.
    #[tokio::test]
    async fn an_unlisted_mandate_never_reports_consumed() {
        let (a, _, net) = spend_adapter(Arc::new(|_| view_ok(ScVal::Bool(true))), Net::default(), false).await;
        let job = as_job(&ua_row(WALLET2, "mtx_mandate_pay"));
        assert_eq!(a.op_consumed(&job).await.unwrap(), Some(true), "listed: its answer counts");
        net.lock().unwrap().executable = Some(ContractExecutable::Wasm(Hash([8; 32])));
        assert_eq!(a.op_consumed(&job).await.unwrap(), None);
    }

    /// Owner 2026-11-03: a listed mandate calls the `token` its job names, so a free `mtx_*` names a token the chain registers, or code nobody
    /// listed runs inside the job. Every mandate function, one change from a job that goes: `TOKEN_NOT_SERVED`, `dead`, nothing simulated.
    /// `op_consumed` holds the same rule: that token's `paid` is never `consumed`.
    #[tokio::test]
    async fn a_mandate_job_names_a_registered_token() {
        let on = |f: &str, token: &str| {
            let mut j = ua_row(WALLET2, f);
            j["op"]["args"]["token"] = json!(token);
            j
        };
        let (a, calls, _) = spend_adapter(void_answer(), Net::default(), false).await;
        for f in UA_FNS.iter().filter(|f| f.class == Class::Mandate) {
            assert_eq!(f.args[0], ("token", "Address"), "{}: read as a token", f.name);
            assert_eq!(job_step(&a, &calls, on(f.name, CONTRACT)).await.0, 1, "{}: a registered token goes", f.name);
            logged(&calls);
            let (sent, state, why) = job_step(&a, &calls, on(f.name, WALLET)).await;
            assert_eq!((sent, state.as_str()), (0, "dead"), "{}: {why}", f.name);
            assert!(why.contains(TOKEN_NOT_SERVED), "{}: {why}", f.name);
            assert_eq!(logged(&calls), Vec::<String>::new(), "{}: nothing simulated", f.name);
        }
        let (a, _, _) = spend_adapter(Arc::new(|_| view_ok(ScVal::Bool(true))), Net::default(), false).await;
        assert_eq!(a.op_consumed(&as_job(&on("mtx_mandate_pay", CONTRACT))).await.unwrap(), Some(true), "registered: its answer counts");
        assert_eq!(a.op_consumed(&as_job(&on("mtx_mandate_pay", WALLET))).await.unwrap(), None);
    }

    #[test]
    fn mandate_wasm_hashes_are_a_list_of_hashes() {
        let cfg = |v: toml::Value| {
            let mut c = ChainCfg::default();
            c.params.insert("mandate_wasm_hashes".into(), v);
            c
        };
        let good = RelayFeePolicy::from_cfg(&cfg(toml::Value::Array(vec![hex(&MANDATE_WASM).into()]))).unwrap();
        assert_eq!(good.mandate_wasms, [MANDATE_WASM]);
        assert!(RelayFeePolicy::from_cfg(&ChainCfg::default()).unwrap().mandate_wasms.is_empty(), "unset: none");
        for bad in [toml::Value::from("00"), toml::Value::Array(vec!["0011".into()]), toml::Value::Array(vec!["zz".into()]), toml::Value::Array(vec![7.into()])] {
            assert!(format!("{:#}", RelayFeePolicy::from_cfg(&cfg(bad.clone())).err().expect("accepted")).contains("mandate_wasm_hashes"), "{bad}");
        }
    }

    /// NET-SOR-22's cap: what the job declares, margin included, up to the cap and not a stroop past it; on a restore as well. Unset, nothing goes.
    #[tokio::test]
    async fn a_job_over_the_resource_fee_cap_is_refused_unsent() {
        const AT_CAP: i64 = 869_565_218; // 15 % on top is the test chain's cap, 1,000,000,000
        let fee = Arc::new(Mutex::new(AT_CAP));
        let f = fee.clone();
        let answer: Answer = Arc::new(move |_| json!({"transactionData": data(*f.lock().unwrap(), &[]), "results": [{"xdr": ScVal::Void.to_xdr_base64(Limits::none()).unwrap(), "auth": []}]}));
        let (a, calls, _) = spend_adapter(answer.clone(), Net::default(), false).await;
        assert_eq!(job_step(&a, &calls, signed_on(7, CONTRACT, "pay")).await.0, 1, "at the cap");
        *fee.lock().unwrap() = AT_CAP + 1;
        let (sent, state, why) = job_step(&a, &calls, signed_on(7, CONTRACT, "pay")).await;
        assert_eq!((sent, state.as_str()), (0, "dead"), "{why}");
        assert!(why.contains(RESOURCE_FEE_OVER_CAP), "{why}");
        *fee.lock().unwrap() = 1;
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: a.rpc.clone(), lanes: vec![0], ..Default::default() };
        c.tokens = vec![crate::config::TokenCfg { address: CONTRACT.into(), decimals: 7 }];
        c.params.insert("network_passphrase".into(), "x".into());
        let unset = SorobanAdapter::new(&c, &[lane_key(1)]).unwrap();
        assert!(job_step(&unset, &calls, signed_on(7, CONTRACT, "pay")).await.2.contains(RESOURCE_FEE_OVER_CAP), "unset: fail closed");
    }

    /// Owner 2026-11-02: the registered tokens are the client's, re-read as EVM's: a token added after the start is served with no restart,
    /// one dropped is refused, and the config's list only stands until the first answer.
    #[tokio::test]
    async fn a_token_registered_after_the_start_is_served() {
        use crate::adapter::tests::{fake_odoo, Fake};
        let (a, calls, _) = spend_adapter(void_answer(), Net::default(), false).await;
        let (sent, _, why) = job_step(&a, &calls, signed_on(7, WALLET2, "pay")).await;
        assert_eq!(sent, 0);
        assert!(why.contains(CALL_TARGET_REFUSED), "{why}");
        let (odoo, _) = fake_odoo(Fake { tokens: json!([{"address": WALLET2, "decimals": 7}]), ..Default::default() }).await;
        crate::adapter::recover_lane(a.as_ref(), &odoo, 0, "n#0").await.unwrap();
        assert_eq!(job_step(&a, &calls, signed_on(7, WALLET2, "pay")).await.0, 1);
        assert!(job_step(&a, &calls, signed_on(7, CONTRACT, "pay")).await.2.contains(CALL_TARGET_REFUSED), "no longer the client's");
    }

    /// A `u64` is a decimal string past 2^53 here too: `set_kem_key`'s `version`, as `ua_value`'s every other.
    #[test]
    fn a_kem_version_may_be_a_decimal_string() {
        let row = ops(&NONE).into_iter().find(|o| o["function"] == "set_kem_key").unwrap();
        let mut op = row.clone();
        op["args"]["version"] = json!("18446744073709551615");
        let Ua8Write::SetKem(k) = ua8_write(&op).unwrap().0 else { panic!() };
        assert_eq!(k.version, u64::MAX);
        op["args"]["version"] = json!("0x01");
        assert!(ua8_write(&op).is_err());
        assert!(ua8_write(&row).is_ok(), "a number stays one");
    }

    /// A proof already stored: a no-op on chain, on the lane's fee, so unsent. No proof stored, or no bytes in the answer: the simulation decides.
    #[tokio::test]
    async fn store_pqz_pop_over_a_stored_proof_is_refused_unsent() {
        let base = registry(vec![], vec![]);
        let stored = Arc::new(Mutex::new(byt(&[1])));
        let s = stored.clone();
        let reply: Answer = Arc::new(move |c| if c.function_name.0.as_slice() == b"pqz_pop_of" { view_ok(s.lock().unwrap().clone()) } else { base(c) });
        let (a, calls) = ua8_adapter(reply).await;
        let op = ops(&NONE).remove(7);
        assert_eq!(op["function"], "store_pqz_pop");
        refused(run(&a, &op).await, "already stored");
        assert_eq!(logged(&calls), ["pqz_pop_of"], "never simulated, never sent");
        for answer in [byt(&[]), ScVal::Void] {
            *stored.lock().unwrap() = answer;
            run(&a, &op).await.unwrap();
            assert_eq!(logged(&calls), ["pqz_pop_of", "store_pqz_pop", "SEND"]);
        }
    }

    /// A re-run acceptance: the slot holds one, so the job is `consumed`, the op done, not `dead` as a job that failed.
    #[tokio::test]
    async fn a_re_run_acceptance_is_consumed() {
        let base = registry(vec![addr(&stub_lane())], classical());
        let reply: Answer = Arc::new(move |c| if c.function_name.0.as_slice() == b"member_accepted" { view_ok(ScVal::Bool(true)) } else { base(c) });
        let (a, calls) = ua8_adapter(reply).await;
        let job = json!({"id": 7, "kind": "ua_metatx", "op": accept_op(membership("msig-classical/0"), &NONE)});
        let (sent, state, why) = job_step(&a, &calls, job).await;
        assert_eq!((sent, state.as_str()), (0, "consumed"), "{why}");
    }

    /// `record_of` over the read bound is what this record answers, for good: `Revert`. As `Transport` the job came back to the queue for ever.
    #[tokio::test]
    async fn a_record_over_the_read_bound_is_the_jobs_answer() {
        let (a, _) = ua8_adapter(Arc::new(|_| view_ok(byt(&vec![7; 1 << 16])))).await;
        let e = a.ua8_record(&sc(REGISTRY), &UA).await.unwrap_err();
        assert!(matches!(e, SimError::Revert(ref r) if r.contains("read bound")), "{e:?}");
    }

    /// What an RPC answers is bounded by depth, as what a job puts in: `Limits::len` alone would overflow the stack and abort the node.
    #[test]
    fn deep_xdr_from_an_rpc_is_refused_not_a_stack_overflow() {
        // `SorobanTransactionData`: no ext, a read-only footprint of one `ContractData` key, that key a `Vec` in a `Vec` …
        let mut x = [0u32.to_be_bytes(), 1u32.to_be_bytes(), 6u32.to_be_bytes(), 1u32.to_be_bytes()].concat();
        x.extend_from_slice(&[0; 32]);
        x.extend_from_slice(&deep_xdr(20_000));
        let x = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, x);
        let e = sim_data(&json!({"transactionData": x}), 0).unwrap_err();
        assert!(matches!(e, SimError::Transport(ref r) if r.to_lowercase().contains("depth")), "{e:?}");
    }
}
