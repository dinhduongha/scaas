//! Stellar Soroban (R65). Meta-tx cấp contract = authorization gốc: chủ thể đã ký
//! `HashIdPreimage::SorobanAuthorization` (Odoo dựng); adapter đặt chữ ký vào `SorobanAuthorizationEntry` của một tx
//! mà **lane account** là source (sequence riêng của lane, trả phí) — chủ thể không có sequence trong đường đi (R30).
//! Nonce auth là ngẫu nhiên (host ghi cặp (địa chỉ, nonce) đã dùng) ⇒ không head-of-line (R62).
//! Tuỳ chọn fee-bump (CAP-15): `params.fee_bump_lane = i` ⇒ account của lane `i` trả phí cho mọi lane.
//! Thiết kế: `docs/history/specs/2026-10-03-net-soroban.md`.
//! UA-Soroban (spec `2026-10-30-ua-soroban-design.md` §8, §9): `ua_metatx` jobs (`ua_metatx_job`), the lane-authority
//! rule (`check_recorded_auth`), Protocol 23 auto-restore within `params.max_deposit_per_job` (`sim_data`), UA events.
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, DecoratedSignature, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
    FeeBumpTransactionInnerTx, HashIdPreimage, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerEntryData,
    LedgerKey, LedgerKeyAccount, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    ReadXdr, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, SequenceNumber, Signature, SignatureHint,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    SorobanTransactionData, SorobanTransactionDataExt, TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, WriteXdr,
};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{stellar_account_strkey, LocalSigner, Signer};

const DEFAULT_BASE_FEE: u32 = 100;
/// Biên cho resource fee mô phỏng (trạng thái có thể đổi giữa mô phỏng và thực thi).
const RESOURCE_FEE_MARGIN_PCT: i64 = 15;
/// `getEvents`: tối đa 5 contract mỗi bộ lọc.
const CONTRACTS_PER_FILTER: usize = 5;
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
    hashes: Mutex<HashMap<u64, String>>,
}

fn hex(b: &[u8]) -> String {
    alloy::hex::encode(b)
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    Ok(alloy::hex::decode(s.trim())?)
}

pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

fn lane_pk(s: &LocalSigner) -> Result<[u8; 32]> {
    s.public_key().try_into().map_err(|_| anyhow!("soroban lanes are ed25519"))
}

/// Chữ ký trong credentials: account `G…` ⇒ `Vec[Map{public_key, signature}]` (định dạng account gốc của host);
/// account contract `C…` ⇒ ScVal XDR (hex) mà `__check_auth` của nó đọc, chèn nguyên văn.
pub fn credential_signature(from: &ScAddress, signature: &str) -> Result<ScVal> {
    let sig = unhex(signature)?;
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
        ScAddress::Contract(_) => Ok(ScVal::from_xdr(&sig, Limits::len(8192))?),
        _ => bail!("unsupported signer address"),
    }
}

/// Một chữ ký chủ thể ⇒ auth entry. Kiểm network id (chặn payload mạng khác trước khi tốn phí).
pub fn auth_entry(network: &[u8; 32], payload: &str, from: &str, signature: &str) -> Result<(SorobanAuthorizationEntry, InvokeContractArgs)> {
    let bytes = unhex(payload)?;
    let HashIdPreimage::SorobanAuthorization(p) = HashIdPreimage::from_xdr(&bytes, Limits::len(bytes.len() + 64))?
    else {
        bail!("payload is not a Soroban authorization preimage");
    };
    if p.network_id.0 != *network {
        bail!("payload signed for another network");
    }
    let SorobanAuthorizedFunction::ContractFn(call) = &p.invocation.function else {
        bail!("payload does not invoke a contract function");
    };
    let address = ScAddress::from_str(from).map_err(|_| anyhow!("bad subject address {from}"))?;
    let signature = credential_signature(&address, signature)?;
    let call = call.clone();
    Ok((
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address,
                nonce: p.nonce,
                signature_expiration_ledger: p.signature_expiration_ledger,
                signature,
            }),
            root_invocation: p.invocation,
        },
        call,
    ))
}

/// Lời gọi host + auth entry từ op `signed_op`. Mặc định lời gọi = invocation chủ thể đã ký; `extra.call` (XDR hex
/// `InvokeContractArgs`) + `extra.auth` (chữ ký bổ sung) cho thao tác nhiều bên như DEX `settle` (R8-5).
pub fn host_call(network: &[u8; 32], op: &Value) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let s = |v: &Value, k: &str| v[k].as_str().map(str::to_owned).ok_or_else(|| anyhow!("op.{k} missing"));
    let (main, signed) = auth_entry(network, &s(op, "payload")?, &s(op, "from")?, &s(op, "signature")?)?;
    let contract = ScAddress::from_str(&s(op, "contract")?).map_err(|_| anyhow!("bad contract"))?;
    let mut auth = vec![main];
    for a in op["extra"]["auth"].as_array().into_iter().flatten() {
        auth.push(auth_entry(network, &s(a, "payload")?, &s(a, "from")?, &s(a, "signature")?)?.0);
    }
    let call = match op["extra"]["call"].as_str() {
        Some(x) => InvokeContractArgs::from_xdr(unhex(x)?, Limits::len(65_536))?,
        None => signed,
    };
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
        .map(|t| ScVal::from_xdr_base64(t.as_str()?, Limits::len(4096)).ok())
        .collect::<Option<_>>()?;
    let value = ScVal::from_xdr_base64(ev["value"].as_str()?, Limits::len(4096)).ok()?;
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
            max_deposit: match p.get("max_deposit_per_job") {
                None => 0,
                Some(v) => v.as_integer().and_then(|n| u64::try_from(n).ok()).ok_or_else(|| {
                    anyhow!("chain {}: params.max_deposit_per_job must be a non-negative integer (stroops), not {v}", cfg.chain_key())
                })?,
            },
            hashes: Mutex::new(HashMap::new()),
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

    /// A read-only call by simulation from lane 0; `None` = it needs a restore (an archived entry): unknown, never a
    /// default value. A simulation error is an `Err` (fail closed): `SimRefused` when the host refused the call.
    async fn view(&self, contract: &ScAddress, f: &str, args: Vec<ScVal>) -> Result<Option<ScVal>> {
        let call = InvokeContractArgs { contract_address: contract.clone(), function_name: ScSymbol(f.try_into()?), args: args.try_into()? };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope { tx: self.tx(0, 0, 0, call, vec![])?, signatures: Default::default() });
        let sim = self.rpc("simulateTransaction", json!({"transaction": env.to_xdr_base64(Limits::none())?})).await?;
        if let Some(e) = sim.get("error").and_then(|e| e.as_str()) {
            return Err(SimRefused(format!("{f}: {e}")).into());
        }
        if sim.get("restorePreamble").is_some_and(|r| !r.is_null()) {
            return Ok(None);
        }
        if let Some(d) = sim["transactionData"].as_str() {
            if restores(&SorobanTransactionData::from_xdr_base64(d, Limits::len(1 << 20))?) {
                return Ok(None);
            }
        }
        let x = sim["results"][0]["xdr"].as_str().ok_or_else(|| anyhow!("{f}: simulation without a result"))?;
        Ok(Some(ScVal::from_xdr_base64(x, Limits { depth: 64, len: 1 << 16 })?))
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

/// `simulateTransaction` answered `error`: the host refused the call (not a transport failure).
#[derive(Debug)]
struct SimRefused(String);

impl std::fmt::Display for SimRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SimRefused {}

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
        let (call, auth, valid_until) = job_tx(&self.network_id, job.kind.as_deref(), &op, &lane_addr, &self.relay_fee).map_err(rv)?;
        let tx = self.tx(lane, 0, valid_until, call.clone(), auth).map_err(rv)?;
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
        check_recorded_auth(&sim, &call).map_err(rv)?;
        let mut tx = tx;
        tx.fee = u32::try_from(self.base_fee as i64 + data.resource_fee).map_err(|_| SimError::Revert("fee overflow".into()))?;
        tx.ext = TransactionExt::V1(data);
        let body = tx.to_xdr(Limits::none()).map_err(|e| SimError::Revert(e.to_string()))?;
        Ok(Built { job_id: job.id, body, valid_until, meta: json!({}) })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let mut tx = Transaction::from_xdr(&built.body, Limits::none())?;
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
        let env = TransactionEnvelope::from_xdr(&signed.raw, Limits::none())?;
        let r = self.rpc("sendTransaction", json!({"transaction": env.to_xdr_base64(Limits::none())?})).await?;
        match r["status"].as_str() {
            Some("PENDING") | Some("DUPLICATE") => Ok(()),
            // ERROR = CheckTx-equivalent refusal (bad seq/auth/fee/malformed): the same bytes never pass ⇒ rebuild.
            // TRY_AGAIN_LATER (queue full) and transport errors stay retryable.
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

    async fn sequence(&self, lane: usize) -> Result<u64> {
        let account = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(lane_pk(self.signer(lane)?)?)));
        let k = LedgerKey::Account(LedgerKeyAccount { account_id: account }).to_xdr_base64(Limits::none())?;
        let r = self.rpc("getLedgerEntries", json!({"keys": [k]})).await?;
        let x = r["entries"][0]["xdr"].as_str().ok_or_else(|| anyhow!("lane {} account does not exist", self.lanes[lane].address))?;
        match LedgerEntryData::from_xdr_base64(x, Limits::len(1 << 16))? {
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

    /// R80 for `ua_metatx` jobs (spec §9.3, NET-SOR-12): a pay ref spent (`ua_ref_used(ua, pay_ref)` on the token; the
    /// mandate's `paid(pay_ref)`), or the UA's lane past the job's nonce (`ua_nonce(ua, lane) > nonce`; a mandate owner
    /// entry reads `owner()` first). A view that needs a restore, a native signer, or a job without a lane is unknown.
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
        let b32 = |b: [u8; 32]| -> Result<ScVal> { Ok(ScVal::Bytes(b.to_vec().try_into()?)) };
        let by_ref = match f.name {
            "ua_pay" => Some((c.clone(), "ua_ref_used", vec![a[0].clone(), a[3].clone()])),
            "ua_pay_meta" => {
                let (Some(salt), Some(meta)) = (bytes_arg(&a[3]), bytes_arg(&a[4])) else { return Ok(None) };
                Some((c.clone(), "ua_ref_used", vec![a[0].clone(), b32(meta_pay_id(salt, meta))?]))
            }
            "ua_relay" => {
                let ScVal::Address(token) = &a[5] else { return Ok(None) };
                if !self.relay_fee.tokens.contains(token) {
                    return Ok(None);
                }
                Some((token.clone(), "ua_ref_used", vec![a[0].clone(), b32(ua_relay_ref(&self.network_id, a)?)?]))
            }
            "mtx_mandate_pay" => Some((c.clone(), "paid", vec![a[3].clone()])),
            _ => None,
        };
        if let Some((contract, view, args)) = by_ref {
            return match self.view(&contract, view, args).await? {
                None => Ok(None),
                Some(ScVal::Bool(b)) => Ok(Some(b)),
                Some(v) => bail!("{view} is not a bool: {v:?}"),
            };
        }
        let Some(l) = f.lane else { return Ok(None) };
        let ScVal::U64(nonce) = a[l + 1] else { return Ok(None) };
        let signer = match f.from {
            Some(i) => a[i].clone(),
            None => match self.view(c, "owner", vec![]).await? {
                Some(o) => o,
                None => return Ok(None),
            },
        };
        let ua = match (&signer, holder(&signer)) {
            (ScVal::Bytes(b), _) if b.len() == 32 => signer.clone(),
            (_, Some(Holder::Ua(u))) => ScVal::Bytes(u.to_vec().try_into()?),
            _ => return Ok(None), // a native signer: host authorisation, no lane
        };
        match self.view(c, "ua_nonce", vec![ua, a[l].clone()]).await? {
            None => Ok(None),
            Some(ScVal::U64(next)) => Ok(Some(next > nonce)),
            Some(v) => bail!("ua_nonce is not a u64: {v:?}"),
        }
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
    unhex(op[k].as_str().ok_or_else(|| anyhow!("op.{k} missing"))?.trim_start_matches("0x"))
}

/// The signed invocation of `op.payload`.
fn signed_call(network: &[u8; 32], op: &Value) -> Result<InvokeContractArgs> {
    let s = |k: &str| op[k].as_str().ok_or_else(|| anyhow!("op.{k} missing"));
    Ok(auth_entry(network, s("payload")?, s("from")?, s("signature")?)?.1)
}

/// Pay-meta job: the signed invocation is the token's `pay_meta`; `op.salt` / `op.meta` must be the signed
/// arguments (the auth entry covers them), `op.pay_ref` (when given) the commitment, `meta` within the cap.
pub fn pay_meta_job(network: &[u8; 32], op: &Value, max_meta: usize) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let (call, auth) = host_call(network, op)?;
    let signed = signed_call(network, op)?;
    if signed.function_name.0.as_slice() != b"pay_meta" || signed.args.len() != 6 {
        bail!("pay-meta job must sign pay_meta(from, to, amount, salt, meta, valid_until)");
    }
    if call != signed {
        bail!("the executed call is not the signed pay_meta");
    }
    let (salt, meta) = (op_bytes(op, "salt")?, op_bytes(op, "meta")?);
    if meta.len() > max_meta {
        bail!("meta is {} B, above max_pay_meta_bytes {max_meta}", meta.len());
    }
    if bytes_arg(&signed.args[3]) != Some(&salt[..]) || bytes_arg(&signed.args[4]) != Some(&meta[..]) {
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
    pub tokens: Vec<ScAddress>,
    pub params: crate::config::RelayParams,
    /// `params.dex` (`C…`): the DEX whose `settle` / `ua_cancel` `ua_metatx` jobs serve; `None` = none.
    pub dex: Option<ScAddress>,
    /// The router's executor (decision (D)), read once from `router.executor()` (`SorobanAdapter::load_executor`).
    pub executor: OnceLock<ScAddress>,
}

impl RelayFeePolicy {
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
        let tokens = cfg.tokens.iter()
            .map(|t| ScAddress::from_str(&t.address).map_err(|e| anyhow!("tokens: {} is not a Soroban address: {e}", t.address)))
            .collect::<Result<_>>()?;
        let dex = match cfg.params.get("dex") {
            None => None,
            Some(v) => match v.as_str().map(ScAddress::from_str) {
                Some(Ok(a @ ScAddress::Contract(_))) => Some(a),
                _ => bail!("params.dex {v} is not a Soroban contract address (C…)"),
            },
        };
        Ok(Self { router, tokens, params, dex, executor: OnceLock::new() })
    }
}

/// The job's invocation, checked before simulation (fail closed): `op.kind` by the one rule (`adapter::op_kind`):
/// `"pay_meta"` (`pay_meta_job`), `"relay_fee"` (`relay_fee_job`), none = the signed invocation as it is; outside a
/// relay, never a pay to the router.
pub fn job_call(network: &[u8; 32], op: &Value, lane: &ScAddress, policy: &RelayFeePolicy)
    -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)>
{
    let kind = crate::adapter::op_kind(op, &crate::adapter::PAY_KINDS)?;
    let (call, auth) = match kind {
        Some("pay_meta") => pay_meta_job(network, op, policy.params.max_pay_meta_bytes)?,
        Some(_) => {
            let (c, a, _) = relay_fee_job(network, op, lane, policy)?;
            return Ok((c, a));
        }
        None => host_call(network, op)?,
    };
    if pays_router(&call, policy) {
        bail!("a pay or approval to the relay-fee router or its executor is refused (CTR-MTX-27: never pay the router)");
    }
    Ok((call, auth))
}

/// CTR-MTX-27: a call that pays (or approves for later pays) the router or its executor: a token `pay` / `pay_meta` /
/// `transfer` to either (argument 1), `approve` to either as spender (argument 1; an amount 0 withdraws, allowed),
/// `transfer_from` with either as spender or `to` (arguments 0, 2), a `Holder::Addr` of either as the `to` / payee
/// (argument 1) of `ua_pay` / `ua_pay_meta` / `ua_transfer` (outside `ua_relay`), `mtx_mandate_pay`, `mtx_withdraw`,
/// `mtx_set_payee` (unless it withdraws the approval), or as either order's `destination` of `settle`; for `relay` /
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
        b"ua_pay" | b"ua_pay_meta" | b"ua_transfer" | b"mtx_mandate_pay" | b"mtx_withdraw" => to == Some(&holder_addr(x)),
        b"mtx_set_payee" => to == Some(&holder_addr(x)) && a.get(2) != Some(&ScVal::Bool(false)),
        b"settle" => a.iter().take(2).any(|o| field(o, "destination") == Some(&holder_addr(x))),
        _ => false,
    })
}

/// Relay-fee job: `extra.call` is the router's `relay(payer, target, func, args, salt, token, to, amount,
/// valid_until, relayer)`; the payer's signed root is the same call with the eight `require_auth_for_args`
/// arguments (no payer, no relayer) and the token's `pay` (carrying `ref`) as sub-invocation. Checks the policy,
/// `ref` against the call bytes, the relayer against this lane (`relayer` is the transaction source) and the signed
/// tree against the executed call. Soroban does not satisfy `relayer.require_auth()` from the transaction source
/// alone: the returned auth carries an explicit `SourceAccount` entry rooted at the same call.
pub fn relay_fee_job(
    network: &[u8; 32],
    op: &Value,
    lane: &ScAddress,
    policy: &RelayFeePolicy,
) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, [u8; 32])> {
    let (call, mut auth) = host_call(network, op)?;
    if op["extra"]["call"].is_null() {
        bail!("relay-fee job needs extra.call (the router call)");
    }
    let SorobanCredentials::Address(cred) = &auth[0].credentials else { bail!("payer entry has no address credentials") };
    let SorobanAuthorizedFunction::ContractFn(root) = &auth[0].root_invocation.function else { bail!("signed root is not a contract call") };
    if call.function_name.0.as_slice() != b"relay" || call.args.len() != 10 || root.function_name.0.as_slice() != b"relay" {
        bail!("relay-fee job must call relay(payer, target, func, args, salt, token, to, amount, valid_until, relayer)");
    }
    if root.contract_address != call.contract_address || root.args.as_slice() != &call.args[1..9] {
        bail!("the signed root is not this relay call");
    }
    if policy.router.as_ref() != Some(&call.contract_address) {
        bail!("relay target is not the configured router");
    }
    if call.args[0] != ScVal::Address(cred.address.clone()) {
        bail!("payer argument is not the signer");
    }
    if call.args[9] != ScVal::Address(lane.clone()) {
        bail!("relayer argument is not this lane");
    }
    if pays_router(&call, policy) {
        bail!("the relayed call pays or approves the relay-fee router or its executor (CTR-MTX-27)");
    }
    let (ScVal::Address(target), ScVal::Symbol(func), ScVal::Vec(Some(inner))) = (&call.args[1], &call.args[2], &call.args[3]) else {
        bail!("relay target / func / args malformed");
    };
    let salt: [u8; 32] = bytes_arg(&call.args[4]).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("salt is 32 bytes"))?;
    let ScVal::Address(token) = &call.args[5] else { bail!("token argument malformed") };
    if !policy.tokens.contains(token) {
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
/// signed arguments), none / `signed_op` ⇒ `job_call` (`op.valid_until`); any other kind is refused.
pub fn job_tx(network: &[u8; 32], kind: Option<&str>, op: &Value, lane: &ScAddress, policy: &RelayFeePolicy)
    -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, u64)>
{
    match kind {
        Some("ua_metatx") => {
            let (call, auth, _) = ua_metatx_job(network, op, lane, policy)?;
            let valid_until = ua_valid_until(&call)?;
            Ok((call, auth, valid_until))
        }
        None | Some("signed_op") => {
            let valid_until = op["valid_until"].as_u64().ok_or_else(|| anyhow!("op.valid_until missing"))?;
            let (call, auth) = job_call(network, op, lane, policy)?;
            Ok((call, auth, valid_until))
        }
        Some(k) => bail!("unknown job kind {k:?} (signed_op | ua_metatx)"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Token,
    Router,
    Dex,
    Mandate,
}

/// One allow-listed `ua_metatx` function (spec §9.1): its contract class, arity (with `auth`, the last argument; `settle`
/// has two order auths) and the indexes of `valid_until` (`None`: the orders' `expiry`), `relayer` (`Option<Address>`;
/// `ua_relay`'s an `Address`), the UA signer `from` (`BytesN<32>`, `mtx_revoke`'s `by` a `Holder`; `None` with a lane =
/// the mandate's owner), its `lane` (the nonce follows it) and `pay_ref`.
struct UaFn {
    name: &'static str,
    class: Class,
    arity: usize,
    valid_until: Option<usize>,
    relayer: Option<usize>,
    from: Option<usize>,
    lane: Option<usize>,
    pay_ref: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
const fn uf(name: &'static str, class: Class, arity: usize, valid_until: Option<usize>, relayer: Option<usize>, from: Option<usize>,
            lane: Option<usize>, pay_ref: Option<usize>) -> UaFn {
    UaFn { name, class, arity, valid_until, relayer, from, lane, pay_ref }
}

/// The contracts' signatures (T5–T8, T6b's `epoch` in the delegate entries).
const UA_FNS: [UaFn; 13] = [
    uf("ua_transfer", Class::Token, 8, Some(5), Some(6), Some(0), Some(3), None),
    uf("ua_pay", Class::Token, 7, Some(4), Some(5), Some(0), None, Some(3)),
    uf("ua_pay_meta", Class::Token, 8, Some(5), Some(6), Some(0), None, None),
    uf("ua_burn", Class::Token, 7, Some(4), Some(5), Some(0), Some(2), None),
    uf("ua_cancel_nonce", Class::Token, 4, Some(2), None, Some(0), None, None),
    uf("ua_relay", Class::Router, 11, Some(8), Some(9), Some(0), None, None),
    uf("settle", Class::Dex, 5, None, None, None, None, None),
    uf("ua_cancel", Class::Dex, 2, None, None, None, None, None),
    uf("mtx_set_mandate", Class::Mandate, 11, Some(8), Some(9), None, Some(6), None),
    uf("mtx_set_payee", Class::Mandate, 8, Some(5), Some(6), None, Some(3), None),
    uf("mtx_revoke", Class::Mandate, 8, Some(5), Some(6), Some(1), Some(3), None),
    uf("mtx_withdraw", Class::Mandate, 8, Some(5), Some(6), None, Some(3), None),
    uf("mtx_mandate_pay", Class::Mandate, 8, Some(5), Some(6), None, None, Some(3)),
];

/// SOR-D14's op: `{contract, function, args: "<hex XDR ScVec>" (every argument, `auth` included), auth?: [{payload,
/// from, signature}]}` ⇒ the call and its table row (function first, then arity).
fn ua_call(op: &Value) -> Result<(InvokeContractArgs, &'static UaFn)> {
    let s = |k: &str| op[k].as_str().ok_or_else(|| anyhow!("op.{k} missing"));
    // decision (C): the kind is `job.kind`; an `op.kind` here is a misrouted job, never ignored
    if op.get("kind").is_some_and(|k| !k.is_null()) {
        bail!("a ua_metatx op carries no op.kind (got {})", op["kind"]);
    }
    let function = s("function")?;
    let f = UA_FNS.iter().find(|f| f.name == function).ok_or_else(|| anyhow!("{function:?} is not a ua_metatx function"))?;
    let contract = match ScAddress::from_str(s("contract")?) {
        Ok(a @ ScAddress::Contract(_)) => a,
        _ => bail!("op.contract is not a Soroban contract address (C…)"),
    };
    let raw = op_bytes(op, "args")?;
    let args = ScVec::from_xdr(&raw, Limits { depth: 64, len: raw.len() })?;
    if args.len() != f.arity {
        bail!("{function} takes {} arguments, not {}", f.arity, args.len());
    }
    Ok((InvokeContractArgs { contract_address: contract, function_name: ScSymbol(function.try_into()?), args: args.0 }, f))
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
    let v = vec![
        ScVal::Symbol(ScSymbol("scaas_metaop_v1".try_into()?)),
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
        "settle" => Ok(None),
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
    if !policy.tokens.contains(token) {
        bail!("token is not registered on this chain");
    }
    let to = &a[6];
    if policy.executor.get().is_some_and(|x| *to == holder_addr(x)) {
        bail!("the fee is bound to the router's executor (BadPayee)");
    }
    let amount = scval_i128(&a[7]).and_then(|v| u128::try_from(v).ok()).ok_or_else(|| anyhow!("amount argument malformed or negative"))?;
    crate::adapter::relay_fee_ours(*to == holder_addr(&call.contract_address), *to == holder_addr(lane), amount, &policy.params)
}

/// The allow-list by contract class: a token ∈ `policy.tokens`, the router, `policy.dex`, any mandate.
fn listed(call: &InvokeContractArgs, f: &UaFn, policy: &RelayFeePolicy) -> bool {
    let c = &call.contract_address;
    match f.class {
        Class::Token => policy.tokens.contains(c),
        Class::Router => policy.router.as_ref() == Some(c),
        Class::Dex => policy.dex.as_ref() == Some(c),
        Class::Mandate => true,
    }
}

/// A `ua_metatx` job (spec §9.1, SOR-D14): the allow-list (token ∈ `policy.tokens`: `ua_transfer`, `ua_pay`,
/// `ua_pay_meta`, `ua_burn`, `ua_cancel_nonce`; router = `policy.router`: `ua_relay`; DEX = `policy.dex`: `settle`,
/// `ua_cancel`; any contract: the mandate's `mtx_*`), `relayer` `None` or this lane (`ua_relay`, and each `settle`
/// order: this lane), `valid_until` from the signed arguments, never a UA pay to the router or its executor outside
/// `ua_relay`. Auth: `op.auth` entries for native legs only (as `host_call`), and when the relayer is this lane one
/// `SourceAccount` entry rooted at exactly the call (S8, §8). Returns the call, its auth and the op digest (zero for
/// `settle`).
pub fn ua_metatx_job(network: &[u8; 32], op: &Value, lane: &ScAddress, policy: &RelayFeePolicy)
    -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, [u8; 32])>
{
    let (call, f) = ua_call(op)?;
    if !listed(&call, f, policy) {
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
    ua_valid_until(&call)?;
    if pays_router(&call, policy) {
        bail!("a pay or approval to the relay-fee router or its executor is refused (outside ua_relay's own fee; CTR-MTX-27)");
    }
    if f.name == "ua_relay" {
        ua_relay_policy(&call, lane, policy)?;
    }
    if let Some(i) = f.pay_ref {
        if a.get(i).and_then(bytes_arg).map(<[u8]>::len) != Some(32) {
            bail!("{}: pay_ref is 32 bytes", f.name);
        }
    }
    let digest = ua_digest(network, &call, f)?.unwrap_or_default();
    let s = |v: &Value, k: &str| v[k].as_str().map(str::to_owned).ok_or_else(|| anyhow!("op.auth[].{k} missing"));
    let mut auth = Vec::new();
    match &op["auth"] {
        Value::Null => {}
        Value::Array(v) => {
            for x in v {
                auth.push(auth_entry(network, &s(x, "payload")?, &s(x, "from")?, &s(x, "signature")?)?.0);
            }
        }
        _ => bail!("op.auth is a list of {{payload, from, signature}}"),
    }
    if lane_bound {
        auth.push(source_entry(&call));
    }
    Ok((call, auth, digest))
}

/// S14 / spec §8: a simulation (recording mode records every `require_auth`) whose auth holds a `SourceAccount` entry
/// that is not rooted at exactly `call` (with nothing below) fails the job before submission: the node never lends a
/// lane's authority to another call. Unreadable entries fail closed.
fn check_recorded_auth(sim: &Value, call: &InvokeContractArgs) -> Result<()> {
    let ours = source_entry(call).root_invocation;
    for r in sim["results"].as_array().into_iter().flatten() {
        for e in r["auth"].as_array().into_iter().flatten() {
            let x = e.as_str().ok_or_else(|| anyhow!("simulation auth entry is not base64 XDR"))?;
            let e = SorobanAuthorizationEntry::from_xdr_base64(x, Limits { depth: 64, len: 1 << 20 })?;
            if matches!(e.credentials, SorobanCredentials::SourceAccount) && e.root_invocation != ours {
                bail!("the call asks for this lane's authority outside the job's own call (S14: a lane's authority is never lent)");
            }
        }
    }
    Ok(())
}

/// Protocol 23 (CAP-0066): the transaction data lists archived entries the transaction restores itself.
fn restores(data: &SorobanTransactionData) -> bool {
    matches!(&data.ext, SorobanTransactionDataExt::V1(x) if !x.archived_soroban_entries.is_empty())
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
    let mut data = SorobanTransactionData::from_xdr_base64(data, Limits::len(1 << 20)).map_err(|e| SimError::Transport(e.to_string()))?;
    data.resource_fee = data.resource_fee.saturating_add(data.resource_fee.saturating_mul(RESOURCE_FEE_MARGIN_PCT) / 100);
    if restores(&data) && u64::try_from(data.resource_fee).map_or(true, |f| f > max_deposit) {
        return Err(SimError::Revert(format!("restore over max_deposit_per_job ({} > {max_deposit} stroops)", data.resource_fee)));
    }
    Ok(data)
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

    fn op(payload: &str, sig: &str) -> Value {
        json!({"payload": payload, "from": FROM, "signature": sig, "contract": CONTRACT, "valid_until": 1_800_000_300u64, "extra": {}})
    }

    #[test]
    fn cross_implementation_vector_decodes_into_the_call() {
        assert_eq!(hex(&Sha256::digest(unhex(PREIMAGE).unwrap())), "0a2127bfdc94f6062f0ec27f6db966ae719dafaca90bc537666eab606b901103");
        let (call, auth) = host_call(&network_id(NETWORK), &op(PREIMAGE, &"ab".repeat(64))).unwrap();
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

    #[test]
    fn foreign_network_wrong_contract_and_bad_signatures_are_refused() {
        let n = network_id(NETWORK);
        assert!(host_call(&network_id("Test SDF Network ; September 2015"), &op(PREIMAGE, &"ab".repeat(64))).is_err());
        let mut o = op(PREIMAGE, &"ab".repeat(64));
        o["contract"] = json!("CBCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEJ5HZ");
        assert!(host_call(&n, &o).is_err());
        assert!(host_call(&n, &op(PREIMAGE, "abcd")).is_err(), "account signatures are 64 bytes");
        assert!(host_call(&n, &op("00000001", &"ab".repeat(64))).is_err());
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

    use stellar_xdr::{
        HashIdPreimageSorobanAuthorization, Hash, Int128Parts, StringM,
    };

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
    fn payload(net: [u8; 32], root: SorobanAuthorizedInvocation) -> String {
        let p = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(net),
            nonce: 42,
            signature_expiration_ledger: 1000,
            invocation: root,
        });
        hex(&p.to_xdr(Limits::none()).unwrap())
    }
    fn sig() -> String {
        "ab".repeat(64)
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
        json!({"payload": payload(NET7, inv(CONTRACT, "pay_meta", args, vec![])), "from": FROM, "signature": sig(),
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
        let (call, auth) = pay_meta_job(&NET7, &op, 2048).unwrap();
        assert_eq!((call.function_name.0.as_slice(), call.args.len(), auth.len()), (&b"pay_meta"[..], 6, 1));
        // pay_ref given by the job must equal the commitment.
        op["pay_ref"] = json!(format!("0x{}", hex(&id)));
        assert!(pay_meta_job(&NET7, &op, 2048).is_ok());
        op["pay_ref"] = json!(format!("0x{}", "00".repeat(32)));
        assert!(pay_meta_job(&NET7, &op, 2048).is_err(), "pay_ref != metaPayId");
        // The unsigned salt / meta must be the signed ones (the auth entry covers them).
        assert!(pay_meta_job(&NET7, &pay_meta_op(&salt, &meta, &[1; 32], &meta), 2048).is_err());
        assert!(pay_meta_job(&NET7, &pay_meta_op(&salt, &meta, &salt, b"other"), 2048).is_err());
        // Wrong function, over the cap.
        let mut plain = pay_meta_op(&salt, &meta, &salt, &meta);
        plain["payload"] = json!(payload(NET7, inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&id), ScVal::U64(1)], vec![])));
        assert!(pay_meta_job(&NET7, &plain, 2048).is_err());
        let big = vec![7u8; 2049];
        assert!(pay_meta_job(&NET7, &pay_meta_op(&salt, &big, &salt, &big), 2048).unwrap_err().to_string().contains("max_pay_meta_bytes"));
        assert!(pay_meta_job(&NET7, &pay_meta_op(&salt, &big, &salt, &big), 4096).is_ok(), "params.max_pay_meta_bytes raises it");
        assert!(pay_meta_job(&network_id(NETWORK), &op, 2048).is_err(), "foreign network");
    }

    fn relay_job(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8]) -> Value {
        relay_job_with(token_pay_ref, relayer, target_in_call, op_ref, sym("revoke"))
    }

    fn relay_job_with(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8], func: ScVal) -> Value {
        relay_job_to(token_pay_ref, relayer, target_in_call, op_ref, func, WALLET2)
    }

    /// `to` = the payee: the router (open mode, the default), the lane, or anyone else (bound).
    fn relay_job_to(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8], func: ScVal, payee: &str) -> Value {
        relay_job_args(token_pay_ref, relayer, target_in_call, op_ref, func, payee, vec![addr(CONTRACT), addr(OWNER)])
    }

    /// `relay_job_to` with the target call's arguments given.
    fn relay_job_args(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8], func: ScVal, payee: &str,
                      args: Vec<ScVal>) -> Value {
        let token = CONTRACT;
        let to = addr(payee);
        let signed = vec![addr(WALLET), func, vecv(args.clone()), byt(&SALT), addr(token), to.clone(), i128v(7), ScVal::U64(1_800_000_300)];
        let pay = inv(token, "pay", vec![addr(OWNER), to.clone(), i128v(7), byt(token_pay_ref), ScVal::U64(1_800_000_300)], vec![]);
        let root = inv(WALLET2, "relay", signed.clone(), vec![pay]);
        let mut full = vec![addr(OWNER)];
        let mut sg = signed;
        sg[0] = addr(target_in_call);
        full.extend(sg);
        full.push(addr(relayer));
        let call = InvokeContractArgs {
            contract_address: ScAddress::from_str(WALLET2).unwrap(),
            function_name: ScSymbol("relay".try_into().unwrap()),
            args: full.try_into().unwrap(),
        };
        json!({"kind": "relay_fee", "payload": payload(NET7, root), "from": OWNER, "signature": sig(), "contract": WALLET2,
               "valid_until": 1_800_000_300u64, "ref": format!("0x{}", hex(op_ref)),
               "extra": {"call": hex(&call.to_xdr(Limits::none()).unwrap())}})
    }
    const WALLET2: &str = "CBCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEJ5HZ"; // the router
    const LANE: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";

    fn policy() -> RelayFeePolicy {
        RelayFeePolicy { router: Some(ScAddress::from_str(WALLET2).unwrap()), tokens: vec![ScAddress::from_str(CONTRACT).unwrap()],
                         params: rp(5), dex: Some(ScAddress::from_str(DEX).unwrap()), executor: OnceLock::new() }
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
        let pay = |to: &str| json!({"payload": payload(NET7, inv(CONTRACT, "pay", vec![addr(FROM), addr(to), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
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
        let to = |payee: &str| relay_job_to(&rf, LANE, WALLET, &rf, sym("revoke"), payee);
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
        let ok = relay_job(&rf, LANE, WALLET, &rf);
        let (call, auth, got) = relay_fee_job(&NET7, &ok, &lane, &policy()).unwrap();
        assert_eq!((call.function_name.0.as_slice(), call.args.len(), got), (&b"relay"[..], 10, rf));
        // The payer's entry plus the explicit source-account entry (source auth is not implicit), rooted at the call.
        assert_eq!(auth.len(), 2);
        assert!(matches!(auth[0].credentials, SorobanCredentials::Address(_)));
        assert!(matches!(auth[1].credentials, SorobanCredentials::SourceAccount));
        assert_eq!(auth[1].root_invocation.function, SorobanAuthorizedFunction::ContractFn(call.clone()));
        assert!(auth[1].root_invocation.sub_invocations.is_empty());
        let bad = |o: Value| relay_fee_job(&NET7, &o, &lane, &policy()).is_err();
        // The payment's ref is not the call's; the job's declared ref is not the call's.
        assert!(bad(relay_job(&[9; 32], LANE, WALLET, &rf)));
        assert!(bad(relay_job(&rf, LANE, WALLET, &[9; 32])));
        // The relayer argument is not this lane (the router marker).
        assert!(bad(relay_job(&rf, FROM, WALLET, &rf)));
        // The executed call differs from the signed one.
        assert!(bad(relay_job(&rf, LANE, CONTRACT, &rf)));
        // No explicit call: refused.
        let mut bare = ok.clone();
        bare["extra"] = json!({});
        assert!(bad(bare));
        // Policy: other router, unregistered token, fee below the minimum.
        let other = RelayFeePolicy { router: Some(ScAddress::from_str(WALLET).unwrap()), ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &other).is_err());
        let none = RelayFeePolicy { router: None, ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &none).is_err());
        let no_token = RelayFeePolicy { tokens: vec![], ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &no_token).is_err());
        let dear = RelayFeePolicy { params: rp(8), ..policy() };
        assert!(relay_fee_job(&NET7, &ok, &lane, &dear).is_err());
        assert!(relay_fee_job(&NET7, &ok, &lane, &RelayFeePolicy { params: rp(7), ..policy() }).is_ok());
    }

    /// A function symbol that is not UTF-8 (32 raw bytes) is hashed as received: no panic, and a bad ref.
    #[test]
    fn relay_fee_job_survives_non_utf8_symbol() {
        let weird = ScVal::Symbol(ScSymbol(StringM::<32>::try_from(vec![0xffu8; 32]).unwrap()));
        let lane = ScAddress::from_str(LANE).unwrap();
        let o = relay_job_with(&[1; 32], LANE, WALLET, &[2; 32], weird);
        assert!(relay_fee_job(&NET7, &o, &lane, &policy()).is_err());
    }

    // ------------------------------------------------------------ UA-Soroban T9 (spec §8, §9; SOR-D14)

    const DEX: &str = "CBTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGM2VL";
    const MANDATE: &str = "CBKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVLO6Q";
    const VU: u64 = 1_800_000_300;
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
    fn ua_op(contract: &str, function: &str, args: Vec<ScVal>) -> Value {
        let a = ScVec(args.try_into().unwrap()).to_xdr(Limits::none()).unwrap();
        json!({"contract": contract, "function": function, "args": format!("0x{}", hex(&a))})
    }
    fn auth_arg() -> ScVal {
        byt(&[0xaa; 8])
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
            (DEX, "settle", vec![order(h_ua(UA), LANE, VU), order(h_addr(FROM), LANE, VU + 9), i128v(5), a, byt(&[])]),
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

    /// SOR-D14: the shared `ua-ops.json` rows rebuilt as jobs give the vector's op digest (the job id); `ua_relay`'s is
    /// the inner `token.ua_pay` with `pay_ref = ref` and `relayer = Some(router)`.
    #[test]
    fn ua_metatx_digest_matches_ua_ops_vectors() {
        let v: Value = serde_json::from_str(include_str!("../../../smartcontracts/soroban/vectors/ua-ops.json")).unwrap();
        let net = network_id(v["network"]["passphrase"].as_str().unwrap());
        let c = &v["contracts"];
        let at = |k: &str| sc(c[k].as_str().unwrap());
        let policy = RelayFeePolicy { router: Some(at("router")), tokens: vec![at("token")], params: rp(5), dex: Some(at("dex")),
                                      executor: OnceLock::new() };
        let xdr = |s: &Value| ScVal::from_xdr(strip(s), Limits::none()).unwrap();
        let mut n = 0;
        for e in v["entries"].as_array().unwrap() {
            if e["name"] == "ua_order" {
                continue; // `ua_trade`'s order digest: signed by the maker, run by the DEX, never a job
            }
            for row in e["perKind"].as_array().unwrap() {
                let mut args: Vec<ScVal> = row["args"].as_array().unwrap().iter().map(|a| xdr(&a["xdr"])).collect();
                let auth = byt(&strip(&row["auth"]));
                let (contract, function) = if e["name"] == "ua_relay" {
                    let r = &e["relay"];
                    assert_eq!(args[3], byt(&strip(&r["ref"])), "the vector's pay_ref is its relay ref");
                    let inner = r["args"].as_array().unwrap().iter().map(|a| xdr(&a["xdr"])).collect();
                    args = vec![args[0].clone(), addr(r["target"].as_str().unwrap()), sym(r["func"].as_str().unwrap()), vecv(inner),
                                byt(&strip(&r["salt"])), addr(e["contract"].as_str().unwrap()), args[1].clone(), args[2].clone(),
                                args[4].clone(), addr(LANE)];
                    (c["router"].as_str().unwrap(), "ua_relay")
                } else {
                    (e["contract"].as_str().unwrap(), e["fn"].as_str().unwrap())
                };
                args.push(auth);
                let (call, _, digest) = ua_metatx_job(&net, &ua_op(contract, function, args), &lane(), &policy)
                    .unwrap_or_else(|x| panic!("{} {}: {x:#}", e["name"], row["kind"]));
                assert_eq!(call.contract_address.to_string(), contract);
                assert_eq!(format!("0x{}", hex(&digest)), row["digest"].as_str().unwrap(), "{} {}", e["name"], row["kind"]);
                n += 1;
            }
        }
        assert_eq!(n, 9 * 7, "every job row of the vector file");
    }

    /// Spec §9.1: token functions on a registered token, `ua_relay` on the router, `settle` / `ua_cancel` on
    /// `params.dex`, the mandate's `mtx_*` on any contract; anything else, or the wrong arity, is refused.
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
        let foreign = vec![order(h_ua(UA), LANE, VU), order(h_addr(FROM), FROM, VU), i128v(5), auth_arg(), byt(&[])];
        assert!(ua_metatx_job(&NET7, &ua_op(DEX, "settle", foreign), &lane(), &p).unwrap_err().to_string().contains("relayer"));
        // valid_until comes from the signed arguments (NET-SOR-15): settle's earlier order expiry
        let (_, _, settle) = ua_ops(ScVal::Void).pop().unwrap();
        let (call, _, _) = ua_metatx_job(&NET7, &ua_op(DEX, "settle", settle), &lane(), &p).unwrap();
        assert_eq!(ua_valid_until(&call).unwrap(), VU);
        // native legs: op.auth entries decoded as host_call does, nothing else
        let mut o = ua_op(CONTRACT, "ua_transfer", ua_ops(ScVal::Void).remove(0).2);
        o["auth"] = json!([{"payload": PREIMAGE, "from": FROM, "signature": sig()}]);
        let (_, auth, _) = ua_metatx_job(&network_id(NETWORK), &o, &lane(), &p).unwrap();
        assert!(matches!(auth.as_slice(), [SorobanAuthorizationEntry { credentials: SorobanCredentials::Address(_), .. }]));
    }

    /// S14 / spec §8: a recorded `SourceAccount` entry not rooted at exactly the job's call fails the job before
    /// submission; the lane's own entry for the call, and subject entries, pass.
    #[test]
    fn ua_metatx_refuses_extra_source_account_auth() {
        let (call, auth, _) = ua_metatx_job(&NET7, &ua_op(CONTRACT, "ua_transfer", ua_ops(addr(LANE)).remove(0).2), &lane(), &policy()).unwrap();
        let b64 = |e: &SorobanAuthorizationEntry| json!(e.to_xdr_base64(Limits::none()).unwrap());
        let sim = |entries: Vec<Value>| json!({"results": [{"xdr": "AAAAAQ==", "auth": entries}]});
        assert!(check_recorded_auth(&sim(vec![b64(&auth[0])]), &call).is_ok(), "the lane's entry for the call");
        let subject = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials { address: sc(FROM), nonce: 1, signature_expiration_ledger: 9, signature: ScVal::Void }),
            root_invocation: inv(WALLET, "anything", vec![], vec![]),
        };
        assert!(check_recorded_auth(&sim(vec![b64(&auth[0]), b64(&subject)]), &call).is_ok(), "a subject entry is not the lane's");
        let elsewhere = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: inv(CONTRACT, "transfer", vec![addr(LANE), addr(FROM), i128v(1)], vec![]),
        };
        let e = check_recorded_auth(&sim(vec![b64(&auth[0]), b64(&elsewhere)]), &call).unwrap_err().to_string();
        assert!(e.contains("lane"), "{e}");
        let deeper = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(call.clone()),
                sub_invocations: vec![inv(CONTRACT, "transfer", vec![addr(LANE)], vec![])].try_into().unwrap(),
            },
        };
        assert!(check_recorded_auth(&sim(vec![b64(&deeper)]), &call).is_err(), "the call plus a lent sub-invocation");
        assert!(check_recorded_auth(&sim(vec![json!("not xdr")]), &call).is_err(), "unreadable: fail closed");
        assert!(check_recorded_auth(&json!({"results": [{"xdr": "AAAAAQ=="}]}), &call).is_ok(), "nothing recorded");
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
        // every other entry that pays or approves a holder: the mandate's payee / withdrawal `to`, settle's destinations
        for f in ["mtx_mandate_pay", "mtx_withdraw", "mtx_set_payee"] {
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
        let e = ua_metatx_job(&NET7, &ua_op(WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)), &lane(), &RelayFeePolicy { tokens: vec![], ..policy() })
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
        let host = |f: &str, args: Vec<ScVal>| json!({"payload": payload(NET7, inv(CONTRACT, f, args, vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": VU, "extra": {}});
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
                let job = relay_job_args(&rf, LANE, WALLET, &rf, sym(f), LANE, args.clone());
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
        assert!(relay_fee_job(&NET7, &relay_job_args(&rf, LANE, WALLET, &rf, sym("pay"), LANE, args), &lane(), &p).is_err());
        // an ordinary relayed call still passes
        let args = vec![addr(CONTRACT), addr(OWNER)];
        let rf = relay_ref(&NET7, &sc(WALLET), &ScSymbol("revoke".try_into().unwrap()), &args, &SALT);
        assert!(relay_fee_job(&NET7, &relay_job_args(&rf, LANE, WALLET, &rf, sym("revoke"), LANE, args), &lane(), &p).is_ok());
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
        let pay = |to: &str| json!({"payload": payload(NET7, inv(CONTRACT, "pay", vec![addr(FROM), addr(to), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": VU, "extra": {}});
        assert!(job_call(&NET7, &pay(WALLET), &lane(), &p).is_ok());
        assert!(job_call(&NET7, &pay(&ex), &lane(), &p).unwrap_err().to_string().contains("executor"));
        let r = meta_row();
        let (salt, meta) = (strip(&r["salt"]), strip(&r["meta"]));
        let mut pm = pay_meta_op(&salt, &meta, &salt, &meta);
        pm["kind"] = json!("pay_meta");
        assert!(job_call(&NET7, &pm, &lane(), &p).is_ok());
        let args = vec![addr(FROM), addr(&ex), i128v(40), byt(&salt), byt(&meta), ScVal::U64(VU)];
        pm["payload"] = json!(payload(NET7, inv(CONTRACT, "pay_meta", args, vec![])));
        assert!(job_call(&NET7, &pm, &lane(), &p).unwrap_err().to_string().contains("executor"));
        let a = vec![addr(CONTRACT), addr(OWNER)];
        let rf = relay_ref(&NET7, &sc(WALLET), &ScSymbol("revoke".try_into().unwrap()), &a, &SALT);
        let sponsored = RelayFeePolicy { params: crate::config::RelayParams { relay_bound_payee: true, ..rp(5) }, ..policy() };
        sponsored.executor.set(executor()).unwrap();
        assert!(relay_fee_job(&NET7, &relay_job_to(&rf, LANE, WALLET, &rf, sym("revoke"), WALLET), &lane(), &sponsored).is_ok());
        let e = relay_fee_job(&NET7, &relay_job_to(&rf, LANE, WALLET, &rf, sym("revoke"), &ex), &lane(), &sponsored).unwrap_err().to_string();
        assert!(e.contains("executor"), "{e}");
    }

    /// The node's job kinds (S15): `ua_metatx`, and `signed_op` / none for the native jobs; anything else is refused.
    #[test]
    fn soroban_unknown_job_kind_refused() {
        let p = policy();
        let pay = json!({"payload": payload(NET7, inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&[3; 32]), ScVal::U64(1)], vec![])),
            "from": FROM, "signature": sig(), "contract": CONTRACT, "valid_until": VU, "extra": {}});
        for k in [None, Some("signed_op")] {
            assert_eq!(job_tx(&NET7, k, &pay, &lane(), &p).unwrap().2, VU, "{k:?}");
        }
        let (c, f, args) = ua_ops(ScVal::Void).remove(0);
        assert_eq!(job_tx(&NET7, Some("ua_metatx"), &ua_op(c, f, args), &lane(), &p).unwrap().2, VU);
        assert!(job_tx(&NET7, Some("ua_metatx"), &pay, &lane(), &p).is_err(), "a signed_op is not a ua_metatx");
        for k in ["metatx", "call", "pay", "", "UA_METATX"] {
            let e = job_tx(&NET7, Some(k), &pay, &lane(), &p).unwrap_err().to_string();
            assert!(e.contains("unknown job kind"), "{k}: {e}");
        }
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

    async fn rpc_stub(answer: Answer, calls: Arc<Mutex<Vec<String>>>) -> String {
        let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(b): axum::Json<Value>| {
            let (answer, calls) = (answer.clone(), calls.clone());
            async move {
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

    fn view_ok(v: ScVal) -> Value {
        json!({"results": [{"xdr": v.to_xdr_base64(Limits::none()).unwrap(), "auth": []}], "transactionData": data(100, &[])})
    }
    fn view_archived(v: ScVal) -> Value {
        json!({"results": [{"xdr": v.to_xdr_base64(Limits::none()).unwrap(), "auth": []}], "transactionData": data(100, &[1])})
    }

    async fn stub_adapter(answer: Answer, router: bool) -> (SorobanAdapter, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let url = rpc_stub(answer, calls.clone()).await;
        let mut c = ChainCfg { family: "soroban".into(), network: Some("local".into()), rpc_urls: vec![url], lanes: vec![0], ..Default::default() };
        c.tokens = vec![crate::config::TokenCfg { address: CONTRACT.into(), decimals: 7 }];
        c.params.insert("network_passphrase".into(), "x".into());
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

    proptest! {
        #[test]
        fn payload_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512), sig in "[0-9a-f]{0,200}") {
            let _ = host_call(&network_id(NETWORK), &op(&hex(&bytes), &sig));
        }

        #[test]
        fn jobs_never_panic_on_untrusted_input(bytes in proptest::collection::vec(any::<u8>(), 0..512), sig in "[0-9a-f]{0,200}",
                                               call in "[0-9a-f]{0,400}", i in any::<usize>(), b in any::<u8>()) {
            let net = network_id(NETWORK);
            let lane = ScAddress::from_str(LANE).unwrap();
            let mut o = op(&hex(&bytes), &sig);
            o["extra"] = json!({"call": call});
            o["salt"] = json!(sig);
            o["meta"] = json!(sig);
            let _ = pay_meta_job(&net, &o, 2048);
            let _ = relay_fee_job(&net, &o, &lane, &policy());
            // A well-formed job with one byte of its call mutated.
            let rf = [1u8; 32];
            let mut v = relay_job(&rf, LANE, WALLET, &rf);
            let mut c = unhex(v["extra"]["call"].as_str().unwrap()).unwrap();
            let n = c.len();
            c[i % n] = b;
            v["extra"]["call"] = json!(hex(&c));
            let _ = relay_fee_job(&NET7, &v, &lane, &policy());
        }

        /// A well-formed `ua_metatx` op with one byte of its arguments mutated: refused or built, never a panic.
        #[test]
        fn ua_metatx_job_never_panics(k in 0usize..13, i in any::<usize>(), b in any::<u8>()) {
            let mut ops = ua_ops(addr(LANE));
            ops.push((WALLET2, "ua_relay", ua_relay_args(h_addr(WALLET2), LANE)));
            let (c, f, args) = ops.swap_remove(k % ops.len());
            let mut a = ScVec(args.try_into().unwrap()).to_xdr(Limits::none()).unwrap();
            let n = a.len();
            a[i % n] = b;
            let o = json!({"contract": c, "function": f, "args": hex(&a)});
            let _ = ua_metatx_job(&NET7, &o, &lane(), &policy());
            let _ = job_tx(&NET7, Some("ua_metatx"), &o, &lane(), &policy());
        }

        #[test]
        fn event_decoder_never_panics(t0 in ".{0,80}", t1 in ".{0,80}", v in ".{0,200}", id in ".{0,30}", tx in ".{0,70}") {
            let _ = decode_event(&json!({"ledger": 1, "contractId": CONTRACT, "txHash": tx, "id": id, "topic": [t0, t1], "value": v}));
        }

        #[test]
        fn mutated_preimage_never_panics(i in any::<usize>(), b in any::<u8>()) {
            let mut p = unhex(PREIMAGE).unwrap();
            let n = p.len();
            p[i % n] = b;
            let _ = host_call(&network_id(NETWORK), &op(&hex(&p), &"ab".repeat(64)));
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
}
