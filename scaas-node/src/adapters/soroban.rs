//! Stellar Soroban (R65). Meta-tx cấp contract = authorization gốc: chủ thể đã ký
//! `HashIdPreimage::SorobanAuthorization` (Odoo dựng); adapter đặt chữ ký vào `SorobanAuthorizationEntry` của một tx
//! mà **lane account** là source (sequence riêng của lane, trả phí) — chủ thể không có sequence trong đường đi (R30).
//! Nonce auth là ngẫu nhiên (host ghi cặp (địa chỉ, nonce) đã dùng) ⇒ không head-of-line (R62).
//! Tuỳ chọn fee-bump (CAP-15): `params.fee_bump_lane = i` ⇒ account của lane `i` trả phí cho mọi lane.
//! Thiết kế: `docs/history/specs/2026-10-03-net-soroban.md`.
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, DecoratedSignature, FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
    FeeBumpTransactionInnerTx, HashIdPreimage, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, LedgerEntryData,
    LedgerKey, LedgerKeyAccount, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    ReadXdr, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, SequenceNumber, Signature, SignatureHint,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanCredentials,
    SorobanTransactionData, TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt,
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
        "from": scval_addr(topics.get(1)?)?,
    });
    match scval_str(topics.first()?)?.as_str() {
        "PaymentSettled" => {
            let ScVal::Vec(Some(data)) = &value else { return None };
            let amount = scval_i128(data.first()?)?;
            if amount < 0 {
                return None;
            }
            out["event"] = json!("PaymentSettled");
            out["to"] = json!(scval_addr(topics.get(2)?)?);
            out["amount"] = json!(amount.to_string());
            out["entry_ref"] = json!(scval_b32(data.get(1)?)?);
        }
        "MetaTransactionExecuted" => {
            out["event"] = json!("MetaTransactionExecuted");
            out["digest"] = json!(scval_b32(&value)?);
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
        let valid_until = op["valid_until"].as_u64().ok_or_else(|| SimError::Revert("op.valid_until missing".into()))?;
        let rv = |e: anyhow::Error| SimError::Revert(format!("{e:#}"));
        let (call, auth) = match op["kind"].as_str() {
            Some("pay_meta") => pay_meta_job(&self.network_id, &op).map_err(rv)?,
            Some("relay_fee") => {
                let pk = lane_pk(self.signer(lane).map_err(rv)?).map_err(rv)?;
                let lane_addr = ScAddress::from_str(&stellar_account_strkey(&pk)).map_err(|e| SimError::Revert(e.to_string()))?;
                let (c, a, _) = relay_fee_job(&self.network_id, &op, &lane_addr).map_err(rv)?;
                (c, a)
            }
            _ => host_call(&self.network_id, &op).map_err(rv)?,
        };
        let tx = self.tx(lane, 0, valid_until, call, auth).map_err(|e| SimError::Revert(format!("{e:#}")))?;
        let env = TransactionEnvelope::Tx(TransactionV1Envelope { tx: tx.clone(), signatures: Default::default() });
        let b64 = env.to_xdr_base64(Limits::none()).map_err(|e| SimError::Revert(e.to_string()))?;
        let sim = self
            .rpc("simulateTransaction", json!({"transaction": b64}))
            .await
            .map_err(|e| SimError::Transport(format!("{e:#}")))?;
        if let Some(err) = sim.get("error").and_then(|e| e.as_str()) {
            return Err(SimError::Revert(err.chars().take(300).collect()));
        }
        if sim.get("restorePreamble").is_some_and(|r| !r.is_null()) {
            return Err(SimError::Revert("contract state is archived; restore it first".into()));
        }
        let data = sim["transactionData"].as_str().ok_or_else(|| SimError::Transport("no transactionData".into()))?;
        let mut data = SorobanTransactionData::from_xdr_base64(data, Limits::len(1 << 20)).map_err(|e| SimError::Transport(e.to_string()))?;
        data.resource_fee += data.resource_fee * RESOURCE_FEE_MARGIN_PCT / 100;
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
                    if let Some(mut e) = decode_event(ev) {
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
        Ok(out)
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

/// `max_pay_meta_bytes` (spec §9): the node's cap on a pay-meta `meta`.
const MAX_PAY_META_BYTES: usize = 2048;

/// CTR-MTX-26: `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`, the token's `meta_pay_id`.
pub fn meta_pay_id(salt: &[u8], meta: &[u8]) -> [u8; 32] {
    let mut b = b"scaas.pay.meta".to_vec();
    b.extend_from_slice(salt);
    b.extend_from_slice(alloy::primitives::keccak256(meta).as_slice());
    alloy::primitives::keccak256(b).0
}

/// CTR-MTX-27 `ref` (the router's `relay_ref`): `keccak256("scaas.relayfee" ‖ network id ‖ xdr(target) ‖
/// keccak256(xdr((func, args))))`.
pub fn relay_ref(network: &[u8; 32], target: &ScAddress, func: &str, args: &[ScVal]) -> [u8; 32] {
    let pair = vec![
        ScVal::Symbol(ScSymbol(func.try_into().expect("function name"))),
        ScVal::Vec(Some(ScVec(args.to_vec().try_into().expect("args")))),
    ];
    let call = ScVal::Vec(Some(ScVec(pair.try_into().expect("pair"))));
    let mut b = b"scaas.relayfee".to_vec();
    b.extend_from_slice(network);
    b.extend_from_slice(&ScVal::Address(target.clone()).to_xdr(Limits::none()).expect("xdr"));
    b.extend_from_slice(alloy::primitives::keccak256(call.to_xdr(Limits::none()).expect("xdr")).as_slice());
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

/// Pay-meta job: the signed invocation is the token's `pay_meta`; `op.salt` / `op.meta` must be the signed
/// arguments (the auth entry covers them), `op.pay_ref` (when given) the commitment, `meta` within the cap.
pub fn pay_meta_job(network: &[u8; 32], op: &Value) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>)> {
    let (call, auth) = host_call(network, op)?;
    if call.function_name.0.as_slice() != b"pay_meta" || call.args.len() != 6 {
        bail!("pay-meta job must call pay_meta(from, to, amount, salt, meta, valid_until)");
    }
    let (salt, meta) = (op_bytes(op, "salt")?, op_bytes(op, "meta")?);
    if meta.len() > MAX_PAY_META_BYTES {
        bail!("meta is {} B, above the {MAX_PAY_META_BYTES} B cap", meta.len());
    }
    if bytes_arg(&call.args[3]) != Some(&salt[..]) || bytes_arg(&call.args[4]) != Some(&meta[..]) {
        bail!("op.salt / op.meta differ from the signed pay_meta arguments");
    }
    if !op["pay_ref"].is_null() && op_bytes(op, "pay_ref")? != meta_pay_id(&salt, &meta) {
        bail!("pay_ref != metaPayId(salt, meta)");
    }
    Ok((call, auth))
}

/// Relay-fee job: `extra.call` is the router's `relay(payer, target, func, args, token, to, amount, valid_until,
/// relayer)`; the payer's signed root is the same call with the seven `require_auth_for_args` arguments and the
/// token's `pay` (carrying `ref`) as sub-invocation. Checks `ref` against the call bytes, the relayer against this
/// lane (`relayer` is the transaction source) and the signed tree against the executed call.
pub fn relay_fee_job(network: &[u8; 32], op: &Value, lane: &ScAddress) -> Result<(InvokeContractArgs, Vec<SorobanAuthorizationEntry>, [u8; 32])> {
    let (call, auth) = host_call(network, op)?;
    if op["extra"]["call"].is_null() {
        bail!("relay-fee job needs extra.call (the router call)");
    }
    let SorobanCredentials::Address(cred) = &auth[0].credentials else { bail!("payer entry has no address credentials") };
    let SorobanAuthorizedFunction::ContractFn(root) = &auth[0].root_invocation.function else { bail!("signed root is not a contract call") };
    if call.function_name.0.as_slice() != b"relay" || call.args.len() != 9 || root.function_name.0.as_slice() != b"relay" {
        bail!("relay-fee job must call relay(payer, target, func, args, token, to, amount, valid_until, relayer)");
    }
    if root.contract_address != call.contract_address || root.args.as_slice() != &call.args[1..8] {
        bail!("the signed root is not this relay call");
    }
    if call.args[0] != ScVal::Address(cred.address.clone()) {
        bail!("payer argument is not the signer");
    }
    if call.args[8] != ScVal::Address(lane.clone()) {
        bail!("relayer argument is not this lane");
    }
    let (ScVal::Address(target), ScVal::Symbol(func), ScVal::Vec(Some(inner))) = (&call.args[1], &call.args[2], &call.args[3]) else {
        bail!("relay target / func / args malformed");
    };
    let rf = relay_ref(network, target, &func.0.to_utf8_string_lossy(), inner.as_slice());
    if op_bytes(op, "ref")? != rf {
        bail!("op.ref != relay_ref(target, func, args)");
    }
    // The signed tree must contain exactly the payment that commits to `ref`.
    let ScVal::Address(token) = &call.args[4] else { bail!("token argument malformed") };
    let pays = auth[0].root_invocation.sub_invocations.iter().filter(|s| match &s.function {
        SorobanAuthorizedFunction::ContractFn(f) => {
            f.contract_address == *token
                && f.function_name.0.as_slice() == b"pay"
                && f.args.len() == 5
                && f.args[0] == call.args[0]
                && f.args[1] == call.args[5]
                && f.args[2] == call.args[6]
                && bytes_arg(&f.args[3]) == Some(&rf[..])
                && f.args[4] == call.args[7]
        }
        _ => false,
    });
    if pays.count() != 1 {
        bail!("the payer's signature does not carry token.pay(payer, to, amount, ref, valid_until)");
    }
    Ok((call, auth, rf))
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

    // ------------------------------------------------------------ metatx-split T10 (CTR-MTX-26 / 27)

    use stellar_xdr::{
        HashIdPreimageSorobanAuthorization, Hash, Int128Parts, SorobanAuthorizedInvocation,
    };

    const WALLET: &str = "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH";
    const OWNER: &str = FROM;
    /// `smartcontracts/soroban/contracts/relay-fee/src/test.rs::VEC_REF` (network id 0x07 x 32).
    const VEC_REF: &str = "1fbf24f83d5c9aa7018ee18b9b29e29a110909eb48a671afc8e086cc8e99efb2";
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
        let (call, auth) = pay_meta_job(&NET7, &op).unwrap();
        assert_eq!((call.function_name.0.as_slice(), call.args.len(), auth.len()), (&b"pay_meta"[..], 6, 1));
        // pay_ref given by the job must equal the commitment.
        op["pay_ref"] = json!(format!("0x{}", hex(&id)));
        assert!(pay_meta_job(&NET7, &op).is_ok());
        op["pay_ref"] = json!(format!("0x{}", "00".repeat(32)));
        assert!(pay_meta_job(&NET7, &op).is_err(), "pay_ref != metaPayId");
        // The unsigned salt / meta must be the signed ones (the auth entry covers them).
        assert!(pay_meta_job(&NET7, &pay_meta_op(&salt, &meta, &[1; 32], &meta)).is_err());
        assert!(pay_meta_job(&NET7, &pay_meta_op(&salt, &meta, &salt, b"other")).is_err());
        // Wrong function, over the cap.
        let mut plain = pay_meta_op(&salt, &meta, &salt, &meta);
        plain["payload"] = json!(payload(NET7, inv(CONTRACT, "pay", vec![addr(FROM), addr(WALLET), i128v(1), byt(&id), ScVal::U64(1)], vec![])));
        assert!(pay_meta_job(&NET7, &plain).is_err());
        let big = vec![7u8; MAX_PAY_META_BYTES + 1];
        assert!(pay_meta_job(&NET7, &pay_meta_op(&salt, &big, &salt, &big)).is_err());
        assert!(pay_meta_job(&network_id(NETWORK), &op).is_err(), "foreign network");
    }

    fn relay_job(token_pay_ref: &[u8], relayer: &str, target_in_call: &str, op_ref: &[u8]) -> Value {
        let token = CONTRACT;
        let args = vec![addr(token), addr(OWNER)];
        let to = addr(WALLET); // any contract as the (bound) payee
        let signed = vec![addr(WALLET), sym("revoke"), vecv(args.clone()), addr(token), to.clone(), i128v(7), ScVal::U64(1_800_000_300)];
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

    #[test]
    fn soroban_relay_fee_job_checks_ref() {
        let args = vec![addr(CONTRACT), addr(OWNER)];
        let rf = relay_ref(&NET7, &ScAddress::from_str(WALLET).unwrap(), "revoke", &args);
        assert_eq!(hex(&rf), VEC_REF, "same ref as the contract's test");
        let lane = ScAddress::from_str(LANE).unwrap();
        let ok = relay_job(&rf, LANE, WALLET, &rf);
        let (call, auth, got) = relay_fee_job(&NET7, &ok, &lane).unwrap();
        assert_eq!((call.function_name.0.as_slice(), call.args.len(), auth.len(), got), (&b"relay"[..], 9, 1, rf));
        // The payment's ref is not the call's ref.
        assert!(relay_fee_job(&NET7, &relay_job(&[9; 32], LANE, WALLET, &rf), &lane).is_err());
        // The job's declared ref is not the call's.
        assert!(relay_fee_job(&NET7, &relay_job(&rf, LANE, WALLET, &[9; 32]), &lane).is_err());
        // The relayer argument is not this lane (the router marker).
        assert!(relay_fee_job(&NET7, &relay_job(&rf, FROM, WALLET, &rf), &lane).is_err());
        // The executed call differs from the signed one.
        assert!(relay_fee_job(&NET7, &relay_job(&rf, LANE, CONTRACT, &rf), &lane).is_err());
        // No explicit call: refused.
        let mut bare = ok.clone();
        bare["extra"] = json!({});
        assert!(relay_fee_job(&NET7, &bare, &lane).is_err());
    }

    proptest! {
        #[test]
        fn payload_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512), sig in "[0-9a-f]{0,200}") {
            let _ = host_call(&network_id(NETWORK), &op(&hex(&bytes), &sig));
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
