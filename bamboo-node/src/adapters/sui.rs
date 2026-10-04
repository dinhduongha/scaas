//! Sui (R64; thiết kế `docs/superpowers/specs/2026-10-03-net-sui.md` §6). Job `signed_op` mang BCS của
//! `bamboo::meta::MetaOp` + chữ ký serialized của ví (base64). Lane = địa chỉ ed25519 của relayer, vừa là
//! sender vừa là chủ gas (không sponsored). PTB BCS dựng TẠI ĐÂY — không ký bytes do RPC dựng (RS7-5).
//! Sui không có sequence tài khoản: một tx bay mỗi lane là đủ (gas coin của lane không bao giờ nằm
//! trong hai tx đã ký khác nhau ⇒ không equivocation); gửi lại = cùng bytes.
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Signed, TxStatus};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{blake2b256, LocalSigner, Signer};

pub type Addr = [u8; 32];

const DOMAIN: &[u8] = b"bamboo.metaop.v1";
const OP_PAY: u8 = 0;
const FLAG_ED25519: u8 = 0;
const FLAG_SECP256R1: u8 = 2;
const FLAG_PASSKEY: u8 = 6;
const DEFAULT_BUDGET: u64 = 50_000_000;
const CLOCK_VERSION: u64 = 1;
/// Độ dài phần chữ ký lane (`0x00 ‖ sig64 ‖ pk32`) nối sau tx bytes trong `Signed::raw`.
const LANE_SIG_LEN: usize = 97;

// ------------------------------------------------------------------ BCS

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).filter(|e| *e <= self.b.len()).ok_or_else(|| anyhow!("truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn uleb(&mut self) -> Result<usize> {
        let (mut n, mut shift) = (0usize, 0u32);
        loop {
            let b = self.u8()?;
            if shift > 28 {
                bail!("uleb128 too long");
            }
            n |= ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                return Ok(n);
            }
            shift += 7;
        }
    }
    fn vec(&mut self) -> Result<Vec<u8>> {
        let n = self.uleb()?;
        Ok(self.take(n)?.to_vec())
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into()?))
    }
    fn addr(&mut self) -> Result<Addr> {
        Ok(self.take(32)?.try_into()?)
    }
    fn done(&self) -> Result<()> {
        if self.i != self.b.len() {
            bail!("trailing bytes");
        }
        Ok(())
    }
}

fn uleb(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn vec(out: &mut Vec<u8>, b: &[u8]) {
    uleb(out, b.len());
    out.extend_from_slice(b);
}

pub fn parse_addr(s: &str) -> Result<Addr> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.is_empty() || h.len() > 64 {
        bail!("bad Sui address {s}");
    }
    let mut a = [0u8; 32];
    alloy::hex::decode_to_slice(format!("{h:0>64}"), &mut a).with_context(|| format!("bad Sui address {s}"))?;
    Ok(a)
}

pub fn addr_hex(a: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(a))
}

// ------------------------------------------------------------------ payload

/// `bamboo::meta::MetaOp` (BCS). `domain` cố định nên không lưu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaOp {
    pub network: Vec<u8>,
    pub contract: Addr,
    pub op: u8,
    pub from: Addr,
    pub to: Addr,
    pub amount: u128,
    pub pay_ref: Vec<u8>,
    pub lane: Vec<u8>,
    pub nonce: u64,
    pub valid_until: u64,
    pub relayer: Addr,
    pub extra: Vec<u8>,
}

impl MetaOp {
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        if r.vec()? != DOMAIN {
            bail!("not a bamboo.metaop.v1 payload");
        }
        let op = Self {
            network: r.vec()?,
            contract: r.addr()?,
            op: r.u8()?,
            from: r.addr()?,
            to: r.addr()?,
            amount: r.u128()?,
            pay_ref: r.vec()?,
            lane: r.vec()?,
            nonce: r.u64()?,
            valid_until: r.u64()?,
            relayer: r.addr()?,
            extra: r.vec()?,
        };
        r.done()?;
        if op.pay_ref.len() != 32 || op.lane.len() != 32 || op.extra.len() != 32 {
            bail!("pay_ref, lane and extra are 32 bytes");
        }
        Ok(op)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::new();
        vec(&mut o, DOMAIN);
        vec(&mut o, &self.network);
        o.extend_from_slice(&self.contract);
        o.push(self.op);
        o.extend_from_slice(&self.from);
        o.extend_from_slice(&self.to);
        o.extend_from_slice(&self.amount.to_le_bytes());
        vec(&mut o, &self.pay_ref);
        vec(&mut o, &self.lane);
        o.extend_from_slice(&self.nonce.to_le_bytes());
        o.extend_from_slice(&self.valid_until.to_le_bytes());
        o.extend_from_slice(&self.relayer);
        vec(&mut o, &self.extra);
        o
    }
}

/// Digest ví Sui ký trong `signPersonalMessage`: intent (3,0,0) ‖ BCS(vector<u8>).
pub fn personal_digest(msg: &[u8]) -> [u8; 32] {
    let mut b = vec![3u8, 0, 0];
    vec(&mut b, msg);
    blake2b256(&b)
}

/// `bamboo::auth::Auth` tách từ chữ ký serialized của Sui.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    pub flag: u8,
    pub sig: Vec<u8>,
    pub public_key: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

/// `flag ‖ sig64 ‖ pk` (ed25519 32 / secp256k1, secp256r1 33) hoặc passkey `0x06 ‖ bcs(PasskeyAuthenticator)`.
pub fn parse_signature(b64: &str) -> Result<Auth> {
    let raw = B64.decode(b64.trim())?;
    let (&flag, rest) = raw.split_first().ok_or_else(|| anyhow!("empty signature"))?;
    match flag {
        0..=2 => {
            let pk_len = if flag == FLAG_ED25519 { 32 } else { 33 };
            if rest.len() != 64 + pk_len {
                bail!("bad signature length");
            }
            Ok(Auth { flag, sig: rest[..64].to_vec(), public_key: rest[64..].to_vec(), authenticator_data: vec![], client_data_json: vec![] })
        }
        FLAG_PASSKEY => {
            let mut r = Reader::new(rest);
            let (ad, cd, user) = (r.vec()?, r.vec()?, r.vec()?);
            r.done()?;
            if user.len() != 98 || user[0] != FLAG_SECP256R1 {
                bail!("bad passkey user signature");
            }
            Ok(Auth { flag, sig: user[1..65].to_vec(), public_key: user[65..].to_vec(), authenticator_data: ad, client_data_json: cd })
        }
        f => bail!("unsupported signature scheme {f}"),
    }
}

/// `0xADDR::module::Name` (không generic) ⇒ BCS TypeTag::Struct.
pub fn type_tag(s: &str) -> Result<Vec<u8>> {
    let mut it = s.split("::");
    let (Some(a), Some(m), Some(n), None) = (it.next(), it.next(), it.next(), it.next()) else {
        bail!("bad coin type {s}");
    };
    let ident = |x: &str| !x.is_empty() && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ident(m) || !ident(n) {
        bail!("bad coin type {s}");
    }
    let mut o = vec![7u8];
    o.extend_from_slice(&parse_addr(a)?);
    vec(&mut o, m.as_bytes());
    vec(&mut o, n.as_bytes());
    uleb(&mut o, 0);
    Ok(o)
}

// ------------------------------------------------------------------ transaction

pub struct ObjRef {
    pub id: Addr,
    pub version: u64,
    pub digest: [u8; 32],
}

/// `TransactionData::V1(ProgrammableTransaction[auth::new, meta::relay_pay<T>])`, expiration None.
#[allow(clippy::too_many_arguments)]
pub fn pay_tx(package: &Addr, op: &MetaOp, auth: &Auth, account_isv: u64, coin_tag: &[u8], sender: &Addr, gas: &ObjRef, price: u64, budget: u64) -> Vec<u8> {
    let pure = |bcs: &[u8]| {
        let mut o = vec![0u8];
        vec(&mut o, bcs);
        o
    };
    let pure_vec = |b: &[u8]| {
        let mut inner = Vec::new();
        vec(&mut inner, b);
        pure(&inner)
    };
    let shared = |id: &Addr, isv: u64, mutable: bool| {
        let mut o = vec![1u8, 1u8];
        o.extend_from_slice(id);
        o.extend_from_slice(&isv.to_le_bytes());
        o.push(mutable as u8);
        o
    };
    let mut clock = [0u8; 32];
    clock[31] = 6;
    let inputs = [
        pure_vec(&auth.sig),                                // 0
        pure_vec(&auth.authenticator_data),                 // 1
        pure_vec(&auth.client_data_json),                   // 2
        shared(&op.contract, account_isv, true),            // 3 account
        pure(&op.to),                                       // 4
        pure(&op.amount.to_le_bytes()),                     // 5
        pure_vec(&op.pay_ref),                              // 6
        pure_vec(&op.lane),                                 // 7
        pure(&op.nonce.to_le_bytes()),                      // 8
        pure(&op.valid_until.to_le_bytes()),                // 9
        pure(&op.relayer),                                  // 10
        pure_vec(&op.extra),                                // 11
        shared(&clock, CLOCK_VERSION, false),               // 12
    ];
    let input = |i: u16| [1u8, i as u8, (i >> 8) as u8];
    let call = |module: &str, function: &str, tags: &[&[u8]], args: &[[u8; 3]]| {
        let mut o = vec![0u8];
        o.extend_from_slice(package);
        vec(&mut o, module.as_bytes());
        vec(&mut o, function.as_bytes());
        uleb(&mut o, tags.len());
        tags.iter().for_each(|t| o.extend_from_slice(t));
        uleb(&mut o, args.len());
        args.iter().for_each(|a| o.extend_from_slice(a));
        o
    };
    let auth_new = call("auth", "new", &[], &[input(0), input(1), input(2)]);
    let result0 = [2u8, 0, 0];
    let relay = call("meta", "relay_pay", &[coin_tag], &[
        input(3), input(4), input(5), input(6), input(7), input(8), input(9), input(10), input(11), result0, input(12),
    ]);
    let mut o = vec![0u8, 0u8]; // TransactionData::V1, TransactionKind::ProgrammableTransaction
    uleb(&mut o, inputs.len());
    inputs.iter().for_each(|i| o.extend_from_slice(i));
    uleb(&mut o, 2);
    o.extend_from_slice(&auth_new);
    o.extend_from_slice(&relay);
    o.extend_from_slice(sender);
    uleb(&mut o, 1); // gas payment
    o.extend_from_slice(&gas.id);
    o.extend_from_slice(&gas.version.to_le_bytes());
    vec(&mut o, &gas.digest);
    o.extend_from_slice(sender); // gas owner
    o.extend_from_slice(&price.to_le_bytes());
    o.extend_from_slice(&budget.to_le_bytes());
    o.push(0); // TransactionExpiration::None
    o
}

/// Digest giao dịch Sui (id hiển thị dạng base58).
pub fn tx_digest(tx: &[u8]) -> [u8; 32] {
    let mut b = b"TransactionData::".to_vec();
    b.extend_from_slice(tx);
    blake2b256(&b)
}

/// Thông điệp lane ký: intent (TransactionData, V0, Sui) ‖ tx bytes.
pub fn tx_signing_digest(tx: &[u8]) -> [u8; 32] {
    let mut b = vec![0u8, 0, 0];
    b.extend_from_slice(tx);
    blake2b256(&b)
}

pub fn lane_address(pk: &[u8]) -> Addr {
    let mut b = vec![FLAG_ED25519];
    b.extend_from_slice(pk);
    blake2b256(&b)
}

// ------------------------------------------------------------------ events

fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Array(a) => a.iter().map(|x| x.as_u64().filter(|n| *n < 256).map(|n| n as u8)).collect(),
        Value::String(s) if s.starts_with("0x") => alloy::hex::decode(&s[2..]).ok(),
        Value::String(s) => B64.decode(s).ok(),
        _ => None,
    }
}

fn str_or_num(v: &Value) -> Option<String> {
    match v {
        Value::String(s) if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) => Some(s.clone()),
        Value::Number(n) => n.as_u64().map(|n| n.to_string()),
        _ => None,
    }
}

fn canon(v: &Value) -> Option<String> {
    v.as_str().and_then(|s| parse_addr(s).ok()).map(|a| addr_hex(&a))
}

/// Một event JSON-RPC của Sui ⇒ event chuẩn hoá cho Odoo; `None` nếu không phải của ta/registry lạ/hỏng.
pub fn normalize(package: &Addr, registries: &[String], ev: &Value, block: u64, block_hash: &str, tx_hash: &str) -> Option<Value> {
    let ty = ev.get("type")?.as_str()?;
    let mut it = ty.splitn(3, "::");
    let (pkg, module, name) = (it.next()?, it.next()?, it.next()?);
    if parse_addr(pkg).ok()? != *package || module != "meta" {
        return None;
    }
    let p = ev.get("parsedJson")?;
    let contract = canon(p.get("contract")?)?;
    if !registries.contains(&contract) {
        return None;
    }
    let log_index = str_or_num(ev.get("id")?.get("eventSeq")?)?.parse::<u64>().ok()?;
    let mut out = json!({
        "contract": contract, "block_number": block, "block_hash": block_hash, "tx_hash": tx_hash,
        "log_index": log_index, "from": canon(p.get("from")?)?,
    });
    match name {
        "PaymentSettled" => {
            let r = bytes_of(p.get("pay_ref")?).filter(|b| b.len() == 32)?;
            out["event"] = json!("PaymentSettled");
            out["to"] = json!(canon(p.get("to")?)?);
            out["amount"] = json!(str_or_num(p.get("amount")?)?);
            out["entry_ref"] = json!(addr_hex(&r));
        }
        "MetaTransactionExecuted" => {
            let d = bytes_of(p.get("digest")?).filter(|b| b.len() == 32)?;
            out["event"] = json!("MetaTransactionExecuted");
            out["digest"] = json!(addr_hex(&d));
        }
        _ => return None,
    }
    Some(out)
}

/// Event của một lô tx `chunk` (digest base58, checkpoint, hash checkpoint) từ `sui_multiGetTransactionBlocks`.
/// Mọi tx phải có mặt, đúng thứ tự, có `events`: tx thiếu/bị prune/lỗi ⇒ `Err`, vùng không được chốt (review L5).
pub fn tx_events(package: &Addr, registries: &[String], chunk: &[(String, u64, String)], r: &Value) -> Result<Vec<Value>> {
    let blocks = r.as_array().ok_or_else(|| anyhow!("multiGetTransactionBlocks: not a list"))?;
    if blocks.len() != chunk.len() {
        bail!("multiGetTransactionBlocks: {} of {} transactions", blocks.len(), chunk.len());
    }
    let mut out = Vec::new();
    for (blk, (d58, seq, ch)) in blocks.iter().zip(chunk) {
        let events = match (blk["digest"].as_str(), blk["events"].as_array()) {
            (Some(d), Some(e)) if d == d58 && blk.get("error").is_none() => e,
            _ => bail!("transaction {d58} not served with its events: {blk}"),
        };
        let tx_hash = addr_hex(&bs58::decode(d58).into_vec()?);
        out.extend(events.iter().filter_map(|ev| normalize(package, registries, ev, *seq, ch, &tx_hash)));
    }
    Ok(out)
}

// ------------------------------------------------------------------ adapter

pub struct SuiAdapter {
    key: String,
    rpcs: Vec<String>,
    http: reqwest::Client,
    /// Đích lệnh gọi (package mới nhất sau nâng cấp).
    package: Addr,
    /// Id package GỐC: type của event giữ id này qua mọi lần nâng cấp (review L1).
    type_package: Addr,
    budget_cap: u64,
    quorum: usize,
    lanes: Vec<Lane>,
    signers: Vec<LocalSigner>,
    /// Thư mục journal lane (review M3): tx đã ký cuối của mỗi lane, sống qua khởi động lại.
    journal: std::path::PathBuf,
}

/// Tx đã ký cuối cùng của một lane, ghi TRƯỚC khi gửi. Khởi động lại: xử lý xong nó rồi mới dựng tx mới trên coin
/// của nó — không bao giờ ký tx thứ hai trên cùng version gas coin (equivocation khoá coin tới hết epoch).
#[derive(serde::Serialize, serde::Deserialize)]
struct Pending {
    tx: String,
    sig: String,
    digest: String,
    gas: String,
    gas_version: u64,
}

struct Work {
    op: MetaOp,
    auth: Auth,
    coin_tag: Vec<u8>,
}

fn param_str<'a>(cfg: &'a ChainCfg, k: &str) -> Option<&'a str> {
    cfg.params.get(k).and_then(|v| v.as_str())
}

impl SuiAdapter {
    pub fn new(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        if cfg.rpc_urls.is_empty() || signers.is_empty() {
            bail!("chain {}: needs rpc_urls and at least one lane", cfg.chain_key());
        }
        let package = parse_addr(param_str(cfg, "package").ok_or_else(|| anyhow!("sui: params.package is required"))?)?;
        let type_package = param_str(cfg, "type_package").map(parse_addr).transpose()?.unwrap_or(package);
        let journal = param_str(cfg, "lane_journal")
            .ok_or_else(|| anyhow!("sui: params.lane_journal (a directory that survives restarts) is required"))?;
        std::fs::create_dir_all(journal).with_context(|| format!("sui: lane_journal {journal}"))?;
        let budget_cap = cfg.params.get("max_gas_budget").and_then(|v| v.as_integer()).map(|v| v as u64).unwrap_or(DEFAULT_BUDGET);
        let mut own = Vec::new();
        let mut lanes = Vec::new();
        for (s, &i) in signers.iter().zip(&cfg.lanes) {
            let LocalSigner::Ed(k) = s else { bail!("sui lanes are ed25519") };
            lanes.push(Lane { index: i, address: addr_hex(&lane_address(&k.verifying_key().to_bytes())) });
            own.push(LocalSigner::Ed(k.clone()));
        }
        Ok(Self {
            key: cfg.chain_key(),
            rpcs: cfg.rpc_urls.clone(),
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).build()?,
            package,
            type_package,
            budget_cap,
            quorum: cfg.finality.quorum.max(1),
            lanes,
            signers: own,
            journal: journal.into(),
        })
    }

    fn journal_path(&self, lane: usize) -> std::path::PathBuf {
        let index = self.lanes.get(lane).map_or(lane as u32, |l| l.index);
        self.journal.join(format!("{}-lane{index}.json", self.key.replace(|c: char| !c.is_ascii_alphanumeric(), "_")))
    }

    fn write_pending(&self, lane: usize, p: &Pending) -> Result<()> {
        use std::io::Write;
        let path = self.journal_path(lane);
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&serde_json::to_vec(p)?)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Coin của tx đã ký trước đó mà CHƯA thể dùng lại (`None` = lane sạch). Tx đã vào sổ hoặc coin đã sang version
    /// khác (tx đó không bao giờ chạy được nữa) ⇒ xoá journal. Còn treo ⇒ gửi lại đúng bytes cũ, giữ coin đó.
    async fn previous_gas(&self, lane: usize) -> Result<Option<Addr>> {
        let path = self.journal_path(lane);
        let p: Pending = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("lane journal {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let gas = parse_addr(&p.gas)?;
        let live = match self.tx_status(&p.digest).await? {
            TxStatus::Mined { .. } | TxStatus::Reverted { .. } => false,
            TxStatus::Pending => true,
            TxStatus::Unknown => {
                let o = self.rpc("sui_getObject", json!([p.gas, {}])).await?;
                let v = o["data"]["version"].as_str().and_then(|v| v.parse().ok()).or_else(|| o["data"]["version"].as_u64());
                let live = v == Some(p.gas_version);
                if live {
                    if let Err(e) = self.execute(&p.tx, &p.sig).await {
                        tracing::warn!(chain = %self.key, lane, digest = %p.digest, "re-send of journaled tx: {e:#}");
                    }
                }
                live
            }
        };
        if live {
            return Ok(Some(gas));
        }
        std::fs::remove_file(&path)?;
        Ok(None)
    }

    async fn execute(&self, tx_b64: &str, sig_b64: &str) -> Result<()> {
        self.rpc("sui_executeTransactionBlock", json!([tx_b64, [sig_b64], {"showEffects": true}])).await.map(|_| ())
    }

    async fn rpc_at(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v: Value = self.http.post(url).json(&body).send().await?.error_for_status()?.json().await?;
        if let Some(e) = v.get("error") {
            bail!("{method}: {e}");
        }
        v.get("result").cloned().ok_or_else(|| anyhow!("{method}: no result"))
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc_at(&self.rpcs[0], method, params).await
    }

    fn work(&self, job: &Job) -> Result<Work> {
        let o = job.op.as_ref().ok_or_else(|| anyhow!("not a signed_op job"))?;
        let payload = alloy::hex::decode(o["payload"].as_str().unwrap_or_default().trim_start_matches("0x"))?;
        let op = MetaOp::decode(&payload)?;
        if op.op != OP_PAY {
            bail!("only pay ops are relayed on Sui");
        }
        if parse_addr(o["contract"].as_str().unwrap_or_default())? != op.contract {
            bail!("payload contract differs from the job contract");
        }
        let auth = parse_signature(o["signature"].as_str().unwrap_or_default())?;
        let coin_tag = type_tag(o["extra"]["coin_type"].as_str().ok_or_else(|| anyhow!("extra.coin_type missing"))?)?;
        Ok(Work { op, auth, coin_tag })
    }

    /// `initial_shared_version` của account; `Ok(None)` = không tồn tại / không phải shared.
    async fn shared_version(&self, id: &Addr) -> Result<Option<u64>> {
        let r = self.rpc("sui_getObject", json!([addr_hex(id), {"showOwner": true}])).await?;
        Ok(r["data"]["owner"]["Shared"]["initial_shared_version"].as_u64()
            .or_else(|| r["data"]["owner"]["Shared"]["initial_shared_version"].as_str().and_then(|s| s.parse().ok())))
    }

    /// Coin SUI lớn nhất của lane (đọc lại mỗi job — lane chỉ có một tx bay nên version luôn mới).
    /// `skip` = coin của tx cũ còn treo (review M3).
    async fn gas_coin(&self, owner: &Addr, skip: Option<Addr>) -> Result<(ObjRef, u64)> {
        let r = self.rpc("suix_getCoins", json!([addr_hex(owner), "0x2::sui::SUI", null, 50])).await?;
        let mut best: Option<(ObjRef, u64)> = None;
        for c in r["data"].as_array().cloned().unwrap_or_default() {
            let bal: u64 = c["balance"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
            if best.as_ref().is_some_and(|(_, b)| *b >= bal) {
                continue;
            }
            if skip.is_some_and(|g| c["coinObjectId"].as_str().and_then(|i| parse_addr(i).ok()) == Some(g)) {
                continue;
            }
            let digest: [u8; 32] = bs58::decode(c["digest"].as_str().unwrap_or_default())
                .into_vec()?
                .try_into()
                .map_err(|_| anyhow!("bad coin digest"))?;
            let version = c["version"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("bad coin version"))?;
            best = Some((ObjRef { id: parse_addr(c["coinObjectId"].as_str().unwrap_or_default())?, version, digest }, bal));
        }
        best.ok_or_else(|| anyhow!("lane {} has no usable SUI for gas (previous tx still pending: {skip:?})", addr_hex(owner)))
    }

    async fn gas_price(&self) -> Result<u64> {
        let v = self.rpc("suix_getReferenceGasPrice", json!([])).await?;
        v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64()).ok_or_else(|| anyhow!("bad gas price"))
    }

    async fn checkpoint_digest(&self, url: &str, seq: u64) -> Result<String> {
        let c = self.rpc_at(url, "sui_getCheckpoint", json!([seq.to_string()])).await?;
        let d = bs58::decode(c["digest"].as_str().unwrap_or_default()).into_vec()?;
        if d.len() != 32 {
            bail!("bad checkpoint digest");
        }
        Ok(addr_hex(&d))
    }

    fn lane_addr(&self, lane: usize) -> Result<Addr> {
        parse_addr(&self.lanes.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?.address)
    }
}

fn transport(e: anyhow::Error) -> SimError {
    SimError::Transport(format!("{e:#}"))
}

#[async_trait]
impl ChainAdapter for SuiAdapter {
    fn family(&self) -> Family {
        Family::Sui
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let w = self.work(job).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        let sender = self.lane_addr(lane).map_err(transport)?;
        let skip = self.previous_gas(lane).await.map_err(transport)?;
        let isv = self
            .shared_version(&w.op.contract)
            .await
            .map_err(transport)?
            .ok_or_else(|| SimError::Revert(format!("account {} does not exist", addr_hex(&w.op.contract))))?;
        let price = self.gas_price().await.map_err(transport)?;
        let (gas, balance) = match self.gas_coin(&sender, skip).await {
            Ok(g) => g,
            Err(e) => {
                // ponytail: runner trả job về hàng đợi rồi thử ngay — chậm lại khi chỉ chờ tx cũ của lane.
                if skip.is_some() {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                return Err(transport(e));
            }
        };
        let cap = self.budget_cap.min(balance);
        let tx = pay_tx(&self.package, &w.op, &w.auth, isv, &w.coin_tag, &sender, &gas, price, cap);
        let dry = self.rpc("sui_dryRunTransactionBlock", json!([B64.encode(&tx)])).await.map_err(transport)?;
        let st = &dry["effects"]["status"];
        if st["status"].as_str() != Some("success") {
            return Err(SimError::Revert(st["error"].as_str().unwrap_or("dry run failed").to_string()));
        }
        let cost = |k: &str| dry["effects"]["gasUsed"][k].as_str().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let used = cost("computationCost") + cost("storageCost");
        let budget = (used + used / 5).max(price * 1000).min(cap);
        let tx = pay_tx(&self.package, &w.op, &w.auth, isv, &w.coin_tag, &sender, &gas, price, budget);
        let meta = json!({"budget": budget, "gas": addr_hex(&gas.id), "gas_version": gas.version});
        Ok(Built { job_id: job.id, body: tx, valid_until: w.op.valid_until, meta })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let s = self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?;
        let sig = s.sign(&tx_signing_digest(&built.body))?;
        let mut raw = built.body.clone();
        raw.push(FLAG_ED25519);
        raw.extend_from_slice(&sig);
        raw.extend_from_slice(&s.public_key());
        let tx_id = addr_hex(&tx_digest(&built.body));
        // Journal TRƯỚC khi trả (trước `signed` ở Odoo và trước khi gửi) — review M3.
        let pending = Pending {
            tx: B64.encode(&built.body),
            sig: B64.encode(&raw[built.body.len()..]),
            digest: tx_id.clone(),
            gas: built.meta["gas"].as_str().ok_or_else(|| anyhow!("built without gas coin"))?.to_string(),
            gas_version: built.meta["gas_version"].as_u64().ok_or_else(|| anyhow!("built without gas version"))?,
        };
        self.write_pending(lane, &pending).context("lane journal")?;
        Ok(Signed { job_id: built.job_id, tx_id, raw, valid_until: built.valid_until, sequence })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        if signed.raw.len() <= LANE_SIG_LEN {
            bail!("signed tx too short");
        }
        let (tx, sig) = signed.raw.split_at(signed.raw.len() - LANE_SIG_LEN);
        self.execute(&B64.encode(tx), &B64.encode(sig)).await
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let d = bs58::encode(parse_addr(tx_id)?).into_string();
        let r = match self.rpc("sui_getTransactionBlock", json!([d, {"showEffects": true}])).await {
            Ok(r) => r,
            Err(e) if format!("{e:#}").contains("Could not find") => return Ok(TxStatus::Unknown),
            Err(e) => return Err(e),
        };
        let height = r["checkpoint"].as_str().and_then(|s| s.parse().ok()).or_else(|| r["checkpoint"].as_u64());
        Ok(match (r["effects"]["status"]["status"].as_str(), height) {
            (Some("success"), Some(h)) => TxStatus::Mined { height: h },
            (Some("failure"), _) => TxStatus::Reverted { reason: r["effects"]["status"]["error"].as_str().unwrap_or("failure").into() },
            _ => TxStatus::Pending,
        })
    }

    async fn sequence(&self, _lane: usize) -> Result<u64> {
        Ok(0) // Sui: không nonce tài khoản (R62).
    }

    /// Journal lane (review M3): tx đã ký trước crash được gửi lại đúng bytes để `recover_lane` thấy nó vào sổ.
    async fn resend_journaled(&self, lane: usize) -> Result<()> {
        self.previous_gas(lane).await.map(|_| ())
    }

    async fn final_head(&self) -> Result<Option<Head>> {
        let v = self.rpc("sui_getLatestCheckpointSequenceNumber", json!([])).await?;
        let seq: u64 = v.as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("bad checkpoint number"))?;
        let hash = self.checkpoint_digest(&self.rpcs[0], seq).await?;
        let mut agree = 1;
        for url in &self.rpcs[1..] {
            if self.checkpoint_digest(url, seq).await.ok().as_deref() == Some(hash.as_str()) {
                agree += 1;
            }
        }
        Ok((agree >= self.quorum).then_some(Head { height: seq, hash }))
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        self.checkpoint_digest(&self.rpcs[0], height).await
    }

    /// `contracts` = id `Registry<T>` các token Odoo đã đăng ký (review H2: không danh sách tĩnh trong cấu hình node).
    /// `ponytail:` quét mọi tx của checkpoint trong vùng — đổi sang gRPC/GraphQL lọc theo package khi tải lớn.
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let registries: Vec<String> = contracts.iter().filter_map(|c| parse_addr(c).ok()).map(|a| addr_hex(&a)).collect();
        if registries.is_empty() || from > to {
            return Ok(vec![]);
        }
        let mut txs: Vec<(String, u64, String)> = Vec::new(); // (tx digest b58, checkpoint, checkpoint hash)
        let mut cursor = from.checked_sub(1).map(|c| c.to_string());
        'pages: loop {
            let page = self.rpc("sui_getCheckpoints", json!([cursor, 100, false])).await?;
            let data = page["data"].as_array().cloned().unwrap_or_default();
            if data.is_empty() {
                break;
            }
            for c in &data {
                let seq: u64 = c["sequenceNumber"].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| anyhow!("bad checkpoint"))?;
                if seq > to {
                    break 'pages;
                }
                let d = bs58::decode(c["digest"].as_str().unwrap_or_default()).into_vec()?;
                let h = addr_hex(&d);
                for t in c["transactions"].as_array().cloned().unwrap_or_default() {
                    txs.push((t.as_str().unwrap_or_default().to_string(), seq, h.clone()));
                }
                cursor = Some(seq.to_string());
                if seq == to {
                    break 'pages;
                }
            }
            if page["hasNextPage"].as_bool() != Some(true) {
                break;
            }
        }
        let mut out = Vec::new();
        for chunk in txs.chunks(50) {
            let ids: Vec<&str> = chunk.iter().map(|t| t.0.as_str()).collect();
            let r = self.rpc("sui_multiGetTransactionBlocks", json!([ids, {"showEvents": true}])).await?;
            out.extend(tx_events(&self.type_package, &registries, chunk, &r)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Vector chéo — cùng bytes ở chains/sui/tests/vectors.move và dms_blockchain/tests/test_fam_sui.py.
    const PAYLOAD: &str = "1062616d626f6f2e6d6574616f702e7631086c6f63616c6e6574d4793a1919a40ebfe5587a3a49fe89bb64c54bd49c75ab2a08ac0d5636706382006a749c33bda66662e3709eea404a27dbb2b27d7a58bc0a1248d12436fb2fae71000000000000000000000000000000000000000000000000000000000000beef6400000000000000000000000000000020010101010101010101010101010101010101010101010101010101010101010120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000";
    const DIGEST: &str = "b1e94f8ff971d3a06b4ef18ac50c0283320db9eeca1171831ce52612d5708799";
    const SIGNATURE: &str = "AEKwatGlEwsMK2lb91bMHMY/KA1dGEh3oqEJBZ0K/X6o3SGonMkOLSBcyNljeDrNj11RBGwPwRhYgxriKwCfmg3Vv0o/zOcXsDiLzCdJ68FIrZlpsj9F7htgX9WHeFdqxA==";
    const TX_B64: &str = "AAANAEFAQrBq0aUTCwwraVv3Vswcxj8oDV0YSHeioQkFnQr9fqjdIaicyQ4tIFzI2WN4Os2PXVEEbA/BGFiDGuIrAJ+aDQABAAABAAEB1Hk6GRmkDr/lWHo6Sf6Ju2TFS9ScdasqCKwNVjZwY4IDAAAAAAAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL7vABBkAAAAAAAAAAAAAAAAAAAAACEgAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAISChoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoQAIAAAAAAAAAAAACOgDAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgEAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsEYXV0aANuZXcAAwEAAAEBAAECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwRtZXRhCXJlbGF5X3BheQEHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIDc3VpA1NVSQALAQMAAQQAAQUAAQYAAQcAAQgAAQkAAQoAAQsAAgAAAQwAHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4BqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqoHAAAAAAAAACAHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBx4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e6AMAAAAAAACAhB4AAAAAAAA=";
    const TX_DIGEST: &str = "0x09e162aa79d60ca6da57387ace50103998c2394d55e793d57527de0368838ecb";
    const ALICE: &str = "0x6a749c33bda66662e3709eea404a27dbb2b27d7a58bc0a1248d12436fb2fae71";

    #[test]
    fn payload_and_digest_match_move_and_python() {
        let b = alloy::hex::decode(PAYLOAD).unwrap();
        let op = MetaOp::decode(&b).unwrap();
        assert_eq!((op.amount, op.nonce, op.valid_until, op.network.as_slice()), (100, 0, 1000, &b"localnet"[..]));
        assert_eq!(addr_hex(&op.from), ALICE);
        assert_eq!(addr_hex(&op.to), addr_hex(&parse_addr("0xbeef").unwrap()));
        assert_eq!(op.encode(), b);
        assert_eq!(alloy::hex::encode(personal_digest(&b)), DIGEST);
        let a = parse_signature(SIGNATURE).unwrap();
        assert_eq!((a.flag, addr_hex(&lane_address(&a.public_key))), (0, ALICE.to_string()));
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&a.public_key.clone().try_into().unwrap()).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&a.sig).unwrap();
        vk.verify_strict(&alloy::hex::decode(DIGEST).unwrap(), &sig).unwrap();
    }

    #[test]
    fn type_tags_and_addresses() {
        assert_eq!(addr_hex(&parse_addr("0x6").unwrap()), format!("0x{:0>64}", "6"));
        assert!(parse_addr(&format!("0x{}", "1".repeat(65))).is_err());
        let t = type_tag("0x2::sui::SUI").unwrap();
        assert_eq!(t[0], 7);
        assert_eq!(&t[33..], b"\x03sui\x03SUI\x00");
        for bad in ["0x2::sui", "0x2::sui::SUI::x", "0x2::s-ui::SUI", "0x2::sui::Coin<T>"] {
            assert!(type_tag(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn passkey_signature_parses() {
        let mut raw = vec![FLAG_PASSKEY];
        vec(&mut raw, &[9u8; 37]);
        vec(&mut raw, br#"{"type":"webauthn.get"}"#);
        let mut user = vec![FLAG_SECP256R1];
        user.extend_from_slice(&[1u8; 64]);
        user.extend_from_slice(&[2u8; 33]);
        vec(&mut raw, &user);
        let a = parse_signature(&B64.encode(&raw)).unwrap();
        assert_eq!((a.flag, a.sig, a.public_key.len(), a.authenticator_data.len()), (6, vec![1u8; 64], 33, 37));
        raw.push(0);
        assert!(parse_signature(&B64.encode(&raw)).is_err(), "trailing bytes");
    }

    #[test]
    fn events_are_normalized_and_filtered() {
        let pkg = parse_addr("0xabc").unwrap();
        let reg = addr_hex(&parse_addr("0x7c95").unwrap());
        let regs = std::slice::from_ref(&reg);
        let ev = |name: &str, contract: &str| {
            json!({"id": {"txDigest": "x", "eventSeq": "1"}, "type": format!("{}::meta::{name}", addr_hex(&pkg)),
                   "parsedJson": {"contract": contract, "from": "0x1", "to": "0xbeef", "amount": "100",
                                  "pay_ref": vec![1u8; 32], "digest": vec![0xb1u8; 32]}})
        };
        let n = normalize(&pkg, regs, &ev("PaymentSettled", "0x7c95"), 5, "0xh", "0xt").unwrap();
        assert_eq!(n["event"], "PaymentSettled");
        assert_eq!(n["contract"], reg);
        assert_eq!((n["amount"].as_str(), n["log_index"].as_u64(), n["block_number"].as_u64()), (Some("100"), Some(1), Some(5)));
        assert_eq!(n["entry_ref"], addr_hex(&[1u8; 32]));
        let m = normalize(&pkg, regs, &ev("MetaTransactionExecuted", "0x7c95"), 5, "0xh", "0xt").unwrap();
        assert_eq!(m["digest"], addr_hex(&[0xb1u8; 32]));
        assert!(normalize(&pkg, regs, &ev("PaymentSettled", "0x9999"), 5, "0xh", "0xt").is_none(), "unregistered registry");
        assert!(normalize(&parse_addr("0xdef").unwrap(), regs, &ev("PaymentSettled", "0x7c95"), 5, "0xh", "0xt").is_none(), "other package");
    }

    /// Review L5: tx thiếu/bị prune/lỗi trong `sui_multiGetTransactionBlocks` ⇒ lỗi (vùng KHÔNG được chốt).
    #[test]
    fn missing_or_pruned_tx_fails_the_range() {
        let pkg = parse_addr("0xabc").unwrap();
        let regs = [addr_hex(&parse_addr("0x7c95").unwrap())];
        let (d1, d2) = (bs58::encode([1u8; 32]).into_string(), bs58::encode([2u8; 32]).into_string());
        let chunk = vec![(d1.clone(), 5, "0xh".to_string()), (d2.clone(), 5, "0xh".to_string())];
        let ev = json!({"id": {"eventSeq": "0"}, "type": format!("{}::meta::PaymentSettled", addr_hex(&pkg)),
                        "parsedJson": {"contract": "0x7c95", "from": "0x1", "to": "0x2", "amount": "1", "pay_ref": vec![1u8; 32]}});
        let ok = json!([{"digest": d1, "events": [ev]}, {"digest": d2, "events": []}]);
        assert_eq!(tx_events(&pkg, &regs, &chunk, &ok).unwrap().len(), 1);
        let short = json!([{"digest": d1, "events": []}]);
        assert!(tx_events(&pkg, &regs, &chunk, &short).is_err(), "short answer");
        let pruned = json!([{"digest": d1, "events": []}, {"error": {"code": "notExists", "object_id": d2}}]);
        assert!(tx_events(&pkg, &regs, &chunk, &pruned).is_err(), "error entry");
        let no_events = json!([{"digest": d1, "events": []}, {"digest": d2}]);
        assert!(tx_events(&pkg, &regs, &chunk, &no_events).is_err(), "events not served");
        let swapped = json!([{"digest": d2, "events": []}, {"digest": d1, "events": []}]);
        assert!(tx_events(&pkg, &regs, &chunk, &swapped).is_err(), "order differs");
    }

    /// Review L1: sau nâng cấp, lệnh gọi trỏ package MỚI còn type event giữ id package GỐC.
    #[test]
    fn upgraded_package_calls_the_new_id_and_reads_original_types() {
        let cfg = |extra: &str| -> ChainCfg {
            toml::from_str(&format!("family = \"sui\"\nnetwork = \"localnet\"\nrpc_urls = [\"http://r\"]\nlanes = [0]\n\
                                     finality = {{ mode = \"instant\" }}\nparams = {{ package = \"0xb\", lane_journal = \"/tmp\"{extra} }}"))
            .unwrap()
        };
        let k = [LocalSigner::new(crate::signer::Curve::Ed25519, &[1; 32]).unwrap()];
        let a = SuiAdapter::new(&cfg(""), &k).unwrap();
        assert_eq!((a.package, a.type_package), (parse_addr("0xb").unwrap(), parse_addr("0xb").unwrap()));
        let a = SuiAdapter::new(&cfg(", type_package = \"0xa\""), &k).unwrap();
        assert_eq!((a.package, a.type_package), (parse_addr("0xb").unwrap(), parse_addr("0xa").unwrap()));
    }

    /// Review L4: bytes `TransactionData` của `pay_tx` (vector cố định). Giải độc lập bằng
    /// `sui keytool decode-or-verify-tx --tx-bytes <TX_B64>` (Sui 1.81): ProgrammableTransaction 13 input
    /// (3 pure Auth, account shared mutable isv 3, 8 pure, Clock 0x6 shared immutable isv 1), MoveCall
    /// `0xb::auth::new(Input 0..2)`, MoveCall `0xb::meta::relay_pay<0x2::sui::SUI>(Input 3..11, Result 0, Input 12)`,
    /// sender = gas owner = lane, gas 0xaa@7, giá 1000, budget 2000000, expiration None.
    #[test]
    fn pay_tx_bytes_vector() {
        let op = MetaOp::decode(&alloy::hex::decode(PAYLOAD).unwrap()).unwrap();
        let auth = parse_signature(SIGNATURE).unwrap();
        let gas = ObjRef { id: [0xaa; 32], version: 7, digest: [7u8; 32] };
        let tx = pay_tx(&parse_addr("0xb").unwrap(), &op, &auth, 3, &type_tag("0x2::sui::SUI").unwrap(), &[0x1e; 32], &gas, 1000, 2_000_000);
        assert_eq!(B64.encode(&tx), TX_B64);
        assert_eq!(addr_hex(&tx_digest(&tx)), TX_DIGEST);
    }

    // ---------------------------------------------------------------- lane journal (review M3)

    /// RPC Sui giả: trạng thái tx đã ghi sổ, version hiện tại của gas coin, danh sách coin; ghi lại tx đã gửi.
    #[derive(Default)]
    struct FakeSui {
        status: Option<&'static str>,
        gas_version: u64,
        coins: Vec<(Addr, u64, u64)>,
        executed: Vec<String>,
        dry_runs: u32,
    }
    type FakeShared = std::sync::Arc<std::sync::Mutex<FakeSui>>;

    async fn fake_sui(f: FakeSui) -> (String, FakeShared) {
        use axum::extract::State;
        use axum::Json;
        async fn h(State(s): State<FakeShared>, Json(b): Json<Value>) -> Json<Value> {
            let mut f = s.lock().unwrap();
            let p = &b["params"];
            let r = match b["method"].as_str().unwrap_or_default() {
                "sui_getTransactionBlock" => match f.status {
                    None => return Json(json!({"error": {"code": -32602, "message": "Could not find the referenced transaction"}})),
                    Some(st) => json!({"checkpoint": "9", "effects": {"status": {"status": st}}}),
                },
                "sui_getObject" if p[0] == addr_hex(&[0xaa; 32]) => json!({"data": {"version": f.gas_version.to_string()}}),
                "sui_getObject" => json!({"data": {"owner": {"Shared": {"initial_shared_version": 3}}}}),
                "sui_executeTransactionBlock" => {
                    f.executed.push(p[0].as_str().unwrap().to_string());
                    json!({"digest": "x"})
                }
                "suix_getReferenceGasPrice" => json!("1000"),
                "suix_getCoins" => json!({"data": f.coins.iter().map(|(id, v, bal)| json!({"coinObjectId": addr_hex(id),
                    "version": v.to_string(), "digest": bs58::encode([7u8; 32]).into_string(), "balance": bal.to_string()})).collect::<Vec<_>>()}),
                "sui_dryRunTransactionBlock" => {
                    f.dry_runs += 1;
                    json!({"effects": {"status": {"status": "success"}, "gasUsed": {"computationCost": "1000000", "storageCost": "0"}}})
                }
                m => panic!("unexpected {m}"),
            };
            Json(json!({"jsonrpc": "2.0", "id": 1, "result": r}))
        }
        let s: FakeShared = std::sync::Arc::new(std::sync::Mutex::new(f));
        let app = axum::Router::new().route("/", axum::routing::post(h)).with_state(s.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, s)
    }

    fn journal_adapter(url: &str, dir: &std::path::Path) -> SuiAdapter {
        let cfg: ChainCfg = toml::from_str(&format!(
            "family = \"sui\"\nnetwork = \"localnet\"\nrpc_urls = [\"{url}\"]\nlanes = [0]\nfinality = {{ mode = \"instant\" }}\n\
             params = {{ package = \"0xb\", lane_journal = \"{}\" }}",
            dir.display()
        ))
        .unwrap();
        SuiAdapter::new(&cfg, &[LocalSigner::new(crate::signer::Curve::Ed25519, &[1; 32]).unwrap()]).unwrap()
    }

    fn pay_job() -> Job {
        let op = MetaOp::decode(&alloy::hex::decode(PAYLOAD).unwrap()).unwrap();
        serde_json::from_value(json!({"id": 1, "kind": "signed_op", "op": {"payload": PAYLOAD, "signature": SIGNATURE,
            "contract": addr_hex(&op.contract), "extra": {"coin_type": "0x2::sui::SUI"}}}))
        .unwrap()
    }

    fn tmp_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sui-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Gas coin của tx trong `body` (`TransactionData` của `pay_tx`): đuôi = id ‖ version ‖ digest ‖ owner ‖ giá ‖ budget ‖ hạn.
    fn gas_of(body: &[u8]) -> Addr {
        body[body.len() - 122..body.len() - 90].try_into().unwrap()
    }

    /// Ký một tx trên coin 0xaa@7 rồi "chết" trước khi gửi: tx đó nằm trong journal của lane.
    async fn crash_after_sign(dir: &std::path::Path) -> Vec<u8> {
        let (url, _f) = fake_sui(FakeSui { coins: vec![([0xaa; 32], 7, 5_000_000_000)], ..Default::default() }).await;
        let a = journal_adapter(&url, dir);
        let built = a.build(&pay_job(), 0).await.unwrap();
        assert_eq!(gas_of(&built.body), [0xaa; 32]);
        a.sign(built.clone(), 0, 0).await.unwrap();
        built.body
    }

    /// Review M3: khởi động lại sau khi ký mà tx cũ chưa thấy trên mạng và coin của nó còn nguyên version ⇒ gửi lại
    /// ĐÚNG bytes cũ, và tx mới không bao giờ dựng trên coin đó (không equivocation).
    #[tokio::test]
    async fn restart_resends_the_journaled_tx_and_never_reuses_its_coin() {
        let dir = tmp_dir("resend");
        let old = crash_after_sign(&dir).await;
        let (url, f) = fake_sui(FakeSui { gas_version: 7, coins: vec![([0xaa; 32], 7, 5_000_000_000), ([0xbb; 32], 2, 1_000_000_000)],
                                          ..Default::default() }).await;
        let a = journal_adapter(&url, &dir); // tiến trình mới
        let built = a.build(&pay_job(), 0).await.unwrap();
        assert_eq!(f.lock().unwrap().executed, [B64.encode(&old)], "old bytes re-sent first");
        assert_eq!(gas_of(&built.body), [0xbb; 32], "new tx on another coin");
        // Coin duy nhất là coin của tx cũ ⇒ chưa dựng gì (thử lại sau), không dry-run.
        let (url, f) = fake_sui(FakeSui { gas_version: 7, coins: vec![([0xaa; 32], 7, 5_000_000_000)], ..Default::default() }).await;
        let a = journal_adapter(&url, &dir);
        assert!(matches!(a.build(&pay_job(), 0).await, Err(SimError::Transport(_))));
        assert_eq!(f.lock().unwrap().dry_runs, 0);
    }

    /// Tx cũ đã vào sổ (hay coin đã sang version khác ⇒ tx cũ không bao giờ chạy được) ⇒ xoá journal, coin dùng lại được.
    #[tokio::test]
    async fn settled_or_superseded_journal_is_cleared() {
        for (status, version) in [(Some("success"), 7), (Some("failure"), 7), (None, 8)] {
            let dir = tmp_dir("clear");
            crash_after_sign(&dir).await;
            let (url, f) = fake_sui(FakeSui { status, gas_version: version, coins: vec![([0xaa; 32], 9, 5_000_000_000)], ..Default::default() }).await;
            let a = journal_adapter(&url, &dir);
            let built = a.build(&pay_job(), 0).await.unwrap();
            assert_eq!(gas_of(&built.body), [0xaa; 32], "{status:?}/{version}");
            assert!(f.lock().unwrap().executed.is_empty());
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "journal cleared");
        }
    }

    #[test]
    fn lane_journal_is_required() {
        let cfg: ChainCfg = toml::from_str("family = \"sui\"\nnetwork = \"localnet\"\nrpc_urls = [\"http://r\"]\nlanes = [0]\n\
                                            finality = { mode = \"instant\" }\nparams = { package = \"0xb\" }")
        .unwrap();
        let k = [LocalSigner::new(crate::signer::Curve::Ed25519, &[1; 32]).unwrap()];
        assert!(SuiAdapter::new(&cfg, &k).err().unwrap().to_string().contains("lane_journal"));
    }

    fn arb_op() -> impl Strategy<Value = MetaOp> {
        (
            proptest::collection::vec(any::<u8>(), 0..300),
            any::<[u8; 32]>(),
            any::<u8>(),
            any::<[u8; 32]>(),
            any::<u128>(),
            any::<[u8; 32]>(),
            any::<(u64, u64)>(),
        )
            .prop_map(|(network, contract, op, from, amount, r, (nonce, valid_until))| MetaOp {
                network, contract, op, from, to: r, amount, pay_ref: r.to_vec(), lane: contract.to_vec(), nonce,
                valid_until, relayer: from, extra: r.to_vec(),
            })
    }

    proptest! {
        #[test]
        fn metaop_round_trips(op in arb_op()) {
            prop_assert_eq!(MetaOp::decode(&op.encode()).unwrap(), op);
        }

        #[test]
        fn decoders_never_panic(b in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = MetaOp::decode(&b);
            let _ = parse_signature(&B64.encode(&b));
        }

        #[test]
        fn normalize_never_panics(s in "\\PC{0,200}", n in any::<u64>()) {
            let ev = json!({"type": s, "id": {"eventSeq": n}, "parsedJson": {"contract": s, "from": n}});
            let _ = normalize(&[0u8; 32], &[], &ev, n, "", "");
        }
    }
}
