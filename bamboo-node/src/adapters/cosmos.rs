//! Cosmos (CosmWasm) dưới dạng `ChainAdapter` (R66). Lane = tài khoản secp256k1 `m/44'/118'/0'/0/i` gửi
//! `MsgExecuteContract{Relay{payload, auth}}` vào `bamboo-token`; chủ thể không gửi tx nào nên không có
//! sequence chủ thể để kẹt (R30, R62). Sequence của lane đọc từ chain trước mỗi job (review S14).
//!
//! Mạng: CometBFT RPC (`rpc_urls[0]`: `status`, `block`, `block_results`) + REST gateway (`params.rest`:
//! account, simulate, broadcast, tx). Protobuf (TxBody/AuthInfo/SignDoc/TxRaw, SIGN_MODE_DIRECT) viết tay:
//! sáu kiểu, không kéo `cosmrs`.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ripemd::Ripemd160;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use crate::chain::SimError;
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::{LocalSigner, Signer};

// ------------------------------------------------------------------ bech32 / địa chỉ

const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// BIP-173 bech32 (không phải bech32m) — địa chỉ Cosmos SDK.
pub fn bech32(hrp: &str, data: &[u8]) -> String {
    let mut five = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            five.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        five.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v.extend(&five);
    v.extend([0u8; 6]);
    let pm = polymod(&v) ^ 1;
    let mut out = format!("{hrp}1");
    for d in five.iter().copied().chain((0..6).map(|i| ((pm >> (5 * (5 - i))) & 31) as u8)) {
        out.push(BECH32[d as usize] as char);
    }
    out
}

/// Địa chỉ tài khoản: bech32(prefix, ripemd160(sha256(pk33))).
pub fn account_address(prefix: &str, pk33: &[u8]) -> String {
    bech32(prefix, &Ripemd160::digest(Sha256::digest(pk33)))
}

// ------------------------------------------------------------------ protobuf tối thiểu

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn bytes_field(n: u64, b: &[u8], out: &mut Vec<u8>) {
    varint(n << 3 | 2, out);
    varint(b.len() as u64, out);
    out.extend_from_slice(b);
}

fn opt_bytes(n: u64, b: &[u8], out: &mut Vec<u8>) {
    if !b.is_empty() {
        bytes_field(n, b, out);
    }
}

fn uint_field(n: u64, v: u64, out: &mut Vec<u8>) {
    if v != 0 {
        varint(n << 3, out);
        varint(v, out);
    }
}

fn any_msg(type_url: &str, value: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    opt_bytes(1, type_url.as_bytes(), &mut o);
    opt_bytes(2, value, &mut o);
    o
}

/// `TxBody{messages:[MsgExecuteContract{sender, contract, msg}]}`.
pub fn tx_body(sender: &str, contract: &str, msg: &[u8]) -> Vec<u8> {
    let mut exec = Vec::new();
    opt_bytes(1, sender.as_bytes(), &mut exec);
    opt_bytes(2, contract.as_bytes(), &mut exec);
    opt_bytes(3, msg, &mut exec);
    let mut body = Vec::new();
    bytes_field(1, &any_msg("/cosmwasm.wasm.v1.MsgExecuteContract", &exec), &mut body);
    body
}

/// `AuthInfo{signer_infos:[{secp256k1 pk, SIGN_MODE_DIRECT, sequence}], fee{[coin], gas_limit}}`.
pub fn auth_info(pk33: &[u8], sequence: u64, denom: &str, fee: u128, gas_limit: u64) -> Vec<u8> {
    let mut pk = Vec::new();
    opt_bytes(1, pk33, &mut pk);
    let mut single = Vec::new();
    uint_field(1, 1, &mut single); // SIGN_MODE_DIRECT
    let mut mode = Vec::new();
    bytes_field(1, &single, &mut mode);
    let mut si = Vec::new();
    bytes_field(1, &any_msg("/cosmos.crypto.secp256k1.PubKey", &pk), &mut si);
    bytes_field(2, &mode, &mut si);
    uint_field(3, sequence, &mut si);
    let mut coin = Vec::new();
    opt_bytes(1, denom.as_bytes(), &mut coin);
    opt_bytes(2, fee.to_string().as_bytes(), &mut coin);
    let mut f = Vec::new();
    if fee > 0 {
        bytes_field(1, &coin, &mut f);
    }
    uint_field(2, gas_limit, &mut f);
    let mut ai = Vec::new();
    bytes_field(1, &si, &mut ai);
    bytes_field(2, &f, &mut ai);
    ai
}

pub fn sign_doc(body: &[u8], auth: &[u8], chain_id: &str, account_number: u64) -> Vec<u8> {
    let mut o = Vec::new();
    opt_bytes(1, body, &mut o);
    opt_bytes(2, auth, &mut o);
    opt_bytes(3, chain_id.as_bytes(), &mut o);
    uint_field(4, account_number, &mut o);
    o
}

/// `TxRaw`; chữ ký rỗng vẫn được mã hoá (mô phỏng cần đúng một chữ ký mỗi signer).
pub fn tx_raw(body: &[u8], auth: &[u8], sig: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    opt_bytes(1, body, &mut o);
    opt_bytes(2, auth, &mut o);
    bytes_field(3, sig, &mut o);
    o
}

// ------------------------------------------------------------------ job → Relay, event → chuẩn hoá

fn hex_arg(s: &str) -> Result<Vec<u8>> {
    Ok(alloy::hex::decode(s.trim().trim_start_matches("0x"))?)
}

/// Job `signed_op` ⇒ (contract, msg JSON `{"relay":{payload, auth}}`, valid_until).
/// `signature`: base64 64 byte (ADR-036) hoặc JSON passkey `{signature, authenticator_data, client_data_json}`.
pub fn relay_msg(op: &Value) -> Result<(String, Vec<u8>, u64)> {
    let contract = op["contract"].as_str().ok_or_else(|| anyhow!("op.contract"))?.to_string();
    let payload = hex_arg(op["payload"].as_str().ok_or_else(|| anyhow!("op.payload"))?)?;
    let sig = op["signature"].as_str().ok_or_else(|| anyhow!("op.signature"))?.trim();
    let pk = B64.encode(hex_arg(op["public_key"].as_str().ok_or_else(|| anyhow!("op.public_key"))?)?);
    let valid_until = op["valid_until"].as_u64().ok_or_else(|| anyhow!("op.valid_until"))?;
    let auth = if sig.starts_with('{') {
        let p: Value = serde_json::from_str(sig).context("passkey signature JSON")?;
        let field = |k: &str| p[k].as_str().map(str::to_string).ok_or_else(|| anyhow!("passkey.{k}"));
        json!({"scheme": "passkey", "pubkey": pk, "signature": field("signature")?,
               "authenticator_data": field("authenticator_data")?, "client_data_json": field("client_data_json")?})
    } else {
        if B64.decode(sig).map(|s| s.len()) != Ok(64) {
            bail!("adr036 signature is 64 bytes base64");
        }
        json!({"scheme": "adr036", "pubkey": pk, "signature": sig})
    };
    let msg = json!({"relay": {"payload": B64.encode(&payload), "auth": auth}});
    Ok((contract, serde_json::to_vec(&msg)?, valid_until))
}

fn hash32(s: &str) -> Option<String> {
    let h = s.trim_start_matches("0x").to_ascii_lowercase();
    (h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("0x{h}"))
}

/// Thuộc tính một event. CometBFT < 0.38 trả khoá/giá trị base64: phát hiện qua `_contract_address` mà wasmd
/// luôn gắn (contract không đặt được khoá `_…`) — không đoán theo chain (review L3).
fn attributes(ev: &Value) -> HashMap<String, String> {
    let pairs = || {
        ev["attributes"].as_array().into_iter().flatten().filter_map(|a| Some((a["key"].as_str()?, a["value"].as_str().unwrap_or(""))))
    };
    let plain: HashMap<String, String> = pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    if plain.contains_key("_contract_address") {
        return plain;
    }
    let dec = |s: &str| B64.decode(s).ok().and_then(|b| String::from_utf8(b).ok());
    pairs().filter_map(|(k, v)| Some((dec(k)?, dec(v)?))).collect()
}

/// gRPC-gateway của `simulate`: lỗi thực thi (contract từ chối, tx hỏng) là Unknown(2)/InvalidArgument(3); còn lại
/// (Unavailable 14, DeadlineExceeded 4, ResourceExhausted 8, cổng không body…) là đường truyền ⇒ thử lại (review L2).
fn sim_error(http: u16, v: &Value) -> SimError {
    let why = v["message"].as_str().map(str::to_string).unwrap_or_else(|| format!("{http} {v}"));
    match v["code"].as_u64() {
        Some(2 | 3) if !why.contains("sequence mismatch") => SimError::Revert(why),
        _ => SimError::Transport(why),
    }
}

/// Phản hồi `broadcast` SYNC. 19 = đã có trong mempool/cache (gửi lại sau khi mất phản hồi); 20 = mempool đầy (cùng
/// bytes có thể qua sau). Mã khác ⇒ CheckTx từ chối, tx không vào mempool ⇒ `Rejected` (review L1).
fn broadcast_outcome(http: u16, v: &Value) -> Result<()> {
    let log = || v["tx_response"]["raw_log"].as_str().map(str::to_string).unwrap_or_else(|| v.to_string());
    match v["tx_response"]["code"].as_u64() {
        Some(0) if http == 200 => Ok(()),
        Some(19) => Ok(()),
        Some(c) if c != 0 && c != 20 => Err(Rejected(format!("CheckTx code {c}: {}", log())).into()),
        _ => bail!("broadcast: {http} {}", log()),
    }
}

/// Trạng thái tx `tx_id` (= sha256 bytes) nếu nó nằm trong khối (`block` + `block_results` của RPC CometBFT).
pub fn tx_in_block(block: &Value, results: &Value, tx_id: &str) -> Option<TxStatus> {
    let want = tx_id.trim_start_matches("0x").to_ascii_lowercase();
    let i = block["block"]["data"]["txs"].as_array()?.iter().position(|t| {
        B64.decode(t.as_str().unwrap_or_default()).is_ok_and(|b| alloy::hex::encode(Sha256::digest(&b)) == want)
    })?;
    let height = block["block"]["header"]["height"].as_str()?.parse().ok()?;
    let r = results["txs_results"].as_array()?.get(i)?;
    Some(match r["code"].as_u64().unwrap_or(0) {
        0 => TxStatus::Mined { height },
        _ => TxStatus::Reverted { reason: r["log"].as_str().unwrap_or("failed").to_string() },
    })
}

/// Event của một tx (`block_results.txs_results[i].events`) ⇒ event chuẩn hoá (thiếu `block_hash`, adapter điền).
/// Chỉ contract trong `contracts`; tx lỗi (code ≠ 0) không có event.
pub fn normalize_tx(tx: &Value, contracts: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    if tx["tx_result"]["code"].as_u64().unwrap_or(0) != 0 {
        return out;
    }
    let (Some(height), Some(hash)) = (
        tx["height"].as_str().and_then(|h| h.parse::<u64>().ok()),
        tx["hash"].as_str().and_then(hash32),
    ) else {
        return out;
    };
    let Some(events) = tx["tx_result"]["events"].as_array() else { return out };
    for (i, ev) in events.iter().enumerate() {
        let kind = match ev["type"].as_str() {
            Some("wasm-payment_settled") => "PaymentSettled",
            Some("wasm-meta_tx_executed") => "MetaTransactionExecuted",
            _ => continue,
        };
        let attrs = attributes(ev);
        let Some(contract) = attrs.get("_contract_address") else { continue };
        if !contracts.iter().any(|c| c == contract) {
            continue;
        }
        let mut e = json!({"event": kind, "contract": contract, "block_number": height, "tx_hash": hash,
                           "log_index": i, "from": attrs.get("from").cloned().unwrap_or_default()});
        if kind == "PaymentSettled" {
            let (Some(to), Some(amount), Some(r)) = (attrs.get("to"), attrs.get("amount"), attrs.get("pay_ref").and_then(|r| hash32(r)))
            else {
                continue;
            };
            e["to"] = json!(to);
            e["amount"] = json!(amount);
            e["entry_ref"] = json!(r);
        } else {
            let Some(d) = attrs.get("digest").and_then(|d| hash32(d)) else { continue };
            e["digest"] = json!(d);
        }
        out.push(e);
    }
    out
}

// ------------------------------------------------------------------ adapter

pub struct CosmosAdapter {
    key: String,
    chain_id: String,
    prefix: String,
    denom: String,
    gas_price: f64,
    max_gas: u64,
    rpc: String,
    rest: String,
    lanes: Vec<Lane>,
    signers: Vec<LocalSigner>,
    http: reqwest::Client,
    account_numbers: Mutex<HashMap<usize, u64>>,
    /// tx đã gửi ⇒ khối kế tiếp cần quét khi indexer tx không trả lời (review M2).
    /// ponytail: mục của tx chết hết hạn không bị xoá (vài byte mỗi job), dọn theo `valid_until` nếu cần.
    scan_from: Mutex<HashMap<String, u64>>,
}

impl CosmosAdapter {
    pub fn new(cfg: &ChainCfg, signers: Vec<LocalSigner>) -> Result<Self> {
        let p = |k: &str| cfg.params.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let prefix = p("prefix").ok_or_else(|| anyhow!("chain {}: params.prefix (bech32) is required", cfg.chain_key()))?;
        let rest = p("rest").ok_or_else(|| anyhow!("chain {}: params.rest (REST gateway URL) is required", cfg.chain_key()))?;
        let lanes = signers
            .iter()
            .zip(&cfg.lanes)
            .map(|(s, &i)| Lane { index: i, address: account_address(&prefix, &s.public_key()) })
            .collect();
        if signers.iter().any(|s| s.curve() != crate::signer::Curve::Secp256k1) {
            bail!("chain {}: cosmos lanes are secp256k1", cfg.chain_key());
        }
        // Review L1: chain-id rỗng ⇒ mọi chữ ký sai (CheckTx 4); giá gas 0 ⇒ thiếu phí (13) trên chain có min-gas-prices.
        let chain_id = cfg.network.clone().filter(|n| !n.is_empty());
        let chain_id = chain_id.ok_or_else(|| anyhow!("chain {}: network (the chain-id) is required", cfg.chain_key()))?;
        let gas_price: f64 = p("gas_price").unwrap_or_else(|| "0".into()).parse().context("params.gas_price")?;
        let zero_fee = cfg.params.get("zero_fee").and_then(|v| v.as_bool()) == Some(true);
        if !zero_fee && (gas_price.is_nan() || gas_price <= 0.0) {
            bail!("chain {}: params.gas_price must be > 0 (params.zero_fee = true only on a zero-fee devnet)", cfg.chain_key());
        }
        Ok(Self {
            key: cfg.chain_key(),
            chain_id,
            prefix,
            denom: p("denom").unwrap_or_else(|| "stake".into()),
            gas_price,
            max_gas: cfg.max_gas_per_tx,
            rpc: cfg.rpc_urls[0].trim_end_matches('/').to_string(),
            rest: rest.trim_end_matches('/').to_string(),
            lanes,
            signers,
            http: reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?,
            account_numbers: Mutex::new(HashMap::new()),
            scan_from: Mutex::new(HashMap::new()),
        })
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    async fn get(&self, url: &str) -> Result<(u16, Value)> {
        let r = self.http.get(url).send().await?;
        let code = r.status().as_u16();
        Ok((code, r.json().await.unwrap_or(Value::Null)))
    }

    async fn post(&self, url: &str, body: &Value) -> Result<(u16, Value)> {
        let r = self.http.post(url).json(body).send().await?;
        let code = r.status().as_u16();
        Ok((code, r.json().await.unwrap_or(Value::Null)))
    }

    async fn rpc(&self, path: &str) -> Result<Value> {
        let (code, v) = self.get(&format!("{}/{path}", self.rpc)).await?;
        if code != 200 || v.get("error").is_some_and(|e| !e.is_null()) {
            bail!("rpc {path}: {code} {}", v.get("error").unwrap_or(&v));
        }
        Ok(v["result"].clone())
    }

    /// (account_number, sequence đã commit).
    async fn account(&self, lane: usize) -> Result<(u64, u64)> {
        let addr = &self.lanes.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?.address;
        let (code, v) = self.get(&format!("{}/cosmos/auth/v1beta1/accounts/{addr}", self.rest)).await?;
        if code != 200 {
            bail!("lane {addr} not found on chain (fund it first): {code} {v}");
        }
        let num = |k: &str| v["account"][k].as_str().unwrap_or("0").parse::<u64>().map_err(|e| anyhow!("{k}: {e}"));
        let (an, seq) = (num("account_number")?, num("sequence")?);
        if let Ok(mut m) = self.account_numbers.lock() {
            m.insert(lane, an);
        }
        Ok((an, seq))
    }

    fn pk(&self, lane: usize) -> Result<Vec<u8>> {
        Ok(self.signers.get(lane).ok_or_else(|| anyhow!("no lane {lane}"))?.public_key())
    }
}

#[async_trait]
impl ChainAdapter for CosmosAdapter {
    fn family(&self) -> Family {
        Family::Cosmos
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    /// R80: `pay` ⇒ `QueryMsg::Nonce {owner, lane}` (`NONCES[(from, lane)]` của token) so với nonce đã ký.
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        let Some(op) = job.op.as_ref().filter(|o| o["op_kind"] == "pay") else { return Ok(None) };
        let payload: Value = serde_json::from_slice(&hex_arg(op["payload"].as_str().unwrap_or_default())?)?;
        let (Some(nonce), Some(contract)) = (payload["nonce"].as_u64(), op["contract"].as_str()) else { return Ok(None) };
        if payload["op"] != "pay" {
            return Ok(None);
        }
        let q = json!({"nonce": {"owner": payload["from"], "lane": payload["lane"]}});
        let q = base64::engine::general_purpose::URL_SAFE.encode(q.to_string());
        let (code, v) = self.get(&format!("{}/cosmwasm/wasm/v1/contract/{contract}/smart/{q}", self.rest)).await?;
        let next = v["data"].as_u64().filter(|_| code == 200).ok_or_else(|| anyhow!("nonce query: {code} {v}"))?;
        Ok(Some(next > nonce))
    }

    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let op = job.op.as_ref().ok_or_else(|| SimError::Revert("job has no op".into()))?;
        let (contract, msg, valid_until) = relay_msg(op).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        let sender = self.lanes.get(lane).ok_or_else(|| SimError::Transport(format!("no lane {lane}")))?.address.clone();
        let (_, seq) = self.account(lane).await.map_err(|e| SimError::Transport(format!("{e:#}")))?;
        let pk = self.pk(lane).map_err(|e| SimError::Transport(e.to_string()))?;
        let body = tx_body(&sender, &contract, &msg);
        let sim = tx_raw(&body, &auth_info(&pk, seq, &self.denom, 0, 0), &[]);
        let (code, v) = self
            .post(&format!("{}/cosmos/tx/v1beta1/simulate", self.rest), &json!({"tx_bytes": B64.encode(&sim)}))
            .await
            .map_err(|e| SimError::Transport(format!("{e:#}")))?;
        if code != 200 {
            return Err(sim_error(code, &v));
        }
        let used: u64 = v["gas_info"]["gas_used"].as_str().and_then(|g| g.parse().ok()).unwrap_or(0);
        let gas = used + used * 3 / 10 + 10_000;
        if gas > self.max_gas {
            return Err(SimError::Revert(format!("gas {gas} above max_gas_per_tx")));
        }
        Ok(Built { job_id: job.id, body, valid_until, meta: json!({"gas": gas}) })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let an = match self.account_numbers.lock().ok().and_then(|m| m.get(&lane).copied()) {
            Some(n) => n,
            None => self.account(lane).await?.0,
        };
        let gas = built.meta["gas"].as_u64().unwrap_or(self.max_gas);
        let fee = (gas as f64 * self.gas_price).ceil() as u128;
        let auth = auth_info(&self.pk(lane)?, sequence, &self.denom, fee, gas);
        let doc = sign_doc(&built.body, &auth, &self.chain_id, an);
        let sig = self.signers[lane].sign(&Sha256::digest(&doc))?;
        let raw = tx_raw(&built.body, &auth, &sig[..64]);
        let tx_id = format!("0x{}", alloy::hex::encode(Sha256::digest(&raw)));
        Ok(Signed { job_id: built.job_id, tx_id, raw, valid_until: built.valid_until, sequence })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        // Mốc quét khối cho `tx_status` (tx chỉ vào khối từ đỉnh hiện tại trở đi).
        if !self.scan_from.lock().is_ok_and(|m| m.contains_key(&signed.tx_id)) {
            let head = self.final_head().await?.map_or(1, |h| h.height);
            if let Ok(mut m) = self.scan_from.lock() {
                m.insert(signed.tx_id.clone(), head);
            }
        }
        let body = json!({"tx_bytes": B64.encode(&signed.raw), "mode": "BROADCAST_MODE_SYNC"});
        let (code, v) = self.post(&format!("{}/cosmos/tx/v1beta1/txs", self.rest), &body).await?;
        broadcast_outcome(code, &v)
    }

    /// REST `GetTx` đọc indexer tx của CometBFT — có thể tắt (`indexer = "null"`) hay trễ: thấy là chắc, không thấy
    /// thì quét `block`/`block_results` (luôn có) từ mốc lúc gửi (review M2). RPC lỗi ⇒ `Err` ⇒ runner thử lại.
    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let h = tx_id.trim_start_matches("0x").to_ascii_uppercase();
        if let Ok((200, v)) = self.get(&format!("{}/cosmos/tx/v1beta1/txs/{h}", self.rest)).await {
            let r = &v["tx_response"];
            let height = r["height"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
            let st = match r["code"].as_u64() {
                Some(0) => Some(TxStatus::Mined { height }),
                Some(_) => Some(TxStatus::Reverted { reason: r["raw_log"].as_str().unwrap_or("failed").to_string() }),
                None => None,
            };
            if let Some(st) = st {
                if let Ok(mut m) = self.scan_from.lock() {
                    m.remove(tx_id);
                }
                return Ok(st);
            }
        }
        let Some(from) = self.scan_from.lock().ok().and_then(|m| m.get(tx_id).copied()) else { return Ok(TxStatus::Unknown) };
        let Some(head) = self.final_head().await? else { return Ok(TxStatus::Unknown) };
        for height in from..=head.height.min(from + 50) {
            let b = self.rpc(&format!("block?height={height}")).await?;
            if b["block"]["data"]["txs"].as_array().is_some_and(|t| !t.is_empty()) {
                let r = self.rpc(&format!("block_results?height={height}")).await?;
                if let Some(st) = tx_in_block(&b, &r, tx_id) {
                    if let Ok(mut m) = self.scan_from.lock() {
                        m.remove(tx_id);
                    }
                    return Ok(st);
                }
            }
            if let Ok(mut m) = self.scan_from.lock() {
                m.insert(tx_id.to_string(), height + 1);
            }
        }
        Ok(TxStatus::Unknown)
    }

    async fn sequence(&self, lane: usize) -> Result<u64> {
        Ok(self.account(lane).await?.1)
    }

    /// CometBFT: khối đã commit là final (BFT). ponytail: một endpoint, không quorum nhiều RPC.
    async fn final_head(&self) -> Result<Option<Head>> {
        let s = self.rpc("status").await?;
        let height: u64 = s["sync_info"]["latest_block_height"].as_str().unwrap_or("0").parse()?;
        let hash = s["sync_info"]["latest_block_hash"].as_str().and_then(hash32);
        Ok(match hash {
            Some(hash) if height > 0 => Some(Head { height, hash }),
            _ => None,
        })
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        let b = self.rpc(&format!("block?height={height}")).await?;
        b["block_id"]["hash"].as_str().and_then(hash32).ok_or_else(|| anyhow!("no block {height}"))
    }

    /// Đọc `block_results` từng khối (kết quả ABCI lưu cùng lúc commit), KHÔNG dùng `tx_search`: indexer tx của
    /// CometBFT chạy bất đồng bộ sau commit, nên khối mới nhất có thể chưa được index ⇒ event lọt mất vĩnh viễn.
    /// `tx_hash` = sha256(bytes tx trong `block`), chỉ đọc `block` khi khối có event của ta.
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        for h in from..=to {
            let br = self.rpc(&format!("block_results?height={h}")).await?;
            let results = br["txs_results"].as_array().cloned().unwrap_or_default();
            let probe = |r: &Value| !normalize_tx(&json!({"hash": "00".repeat(32), "height": h.to_string(), "tx_result": r}), contracts).is_empty();
            if !results.iter().any(probe) {
                continue;
            }
            let b = self.rpc(&format!("block?height={h}")).await?;
            let hash = b["block_id"]["hash"].as_str().and_then(hash32).ok_or_else(|| anyhow!("block {h}: no hash"))?;
            let txs = b["block"]["data"]["txs"].as_array().cloned().unwrap_or_default();
            if txs.len() != results.len() {
                bail!("block {h}: {} txs but {} results", txs.len(), results.len());
            }
            for (raw, r) in txs.iter().zip(&results) {
                let bytes = B64.decode(raw.as_str().unwrap_or_default()).context("tx bytes")?;
                let tx = json!({"hash": alloy::hex::encode(Sha256::digest(&bytes)), "height": h.to_string(), "tx_result": r});
                for mut e in normalize_tx(&tx, contracts) {
                    e["block_hash"] = json!(hash);
                    out.push(e);
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Vector chéo: cùng khoá/địa chỉ/digest như `chains/cosmos/tests/tests/vector.txt` và `test_fam_cosmos.py`.
    #[test]
    fn cross_implementation_vector() {
        let seed = crate::keys::Seed::from_words(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            None,
        )
        .unwrap();
        let (curve, key) = crate::keys::lane_secret(&seed, "cosmos", 0).unwrap();
        let s = LocalSigner::new(curve, &key).unwrap();
        assert_eq!(account_address("wasm", &s.public_key()), "wasm1r5v5srda7xfth3hn2s26txvrcrntldju3hkw75");
        assert_eq!(bech32("wasm", &[0x33; 20]), "wasm1xvenxvenxvenxvenxvenxvenxvenxvenkz5vxp");
        assert_eq!(bech32("wasm", &[0x44; 32]), "wasm1g3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqn0lflt");
        let vector = include_str!("../../../chains/cosmos/tests/tests/vector.txt");
        let line = |k: &str| vector.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap().to_string();
        let payload = line("payload");
        assert_eq!(alloy::hex::encode(Sha256::digest(payload.as_bytes())), line("digest"));
        let op = json!({"contract": line("contract"), "payload": alloy::hex::encode(&payload), "signature": line("sig"),
                        "public_key": alloy::hex::encode(s.public_key()), "valid_until": 2_000_000_000u64});
        let (contract, msg, vu) = relay_msg(&op).unwrap();
        assert_eq!((contract.as_str(), vu), (line("contract").as_str(), 2_000_000_000));
        let m: Value = serde_json::from_slice(&msg).unwrap();
        assert_eq!(B64.decode(m["relay"]["payload"].as_str().unwrap()).unwrap(), payload.as_bytes());
        assert_eq!(m["relay"]["auth"]["scheme"], "adr036");
    }

    #[test]
    fn protobuf_and_bech32_basics() {
        let mut v = Vec::new();
        varint(300, &mut v);
        assert_eq!(v, [0xac, 0x02]);
        // BIP-173 vector.
        assert_eq!(bech32("a", &[]), "a12uel5l");
        // TxRaw keeps an empty signature slot for simulation.
        assert_eq!(tx_raw(b"b", b"a", &[]), [0x0a, 1, b'b', 0x12, 1, b'a', 0x1a, 0]);
        let ai = auth_info(&[2; 33], 5, "stake", 0, 0);
        assert!(ai.windows(2).any(|w| w == [0x18, 5]), "sequence 5 encoded");
    }

    #[test]
    fn passkey_signature_maps_to_passkey_auth() {
        let sig = r#"{"signature":"AQ==","authenticator_data":"Ag==","client_data_json":"{\"type\":\"webauthn.get\"}"}"#;
        let op = json!({"contract": "wasm1x", "payload": "7b7d", "signature": sig, "public_key": "04aa", "valid_until": 9});
        let (_, msg, _) = relay_msg(&op).unwrap();
        let m: Value = serde_json::from_slice(&msg).unwrap();
        assert_eq!(m["relay"]["auth"]["scheme"], "passkey");
        assert_eq!(m["relay"]["auth"]["client_data_json"], r#"{"type":"webauthn.get"}"#);
        let bad = json!({"contract": "c", "payload": "00", "signature": "AQ==", "public_key": "02", "valid_until": 1});
        assert!(relay_msg(&bad).is_err(), "adr036 signature must be 64 bytes");
    }

    fn tx(events: Value) -> Value {
        json!({"hash": "AB".repeat(32), "height": "7", "tx_result": {"code": 0, "events": events}})
    }

    #[test]
    fn events_are_normalized_and_filtered() {
        let ev = json!([
            {"type": "message", "attributes": []},
            {"type": "wasm-payment_settled", "attributes": [
                {"key": "_contract_address", "value": "wasm1tok"}, {"key": "from", "value": "wasm1a"},
                {"key": "to", "value": "wasm1b"}, {"key": "amount", "value": "5"},
                {"key": "pay_ref", "value": format!("0x{}", "22".repeat(32))}]},
            {"type": "wasm-meta_tx_executed", "attributes": [
                {"key": "_contract_address", "value": "wasm1tok"}, {"key": "from", "value": "wasm1a"},
                {"key": "digest", "value": format!("0x{}", "EE".repeat(32))}]},
            {"type": "wasm-payment_settled", "attributes": [{"key": "_contract_address", "value": "wasm1other"}]}
        ]);
        let out = normalize_tx(&tx(ev.clone()), &["wasm1tok".into()]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["event"], "PaymentSettled");
        assert_eq!((out[0]["log_index"].as_u64(), out[0]["block_number"].as_u64()), (Some(1), Some(7)));
        assert_eq!(out[0]["tx_hash"], format!("0x{}", "ab".repeat(32)));
        assert_eq!(out[1]["digest"], format!("0x{}", "ee".repeat(32)));
        let mut failed = tx(ev);
        failed["tx_result"]["code"] = json!(5);
        assert!(normalize_tx(&failed, &["wasm1tok".into()]).is_empty());
    }

    /// Review L2: chỉ lỗi thực thi (gRPC Unknown/InvalidArgument) là `Revert`; lỗi cổng/gRPC thoáng qua thử lại.
    #[test]
    fn simulate_errors_are_classified() {
        let revert = |code: u16, v: Value| matches!(sim_error(code, &v), SimError::Revert(_));
        assert!(revert(500, json!({"code": 2, "message": "execute wasm contract failed: metaop: expired"})));
        assert!(revert(400, json!({"code": 3, "message": "tx parse error"})));
        assert!(!revert(500, json!({"code": 2, "message": "account sequence mismatch, expected 4, got 3"})));
        for c in [4, 8, 13, 14] {
            assert!(!revert(503, json!({"code": c, "message": "upstream"})), "grpc {c} is transport");
        }
        assert!(!revert(502, Value::Null), "gateway without a body");
    }

    /// Review L1: CheckTx từ chối ⇒ tx không vào mempool, gửi lại cùng bytes vô ích ⇒ `Rejected`.
    #[test]
    fn checktx_rejections_are_not_retried_byte_for_byte() {
        let r = |code: u64| broadcast_outcome(200, &json!({"tx_response": {"code": code, "raw_log": "x"}}));
        assert!(r(0).is_ok() && r(19).is_ok());
        for c in [4, 5, 13, 32] {
            assert!(r(c).unwrap_err().downcast_ref::<crate::adapter::Rejected>().is_some(), "code {c}");
        }
        let full = r(20).unwrap_err();
        assert!(full.downcast_ref::<crate::adapter::Rejected>().is_none(), "mempool full: same bytes may pass later");
        assert!(broadcast_outcome(502, &Value::Null).unwrap_err().downcast_ref::<crate::adapter::Rejected>().is_none());
    }

    fn chain(extra: &str) -> ChainCfg {
        toml::from_str(&format!(
            "family = \"cosmos\"\nrpc_urls = [\"http://r\"]\nlanes = [0]\nfinality = {{ mode = \"instant\" }}\n{extra}"
        ))
        .unwrap()
    }

    /// Review L1: chain-id rỗng (chữ ký sai mọi tx) hay giá gas 0 trên chain có phí tối thiểu ⇒ không khởi động.
    #[test]
    fn adapter_refuses_unsafe_config() {
        let k = || vec![LocalSigner::new(crate::signer::Curve::Secp256k1, &[1; 32]).unwrap()];
        let p = "params = { rest = \"http://x\", prefix = \"wasm\"";
        assert!(CosmosAdapter::new(&chain(&format!("network = \"c-1\"\n{p}, gas_price = \"0.025\" }}")), k()).is_ok());
        let err = |cfg: &str| CosmosAdapter::new(&chain(cfg), k()).err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err(&format!("{p}, gas_price = \"0.025\" }}")).contains("network"));
        assert!(err(&format!("network = \"c-1\"\n{p} }}")).contains("gas_price"));
        assert!(err(&format!("network = \"c-1\"\n{p}, gas_price = \"0\" }}")).contains("gas_price"));
        assert!(CosmosAdapter::new(&chain(&format!("network = \"c-1\"\n{p}, zero_fee = true }}")), k()).is_ok());
    }

    /// Review L3: CometBFT 0.34 trả khoá/giá trị base64; phát hiện qua `_contract_address`, không theo chain.
    #[test]
    fn base64_attributes_are_detected() {
        let b = |s: &str| B64.encode(s);
        let ev = json!([{"type": "wasm-payment_settled", "attributes": [
            {"key": b("_contract_address"), "value": b("wasm1tok"), "index": true}, {"key": b("from"), "value": b("wasm1a")},
            {"key": b("to"), "value": b("wasm1b")}, {"key": b("amount"), "value": b("5")},
            {"key": b("pay_ref"), "value": b(&format!("0x{}", "22".repeat(32)))}]}]);
        let out = normalize_tx(&tx(ev), &["wasm1tok".into()]);
        assert_eq!(out.len(), 1);
        assert_eq!((out[0]["from"].as_str(), out[0]["amount"].as_str()), (Some("wasm1a"), Some("5")));
    }

    /// Review M2: không có indexer tx, tx vẫn được tìm trong `block` + `block_results` theo sha256(bytes).
    #[test]
    fn tx_is_found_in_a_block_without_the_indexer() {
        let (a, b) = (b"tx-a".to_vec(), b"tx-b".to_vec());
        let block = json!({"block": {"header": {"height": "9"}, "data": {"txs": [B64.encode(&a), B64.encode(&b)]}}});
        let results = json!({"txs_results": [{"code": 0}, {"code": 5, "log": "out of funds"}]});
        let id = |t: &[u8]| format!("0x{}", alloy::hex::encode(Sha256::digest(t)));
        assert_eq!(tx_in_block(&block, &results, &id(&a)), Some(TxStatus::Mined { height: 9 }));
        assert_eq!(tx_in_block(&block, &results, &id(&b)), Some(TxStatus::Reverted { reason: "out of funds".into() }));
        assert_eq!(tx_in_block(&block, &results, &id(b"other")), None);
    }

    proptest! {
        /// Decoder không bao giờ panic trên JSON bất kỳ (phản hồi RPC là đầu vào không tin cậy — R54).
        #[test]
        fn normalize_never_panics(s in "\\PC{0,300}") {
            if let Ok(v) = serde_json::from_str::<Value>(&s) {
                let _ = normalize_tx(&v, &["wasm1tok".into()]);
                let _ = relay_msg(&v);
            }
        }

        /// Thuộc tính đi qua nguyên vẹn: from/to/amount/pay_ref.
        #[test]
        fn payment_attributes_round_trip(amount in any::<u128>(), r in any::<[u8; 32]>(), log in 0usize..5) {
            let mut evs = vec![json!({"type": "x", "attributes": []}); log];
            evs.push(json!({"type": "wasm-payment_settled", "attributes": [
                {"key": "_contract_address", "value": "wasm1tok"}, {"key": "from", "value": "wasm1a"},
                {"key": "to", "value": "wasm1b"}, {"key": "amount", "value": amount.to_string()},
                {"key": "pay_ref", "value": format!("0x{}", alloy::hex::encode(r))}]}));
            let out = normalize_tx(&tx(json!(evs)), &["wasm1tok".into()]);
            prop_assert_eq!(out.len(), 1);
            prop_assert_eq!(out[0]["amount"].as_str().unwrap(), amount.to_string());
            prop_assert_eq!(out[0]["entry_ref"].as_str().unwrap(), format!("0x{}", alloy::hex::encode(r)));
            prop_assert_eq!(out[0]["log_index"].as_u64().unwrap(), log as u64);
        }
    }
}
