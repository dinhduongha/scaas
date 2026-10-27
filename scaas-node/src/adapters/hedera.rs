//! Hedera HSCS qua Hedera JSON-RPC Relay (R63). Contract là Solidity (the token kinds with `IS_HEDERA`), tx là tx Ethereum
//! ký ECDSA từ lane (alias EVM, `m/44'/3030'/0'/0/i`), nên phần lớn đi nhờ `EvmAdapter`. Riêng Hedera:
//!
//! - **R6-1**: không mempool — tx vào đồng thuận trong vài giây hoặc bị từ chối; nonce tương lai có thể tới
//!   đồng thuận trước nonce trước nó (qua node khác) ⇒ `WRONG_NONCE`. Vì vậy Hedera chạy dưới `lane_runner`
//!   (một tx bay mỗi lane, nonce đã commit đọc trước mỗi job), không qua `submit.rs` (pipeline + thay thế).
//! - Receipt đọc thô: receipt của Relay mang `revertReason` (mã Hedera như `WRONG_NONCE`, hoặc dữ liệu revert
//!   ABI); chưa có ở mirror node ⇒ `Unknown` (runner chờ tới hạn payload). Mã Hedera khác
//!   `CONTRACT_REVERT_EXECUTED` = mạng từ chối mà meta-tx KHÔNG chạy ⇒ `Rejected` (job về hàng đợi, review M2);
//!   precheck của Relay từ chối `eth_sendRawTransaction` cũng vậy.
//! - Phí: type-2, `maxFee = eth_gasPrice × 1.2`, priority 0 (giá gas Hedera cố định theo biểu phí — spec §4).
//! - Lane phải là tài khoản Hedera đã tồn tại và có HBAR (review S22): lane số dư 0 ⇒ job về hàng đợi; payload
//!   đã hết hạn thì `dead` trước cả bước kiểm số dư (không xoay vòng mãi trên lane chưa nạp tiền).
//! - Danh sách token lọc event: token Odoo đăng ký, lấy từ `node_config` mỗi vòng `index_step` (review H2;
//!   không danh sách tĩnh trong cấu hình node — event của contract lạ không bao giờ gửi Odoo).
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use serde_json::Value;

use super::evm::EvmAdapter;
use crate::abi::decode_revert;
use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Rejected, Signed, TxStatus};
use crate::chain::{Chain, SimError};
use crate::config::ChainCfg;
use crate::odoo::Job;
use crate::signer::LocalSigner;
use crate::submit::{now, work_from_job};

/// 295 mainnet, 296 testnet, 297 previewnet, 298 localnet (hedera-local-node / solo).
pub const CHAIN_IDS: [u64; 4] = [295, 296, 297, 298];

pub struct HederaAdapter {
    inner: EvmAdapter,
    rpc: DynProvider,
    lane_addrs: Vec<Address>,
}

impl HederaAdapter {
    pub fn new(cfg: &ChainCfg, chains: Vec<Chain>) -> Result<Self> {
        if cfg.family != "hedera" || !CHAIN_IDS.contains(&cfg.evm_chain_number) {
            bail!("chain {}: Hedera needs family=hedera and evm_chain_number 295..298", cfg.chain_key());
        }
        let url = cfg.rpc_urls.first().ok_or_else(|| anyhow!("chain {}: no rpc_urls", cfg.chain_key()))?;
        let rpc = ProviderBuilder::new().disable_recommended_fillers().connect_http(url.parse()?).erased();
        let lane_addrs = chains.iter().map(Chain::address).collect();
        Ok(Self { inner: EvmAdapter::new(cfg, chains, Default::default())?, rpc, lane_addrs })
    }

    /// Từ config: một `Chain` mỗi lane (khoá secp256k1 coin 3030).
    pub fn from_cfg(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Self> {
        Self::new(cfg, Chain::connect_lanes(cfg, signers)?)
    }
}

/// Receipt thô của Relay → trạng thái. `None` = chưa có (mirror node chưa nhập). Không panic với dữ liệu lạ.
pub fn decode_receipt(rc: &Value) -> Option<TxStatus> {
    if rc.is_null() {
        return None;
    }
    let height = rc.get("blockNumber").and_then(Value::as_str).and_then(hex_u64);
    match (rc.get("status").and_then(Value::as_str).and_then(hex_u64), height) {
        (Some(1), Some(height)) => Some(TxStatus::Mined { height, tx_hash: None }),
        (Some(0), _) => Some(TxStatus::Reverted { reason: revert_reason(rc.get("revertReason")) }),
        _ => None, // receipt dở dang: coi như chưa có
    }
}

/// Mã `ResponseCodeEnum` của Hedera có thể về trong receipt/precheck của một tx Ethereum. Chỉ các chuỗi này được
/// đọc là mã Hedera; dữ liệu revert ABI tình cờ toàn byte `[A-Z0-9_]` vẫn giải như lỗi contract.
pub const HEDERA_STATUS: &[&str] = &[
    "CONTRACT_REVERT_EXECUTED",
    "WRONG_NONCE",
    "INSUFFICIENT_PAYER_BALANCE",
    "INSUFFICIENT_ACCOUNT_BALANCE",
    "INSUFFICIENT_TX_FEE",
    "INSUFFICIENT_GAS",
    "MAX_GAS_LIMIT_EXCEEDED",
    "CONSENSUS_GAS_EXHAUSTED",
    "DUPLICATE_TRANSACTION",
    "TRANSACTION_EXPIRED",
    "INVALID_TRANSACTION_START",
    "INVALID_ETHEREUM_TRANSACTION",
    "INVALID_SIGNATURE",
    "INVALID_ACCOUNT_ID",
    "PAYER_ACCOUNT_NOT_FOUND",
    "BUSY",
    "PLATFORM_TRANSACTION_NOT_CREATED",
    "THROTTLED_AT_CONSENSUS",
    "MAX_CHILD_RECORDS_EXCEEDED",
];

/// Mã Hedera mà meta-tx KHÔNG chạy (lỗi phía relayer: nonce, phí, trùng, nghẽn…) ⇒ dựng lại, không chết job.
/// Chỉ `CONTRACT_REVERT_EXECUTED` là contract đã chạy và từ chối (review M2).
pub fn requeues(reason: &str) -> bool {
    reason != "CONTRACT_REVERT_EXECUTED" && HEDERA_STATUS.contains(&reason)
}

/// `revertReason` của Relay: dữ liệu revert ABI (lỗi của contract) hoặc mã Hedera ASCII hex (`WRONG_NONCE`…).
pub fn revert_reason(v: Option<&Value>) -> String {
    let Some(s) = v.and_then(Value::as_str) else { return "execution reverted".into() };
    let Ok(bytes) = alloy::hex::decode(s.strip_prefix("0x").unwrap_or(s)) else { return s.chars().take(200).collect() };
    if bytes.is_empty() {
        return "execution reverted".into();
    }
    match std::str::from_utf8(&bytes) {
        Ok(code) if HEDERA_STATUS.contains(&code) => code.to_string(),
        _ => decode_revert(&bytes),
    }
}

/// Precheck của Relay/consensus node từ chối `eth_sendRawTransaction` (lỗi JSON-RPC có nội dung): tx không vào
/// đồng thuận, gửi lại cùng bytes vô ích ⇒ `Rejected`. Trùng (`DUPLICATE_TRANSACTION`, already known) = chính tx này
/// đã vào ⇒ coi như đã gửi. Lỗi đường truyền ⇒ giữ nguyên (runner gửi lại cùng bytes).
pub fn submit_outcome(r: Result<()>) -> Result<()> {
    let Err(e) = r else { return Ok(()) };
    let Some(resp) = e.downcast_ref::<alloy::transports::TransportError>().and_then(|t| t.as_error_resp()) else {
        return Err(e);
    };
    let msg = resp.message.to_string();
    if msg.contains("DUPLICATE_TRANSACTION") || msg.to_ascii_lowercase().contains("already known") {
        return Ok(());
    }
    Err(Rejected(msg).into())
}

/// Spec §4: giá gas Hedera cố định ⇒ `maxFee = gasPrice × 1.2`, priority 0 (số dư lane cần ≈ gasLimit × 1.2 × giá).
pub fn fees(gas_price: u128) -> (u128, u128) {
    (gas_price + gas_price / 5, 0)
}

fn hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.strip_prefix("0x")?, 16).ok()
}

#[async_trait]
impl ChainAdapter for HederaAdapter {
    fn family(&self) -> Family {
        Family::Hedera
    }

    fn chain_key(&self) -> &str {
        self.inner.chain_key()
    }

    fn lanes(&self) -> &[Lane] {
        self.inner.lanes()
    }

    /// R80: meta-tx ⇒ `mtxNonce(from, batch)` (both structs share the lane); job `call` ⇒ không biết.
    async fn op_consumed(&self, job: &Job) -> Result<Option<bool>> {
        let Some(m) = work_from_job(job, self.inner.fee_recipient).ok().and_then(|w| w.meta) else { return Ok(None) };
        Ok(Some(self.inner.lane(0)?.mtx_nonce(m.token, m.from, m.batch).await? > m.nonce))
    }

    async fn digest(&self, job: &Job) -> std::result::Result<Option<B256>, SimError> {
        self.inner.digest(job).await
    }

    async fn start_check(&self) -> Result<()> {
        self.inner.start_check().await
    }

    fn refresh_tokens(&self, nc: &crate::odoo::NodeConfig) {
        self.inner.refresh_tokens(nc)
    }

    fn already_done(&self, job: &Job, reason: &str) -> bool {
        self.inner.already_done(job, reason)
    }

    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let w = work_from_job(job, self.inner.fee_recipient).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        if now() > w.valid_until {
            return Err(SimError::Revert("expired before inclusion".into()));
        }
        let addr = *self.lane_addrs.get(lane).ok_or_else(|| SimError::Transport(format!("no lane {lane}")))?;
        let bal = self.rpc.get_balance(addr).await.map_err(|e| SimError::Transport(e.to_string()))?;
        if bal == U256::ZERO {
            return Err(SimError::Transport(format!("lane {addr:#x} is not a funded Hedera account")));
        }
        self.inner.build(job, lane).await
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let chain = self.inner.lane(lane)?;
        let to: Address = built.meta["to"].as_str().unwrap_or_default().parse()?;
        let gas = built.meta["gas"].as_u64().ok_or_else(|| anyhow!("built tx without gas"))?;
        let fees = fees(self.rpc.get_gas_price().await?);
        let (raw, hash) = chain.sign(sequence, to, Bytes::from(built.body), gas, fees).await?;
        Ok(Signed { job_id: built.job_id, tx_id: format!("{hash:#x}"), raw: raw.to_vec(), valid_until: built.valid_until, sequence })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        submit_outcome(self.inner.submit(signed).await)
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let rc: Value = self.rpc.raw_request("eth_getTransactionReceipt".into(), (tx_id,)).await?;
        if let Some(st) = decode_receipt(&rc) {
            if let TxStatus::Reverted { reason } = &st {
                if requeues(reason) {
                    return Err(Rejected(reason.clone()).into());
                }
            }
            return Ok(st);
        }
        let tx: Value = self.rpc.raw_request("eth_getTransactionByHash".into(), (tx_id,)).await?;
        Ok(if tx.is_null() { TxStatus::Unknown } else { TxStatus::Pending })
    }

    async fn sequence(&self, lane: usize) -> Result<u64> {
        self.inner.sequence(lane).await
    }

    async fn final_head(&self) -> Result<Option<Head>> {
        self.inner.final_head().await
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        self.inner.block_hash(height).await
    }

    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        self.inner.events(from, to, contracts).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;
    use alloy::rpc::types::{Block, Log, TransactionReceipt};
    use proptest::prelude::*;
    use serde_json::json;

    const RELAY: &str = include_str!("../../tests/vectors/hedera_testnet.json");
    const KAT: &str = include_str!("../../../smartcontracts/evm/test/vectors/hedera_kat.json");

    fn relay() -> Value {
        serde_json::from_str(RELAY).unwrap()
    }

    /// Dữ liệu THẬT của Relay testnet (ghi 2026-10-03) phải đi qua đúng các kiểu alloy mà `EvmAdapter` dùng —
    /// nếu không, `final_head`/`events` im lặng không bao giờ báo gì.
    #[test]
    fn recorded_relay_responses_parse_with_alloy_types() {
        let v = relay();
        let b: Block = serde_json::from_value(v["block"].clone()).expect("block");
        assert_eq!(format!("{:#x}", b.header.hash), v["block"]["hash"].as_str().unwrap());
        assert_eq!(b.header.number, hex_u64(v["block"]["number"].as_str().unwrap()).unwrap());
        let rc: TransactionReceipt = serde_json::from_value(v["receipt"].clone()).expect("receipt");
        assert!(rc.status());
        let logs: Vec<Log> = serde_json::from_value(v["logs"].clone()).expect("logs");
        assert!(!logs.is_empty());
        assert!(logs.iter().all(|l| l.block_hash.is_some() && l.log_index.is_some()));
    }

    #[test]
    fn recorded_receipt_decodes() {
        let v = relay();
        let h = hex_u64(v["receipt"]["blockNumber"].as_str().unwrap()).unwrap();
        assert_eq!(decode_receipt(&v["receipt"]), Some(TxStatus::Mined { height: h, tx_hash: None }));
        assert_eq!(decode_receipt(&v["receipt_unknown"]["result"]), None);
    }

    #[test]
    fn hedera_revert_reasons() {
        let mut rc = relay()["receipt"].clone();
        rc["status"] = json!("0x0");
        rc["revertReason"] = json!("0x57524f4e475f4e4f4e4345"); // "WRONG_NONCE"
        assert_eq!(decode_receipt(&rc), Some(TxStatus::Reverted { reason: "WRONG_NONCE".into() }));
        rc["revertReason"] = json!("0x0bdf5a6b"); // MetaTxBadSignature()
        assert_eq!(decode_receipt(&rc), Some(TxStatus::Reverted { reason: "MetaTxBadSignature(MetaTxBadSignature)".into() }));
        rc.as_object_mut().unwrap().remove("revertReason");
        assert_eq!(decode_receipt(&rc), Some(TxStatus::Reverted { reason: "execution reverted".into() }));
    }

    /// Low: dữ liệu revert ABI toàn byte `[A-Z0-9_]` (selector `ABCD`) không phải mã Hedera.
    #[test]
    fn only_known_hedera_codes_read_as_status() {
        assert_ne!(revert_reason(Some(&json!("0x41424344"))), "ABCD");
        assert_eq!(revert_reason(Some(&json!(format!("0x{}", alloy::hex::encode("BUSY"))))), "BUSY");
        assert!(requeues("WRONG_NONCE") && requeues("INSUFFICIENT_PAYER_BALANCE") && requeues("DUPLICATE_TRANSACTION"));
        assert!(!requeues("CONTRACT_REVERT_EXECUTED") && !requeues("MetaTxBadSignature(MetaTxBadSignature)"));
    }

    // ---- lane_step over a fake JSON-RPC Relay + fake Odoo (Hedera outcomes anvil cannot produce) ----

    use axum::extract::{Path, State};
    use alloy::sol_types::SolError;
    use crate::abi::IToken;
    use crate::guard;
    use axum::routing::post;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Net {
        balance: &'static str,
        receipt: Value,
        send_error: Option<Value>,
        /// `eth_call` trả về word này (mô phỏng bỏ qua nó; `mtxNonce` đọc nó).
        mtx_nonce: u64,
        sent: Vec<String>,
        jobs: Vec<Value>,
        reports: Vec<Value>,
        /// `eth_getBlockByNumber` (Null = a pruned RPC: the pin is trusted).
        block0: Value,
        /// `eth_getBlockByNumber` answers this JSON-RPC error instead; `block0_reads` counts the asks.
        block0_err: Option<Value>,
        block0_reads: u32,
        /// Revert data of an `mtxInvalidateNonces` simulation.
        invalidate_revert: Option<Vec<u8>>,
    }
    type Shared = Arc<Mutex<Net>>;
    const GAS_PRICE: u128 = 0xca900a7c00; // testnet eth_gasPrice (spec §4)

    async fn fake_relay(State(s): State<Shared>, axum::Json(b): axum::Json<Value>) -> axum::Json<Value> {
        let mut n = s.lock().unwrap();
        let id = b["id"].clone();
        let ok = |r: Value| json!({"jsonrpc": "2.0", "id": id, "result": r});
        axum::Json(match b["method"].as_str().unwrap_or_default() {
            "eth_getBalance" => ok(json!(n.balance)),
            // the recorded testnet block's gasLimit (tests/vectors/hedera_testnet.json): the gas cap reads `latest`
            "eth_getBlockByNumber" if b["params"][0] == "latest" => ok(json!({"gasLimit": "0x8f0d180"})),
            "eth_getBlockByNumber" => {
                n.block0_reads += 1;
                match n.block0_err.clone() {
                    Some(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
                    None => ok(n.block0.clone()),
                }
            }
            "eth_getCode" => ok(json!("0x")),
            "eth_call" => {
                let input = b["params"][0]["input"].as_str().or(b["params"][0]["data"].as_str()).unwrap_or_default().to_string();
                match &n.invalidate_revert {
                    Some(d) if input.starts_with(&format!("0x{}", alloy::hex::encode(guard::SEL_MTX_INVALIDATE_NONCES))) => json!(
                        {"jsonrpc": "2.0", "id": id, "error": {"code": 3, "message": "execution reverted", "data": format!("0x{}", alloy::hex::encode(d))}}),
                    _ => ok(json!(format!("0x{:064x}", n.mtx_nonce))),
                }
            }
            "eth_estimateGas" => ok(json!("0x186a0")),
            "eth_gasPrice" => ok(json!(format!("0x{GAS_PRICE:x}"))),
            "eth_getTransactionCount" => ok(json!("0x7")),
            "eth_sendRawTransaction" => {
                n.sent.push(b["params"][0].as_str().unwrap().to_string());
                match n.send_error.clone() {
                    Some(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
                    None => ok(json!(format!("0x{}", "11".repeat(32)))),
                }
            }
            "eth_getTransactionReceipt" => ok(n.receipt.clone()),
            "eth_getTransactionByHash" => ok(Value::Null),
            m => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("unexpected {m}")}}),
        })
    }

    async fn odoo(State(s): State<Shared>, Path((_m, method)): Path<(String, String)>, axum::Json(b): axum::Json<Value>) -> axum::Json<Value> {
        let mut n = s.lock().unwrap();
        axum::Json(match method.as_str() {
            "relay_poll" => Value::Array(std::mem::take(&mut n.jobs)),
            "relay_claim" => b["job_ids"].clone(),
            "relay_report" => {
                n.reports.push(b);
                json!({"ok": true})
            }
            "node_config" => json!({"evm_chain_number": 296, "finality_mode": "instant", "finality_depth": 0,
                "finality_quorum": 1, "indexed_block": 0, "journal_max_nonce": null, "inflight": [],
                "tokens": [{"address": format!("{:#x}", Address::repeat_byte(0x70)), "decimals": 6}]}),
            _ => json!({"error": "unexpected"}),
        })
    }

    /// Một job meta-tx tối thiểu (mô phỏng của Relay giả luôn qua).
    fn job(valid_until: u64) -> Value {
        let z = format!("{:#x}", Address::ZERO);
        json!({"id": 7, "token": format!("{:#x}", Address::repeat_byte(0x70)), "signature": format!("0x{}", "ab".repeat(64)),
               "struct": "transfer",
               "metatx": {"from": format!("{:#x}", Address::repeat_byte(1)), "to": format!("{:#x}", Address::repeat_byte(2)),
                          "value": "1", "entryRef": format!("{:#x}", B256::ZERO), "batch": "1", "nonce": "0",
                          "validUntil": valid_until.to_string(), "mode": 0, "relayer": z, "fee": "0", "feeRecipient": z}})
    }

    /// Chạy MỘT `lane_step` của `HederaAdapter` thật; trả các `chain_state` đã báo và trạng thái mạng giả.
    async fn step(net: Net, valid_until: u64) -> (Vec<String>, Shared) {
        step_with(net, job(valid_until)).await
    }

    /// The adapter on the fake Relay/client: `(adapter, client, network)`. The job's token 0x70… is registered.
    async fn adapter(net: Net) -> (HederaAdapter, crate::odoo::Odoo, Shared) {
        let s: Shared = Arc::new(Mutex::new(net));
        let app = axum::Router::new().route("/", post(fake_relay)).route("/json/2/{m}/{method}", post(odoo)).with_state(s.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let mut cfg: ChainCfg = toml::from_str("family = \"hedera\"\nevm_chain_number = 296\nrpc_urls = [\"http://x\"]\n").unwrap();
        cfg.rpc_urls = vec![url.clone()];
        // every `eth_call` of the fake answers the same word: `chainUid()` too, so the pinned chain_uid is that word
        cfg.chain_uid = Some(B256::from(U256::from(s.lock().unwrap().mtx_nonce)));
        let signer = LocalSigner::new(crate::signer::Curve::Secp256k1, &[7u8; 32]).unwrap();
        let a = HederaAdapter::from_cfg(&cfg, &[signer]).unwrap();
        let nc: crate::odoo::NodeConfig = serde_json::from_value(json!({"evm_chain_number": 296, "finality_mode": "instant",
            "finality_depth": 0, "finality_quorum": 1, "indexed_block": 0, "journal_max_nonce": null,
            "tokens": [{"address": format!("{:#x}", Address::repeat_byte(0x70)), "decimals": 6}]})).unwrap();
        a.refresh_tokens(&nc);
        let oc = crate::config::OdooCfg { url, database: "t".into(), relay_api_key_env: String::new(), indexer_api_key_env: String::new() };
        (a, crate::odoo::Odoo::with_key(&oc, "k".into()).unwrap(), s)
    }

    async fn step_with(mut net: Net, job: Value) -> (Vec<String>, Shared) {
        net.jobs = vec![job];
        let (a, o, s) = adapter(net).await;
        let fut = crate::adapter::lane_step(&a, &o, 0, "t#0");
        assert!(tokio::time::timeout(std::time::Duration::from_secs(10), fut).await.expect("lane held").unwrap());
        let states = s.lock().unwrap().reports.iter().map(|r| r["chain_state"].as_str().unwrap().to_string()).collect();
        (states, s)
    }

    fn receipt(status: &str, reason: &str) -> Value {
        json!({"status": status, "blockNumber": "0x5", "revertReason": format!("0x{}", alloy::hex::encode(reason))})
    }

    fn last_error(s: &Shared) -> String {
        s.lock().unwrap().reports.last().unwrap()["error"].as_str().unwrap_or_default().to_string()
    }

    /// Review M2: WRONG_NONCE (và mọi mã Hedera mà meta-tx không chạy) ⇒ `queued`, không `reverted` vĩnh viễn.
    /// Low (phí): tx gửi đi là type-2 với `maxFee = gasPrice × 1.2`, priority 0.
    #[tokio::test]
    async fn hedera_refusal_without_execution_requeues() {
        let net = Net { balance: "0x1", receipt: receipt("0x0", "WRONG_NONCE"), ..Default::default() };
        let (states, s) = step(net, now() + 600).await;
        assert_eq!(states, ["signed", "broadcast", "queued"]);
        assert!(last_error(&s).contains("WRONG_NONCE"));
        use alloy::consensus::{Transaction, TxEnvelope};
        use alloy::eips::eip2718::Decodable2718;
        let raw = alloy::hex::decode(&s.lock().unwrap().sent[0]).unwrap();
        let tx = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
        assert_eq!((tx.max_fee_per_gas(), tx.max_priority_fee_per_gas()), (GAS_PRICE * 12 / 10, Some(0)));
        assert_eq!((tx.nonce(), tx.chain_id()), (7, Some(296)));
    }

    #[tokio::test]
    async fn contract_revert_stays_terminal() {
        let net = Net { balance: "0x1", receipt: receipt("0x0", "CONTRACT_REVERT_EXECUTED"), ..Default::default() };
        assert_eq!(step(net, now() + 600).await.0, ["signed", "broadcast", "reverted"]);
    }

    /// R80/H3: revert vì relayer khác đã dùng nonce chủ thể (`mtxNonce` đã qua) ⇒ `consumed`, không `reverted`.
    #[tokio::test]
    async fn revert_after_a_lost_race_is_consumed() {
        let net = Net { balance: "0x1", receipt: receipt("0x0", "CONTRACT_REVERT_EXECUTED"), mtx_nonce: 1, ..Default::default() };
        assert_eq!(step(net, now() + 600).await.0, ["signed", "broadcast", "consumed"]);
    }

    /// Precheck từ chối khi gửi ⇒ lane nhả ngay, job về hàng đợi; trùng = tx đã vào ⇒ theo dõi tới mined.
    #[tokio::test]
    async fn relay_precheck_rejection_requeues_and_duplicate_counts_as_sent() {
        let err = json!({"code": -32000, "message": "transaction precheck failed: INSUFFICIENT_PAYER_BALANCE"});
        let net = Net { balance: "0x1", send_error: Some(err), ..Default::default() };
        let (states, s) = step(net, now() + 600).await;
        assert_eq!(states, ["signed", "queued"]);
        assert!(last_error(&s).contains("INSUFFICIENT_PAYER_BALANCE"));
        let dup = json!({"code": -32000, "message": "DUPLICATE_TRANSACTION"});
        let net = Net { balance: "0x1", send_error: Some(dup), receipt: receipt("0x1", ""), ..Default::default() };
        assert_eq!(step(net, now() + 600).await.0, ["signed", "broadcast", "mined"]);
    }

    /// Low: lane chưa nạp tiền + payload đã hết hạn ⇒ `dead`, không quay lại hàng đợi mãi.
    #[tokio::test]
    async fn expired_job_on_unfunded_lane_is_dead() {
        let (states, s) = step(Net { balance: "0x0", ..Default::default() }, now() - 10).await;
        assert_eq!(states, ["dead"]);
        assert!(last_error(&s).contains("expired"));
        let (states, _) = step(Net { balance: "0x0", ..Default::default() }, now() + 600).await;
        assert_eq!(states, ["queued"]);
    }

    /// T17: the Hedera lane runs the EVM job rules (`work_from_job` + the guard): one job-kind rule, and a job of
    /// another kind is dead before any chain read.
    #[tokio::test]
    async fn the_hedera_lane_keeps_the_job_kind_rule() {
        let mut j = job(now() + 300);
        j["kind"] = json!("signed_op");
        let (states, s) = step_with(Net { balance: "0x1", ..Default::default() }, j).await;
        assert_eq!(states, ["dead"]);
        assert!(last_error(&s).contains("unknown job kind"), "{}", last_error(&s));
    }

    /// Review T4 I2: the Hedera lane path keeps N6 (an invalidation already in force is done, never dead), N2 (a lane
    /// whose RPC block 0 is not the pinned chain_uid never starts) and I1 (only registered tokens).
    #[tokio::test]
    async fn the_hedera_lane_keeps_n6_n2_and_registration() {
        let inv = |token: Address| json!({"id": 8, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": format!("{token:#x}"),
            "from": format!("{:#x}", Address::repeat_byte(1)), "batch": "1", "newMin": "9",
            "signature": format!("0x{}", "11".repeat(65)), "validUntil": (now() + 300).to_string()});
        let already = IToken::MinNonceNotIncreasing { current: U256::from(9), requested: U256::from(9) }.abi_encode();
        let net = || Net { balance: "0x1", invalidate_revert: Some(already.clone()), ..Default::default() };
        let (states, s) = step_with(net(), inv(Address::repeat_byte(0x70))).await;
        assert_eq!((states, last_error(&s)), (vec!["consumed".to_string()], "already_invalidated".to_string()));
        let (states, s) = step_with(net(), inv(Address::repeat_byte(0x71))).await;
        assert_eq!(states, ["dead"]);
        assert!(last_error(&s).contains("TOKEN_NOT_SERVED"), "{}", last_error(&s));
        // N2: the recorded testnet block 0 is not the pinned word: the lane never takes a job (and its task, so the
        // node, keeps running: review P5 m1)
        let block: Value = serde_json::from_str::<Value>(include_str!("../../tests/vectors/hedera_testnet.json")).unwrap()["block"].clone();
        let (a, o, s) = adapter(Net { balance: "0x1", block0: block, jobs: vec![job(now() + 300)], ..Default::default() }).await;
        assert!(a.start_check().await.is_err());
        let run = crate::adapter::lane_runner(Arc::new(a), o, 0, "t#0".into(), std::time::Duration::from_millis(10),
            Arc::new(Mutex::new(crate::breaker::Breaker::new(Default::default()))), Default::default());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(1500), run).await.is_err(), "the lane task keeps running");
        assert_eq!(s.lock().unwrap().jobs.len(), 1, "a lane on the wrong chain takes no job");
        let (a, _, _) = adapter(Net { balance: "0x1", ..Default::default() }).await;
        a.start_check().await.expect("a pruned RPC trusts the pin");
    }

    /// Review P5 m1: with a pinned chain_uid, an RPC that errors on block 0 keeps the lane stopped, never the node: the
    /// lane asks again with backoff and starts once block 0 reads (here pruned, so the pin is trusted).
    #[tokio::test]
    async fn a_block_zero_rpc_error_keeps_the_lane_stopped_and_retries() {
        let err = json!({"code": -32603, "message": "block 0 unavailable"});
        let (a, o, s) = adapter(Net { balance: "0x1", block0_err: Some(err), jobs: vec![job(now() + 300)], ..Default::default() }).await;
        let run = tokio::spawn(crate::adapter::lane_runner(Arc::new(a), o, 0, "t#0".into(), std::time::Duration::from_millis(10),
            Arc::new(Mutex::new(crate::breaker::Breaker::new(Default::default()))), Default::default()));
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        {
            let mut n = s.lock().unwrap();
            assert_eq!((n.jobs.len(), n.block0_reads), (1, 2), "stopped, asked again after 1 s");
            n.block0_err = None;
        }
        for _ in 0..50 {
            if s.lock().unwrap().jobs.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(s.lock().unwrap().jobs.is_empty(), "the lane started once block 0 read");
        assert!(!run.is_finished());
        run.abort();
    }

    /// The Hedera vector (`HederaKat.t.sol` + `gen_hedera_kat.py`): the salted `MetaTransfer` digest of an `IS_HEDERA`
    /// token and a real ed25519 signature of the account 0.0.1234567 over those 32 bytes (what HIP-632 checks).
    #[test]
    fn kat_digest_and_ed25519_signature() {
        use crate::metatx::{Domain, Mtx};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let k: Value = serde_json::from_str(KAT).unwrap();
        let s = |f: &str| k[f].as_str().unwrap().to_string();
        let wire = json!({"from": s("from"), "to": s("to"), "value": s("value"), "entryRef": s("entry_ref"),
            "batch": s("batch"), "nonce": s("nonce"), "validUntil": s("valid_until"), "mode": s("mode").parse::<u32>().unwrap(),
            "relayer": s("relayer"), "fee": s("fee"), "feeRecipient": s("fee_recipient")});
        let m = Mtx::from_wire(Some("transfer"), &wire).unwrap();
        let d = Domain {
            name: "SCaaS MetaToken".into(),
            version: "1".into(),
            chain_id: s("chain_id").parse().unwrap(),
            verifying_contract: s("verifying_contract").parse().unwrap(),
            salt: s("salt").parse().unwrap(),
        };
        let dg = m.digest(&d);
        assert_eq!(dg, s("digest").parse::<B256>().unwrap());
        let pk: [u8; 32] = alloy::hex::decode(&s("ed25519_public_key")[2..]).unwrap().try_into().unwrap();
        let sig: [u8; 64] = alloy::hex::decode(&s("ed25519_signature")[2..]).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        vk.verify(dg.as_slice(), &Signature::from_bytes(&sig)).expect("ed25519 over the digest");
        // Hedera account 0.0.1234567 ⇒ long-zero `from`.
        assert_eq!(m.from(), Address::left_padding_from(&1_234_567u64.to_be_bytes()));
    }

    /// Review H1/M1: a Hedera chain from `node.toml` (EVM-style: `evm_chain_number`, no `network`, finality
    /// `instant`) starts, keys as Odoo does (`hedera:<chainId>`) and runs on `HederaAdapter` under the lane
    /// runner — never the pipelined EVM submitter.
    #[test]
    fn config_routes_hedera_through_the_adapter() {
        let raw = "[odoo]\nurl = \"http://o\"\ndatabase = \"d\"\nrelay_api_key_env = \"R\"\nindexer_api_key_env = \"I\"\n\
            [store]\nurl = \"sqlite:///var/lib/scaas/node.db\"\n\
            [[chains]]\nfamily = \"hedera\"\nevm_chain_number = 296\nrpc_urls = [\"http://127.0.0.1:1\"]\n\
            signer_key_env = \"SCAAS_TEST_HEDERA_KEY\"\n\
            finality = { mode = \"instant\" }\n";
        std::env::set_var("SCAAS_TEST_HEDERA_KEY", format!("0x{}", "07".repeat(32)));
        let c: crate::config::Config = toml::from_str(raw).unwrap();
        c.validate().unwrap();
        let cc = &c.chains[0];
        assert!(cc.uses_adapter(), "hedera must not take the EVM submit.rs path");
        assert_eq!(cc.chain_key(), "hedera:296");
        let mut with_net = cc.clone();
        with_net.network = Some("testnet".into());
        assert_eq!(with_net.chain_key(), "hedera:296", "Odoo keys Hedera by chain id");
        let a = crate::adapters::build(cc, &c.lane_signers(cc).unwrap()).unwrap();
        assert_eq!((a.family(), a.chain_key()), (Family::Hedera, "hedera:296"));
        let evm: crate::config::ChainCfg =
            toml::from_str("evm_chain_number = 1\nrpc_urls = [\"http://a\"]\nfinality = { mode = \"instant\" }\n").unwrap();
        assert!(!evm.uses_adapter());
        let mut bad = c.clone();
        bad.chains[0] = evm;
        bad.chains[0].signer_key_env = cc.signer_key_env.clone();
        assert!(bad.validate().is_err(), "instant is Hedera-only");
    }

    #[test]
    fn refuses_non_hedera_chain_ids() {
        let cfg: ChainCfg = toml::from_str(
            "family = \"hedera\"\nevm_chain_number = 1\nrpc_urls = [\"http://127.0.0.1:7546\"]\n",
        )
        .unwrap();
        let s = crate::signer::LocalSigner::new(crate::signer::Curve::Secp256k1, &[7u8; 32]).unwrap();
        assert!(HederaAdapter::from_cfg(&cfg, &[s]).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

        #[test]
        fn receipt_decoder_never_panics(status in ".{0,12}", block in ".{0,20}", reason in ".{0,90}",
                                         hexreason in "0x[0-9a-fA-F]{0,200}") {
            let _ = decode_receipt(&json!({"status": status, "blockNumber": block, "revertReason": reason}));
            let _ = decode_receipt(&json!({"status": "0x0", "revertReason": hexreason}));
            let _ = decode_receipt(&json!({"status": 1, "blockNumber": null}));
            let _ = decode_receipt(&json!([status]));
        }

        #[test]
        fn mined_only_with_status_one_and_a_height(n in any::<u64>()) {
            let rc = json!({"status": "0x1", "blockNumber": format!("0x{n:x}")});
            prop_assert_eq!(decode_receipt(&rc), Some(TxStatus::Mined { height: n, tx_hash: None }));
            let rc = json!({"status": "0x2", "blockNumber": format!("0x{n:x}")});
            prop_assert_eq!(decode_receipt(&rc), None);
        }
    }
}
