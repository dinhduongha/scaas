//! `/json/2` — đường duy nhất vào Odoo (ruling R6). Một client cho mỗi API key.
use alloy::primitives::Address;
use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::OdooCfg;

#[derive(Clone)]
pub struct Odoo {
    http: reqwest::Client,
    base: String,
    db: String,
    key: String,
}

pub use crate::config::TokenCfg;

#[derive(Debug, Clone, Deserialize)]
pub struct InflightJob {
    pub job_id: i64,
    pub nonce: Option<u64>,
    pub state: String,
    pub tx_hash: Option<String>,
    pub payload: Job,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Số EIP-155 (EVM/Hedera) hoặc khoá `family:network` — không ai đọc, chỉ để log.
    #[serde(default)]
    pub evm_chain_number: Value,
    /// `active` | `paused` (R53: paused = indexing continues, nothing new is submitted).
    #[serde(default)]
    pub state: Option<String>,
    pub finality_mode: String,
    pub finality_depth: u64,
    pub finality_quorum: usize,
    pub indexed_block: u64,
    pub tokens: Vec<TokenCfg>,
    pub journal_max_nonce: Option<u64>,
    #[serde(default)]
    pub inflight: Vec<InflightJob>,
    /// Ví nhận đã duyệt (drift R56). Chuỗi theo dạng chuẩn của họ mạng — EVM tự parse.
    #[serde(default)]
    pub receiving_addresses: Vec<Receiving>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Receiving {
    pub token: String,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalanceReport {
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub mismatch: u64,
}

impl NodeConfig {
    /// Token list the open gateway may accept: none while the chain is paused (R53).
    pub fn submittable_tokens(&self) -> Vec<Address> {
        if self.state.as_deref().unwrap_or("active") == "active" {
            self.tokens.iter().filter_map(TokenCfg::evm).collect()
        } else {
            Vec::new()
        }
    }
}

/// Một job outbox. `kind = "metatx"`: `token`/`signature`/`metatx` có mặt, `struct` names the signed struct
/// (`call` = `MetaTransaction`, `transfer` = `MetaTransfer`; absent = `transfer`, CTR-MTX-15). `kind = "call"`:
/// chỉ `call` — calldata Odoo đã dựng (MandateWallet, R25), node chỉ gửi.
#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub id: i64,
    #[serde(default)]
    pub token: Option<Address>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default, rename = "struct")]
    pub struct_: Option<String>,
    #[serde(default)]
    pub metatx: Option<Value>,
    #[serde(default)]
    pub call: Option<WireCall>,
    /// `metatx` | `call` | `signed_op` (họ không phải EVM: payload ký + chữ ký + khoá công khai, adapter tự đọc).
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub op: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireCall {
    pub target: Address,
    pub calldata: String,
    #[serde(rename = "validUntil")]
    pub valid_until: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub job_id: i64,
    pub chain_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outer_nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestResult {
    pub indexed_block: u64,
    pub created: u64,
}

impl Odoo {
    pub fn new(cfg: &OdooCfg, key_env: &str) -> Result<Self> {
        let key = std::env::var(key_env).with_context(|| format!("env {key_env} not set"))?;
        Self::with_key(cfg, key)
    }

    pub fn with_key(cfg: &OdooCfg, key: String) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build()?,
            base: cfg.url.trim_end_matches('/').to_string(),
            db: cfg.database.clone(),
            key,
        })
    }

    pub async fn call<T: DeserializeOwned>(&self, model: &str, method: &str, body: Value) -> Result<T> {
        let res = self
            .http
            .post(format!("{}/json/2/{model}/{method}", self.base))
            .bearer_auth(&self.key)
            .header("X-Odoo-Database", &self.db)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("{model}.{method}: transport"))?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            // Cắt ngắn: lỗi Odoo có thể kèm traceback dài.
            let head: String = text.chars().take(300).collect();
            return Err(anyhow!("{model}.{method}: HTTP {status}: {head}"));
        }
        serde_json::from_str(&text).with_context(|| format!("{model}.{method}: decode"))
    }

    pub async fn node_config(&self, chain: u64, relayer: Option<Address>) -> Result<NodeConfig> {
        self.node_config_ref(json!(chain), relayer.map(|r| format!("{r:#x}")), None).await
    }

    /// `chain` = số EIP-155 (EVM) hoặc khoá `family:network` (R61). `worker` lọc job đã claim mà
    /// chưa ký về đúng lane đã claim (nhiều lane cùng chain).
    pub async fn node_config_ref(&self, chain: Value, relayer: Option<String>, worker: Option<String>) -> Result<NodeConfig> {
        let mut body = json!({"evm_chain_number": chain});
        if let Some(r) = relayer {
            body["relayer_address"] = json!(r);
        }
        if let Some(w) = worker {
            body["worker"] = json!(w);
        }
        self.call("blockchain.chain", "node_config", body).await
    }

    pub async fn relay_poll(&self, chain: u64, limit: u32) -> Result<Vec<Job>> {
        self.relay_poll_ref(json!(chain), limit).await
    }

    pub async fn relay_poll_ref(&self, chain: Value, limit: u32) -> Result<Vec<Job>> {
        self.call("blockchain.relay.job", "relay_poll", json!({"evm_chain_number": chain, "limit": limit}))
            .await
    }

    pub async fn relay_claim(&self, ids: &[i64], worker: &str) -> Result<Vec<i64>> {
        self.call("blockchain.relay.job", "relay_claim", json!({"job_ids": ids, "worker": worker})).await
    }

    pub async fn relay_report(&self, r: &Report) -> Result<()> {
        let _: Value = self.call("blockchain.relay.job", "relay_report", serde_json::to_value(r)?).await?;
        Ok(())
    }

    /// Drift C (R56): số dư ví nhận tại `height` (= cursor đã index). `stale` = cursor đã đi tiếp, đọc lại.
    pub async fn balance_report(&self, chain_key: &str, height: u64, balances: &[Value]) -> Result<BalanceReport> {
        self.call(
            "blockchain.chain",
            "balance_report",
            json!({"chain_key": chain_key, "height": height, "balances": balances}),
        )
        .await
    }

    pub async fn ingest(&self, chain: u64, from: u64, to: u64, hash: &str, events: &[Value]) -> Result<IngestResult> {
        self.ingest_ref(json!(chain), from, to, hash, events).await
    }

    pub async fn ingest_ref(&self, chain: Value, from: u64, to: u64, hash: &str, events: &[Value]) -> Result<IngestResult> {
        self.call(
            "blockchain.chain.event",
            "chain_event_ingest",
            json!({
                "evm_chain_number": chain, "from_block": from, "to_block": to,
                "to_block_hash": hash, "events": events,
            }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_payload_from_odoo_decodes() {
        let raw = r#"{"id": 3, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "digest": "0x33", "signature": "0x44", "struct": "transfer",
            "metatx": {"from": "0xabababababababababababababababababababab",
                       "to": "0x0101010101010101010101010101010101010101", "value": "100",
                       "entryRef": "0x0000000000000000000000000000000000000000000000000000000000000042",
                       "batch": "7", "nonce": "0", "validUntil": "1800000300",
                       "mode": 1, "relayer": "0x0202020202020202020202020202020202020202",
                       "fee": "0", "feeRecipient": "0x0000000000000000000000000000000000000000"}}"#;
        let job: Job = serde_json::from_str(raw).unwrap();
        assert_eq!(job.id, 3);
        let m = crate::metatx::Mtx::from_wire(job.struct_.as_deref(), job.metatx.as_ref().unwrap()).unwrap();
        assert_eq!(m.batch(), alloy::primitives::U256::from(7));
    }

    #[test]
    fn call_job_payload_decodes() {
        let raw = r#"{"id": 9, "kind": "call", "call": {"target": "0xbabababababababababababababababababababa",
            "calldata": "0xdeadbeef", "validUntil": "1800000300"}}"#;
        let job: Job = serde_json::from_str(raw).unwrap();
        assert!(job.metatx.is_none());
        let w = crate::submit::work_from_job(&job).unwrap();
        assert_eq!(w.data.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(w.valid_until, 1_800_000_300);
    }

    #[test]
    fn paused_chain_serves_no_tokens_to_the_gateway() {
        let mk = |state: &str| -> NodeConfig {
            serde_json::from_value(json!({"evm_chain_number": 1, "state": state, "finality_mode": "depth",
                "finality_depth": 1, "finality_quorum": 1, "indexed_block": 0, "journal_max_nonce": null,
                "tokens": [{"address": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "decimals": 6}]}))
            .unwrap()
        };
        assert_eq!(mk("active").submittable_tokens().len(), 1);
        assert!(mk("paused").submittable_tokens().is_empty());
    }

    /// Review H1: Odoo gửi địa chỉ token dạng chuẩn của HỌ (`wasm1…`, `0.0.x`, …); chỉ đường EVM đọc thành `Address`.
    #[test]
    fn non_evm_token_addresses_decode() {
        let nc: NodeConfig = serde_json::from_value(json!({"evm_chain_number": "cosmos:scaas-1", "finality_mode": "instant",
            "finality_depth": 0, "finality_quorum": 1, "indexed_block": 0, "journal_max_nonce": null,
            "tokens": [{"address": "wasm1g3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqn0lflt", "decimals": 6}]}))
        .unwrap();
        assert_eq!(nc.tokens[0].address, "wasm1g3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zqn0lflt");
        assert!(nc.submittable_tokens().is_empty(), "never an EVM address");
    }

    #[test]
    fn report_omits_absent_fields() {
        let r = Report { job_id: 1, chain_state: "dead".into(), error: Some("x".into()), ..Default::default() };
        let v = serde_json::to_value(r).unwrap();
        assert!(v.get("tx_hash").is_none());
        assert_eq!(v["error"], "x");
    }
}
