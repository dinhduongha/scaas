//! `/json/2` — đường duy nhất vào Odoo (ruling R6). Một client cho mỗi API key.
use alloy::primitives::Address;
use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::OdooCfg;
use crate::metatx::WireMetaTx;

#[derive(Clone)]
pub struct Odoo {
    http: reqwest::Client,
    base: String,
    db: String,
    key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenCfg {
    pub address: Address,
    pub decimals: u8,
}

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
    pub evm_chain_number: u64,
    pub finality_mode: String,
    pub finality_depth: u64,
    pub finality_quorum: usize,
    pub indexed_block: u64,
    pub tokens: Vec<TokenCfg>,
    pub journal_max_nonce: Option<u64>,
    #[serde(default)]
    pub inflight: Vec<InflightJob>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub id: i64,
    pub token: Address,
    pub digest: String,
    pub signature: String,
    pub metatx: WireMetaTx,
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
        let mut body = json!({"evm_chain_number": chain});
        if let Some(r) = relayer {
            body["relayer_address"] = json!(format!("{r:#x}"));
        }
        self.call("blockchain.chain", "node_config", body).await
    }

    pub async fn relay_poll(&self, chain: u64, limit: u32) -> Result<Vec<Job>> {
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

    pub async fn ingest(&self, chain: u64, from: u64, to: u64, hash: &str, events: &[Value]) -> Result<IngestResult> {
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
            "digest": "0x33", "signature": "0x44",
            "metatx": {"from": "0xabababababababababababababababababababab",
                       "to": "0x0101010101010101010101010101010101010101", "value": "100",
                       "data": "0x", "batch": "7", "nonce": "0", "validUntil": "1800000300",
                       "mode": 1, "relayer": "0x0202020202020202020202020202020202020202",
                       "fee": "0", "feeRecipient": "0x0000000000000000000000000000000000000000"}}"#;
        let job: Job = serde_json::from_str(raw).unwrap();
        assert_eq!(job.id, 3);
        assert_eq!(job.metatx.to_sol().unwrap().batch, alloy::primitives::U256::from(7));
    }

    #[test]
    fn report_omits_absent_fields() {
        let r = Report { job_id: 1, chain_state: "dead".into(), error: Some("x".into()), ..Default::default() };
        let v = serde_json::to_value(r).unwrap();
        assert!(v.get("tx_hash").is_none());
        assert_eq!(v["error"], "x");
    }
}
