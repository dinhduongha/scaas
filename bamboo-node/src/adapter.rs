//! `ChainAdapter` (R58): một mạng = một adapter. EVM giữ runner riêng (`submit.rs`: pipeline nonce,
//! thay thế, gap-fill) nhưng cũng cài trait; các họ khác chạy `lane_runner` — mỗi lane MỘT tx đang bay,
//! song song giữa các lane (R62: sequence của relayer không thành khoá toàn cục, chủ thể không có
//! sequence trong đường đi — R30).
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

use crate::chain::SimError;
use crate::finality::next_range;
use crate::odoo::{Job, Odoo, Report};
use crate::submit::now;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Evm,
    Hedera,
    Sui,
    Soroban,
    Cosmos,
    Ton,
}

impl Family {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "evm" => Self::Evm,
            "hedera" => Self::Hedera,
            "sui" => Self::Sui,
            "soroban" => Self::Soroban,
            "cosmos" => Self::Cosmos,
            "ton" => Self::Ton,
            _ => return None,
        })
    }
}

/// Một lane relayer: địa chỉ/khoá công khai dạng chuẩn của họ (chỉ để log và báo Odoo).
#[derive(Debug, Clone)]
pub struct Lane {
    pub index: u32,
    pub address: String,
}

/// Tx native đã dựng + đã mô phỏng, chưa ký. `valid_until` = hạn của payload chủ thể đã ký.
#[derive(Debug, Clone)]
pub struct Built {
    pub job_id: i64,
    pub body: Vec<u8>,
    pub valid_until: u64,
    pub meta: Value,
}

#[derive(Debug, Clone)]
pub struct Signed {
    pub job_id: i64,
    pub tx_id: String,
    pub raw: Vec<u8>,
    pub valid_until: u64,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    Pending,
    Mined { height: u64 },
    Reverted { reason: String },
    /// Không thấy trên mạng (chưa vào mempool, hoặc đã rơi).
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub height: u64,
    pub hash: String,
}

#[async_trait]
pub trait ChainAdapter: Send + Sync {
    fn family(&self) -> Family;
    fn chain_key(&self) -> &str;
    fn lanes(&self) -> &[Lane];
    /// Dựng tx native từ job outbox và MÔ PHỎNG. `Revert` = vĩnh viễn (job chết), `Transport` = thử lại.
    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError>;
    /// Ký bằng `Signer` của lane với sequence/nonce/seqno đã đọc.
    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed>;
    async fn submit(&self, signed: &Signed) -> Result<()>;
    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus>;
    /// Sequence đã COMMIT của lane (review S14) — không đoán từ bộ nhớ.
    async fn sequence(&self, lane: usize) -> Result<u64>;
    /// Đỉnh đã final (độ sâu/tag/BFT + quorum endpoint) — chỉ vùng này được báo Odoo.
    async fn final_head(&self) -> Result<Option<Head>>;
    /// Hash (`0x` + 64 hex) của khối/ledger/checkpoint `height` — đầu cuối vùng báo Odoo.
    async fn block_hash(&self, height: u64) -> Result<String>;
    /// Event chuẩn hoá cho `chain_event_ingest` trong [from, to]; hash và địa chỉ đã ở dạng chuẩn
    /// (hash `0x`+64 hex; địa chỉ theo họ — R61).
    async fn events(&self, from: u64, to: u64) -> Result<Vec<Value>>;
}

const STATUS_POLL: Duration = Duration::from_millis(500);
const EXPIRY_GRACE: u64 = 30;

async fn report(odoo: &Odoo, r: Report) -> bool {
    match odoo.relay_report(&r).await {
        Ok(()) => true,
        Err(e) => {
            warn!(job = r.job_id, state = %r.chain_state, "relay_report: {e:#}");
            false
        }
    }
}

fn rep(job: i64, state: &str) -> Report {
    Report { job_id: job, chain_state: state.into(), ..Default::default() }
}

/// Một lane: claim → build/simulate → sign → journal `signed` → submit → theo dõi tới mined/reverted.
pub async fn lane_runner(adapter: Arc<dyn ChainAdapter>, odoo: Odoo, lane: usize, worker: String, poll: Duration) {
    let key = adapter.chain_key().to_string();
    info!(chain = %key, lane, address = %adapter.lanes()[lane].address, "lane ready");
    loop {
        match lane_step(adapter.as_ref(), &odoo, lane, &worker).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => warn!(chain = %key, lane, "lane: {e:#}"),
        }
        tokio::time::sleep(poll).await;
    }
}

/// `true` = đã xử lý một job (đi tiếp ngay).
pub async fn lane_step(adapter: &dyn ChainAdapter, odoo: &Odoo, lane: usize, worker: &str) -> Result<bool> {
    let jobs = odoo.relay_poll_ref(adapter.chain_key().into(), 5).await?;
    let mut job = None;
    for j in jobs {
        if odoo.relay_claim(&[j.id], worker).await?.contains(&j.id) {
            job = Some(j);
            break;
        }
    }
    let Some(job) = job else { return Ok(false) };
    let built = match adapter.build(&job, lane).await {
        Ok(b) => b,
        Err(SimError::Revert(r)) => {
            report(odoo, Report { error: Some(format!("simulation: {r}")), ..rep(job.id, "dead") }).await;
            return Ok(true);
        }
        Err(SimError::Transport(r)) => {
            report(odoo, Report { error: Some(format!("rpc: {r}")), ..rep(job.id, "queued") }).await;
            return Ok(true);
        }
    };
    let seq = adapter.sequence(lane).await?;
    let signed = adapter.sign(built, lane, seq).await?;
    let signer = adapter.lanes()[lane].address.clone();
    // Journal TRƯỚC khi gửi (review I5): không ghi được thì không gửi, job về hàng đợi.
    if !report(odoo, Report { tx_hash: Some(signed.tx_id.clone()), outer_nonce: Some(seq), signer_address: Some(signer), ..rep(job.id, "signed") }).await {
        report(odoo, Report { error: Some("journal write failed".into()), ..rep(job.id, "queued") }).await;
        return Ok(true);
    }
    let mut sent = adapter.submit(&signed).await.is_ok();
    if sent {
        report(odoo, rep(job.id, "broadcast")).await;
    }
    loop {
        match adapter.tx_status(&signed.tx_id).await {
            Ok(TxStatus::Mined { .. }) => {
                report(odoo, rep(job.id, "mined")).await;
                return Ok(true);
            }
            Ok(TxStatus::Reverted { reason }) => {
                report(odoo, Report { error: Some(reason), ..rep(job.id, "reverted") }).await;
                return Ok(true);
            }
            Ok(TxStatus::Pending) => {}
            Ok(TxStatus::Unknown) | Err(_) => {
                if now() > signed.valid_until + EXPIRY_GRACE {
                    // Payload chủ thể đã hết hạn: tx (nếu còn đâu đó) sẽ bị contract từ chối.
                    report(odoo, Report { error: Some("expired before inclusion".into()), ..rep(job.id, "dead") }).await;
                    return Ok(true);
                }
                if !sent {
                    sent = adapter.submit(&signed).await.is_ok();
                    if sent {
                        report(odoo, rep(job.id, "broadcast")).await;
                    }
                }
            }
        }
        tokio::time::sleep(STATUS_POLL).await;
    }
}

/// Indexer chung cho adapter không phải EVM: đỉnh final → event → `chain_event_ingest`.
pub async fn index_runner(adapter: Arc<dyn ChainAdapter>, odoo: Odoo, poll: Duration) {
    loop {
        match index_step(adapter.as_ref(), &odoo).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => warn!(chain = %adapter.chain_key(), "indexer: {e:#}"),
        }
        tokio::time::sleep(poll).await;
    }
}

pub async fn index_step(adapter: &dyn ChainAdapter, odoo: &Odoo) -> Result<bool> {
    let key: Value = adapter.chain_key().into();
    let nc = odoo.node_config_ref(key.clone(), None, None).await?;
    let Some(head) = adapter.final_head().await? else { return Ok(false) };
    let Some((from, to)) = next_range(nc.indexed_block, head.height, 1000) else { return Ok(false) };
    let events = adapter.events(from, to).await?;
    let hash = if to == head.height { head.hash.clone() } else { adapter.block_hash(to).await? };
    let r = odoo.ingest_ref(key, from, to, &hash, &events).await?;
    Ok(r.indexed_block >= to && to < head.height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_parse() {
        assert_eq!(Family::parse("sui"), Some(Family::Sui));
        assert_eq!(Family::parse("solana"), None);
    }
}
