//! Mô-đun `submit`: MỘT task mỗi chain, sở hữu duy nhất nonce vỏ (`_USER-DECISIONS` §23.1).
//!
//! Bất biến: không bao giờ bỏ một nonce (R18) — tx kẹt được thay thế với phí cao hơn; job phải
//! bỏ thì nonce của nó được lấp bằng tx 0-value tự chuyển. `final` của job KHÔNG đến từ đây mà từ
//! indexer (`MetaTransactionExecuted`), nên một meta-tx được người khác thực thi vẫn thành `final`.
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::abi::IMetaToken;
use crate::chain::{Chain, SimError};
use crate::config::ChainCfg;
use crate::nonce::{bump, plan, Inflight};
use crate::odoo::{Job, Odoo, Report};

const GAP_FILL_GAS: u64 = 21_000;

/// Một việc cần lên chain: job outbox Odoo (`job_id`) hoặc việc của gateway (`None`).
#[derive(Debug, Clone)]
pub struct Work {
    pub job_id: Option<i64>,
    pub to: Address,
    pub data: Bytes,
    pub valid_until: u64,
}

struct Sent {
    work: Option<Work>,
    hash: B256,
    gas: u64,
    fees: (u128, u128),
    at: Instant,
}

pub fn work_from_job(job: &Job) -> Result<Work> {
    let m = job.metatx.to_sol()?;
    let hex = job.signature.strip_prefix("0x").unwrap_or(&job.signature);
    let sig = alloy::hex::decode(hex)?;
    let valid_until = m.validUntil.saturating_to();
    let data = IMetaToken::executeMetaTransactionCall { m, signature: sig.into() }.abi_encode();
    Ok(Work { job_id: Some(job.id), to: job.token, data: data.into(), valid_until })
}

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub struct Submitter {
    chain: Chain,
    odoo: Odoo,
    cfg: ChainCfg,
    node_id: String,
    next: u64,
    inflight: BTreeMap<u64, Sent>,
}

impl Submitter {
    pub async fn start(chain: Chain, odoo: Odoo, cfg: ChainCfg, node_id: String) -> Result<Self> {
        let nc = odoo.node_config(cfg.evm_chain_number, Some(chain.address())).await?;
        let pending = chain.pending_nonce().await?;
        let jobs: Vec<Inflight> = nc
            .inflight
            .iter()
            .map(|j| Inflight { job_id: j.job_id, nonce: j.nonce, state: j.state.clone() })
            .collect();
        let p = plan(pending, nc.journal_max_nonce, &jobs);
        let mut me = Self { chain, odoo, cfg, node_id, next: p.next, inflight: BTreeMap::new() };
        for n in &p.gap_fill {
            me.gap_fill(*n).await?;
        }
        for id in &p.requeue {
            me.report(*id, "queued", None, None, Some("requeued at node start".into())).await;
        }
        for j in nc.inflight.iter().filter(|j| p.track.contains(&j.job_id)) {
            let (Some(n), Some(h)) = (j.nonce, j.tx_hash.as_deref()) else { continue };
            let Ok(hash) = h.parse::<B256>() else { continue };
            let fees = me.chain.fees().await?;
            let work = work_from_job(&j.payload).ok();
            me.inflight.insert(n, Sent { work, hash, gas: me.cfg.max_gas_per_tx, fees, at: Instant::now() });
        }
        info!(chain = me.cfg.evm_chain_number, next = me.next, tracked = me.inflight.len(), "submit ready");
        Ok(me)
    }

    pub fn address(&self) -> Address {
        self.chain.address()
    }

    async fn report(&self, job: i64, state: &str, hash: Option<B256>, nonce: Option<u64>, err: Option<String>) {
        let r = Report {
            job_id: job,
            chain_state: state.into(),
            tx_hash: hash.map(|h| format!("{h:#x}")),
            outer_nonce: nonce,
            signer_address: nonce.map(|_| format!("{:#x}", self.chain.address())),
            error: err,
        };
        if let Err(e) = self.odoo.relay_report(&r).await {
            warn!(job, state, "relay_report failed: {e:#}");
        }
    }

    /// Tx 0-value tự chuyển ở đúng `nonce` — lấp lỗ, không bao giờ bỏ nonce (R18).
    async fn gap_fill(&mut self, nonce: u64) -> Result<()> {
        let fees = self.chain.fees().await?;
        let (raw, hash) = self.chain.sign(nonce, self.chain.address(), Bytes::new(), GAP_FILL_GAS, fees).await?;
        if let Err(e) = self.chain.send_raw(&raw).await {
            warn!(nonce, "gap-fill send: {e:#}");
        }
        self.inflight.insert(nonce, Sent { work: None, hash, gas: GAP_FILL_GAS, fees, at: Instant::now() });
        warn!(nonce, "gap-filled");
        Ok(())
    }

    pub async fn submit(&mut self, w: Work) {
        if w.valid_until <= now() {
            if let Some(id) = w.job_id {
                self.report(id, "dead", None, None, Some("expired before submit".into())).await;
            }
            return;
        }
        let gas = match self.chain.simulate(w.to, w.data.clone()).await {
            Ok(g) if g <= self.cfg.max_gas_per_tx => g + g / 5,
            Ok(g) => return self.fail(&w, format!("gas {g} above max_gas_per_tx")).await,
            Err(SimError::Revert(reason)) => return self.fail(&w, reason).await,
            Err(SimError::Transport(reason)) => return self.requeue(&w, format!("simulate: {reason}")).await,
        };
        let fees = match self.chain.fees().await {
            Ok(f) => f,
            Err(e) => return self.requeue(&w, format!("fees: {e:#}")).await,
        };
        let nonce = self.next;
        let (raw, hash) = match self.chain.sign(nonce, w.to, w.data.clone(), gas, fees).await {
            Ok(x) => x,
            Err(e) => return self.requeue(&w, format!("{e:#}")).await,
        };
        // Journal TRƯỚC khi gửi (review F5): crash giữa hai bước không dẫn tới ký lại.
        if let Some(id) = w.job_id {
            self.report(id, "signed", Some(hash), Some(nonce), None).await;
        }
        self.next += 1;
        match self.chain.send_raw(&raw).await {
            Ok(()) => {
                if let Some(id) = w.job_id {
                    self.report(id, "broadcast", None, None, None).await;
                }
            }
            // Không trả nonce lại: tx đã ký nằm trong journal; vòng `track` sẽ thay thế nó.
            Err(e) => warn!(nonce, "send failed, will replace: {e:#}"),
        }
        self.inflight.insert(nonce, Sent { work: Some(w), hash, gas, fees, at: Instant::now() });
    }

    async fn fail(&self, w: &Work, reason: String) {
        warn!(job = ?w.job_id, "simulation refused: {reason}");
        if let Some(id) = w.job_id {
            self.report(id, "dead", None, None, Some(reason)).await;
        }
    }

    async fn requeue(&self, w: &Work, reason: String) {
        warn!(job = ?w.job_id, "transient, requeue: {reason}");
        if let Some(id) = w.job_id {
            self.report(id, "queued", None, None, Some(reason)).await;
        }
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Receipt → mined/reverted; quá hạn → thay thế cùng nonce. Meta-tx hết hạn ⇒ lấp lỗ.
    pub async fn track(&mut self) {
        let nonces: Vec<u64> = self.inflight.keys().copied().collect();
        for n in nonces {
            let Some(s) = self.inflight.get(&n) else { continue };
            match self.chain.primary().get_transaction_receipt(s.hash).await {
                Ok(Some(rc)) => {
                    let s = self.inflight.remove(&n).expect("present");
                    if let Some(id) = s.work.and_then(|w| w.job_id) {
                        let st = if rc.status() { "mined" } else { "reverted" };
                        self.report(id, st, None, None, None).await;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(nonce = n, "receipt: {e:#}");
                    continue;
                }
            }
            if s.at.elapsed() < Duration::from_secs(self.cfg.stuck_after_secs) {
                continue;
            }
            let cap = u128::from(self.cfg.max_fee_cap_gwei) * 1_000_000_000;
            let fees = (bump(s.fees.0, cap), bump(s.fees.1, cap));
            let live = s.work.as_ref().filter(|w| w.valid_until > now()).cloned();
            let expired_job = match (&s.work, &live) {
                (Some(w), None) => w.job_id,
                _ => None,
            };
            let (to, data, gas) = match &live {
                Some(w) => (w.to, w.data.clone(), s.gas),
                None => (self.chain.address(), Bytes::new(), GAP_FILL_GAS),
            };
            if let Some(id) = expired_job {
                self.report(id, "dead", None, None, Some("expired while stuck; nonce gap-filled".into())).await;
            }
            match self.chain.sign(n, to, data, gas, fees).await {
                Ok((raw, h)) => {
                    if let Err(e) = self.chain.send_raw(&raw).await {
                        warn!(nonce = n, "replace send: {e:#}");
                    }
                    if let Some(id) = live.as_ref().and_then(|w| w.job_id) {
                        self.report(id, "broadcast", Some(h), None, None).await;
                    }
                    self.inflight.insert(n, Sent { work: live, hash: h, gas, fees, at: Instant::now() });
                    info!(nonce = n, "replaced");
                }
                Err(e) => warn!(nonce = n, "replace sign: {e:#}"),
            }
        }
    }

    pub async fn poll_outbox(&mut self) {
        let jobs = match self.odoo.relay_poll(self.cfg.evm_chain_number, 10).await {
            Ok(j) => j,
            Err(e) => {
                warn!("relay_poll: {e:#}");
                return;
            }
        };
        for job in jobs {
            match self.odoo.relay_claim(&[job.id], &self.node_id).await {
                Ok(ids) if ids.contains(&job.id) => {}
                Ok(_) => continue,
                Err(e) => {
                    warn!("relay_claim: {e:#}");
                    continue;
                }
            }
            match work_from_job(&job) {
                Ok(w) => self.submit(w).await,
                Err(e) => self.report(job.id, "dead", None, None, Some(format!("bad payload: {e:#}"))).await,
            }
        }
    }
}

pub async fn run(mut s: Submitter, mut rx: mpsc::Receiver<Work>, poll: Duration) {
    loop {
        s.poll_outbox().await;
        while let Ok(w) = rx.try_recv() {
            s.submit(w).await;
        }
        s.track().await;
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            Some(w) = rx.recv() => s.submit(w).await,
        }
    }
}
