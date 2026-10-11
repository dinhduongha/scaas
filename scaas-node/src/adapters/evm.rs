//! EVM (và Hedera HSCS) dưới dạng `ChainAdapter`. Runner chính của EVM vẫn là `submit.rs` (pipeline
//! nonce + thay thế + gap-fill, không đổi hành vi); adapter này phục vụ `lane_runner`/`index_runner`
//! dùng chung và là mẫu cho các họ khác.
use std::sync::{Arc, RwLock};

use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde_json::{json, Value};

use crate::abi::IToken;
use crate::adapter::{Built, ChainAdapter, Family, Head, Lane, Signed, TxStatus};
use crate::chain::{Chain, SimError};
use crate::config::ChainCfg;
use crate::finality::{quorum_ok, safe_head, Mode};
use crate::guard::{self, Guard};
use crate::indexer::encode_event;
use crate::odoo::Job;
use crate::submit::{job_digest, work_from_job};

pub struct EvmAdapter {
    key: String,
    family: Family,
    chains: Vec<Chain>,
    lanes: Vec<Lane>,
    mode: Mode,
    quorum: usize,
    max_gas: u64,
    /// Token đã đăng ký (làm mới từ `node_config`); event của contract lạ không bao giờ gửi Odoo.
    pub tokens: Arc<RwLock<Vec<Address>>>,
    /// PAY-FIX2, NODE-GW-07, NODE-JOB-20: checked before every simulation.
    guard: Guard,
    /// `[[chains]] fee_recipient`: NODE-LANE-10 normalizes every job with it (`work_from_job`).
    pub(crate) fee_recipient: Option<Address>,
}

impl EvmAdapter {
    pub fn new(cfg: &ChainCfg, chains: Vec<Chain>, tokens: Arc<RwLock<Vec<Address>>>) -> Result<Self> {
        if chains.is_empty() {
            return Err(anyhow!("chain {}: no lane", cfg.chain_key()));
        }
        let lanes = chains
            .iter()
            .zip(&cfg.lanes)
            .map(|(c, &i)| Lane { index: i, address: format!("{:#x}", c.address()) })
            .collect();
        let mode = if cfg.finality.mode == "tag" { Mode::Tag } else { Mode::Depth(cfg.finality.depth) };
        Ok(Self {
            guard: Guard::new(cfg, tokens.clone()),
            key: cfg.chain_key(),
            family: if cfg.family == "hedera" { Family::Hedera } else { Family::Evm },
            chains,
            lanes,
            mode,
            quorum: cfg.finality.quorum,
            max_gas: cfg.max_gas_per_tx,
            tokens,
            fee_recipient: cfg.fee_recipient,
        })
    }

    pub(crate) fn lane(&self, i: usize) -> Result<&Chain> {
        self.chains.get(i).ok_or_else(|| anyhow!("no lane {i}"))
    }
}

#[async_trait]
impl ChainAdapter for EvmAdapter {
    fn family(&self) -> Family {
        self.family
    }

    fn chain_key(&self) -> &str {
        &self.key
    }

    fn lanes(&self) -> &[Lane] {
        &self.lanes
    }

    async fn digest(&self, job: &Job) -> std::result::Result<Option<B256>, SimError> {
        let Ok(w) = work_from_job(job, self.fee_recipient) else { return Ok(None) };
        let Some((m, _)) = crate::metatx::Mtx::from_calldata(&w.data) else { return Ok(job_digest(job)) };
        let chain = self.lane(0).map_err(|e| SimError::Transport(e.to_string()))?;
        chain.mtx_digest(w.to, m).await.map(Some)
    }

    async fn build(&self, job: &Job, lane: usize) -> std::result::Result<Built, SimError> {
        let w = work_from_job(job, self.fee_recipient).map_err(|e| SimError::Revert(format!("bad payload: {e:#}")))?;
        let chain = self.lane(lane).map_err(|e| SimError::Transport(e.to_string()))?;
        self.guard.check(chain, &w).await?;
        let gas = guard::gas(chain, &w, self.max_gas).await?;
        Ok(Built {
            job_id: job.id,
            body: w.data.to_vec(),
            valid_until: w.valid_until,
            meta: json!({"to": format!("{:#x}", w.to), "gas": gas}),
        })
    }

    async fn sign(&self, built: Built, lane: usize, sequence: u64) -> Result<Signed> {
        let chain = self.lane(lane)?;
        let to: Address = built.meta["to"].as_str().unwrap_or_default().parse()?;
        let gas = built.meta["gas"].as_u64().unwrap_or(self.max_gas);
        let fees = chain.fees().await?;
        let (raw, hash) = chain.sign(sequence, to, Bytes::from(built.body), gas, fees).await?;
        Ok(Signed { job_id: built.job_id, tx_id: format!("{hash:#x}"), raw: raw.to_vec(), valid_until: built.valid_until, sequence })
    }

    async fn submit(&self, signed: &Signed) -> Result<()> {
        self.chains[0].send_raw(&Bytes::from(signed.raw.clone())).await
    }

    async fn tx_status(&self, tx_id: &str) -> Result<TxStatus> {
        let hash: B256 = tx_id.parse()?;
        Ok(match self.chains[0].primary().get_transaction_receipt(hash).await? {
            Some(rc) if rc.status() => TxStatus::Mined { height: rc.block_number.unwrap_or_default(), tx_hash: None },
            Some(_) => TxStatus::Reverted { reason: "execution reverted".into() },
            None => match self.chains[0].primary().get_transaction_by_hash(hash).await? {
                Some(_) => TxStatus::Pending,
                None => TxStatus::Unknown,
            },
        })
    }

    async fn sequence(&self, lane: usize) -> Result<u64> {
        let chain = self.lane(lane)?;
        Ok(chain.primary().get_transaction_count(chain.address()).latest().await?)
    }

    async fn final_head(&self) -> Result<Option<Head>> {
        let c = &self.chains[0];
        let latest = c.primary().get_block_number().await?;
        let finalized = if self.mode == Mode::Tag { c.finalized_number().await? } else { None };
        let Some(safe) = safe_head(&self.mode, latest, finalized) else { return Ok(None) };
        let Some(hash) = Chain::block_hash(c.primary(), safe).await else { return Ok(None) };
        let mut others = Vec::new();
        for p in c.others() {
            others.push(Chain::block_hash(p, safe).await);
        }
        if !quorum_ok(hash, &others, self.quorum) {
            return Ok(None);
        }
        Ok(Some(Head { height: safe, hash: format!("{hash:#x}") }))
    }

    async fn block_hash(&self, height: u64) -> Result<String> {
        Chain::block_hash(self.chains[0].primary(), height)
            .await
            .map(|h| format!("{h:#x}"))
            .ok_or_else(|| anyhow!("no block {height}"))
    }

    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>> {
        let addrs: Vec<Address> = contracts.iter().filter_map(|c| c.parse().ok()).collect();
        if addrs.is_empty() {
            return Ok(vec![]);
        }
        let f = Filter::new().from_block(from).to_block(to).address(addrs).event_signature(vec![
            IToken::PaymentSettled::SIGNATURE_HASH,
            IToken::MetaTransactionExecuted::SIGNATURE_HASH,
        ]);
        Ok(self.chains[0].primary().get_logs(&f).await?.iter().filter_map(encode_event).collect())
    }

    async fn lane_balance(&self, lane: usize) -> Result<Option<u128>> {
        let c = self.lane(lane)?;
        Ok(Some(c.primary().get_balance(c.address()).await?.saturating_to()))
    }

    async fn tx_fee(&self, tx_id: &str) -> Result<Option<u128>> {
        let hash: B256 = tx_id.parse()?;
        Ok(self.chains[0]
            .primary()
            .get_transaction_receipt(hash)
            .await?
            .map(|rc| u128::from(rc.gas_used).saturating_mul(rc.effective_gas_price)))
    }
}
