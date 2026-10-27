//! Mô-đun `submit`: MỘT task mỗi chain, sở hữu duy nhất nonce vỏ (`_USER-DECISIONS` §23.1).
//!
//! Bất biến: không bao giờ bỏ một nonce (R18) — tx kẹt được thay thế với phí cao hơn; job phải
//! bỏ thì nonce của nó được lấp bằng tx 0-value tự chuyển. `final` của job KHÔNG đến từ đây mà từ
//! indexer (`MetaTransactionExecuted`), nên một meta-tx được người khác thực thi vẫn thành `final`.
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionReceipt;
use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::breaker::Breaker;
use crate::chain::{Chain, SimError};
use crate::abi::IToken;
use crate::config::ChainCfg;
use crate::guard::{self, Guard, Refusal};
use crate::metatx::{addr, uint, Mtx};
use crate::nonce::{bump, plan, Inflight};
use crate::odoo::{Job, Odoo, Report};

/// A 0-value self-transfer: 21,000 before Amsterdam, 12,000 under EIP-2780 (no recipient charge for the sender
/// itself; the SCaaS testnet's value transfer to another account used 21,000 = 12,000 + 3,000 + 6,000), so 21,000 fits both.
const GAP_FILL_GAS: u64 = 21_000;
/// Nhịp lấy mẫu base fee + số dư lane cho cầu dao (R55).
const SAMPLE_EVERY: Duration = Duration::from_secs(15);
/// §8.5: số khối gần nhất tìm `MetaTransactionExecuted` khi phân loại một meta-tx đã bị tiêu thụ.
/// ponytail: cửa sổ cố định; ghi khối lúc claim vào `Sent` nếu tx kẹt lâu hay ra `unknown`.
const CLASSIFY_LOOKBACK: u64 = 1_000;

/// `scaas_submit_bump_skipped_consumed_total`: lần `track()` KHÔNG bump vì meta-tx đã bị tiêu thụ (R80).
pub static BUMP_SKIPPED_CONSUMED: AtomicU64 = AtomicU64::new(0);

/// Một việc cần lên chain: job outbox Odoo (`job_id`) hoặc việc của gateway (`None`).
#[derive(Debug, Clone)]
pub struct Work {
    pub job_id: Option<i64>,
    pub to: Address,
    pub data: Bytes,
    pub valid_until: u64,
    /// `None` cho job `call`.
    pub meta: Option<MetaRef>,
    /// A token's order or wrap entry (`metatx` job naming `entry`), not a `call` (`guard`).
    pub entry: bool,
}

/// Meta-tx bên trong `Work`: đủ để đọc nonce chủ thể (R80) và nhận ra digest trong event (§8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaRef {
    pub token: Address,
    pub from: Address,
    pub batch: U256,
    pub nonce: U256,
    /// `None` = không biết (payload Odoo không có digest): không dedup, không nhận ra là của ta.
    pub digest: Option<B256>,
}

impl MetaRef {
    pub fn of(token: Address, m: &Mtx, digest: Option<B256>) -> Self {
        Self { token, from: m.from(), batch: m.batch(), nonce: m.nonce(), digest }
    }
}

/// G2 (§8.4): digest đang có tx vỏ sống trên MỘT chain, chung cho mọi lane `Submitter` (gateway đi qua lane 0) và
/// mọi `lane_runner`. Giữ bằng guard RAII nên mọi lối ra không để lại `Sent` đều nhả digest (review N2).
#[derive(Clone, Default)]
pub struct InflightSet(Arc<Mutex<HashSet<B256>>>);

impl InflightSet {
    /// `None` = digest đã có đường khác giữ.
    pub fn try_acquire(&self, d: B256) -> Option<InflightGuard> {
        self.0.lock().ok()?.insert(d).then(|| InflightGuard { set: self.clone(), d })
    }

    pub fn contains(&self, d: &B256) -> bool {
        self.0.lock().is_ok_and(|s| s.contains(d))
    }
}

pub struct InflightGuard {
    set: InflightSet,
    d: B256,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.set.0.lock() {
            s.remove(&self.d);
        }
    }
}

/// Digest của job outbox (`metatx`: `digest`, `signed_op`: `op.digest`); không parse được ⇒ `None`.
pub fn job_digest(job: &Job) -> Option<B256> {
    job.digest.as_deref().or_else(|| job.op.as_ref()?.get("digest")?.as_str()).and_then(|d| d.parse().ok())
}

struct Sent {
    work: Option<Work>,
    /// Mọi hash đã gửi ở nonce này, cũ → mới: một bản đã bị thay thế vẫn có thể là bản vào khối.
    hashes: Vec<B256>,
    gas: u64,
    fees: (u128, u128),
    at: Instant,
    _guard: Option<InflightGuard>,
    /// A job tracked after a restart whose payload is not re-signed (refused by the guard, or unreadable): reported
    /// from its own hash (`hashes[0]`) or from the gap-fill that takes its nonce (review P5 m7).
    orphan: Option<i64>,
}

/// NODE-LANE-10 (R84) for the outbox: the unbound `relayer`/`feeRecipient` are normalized here as the gateway does
/// (`fee_recipient` = `[[chains]] fee_recipient`), never relayed as the job carries them. The digest is left `None`:
/// the dedup key is the token's own `mtxDigest`, read before submit (`Submitter::with_chain_digest`), never the job's.
pub fn work_from_job(job: &Job, fee_recipient: Option<Address>) -> Result<Work> {
    // T17 (one job-kind rule): an EVM job is `metatx` or `call`; any other kind is refused, never guessed.
    if let Some(k) = job.kind.as_deref().filter(|k| !matches!(*k, "metatx" | "call")) {
        anyhow::bail!("unknown job kind {k:?} (metatx | call)");
    }
    if job.receiver_fee.is_some() {
        anyhow::bail!("receiver-pays (receiver_fee) is not built in the node; refused, never relayed without it");
    }
    if let Some(e) = job.entry.as_deref() {
        return entry_work(job, e);
    }
    if let Some(c) = &job.call {
        let data = alloy::hex::decode(c.calldata.strip_prefix("0x").unwrap_or(&c.calldata))?;
        let valid_until = c.valid_until.parse::<u64>()?;
        return Ok(Work { job_id: Some(job.id), to: c.target, data: data.into(), valid_until, meta: None, entry: false });
    }
    let (Some(m), Some(token), Some(sig)) = (&job.metatx, job.token, &job.signature) else {
        anyhow::bail!("job {} has neither a meta-transaction nor a call", job.id);
    };
    let mut m = Mtx::from_wire(job.struct_.as_deref(), m)?;
    m.normalize(fee_recipient);
    let sig: Bytes = alloy::hex::decode(sig.strip_prefix("0x").unwrap_or(sig))?.into();
    let valid_until = m.valid_until().saturating_to();
    let meta = Some(MetaRef::of(token, &m, None));
    let hex = |s: &str| alloy::hex::decode(s.strip_prefix("0x").unwrap_or(s));
    let data = match (&job.salt, &job.meta) {
        (None, None) => m.calldata(sig),
        (Some(salt), Some(pm)) => {
            let salt = B256::try_from(&hex(salt)?[..]).map_err(|_| anyhow::anyhow!("salt is 32 bytes"))?;
            m.pay_meta_calldata(salt, hex(pm)?.into(), sig, job.meta_offchain != Some(true))?
        }
        _ => anyhow::bail!("a pay-meta job carries both salt and meta"),
    };
    Ok(Work { job_id: Some(job.id), to: token, data, valid_until, meta, entry: false })
}

/// A token's other signed entry point as a `metatx` job (job-api.md, order and wrap entries): the signature is in the
/// calldata, the target is `token`, no meta-tx lane is involved (`meta` None).
fn entry_work(job: &Job, entry: &str) -> Result<Work> {
    use alloy::sol_types::SolCall;
    let (Some(token), Some(sig)) = (job.token, &job.signature) else {
        anyhow::bail!("entry job {} without token or signature", job.id);
    };
    let sig: Bytes = alloy::hex::decode(sig.strip_prefix("0x").unwrap_or(sig))?.into();
    let order = || -> Result<crate::abi::TradeOrder> {
        let w = job.order.clone().ok_or_else(|| anyhow::anyhow!("entry {entry} without order"))?;
        serde_json::from_value::<crate::dex::WireOrder>(w)?.to_sol()
    };
    let deadline = || -> Result<u64> {
        Ok(job.valid_until.as_deref().ok_or_else(|| anyhow::anyhow!("entry {entry} without validUntil"))?.parse()?)
    };
    let text = |v: &Option<String>, f: &str| v.clone().ok_or_else(|| anyhow::anyhow!("entry {entry} without {f}"));
    let (data, valid_until) = match entry {
        "mtxCancelOrder" => (IToken::mtxCancelOrderCall { o: order()?, sig }.abi_encode(), deadline()?),
        "mtxInvalidateNonces" => {
            let (from, batch, new_min) = (addr(&text(&job.from, "from")?)?, uint(&text(&job.batch, "batch")?)?,
                uint(&text(&job.new_min, "newMin")?)?);
            (IToken::mtxInvalidateNoncesCall { from, batch, newMin: new_min, sig }.abi_encode(), deadline()?)
        }
        "mtxWrap" => {
            let o = order()?;
            let until = o.validUntil.saturating_to();
            let underlying = job.underlying.ok_or_else(|| anyhow::anyhow!("mtxWrap without underlying"))?;
            (IToken::mtxWrapCall { underlying, o, sig }.abi_encode(), until)
        }
        e => anyhow::bail!("unknown entry {e:?}"),
    };
    Ok(Work { job_id: Some(job.id), to: token, data: data.into(), valid_until, meta: None, entry: true })
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
    /// Việc chưa ghi được journal `signed` vào Odoo: chưa gửi, thử lại vòng sau (review I5) — vẫn giữ digest.
    retry: VecDeque<(Work, Option<InflightGuard>)>,
    digests: InflightSet,
    breaker: Arc<Mutex<Breaker>>,
    sampled: Option<Instant>,
    tripped: Option<&'static str>,
    /// PAY-FIX2, NODE-GW-07, NODE-JOB-20: checked before every simulation.
    guard: Guard,
}

impl Submitter {
    /// `digests`: tập in-flight CHUNG của chain (G2) — mọi lane của chain nhận cùng một bản.
    pub async fn start(chain: Chain, odoo: Odoo, cfg: ChainCfg, node_id: String, digests: InflightSet) -> Result<Self> {
        // `worker` lọc job đã claim mà chưa ký về đúng lane này (nhiều lane cùng chain — R62).
        let nc = odoo
            .node_config_ref(serde_json::json!(cfg.evm_chain_number), Some(format!("{:#x}", chain.address())), Some(node_id.clone()))
            .await?;
        // NODE-GW-07: a lane of a chain whose block 0 is not the configured chain_uid never starts.
        let uid = chain.uid().await?;
        let pending = chain.pending_nonce().await?;
        let jobs: Vec<Inflight> = nc
            .inflight
            .iter()
            .map(|j| Inflight { job_id: j.job_id, nonce: j.nonce, state: j.state.clone() })
            .collect();
        let p = plan(pending, nc.journal_max_nonce, &jobs);
        let breaker = Arc::new(Mutex::new(Breaker::new(cfg.breaker.clone())));
        let tokens = std::sync::RwLock::new(nc.tokens.iter().filter_map(crate::odoo::TokenCfg::evm).collect());
        let guard = Guard::new(&cfg, Arc::new(tokens))?;
        let mut me = Self {
            chain,
            odoo,
            cfg,
            node_id,
            next: p.next,
            inflight: BTreeMap::new(),
            retry: VecDeque::new(),
            digests,
            breaker,
            sampled: None,
            tripped: None,
            guard,
        };
        for n in &p.gap_fill {
            me.gap_fill(*n).await?;
        }
        for id in &p.requeue {
            let _ = me.report(*id, "queued", None, None, Some("requeued at node start".into())).await;
        }
        for j in nc.inflight.iter().filter(|j| p.track.contains(&j.job_id)) {
            let (Some(n), Some(h)) = (j.nonce, j.tx_hash.as_deref()) else { continue };
            let Ok(hash) = h.parse::<B256>() else { continue };
            let fees = me.chain.fees().await?;
            let work = match work_from_job(&j.payload, me.cfg.fee_recipient) {
                Ok(w) => Some(match me.with_chain_digest(w.clone()).await {
                    Ok(w) => w,
                    Err(SimError::Revert(_)) => w, // no dedup key; its simulation answers for it
                    Err(SimError::Transport(e)) => anyhow::bail!("mtxDigest: {e}"),
                }),
                Err(_) => None,
            };
            // review T4 m2: a rebuilt payload is re-signed by `track`, so it passes the guard too; refused ⇒ that
            // nonce is only ever gap-filled
            let work = match work {
                Some(w) => match me.guard.check(&me.chain, &w).await {
                    Ok(()) => Some(w),
                    Err(Refusal::Policy(r)) => {
                        warn!(job = j.job_id, nonce = n, "tracked job refused by the guard: {r}; its nonce is only gap-filled");
                        None
                    }
                    Err(Refusal::Transport(r)) => anyhow::bail!("guard: {r}"),
                },
                None => None,
            };
            // its replacements reuse the original transaction's gas limit (review M3); only when the RPC cannot tell,
            // the cap: the operator's, never past what the chain's blocks take (an unreadable block fails the start)
            let gas = match me.chain.tx_gas(hash).await {
                Ok(Some(g)) => g,
                _ => guard::total_cap(me.cfg.max_gas_per_tx, me.chain.block_gas().await?),
            };
            // Tập in-flight dựng lại từ việc đang theo dõi (§8.6).
            let guard = work.as_ref().and_then(|w| w.meta?.digest).and_then(|d| me.digests.try_acquire(d));
            let orphan = work.is_none().then_some(j.job_id);
            me.inflight.insert(n, Sent { work, hashes: vec![hash], gas, fees, at: Instant::now(), _guard: guard, orphan });
        }
        info!(chain = me.cfg.evm_chain_number, chain_uid = %uid, next = me.next, tracked = me.inflight.len(), "submit ready");
        Ok(me)
    }

    pub fn address(&self) -> Address {
        self.chain.address()
    }

    /// Cầu dao của lane này (đọc bởi cổng quản trị cho `/metrics`).
    pub fn breaker(&self) -> Arc<Mutex<Breaker>> {
        self.breaker.clone()
    }

    /// Lấy mẫu base fee + số dư (tối đa mỗi `SAMPLE_EVERY`). Lỗi RPC: giữ mẫu cũ, không nhảy cầu dao.
    pub async fn sample(&mut self) {
        if self.sampled.is_some_and(|t| t.elapsed() < SAMPLE_EVERY) {
            return;
        }
        self.sampled = Some(Instant::now());
        let base = match self.chain.primary().get_block_by_number(alloy::eips::BlockNumberOrTag::Latest).await {
            Ok(b) => b.and_then(|b| b.header.base_fee_per_gas),
            Err(e) => {
                warn!("breaker sample (block): {e:#}");
                None
            }
        };
        let bal = match self.chain.primary().get_balance(self.chain.address()).await {
            Ok(b) => Some(b.saturating_to::<u128>()),
            Err(e) => {
                warn!("breaker sample (balance): {e:#}");
                None
            }
        };
        // review T4 m1: the guard's registered tokens follow the client (same cadence as the breaker sample)
        match self.odoo.node_config(self.cfg.evm_chain_number, None).await {
            Ok(nc) => {
                if let Ok(mut t) = self.guard.tokens.write() {
                    *t = nc.tokens.iter().filter_map(crate::odoo::TokenCfg::evm).collect();
                }
            }
            Err(e) => warn!("token refresh: {e:#}"),
        }
        if let Ok(mut k) = self.breaker.lock() {
            if let Some(f) = base {
                k.base_fee(now(), f.into());
            }
            if let Some(b) = bal {
                k.balance(b);
            }
        }
    }

    /// Cầu dao đang mở ⇒ không nhận việc mới (vẫn theo dõi/thay thế tx đã ký). Log khi đổi trạng thái.
    pub fn accepting(&mut self) -> bool {
        let open = self.breaker.lock().map(|mut k| k.open(now())).unwrap_or(None);
        if open != self.tripped {
            match open {
                Some(b) => warn!(chain = self.cfg.evm_chain_number, lane = %self.node_id, breaker = b, "circuit breaker open: new work paused"),
                None => info!(chain = self.cfg.evm_chain_number, lane = %self.node_id, "circuit breakers closed"),
            }
            self.tripped = open;
        }
        open.is_none()
    }

    async fn report(&self, job: i64, state: &str, hash: Option<B256>, nonce: Option<u64>, err: Option<String>) -> bool {
        let r = Report {
            job_id: job,
            chain_state: state.into(),
            tx_hash: hash.map(|h| format!("{h:#x}")),
            outer_nonce: nonce,
            signer_address: nonce.map(|_| format!("{:#x}", self.chain.address())),
            error: err,
        };
        match self.odoo.relay_report(&r).await {
            Ok(()) => true,
            Err(e) => {
                warn!(job, state, "relay_report failed: {e:#}");
                false
            }
        }
    }

    /// Tx 0-value tự chuyển ở đúng `nonce` — lấp lỗ, không bao giờ bỏ nonce (R18).
    async fn gap_fill(&mut self, nonce: u64) -> Result<()> {
        let fees = self.chain.fees().await?;
        let (raw, hash) = self.chain.sign(nonce, self.chain.address(), Bytes::new(), GAP_FILL_GAS, fees).await?;
        if let Err(e) = self.chain.send_raw(&raw).await {
            warn!(nonce, "gap-fill send: {e:#}");
        }
        self.inflight.insert(nonce, Sent { work: None, hashes: vec![hash], gas: GAP_FILL_GAS, fees, at: Instant::now(), _guard: None, orphan: None });
        warn!(nonce, "gap-filled");
        Ok(())
    }

    /// The in-flight key of a meta-tx job: the token's own digest (`mtxDigest`/`mtxTransferDigest`, as the gateway
    /// reads it), never the job's `digest` field (review T2 m6). Other work passes unchanged.
    async fn with_chain_digest(&self, mut w: Work) -> std::result::Result<Work, SimError> {
        let (Some(r), Some((m, _))) = (w.meta, Mtx::from_calldata(&w.data)) else { return Ok(w) };
        w.meta = Some(MetaRef { digest: Some(self.chain.mtx_digest(w.to, m).await?), ..r });
        Ok(w)
    }

    /// The guard first (PAY-FIX2, NODE-GW-07, NODE-JOB-20: before any read of the target, simulation or signature),
    /// then the outbox job's token digest; G2: digest đã có tx vỏ sống ở đường khác (lane khác, gateway) ⇒ không ký
    /// lần hai.
    pub async fn submit(&mut self, w: Work) {
        match self.guard.check(&self.chain, &w).await {
            Ok(()) => {}
            Err(Refusal::Policy(reason)) => return self.fail(&w, reason).await,
            Err(Refusal::Transport(reason)) => return self.requeue(&w, reason).await,
        }
        let w = match w.meta.filter(|m| m.digest.is_none()) {
            None => w,
            Some(_) => match self.with_chain_digest(w.clone()).await {
                Ok(w) => w,
                Err(SimError::Revert(r)) => return self.fail(&w, format!("mtxDigest: {r}")).await,
                Err(SimError::Transport(r)) => return self.requeue(&w, format!("mtxDigest: {r}")).await,
            },
        };
        let guard = match w.meta.and_then(|m| m.digest) {
            None => None,
            Some(d) => match self.digests.try_acquire(d) {
                Some(g) => Some(g),
                None => return self.requeue(&w, "in flight on another path".into()).await,
            },
        };
        self.send(w, guard).await
    }

    /// `guard` theo `w` vào `Sent` khi tx được gửi; mọi lối ra khác thả nó (nhả digest).
    async fn send(&mut self, w: Work, guard: Option<InflightGuard>) {
        if w.valid_until <= now() {
            if let Some(id) = w.job_id {
                self.report(id, "dead", None, None, Some("expired before submit".into())).await;
            }
            return;
        }
        let gas = match guard::gas(&self.chain, &w, self.cfg.max_gas_per_tx).await {
            Ok(g) => g,
            Err(SimError::Revert(reason)) => return self.refused(&w, reason).await,
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
        // Journal TRƯỚC khi gửi (review F5): crash giữa hai bước không dẫn tới ký lại. Không ghi
        // được journal thì KHÔNG gửi, không tiêu nonce: thử lại vòng sau (review I5).
        if let Some(id) = w.job_id {
            if !self.report(id, "signed", Some(hash), Some(nonce), None).await {
                self.retry.push_back((w, guard));
                return;
            }
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
        self.inflight.insert(nonce, Sent { work: Some(w), hashes: vec![hash], gas, fees, at: Instant::now(), _guard: guard, orphan: None });
    }

    /// Mô phỏng revert. Meta-tx mà nonce chủ thể đã qua ⇒ `consumed` (R80: relayer khác có thể đã đưa nó lên chain),
    /// không `dead`; không đọc được nonce ⇒ tạm thời. An invalidation already in force is done, never dead (MT-8).
    async fn refused(&self, w: &Work, reason: String) {
        if guard::already_invalidated(&w.data, &reason) {
            if let Some(id) = w.job_id {
                self.report(id, "consumed", None, None, Some("already_invalidated".into())).await;
            }
            return;
        }
        match self.consumed(w).await {
            Ok(true) => self.report_consumed(w).await,
            Ok(false) => self.fail(w, reason).await,
            Err(e) => self.requeue(w, format!("mtxNonce: {e:#}")).await,
        }
    }

    /// R80: `mtxNonce(from, batch) > nonce` ⇔ nonce chủ thể của meta-tx đã bị dùng (bởi ai thì `classify`).
    /// `Ok(false)` cho job `call`. Lỗi RPC ⇒ `Err`: người gọi không bump, không kết luận (fail closed).
    async fn consumed(&self, w: &Work) -> Result<bool> {
        let Some(m) = &w.meta else { return Ok(false) };
        Ok(self.chain.mtx_nonce(m.token, m.from, m.batch).await? > m.nonce)
    }

    /// §8.5 — chỉ là nhãn cho `last_error` ở Odoo; `landed_elsewhere` do indexer quyết khi `final`.
    async fn classify(&self, m: &MetaRef) -> &'static str {
        match self.chain.meta_executed(m.token, m.from, m.batch, m.nonce, CLASSIFY_LOOKBACK).await {
            Ok(Some((d, r))) if Some(d) == m.digest && r == self.chain.address() => "landed",
            Ok(Some((d, _))) if Some(d) == m.digest => "landed_elsewhere",
            Ok(Some(_)) if m.digest.is_some() => "superseded",
            _ => "unknown",
        }
    }

    /// G6: job của ta không bao giờ `dead`/`reverted` chỉ vì người khác đã thực thi nó.
    async fn report_consumed(&self, w: &Work) {
        let Some(m) = &w.meta else { return };
        let kind = self.classify(m).await;
        warn!(job = ?w.job_id, from = %m.from, nonce = %m.nonce, kind, "meta-tx nonce consumed");
        if let Some(id) = w.job_id {
            self.report(id, "consumed", None, None, Some(kind.into())).await;
        }
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

    /// Việc đang chờ ghi journal được thử lại trước việc mới.
    pub async fn drain_retry(&mut self) {
        for _ in 0..self.retry.len() {
            if let Some((w, g)) = self.retry.pop_front() {
                self.send(w, g).await;
            }
        }
    }

    /// Receipt (của BẤT KỲ hash nào đã gửi ở nonce đó) → mined/reverted/consumed; kẹt → kiểm tiêu thụ (R80) rồi mới
    /// thay thế cùng nonce. Meta-tx hết hạn hoặc đã bị tiêu thụ ⇒ lấp lỗ, không bao giờ gửi lại nó.
    pub async fn track(&mut self) {
        let nonces: Vec<u64> = self.inflight.keys().copied().collect();
        for n in nonces {
            let Some(s) = self.inflight.get(&n) else { continue };
            match self.receipt_of(s.hashes.clone()).await {
                Ok(Some((h, rc))) => {
                    self.settle(n, h, rc).await;
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(nonce = n, "receipt: {e:#}");
                    continue;
                }
            }
            let Some(s) = self.inflight.get(&n) else { continue };
            if s.at.elapsed() < Duration::from_secs(self.cfg.stuck_after_secs) {
                continue;
            }
            // R80, fail closed: một lần đọc hỏng ⇒ không bump vòng này.
            let count = match self.chain.nonce_at().await {
                Ok(c) => c,
                Err(e) => {
                    warn!(nonce = n, "nonce_at: {e:#}; no bump this round");
                    continue;
                }
            };
            if count > n {
                // Nonce vỏ đã dùng bởi một tx ta không còn giữ hash (vd. bản thay thế trước khi khởi động lại).
                let s = self.inflight.remove(&n).expect("present");
                if let Some(w) = s.work.filter(|w| w.meta.is_some()) {
                    self.report_consumed(&w).await;
                }
                continue;
            }
            if let Some(w) = s.work.clone().filter(|w| w.meta.is_some()) {
                match self.consumed(&w).await {
                    Err(e) => {
                        warn!(nonce = n, "mtxNonce: {e:#}; no bump this round");
                        continue;
                    }
                    Ok(true) => {
                        BUMP_SKIPPED_CONSUMED.fetch_add(1, Ordering::Relaxed);
                        self.report_consumed(&w).await;
                        // Từ giờ nonce này chỉ còn là gap-filler: meta-tx KHÔNG bao giờ được gửi lại (G3, R18).
                        if let Some(s) = self.inflight.get_mut(&n) {
                            s.work = None;
                        }
                    }
                    Ok(false) => {}
                }
            }
            let Some(s) = self.inflight.get(&n) else { continue };
            let cap = u128::from(self.cfg.max_fee_cap_gwei) * 1_000_000_000;
            let fees = (bump(s.fees.0, cap), bump(s.fees.1, cap));
            if fees.0 <= s.fees.0 {
                // Ở trần phí: một bản thay thế cùng giá bị node từ chối (underpriced). Chờ,
                // không spam RPC; vẫn không bỏ nonce (review I10).
                warn!(nonce = n, "stuck at the fee cap; waiting");
                if let Some(s) = self.inflight.get_mut(&n) {
                    s.at = Instant::now();
                }
                continue;
            }
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
            let replaced = match self.chain.sign(n, to, data, gas, fees).await {
                Ok((raw, h)) => match self.chain.send_raw(&raw).await {
                    Ok(()) => Some(h),
                    Err(e) => {
                        warn!(nonce = n, "replace send: {e:#}");
                        None
                    }
                },
                Err(e) => {
                    warn!(nonce = n, "replace sign: {e:#}");
                    None
                }
            };
            if let Some(h) = replaced {
                if let Some(id) = live.as_ref().and_then(|w| w.job_id) {
                    self.report(id, "broadcast", Some(h), None, None).await;
                }
                info!(nonce = n, "replaced");
            }
            if let Some(s) = self.inflight.get_mut(&n) {
                // Chỉ thêm hash khi bản thay thế THỰC SỰ vào mempool (review I4); hash cũ vẫn được hỏi receipt.
                if let Some(h) = replaced {
                    s.hashes.push(h);
                    (s.work, s.gas, s.fees) = (live, gas, fees);
                }
                s.at = Instant::now();
            }
        }
    }

    /// Receipt của hash mới nhất có receipt (chỉ một tx ở một nonce vào được khối).
    async fn receipt_of(&self, hashes: Vec<B256>) -> Result<Option<(B256, TransactionReceipt)>> {
        for h in hashes.into_iter().rev() {
            if let Some(rc) = self.chain.primary().get_transaction_receipt(h).await? {
                return Ok(Some((h, rc)));
            }
        }
        Ok(None)
    }

    /// Hash `h` ở nonce `n` đã vào khối. Meta-tx revert ⇒ kiểm nonce chủ thể TRƯỚC (review H3): đã tiêu thụ ⇒
    /// `consumed`, không `reverted` (Odoo đặt `failed` và chạy `_fail_dependents`); không đọc được ⇒ giữ, vòng sau.
    async fn settle(&mut self, n: u64, h: B256, rc: TransactionReceipt) {
        let work = self.inflight.get(&n).and_then(|s| s.work.clone());
        let orphan = self.inflight.get(&n).and_then(|s| Some((s.orphan?, s.hashes.first() == Some(&h))));
        let consumed = match &work {
            Some(w) if !rc.status() => match self.consumed(w).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(nonce = n, "reverted receipt, mtxNonce unreadable; retry: {e:#}");
                    return;
                }
            },
            _ => false,
        };
        self.inflight.remove(&n);
        let paid = u128::from(rc.gas_used).saturating_mul(rc.effective_gas_price);
        if let Ok(mut k) = self.breaker.lock() {
            k.spend(now(), paid);
        }
        let Some(w) = work else {
            match orphan {
                Some((id, true)) if rc.status() => _ = self.report(id, "mined", Some(h), None, None).await,
                Some((id, true)) => _ = self.report(id, "reverted", None, None, None).await,
                Some((id, false)) => {
                    let why = "not re-signed after a restart (refused by the guard or unreadable); nonce gap-filled";
                    _ = self.report(id, "dead", None, None, Some(why.into())).await;
                }
                None => {}
            }
            return;
        };
        match (rc.status(), consumed, w.job_id) {
            (false, true, _) => self.report_consumed(&w).await,
            (true, _, Some(id)) => _ = self.report(id, "mined", Some(h), None, None).await,
            (false, false, Some(id)) => _ = self.report(id, "reverted", None, None, None).await,
            _ => {}
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
            // N2: digest đang bay ở đường khác ⇒ bỏ qua TRƯỚC claim (không claim, không báo, `attempt_count` giữ nguyên).
            if job_digest(&job).is_some_and(|d| self.digests.contains(&d)) {
                continue;
            }
            match self.odoo.relay_claim(&[job.id], &self.node_id).await {
                Ok(ids) if ids.contains(&job.id) => {}
                Ok(_) => continue,
                Err(e) => {
                    warn!("relay_claim: {e:#}");
                    continue;
                }
            }
            match work_from_job(&job, self.cfg.fee_recipient) {
                Ok(w) => self.submit(w).await,
                Err(e) => {
                    let _ = self.report(job.id, "dead", None, None, Some(format!("bad payload: {e:#}"))).await;
                }
            }
        }
    }
}

pub async fn run(mut s: Submitter, mut rx: mpsc::Receiver<Work>, poll: Duration) {
    loop {
        s.sample().await;
        // Cầu dao mở: job Odoo nằm yên `queued`, việc gateway đợi trong kênh (đầy ⇒ gateway trả 503).
        let accepting = s.accepting();
        if accepting {
            s.drain_retry().await;
            s.poll_outbox().await;
            while let Ok(w) = rx.try_recv() {
                s.submit(w).await;
            }
        }
        s.track().await;
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            Some(w) = rx.recv(), if accepting => s.submit(w).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::consensus::{Transaction as _, TxEnvelope};
    use alloy::eips::eip2718::Decodable2718;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol_types::{SolCall, SolValue};
    use serde_json::{json, Value};

    use super::*;
    use crate::abi::{IToken, MetaTransfer};
    use crate::adapter::tests::{fake_odoo, Fake, Shared};

    const D: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";
    /// The fake chain's `chain_uid`: pinned in the config (the fake serves no block 0) and answered by `chainUid()`.
    const UID: u64 = 0x24;
    const TOKEN: Address = Address::repeat_byte(0xcd);

    /// Chain EVM giả qua JSON-RPC thật (alloy nói chuyện với nó như với node thật).
    #[derive(Default)]
    struct Evm {
        /// Mô phỏng `mtxExecuteTransfer`: `None` ok, `"revert"`, `"transport"`.
        sim: Option<&'static str>,
        /// `mtxNonce`: `None` ⇒ lỗi RPC.
        mtx_nonce: Option<u64>,
        /// Số tx của lane đã vào khối (`latest` = `pending`).
        count: u64,
        receipts: HashMap<B256, bool>,
        /// (hash, to, input) mỗi lần `eth_sendRawTransaction`.
        sent: Vec<(B256, Address, Bytes)>,
        /// The gas limit of each sent tx.
        gas: Vec<u64>,
        /// `chainUid()` answers this instead of `UID` (a contract of another chain).
        uid: Option<u64>,
        /// `eth_getCode` of every address is non-empty (a contract signer).
        contract_signer: bool,
        /// `mtxSettle` settles everything only from this much gas (below: one `ok` false, an empty `MatchFailed`).
        settle_from: u64,
        /// `chainUid()`: `"revert"` (no such function) or `"transport"`.
        uid_err: Option<&'static str>,
        /// `eth_estimateGas` answers this (default 0x30000).
        estimate: Option<u64>,
        /// Only this address has code (`contract_signer` = every address).
        code_only: Option<Address>,
        /// Block 0 is the recorded Hedera testnet block, not the pinned `UID` (default: a pruned RPC).
        genesis: bool,
        /// `latest`'s `gasLimit` (default 200,000,000, the SCaaS testnet's target).
        block_gas: Option<u64>,
        /// `latest` has no `blockAccessListHash`: a chain before Amsterdam (Osaka, an L2, anvil).
        osaka: bool,
        /// `eth_getBlockByNumber latest` fails (a transport error).
        block_err: bool,
        /// `eth_getTransactionByHash` answers a transaction with this gas limit (`None`: unknown, `null`).
        tx_gas: Option<u64>,
    }
    type Rpc = Arc<Mutex<Evm>>;

    fn err(code: i64, message: &str, data: Option<String>) -> Value {
        json!({"code": code, "message": message, "data": data})
    }

    async fn fake_evm(e: Evm) -> (String, Rpc) {
        use axum::extract::State;
        use axum::Json;
        async fn h(State(s): State<Rpc>, Json(r): Json<Value>) -> Json<Value> {
            let mut e = s.lock().unwrap();
            let p = &r["params"];
            let word = |v: U256| Value::String(format!("0x{}", alloy::hex::encode(v.abi_encode())));
            let out: Result<Value, Value> = match r["method"].as_str().unwrap() {
                "eth_getTransactionCount" => Ok(json!(format!("{:#x}", e.count))),
                // Nethermind 2.2.0's estimate-stage answer for a call over 2^24 regular gas (at its 100 M RPC gas cap)
                "eth_estimateGas" if e.sim == Some("estimate_oog") => Err(err(-32000, "gas required exceeds allowance (100000000)", None)),
                "eth_estimateGas" if e.sim == Some("estimate_down") => Err(err(-32000, "upstream timeout", None)),
                "eth_estimateGas" => Ok(json!(format!("{:#x}", e.estimate.unwrap_or(0x30000)))),
                "eth_getTransactionByHash" => Ok(e.tx_gas.map_or(Value::Null, |g| json!({"gas": format!("{g:#x}")}))),
                "eth_getBlockByNumber" if p[0] == "latest" && e.block_err => Err(err(-32000, "upstream timeout", None)),
                "eth_feeHistory" => Ok(json!({"oldestBlock": "0x1", "baseFeePerGas": ["0x3b9aca00", "0x3b9aca00"],
                    "gasUsedRatio": [0.5], "reward": [["0x3b9aca00"]]})),
                "eth_blockNumber" => Ok(json!("0x10")),
                "eth_getLogs" => Ok(json!([])),
                "eth_getBalance" => Ok(json!("0xde0b6b3a7640000")),
                "eth_getBlockByNumber" if p[0] == "latest" => {
                    let mut b = json!({"number": "0x10", "gasLimit": format!("{:#x}", e.block_gas.unwrap_or(200_000_000))});
                    if !e.osaka {
                        b["blockAccessListHash"] = json!(format!("{:#x}", B256::repeat_byte(0xba)));
                    }
                    Ok(b)
                }
                "eth_getBlockByNumber" if e.genesis => {
                    Ok(serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json")).unwrap()["block"].clone())
                }
                "eth_getBlockByNumber" => Ok(Value::Null),
                "eth_getCode" => {
                    let a: Address = p[0].as_str().unwrap().parse().unwrap();
                    Ok(json!(if e.contract_signer || e.code_only == Some(a) { "0x6001" } else { "0x" }))
                }
                "eth_call" => {
                    let input = p[0]["input"].as_str().or(p[0]["data"].as_str()).unwrap();
                    let sel = alloy::hex::decode(&input[2..10]).unwrap();
                    if sel == IToken::mtxSelectorsCall::SELECTOR {
                        // the published allowlist: cancelNonce, ABSOLUTE
                        let out = IToken::mtxSelectorsCall::abi_encode_returns(&IToken::mtxSelectorsReturn {
                            selectors: vec![alloy::primitives::FixedBytes::<4>::from([0xcf, 0xdd, 0x7a, 0xea])],
                            feeClass: vec![1],
                            amountArg: vec![0],
                        });
                        Ok(json!(format!("0x{}", alloy::hex::encode(out))))
                    } else if sel == IToken::supportedModesCall::SELECTOR {
                        Ok(word(U256::from(0xF3)))
                    } else if sel == IToken::chainUidCall::SELECTOR {
                        match e.uid_err {
                            Some("revert") => Err(err(3, "execution reverted", Some("0x".into()))),
                            Some(_) => Err(err(-32000, "upstream timeout", None)),
                            None => Ok(word(U256::from(e.uid.unwrap_or(UID)))),
                        }
                    } else if sel == guard::SEL_MTX_SETTLE {
                        let gas = p[0]["gas"].as_str().map_or(u64::MAX, |g| u64::from_str_radix(&g[2..], 16).unwrap());
                        let ok = vec![true, gas >= e.settle_from];
                        Ok(json!(format!("0x{}", alloy::hex::encode(<Vec<bool> as SolValue>::abi_encode(&ok)))))
                    } else if sel == IToken::mtxTransferDigestCall::SELECTOR || sel == IToken::mtxDigestCall::SELECTOR {
                        Ok(json!(D))
                    } else if sel == IToken::mtxNonceCall::SELECTOR {
                        e.mtx_nonce.map(|n| word(U256::from(n))).ok_or_else(|| err(-32000, "upstream timeout", None))
                    } else {
                        match e.sim {
                            Some("revert") => {
                                let data = IToken::MetaTxBadNonce { expected: U256::from(1), got: U256::ZERO };
                                let data = alloy::sol_types::SolError::abi_encode(&data);
                                Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
                            }
                            Some("min_nonce") => {
                                let data = IToken::MinNonceNotIncreasing { current: U256::from(9), requested: U256::from(9) };
                                let data = alloy::sol_types::SolError::abi_encode(&data);
                                Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
                            }
                            // Nethermind 2.2.0's answer for a call over 2^24 regular gas (EIP-7825 under EIP-8037)
                            Some("oog") => Err(err(-32000, "out of gas", None)),
                            Some("estimate_oog" | "estimate_down") => Ok(word(U256::from(1))),
                            Some(_) => Err(err(-32000, "upstream timeout", None)),
                            None => Ok(word(U256::from(1))),
                        }
                    }
                }
                "eth_sendRawTransaction" => {
                    let raw = alloy::hex::decode(p[0].as_str().unwrap()).unwrap();
                    let tx = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
                    let h = *tx.tx_hash();
                    e.sent.push((h, tx.to().unwrap(), tx.input().clone()));
                    e.gas.push(tx.gas_limit());
                    Ok(json!(format!("{h:#x}")))
                }
                "eth_getTransactionReceipt" => {
                    let h: B256 = p[0].as_str().unwrap().parse().unwrap();
                    Ok(match e.receipts.get(&h) {
                        None => Value::Null,
                        Some(ok) => json!({"type": "0x2", "status": if *ok { "0x1" } else { "0x0" },
                            "cumulativeGasUsed": "0x5208", "logs": [], "logsBloom": format!("0x{}", "00".repeat(256)),
                            "transactionHash": format!("{h:#x}"), "transactionIndex": "0x0",
                            "blockHash": format!("0x{}", "11".repeat(32)), "blockNumber": "0x1", "gasUsed": "0x5208",
                            "effectiveGasPrice": "0x1", "from": format!("{:#x}", Address::ZERO),
                            "to": format!("{TOKEN:#x}"), "contractAddress": null}),
                    })
                }
                m => panic!("unexpected {m}"),
            };
            Json(match out {
                Ok(v) => json!({"jsonrpc": "2.0", "id": r["id"], "result": v}),
                Err(e) => json!({"jsonrpc": "2.0", "id": r["id"], "error": e}),
            })
        }
        let s: Rpc = Arc::new(Mutex::new(e));
        let app = axum::Router::new().route("/", axum::routing::post(h)).with_state(s.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, s)
    }

    fn meta(batch: u64) -> Mtx {
        Mtx::Transfer(MetaTransfer {
            from: Address::repeat_byte(0xab),
            to: Address::repeat_byte(0x5e),
            value: U256::from(1_000u64),
            entryRef: B256::repeat_byte(0x42),
            batch: U256::from(batch),
            nonce: U256::ZERO,
            validUntil: U256::from(now() + 600),
            mode: 0,
            relayer: Address::ZERO,
            fee: U256::ZERO,
            feeRecipient: Address::ZERO,
        })
    }

    /// The fake client's registered tokens: `TOKEN`.
    fn toks() -> Value {
        json!([{"address": format!("{TOKEN:#x}"), "decimals": 6}])
    }

    fn job(id: i64) -> Value {
        let (kind, wire) = meta(7).to_wire();
        json!({"id": id, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
               "signature": format!("0x{}", "11".repeat(65)), "metatx": wire})
    }

    async fn lane(rpc: &str, odoo: crate::odoo::Odoo, key: u8, set: InflightSet) -> Submitter {
        lane_with(rpc, odoo, key, set, None).await
    }

    async fn lane_with(rpc: &str, odoo: crate::odoo::Odoo, key: u8, set: InflightSet, dex: Option<Address>) -> Submitter {
        lane_cfg(rpc, odoo, key, set, |c| c.dex = dex).await.unwrap()
    }

    fn test_cfg(rpc: &str) -> ChainCfg {
        ChainCfg {
            family: "evm".into(),
            evm_chain_number: 31337,
            rpc_urls: vec![rpc.into()],
            stuck_after_secs: 0,
            max_gas_per_tx: 3_000_000,
            max_fee_cap_gwei: 500,
            chain_uid: Some(B256::from(U256::from(UID))),
            ..Default::default()
        }
    }

    async fn lane_cfg(rpc: &str, odoo: crate::odoo::Odoo, key: u8, set: InflightSet, tweak: impl FnOnce(&mut ChainCfg))
        -> Result<Submitter>
    {
        let mut cfg = test_cfg(rpc);
        tweak(&mut cfg);
        let signer = PrivateKeySigner::from_bytes(&B256::repeat_byte(key)).unwrap();
        Submitter::start(Chain::with_signer(&cfg, signer).unwrap(), odoo, cfg, format!("t#{key}"), set).await
    }

    /// Một lane đã gửi job 7 (`signed`, `broadcast`).
    async fn sent_one(e: Evm) -> (Submitter, Rpc, Shared, InflightSet) {
        let (url, rpc) = fake_evm(e).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: toks(), ..Default::default() }).await;
        let set = InflightSet::default();
        let mut s = lane(&url, odoo, 1, set.clone()).await;
        s.poll_outbox().await;
        assert_eq!(states(&o), ["signed", "broadcast"]);
        (s, rpc, o, set)
    }

    fn states(o: &Shared) -> Vec<String> {
        o.lock().unwrap().reports.iter().map(|r| r["chain_state"].as_str().unwrap().to_string()).collect()
    }

    /// R80: kẹt mà nonce chủ thể đã bị dùng ⇒ `consumed`, nonce vỏ lấp bằng gap-filler, meta-tx KHÔNG bao giờ gửi lại.
    #[tokio::test]
    async fn consumed_before_bump_gap_fills_and_never_resends_the_metatx() {
        let (mut s, rpc, o, set) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        rpc.lock().unwrap().mtx_nonce = Some(1);
        let before = BUMP_SKIPPED_CONSUMED.load(Ordering::Relaxed);
        s.track().await;
        s.track().await;
        assert!(BUMP_SKIPPED_CONSUMED.load(Ordering::Relaxed) > before);
        let me = s.address();
        let sent = rpc.lock().unwrap().sent.clone();
        assert_eq!(sent.len(), 3, "meta-tx, then two gap-filler bumps");
        assert!(sent[1..].iter().all(|(_, to, input)| *to == me && input.is_empty()), "only gap-fillers after consumption");
        assert_eq!(states(&o), ["signed", "broadcast", "consumed"]);
        rpc.lock().unwrap().receipts.insert(sent[2].0, true);
        s.track().await;
        assert_eq!(s.inflight_count(), 0);
        assert_eq!(states(&o), ["signed", "broadcast", "consumed"], "the gap-filler's receipt reports nothing");
        assert!(!set.contains(&D.parse().unwrap()));
    }

    /// R80 fail closed: `mtxNonce` không đọc được ⇒ không bump vòng này.
    #[tokio::test]
    async fn unreadable_mtx_nonce_means_no_bump() {
        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        rpc.lock().unwrap().mtx_nonce = None;
        s.track().await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 1);
        assert_eq!(states(&o), ["signed", "broadcast"]);
    }

    /// `Sent.hashes`: bản đã bị thay thế mà vào khối vẫn được nhận ra (trước đây bị thử lại mãi).
    #[tokio::test]
    async fn an_earlier_replaced_hash_that_mines_settles_the_nonce() {
        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        s.track().await;
        let sent = rpc.lock().unwrap().sent.clone();
        assert_eq!((sent.len(), &sent[1].2), (2, &sent[0].2), "live and unconsumed ⇒ the meta-tx is bumped");
        rpc.lock().unwrap().receipts.insert(sent[0].0, true);
        s.track().await;
        assert_eq!(s.inflight_count(), 0);
        let last = o.lock().unwrap().reports.last().cloned().unwrap();
        assert_eq!((last["chain_state"].as_str(), last["tx_hash"].as_str()), (Some("mined"), Some(format!("{:#x}", sent[0].0).as_str())));
    }

    /// Review H3: tx của ta revert vì người khác đã dùng nonce ⇒ `consumed`, không `reverted`. Đọc nonce hỏng ⇒ giữ, thử lại.
    #[tokio::test]
    async fn a_reverted_receipt_of_a_consumed_metatx_reports_consumed() {
        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let h = rpc.lock().unwrap().sent[0].0;
        rpc.lock().unwrap().receipts.insert(h, false);
        rpc.lock().unwrap().mtx_nonce = None;
        s.track().await;
        assert_eq!((s.inflight_count(), states(&o).len()), (1, 2), "unreadable ⇒ kept, nothing reported");
        rpc.lock().unwrap().mtx_nonce = Some(1);
        s.track().await;
        assert_eq!(states(&o), ["signed", "broadcast", "consumed"]);
        let (mut s, rpc, o, _) = sent_one(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let h = rpc.lock().unwrap().sent[0].0;
        rpc.lock().unwrap().receipts.insert(h, false);
        s.track().await;
        assert_eq!(states(&o), ["signed", "broadcast", "reverted"], "not consumed ⇒ still reverted");
    }

    /// R80: mô phỏng revert ⇒ `consumed` nếu nonce chủ thể đã qua, `dead` nếu không, `queued` nếu không đọc được.
    #[tokio::test]
    async fn simulation_revert_is_classified_by_the_subject_nonce() {
        for (nonce, want) in [(Some(1), "consumed"), (Some(0), "dead"), (None, "queued")] {
            let (url, _) = fake_evm(Evm { sim: Some("revert"), mtx_nonce: nonce, ..Default::default() }).await;
            let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: toks(), ..Default::default() }).await;
            lane(&url, odoo, 1, InflightSet::default()).await.poll_outbox().await;
            assert_eq!(states(&o), [want], "mtxNonce {nonce:?}");
        }
    }

    /// PAY-FIX2 / NODE-GW-07 / MT-8, wired into the submitter: refusals come before any simulation or signature.
    #[tokio::test]
    async fn the_guard_runs_before_simulation_and_signing() {
        let run = |e: Evm, jobs: Vec<Value>, dex: Option<Address>| async move {
            let (url, rpc) = fake_evm(e).await;
            let (odoo, o) = fake_odoo(Fake { jobs, tokens: json!([{"address": format!("{TOKEN:#x}"), "decimals": 6}]), ..Default::default() }).await;
            lane_with(&url, odoo, 1, InflightSet::default(), dex).await.poll_outbox().await;
            let last = o.lock().unwrap().reports.last().cloned().unwrap();
            let sent = rpc.lock().unwrap().sent.len();
            (last["chain_state"].as_str().unwrap().to_string(), last["error"].as_str().unwrap_or_default().to_string(), sent, rpc)
        };
        let call = |target: Address, data: Vec<u8>| json!({"id": 9, "kind": "call", "call": {"target": format!("{target:#x}"),
            "calldata": format!("0x{}", alloy::hex::encode(data)), "validUntil": (now() + 300).to_string()}});
        // a lane's own token balance never leaves through a `call` job
        let steal = IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1) }.abi_encode();
        let (st, err, sent, _) = run(Evm { mtx_nonce: Some(0), ..Default::default() }, vec![call(TOKEN, steal)], None).await;
        assert_eq!((st.as_str(), sent), ("dead", 0));
        assert!(err.starts_with("CALL_TARGET_REFUSED"), "{err}");
        // a call-table row on a target it does not name: `mtxSettle` on a registered token
        let settle = [&guard::SEL_MTX_SETTLE[..], &[0u8; 32]].concat();
        let (st, err, ..) = run(Evm::default(), vec![call(TOKEN, settle.clone())], Some(TOKEN)).await;
        assert_eq!(st, "dead");
        assert!(err.starts_with("CALL_TARGET_REFUSED"), "{err}");
        // a meta-transaction on a contract of another chain
        let (st, err, sent, _) = run(Evm { uid: Some(0x25), mtx_nonce: Some(0), ..Default::default() }, vec![job(7)], None).await;
        assert_eq!((st.as_str(), sent), ("dead", 0));
        assert!(err.starts_with("CHAIN_UID_MISMATCH"), "{err}");
        // an order entry on a contract of another chain
        let inv_on = |token: Address| json!({"id": 8, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": format!("{token:#x}"),
            "from": format!("{:#x}", Address::repeat_byte(0xab)), "batch": "1", "newMin": "9",
            "signature": format!("0x{}", "11".repeat(65)), "validUntil": (now() + 300).to_string()});
        let (st, err, sent, _) = run(Evm { uid: Some(0x25), ..Default::default() }, vec![inv_on(TOKEN)], None).await;
        assert_eq!((st.as_str(), sent), ("dead", 0));
        assert!(err.starts_with("CHAIN_UID_MISMATCH"), "{err}");
        // a self-call outside the token's published allowlist (NODE-JOB-20); on it, it goes
        let self_call = |data: &str| {
            let m = Mtx::Call(crate::abi::MetaTransaction { from: Address::repeat_byte(0xab), data: alloy::hex::decode(data).unwrap().into(),
                batch: U256::from(7), nonce: U256::ZERO, validUntil: U256::from(now() + 600), mode: 0, relayer: Address::ZERO,
                fee: U256::ZERO, feeRecipient: Address::ZERO });
            let (kind, wire) = m.to_wire();
            json!({"id": 7, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
                   "signature": format!("0x{}", "11".repeat(65)), "metatx": wire})
        };
        let (st, err, sent, _) = run(Evm { mtx_nonce: Some(0), ..Default::default() }, vec![self_call("12345678")], None).await;
        assert_eq!((st.as_str(), sent), ("dead", 0));
        assert!(err.starts_with("SELECTOR_NOT_ALLOWED"), "{err}");
        let cancel = format!("cfdd7aea{}", "00".repeat(32));
        let (st, err, sent, _) = run(Evm { mtx_nonce: Some(0), ..Default::default() }, vec![self_call(&cancel)], None).await;
        assert_eq!((st.as_str(), sent), ("broadcast", 1), "{err}");
        // an invalidation already in force is done, never dead
        let inv = json!({"id": 8, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": format!("{TOKEN:#x}"),
            "from": format!("{:#x}", Address::repeat_byte(0xab)), "batch": "1", "newMin": "9",
            "signature": format!("0x{}", "11".repeat(65)), "validUntil": (now() + 300).to_string()});
        let (st, err, sent, _) = run(Evm { sim: Some("min_nonce"), ..Default::default() }, vec![inv], None).await;
        assert_eq!((st.as_str(), err.as_str(), sent), ("consumed", "already_invalidated", 0));
        // mtxSettle on the chain's DEX: gas raised until every settlement settles (an empty MatchFailed is gas)
        let dex = Address::repeat_byte(0xd0);
        let (st, _, sent, rpc) = run(Evm { settle_from: 300_000, ..Default::default() }, vec![call(dex, settle)], Some(dex)).await;
        assert_eq!((st.as_str(), sent), ("broadcast", 1));
        let g = rpc.lock().unwrap().gas[0];
        assert!(g >= 300_000 && g == 0x30000 * 6 / 5 * 3 / 2, "estimate +20 %, then ×1.5 once: {g}");
        // a contract signer's meta-tx gets the ERC-1271 floor
        let (st, _, _, rpc) = run(Evm { mtx_nonce: Some(0), contract_signer: true, ..Default::default() }, vec![job(7)], None).await;
        assert_eq!(st, "broadcast");
        assert_eq!(rpc.lock().unwrap().gas[0], guard::ERC1271_FLOOR);
    }

    /// The token's order entries as `metatx` jobs (job-api.md): byte-identical with the forge KAT's relayed calldata.
    #[test]
    fn entry_jobs_encode_as_the_token_reads_them() {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/trade_kat.json");
        let k: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let s = |f: &str| k[f].as_str().unwrap().to_string();
        let o = <crate::abi::TradeOrder as SolValue>::abi_decode(&alloy::hex::decode(&s("order_abi")[2..]).unwrap()).unwrap();
        let token = s("verifying_contract");
        let job = |v: Value| -> crate::odoo::Job { serde_json::from_value(v).unwrap() };
        let cancel = job(json!({"id": 1, "kind": "metatx", "entry": "mtxCancelOrder", "token": token,
            "order": crate::dex::WireOrder::from_sol(&o), "signature": s("cancel_signature"), "validUntil": "1800000300"}));
        let w = work_from_job(&cancel, None).unwrap();
        assert_eq!((format!("0x{}", alloy::hex::encode(&w.data)), w.valid_until, w.meta), (s("cancel_calldata").to_lowercase(), 1_800_000_300, None));
        let inv = job(json!({"id": 2, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": token,
            "from": s("signer").to_lowercase(), "batch": s("invalidate_batch"), "newMin": s("invalidate_min_nonce"),
            "signature": s("invalidate_signature"), "validUntil": "1800000300"}));
        assert_eq!(format!("0x{}", alloy::hex::encode(&work_from_job(&inv, None).unwrap().data)), s("invalidate_calldata").to_lowercase());
        let wrap = job(json!({"id": 3, "kind": "metatx", "entry": "mtxWrap", "token": token, "underlying": format!("{:#x}", TOKEN),
            "order": crate::dex::WireOrder::from_sol(&o), "signature": s("order_signature")}));
        let w = work_from_job(&wrap, None).unwrap();
        assert_eq!((&w.data[..4], w.valid_until), (&[0x3e, 0xd1, 0x8b, 0xa8][..], o.validUntil.saturating_to()));
        for bad in [json!({"id": 4, "kind": "metatx", "entry": "mtxTrade", "token": token, "signature": "0x00"}),
                    json!({"id": 5, "kind": "metatx", "entry": "mtxCancelOrder", "token": token, "signature": "0x00", "validUntil": "1"}),
                    json!({"id": 6, "kind": "metatx", "entry": "mtxCancelOrder", "token": token, "signature": "0x00",
                           "order": crate::dex::WireOrder::from_sol(&o)})] {
            assert!(work_from_job(&job(bad), None).is_err(), "mtxTrade is never a job; an order and a deadline are needed");
        }
    }

    /// Review H6/N2: cùng digest từ gateway (lane A) và outbox (lane B) ⇒ một chữ ký; job outbox bỏ qua trước claim.
    /// Lỗi tạm thời nhả digest ngay (không ai bị chặn tới hết hạn).
    #[tokio::test]
    async fn one_digest_is_signed_once_across_lanes_and_released_on_transient_errors() {
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: toks(), ..Default::default() }).await;
        let set = InflightSet::default();
        let mut a = lane(&url, odoo.clone(), 1, set.clone()).await;
        let mut b = lane(&url, odoo, 2, set.clone()).await;
        let mut w = work_from_job(&serde_json::from_value(job(0)).unwrap(), None).unwrap();
        w.job_id = None; // gateway: `post_metatx` read the digest from the token
        w.meta = w.meta.map(|m| MetaRef { digest: Some(D.parse().unwrap()), ..m });
        a.submit(w.clone()).await;
        b.poll_outbox().await;
        a.submit(w).await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 1);
        let claims = o.lock().unwrap().claims;
        assert_eq!((claims, states(&o).len()), (0, 0), "skipped before relay_claim");

        let (url, _) = fake_evm(Evm { sim: Some("transport"), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job(8)], tokens: toks(), ..Default::default() }).await;
        let set = InflightSet::default();
        lane(&url, odoo, 1, set.clone()).await.poll_outbox().await;
        assert_eq!(states(&o), ["queued"]);
        assert!(!set.contains(&D.parse().unwrap()));
    }

    /// NODE-LANE-10 for every origin (review T2 I1): an outbox job's unbound `feeRecipient`/`relayer` never reach the
    /// chain as the job carries them; receiver-pays is refused, not dropped (m5); the in-flight key is the token's
    /// digest, never the job's `digest` (m6).
    #[tokio::test]
    async fn outbox_jobs_are_normalized_and_keyed_by_the_token_digest() {
        let (thief, ours) = (Address::repeat_byte(0x7e), Address::repeat_byte(0x99));
        let Mtx::Transfer(mut t) = meta(7) else { unreachable!() };
        (t.mode, t.fee, t.feeRecipient, t.relayer) = (0x20, U256::from(1_000u64), thief, thief); // FIXED fee, nothing bound
        let raw = |t: &MetaTransfer| {
            let (kind, wire) = Mtx::Transfer(t.clone()).to_wire();
            json!({"id": 1, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": format!("0x{}", "99".repeat(32)), "struct": kind,
                   "signature": format!("0x{}", "11".repeat(65)), "metatx": wire})
        };
        let sent = |v: Value, fr: Option<Address>| {
            let w = work_from_job(&serde_json::from_value(v).unwrap(), fr).unwrap();
            assert_eq!(w.meta.unwrap().digest, None, "never the job's digest");
            Mtx::from_calldata(&w.data).unwrap().0
        };
        let m = sent(raw(&t), Some(ours));
        assert_eq!((m.fee_recipient(), m.relayer()), (ours, Address::ZERO));
        let m = sent(raw(&t), None);
        assert_eq!((m.fee_recipient(), m.relayer()), (Address::ZERO, Address::ZERO), "unset: the contract pays msg.sender");
        let bound = MetaTransfer { mode: 0x23, ..t.clone() };
        assert_eq!(sent(raw(&bound), Some(ours)), Mtx::Transfer(bound.clone()), "bound fields are the signer's");
        let mut rf = raw(&t);
        rf["receiver_fee"] = json!({"fee": "1", "feeRecipient": format!("{thief:#x}"), "validUntil": "1", "signature": "0x"});
        assert!(work_from_job(&serde_json::from_value(rf).unwrap(), None).is_err(), "receiver-pays is not built");
        // through the lane: normalized on chain, keyed by `mtxTransferDigest` (the fake answers D)
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![raw(&t)], tokens: toks(), ..Default::default() }).await;
        let set = InflightSet::default();
        let mut s = lane(&url, odoo, 1, set.clone()).await;
        s.poll_outbox().await;
        assert_eq!(states(&o), ["signed", "broadcast"]);
        assert!(set.contains(&D.parse().unwrap()), "held while in flight");
        assert!(!set.contains(&B256::repeat_byte(0x99)), "the job's own digest is no key");
        let m = Mtx::from_calldata(&rpc.lock().unwrap().sent[0].2).unwrap().0;
        assert_eq!((m.fee_recipient(), m.relayer()), (Address::ZERO, Address::ZERO));
    }

    /// Every report of one poll on a lane built with `tweak`, and the fake chain.
    async fn outcomes(e: Evm, jobs: Vec<Value>, tweak: impl FnOnce(&mut ChainCfg)) -> (Vec<(String, String)>, Rpc) {
        let (url, rpc) = fake_evm(e).await;
        let (odoo, o) = fake_odoo(Fake { jobs, tokens: toks(), ..Default::default() }).await;
        lane_cfg(&url, odoo, 1, InflightSet::default(), tweak).await.unwrap().poll_outbox().await;
        let r = o.lock().unwrap().reports.iter()
            .map(|r| (r["chain_state"].as_str().unwrap().to_string(), r["error"].as_str().unwrap_or_default().to_string()))
            .collect();
        (r, rpc)
    }

    fn call_job(id: i64, target: Address, data: Vec<u8>) -> Value {
        json!({"id": id, "kind": "call", "call": {"target": format!("{target:#x}"),
               "calldata": format!("0x{}", alloy::hex::encode(data)), "validUntil": (now() + 300).to_string()}})
    }

    fn states_of(r: &[(String, String)]) -> Vec<&str> {
        r.iter().map(|x| x.0.as_str()).collect()
    }

    /// Review T4 I1 (the reviewer's PoC `poc_unregistered_targets_are_relayed`, inverted): a transfer meta-tx or an
    /// order entry on a contract outside the registered tokens is never relayed, however it answers `chainUid()`.
    #[tokio::test]
    async fn unregistered_targets_are_refused() {
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: json!([]), ..Default::default() }).await;
        lane(&url, odoo, 1, InflightSet::default()).await.poll_outbox().await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 0);
        assert_eq!(states(&o), ["dead"]);
        let other = Address::repeat_byte(0x99);
        let inv = json!({"id": 8, "kind": "metatx", "entry": "mtxInvalidateNonces", "token": format!("{other:#x}"),
            "from": format!("{:#x}", Address::repeat_byte(0xab)), "batch": "1", "newMin": "9",
            "signature": format!("0x{}", "11".repeat(65)), "validUntil": (now() + 300).to_string()});
        let (r, rpc) = outcomes(Evm::default(), vec![inv], |_| {}).await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 0);
        assert!(r[0].0 == "dead" && r[0].1.starts_with("TOKEN_NOT_SERVED"), "{r:?}");
    }

    /// Review T4 I3: the guard's chain facts — binding (mismatch never cached, a revert or no `chainUid()` unbound, a
    /// transport error transient), the factories and the DEX list by address, the gas bounds and the 1271 floor's
    /// signer — each pinned on the lane.
    #[tokio::test]
    async fn the_guard_derives_its_facts_from_the_chain_and_the_config() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        // two jobs to a contract of another chain: both refused (a mismatch is never cached as bound)
        let mut j8 = job(8);
        j8["metatx"]["batch"] = json!("8");
        let (r, rpc) = outcomes(Evm { uid: Some(0x25), ..ok() }, vec![job(7), j8], |_| {}).await;
        assert_eq!((states_of(&r), rpc.lock().unwrap().sent.len()), (vec!["dead", "dead"], 0), "{r:?}");
        // no `chainUid()` (it reverts): not bound
        let (r, _) = outcomes(Evm { uid_err: Some("revert"), ..ok() }, vec![job(7)], |_| {}).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("CHAIN_UID_MISMATCH"), "{r:?}");
        // an unreadable chain is transient: queued, never dead
        let (r, _) = outcomes(Evm { uid_err: Some("transport"), ..ok() }, vec![job(7)], |_| {}).await;
        assert_eq!(states_of(&r), ["queued"], "{r:?}");
        // the factories and the DEX are known by address, never assumed
        let (x, af, tf, dex) = (Address::repeat_byte(0x31), Address::repeat_byte(0x32), Address::repeat_byte(0x33), Address::repeat_byte(0x34));
        let cfg = move |c: &mut ChainCfg| {
            (c.account_factory, c.token_factory, c.dex) = (Some(af), Some(tf), Some(dex));
        };
        let deploy = [&[0x45, 0x9b, 0x5b, 0x50][..], &[0u8; 32]].concat();
        let as_owner = [&[0xfd, 0xf2, 0xd3, 0x38][..], &[0u8; 32]].concat();
        let settle = [&guard::SEL_MTX_SETTLE[..], &[0u8; 32]].concat();
        for (target, data, want) in [(x, &deploy, "dead"), (af, &deploy, "broadcast"), (x, &settle, "dead"),
                                     (dex, &settle, "broadcast"), (tf, &as_owner, "dead"), (x, &as_owner, "broadcast")] {
            let (r, _) = outcomes(ok(), vec![call_job(9, target, data.clone())], cfg).await;
            assert_eq!(r.last().unwrap().0, want, "{target:#x} 0x{}: {r:?}", alloy::hex::encode(&data[..4]));
        }
        // gas: an estimate above max_gas_per_tx is refused
        let (r, _) = outcomes(Evm { estimate: Some(3_000_001), ..ok() }, vec![job(7)], |_| {}).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("above max_gas_per_tx"), "{r:?}");
        // the first settle try never passes max
        let (r, rpc) = outcomes(ok(), vec![call_job(9, dex, settle.clone())], move |c| { cfg(c); c.max_gas_per_tx = 200_000; }).await;
        assert_eq!((states_of(&r).last().copied(), rpc.lock().unwrap().gas.clone()), (Some("broadcast"), vec![200_000]));
        // Amsterdam: a settlement may take more than 2^24 (state gas on top of the regular 2^24) up to max_gas_per_tx ...
        let (r, rpc) = outcomes(Evm { settle_from: guard::MAX_TX_GAS + 1, ..ok() }, vec![call_job(9, dex, settle.clone())],
            move |c| { cfg(c); c.max_gas_per_tx = 1 << 25; }).await;
        assert_eq!(states_of(&r).last().copied(), Some("broadcast"), "{r:?}");
        assert!(rpc.lock().unwrap().gas[0] > guard::MAX_TX_GAS);
        // ... but never past the chain's block gas limit, read from the chain
        let (r, rpc) = outcomes(Evm { settle_from: guard::MAX_TX_GAS + 1, block_gas: Some(guard::MAX_TX_GAS), ..ok() },
            vec![call_job(9, dex, settle)], move |c| { cfg(c); c.max_gas_per_tx = 1 << 25; }).await;
        assert_eq!((r[0].0.as_str(), rpc.lock().unwrap().sent.len()), ("dead", 0), "{r:?}");
        // the 1271 floor follows the signer, not the target
        let (_, rpc) = outcomes(Evm { code_only: Some(TOKEN), ..ok() }, vec![job(7)], |_| {}).await;
        assert_eq!(rpc.lock().unwrap().gas, vec![0x30000 * 6 / 5], "an EOA signer on a contract token");
        let (_, rpc) = outcomes(Evm { code_only: Some(Address::repeat_byte(0xab)), ..ok() }, vec![job(7)], |_| {}).await;
        assert_eq!(rpc.lock().unwrap().gas, vec![guard::ERC1271_FLOOR]);
    }

    /// The Amsterdam gas model (EIP-7825 + EIP-8037): regular gas ≤ 2^24, the gas limit (regular + state) bounded by
    /// `max_gas_per_tx` and the chain's block gas limit, never by 2^24.
    #[tokio::test]
    async fn gas_follows_the_two_dimensional_model() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let cap = |c: &mut ChainCfg| c.max_gas_per_tx = 64_000_000;
        // regular ≤ 2^24, total > 2^24: the largest Zether edge cell measured under Amsterdam needs 31.2 M in total
        // (F185, ZetherGasLimit test_edge_*); accepted, its limit is the estimate + 20 %, past 2^24
        let (r, rpc) = outcomes(Evm { estimate: Some(31_200_000), ..ok() }, vec![job(7)], cap).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        assert_eq!(rpc.lock().unwrap().gas, vec![37_440_000]);
        // the block gas limit binds before max_gas_per_tx (a smaller chain, or the ramp after a reset)
        let (r, rpc) = outcomes(Evm { estimate: Some(31_200_000), block_gas: Some(30_000_000), ..ok() }, vec![job(7)], cap).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("above the chain's block gas limit 30000000"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        // the padded limit stops at the block gas limit, never below the estimate
        let (_, rpc) = outcomes(Evm { estimate: Some(31_200_000), block_gas: Some(32_000_000), ..ok() }, vec![job(7)], cap).await;
        assert_eq!(rpc.lock().unwrap().gas, vec![32_000_000]);
        // regular over 2^24 (1): the chain's simulation fails "out of gas" at its gas cap: refused, never requeued
        let (r, rpc) = outcomes(Evm { sim: Some("oog"), ..ok() }, vec![job(7)], cap).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("2^24 regular gas"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        // regular over 2^24 (2): a calldata floor over 2^24 (261,910 B: 15,000 + 64 · 261,910 > 2^24) is refused before
        // any simulation; 261,909 B still goes
        let af = Address::repeat_byte(0x32);
        let deploy = |n: usize| [&[0x45, 0x9b, 0x5b, 0x50][..], &vec![0u8; n - 4]].concat();
        let fac = move |c: &mut ChainCfg| { c.max_gas_per_tx = 64_000_000; c.account_factory = Some(af); };
        let (r, rpc) = outcomes(ok(), vec![call_job(9, af, deploy(261_910))], fac).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("calldata floor 16777240 above the 2^24 regular gas"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = outcomes(ok(), vec![call_job(9, af, deploy(261_909))], fac).await;
        assert_eq!(states_of(&r).last().copied(), Some("broadcast"), "{r:?}");
    }

    /// Review amsterdam-node M1, M2, L5: the fork is read per chain from its `latest` header; before Amsterdam (no
    /// `blockAccessListHash`: Osaka, an L2, anvil) the whole gas limit stays under 2^24 and there is no 64 gas/byte
    /// floor; the estimate-stage "gas required exceeds allowance" is a refusal; an unreadable block, or any other
    /// simulation error, is transient.
    #[tokio::test]
    async fn gas_follows_each_chains_fork_and_tells_refusals_from_transport() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let cap = |c: &mut ChainCfg| c.max_gas_per_tx = 64_000_000;
        // Osaka: an estimate over 2^24 is refused, a large one under it is padded to 2^24 at most
        let (r, rpc) = outcomes(Evm { estimate: Some(31_200_000), osaka: true, ..ok() }, vec![job(7)], cap).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("above the 2^24 gas limit of a transaction"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, rpc) = outcomes(Evm { estimate: Some(15_000_000), osaka: true, ..ok() }, vec![job(7)], cap).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        assert_eq!(rpc.lock().unwrap().gas, vec![guard::MAX_TX_GAS], "clamped to 2^24 before Amsterdam");
        // Amsterdam: the same estimate goes past 2^24
        let (_, rpc) = outcomes(Evm { estimate: Some(15_000_000), ..ok() }, vec![job(7)], cap).await;
        assert_eq!(rpc.lock().unwrap().gas, vec![18_000_000]);
        // Osaka: no Amsterdam calldata floor (261,910 B is not refused by the node; the chain's own rules apply)
        let af = Address::repeat_byte(0x32);
        let big = [&[0x45, 0x9b, 0x5b, 0x50][..], &vec![0u8; 261_906]].concat();
        let fac = move |c: &mut ChainCfg| { c.max_gas_per_tx = 64_000_000; c.account_factory = Some(af); };
        let (r, _) = outcomes(Evm { osaka: true, ..ok() }, vec![call_job(9, af, big)], fac).await;
        assert_eq!(states_of(&r).last().copied(), Some("broadcast"), "{r:?}");
        // the estimate stage refuses (regular gas over 2^24 at the RPC's gas cap): dead, nothing sent
        let (r, rpc) = outcomes(Evm { sim: Some("estimate_oog"), ..ok() }, vec![job(7)], cap).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("gas required exceeds allowance"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        // any other estimate error stays transient (classify_sim leaves it a transport error): queued, never dead
        let (r, _) = outcomes(Evm { sim: Some("estimate_down"), ..ok() }, vec![job(7)], cap).await;
        assert_eq!(states_of(&r), ["queued"], "{r:?}");
        // an unreadable block gas limit is transient too
        let (r, rpc) = outcomes(Evm { block_err: true, ..ok() }, vec![job(7)], cap).await;
        assert_eq!(states_of(&r), ["queued"], "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
    }

    /// NODE-GW-07: a lane whose RPC block 0 is not the pinned chain_uid never starts (review T4 I3).
    #[tokio::test]
    async fn a_lane_never_starts_on_a_chain_whose_block_zero_is_not_the_pin() {
        let (url, _) = fake_evm(Evm { genesis: true, ..Default::default() }).await;
        let (odoo, _) = fake_odoo(Fake { tokens: toks(), ..Default::default() }).await;
        assert!(lane_cfg(&url, odoo, 1, InflightSet::default(), |_| {}).await.is_err());
    }

    /// The adapter path (Hedera and the generic runner) runs the same guard before simulating (review T4 I3).
    #[tokio::test]
    async fn the_adapter_path_runs_the_guard() {
        use crate::adapter::ChainAdapter;
        let (url, _) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let cfg = test_cfg(&url);
        let chain = Chain::with_signer(&cfg, PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap()).unwrap();
        let a = crate::adapters::evm::EvmAdapter::new(&cfg, vec![chain], Arc::new(std::sync::RwLock::new(vec![TOKEN]))).unwrap();
        let steal = IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1) }.abi_encode();
        let j: Job = serde_json::from_value(call_job(9, TOKEN, steal)).unwrap();
        assert!(matches!(a.build(&j, 0).await, Err(SimError::Revert(r)) if r.starts_with("CALL_TARGET_REFUSED")));
        let j: Job = serde_json::from_value(job(7)).unwrap();
        assert!(a.build(&j, 0).await.is_ok(), "a registered token's transfer builds");
    }

    /// Review T4 m1/m2: the registered tokens follow the client; a job rebuilt after a restart passes the guard (a
    /// refused one is only gap-filled) and is tracked with its original transaction's gas limit (review M3); only when
    /// the RPC does not know it, with `max_gas_per_tx` clamped by the block gas limit (Amsterdam: no longer 2^24); an
    /// unreadable block then fails the start (review L5).
    #[tokio::test]
    async fn tokens_refresh_and_rebuilt_jobs_pass_the_guard() {
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { tokens: json!([]), ..Default::default() }).await;
        let mut s = lane(&url, odoo, 1, InflightSet::default()).await;
        o.lock().unwrap().tokens = toks();
        s.sample().await;
        o.lock().unwrap().jobs = vec![job(7)];
        s.poll_outbox().await;
        assert_eq!((states(&o), rpc.lock().unwrap().sent.len()), (vec!["signed".to_string(), "broadcast".into()], 1));
        let tracked = |payload: Value| json!([{"job_id": 7, "nonce": 0, "state": "broadcast",
            "tx_hash": format!("{:#x}", B256::repeat_byte(0x77)), "payload": payload}]);
        let (url, _) = fake_evm(Evm { mtx_nonce: Some(0), count: 1, ..Default::default() }).await;
        for (toks, kept) in [(toks(), true), (json!([]), false)] {
            let (odoo, _) = fake_odoo(Fake { tokens: toks, inflight: tracked(job(7)), ..Default::default() }).await;
            let s = lane_cfg(&url, odoo, 1, InflightSet::default(), |c| c.max_gas_per_tx = 1 << 30).await.unwrap();
            let sent = s.inflight.get(&0).expect("tracked");
            assert_eq!((sent.work.is_some(), sent.gas), (kept, 200_000_000), "the block gas limit binds");
        }
        // the original transaction's gas limit when the RPC knows it
        let (url, _) = fake_evm(Evm { mtx_nonce: Some(0), count: 1, tx_gas: Some(0x5_5555), ..Default::default() }).await;
        let (odoo, _) = fake_odoo(Fake { tokens: toks(), inflight: tracked(job(7)), ..Default::default() }).await;
        let s = lane_cfg(&url, odoo, 1, InflightSet::default(), |c| c.max_gas_per_tx = 1 << 30).await.unwrap();
        assert_eq!(s.inflight.get(&0).expect("tracked").gas, 0x5_5555);
        // before Amsterdam the fallback stays under 2^24
        let (url, _) = fake_evm(Evm { mtx_nonce: Some(0), count: 1, osaka: true, ..Default::default() }).await;
        let (odoo, _) = fake_odoo(Fake { tokens: toks(), inflight: tracked(job(7)), ..Default::default() }).await;
        let s = lane_cfg(&url, odoo, 1, InflightSet::default(), |c| c.max_gas_per_tx = 1 << 30).await.unwrap();
        assert_eq!(s.inflight.get(&0).expect("tracked").gas, guard::MAX_TX_GAS);
        // no original gas and no block: the lane does not start (retried like any start-up RPC failure)
        let (url, _) = fake_evm(Evm { mtx_nonce: Some(0), count: 1, block_err: true, ..Default::default() }).await;
        let (odoo, _) = fake_odoo(Fake { tokens: toks(), inflight: tracked(job(7)), ..Default::default() }).await;
        assert!(lane_cfg(&url, odoo, 1, InflightSet::default(), |_| {}).await.is_err());
    }

    /// Review P5 m7: a job tracked after a restart and refused by the guard is still reported: `mined` when its own
    /// transaction lands, `dead` when the gap-fill takes its nonce.
    #[tokio::test]
    async fn a_refused_rebuilt_job_is_reported_from_its_hash_or_the_gap_fill() {
        let tracked = json!([{"job_id": 7, "nonce": 0, "state": "broadcast",
            "tx_hash": format!("{:#x}", B256::repeat_byte(0x77)), "payload": job(7)}]);
        for original in [true, false] {
            let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), count: 1, ..Default::default() }).await;
            let (odoo, o) = fake_odoo(Fake { tokens: json!([]), inflight: tracked.clone(), ..Default::default() }).await;
            let mut s = lane(&url, odoo, 1, InflightSet::default()).await;
            assert!(s.inflight.get(&0).expect("tracked").work.is_none(), "refused: only gap-filled");
            if original {
                rpc.lock().unwrap().receipts.insert(B256::repeat_byte(0x77), true);
            } else {
                rpc.lock().unwrap().count = 0; // still pending: the stuck nonce is replaced by a gap-fill
                s.track().await;
                let fill = rpc.lock().unwrap().sent.last().cloned().expect("gap-fill");
                assert_eq!((fill.1, fill.2.len()), (s.address(), 0));
                rpc.lock().unwrap().receipts.insert(fill.0, true);
            }
            s.track().await;
            assert_eq!(s.inflight_count(), 0);
            let last = o.lock().unwrap().reports.last().cloned().unwrap();
            match original {
                true => assert_eq!((last["chain_state"].as_str(), last["tx_hash"].as_str()),
                                   (Some("mined"), Some(&*format!("{:#x}", B256::repeat_byte(0x77))))),
                false => assert!(last["chain_state"] == "dead" && last["error"].as_str().unwrap().contains("gap-filled"), "{last}"),
            }
        }
    }

    // ------------------------------------------------------------------ CTR-MTX-26 / -27 on EVM (T17)

    fn vector(i: usize) -> (B256, Vec<u8>) {
        let v: Value = serde_json::from_str(include_str!("../../smartcontracts/vectors/metatx/paymeta.json")).unwrap();
        let h = |k: &str| alloy::hex::decode(&v[i][k].as_str().unwrap()[2..]).unwrap();
        (B256::from_slice(&h("salt")), h("meta"))
    }

    fn pay_meta_job(id: i64, salt: B256, pm: &[u8], tweak: impl FnOnce(&mut MetaTransfer)) -> Value {
        let p = crate::metatx::meta_pay_id(&salt, pm);
        let Mtx::Transfer(mut t) = meta(7) else { unreachable!() };
        (t.entryRef, t.batch) = (p, crate::metatx::pay_lane(&p));
        tweak(&mut t);
        let (kind, wire) = Mtx::Transfer(t).to_wire();
        json!({"id": id, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
               "signature": format!("0x{}", "11".repeat(65)), "metatx": wire,
               "salt": format!("{salt:#x}"), "meta": format!("0x{}", alloy::hex::encode(pm))})
    }

    /// CTR-MTX-26 on EVM (spec §9): the node checks `entryRef == metaPayId(salt, meta)`, `batch == payLane(entryRef)`,
    /// `nonce == 0` before any simulation, then relays `mtxPayMeta` (or, off-chain, `mtxExecuteTransfer`) of the signed
    /// struct; the shared vectors' hashes are the node's.
    #[tokio::test]
    async fn pay_meta_job_checks_commitment_lane_nonce() {
        let v: Value = serde_json::from_str(include_str!("../../smartcontracts/vectors/metatx/paymeta.json")).unwrap();
        for r in v.as_array().unwrap() {
            let h = |k: &str| alloy::hex::decode(&r[k].as_str().unwrap()[2..]).unwrap();
            let p = crate::metatx::meta_pay_id(&B256::from_slice(&h("salt")), &h("meta"));
            assert_eq!(p.as_slice(), &h("payId")[..], "{}", r["name"]);
            assert_eq!(crate::metatx::pay_lane(&p).to_be_bytes::<32>().as_slice(), &h("payLane")[..], "{}", r["name"]);
        }
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let (salt, pm) = vector(0);
        let (r, rpc) = outcomes(ok(), vec![pay_meta_job(7, salt, &pm, |_| {})], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let sent = rpc.lock().unwrap().sent[0].2.clone();
        let c = IToken::mtxPayMetaCall::abi_decode(&sent).unwrap();
        assert_eq!((c.salt, c.meta.to_vec()), (salt, pm.clone()));
        let (Mtx::Transfer(t), _) = Mtx::from_calldata(&sent).unwrap() else { panic!() };
        assert_eq!((t.entryRef, t.nonce), (crate::metatx::meta_pay_id(&salt, &pm), U256::ZERO), "mtxPayMeta is its MetaTransfer");
        // off-chain meta: the same checks, the plain mtxExecuteTransfer of the same struct
        let mut off = pay_meta_job(7, salt, &pm, |_| {});
        off["meta_offchain"] = json!(true);
        let (r, rpc) = outcomes(ok(), vec![off], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        assert_eq!(rpc.lock().unwrap().sent[0].2[..4], IToken::mtxExecuteTransferCall::SELECTOR);
        // a struct that is not the payment of (salt, meta): refused before any RPC
        let bad: [fn(&mut MetaTransfer); 3] = [
            |t| t.entryRef = B256::repeat_byte(0x42),
            |t| t.batch += U256::from(1),
            |t| t.nonce = U256::from(1),
        ];
        for (i, tweak) in bad.into_iter().enumerate() {
            let (r, rpc) = outcomes(ok(), vec![pay_meta_job(7, salt, &pm, tweak)], |_| {}).await;
            assert!(r[0].0 == "dead" && r[0].1.contains("pay-meta"), "{i}: {r:?}");
            assert!(rpc.lock().unwrap().sent.is_empty());
        }
        let mut half = pay_meta_job(7, salt, &pm, |_| {});
        half.as_object_mut().unwrap().remove("meta");
        assert_eq!(outcomes(ok(), vec![half], |_| {}).await.0[0].0, "dead", "salt without meta");
        let (kind, wire) = Mtx::Call(crate::abi::MetaTransaction { from: Address::repeat_byte(0xab),
            data: Bytes::from_static(&[0xcf, 0xdd, 0x7a, 0xea]), batch: U256::from(7), nonce: U256::ZERO,
            validUntil: U256::from(now() + 600), mode: 0, relayer: Address::ZERO, fee: U256::ZERO, feeRecipient: Address::ZERO }).to_wire();
        let call = json!({"id": 7, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
            "signature": format!("0x{}", "11".repeat(65)), "metatx": wire, "salt": format!("{salt:#x}"), "meta": "0x"});
        assert!(outcomes(ok(), vec![call], |_| {}).await.0[0].1.contains("transfer struct"), "a call struct is no pay-meta");
        let mut other = job(7);
        other["kind"] = json!("signed_op");
        assert!(outcomes(ok(), vec![other], |_| {}).await.0[0].1.contains("unknown job kind"), "one job-kind rule");
    }

    /// `max_pay_meta_bytes` (default 2,048, spec §9) caps the `meta` a pay-meta job relays; the config raises it.
    #[tokio::test]
    async fn pay_meta_cap_refused() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let salt = B256::repeat_byte(3);
        let (r, _) = outcomes(ok(), vec![pay_meta_job(7, salt, &[7; 2048], |_| {})], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let (r, rpc) = outcomes(ok(), vec![pay_meta_job(7, salt, &[7; 2049], |_| {})], |_| {}).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("PAY_META_TOO_LONG"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = outcomes(ok(), vec![pay_meta_job(7, salt, &[7; 2049], |_| {})],
            |c| { c.params.insert("max_pay_meta_bytes".into(), 4096.into()); }).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
    }

    const ROUTER: Address = Address::repeat_byte(0x7f);
    const TARGET: Address = Address::repeat_byte(0x7a);

    fn relay_params(c: &mut ChainCfg, more: &[(&str, toml::Value)]) {
        let mut t = toml::Table::new();
        t.insert("router".into(), format!("{ROUTER:#x}").into());
        t.insert("min_amount".into(), 100.into());
        for (k, v) in more {
            t.insert((*k).into(), v.clone());
        }
        c.params.insert("relay_fee".into(), toml::Value::Table(t));
    }

    /// A router-bound payment of `value` to `to` for `TARGET.cancelNonce(9)`, as `relay` calldata.
    fn relay_data(to: Address, value: u64, tweak: impl FnOnce(&mut MetaTransfer)) -> Vec<u8> {
        let call: Bytes = IToken::mtxNonceCall { from: Address::ZERO, batch: U256::ZERO }.abi_encode().into();
        let r = crate::metatx::relay_ref(31337, TARGET, &call);
        let mut t = MetaTransfer { from: Address::repeat_byte(0xab), to, value: U256::from(value), entryRef: r,
            batch: crate::metatx::pay_lane(&r), nonce: U256::ZERO, validUntil: U256::from(now() + 600),
            mode: crate::metatx::MODE_RESTRICT_RELAYER, relayer: ROUTER, fee: U256::ZERO, feeRecipient: Address::ZERO };
        tweak(&mut t);
        crate::abi::IMtxRelayFee::relayCall { target: TARGET, callData: call, token: TOKEN, t, sig: Bytes::from(vec![0x11; 65]) }.abi_encode()
    }

    fn lane1() -> Address {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap().address()
    }

    /// CTR-MTX-27 call-table row: only `relay` on the configured router, for a registered token's payment bound to
    /// exactly this call (the router's shape, checked before any gas is spent); never a plain pay to the router or its
    /// executor; a router that is not an address is a startup error.
    #[tokio::test]
    async fn relay_fee_row_requires_router_and_registered_token() {
        let sig = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        let t = "(address,address,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
        assert_eq!(guard::CALL_TABLE[10].0, sig(&format!("relay(address,bytes,address,{t},bytes)")));
        assert_eq!(IToken::mtxPayMetaCall::SELECTOR,
            sig("mtxPayMeta(address,address,uint256,bytes32,bytes,uint256,uint32,address,uint256,address,bytes)"));
        let mut cfg = test_cfg("http://127.0.0.1:9");
        relay_params(&mut cfg, &[]);
        let rf = guard::RelayFee::from_cfg(&cfg).unwrap().unwrap();
        assert_eq!(rf.executor, ROUTER.create(1), "the router's constructor CREATE");
        let lane = lane1();
        let reg = |a: Address| a == TOKEN;
        let check = |to: Address, data: &[u8]| guard::relay_call_ok(&rf, 31337, lane, to, data, reg);
        assert_eq!(check(ROUTER, &relay_data(ROUTER, 100, |_| {})), Ok(TARGET));
        assert!(check(TARGET, &relay_data(ROUTER, 100, |_| {})).unwrap_err().starts_with("CALL_TARGET_REFUSED"), "only the router");
        assert!(check(ROUTER, &[1, 2, 3, 4]).unwrap_err().starts_with("BAD_PAYLOAD"));
        let c = crate::abi::IMtxRelayFee::relayCall::abi_decode(&relay_data(ROUTER, 100, |_| {})).unwrap();
        let other = crate::abi::IMtxRelayFee::relayCall { token: Address::repeat_byte(0x99), ..c }.abi_encode();
        assert!(check(ROUTER, &other).unwrap_err().starts_with("TOKEN_NOT_SERVED"), "a registered token only");
        let shapes: [fn(&mut MetaTransfer); 8] = [
            |t| t.entryRef = B256::repeat_byte(1),
            |t| t.batch = U256::from(1),
            |t| t.nonce = U256::from(1),
            |t| t.mode = 0,
            |t| t.relayer = lane1(),
            |t| t.mode |= 0x20,
            |t| t.fee = U256::from(1),
            |t| t.to = ROUTER.create(1),
        ];
        for (i, tweak) in shapes.into_iter().enumerate() {
            assert!(check(ROUTER, &relay_data(ROUTER, 100, tweak)).unwrap_err().starts_with("RELAY_FEE_SHAPE"), "{i}");
        }
        // config: a router that is not an address fails at startup, in every module that reads it
        for bad in [toml::Value::from("0x12"), toml::Value::from(7)] {
            let mut c = test_cfg("http://127.0.0.1:9");
            relay_params(&mut c, &[]);
            c.params["relay_fee"].as_table_mut().unwrap().insert("router".into(), bad);
            assert!(guard::Guard::new(&c, Default::default()).is_err());
        }
        // on the lane: a plain pay (or pay-meta) to the router or its executor is refused; no router ⇒ no relay row
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        for to in [ROUTER, ROUTER.create(1)] {
            let Mtx::Transfer(mut t) = meta(7) else { unreachable!() };
            t.to = to;
            let (kind, wire) = Mtx::Transfer(t).to_wire();
            let j = json!({"id": 7, "kind": "metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
                           "signature": format!("0x{}", "11".repeat(65)), "metatx": wire});
            let (r, rpc) = outcomes(ok(), vec![j], |c| relay_params(c, &[])).await;
            assert!(r[0].0 == "dead" && r[0].1.starts_with("PAYEE_REFUSED"), "{r:?}");
            assert!(rpc.lock().unwrap().sent.is_empty());
        }
        let (r, _) = outcomes(ok(), vec![call_job(9, ROUTER, relay_data(ROUTER, 100, |_| {}))], |_| {}).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("no params.relay_fee.router"), "{r:?}");
    }

    /// CTR-MTX-27 on the lane: the whole `relay` is simulated and sent only when the fee reaches this lane (open mode,
    /// or bound to it) and is at least `min_amount` (the operator's price of the gas: no token price feed, no gas
    /// price or block limit assumed); a fee bound elsewhere only with `relay_bound_payee` (sponsored); the inner
    /// target must be bound to this chain.
    #[tokio::test]
    async fn relay_fee_submits_only_when_fee_covers_gas() {
        let go = |data: Vec<u8>, more: Vec<(&'static str, toml::Value)>, e: Evm| async move {
            outcomes(e, vec![call_job(9, ROUTER, data)], move |c| relay_params(c, &more)).await
        };
        let (r, rpc) = go(relay_data(ROUTER, 100, |_| {}), vec![], Evm::default()).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "open mode at min_amount: {r:?}");
        let sent = rpc.lock().unwrap().sent[0].clone();
        assert_eq!((sent.1, &sent.2[..4]), (ROUTER, &guard::CALL_TABLE[10].0[..]));
        assert_eq!(rpc.lock().unwrap().gas[0], 0x30000 * 6 / 5, "the simulated relay +20 %");
        let (r, rpc) = go(relay_data(ROUTER, 99, |_| {}), vec![], Evm::default()).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("below relay_fee.min_amount 100"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = go(relay_data(lane1(), 100, |_| {}), vec![], Evm::default()).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "bound to this lane: {r:?}");
        let elsewhere = Address::repeat_byte(0x5e);
        let (r, _) = go(relay_data(elsewhere, 1_000, |_| {}), vec![], Evm::default()).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("relay_bound_payee"), "a fee bound elsewhere: {r:?}");
        let (r, _) = go(relay_data(elsewhere, 1, |_| {}), vec![("relay_bound_payee", true.into())], Evm::default()).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "sponsored: no min_amount: {r:?}");
        let (r, _) = go(relay_data(ROUTER, 100, |_| {}), vec![], Evm { uid: Some(UID + 1), ..Default::default() }).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("CHAIN_UID_MISMATCH"), "the inner target is of another chain: {r:?}");
    }
}
