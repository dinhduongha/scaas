//! `ChainAdapter` (R58): một mạng = một adapter. EVM giữ runner riêng (`submit.rs`: pipeline nonce,
//! thay thế, gap-fill) nhưng cũng cài trait; các họ khác chạy `lane_runner` — mỗi lane MỘT tx đang bay,
//! song song giữa các lane (R62: sequence của relayer không thành khoá toàn cục, chủ thể không có
//! sequence trong đường đi — R30).
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use tracing::{info, warn};

use crate::breaker::Breaker;
use crate::chain::SimError;
use crate::finality::next_range;
use crate::odoo::{Job, Odoo, Report};
use crate::submit::{job_digest, now, InflightSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Evm,
    Hedera,
    Sui,
    Soroban,
    Cosmos,
    Ton,
    Solana,
    Aptos,
    Near,
    Algorand,
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
            "solana" => Self::Solana,
            "aptos" => Self::Aptos,
            "near" => Self::Near,
            "algorand" => Self::Algorand,
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
    /// `tx_hash` = the transaction whose events the indexer reports, when it is not the signed tx id (TON: the
    /// payer jetton wallet's tx, not the lane wallet's external message) — sent with `mined` so Odoo's `final`
    /// matches it as ours. `None` = the tx id itself.
    Mined { height: u64, tx_hash: Option<String> },
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
    /// Event chuẩn hoá cho `chain_event_ingest` trong [from, to], CHỈ của `contracts` (token Odoo đã đăng ký,
    /// dạng chuẩn của họ — review M1: không danh sách tĩnh trong cấu hình node); hash và địa chỉ đã ở dạng
    /// chuẩn (hash `0x`+64 hex; địa chỉ theo họ — R61).
    async fn events(&self, from: u64, to: u64, contracts: &[String]) -> Result<Vec<Value>>;
    /// Số dư coin gas của lane (đơn vị nhỏ nhất) cho cầu dao sàn số dư (R55). `None` = chưa hỗ trợ.
    async fn lane_balance(&self, _lane: usize) -> Result<Option<u128>> {
        Ok(None)
    }
    /// Phí thực trả của tx đã vào khối (đơn vị nhỏ nhất) cho ngân sách gas theo giờ (R55).
    async fn tx_fee(&self, _tx_id: &str) -> Result<Option<u128>> {
        Ok(None)
    }
    /// Khởi động lại (merge TODO b): gửi lại tx của `lane` mà adapter TỰ journal trên đĩa (Sui), để
    /// `recover_lane` thấy nó vào sổ. Mặc định: họ không journal bytes ⇒ không gì để gửi lại.
    async fn resend_journaled(&self, _lane: usize) -> Result<()> {
        Ok(())
    }
    /// R80: `Some(true)` ⇔ nonce lane của chủ thể đã qua nonce của op (ai đó đã dùng nó). `Ok(None)` = không biết
    /// ⇒ không bao giờ dừng job vì nó: mọi loại op mà replay guard không phải nonce lane (review M6). v1 chỉ trả lời
    /// cho `pay` (và meta-tx Hedera qua `mtxNonce`). Lỗi RPC ⇒ `Err`: không gửi lại vòng này (fail closed).
    async fn op_consumed(&self, _job: &Job) -> Result<Option<bool>> {
        Ok(None)
    }
    /// G2's in-flight key of a claimed job. Default: the job's own digest; an EVM meta-tx answers the token's
    /// `mtxDigest`, never the job's field (review T2 m6). `Revert` = no key (its simulation answers for it).
    async fn digest(&self, job: &Job) -> std::result::Result<Option<alloy::primitives::B256>, SimError> {
        Ok(job_digest(job))
    }
    /// NODE-GW-07 at lane start: an EVM chain whose RPC's block 0 is not the configured `chain_uid` never runs a
    /// lane (review T4 I2). Default: nothing to check.
    async fn start_check(&self) -> Result<()> {
        Ok(())
    }
    /// The chain's registered tokens from the client, for the guard (review T4 I2, m1). Default: unused.
    fn refresh_tokens(&self, _nc: &crate::odoo::NodeConfig) {}
    /// The job's simulation refused it because what it asks already holds (`mtxInvalidateNonces` past its minimum,
    /// MT-8): done, never dead. Default: no such job.
    fn already_done(&self, _job: &Job, _reason: &str) -> bool {
        false
    }
}

/// Lỗi `submit` khi mạng TỪ CHỐI tx trước mempool (sequence lệch, thiếu phí, chữ ký sai…): gửi lại cùng bytes
/// không bao giờ qua, nên runner trả job về hàng đợi để dựng lại với sequence mới thay vì giữ lane tới hạn
/// payload (review L1). Lỗi khác của `submit` (mạng, mempool đầy) vẫn là thử lại cùng bytes.
/// `tx_status` cũng trả `Rejected` khi tx đã vào sổ nhưng mạng từ chối mà KHÔNG chạy nó (Hedera `WRONG_NONCE`,
/// `INSUFFICIENT_PAYER_BALANCE`…): chữ ký chủ thể còn nguyên ⇒ job về hàng đợi, không `reverted` (review M2 S6).
#[derive(Debug)]
pub struct Rejected(pub String);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rejected before mempool: {}", self.0)
    }
}

impl std::error::Error for Rejected {}

/// The pay kinds every family serves (CTR-MTX-26 / -27); a family adds its own wrapper kinds, if any.
pub const PAY_KINDS: [&str; 2] = ["pay_meta", "relay_fee"];

/// `op.kind` of a `signed_op` job, one rule for every family (T17, controller ruling 2026-10-28): absent (or null) =
/// the plain pay; one of `known` = that kind; any other string, or a present non-string (`7`, `true`, `{}`), is
/// refused, never a plain pay (a typo must not burn the `(payer, payId)` lane as one). A kind-less job carrying
/// `salt` / `meta` is refused too: that is a pay-meta without its kind.
pub fn op_kind<'a>(op: &'a Value, known: &[&str]) -> anyhow::Result<Option<&'a str>> {
    match op.get("kind").filter(|k| !k.is_null()) {
        None if op.get("salt").is_some_and(|v| !v.is_null()) || op.get("meta").is_some_and(|v| !v.is_null()) => {
            anyhow::bail!("a plain pay carries no salt / meta (a pay-meta is op.kind = \"pay_meta\")")
        }
        None => Ok(None),
        Some(Value::String(k)) if known.contains(&k.as_str()) => Ok(Some(k.as_str())),
        Some(k) => anyhow::bail!("unknown op.kind {k} ({}, or none for a plain pay)", known.join(", ")),
    }
}

/// Whose fee a relay-fee job is, one rule for every family (T17, controller ruling 2026-10-28): the node relays a job
/// whose fee reaches its own lane (open mode, or a bound payee that is the lane) only when `amount >= min_amount`; a
/// fee bound to anyone else only with `params.relay_fee.relay_bound_payee = true`, and then as a sponsored job (no
/// `min_amount`: the fee is not the node's).
pub fn relay_fee_ours(open: bool, payee_is_lane: bool, amount: u128, p: &crate::config::RelayParams) -> anyhow::Result<()> {
    if open || payee_is_lane {
        if amount < p.min_amount {
            anyhow::bail!("fee {amount} is below relay_fee.min_amount {}", p.min_amount);
        }
        return Ok(());
    }
    if !p.relay_bound_payee {
        anyhow::bail!("the fee is bound to another payee, not this lane (params.relay_fee.relay_bound_payee is false)");
    }
    Ok(())
}

const STATUS_POLL: Duration = Duration::from_millis(500);
/// Lùi khi lane lỗi (RPC/Odoo chết): 1 s nhân đôi tới 60 s; một vòng thành công đặt lại (merge TODO c).
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
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
/// Cầu dao (R55) chỉ chặn việc claim job MỚI; job đang bay của lane được `lane_step` theo dõi tới cùng.
pub async fn lane_runner(
    adapter: Arc<dyn ChainAdapter>,
    odoo: Odoo,
    lane: usize,
    worker: String,
    poll: Duration,
    breaker: Arc<Mutex<Breaker>>,
    inflight: InflightSet,
) {
    let key = adapter.chain_key().to_string();
    // Review P5 m1: a failed chain_uid check (a wrong pin, or an RPC that errors on block 0) keeps THIS lane stopped and
    // asks again with backoff; the node and its other chains keep running (fail closed per lane).
    let mut backoff = BACKOFF_MIN;
    while let Err(e) = adapter.start_check().await {
        tracing::error!(chain = %key, lane, retry_in = ?backoff, "lane not started: {e:#}");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
    info!(chain = %key, lane, address = %adapter.lanes()[lane].address, "lane ready");
    backoff = BACKOFF_MIN;
    while let Err(e) = recover_lane(adapter.as_ref(), &odoo, lane, &worker).await {
        warn!(chain = %key, lane, "restart recovery: {e:#}");
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
    backoff = BACKOFF_MIN;
    let (mut tripped, mut sampled) = (None, None::<std::time::Instant>);
    loop {
        if sampled.is_none_or(|t| t.elapsed() >= Duration::from_secs(15)) {
            sampled = Some(std::time::Instant::now());
            match odoo.node_config_ref(key.clone().into(), None, None).await {
                Ok(nc) => adapter.refresh_tokens(&nc),
                Err(e) => warn!(chain = %key, lane, "token refresh: {e:#}"),
            }
            match adapter.lane_balance(lane).await {
                Ok(Some(b)) => breaker.lock().map(|mut k| k.balance(b)).unwrap_or(()),
                Ok(None) => {}
                Err(e) => warn!(chain = %key, lane, "lane balance: {e:#}"),
            }
        }
        let open = breaker.lock().map(|mut k| k.open(now())).unwrap_or(None);
        if open != tripped {
            match open {
                Some(b) => warn!(chain = %key, lane, breaker = b, "circuit breaker open: new work paused"),
                None => info!(chain = %key, lane, "circuit breakers closed"),
            }
            tripped = open;
        }
        if open.is_some() {
            tokio::time::sleep(poll).await;
            continue;
        }
        let why = match step_once(adapter.as_ref(), &odoo, lane, &worker, Some(&breaker), &inflight).await {
            Ok(Step::Done) => {
                backoff = BACKOFF_MIN;
                continue;
            }
            Ok(Step::Idle) => None,
            Ok(Step::Retry(why)) => Some(why),
            Err(e) => Some(format!("{e:#}")),
        };
        if let Some(why) = why {
            warn!(chain = %key, lane, retry_in = ?backoff, "lane: {why}");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
            continue;
        }
        backoff = BACKOFF_MIN;
        tokio::time::sleep(poll).await;
    }
}

/// Khởi động lại (merge TODO b): job lane này để lại giữa chừng được chốt TRƯỚC khi nhận việc mới, nếu không
/// job `signed`/`broadcast` treo mãi và payment request bị chặn qua `_live_job()`. Bytes đã ký mất theo tiến trình
/// (trừ họ tự journal — `resend_journaled`), nên chỉ còn hỏi `tx_status`: vào sổ ⇒ chốt; từ chối ⇒ hàng đợi;
/// không thấy ⇒ chờ tới khi slot sequence của nó bị dùng (không bao giờ vào được nữa ⇒ hàng đợi) hoặc payload hết
/// hạn (`dead` ⇒ payer ký lại). Dựng lại một job mà tx cũ vẫn vào sổ không trả hai lần: contract chặn replay (R30).
pub async fn recover_lane(adapter: &dyn ChainAdapter, odoo: &Odoo, lane: usize, worker: &str) -> Result<()> {
    adapter.resend_journaled(lane).await?;
    let address = adapter.lanes()[lane].address.clone();
    let nc = odoo.node_config_ref(adapter.chain_key().into(), Some(address), Some(worker.into())).await?;
    adapter.refresh_tokens(&nc);
    for j in nc.inflight {
        let Some(tx_id) = j.tx_hash else {
            // Chưa ký ⇒ chưa gửi gì: journal `signed` luôn có trước lần gửi đầu.
            report(odoo, Report { error: Some("node restarted before signing".into()), ..rep(j.job_id, "queued") }).await;
            continue;
        };
        info!(chain = %adapter.chain_key(), lane, job = j.job_id, tx = %tx_id, "re-checking in-flight job after restart");
        let valid_until = j.payload.op.as_ref().and_then(|o| o["valid_until"].as_u64()).unwrap_or(0);
        let f = InFlight { job: &j.payload, tx_id: &tx_id, valid_until, lane, signed: None, nonce: j.nonce };
        follow(adapter, odoo, f, Ok(()), None).await;
    }
    Ok(())
}

/// Một tx đang bay. `signed` = bytes còn trong tay (gửi lại được); `None` sau khởi động lại.
struct InFlight<'a> {
    job: &'a Job,
    tx_id: &'a str,
    valid_until: u64,
    lane: usize,
    signed: Option<&'a Signed>,
    nonce: Option<u64>,
}

/// Theo dõi tới mined/reverted/consumed/queued/dead. `sent` = kết quả lần gửi gần nhất.
/// R80: revert ⇒ kiểm `op_consumed` trước (review H3); trước MỖI lần gửi lại cũng vậy. Đã tiêu thụ ⇒ báo `consumed`
/// một lần, thôi gửi lại, vẫn giữ lane theo dõi tx tới trạng thái cuối hoặc hết hạn (không báo gì thêm ngoài `mined`).
async fn follow(adapter: &dyn ChainAdapter, odoo: &Odoo, f: InFlight<'_>, mut sent: Result<()>, breaker: Option<&Mutex<Breaker>>) {
    let job = f.job.id;
    let mut consumed = false;
    loop {
        match adapter.tx_status(f.tx_id).await {
            Ok(TxStatus::Mined { tx_hash, .. }) => {
                if let (Some(k), Ok(Some(fee))) = (breaker, adapter.tx_fee(f.tx_id).await) {
                    if let Ok(mut k) = k.lock() {
                        k.spend(now(), fee);
                    }
                }
                report(odoo, Report { tx_hash, ..rep(job, "mined") }).await;
                return;
            }
            Ok(TxStatus::Reverted { .. }) if consumed => return,
            Ok(TxStatus::Reverted { reason }) => match adapter.op_consumed(f.job).await {
                Ok(Some(true)) => {
                    report(odoo, Report { error: Some(format!("unknown; ours reverted: {reason}")), ..rep(job, "consumed") }).await;
                    return;
                }
                Ok(_) => {
                    report(odoo, Report { error: Some(reason), ..rep(job, "reverted") }).await;
                    return;
                }
                Err(e) => warn!(chain = %adapter.chain_key(), job, "reverted, op_consumed unreadable; retry: {e:#}"),
            },
            Ok(TxStatus::Pending) => {}
            Err(e) if e.downcast_ref::<Rejected>().is_some() => {
                if !consumed {
                    report(odoo, Report { error: Some(e.to_string()), ..rep(job, "queued") }).await;
                }
                return;
            }
            Ok(TxStatus::Unknown) | Err(_) => {
                // Hỏi trạng thái TRƯỚC: bị từ chối khi gửi lại có thể vì tx lần trước đã vào khối.
                if let Some(r) = sent.as_ref().err().and_then(|e| e.downcast_ref::<Rejected>()) {
                    if !consumed {
                        report(odoo, Report { error: Some(r.to_string()), ..rep(job, "queued") }).await;
                    }
                    return;
                }
                if now() > f.valid_until + EXPIRY_GRACE {
                    // Payload chủ thể đã hết hạn: tx (nếu còn đâu đó) sẽ bị contract từ chối.
                    if !consumed {
                        report(odoo, Report { error: Some("expired before inclusion".into()), ..rep(job, "dead") }).await;
                    }
                    return;
                }
                match f.signed {
                    Some(signed) if sent.is_err() && !consumed => match adapter.op_consumed(f.job).await {
                        Ok(Some(true)) => {
                            consumed = true;
                            report(odoo, Report { error: Some("unknown".into()), ..rep(job, "consumed") }).await;
                        }
                        Ok(_) => {
                            sent = adapter.submit(signed).await;
                            if sent.is_ok() {
                                report(odoo, rep(job, "broadcast")).await;
                            }
                        }
                        Err(e) => warn!(chain = %adapter.chain_key(), job, "op_consumed: {e:#}; no resend this round"),
                    },
                    Some(_) => {}
                    None => {
                        // Không còn bytes: tx chỉ vào được đúng slot sequence của nó. Slot đã bị dùng mà hỏi lại vẫn
                        // không thấy tx ⇒ nó không bao giờ vào sổ nữa.
                        let moved = matches!((f.nonce, adapter.sequence(f.lane).await), (Some(n), Ok(s)) if s != n);
                        if moved && matches!(adapter.tx_status(f.tx_id).await, Ok(TxStatus::Unknown)) {
                            let why = "lost with a node restart; its lane sequence moved on";
                            report(odoo, Report { error: Some(why.into()), ..rep(job, "queued") }).await;
                            return;
                        }
                    }
                }
            }
        }
        tokio::time::sleep(STATUS_POLL).await;
    }
}

/// `true` = đã xử lý một job (đi tiếp ngay).
pub async fn lane_step(adapter: &dyn ChainAdapter, odoo: &Odoo, lane: usize, worker: &str) -> Result<bool> {
    lane_step_metered(adapter, odoo, lane, worker, None).await
}

/// `lane_step` + ghi phí thực trả của tx đã vào khối vào ngân sách gas của lane.
pub async fn lane_step_metered(
    adapter: &dyn ChainAdapter,
    odoo: &Odoo,
    lane: usize,
    worker: &str,
    breaker: Option<&Mutex<Breaker>>,
) -> Result<bool> {
    Ok(!matches!(step_once(adapter, odoo, lane, worker, breaker, &InflightSet::default()).await?, Step::Idle))
}

/// Kết quả một vòng lane. `Retry` = job đã về hàng đợi vì RPC/Odoo không với tới: runner lùi (merge TODO c).
enum Step {
    Idle,
    Done,
    Retry(String),
}

async fn step_once(
    adapter: &dyn ChainAdapter,
    odoo: &Odoo,
    lane: usize,
    worker: &str,
    breaker: Option<&Mutex<Breaker>>,
    inflight: &InflightSet,
) -> Result<Step> {
    let jobs = odoo.relay_poll_ref(adapter.chain_key().into(), 5).await?;
    let mut job = None;
    for j in jobs {
        // N2: digest đang bay ở lane/đường khác ⇒ bỏ qua TRƯỚC claim (không claim, không báo).
        if job_digest(&j).is_some_and(|d| inflight.contains(&d)) {
            continue;
        }
        if odoo.relay_claim(&[j.id], worker).await?.contains(&j.id) {
            job = Some(j);
            break;
        }
    }
    let Some(job) = job else { return Ok(Step::Idle) };
    // G2: giữ digest tới khi `follow` xong (guard rơi ở mọi lối ra của hàm này).
    let digest = match adapter.digest(&job).await {
        Ok(d) => d,
        Err(SimError::Revert(_)) => None,
        Err(SimError::Transport(r)) => {
            report(odoo, Report { error: Some(format!("rpc: {r}")), ..rep(job.id, "queued") }).await;
            return Ok(Step::Retry(format!("rpc: {r}")));
        }
    };
    let _guard = match digest.map(|d| inflight.try_acquire(d)) {
        Some(None) => {
            report(odoo, Report { error: Some("in flight on another path".into()), ..rep(job.id, "queued") }).await;
            return Ok(Step::Done);
        }
        Some(g) => g,
        None => None,
    };
    let built = match adapter.build(&job, lane).await {
        Ok(b) => b,
        Err(SimError::Revert(r)) if adapter.already_done(&job, &r) => {
            report(odoo, Report { error: Some("already_invalidated".into()), ..rep(job.id, "consumed") }).await;
            return Ok(Step::Done);
        }
        Err(SimError::Revert(r)) => {
            // R80: op đã bị tiêu thụ (relayer khác đưa lên trước) ⇒ `consumed`, không `dead`.
            let (state, error) = match adapter.op_consumed(&job).await {
                Ok(Some(true)) => ("consumed", "unknown".to_string()),
                Ok(_) => ("dead", format!("simulation: {r}")),
                Err(e) => {
                    report(odoo, Report { error: Some(format!("op_consumed: {e:#}")), ..rep(job.id, "queued") }).await;
                    return Ok(Step::Retry(format!("op_consumed: {e:#}")));
                }
            };
            report(odoo, Report { error: Some(error), ..rep(job.id, state) }).await;
            return Ok(Step::Done);
        }
        Err(SimError::Transport(r)) => {
            report(odoo, Report { error: Some(format!("rpc: {r}")), ..rep(job.id, "queued") }).await;
            return Ok(Step::Retry(format!("rpc: {r}")));
        }
    };
    let seq = adapter.sequence(lane).await?;
    let signed = adapter.sign(built, lane, seq).await?;
    let signer = adapter.lanes()[lane].address.clone();
    // Journal TRƯỚC khi gửi (review I5): không ghi được thì không gửi, job về hàng đợi.
    if !report(odoo, Report { tx_hash: Some(signed.tx_id.clone()), outer_nonce: Some(seq), signer_address: Some(signer), ..rep(job.id, "signed") }).await {
        report(odoo, Report { error: Some("journal write failed".into()), ..rep(job.id, "queued") }).await;
        return Ok(Step::Retry("journal write failed".into()));
    }
    let sent = adapter.submit(&signed).await;
    if sent.is_ok() {
        report(odoo, rep(job.id, "broadcast")).await;
    }
    let f = InFlight { job: &job, tx_id: &signed.tx_id, valid_until: signed.valid_until, lane, signed: Some(&signed), nonce: Some(seq) };
    follow(adapter, odoo, f, sent, breaker).await;
    Ok(Step::Done)
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
    // Không token nào đăng ký: không ai lọc được vùng này ⇒ giữ con trỏ (review M1), đọc lại khi có token.
    let contracts: Vec<String> = nc.tokens.iter().map(|t| t.address.clone()).collect();
    if contracts.is_empty() {
        return Ok(false);
    }
    let events = adapter.events(from, to, &contracts).await?;
    let hash = if to == head.height { head.hash.clone() } else { adapter.block_hash(to).await? };
    let r = odoo.ingest_ref(key, from, to, &hash, &events).await?;
    Ok(r.indexed_block >= to && to < head.height)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// T17: one job-kind rule and one payee rule for every family.
    #[test]
    fn one_kind_rule_and_one_payee_rule() {
        use serde_json::json;
        let k = |op: Value| op_kind(&op, &PAY_KINDS).map(|o| o.map(str::to_string)).map_err(|e| e.to_string());
        assert_eq!(k(json!({})), Ok(None));
        assert_eq!(k(json!({"kind": null})), Ok(None));
        assert_eq!(k(json!({"kind": "pay_meta"})), Ok(Some("pay_meta".into())));
        assert_eq!(k(json!({"kind": "relay_fee"})), Ok(Some("relay_fee".into())));
        for bad in [json!("pay"), json!("PAY_META"), json!(7), json!(true), json!({}), json!([])] {
            assert!(k(json!({"kind": bad})).unwrap_err().contains("unknown op.kind"), "{bad}");
        }
        assert!(k(json!({"salt": "0x00"})).is_err() && k(json!({"meta": "0x"})).is_err(), "a pay-meta without its kind");
        assert_eq!(op_kind(&json!({"kind": "wrap"}), &["pay_meta", "wrap"]).unwrap(), Some("wrap"), "a family's own kind");
        let p = crate::config::RelayParams { router: None, min_amount: 10, relay_bound_payee: false, max_pay_meta_bytes: 2048 };
        assert!(relay_fee_ours(true, false, 10, &p).is_ok());
        assert!(relay_fee_ours(true, false, 9, &p).unwrap_err().to_string().contains("min_amount"));
        assert!(relay_fee_ours(false, true, 10, &p).is_ok(), "bound to the lane");
        assert!(relay_fee_ours(false, false, 1_000, &p).unwrap_err().to_string().contains("relay_bound_payee"));
        let sponsored = crate::config::RelayParams { relay_bound_payee: true, ..p };
        assert!(relay_fee_ours(false, false, 0, &sponsored).is_ok(), "sponsored: no minimum");
    }

    #[test]
    fn families_parse() {
        assert_eq!(Family::parse("sui"), Some(Family::Sui));
        assert_eq!(Family::parse("solana"), Some(Family::Solana));
        assert_eq!(Family::parse("aptos"), Some(Family::Aptos));
        assert_eq!(Family::parse("near"), Some(Family::Near));
        assert_eq!(Family::parse("algorand"), Some(Family::Algorand));
    }

    /// Adapter giả: lane luôn bị CheckTx từ chối, indexer ghi lại tập contract được đưa vào; `.1` đếm `refresh_tokens`.
    #[derive(Default)]
    struct Mock(std::sync::Mutex<Vec<Vec<String>>>, std::sync::atomic::AtomicU32);

    #[async_trait]
    impl ChainAdapter for Mock {
        fn family(&self) -> Family {
            Family::Cosmos
        }
        fn chain_key(&self) -> &str {
            "cosmos:t"
        }
        fn lanes(&self) -> &[Lane] {
            static L: std::sync::OnceLock<Vec<Lane>> = std::sync::OnceLock::new();
            L.get_or_init(|| vec![Lane { index: 0, address: "wasm1lane".into() }])
        }
        async fn build(&self, job: &Job, _: usize) -> std::result::Result<Built, SimError> {
            Ok(Built { job_id: job.id, body: vec![], valid_until: now() + 600, meta: Value::Null })
        }
        async fn sign(&self, b: Built, _: usize, sequence: u64) -> Result<Signed> {
            Ok(Signed { job_id: b.job_id, tx_id: "0x01".into(), raw: vec![], valid_until: b.valid_until, sequence })
        }
        async fn submit(&self, _: &Signed) -> Result<()> {
            Err(Rejected("code 32: account sequence mismatch".into()).into())
        }
        async fn tx_status(&self, _: &str) -> Result<TxStatus> {
            Ok(TxStatus::Unknown)
        }
        async fn sequence(&self, _: usize) -> Result<u64> {
            Ok(3)
        }
        async fn final_head(&self) -> Result<Option<Head>> {
            Ok(Some(Head { height: 5, hash: format!("0x{}", "ab".repeat(32)) }))
        }
        async fn block_hash(&self, _: u64) -> Result<String> {
            unreachable!()
        }
        async fn events(&self, _: u64, _: u64, contracts: &[String]) -> Result<Vec<Value>> {
            self.0.lock().unwrap().push(contracts.to_vec());
            Ok(vec![])
        }
        fn refresh_tokens(&self, _: &crate::odoo::NodeConfig) {
            self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Review T4 I2/m1: the running lane re-reads the registered tokens (every 15 s, the first round at once), not only
    /// at recovery: a token registered after the lane started is served without a restart.
    #[tokio::test]
    async fn the_lane_loop_refreshes_the_registered_tokens() {
        let (odoo, _) = fake_odoo(Fake { tokens: serde_json::json!([]), ..Default::default() }).await;
        let a = Arc::new(Mock::default());
        let k = Arc::new(Mutex::new(Breaker::new(crate::config::BreakerCfg::default())));
        let run = lane_runner(a.clone(), odoo, 0, "n#0".into(), Duration::from_millis(10), k, InflightSet::default());
        let _ = tokio::time::timeout(Duration::from_millis(500), run).await;
        assert_eq!(a.1.load(std::sync::atomic::Ordering::SeqCst), 2, "recovery, then the loop's first round");
    }

    #[derive(Default)]
    pub(crate) struct Fake {
        pub tokens: Value,
        pub jobs: Vec<Value>,
        pub reports: Vec<Value>,
        pub ingests: u32,
        /// `node_config.inflight` (Null = []).
        pub inflight: Value,
        /// `relay_poll` keeps returning `jobs` instead of draining them.
        pub repeat: bool,
        pub claims: u32,
        /// `dex_sync`'s answer (Null = the generic reply).
        pub dex_sync: Value,
    }
    pub(crate) type Shared = Arc<std::sync::Mutex<Fake>>;

    pub(crate) async fn fake_odoo(fake: Fake) -> (Odoo, Shared) {
        use axum::extract::{Path, State};
        use axum::Json;
        async fn h(State(s): State<Shared>, Path((_m, method)): Path<(String, String)>, Json(b): Json<Value>) -> Json<Value> {
            let mut o = s.lock().unwrap();
            Json(match method.as_str() {
                "node_config" => serde_json::json!({"finality_mode": "instant", "finality_depth": 0, "finality_quorum": 1,
                    "indexed_block": 0, "tokens": o.tokens, "journal_max_nonce": null,
                    "inflight": if o.inflight.is_null() { serde_json::json!([]) } else { o.inflight.clone() }}),
                "relay_poll" if o.repeat => Value::Array(o.jobs.clone()),
                "relay_poll" => Value::Array(std::mem::take(&mut o.jobs)),
                "relay_claim" => {
                    o.claims += 1;
                    b["job_ids"].clone()
                }
                "relay_report" => {
                    o.reports.push(b);
                    serde_json::json!({"ok": true})
                }
                "dex_sync" if !o.dex_sync.is_null() => std::mem::take(&mut o.dex_sync),
                _ => {
                    o.ingests += 1;
                    serde_json::json!({"indexed_block": 5, "created": 0})
                }
            })
        }
        let s: Shared = Arc::new(std::sync::Mutex::new(fake));
        let app = axum::Router::new().route("/json/2/{m}/{method}", axum::routing::post(h)).with_state(s.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let cfg = crate::config::OdooCfg { url, database: "t".into(), relay_api_key_env: String::new(), indexer_api_key_env: String::new() };
        (Odoo::with_key(&cfg, "k".into()).unwrap(), s)
    }

    /// Review H1+M1: tập contract đến từ Odoo (địa chỉ dạng chuẩn của họ, không phải EVM), và khi tập rỗng
    /// con trỏ KHÔNG tiến — event của token kích hoạt sau vẫn được đọc lại.
    #[tokio::test]
    async fn index_step_filters_on_odoo_tokens_and_holds_the_cursor_without_them() {
        let a = Mock::default();
        let (odoo, o) = fake_odoo(Fake { tokens: serde_json::json!([]), ..Default::default() }).await;
        assert!(!index_step(&a, &odoo).await.unwrap());
        assert_eq!((o.lock().unwrap().ingests, a.0.lock().unwrap().len()), (0, 0), "no contracts => no ingest");
        let (odoo, o) = fake_odoo(Fake { tokens: serde_json::json!([{"address": "wasm1tok", "decimals": 6}]), ..Default::default() }).await;
        index_step(&a, &odoo).await.unwrap();
        assert_eq!(o.lock().unwrap().ingests, 1);
        assert_eq!(a.0.lock().unwrap().as_slice(), [vec!["wasm1tok".to_string()]]);
    }

    /// Review L1: CheckTx từ chối vĩnh viễn ⇒ lane nhả ngay, job về hàng đợi kèm lý do (không chờ tới hạn payload).
    #[tokio::test]
    async fn rejected_broadcast_releases_the_lane_at_once() {
        let job = serde_json::json!({"id": 7, "kind": "signed_op", "op": {}});
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job], ..Default::default() }).await;
        let mock = Mock::default();
        let step = lane_step(&mock, &odoo, 0, "n#0");
        assert!(tokio::time::timeout(Duration::from_secs(5), step).await.expect("lane held").unwrap());
        let o = o.lock().unwrap();
        let states: Vec<&str> = o.reports.iter().filter_map(|r| r["chain_state"].as_str()).collect();
        assert_eq!(states, ["signed", "queued"]);
        assert!(o.reports[1]["error"].as_str().unwrap().contains("sequence mismatch"));
    }

    /// Adapter giả: trạng thái tx theo tx id, sequence lane = 4, RPC mô phỏng luôn lỗi mạng.
    #[derive(Default)]
    struct Scripted {
        resent: std::sync::atomic::AtomicBool,
        builds: std::sync::atomic::AtomicU32,
    }

    #[async_trait]
    impl ChainAdapter for Scripted {
        fn family(&self) -> Family {
            Family::Ton
        }
        fn chain_key(&self) -> &str {
            "ton:t"
        }
        fn lanes(&self) -> &[Lane] {
            static L: std::sync::OnceLock<Vec<Lane>> = std::sync::OnceLock::new();
            L.get_or_init(|| vec![Lane { index: 0, address: "lane0".into() }])
        }
        async fn build(&self, _: &Job, _: usize) -> std::result::Result<Built, SimError> {
            self.builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(SimError::Transport("connection refused".into()))
        }
        async fn sign(&self, _: Built, _: usize, _: u64) -> Result<Signed> {
            unreachable!()
        }
        async fn submit(&self, _: &Signed) -> Result<()> {
            unreachable!("recovery has no bytes to send")
        }
        async fn tx_status(&self, tx: &str) -> Result<TxStatus> {
            match tx {
                "0x0a" => Ok(TxStatus::Mined { height: 1, tx_hash: None }),
                "0x0d" => Err(Rejected("WRONG_NONCE".into()).into()),
                "0x0e" => Ok(TxStatus::Reverted { reason: "boom".into() }),
                _ => Ok(TxStatus::Unknown),
            }
        }
        async fn sequence(&self, _: usize) -> Result<u64> {
            Ok(4)
        }
        async fn final_head(&self) -> Result<Option<Head>> {
            Ok(None)
        }
        async fn block_hash(&self, _: u64) -> Result<String> {
            unreachable!()
        }
        async fn events(&self, _: u64, _: u64, _: &[String]) -> Result<Vec<Value>> {
            unreachable!()
        }
        async fn resend_journaled(&self, _: usize) -> Result<()> {
            self.resent.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// Merge TODO b: sau crash, job lane này để lại `nonce_leased`/`signed`/`broadcast` được chốt TRƯỚC việc mới —
    /// không job nào treo mãi chặn `_live_job()` của payment request.
    #[tokio::test]
    async fn restart_settles_the_lanes_inflight_jobs() {
        let live = now() + 600;
        let job = |id: i64, state: &str, tx: Option<&str>, nonce: Option<u64>, vu: u64| serde_json::json!({
            "job_id": id, "state": state, "tx_hash": tx, "nonce": nonce,
            "payload": {"id": id, "kind": "signed_op", "op": {"valid_until": vu}}});
        let inflight = serde_json::json!([
            job(1, "nonce_leased", None, None, live),          // claimed, never signed ⇒ back to the queue
            job(2, "broadcast", Some("0x0a"), Some(3), live),  // landed while we were down ⇒ mined
            job(3, "signed", Some("0x0b"), Some(4), now() - 100), // never seen, payload expired ⇒ dead
            job(4, "signed", Some("0x0c"), Some(3), live),     // never seen, lane sequence moved on ⇒ never lands ⇒ queued
            job(5, "broadcast", Some("0x0d"), Some(4), live),  // refused without running ⇒ queued
            job(6, "broadcast", Some("0x0e"), Some(3), live),  // ran and reverted
        ]);
        let (odoo, o) = fake_odoo(Fake { inflight, tokens: serde_json::json!([]), ..Default::default() }).await;
        let a = Scripted::default();
        let run = recover_lane(&a, &odoo, 0, "n#0");
        tokio::time::timeout(Duration::from_secs(10), run).await.expect("recovery hung").unwrap();
        assert!(a.resent.load(std::sync::atomic::Ordering::SeqCst), "journaled bytes re-sent first");
        let o = o.lock().unwrap();
        let got: Vec<(i64, &str)> =
            o.reports.iter().map(|r| (r["job_id"].as_i64().unwrap(), r["chain_state"].as_str().unwrap())).collect();
        assert_eq!(got, [(1, "queued"), (2, "mined"), (3, "dead"), (4, "queued"), (5, "queued"), (6, "reverted")]);
    }

    /// Merge TODO c: RPC chết ⇒ job về hàng đợi rồi lane LÙI dần (mũ, có trần), không quay vòng claim/build.
    #[tokio::test]
    async fn transport_errors_back_off() {
        let job = serde_json::json!({"id": 9, "kind": "signed_op", "op": {}});
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job], repeat: true, tokens: serde_json::json!([]), ..Default::default() }).await;
        let a = Arc::new(Scripted::default());
        let k = Arc::new(Mutex::new(Breaker::new(crate::config::BreakerCfg::default())));
        let run = lane_runner(a.clone(), odoo, 0, "n#0".into(), Duration::from_millis(10), k, InflightSet::default());
        let _ = tokio::time::timeout(Duration::from_millis(2500), run).await;
        let n = a.builds.load(std::sync::atomic::Ordering::SeqCst);
        assert!((1..=3).contains(&n), "{n} builds in 2.5 s");
        assert!(o.lock().unwrap().reports.iter().all(|r| r["chain_state"] == "queued"));
    }

    /// Adapter giả cho R80: build/gửi/trạng thái theo kịch bản, `op_consumed` cố định.
    struct Racy {
        build_revert: bool,
        consumed: Option<bool>,
        /// Kết quả `submit` lần lượt (`true` = vào mempool); hết ⇒ lỗi mạng.
        sends: std::sync::Mutex<std::collections::VecDeque<bool>>,
        /// `tx_status` lần lượt; phần tử cuối lặp lại.
        statuses: std::sync::Mutex<std::collections::VecDeque<TxStatus>>,
        submits: std::sync::atomic::AtomicU32,
    }

    fn racy(build_revert: bool, consumed: Option<bool>, sends: &[bool], statuses: &[TxStatus]) -> Racy {
        Racy {
            build_revert,
            consumed,
            sends: std::sync::Mutex::new(sends.iter().copied().collect()),
            statuses: std::sync::Mutex::new(statuses.iter().cloned().collect()),
            submits: Default::default(),
        }
    }

    #[async_trait]
    impl ChainAdapter for Racy {
        fn family(&self) -> Family {
            Family::Sui
        }
        fn chain_key(&self) -> &str {
            "sui:t"
        }
        fn lanes(&self) -> &[Lane] {
            static L: std::sync::OnceLock<Vec<Lane>> = std::sync::OnceLock::new();
            L.get_or_init(|| vec![Lane { index: 0, address: "0xlane".into() }])
        }
        async fn build(&self, job: &Job, _: usize) -> std::result::Result<Built, SimError> {
            if self.build_revert {
                return Err(SimError::Revert("lane nonce already used".into()));
            }
            Ok(Built { job_id: job.id, body: vec![], valid_until: now() + 600, meta: Value::Null })
        }
        async fn sign(&self, b: Built, _: usize, sequence: u64) -> Result<Signed> {
            Ok(Signed { job_id: b.job_id, tx_id: "0x0f".into(), raw: vec![], valid_until: b.valid_until, sequence })
        }
        async fn submit(&self, _: &Signed) -> Result<()> {
            self.submits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match self.sends.lock().unwrap().pop_front() {
                Some(true) => Ok(()),
                _ => Err(anyhow::anyhow!("timeout")),
            }
        }
        async fn tx_status(&self, _: &str) -> Result<TxStatus> {
            let mut q = self.statuses.lock().unwrap();
            Ok(if q.len() > 1 { q.pop_front().unwrap() } else { q[0].clone() })
        }
        async fn sequence(&self, _: usize) -> Result<u64> {
            Ok(0)
        }
        async fn final_head(&self) -> Result<Option<Head>> {
            Ok(None)
        }
        async fn block_hash(&self, _: u64) -> Result<String> {
            unreachable!()
        }
        async fn events(&self, _: u64, _: u64, _: &[String]) -> Result<Vec<Value>> {
            unreachable!()
        }
        async fn op_consumed(&self, _: &Job) -> Result<Option<bool>> {
            Ok(self.consumed)
        }
    }

    const DIGEST: &str = "0x7777777777777777777777777777777777777777777777777777777777777777";

    async fn race(a: &Racy, inflight: &InflightSet) -> (Vec<String>, Shared) {
        let job = serde_json::json!({"id": 5, "kind": "signed_op", "op": {"op_kind": "pay", "digest": DIGEST}});
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job], tokens: serde_json::json!([]), ..Default::default() }).await;
        let step = step_once(a, &odoo, 0, "n#0", None, inflight);
        tokio::time::timeout(Duration::from_secs(10), step).await.expect("lane held").unwrap();
        let states = o.lock().unwrap().reports.iter().map(|r| r["chain_state"].as_str().unwrap().to_string()).collect();
        (states, o)
    }

    /// R80 (§8.4 `follow`): đã tiêu thụ trước lần gửi lại ⇒ `consumed`, KHÔNG gửi lại, vẫn theo tx tới trạng thái cuối
    /// rồi mới nhả lane (và không báo `reverted` cho revert của chính nó).
    #[tokio::test]
    async fn consumed_before_resend_stops_resending_and_releases_the_lane_at_the_end() {
        let a = racy(false, Some(true), &[], &[TxStatus::Unknown, TxStatus::Unknown, TxStatus::Reverted { reason: "nonce".into() }]);
        let set = InflightSet::default();
        let (states, _) = race(&a, &set).await;
        assert_eq!(states, ["signed", "consumed"]);
        assert_eq!(a.submits.load(std::sync::atomic::Ordering::SeqCst), 1, "never resent");
        assert!(!set.contains(&DIGEST.parse().unwrap()), "digest released with the lane");
    }

    /// Review H3: tx của ta revert vì người khác đã dùng nonce ⇒ `consumed`, không `reverted` (Odoo: failed + dependents).
    #[tokio::test]
    async fn reverted_status_of_a_consumed_op_reports_consumed() {
        let a = racy(false, Some(true), &[true], &[TxStatus::Reverted { reason: "nonce".into() }]);
        assert_eq!(race(&a, &InflightSet::default()).await.0, ["signed", "broadcast", "consumed"]);
    }

    /// Review M6: `op_consumed = None` (op không có nonce lane) không bao giờ dừng job: vẫn gửi lại, revert vẫn `reverted`.
    #[tokio::test]
    async fn unknown_consumption_never_stops_a_job() {
        let a = racy(false, None, &[false, true], &[TxStatus::Unknown, TxStatus::Mined { height: 1, tx_hash: None }]);
        assert_eq!(race(&a, &InflightSet::default()).await.0, ["signed", "broadcast", "mined"]);
        assert_eq!(a.submits.load(std::sync::atomic::Ordering::SeqCst), 2);
        let a = racy(false, None, &[true], &[TxStatus::Reverted { reason: "boom".into() }]);
        assert_eq!(race(&a, &InflightSet::default()).await.0, ["signed", "broadcast", "reverted"]);
    }

    /// TON (mesh S2): `mined` carries the hash the indexer will report (payer wallet tx), so Odoo's `final` sees ours;
    /// other families send none and Odoo keeps the signed tx id.
    #[tokio::test]
    async fn mined_report_carries_the_final_tx_hash_when_the_adapter_has_one() {
        let h = "0x".to_string() + &"ab".repeat(32);
        let a = racy(false, None, &[true], &[TxStatus::Mined { height: 1, tx_hash: Some(h.clone()) }]);
        let (_, o) = race(&a, &InflightSet::default()).await;
        let mined = o.lock().unwrap().reports.iter().find(|r| r["chain_state"] == "mined").cloned().unwrap();
        assert_eq!(mined["tx_hash"].as_str(), Some(h.as_str()));
        let a = racy(false, None, &[true], &[TxStatus::Mined { height: 1, tx_hash: None }]);
        let (_, o) = race(&a, &InflightSet::default()).await;
        let mined = o.lock().unwrap().reports.iter().find(|r| r["chain_state"] == "mined").cloned().unwrap();
        assert!(mined.get("tx_hash").is_none(), "{mined}");
    }

    /// R80 (§8.4 `step_once`): mô phỏng revert vì op đã bị tiêu thụ ⇒ `consumed`, không `dead`.
    #[tokio::test]
    async fn simulation_revert_of_a_consumed_op_reports_consumed() {
        assert_eq!(race(&racy(true, Some(true), &[], &[TxStatus::Unknown]), &InflightSet::default()).await.0, ["consumed"]);
        assert_eq!(race(&racy(true, Some(false), &[], &[TxStatus::Unknown]), &InflightSet::default()).await.0, ["dead"]);
    }

    /// Review N2: digest đang bay ở đường khác ⇒ job bị bỏ qua TRƯỚC `relay_claim` (không claim, không báo).
    #[tokio::test]
    async fn a_job_whose_digest_is_in_flight_is_skipped_before_claim() {
        let set = InflightSet::default();
        let _held = set.try_acquire(DIGEST.parse().unwrap()).unwrap();
        let a = racy(false, None, &[true], &[TxStatus::Mined { height: 1, tx_hash: None }]);
        let (states, o) = race(&a, &set).await;
        assert!(states.is_empty(), "{states:?}");
        assert_eq!(o.lock().unwrap().claims, 0);
    }
}

