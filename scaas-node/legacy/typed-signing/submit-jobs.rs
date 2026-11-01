//! Mô-đun `submit`: MỘT task mỗi chain, sở hữu duy nhất nonce vỏ (`_USER-DECISIONS` §23.1).
//!
//! Bất biến: không bao giờ bỏ một nonce (R18) — tx kẹt được thay thế với phí cao hơn; job phải
//! bỏ thì nonce của nó được lấp bằng tx 0-value tự chuyển. `final` của job KHÔNG đến từ đây mà từ
//! indexer (`MetaTransactionExecuted`), nên một meta-tx được người khác thực thi vẫn thành `final`.
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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
use crate::metatx::{addr, uint, Mtx, UaMtx};
use crate::nonce::{bump, plan, replaceable, Inflight};
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
    /// The subject as an id: an address zero-padded (`MetaTxLib.pad`), or a derived UA (`ua_metatx`).
    pub from: B256,
    pub batch: U256,
    pub nonce: U256,
    /// `None` = không biết (payload Odoo không có digest): không dedup, không nhận ra là của ta.
    pub digest: Option<B256>,
    /// A `ua_metatx` job: the UA ledger's nonce map (`uaNonce`), digest and `UAMetaTransactionExecuted`.
    pub ua: bool,
}

impl MetaRef {
    pub fn of(token: Address, m: &Mtx, digest: Option<B256>) -> Self {
        Self { token, from: m.from().into_word(), batch: m.batch(), nonce: m.nonce(), digest, ua: false }
    }

    pub fn of_ua(token: Address, m: &UaMtx, digest: Option<B256>) -> Self {
        Self { token, from: m.from(), batch: m.batch(), nonce: m.nonce(), digest, ua: true }
    }
}

/// G2 (§8.4): digest đang có tx vỏ sống trên MỘT chain, chung cho mọi lane `Submitter` (gateway đi qua lane 0) và
/// mọi `lane_runner`. Giữ bằng guard RAII nên mọi lối ra không để lại `Sent` đều nhả digest (review N2). Fix 1 (review
/// I2): the same set holds subjects: `(relay-fee jobs, other jobs)` in flight per [`crate::guard::subject_key`].
#[derive(Clone, Default)]
pub struct InflightSet(Arc<Mutex<HashSet<B256>>>, Arc<Mutex<HashMap<B256, (u32, u32)>>>);

impl InflightSet {
    /// `None` = digest đã có đường khác giữ.
    pub fn try_acquire(&self, d: B256) -> Option<InflightGuard> {
        self.0.lock().ok()?.insert(d).then(|| InflightGuard { set: self.clone(), d: Some(d), _hold: None })
    }

    pub fn contains(&self, d: &B256) -> bool {
        self.0.lock().is_ok_and(|s| s.contains(d))
    }

    /// Review I2: a relay-fee job of a subject runs alone (no other job of it in flight); any other job of the subject
    /// waits while a relay-fee job of it is in flight. `None` = held.
    pub fn hold_subject(&self, key: B256, relay: bool) -> Option<SubjectHold> {
        let mut m = self.1.lock().ok()?;
        let e = m.entry(key).or_default();
        let free = if relay { *e == (0, 0) } else { e.0 == 0 };
        if !free {
            return None;
        }
        if relay { e.0 += 1 } else { e.1 += 1 }
        Some(SubjectHold { set: self.clone(), key, relay })
    }

    /// `g` (if any) carrying the subject hold `h` too, so both end with the job.
    pub fn with_hold(&self, g: Option<InflightGuard>, h: Option<SubjectHold>) -> Option<InflightGuard> {
        match (g, h) {
            (g, None) => g,
            (Some(mut g), h) => {
                g._hold = h;
                Some(g)
            }
            (None, h) => Some(InflightGuard { set: self.clone(), d: None, _hold: h }),
        }
    }
}

pub struct InflightGuard {
    set: InflightSet,
    d: Option<B256>,
    _hold: Option<SubjectHold>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let (Some(d), Ok(mut s)) = (self.d, self.set.0.lock()) {
            s.remove(&d);
        }
    }
}

pub struct SubjectHold {
    set: InflightSet,
    key: B256,
    relay: bool,
}

impl Drop for SubjectHold {
    fn drop(&mut self) {
        if let Ok(mut m) = self.set.1.lock() {
            if let Some(e) = m.get_mut(&self.key) {
                if self.relay { e.0 -= 1 } else { e.1 -= 1 }
                if *e == (0, 0) {
                    m.remove(&self.key);
                }
            }
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
    /// A priced relay-fee job's fee ceiling (review I1): replacements never sign a max fee above it.
    ceiling: Option<u128>,
}

/// NODE-LANE-10 (R84) for the outbox: the unbound `relayer`/`feeRecipient` are normalized here as the gateway does
/// (`fee_recipient` = `[[chains]] fee_recipient`), never relayed as the job carries them. The digest is left `None`:
/// the dedup key is the token's own `mtxDigest`, read before submit (`Submitter::with_chain_digest`), never the job's.
pub fn work_from_job(job: &Job, fee_recipient: Option<Address>) -> Result<Work> {
    // T17 (one job-kind rule): an EVM job is `metatx`, `ua_metatx` or `call`; any other kind is refused, never guessed.
    if let Some(k) = job.kind.as_deref().filter(|k| !matches!(*k, "metatx" | "ua_metatx" | "call")) {
        anyhow::bail!("unknown job kind {k:?} (metatx | ua_metatx | call)");
    }
    if job.receiver_fee.is_some() {
        anyhow::bail!("receiver-pays (receiver_fee) is not built in the node; refused, never relayed without it");
    }
    if job.kind.as_deref() == Some("ua_metatx") {
        return ua_work(job, fee_recipient);
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
    let sig = hex_bytes(sig)?;
    let valid_until = m.valid_until().saturating_to();
    let meta = Some(MetaRef::of(token, &m, None));
    let data = match pay_meta(job)? {
        None => m.calldata(sig),
        Some((salt, pm, on_chain)) => m.pay_meta_calldata(salt, pm, sig, on_chain)?,
    };
    Ok(Work { job_id: Some(job.id), to: token, data, valid_until, meta, entry: false })
}

fn hex_bytes(s: &str) -> Result<Bytes> {
    Ok(alloy::hex::decode(s.strip_prefix("0x").unwrap_or(s))?.into())
}

/// A pay-meta job's `(salt, meta, on chain)` (CTR-MTX-26); `None` for a plain job, an error for half of one.
fn pay_meta(job: &Job) -> Result<Option<(B256, Bytes, bool)>> {
    match (&job.salt, &job.meta) {
        (None, None) => Ok(None),
        (Some(salt), Some(pm)) => {
            let salt = B256::try_from(&hex_bytes(salt)?[..]).map_err(|_| anyhow::anyhow!("salt is 32 bytes"))?;
            Ok(Some((salt, hex_bytes(pm)?, job.meta_offchain != Some(true))))
        }
        _ => anyhow::bail!("a pay-meta job carries both salt and meta"),
    }
}

/// A `ua_metatx` job (job-api.md, CTR-UA-26): `{token, struct, m, auth}` (+ `salt` / `meta` for `uaPayMeta`), relayed
/// as `uaExecute` / `uaExecuteTransfer` / `uaPayMeta` of the normalized struct on the token's UA ledger.
fn ua_work(job: &Job, fee_recipient: Option<Address>) -> Result<Work> {
    if job.metatx.is_some() || job.signature.is_some() || job.entry.is_some() || job.call.is_some() {
        anyhow::bail!("a ua_metatx job is {{token, struct, m, auth}}: no metatx, signature, entry or call");
    }
    let (Some(m), Some(token), Some(auth)) = (&job.m, job.token, &job.auth) else {
        anyhow::bail!("ua_metatx job {} without token, m or auth", job.id);
    };
    let mut m = UaMtx::from_wire(job.struct_.as_deref(), m)?;
    m.normalize(fee_recipient);
    let auth = hex_bytes(auth)?;
    let data = match pay_meta(job)? {
        None => m.calldata(auth),
        Some((salt, pm, on_chain)) => m.pay_meta_calldata(salt, pm, auth, on_chain)?,
    };
    let meta = Some(MetaRef::of_ua(token, &m, None));
    Ok(Work { job_id: Some(job.id), to: token, data, valid_until: m.valid_until().saturating_to(), meta, entry: false })
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
