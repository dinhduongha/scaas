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
use alloy::sol_types::SolValue;
use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::abi::PqzRefusal;
use crate::breaker::Breaker;
use crate::chain::{Chain, SimError};
use crate::config::ChainCfg;
use crate::guard::{self, Guard, Refusal};
use crate::metatx::{Mtx, UaMtx};
use crate::nonce::{bump, plan, replaceable, Inflight};
use crate::odoo::{Job, Odoo, Report};
use crate::typed::{hex_refused, parse, Op, Typed};

/// A 0-value self-transfer: 21,000 before Amsterdam, 12,000 under EIP-2780 (no recipient charge for the sender
/// itself; the SCaaS testnet's value transfer to another account used 21,000 = 12,000 + 3,000 + 6,000), so 21,000 fits both.
const GAP_FILL_GAS: u64 = 21_000;
/// Nhịp lấy mẫu base fee + số dư lane cho cầu dao (R55).
const SAMPLE_EVERY: Duration = Duration::from_secs(15);
/// §8.5: số khối gần nhất tìm `MetaTransactionExecuted` khi phân loại một meta-tx đã bị tiêu thụ.
/// ponytail: cửa sổ cố định; ghi khối lúc claim vào `Sent` nếu tx kẹt lâu hay ra `unknown`.
const CLASSIFY_LOOKBACK: u64 = 1_000;
/// Group 3g: how far back a party's `UAPqzKeyCurrent` counts as "since intake" for `PQZ_KEY_ROTATED`.
// ponytail: a fixed window, not the job's own intake block (the pull path carries none); a job older than this window that
// meets a rotation is reported `dead` with `ProofRejected`; use the job's claim block once the node's own queue carries it
const ROTATION_LOOKBACK: u64 = 10_000;

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
    /// A named entry ([`crate::typed::Op`]): the guard reads its row; else a transfer struct (`meta`).
    pub entry: bool,
    /// What the calldata signs and the rule's contract kind, built with `data`; `None` only for a job with no `data` yet.
    pub typed: Option<Typed>,
}

impl Work {
    /// The typed digest once `guard::fill_digest` has run.
    pub fn digest(&self) -> Option<B256> {
        self.typed.as_ref()?.digest
    }

    /// The second half of the in-flight key: the bytes sent. The typed digest depends on `contract`, which the calldata does
    /// not carry, and on two digest-only fields of the Zether owner ops; one call never flies twice under another claim.
    pub fn call_key(&self) -> B256 {
        alloy::primitives::keccak256([&b"scaas.node.call"[..], self.to.as_slice(), &self.data].concat())
    }
}

/// Meta-tx bên trong `Work`: đủ để đọc nonce chủ thể (R80) và nhận ra digest trong event (§8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaRef {
    pub token: Address,
    /// The subject as an id: an address zero-padded (`MetaTxLib.pad`), or a derived UA (`ua_metatx`).
    pub from: B256,
    pub batch: U256,
    pub nonce: U256,
    /// The typed digest, computed here (`guard::fill_digest`); `None` until then.
    pub digest: Option<B256>,
    /// A `ua_metatx` job: a merged entry or a struct on ids (`UaMtx`), its `UAMetaTransactionExecuted`.
    pub ua: bool,
    /// The subject's nonce is `mtxNonce(address, batch)` (`SmartKeyAccount`, `IMetaTxAddress`); else `mtxNonce(bytes32, batch)`
    /// (tokens, the router, the mandate wallets: one nonce map on ids, ua-mtx-merge plan T14).
    pub addr_nonce: bool,
}

impl MetaRef {
    pub fn of(token: Address, m: &Mtx, digest: Option<B256>) -> Self {
        Self { token, from: m.from().into_word(), batch: m.batch(), nonce: m.nonce(), digest, ua: false, addr_nonce: false }
    }

    pub fn of_ua(token: Address, m: &UaMtx, digest: Option<B256>) -> Self {
        Self { token, from: m.from(), batch: m.batch(), nonce: m.nonce(), digest, ua: true, addr_nonce: false }
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
        self.0.lock().ok()?.insert(d).then(|| InflightGuard { set: self.clone(), d: Some(d), call: None, _hold: None })
    }

    /// G2 for a typed op: the typed digest and the bytes sent, both free or neither taken.
    pub fn try_acquire_op(&self, d: B256, call: B256) -> Option<InflightGuard> {
        let mut s = self.0.lock().ok()?;
        if s.contains(&d) || s.contains(&call) {
            return None;
        }
        s.insert(d);
        s.insert(call);
        Some(InflightGuard { set: self.clone(), d: Some(d), call: Some(call), _hold: None })
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
            (None, h) => Some(InflightGuard { set: self.clone(), d: None, call: None, _hold: h }),
        }
    }
}

pub struct InflightGuard {
    set: InflightSet,
    d: Option<B256>,
    call: Option<B256>,
    _hold: Option<SubjectHold>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Ok(mut s) = self.set.0.lock() {
            for k in [self.d, self.call].into_iter().flatten() {
                s.remove(&k);
            }
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

/// One job, one `Work` (job-api.md): a named `op`, or a transfer struct. NODE-LANE-10 (R84): the unbound `relayer` /
/// `feeRecipient` are normalized here (`fee_recipient` = `[[chains]] fee_recipient`), never relayed as the job carries them.
/// The dedup key is the typed digest of what is built here (`guard::fill_digest`), never the job's `digest` field.
pub fn work_from_job(job: &Job, fee_recipient: Option<Address>) -> Result<Work> {
    // T17 (one job-kind rule): an EVM job is `metatx`, `ua_metatx` or `call`; any other kind is refused, never guessed.
    if let Some(k) = job.kind.as_deref().filter(|k| !matches!(*k, "metatx" | "ua_metatx" | "call")) {
        anyhow::bail!("unknown job kind {k:?} (metatx | ua_metatx | call)");
    }
    if job.receiver_fee.is_some() {
        anyhow::bail!("receiver-pays (receiver_fee) goes as the named entry mtxPayReceiverFee; refused, never relayed without it");
    }
    if job.call.is_some() || job.calldata.is_some() || job.data.is_some() {
        return Err(hex_refused("call"));
    }
    if job.struct_.as_deref() == Some("call") {
        return Err(hex_refused("struct = call"));
    }
    if [&job.metatx, &job.m].into_iter().flatten().any(|m| m.get("data").is_some()) {
        return Err(hex_refused("data"));
    }
    if let Some(op) = &job.op {
        return op_work(job, op, fee_recipient);
    }
    if job.kind.as_deref() == Some("ua_metatx") {
        return ua_work(job, fee_recipient);
    }
    if job.metatx.is_some() {
        // R43 / CTR-MTX-30: an address `MetaTransfer` names the token's `mtxExecuteTransfer(MetaTransfer, bytes)` (or the address
        // `mtxPayMeta`), which no token has left; refused by name, never relayed to a revert (legacy/ua-mtx-merge/submit.rs)
        anyhow::bail!("OP_KIND_MISMATCH: a metatx job's MetaTransfer names the address mtxExecuteTransfer, no token entry since the \
            merged entries: send ua_metatx with m (UAMetaTransfer, from / to bytes32 ids) and auth (UASig)");
    }
    anyhow::bail!("job {} has neither an op nor a transfer struct", job.id)
}

/// The domain of a transfer struct: the job's `contract`, a token kind.
pub fn transfer_typed(contract: Option<&str>, token: Address, struct_hash: B256, signer: Option<(Address, Bytes)>) -> Result<Typed> {
    let contract = match contract.unwrap_or("token") {
        "token" => "token",
        "zether" => "zether",
        "pqz" => "pqz",
        c => anyhow::bail!("BAD_PAYLOAD: contract {c:?} (token | zether | pqz)"),
    };
    Ok(Typed { pay_meta_len: 0, pqz_parties: vec![], pqz_auditor: false, pqz_verdict: None, contract, domain_of: token, struct_hash: Some(struct_hash), lane_hash: None, signer, payee: None, digest: None,
        derived_signer: false, derived_side: false })
}

/// A named entry: everything comes out of one [`Op::parse`]; a job carries it or a transfer struct, never both.
fn op_work(job: &Job, op: &serde_json::Value, fee_recipient: Option<Address>) -> Result<Work> {
    if job.metatx.is_some() || job.m.is_some() || job.signature.is_some() || job.auth.is_some() || job.token.is_some() {
        anyhow::bail!("BAD_PAYLOAD: an op job is {{kind, op}}: token, signature and auth live in the op");
    }
    let (w, ua) = work_of_op(Some(job.id), op, fee_recipient)?;
    // R43: the per-kind call table: a merged entry (a `UA*` struct) is a `ua_metatx` job, an address entry a `metatx` one
    if (job.kind.as_deref() == Some("ua_metatx")) != ua {
        let want = if ua { "ua_metatx" } else { "metatx" };
        anyhow::bail!("OP_KIND_MISMATCH: {} ({}) is no entry of a {:?} job: the call table lists it for {want}", op["entry"], op["struct"], job.kind);
    }
    Ok(w)
}

/// `(work, a ua* entry)`, one [`Op::parse`]: the job path and the gateway.
pub fn work_of_op(job_id: Option<i64>, op: &serde_json::Value, fee_recipient: Option<Address>) -> Result<(Work, bool)> {
    let p = Op::parse(op, fee_recipient)?;
    let ua = p.row.ua();
    let addr_nonce = p.typed.contract == "account";
    let meta = p.lane.map(|(from, batch, nonce)| MetaRef { token: p.to, from, batch, nonce, digest: None, ua, addr_nonce });
    Ok((Work { job_id, to: p.to, data: p.data, valid_until: p.valid_until, meta, entry: true, typed: Some(p.typed) }, ua))
}

/// A `ua_metatx` struct job (job-api.md, CTR-UA-26, CTR-MTX-30): `{token, m, auth}`, relayed as `mtxExecuteTransfer` of the
/// normalized struct on ids (pay-meta-tax O12: the generic path, any `entryRef`, no metadata); `auth` the `UASig` object. A
/// pay with its `PayMeta` is the named entry `mtxPay` (`{op}`, spec §7.1): the old `salt` + hex `meta` form is refused
/// `HEX_ARGS_REFUSED` (`legacy/ua-mtx-merge/3e/submit.rs`). A native `from` and `to` run at `registry() == 0` (R9); a derived
/// side needs the UA ledger (R44, the guard).
fn ua_work(job: &Job, fee_recipient: Option<Address>) -> Result<Work> {
    if job.metatx.is_some() || job.signature.is_some() {
        anyhow::bail!("a ua_metatx job is {{token, m, auth}} or {{op}}: no metatx or signature");
    }
    let (Some(m), Some(token), Some(auth)) = (&job.m, job.token, &job.auth) else {
        anyhow::bail!("ua_metatx job {} without op, or token, m and auth", job.id);
    };
    let mut m = UaMtx::from_wire(job.struct_.as_deref(), m)?;
    m.normalize(fee_recipient);
    let auth = crate::abi::UASig::abi_decode(&parse("UASig", auth, "auth")?.abi_encode())?;
    let native_sig = (auth.keyData.is_empty() && auth.members.is_empty()).then(|| auth.signature.clone());
    let signer = crate::metatx::native(&m.from()).zip(native_sig);
    let mut typed = transfer_typed(job.contract.as_deref(), token, m.struct_hash(), signer)?;
    let to = match &m { UaMtx::Transfer(t) => Some(t.to), UaMtx::Call(_) => None };
    typed.derived_signer = crate::metatx::native(&m.from()).is_none();
    typed.derived_side = typed.derived_signer || to.is_some_and(|t| crate::metatx::native(&t).is_none());
    let typed = Some(typed);
    if job.salt.is_some() || job.meta.is_some() || job.meta_offchain.is_some() {
        anyhow::bail!("HEX_ARGS_REFUSED: salt / meta: a pay goes as its named entry {{op: {{entry: \"mtxPay\", args: {{…, meta: \
            {{salt, payNo, schema, body: named fields}}}}}}}}, never a hex meta");
    }
    let data = m.calldata(auth);
    let meta = Some(MetaRef::of_ua(token, &m, None));
    Ok(Work { job_id: Some(job.id), to: token, data, valid_until: m.valid_until().saturating_to(), meta, entry: false, typed })
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
                Ok(mut w) => {
                    if let Err(e) = guard::fill_digest(&me.chain, &mut w).await {
                        anyhow::bail!("typed digest: {e:?}");
                    }
                    Some(w)
                }
                Err(_) => None,
            };
            // review T4 m2: a rebuilt payload is re-signed by `track`, so it passes the guard too; refused ⇒ that
            // nonce is only ever gap-filled
            let work = match work {
                Some(mut w) => match me.guard.check(&me.chain, &w).await {
                    // group 3f: a replacement re-signs the bytes, so a PQZ debit gets its verdict again; none ⇒ gap-filled only
                    Ok(()) => match me.guard.pqz_fill(&me.chain, &mut w).await {
                        Ok(()) => Some(w),
                        Err(r) => {
                            warn!(job = j.job_id, nonce = n, "tracked PQZ job without a verdict ({r:?}); its nonce is only gap-filled");
                            None
                        }
                    },
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
            let sent = me.chain.tx_fees(hash).await.ok().flatten();
            let gas = match sent {
                Some((g, _)) => g,
                None => guard::total_cap(me.cfg.max_gas_per_tx, me.chain.block_gas().await?),
            };
            // review I1: a priced relay-fee job is re-checked before it is ever re-signed: its ceiling is now the tracked
            // transaction's max fee (the first send's ceiling is not journaled, and this one was signed under it); a
            // fee that does not cover gas x that fee, an unknown fee, or an OP-stack chain (the L1 fee of the tracked
            // bytes is not re-read) leaves the nonce to the gap-fill
            let (work, ceiling) = match work {
                Some(w) => match me.guard.relay_priced(me.chain.address(), &w) {
                    Ok(false) => (Some(w), None),
                    priced => {
                        let covered = match (priced, sent.and_then(|s| s.1)) {
                            (Ok(true), Some(max_fee)) if !me.guard.op_stack() =>
                                me.guard.relay_covers(me.chain.address(), &w, gas, max_fee, 0).is_ok().then_some(max_fee),
                            _ => None,
                        };
                        if covered.is_none() {
                            warn!(job = j.job_id, nonce = n, "tracked relay-fee job not covered at its signed fee; its nonce is only gap-filled");
                        }
                        (covered.map(|_| w), covered)
                    }
                },
                None => (None, None),
            };
            // Tập in-flight dựng lại từ việc đang theo dõi (§8.6).
            let guard = work.as_ref().and_then(|w| me.digests.try_acquire_op(w.digest()?, w.call_key()));
            let hold = work.as_ref().and_then(|w| me.guard.subject(w)).and_then(|(k, relay)| me.digests.hold_subject(k, relay));
            let guard = me.digests.with_hold(guard, hold);
            let orphan = work.is_none().then_some(j.job_id);
            me.inflight.insert(n, Sent { work, hashes: vec![hash], gas, fees, at: Instant::now(), _guard: guard, orphan, ceiling });
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
        self.inflight.insert(nonce, Sent { work: None, hashes: vec![hash], gas: GAP_FILL_GAS, fees, at: Instant::now(), _guard: None, orphan: None, ceiling: None });
        warn!(nonce, "gap-filled");
        Ok(())
    }

    /// The guard first (PAY-FIX2, NODE-GW-07: before any read of the target, simulation or signature), then the typed
    /// digest, computed here; G2: a digest or the same bytes with a live transaction on another path (another lane, the
    /// gateway) is not signed twice.
    pub async fn submit(&mut self, w: Work) {
        match self.guard.check(&self.chain, &w).await {
            Ok(()) => {}
            Err(Refusal::Policy(reason)) => return self.fail(&w, reason).await,
            Err(Refusal::Transport(reason)) => return self.requeue(&w, reason).await,
        }
        let mut w = w;
        // group 3f (spec §11.1): a PQZ debit's verdict, rebuilt by the node, before the digest and any simulation
        match self.guard.pqz_fill(&self.chain, &mut w).await {
            Ok(()) => {}
            Err(Refusal::Policy(reason)) => return self.fail(&w, reason).await,
            Err(Refusal::Transport(reason)) => return self.requeue(&w, reason).await,
        }
        match guard::fill_digest(&self.chain, &mut w).await {
            Ok(()) => {}
            Err(SimError::Revert(r)) => return self.fail(&w, r).await,
            Err(SimError::Transport(r)) => return self.requeue(&w, format!("chain_uid: {r}")).await,
        }
        let guard = match w.digest() {
            None => None,
            Some(d) => match self.digests.try_acquire_op(d, w.call_key()) {
                Some(g) => Some(g),
                None => return self.requeue(&w, "in flight on another path".into()).await,
            },
        };
        // review I2: a relay-fee job of a subject and the jobs that can lower its balance never fly together
        let hold = match self.guard.subject(&w) {
            None => None,
            Some((key, relay)) => match self.digests.hold_subject(key, relay) {
                Some(h) => Some(h),
                None => return self.requeue(&w, "SUBJECT_HELD: a relay-fee job and another job of its payer are never in \
                                                 flight together".into()).await,
            },
        };
        let guard = self.digests.with_hold(guard, hold);
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
        let priced = match self.guard.relay_priced(self.chain.address(), &w) {
            Ok(p) => p,
            Err(Refusal::Policy(r)) => return self.fail(&w, r).await,
            Err(Refusal::Transport(r)) => return self.requeue(&w, r).await,
        };
        let nonce = self.next;
        let (raw, hash) = match self.chain.sign(nonce, w.to, w.data.clone(), gas, fees).await {
            Ok(x) => x,
            Err(e) => return self.requeue(&w, format!("{e:#}")).await,
        };
        // review I1 / I3: a priced relay fee covers the quote at the job's fee ceiling (FEE_HEADROOM x this max fee,
        // which every replacement stays under) plus the L1 data fee of this very transaction; nothing is sent otherwise
        let ceiling = guard::fee_ceiling(fees.0);
        if priced {
            let covered = match self.guard.l1_fee(&self.chain, &raw).await {
                Ok(l1) => self.guard.relay_covers(self.chain.address(), &w, gas, ceiling, l1),
                Err(e) => Err(e),
            };
            match covered {
                Ok(()) => {}
                Err(Refusal::Policy(r)) => return self.fail(&w, r).await,
                Err(Refusal::Transport(r)) => return self.requeue(&w, r).await,
            }
        }
        let ceiling = priced.then_some(ceiling);
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
        self.inflight.insert(nonce, Sent { work: Some(w), hashes: vec![hash], gas, fees, at: Instant::now(), _guard: guard, orphan: None, ceiling });
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
            // regulated-kinds spec §7: a freeze, a pause, an eligibility or the registry may lift and the payload may still
            // land (here later, or by another relayer): a named refusal, back in the queue, never `dead`
            Ok(false) if crate::abi::regulated_refusal(&reason).is_some() => {
                self.requeue(w, format!("REGULATED_REFUSED: {reason}")).await
            }
            // group 3f (spec §11.1): a PQZ verifier mode refusal by name, never `dead` while the op may land with another verdict
            Ok(false) if crate::abi::pqz_verdict_refusal(&reason).is_some() => self.pqz_refused(w, reason).await,
            // group 3g (spec §7.3): the PQZ key-version reverts by name; a stale debit or two equal keys never land, a version
            // above current may become current, a proof built before a party's rotation is `PQZ_KEY_ROTATED`, never `dead`
            Ok(false) => match crate::abi::pqz_refusal(&reason) {
                Some(PqzRefusal::Stale) => self.fail(w, format!("PQZ_KEY_STALE: {reason}")).await,
                Some(PqzRefusal::Reused) => self.fail(w, format!("PQZ_KEY_REUSED: {reason}")).await,
                Some(PqzRefusal::Unknown) => self.requeue(w, format!("PQZ_KEY_VERSION_UNKNOWN: {reason}")).await,
                Some(PqzRefusal::ProofRejected) => match guard::pqz_rotated(&self.chain, w, ROTATION_LOOKBACK).await {
                    Ok(true) => self.requeue(w, format!("PQZ_KEY_ROTATED: {reason}")).await,
                    Ok(false) => self.fail(w, reason).await,
                    Err(e) => self.requeue(w, format!("PQZ_KEY_ROTATED read: {e:#}; {reason}")).await,
                },
                None => self.fail(w, reason).await,
            },
            Err(e) => self.requeue(w, format!("mtxNonce: {e:#}")).await,
        }
    }

    /// Group 3f (spec §11.1): a verdict, epoch, `eta` or registration may lift it: back in the queue (`PQZ_KEY_ROTATED` for a
    /// `PqzVerdictMismatch` after a party's indexed `UAPqzKeyCurrent`, T55); the op's own shape never lands: `dead`.
    async fn pqz_refused(&self, w: &Work, reason: String) {
        let Some((name, liftable)) = crate::abi::pqz_verdict_refusal(&reason) else { return self.fail(w, reason).await };
        if name == "PqzVerdictMismatch" {
            match guard::pqz_rotated(&self.chain, w, ROTATION_LOOKBACK).await {
                Ok(true) => return self.requeue(w, format!("PQZ_KEY_ROTATED: {reason}")).await,
                Ok(false) => {}
                Err(e) => return self.requeue(w, format!("PQZ_KEY_ROTATED read: {e:#}; {reason}")).await,
            }
        }
        if liftable {
            self.requeue(w, format!("PQZ_VERDICT_REFUSED: {reason}")).await
        } else {
            self.fail(w, reason).await
        }
    }

    /// R80: `mtxNonce(from, batch) > nonce` ⇔ nonce chủ thể của meta-tx đã bị dùng (bởi ai thì `classify`).
    /// `Ok(false)` cho job `call`. Lỗi RPC ⇒ `Err`: người gọi không bump, không kết luận (fail closed).
    async fn consumed(&self, w: &Work) -> Result<bool> {
        let Some(m) = &w.meta else { return Ok(false) };
        Ok(self.chain.subject_nonce(m).await? > m.nonce)
    }

    /// §8.5 — chỉ là nhãn cho `last_error` ở Odoo; `landed_elsewhere` do indexer quyết khi `final`.
    async fn classify(&self, m: &MetaRef) -> &'static str {
        match self.chain.meta_executed(m, CLASSIFY_LOOKBACK).await {
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

    /// N2: the job's typed digest or bytes are in flight on another path.
    async fn held(&self, job: &Job) -> bool {
        let Ok(mut w) = work_from_job(job, self.cfg.fee_recipient) else { return false };
        // an unreadable chain_uid: not known to be held, the submit path answers for it
        let _ = guard::fill_digest(&self.chain, &mut w).await;
        w.digest().is_some_and(|d| self.digests.contains(&d) || self.digests.contains(&w.call_key()))
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
            // review I1: a live priced relay-fee job never signs above its fee ceiling (at it, it waits and expires; the
            // gap-fill that then takes the nonce is the operator's cap, it runs no job)
            let live_now = s.work.as_ref().is_some_and(|w| w.valid_until > now());
            let cap = u128::from(self.cfg.max_fee_cap_gwei) * 1_000_000_000;
            let cap = match s.ceiling.filter(|_| live_now) {
                Some(c) => cap.min(c),
                None => cap,
            };
            let fees = (bump(s.fees.0, cap), bump(s.fees.1, cap));
            if !replaceable(s.fees, fees) {
                // Ở trần phí: một bản thay thế cùng giá (or a clamped step under +10 %, fix 2) bị node từ chối
                // (underpriced). Chờ, không spam RPC; vẫn không bỏ nonce (review I10).
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
            if self.held(&job).await {
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
pub(crate) mod tests {
    use std::collections::HashMap;

    use alloy::consensus::{Transaction as _, TxEnvelope};
    use alloy::eips::eip2718::Decodable2718;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use crate::abi::UASig;
    use alloy::sol_types::{SolCall, SolValue};
    use serde_json::{json, Value};

    use super::*;
    use crate::abi::{IToken, MetaTransfer, UAMetaTransfer};
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
        /// `mtxNonce(bytes32, batch)`, the token's one view on ids (ua-mtx-merge): `None` ⇒ lỗi RPC. The address view
        /// `mtxNonce(address, batch)` is `SmartKeyAccount`'s: a token answers it with a revert here.
        mtx_nonce: Option<u64>,
        /// Số tx của lane đã vào khối (`latest` = `pending`).
        count: u64,
        receipts: HashMap<B256, bool>,
        /// (hash, to, input) mỗi lần `eth_sendRawTransaction`.
        sent: Vec<(B256, Address, Bytes)>,
        /// Every method asked, in order.
        calls: Vec<String>,
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
        /// This address's code is an EIP-7702 designator `0xef0100 ‖ 0x55…55` (an EOA, not a contract signer).
        designator: Option<Address>,
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
        /// `registry()` answers 0: the token's UA ledger is off.
        ua_off: bool,
        /// The `maxFeePerGas` of each sent tx.
        fees: Vec<u128>,
        /// `GasPriceOracle.getL1Fee` answers this (`None`: it reverts, no oracle).
        l1_fee: Option<u64>,
        /// `eth_getTransactionByHash` also answers this `maxFeePerGas`.
        tx_max_fee: Option<u128>,
        /// Group 3g: `pqzKeyLatest(ua)` of every UA (current is version 0, key `PQZ_KEY0`; `pqzKeyAt` answers `PQZ_KEY1`).
        pqz_latest: u64,
        /// `PQZ_KEY1`'s code is one byte longer than `PQZ_KEY0`'s (a version of another set's length).
        pqz_other_len: bool,
        /// `eth_getLogs` for `UAPqzKeyCurrent` answers one log (a party rotated).
        pqz_rotated: bool,
        /// Group 3f: `pqzVerifyConfig()` answers `(mode, verifier, epoch)`; `None`: it reverts (a token without the view).
        pqz_cfg: Option<(u8, B256, u32)>,
        /// Group 3f: the input of every `eth_call` to a PQZ view (`pqzVerifyConfig`, `proofSystemId`, `envelopeBinding`, the
        /// statement views), in order.
        views: Vec<Vec<u8>>,
        /// Every address whose code was asked (`eth_getCode`).
        code_asked: Vec<Address>,
    }
    /// Group 3f: what the fake token's views answer: its `proofSystemId()`, the relayed op's `envelopeBinding`, the statement.
    const PSID: B256 = B256::repeat_byte(0x9d);
    const BINDING: B256 = B256::repeat_byte(0xb1);
    const STATEMENT: [u8; 40] = [0x5a; 40];
    /// The PQZ views of the fake token: `pqzVerifyConfig`, `proofSystemId`, `envelopeBinding`, the four statement views (the forge
    /// artifact's selectors, pinned in `pqz::tests::views_are_the_contracts`).
    // group 3h T59: the four statement views after `ownTag` (pqz.rs `views_are_the_contracts`)
    const PQZ_VIEWS: [[u8; 4]; 7] = [[0xdc, 0x59, 0xc6, 0x6e], [0x1f, 0x3b, 0x28, 0xf2], [0x35, 0xad, 0x08, 0xaa], [0x93, 0x14, 0x15, 0xee],
        [0x8a, 0x21, 0x61, 0xba], [0xda, 0x8c, 0x9e, 0xed], [0x8e, 0x4c, 0xcf, 0x2e]];
    const PQZ_KEY0: Address = Address::repeat_byte(0xe0);
    const PQZ_KEY1: Address = Address::repeat_byte(0xe1);
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
            e.calls.push(r["method"].as_str().unwrap().to_string());
            let out: Result<Value, Value> = match r["method"].as_str().unwrap() {
                "eth_getTransactionCount" => Ok(json!(format!("{:#x}", e.count))),
                // Nethermind 2.2.0's estimate-stage answer for a call over 2^24 regular gas (at its 100 M RPC gas cap)
                "eth_estimateGas" if e.sim == Some("estimate_oog") => Err(err(-32000, "gas required exceeds allowance (100000000)", None)),
                "eth_estimateGas" if e.sim == Some("estimate_down") => Err(err(-32000, "upstream timeout", None)),
                "eth_estimateGas" => Ok(json!(format!("{:#x}", e.estimate.unwrap_or(0x30000)))),
                "eth_getTransactionByHash" => Ok(e.tx_gas.map_or(Value::Null, |g| {
                    let mut t = json!({"gas": format!("{g:#x}")});
                    if let Some(f) = e.tx_max_fee {
                        t["maxFeePerGas"] = json!(format!("{f:#x}"));
                    }
                    t
                })),
                "eth_getBlockByNumber" if p[0] == "latest" && e.block_err => Err(err(-32000, "upstream timeout", None)),
                "eth_feeHistory" => Ok(json!({"oldestBlock": "0x1", "baseFeePerGas": ["0x3b9aca00", "0x3b9aca00"],
                    "gasUsedRatio": [0.5], "reward": [["0x3b9aca00"]]})),
                "eth_blockNumber" => Ok(json!("0x10")),
                "eth_getLogs" if e.pqz_rotated && p[0]["topics"][0] == json!(format!("{:#x}",
                    <crate::abi::IUARegistry::UAPqzKeyCurrent as alloy::sol_types::SolEvent>::SIGNATURE_HASH)) => Ok(json!([{
                    "address": p[0]["address"].clone(), "topics": [p[0]["topics"][0].clone(), format!("{:#x}", B256::repeat_byte(1)),
                        format!("{:#x}", B256::from(U256::from(1)))],
                    "data": "0x", "blockNumber": "0x9", "blockHash": format!("{:#x}", B256::repeat_byte(9)),
                    "transactionHash": format!("{:#x}", B256::repeat_byte(8)), "transactionIndex": "0x0", "logIndex": "0x0",
                    "removed": false}])),
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
                    e.code_asked.push(a);
                    Ok(json!(if a == PQZ_KEY0 || a == PQZ_KEY1 { format!("0x00{}", "42".repeat(4 + usize::from(e.pqz_other_len && a == PQZ_KEY1))) }
                             else if e.designator == Some(a) { format!("0xef0100{}", "55".repeat(20)) }
                             else if e.contract_signer || e.code_only == Some(a) { "0x6001".into() } else { "0x".into() }))
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
                    } else if sel == crate::abi::IGasPriceOracle::getL1FeeCall::SELECTOR {
                        assert_eq!(p[0]["to"].as_str().map(str::to_lowercase), Some(format!("{:#x}", guard::GAS_PRICE_ORACLE)));
                        e.l1_fee.map(|f| word(U256::from(f))).ok_or_else(|| err(3, "execution reverted", Some("0x".into())))
                    } else if sel == crate::abi::IUARegistry::pqzKeyOfCall::SELECTOR {
                        Ok(json!(format!("0x{}", alloy::hex::encode(crate::abi::IUARegistry::pqzKeyOfCall::abi_encode_returns(
                            &crate::abi::IUARegistry::pqzKeyOfReturn { version: 0, ptr: PQZ_KEY0, pqzPopHash: B256::ZERO, proven: true })))))
                    } else if sel == crate::abi::IUARegistry::pqzKeyLatestCall::SELECTOR {
                        Ok(word(U256::from(e.pqz_latest)))
                    } else if sel == crate::abi::IUARegistry::pqzKeyAtCall::SELECTOR {
                        Ok(json!(format!("0x{}", alloy::hex::encode(crate::abi::IUARegistry::pqzKeyAtCall::abi_encode_returns(
                            &crate::abi::IUARegistry::pqzKeyAtReturn { ptr: PQZ_KEY1, pqzPopHash: B256::ZERO, proven: false })))))
                    } else if PQZ_VIEWS.contains(&<[u8; 4]>::try_from(&sel[..]).unwrap()) {
                        // group 3f: the views a PQZ debit's verdict is rebuilt from
                        let input = alloy::hex::decode(&input[2..]).unwrap();
                        e.views.push(input.clone());
                        let s4: [u8; 4] = sel[..].try_into().unwrap();
                        if s4 == crate::abi::IPqzToken::pqzVerifyConfigCall::SELECTOR {
                            match e.pqz_cfg {
                                None => Err(err(3, "execution reverted", Some("0x".into()))),
                                Some((mode, verifier, epoch)) => Ok(json!(format!("0x{}", alloy::hex::encode(
                                    crate::abi::IPqzToken::pqzVerifyConfigCall::abi_encode_returns(&crate::abi::IPqzToken::PqzVerifyConfig {
                                        pqzVerifyMode: mode, verifier, fixed_: false, pqzVerifierEpoch: epoch, pending: B256::ZERO, eta: 0,
                                        noticePeriod: 0 }))))),
                            }
                        } else if s4 == crate::abi::IPqzToken::proofSystemIdCall::SELECTOR {
                            Ok(json!(format!("{PSID:#x}")))
                        } else if s4 == crate::abi::IPqzToken::envelopeBindingCall::SELECTOR {
                            Ok(json!(format!("{BINDING:#x}")))
                        } else {
                            Ok(json!(format!("0x{}", alloy::hex::encode(Bytes::from(STATEMENT.to_vec()).abi_encode()))))
                        }
                    } else if sel == crate::abi::IPqzToken::auditorUACall::SELECTOR {
                        Ok(json!(format!("{:#x}", B256::repeat_byte(0xa7))))
                    } else if sel == crate::abi::IUALedger::registryCall::SELECTOR {
                        Ok(word(U256::from(if e.ua_off { 0 } else { 0x5ca0_0001u64 })))
                    } else if sel == crate::abi::IMtxIds::mtxNonceCall::SELECTOR {
                        e.mtx_nonce.map(|n| word(U256::from(n))).ok_or_else(|| err(-32000, "upstream timeout", None))
                    } else if sel == IToken::mtxNonceCall::SELECTOR {
                        Err(err(3, "execution reverted", Some("0x".into()))) // no address view on a token
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
                            // a regulated token's refusals (regulated-kinds spec §3.1)
                            Some("frozen") => {
                                let data = crate::abi::IRegulatedToken::Frozen { account: B256::repeat_byte(0xf1) };
                                let data = alloy::sol_types::SolError::abi_encode(&data);
                                Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
                            }
                            Some("registry_unavailable") => {
                                let data = crate::abi::IRegulatedToken::RegistryUnavailable { registry: Address::repeat_byte(0xc0) };
                                let data = alloy::sol_types::SolError::abi_encode(&data);
                                Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
                            }
                            // group 3g: a PQZ token's key-version reverts
                            Some(k @ ("proof_rejected" | "stale" | "reused" | "unknown")) => {
                                let ua = B256::repeat_byte(0xab);
                                let data = match k {
                                    "proof_rejected" => alloy::sol_types::SolError::abi_encode(&crate::abi::IPqzToken::ProofRejected {}),
                                    "stale" => alloy::sol_types::SolError::abi_encode(&crate::abi::IPqzToken::StaleKeyVersion { ua, keyVersion: 0, current: 1 }),
                                    "reused" => alloy::sol_types::SolError::abi_encode(&crate::abi::IPqzToken::KeyReused { ua }),
                                    _ => alloy::sol_types::SolError::abi_encode(&crate::abi::IPqzToken::KeyVersionUnknown { ua, keyVersion: 2 }),
                                };
                                Err(err(3, "execution reverted", Some(format!("0x{}", alloy::hex::encode(data)))))
                            }
                            // group 3f: the token refuses the verdict the node rebuilt (here: field 3, the statement moved)
                            Some("verdict_mismatch") => {
                                let data = alloy::sol_types::SolError::abi_encode(&crate::abi::IPqzToken::PqzVerdictMismatch { field: 3 });
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
                    e.fees.push(tx.max_fee_per_gas());
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

    /// The payer's (a native id: an EOA padded) `UAMetaTransfer` (ua-mtx-merge: an EOA's transfer is the struct on ids).
    fn meta(batch: u64) -> UaMtx {
        UaMtx::Transfer(UAMetaTransfer {
            from: payer().into_word(),
            to: Address::repeat_byte(0x5e).into_word(),
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

    /// The address `MetaTransfer` an EOA signed before the merged entries: no token entry takes it (refused by name).
    fn addr_meta(batch: u64) -> Mtx {
        let UaMtx::Transfer(t) = meta(batch) else { unreachable!() };
        Mtx::Transfer(MetaTransfer { from: payer(), to: Address::from_word(t.to), value: t.value, entryRef: t.entryRef, batch: t.batch,
            nonce: t.nonce, validUntil: t.validUntil, mode: t.mode, relayer: t.relayer, fee: t.fee, feeRecipient: t.feeRecipient })
    }

    /// The fake client's registered tokens: `TOKEN`.
    fn toks() -> Value {
        json!([{"address": format!("{TOKEN:#x}"), "decimals": 6}])
    }

    /// The payer's transfer job: `ua_metatx`, `auth` its native `UASig` (the `0x11…` sentinel [`resign`] replaces).
    fn job(id: i64) -> Value {
        let (kind, wire) = meta(7).to_wire();
        json!({"id": id, "kind": "ua_metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
               "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}, "m": wire})
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

    /// Regulated-kinds spec §7: a simulation revert `Frozen` is a named refusal, never `dead` while the payload may still land
    /// (an unfreeze, another relayer): the job goes back `queued` with the error named, nothing sent. A spent subject nonce is
    /// still `consumed` first, an unreadable one still `queued`.
    #[tokio::test]
    async fn frozen_revert_is_refusal_not_dead() {
        for (nonce, want) in [(Some(0), "queued"), (Some(1), "consumed"), (None, "queued")] {
            let (url, rpc) = fake_evm(Evm { sim: Some("frozen"), mtx_nonce: nonce, ..Default::default() }).await;
            let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: toks(), ..Default::default() }).await;
            lane(&url, odoo, 1, InflightSet::default()).await.poll_outbox().await;
            assert_eq!(states(&o), [want], "mtxNonce {nonce:?}");
            assert!(rpc.lock().unwrap().sent.is_empty());
            if nonce == Some(0) {
                let err = o.lock().unwrap().reports[0]["error"].as_str().unwrap().to_string();
                assert!(err.starts_with("REGULATED_REFUSED: Frozen("), "{err}");
            }
        }
    }

    /// As `Frozen`: `RegistryUnavailable` (the token's bounded registry call failed) is a refusal, named, never `dead`.
    #[tokio::test]
    async fn registry_unavailable_is_refusal() {
        let (url, rpc) = fake_evm(Evm { sim: Some("registry_unavailable"), mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: toks(), ..Default::default() }).await;
        lane(&url, odoo, 1, InflightSet::default()).await.poll_outbox().await;
        assert_eq!(states(&o), ["queued"]);
        let err = o.lock().unwrap().reports[0]["error"].as_str().unwrap().to_string();
        assert!(err.starts_with("REGULATED_REFUSED: RegistryUnavailable("), "{err}");
        assert!(rpc.lock().unwrap().sent.is_empty());
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
        let call = |target: Address, data: Vec<u8>| call_job(9, target, data);
        // a lane's own token balance never leaves: `transfer` is no entry, there is no hex path to it
        let steal = IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1) }.abi_encode();
        let (st, err, sent, _) = run(Evm { mtx_nonce: Some(0), ..Default::default() }, vec![call(TOKEN, steal)], None).await;
        assert_eq!((st.as_str(), sent), ("dead", 0));
        assert!(err.contains("UNKNOWN_ENTRY"), "{err}");
        // a row on a target it does not name: `mtxSettle` on a registered token
        let settle = settle_calldata();
        let (st, err, ..) = run(Evm::default(), vec![call(TOKEN, settle.clone())], Some(TOKEN)).await;
        assert_eq!(st, "dead");
        assert!(err.starts_with("CALL_TARGET_REFUSED"), "{err}");
        // a meta-transaction on a contract of another chain
        let (st, err, sent, _) = run(Evm { uid: Some(0x25), mtx_nonce: Some(0), ..Default::default() }, vec![job(7)], None).await;
        assert_eq!((st.as_str(), sent), ("dead", 0));
        assert!(err.starts_with("CHAIN_UID_MISMATCH"), "{err}");
        // an order entry on a contract of another chain
        let inv_on = |token: Address| inv_job(8, token);
        let (st, err, sent, _) = run(Evm { uid: Some(0x25), ..Default::default() }, vec![inv_on(TOKEN)], None).await;
        assert_eq!((st.as_str(), sent), ("dead", 0));
        assert!(err.starts_with("CHAIN_UID_MISMATCH"), "{err}");
        // an invalidation already in force is done, never dead
        let (st, err, sent, _) = run(Evm { sim: Some("min_nonce"), ..Default::default() }, vec![inv_on(TOKEN)], None).await;
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
        let len = rpc.lock().unwrap().sent[0].2.len();
        assert_eq!(rpc.lock().unwrap().gas[0], guard::erc1271_floor(len));
    }

    /// The token's invalidation on ids (R12, R38): a merged entry, a `ua_metatx` job.
    fn inv_job(id: i64, token: Address) -> Value {
        json!({"id": id, "kind": "ua_metatx", "op": {"entry": "mtxInvalidateNonces", "contract": "token", "token": format!("{token:#x}"),
            "args": {"from": format!("{:#x}", payer().into_word()), "batch": "1", "minNonce": "9"},
            "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}, "validUntil": (now() + 300).to_string()}})
    }

    /// The token's order entries on ids (R12, R38: `UATradeOrder`, `UASig`) as `ua_metatx` jobs (job-api.md): the cancel and the
    /// invalidation of every signer row of `uatrade_kat.json` (clientkeys, cross-checked by forge's `UATradeVectors.t.sol`) give its
    /// digests; their bytes are `typed_ops_kat_every_entry`'s (`CancelUAOrder`) and `invalidate_digests_match_the_vectors`'.
    #[test]
    fn entry_jobs_encode_as_the_token_reads_them() {
        let k: Value = serde_json::from_str(include_str!("../../smartcontracts/vectors/ua/uatrade_kat.json")).unwrap();
        let (chain, uid) = (k["chainId"].as_u64().unwrap(), k["chainUid"].as_str().unwrap().parse::<B256>().unwrap());
        let job = |op: Value| -> Job { serde_json::from_value(json!({"id": 1, "kind": "ua_metatx", "op": op})).unwrap() };
        let auth = |s: &Value| json!({"keyData": "0x", "signature": s, "members": []});
        let native = k["rows"].as_array().unwrap().iter().find(|r| r["name"] == "native").unwrap();
        let token = native["order"]["domain"]["verifyingContract"].clone();
        let op = json!({"entry": "mtxCancelOrder", "struct": "CancelUAOrder", "contract": "token", "token": token,
            "args": {"order": native["order"]["message"]}, "auth": auth(&native["cancelAuth"]), "validUntil": "1800000300"});
        let w = work_from_job(&job(op.clone()), None).unwrap();
        assert_eq!((w.valid_until, w.meta, w.entry), (1_800_000_300, None, true));
        assert_eq!(format!("{:#x}", w.typed.as_ref().unwrap().digest_on(chain, uid).unwrap()), native["cancelDigest"].as_str().unwrap());
        let inv = json!({"entry": "mtxInvalidateNonces", "contract": "token", "token": token, "validUntil": "1800000300",
            "args": native["invalidate"]["message"], "auth": auth(&native["invalidateAuth"])});
        let w = work_from_job(&job(inv), None).unwrap();
        assert_eq!(format!("{:#x}", w.typed.as_ref().unwrap().digest_on(chain, uid).unwrap()), native["invalidateDigest"].as_str().unwrap());
        // mtxTrade is never a job; an order that is not one; the address form of the cancel is gone (legacy/ua-mtx-merge)
        for (bad, why) in [(json!({"entry": "mtxTrade", "contract": "token", "token": token}), "UNKNOWN_ENTRY"),
            (json!({"entry": "mtxCancelOrder", "struct": "CancelOrder", "contract": "token", "token": token, "signature": "0x00"}), "UNKNOWN_ENTRY"),
            (json!({"entry": "mtxCancelOrder", "struct": "CancelUAOrder", "contract": "token", "token": token, "auth": auth(&json!("0x"))}), "args.order: missing"),
            (json!({"entry": "mtxCancelOrder", "struct": "CancelUAOrder", "contract": "token", "token": token, "args": {"order": {}}, "auth": auth(&json!("0x"))}), "args.order.from: missing")] {
            assert!(work_from_job(&job(bad), None).unwrap_err().to_string().contains(why), "{why}");
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
        let mut w = work_from_job(&serde_json::from_value(resign(job(0))).unwrap(), None).unwrap();
        w.job_id = None; // the gateway's path
        a.submit(w.clone()).await;
        b.poll_outbox().await;
        a.submit(w).await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 1);
        let claims = o.lock().unwrap().claims;
        assert_eq!((claims, states(&o).len()), (0, 0), "skipped before relay_claim");

        let (url, _) = fake_evm(Evm { sim: Some("transport"), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![job(8)], tokens: toks(), ..Default::default() }).await;
        let set = InflightSet::default();
        let want = {
            let j: Job = serde_json::from_value(resign(job(8))).unwrap();
            work_from_job(&j, None).unwrap().typed.unwrap().digest_on(31337, B256::from(U256::from(UID))).unwrap()
        };
        lane(&url, odoo, 1, set.clone()).await.poll_outbox().await;
        assert_eq!(states(&o), ["queued"]);
        assert!(!set.contains(&want), "released on a transient error");
    }

    /// NODE-LANE-10 for every origin (review T2 I1): an outbox job's unbound `feeRecipient`/`relayer` never reach the
    /// chain as the job carries them; receiver-pays is refused, not dropped (m5); the in-flight key is the token's
    /// digest, never the job's `digest` (m6).
    #[tokio::test]
    async fn outbox_jobs_are_normalized_and_keyed_by_the_token_digest() {
        let (thief, ours) = (Address::repeat_byte(0x7e), Address::repeat_byte(0x99));
        let UaMtx::Transfer(mut t) = meta(7) else { unreachable!() };
        (t.mode, t.fee, t.feeRecipient, t.relayer) = (0x20, U256::from(1_000u64), thief, thief); // FIXED fee, nothing bound
        let raw = |t: &UAMetaTransfer| {
            let mut j = job(1);
            j["digest"] = json!(format!("0x{}", "99".repeat(32)));
            j["m"] = UaMtx::Transfer(t.clone()).to_wire().1;
            j
        };
        let unbound = |m: &UaMtx| match m { UaMtx::Transfer(t) => (t.feeRecipient, t.relayer), UaMtx::Call(c) => (c.feeRecipient, c.relayer) };
        let sent = |v: Value, fr: Option<Address>| {
            let w = work_from_job(&serde_json::from_value(v).unwrap(), fr).unwrap();
            assert_eq!(w.meta.unwrap().digest, None, "never the job's digest");
            UaMtx::from_calldata(&w.data).unwrap().0
        };
        let m = sent(raw(&t), Some(ours));
        assert_eq!(unbound(&m), (ours, Address::ZERO));
        let m = sent(raw(&t), None);
        assert_eq!(unbound(&m), (Address::ZERO, Address::ZERO), "unset: the contract pays msg.sender");
        let bound = UAMetaTransfer { mode: 0x23, ..t.clone() };
        assert_eq!(sent(raw(&bound), Some(ours)), UaMtx::Transfer(bound.clone()), "bound fields are the signer's");
        let mut rf = raw(&t);
        rf["receiver_fee"] = json!({"fee": "1", "feeRecipient": format!("{thief:#x}"), "validUntil": "1", "signature": "0x"});
        assert!(work_from_job(&serde_json::from_value(rf).unwrap(), None).is_err(), "receiver-pays is not built");
        // through the lane: normalized on chain, keyed by the typed digest computed here
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![raw(&t)], tokens: toks(), ..Default::default() }).await;
        let set = InflightSet::default();
        let mut s = lane(&url, odoo, 1, set.clone()).await;
        s.poll_outbox().await;
        assert_eq!(states(&o), ["signed", "broadcast"]);
        let held = work_from_job(&serde_json::from_value(resign(raw(&t))).unwrap(), None).unwrap().typed.unwrap();
        assert!(set.contains(&held.digest_on(31337, B256::from(U256::from(UID))).unwrap()), "held while in flight");
        assert!(!set.contains(&B256::repeat_byte(0x99)), "the job's own digest is no key");
        let m = UaMtx::from_calldata(&rpc.lock().unwrap().sent[0].2).unwrap().0;
        assert_eq!(unbound(&m), (Address::ZERO, Address::ZERO));
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

    /// A named op job for calldata as the old `call` job carried it: a plain row's fields, a relay fee with a named inner call,
    /// an entry with no row as itself.
    fn call_job(id: i64, target: Address, data: Vec<u8>) -> Value {
        let until = (now() + 300).to_string();
        let sel: [u8; 4] = data[..4].try_into().unwrap();
        if sel == crate::abi::IMtxRelayFee::relayCall::SELECTOR {
            // one `relay` on ids (R28): a native payer's own key (the `0x11…` sentinel [`resign`] replaces), a derived one's 96 bytes
            let c = crate::abi::IMtxRelayFee::relayCall::abi_decode(&data).unwrap();
            let args = json!({"from": format!("{:#x}", c.from), "payee": format!("{:#x}", c.payee), "value": c.value.to_string(),
                "batch": c.batch.to_string(), "nonce": c.nonce.to_string(), "validUntil": c.validUntil.to_string(),
                "relayer": format!("{target:#x}")});
            let sig = if crate::metatx::native(&c.from).is_some() { "11".repeat(65) } else { "22".repeat(96) };
            return json!({"id": id, "kind": "ua_metatx", "op": {"entry": "mtxRelayFee", "contract": "token", "token": format!("{:#x}", c.token),
                "args": args, "call": inner_op(), "auth": {"keyData": "0x", "signature": format!("0x{sig}"), "members": []}}});
        }
        let row = crate::typed::rows().iter().find(|r| !r.typed && r.selector == sel);
        let op = match row {
            Some(r) => crate::typed::call_op(r.contracts[0], target, &data, &until).unwrap(),
            None => json!({"entry": "transfer", "token": format!("{target:#x}"), "args": {}, "validUntil": until}),
        };
        json!({"id": id, "kind": "call", "op": op})
    }

    /// The relayed call of the relay-fee jobs: a named entry on `TARGET`, fee 0, the executor's to run.
    fn inner_op() -> Value {
        json!({"entry": "mtxCancelNonce", "contract": "token", "token": format!("{TARGET:#x}"), "args": {"lane": "9"},
            "envelope": {"from": format!("{:#x}", payer().into_word()), "batch": "1", "nonce": "0", "validUntil": (now() + 600).to_string(), "mode": 0,
                "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)},
            "auth": {"keyData": "0x", "signature": format!("0x{}", "22".repeat(65)), "members": []}})
    }

    fn settle_calldata() -> Vec<u8> {
        crate::abi::ISCaaSDex::mtxSettleCall { s: vec![] }.abi_encode()
    }

    fn deploy_job(id: i64, target: Address) -> Value {
        let z = format!("{:#x}", B256::ZERO);
        json!({"id": id, "kind": "call", "op": {"entry": "deploy", "token": format!("{target:#x}"), "validUntil": (now() + 300).to_string(),
            "args": {"firstKey": {"kind": 0, "x": z, "y": z, "rpIdHash": z, "originHash": z}, "guardian": format!("{:#x}", Address::ZERO)}}})
    }

    fn owner_job(id: i64, target: Address) -> Value {
        json!({"id": id, "kind": "call", "op": {"entry": "mtxExecuteAsOwner", "contract": "account", "token": format!("{target:#x}"),
            "validUntil": (now() + 300).to_string(),
            "args": {"data": "0x", "nonce": "0", "validUntil": (now() + 300).to_string(), "sig": format!("0x{}", "11".repeat(65))}}})
    }

    /// Every job kind refuses hex by name; a job one change away passes (the positive controls are the jobs below).
    #[test]
    fn hex_data_refused() {
        let v = crate::typed::testkit::vectors();
        let op = crate::typed::testkit::op_of("UAUnwrap", "token", &v).unwrap();
        let ok = |j: Value| work_from_job(&serde_json::from_value::<Job>(j).unwrap(), None);
        ok(json!({"id": 1, "kind": "ua_metatx", "op": op})).unwrap();
        ok(job(7)).unwrap();
        let refused = |j: Value, what: &str| {
            let e = ok(j).unwrap_err().to_string();
            assert!(e.starts_with("HEX_DATA_REFUSED"), "{what}: {e}");
        };
        let mut hexop = op.clone();
        hexop["calldata"] = json!("0x1234");
        refused(json!({"id": 1, "kind": "metatx", "op": hexop}), "op.calldata");
        let mut hexarg = op.clone();
        hexarg["args"]["data"] = json!("0x1234");
        refused(json!({"id": 1, "kind": "metatx", "op": hexarg}), "op.args.data");
        refused(json!({"id": 1, "kind": "call", "call": {"target": format!("{TOKEN:#x}"), "calldata": "0x1234", "validUntil": "1"}}), "call");
        refused(json!({"id": 1, "kind": "call", "calldata": "0x1234"}), "top-level calldata");
        refused(json!({"id": 1, "kind": "metatx", "data": "0x1234"}), "top-level data");
        refused(json!({"id": 1, "kind": "metatx", "op": "0x1234"}), "op as hex");
        let mut hexcall = op.clone();
        hexcall["call"] = json!("0x1234");
        refused(json!({"id": 1, "kind": "metatx", "op": hexcall}), "op.call as hex");
        let mut m = job(7);
        m["metatx"] = m["m"].take();
        m["metatx"]["data"] = json!("0x1234");
        refused(m, "metatx.data");
        let mut m = job(7);
        m["struct"] = json!("call");
        refused(m, "struct = call");
        let u = ua_job(7, &ua_meta(7));
        ok(u.clone()).unwrap();
        let mut m = u.clone();
        m["struct"] = json!("call");
        refused(m, "ua_metatx struct = call");
        let mut m = u;
        m["m"]["data"] = json!("0x1234");
        refused(m, "ua_metatx m.data");
        // a merged entry is a `ua_metatx` job only (R43)
        let e = ok(json!({"id": 1, "kind": "metatx", "op": op})).unwrap_err().to_string();
        assert!(e.starts_with("OP_KIND_MISMATCH"), "{e}");
    }

    /// A job, by its kind's JSON, through serde and `work_from_job`, read back from the bytes: every row of the vector file.
    /// Fields come back as sent, so nothing was dropped, defaulted or reordered on the way; a second parse gives the same digest.
    #[test]
    fn job_api_explicit_json_roundtrip() {
        use crate::typed::testkit::{op_from_calldata, op_of, row_of, vectors};
        let v = vectors();
        let mut n = 0;
        for (name, o) in v["ops"].as_object().unwrap() {
            for kind in o["domains"].as_object().unwrap().keys() {
                let Some(mut op) = op_of(name, kind, &v) else { continue };
                let row = row_of(name, kind);
                if matches!(row.name, "UAPayUnderMandate" | "UADelegateRevoke") {
                    op["envelope"]["nonce"] = json!("0");
                    op["envelope"]["batch"] = json!(match row.name {
                        "UAPayUnderMandate" => crate::typed::mandate_pay_lane(&crate::typed::testkit::hex(&op["args"]["entryRef"])),
                        _ => crate::typed::mandate_revoke_lane(op["args"]["token"].as_str().unwrap().parse().unwrap(),
                            op["args"]["epoch"].as_str().unwrap().parse().unwrap()),
                    }.to_string());
                }
                let job: Job = serde_json::from_str(&json!({"id": 3, "kind": if row.ua() { "ua_metatx" } else { "metatx" }, "op": op}).to_string()).unwrap();
                let w = work_from_job(&job, None).unwrap_or_else(|e| panic!("{name} on {kind}: {e:#}"));
                let (env, mut args, sig) = op_from_calldata(row, &w.data);
                for k in ["accSeq", "modeNonce"].iter().filter(|_| matches!(row.name, "ZetherRollOver" | "ZetherSetRollOverMode")) {
                    if let Some(x) = op["args"].get(*k) {
                        args[*k] = x.clone();
                    }
                }
                assert_eq!(env.as_ref(), op.get("envelope"), "{name}");
                assert_eq!(args.to_string().to_lowercase(), op["args"].to_string().to_lowercase(), "{name}");
                assert_eq!(sig.as_ref(), op.get("signature").or(op.get("auth")), "{name}");
                let mut again = op.clone();
                again["args"] = args;
                if let Some(e) = env {
                    again["envelope"] = e;
                }
                let p = Op::parse(&again, None).unwrap();
                assert_eq!((p.data, Some(p.typed.struct_hash)), (w.data.clone(), w.typed.as_ref().map(|t| t.struct_hash)), "{name}");
                assert_eq!(w.to, op["token"].as_str().unwrap().parse::<Address>().unwrap(), "{name}");
                n += 1;
            }
        }
        // plan T34 added the router's eight regulated control rows to typed_ops.json (97 -> 105); pay-meta-tax T41: -> 110
        // (UAPayWithTax's three domains, the router's two tax ops); group 3f T46 / T47: -> 113, the router's three verifier ops
        // group 3h T61: -> 114, the router's `UASetProofStore`
        assert_eq!(n, 114, "every row with an entry, but the relay fees (relay_fee_call_object)");
    }

    /// `EvmAdapter::call_key`, which the Hedera adapter delegates to (`the_hedera_lane_skips_bytes_already_in_flight` is the
    /// production path): a job whose call flies under another claimed `contract` is skipped before the claim; the same job with the
    /// set free is claimed (the control); a plain entry has no key of its own.
    #[tokio::test]
    async fn evm_call_key_follows_the_bytes() {
        use crate::adapter::ChainAdapter;
        let ua = |contract: &str| -> Value {
            json!({"id": 9, "kind": "ua_metatx", "op": {"entry": "mtxBurn", "contract": contract, "token": format!("{TOKEN:#x}"), "args": {"amount": "5"},
                "envelope": {"from": format!("{UA:#x}"), "batch": "9", "nonce": "0", "validUntil": "4000000000", "mode": 0,
                    "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)},
                "auth": {"keyData": "0x", "signature": format!("0x{}", "22".repeat(96)), "members": []}}})
        };
        let (url, _) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let cfg = test_cfg(&url);
        let chain = Chain::with_signer(&cfg, PrivateKeySigner::from_bytes(&B256::repeat_byte(1)).unwrap()).unwrap();
        let a = crate::adapters::evm::EvmAdapter::new(&cfg, vec![chain], Arc::new(std::sync::RwLock::new(vec![TOKEN]))).unwrap();
        let of = |j: Value| serde_json::from_value::<Job>(j).unwrap();
        let w = work_from_job(&of(ua("token")), None).unwrap();
        assert_eq!(a.call_key(&of(ua("pqz"))), Some(w.call_key()), "the claim moves the digest, not the bytes");
        assert_eq!(a.call_key(&of(deploy_job(9, TOKEN))), None, "no typed digest, no key");
        let held = InflightSet::default();
        let _flying = held.try_acquire_op(B256::repeat_byte(0x71), w.call_key()).unwrap();
        let (odoo, o) = fake_odoo(Fake { jobs: vec![ua("pqz")], tokens: toks(), ..Default::default() }).await;
        // bounded both ways: if `call_key` regresses the job is claimed and follows a transaction until its `validUntil`
        let _ = tokio::time::timeout(Duration::from_secs(2), crate::adapter::step_once(&a, &odoo, 0, "n#0", None, &held)).await;
        assert_eq!(o.lock().unwrap().claims, 0, "skipped before the claim");
        let (odoo, o) = fake_odoo(Fake { jobs: vec![ua("pqz")], tokens: toks(), ..Default::default() }).await;
        // the claimed job goes on to wait for a receipt the fake never gives: only the claim is this test's
        let _ = tokio::time::timeout(Duration::from_secs(2), crate::adapter::step_once(&a, &odoo, 0, "n#0", None, &InflightSet::default())).await;
        assert_eq!(o.lock().unwrap().claims, 1, "the control");
    }

    /// A fixed op (its `validUntil` does not follow the clock, so two calls are one digest).
    fn op_job(id: i64) -> Value {
        let env = json!({"from": format!("{:#x}", payer().into_word()), "batch": "7", "nonce": "0", "validUntil": "4000000000", "mode": 0,
            "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)});
        json!({"id": id, "kind": "ua_metatx", "op": {"entry": "mtxBurn", "contract": "token", "token": format!("{TOKEN:#x}"),
            "envelope": env, "args": {"amount": "5"}, "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}}})
    }

    /// G2 by the digest computed here: no contract is read for it, two lanes sign one op once, both keys are held, and it
    /// is the digest of `digest_on`. Under another claimed `contract` the digest differs but the bytes do not: still one send.
    #[tokio::test]
    async fn dedup_by_typed_digest() {
        let set = InflightSet::default();
        let e = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let (url, rpc) = fake_evm(e()).await;
        let (odoo, o) = fake_odoo(Fake { jobs: vec![op_job(7)], tokens: toks(), ..Default::default() }).await;
        let mut a = lane(&url, odoo.clone(), 1, set.clone()).await;
        a.poll_outbox().await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 1, "{:?}", o.lock().unwrap().reports);
        let job0: Job = serde_json::from_value(resign(op_job(7))).unwrap();
        let mut w = work_from_job(&job0, None).unwrap();
        let chain = Chain::with_signer(&test_cfg(&url), PrivateKeySigner::from_bytes(&B256::repeat_byte(2)).unwrap()).unwrap();
        let views = || rpc.lock().unwrap().calls.iter().filter(|m| *m == "eth_call").count();
        let calls = views();
        guard::fill_digest(&chain, &mut w).await.unwrap();
        let d = w.digest().unwrap();
        assert_eq!(views(), calls, "no contract is asked for the digest: only the cached chain_uid");
        let want = w.typed.as_ref().unwrap().digest_on(31337, B256::from(U256::from(UID))).unwrap();
        assert_eq!((d, w.meta.unwrap().digest), (want, Some(want)));
        assert!(set.contains(&d), "the key held is the typed digest");
        assert!(set.contains(&w.call_key()), "and the bytes");
        // the same op, the same digest: another lane does not sign it
        let (odoo2, o2) = fake_odoo(Fake { jobs: vec![op_job(8)], tokens: toks(), ..Default::default() }).await;
        let mut b = lane(&url, odoo2, 2, set.clone()).await;
        b.poll_outbox().await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 1, "one op, one send");
        assert_eq!(o2.lock().unwrap().claims, 0, "skipped before the claim");
        // the same bytes under another `contract`: the digest moved, the bytes did not: not signed twice (a UA signer, so no
        // local signature check catches the claim first)
        let ua = |contract: &str| {
            let mut j = call_job(9, ROUTER, ua_relay_data(ROUTER.into_word(), 1_000));
            j["op"] = json!({"entry": "mtxBurn", "contract": contract, "token": format!("{TOKEN:#x}"), "args": {"amount": "5"},
                "envelope": {"from": format!("{UA:#x}"), "batch": "9", "nonce": "0", "validUntil": "4000000000", "mode": 0,
                    "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)},
                "auth": {"keyData": "0x", "signature": format!("0x{}", "22".repeat(96)), "members": []}});
            j
        };
        let set = InflightSet::default();
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, _) = fake_odoo(Fake { jobs: vec![ua("token")], tokens: toks(), ..Default::default() }).await;
        let mut first = lane(&url, odoo, 1, set.clone()).await;
        first.poll_outbox().await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 1, "the control sends");
        let (odoo, o) = fake_odoo(Fake { jobs: vec![ua("pqz")], tokens: toks(), ..Default::default() }).await;
        lane(&url, odoo, 2, set).await.poll_outbox().await;
        assert_eq!(rpc.lock().unwrap().sent.len(), 1, "one call, one send");
        assert_eq!(o.lock().unwrap().claims, 0, "skipped before the claim");
    }

    /// A signature the fake chain's payer really made: the sentinel `0x11…` of a job the payer signs becomes the real one over
    /// the typed digest of the job as it stands, so a test that changes a field keeps a valid job.
    pub(crate) fn resign(mut j: Value) -> Value {
        let uid = B256::from(U256::from(UID));
        let Ok(job) = serde_json::from_value::<Job>(j.clone()) else { return j };
        let Ok(w) = work_from_job(&job, None) else { return j };
        let Some(t) = &w.typed else { return j };
        let Some((who, sig)) = &t.signer else { return j };
        if *who != payer() || sig[..] != [0x11; 65] {
            return j;
        }
        let d = t.digest_on(31337, uid).unwrap();
        let s = format!("0x{}", alloy::hex::encode(payer_key().sign_hash_sync(&d).unwrap().as_bytes()));
        let at = if j.get("op").is_some() { &mut j["op"] } else { &mut j };
        if at.get("auth").is_some() {
            at["auth"]["signature"] = json!(s);
        } else {
            at["signature"] = json!(s);
        }
        j
    }

    fn payer_key() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0x55)).unwrap()
    }

    fn payer() -> Address {
        payer_key().address()
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
        let (r, rpc) = outcomes(Evm::default(), vec![inv_job(8, other)], |_| {}).await;
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
        let settle = settle_calldata();
        for (j, want) in [(deploy_job(9, x), "dead"), (deploy_job(9, af), "broadcast"), (call_job(9, x, settle.clone()), "dead"),
                          (call_job(9, dex, settle.clone()), "broadcast"), (owner_job(9, tf), "dead"), (owner_job(9, x), "broadcast")] {
            let (r, _) = outcomes(ok(), vec![j.clone()], cfg).await;
            assert_eq!(r.last().unwrap().0, want, "{j}: {r:?}");
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
        let (_, rpc) = outcomes(Evm { code_only: Some(payer()), ..ok() }, vec![job(7)], |_| {}).await;
        let len = rpc.lock().unwrap().sent[0].2.len();
        assert_eq!(rpc.lock().unwrap().gas, vec![guard::erc1271_floor(len)]);
        // an EIP-7702 designator signer is an EOA (ECDSA only, owner ruling 2026-10-30): no 1271 floor
        let (_, rpc) = outcomes(Evm { designator: Some(payer()), ..ok() }, vec![job(7)], |_| {}).await;
        assert_eq!(rpc.lock().unwrap().gas, vec![0x30000 * 6 / 5], "a designator signer gets no 1271 floor");
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
        // (named fields pad to 32 B: the nearest lengths around the 261,910 B limit, 261,924 and 261,892 B)
        let deploy = |n: usize| crate::abi::IUARegistry::storePqzPopCall { ua: B256::repeat_byte(1), version: 0, pqzPop: vec![0u8; n - 132].into() }.abi_encode();
        assert_eq!((deploy(261_924).len(), deploy(261_892).len()), (261_924, 261_892));
        let fac = move |c: &mut ChainCfg| { c.max_gas_per_tx = 64_000_000; c.ua_registry = Some(af); };
        let (r, rpc) = outcomes(ok(), vec![call_job(9, af, deploy(261_924))], fac).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("calldata floor 16778136 above the 2^24 regular gas"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = outcomes(ok(), vec![call_job(9, af, deploy(261_892))], fac).await;
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
        let big = crate::abi::IUARegistry::storePqzPopCall { ua: B256::repeat_byte(1), version: 0, pqzPop: vec![0u8; 261_792].into() }.abi_encode();
        let fac = move |c: &mut ChainCfg| { c.max_gas_per_tx = 64_000_000; c.ua_registry = Some(af); };
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
        assert!(matches!(a.build(&j, 0).await, Err(SimError::Revert(r)) if r.contains("UNKNOWN_ENTRY")));
        let j: Job = serde_json::from_value(deploy_job(9, TOKEN)).unwrap();
        assert!(matches!(a.build(&j, 0).await, Err(SimError::Revert(r)) if r.starts_with("CALL_TARGET_REFUSED")));
        let j: Job = serde_json::from_value(resign(job(7))).unwrap();
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
        o.lock().unwrap().jobs = vec![resign(job(7))];
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

    /// A pay job (pay-meta-tax spec §7.1): `{op: {entry: "mtxPay", token, args: {t, meta}, auth}}`, `meta` named per schema; the
    /// payment's `entryRef` the commitment of that `meta` (`tweak` edits the payment, `meta` the meta).
    fn pay_job(id: i64, pm: Value, tweak: impl FnOnce(&mut UAMetaTransfer)) -> Value {
        let UaMtx::Transfer(mut t) = meta(7) else { unreachable!() };
        t.entryRef = op_meta_id(&pm);
        tweak(&mut t);
        let (_, wire) = UaMtx::Transfer(t).to_wire();
        json!({"id": id, "kind": "ua_metatx", "op": {"entry": "mtxPay", "contract": "token", "token": format!("{TOKEN:#x}"),
            "args": {"t": wire, "meta": pm}, "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}}})
    }

    /// `metaPayId` of a job's named `meta`, as the node builds it.
    fn op_meta_id(meta: &Value) -> B256 {
        let v = crate::typed::parse("PayMeta", meta, "meta").unwrap();
        crate::metatx::meta_pay_id(&crate::typed::pay_meta_of(&v).unwrap())
    }

    fn structured() -> Value {
        json!({"salt": format!("{:#x}", B256::repeat_byte(0x51)), "payNo": "INV-2026-0042", "schema": 2,
            "body": {"creditorRef": "RF18539007547034", "dueDate": "1830297600"}})
    }

    /// pay-meta-tax T42 (`pay_job_named_meta_builds_body`, `pay_job_free_lane_accepted`): the named meta's schema 2 body is
    /// `abi.encode(string creditorRef, uint64 dueDate)` and its commitment the paymeta.json row's; the pay is relayed as
    /// `mtxPay(t, auth, meta)` on any lane (O3: lane 7, nonce 3 too, no `payLane` check).
    #[tokio::test]
    async fn pay_job_named_meta_builds_body() {
        let v: Value = serde_json::from_str(include_str!("../../smartcontracts/vectors/metatx/paymeta.json")).unwrap();
        let row = v.as_array().unwrap().iter().find(|r| r["name"] == "structured_reference").unwrap();
        let named = json!({"salt": row["salt"], "payNo": row["payNo"], "schema": 2,
            "body": {"creditorRef": "RF18539007547034", "dueDate": "1830297600"}});
        assert_eq!(format!("{:#x}", op_meta_id(&named)), row["payId"].as_str().unwrap(), "the forge row's commitment");
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let (r, rpc) = outcomes(ok(), vec![pay_job(7, named.clone(), |_| {})], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let sent = rpc.lock().unwrap().sent[0].2.clone();
        let c = crate::abi::IMtxIds::mtxPayCall::abi_decode(&sent).unwrap();
        assert_eq!(format!("0x{}", alloy::hex::encode(&c.meta.body)), row["body"].as_str().unwrap());
        assert_eq!((c.meta.payNo.as_str(), c.meta.schema), ("INV-2026-0042", 2));
        assert_eq!(c.t.entryRef, op_meta_id(&named));
        let (r, _) = outcomes(Evm { mtx_nonce: Some(3), ..Default::default() }, vec![pay_job(7, named, |t| t.nonce = U256::from(3))],
            |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "a free lane: nonce 3, no payLane check: {r:?}");
    }

    /// `pay_job_hex_meta_refused`, `pay_job_payno_257_refused`, `PAY_META_MISMATCH`, `ENTRY_RETIRED`: refused by name before any
    /// RPC; the old `salt` + hex `meta` struct job too.
    #[tokio::test]
    async fn pay_job_refusals_by_name() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let refused = |r: &[(String, String)], what: &str| assert!(r[0].0 == "dead" && r[0].1.contains(what), "{what}: {r:?}");
        let mut hexed = structured();
        hexed["body"] = json!("0x1234");
        let mut bad = pay_job(7, structured(), |_| {});
        bad["op"]["args"]["meta"] = hexed;
        let (r, rpc) = outcomes(ok(), vec![bad], |_| {}).await;
        refused(&r, "HEX_ARGS_REFUSED");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let mut long = structured();
        long["payNo"] = json!("A".repeat(257));
        let mut bad = pay_job(7, structured(), |_| {});
        bad["op"]["args"]["meta"] = long;
        refused(&outcomes(ok(), vec![bad], |_| {}).await.0, "PAY_NO_TOO_LONG");
        refused(&outcomes(ok(), vec![pay_job(7, structured(), |t| t.entryRef = B256::repeat_byte(0x42))], |_| {}).await.0,
            "PAY_META_MISMATCH");
        let mut retired = pay_job(7, structured(), |_| {});
        retired["op"]["entry"] = json!("mtxPayMeta");
        refused(&outcomes(ok(), vec![retired], |_| {}).await.0, "ENTRY_RETIRED");
        let mut old = job(7);
        (old["salt"], old["meta"]) = (json!(format!("{:#x}", B256::repeat_byte(3))), json!("0x0001"));
        refused(&outcomes(ok(), vec![old], |_| {}).await.0, "HEX_ARGS_REFUSED");
        let mut other = job(7);
        other["kind"] = json!("signed_op");
        assert!(outcomes(ok(), vec![other], |_| {}).await.0[0].1.contains("unknown job kind"), "one job-kind rule");
    }

    /// The UA-8 registry writes for `ua_registry` (typed-signing R1's explicit ABI, R1b's typed single-key entries), with these sizes (a `register`
    /// with or without its proof).
    fn ua8_writes(pqz_pop: usize) -> Vec<Vec<u8>> {
        use crate::abi::IUARegistry::*;
        let ua = B256::repeat_byte(0x11);
        let b = |n: usize, v: u8| Bytes::from(vec![v; n]);
        // scheme 1 key: 0x01 ‖ ek (1,568 B) ‖ x25519 (CTR-UA-32, TS-D11)
        let kem = |v: u8| KemKey { scheme: 1, mlkemEk: b(1568, v), x25519: B256::repeat_byte(v) };
        let sig = |n: usize, v: u8| UASig { keyData: Bytes::new(), signature: b(n, v), members: vec![] };
        let attrs = || UAAttrs { pqzKey: b(18_432, 2), pqzPopHash: B256::repeat_byte(3), kem: kem(4), kemPkHash: B256::ZERO };
        let members = |n: u16| (0..n).map(|i| MsigMember { kind: 0x0131, id: B256::repeat_byte(0x20 + i as u8), weight: 1 }).collect();
        let pops = |n: u16| (0..n).map(|i| crate::abi::MemberSig { index: i, members: vec![], sig: b(3309, 13) }).collect();
        let none = || UAAttrs { pqzKey: Bytes::new(), pqzPopHash: B256::ZERO, kem: KemKey { scheme: 0, mlkemEk: Bytes::new(), x25519: B256::ZERO },
            kemPkHash: B256::ZERO };
        vec![
            registerCall { kind: 0x0131, keyData: b(1952, 1), attrs: attrs(), pop: b(3309, 5), pqzPop: b(pqz_pop, 12) }
                .abi_encode(),
            setKemKeyCall { ua, version: 2, kem: kem(6), sig: sig(3309, 7) }.abi_encode(),
            storePqzPopCall { ua, version: 0, pqzPop: b(30_381, 8) }.abi_encode(),
            setPqzKeyCall { ua, version: 0, pqzKey: b(18_432, 9), pqzPopHash: B256::repeat_byte(10), sig: sig(3309, 11) }.abi_encode(),
            storePqzPopCall { ua, version: 1, pqzPop: b(30_381, 8) }.abi_encode(),
            setPqzKeyCall { ua, version: 1, pqzKey: b(18_432, 9), pqzPopHash: B256::repeat_byte(10), sig: sig(3309, 11) }.abi_encode(),
            // CTR-UA-37: an `msig` member accepts its place; anyone submits, so the member needs no gas
            acceptMembershipCall { ua, memberSig: crate::abi::MemberSig { index: 3, members: vec![], sig: b(3309, 36) } }.abi_encode(),
            registerMsigCall { structure: MsigStructure { threshold: 2, members: members(2) }, attrs: attrs(), pop: pops(2),
                pqzPop: b(pqz_pop, 12) }.abi_encode(),
            // typed-signing R1b (TS-D13): the typed single-key entries (no PQZ / KEM holders: empty attributes)
            registerWebAuthnCall { key: WebAuthnKey { x: B256::repeat_byte(14), y: B256::repeat_byte(15), rpIdHash: B256::repeat_byte(16) },
                attrs: none(), pop: b(640, 17), pqzPop: Bytes::new() }.abi_encode(),
            registerMuSig2Call { kind: 0x0110, key: MuSig2Key { aggKey: b(33, 18), memberKeys: vec![b(33, 19), b(33, 20)] },
                attrs: none(), pop: b(64, 21), pqzPop: Bytes::new() }.abi_encode(),
            registerFrostCall { kind: 0x0111, key: FrostKey { groupKey: b(33, 22), threshold: 2, members: (0..3)
                .map(|i| FrostMember { commitments: vec![b(33, 23 + i), b(33, 26 + i)], r: b(33, 29 + i), z: B256::repeat_byte(32 + i) })
                .collect() }, attrs: none(), pop: b(64, 35), pqzPop: Bytes::new() }.abi_encode(),
        ]
    }

    /// UA8-D16 / ruling R-node: the UA-8 registry writes (`register` with `UAAttrs`, `setKemKey`, `storePqzPop`,
    /// `setPqzKey`) are `call` jobs on the configured `ua_registry`: the guard's call table takes each there (bound to
    /// this chain) and the lane sends it byte for byte (no meta-tx, no fee); on another target, without `ua_registry`, or
    /// on a registry of another chain each is refused `CALL_TARGET_REFUSED` and nothing is sent. The selectors are
    /// pinned as literals here and in forge `test_ua8_writeSelectorsPinned`, so an ABI change fails on both sides.
    #[tokio::test]
    async fn ua8_registry_writes_are_call_jobs() {
        use crate::abi::IUARegistry::*;
        assert_eq!(registerCall::SIGNATURE, "register(uint16,bytes,(bytes,bytes32,(uint8,bytes,bytes32),bytes32),bytes,bytes)");
        assert_eq!(registerCall::SELECTOR, [0x4e, 0x22, 0x9e, 0xfb]);
        assert_eq!(registerMsigCall::SELECTOR, [0x61, 0x94, 0x71, 0x29]);
        assert_eq!(registerWebAuthnCall::SELECTOR, [0xee, 0x03, 0xa1, 0xfe]);
        assert_eq!(registerMuSig2Call::SELECTOR, [0xe1, 0xed, 0xdc, 0xdf]);
        assert_eq!(registerFrostCall::SELECTOR, [0x7b, 0xd6, 0x34, 0x10]);
        assert_eq!(setKemKeyCall::SELECTOR, [0x6a, 0x33, 0x18, 0xf9]);
        // group 3g (KV-1): the versioned entries, the contract's pins (test_ua8_writeSelectorsPinned): 0x7fac161a -> 0x9f7be2a3,
        // 0x0052c1b5 -> 0xbd97b6a1
        assert_eq!(storePqzPopCall::SELECTOR, [0x9f, 0x7b, 0xe2, 0xa3]);
        assert_eq!(setPqzKeyCall::SELECTOR, [0xbd, 0x97, 0xb6, 0xa1]);
        assert_eq!(acceptMembershipCall::SIGNATURE, "acceptMembership(bytes32,(uint16,(uint16,bytes)[],bytes))");
        assert_eq!(acceptMembershipCall::SELECTOR, [0x2c, 0x1a, 0xc9, 0x86]);
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let (reg, other) = (Address::repeat_byte(0x5e), Address::repeat_byte(0x5f));
        let cfg = move |c: &mut ChainCfg| c.ua_registry = Some(reg);
        let refused = |r: &[(String, String)]| r.len() == 1 && r[0].0 == "dead" && r[0].1.starts_with("CALL_TARGET_REFUSED");
        for (i, data) in ua8_writes(30_381).into_iter().enumerate() {
            let (r, rpc) = outcomes(ok(), vec![call_job(9, reg, data.clone())], cfg).await;
            assert_eq!(states_of(&r), ["signed", "broadcast"], "write {i}: {r:?}");
            let sent = rpc.lock().unwrap().sent.clone();
            assert_eq!((sent.len(), sent[0].1, sent[0].2.to_vec()), (1, reg, data.clone()), "write {i}: the calldata as given");
            for (e, to, with_reg) in [(ok(), other, true), (ok(), reg, false), (Evm { uid: Some(0x25), ..ok() }, reg, true)] {
                let (r, rpc) = outcomes(e, vec![call_job(9, to, data.clone())], move |c| if with_reg { cfg(c) }).await;
                assert!(refused(&r), "write {i} on {to:#x}, ua_registry {with_reg}: {r:?}");
                assert!(rpc.lock().unwrap().sent.is_empty());
            }
        }
    }

    /// Ruling R-node: a relayed PQ registration (`register` with its `R_REG` proof) whose estimate is over the transaction
    /// cap — `max_gas_per_tx` (the SCaaS testnet's 64 M) or the chain's block gas limit — or that the chain's estimate
    /// refuses for gas is refused `UA_REGISTER_SPLIT`, nothing sent: the client sends `register` without the proof, then
    /// `storePqzPop`. Those halves, and a full registration under the cap, follow the ordinary gas rules.
    #[tokio::test]
    async fn ua8_relayed_pq_register_over_the_cap_is_split() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let reg = Address::repeat_byte(0x5e);
        let tn = move |c: &mut ChainCfg| { c.ua_registry = Some(reg); c.max_gas_per_tx = 64_000_000; };
        let (full, bare) = (ua8_writes(30_381).remove(0), ua8_writes(0).remove(0));
        let split = |r: &[(String, String)], why: &str| r.len() == 1 && r[0].0 == "dead"
            && r[0].1.starts_with("UA_REGISTER_SPLIT: ") && r[0].1.contains(why) && r[0].1.ends_with("then storePqzPop");
        // 84.8 M (the smallest full PQ registration measured) on the 200 M testnet, over the 64 M relayer cap
        let (r, rpc) = outcomes(Evm { estimate: Some(84_800_000), ..ok() }, vec![call_job(9, reg, full.clone())], tn).await;
        assert!(split(&r, "transaction cap 64000000 (max_gas_per_tx 64000000"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        // a 60 M block binds below a larger relayer cap
        let (r, _) = outcomes(Evm { estimate: Some(60_000_001), block_gas: Some(60_000_000), ..ok() },
            vec![call_job(9, reg, full.clone())], move |c| { tn(c); c.max_gas_per_tx = 200_000_000; }).await;
        assert!(split(&r, "block gas limit 60000000"), "{r:?}");
        // the chain's estimate refuses it for gas
        let (r, _) = outcomes(Evm { sim: Some("estimate_oog"), ..ok() }, vec![call_job(9, reg, full.clone())], tn).await;
        assert!(split(&r, "gas required exceeds allowance"), "{r:?}");
        // under the cap a full registration goes in one transaction
        let (r, _) = outcomes(Evm { estimate: Some(50_000_000), ..ok() }, vec![call_job(9, reg, full)], tn).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        // register without the proof (and every other write) keeps the ordinary refusal, never the split code
        let (r, _) = outcomes(Evm { estimate: Some(40_000_000), ..ok() }, vec![call_job(9, reg, bare.clone())], tn).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let (r, _) = outcomes(Evm { estimate: Some(64_000_001), ..ok() }, vec![call_job(9, reg, bare)], tn).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("above max_gas_per_tx 64000000") && !r[0].1.contains("UA_REGISTER_SPLIT"), "{r:?}");
        let store = ua8_writes(0).remove(2);
        let (r, _) = outcomes(Evm { estimate: Some(64_000_001), ..ok() }, vec![call_job(9, reg, store)], tn).await;
        assert!(r[0].0 == "dead" && !r[0].1.contains("UA_REGISTER_SPLIT"), "{r:?}");
    }

    /// A PQZ op 1 job (group 3g) from typed_ops.json's `UAPqzTransferSingle` row, its subject a derived UA (no local signature
    /// check), on `TOKEN`.
    fn pqz_job(id: i64) -> Value {
        let v = crate::typed::testkit::vectors();
        let row = crate::typed::testkit::row_of("UAPqzTransferSingle", "pqz");
        let (env, args, sig) = crate::typed::testkit::split(row, "UAPqzTransferSingle", "pqz", &v);
        let mut env = env.unwrap();
        env["from"] = json!(format!("{:#x}", B256::repeat_byte(0xab)));
        json!({"id": id, "kind": "ua_metatx", "op": {"entry": row.entry, "contract": "pqz", "token": format!("{TOKEN:#x}"),
            "envelope": env, "args": args, "auth": sig.unwrap()}})
    }

    /// Group 3g (KV-7, spec §7.3): a receiver (or the auditor) whose latest stored version is above its current one, with the
    /// current key's length, is pending: the debit is refused `PQZ_KEY_ROTATION_PENDING` at intake, nothing simulated or sent.
    /// The controls: no newer version, a newer version of another set's length.
    #[tokio::test]
    async fn rotation_pending_refused_at_intake() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let (r, rpc) = outcomes(Evm { pqz_latest: 1, ..ok() }, vec![pqz_job(7)], |_| {}).await;
        assert!(r.len() == 1 && r[0].0 == "dead" && r[0].1.starts_with("PQZ_KEY_ROTATION_PENDING: "), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        assert!(!rpc.lock().unwrap().calls.iter().any(|m| m == "eth_estimateGas"), "refused before any simulation");
        for e in [ok(), Evm { pqz_latest: 1, pqz_other_len: true, ..ok() }] {
            let (r, _) = outcomes(e, vec![pqz_job(7)], |_| {}).await;
            assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        }
    }

    /// Group 3g (spec §7.3): `ProofRejected` after an indexed `UAPqzKeyCurrent` of a party is `PQZ_KEY_ROTATED`, the simulation
    /// error carried, back in the queue, never `dead`; without the event it is the plain revert.
    #[tokio::test]
    async fn rotated_after_event_not_dead() {
        let e = Evm { mtx_nonce: Some(0), sim: Some("proof_rejected"), pqz_rotated: true, ..Default::default() };
        let (r, rpc) = outcomes(e, vec![pqz_job(7)], |_| {}).await;
        assert!(r.len() == 1 && r[0].0 == "queued" && r[0].1.starts_with("PQZ_KEY_ROTATED: ProofRejected"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
    }

    #[tokio::test]
    async fn rotated_needs_event() {
        let e = Evm { mtx_nonce: Some(0), sim: Some("proof_rejected"), ..Default::default() };
        let (r, _) = outcomes(e, vec![pqz_job(7)], |_| {}).await;
        assert!(r.len() == 1 && r[0].0 == "dead" && r[0].1.starts_with("ProofRejected"), "{r:?}");
    }

    /// Group 3g (spec §7.3): the token's key-version reverts by name: a stale debit and two equal keys `dead`, a version above
    /// current back in the queue (it may become current).
    #[tokio::test]
    async fn stale_refused_by_name() {
        for (sim, state, code) in [("stale", "dead", "PQZ_KEY_STALE: StaleKeyVersion"), ("reused", "dead", "PQZ_KEY_REUSED: KeyReused"),
            ("unknown", "queued", "PQZ_KEY_VERSION_UNKNOWN: KeyVersionUnknown")] {
            let (r, rpc) = outcomes(Evm { mtx_nonce: Some(0), sim: Some(sim), ..Default::default() }, vec![pqz_job(7)], |_| {}).await;
            assert!(r.len() == 1 && r[0].0 == state && r[0].1.starts_with(code), "{sim}: {r:?}");
            assert!(rpc.lock().unwrap().sent.is_empty());
        }
    }

    /// `max_pay_meta_bytes` (default 2,048, spec §7.1) caps `payNo + body` of a pay job; the config raises it.
    #[tokio::test]
    async fn pay_meta_cap_refused() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let note = |n: usize| json!({"salt": format!("{:#x}", B256::repeat_byte(3)), "payNo": "", "schema": 1, "body": {"note": "x".repeat(n)}});
        let (r, _) = outcomes(ok(), vec![pay_job(7, note(2048), |_| {})], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let (r, rpc) = outcomes(ok(), vec![pay_job(7, note(2049), |_| {})], |_| {}).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("PAY_META_TOO_LONG"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = outcomes(ok(), vec![pay_job(7, note(2049), |_| {})],
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

    /// A relay of `TARGET`'s call paying `value` to `to`, as the router's calldata.
    fn relay_data(to: Address, value: u64) -> Vec<u8> {
        let call: Bytes = IToken::mtxNonceCall { from: Address::ZERO, batch: U256::ZERO }.abi_encode().into();
        crate::abi::IMtxRelayFee::relayCall { target: TARGET, callData: call, token: TOKEN, from: payer().into_word(), payee: to.into_word(),
            value: U256::from(value), batch: U256::from(7), nonce: U256::ZERO, validUntil: U256::from(now() + 600),
            auth: UASig { keyData: Bytes::new(), signature: Bytes::from(vec![0x11; 65]), members: vec![] } }.abi_encode()
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
        assert_eq!(crate::abi::IMtxIds::mtxPayCall::SELECTOR, sig("mtxPay((bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,\
address,uint256,address),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]),(bytes32,string,uint16,bytes))"));
        let mut cfg = test_cfg("http://127.0.0.1:9");
        relay_params(&mut cfg, &[]);
        let rf = guard::RelayFee::from_cfg(&cfg).unwrap().unwrap();
        assert_eq!(rf.executor, ROUTER.create(1), "the router's constructor CREATE");
        let lane = lane1();
        let reg = |a: Address| a == TOKEN;
        let check = |to: Address, data: &[u8]| guard::relay_call_ok(&rf, lane, to, data, reg);
        assert_eq!(check(ROUTER, &relay_data(ROUTER, 100)), Ok(TARGET));
        assert!(check(TARGET, &relay_data(ROUTER, 100)).unwrap_err().starts_with("CALL_TARGET_REFUSED"), "only the router");
        assert!(check(ROUTER, &[1, 2, 3, 4]).unwrap_err().starts_with("BAD_PAYLOAD"));
        let c = crate::abi::IMtxRelayFee::relayCall::abi_decode(&relay_data(ROUTER, 100)).unwrap();
        let other = crate::abi::IMtxRelayFee::relayCall { token: Address::repeat_byte(0x99), ..c }.abi_encode();
        assert!(check(ROUTER, &other).unwrap_err().starts_with("TOKEN_NOT_SERVED"), "a registered token only");
        assert!(check(ROUTER, &relay_data(ROUTER.create(1), 100)).unwrap_err().starts_with("RELAY_FEE_SHAPE"), "never the executor");
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
            let UaMtx::Transfer(mut t) = meta(7) else { unreachable!() };
            t.to = to.into_word();
            let mut j = job(7);
            j["m"] = UaMtx::Transfer(t).to_wire().1;
            let (r, rpc) = outcomes(ok(), vec![j], |c| relay_params(c, &[])).await;
            assert!(r[0].0 == "dead" && r[0].1.starts_with("PAYEE_REFUSED"), "{r:?}");
            assert!(rpc.lock().unwrap().sent.is_empty());
        }
        let (r, _) = outcomes(ok(), vec![call_job(9, ROUTER, relay_data(ROUTER, 100))], |_| {}).await;
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
        let (r, rpc) = go(relay_data(ROUTER, 100), vec![], Evm::default()).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "open mode at min_amount: {r:?}");
        let sent = rpc.lock().unwrap().sent[0].clone();
        assert_eq!((sent.1, &sent.2[..4]), (ROUTER, &crate::abi::IMtxRelayFee::relayCall::SELECTOR[..]));
        assert_eq!(rpc.lock().unwrap().gas[0], 0x30000 * 6 / 5, "the simulated relay +20 %");
        let (r, rpc) = go(relay_data(ROUTER, 99), vec![], Evm::default()).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("below relay_fee.min_amount 100"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = go(relay_data(lane1(), 100), vec![], Evm::default()).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "bound to this lane: {r:?}");
        let elsewhere = Address::repeat_byte(0x5e);
        let (r, _) = go(relay_data(elsewhere, 1_000), vec![], Evm::default()).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("relay_bound_payee"), "a fee bound elsewhere: {r:?}");
        let (r, _) = go(relay_data(elsewhere, 1), vec![("relay_bound_payee", true.into())], Evm::default()).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "sponsored: no min_amount: {r:?}");
        let (r, _) = go(relay_data(ROUTER, 100), vec![], Evm { uid: Some(UID + 1), ..Default::default() }).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("CHAIN_UID_MISMATCH"), "the inner target is of another chain: {r:?}");
    }

    // ------------------------------------------------------------------ ua_metatx (job-api.md, CTR-UA-26)

    const UA: B256 = B256::repeat_byte(0xaa);

    /// R43 (CTR-MTX-30, plan T14): a merged entry is a `ua_metatx` job and an address entry a `metatx` one; a job naming an entry its kind's
    /// call table does not list is refused by name, never built. The address `MetaTransfer` struct job names the token's address
    /// `mtxExecuteTransfer(MetaTransfer, bytes)`, which no token has left: refused by name too.
    #[test]
    fn a_metatx_job_naming_a_merged_entry_is_refused_by_name() {
        let v = crate::typed::testkit::vectors();
        let of = |kind: &str, op: &Value| -> Job { serde_json::from_value(json!({"id": 1, "kind": kind, "op": op})).unwrap() };
        let mut unwrap = crate::typed::testkit::op_of("UAUnwrap", "token", &v).unwrap();
        unwrap["entry"] = json!("mtxUnwrap");
        let e = work_from_job(&of("metatx", &unwrap), None).unwrap_err().to_string();
        assert!(e.starts_with("OP_KIND_MISMATCH") && e.contains("mtxUnwrap"), "{e}");
        work_from_job(&of("ua_metatx", &unwrap), None).unwrap();
        let wrap = crate::typed::testkit::op_of("Wrap", "token", &v).unwrap();
        assert!(work_from_job(&of("ua_metatx", &wrap), None).unwrap_err().to_string().starts_with("OP_KIND_MISMATCH"), "the reverse");
        work_from_job(&of("metatx", &wrap), None).unwrap();
        let (kind, wire) = addr_meta(7).to_wire();
        let addr: Job = serde_json::from_value(json!({"id": 1, "kind": "metatx", "token": format!("{TOKEN:#x}"), "struct": kind,
            "signature": format!("0x{}", "11".repeat(65)), "metatx": wire})).unwrap();
        let e = work_from_job(&addr, None).unwrap_err().to_string();
        assert!(e.starts_with("OP_KIND_MISMATCH") && e.contains("mtxExecuteTransfer"), "{e}");
    }

    fn ua_meta(batch: u64) -> crate::metatx::UaMtx {
        crate::metatx::UaMtx::Transfer(crate::abi::UAMetaTransfer { from: UA, to: Address::repeat_byte(0x5e).into_word(),
            value: U256::from(1_000u64), entryRef: B256::repeat_byte(0x42), batch: U256::from(batch), nonce: U256::ZERO,
            validUntil: U256::from(now() + 600), mode: 0, relayer: Address::ZERO, fee: U256::ZERO, feeRecipient: Address::ZERO })
    }

    fn ua_job(id: i64, m: &crate::metatx::UaMtx) -> Value {
        let (kind, wire) = m.to_wire();
        json!({"id": id, "kind": "ua_metatx", "token": format!("{TOKEN:#x}"), "digest": D, "struct": kind,
               "auth": {"keyData": "0x", "signature": format!("0x{}", "22".repeat(96)), "members": []}, "m": wire})
    }

    fn work(j: Value) -> Result<Work> {
        work_from_job(&serde_json::from_value(j).unwrap(), Some(Address::repeat_byte(0xfe)))
    }

    /// `ua_metatx` (job-api.md): `{token, struct, m, auth}` with `from: bytes32` relays `uaExecute` /
    /// `uaExecuteTransfer` (or `uaPayMeta` with `salt` / `meta`, CTR-MTX-26) of the normalized struct; the work's
    /// subject is the id on the UA nonce map. Any other payload shape is refused.
    #[test]
    fn ua_metatx_jobs_build_the_ua_entry_points() {
        use crate::abi::IMtxIds;
        let auth = UASig { keyData: Bytes::new(), signature: Bytes::from(vec![0x22; 96]), members: vec![] };
        let w = work(ua_job(7, &ua_meta(7))).unwrap();
        let mut m = ua_meta(7);
        m.normalize(Some(Address::repeat_byte(0xfe)));
        assert_eq!((w.to, w.data.clone(), w.entry), (TOKEN, m.calldata(auth.clone()), false));
        assert_eq!(w.meta, Some(MetaRef { token: TOKEN, from: UA, batch: U256::from(7), nonce: U256::ZERO, digest: None, ua: true, addr_nonce: false }));
        assert_eq!(w.valid_until, m.valid_until().saturating_to::<u64>());
        assert_eq!(w.data[..4], IMtxIds::mtxExecuteTransferCall::SELECTOR);
        assert_eq!(UaMtx::from_calldata(&w.data).map(|x| x.1), Some(auth.clone()), "auth is the UASig, field by field");
        // pay-meta-tax T42: the old `salt` + hex `meta` struct job is refused by name (a pay is the named entry mtxPay)
        let mut j = ua_job(9, &ua_meta(0));
        (j["salt"], j["meta"]) = (json!(format!("{:#x}", B256::repeat_byte(3))), json!("0x0909"));
        assert!(work(j).unwrap_err().to_string().starts_with("HEX_ARGS_REFUSED"));
        // refused shapes: the address body or fields in a UA job, a UA body in a metatx job, an address `from`
        let mut addr = ua_job(10, &ua_meta(7));
        addr["signature"] = json!("0x22");
        assert!(work(addr).is_err(), "a ua_metatx job carries auth, never signature");
        let mut x = ua_job(10, &ua_meta(7));
        x["metatx"] = x["m"].take();
        assert!(work(x).is_err(), "m, never metatx");
        let mut x = ua_job(10, &ua_meta(7));
        x["kind"] = json!("metatx");
        assert!(work(x).is_err(), "a UA body is no metatx job");
        let mut x = ua_job(10, &ua_meta(7));
        x["m"]["from"] = json!(format!("{:#x}", payer()));
        assert!(work(x).is_err(), "from is a bytes32 id");
        let mut x = ua_job(10, &ua_meta(7));
        x["kind"] = json!("ua_call");
        let e = format!("{:#}", work(x).unwrap_err());
        assert!(e.contains("unknown job kind") && e.contains("ua_metatx"), "{e}");
    }

    /// The lane relays a `ua_metatx` job like a `metatx` one: the guard first (a registered token whose UA ledger is
    /// on), the typed digest computed here as the in-flight key, the simulated `uaExecuteTransfer`; a refused
    /// simulation whose UA nonce is spent (`uaNonce(id, batch) > nonce`) is `consumed`, never `dead`.
    #[tokio::test]
    async fn ua_metatx_job_relays_and_a_spent_ua_nonce_is_consumed() {
        let ok = || Evm { mtx_nonce: Some(0), ..Default::default() };
        let (r, rpc) = outcomes(ok(), vec![ua_job(7, &ua_meta(7))], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let sent = rpc.lock().unwrap().sent[0].clone();
        assert_eq!((sent.1, &sent.2[..4]), (TOKEN, &crate::abi::IMtxIds::mtxExecuteTransferCall::SELECTOR[..]));
        let (r, rpc) = outcomes(Evm { sim: Some("revert"), mtx_nonce: Some(1), ..Default::default() }, vec![ua_job(7, &ua_meta(7))], |_| {}).await;
        assert_eq!(states_of(&r), ["consumed"], "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = outcomes(Evm { sim: Some("revert"), mtx_nonce: Some(0), ..Default::default() }, vec![ua_job(7, &ua_meta(7))], |_| {}).await;
        assert_eq!(states_of(&r), ["dead"], "{r:?}");
        let (r, _) = outcomes(Evm { sim: Some("revert"), mtx_nonce: None, ..Default::default() }, vec![ua_job(7, &ua_meta(7))], |_| {}).await;
        assert_eq!(states_of(&r), ["queued"], "an unreadable UA nonce decides nothing: {r:?}");
        // the guard: the UA ledger off, an unregistered token, a UA pay to the router, a UA meta above the cap
        let (r, rpc) = outcomes(Evm { ua_off: true, ..ok() }, vec![ua_job(7, &ua_meta(7))], |_| {}).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("FEATURE_UNSUPPORTED"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let mut other = ua_job(7, &ua_meta(7));
        other["token"] = json!(format!("{:#x}", Address::repeat_byte(0x99)));
        let (r, _) = outcomes(ok(), vec![other], |_| {}).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("TOKEN_NOT_SERVED"), "{r:?}");
        for to in [ROUTER, ROUTER.create(1)] {
            let crate::metatx::UaMtx::Transfer(mut t) = ua_meta(7) else { unreachable!() };
            t.to = to.into_word();
            let (r, _) = outcomes(ok(), vec![ua_job(7, &crate::metatx::UaMtx::Transfer(t))], |c| relay_params(c, &[])).await;
            assert!(r[0].0 == "dead" && r[0].1.starts_with("PAYEE_REFUSED"), "{r:?}");
        }
    }

    /// `relay` for a derived payer `UA`: its `UARelayFee` of `value` to `to` for `TARGET`'s call.
    fn ua_relay_data(to: B256, value: u64) -> Vec<u8> {
        let call: Bytes = IToken::mtxNonceCall { from: Address::ZERO, batch: U256::ZERO }.abi_encode().into();
        crate::abi::IMtxRelayFee::relayCall { target: TARGET, callData: call, token: TOKEN, from: UA, payee: to, value: U256::from(value),
            batch: U256::from(7), nonce: U256::ZERO, validUntil: U256::from(now() + 600), auth: UASig { keyData: Bytes::new(), signature: Bytes::from(vec![0x22; 96]), members: vec![] } }.abi_encode()
    }

    /// CTR-MTX-27 for a derived payer: the call-table row `MtxRelayFee.relay` takes the router's shape on ids (payee never
    /// the executor's id) and `min_amount`; the lane's cost is known only after the simulation (a UA verify costs what its
    /// kind costs, millions of gas for a PQ kind), so the fee must also be worth, at the token's `relay_fee.min_wei_value`, at
    /// least the quote = the gas limit × the max fee per gas the lane signs with. A token without a price is refused for a
    /// derived payer; a native payer (an EOA padded) is priced only when its token has one.
    #[tokio::test]
    async fn ua_relay_fee_needs_a_price_and_covers_the_quote() {
        let sig = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        assert_eq!(crate::abi::IMtxRelayFee::relayCall::SELECTOR,
            sig("relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))"));
        let mut cfg = test_cfg("http://127.0.0.1:9");
        relay_params(&mut cfg, &[]);
        let rf = guard::RelayFee::from_cfg(&cfg).unwrap().unwrap();
        let check = |data: &[u8]| guard::relay_call_ok(&rf, lane1(), ROUTER, data, |a| a == TOKEN);
        let open = ROUTER.into_word();
        assert_eq!(check(&ua_relay_data(open, 100)), Ok(TARGET));
        assert!(check(&ua_relay_data(ROUTER.create(1).into_word(), 100)).unwrap_err().starts_with("RELAY_FEE_SHAPE"), "never the executor");
        assert!(check(&ua_relay_data(open, 99)).unwrap_err().contains("below relay_fee.min_amount 100"));
        assert_eq!(check(&ua_relay_data(lane1().into_word(), 100)), Ok(TARGET), "bound to this lane");
        assert!(check(&ua_relay_data(B256::repeat_byte(0x5e), 100)).unwrap_err().contains("relay_bound_payee"));
        let c = crate::abi::IMtxRelayFee::relayCall::abi_decode(&ua_relay_data(open, 100)).unwrap();
        let other = crate::abi::IMtxRelayFee::relayCall { token: Address::repeat_byte(0x99), ..c }.abi_encode();
        assert!(check(&other).unwrap_err().starts_with("TOKEN_NOT_SERVED"));
        // on the lane: no price ⇒ refused before any signature; then exactly the quote passes, one wei less does not
        let price = |p: u128| -> Vec<(&'static str, toml::Value)> {
            let mut t = toml::Table::new();
            t.insert(format!("{TOKEN:#x}"), p.to_string().into());
            vec![("min_wei_value", toml::Value::Table(t))]
        };
        let go = |data: Vec<u8>, more: Vec<(&'static str, toml::Value)>| async move {
            outcomes(Evm::default(), vec![call_job(9, ROUTER, data)], move |c| relay_params(c, &more)).await
        };
        let (r, rpc) = go(ua_relay_data(open, 1_000), vec![]).await;
        assert!(r[0].0 == "dead" && r[0].1.starts_with("RELAY_FEE_REFUSED") && r[0].1.contains("min_wei_value"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, rpc) = go(ua_relay_data(open, 1_000), price(u128::MAX / 1_000)).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let (gas, fee, sel) = {
            let e = rpc.lock().unwrap();
            (e.gas[0], e.fees[0], e.sent[0].2[..4].to_vec())
        };
        assert_eq!(sel, crate::abi::IMtxRelayFee::relayCall::SELECTOR);
        // fix 1 (I1): the quote is taken at the job's fee ceiling, FEE_HEADROOM x the first max fee
        let quote = u128::from(gas) * guard::FEE_HEADROOM * fee;
        assert_eq!(guard::relay_quote(gas, guard::fee_ceiling(fee), 0), quote);
        let (r, _) = go(ua_relay_data(open, 1_000), price(quote.div_ceil(1_000))).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "fee x price = the quote: {r:?}");
        let (r, rpc) = go(ua_relay_data(open, 1_000), price((quote - 1) / 1_000)).await;
        // fix 1 (minor 3): the quote follows the current fees, so below it is a retry, never a kill
        assert!(r[0].0 == "queued" && r[0].1.starts_with("RELAY_FEE_REFUSED") && r[0].1.contains("quote"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty(), "nothing sent below the quote");
        // a native payer: priced only when its token has a price (T17's min_amount rule otherwise)
        let (r, _) = go(relay_data(ROUTER, 1_000), vec![]).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let (r, _) = go(relay_data(ROUTER, 1_000), price((quote - 1) / 1_000)).await;
        assert!(r[0].0 == "queued" && r[0].1.starts_with("RELAY_FEE_REFUSED"), "{r:?}");
    }

    /// `relay_fee.min_wei_value = { "<token>" = wei per base unit }` (EVM only): an integer or a decimal string per token
    /// address; anything else is a startup error.
    #[test]
    fn min_wei_value_is_parsed_or_refused() {
        let with = |v: toml::Value| {
            let mut c = test_cfg("http://127.0.0.1:9");
            let mut t = toml::Table::new();
            t.insert(format!("{TOKEN:#x}"), v);
            relay_params(&mut c, &[("min_wei_value", toml::Value::Table(t))]);
            guard::RelayFee::from_cfg(&c)
        };
        let p = |wei: u128, per: u128| guard::Price { wei, per };
        assert_eq!(with(7.into()).unwrap().unwrap().min_wei_value.get(&TOKEN), Some(&p(7, 1)));
        let big = (1u128 << 127).to_string();
        assert_eq!(with(big.clone().into()).unwrap().unwrap().min_wei_value[&TOKEN], p(1 << 127, 1));
        // fix 1 (minor 1): wei per 10^k base units, so an 18-decimal token below 1 wei per unit is priced exactly
        assert_eq!(with("3/1000000000000000000".into()).unwrap().unwrap().min_wei_value[&TOKEN], p(3, 1_000_000_000_000_000_000));
        for bad in [toml::Value::from(-1), toml::Value::from("1e3"), toml::Value::from(1.5), toml::Value::from("3/7"),
                    toml::Value::from("3/0"), toml::Value::from("/10"), toml::Value::from("3/10/10")] {
            assert!(with(bad.clone()).is_err(), "{bad}");
        }
        assert!(guard::price_covers(&p(3, 1_000), 1_000, 3), "1,000 units x 3 wei / 1,000 = 3 wei");
        assert!(!guard::price_covers(&p(3, 1_000), 999, 3), "floor(999 x 3 / 1,000) = 2 wei");
        assert!(guard::price_covers(&p(u128::MAX, 1), u128::MAX, u128::MAX), "exact, no overflow");
        // fix 1 (minor 2): set-but-unusable is a startup error: no router, or one token twice (case only)
        let mut c = test_cfg("http://127.0.0.1:9");
        let mut t = toml::Table::new();
        t.insert(format!("{TOKEN:#x}"), 1.into());
        c.params.insert("relay_fee".into(), toml::Value::Table([("min_wei_value".to_string(), toml::Value::Table(t.clone()))].into_iter().collect()));
        assert!(guard::RelayFee::from_cfg(&c).is_err(), "min_wei_value without a router");
        t.insert(format!("{TOKEN:#x}").replace("cd", "CD"), 2.into());
        let mut c = test_cfg("http://127.0.0.1:9");
        relay_params(&mut c, &[("min_wei_value", toml::Value::Table(t))]);
        assert!(guard::RelayFee::from_cfg(&c).is_err(), "one token under two spellings");
        let mut c = test_cfg("http://127.0.0.1:9");
        let mut t = toml::Table::new();
        t.insert("not-an-address".into(), 1.into());
        relay_params(&mut c, &[("min_wei_value", toml::Value::Table(t))]);
        assert!(guard::RelayFee::from_cfg(&c).is_err());
        let near = ChainCfg { family: "near".into(), params: toml::from_str("relay_fee = { min_wei_value = {} }").unwrap(), ..Default::default() };
        assert!(near.relay_params().is_err(), "an EVM key only");
    }

    // ------------------------------------------------------------------ fix 1 (review C1 / I1 / I2 / I3)

    fn priced(price: u128) -> impl FnOnce(&mut ChainCfg) {
        move |c| {
            let mut t = toml::Table::new();
            t.insert(format!("{TOKEN:#x}"), price.to_string().into());
            relay_params(c, &[("min_wei_value", toml::Value::Table(t))]);
        }
    }

    /// I1: a priced relay-fee job is quoted at its fee ceiling (`FEE_HEADROOM` x the first max fee) and every
    /// replacement of a stuck send stays at or under it: the lane waits at the ceiling (the job then expires and its
    /// nonce is gap-filled), it never bumps past what the payer's fee covers. An unpriced job still bumps to the cap.
    #[tokio::test]
    async fn priced_relay_fee_replacements_stay_under_the_job_ceiling() {
        let (url, rpc) = fake_evm(Evm::default()).await;
        let (odoo, _o) = fake_odoo(Fake { jobs: vec![call_job(9, ROUTER, ua_relay_data(ROUTER.into_word(), 1_000))],
            tokens: toks(), ..Default::default() }).await;
        let mut s = lane_cfg(&url, odoo, 1, InflightSet::default(), priced(u128::MAX / 1_000)).await.unwrap();
        s.poll_outbox().await;
        for _ in 0..8 {
            s.track().await;
        }
        let (fees, first) = {
            let e = rpc.lock().unwrap();
            (e.fees.clone(), e.fees[0])
        };
        let ceiling = guard::fee_ceiling(first);
        assert!(fees.len() >= 3, "replaced while stuck: {fees:?}");
        assert!(fees.iter().all(|f| *f <= ceiling), "every send under the ceiling {ceiling}: {fees:?}");
        // fix 2: the clamped last step (5.86 -> 6 gwei, +2.4 %) is no replacement a mempool takes, so the lane waits
        // below the ceiling; every send is +10 % over the one it replaces
        let last = *fees.last().unwrap();
        assert!(last < ceiling && last * 11 > ceiling * 10, "waits one step under the ceiling: {fees:?}");
        assert!(fees.windows(2).all(|w| w[1] * 10 >= w[0] * 11), "each replacement is +10 %: {fees:?}");
        assert_eq!(s.inflight.get(&0).unwrap().ceiling, Some(ceiling));
        // a metatx job (no quote) keeps the operator's cap
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, _o) = fake_odoo(Fake { jobs: vec![job(7)], tokens: toks(), ..Default::default() }).await;
        let mut s = lane(&url, odoo, 1, InflightSet::default()).await;
        s.poll_outbox().await;
        for _ in 0..8 {
            s.track().await;
        }
        let fees = rpc.lock().unwrap().fees.clone();
        assert!(*fees.last().unwrap() > guard::fee_ceiling(fees[0]), "unpriced: bumped past 2x: {fees:?}");
        assert_eq!(s.inflight.get(&0).unwrap().ceiling, None);
    }

    /// I1 after a restart: a tracked priced relay-fee job is re-checked before it is ever re-signed: its ceiling is
    /// the tracked transaction's max fee, and a fee that does not cover gas x that fee (or an unknown fee) leaves the
    /// nonce to the gap-fill only.
    #[tokio::test]
    async fn a_tracked_priced_relay_job_is_rechecked_after_a_restart() {
        let tracked = json!([{"job_id": 9, "nonce": 0, "state": "broadcast", "tx_hash": format!("{:#x}", B256::repeat_byte(0x77)),
            "payload": call_job(9, ROUTER, ua_relay_data(ROUTER.into_word(), 1_000))}]);
        let (gas, max_fee) = (300_000u64, 3_000_000_000u128);
        let quote = u128::from(gas) * max_fee;
        for (tx_max_fee, price, kept) in [(Some(max_fee), quote.div_ceil(1_000), true), (Some(max_fee), (quote - 1) / 1_000, false),
                                          (None, u128::MAX / 1_000, false)] {
            let (url, _) = fake_evm(Evm { count: 1, tx_gas: Some(gas), tx_max_fee, ..Default::default() }).await;
            let (odoo, _) = fake_odoo(Fake { tokens: toks(), inflight: tracked.clone(), ..Default::default() }).await;
            let s = lane_cfg(&url, odoo, 1, InflightSet::default(), priced(price)).await.unwrap();
            let sent = s.inflight.get(&0).expect("tracked");
            assert_eq!((sent.work.is_some(), sent.ceiling), (kept, kept.then_some(max_fee)), "{tx_max_fee:?} {price}");
        }
    }

    /// I2: while a relay-fee job of subject S (its payer) is in flight, no other job that can lower S's balance on that
    /// token is signed (requeued `SUBJECT_HELD`), nor a relay-fee job of S while another job of S is in flight; other
    /// subjects run, and the hold ends with the job. One key for both payer forms (`relay`'s address is its padded id).
    #[tokio::test]
    async fn a_relay_fee_job_holds_its_payer() {
        let (url, rpc) = fake_evm(Evm { mtx_nonce: Some(0), ..Default::default() }).await;
        let (odoo, o) = fake_odoo(Fake { tokens: toks(), ..Default::default() }).await;
        let mut s = lane_cfg(&url, odoo, 1, InflightSet::default(), priced(u128::MAX / 1_000)).await.unwrap();
        let last = |o: &Shared, id: i64| o.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap();
        o.lock().unwrap().jobs = vec![call_job(9, ROUTER, ua_relay_data(ROUTER.into_word(), 1_000))];
        s.poll_outbox().await;
        assert_eq!(last(&o, 9)["chain_state"], "broadcast");
        let other = { let crate::metatx::UaMtx::Transfer(mut t) = ua_meta(8) else { unreachable!() }; t.from = B256::repeat_byte(0xbb);
            crate::metatx::UaMtx::Transfer(t) };
        o.lock().unwrap().jobs = vec![ua_job(10, &ua_meta(7)), ua_job(11, &other)];
        s.poll_outbox().await;
        let held = last(&o, 10);
        assert!(held["chain_state"] == "queued" && held["error"].as_str().unwrap().starts_with("SUBJECT_HELD"), "{held}");
        assert_eq!(last(&o, 11)["chain_state"], "broadcast", "another subject runs");
        assert_eq!(rpc.lock().unwrap().sent.len(), 2);
        // the hold ends with the relay job; then S's job runs and, in flight, holds S against a new relay-fee job
        {
            // both jobs land (the fake answers one UA digest for every job, so job 11 would also keep job 10 out)
            let mut e = rpc.lock().unwrap();
            let (a, b) = (e.sent[0].0, e.sent[1].0);
            e.receipts.insert(a, true);
            e.receipts.insert(b, true);
        }
        s.track().await;
        o.lock().unwrap().jobs = vec![ua_job(10, &ua_meta(7))];
        s.poll_outbox().await;
        assert_eq!(last(&o, 10)["chain_state"], "broadcast");
        o.lock().unwrap().jobs = vec![call_job(12, ROUTER, ua_relay_data(ROUTER.into_word(), 1_000))];
        s.poll_outbox().await;
        let held = last(&o, 12);
        assert!(held["chain_state"] == "queued" && held["error"].as_str().unwrap().starts_with("SUBJECT_HELD"), "{held}");
        // the key: the payer id on the fee token, the same for relay (address payer) and that address's own jobs
        let mut cfg = test_cfg("http://127.0.0.1:9");
        relay_params(&mut cfg, &[]);
        let g = guard::Guard::new(&cfg, Default::default()).unwrap();
        let w = |j: Value| work(j).unwrap();
        let payer = payer().into_word();
        let addr_relay = g.subject(&w(call_job(9, ROUTER, relay_data(ROUTER, 100)))).unwrap();
        assert_eq!(addr_relay, (guard::subject_key(TOKEN, payer), true));
        assert_eq!(g.subject(&w(job(7))), Some((guard::subject_key(TOKEN, payer), false)), "the payer's own metatx");
        assert_eq!(g.subject(&w(ua_job(7, &ua_meta(7)))), Some((guard::subject_key(TOKEN, UA), false)));
        assert_ne!(guard::subject_key(TOKEN, UA), guard::subject_key(Address::repeat_byte(0x99), UA), "per token");
        assert_eq!(g.subject(&w(deploy_job(9, TARGET))), None, "a plain entry has no subject");
    }

    /// I3: on an OP-stack chain (`params.l1_fee = "op-stack"`) a priced relay-fee job's quote adds the L1 data fee of
    /// the signed transaction (`GasPriceOracle.getL1Fee` at 0x420…0F, x FEE_HEADROOM); an oracle that does not answer
    /// refuses the job; any other value of `l1_fee` is a startup error.
    #[tokio::test]
    async fn op_stack_l1_fee_is_in_the_quote() {
        let op = |price: u128| move |c: &mut ChainCfg| {
            priced(price)(c);
            c.params.insert("l1_fee".into(), "op-stack".into());
        };
        let data = || ua_relay_data(ROUTER.into_word(), 1_000);
        let (r, rpc) = outcomes(Evm { l1_fee: Some(5_000_000_000_000), ..Default::default() }, vec![call_job(9, ROUTER, data())], op(u128::MAX / 1_000)).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let (gas, fee) = { let e = rpc.lock().unwrap(); (e.gas[0], e.fees[0]) };
        let quote = guard::relay_quote(gas, guard::fee_ceiling(fee), 5_000_000_000_000);
        assert_eq!(quote, u128::from(gas) * 2 * fee + 2 * 5_000_000_000_000);
        let go = |price: u128, l1_fee: Option<u64>| async move {
            outcomes(Evm { l1_fee, ..Default::default() }, vec![call_job(9, ROUTER, data())], op(price)).await
        };
        assert_eq!(states_of(&go(quote.div_ceil(1_000), Some(5_000_000_000_000)).await.0), ["signed", "broadcast"]);
        let (r, rpc) = go((quote - 1) / 1_000, Some(5_000_000_000_000)).await;
        assert!(r[0].0 == "queued" && r[0].1.contains("quote"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, rpc) = go(u128::MAX / 1_000, None).await;
        assert!(r[0].0 == "dead" && r[0].1.contains("getL1Fee"), "no oracle: refused: {r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        // not an OP-stack chain: the oracle is never asked (the fake asserts its address when asked)
        assert_eq!(states_of(&outcomes(Evm::default(), vec![call_job(9, ROUTER, data())], priced(u128::MAX / 1_000)).await.0),
            ["signed", "broadcast"]);
        let mut c = test_cfg("http://127.0.0.1:9");
        c.params.insert("l1_fee".into(), "arbitrum".into());
        assert!(guard::Guard::new(&c, Default::default()).is_err());
    }

    // ---- group 3f, PQZ verifier mode (spec 2026-11-06-attested-verify §11.1): the node rebuilds the verdict, holds no key

    /// The fake token's verifier UA (a native id) and an `OFFCHAIN` token at epoch 2.
    const VERIFIER: B256 = B256::repeat_byte(0x0e);
    fn offchain() -> Evm {
        Evm { mtx_nonce: Some(0), pqz_cfg: Some((1, VERIFIER, 2)), ..Default::default() }
    }

    /// A verifier's `UASig` (a native id's 65 bytes), `tag` its first byte.
    fn verdict_auth(tag: u8) -> Value {
        json!({"keyData": "0x", "signature": format!("0x{}", format!("{tag:02x}").repeat(65)), "members": []})
    }

    /// A job's `pqz_verdict` sub-object, or a verifier's answer of that shape.
    fn verdict_json(epoch: u32, valid_until: u64, tag: u8) -> Value {
        json!({"pqzVerifierEpoch": epoch, "validUntil": valid_until.to_string(), "auth": verdict_auth(tag)})
    }

    /// The reference PQZ verifier's answer (scaas-pqz-verifier `Signed`): its verdict (the node reads the epoch and `validUntil`
    /// only) and its signature.
    fn answer_json(epoch: u32, valid_until: u64, tag: u8) -> Value {
        let z = format!("{:#x}", B256::ZERO);
        json!({"pqzVerdict": {"token": format!("{TOKEN:#x}"), "chainId": "0x7a69", "proofSystemId": z, "statementHash": z, "proofHash": z,
            "pqzVerifierEpoch": epoch, "validUntil": valid_until}, "pqzVerdictSig": verdict_auth(tag)})
    }

    fn with_verdict(mut j: Value, v: Value) -> Value {
        j["op"]["args"]["pqz_verdict"] = v;
        j
    }

    /// A fake PQZ verifier (off-chain): `POST /v1/pqz-verdict` answers `answer` with `status`, every request body kept.
    #[derive(Default)]
    struct Ver {
        answer: Value,
        status: u16,
        reqs: Vec<Value>,
    }
    type VerRef = Arc<Mutex<Ver>>;

    async fn fake_verifier(answer: Value) -> (String, VerRef) {
        use axum::extract::State;
        async fn h(State(s): State<VerRef>, body: axum::body::Bytes) -> (axum::http::StatusCode, String) {
            let mut v = s.lock().unwrap();
            v.reqs.push(serde_json::from_slice(&body).unwrap_or(Value::Null));
            (axum::http::StatusCode::from_u16(if v.status == 0 { 200 } else { v.status }).unwrap(), v.answer.to_string())
        }
        let s: VerRef = Arc::new(Mutex::new(Ver { answer, ..Default::default() }));
        let app = axum::Router::new().route("/v1/pqz-verdict", axum::routing::post(h)).route("/v1/pqz-verdict/probe", axum::routing::post(h))
            .with_state(s.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, s)
    }

    /// An endpoint nothing listens on (connection refused at once).
    const DEAD: &str = "http://127.0.0.1:9";

    fn endpoints(list: Vec<String>) -> impl FnOnce(&mut ChainCfg) {
        move |c: &mut ChainCfg| {
            c.pqz_verifier.endpoints = list;
            c.pqz_verifier.timeout_ms = 2_000;
        }
    }

    /// The trailing `PqzSignedVerdict` of a sent PQZ debit (`name`'s row).
    fn sent_verdict(name: &str, data: &[u8]) -> crate::abi::IPqzToken::PqzSignedVerdict {
        let row = crate::typed::testkit::row_of(name, "pqz");
        let vals = crate::typed::call_values(row, data).unwrap();
        let v = vals.last().unwrap().abi_encode();
        <crate::abi::IPqzToken::PqzSignedVerdict as SolValue>::abi_decode(&v).unwrap()
    }

    fn ua_sig(v: &Value) -> UASig {
        UASig::abi_decode(&crate::typed::parse("UASig", v, "auth").unwrap().abi_encode()).unwrap()
    }

    /// The job's proof bytes (`args.proof`).
    fn proof_of(j: &Value) -> Vec<u8> {
        crate::typed::testkit::hex(&j["op"]["args"]["proof"])
    }

    /// Spec §11.1: the job's `pqz_verdict` carries the verifier's epoch, `validUntil` and signature only; the node rebuilds the
    /// `PqzVerdict` they sign from the token (the target), the chain id, `proofSystemId()`, the statement the token's own view
    /// builds for the job's named `args` and the relayed envelope's binding, and the job's proof, and sends that struct with
    /// the job's signature last. The views it asked: the config, the binding of the envelope, the statement of the job's args.
    #[tokio::test]
    async fn pqz_verdict_subobject_builds_struct() {
        let until = now() + 600;
        let j = with_verdict(pqz_job(7), verdict_json(2, until, 0x7e));
        let (r, rpc) = outcomes(offchain(), vec![j.clone()], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let e = rpc.lock().unwrap();
        let v = sent_verdict("UAPqzTransferSingle", &e.sent[0].2);
        assert_eq!(v.pqzVerdict, crate::abi::IPqzToken::PqzVerdict { token: TOKEN, chainId: U256::from(31337), proofSystemId: PSID,
            statementHash: alloy::primitives::keccak256(STATEMENT), proofHash: alloy::primitives::keccak256(proof_of(&j)),
            pqzVerifierEpoch: 2, validUntil: until });
        assert_eq!(v.sig, ua_sig(&verdict_auth(0x7e)), "the job's signature, as it named it");
        // the statement view: the job's own `args` and the binding the token gave for its envelope
        let st = e.views.iter().find(|i| i[..4] == [0x93, 0x14, 0x15, 0xee]).expect("transferSingleStatement asked");
        let ty = alloy::dyn_abi::DynSolType::parse(&format!("({},bytes32)", crate::typed::abi_of("PqzTransferArgs"))).unwrap();
        let got = ty.abi_decode_params(&st[4..]).unwrap();
        let want = crate::typed::parse("PqzTransferArgs", &j["op"]["args"]["args"], "args").unwrap();
        assert_eq!(got.as_tuple().unwrap()[0], want, "the job's named args");
        assert_eq!(got.as_tuple().unwrap()[1], alloy::dyn_abi::DynSolValue::FixedBytes(BINDING, 32), "the envelope's binding");
        let b = e.views.iter().find(|i| i[..4] == crate::abi::IPqzToken::envelopeBindingCall::SELECTOR).expect("envelopeBinding asked");
        let m = crate::abi::IPqzToken::envelopeBindingCall::abi_decode(b).unwrap().m;
        assert_eq!((m.from, m.data.len()), (B256::repeat_byte(0xab), 0), "the job's envelope, no data");
    }

    /// Spec §11.1: an `OFFCHAIN` job without `pqz_verdict` is sent to the configured endpoints in order (`POST /v1/pqz-verdict`
    /// with named fields: the token, the chain, the job's named op, the statement and proof the node rebuilt, the epoch); the
    /// first answer decoded with the bounded `UASig` decoder is used. None answers (refused, too long, a `UASig` past the bound, a
    /// non-2xx) ⇒ `PQZ_VERDICT_MISSING` back in the queue, zero sends; no endpoint at all ⇒ `dead` by name, nothing asked.
    #[tokio::test]
    async fn offchain_job_without_pqz_verdict_fetches_or_refuses() {
        let until = now() + 600;
        let (url, ver) = fake_verifier(answer_json(2, until, 0x7f)).await;
        let (r, rpc) = outcomes(offchain(), vec![pqz_job(7)], endpoints(vec![DEAD.into(), url.clone()])).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "the second endpoint answers: {r:?}");
        let v = sent_verdict("UAPqzTransferSingle", &rpc.lock().unwrap().sent[0].2);
        assert_eq!((v.sig, v.pqzVerdict.pqzVerifierEpoch, v.pqzVerdict.validUntil), (ua_sig(&verdict_auth(0x7f)), 2, until));
        assert_eq!(v.pqzVerdict.statementHash, alloy::primitives::keccak256(STATEMENT));
        let req = ver.lock().unwrap().reqs[0].clone();
        let keys: Vec<&str> = req.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["chainId", "op", "pqzVerifierEpoch", "proof", "statement", "token"], "named fields only: {req}");
        assert_eq!((req["token"].as_str(), req["chainId"].as_u64(), req["pqzVerifierEpoch"].as_u64()),
            (Some(format!("{TOKEN:#x}").as_str()), Some(31337), Some(2)));
        assert_eq!(req["statement"], json!(format!("0x{}", alloy::hex::encode(STATEMENT))));
        assert_eq!(req["proof"], pqz_job(7)["op"]["args"]["proof"]);
        // `op` as the reference verifier's `Op` reads it: the entry, the args struct (the sol types' serde form), the binding
        let op_keys: Vec<&str> = req["op"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(op_keys, ["args", "binding", "entry"], "the statement's inputs only: {}", req["op"]);
        assert_eq!((req["op"]["entry"].as_str(), req["op"]["binding"].as_str()),
            (Some("mtxConfidentialTransferSingle"), Some(format!("{BINDING:#x}").as_str())));
        let job_args = &pqz_job(7)["op"]["args"];
        assert_eq!(req["op"]["args"], crate::typed::to_serde_json("PqzTransferArgs",
            &crate::typed::parse("PqzTransferArgs", &job_args["args"], "args").unwrap()), "the job's named args");
        assert!(req["op"]["args"]["keyVersion"].is_u64() && req["op"]["args"]["validUntilBlock"].is_string(), "u64 numbers, u256 strings");
        // none answers: refused, a non-2xx, an answer above `max_response_bytes`, a UASig past the 16-slot bound
        let slot = json!({"index": 0, "members": [], "sig": "0x01"});
        let mut wide = answer_json(2, until, 0x7f);
        wide["pqzVerdictSig"]["members"] = json!(vec![slot; 17]);
        for (answer, cap, why) in [(Value::Null, 0, "not an object"), (answer_json(2, until, 0x7f), 64, "above max_response_bytes"),
            (wide, 0, "17 slots")] {
            let (url, _) = fake_verifier(answer).await;
            let (r, rpc) = outcomes(offchain(), vec![pqz_job(7)], move |c| {
                endpoints(vec![DEAD.into(), url])(c);
                if cap > 0 {
                    c.pqz_verifier.max_response_bytes = cap;
                }
            }).await;
            assert!(r.len() == 1 && r[0].0 == "queued" && r[0].1.starts_with("PQZ_VERDICT_MISSING"), "{why}: {r:?}");
            assert!(rpc.lock().unwrap().sent.is_empty(), "{why}");
        }
        let (url, ver) = fake_verifier(answer_json(2, until, 0x7f)).await;
        ver.lock().unwrap().status = 500;
        let (r, rpc) = outcomes(offchain(), vec![pqz_job(7)], endpoints(vec![url])).await;
        assert!(r.len() == 1 && r[0].0 == "queued" && r[0].1.starts_with("PQZ_VERDICT_MISSING"), "a 500 is no answer: {r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, rpc) = outcomes(offchain(), vec![pqz_job(7)], |_| {}).await;
        assert!(r.len() == 1 && r[0].0 == "dead" && r[0].1.starts_with("PQZ_VERDICT_MISSING"), "no endpoint: {r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty() && !rpc.lock().unwrap().calls.iter().any(|m| m == "eth_estimateGas"));
    }

    /// Spec §11.1: a `PRECOMPILE` token takes the empty verdict and never reads one, so a job naming `pqz_verdict` there is
    /// refused `PQZ_VERDICT_NOT_EXPECTED`, zero sends; without it the job is sent with the empty verdict, no endpoint asked. A token
    /// whose `pqzVerifyConfig()` reverts is no `OFFCHAIN` token: the same.
    #[tokio::test]
    async fn precompile_job_with_pqz_verdict_refused() {
        let precompile = || Evm { mtx_nonce: Some(0), pqz_cfg: Some((0, B256::ZERO, 0)), ..Default::default() };
        let j = with_verdict(pqz_job(7), verdict_json(0, now() + 600, 0x7e));
        let (url, ver) = fake_verifier(answer_json(0, now() + 600, 0x7f)).await;
        for e in [precompile(), Evm { mtx_nonce: Some(0), ..Default::default() }] {
            let (r, rpc) = outcomes(e, vec![j.clone()], endpoints(vec![url.clone()])).await;
            assert!(r.len() == 1 && r[0].0 == "dead" && r[0].1.starts_with("PQZ_VERDICT_NOT_EXPECTED"), "{r:?}");
            assert!(rpc.lock().unwrap().sent.is_empty());
        }
        for e in [precompile(), Evm { mtx_nonce: Some(0), ..Default::default() }] {
            let (r, rpc) = outcomes(e, vec![pqz_job(7)], endpoints(vec![url.clone()])).await;
            assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
            let v = sent_verdict("UAPqzTransferSingle", &rpc.lock().unwrap().sent[0].2);
            let empty = crate::abi::IPqzToken::PqzSignedVerdict { pqzVerdict: crate::abi::IPqzToken::PqzVerdict { token: Address::ZERO,
                chainId: U256::ZERO, proofSystemId: B256::ZERO, statementHash: B256::ZERO, proofHash: B256::ZERO, pqzVerifierEpoch: 0,
                validUntil: 0 }, sig: UASig { keyData: Bytes::new(), signature: Bytes::new(), members: vec![] } };
            assert_eq!(v, empty, "the empty verdict");
        }
        assert!(ver.lock().unwrap().reqs.is_empty(), "no endpoint asked for a PRECOMPILE token");
    }

    /// Spec §11.1: a verdict at another epoch than the token's is re-fetched once: the job's stale one ⇒ one request; the
    /// endpoint's answer still stale ⇒ back in the queue, zero sends (never a second re-fetch); a job without a verdict ⇒ the
    /// fetch and one re-fetch.
    #[tokio::test]
    async fn pqz_verdict_epoch_mismatch_refetch_once() {
        let until = now() + 600;
        let stale = with_verdict(pqz_job(7), verdict_json(1, until, 0x7e));
        let (url, ver) = fake_verifier(answer_json(2, until, 0x7f)).await;
        let (r, rpc) = outcomes(offchain(), vec![stale.clone()], endpoints(vec![url])).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        assert_eq!(sent_verdict("UAPqzTransferSingle", &rpc.lock().unwrap().sent[0].2).sig, ua_sig(&verdict_auth(0x7f)));
        assert_eq!(ver.lock().unwrap().reqs.len(), 1);
        let (url, ver) = fake_verifier(answer_json(1, until, 0x7f)).await;
        let (r, rpc) = outcomes(offchain(), vec![stale], endpoints(vec![url.clone()])).await;
        assert!(r.len() == 1 && r[0].0 == "queued" && r[0].1.starts_with("PQZ_VERDICT_MISSING"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        assert_eq!(ver.lock().unwrap().reqs.len(), 1, "one re-fetch on a mismatch");
        let (r, _) = outcomes(offchain(), vec![pqz_job(7)], endpoints(vec![url])).await;
        assert!(r.len() == 1 && r[0].0 == "queued", "{r:?}");
        assert_eq!(ver.lock().unwrap().reqs.len(), 3, "the fetch and one re-fetch");
        // an expiring verdict (inside `valid_margin_secs`) is no usable verdict either
        let (url, ver) = fake_verifier(answer_json(2, until, 0x7f)).await;
        let soon = with_verdict(pqz_job(7), verdict_json(2, now() + 5, 0x7e));
        let (r, _) = outcomes(offchain(), vec![soon], endpoints(vec![url])).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        assert_eq!(ver.lock().unwrap().reqs.len(), 1);
    }

    /// Spec §11.1: the token's verdict refusals are named and never `dead` while the op may land with another verdict:
    /// `PqzVerdictMismatch` in the simulation back in the queue; after an indexed `UAPqzKeyCurrent` of a party it is
    /// `PQZ_KEY_ROTATED` (T55); a revoked verifier (`pqzVerifyConfig().verifier == 0`) back in the queue, nothing fetched.
    #[tokio::test]
    async fn pqz_verdict_mismatch_not_dead() {
        let j = with_verdict(pqz_job(7), verdict_json(2, now() + 600, 0x7e));
        let (r, rpc) = outcomes(Evm { sim: Some("verdict_mismatch"), ..offchain() }, vec![j.clone()], |_| {}).await;
        assert!(r.len() == 1 && r[0].0 == "queued" && r[0].1.starts_with("PQZ_VERDICT_REFUSED: PqzVerdictMismatch"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty());
        let (r, _) = outcomes(Evm { sim: Some("verdict_mismatch"), pqz_rotated: true, ..offchain() }, vec![j.clone()], |_| {}).await;
        assert!(r.len() == 1 && r[0].0 == "queued" && r[0].1.starts_with("PQZ_KEY_ROTATED: PqzVerdictMismatch"), "{r:?}");
        let (url, ver) = fake_verifier(answer_json(2, now() + 600, 0x7f)).await;
        let revoked = Evm { pqz_cfg: Some((1, B256::ZERO, 3)), ..offchain() };
        let (r, rpc) = outcomes(revoked, vec![pqz_job(7)], endpoints(vec![url])).await;
        assert!(r.len() == 1 && r[0].0 == "queued" && r[0].1.contains("PqzVerifierRevoked"), "{r:?}");
        assert!(rpc.lock().unwrap().sent.is_empty() && ver.lock().unwrap().reqs.is_empty());
    }

    /// The node never asks for the PQZ precompile on an `OFFCHAIN` token's job (spec §3, O1: OFFCHAIN ignores whether a
    /// precompile exists): sent on a chain where nothing has code at `0x…5caa0f01`.
    #[tokio::test]
    async fn offchain_job_not_refused_without_precompile() {
        let j = with_verdict(pqz_job(7), verdict_json(2, now() + 600, 0x7e));
        let (r, rpc) = outcomes(offchain(), vec![j], |_| {}).await;
        assert_eq!(states_of(&r), ["signed", "broadcast"], "{r:?}");
        let pqz: Address = "0x000000000000000000000000000000005caa0f01".parse().unwrap();
        assert!(!rpc.lock().unwrap().code_asked.contains(&pqz));
    }

    /// A shield (`UAShield`) and a wrap-shield (`WrapShield`) job of the payer on the fake PQZ token.
    fn shield_jobs() -> Vec<Value> {
        let v = crate::typed::testkit::vectors();
        let mut out = vec![];
        for (id, name) in [(7, "UAShield"), (8, "WrapShield")] {
            let mut op = crate::typed::testkit::op_of(name, "pqz", &v).unwrap();
            op["token"] = json!(format!("{TOKEN:#x}"));
            op["validUntil"] = json!((now() + 600).to_string());
            let from = if name == "UAShield" { format!("{:#x}", payer().into_word()) } else { format!("{:#x}", payer()) };
            op["envelope"]["from"] = json!(from);
            op["envelope"]["validUntil"] = json!((now() + 600).to_string());
            let sentinel = json!(format!("0x{}", "11".repeat(65)));
            if name == "UAShield" { op["auth"]["signature"] = sentinel } else { op["signature"] = sentinel }
            let kind = if name == "UAShield" { "ua_metatx" } else { "metatx" };
            out.push(json!({"id": id, "kind": kind, "op": op}));
        }
        out
    }

    /// Spec §11.1 (C8): with `refuse_shield_when_unserved` on, a shield or wrap-shield into an `OFFCHAIN` token whose verifier
    /// is revoked (the endpoints serving) or whose endpoints none serves it (none answers, its probe refused, none configured;
    /// the verifier set) is refused `PQZ_VERIFIER_UNREACHABLE`, zero sends; the controls: the verifier set and an endpoint whose
    /// probe answers, a `PRECOMPILE` token.
    #[tokio::test]
    async fn shield_refused_when_unserved_and_enabled() {
        let (url, ver) = fake_verifier(answer_json(2, now() + 600, 0x7f)).await;
        let (refusing, r) = fake_verifier(json!({"error": "NOT_THIS_VERIFIER", "detail": "x"})).await;
        r.lock().unwrap().status = 422;
        let on = |urls: Vec<String>| move |c: &mut ChainCfg| {
            endpoints(urls)(c);
            c.pqz_verifier.refuse_shield_when_unserved = true;
        };
        let revoked = Evm { pqz_cfg: Some((1, B256::ZERO, 3)), ..offchain() };
        for (e, urls, why) in [(revoked, vec![url.clone()], "revoked"), (offchain(), vec![DEAD.to_string()], "unreachable"),
            (offchain(), vec![refusing.clone()], "probe refused"), (offchain(), vec![], "no endpoint")] {
            let (r, rpc) = outcomes(e, shield_jobs(), on(urls)).await;
            assert!(r.len() == 2 && r.iter().all(|x| x.0 == "dead" && x.1.starts_with("PQZ_VERIFIER_UNREACHABLE")), "{why}: {r:?}");
            assert!(rpc.lock().unwrap().sent.is_empty(), "{why}");
        }
        let precompile = Evm { mtx_nonce: Some(0), pqz_cfg: Some((0, B256::ZERO, 0)), ..Default::default() };
        for (e, urls) in [(offchain(), vec![DEAD.to_string(), refusing, url.clone()]), (precompile, vec![])] {
            let (r, rpc) = outcomes(e, shield_jobs(), on(urls)).await;
            assert_eq!(states_of(&r), ["signed", "broadcast", "signed", "broadcast"], "{r:?}");
            assert_eq!(rpc.lock().unwrap().sent.len(), 2);
        }
        let probe = ver.lock().unwrap().reqs.last().cloned().unwrap();
        assert_eq!((probe["token"].as_str(), probe["chainId"].as_u64()), (Some(format!("{TOKEN:#x}").as_str()), Some(31337)), "the probe");
    }

    /// The switch is off by default: a shield into a token whose verifier is revoked and that no endpoint serves is sent.
    #[tokio::test]
    async fn shield_sent_when_disabled() {
        let revoked = Evm { pqz_cfg: Some((1, B256::ZERO, 3)), ..offchain() };
        let (r, rpc) = outcomes(revoked, shield_jobs(), endpoints(vec![DEAD.into()])).await;
        assert_eq!(states_of(&r), ["signed", "broadcast", "signed", "broadcast"], "{r:?}");
        assert_eq!(rpc.lock().unwrap().sent.len(), 2);
        assert!(!crate::config::PqzVerifierCfg::default().refuse_shield_when_unserved);
    }
}
