//! Store v2 của node (NI spec §4, R88–R95, R110; A1 = R111). Một store, luôn mở, một process chủ (owner lock +
//! fencing epoch). Backend sau trait `Backend`: SQLite ở P1; PostgreSQL/MySQL ở P1b cài cùng trait, cùng bộ test
//! hợp đồng (`tests.rs`). Logic thuần (bảng chuyển trạng thái, chuỗi hash audit, so drift toml) nằm ở đây, chung
//! cho mọi backend; backend chỉ giữ SQL.
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[cfg(feature = "store-sqlite")]
pub mod sqlite;
#[cfg(all(test, feature = "store-sqlite"))]
mod tests;

pub type Store = Arc<dyn Backend>;

/// Mở store CÓ SẴN theo scheme của `[store] url`: lấy owner lock, migrate, tăng fencing epoch, incarnation mới.
/// Store vắng mặt ⇒ lỗi (review F5); store mới chỉ qua `create` (`scaas-node store init`).
pub async fn open(url: &str, owner: &str) -> Result<Store> {
    open_with(url, owner, false).await
}

/// `scaas-node store init`: tạo store mới; store đã có ⇒ lỗi.
pub async fn create(url: &str, owner: &str) -> Result<Store> {
    open_with(url, owner, true).await
}

async fn open_with(url: &str, owner: &str, create: bool) -> Result<Store> {
    #[cfg(feature = "store-sqlite")]
    if url.starts_with("sqlite:") {
        let s = match create {
            true => sqlite::SqliteStore::create(url, owner).await?,
            false => sqlite::SqliteStore::open(url, owner).await?,
        };
        return Ok(Arc::new(s));
    }
    let _ = (owner, create);
    Err(StoreError::Invalid(format!("unsupported store url scheme: {}", url.split(':').next().unwrap_or(""))))
}

// ------------------------------------------------------------------ errors

#[derive(Debug)]
pub enum StoreError {
    /// Process khác giữ owner lock (A1.1): không khởi động.
    Owned(String),
    /// Fencing epoch đã đổi: process này không còn là chủ, không được ghi journal (và vì vậy không broadcast).
    NotOwner,
    /// Cặp chuyển trạng thái không có trong `TRANSITIONS`.
    Illegal { from: State, to: State },
    NotFound,
    Invalid(String),
    Db(sqlx::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Owned(m) => write!(f, "store is owned by another process: {m}"),
            Self::NotOwner => f.write_str("NOT_OWNER: fencing epoch changed"),
            Self::Illegal { from, to } => write!(f, "transition {} -> {} is not allowed", from.as_str(), to.as_str()),
            Self::NotFound => f.write_str("job not found"),
            Self::Invalid(m) => f.write_str(m),
            Self::Db(e) => write!(f, "store: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<sqlx::Error> for StoreError {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e)
    }
}

impl From<sqlx::migrate::MigrateError> for StoreError {
    fn from(e: sqlx::migrate::MigrateError) -> Self {
        Self::Db(e.into())
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

// ------------------------------------------------------------------ job state machine (§4, transitions.json)

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Queued,
    Leased,
    Signed,
    Broadcast,
    Mined,
    Reverted,
    Dead,
    Consumed,
    Cancelled,
}

use State::*;

impl State {
    pub const ALL: [State; 9] = [Queued, Leased, Signed, Broadcast, Mined, Reverted, Dead, Consumed, Cancelled];
    /// Trạng thái giữ `job_live_digest` (G2 bền).
    pub const LIVE: [State; 4] = [Queued, Leased, Signed, Broadcast];

    pub fn as_str(self) -> &'static str {
        match self {
            Queued => "queued",
            Leased => "leased",
            Signed => "signed",
            Broadcast => "broadcast",
            Mined => "mined",
            Reverted => "reverted",
            Dead => "dead",
            Consumed => "consumed",
            Cancelled => "cancelled",
        }
    }

    pub fn is_live(self) -> bool {
        Self::LIVE.contains(&self)
    }
}

impl TryFrom<String> for State {
    type Error = String;
    fn try_from(s: String) -> std::result::Result<Self, String> {
        Self::ALL.into_iter().find(|x| x.as_str() == s).ok_or_else(|| format!("unknown job state {s}"))
    }
}

/// Bảng của node, phản chiếu Odoo `TRANSITIONS` (`blockchain_relay_job.py:20-26`) + `leased`/`cancelled`.
/// `tests/api/transitions.json` là bản chung với Odoo; test so hai bên.
pub const TRANSITIONS: &[(State, &[State])] = &[
    (Queued, &[Leased, Cancelled, Dead]),
    (Leased, &[Queued, Signed, Dead, Consumed, Cancelled]),
    (Signed, &[Broadcast, Mined, Reverted, Queued, Dead, Consumed]),
    (Broadcast, &[Broadcast, Mined, Reverted, Queued, Dead, Consumed]),
    (Mined, &[Reverted]),
];
/// Báo cáo muộn sau `consumed`: no-op, không ghi.
pub const LATE_NOOP: &[(State, &[State])] = &[(Consumed, &[Mined, Reverted, Consumed])];

fn in_table(t: &[(State, &[State])], from: State, to: State) -> bool {
    t.iter().any(|(f, tos)| *f == from && tos.contains(&to))
}

pub fn allowed(from: State, to: State) -> bool {
    in_table(TRANSITIONS, from, to)
}

pub fn late_noop(from: State, to: State) -> bool {
    in_table(LATE_NOOP, from, to)
}

/// Kiểm thuần trước mọi CAS `transition`, chung cho mọi backend.
/// - `Cancelled` chỉ qua `cancel`/`cancel_by_origin` (R98: đã publish ⇒ hold + TOO_LATE, không bao giờ huỷ); cặp
///   vẫn nằm trong `TRANSITIONS` để khớp `transitions.json`.
/// - `outer_nonce` chỉ đi với `signed` (nó nâng `lane.journal_max`); `tx_hash` chỉ với `signed` và `broadcast`
///   (thay thế).
pub fn check_transition(from: State, to: State, f: &Fields) -> Result<()> {
    if to == Cancelled || !(allowed(from, to) || late_noop(from, to)) {
        return Err(StoreError::Illegal { from, to });
    }
    let refuse = |m: &str| Err(StoreError::Invalid(format!("{} -> {}: {m}", from.as_str(), to.as_str())));
    if to == Leased && f.lane_label.is_none() {
        return refuse("a lease names its lane");
    }
    if to == Signed && (f.outer_nonce.is_none() || f.tx_hash.is_none()) {
        return refuse("signed needs outer_nonce and tx_hash");
    }
    if to != Signed && f.outer_nonce.is_some() {
        return refuse("outer_nonce is journaled only on signed");
    }
    if !matches!(to, Signed | Broadcast) && f.tx_hash.is_some() {
        return refuse("tx_hash is journaled only on signed or broadcast");
    }
    Ok(())
}

// ------------------------------------------------------------------ jobs

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub scope: String,
    pub producer: String,
    pub key: String,
    pub generation: i64,
}

/// Một job mới. `digest` và `payload_hash` do NODE tính (R89, R91) trước khi gọi store.
#[derive(Debug, Clone)]
pub struct NewJob {
    pub namespace: String,
    pub origin: Origin,
    pub client_ref: Option<String>,
    pub chain_key: String,
    /// `metatx` | `call` | `signed_op` (CHECK trong DDL).
    pub kind: String,
    pub digest: Option<[u8; 32]>,
    pub payload: Vec<u8>,
    pub payload_hash: [u8; 32],
    /// unix s.
    pub valid_until: i64,
    pub lane_hint: Option<String>,
    /// `restricted` | `open` | `public`.
    pub bus_scope: String,
    pub private_window_secs: i64,
}

/// Snapshot một dòng `job` (C1: kết quả accept và feed mang snapshot).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct JobRow {
    pub uid: i64,
    pub namespace: String,
    pub origin_scope: String,
    pub origin_producer: String,
    pub origin_key: String,
    pub generation: i64,
    pub client_ref: Option<String>,
    pub chain_key: String,
    pub kind: String,
    pub digest: Option<Vec<u8>>,
    pub payload: Option<Vec<u8>>,
    pub payload_hash: Option<Vec<u8>>,
    pub valid_until: i64,
    pub lane_hint: Option<String>,
    pub bus_scope: String,
    pub private_window_secs: i64,
    pub published_at: Option<i64>,
    pub hold: bool,
    #[sqlx(try_from = "String")]
    pub state: State,
    pub lane_label: Option<String>,
    pub outer_nonce: Option<i64>,
    pub tx_hash: Option<String>,
    pub claim_block: Option<i64>,
    pub attempt_count: i64,
    pub last_error: Option<String>,
    pub last_seq: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Kết quả accept (§5.2 bước 8, R91).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // a short-lived return value, never stored in bulk
pub enum Accept {
    Created(JobRow),
    /// Cùng khoá + cùng hash, hoặc tombstone (`state = cancelled`): trả snapshot hiện tại.
    Existing(JobRow),
    IdempotencyMismatch { uid: i64 },
    PreviousGenerationLive { uid: i64 },
    /// Có generation cao hơn dưới cùng khoá (`409 SUPERSEDED`): một push cũ, không bao giờ tạo lại.
    Superseded { uid: i64 },
    /// `valid_until` đã qua (`422 EXPIRED`): khoá đã purge không bao giờ được nhận lại (§4).
    Expired,
    DuplicateDigest,
    Quota,
}

/// Trường đi kèm một chuyển trạng thái. `lane_label`/`claim_block` ghi ở `leased` (lane phải có trong store);
/// `lane_label` ở `signed` phải là lane đã lease. `outer_nonce` + `tx_hash` bắt buộc cho `signed` (nonce chỉ ở đó;
/// `tx_hash` thêm ở `broadcast` thay thế), xem `check_transition`. Về `queued` xoá các trường journal.
#[derive(Debug, Clone, Default)]
pub struct Fields {
    pub lane_label: Option<String>,
    pub claim_block: Option<i64>,
    pub outer_nonce: Option<i64>,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
}

/// Ba trạng thái của `transition` (§9.1, review H3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// Đã commit; `seq` của `job_event`.
    Ok { seq: i64 },
    /// Dòng không ở `from` (người khác đã chuyển, hoặc job bị hold / ghim lane khác): không ghi gì.
    /// `Moved{signed, tx_hash của ta}` sau một lần thử lại = journal của ta đã có, gửi được.
    Moved { state: State, tx_hash: Option<String> },
    /// Không biết commit có thành không (mất kết nối sau COMMIT): đọc lại dòng trước mọi hành động.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // a short-lived return value, never stored in bulk
pub enum Cancel {
    Cancelled(JobRow),
    /// `409 TOO_LATE`. `published` ⇒ nếu còn `queued`, job đã bị `hold` (không bao giờ lease ở đây).
    TooLate { state: State, published: bool },
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct JobEvent {
    pub seq: i64,
    pub job_uid: i64,
    pub namespace: String,
    pub state: String,
    pub tx_hash: Option<String>,
    pub outer_nonce: Option<i64>,
    pub signer: Option<String>,
    pub error: Option<String>,
    pub at: i64,
}

/// Danh tính store trên mỗi trang feed (R93) và ở `/v1/info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub store_id: String,
    pub incarnation: String,
    /// Fencing epoch của process này (A1.1).
    pub epoch: i64,
    pub restore_epoch: i64,
}

// ------------------------------------------------------------------ audit (R110, §7.5)

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditEntry {
    /// `user` | `oidc` | `cli` | `bootstrap`.
    pub actor_kind: String,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub roles: String,
    pub method: String,
    pub route: String,
    pub target: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    pub result: i64,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AuditRow {
    pub seq: i64,
    pub at: i64,
    pub actor_kind: String,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub roles: String,
    pub method: String,
    pub route: String,
    pub target: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    pub result: i64,
    pub request_id: String,
    pub prev_hash: Vec<u8>,
    pub row_hash: Vec<u8>,
}

/// `row_hash = sha256(prev_hash ‖ canonical row)`. Dạng chuẩn: mỗi trường theo thứ tự cột, `u32be(len) ‖ bytes`,
/// NULL = `u32be(0xFFFF_FFFF)`; số nguyên là i64 big-endian. Không mơ hồ, không phụ thuộc backend.
pub fn audit_hash(prev: &[u8], seq: i64, at: i64, e: &AuditEntry) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(seq.to_be_bytes());
    h.update(at.to_be_bytes());
    let texts = [Some(&e.actor_kind), e.iss.as_ref(), e.sub.as_ref(), Some(&e.roles), Some(&e.method),
                 Some(&e.route), e.target.as_ref(), e.before.as_ref(), e.after.as_ref()];
    for t in texts {
        match t {
            Some(s) => {
                h.update((s.len() as u32).to_be_bytes());
                h.update(s.as_bytes());
            }
            None => h.update(u32::MAX.to_be_bytes()),
        }
    }
    h.update(e.result.to_be_bytes());
    h.update((e.request_id.len() as u32).to_be_bytes());
    h.update(e.request_id.as_bytes());
    h.finalize().into()
}

impl AuditRow {
    fn entry(&self) -> AuditEntry {
        AuditEntry {
            actor_kind: self.actor_kind.clone(),
            iss: self.iss.clone(),
            sub: self.sub.clone(),
            roles: self.roles.clone(),
            method: self.method.clone(),
            route: self.route.clone(),
            target: self.target.clone(),
            before: self.before.clone(),
            after: self.after.clone(),
            result: self.result,
            request_id: self.request_id.clone(),
        }
    }
}

/// Kiểm chuỗi audit theo `seq`; trả hash đầu chuỗi (`scaas_audit_head_info`), hoặc `seq` đầu tiên bị sửa.
pub fn verify_audit(rows: &[AuditRow]) -> std::result::Result<[u8; 32], i64> {
    let mut prev = [0u8; 32];
    for r in rows {
        if r.prev_hash != prev || r.row_hash != audit_hash(&prev, r.seq, r.at, &r.entry()) {
            return Err(r.seq);
        }
        prev = audit_hash(&prev, r.seq, r.at, &r.entry());
    }
    Ok(prev)
}

// ------------------------------------------------------------------ configuration authority (R95, §8)

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct ChainRow {
    pub chain_key: String,
    pub family: String,
    /// `active` | `paused` | `halted` — không có trong toml (import = `active`).
    pub state: String,
    pub profile: String,
    pub finality_mode: String,
    pub finality_depth: i64,
    pub finality_quorum: i64,
    pub fee_recipient: Option<String>,
    pub poll_ms: i64,
    pub stuck_after_secs: i64,
    pub max_gas_per_tx: i64,
    pub max_fee_cap_gwei: i64,
    pub max_index_lag: i64,
    /// `BreakerCfg` dạng JSON (metadata nhỏ).
    pub breaker: String,
    pub dex: Option<String>,
    pub gossip: bool,
    pub exclusive_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct TokenRow {
    pub chain_key: String,
    pub address: String,
    pub decimals: i64,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct LaneRow {
    pub chain_key: String,
    pub label: String,
    pub account_index: i64,
    /// Đơn điệu, chỉ journal tăng; không bao giờ đến từ toml.
    pub journal_max: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NamespaceRow {
    pub name: String,
    pub state: String,
    pub allow_call: bool,
    pub max_live_jobs: i64,
    /// Chain được cấp, sắp xếp.
    pub chains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct PeerRow {
    pub name: String,
    pub url: String,
    pub spki_sha256: String,
    pub class: String,
    /// Chain key cách nhau bởi dấu cách.
    pub chains: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
pub struct PolicyRow {
    pub chain_key: String,
    pub contract: String,
    pub selector: String,
    pub support: String,
    pub submit: bool,
    pub pool_visibility: String,
    pub min_fee: String,
    pub fee_recipient_allow: String,
    pub gossip: bool,
}

/// Cấu hình không bí mật: dựng từ toml (bootstrap) hoặc đọc từ store (snapshot runtime).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ConfigSet {
    pub chains: Vec<ChainRow>,
    pub tokens: Vec<TokenRow>,
    pub lanes: Vec<LaneRow>,
    pub namespaces: Vec<NamespaceRow>,
    pub peers: Vec<PeerRow>,
    pub policy: Vec<PolicyRow>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootReport {
    /// `chain:evm:7622`, `token:evm:7622/0x…`… đã import.
    pub imported: Vec<String>,
    /// Có trong store và khác toml: không ghi đè (R95), chỉ cảnh báo + gauge `scaas_config_toml_drift`.
    pub drift: Vec<String>,
}

/// Tách `toml` thành phần vắng mặt trong store (để import) và nhãn của phần lệch. `view` xoá các trường không
/// đến từ toml (state, journal_max…) trước khi so.
fn split<T: Clone + PartialEq + Label, K: PartialEq>(
    stored: &[T],
    toml: &[T],
    key: impl Fn(&T) -> K,
    view: impl Fn(&T) -> T,
    report: &mut BootReport,
) -> Vec<T> {
    let mut absent = Vec::new();
    for t in toml {
        match stored.iter().find(|s| key(s) == key(t)) {
            None => {
                report.imported.push(t.label());
                absent.push(t.clone());
            }
            Some(s) if view(s) != view(t) => report.drift.push(t.label()),
            Some(_) => {}
        }
    }
    absent
}

/// Nhãn một mục cấu hình trong báo cáo bootstrap và cột `target` của audit.
pub trait Label {
    fn label(&self) -> String;
}
impl Label for ChainRow {
    fn label(&self) -> String {
        format!("chain:{}", self.chain_key)
    }
}
impl Label for TokenRow {
    fn label(&self) -> String {
        format!("token:{}/{}", self.chain_key, self.address)
    }
}
impl Label for LaneRow {
    fn label(&self) -> String {
        format!("lane:{}/{}", self.chain_key, self.label)
    }
}
impl Label for NamespaceRow {
    fn label(&self) -> String {
        format!("namespace:{}", self.name)
    }
}
impl Label for PeerRow {
    fn label(&self) -> String {
        format!("peer:{}", self.name)
    }
}
impl Label for PolicyRow {
    fn label(&self) -> String {
        format!("policy:{}/{}/{}", self.chain_key, self.contract, self.selector)
    }
}

/// Phần toml chưa có trong store + báo cáo (R95: có rồi thì không ghi đè).
pub fn plan_bootstrap(stored: &ConfigSet, toml: &ConfigSet) -> (ConfigSet, BootReport) {
    let mut r = BootReport::default();
    let set = ConfigSet {
        chains: split(&stored.chains, &toml.chains, |c| c.chain_key.clone(),
                      |c| ChainRow { state: String::new(), ..c.clone() }, &mut r),
        tokens: split(&stored.tokens, &toml.tokens, |t| (t.chain_key.clone(), t.address.clone()),
                      |t| TokenRow { active: true, ..t.clone() }, &mut r),
        lanes: split(&stored.lanes, &toml.lanes, |l| (l.chain_key.clone(), l.label.clone()),
                     |l| LaneRow { journal_max: None, ..l.clone() }, &mut r),
        namespaces: split(&stored.namespaces, &toml.namespaces, |n| n.name.clone(),
                          |n| NamespaceRow { state: String::new(), ..n.clone() }, &mut r),
        peers: split(&stored.peers, &toml.peers, |p| p.name.clone(), Clone::clone, &mut r),
        policy: split(&stored.policy, &toml.policy, |p| (p.chain_key.clone(), p.contract.clone(), p.selector.clone()),
                      Clone::clone, &mut r),
    };
    (set, r)
}

/// Bootstrap R95 (§8): import phần toml vắng mặt (mỗi mục một dòng audit `bootstrap`), báo drift.
pub async fn bootstrap(store: &dyn Backend, toml: &ConfigSet, now_ms: i64) -> Result<BootReport> {
    let stored = store.load_config().await?;
    let (absent, report) = plan_bootstrap(&stored, toml);
    if !report.imported.is_empty() {
        store.import(&absent, now_ms).await?;
    }
    Ok(report)
}

// ------------------------------------------------------------------ backend

/// Một backend lưu trữ (R111: "storage only"). Mọi phương thức ghi journal (job CAS, feed, audit) kiểm fencing
/// epoch trong chính transaction và trả `NotOwner` khi epoch đổi. P1b thêm `postgres.rs`/`mysql.rs` với cùng
/// trait; mọi khác biệt dialect (placeholder, `GREATEST`, khoá advisory, phân loại unique theo tên constraint)
/// nằm trong backend.
#[async_trait]
pub trait Backend: Send + Sync {
    fn identity(&self) -> &Identity;

    /// Giá trị hiện tại của một counter (`job`, `job_event`, `feed_item`, `audit`, `intent`) = `head_seq`.
    async fn head_seq(&self, counter: &str) -> Result<i64>;

    /// §5.2 bước 8 trong một transaction: idempotency (R91), tombstone, generation, quota, INSERT, `job_event`.
    async fn accept(&self, job: &NewJob, now_ms: i64) -> Result<Accept>;

    /// CAS `from → to` + `job_event` + `job.last_seq` + `lane.journal_max` + fencing, một transaction.
    /// Trước hết `check_transition` (không bao giờ vào `cancelled`). `queued → leased` cần `hold = 0`, `lane_hint`
    /// rỗng hoặc bằng `fields.lane_label`, và lane có trong store.
    /// Lỗi DB ⇒ `Transition::Unknown` (người gọi đọc lại dòng); `NotOwner`/`Illegal`/`NotFound` là `Err`.
    async fn transition(&self, uid: i64, from: State, to: State, fields: &Fields, now_ms: i64) -> Result<Transition>;

    /// R98: `queued`/`leased` chưa publish ⇒ `cancelled`; `queued` đã publish ⇒ `hold = 1` + `TooLate`.
    async fn cancel(&self, uid: i64, now_ms: i64) -> Result<Cancel>;

    /// Huỷ theo origin; không có job ⇒ ghi tombstone `cancelled` hết hạn ở `valid_until` (unix s).
    async fn cancel_by_origin(&self, namespace: &str, origin: &Origin, valid_until: i64, now_ms: i64) -> Result<Cancel>;

    /// Đặt `published_at` cho job còn `queued` chưa publish (R99, node tự publish). `false` nếu không đổi gì.
    async fn publish(&self, uid: i64, now_ms: i64) -> Result<bool>;

    async fn job(&self, uid: i64) -> Result<Option<JobRow>>;

    /// `job_event` với `seq > after`, theo `seq`.
    async fn job_events(&self, after: i64, limit: i64) -> Result<Vec<JobEvent>>;

    /// Đầu vào `plan()` (R18): `lane.journal_max`, không bao giờ là aggregate trên dòng job (purge được).
    async fn journal_max(&self, chain_key: &str, lane: &str) -> Result<Option<i64>>;

    /// `max(journal_max, n)` có fencing — cho báo cáo `signed` của đường legacy (R104).
    async fn bump_journal_max(&self, chain_key: &str, lane: &str, nonce: i64) -> Result<()>;

    /// Janitor: job kết thúc với `updated_at < now − job_retention` VÀ `valid_until < now − 86 400`;
    /// `job_event`/`feed_item` cũ hơn `feed_retention`. Trả số dòng job đã xoá.
    async fn purge(&self, now_ms: i64, job_retention_secs: i64, feed_retention_secs: i64) -> Result<u64>;

    /// `seq` cao nhất đã purge của `job_event`/`feed_item` (0 = chưa purge gì). R93: `cursor < floor` ⇒ `410`.
    async fn purge_floor(&self, feed: &str) -> Result<i64>;

    /// Kiểm rẻ A1.1 (≤ 2 s): file khoá vẫn là file đang giữ (`Owned` nếu không) và epoch vẫn của ta (`NotOwner`).
    async fn check_owner(&self) -> Result<()>;

    async fn append_audit(&self, entry: &AuditEntry, now_ms: i64) -> Result<AuditRow>;

    async fn audit_log(&self) -> Result<Vec<AuditRow>>;

    /// CLI `store restored`: `restore_epoch + 1` + dòng audit, một transaction. Trả epoch mới.
    async fn mark_restored(&self, entry: &AuditEntry, now_ms: i64) -> Result<i64>;

    async fn load_config(&self) -> Result<ConfigSet>;

    /// INSERT các dòng (chưa có) + một dòng audit `bootstrap` mỗi mục. Dùng qua `bootstrap()`.
    async fn import(&self, set: &ConfigSet, now_ms: i64) -> Result<()>;
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Janitor: `check_owner` mỗi `check_every` (A1.1, 2 s ở `main.rs`), purge mỗi `purge_every` (60 s). Mất quyền
/// chủ (`NotOwner`, `Owned`) là lỗi chết: trả `Err`, `main` thoát, supervisor khởi động lại — process bị fence
/// không chạy tiếp các đường legacy. Lỗi DB khác chỉ cảnh báo.
pub async fn janitor(store: Store, check_every: Duration, purge_every: Duration, job_retention_secs: i64,
                     feed_retention_secs: i64) -> Result<()> {
    let fatal = |e: StoreError| match e {
        StoreError::NotOwner | StoreError::Owned(_) => Err(e),
        e => {
            tracing::warn!("store janitor: {e}");
            Ok(())
        }
    };
    let mut last_purge = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(check_every).await;
        if let Err(e) = store.check_owner().await {
            fatal(e)?;
        }
        if last_purge.elapsed() < purge_every {
            continue;
        }
        last_purge = tokio::time::Instant::now();
        match store.purge(now_ms(), job_retention_secs, feed_retention_secs).await {
            Ok(n) if n > 0 => tracing::info!(purged = n, "store janitor"),
            Ok(_) => {}
            Err(e) => fatal(e)?,
        }
    }
}
