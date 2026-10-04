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
/// Cầu dao (R55) chỉ chặn việc claim job MỚI; job đang bay của lane được `lane_step` theo dõi tới cùng.
pub async fn lane_runner(
    adapter: Arc<dyn ChainAdapter>,
    odoo: Odoo,
    lane: usize,
    worker: String,
    poll: Duration,
    breaker: Arc<Mutex<Breaker>>,
) {
    let key = adapter.chain_key().to_string();
    info!(chain = %key, lane, address = %adapter.lanes()[lane].address, "lane ready");
    let (mut tripped, mut sampled) = (None, None::<std::time::Instant>);
    loop {
        if sampled.is_none_or(|t| t.elapsed() >= Duration::from_secs(15)) {
            sampled = Some(std::time::Instant::now());
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
        match lane_step_metered(adapter.as_ref(), &odoo, lane, &worker, Some(&breaker)).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => warn!(chain = %key, lane, "lane: {e:#}"),
        }
        tokio::time::sleep(poll).await;
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
    let mut sent = adapter.submit(&signed).await;
    if sent.is_ok() {
        report(odoo, rep(job.id, "broadcast")).await;
    }
    loop {
        match adapter.tx_status(&signed.tx_id).await {
            Ok(TxStatus::Mined { .. }) => {
                if let (Some(k), Ok(Some(fee))) = (breaker, adapter.tx_fee(&signed.tx_id).await) {
                    if let Ok(mut k) = k.lock() {
                        k.spend(now(), fee);
                    }
                }
                report(odoo, rep(job.id, "mined")).await;
                return Ok(true);
            }
            Ok(TxStatus::Reverted { reason }) => {
                report(odoo, Report { error: Some(reason), ..rep(job.id, "reverted") }).await;
                return Ok(true);
            }
            Ok(TxStatus::Pending) => {}
            Err(e) if e.downcast_ref::<Rejected>().is_some() => {
                report(odoo, Report { error: Some(e.to_string()), ..rep(job.id, "queued") }).await;
                return Ok(true);
            }
            Ok(TxStatus::Unknown) | Err(_) => {
                // Hỏi trạng thái TRƯỚC: bị từ chối khi gửi lại có thể vì tx lần trước đã vào khối.
                if let Some(r) = sent.as_ref().err().and_then(|e| e.downcast_ref::<Rejected>()) {
                    report(odoo, Report { error: Some(r.to_string()), ..rep(job.id, "queued") }).await;
                    return Ok(true);
                }
                if now() > signed.valid_until + EXPIRY_GRACE {
                    // Payload chủ thể đã hết hạn: tx (nếu còn đâu đó) sẽ bị contract từ chối.
                    report(odoo, Report { error: Some("expired before inclusion".into()), ..rep(job.id, "dead") }).await;
                    return Ok(true);
                }
                if sent.is_err() {
                    sent = adapter.submit(&signed).await;
                    if sent.is_ok() {
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
mod tests {
    use super::*;

    #[test]
    fn families_parse() {
        assert_eq!(Family::parse("sui"), Some(Family::Sui));
        assert_eq!(Family::parse("solana"), None);
    }

    /// Adapter giả: lane luôn bị CheckTx từ chối, indexer ghi lại tập contract được đưa vào.
    #[derive(Default)]
    struct Mock(std::sync::Mutex<Vec<Vec<String>>>);

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
    }

    #[derive(Default)]
    struct Fake {
        tokens: Value,
        jobs: Vec<Value>,
        reports: Vec<Value>,
        ingests: u32,
    }
    type Shared = Arc<std::sync::Mutex<Fake>>;

    async fn fake_odoo(fake: Fake) -> (Odoo, Shared) {
        use axum::extract::{Path, State};
        use axum::Json;
        async fn h(State(s): State<Shared>, Path((_m, method)): Path<(String, String)>, Json(b): Json<Value>) -> Json<Value> {
            let mut o = s.lock().unwrap();
            Json(match method.as_str() {
                "node_config" => serde_json::json!({"finality_mode": "instant", "finality_depth": 0, "finality_quorum": 1,
                    "indexed_block": 0, "tokens": o.tokens, "journal_max_nonce": null}),
                "relay_poll" => Value::Array(std::mem::take(&mut o.jobs)),
                "relay_claim" => b["job_ids"].clone(),
                "relay_report" => {
                    o.reports.push(b);
                    serde_json::json!({"ok": true})
                }
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
}
