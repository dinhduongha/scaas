//! Cổng quản trị (R51, GA 2.1#3, 2.3#12): `/healthz` `/readyz` `/metrics` trên `[modules] admin_bind`, tách khỏi
//! gateway công khai — có cả khi không bật gateway. `/readyz` và `/metrics` trả ngay từ ảnh chụp đệm do một task
//! nền làm mới mỗi 10 s (review S19): request không bao giờ chờ RPC/Odoo.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::adapter::ChainAdapter;
use crate::breaker::{Breaker, NAMES};
use crate::odoo::Odoo;
use crate::submit::now;

const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const REFRESH: Duration = Duration::from_secs(10);

pub struct LaneProbe {
    pub lane: String,
    pub breaker: Arc<Mutex<Breaker>>,
}

pub struct ChainProbe {
    pub key: String,
    /// `final_head()` = đủ `finality.quorum` endpoint đồng ý trong 3 s.
    pub adapter: Arc<dyn ChainAdapter>,
    pub max_lag: u64,
    pub lanes: Vec<LaneProbe>,
}

/// `blockchain.chain.relay_stats` (Odoo).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Stats {
    pub indexed_block: u64,
    #[serde(default)]
    pub jobs: BTreeMap<String, u64>,
    #[serde(default)]
    pub attention: u64,
    #[serde(default)]
    pub drift_alerts: u64,
}

#[derive(Debug, Clone)]
pub struct Reading {
    pub key: String,
    pub head: Result<u64, String>,
    pub stats: Result<Stats, String>,
    pub max_lag: u64,
    /// (nhãn lane, số dư gần nhất, trạng thái cầu dao theo `NAMES`)
    pub lanes: Vec<(String, Option<u128>, [bool; 3])>,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub ready: bool,
    pub reasons: Vec<String>,
    pub metrics: String,
}

fn esc(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// Thuần: số đọc ⇒ sẵn sàng + lý do + văn bản Prometheus (viết tay, không thêm crate).
pub fn render(readings: &[Reading]) -> Snapshot {
    let mut reasons = Vec::new();
    let mut m = String::new();
    let mut fam = |name: &str, help: &str, kind: &str, rows: Vec<(String, String)>| {
        let _ = writeln!(m, "# HELP {name} {help}\n# TYPE {name} {kind}");
        for (labels, v) in rows {
            let _ = writeln!(m, "{name}{{{labels}}} {v}");
        }
    };
    let mut jobs = Vec::new();
    let (mut attention, mut lag, mut drift, mut balance, mut open) = (vec![], vec![], vec![], vec![], vec![]);
    for r in readings {
        let c = esc(&r.key);
        if let Err(e) = &r.head {
            reasons.push(format!("{}: rpc: {e}", r.key));
        }
        match &r.stats {
            Err(e) => reasons.push(format!("{}: odoo: {e}", r.key)),
            Ok(s) => {
                for (state, n) in &s.jobs {
                    jobs.push((format!("chain=\"{c}\",state=\"{}\"", esc(state)), n.to_string()));
                }
                attention.push((format!("chain=\"{c}\""), s.attention.to_string()));
                drift.push((format!("chain=\"{c}\""), s.drift_alerts.to_string()));
                if let Ok(h) = r.head {
                    let l = h.saturating_sub(s.indexed_block);
                    lag.push((format!("chain=\"{c}\""), l.to_string()));
                    if l > r.max_lag {
                        reasons.push(format!("{}: indexer lag {l} > {}", r.key, r.max_lag));
                    }
                }
            }
        }
        for (lane, bal, states) in &r.lanes {
            let l = esc(lane);
            if let Some(b) = bal {
                balance.push((format!("chain=\"{c}\",lane=\"{l}\""), b.to_string()));
            }
            for (name, on) in NAMES.iter().zip(states) {
                open.push((format!("chain=\"{c}\",lane=\"{l}\",breaker=\"{name}\""), u8::from(*on).to_string()));
            }
        }
    }
    fam("bamboo_relay_jobs", "Relay jobs by chain state.", "gauge", jobs);
    fam("bamboo_payment_requests_attention", "Payment requests needing attention.", "gauge", attention);
    fam("bamboo_indexer_lag_blocks", "Final head minus the indexed block.", "gauge", lag);
    fam("bamboo_relayer_balance", "Relayer lane balance in the smallest gas-coin unit.", "gauge", balance);
    fam("bamboo_breaker_open", "Gas circuit breaker open (1) per lane.", "gauge", open);
    fam("bamboo_drift_alerts", "Unmatched inbound transfers plus balance mismatches.", "gauge", drift);
    let ready = reasons.is_empty() && !readings.is_empty();
    Snapshot { ready, reasons, metrics: m }
}

async fn read(p: &ChainProbe, odoo: &Odoo) -> Reading {
    let head = match tokio::time::timeout(PROBE_TIMEOUT, p.adapter.final_head()).await {
        Ok(Ok(Some(h))) => Ok(h.height),
        Ok(Ok(None)) => Err("no final head (quorum not reached)".into()),
        Ok(Err(e)) => Err(format!("{e:#}")),
        Err(_) => Err("timeout".into()),
    };
    let stats = match tokio::time::timeout(
        PROBE_TIMEOUT,
        odoo.call::<Stats>("blockchain.chain", "relay_stats", json!({"chain_key": p.key})),
    )
    .await
    {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("{e:#}")),
        Err(_) => Err("timeout".into()),
    };
    let t = now();
    let lanes = p
        .lanes
        .iter()
        .map(|l| {
            let (bal, st) = l.breaker.lock().map(|mut k| (k.last_balance(), k.states(t))).unwrap_or((None, [false; 3]));
            (l.lane.clone(), bal, st)
        })
        .collect();
    Reading { key: p.key.clone(), head, stats, max_lag: p.max_lag, lanes }
}

/// Tuần tự theo chain, mỗi lần đọc có trần 3 s.
/// ponytail: sequential probes; spawn one per chain if a node ever serves many chains.
pub async fn refresh(probes: &[ChainProbe], odoo: &Odoo) -> Snapshot {
    let mut readings = Vec::new();
    for p in probes {
        readings.push(read(p, odoo).await);
    }
    render(&readings)
}

pub async fn refresh_loop(probes: Vec<ChainProbe>, odoo: Odoo, snap: Arc<RwLock<Snapshot>>) {
    loop {
        let s = refresh(&probes, &odoo).await;
        if let Ok(mut w) = snap.write() {
            *w = s;
        }
        tokio::time::sleep(REFRESH).await;
    }
}

async fn readyz(State(snap): State<Arc<RwLock<Snapshot>>>) -> impl IntoResponse {
    let s = snap.read().map(|s| s.clone()).unwrap_or_default();
    let code = if s.ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    let reasons = if s.ready || !s.reasons.is_empty() { s.reasons } else { vec!["starting".into()] };
    (code, Json(json!({"ready": s.ready, "reasons": reasons})))
}

async fn metrics(State(snap): State<Arc<RwLock<Snapshot>>>) -> impl IntoResponse {
    let body = snap.read().map(|s| s.metrics.clone()).unwrap_or_default();
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body)
}

pub fn router(snap: Arc<RwLock<Snapshot>>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(snap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    fn ok_reading() -> Reading {
        Reading {
            key: "evm:9000".into(),
            head: Ok(120),
            stats: Ok(Stats {
                indexed_block: 100,
                jobs: [("dead".to_string(), 2), ("queued".to_string(), 5)].into_iter().collect(),
                attention: 1,
                drift_alerts: 3,
            }),
            max_lag: 50,
            lanes: vec![("0xaa".into(), Some(10), [false, true, false])],
        }
    }

    #[test]
    fn ready_only_when_rpc_odoo_and_lag_are_fine() {
        assert!(render(&[ok_reading()]).ready);
        assert!(!render(&[]).ready, "nothing probed yet");
        let mut r = ok_reading();
        r.head = Err("timeout".into());
        let s = render(&[r]);
        assert!(!s.ready && s.reasons[0].contains("rpc"));
        let mut r = ok_reading();
        r.stats = Err("HTTP 500".into());
        let s = render(&[r]);
        assert!(!s.ready && s.reasons[0].contains("odoo"));
        let mut r = ok_reading();
        r.max_lag = 10;
        let s = render(&[r]);
        assert!(!s.ready && s.reasons[0].contains("lag 20 > 10"));
    }

    #[test]
    fn metrics_text_format_golden() {
        let want = "\
# HELP bamboo_relay_jobs Relay jobs by chain state.
# TYPE bamboo_relay_jobs gauge
bamboo_relay_jobs{chain=\"evm:9000\",state=\"dead\"} 2
bamboo_relay_jobs{chain=\"evm:9000\",state=\"queued\"} 5
# HELP bamboo_payment_requests_attention Payment requests needing attention.
# TYPE bamboo_payment_requests_attention gauge
bamboo_payment_requests_attention{chain=\"evm:9000\"} 1
# HELP bamboo_indexer_lag_blocks Final head minus the indexed block.
# TYPE bamboo_indexer_lag_blocks gauge
bamboo_indexer_lag_blocks{chain=\"evm:9000\"} 20
# HELP bamboo_relayer_balance Relayer lane balance in the smallest gas-coin unit.
# TYPE bamboo_relayer_balance gauge
bamboo_relayer_balance{chain=\"evm:9000\",lane=\"0xaa\"} 10
# HELP bamboo_breaker_open Gas circuit breaker open (1) per lane.
# TYPE bamboo_breaker_open gauge
bamboo_breaker_open{chain=\"evm:9000\",lane=\"0xaa\",breaker=\"base_fee_spike\"} 0
bamboo_breaker_open{chain=\"evm:9000\",lane=\"0xaa\",breaker=\"gas_budget\"} 1
bamboo_breaker_open{chain=\"evm:9000\",lane=\"0xaa\",breaker=\"balance_floor\"} 0
# HELP bamboo_drift_alerts Unmatched inbound transfers plus balance mismatches.
# TYPE bamboo_drift_alerts gauge
bamboo_drift_alerts{chain=\"evm:9000\"} 3
";
        assert_eq!(render(&[ok_reading()]).metrics, want);
        assert_eq!(esc("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[tokio::test]
    async fn endpoints_serve_the_cached_snapshot() {
        let snap = Arc::new(RwLock::new(Snapshot::default()));
        let app = router(snap.clone());
        let get = |p: &str| Request::builder().uri(p).body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(get("/healthz")).await.unwrap().status(), StatusCode::OK);
        let r = app.clone().oneshot(get("/readyz")).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("starting"));
        *snap.write().unwrap() = render(&[ok_reading()]);
        assert_eq!(app.clone().oneshot(get("/readyz")).await.unwrap().status(), StatusCode::OK);
        let r = app.oneshot(get("/metrics")).await.unwrap();
        assert!(r.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/plain"));
        let body = to_bytes(r.into_body(), 1 << 16).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("bamboo_breaker_open"));
    }
}
