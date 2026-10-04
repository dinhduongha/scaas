//! Mô-đun `gateway`: relayer mở (SRS §4.9.4). Xác thực là lớp bọc ngoài (`gwauth`, R54); ở đây chỉ giới hạn
//! kích thước và đồng thời (mỗi request tốn một `eth_call`). Đặt sau reverse proxy cho rate-limit theo IP.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::limit::GlobalConcurrencyLimitLayer;

use crate::abi::IMetaToken;
use crate::breaker::Breaker;
use crate::chain::{Chain, SimError};
use crate::dex::venue::{Venue, VenueError};
use crate::dex::WireOrder;
use crate::metatx::WireMetaTx;
use crate::submit::{now, Work};

#[derive(Clone)]
pub struct GwChain {
    pub chain: Arc<Chain>,
    pub tx: mpsc::Sender<Work>,
    pub tokens: Arc<RwLock<Vec<Address>>>,
    /// Sổ lệnh + thanh toán của `OrderBookDex` trên chain này (R35); None = chain không có DEX.
    pub dex: Option<Arc<Venue>>,
    /// Cầu dao của lane nhận việc gateway (R55): mở ⇒ 503 trước khi mô phỏng, không nhận rồi bỏ rơi.
    pub breaker: Option<Arc<Mutex<Breaker>>>,
}

#[derive(Clone, Default)]
pub struct AppState {
    pub chains: Arc<HashMap<u64, GwChain>>,
}

#[derive(Deserialize)]
pub struct SignedReq {
    pub chain: u64,
    pub token: Address,
    pub m: WireMetaTx,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct OrderReq {
    pub chain: u64,
    pub order: WireOrder,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct CancelReqBody {
    pub chain: u64,
    #[serde(rename = "orderHash")]
    pub order_hash: alloy::primitives::B256,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct CancelAllReq {
    pub chain: u64,
    pub maker: Address,
    #[serde(rename = "minNonce")]
    pub min_nonce: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct MarketQuery {
    pub chain: u64,
    #[serde(default)]
    pub market: i64,
    #[serde(default)]
    pub levels: Option<usize>,
    #[serde(default)]
    pub maker: Option<Address>,
}

type Reply = (StatusCode, Json<Value>);

fn bad(msg: impl ToString) -> Reply {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.to_string()})))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/metatx", post(post_metatx))
        .merge(dex_routes())
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(GlobalConcurrencyLimitLayer::new(32))
        .with_state(state)
}

fn chain_of(s: &AppState, id: u64, token: Address) -> Result<&GwChain, Reply> {
    let c = s.chains.get(&id).ok_or_else(|| bad("unknown chain"))?;
    if !c.tokens.read().map(|t| t.contains(&token)).unwrap_or(false) {
        return Err(bad("token not served by this relayer"));
    }
    let open = c.breaker.as_ref().and_then(|k| k.lock().ok().and_then(|mut k| k.open(now())));
    if let Some(b) = open {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": format!("circuit breaker open: {b}")}))));
    }
    Ok(c)
}

fn sig_bytes(s: &str) -> Result<Bytes, Reply> {
    let raw = alloy::hex::decode(s.strip_prefix("0x").unwrap_or(s)).map_err(|_| bad("signature is not hex"))?;
    if raw.len() < 65 || raw.len() > 2048 {
        return Err(bad("signature length"));
    }
    Ok(raw.into())
}

fn sim_reply(e: SimError) -> Reply {
    match e {
        SimError::Revert(r) => bad(format!("simulation: {r}")),
        SimError::Transport(r) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": format!("rpc: {r}")}))),
    }
}

async fn enqueue(c: &GwChain, w: Work, status: &str) -> Reply {
    // try_send: lane đứng (cầu dao mở, R55) ⇒ kênh đầy ⇒ 503 ngay, không treo request.
    if let Err(e) = c.tx.try_send(w) {
        let why = if matches!(e, mpsc::error::TrySendError::Full(_)) { "submit busy" } else { "submit stopped" };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": why})));
    }
    (StatusCode::ACCEPTED, Json(json!({"status": status})))
}

async fn post_metatx(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
    let c = match chain_of(&s, r.chain, r.token) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let m = match r.m.to_sol() {
        Ok(m) => m,
        Err(e) => return bad(e),
    };
    let sig = match sig_bytes(&r.signature) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if m.validUntil <= U256::from(now()) {
        return bad("expired");
    }
    let valid_until = m.validUntil.saturating_to();
    let data: Bytes = IMetaToken::executeMetaTransactionCall { m, signature: sig }.abi_encode().into();
    if let Err(e) = c.chain.simulate(r.token, data.clone()).await {
        return sim_reply(e);
    }
    enqueue(c, Work { job_id: None, to: r.token, data, valid_until }, "queued").await
}

// ---------------------------------------------------------------------------------- DEX (R35)

/// Route DEX, gộp vào `router`. Không tự xác thực: lớp auth của gateway (R54) bọc router ngoài cùng.
pub fn dex_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/dex/orders", post(dex_place).get(dex_orders))
        .route("/v1/dex/cancel", post(dex_cancel))
        .route("/v1/dex/cancel-all", post(dex_cancel_all))
        .route("/v1/dex/markets", get(dex_markets))
        .route("/v1/dex/depth", get(dex_depth))
        .route("/v1/dex/trades", get(dex_trades))
        .route("/v1/dex/ticker", get(dex_ticker))
}

fn venue(s: &AppState, chain: u64) -> Result<Arc<Venue>, Reply> {
    s.chains.get(&chain).and_then(|c| c.dex.clone()).ok_or_else(|| bad("no DEX on this chain"))
}

fn venue_err(e: VenueError) -> Reply {
    match e {
        VenueError::Bad(m) => bad(m),
        VenueError::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": m}))),
    }
}

async fn dex_place(State(s): State<AppState>, Json(r): Json<OrderReq>) -> Reply {
    let v = match venue(&s, r.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match v.place(&r.order, &r.signature).await {
        Ok(p) => (StatusCode::ACCEPTED, Json(serde_json::to_value(p).unwrap_or_default())),
        Err(e) => venue_err(e),
    }
}

async fn dex_cancel(State(s): State<AppState>, Json(r): Json<CancelReqBody>) -> Reply {
    let v = match venue(&s, r.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match v.cancel(r.order_hash, &r.signature).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(json!({"status": "cancelled"}))),
        Err(e) => venue_err(e),
    }
}

async fn dex_cancel_all(State(s): State<AppState>, Json(r): Json<CancelAllReq>) -> Reply {
    let v = match venue(&s, r.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Ok(min) = r.min_nonce.parse::<U256>() else { return bad("minNonce is not a uint256") };
    match v.cancel_all(r.maker, min, &r.signature).await {
        Ok(n) => (StatusCode::ACCEPTED, Json(json!({"status": "cancelled", "orders": n}))),
        Err(e) => venue_err(e),
    }
}

async fn dex_markets(State(s): State<AppState>, Query(q): Query<MarketQuery>) -> Reply {
    match venue(&s, q.chain) {
        Ok(v) => (StatusCode::OK, Json(json!({"dex": format!("{:#x}", v.dex), "markets": v.markets().await}))),
        Err(e) => e,
    }
}

async fn dex_depth(State(s): State<AppState>, Query(q): Query<MarketQuery>) -> Reply {
    let v = match venue(&s, q.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match v.depth(q.market, q.levels.unwrap_or(20).min(200)).await {
        Some(d) => (StatusCode::OK, Json(d)),
        None => bad("unknown market"),
    }
}

async fn dex_trades(State(s): State<AppState>, Query(q): Query<MarketQuery>) -> Reply {
    match venue(&s, q.chain) {
        Ok(v) => (StatusCode::OK, Json(json!({"trades": v.trades(q.market)}))),
        Err(e) => e,
    }
}

async fn dex_ticker(State(s): State<AppState>, Query(q): Query<MarketQuery>) -> Reply {
    let v = match venue(&s, q.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match v.ticker(q.market).await {
        Some(t) => (StatusCode::OK, Json(t)),
        None => bad("unknown market"),
    }
}

async fn dex_orders(State(s): State<AppState>, Query(q): Query<MarketQuery>) -> Reply {
    let v = match venue(&s, q.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(maker) = q.maker else { return bad("maker is required") };
    (StatusCode::OK, Json(json!({"orders": v.orders_of(maker).await})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    /// R55 (review S1-7): lane đứng ⇒ gateway trả 503 ngay, không nhận rồi để hết hạn trong kênh.
    #[tokio::test]
    async fn open_breaker_refuses_before_simulation() {
        let cfg = crate::config::ChainCfg { evm_chain_number: 7, rpc_urls: vec!["http://127.0.0.1:9".into()], ..Default::default() };
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let token = Address::repeat_byte(0xcd);
        let mut k = Breaker::new(crate::config::BreakerCfg { min_relayer_balance: Some(10), ..Default::default() });
        k.balance(1);
        let (tx, _rx) = mpsc::channel(1);
        let gw = GwChain {
            chain: Arc::new(Chain::with_signer(&cfg, signer).unwrap()),
            tx,
            tokens: Arc::new(RwLock::new(vec![token])),
            dex: None,
            breaker: Some(Arc::new(Mutex::new(k))),
        };
        let app = router(AppState { chains: Arc::new([(7, gw)].into_iter().collect()) });
        let body = json!({"chain": 7, "token": format!("{token:#x}"), "signature": "0x00", "m": {
            "from": format!("{:#x}", Address::ZERO), "to": format!("{:#x}", Address::ZERO), "value": "1", "data": "0x",
            "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0, "relayer": format!("{:#x}", Address::ZERO),
            "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
        let req = Request::builder().method("POST").uri("/v1/metatx").header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let r = app.oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&b).contains("circuit breaker open: balance_floor"), "not the RPC error");
    }
}
