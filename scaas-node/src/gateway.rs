//! Mô-đun `gateway`: relayer mở (SRS §4.9.4). Xác thực là lớp bọc ngoài (`gwauth`, R54); ở đây chỉ giới hạn
//! kích thước và đồng thời (mỗi request tốn một `eth_call`). Đặt sau reverse proxy cho rate-limit theo IP.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use alloy::primitives::{Address, Bytes, U256};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::limit::GlobalConcurrencyLimitLayer;

use crate::breaker::Breaker;
use crate::chain::{Chain, SimError};
use crate::dex::venue::{Venue, VenueError};
use crate::dex::WireOrder;
use crate::metatx::Mtx;
use crate::submit::{now, MetaRef, Work};

#[derive(Clone)]
pub struct GwChain {
    pub chain: Arc<Chain>,
    pub tx: mpsc::Sender<Work>,
    pub tokens: Arc<RwLock<Vec<Address>>>,
    /// Sổ lệnh + thanh toán của `SCaaSDex` trên chain này (R35); None = chain không có DEX.
    pub dex: Option<Arc<Venue>>,
    /// Cầu dao của lane nhận việc gateway (R55): mở ⇒ 503 trước khi mô phỏng, không nhận rồi bỏ rơi.
    pub breaker: Option<Arc<Mutex<Breaker>>>,
    /// `[[chains]] fee_recipient` (R84): đích của phí khi người ký không ràng buộc `feeRecipient`.
    pub fee_recipient: Option<Address>,
}

#[derive(Clone, Default)]
pub struct AppState {
    pub chains: Arc<HashMap<u64, GwChain>>,
}

/// `POST /v1/metatx {chain, token, struct?, m, signature}`: `struct` = `call` | `transfer` (default `transfer`).
#[derive(Deserialize)]
pub struct SignedReq {
    pub chain: u64,
    pub token: Address,
    #[serde(default, rename = "struct")]
    pub struct_: Option<String>,
    pub m: Value,
    pub signature: String,
}

/// `POST /v1/dex/orders`: the `TradeOrder` and its sell token (the token's domain signs a SCaaS order, the DEX's an
/// outside one, NODE-DEX-15).
#[derive(Deserialize)]
pub struct OrderReq {
    pub chain: u64,
    #[serde(rename = "sellToken")]
    pub sell_token: Address,
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

/// `POST /v1/dex/cancel-all`: `InvalidateNonces(from, batch, minNonce)` in the sell token's domain (its SCaaS orders)
/// or the DEX's (outside-token orders).
#[derive(Deserialize)]
pub struct CancelAllReq {
    pub chain: u64,
    #[serde(rename = "sellToken")]
    pub sell_token: Address,
    pub from: Address,
    pub batch: String,
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

/// Nơi duy nhất dựng `Work` từ request; chuẩn hoá R84 ở đây, trước mô phỏng.
fn work_of(r: SignedReq, fee_recipient: Option<Address>) -> Result<Work, Reply> {
    let mut m = Mtx::from_wire(r.struct_.as_deref(), &r.m).map_err(bad)?;
    m.normalize(fee_recipient);
    let sig = sig_bytes(&r.signature)?;
    if m.valid_until() <= U256::from(now()) {
        return Err(bad("expired"));
    }
    let valid_until = m.valid_until().saturating_to();
    let meta = Some(MetaRef::of(r.token, &m, None));
    Ok(Work { job_id: None, to: r.token, data: m.calldata(sig), valid_until, meta, entry: false })
}

async fn post_metatx(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
    let c = match chain_of(&s, r.chain, r.token) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut w = match work_of(r, c.fee_recipient) {
        Ok(w) => w,
        Err(e) => return e,
    };
    if let Err(e) = c.chain.simulate(w.to, w.data.clone()).await {
        return sim_reply(e);
    }
    // G2: digest thật của token ⇒ cùng một intent gửi hai lần không thành hai tx vỏ (tập in-flight của chain).
    let Some((m, _)) = Mtx::from_calldata(&w.data) else { return bad("not a meta-transaction") };
    match c.chain.mtx_digest(w.to, m).await {
        Ok(d) => w.meta = w.meta.map(|r| MetaRef { digest: Some(d), ..r }),
        Err(e) => return sim_reply(SimError::Transport(format!("mtxDigest: {e:#}"))),
    }
    enqueue(c, w, "queued").await
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
    match v.place(r.sell_token, &r.order, &r.signature).await {
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
    let (Ok(batch), Ok(min)) = (crate::metatx::uint(&r.batch), crate::metatx::uint(&r.min_nonce)) else {
        return bad("batch and minNonce are decimal uint256");
    };
    match v.cancel_all(r.sell_token, r.from, batch, min, &r.signature).await {
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
    use crate::metatx::{Domain, MetaTransaction, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};
    use alloy::primitives::B256;
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
            fee_recipient: None,
        };
        let app = router(AppState { chains: Arc::new([(7, gw)].into_iter().collect()) });
        let body = json!({"chain": 7, "token": format!("{token:#x}"), "signature": "0x00", "m": {
            "from": format!("{:#x}", Address::ZERO), "to": format!("{:#x}", Address::ZERO), "value": "1",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0,
            "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
        let req = Request::builder().method("POST").uri("/v1/metatx").header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let r = app.oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&b).contains("circuit breaker open: balance_floor"), "not the RPC error");
    }

    /// A `call` request (`MetaTransaction`): `cancelNonce(1)` with a FIXED fee.
    fn req(mode: u32) -> SignedReq {
        let m = Mtx::Call(MetaTransaction {
            from: Address::repeat_byte(0xab),
            data: alloy::hex::decode("cfdd7aea0000000000000000000000000000000000000000000000000000000000000001").unwrap().into(),
            batch: U256::from(7),
            nonce: U256::ZERO,
            validUntil: U256::from(99_999_999_999u64),
            mode,
            relayer: Address::repeat_byte(0x66),
            fee: U256::from(1000),
            feeRecipient: Address::repeat_byte(0x77),
        });
        let (kind, wire) = m.to_wire();
        SignedReq { chain: 7, token: Address::repeat_byte(0xcd), struct_: Some(kind.into()), m: wire,
                    signature: format!("0x{}", "11".repeat(65)) }
    }

    fn sent(w: &Work) -> Mtx {
        Mtx::from_calldata(&w.data).unwrap().0
    }

    fn wire(r: &SignedReq) -> Mtx {
        Mtx::from_wire(r.struct_.as_deref(), &r.m).unwrap()
    }

    /// R84 (review C1): bit tắt ⇒ giá trị trên dây không được ký, ai cũng ghi đè được ⇒ không bao giờ gửi nó.
    #[test]
    fn unbound_fee_recipient_and_relayer_are_normalized() {
        let d = Domain { name: "T".into(), version: "1".into(), chain_id: 7, verifying_contract: Address::repeat_byte(0xcd),
                         salt: B256::repeat_byte(0x24) };
        let ours = Address::repeat_byte(0x99);
        let r = req(0x20);
        let signed = wire(&r);
        let m = sent(&work_of(r, Some(ours)).unwrap());
        assert_eq!((m.fee_recipient(), m.relayer()), (ours, Address::ZERO));
        assert_eq!(m.digest(&d), signed.digest(&d));
        let m = sent(&work_of(req(0x20), None).unwrap());
        assert_eq!((m.fee_recipient(), m.relayer()), (Address::ZERO, Address::ZERO), "unset ⇒ the contract pays msg.sender");
    }

    #[test]
    fn bound_fields_are_untouched() {
        let r = req(MODE_RESTRICT_RELAYER | MODE_RESTRICT_FEE_RECIPIENT | 0x20);
        let signed = wire(&r);
        assert_eq!(sent(&work_of(r, Some(Address::repeat_byte(0x99))).unwrap()), signed);
    }

    /// `struct` absent = `transfer`; a call body without `struct` is refused, never misread.
    #[test]
    fn the_struct_is_named_or_a_transfer() {
        let mut r = req(0);
        r.struct_ = None;
        assert!(work_of(r, None).is_err());
    }
}
