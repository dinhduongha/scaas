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
use crate::submit::{now, transfer_typed, work_of_op, MetaRef, Work};

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
    /// The lanes' guard (PAY-FIX2, NODE-GW-07, NODE-JOB-20), run before the simulation (review P5 m2).
    pub guard: Arc<crate::guard::Guard>,
}

#[derive(Clone, Default)]
pub struct AppState {
    pub chains: Arc<HashMap<u64, GwChain>>,
}

/// `POST /v1/metatx {chain, token, contract?, m, signature}`: a `MetaTransfer` (`contract`: its token kind, default `token`).
/// `struct = call` is refused: a named entry goes to `POST /v1/op`.
#[derive(Deserialize)]
pub struct SignedReq {
    pub chain: u64,
    pub token: Address,
    #[serde(default, rename = "struct")]
    pub struct_: Option<String>,
    #[serde(default)]
    pub contract: Option<String>,
    pub m: Value,
    pub signature: String,
}

/// `POST /v1/op {chain, op}`: a named entry on a registered token, as explicit JSON (job-api.md); door A, nothing else.
#[derive(Deserialize)]
pub struct OpReq {
    pub chain: u64,
    pub op: Value,
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
        .route("/v1/op", post(post_op))
        .merge(dex_routes())
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(GlobalConcurrencyLimitLayer::new(32))
        .with_state(state)
}

fn chain_of(s: &AppState, id: u64, token: Address) -> Result<&GwChain, Reply> {
    let c = open_chain(s, id)?;
    if !c.tokens.read().map(|t| t.contains(&token)).unwrap_or(false) {
        return Err(bad("token not served by this relayer"));
    }
    Ok(c)
}

fn open_chain(s: &AppState, id: u64) -> Result<&GwChain, Reply> {
    let c = s.chains.get(&id).ok_or_else(|| bad("unknown chain"))?;
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

/// The one place a transfer request becomes `Work`; R84 normalization here, before the simulation.
fn work_of(r: SignedReq, fee_recipient: Option<Address>) -> Result<Work, Reply> {
    if r.struct_.as_deref() == Some("call") {
        return Err(bad(crate::typed::hex_refused("struct = call")));
    }
    if r.m.get("data").is_some() {
        return Err(bad(crate::typed::hex_refused("m.data")));
    }
    let mut m = Mtx::from_wire(r.struct_.as_deref(), &r.m).map_err(bad)?;
    m.normalize(fee_recipient);
    let sig = sig_bytes(&r.signature)?;
    let typed = transfer_typed(r.contract.as_deref(), r.token, m.struct_hash(), Some((m.from(), sig.clone()))).map_err(bad)?;
    let valid_until = fresh(m.valid_until())?;
    let meta = Some(MetaRef::of(r.token, &m, None));
    Ok(Work { job_id: None, to: r.token, data: m.calldata(sig), valid_until, meta, entry: false, typed: Some(typed) })
}

fn fresh(valid_until: U256) -> Result<u64, Reply> {
    if valid_until <= U256::from(now()) {
        return Err(bad("expired"));
    }
    Ok(valid_until.saturating_to())
}

/// The guard (the same one the lane runs again): a refusal is the client's 400 before any simulation, never a 202; then the
/// simulation; G2: the typed digest computed here keeps one intent sent twice from being two outer transactions.
async fn relay(c: &GwChain, mut w: Work) -> Reply {
    if let Err(e) = c.guard.check(&c.chain, &w).await {
        return match SimError::from(e) {
            SimError::Revert(r) => bad(r),
            t => sim_reply(t),
        };
    }
    if let Err(e) = c.chain.simulate(w.to, w.data.clone()).await {
        return sim_reply(e);
    }
    if let Err(e) = crate::guard::fill_digest(&c.chain, &mut w).await {
        return sim_reply(e);
    }
    enqueue(c, w, "queued").await
}

async fn post_metatx(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
    let c = match chain_of(&s, r.chain, r.token) {
        Ok(c) => c,
        Err(e) => return e,
    };
    match work_of(r, c.fee_recipient) {
        Ok(w) => relay(c, w).await,
        Err(e) => e,
    }
}

async fn post_op(State(s): State<AppState>, Json(r): Json<OpReq>) -> Reply {
    let c = match open_chain(&s, r.chain) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (w, ua) = match work_of_op(None, &r.op, c.fee_recipient) {
        Ok(x) => x,
        Err(e) => return bad(format!("{e:#}")),
    };
    // the old door, default closed: a registered token (NODE-GW-01, NODE-GW-03), and it had no UA path. A deploy, a registry
    // write, a DEX settlement, a wallet, a relay fee or a `ua*` entry goes as a job of a namespace that has the grant
    if ua {
        return bad("FEATURE_UNSUPPORTED: a ua* entry is a ua_metatx job, not a gateway request");
    }
    if let Err(e) = chain_of(&s, r.chain, w.to) {
        return e;
    }
    if let Err(e) = fresh(U256::from(w.valid_until)) {
        return e;
    }
    relay(c, w).await
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
    use crate::metatx::{Domain, MetaTransfer, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};
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
            guard: Arc::new(crate::guard::Guard::new(&cfg, Arc::new(RwLock::new(vec![token]))).unwrap()),
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

    /// Review P5 m2: the guard runs before the simulation: a meta-tx on a contract of another chain is the client's 400
    /// (`CHAIN_UID_MISMATCH`), never a 202 refused later at the lane. The fake RPC fails every simulation.
    #[tokio::test]
    async fn the_guard_refuses_before_the_simulation() {
        let app = axum::Router::new().route("/", post(|Json(r): Json<Value>| async move {
            Json(match r["method"].as_str().unwrap() {
                "eth_getBlockByNumber" => json!({"jsonrpc": "2.0", "id": r["id"], "result": null}),
                "eth_call" => json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{:064x}", 1)}),
                _ => json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32603, "message": "no simulation here"}}),
            })
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let cfg = crate::config::ChainCfg { evm_chain_number: 7, rpc_urls: vec![url], chain_uid: Some(B256::repeat_byte(0x24)),
                                            ..Default::default() };
        let token = Address::repeat_byte(0xcd);
        let tokens = Arc::new(RwLock::new(vec![token]));
        let (tx, mut rx) = mpsc::channel(1);
        let gw = GwChain { chain: Arc::new(Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap()),
            tx, tokens: tokens.clone(), dex: None, breaker: None, fee_recipient: None,
            guard: Arc::new(crate::guard::Guard::new(&cfg, tokens).unwrap()) };
        let app = router(AppState { chains: Arc::new([(7, gw)].into_iter().collect()) });
        let body = json!({"chain": 7, "token": format!("{token:#x}"), "signature": format!("0x{}", "11".repeat(65)), "m": {
            "from": format!("{:#x}", Address::repeat_byte(1)), "to": format!("{:#x}", Address::repeat_byte(2)), "value": "1",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0,
            "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
        let req = Request::builder().method("POST").uri("/v1/metatx").header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let r = app.oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&b).contains("CHAIN_UID_MISMATCH"), "{}", String::from_utf8_lossy(&b));
        assert!(rx.try_recv().is_err(), "nothing queued");
    }

    /// A transfer request with a FIXED fee.
    fn req(mode: u32) -> SignedReq {
        let m = Mtx::Transfer(MetaTransfer {
            from: Address::repeat_byte(0xab),
            to: Address::repeat_byte(0x5e),
            value: U256::from(1),
            entryRef: B256::ZERO,
            batch: U256::from(7),
            nonce: U256::ZERO,
            validUntil: U256::from(99_999_999_999u64),
            mode,
            relayer: Address::repeat_byte(0x66),
            fee: U256::from(1000),
            feeRecipient: Address::repeat_byte(0x77),
        });
        let (kind, wire) = m.to_wire();
        SignedReq { chain: 7, token: Address::repeat_byte(0xcd), struct_: Some(kind.into()), contract: None, m: wire,
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

    /// Expired at arrival (`validUntil <= now`): refused before any simulation.
    #[test]
    fn an_expired_request_is_refused() {
        let mut r = req(0x20);
        r.m["validUntil"] = json!(now().to_string());
        assert_eq!(work_of(r, None).unwrap_err().1 .0["error"], "expired");
        let mut r = req(0x20);
        r.m["validUntil"] = json!((now() + 60).to_string());
        assert!(work_of(r, None).is_ok());
    }

    /// `struct` absent = `transfer`; `struct = call` and a `data` field are refused by name, a transfer passes.
    #[test]
    fn hex_data_is_refused_at_the_gateway() {
        work_of(req(0x20), None).unwrap();
        let mut r = req(0);
        r.struct_ = None;
        assert!(work_of(r, None).is_ok());
        let mut r = req(0);
        r.struct_ = Some("call".into());
        assert!(work_of(r, None).unwrap_err().1 .0["error"].as_str().unwrap().starts_with("HEX_DATA_REFUSED"));
        let mut r = req(0);
        r.m["data"] = json!("0x1234");
        assert!(work_of(r, None).unwrap_err().1 .0["error"].as_str().unwrap().starts_with("HEX_DATA_REFUSED"));
    }

    const FACTORY: Address = Address::repeat_byte(0xf1);
    const REGISTRY: Address = Address::repeat_byte(0xf2);
    const DEX: Address = Address::repeat_byte(0xf3);

    /// A chain for `POST /v1/op`: bound to `uid`, `code` = what `eth_getCode` answers; `(gateway, lane receiver, RPC methods)`.
    async fn gateway(code: &'static str, tokens: Vec<Address>) -> (Router, mpsc::Receiver<Work>, Arc<Mutex<Vec<String>>>) {
        let log: Arc<Mutex<Vec<String>>> = Default::default();
        let l2 = log.clone();
        let uid = crate::typed::testkit::vectors()["ops"]["Unwrap"]["domains"]["token"]["domain"]["salt"].clone();
        let app = axum::Router::new().route("/", post(move |Json(r): Json<Value>| {
            let (l2, uid) = (l2.clone(), uid.clone());
            async move {
                let m = r["method"].as_str().unwrap().to_string();
                l2.lock().unwrap().push(m.clone());
                Json(match m.as_str() {
                    "eth_getBlockByNumber" => json!({"jsonrpc": "2.0", "id": r["id"], "result": null}),
                    "eth_call" => json!({"jsonrpc": "2.0", "id": r["id"], "result": uid}),
                    "eth_getCode" => json!({"jsonrpc": "2.0", "id": r["id"], "result": code}),
                    "eth_estimateGas" => json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x5208"}),
                    _ => json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32603, "message": "no"}}),
                })
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let v = crate::typed::testkit::vectors();
        let d = &v["ops"]["Unwrap"]["domains"]["token"]["domain"];
        let cfg = crate::config::ChainCfg { evm_chain_number: d["chainId"].as_str().unwrap().parse().unwrap(), rpc_urls: vec![url],
            chain_uid: Some(d["salt"].as_str().unwrap().parse().unwrap()), account_factory: Some(FACTORY), ua_registry: Some(REGISTRY),
            dex: Some(DEX), ..Default::default() };
        let tokens = Arc::new(RwLock::new(tokens));
        let (tx, rx) = mpsc::channel(4);
        let gw = GwChain { chain: Arc::new(Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap()),
            tx, tokens: tokens.clone(), dex: None, breaker: None, fee_recipient: None,
            guard: Arc::new(crate::guard::Guard::new(&cfg, tokens).unwrap()) };
        (router(AppState { chains: Arc::new([(cfg.evm_chain_number, gw)].into_iter().collect()) }), rx, log)
    }

    async fn post_op_body(app: Router, chain: u64, op: &Value) -> (StatusCode, String) {
        let body = json!({"chain": chain, "op": op});
        let req = Request::builder().method("POST").uri("/v1/op").header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let r = app.oneshot(req).await.unwrap();
        let s = r.status();
        (s, String::from_utf8_lossy(&axum::body::to_bytes(r.into_body(), 4096).await.unwrap()).into_owned())
    }

    /// Door A is not the job API: every entry below would pass the guard on its configured target (the factory, the registry, the
    /// listed DEX, a bound wallet), and each has no fee for this lane: refused at the door, zero simulations, nothing queued. An
    /// expired signed deadline stays expired whatever `op.validUntil` says.
    #[tokio::test]
    async fn door_a_takes_registered_tokens_only() {
        let v = crate::typed::testkit::vectors();
        let d = &v["ops"]["Unwrap"]["domains"]["token"];
        let token: Address = d["domain"]["verifyingContract"].as_str().unwrap().parse().unwrap();
        let chain: u64 = d["domain"]["chainId"].as_str().unwrap().parse().unwrap();
        let until = (now() + 300).to_string();
        let z = format!("{:#x}", B256::ZERO);
        let zero = format!("{:#x}", Address::ZERO);
        let none = json!({"pqzKey": "0x", "pqzPopHash": z, "kem": {"scheme": 0, "mlkemEk": "0x", "x25519": z}, "kemPkHash": z});
        let deploy = json!({"entry": "deploy", "token": format!("{FACTORY:#x}"), "validUntil": until, "args": {
            "firstKey": {"kind": 0, "x": z, "y": z, "rpIdHash": z, "originHash": z}, "guardian": zero}});
        let register = json!({"entry": "register", "token": format!("{REGISTRY:#x}"), "validUntil": until, "args": {
            "kind": 1, "keyData": "0x", "attrs": none, "pop": "0x", "pqzPop": "0x"}});
        let settle = json!({"entry": "mtxSettle", "contract": "dex", "token": format!("{DEX:#x}"), "validUntil": until, "args": {"s": []}});
        let owner = json!({"entry": "mtxExecuteAsOwner", "contract": "wallet", "token": format!("{:#x}", Address::repeat_byte(0x77)),
            "validUntil": until, "args": {"data": "0x", "nonce": "0", "validUntil": until, "sig": "0x"}});
        let mut unregistered = crate::typed::testkit::op_of("Unwrap", "token", &v).unwrap();
        unregistered["token"] = json!(format!("{:#x}", Address::repeat_byte(0x99)));
        unregistered["validUntil"] = json!(until);
        for (what, op) in [("deploy", deploy), ("register", register), ("mtxSettle", settle), ("a wallet", owner), ("an unregistered contract", unregistered)] {
            let (app, mut rx, log) = gateway("0x", vec![token]).await;
            let (st, body) = post_op_body(app, chain, &op).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{what}: {body}");
            assert!(body.contains("token not served"), "{what}: {body}");
            assert!(rx.try_recv().is_err(), "{what}: nothing queued");
            assert!(log.lock().unwrap().iter().all(|m| m != "eth_estimateGas"), "{what}: zero simulations");
        }
        // the signed deadline holds: the vector's `validUntil` passed by now in the envelope below
        let mut late = crate::typed::testkit::op_of("Unwrap", "token", &v).unwrap();
        late["envelope"]["validUntil"] = json!((now() - 1).to_string());
        late["validUntil"] = json!(until);
        let (app, mut rx, _) = gateway("0x", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &late).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("expired"), "{body}");
        assert!(rx.try_recv().is_err());
    }

    /// The old door had no UA path: a `ua*` entry on a registered token is refused before the guard, zero simulations, nothing
    /// queued, its signature never looked at; the `mtx*` twin on the same token passes (the control). No lane runs here: the
    /// test reads the channel once, nothing waits on a receipt.
    #[tokio::test]
    async fn ua_entries_stay_off_the_gateway_door() {
        let v = crate::typed::testkit::vectors();
        let d = &v["ops"]["Unwrap"]["domains"]["token"]["domain"];
        let token: Address = d["verifyingContract"].as_str().unwrap().parse().unwrap();
        let chain: u64 = d["chainId"].as_str().unwrap().parse().unwrap();
        for name in ["UAUnwrap", "UABurn", "UACancelNonce"] {
            let op = crate::typed::testkit::op_of(name, "token", &v).unwrap();
            let (app, mut rx, log) = gateway("0x", vec![token]).await;
            let (st, body) = post_op_body(app, chain, &op).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{name}: {body}");
            assert!(body.contains("FEATURE_UNSUPPORTED"), "{name}: {body}");
            assert!(rx.try_recv().is_err(), "{name}: nothing queued");
            assert!(log.lock().unwrap().is_empty(), "{name}: no chain read at all: {:?}", log.lock().unwrap());
        }
        let (app, mut rx, _) = gateway("0x", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &crate::typed::testkit::op_of("Unwrap", "token", &v).unwrap()).await;
        assert_eq!(st, StatusCode::ACCEPTED, "the mtx twin: {body}");
        assert!(rx.try_recv().is_ok());
    }

    /// The pre-check: the positive control queues; one changed thing each: a signature of another op on an account
    /// without code is `BAD_SIGNATURE`, nothing simulated, nothing queued; the same bytes from a contract signer go on to the
    /// simulation (ERC-1271).
    #[tokio::test]
    async fn the_gateway_checks_the_typed_signature_before_the_simulation() {
        let v = crate::typed::testkit::vectors();
        let d = &v["ops"]["Unwrap"]["domains"]["token"];
        let token: Address = d["domain"]["verifyingContract"].as_str().unwrap().parse().unwrap();
        let chain: u64 = d["domain"]["chainId"].as_str().unwrap().parse().unwrap();
        let op = crate::typed::testkit::op_of("Unwrap", "token", &v).unwrap();
        let (app, mut rx, log) = gateway("0x", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &op).await;
        assert_eq!(st, StatusCode::ACCEPTED, "{body}");
        let w = rx.try_recv().unwrap();
        assert_eq!(w.data.len(), crate::typed::Op::parse(&op, None).unwrap().data.len());
        assert!(w.digest().is_some(), "the digest reached the lane");
        assert_eq!(format!("{:#x}", w.digest().unwrap()), d["digest"].as_str().unwrap());
        assert!(log.lock().unwrap().iter().all(|m| m != "eth_getCode"), "a good signature needs no chain read");
        // another row's signature, same key: the digest differs, so the signer does
        let mut bad_op = op.clone();
        bad_op["signature"] = v["ops"]["Burn"]["domains"]["token"]["signature"].clone();
        let (app, mut rx, log) = gateway("0x", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &bad_op).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(body.contains("BAD_SIGNATURE"), "{body}");
        assert!(rx.try_recv().is_err(), "nothing queued");
        assert!(log.lock().unwrap().iter().all(|m| m != "eth_estimateGas"), "nothing simulated");
        let (app, mut rx, _) = gateway("0x60", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &bad_op).await;
        assert_eq!(st, StatusCode::ACCEPTED, "a contract signer: {body}");
        assert!(rx.try_recv().is_ok());
        // a wrong kind claim changes the digest: the same refusal
        let mut lie = op.clone();
        lie["contract"] = json!("zether");
        let (app, _, _) = gateway("0x", vec![token]).await;
        assert!(post_op_body(app, chain, &lie).await.1.contains("BAD_SIGNATURE"));
    }
}
