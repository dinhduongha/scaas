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
use crate::submit::{now, work_from_job, work_of_op, Work};

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

/// `POST /v1/metatx {chain, token, contract?, m, signature}`: an address `MetaTransfer`. No token and no mandate wallet has that
/// entry left (CTR-MTX-30, Q6): refused by name, the rest of the body never read (legacy/ua-mtx-merge/gateway.rs built it).
#[derive(Deserialize)]
pub struct SignedReq {
    pub chain: u64,
    pub token: Address,
    #[serde(default)]
    pub contract: Option<String>,
}

/// `POST /v1/ua-metatx {chain, token, contract?, struct?, m, auth}` (R44, Q7): a `UAMetaTransfer` on ids, `auth` its `UASig`
/// object; the job API's `ua_metatx` struct job with the same checks (`struct = call` and a `data` field refused by name).
#[derive(Deserialize)]
pub struct UaReq {
    pub chain: u64,
    pub token: Address,
    #[serde(default, rename = "struct")]
    pub struct_: Option<String>,
    #[serde(default)]
    pub contract: Option<String>,
    pub m: Value,
    pub auth: Value,
}

/// `POST /v1/op {chain, op}`: a named entry on a registered token, as explicit JSON (job-api.md); door A, nothing else.
#[derive(Deserialize)]
pub struct OpReq {
    pub chain: u64,
    pub op: Value,
}

/// `POST /v1/dex/orders`: the order and its sell token, in the leg's form (CTR-DEX-26, ua-mtx-merge T17): a SCaaS sell
/// token's `UATradeOrder` (`from`, `destination` ids) with `auth` (a `UASig`, the token's domain, purpose `trade`); an
/// outside token's `TradeOrder` with `signature` (a `DexOrder` in the DEX's domain).
#[derive(Deserialize)]
pub struct OrderReq {
    pub chain: u64,
    #[serde(rename = "sellToken")]
    pub sell_token: Address,
    pub order: WireOrder,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub auth: Option<Value>,
}

/// `POST /v1/dex/cancel`: `CancelUAOrder` with `auth` (a SCaaS order) or `CancelDexOrder` with `signature` (an outside one).
#[derive(Deserialize)]
pub struct CancelReqBody {
    pub chain: u64,
    #[serde(rename = "orderHash")]
    pub order_hash: alloy::primitives::B256,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub auth: Option<Value>,
}

/// `POST /v1/dex/cancel-all`: `UAInvalidateNonces(from, batch, minNonce)` with `auth` in the sell token's domain (its SCaaS
/// orders, `from` an id) or `InvalidateNonces` with `signature` in the DEX's (outside-token orders, `from` an address).
#[derive(Deserialize)]
pub struct CancelAllReq {
    pub chain: u64,
    #[serde(rename = "sellToken")]
    pub sell_token: Address,
    pub from: String,
    pub batch: String,
    #[serde(rename = "minNonce")]
    pub min_nonce: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub auth: Option<Value>,
}

#[derive(Deserialize)]
pub struct MarketQuery {
    pub chain: u64,
    #[serde(default)]
    pub market: i64,
    #[serde(default)]
    pub levels: Option<usize>,
    /// An id (32-byte hex) or an address (its zero-padded id: both shapes of its orders).
    #[serde(default)]
    pub maker: Option<String>,
}

type Reply = (StatusCode, Json<Value>);

/// Fable E N-8: every gateway error text is free of endpoint URLs ([`crate::chain::redact_urls`]).
fn bad(msg: impl ToString) -> Reply {
    (StatusCode::BAD_REQUEST, Json(json!({"error": crate::chain::redact_urls(&msg.to_string())})))
}

/// A PQZ fill's refusal as a reply: `PQZ_FEE_MISMATCH` is the job's own, 422 (job-api.md; Fable E N-11), though the lane keeps
/// such a job queued (a decrease may restore the word); another rule 400, the chain 503.
fn fill_reply(e: crate::guard::Refusal) -> Reply {
    match e {
        crate::guard::Refusal::Transport(r) if r.starts_with("PQZ_FEE_MISMATCH") => {
            (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": crate::chain::redact_urls(&r)})))
        }
        e => match SimError::from(e) {
            SimError::Revert(r) => bad(r),
            t => sim_reply(t),
        },
    }
}

fn unavailable(msg: impl ToString) -> Reply {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": crate::chain::redact_urls(&msg.to_string())})))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/metatx", post(post_metatx))
        .route("/v1/ua-metatx", post(post_ua_metatx))
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
        SimError::Transport(r) => unavailable(format!("rpc: {r}")),
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

/// The one place a `/v1/ua-metatx` request becomes `Work`: the job path's `ua_metatx` struct job (R84 normalization, the hex
/// refusals, `auth` decoded as `UASig`), before the simulation.
fn ua_work_of(r: UaReq, fee_recipient: Option<Address>) -> Result<Work, Reply> {
    let job = json!({"id": 0, "kind": "ua_metatx", "token": r.token, "struct": r.struct_, "contract": r.contract, "m": r.m, "auth": r.auth});
    let job: crate::odoo::Job = serde_json::from_value(job).map_err(bad)?;
    let mut w = work_from_job(&job, fee_recipient).map_err(|e| bad(format!("{e:#}")))?;
    w.job_id = None;
    fresh(U256::from(w.valid_until))?;
    Ok(w)
}

fn fresh(valid_until: U256) -> Result<u64, Reply> {
    if valid_until <= U256::from(now()) {
        return Err(bad("expired"));
    }
    Ok(valid_until.saturating_to())
}

/// The guard (the same one the lane runs again): a refusal is the client's 400 before any simulation, never a 202; then the
/// simulation; G2: the typed digest computed here keeps one intent sent twice from being two outer transactions.
///
/// Fable recheck 5 R5-4: a refusal (4xx) read while a failover endpoint answered is no verdict: 503, the client retries.
async fn relay(c: &GwChain, w: Work) -> Reply {
    let mark = c.chain.failover_answers();
    let r = relay_checked(c, w).await;
    if r.0.is_client_error() && c.chain.failover_answers() != mark {
        return unavailable(crate::adapters::evm::failover_answer(r.1["error"].as_str().unwrap_or_default()));
    }
    r
}

async fn relay_checked(c: &GwChain, mut w: Work) -> Reply {
    if let Err(e) = c.guard.check(&c.chain, &w).await {
        return match SimError::from(e) {
            SimError::Revert(r) => bad(r),
            t => sim_reply(t),
        };
    }
    // group 3f (spec §11.1): a PQZ debit's verdict, rebuilt as on the lane (which reuses it), before the simulation; round 3t: a
    // `PQZ_FEE_MISMATCH` is the job's own (422 here), though the lane keeps such a job queued (a decrease may restore the word)
    if let Err(e) = c.guard.pqz_fill(&c.chain, &mut w).await {
        return fill_reply(e);
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
    let c = match open_chain(&s, r.chain) {
        Ok(c) => c,
        Err(e) => return e,
    };
    // R43 / R44 (CTR-MTX-30): the address `mtxExecuteTransfer(MetaTransfer, bytes)` is no token's and no mandate wallet's entry
    if r.contract.as_deref() == Some("wallet") || c.tokens.read().map(|t| t.contains(&r.token)).unwrap_or(false) {
        return bad("OP_KIND_MISMATCH: an address MetaTransfer names no token or mandate wallet entry since the merged entries: \
            POST /v1/ua-metatx with m (UAMetaTransfer, from / to bytes32 ids) and auth (UASig), or a named entry to POST /v1/op");
    }
    bad("token not served by this relayer")
}

async fn post_ua_metatx(State(s): State<AppState>, Json(r): Json<UaReq>) -> Reply {
    let c = match chain_of(&s, r.chain, r.token) {
        Ok(c) => c,
        Err(e) => return e,
    };
    // the UA ledger (`registry() ≠ 0`) only for a derived `from` or `to`: the guard's (R44, step 7a)
    match ua_work_of(r, c.fee_recipient) {
        Ok(w) => relay(c, w).await,
        Err(e) => e,
    }
}

async fn post_op(State(s): State<AppState>, Json(r): Json<OpReq>) -> Reply {
    let c = match open_chain(&s, r.chain) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let (w, _) = match work_of_op(None, &r.op, c.fee_recipient) {
        Ok(x) => x,
        Err(e) => return bad(format!("{e:#}")),
    };
    // door A: a registered token (NODE-GW-01, NODE-GW-03), its merged entries (`auth` a `UASig`, R44) and the address ones left.
    // A deploy, a registry write, a DEX settlement, a wallet, a relay fee or a router op goes as a job of a namespace with the grant
    if let Err(e) = chain_of(&s, r.chain, w.to) {
        return e;
    }
    // the bound of `/v1/metatx` on an address entry's `signature`
    if let Some(Err(e)) = r.op.get("signature").and_then(Value::as_str).map(sig_bytes) {
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
        VenueError::Unavailable(m) => unavailable(m),
    }
}

async fn dex_place(State(s): State<AppState>, Json(r): Json<OrderReq>) -> Reply {
    let v = match venue(&s, r.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match v.place(r.sell_token, &r.order, r.signature.as_deref(), r.auth.as_ref()).await {
        Ok(p) => (StatusCode::ACCEPTED, Json(serde_json::to_value(p).unwrap_or_default())),
        Err(e) => venue_err(e),
    }
}

async fn dex_cancel(State(s): State<AppState>, Json(r): Json<CancelReqBody>) -> Reply {
    let v = match venue(&s, r.chain) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match v.cancel(r.order_hash, r.signature.as_deref(), r.auth.as_ref()).await {
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
    match v.cancel_all(r.sell_token, &r.from, batch, min, r.signature.as_deref(), r.auth.as_ref()).await {
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
    let Ok(id) = crate::metatx::b32(&maker).or_else(|_| crate::metatx::addr(&maker).map(|a| a.into_word())) else {
        return bad("maker is an id (32-byte hex) or an address");
    };
    (StatusCode::OK, Json(json!({"orders": v.orders_of(id).await})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use crate::abi::UAMetaTransfer;

    /// Fable E N-8: a gateway error carries no endpoint URL (an RPC's host, a key in its path).
    #[test]
    fn gateway_errors_carry_no_endpoint_url() {
        assert_eq!(bad("simulation: http://10.0.0.7:8545/KEY down").1 .0["error"], "simulation: <url> down");
        assert_eq!(sim_reply(SimError::Transport("x https://h/k".into())).1 .0["error"], "rpc: x <url>");
        assert_eq!(venue_err(VenueError::Unavailable("y (http://h)".into())).1 .0["error"], "y (<url>)");
    }

    /// Fable E N-11: a PQZ fill's `PQZ_FEE_MISMATCH` answers 422 as job-api.md documents; another transport error 503, a rule 400.
    #[test]
    fn pqz_fee_mismatch_is_422() {
        use crate::guard::Refusal;
        let m = crate::pqz::fee_mismatch(1, alloy::primitives::U256::from(2), alloy::primitives::U256::ZERO, 2, alloy::primitives::U256::ZERO);
        assert_eq!(fill_reply(Refusal::Transport(m)).0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(fill_reply(Refusal::Transport("proofSystemId(): timeout".into())).0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(fill_reply(Refusal::Policy("BAD_PAYLOAD: no pqz_fee".into())).0, StatusCode::BAD_REQUEST);
    }
    use crate::metatx::{Domain, UaMtx, MODE_RESTRICT_FEE_RECIPIENT, MODE_RESTRICT_RELAYER};
    use alloy::primitives::B256;
    use alloy::signers::SignerSync;
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
        let body = json!({"chain": 7, "token": format!("{token:#x}"), "auth": {"keyData": "0x", "signature": "0x00", "members": []}, "m": {
            "from": format!("{:#x}", B256::ZERO), "to": format!("{:#x}", B256::ZERO), "value": "1",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0,
            "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
        let req = Request::builder().method("POST").uri("/v1/ua-metatx").header("content-type", "application/json")
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
        let body = json!({"chain": 7, "token": format!("{token:#x}"), "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)),
            "members": []}, "m": {
            "from": format!("{:#x}", Address::repeat_byte(1).into_word()), "to": format!("{:#x}", Address::repeat_byte(2).into_word()), "value": "1",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0,
            "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
        let req = Request::builder().method("POST").uri("/v1/ua-metatx").header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let r = app.oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&b).contains("CHAIN_UID_MISMATCH"), "{}", String::from_utf8_lossy(&b));
        assert!(rx.try_recv().is_err(), "nothing queued");
    }

    /// Fable recheck 5 R5-4: the same refusal read on a failover endpoint (the first down) is no verdict: 503 with
    /// `FAILOVER_ANSWER`, nothing queued. Control: `the_guard_refuses_before_the_simulation` (400 on the first endpoint).
    #[tokio::test]
    async fn a_refusal_on_a_failover_answer_is_503() {
        let app = axum::Router::new().route("/", post(|Json(r): Json<Value>| async move {
            let mut block: Value = serde_json::from_str::<Value>(include_str!("../tests/vectors/hedera_testnet.json")).unwrap()["block"].clone();
            block["hash"] = json!(format!("{:#x}", B256::repeat_byte(0x24)));
            Json(match r["method"].as_str().unwrap() {
                "eth_chainId" => json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x7"}),
                "eth_blockNumber" => json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x10"}),
                "eth_getBlockByNumber" => json!({"jsonrpc": "2.0", "id": r["id"], "result": block}),
                "eth_call" => json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{:064x}", 1)}),
                _ => json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32603, "message": "no simulation here"}}),
            })
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let cfg = crate::config::ChainCfg { evm_chain_number: 7, rpc_urls: vec!["http://127.0.0.1:9".into(), url],
            chain_uid: Some(B256::repeat_byte(0x24)), ..Default::default() };
        let token = Address::repeat_byte(0xcd);
        let tokens = Arc::new(RwLock::new(vec![token]));
        let (tx, mut rx) = mpsc::channel(1);
        let gw = GwChain { chain: Arc::new(Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap()),
            tx, tokens: tokens.clone(), dex: None, breaker: None, fee_recipient: None,
            guard: Arc::new(crate::guard::Guard::new(&cfg, tokens).unwrap()) };
        let app = router(AppState { chains: Arc::new([(7, gw)].into_iter().collect()) });
        let body = json!({"chain": 7, "token": format!("{token:#x}"), "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)),
            "members": []}, "m": {
            "from": format!("{:#x}", Address::repeat_byte(1).into_word()), "to": format!("{:#x}", Address::repeat_byte(2).into_word()), "value": "1",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "99999999999", "mode": 0,
            "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)}});
        let req = Request::builder().method("POST").uri("/v1/ua-metatx").header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let r = app.oneshot(req).await.unwrap();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let b = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        let b = String::from_utf8_lossy(&b);
        assert!(b.contains("FAILOVER_ANSWER") && b.contains("CHAIN_UID_MISMATCH"), "{b}");
        assert!(rx.try_recv().is_err(), "nothing queued");
    }

    /// A `/v1/ua-metatx` request with a FIXED fee (ids).
    fn req(mode: u32) -> UaReq {
        let m = UaMtx::Transfer(UAMetaTransfer {
            from: Address::repeat_byte(0xab).into_word(),
            to: Address::repeat_byte(0x5e).into_word(),
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
        UaReq { chain: 7, token: Address::repeat_byte(0xcd), struct_: Some(kind.into()), contract: None, m: wire,
                auth: json!({"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}) }
    }

    fn sent(w: &Work) -> UaMtx {
        UaMtx::from_calldata(&w.data).unwrap().0
    }

    fn wire(r: &UaReq) -> UaMtx {
        UaMtx::from_wire(r.struct_.as_deref(), &r.m).unwrap()
    }

    /// R84 (review C1): bit tắt ⇒ giá trị trên dây không được ký, ai cũng ghi đè được ⇒ không bao giờ gửi nó.
    #[test]
    fn unbound_fee_recipient_and_relayer_are_normalized() {
        let d = Domain { name: "T".into(), version: "1".into(), chain_id: 7, verifying_contract: Address::repeat_byte(0xcd),
                         salt: B256::repeat_byte(0x24) };
        let ours = Address::repeat_byte(0x99);
        let r = req(0x20);
        let signed = wire(&r);
        let m = sent(&ua_work_of(r, Some(ours)).unwrap());
        let unbound = |m: &UaMtx| match m { UaMtx::Transfer(t) => (t.feeRecipient, t.relayer), UaMtx::Call(c) => (c.feeRecipient, c.relayer) };
        assert_eq!(unbound(&m), (ours, Address::ZERO));
        assert_eq!(m.digest(&d), signed.digest(&d));
        let m = sent(&ua_work_of(req(0x20), None).unwrap());
        assert_eq!(unbound(&m), (Address::ZERO, Address::ZERO), "unset ⇒ the contract pays msg.sender");
    }

    #[test]
    fn bound_fields_are_untouched() {
        let r = req(MODE_RESTRICT_RELAYER | MODE_RESTRICT_FEE_RECIPIENT | 0x20);
        let signed = wire(&r);
        assert_eq!(sent(&ua_work_of(r, Some(Address::repeat_byte(0x99))).unwrap()), signed);
    }

    /// Expired at arrival (`validUntil <= now`): refused before any simulation.
    #[test]
    fn an_expired_request_is_refused() {
        let mut r = req(0x20);
        r.m["validUntil"] = json!(now().to_string());
        assert_eq!(ua_work_of(r, None).unwrap_err().1 .0["error"], "expired");
        let mut r = req(0x20);
        r.m["validUntil"] = json!((now() + 60).to_string());
        assert!(ua_work_of(r, None).is_ok());
    }

    /// `struct` absent = `transfer`; `struct = call` and a `data` field are refused by name, a transfer passes.
    #[test]
    fn hex_data_is_refused_at_the_gateway() {
        ua_work_of(req(0x20), None).unwrap();
        let mut r = req(0);
        r.struct_ = None;
        assert!(ua_work_of(r, None).is_ok());
        let mut r = req(0);
        r.struct_ = Some("call".into());
        assert!(ua_work_of(r, None).unwrap_err().1 .0["error"].as_str().unwrap().starts_with("HEX_DATA_REFUSED"));
        let mut r = req(0);
        r.m["data"] = json!("0x1234");
        assert!(ua_work_of(r, None).unwrap_err().1 .0["error"].as_str().unwrap().starts_with("HEX_DATA_REFUSED"));
    }

    const FACTORY: Address = Address::repeat_byte(0xf1);
    const REGISTRY: Address = Address::repeat_byte(0xf2);
    const DEX: Address = Address::repeat_byte(0xf3);

    /// A chain for the doors: bound to `uid`, its token's `registry()` 0 (the UA ledger off, R9), `code` = what `eth_getCode`
    /// answers; `(gateway, lane receiver, RPC methods)`.
    async fn gateway(code: &'static str, tokens: Vec<Address>) -> (Router, mpsc::Receiver<Work>, Arc<Mutex<Vec<String>>>) {
        let log: Arc<Mutex<Vec<String>>> = Default::default();
        let l2 = log.clone();
        let uid = crate::typed::testkit::vectors()["ops"]["Wrap"]["domains"]["token"]["domain"]["salt"].clone();
        let reg = format!("0x{}", alloy::hex::encode(<crate::abi::IUALedger::registryCall as alloy::sol_types::SolCall>::SELECTOR));
        let app = axum::Router::new().route("/", post(move |Json(r): Json<Value>| {
            let (l2, uid, reg) = (l2.clone(), uid.clone(), reg.clone());
            async move {
                let m = r["method"].as_str().unwrap().to_string();
                l2.lock().unwrap().push(m.clone());
                let input = r["params"][0]["input"].as_str().or(r["params"][0]["data"].as_str()).unwrap_or("0x").to_string();
                Json(match m.as_str() {
                    "eth_getBlockByNumber" => json!({"jsonrpc": "2.0", "id": r["id"], "result": null}),
                    "eth_call" if input.starts_with(&reg) => json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("{:#x}", B256::ZERO)}),
                    "eth_call" if crate::typed::testkit::domain_answer(&input, r["params"][0]["to"].as_str().unwrap_or_default().parse().unwrap_or_default()).is_some() =>
                        json!({"jsonrpc": "2.0", "id": r["id"], "result": crate::typed::testkit::domain_answer(&input,
                            r["params"][0]["to"].as_str().unwrap_or_default().parse().unwrap_or_default())}),
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
        let d = &v["ops"]["Wrap"]["domains"]["token"]["domain"];
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
        post_to(app, "/v1/op", &json!({"chain": chain, "op": op})).await
    }

    async fn post_to(app: Router, uri: &str, body: &Value) -> (StatusCode, String) {
        let req = Request::builder().method("POST").uri(uri).header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let r = app.oneshot(req).await.unwrap();
        let s = r.status();
        (s, String::from_utf8_lossy(&axum::body::to_bytes(r.into_body(), 4096).await.unwrap()).into_owned())
    }

    /// A vector row on `token` under a deadline the clock never reaches, signed again by the vector's key where the row carries
    /// its signature (`signature`, or `auth.signature` of a merged entry's `UASig`), so these tests do not expire.
    fn live(name: &str, v: &Value) -> Value {
        let d = &v["ops"][name]["domains"]["token"]["domain"];
        let mut op = crate::typed::testkit::op_of(name, "token", v).unwrap();
        op.as_object_mut().unwrap().remove("validUntil");
        op["envelope"]["validUntil"] = json!("4000000000");
        let chain: u64 = d["chainId"].as_str().unwrap().parse().unwrap();
        let digest = crate::typed::Op::parse(&op, None).unwrap().typed.digest_on(chain, d["salt"].as_str().unwrap().parse().unwrap()).unwrap();
        let key: alloy::signers::local::PrivateKeySigner = v["key"]["private"].as_str().unwrap().parse().unwrap();
        let sig = json!(format!("0x{}", alloy::hex::encode(key.sign_hash_sync(&digest).unwrap().as_bytes())));
        if op.get("auth").is_some() { op["auth"]["signature"] = sig } else { op["signature"] = sig }
        op
    }

    /// `(chain, token, uid, the vector's key)`: the token the doors' chain serves.
    fn served() -> (u64, Address, B256, alloy::signers::local::PrivateKeySigner) {
        let v = crate::typed::testkit::vectors();
        let d = &v["ops"]["Wrap"]["domains"]["token"]["domain"];
        (d["chainId"].as_str().unwrap().parse().unwrap(), d["verifyingContract"].as_str().unwrap().parse().unwrap(),
         d["salt"].as_str().unwrap().parse().unwrap(), v["key"]["private"].as_str().unwrap().parse().unwrap())
    }

    /// A `POST /v1/ua-metatx` body: a `UAMetaTransfer` `from` → `to` (ids) on the served token, `auth` a native `UASig` signed by
    /// the vector's key over the token's digest; a placeholder signature where `from` is not the key's.
    fn ua_body(from: B256, to: B256) -> Value {
        let (chain, token, uid, key) = served();
        let z = format!("{:#x}", Address::ZERO);
        let m = json!({"from": format!("{from:#x}"), "to": format!("{to:#x}"), "value": "1", "entryRef": format!("{:#x}", B256::ZERO),
            "batch": "0", "nonce": "0", "validUntil": "4000000000", "mode": 0, "relayer": z, "fee": "0", "feeRecipient": z});
        let mut sig = format!("0x{}", "11".repeat(65));
        if from == key.address().into_word() {
            let h = crate::metatx::UaMtx::from_wire(None, &m).unwrap().struct_hash();
            let d = crate::submit::transfer_typed(None, token, h, None).unwrap().digest_on(chain, uid).unwrap();
            sig = format!("0x{}", alloy::hex::encode(key.sign_hash_sync(&d).unwrap().as_bytes()));
        }
        json!({"chain": chain, "token": format!("{token:#x}"), "struct": "transfer", "m": m,
               "auth": {"keyData": "0x", "signature": sig, "members": []}})
    }

    fn calls(log: &Arc<Mutex<Vec<String>>>, m: &str) -> usize {
        log.lock().unwrap().iter().filter(|x| *x == m).count()
    }

    /// R44 / Q7 (reverses `ua_entries_stay_off_the_gateway_door`): `POST /v1/op` takes the merged named entries, `auth` the
    /// `UASig` object, on a registered token whose `registry()` is 0 (all native, R9): queued, the calldata `Op::parse`'s (the
    /// `UASig` tuple, never `bytes`), the digest the lane's.
    #[tokio::test]
    async fn op_door_takes_a_merged_entry_with_uasig() {
        let v = crate::typed::testkit::vectors();
        for name in ["UABurn", "UAUnwrap", "UACancelNonce"] {
            let d = &v["ops"][name]["domains"]["token"]["domain"];
            let token: Address = d["verifyingContract"].as_str().unwrap().parse().unwrap();
            let (chain, uid): (u64, B256) = (d["chainId"].as_str().unwrap().parse().unwrap(), d["salt"].as_str().unwrap().parse().unwrap());
            let op = live(name, &v);
            assert!(op["auth"].is_object(), "{name}: a merged entry signs with a UASig");
            let (app, mut rx, _) = gateway("0x", vec![token]).await;
            let (st, body) = post_op_body(app, chain, &op).await;
            assert_eq!(st, StatusCode::ACCEPTED, "{name}: {body}");
            let w = rx.try_recv().unwrap();
            let p = crate::typed::Op::parse(&op, None).unwrap();
            assert!(p.row.ua(), "{name}");
            assert_eq!(w.data, p.data, "{name}");
            assert_eq!(w.digest(), p.typed.digest_on(chain, uid), "{name}: the digest reached the lane");
            assert!(w.meta.is_some_and(|m| m.ua), "{name}: the lane reads the UA nonce and event");
        }
    }

    /// R44, R9: `POST /v1/ua-metatx` relays an EOA's `UAMetaTransfer` to an EOA on a token whose `registry()` is 0: no registry
    /// asked, `mtxExecuteTransfer(UAMetaTransfer, UASig)` queued with the signer's struct.
    #[tokio::test]
    async fn ua_metatx_door_runs_an_eoa_at_registry_zero() {
        let (_, token, _, key) = served();
        let (from, to) = (key.address().into_word(), Address::repeat_byte(0x5e).into_word());
        let (app, mut rx, log) = gateway("0x", vec![token]).await;
        let (st, body) = post_to(app, "/v1/ua-metatx", &ua_body(from, to)).await;
        assert_eq!(st, StatusCode::ACCEPTED, "{body}");
        let w = rx.try_recv().unwrap();
        let (m, auth) = crate::metatx::UaMtx::from_calldata(&w.data).unwrap();
        assert!(matches!(m, crate::metatx::UaMtx::Transfer(ref t) if t.from == from && t.to == to), "{m:?}");
        assert!(auth.keyData.is_empty() && auth.members.is_empty() && auth.signature.len() == 65, "a native UASig");
        assert_eq!(w.to, token);
        assert!(w.meta.is_some_and(|r| r.ua && r.from == from) && w.digest().is_some());
        assert_eq!(calls(&log, "eth_estimateGas"), 1, "simulated once");
    }

    /// R44: a derived `from` or `to` needs the UA ledger: at `registry() == 0` the door refuses it by name, zero simulations,
    /// nothing queued.
    #[tokio::test]
    async fn ua_metatx_door_refuses_a_derived_side_at_registry_zero_by_name() {
        let (_, token, _, key) = served();
        let (native, derived) = (key.address().into_word(), B256::repeat_byte(0xaa));
        for (from, to) in [(derived, native), (native, derived)] {
            let (app, mut rx, log) = gateway("0x", vec![token]).await;
            let (st, body) = post_to(app, "/v1/ua-metatx", &ua_body(from, to)).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
            assert!(body.contains("FEATURE_UNSUPPORTED") && body.contains("registry() = 0"), "{body}");
            assert!(rx.try_recv().is_err(), "nothing queued");
            assert_eq!(calls(&log, "eth_estimateGas"), 0, "zero simulations");
        }
    }

    /// The old `/v1/metatx` request (an address `MetaTransfer` on a registered token): no token has that entry left
    /// (CTR-MTX-30), refused by name toward `/v1/ua-metatx`, before any chain read, nothing queued.
    #[tokio::test]
    async fn metatx_door_refuses_a_token_by_name() {
        let (chain, token, _, _) = served();
        let mut body = req_body(chain, token);
        body["contract"] = json!("token");
        let (app, mut rx, log) = gateway("0x", vec![token]).await;
        let (st, b) = post_to(app, "/v1/metatx", &body).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{b}");
        assert!(b.contains("OP_KIND_MISMATCH") && b.contains("/v1/ua-metatx"), "{b}");
        assert!(rx.try_recv().is_err() && log.lock().unwrap().is_empty(), "no chain read, nothing queued");
    }

    /// Q6: a mandate wallet has no address entry left either: refused by name, no chain read. The control, one change: the same
    /// body claiming a `SmartKeyAccount` is not a merged-entry refusal; this door serves no account (its named entries are
    /// `metatx` op jobs of the job API, NODE-GW-03), so it is not served.
    #[tokio::test]
    async fn metatx_door_refuses_a_mandate_wallet_by_name() {
        let (chain, token, _, _) = served();
        let wallet = Address::repeat_byte(0x77);
        for (contract, why) in [("wallet", "OP_KIND_MISMATCH"), ("account", "token not served")] {
            let mut body = req_body(chain, wallet);
            body["contract"] = json!(contract);
            let (app, mut rx, log) = gateway("0x", vec![token]).await;
            let (st, b) = post_to(app, "/v1/metatx", &body).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{contract}: {b}");
            assert!(b.contains(why), "{contract}: {b}");
            assert!(rx.try_recv().is_err() && log.lock().unwrap().is_empty(), "{contract}: no chain read");
        }
    }

    /// The pre-merge `/v1/metatx` body: an address `MetaTransfer` with a placeholder signature.
    fn req_body(chain: u64, token: Address) -> Value {
        let z = format!("{:#x}", Address::ZERO);
        json!({"chain": chain, "token": format!("{token:#x}"), "signature": format!("0x{}", "11".repeat(65)), "m": {
            "from": format!("{:#x}", Address::repeat_byte(0xab)), "to": format!("{:#x}", Address::repeat_byte(0x5e)), "value": "1",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": "4000000000", "mode": 0,
            "relayer": z, "fee": "0", "feeRecipient": z}})
    }

    /// Door A is not the job API: every entry below would pass the guard on its configured target (the factory, the registry, the
    /// listed DEX, a bound wallet), and each has no fee for this lane: refused at the door, zero simulations, nothing queued. An
    /// expired signed deadline stays expired whatever `op.validUntil` says.
    #[tokio::test]
    async fn door_a_takes_registered_tokens_only() {
        let v = crate::typed::testkit::vectors();
        let d = &v["ops"]["Wrap"]["domains"]["token"];
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
        let owner = json!({"entry": "mtxExecuteAsOwner", "contract": "account", "token": format!("{:#x}", Address::repeat_byte(0x77)),
            "validUntil": until, "args": {"data": "0x", "nonce": "0", "validUntil": until, "sig": "0x"}});
        let mut unregistered = crate::typed::testkit::op_of("Wrap", "token", &v).unwrap();
        unregistered["token"] = json!(format!("{:#x}", Address::repeat_byte(0x99)));
        // on a registered fee token, but the call goes to the router: a relay fee is a job
        let relay = json!({"entry": "mtxRelayFee", "contract": "token", "token": format!("{token:#x}"),
            "call": crate::typed::testkit::op_of("UABurn", "token", &v).unwrap(),
            "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []},
            "args": {"from": z, "payee": z, "value": "1", "batch": "7", "nonce": "0", "validUntil": until,
                "relayer": format!("{:#x}", Address::repeat_byte(0xf4))}});
        // a GovernanceRouter op (spec 2026-11-02-governance §12.7) is a job of a namespace with the grant, never a door-A request
        let governance = crate::typed::testkit::op_of("UAGrantRole", "gov_router", &v).unwrap();
        // ua-mtx-merge T15: the door takes merged entries (R44), so the relay fee and the router op meet the token rule again
        let served = "token not served";
        for (what, op, why) in [("deploy", deploy, served), ("register", register, served), ("mtxSettle", settle, served), ("a wallet", owner, served),
            ("a relay fee", relay, served), ("an unregistered contract", unregistered, served), ("a router op", governance, served)] {
            let (app, mut rx, log) = gateway("0x", vec![token]).await;
            let (st, body) = post_op_body(app, chain, &op).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{what}: {body}");
            assert!(body.contains(why), "{what}: {body}");
            assert!(rx.try_recv().is_err(), "{what}: nothing queued");
            assert!(log.lock().unwrap().is_empty(), "{what}: zero simulations, no chain read at all");
        }
        // the signed deadline holds: the vector's `validUntil` passed by now in the envelope below
        let mut late = crate::typed::testkit::op_of("Wrap", "token", &v).unwrap();
        late["envelope"]["validUntil"] = json!((now() - 1).to_string());
        late["validUntil"] = json!(until);
        let (app, mut rx, log) = gateway("0x", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &late).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("expired"), "{body}");
        assert!(rx.try_recv().is_err());
        assert!(log.lock().unwrap().is_empty());
        // the signature bound of `/v1/metatx`, one length each side of it; `the_gateway_checks_…` is the control at 65
        for n in [64, 2049] {
            let mut op = live("Wrap", &v);
            op["signature"] = json!(format!("0x{}", "ab".repeat(n)));
            let (app, mut rx, log) = gateway("0x", vec![token]).await;
            let (st, body) = post_op_body(app, chain, &op).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{n}: {body}");
            assert!(body.contains("signature length"), "{n}: {body}");
            assert!(rx.try_recv().is_err() && log.lock().unwrap().is_empty(), "{n}");
        }
    }

    /// The pre-check: the positive control queues; one changed thing each: a signature of another op on an account
    /// without code is `BAD_SIGNATURE`, nothing simulated, nothing queued; the same bytes from a contract signer go on to the
    /// simulation (ERC-1271).
    #[tokio::test]
    async fn the_gateway_checks_the_typed_signature_before_the_simulation() {
        let v = crate::typed::testkit::vectors();
        let d = &v["ops"]["Wrap"]["domains"]["token"];
        let token: Address = d["domain"]["verifyingContract"].as_str().unwrap().parse().unwrap();
        let chain: u64 = d["domain"]["chainId"].as_str().unwrap().parse().unwrap();
        let op = live("Wrap", &v);
        let (app, mut rx, log) = gateway("0x", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &op).await;
        assert_eq!(st, StatusCode::ACCEPTED, "{body}");
        let w = rx.try_recv().unwrap();
        let p = crate::typed::Op::parse(&op, None).unwrap();
        assert_eq!(w.data, p.data);
        let uid = d["domain"]["salt"].as_str().unwrap().parse().unwrap();
        assert_eq!(w.digest(), p.typed.digest_on(chain, uid), "the digest reached the lane");
        assert!(log.lock().unwrap().iter().all(|m| m != "eth_getCode"), "a good signature needs no chain read");
        // another row's signature, same key: the digest differs, so the signer does
        let mut bad_op = op.clone();
        bad_op["signature"] = v["ops"]["WrapLeg"]["domains"]["token"]["signature"].clone();
        let (app, mut rx, log) = gateway("0x", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &bad_op).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(body.contains("BAD_SIGNATURE"), "{body}");
        assert!(rx.try_recv().is_err(), "nothing queued");
        let calls = |m: &str| log.lock().unwrap().iter().filter(|x| *x == m).count();
        assert_eq!((calls("eth_estimateGas"), calls("eth_call")), (0, 2), "nothing simulated: the two eth_calls are the guard's chainUid() and eip712Domain()");
        let (app, mut rx, _) = gateway("0x60", vec![token]).await;
        let (st, body) = post_op_body(app, chain, &bad_op).await;
        assert_eq!(st, StatusCode::ACCEPTED, "a contract signer: {body}");
        assert!(rx.try_recv().is_ok());
        // a wrong kind claim would change the digest: refused by name before the signature (Fable E N-6)
        let mut lie = op.clone();
        lie["contract"] = json!("zether");
        let (app, _, _) = gateway("0x", vec![token]).await;
        assert!(post_op_body(app, chain, &lie).await.1.contains("CONTRACT_KIND_MISMATCH"));
    }
}
