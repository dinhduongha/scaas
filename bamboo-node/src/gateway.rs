//! Mô-đun `gateway`: relayer mở (SRS §4.9.4). Không xác thực; giới hạn kích thước và đồng thời
//! (mỗi request tốn một `eth_call`). Đặt sau reverse proxy cho rate-limit theo IP.
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

use crate::abi::{IMetaToken, IMetaTxDex, Leg};
use crate::chain::{Chain, SimError};
use crate::dex::{Book, Order};
use crate::metatx::{WireMetaTx, MODE_FEE_MASK, MODE_RESTRICT_FEE_RECIPIENT};
use crate::submit::{now, Work};

#[derive(Clone)]
pub struct GwChain {
    pub chain: Arc<Chain>,
    pub tx: mpsc::Sender<Work>,
    pub tokens: Arc<RwLock<Vec<Address>>>,
    pub dex: Option<Address>,
    pub book: Arc<Mutex<Book>>,
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
pub struct BookQuery {
    pub chain: u64,
    pub sell: Address,
    pub buy: Address,
}

type Reply = (StatusCode, Json<Value>);

fn bad(msg: impl ToString) -> Reply {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.to_string()})))
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/metatx", post(post_metatx))
        .route("/v1/dex/orders", post(post_order).get(get_orders))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(GlobalConcurrencyLimitLayer::new(32))
        .with_state(state)
}

fn chain_of(s: &AppState, id: u64, token: Address) -> Result<&GwChain, Reply> {
    let c = s.chains.get(&id).ok_or_else(|| bad("unknown chain"))?;
    if !c.tokens.read().map(|t| t.contains(&token)).unwrap_or(false) {
        return Err(bad("token not served by this relayer"));
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
    if c.tx.send(w).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "submit stopped"})));
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

async fn post_order(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
    let c = match chain_of(&s, r.chain, r.token) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Some(dex) = c.dex else { return bad("no DEX on this chain") };
    let mut m = match r.m.to_sol() {
        Ok(m) => m,
        Err(e) => return bad(e),
    };
    let sig = match sig_bytes(&r.signature) {
        Ok(x) => x,
        Err(e) => return e,
    };
    if m.to != dex || m.relayer != dex {
        return bad("leg must be routed through this DEX");
    }
    if m.validUntil <= U256::from(now()) {
        return bad("expired");
    }
    // Phí không ràng buộc + feeRecipient 0 ⇒ ERC20MetaTx trả phí cho msg.sender = DEX, kẹt vĩnh
    // viễn; điền địa chỉ relayer (review F10). Đã ràng buộc mà trỏ vào 0/DEX ⇒ từ chối.
    if m.mode & MODE_FEE_MASK != 0 {
        if m.mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
            if m.feeRecipient == Address::ZERO {
                m.feeRecipient = c.chain.address();
            }
        } else if m.feeRecipient == Address::ZERO || m.feeRecipient == dex {
            return bad("restricted fee recipient would strand the fee in the DEX");
        }
    }
    let order = Order { token: r.token, m: m.clone(), sig: sig.clone() };
    if order.terms().is_err() {
        return bad("not a trade leg");
    }
    let leg_call: Bytes = IMetaToken::executeMetaTransactionCall { m, signature: sig }.abi_encode().into();
    if let Err(e) = c.chain.simulate_from(dex, r.token, leg_call).await {
        return sim_reply(e);
    }
    let matched = match c.book.lock() {
        Ok(mut b) => {
            b.purge(now());
            b.insert(order, now())
        }
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "book poisoned"}))),
    };
    let Some((rest, inc)) = matched else {
        return (StatusCode::ACCEPTED, Json(json!({"status": "resting"})));
    };
    let valid_until = rest.m.validUntil.min(inc.m.validUntil).saturating_to();
    let call = IMetaTxDex::settleCall {
        a: Leg { token: rest.token, m: rest.m, sig: rest.sig },
        b: Leg { token: inc.token, m: inc.m, sig: inc.sig },
    };
    enqueue(c, Work { job_id: None, to: dex, data: call.abi_encode().into(), valid_until }, "matched").await
}

async fn get_orders(State(s): State<AppState>, Query(q): Query<BookQuery>) -> Reply {
    let Some(c) = s.chains.get(&q.chain) else { return bad("unknown chain") };
    let list: Vec<Value> = match c.book.lock() {
        Ok(b) => b
            .list(q.sell, q.buy, now())
            .into_iter()
            .map(|o| {
                json!({
                    "token": format!("{:#x}", o.token),
                    "m": WireMetaTx::from_sol(&o.m),
                    "signature": format!("0x{}", alloy::hex::encode(&o.sig)),
                })
            })
            .collect(),
        Err(_) => vec![],
    };
    (StatusCode::OK, Json(json!({"orders": list})))
}
