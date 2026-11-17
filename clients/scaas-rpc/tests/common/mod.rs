// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Fake JSON-RPC endpoints of the EVM tests (the node's `chain::tests` fakes, copied): in-process axum servers on 127.0.0.1:0.
#![allow(dead_code)]
use alloy::primitives::B256;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

/// A block of chain 296 (any shape alloy reads; only its number and hash matter here).
pub fn block(number: u64, hash: B256) -> Value {
    json!({"timestamp": "0x6ac07487", "difficulty": "0x0", "extraData": "0x", "gasLimit": "0x1c9c380", "baseFeePerGas": "0x7",
        "gasUsed": "0x0", "logsBloom": format!("0x{}", "00".repeat(256)), "miner": format!("{:#x}", alloy::primitives::Address::ZERO),
        "mixHash": format!("{:#x}", B256::ZERO), "nonce": "0x0000000000000000", "receiptsRoot": format!("{:#x}", B256::ZERO),
        "sha3Uncles": format!("{:#x}", B256::ZERO), "size": "0x200", "stateRoot": format!("{:#x}", B256::ZERO), "totalDifficulty": "0x0",
        "transactions": [], "transactionsRoot": format!("{:#x}", B256::ZERO), "uncles": [], "number": format!("{number:#x}"),
        "hash": format!("{hash:#x}"), "parentHash": format!("{:#x}", B256::repeat_byte(0x11))})
}

/// The block 0 hash of the fake chain 296.
pub fn genesis() -> B256 {
    B256::repeat_byte(0x60)
}

/// The URL of an app on 127.0.0.1:0.
pub async fn serve(app: axum::Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

/// A fake RPC answering each request with `f(request)` (a `result` or an `error` member), counting the requests; `eth_chainId`
/// answers 296 and block 0 has [`genesis`] (neither counted).
pub async fn fake_rpc(f: fn(&Value) -> Value) -> (String, Arc<AtomicUsize>) {
    fake_rpc_on(f, 296, genesis()).await
}

/// [`fake_rpc`] answering `eth_chainId` with `id` and block 0 with hash `zero`.
pub async fn fake_rpc_on(
    f: fn(&Value) -> Value,
    id: u64,
    zero: B256,
) -> (String, Arc<AtomicUsize>) {
    let n: Arc<AtomicUsize> = Default::default();
    let n2 = n.clone();
    let b0 = block(0, zero);
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let mut a = if r["method"] == "eth_chainId" {
                json!({"result": format!("{id:#x}")})
            } else if r["method"] == "eth_getBlockByNumber" && r["params"][0] == "0x0" {
                json!({"result": b0.clone()})
            } else {
                n2.fetch_add(1, SeqCst);
                f(&r)
            };
            async move {
                a["jsonrpc"] = json!("2.0");
                a["id"] = r["id"].clone();
                axum::Json(a)
            }
        }),
    );
    (serve(app).await, n)
}

/// An endpoint that accepts and never answers.
pub async fn hung() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = vec![];
        while let Ok((c, _)) = l.accept().await {
            held.push(c);
        }
    });
    url
}

/// A down endpoint.
pub const DOWN: &str = "http://127.0.0.1:9";

/// [`fake_rpc`] with a closure (chain 296, block 0 [`genesis`], neither counted).
pub async fn fake_dyn(f: Arc<dyn Fn(&Value) -> Value + Send + Sync>) -> (String, Arc<AtomicUsize>) {
    let n: Arc<AtomicUsize> = Default::default();
    let n2 = n.clone();
    let b0 = block(0, genesis());
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let mut a = if r["method"] == "eth_chainId" {
                json!({"result": "0x128"})
            } else if r["method"] == "eth_getBlockByNumber" && r["params"][0] == "0x0" {
                json!({"result": b0.clone()})
            } else {
                n2.fetch_add(1, SeqCst);
                f(&r)
            };
            async move {
                a["jsonrpc"] = json!("2.0");
                a["id"] = r["id"].clone();
                axum::Json(a)
            }
        }),
    );
    (serve(app).await, n)
}
