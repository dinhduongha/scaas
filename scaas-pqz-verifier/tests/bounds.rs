// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-rpc plan T8: the verifier's reads run on the crate's bounded transport (CLI-RPC-07, F5): an answer above 16 MiB is that
//! node's failure (`ChainError::Rpc`, the request fails over); a redirect is not followed. Controls beside each.
use alloy::primitives::{Address, Bytes};
use scaas_pqz_verifier::chain::{Chain, ChainError, Rpc};
use serde_json::{json, Value};

const CHAIN_ID: u64 = 7622;

/// A node answering `eth_chainId`, and `eth_getCode` with `code_len` bytes of `0x60` (or a 307 when `redirect`).
async fn node(code_len: usize, redirect: bool) -> String {
    let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
        let result = match r["method"].as_str() {
            Some("eth_chainId") => json!(format!("{CHAIN_ID:#x}")),
            _ if redirect => {
                return axum::response::Response::builder().status(307).header("location", "http://127.0.0.1:9/")
                    .body(axum::body::Body::empty()).unwrap();
            }
            _ => json!(format!("0x{}", "60".repeat(code_len))),
        };
        let b = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": r["id"], "result": result})).unwrap();
        axum::response::Response::builder().header("content-type", "application/json").body(axum::body::Body::from(b)).unwrap()
    }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

async fn code(url: String) -> Result<Bytes, ChainError> {
    let rpc = Rpc::connect(&[url], CHAIN_ID).await.unwrap();
    rpc.code(0, 1, Address::ZERO).await
}

#[tokio::test]
async fn an_answer_above_16_mib_is_the_nodes_failure() {
    // 16 MiB of hex is 8 MiB of code: twice that is above the cap
    assert!(matches!(code(node(8 << 20, false).await).await, Err(ChainError::Rpc(_))));
    assert_eq!(code(node(1_000, false).await).await.unwrap().len(), 1_000, "control");
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    assert!(matches!(code(node(1, true).await).await, Err(ChainError::Rpc(_))));
}
