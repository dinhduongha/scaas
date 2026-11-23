// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T21 (a): Cosmos on the family client (spec §5.3): the adapter's CometBFT reads (a `result`, an error kept whole)
//! and its REST GET and POST (each answer's status and JSON, an empty body `null`) copied onto `scaas_rpc::cosmos::Cosmos`,
//! the bounds; (b) the REST gateways' failover identity (`node_info`'s network) and floor (the latest block's height).
#![cfg(feature = "cosmos")]
mod common;
use common::*;
use scaas_rpc::cosmos::Cosmos;
use scaas_rpc::family::{Client, FamilyError};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// A CometBFT RPC and REST gateway in one, at height `height` of chain `chain`: `status`, a failing `block`, the REST
/// `node_info` and latest block, a smart query that answers 400 with its code, a simulate whose body is empty.
async fn node(height: u64, chain: &'static str) -> String {
    serve(axum::Router::new().fallback(move |uri: axum::http::Uri| async move {
        let p = uri.path().to_string();
        let ok = |v: Value| (axum::http::StatusCode::OK, serde_json::to_vec(&v).unwrap());
        match p.as_str() {
            "/status" => ok(json!({"result": {"node_info": {"network": chain}, "sync_info": {"latest_block_height": height.to_string()}}})),
            "/block" => ok(json!({"error": {"code": -32603, "message": "height 99 must be less than or equal to the current blockchain height"}})),
            // review T26 B-10: a 200 with neither `result` nor `error`, and one whose `result` is null
            "/block_results" => ok(json!({})),
            "/validators" => ok(json!({"jsonrpc": "2.0", "result": null})),
            "/cosmos/base/tendermint/v1beta1/node_info" => ok(json!({"default_node_info": {"network": chain}})),
            "/cosmos/base/tendermint/v1beta1/blocks/latest" => ok(json!({"block": {"header": {"height": height.to_string()}}})),
            "/cosmos/tx/v1beta1/simulate" => (axum::http::StatusCode::OK, Vec::new()),
            // the gateway's answer to a refused simulate: a 500 with its code
            "/cosmos/tx/v1beta1/txs" => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, serde_json::to_vec(&json!({"code": 2, "message": "payload expired"})).unwrap()),
            _ => (axum::http::StatusCode::BAD_REQUEST, serde_json::to_vec(&json!({"code": 2, "message": "query wasm contract failed"})).unwrap()),
        }
    }))
    .await
}

fn cosmos(rpc: &[&str], rest: &[&str]) -> Cosmos {
    let l = |u: &[&str]| {
        Client::of_urls(&u.iter().map(|s| s.to_string()).collect::<Vec<_>>(), None).unwrap()
    };
    Cosmos::new(l(rpc), l(rest), "scaas-1")
}

/// The adapter's reads: a CometBFT `result`, its error object whole; a REST answer's status and JSON (a 4xx is an answer),
/// an empty body `null`.
#[tokio::test]
async fn the_cometbft_and_rest_reads() {
    let u = node(7, "scaas-1").await;
    let n = cosmos(&[&u], &[&u]);
    assert_eq!(
        n.rpc_at(0, "status").await.unwrap()["sync_info"]["latest_block_height"],
        "7"
    );
    match n.rpc_at(0, "block?height=99").await.unwrap_err() {
        FamilyError::Rpc { error, .. } => assert_eq!(error["code"], -32603),
        e => panic!("{e:?}"),
    }
    // review T26 B-10 (CLI-RPC-07): an answer without its `result` is the endpoint's malformed answer, never a null result
    for path in ["block_results?height=7", "validators"] {
        match n.rpc_at(0, path).await.unwrap_err() {
            FamilyError::Failure(f) => {
                assert_eq!(f.kind, scaas_rpc::FailureKind::AnswerMalformed, "{path}")
            }
            e => panic!("{path}: {e:?}"),
        }
    }
    let (s, v) = n
        .rest
        .get(0, "/cosmwasm/wasm/v1/contract/x/smart/e30=")
        .await
        .unwrap();
    assert_eq!((s, v["code"].as_u64()), (400, Some(2)));
    assert_eq!(
        n.rest
            .post(0, "/cosmos/tx/v1beta1/simulate", &json!({}))
            .await
            .unwrap(),
        (200, Value::Null)
    );
    let (s, v) = n
        .rest
        .post(0, "/cosmos/tx/v1beta1/txs", &json!({}))
        .await
        .unwrap();
    assert_eq!(
        (s, v["code"].as_u64()),
        (500, Some(2)),
        "a 5xx's JSON is the gateway's answer (a refused simulate)"
    );
}

/// F5 over Cosmos's shapes: a REST answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn a_cosmos_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().fallback(move || async move {
            let mut b = serde_json::to_vec(&json!({"account": {}})).unwrap();
            b.resize(len, b' ');
            b
        }))
        .await
    }
    // T24.8 (fixture correction): endpoint 0 passes its identity before its reads; the bound is read on endpoint 1
    let u = big((16 << 20) + 1).await;
    let e = cosmos(&[&u], &[DOWN, &u])
        .rest
        .get(1, "/x")
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    let u = big(100).await;
    assert_eq!(
        cosmos(&[&u], &[DOWN, &u])
            .rest
            .get(1, "/x")
            .await
            .unwrap()
            .0,
        200,
        "control"
    );
}

/// (b) the REST gateways' failover: one of another chain id is dropped, one behind the height endpoint 0 showed is skipped.
#[tokio::test]
async fn the_failover_drops_another_network_and_skips_an_endpoint_behind() {
    let (other, behind, good) = (
        node(100, "other-1").await,
        node(10, "scaas-1").await,
        node(100, "scaas-1").await,
    );
    let n = cosmos(&[&good], &[DOWN, &other, &behind, &good]);
    n.rest.client.pool().saw_block(100);
    let seen: Arc<Mutex<Vec<usize>>> = Default::default();
    let a = n
        .rest
        .client
        .failover(&n.rest, |i| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(i);
                Ok::<usize, scaas_rpc::pool::ReadError>(i)
            }
        })
        .await
        .unwrap();
    assert_eq!((a.endpoint, seen.lock().unwrap().clone()), (3, vec![3]));
    assert_eq!(n.rest.client.pool().identity_of(1), Some(false));
}

/// SDK plan T24.cosmos: `get_at_height` sends `x-cosmos-block-height` (the gateway answers from that block's state); `get`
/// sends none (control).
#[tokio::test]
async fn a_rest_read_at_a_height_sends_the_height_header() {
    let u = serve(axum::Router::new().fallback(
        |uri: axum::http::Uri, h: axum::http::HeaderMap| async move {
            let v = match uri.path() {
                "/cosmos/base/tendermint/v1beta1/node_info" => {
                    json!({"default_node_info": {"network": "scaas-1"}})
                }
                _ => json!({"height": h.get("x-cosmos-block-height").map(|v| v.to_str().unwrap())}),
            };
            serde_json::to_vec(&v).unwrap()
        },
    ))
    .await;
    let n = cosmos(&[&u], &[&u]);
    let (s, v) = n.rest.get_at_height(0, "/x", 4242).await.unwrap();
    assert_eq!((s, v["height"].as_str()), (200, Some("4242")));
    assert_eq!(
        n.rest.get(0, "/x").await.unwrap().1["height"],
        Value::Null,
        "control"
    );
}
