// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T19 (a): Aptos REST and the Indexer API on the family client (spec §5.3): the adapter's GET (a 404 is none), its
//! views' status and body, the quorum read (`agreed`) and the Indexer API's GraphQL (its key to the indexer only) copied
//! onto `scaas_rpc::aptos::Aptos`, the bounds; the failover's identity (ledger info `chain_id`) and floor.
#![cfg(feature = "aptos")]
mod common;
use common::*;
use scaas_rpc::aptos::Aptos;
use scaas_rpc::family::{AgreedError, Client, FamilyError};
use scaas_rpc::{EndpointAuth, Secret};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// Each request's authorization header.
type Seen = Arc<Mutex<Vec<Option<String>>>>;

/// An Aptos REST at block height `head`, chain id `chain`, whose block hashes are `fork` + the height; `/v1/view` aborts.
async fn rest(head: u64, fork: &'static str, chain: u8, seen: Seen) -> String {
    let app = axum::Router::new().fallback(
        move |m: axum::http::Method, uri: axum::http::Uri, h: axum::http::HeaderMap| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(h.get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string));
                let p = uri.path().to_string();
                let ok = |v: Value| (axum::http::StatusCode::OK, axum::Json(v));
                if p == "/v1" {
                    ok(json!({"chain_id": chain, "block_height": head.to_string(), "ledger_version": "9"}))
                } else if let Some(h) = p.strip_prefix("/v1/blocks/by_height/") {
                    ok(json!({"block_height": h, "block_hash": format!("0x{fork}{h}")}))
                } else if p == "/v1/view" && m == axum::http::Method::POST {
                    (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({"message": "Move abort in 0x1::meta: E_NONCE", "error_code": "invalid_input"})))
                } else {
                    (axum::http::StatusCode::NOT_FOUND, axum::Json(json!({"message": "not found", "error_code": "resource_not_found"})))
                }
            }
        },
    );
    format!("{}/v1", serve(app).await)
}

/// An Indexer API answering `data`, recording its authorization header.
async fn indexer(seen: Seen) -> String {
    indexer_of(seen, 4).await
}

/// [`indexer`] of the network `chain` (its `ledger_infos` `chain_id`).
async fn indexer_of(seen: Seen, chain: u8) -> String {
    serve(axum::Router::new().fallback(
        move |h: axum::http::HeaderMap, axum::Json(r): axum::Json<Value>| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(
                    h.get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string),
                );
                match r["query"].as_str() {
                    Some("bad") => {
                        return axum::Json(json!({"errors": [{"message": "field not found"}]}))
                    }
                    // review T26 B-9: the indexer's identity, and an answer without its data
                    Some(q) if q.contains("ledger_infos") => {
                        return axum::Json(json!({"data": {"ledger_infos": [{"chain_id": chain}]}}))
                    }
                    Some("empty") => return axum::Json(json!({"data": null})),
                    _ => {}
                }
                axum::Json(json!({"data": {"processor_status": [{"last_success_version": 7}]}}))
            }
        },
    ))
    .await
}

fn aptos(urls: &[&str], indexer: &str, key: Option<&str>) -> Aptos {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    let k = key.map(|k| EndpointAuth::Bearer(Secret::new(k)));
    Aptos::new(
        Client::of_urls(&urls, None).unwrap(),
        Client::of_urls(&[indexer.to_string()], k).unwrap(),
        4,
    )
}

/// The adapter's reads: ledger info and a block (the REST root kept as the base), a 404 as none, a view's abort as its
/// status and body, the quorum read, GraphQL's data and errors; the indexer's key to the indexer only.
#[tokio::test]
async fn the_rest_reads_the_quorum_read_and_the_indexer() {
    let (rs, is): (Seen, Seen) = Default::default();
    let (a, b, c) = (
        rest(30, "aa", 4, rs.clone()).await,
        rest(30, "aa", 4, rs.clone()).await,
        rest(30, "cc", 4, rs.clone()).await,
    );
    let n = aptos(
        &[&a, &b, &c, DOWN],
        &indexer(is.clone()).await,
        Some("ikey"),
    );
    assert_eq!(
        n.get_at(0, "").await.unwrap().unwrap()["block_height"],
        "30"
    );
    assert_eq!(n.block(2, 7).await.unwrap()["block_hash"], "0xcc7");
    assert_eq!(
        n.get_at(0, "/transactions/by_hash/0x11").await.unwrap(),
        None
    );
    let (status, v) = n
        .post_json(0, "/view", b"{}".to_vec(), "application/json")
        .await
        .unwrap();
    assert_eq!(status, 400);
    assert!(v["message"].as_str().unwrap().contains("Move abort"));
    let pick = |b: &Value| b["block_hash"].clone();
    assert!(
        n.agreed("/blocks/by_height/9", pick, 2).await.is_ok(),
        "endpoint 0 and b"
    );
    assert_eq!(
        n.agreed("/blocks/by_height/9", pick, 3).await.unwrap_err(),
        AgreedError::Quorum {
            agree: 2,
            quorum: 3
        }
    );
    assert_eq!(
        n.graphql("q", json!({})).await.unwrap()["processor_status"][0]["last_success_version"],
        7
    );
    assert!(matches!(
        n.graphql("bad", json!({})).await,
        Err(FamilyError::Graphql { .. })
    ));
    // review T26 B-9 (CLI-RPC-07): an answer without its data is the indexer's malformed answer, not an empty list
    match n.graphql("empty", json!({})).await {
        Err(FamilyError::Failure(f)) => assert_eq!(f.kind, scaas_rpc::FailureKind::AnswerMalformed),
        r => panic!("{r:?}"),
    }
    assert!(is
        .lock()
        .unwrap()
        .iter()
        .all(|h| h.as_deref() == Some("Bearer ikey")));
    assert!(
        rs.lock().unwrap().iter().all(Option::is_none),
        "the indexer's key never reaches a fullnode"
    );
}

/// F5 over Aptos's shapes: a block answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn an_aptos_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().fallback(move || async move {
            let mut b = serde_json::to_vec(&json!({"block_hash": "0x1"})).unwrap();
            b.resize(len, b' ');
            b
        }))
        .await
    }
    // T24.8 (fixture correction): endpoint 0 passes its identity before its reads; the bound is read on endpoint 1
    let e = aptos(&[DOWN, &big((16 << 20) + 1).await], DOWN, None)
        .block(1, 1)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        aptos(&[DOWN, &big(100).await], DOWN, None)
            .block(1, 1)
            .await
            .unwrap()["block_hash"],
        "0x1",
        "control"
    );
}

/// (b) the failover's checks: an endpoint of another chain id is dropped, one behind the head endpoint 0 showed is skipped.
#[tokio::test]
async fn the_failover_drops_another_network_and_skips_an_endpoint_behind() {
    let s: Seen = Default::default();
    let (other, behind, good) = (
        rest(100, "aa", 2, s.clone()).await,
        rest(10, "aa", 4, s.clone()).await,
        rest(100, "aa", 4, s).await,
    );
    let n = aptos(&[DOWN, &other, &behind, &good], DOWN, None);
    n.client.pool().saw_block(100);
    let seen: Arc<Mutex<Vec<usize>>> = Default::default();
    let a = n
        .client
        .failover(&n, |i| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(i);
                Ok::<usize, scaas_rpc::pool::ReadError>(i)
            }
        })
        .await
        .unwrap();
    assert_eq!((a.endpoint, seen.lock().unwrap().clone()), (3, vec![3]));
    assert_eq!(n.client.pool().identity_of(1), Some(false));
}

/// Review T26 B-9 (CLI-RPC-03): the indexer names its network before its first query: another network's indexer answers no
/// query (`WrongChain`); the twin, this network's, answers (`the_rest_reads_the_quorum_read_and_the_indexer`).
#[tokio::test]
async fn an_indexer_of_another_network_answers_nothing() {
    let rs: Seen = Default::default();
    let a = rest(30, "aa", 4, rs.clone()).await;
    let n = aptos(&[&a], &indexer_of(rs.clone(), 2).await, None);
    match n.graphql("q", json!({})).await {
        Err(FamilyError::Failure(f)) => assert_eq!(f.kind, scaas_rpc::FailureKind::WrongChain),
        r => panic!("{r:?}"),
    }
    let n = aptos(&[&a], &indexer_of(rs, 4).await, None);
    assert!(n.graphql("q", json!({})).await.is_ok());
}
