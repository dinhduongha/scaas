// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T17 (a): NEAR JSON-RPC on the family client (spec §5.3): the adapter's quorum read (`agreed`) and block reads copied
//! onto `scaas_rpc::near::Near`, the bounds over its answer shapes; the failover's identity (`status`'s genesis) and floor.
#![cfg(feature = "near")]
mod common;
use common::*;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::near::{AgreedError, Near};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const GENESIS: &str = "GVm8fKh1bvzmxHZSGZPjGjFnEXa9dSLTD5ACFRhnWzAa";

/// A NEAR RPC at final height `fin` whose block hashes are `fork` + the height, genesis `genesis`.
async fn rpc(fin: u64, fork: &'static str, genesis: &'static str) -> String {
    serve(axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
            let p = &r["params"];
            let result = match r["method"].as_str() {
                Some("status") => json!({"chain_id": "localnet", "genesis_hash": genesis}),
                Some("block") => {
                    let h = p["block_id"].as_u64().unwrap_or(fin);
                    json!({"header": {"height": h, "hash": format!("{fork}{h}")}})
                }
                _ => {
                    return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "error": {"name": "HANDLER_ERROR",
                        "cause": {"name": "UNKNOWN_BLOCK"}, "code": -32000, "message": "Server error"}}))
                }
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
        }),
    ))
    .await
}

fn near(urls: &[&str]) -> Near {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Near::new(Client::of_urls(&urls, None).unwrap(), GENESIS)
}

/// The adapter's `final_head`, `block_hash` and `agreed` read these: the final header, a header at a height, and the quorum
/// read (endpoint 0's answer, repeated on the picked part by enough endpoints); an error object kept whole.
#[tokio::test]
async fn the_block_reads_and_the_quorum_read() {
    let (a, b, c) = (
        rpc(30, "a", GENESIS).await,
        rpc(30, "a", GENESIS).await,
        rpc(30, "c", GENESIS).await,
    );
    let n = near(&[&a, &b, &c, DOWN]);
    assert_eq!(n.final_header(0).await.unwrap(), (30, "a30".into()));
    assert_eq!(n.header_at(2, 7).await.unwrap(), (7, "c7".into()));
    let pick = |b: &Value| b["header"]["hash"].clone();
    let p = json!({"block_id": 9});
    assert!(
        n.agreed("block", p.clone(), pick, 2).await.is_ok(),
        "endpoint 0 and b"
    );
    assert_eq!(
        n.agreed("block", p.clone(), pick, 3).await.unwrap_err(),
        AgreedError::Quorum {
            agree: 2,
            quorum: 3
        }
    );
    match n.call(0, "chunk", json!({})).await.unwrap_err() {
        FamilyError::Rpc { error, .. } => assert_eq!(error["cause"]["name"], "UNKNOWN_BLOCK"),
        e => panic!("{e:?}"),
    }
}

/// F5 over NEAR's answer shapes: a `block` answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn a_near_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
                let mut b = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": r["id"],
                    "result": {"header": {"height": 1, "hash": "h"}}}))
                .unwrap();
                b.resize(len, b' ');
                b
            }),
        ))
        .await
    }
    let e = near(&[&big((16 << 20) + 1).await])
        .final_header(0)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        near(&[&big(100).await]).final_header(0).await.unwrap(),
        (1, "h".into()),
        "control"
    );
}

/// (b) the failover's checks: an endpoint of another genesis is dropped, one behind the head endpoint 0 showed is skipped.
#[tokio::test]
async fn the_failover_drops_another_network_and_skips_an_endpoint_behind() {
    let (other, behind, good) = (
        rpc(100, "a", "Other1111111111111111111111111111111111111111").await,
        rpc(10, "a", GENESIS).await,
        rpc(100, "a", GENESIS).await,
    );
    let n = near(&[DOWN, &other, &behind, &good]);
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
