// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T20 (a): Sui JSON-RPC on the family client (spec §5.3): the adapter's calls and checkpoint reads copied onto
//! `scaas_rpc::sui::Sui`, the bounds over its answer shapes; the failover's identity (`sui_getChainIdentifier`, the first
//! endpoint's) and floor.
#![cfg(feature = "sui")]
mod common;
use common::*;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::sui::Sui;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// A Sui RPC at checkpoint `head` whose checkpoint digests are `fork` + the sequence number, chain identifier `chain`.
async fn rpc(head: u64, fork: &'static str, chain: &'static str) -> String {
    serve(axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
            let result = match r["method"].as_str() {
                Some("sui_getChainIdentifier") => json!(chain),
                Some("sui_getLatestCheckpointSequenceNumber") => json!(head.to_string()),
                Some("sui_getCheckpoint") => {
                    let s = r["params"][0].as_str().unwrap().to_string();
                    json!({"sequenceNumber": s, "digest": format!("{fork}{s}")})
                }
                _ => {
                    return axum::Json(
                        json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32602,
                        "message": "Could not find the referenced transaction"}}),
                    )
                }
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
        }),
    ))
    .await
}

fn sui(urls: &[&str]) -> Sui {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Sui::new(Client::of_urls(&urls, None).unwrap())
}

/// The adapter's `final_head` and `block_hash` read these: the latest checkpoint and a checkpoint's digest; an error answer
/// kept whole (the adapter's "Could not find" class reads its message).
#[tokio::test]
async fn the_checkpoint_reads_and_an_error_answer() {
    let (a, b) = (
        rpc(30, "A", "4c78adac").await,
        rpc(30, "C", "4c78adac").await,
    );
    let n = sui(&[&a, &b]);
    assert_eq!(n.latest_checkpoint(0).await.unwrap(), 30);
    assert_eq!(n.checkpoint_digest(1, 7).await.unwrap(), "C7");
    match n
        .call(0, "sui_getTransactionBlock", json!(["x"]))
        .await
        .unwrap_err()
    {
        e @ FamilyError::Rpc { .. } => assert!(e.to_string().contains("Could not find"), "{e}"),
        e => panic!("{e:?}"),
    }
}

/// F5 over Sui's shapes: a checkpoint answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn a_sui_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
                let mut b = serde_json::to_vec(
                    &json!({"jsonrpc": "2.0", "id": r["id"], "result": {"digest": "D"}}),
                )
                .unwrap();
                b.resize(len, b' ');
                b
            }),
        ))
        .await
    }
    let e = sui(&[&big((16 << 20) + 1).await])
        .checkpoint_digest(0, 1)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        sui(&[&big(100).await])
            .checkpoint_digest(0, 1)
            .await
            .unwrap(),
        "D",
        "control"
    );
}

/// (b) the failover's checks: an endpoint of another chain identifier than the first endpoint's is dropped, one behind the
/// head endpoint 0 showed is skipped; with the first endpoint never read, no later endpoint is this network yet.
#[tokio::test]
async fn the_failover_drops_another_network_and_skips_an_endpoint_behind() {
    let (first, other, behind, good) = (
        rpc(100, "A", "4c78adac").await,
        rpc(100, "A", "deadbeef").await,
        rpc(10, "A", "4c78adac").await,
        rpc(100, "A", "4c78adac").await,
    );
    let n = sui(&[&first, &other, &behind, &good]);
    let asked: Arc<Mutex<Vec<usize>>> = Default::default();
    assert_eq!(
        read(&n, 0, &asked).await.unwrap().endpoint,
        0,
        "the first endpoint's identity read first"
    );
    n.client.pool().saw_block(100);
    asked.lock().unwrap().clear();
    assert_eq!(read(&n, 1, &asked).await.unwrap().endpoint, 3);
    assert_eq!(*asked.lock().unwrap(), vec![0, 3]);
    assert_eq!(n.client.pool().identity_of(1), Some(false));
    // the first endpoint down from the start: its identity unread, so no later endpoint is taken for this network
    let n = sui(&[DOWN, &good]);
    assert!(read(&n, 0, &asked).await.is_err());
}

/// A failover read through `n` whose endpoints below `down` fail; records which endpoints were asked.
async fn read(
    n: &Sui,
    down: usize,
    asked: &Arc<Mutex<Vec<usize>>>,
) -> Result<scaas_rpc::pool::Answer<usize>, scaas_rpc::RpcError> {
    n.client
        .failover(n, |i| {
            let asked = asked.clone();
            async move {
                asked.lock().unwrap().push(i);
                if i < down {
                    return Err(scaas_rpc::pool::ReadError::Failure(
                        scaas_rpc::EndpointFailure::new(
                            i,
                            scaas_rpc::FailureKind::Transport,
                            "down",
                        ),
                    ));
                }
                Ok(i)
            }
        })
        .await
}
