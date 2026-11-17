// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T16 (a): Solana JSON-RPC on the family client (spec §5.3): the adapter's finalized-head reads copied onto
//! `scaas_rpc::solana::Solana`, the bounds over its answer shapes; the failover's identity (`getGenesisHash`) and floor.
#![cfg(feature = "solana")]
mod common;
use common::*;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::solana::{Block, Solana};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

/// A cluster at finalized slot `fin` (blocks at even slots only, each hash `h<slot>`), head `fin + 2`, genesis `genesis`.
async fn rpc(fin: u64, genesis: &'static str) -> String {
    serve(axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
            let p = &r["params"];
            let result = match r["method"].as_str() {
                Some("getGenesisHash") => json!(genesis),
                Some("getSlot") if p[0]["commitment"] == "finalized" => json!(fin),
                Some("getSlot") => json!(fin + 2),
                Some("getBlocks") => {
                    let (a, b) = (p[0].as_u64().unwrap(), p[1].as_u64().unwrap());
                    json!((a..=b).filter(|s| s % 2 == 0).collect::<Vec<_>>())
                }
                Some("getBlock") => json!({"blockhash": format!("h{}", p[0])}),
                _ => {
                    return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32601, "message": "Method not found"}}))
                }
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
        }),
    ))
    .await
}

fn solana(urls: &[&str]) -> Solana {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Solana::new(Client::of_urls(&urls, None).unwrap(), GENESIS)
}

/// The adapter's `final_head` and `block_hash` read these: the finalized slot, the block produced at or before a slot (an odd
/// slot has none: the even one below), its blockhash; a JSON-RPC error kept whole for the classifier.
#[tokio::test]
async fn the_finalized_reads() {
    let s = solana(&[&rpc(41, GENESIS).await]);
    assert_eq!(s.finalized_slot(0).await.unwrap(), 41);
    assert_eq!(
        s.produced_at_or_before(0, 41).await.unwrap(),
        Block {
            slot: 40,
            hash: "h40".into()
        }
    );
    match s.call(0, "nope", json!([])).await.unwrap_err() {
        FamilyError::Rpc { error, .. } => assert_eq!(error["code"], -32601),
        e => panic!("{e:?}"),
    }
}

/// F5 over Solana's answer shapes: a `getBlock` answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn a_solana_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
                let mut b = serde_json::to_vec(
                    &json!({"jsonrpc": "2.0", "id": r["id"], "result": {"blockhash": "h1"}}),
                )
                .unwrap();
                b.resize(len, b' ');
                b
            }),
        ))
        .await
    }
    let e = solana(&[&big((16 << 20) + 1).await])
        .blockhash_at(0, 1)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        solana(&[&big(100).await]).blockhash_at(0, 1).await.unwrap(),
        "h1",
        "control"
    );
}

/// (b) the failover's checks: an endpoint of another genesis is dropped, one behind the head endpoint 0 showed is skipped.
#[tokio::test]
async fn the_failover_drops_another_cluster_and_skips_an_endpoint_behind() {
    let (other, behind, good) = (
        rpc(100, "Another1111111111111111111111111111111111111").await,
        rpc(10, GENESIS).await,
        rpc(100, GENESIS).await,
    );
    let s = solana(&[DOWN, &other, &behind, &good]);
    s.client.pool().saw_block(100);
    let seen: Arc<Mutex<Vec<usize>>> = Default::default();
    let a = s
        .client
        .failover(&s, |i| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(i);
                Ok::<usize, scaas_rpc::pool::ReadError>(i)
            }
        })
        .await
        .unwrap();
    assert_eq!((a.endpoint, seen.lock().unwrap().clone()), (3, vec![3]));
    assert_eq!(s.client.pool().identity_of(1), Some(false));
}
