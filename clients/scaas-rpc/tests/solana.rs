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
/// T26 B2-12: a `getBlocks` answer naming a slot outside the range asked (above the slot) is the endpoint's malformed answer,
/// never taken as the block produced; the control is `the_finalized_reads`.
#[tokio::test]
async fn a_produced_slot_outside_the_range_is_refused() {
    let url = serve(axum::Router::new().route(
        "/",
        axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
            let result = match r["method"].as_str() {
                Some("getGenesisHash") => json!(GENESIS),
                Some("getBlocks") => json!([r["params"][1].as_u64().unwrap() + 100]),
                _ => json!({"blockhash": "h"}),
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
        }),
    ))
    .await;
    assert!(solana(&[&url]).produced_at_or_before(0, 41).await.is_err());
}

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
    // T24.8 (fixture correction): endpoint 0 passes its identity before its reads; the bound is read on endpoint 1
    let e = solana(&[DOWN, &big((16 << 20) + 1).await])
        .blockhash_at(1, 1)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        solana(&[DOWN, &big(100).await])
            .blockhash_at(1, 1)
            .await
            .unwrap(),
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

/// T24.2: the head is the confirmed slot, compared with the confirmed slots endpoint 0 showed (a landed transaction's): an
/// endpoint finalized at 100 and confirmed at 102 answers a read whose floor is 101.
#[tokio::test]
async fn the_head_is_the_confirmed_slot() {
    let s = solana(&[DOWN, &rpc(100, GENESIS).await]);
    s.client.pool().saw_block(101);
    let a = s
        .client
        .failover(
            &s,
            |i| async move { Ok::<usize, scaas_rpc::pool::ReadError>(i) },
        )
        .await
        .unwrap();
    assert_eq!(a.endpoint, 1);
}

/// SDK plan T24.solana: `Solana::batch`, one JSON-RPC batch (a read set answered together): each call's result or its error
/// object in the calls' order, whatever order the answer lists them in; an answer that is not one member per call by `id` (one
/// missing, one twice, an id not asked, not an array) is the endpoint's `AnswerMalformed`. Control: the full answer reversed.
#[tokio::test]
async fn a_batch_answers_each_call_by_id() {
    async fn batch(shape: &'static str) -> String {
        serve(axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
                if r["method"] == "getGenesisHash" {
                    return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": GENESIS}));
                }
                let mut out: Vec<Value> = r
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| match c["method"].as_str() {
                        Some("getBalance") => json!({"jsonrpc": "2.0", "id": c["id"], "result": {"context": {"slot": 9}, "value": 5}}),
                        _ => json!({"jsonrpc": "2.0", "id": c["id"], "error": {"code": -32601, "message": "Method not found"}}),
                    })
                    .collect();
                out.reverse();
                match shape {
                    "missing" => drop(out.pop()),
                    "twice" => out.push(out[0].clone()),
                    "foreign" => out[0]["id"] = json!(7),
                    "object" => return axum::Json(out[0].clone()),
                    _ => {}
                }
                axum::Json(Value::Array(out))
            }),
        ))
        .await
    }
    let calls = [
        ("getBalance", json!(["a"])),
        ("nope", json!([])),
        ("getBalance", json!(["b"])),
    ];
    let s = solana(&[&batch("full").await]);
    let r = s.batch(0, &calls).await.unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!(r[0].as_ref().unwrap()["value"], 5);
    assert_eq!(
        r[1].as_ref().unwrap_err().rpc_error().unwrap()["code"],
        -32601
    );
    assert_eq!(r[2].as_ref().unwrap()["context"]["slot"], 9);
    for shape in ["missing", "twice", "foreign", "object"] {
        let s = solana(&[&batch(shape).await]);
        match s.batch(0, &calls).await {
            Err(FamilyError::Failure(f)) => {
                assert_eq!(f.kind, scaas_rpc::FailureKind::AnswerMalformed, "{shape}")
            }
            r => panic!("{shape}: {r:?}"),
        }
    }
}
