// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T15 (a): Soroban RPC on the family client (spec §5.3): the adapter's transport and ledger reads copied onto
//! `scaas_rpc::soroban::Soroban`, the bounds over its answer shapes, the head quorum; (b) the failover's identity and floor.
#![cfg(feature = "soroban")]
mod common;
use common::*;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::soroban::{Ledger, Soroban};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

const PASS: &str = "Standalone Network ; February 2017";

/// A Soroban RPC at ledger `seq` whose ledger hashes are `fork` + the sequence, answering `getNetwork` with `pass`; counts
/// every request.
async fn rpc(seq: u64, fork: &'static str, pass: &'static str) -> (String, Arc<AtomicUsize>) {
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    let url = serve(axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let n2 = n2.clone();
            async move {
                n2.fetch_add(1, SeqCst);
                let result = match r["method"].as_str() {
                    Some("getNetwork") => json!({"passphrase": pass, "protocolVersion": 30}),
                    Some("getLatestLedger") => json!({"id": format!("{fork}{seq:x}").to_uppercase(), "sequence": seq}),
                    Some("getLedgers") => {
                        let s = r["params"]["startLedger"].as_u64().unwrap();
                        json!({"ledgers": [{"sequence": s, "hash": format!("{fork}{s:x}").to_uppercase()}]})
                    }
                    Some("getTransaction") => json!({"status": "SUCCESS", "ledger": 5}),
                    _ => {
                        return axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32601, "message": "no such method"}}))
                    }
                };
                axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
            }
        }),
    ))
    .await;
    (url, n)
}

fn soroban(urls: &[&str]) -> Soroban {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Soroban::new(Client::of_urls(&urls, None).unwrap(), PASS)
}

/// The adapter's `final_head` and `block_hash` read these: the latest ledger (its id lowercased, `0x`), a ledger's hash, and
/// the head quorum (endpoint 0 and every endpoint giving the same hash at its sequence).
#[tokio::test]
async fn the_ledger_reads_and_the_head_quorum() {
    let (a, _) = rpc(0x20, "ab", PASS).await;
    let (b, _) = rpc(0x20, "ab", PASS).await;
    let (c, _) = rpc(0x20, "cd", PASS).await;
    let s = soroban(&[&a, &b, &c, DOWN]);
    assert_eq!(
        s.latest_ledger(0).await.unwrap(),
        Ledger {
            sequence: 0x20,
            hash: "0xab20".into()
        }
    );
    assert_eq!(s.ledger_hash(2, 7).await.unwrap(), "0xcd7");
    let (head, agree) = s.head_agreement().await.unwrap();
    assert_eq!(
        (head.sequence, agree),
        (0x20, 2),
        "endpoint 0 and b agree; c forks, the fourth is down"
    );
}

/// A JSON-RPC error answer is the caller's to classify, whole and named by its method; a down endpoint is a failure.
#[tokio::test]
async fn an_error_answer_is_kept_whole() {
    let (a, _) = rpc(1, "ab", PASS).await;
    match soroban(&[&a]).call(0, "nope", json!({})).await.unwrap_err() {
        FamilyError::Rpc { method, error } => {
            assert_eq!(method, "nope");
            assert_eq!(error["code"], -32601);
        }
        e => panic!("{e:?}"),
    }
    assert!(matches!(
        soroban(&[DOWN]).call(0, "getNetwork", json!({})).await,
        Err(FamilyError::Failure(_))
    ));
}

/// F5 over Soroban's answer shapes: a `getLedgers` answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn a_soroban_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
                let mut b = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": r["id"],
                    "result": {"ledgers": [{"sequence": 1, "hash": "ab"}]}}))
                .unwrap();
                b.resize(len, b' ');
                b
            }),
        ))
        .await
    }
    let e = soroban(&[&big((16 << 20) + 1).await])
        .ledger_hash(0, 1)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        soroban(&[&big(100).await]).ledger_hash(0, 1).await.unwrap(),
        "0xab",
        "control"
    );
}

/// (b) the failover's checks: an endpoint of another passphrase is dropped (asked once, never again); one behind the head
/// endpoint 0 showed is skipped; endpoint 0 down, the next good endpoint answers.
#[tokio::test]
async fn the_failover_drops_another_network_and_skips_an_endpoint_behind() {
    let seen: Arc<Mutex<Vec<usize>>> = Default::default();
    let (other, _) = rpc(0x20, "ab", "Another Network").await;
    let (behind, _) = rpc(0x10, "ab", PASS).await;
    let (good, _) = rpc(0x20, "ab", PASS).await;
    let s = soroban(&[DOWN, &other, &behind, &good]);
    s.client.pool().saw_block(0x20);
    assert_eq!(read(&s, seen.clone()).await.unwrap().endpoint, 3);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![3],
        "neither the other network nor the endpoint behind is asked"
    );
    assert_eq!(
        s.client.pool().identity_of(1),
        Some(false),
        "dropped for good"
    );
    let s = soroban(&[&good, &other]);
    assert_eq!(
        read(&s, Default::default()).await.unwrap().endpoint,
        0,
        "control: endpoint 0 answers itself"
    );
}

/// A failover read through `s` that records which endpoints were asked.
async fn read(
    s: &Soroban,
    seen: Arc<Mutex<Vec<usize>>>,
) -> Result<scaas_rpc::pool::Answer<usize>, scaas_rpc::RpcError> {
    s.client
        .failover(s, |i| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(i);
                Ok::<usize, scaas_rpc::pool::ReadError>(i)
            }
        })
        .await
}
