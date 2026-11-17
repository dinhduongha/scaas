// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T18 (a): Algorand algod on the family client (spec §5.3): the adapter's raw GET (msgpack blocks, query strings), its
//! status classes and its key header copied onto `scaas_rpc::algorand::Algorand`, the bounds; the failover's identity
//! (`/v2/transactions/params`'s genesis) and floor.
#![cfg(feature = "algorand")]
mod common;
use common::*;
use scaas_rpc::algorand::Algorand;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::{EndpointAuth, Secret};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// Each request's path and token header.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

const GENESIS: &str = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";

/// An algod at round `round`, genesis `genesis`: a block's msgpack bytes (not JSON) at `/v2/blocks/{n}?format=msgpack`, its
/// hash at `/v2/blocks/{n}/hash`, a 404 with algod's message for a box; records each request's path and token.
async fn algod(round: u64, genesis: &'static str, seen: Seen) -> String {
    serve(axum::Router::new().fallback(
        move |uri: axum::http::Uri, headers: axum::http::HeaderMap| {
            let seen = seen.clone();
            async move {
                let path = uri
                    .path_and_query()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                let token = headers
                    .get("x-algo-api-token")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                seen.lock().unwrap().push((path.clone(), token));
                let json = |v: Value| (axum::http::StatusCode::OK, serde_json::to_vec(&v).unwrap());
                if path.starts_with("/v2/transactions/params") {
                    json(json!({"genesis-hash": genesis, "last-round": round}))
                } else if path.starts_with("/v2/status") {
                    json(json!({"last-round": round}))
                } else if path.ends_with("/hash") {
                    json(json!({"blockHash": format!("h{}", path.split('/').nth(3).unwrap())}))
                } else if path.contains("format=msgpack") {
                    // msgpack: a fixmap of one entry whose bytes open many '[' (0x5b): a JSON depth scan would refuse them
                    let mut b = vec![0x81, 0xa1, b'x', 0xc4, 100];
                    b.extend([0x5b; 100]);
                    (axum::http::StatusCode::OK, b)
                } else {
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        serde_json::to_vec(&json!({"message": "box not found"})).unwrap(),
                    )
                }
            }
        },
    ))
    .await
}

fn algorand(urls: &[&str], token: Option<&str>) -> Algorand {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    let auth = token.map(|t| EndpointAuth::Header {
        name: "X-Algo-API-Token".into(),
        value: Secret::new(t),
    });
    Algorand::new(Client::of_urls(&urls, auth).unwrap(), GENESIS)
}

/// The adapter's reads: a msgpack block comes back raw (no JSON scan), a block hash, a non-2xx is `Status` with algod's
/// message, the query string encoded; the token header goes to every endpoint as today.
#[tokio::test]
async fn the_raw_reads_the_status_classes_and_the_token() {
    let seen: Seen = Default::default();
    let (a, b) = (
        algod(10, GENESIS, seen.clone()).await,
        algod(10, GENESIS, seen.clone()).await,
    );
    let n = algorand(&[&a, &b], Some("tok"));
    let raw = n
        .get_raw(0, "/v2/blocks/7", &[("format", "msgpack".into())])
        .await
        .unwrap();
    assert_eq!(&raw[..3], &[0x81, 0xa1, b'x']);
    assert_eq!(n.block_hash(1, 7).await.unwrap(), "h7");
    match n
        .get_raw(0, "/v2/applications/5/box", &[("name", "b64:AQ==".into())])
        .await
        .unwrap_err()
    {
        FamilyError::Status { status, message } => {
            assert_eq!((status, message.as_str()), (404, "box not found"))
        }
        e => panic!("{e:?}"),
    }
    let s = seen.lock().unwrap();
    assert!(
        s.iter()
            .any(|(p, _)| p == "/v2/applications/5/box?name=b64%3AAQ%3D%3D"),
        "{s:?}"
    );
    assert!(
        s.iter().all(|(_, t)| t.as_deref() == Some("tok")),
        "the token to every endpoint: {s:?}"
    );
}

/// F5 over algod's shapes: an answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn an_algod_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().fallback(move || async move {
            let mut b = serde_json::to_vec(&json!({"blockHash": "h1"})).unwrap();
            b.resize(len, b' ');
            b
        }))
        .await
    }
    let e = algorand(&[&big((16 << 20) + 1).await], None)
        .block_hash(0, 1)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        algorand(&[&big(100).await], None)
            .block_hash(0, 1)
            .await
            .unwrap(),
        "h1",
        "control"
    );
}

/// (b) the failover's checks: an endpoint of another genesis is dropped, one behind the head endpoint 0 showed is skipped.
#[tokio::test]
async fn the_failover_drops_another_network_and_skips_an_endpoint_behind() {
    let s: Seen = Default::default();
    let (other, behind, good) = (
        algod(100, "other=", s.clone()).await,
        algod(10, GENESIS, s.clone()).await,
        algod(100, GENESIS, s).await,
    );
    let n = algorand(&[DOWN, &other, &behind, &good], None);
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
