// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T22 (a): TON Center v3 on the family client (spec §5.3): the adapter's GET with its query, its JSON POST and the
//! status class copied onto `scaas_rpc::ton::Ton`, the API key to the endpoint it goes to today (the first) and no other, the
//! bounds; the failover's identity (the profile constant) and floor.
#![cfg(feature = "ton")]
mod common;
use common::*;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::ton::Ton;
use scaas_rpc::{EndpointAuth, Secret};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// Each request's path with its query and its API key header.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A TON Center at masterchain seqno `seqno`; `runGetMethod` answers its body back, anything unknown a 404.
async fn center(seqno: u64, seen: Seen) -> String {
    center_of(seqno, "b", seen).await
}

/// [`center`] whose masterchain block `n` has root hash `{fork}{n}` (T24.6: a later endpoint's identity reads it).
async fn center_of(seqno: u64, fork: &'static str, seen: Seen) -> String {
    serve(axum::Router::new().fallback(
        move |uri: axum::http::Uri, h: axum::http::HeaderMap, body: axum::body::Bytes| {
            let seen = seen.clone();
            async move {
                let p = uri.path_and_query().map(|p| p.to_string()).unwrap_or_default();
                seen.lock().unwrap().push((p.clone(), h.get("x-api-key").and_then(|v| v.to_str().ok()).map(str::to_string)));
                let ok = |v: Value| (axum::http::StatusCode::OK, serde_json::to_vec(&v).unwrap());
                if p.starts_with("/api/v3/masterchainInfo") {
                    ok(json!({"last": {"seqno": seqno, "root_hash": "rh"}}))
                } else if p.starts_with("/api/v3/runGetMethod") {
                    ok(json!({"exit_code": 0, "echo": serde_json::from_slice::<Value>(&body).unwrap()}))
                } else if p.starts_with("/api/v3/blocks") {
                    let n = p.split("seqno=").nth(1).and_then(|s| s.split('&').next()).unwrap_or_default().to_string();
                    ok(json!({"blocks": [{"root_hash": format!("{fork}{n}")}]}))
                } else {
                    (axum::http::StatusCode::NOT_FOUND, b"not found".to_vec())
                }
            }
        },
    ))
    .await
}

/// The key to endpoint 0 only (today the adapter asks endpoint 0 alone, with its key).
fn ton(urls: &[&str], key: Option<&str>) -> Ton {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    let c = Client::of_urls_each(&urls, |i| {
        key.filter(|_| i == 0).map(|k| EndpointAuth::Header {
            name: "X-API-Key".into(),
            value: Secret::new(k),
        })
    })
    .unwrap();
    Ton::new(c)
}

/// The adapter's reads: a GET with its query under `/api/v3/`, a JSON POST, a status other than 2xx as `Status` with its
/// text; the key to endpoint 0 and never to another.
#[tokio::test]
async fn the_reads_the_status_class_and_the_key_to_the_first_endpoint_only() {
    let seen: Seen = Default::default();
    let (a, b) = (center(7, seen.clone()).await, center(7, seen.clone()).await);
    let n = ton(&[&a, &b], Some("k"));
    assert_eq!(n.masterchain_last(0).await.unwrap()["seqno"], 7);
    let v = n
        .post(0, "runGetMethod", &json!({"method": "get_lane_nonce"}))
        .await
        .unwrap();
    assert_eq!(v["echo"]["method"], "get_lane_nonce");
    match n
        .get(0, "transactionsByMessage", &[("msg_hash", "a b".into())])
        .await
        .unwrap_err()
    {
        FamilyError::Status { status, message } => {
            assert_eq!((status, message.as_str()), (404, "not found"))
        }
        e => panic!("{e:?}"),
    }
    n.get(1, "masterchainInfo", &[]).await.unwrap();
    let s = seen.lock().unwrap();
    assert!(
        s.iter()
            .any(|(p, _)| p == "/api/v3/transactionsByMessage?msg_hash=a+b"),
        "{s:?}"
    );
    assert!(
        s[..3].iter().all(|(_, k)| k.as_deref() == Some("k")),
        "{s:?}"
    );
    assert_eq!(s[3].1, None, "endpoint 1 gets no key but its own (none)");
}

/// F5 over TON Center's shapes: an answer of 16 MiB + 1 is the endpoint's failure. Control: a small one is read.
#[tokio::test]
async fn a_ton_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(axum::Router::new().fallback(move || async move {
            let mut b = serde_json::to_vec(&json!({"last": {"seqno": 1}})).unwrap();
            b.resize(len, b' ');
            b
        }))
        .await
    }
    let e = ton(&[&big((16 << 20) + 1).await], None)
        .masterchain_last(0)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        ton(&[&big(100).await], None)
            .masterchain_last(0)
            .await
            .unwrap()["seqno"],
        1,
        "control"
    );
}

/// (b) the failover's checks: the identity is the profile constant (every listed endpoint), one behind the head endpoint 0
/// showed is skipped.
#[tokio::test]
async fn the_failover_skips_an_endpoint_behind() {
    let s: Seen = Default::default();
    let (behind, good) = (center(10, s.clone()).await, center(100, s).await);
    let n = ton(&[DOWN, &behind, &good], None);
    // T24.6 (fixture correction): endpoint 0's head seen with its root hash, the later endpoints' identity reference
    n.saw(100, "b100");
    let seen: Arc<Mutex<Vec<usize>>> = Default::default();
    let a = n
        .client
        .failover(&n, |i| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(i);
                if i == 0 {
                    // endpoint 0 down: the read itself fails (the identity is no request)
                    return Err(scaas_rpc::pool::ReadError::Failure(
                        scaas_rpc::EndpointFailure::new(
                            0,
                            scaas_rpc::FailureKind::Transport,
                            "down",
                        ),
                    ));
                }
                Ok(i)
            }
        })
        .await
        .unwrap();
    assert_eq!(
        (a.endpoint, seen.lock().unwrap().clone()),
        (2, vec![0, 2]),
        "the endpoint behind is never asked"
    );
}

/// T24.6 (owner 2026-11-18): a later endpoint is this network when its masterchain block at the last seqno endpoint 0 showed
/// has endpoint 0's root hash. None seen yet: unread (skipped, asked again); another hash: dropped; the same: it answers.
#[tokio::test]
async fn a_later_endpoint_is_checked_by_endpoint_0s_root_hash() {
    let s: Seen = Default::default();
    let (other, good) = (center_of(100, "x", s.clone()).await, center(100, s).await);
    let n = ton(&[DOWN, &other, &good], None);
    let read = || {
        n.client.failover(&n, |i| async move {
            if i == 0 {
                return Err(scaas_rpc::pool::ReadError::Failure(
                    scaas_rpc::EndpointFailure::new(0, scaas_rpc::FailureKind::Transport, "down"),
                ));
            }
            Ok(i)
        })
    };
    assert!(
        read().await.is_err(),
        "no block of endpoint 0 seen: no later endpoint is this network yet"
    );
    assert_eq!(
        (
            n.client.pool().identity_of(1),
            n.client.pool().identity_of(2)
        ),
        (None, None),
        "asked again"
    );
    n.saw(100, "b100");
    assert_eq!(read().await.unwrap().endpoint, 2);
    assert_eq!(
        n.client.pool().identity_of(1),
        Some(false),
        "another root hash: dropped"
    );
}
