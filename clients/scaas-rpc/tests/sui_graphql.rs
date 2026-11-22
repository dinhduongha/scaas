// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! SDK plan rpc T24.sui-graphql: Sui GraphQL on the family client (public fullnodes refuse JSON-RPC, docs/networks/sui.md
//! §14): a POST of `{query, variables}`, the answer's `data` or its `errors` kept whole, bounded as every family answer; the
//! failover's identity (`chainIdentifier`, the genesis checkpoint's digest) and floor (the latest checkpoint). The fixtures
//! are answers recorded from the public Sui testnet GraphQL service on 2026-11-21.
#![cfg(feature = "sui")]
mod common;
use common::*;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::sui::SuiGraphql;
use scaas_rpc::FailureKind;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// Sui testnet's `chainIdentifier` (recorded): base58 of its genesis checkpoint digest, `4c78adac…` in hex.
const TESTNET: &str = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD";
/// Checkpoint 1000's digest on Sui testnet (recorded).
const CP1000: &str = "B8TBxTd9LJjFxkDF4LafUE9WjTsLf9B8ehda9G56bmcN";
/// The recorded answer to `{ nope }`: a validation error, status 200, `data` null.
const UNKNOWN_FIELD: &str = r#"{"data":null,"errors":[{"message":"Unknown field \"nope\" on type \"Query\". Did you mean \"node\"?","locations":[{"line":1,"column":3}],"extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}"#;

/// A Sui GraphQL service at checkpoint `head` whose checkpoint digests are `fork` + the sequence number (checkpoint 1000:
/// the recorded digest when `fork` is empty), chain identifier `chain`; every request body kept in `seen`.
async fn gql(
    head: u64,
    fork: &'static str,
    chain: &'static str,
    seen: Arc<Mutex<Vec<Value>>>,
) -> String {
    serve(axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
            seen.lock().unwrap().push(r.clone());
            let q = r["query"].as_str().unwrap_or("");
            let a = if q.contains("chainIdentifier") {
                json!({"data": {"chainIdentifier": chain}})
            } else if q.contains("checkpoint(sequenceNumber") {
                let s = r["variables"]["s"].as_u64().unwrap_or(0);
                let d = if fork.is_empty() && s == 1000 {
                    CP1000.to_string()
                } else {
                    format!("{fork}{s}")
                };
                json!({"data": {"checkpoint": {"sequenceNumber": s, "digest": d}}})
            } else if q.contains("checkpoint") {
                json!({"data": {"checkpoint": {"sequenceNumber": head}}})
            } else {
                serde_json::from_str(UNKNOWN_FIELD).unwrap()
            };
            axum::Json(a)
        }),
    ))
    .await
}

/// A service answering every request with `status` and `body` (the identity query answered as Sui testnet, so endpoint 0
/// passes its check).
async fn fixed(status: u16, body: Vec<u8>) -> String {
    serve(axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| async move {
            if r["query"]
                .as_str()
                .unwrap_or("")
                .contains("chainIdentifier")
            {
                let b = json!({"data": {"chainIdentifier": TESTNET}}).to_string();
                return (axum::http::StatusCode::OK, b.into_bytes());
            }
            (axum::http::StatusCode::from_u16(status).unwrap(), body)
        }),
    ))
    .await
}

fn sui(urls: &[&str]) -> SuiGraphql {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    SuiGraphql::new(Client::of_urls(&urls, None).unwrap())
}

fn kind(e: FamilyError) -> FailureKind {
    match e {
        FamilyError::Failure(f) => f.kind,
        e => panic!("not the endpoint's failure: {e:?}"),
    }
}

/// The request is `{query, variables}` and nothing else; the latest checkpoint and checkpoint 1000's digest (recorded) are
/// read from `data`.
#[tokio::test]
async fn a_query_sends_its_variables_and_reads_the_checkpoints() {
    let seen: Arc<Mutex<Vec<Value>>> = Default::default();
    let n = sui(&[&gql(409_041_184, "", TESTNET, seen.clone()).await]);
    assert_eq!(n.latest_checkpoint(0).await.unwrap(), 409_041_184);
    let digest = n.checkpoint_digest(0, 1000).await;
    let last = seen.lock().unwrap().last().cloned().unwrap();
    let keys: Vec<&String> = last.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["query", "variables"]);
    assert_eq!(last["variables"], json!({"s": 1000}), "the variables sent");
    assert_eq!(digest.unwrap(), CP1000);
    assert_eq!(
        n.query(0, "{ chainIdentifier }", json!({})).await.unwrap(),
        json!({"chainIdentifier": TESTNET})
    );
}

/// An `errors` list is the endpoint's own words, kept whole (the recorded validation error); beside `data` too, a partial
/// answer is never read. Controls: the same `data` without `errors`, or with an empty list, is read.
#[tokio::test]
async fn an_errors_answer_is_kept_whole_and_never_read_beside_data() {
    let seen = Default::default();
    match sui(&[&gql(1, "A", TESTNET, seen).await])
        .query(0, "{ nope }", json!({}))
        .await
        .unwrap_err()
    {
        e @ FamilyError::Graphql { .. } => {
            assert!(e.to_string().contains("Unknown field"), "{e}")
        }
        e => panic!("{e:?}"),
    }
    let data = json!({"checkpoint": {"sequenceNumber": 7}});
    let partial = json!({"data": data, "errors": [{"message": "a field failed"}]});
    let e = sui(&[&fixed(200, partial.to_string().into_bytes()).await])
        .query(0, "{ checkpoint { sequenceNumber } }", json!({}))
        .await
        .unwrap_err();
    assert!(matches!(e, FamilyError::Graphql { .. }), "{e:?}");
    for ok in [json!({"data": data}), json!({"data": data, "errors": []})] {
        let got = sui(&[&fixed(200, ok.to_string().into_bytes()).await])
            .query(0, "{ checkpoint { sequenceNumber } }", json!({}))
            .await
            .unwrap();
        assert_eq!(got, data, "control {ok}");
    }
}

/// A 2xx without `data` (absent or null) is the endpoint's `AnswerMalformed`; a 4xx without `errors` is its status. Controls:
/// an empty `data` object is read; a 4xx with `errors` is the errors.
#[tokio::test]
async fn an_answer_without_data_is_malformed_and_a_bare_4xx_is_its_status() {
    for bad in [json!({}), json!({"data": null})] {
        let e = sui(&[&fixed(200, bad.to_string().into_bytes()).await])
            .query(0, "{ x }", json!({}))
            .await
            .unwrap_err();
        assert_eq!(kind(e), FailureKind::AnswerMalformed, "{bad}");
    }
    let ok = sui(&[&fixed(200, br#"{"data":{}}"#.to_vec()).await])
        .query(0, "{ x }", json!({}))
        .await
        .unwrap();
    assert_eq!(ok, json!({}), "control");
    let e = sui(&[&fixed(400, br#"{"message":"bad request"}"#.to_vec()).await])
        .query(0, "{ x }", json!({}))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, FamilyError::Status { status: 400, message } if message.contains("bad request")),
        "{e:?}"
    );
    let e = sui(&[&fixed(400, UNKNOWN_FIELD.as_bytes().to_vec()).await])
        .query(0, "{ x }", json!({}))
        .await
        .unwrap_err();
    assert!(matches!(e, FamilyError::Graphql { .. }), "control: {e:?}");
}

/// F5 and the depth bound over GraphQL answers: 16 MiB + 1 is `AnswerTooLarge`, 65 levels `AnswerTooDeep`. Controls: a
/// small answer and 63 levels are read.
#[tokio::test]
async fn a_graphql_answer_above_its_bounds_is_refused() {
    let padded = |len: usize| {
        let mut b = br#"{"data":{"checkpoint":{"sequenceNumber":5}}}"#.to_vec();
        b.resize(len, b' ');
        b
    };
    let nested = |levels: usize| {
        // the answer object is level 1; `levels` objects in all
        let inner = "{\"a\":".repeat(levels - 1) + "1" + &"}".repeat(levels - 1);
        format!("{{\"data\":{inner}}}").into_bytes()
    };
    let q = |b: Vec<u8>| async move {
        sui(&[&fixed(200, b).await])
            .query(0, "{ checkpoint { sequenceNumber } }", json!({}))
            .await
    };
    assert_eq!(
        kind(q(padded((16 << 20) + 1)).await.unwrap_err()),
        FailureKind::AnswerTooLarge
    );
    assert_eq!(
        kind(q(nested(65)).await.unwrap_err()),
        FailureKind::AnswerTooDeep
    );
    assert!(q(padded(100)).await.is_ok(), "control: small");
    assert!(q(nested(63)).await.is_ok(), "control: 63 levels");
}

/// A checkpoint answer naming another sequence number than asked, and a head that is not a JSON number, are the endpoint's
/// `AnswerMalformed`. Controls: the asked number, a number head.
#[tokio::test]
async fn a_checkpoint_of_another_number_or_a_head_not_a_number_is_malformed() {
    let other = json!({"data": {"checkpoint": {"sequenceNumber": 999, "digest": CP1000}}});
    let e = sui(&[&fixed(200, other.to_string().into_bytes()).await])
        .checkpoint_digest(0, 1000)
        .await
        .unwrap_err();
    assert_eq!(kind(e), FailureKind::AnswerMalformed);
    let same = json!({"data": {"checkpoint": {"sequenceNumber": 1000, "digest": CP1000}}});
    assert_eq!(
        sui(&[&fixed(200, same.to_string().into_bytes()).await])
            .checkpoint_digest(0, 1000)
            .await
            .unwrap(),
        CP1000,
        "control"
    );
    let text = json!({"data": {"checkpoint": {"sequenceNumber": "30"}}});
    let e = sui(&[&fixed(200, text.to_string().into_bytes()).await])
        .latest_checkpoint(0)
        .await
        .unwrap_err();
    assert_eq!(kind(e), FailureKind::AnswerMalformed);
    let num = json!({"data": {"checkpoint": {"sequenceNumber": 30}}});
    assert_eq!(
        sui(&[&fixed(200, num.to_string().into_bytes()).await])
            .latest_checkpoint(0)
            .await
            .unwrap(),
        30,
        "control"
    );
}

/// The failover's checks: an endpoint of another chain identifier than the first endpoint's is dropped, one behind the head
/// endpoint 0 showed is skipped; the first endpoint down, no later endpoint is this network yet.
#[tokio::test]
async fn the_failover_drops_another_network_and_skips_an_endpoint_behind() {
    let s = Arc::new(Mutex::new(vec![]));
    let (first, other, behind, good) = (
        gql(100, "A", TESTNET, s.clone()).await,
        gql(
            100,
            "A",
            "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S",
            s.clone(),
        )
        .await,
        gql(10, "A", TESTNET, s.clone()).await,
        gql(100, "A", TESTNET, s.clone()).await,
    );
    let n = sui(&[&first, &other, &behind, &good]);
    let asked: Arc<Mutex<Vec<usize>>> = Default::default();
    assert_eq!(read(&n, 0, &asked).await.unwrap().endpoint, 0);
    n.client.pool().saw_block(100);
    asked.lock().unwrap().clear();
    assert_eq!(read(&n, 1, &asked).await.unwrap().endpoint, 3);
    assert_eq!(*asked.lock().unwrap(), vec![0, 3]);
    assert_eq!(n.client.pool().identity_of(1), Some(false));
    let n = sui(&[DOWN, &good]);
    assert!(read(&n, 0, &asked).await.is_err());
}

/// A pinned identity (the profile's `chain_uid` in base58): endpoint 0 of another network is refused before its first
/// query. Control: endpoint 0 of the pinned network is read.
#[tokio::test]
async fn a_pinned_identity_refuses_endpoint_0_of_another_network() {
    let s = Arc::new(Mutex::new(vec![]));
    let mainnet = gql(
        5,
        "A",
        "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S",
        s.clone(),
    )
    .await;
    let pinned = |u: &str| {
        SuiGraphql::pinned(
            Client::of_urls(&[u.to_string()], None).unwrap(),
            Some(TESTNET),
        )
    };
    assert!(pinned(&mainnet).latest_checkpoint(0).await.is_err());
    let testnet = gql(5, "A", TESTNET, s).await;
    assert_eq!(
        pinned(&testnet).latest_checkpoint(0).await.unwrap(),
        5,
        "control"
    );
}

/// A failover read through `n` whose endpoints below `down` fail; records which endpoints were asked.
async fn read(
    n: &SuiGraphql,
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
                        scaas_rpc::EndpointFailure::new(i, FailureKind::Transport, "down"),
                    ));
                }
                Ok(i)
            }
        })
        .await
}
