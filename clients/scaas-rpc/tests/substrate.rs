// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! SDK plan T32's read part (decisions CLI-SDK-32's Change of 2026-11-22): `scaas_rpc::substrate`, one code path for Polkadot
//! Hub's Substrate side and the relay chain. The fixtures under `tests/fixtures/substrate/` are answers recorded on 2026-11-22
//! from the public Westend Asset Hub (`hub_*`, finalized block 0x12ca1c6) and Westend relay chain (`relay_*`, finalized block
//! 0x2047865) RPC endpoints (read-only): `chain_getBlockHash(0)`, `chain_getFinalizedHead`, `chain_getHeader` of that head and
//! `state_getStorage` of `System.Account` at it for two `ua-rs` accounts of `smartcontracts/vectors/native/native.json`:
//! `bip39_abandon`'s bare account (funded on the Hub, nothing on the relay chain: its balance lives on the Hub) and its
//! `//xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` account (no entry anywhere). The best head (`chain_getBlockHash` with no block) is the
//! fake's own, another hash, so a read at it shows. Every refusal beside its control.
#![cfg(feature = "substrate")]
mod common;
use common::*;
use scaas_rpc::family::{Client, FamilyError};
use scaas_rpc::substrate::{AccountInfo, Substrate};
use scaas_rpc::FailureKind;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const FUNDED: &str = "26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da985eed350b03894f4ee3db867915c839566933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972";
const EMPTY: &str = "26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9fc0a705871b9c7a603ada16c7ca084570c85dadd1fd4f8f74c09325ddee155ff059236809826c524014f6bda98d1ac20";
const HUB_GENESIS: &str = "0x67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9";
const RELAY_GENESIS: &str = "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";
const HUB_FIN: &str = "0x00c08a64b9900c0e765af6b95322583fa2298b968921ce2d04be9f328f7a2c8a";
const HUB_NUMBER: u64 = 0x12ca1c6;
const BEST: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// The recorded answer `name` of chain `set` (`hub` or `relay`), its `result`.
fn fixture(set: &str, name: &str) -> Value {
    let s = match (set, name) {
        ("hub", "genesis") => include_str!("fixtures/substrate/hub_genesis.json"),
        ("hub", "finalized") => include_str!("fixtures/substrate/hub_finalized.json"),
        ("hub", "header") => include_str!("fixtures/substrate/hub_header.json"),
        ("hub", "funded") => include_str!("fixtures/substrate/hub_funded.json"),
        ("hub", "empty") => include_str!("fixtures/substrate/hub_empty.json"),
        ("relay", "genesis") => include_str!("fixtures/substrate/relay_genesis.json"),
        ("relay", "finalized") => include_str!("fixtures/substrate/relay_finalized.json"),
        ("relay", "header") => include_str!("fixtures/substrate/relay_header.json"),
        ("relay", "funded") => include_str!("fixtures/substrate/relay_funded.json"),
        ("relay", "empty") => include_str!("fixtures/substrate/relay_empty.json"),
        _ => unreachable!(),
    };
    serde_json::from_str::<Value>(s).unwrap()["result"].clone()
}

/// One fake endpoint's answers: a recorded chain, with the funded account's storage answer replaceable.
#[derive(Clone)]
struct Node {
    set: &'static str,
    storage: Option<Value>,
    header: Option<Value>,
    finalized: Option<Value>,
}

fn node(set: &'static str) -> Node {
    Node {
        set,
        storage: None,
        header: None,
        finalized: None,
    }
}

type Seen = Arc<Mutex<Vec<Value>>>;

/// A Substrate JSON-RPC answering from `n`'s recorded chain: block 0, the finalized head and its header, the two accounts'
/// storage at that head only (another block is the node's "unknown block" error), the best head [`BEST`].
async fn up(n: Node, seen: Seen) -> String {
    serve(axum::Router::new().fallback(move |axum::Json(r): axum::Json<Value>| {
        let (n, seen) = (n.clone(), seen.clone());
        async move {
            seen.lock().unwrap().push(r.clone());
            let fin = n.finalized.clone().unwrap_or_else(|| fixture(n.set, "finalized"));
            let p = &r["params"];
            let res = match r["method"].as_str().unwrap() {
                "chain_getBlockHash" if p[0] == 0 => Ok(fixture(n.set, "genesis")),
                "chain_getBlockHash" if p.as_array().is_none_or(|a| a.is_empty()) => Ok(json!(BEST)),
                "chain_getFinalizedHead" => Ok(fin.clone()),
                "chain_getHeader" if p[0] == fin => Ok(n.header.clone().unwrap_or_else(|| fixture(n.set, "header"))),
                "state_getStorage" if p[1] == fin => match p[0].as_str().unwrap().trim_start_matches("0x") {
                    FUNDED => Ok(n.storage.clone().unwrap_or_else(|| fixture(n.set, "funded"))),
                    _ => Ok(fixture(n.set, "empty")),
                },
                _ => Err(json!({"code": 4003, "message": "Client error: UnknownBlock: header not found"})),
            };
            let mut a = match res {
                Ok(v) => json!({"result": v}),
                Err(e) => json!({"error": e}),
            };
            a["jsonrpc"] = json!("2.0");
            a["id"] = r["id"].clone();
            axum::Json(a)
        }
    }))
    .await
}

fn sub(urls: &[&str], genesis: &str) -> Substrate {
    let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
    Substrate::new(Client::of_urls(&urls, None).unwrap(), genesis)
}

fn key(k: &str) -> Vec<u8> {
    (0..k.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&k[i..i + 2], 16).unwrap())
        .collect()
}

fn kind(e: FamilyError) -> FailureKind {
    match e {
        FamilyError::Failure(f) => f.kind,
        e => panic!("{e:?}"),
    }
}

/// The recorded funded account's `AccountInfo` on Westend Asset Hub.
fn funded() -> AccountInfo {
    AccountInfo {
        nonce: 15,
        consumers: 1,
        providers: 2,
        sufficients: 0,
        free: 0x424f_b28f,
        reserved: 0x0c70_72c3_27da,
        frozen: 0,
        flags: 1 << 127,
    }
}

/// The positive control: the Hub's finalized head (hash and number), the funded account's `AccountInfo` decoded at it, an
/// account without an entry as zeros, no read at the best head; the same code path on the relay chain, where the same account
/// holds nothing (its DOT moved to the Hub: T32's probe answer, recorded).
#[tokio::test]
async fn the_hub_and_the_relay_chain_read_at_the_finalized_head() {
    let seen: Seen = Default::default();
    let h = sub(&[&up(node("hub"), seen.clone()).await], HUB_GENESIS);
    let (fin, n) = h.finalized(0).await.unwrap();
    assert_eq!((fin.as_str(), n), (HUB_FIN, HUB_NUMBER));
    assert_eq!(h.account(0, &key(FUNDED), &fin).await.unwrap(), funded());
    assert_eq!(
        h.account(0, &key(EMPTY), &fin).await.unwrap(),
        AccountInfo::default()
    );
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|r| r["params"] != json!([]) || r["method"] != "chain_getBlockHash"),
        "never the best head"
    );
    let r = sub(&[&up(node("relay"), seen).await], RELAY_GENESIS);
    let (fin, n) = r.finalized(0).await.unwrap();
    assert_eq!(n, 0x2047865);
    assert_eq!(
        r.account(0, &key(FUNDED), &fin).await.unwrap(),
        AccountInfo::default()
    );
}

/// CLI-RPC-03: endpoint 0 of another genesis (the relay chain's on a Hub client) is refused before its read. Control: the Hub's.
#[tokio::test]
async fn endpoint_0_of_another_genesis_is_refused() {
    let seen: Seen = Default::default();
    let relay = up(node("relay"), seen.clone()).await;
    let e = sub(&[&relay], HUB_GENESIS).finalized(0).await.unwrap_err();
    assert_eq!(kind(e), FailureKind::WrongChain);
    assert!(
        sub(&[&relay], RELAY_GENESIS).finalized(0).await.is_ok(),
        "control"
    );
}

/// The bounded decode: a value of 79 or 81 bytes, an odd or non-hex value, a number instead of a string are the endpoint's
/// `AnswerMalformed`, each beside the recorded 80-byte value (control).
#[tokio::test]
async fn malformed_and_oversized_storage_is_refused() {
    let seen: Seen = Default::default();
    let rec = fixture("hub", "funded").as_str().unwrap().to_string();
    for (bad, why) in [
        (json!(rec[..rec.len() - 2]), "79 bytes"),
        (json!(format!("{rec}00")), "81 bytes"),
        (json!(format!("{rec}0")), "odd"),
        (json!(format!("{}zz", &rec[..rec.len() - 2])), "not hex"),
        (json!(rec.trim_start_matches("0x")), "no 0x"),
        (json!(7), "a number"),
    ] {
        let mut n = node("hub");
        n.storage = Some(bad);
        let h = sub(&[&up(n, seen.clone()).await], HUB_GENESIS);
        let e = h.account(0, &key(FUNDED), HUB_FIN).await.unwrap_err();
        assert_eq!(kind(e), FailureKind::AnswerMalformed, "{why}");
    }
    let mut n = node("hub");
    n.storage = Some(json!(rec));
    let h = sub(&[&up(n, seen).await], HUB_GENESIS);
    assert_eq!(
        h.account(0, &key(FUNDED), HUB_FIN).await.unwrap(),
        funded(),
        "control"
    );
    assert_eq!(AccountInfo::decode(&[0; 80]), Some(AccountInfo::default()));
    assert_eq!(AccountInfo::decode(&[0; 81]), None);
}

/// A storage answer above 16 MiB is the endpoint's failure before it is parsed (CLI-RPC-07). Control: the recorded one.
#[tokio::test]
async fn a_storage_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        serve(
            axum::Router::new().fallback(move |axum::Json(r): axum::Json<Value>| async move {
                let storage = r["method"] == "state_getStorage";
                let v = fixture("hub", if storage { "funded" } else { "genesis" });
                let mut b =
                    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": r["id"], "result": v}))
                        .unwrap();
                if storage {
                    b.resize(len, b' ');
                }
                b
            }),
        )
        .await
    }
    let e = sub(&[&big((16 << 20) + 1).await], HUB_GENESIS)
        .account(0, &key(FUNDED), HUB_FIN)
        .await
        .unwrap_err();
    assert_eq!(kind(e), FailureKind::AnswerTooLarge);
    assert_eq!(
        sub(&[&big(1000).await], HUB_GENESIS)
            .account(0, &key(FUNDED), HUB_FIN)
            .await
            .unwrap(),
        funded(),
        "control"
    );
}

/// A storage answer nested deeper than 64 is the endpoint's `AnswerTooDeep` (the flat scan, before parsing). Control: depth 2.
#[tokio::test]
async fn a_too_deep_storage_answer_is_refused() {
    async fn deep(depth: usize) -> String {
        serve(
            axum::Router::new().fallback(move |axum::Json(r): axum::Json<Value>| async move {
                let body = if r["method"] == "state_getStorage" {
                    format!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":null,"x":{}{}}}"#,
                        "[".repeat(depth),
                        "]".repeat(depth)
                    )
                } else {
                    json!({"jsonrpc": "2.0", "id": r["id"], "result": fixture("hub", "genesis")})
                        .to_string()
                };
                body.into_bytes()
            }),
        )
        .await
    }
    let e = sub(&[&deep(64).await], HUB_GENESIS)
        .account(0, &key(FUNDED), HUB_FIN)
        .await
        .unwrap_err();
    assert_eq!(kind(e), FailureKind::AnswerTooDeep);
    assert!(
        sub(&[&deep(1).await], HUB_GENESIS)
            .account(0, &key(FUNDED), HUB_FIN)
            .await
            .is_ok(),
        "control"
    );
}

/// The finalized head must be a 32-byte hash and its header's number a hex `u64`: otherwise `AnswerMalformed`.
#[tokio::test]
async fn a_malformed_finalized_head_or_number_is_refused() {
    let seen: Seen = Default::default();
    let mut n = node("hub");
    n.finalized = Some(json!("0x1234"));
    let e = sub(&[&up(n, seen.clone()).await], HUB_GENESIS)
        .finalized(0)
        .await
        .unwrap_err();
    assert_eq!(kind(e), FailureKind::AnswerMalformed, "a short hash");
    let mut n = node("hub");
    let mut h = fixture("hub", "header");
    h["number"] = json!("0x1ffffffffffffffff");
    n.header = Some(h);
    let e = sub(&[&up(n, seen.clone()).await], HUB_GENESIS)
        .finalized(0)
        .await
        .unwrap_err();
    assert_eq!(kind(e), FailureKind::AnswerMalformed, "a number above u64");
    assert!(
        sub(&[&up(node("hub"), seen).await], HUB_GENESIS)
            .finalized(0)
            .await
            .is_ok(),
        "control"
    );
}

/// ARCH-POS-15's failover: one endpoint down and one of another genesis are passed over, the Hub's answers; the identity of
/// each endpoint read by `chain_getBlockHash(0)`.
#[tokio::test]
async fn the_failover_passes_one_down_and_another_genesis() {
    let seen: Seen = Default::default();
    let (relay, hub) = (
        up(node("relay"), seen.clone()).await,
        up(node("hub"), seen).await,
    );
    let h = sub(&[DOWN, &relay, &hub], HUB_GENESIS);
    let a = h
        .client
        .failover(&h, |i| {
            let h = &h;
            async move {
                h.finalized(i).await.map_err(|e| {
                    scaas_rpc::pool::ReadError::Failure(match e {
                        FamilyError::Failure(f) => f,
                        e => panic!("{e:?}"),
                    })
                })
            }
        })
        .await
        .unwrap();
    assert_eq!((a.endpoint, a.value.0.as_str()), (2, HUB_FIN));
    assert_eq!(h.client.pool().identity_of(1), Some(false));
}
