// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.algorand (spec §8.7; decisions CLI-SDK-15's Change of 2026-11-21): `wallet().balances` on an Algorand profile,
//! against a fake algod (`tests/common/fake_http.rs`, local only) answering in algod's shapes (`/v2/transactions/params`,
//! `/v2/status`, `/v2/accounts/{a}?exclude=all`, `/v2/applications/{app}/box?name=b64:…`). One token app's boxes, `"b" ‖ pk32`
//! for an address and `"u" ‖ id32` for a UA id, each a 32-byte big-endian amount (NET-ALG; kept apart from NEAR's per-token
//! ledgers). Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_http.rs"]
mod fake_http;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fake_http::{serve, Seen, DOWN};
use scaas_sdk::vault::MemoryStore;
use scaas_sdk::wallet::Balances;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, ListedToken, RuntimeChoice, Sdk,
    SdkConfig, SdkError,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// The network's 32 bytes (`chain_uid`) and their base64 form, the `genesis-hash` algod names.
const UID: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const GENESIS: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const OTHER: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
/// The address of the key 0x07 × 32, and of 0x09 × 32.
const ALICE: &str = "A4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DVZ36IB4";
const BOB: &str = "BEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEURVP5F4";
const USDC: u64 = 1001;
const VND: u64 = 1002;
const ROUND: u64 = 5_000;

/// One fake algod's state.
#[derive(Clone)]
struct Node {
    genesis: &'static str,
    round: u64,
    /// the account's `amount` (algod answers 0 for an account it does not know)
    native: HashMap<String, Value>,
    /// a box's value bytes by (app, name); absent: 404
    boxes: HashMap<(u64, Vec<u8>), Vec<u8>>,
    /// every answer after the first of a set names one round more (the chain moved between two reads), this many times
    moves: u32,
}

type Fake = Arc<Mutex<Node>>;

fn word(v: u128) -> Vec<u8> {
    let mut w = vec![0u8; 16];
    w.extend_from_slice(&v.to_be_bytes());
    w
}

fn name(tag: u8, key: [u8; 32]) -> Vec<u8> {
    let mut n = vec![tag];
    n.extend_from_slice(&key);
    n
}

fn node() -> Fake {
    let mut n = Node {
        genesis: GENESIS,
        round: ROUND,
        native: HashMap::new(),
        boxes: HashMap::new(),
        moves: 0,
    };
    n.native.insert(ALICE.into(), json!(2_500_000u64));
    n.boxes.insert((USDC, name(b'b', [7; 32])), word(5_000_000));
    n.boxes.insert((VND, name(b'b', [7; 32])), word(1_000));
    n.boxes.insert((USDC, name(b'u', [11; 32])), word(7));
    Arc::new(Mutex::new(n))
}

/// `%XX` escapes decoded (the query's `name`).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let (mut out, mut i) = (vec![], 0);
    while i < b.len() {
        if b[i] == b'%' {
            out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn not_found() -> (u16, Vec<u8>) {
    (404, br#"{"message":"box not found"}"#.to_vec())
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap())
}

fn answer(n: &mut Node, path: &str) -> (u16, Vec<u8>) {
    let (p, q) = path.split_once('?').unwrap_or((path, ""));
    let round = n.round;
    if n.moves > 0 {
        n.moves -= 1;
        n.round += 1;
    }
    match p.split('/').collect::<Vec<_>>()[1..] {
        ["v2", "transactions", "params"] => ok(
            json!({"genesis-hash": n.genesis, "genesis-id": "testnet-v1.0", "last-round": round}),
        ),
        ["v2", "status"] => ok(json!({"last-round": round, "catchup-time": 0})),
        ["v2", "blocks", r, "hash"] => ok(json!({"blockHash": format!("h{r}")})),
        ["v2", "accounts", a] => {
            assert_eq!(q, "exclude=all");
            let amount = n.native.get(a).cloned().unwrap_or(json!(0));
            ok(
                json!({"address": a, "amount": amount, "round": round, "status": "Offline",
                       "min-balance": 100000, "total-apps-opted-in": 0}),
            )
        }
        ["v2", "applications", app, "box"] => {
            let nm = unescape(q.strip_prefix("name=").unwrap());
            let raw = B64.decode(nm.strip_prefix("b64:").unwrap()).unwrap();
            match n.boxes.get(&(app.parse().unwrap(), raw)) {
                Some(v) => ok(
                    json!({"name": nm.strip_prefix("b64:").unwrap(), "round": round,
                                       "value": B64.encode(v)}),
                ),
                None => not_found(),
            }
        }
        _ => (404, br#"{"message":"no route"}"#.to_vec()),
    }
}

async fn up(f: &Fake) -> (String, Seen) {
    let f = f.clone();
    serve(Arc::new(move |_, path: &str, _| {
        answer(&mut f.lock().unwrap(), path)
    }))
    .await
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

fn token(address: &str, symbol: &str, decimals: u8) -> ListedToken {
    ListedToken {
        address: address.into(),
        symbol: symbol.into(),
        decimals,
    }
}

fn profile(rpc: &[&str], policy: scaas_rpc::Policy) -> ChainProfile {
    ChainProfile {
        key: "algorand-testnet".into(),
        family: Family::Algorand,
        chain_id: None,
        chain_uid: UID.into(),
        rpc: rpc.iter().map(|u| endpoint(u)).collect(),
        rpc_policy: policy,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: None,
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![
            token(&USDC.to_string(), "USDC", 6),
            token(&VND.to_string(), "VND", 0),
        ],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    }
}

async fn sdk(p: ChainProfile) -> Arc<Sdk> {
    Sdk::open(SdkConfig {
        profiles: vec![p],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap()
}

async fn read(p: ChainProfile, id: &str) -> Result<Balances, SdkError> {
    sdk(p)
        .await
        .wallet()
        .balances(id.into(), "algorand-testnet".into())
        .await
}

async fn balances(rpc: &[&str], id: &str) -> Result<Balances, SdkError> {
    read(profile(rpc, scaas_rpc::Policy::Failover), id).await
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn amounts(b: &Balances) -> Vec<&str> {
    b.tokens.iter().map(|t| t.amount.as_str()).collect()
}

/// The positive control: the account's `amount` (microalgos) and each token app's `"b" ‖ pk` box, all naming one round, which
/// is `block`; the tokens as the profile lists them.
#[tokio::test(flavor = "multi_thread")]
async fn algorand_balances_at_one_round() {
    let f = node();
    let (u, seen) = up(&f).await;
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(b.block, ROUND);
    assert_eq!(b.native.as_deref(), Some("2500000"));
    assert_eq!(amounts(&b), ["5000000", "1000"]);
    assert_eq!(
        (
            b.tokens[1].address.as_str(),
            b.tokens[1].display.as_str(),
            b.tokens[1].decimals
        ),
        ("1002", "VND", 0)
    );
    let paths: Vec<String> = seen.lock().unwrap().iter().map(|r| r.1.clone()).collect();
    assert!(
        paths.contains(&format!("/v2/accounts/{ALICE}?exclude=all")),
        "{paths:?}"
    );
}

/// A `0x` 32-byte UA id reads the `"u" ‖ id` box and holds no native coin; a box algod does not have (404) is 0, as the
/// app keeps no box for a zero balance.
#[tokio::test(flavor = "multi_thread")]
async fn algorand_ua_id_reads_the_u_box() {
    let f = node();
    let (u, _) = up(&f).await;
    let b = balances(&[&u], &format!("0x{}", "0b".repeat(32)))
        .await
        .unwrap();
    assert_eq!((b.native.as_deref(), amounts(&b)), (None, vec!["7", "0"]));
    assert_eq!(b.block, ROUND, "the round its one box answer named");
    let b = balances(&[&u], BOB).await.unwrap();
    assert_eq!(
        (b.native.as_deref(), amounts(&b)),
        (Some("0"), vec!["0", "0"])
    );
}

/// A holder that is not an Algorand address (a bad checksum, lower case, 57 characters) nor a `0x` 32-byte id, and a listed
/// token that is not an app id in decimal (a leading zero, 0, a name, above u64) are `Argument` before any read; the controls
/// are read.
#[tokio::test(flavor = "multi_thread")]
async fn algorand_holder_and_token_forms() {
    let f = node();
    let (u, seen) = up(&f).await;
    let bad_sum = format!("{}A", &ALICE[..57]);
    let lower = ALICE.to_ascii_lowercase();
    for bad in [
        bad_sum.as_str(),
        lower.as_str(),
        &ALICE[..57],
        "0x0b0b",
        "alice.testnet",
    ] {
        assert_eq!(code(balances(&[&u], bad).await), "Argument", "{bad}");
    }
    assert!(seen.lock().unwrap().is_empty(), "nothing read");
    for t in ["01001", "0", "usdc", "18446744073709551616", ""] {
        let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
        p.tokens.push(token(t, "X", 0));
        assert_eq!(code(read(p, ALICE).await), "Argument", "{t:?}");
    }
    assert_eq!(code(balances(&[&u], ALICE).await), "Ok", "control");
}

/// Bounded decode: a box value of another length than 32 bytes, a value that is not base64, an account `amount` that is not an
/// integer (a float, a string, negative) is the endpoint's `AnswerMalformed`: alone the read fails, behind it a good endpoint
/// answers. Control: a 32-byte value of 2^256 - 1.
#[tokio::test(flavor = "multi_thread")]
async fn algorand_malformed_answers_are_refused() {
    let good = node();
    let (g, _) = up(&good).await;
    let short = vec![1u8; 31];
    let long = vec![1u8; 33];
    for (native, value) in [
        (None, Some(short)),
        (None, Some(long)),
        (Some(json!(1.5)), None),
        (Some(json!("2500000")), None),
        (Some(json!(-1)), None),
    ] {
        let f = node();
        if let Some(v) = native.clone() {
            f.lock().unwrap().native.insert(ALICE.into(), v);
        }
        if let Some(v) = value.clone() {
            f.lock()
                .unwrap()
                .boxes
                .insert((USDC, name(b'b', [7; 32])), v);
        }
        let (u, _) = up(&f).await;
        assert_eq!(
            code(balances(&[&u], ALICE).await),
            "EndpointAllFailed",
            "{native:?} {value:?}"
        );
        let b = balances(&[&u, &g], ALICE).await.unwrap();
        assert_eq!(amounts(&b), ["5000000", "1000"], "the second endpoint's");
    }
    let f = node();
    f.lock()
        .unwrap()
        .boxes
        .insert((USDC, name(b'b', [7; 32])), vec![0xff; 32]);
    let (u, _) = up(&f).await;
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(
        b.tokens[0].amount,
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        "control"
    );
}

/// One round: when the chain moves between two reads of the set, the set is read again once; moving again, the endpoint's
/// answer is refused. Control: a move once is absorbed (the second pass is at one round).
#[tokio::test(flavor = "multi_thread")]
async fn algorand_answers_at_two_rounds_are_retried_once() {
    let f = node();
    let (u, _) = up(&f).await;
    // the probe's identity read comes first: one move lands inside the first pass of the set
    f.lock().unwrap().moves = 2;
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(
        amounts(&b),
        ["5000000", "1000"],
        "control: read again at one round"
    );
    let f = node();
    let (u, _) = up(&f).await;
    f.lock().unwrap().moves = 100;
    assert_eq!(code(balances(&[&u], ALICE).await), "EndpointAllFailed");
}

/// ARCH-POS-15 failover with two endpoints, one down: either order answers; endpoint 0 answers when it is up.
#[tokio::test(flavor = "multi_thread")]
async fn algorand_two_endpoints_one_down() {
    let (a, b) = (node(), node());
    b.lock().unwrap().native.insert(ALICE.into(), json!(2));
    let ((ua, _), (ub, _)) = (up(&a).await, up(&b).await);
    let r = balances(&[DOWN, &ub], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2"));
    let r = balances(&[&ua, DOWN], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"));
    let r = balances(&[&ua, &ub], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"), "endpoint 0 first");
}

/// The profile's `chain_uid` is the genesis hash, base64 as algod names it: an endpoint of another genesis is dropped.
#[tokio::test(flavor = "multi_thread")]
async fn algorand_endpoint_of_another_genesis_is_dropped() {
    let (other, good) = (node(), node());
    other.lock().unwrap().genesis = OTHER;
    let ((uo, _), (ug, _)) = (up(&other).await, up(&good).await);
    assert_eq!(code(balances(&[&uo], ALICE).await), "EndpointAllFailed");
    assert_eq!(code(balances(&[&uo, &ug], ALICE).await), "Ok", "control");
}

/// `strict_majority`: the others' sets must name the answering endpoint's round and agree; one liar of three is outvoted, two
/// disagreeing are `EndpointNoMajority`, an endpoint of another genesis does not count, nor one a round ahead.
#[tokio::test(flavor = "multi_thread")]
async fn algorand_strict_majority_agrees_at_one_round() {
    let (a, b, liar, liar2, other, ahead) = (node(), node(), node(), node(), node(), node());
    liar.lock().unwrap().native.insert(ALICE.into(), json!(666));
    liar2
        .lock()
        .unwrap()
        .boxes
        .insert((VND, name(b'b', [7; 32])), word(1));
    other.lock().unwrap().genesis = OTHER;
    ahead.lock().unwrap().round = ROUND + 1;
    let mut u = vec![];
    for f in [&a, &b, &liar, &liar2, &other, &ahead] {
        u.push(up(f).await.0);
    }
    let maj = |l: Vec<&String>| {
        let l: Vec<&str> = l.iter().map(|s| s.as_str()).collect();
        read(profile(&l, scaas_rpc::Policy::StrictMajority), ALICE)
    };
    let r = maj(vec![&u[0], &u[2], &u[1]]).await.unwrap();
    assert_eq!((r.block, r.native.as_deref()), (ROUND, Some("2500000")));
    assert_eq!(
        code(maj(vec![&u[0], &u[2], &u[3]]).await),
        "EndpointNoMajority"
    );
    assert_eq!(
        code(maj(vec![&u[0], &u[4], &u[2]]).await),
        "EndpointNoMajority"
    );
    assert_eq!(
        code(maj(vec![&u[0], &u[5], &u[2]]).await),
        "EndpointNoMajority"
    );
    assert_eq!(code(maj(vec![&u[0], &u[4], &u[1]]).await), "Ok", "control");
}
