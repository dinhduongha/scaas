// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.sui (spec §8.7; decisions CLI-SDK-15's Change of 2026-11-21, T24.sui): `wallet().balances` on a Sui profile,
//! against a fake Sui GraphQL service (`tests/common/fake_http.rs`, local only) answering in the shapes recorded from the public
//! testnet service on 2026-11-21: `chainIdentifier`, the latest checkpoint, and one query holding the set at one checkpoint
//! (`address(atCheckpoint) { balance(SUI) { totalBalance } }`, `object(atCheckpoint) { asMoveObject { contents { json } } }`
//! per token). The tokens' `Account<T>` ids are the rows of smartcontracts/vectors/families/sui.json (clientkeys'), never
//! derived here. Every refusal beside its control.
#![cfg(feature = "sui")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_http.rs"]
mod fake_http;

use fake_http::{serve, DOWN};
use scaas_sdk::vault::MemoryStore;
use scaas_sdk::wallet::Balances;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, FamilyParams, Finality, Limits, ListedToken,
    RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Sui testnet: its genesis checkpoint digest (`chain_uid`) and the same 32 bytes as `chainIdentifier` names them (recorded).
const UID: &str = "0x4c78adacf2a2f5ad80f27ed7d54aa69d3a78f1ca67fdef9ecf5754f5b8bb77b0";
const TESTNET: &str = "69WiPg3DAQiwdxfncX6wYQ2siKwAe6L9BZthQea3JNMD";
const MAINNET: &str = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";
const H: u64 = 409_048_473;

/// The rows' registries, owners and their `Account<T>` ids: (registry, owner, account) of rows 1 to 4 (two owners under two
/// registries).
fn rows() -> Vec<(String, String, String)> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../smartcontracts/vectors/families/sui.json"
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["account"].as_array().unwrap()[1..5]
        .iter()
        .map(|r| {
            let s = |k: &str| r[k].as_str().unwrap().to_string();
            (s("registry"), s("owner"), s("account"))
        })
        .collect()
}
fn reg(i: usize) -> String {
    rows()[i].0.clone()
}
fn alice() -> String {
    rows()[0].1.clone()
}
fn bob() -> String {
    rows()[2].1.clone()
}

/// One fake service's state.
#[derive(Clone)]
struct Node {
    chain: &'static str,
    head: u64,
    /// SUI by holder (unknown: "0", as the service answers)
    native: HashMap<String, Value>,
    /// the `Account<T>` objects by id: their contents' json
    objects: HashMap<String, Value>,
    /// Alice's SUI from this checkpoint on (the chain moved after the set's checkpoint)
    moved: Option<(u64, Value)>,
    /// every set answer's body, instead of the state's
    raw: Option<Vec<u8>>,
    /// the checkpoint each set query named, and whether each of its reads was pinned to it
    sets: Vec<(u64, bool)>,
}

type Fake = Arc<Mutex<Node>>;
/// One change to a fake's state.
type Change = Box<dyn Fn(&mut Node)>;

fn account(registry: &str, owner: &str, balance: Value) -> Value {
    json!({"id": "0x00", "registry": registry, "network": [], "owner": owner, "balance": balance})
}

fn node() -> Fake {
    let mut n = Node {
        chain: TESTNET,
        head: H,
        native: HashMap::new(),
        objects: HashMap::new(),
        moved: None,
        raw: None,
        sets: vec![],
    };
    n.native.insert(alice(), json!("2500000000"));
    for (r, o, a) in rows() {
        // Bob has no Account of the second registry: its object is absent
        if o == bob() && r == reg(1) {
            continue;
        }
        let b = if o == alice() { "5000000" } else { "7" };
        n.objects.insert(a, account(&r, &o, json!(b)));
    }
    Arc::new(Mutex::new(n))
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap())
}

fn answer(n: &mut Node, body: &[u8]) -> (u16, Vec<u8>) {
    let r: Value = serde_json::from_slice(body).unwrap();
    let (q, v) = (r["query"].as_str().unwrap(), &r["variables"]);
    if q.contains("chainIdentifier") {
        return ok(json!({"data": {"chainIdentifier": n.chain}}));
    }
    if !q.contains("atCheckpoint") {
        return ok(json!({"data": {"checkpoint": {"sequenceNumber": n.head}}}));
    }
    let c = v["c"].as_u64().unwrap();
    let tokens = v
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| k.starts_with('t'))
        .count();
    n.sets
        .push((c, q.matches("atCheckpoint: $c").count() == 1 + tokens));
    if let Some(raw) = &n.raw {
        return (200, raw.clone());
    }
    if c > n.head {
        // recorded: a checkpoint the service has not reached
        return ok(json!({"data": {"checkpoint": null, "address": null},
            "errors": [{"message": format!("Checkpoint {c} in the future"), "path": ["address"],
            "extensions": {"code": "BAD_USER_INPUT"}}]}));
    }
    let a = v["a"].as_str().unwrap();
    let native = match &n.moved {
        Some((from, x)) if a == alice() && c >= *from => x.clone(),
        _ => n.native.get(a).cloned().unwrap_or(json!("0")),
    };
    let mut data = json!({
        "checkpoint": {"sequenceNumber": c},
        "address": {"balance": {"totalBalance": native}},
    });
    for k in 0..tokens {
        let id = v[format!("t{k}")].as_str().unwrap();
        data[format!("t{k}")] = match n.objects.get(id) {
            Some(j) => json!({"asMoveObject": {"contents": {"json": j}}}),
            None => Value::Null,
        };
    }
    ok(json!({ "data": data }))
}

async fn up(f: &Fake) -> String {
    let f = f.clone();
    serve(Arc::new(move |_, _, body: &[u8]| {
        answer(&mut f.lock().unwrap(), body)
    }))
    .await
    .0
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

fn profile(graphql: &[&str], policy: scaas_rpc::Policy) -> ChainProfile {
    ChainProfile {
        key: "sui-testnet".into(),
        family: Family::Sui,
        chain_id: None,
        chain_uid: UID.into(),
        // the JSON-RPC endpoints (the node's): the balance reads never ask them
        rpc: vec![endpoint(DOWN)],
        rpc_policy: scaas_rpc::Policy::Failover,
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
        tokens: vec![token(&reg(0), "USDC", 6), token(&reg(1), "VND", 0)],
        family_params: Some(FamilyParams::Sui {
            graphql: graphql.iter().map(|u| endpoint(u)).collect(),
            graphql_policy: policy,
        }),
    }
}

async fn open(p: ChainProfile) -> Result<Arc<Sdk>, SdkError> {
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
}

async fn read(p: ChainProfile, id: &str) -> Result<Balances, SdkError> {
    open(p)
        .await?
        .wallet()
        .balances(id.into(), "sui-testnet".into())
        .await
}

async fn balances(urls: &[&str], id: &str) -> Result<Balances, SdkError> {
    read(profile(urls, scaas_rpc::Policy::Failover), id).await
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn amounts(b: &Balances) -> Vec<&str> {
    b.tokens.iter().map(|t| t.amount.as_str()).collect()
}

/// The positive control: the holder's SUI and each token's `Account<T>` balance (the rows' derived ids), one query at the
/// latest checkpoint, every read in it pinned there, which is `block`; the tokens as the profile lists them. Bob has no
/// Account of the second token (its object absent): 0.
#[tokio::test(flavor = "multi_thread")]
async fn sui_balances_at_one_checkpoint() {
    let f = node();
    let u = up(&f).await;
    let b = balances(&[&u], &alice()).await.unwrap();
    assert_eq!(b.block, H);
    assert_eq!(b.native.as_deref(), Some("2500000000"));
    assert_eq!(amounts(&b), ["5000000", "5000000"]);
    assert_eq!(
        (
            b.tokens[1].address.as_str(),
            b.tokens[1].display.as_str(),
            b.tokens[1].decimals
        ),
        (reg(1).as_str(), "VND", 0)
    );
    assert_eq!(
        f.lock().unwrap().sets,
        vec![(H, true)],
        "one set, every read pinned"
    );
    let b = balances(&[&u], &bob()).await.unwrap();
    assert_eq!(
        (b.native.as_deref(), amounts(&b)),
        (Some("0"), vec!["7", "0"])
    );
}

/// The holder and the tokens in Sui's long form (`0x` + 64 lowercase hex; Sui has no UA ledger, so such a value is an
/// address): uppercase, short, no `0x`: `Argument`, nothing read; a token out of form likewise; params of another family and a
/// Sui profile without params: `Argument`. Control: the right forms read.
#[tokio::test(flavor = "multi_thread")]
async fn sui_holder_and_token_forms() {
    let f = node();
    let u = up(&f).await;
    let a = alice();
    for id in [
        a.to_uppercase().replacen("0X", "0x", 1),
        a[..65].to_string(),
        a[2..].to_string(),
    ] {
        assert_eq!(code(balances(&[&u], &id).await), "Argument", "{id}");
    }
    assert!(f.lock().unwrap().sets.is_empty(), "nothing read");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.push(token("0x2::sui::SUI", "X", 0));
    assert_eq!(
        code(read(p, &a).await),
        "Argument",
        "a token not of the form"
    );
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family = Family::Aptos;
    assert_eq!(code(open(p).await), "Argument", "params of another family");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family_params = None;
    assert_eq!(code(read(p, &a).await), "Argument", "no params");
    assert_eq!(code(balances(&[&u], &a).await), "Ok", "control");
}

/// One change each from the control: a balance that is not a decimal string, an `Account` of another registry or another
/// owner at the derived id, the answer naming another checkpoint, the recorded partial answer (`errors` beside `data`), a
/// set without the holder's balance: the endpoint's `AnswerMalformed` (alone `EndpointAllFailed`; behind it a good endpoint
/// answers). Control: 2^256 - 1 is read.
#[tokio::test(flavor = "multi_thread")]
async fn sui_malformed_answers_are_refused() {
    let good = node();
    let g = up(&good).await;
    let (a, rs) = (alice(), rows());
    let acct0 = rs[0].2.clone();
    let bad_state: Vec<(&str, Change)> = vec![
        (
            "a number",
            Box::new(|n| {
                n.native.insert(alice(), json!(12));
            }),
        ),
        (
            "a sign",
            Box::new(|n| {
                n.native.insert(alice(), json!("-1"));
            }),
        ),
        (
            "79 digits",
            Box::new(|n| {
                n.native.insert(alice(), json!("0".repeat(79)));
            }),
        ),
        ("another registry", {
            let (id, o) = (acct0.clone(), a.clone());
            Box::new(move |n| {
                n.objects
                    .insert(id.clone(), account(&reg(1), &o, json!("1")));
            })
        }),
        ("another owner", {
            let id = acct0.clone();
            Box::new(move |n| {
                n.objects
                    .insert(id.clone(), account(&reg(0), &bob(), json!("1")));
            })
        }),
        ("an account balance as a number", {
            let (id, o) = (acct0.clone(), a.clone());
            Box::new(move |n| {
                n.objects.insert(id.clone(), account(&reg(0), &o, json!(1)));
            })
        }),
        (
            "another checkpoint",
            Box::new(|n| {
                n.raw = Some(
                    serde_json::to_vec(&json!({"data": {"checkpoint": {"sequenceNumber": H - 1},
                "address": {"balance": {"totalBalance": "1"}}, "t0": null, "t1": null}}))
                    .unwrap(),
                );
            }),
        ),
        (
            "the recorded partial answer",
            Box::new(|n| {
                n.raw = Some(serde_json::to_vec(&json!({"data": {"checkpoint": {"sequenceNumber": H},
                "address": {"balance": null}, "t0": null, "t1": null},
                "errors": [{"message": "Request is outside consistent range", "path": ["address", "balance"],
                "extensions": {"code": "BAD_USER_INPUT"}}]})).unwrap());
            }),
        ),
        (
            "no holder balance",
            Box::new(|n| {
                n.raw = Some(
                    serde_json::to_vec(&json!({"data": {"checkpoint": {"sequenceNumber": H},
                "address": {"balance": null}, "t0": null, "t1": null}}))
                    .unwrap(),
                );
            }),
        ),
    ];
    for (why, change) in bad_state {
        let f = node();
        change(&mut f.lock().unwrap());
        let u = up(&f).await;
        assert_eq!(
            code(balances(&[&u], &a).await),
            "EndpointAllFailed",
            "{why}"
        );
        let b = balances(&[&u, &g], &a).await.unwrap();
        assert_eq!(
            b.native.as_deref(),
            Some("2500000000"),
            "the second endpoint's ({why})"
        );
    }
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let f = node();
    f.lock().unwrap().native.insert(a.clone(), json!(max));
    let u = up(&f).await;
    assert_eq!(
        balances(&[&u], &a).await.unwrap().native.as_deref(),
        Some(max),
        "control"
    );
}

/// An answer above the family client's bound (16 MiB) is the endpoint's failure; behind it a good endpoint answers. Control:
/// the same answer padded to 1 KiB is read.
#[tokio::test(flavor = "multi_thread")]
async fn sui_oversized_answer_is_refused() {
    let good = node();
    let g = up(&good).await;
    let f = node();
    let mut body = serde_json::to_vec(&json!({"data": {"checkpoint": {"sequenceNumber": H},
        "address": {"balance": {"totalBalance": "3"}}, "t0": null, "t1": null}}))
    .unwrap();
    body.resize((16 << 20) + 1, b' ');
    f.lock().unwrap().raw = Some(body.clone());
    let u = up(&f).await;
    assert_eq!(code(balances(&[&u], &alice()).await), "EndpointAllFailed");
    assert_eq!(
        balances(&[&u, &g], &alice())
            .await
            .unwrap()
            .native
            .as_deref(),
        Some("2500000000")
    );
    body.truncate(1024);
    f.lock().unwrap().raw = Some(body);
    let b = balances(&[&u], &alice()).await.unwrap();
    assert_eq!(
        (b.native.as_deref(), amounts(&b)),
        (Some("3"), vec!["0", "0"]),
        "control"
    );
}

/// ARCH-POS-15 failover with two services, one down: either order answers; endpoint 0 answers when it is up.
#[tokio::test(flavor = "multi_thread")]
async fn sui_two_endpoints_one_down() {
    let (a, b) = (node(), node());
    b.lock().unwrap().native.insert(alice(), json!("2"));
    let (ua, ub) = (up(&a).await, up(&b).await);
    let r = balances(&[DOWN, &ub], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2"), "the second endpoint");
    let r = balances(&[&ua, DOWN], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"));
    let r = balances(&[&ua, &ub], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"), "endpoint 0 first");
}

/// `chain_uid` is the identity (its 32 bytes in base58 against `chainIdentifier`): a mainnet service is dropped, endpoint 0
/// included. Control: the testnet one behind it answers.
#[tokio::test(flavor = "multi_thread")]
async fn sui_endpoint_of_another_network_is_dropped() {
    let (other, good) = (node(), node());
    other.lock().unwrap().chain = MAINNET;
    other.lock().unwrap().native.insert(alice(), json!("666"));
    let (uo, ug) = (up(&other).await, up(&good).await);
    assert_eq!(code(balances(&[&uo], &alice()).await), "EndpointAllFailed");
    let r = balances(&[&uo, &ug], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"));
    assert!(
        other.lock().unwrap().sets.is_empty(),
        "nothing read from another network"
    );
}

async fn majority(urls: &[&str]) -> Result<Balances, SdkError> {
    read(profile(urls, scaas_rpc::Policy::StrictMajority), &alice()).await
}

/// `strict_majority`: the other services read the set at endpoint 0's checkpoint (their own head further, Alice's SUI moved
/// since: `atCheckpoint` pins the old state) and a strict majority must agree; one liar of three is outvoted (control), two
/// disagreeing of three is `EndpointNoMajority`, and a service of another network repeating endpoint 0's answer does not
/// count; a service behind endpoint 0's checkpoint (the recorded "in the future") does not agree.
#[tokio::test(flavor = "multi_thread")]
async fn sui_strict_majority_agrees_at_one_checkpoint() {
    let (a, b, liar, liar2, other, behind) = (node(), node(), node(), node(), node(), node());
    liar.lock().unwrap().native.insert(alice(), json!("666"));
    let acct1 = rows()[1].2.clone();
    liar2
        .lock()
        .unwrap()
        .objects
        .insert(acct1, account(&reg(1), &alice(), json!("1")));
    other.lock().unwrap().chain = MAINNET;
    b.lock().unwrap().head = H + 5;
    b.lock().unwrap().moved = Some((H + 1, json!("999")));
    behind.lock().unwrap().head = H - 1;
    let (ua, ub, ul, ul2, uo, uh) = (
        up(&a).await,
        up(&b).await,
        up(&liar).await,
        up(&liar2).await,
        up(&other).await,
        up(&behind).await,
    );
    let r = majority(&[&ua, &ul, &ub]).await.unwrap();
    assert_eq!((r.block, r.native.as_deref()), (H, Some("2500000000")));
    assert_eq!(
        b.lock().unwrap().sets,
        vec![(H, true)],
        "endpoint 0's checkpoint"
    );
    assert_eq!(
        code(majority(&[&ua, &ul, &ul2]).await),
        "EndpointNoMajority"
    );
    assert_eq!(code(majority(&[&ua, &uo, &ul]).await), "EndpointNoMajority");
    assert_eq!(code(majority(&[&ua, &uh, &ul]).await), "EndpointNoMajority");
    assert_eq!(
        code(majority(&[&ua, &uh, &ub]).await),
        "Ok",
        "control: two of three"
    );
}
