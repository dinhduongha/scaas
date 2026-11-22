// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.cosmos (spec §8.7; decisions CLI-SDK-15's Changes of 2026-11-21): `wallet().balances` on a Cosmos profile, against
//! a fake REST gateway (`tests/common/fake_http.rs`, local only) answering in the Cosmos SDK gateway's shapes (`node_info`, the
//! latest block, `bank/v1beta1/balances/{a}/by_denom`, a CW20 smart query), each balance read at the height its
//! `x-cosmos-block-height` header names. Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_http.rs"]
mod fake_http;

use base64::Engine;
use fake_http::{serve_head, DOWN};
use scaas_sdk::vault::MemoryStore;
use scaas_sdk::wallet::Balances;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, FamilyParams, Finality, Limits, ListedToken,
    RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const UID: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const CHAIN: &str = "scaas-local-1";
const DENOM: &str = "uscaas";
/// bech32 `wasm` of 0x07 × 20 and 0x09 × 20 (accounts), of 0x01 × 32 and 0x02 × 32 (contracts); 0x07 × 20 as `osmo`
const ALICE: &str = "wasm1qurswpc8qurswpc8qurswpc8qurswpc8e0k0f2";
const BOB: &str = "wasm1pyysjzgfpyysjzgfpyysjzgfpyysjzgfh8968j";
const USDC: &str = "wasm1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqssdk9vm";
const VND: &str = "wasm1qgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqam3zen";
const OSMO_ALICE: &str = "osmo1qurswpc8qurswpc8qurswpc8qurswpc8mg52kn";
/// 0x01 × 32 with a padding bit set, its checksum right (a decoder refuses it)
const PADDED: &str = "wasm1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyq3dmzs3f";
const H: u64 = 7_000;

/// One fake gateway's state.
#[derive(Clone)]
struct Node {
    network: &'static str,
    height: u64,
    /// the bank's amount of `DENOM` by address (an unknown one: "0")
    native: HashMap<String, Value>,
    /// a CW20 balance by (contract, address) (an unknown holder: "0")
    cw: HashMap<(String, String), Value>,
    /// Alice's native amount from this height on (the chain moved after the set's height)
    moved: Option<(u64, Value)>,
    /// every balance answer's body, instead of the state's
    raw: Option<Vec<u8>>,
    /// the heights the balance reads named
    heights: Vec<Option<u64>>,
}

type Fake = Arc<Mutex<Node>>;

fn node() -> Fake {
    let mut n = Node {
        network: CHAIN,
        height: H,
        native: HashMap::new(),
        cw: HashMap::new(),
        moved: None,
        raw: None,
        heights: vec![],
    };
    n.native.insert(ALICE.into(), json!("2500000"));
    n.cw.insert((USDC.into(), ALICE.into()), json!("5000000"));
    n.cw.insert((VND.into(), ALICE.into()), json!("1000"));
    Arc::new(Mutex::new(n))
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap())
}

fn answer(n: &mut Node, path: &str, head: &str) -> (u16, Vec<u8>) {
    let (p, q) = path.split_once('?').unwrap_or((path, ""));
    let at = head.lines().find_map(|l| {
        l.strip_prefix("x-cosmos-block-height:")
            .map(|v| v.trim().parse::<u64>().unwrap())
    });
    let parts: Vec<&str> = p.split('/').collect();
    match parts[1..] {
        ["cosmos", "base", "tendermint", "v1beta1", "node_info"] => {
            ok(json!({"default_node_info": {"network": n.network}}))
        }
        ["cosmos", "base", "tendermint", "v1beta1", "blocks", "latest"] => {
            ok(json!({"block": {"header": {"height": n.height.to_string()}}}))
        }
        ["cosmos", "bank", "v1beta1", "balances", a, "by_denom"] => {
            n.heights.push(at);
            assert_eq!(q, format!("denom={DENOM}"));
            if let Some(r) = &n.raw {
                return (200, r.clone());
            }
            let h = at.unwrap_or(n.height);
            let amount = match &n.moved {
                Some((from, v)) if a == ALICE && h >= *from => v.clone(),
                _ => n.native.get(a).cloned().unwrap_or(json!("0")),
            };
            ok(json!({"balance": {"denom": DENOM, "amount": amount}}))
        }
        ["cosmwasm", "wasm", "v1", "contract", c, "smart", q64] => {
            n.heights.push(at);
            if let Some(r) = &n.raw {
                return (200, r.clone());
            }
            let qv: Value = serde_json::from_slice(
                &base64::engine::general_purpose::URL_SAFE
                    .decode(q64)
                    .unwrap(),
            )
            .unwrap();
            let a = qv["balance"]["address"].as_str().unwrap();
            let b =
                n.cw.get(&(c.to_string(), a.to_string()))
                    .cloned()
                    .unwrap_or(json!("0"));
            ok(json!({"data": {"balance": b}}))
        }
        _ => (400, br#"{"code":12,"message":"Not Implemented"}"#.to_vec()),
    }
}

async fn up(f: &Fake) -> String {
    let f = f.clone();
    serve_head(Arc::new(move |_, path: &str, head: &str, _| {
        answer(&mut f.lock().unwrap(), path, head)
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

fn params(rest: &[&str], policy: scaas_rpc::Policy) -> FamilyParams {
    FamilyParams::Cosmos {
        chain_id: CHAIN.into(),
        rest: rest.iter().map(|u| endpoint(u)).collect(),
        rest_policy: policy,
        denom: DENOM.into(),
        prefix: "wasm".into(),
    }
}

fn profile(rest: &[&str], policy: scaas_rpc::Policy) -> ChainProfile {
    ChainProfile {
        key: "cosmos-testnet".into(),
        family: Family::Cosmos,
        chain_id: None,
        chain_uid: UID.into(),
        // the CometBFT endpoints: the balance reads never ask them
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
        tokens: vec![token(USDC, "USDC", 6), token(VND, "VND", 0)],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: Some(params(rest, policy)),
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
        .balances(id.into(), "cosmos-testnet".into())
        .await
}

async fn balances(rest: &[&str], id: &str) -> Result<Balances, SdkError> {
    read(profile(rest, scaas_rpc::Policy::Failover), id).await
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn amounts(b: &Balances) -> Vec<&str> {
    b.tokens.iter().map(|t| t.amount.as_str()).collect()
}

/// The positive control: the bank's `uscaas` amount and each CW20's `data.balance`, every read carrying the latest block's
/// height in `x-cosmos-block-height`, which is `block`; the tokens as the profile lists them; an address the chain does not
/// know reads "0" everywhere (the bank's and the CW20's own answer).
#[tokio::test(flavor = "multi_thread")]
async fn cosmos_balances_at_one_height() {
    let f = node();
    let u = up(&f).await;
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(b.block, H);
    assert_eq!(b.native.as_deref(), Some("2500000"));
    assert_eq!(amounts(&b), ["5000000", "1000"]);
    assert_eq!(
        (
            b.tokens[0].address.as_str(),
            b.tokens[0].display.as_str(),
            b.tokens[0].decimals
        ),
        (USDC, "USDC", 6)
    );
    assert_eq!(
        f.lock().unwrap().heights,
        vec![Some(H); 3],
        "every read pinned"
    );
    let b = balances(&[&u], BOB).await.unwrap();
    assert_eq!(
        (b.native.as_deref(), amounts(&b)),
        (Some("0"), vec!["0", "0"])
    );
}

/// The holder and the token ids in the chain's form: a `0x` UA id (Cosmos has no UA ledger), another prefix, a wrong checksum,
/// an uppercase address, a padding bit set, a token that is no address of the prefix: `Argument`, nothing read. Params of another family, a
/// Cosmos profile without params, a denom or a chain id out of form: `Argument`. Control: the right forms read.
#[tokio::test(flavor = "multi_thread")]
async fn cosmos_holder_and_token_forms() {
    let f = node();
    let u = up(&f).await;
    let ua = format!("0x{}", "0b".repeat(32));
    let bad_sum = format!("{}3", &ALICE[..ALICE.len() - 1]);
    for id in [
        ua.as_str(),
        OSMO_ALICE,
        bad_sum.as_str(),
        &ALICE.to_uppercase(),
        USDC.trim_end_matches('m'),
        PADDED,
    ] {
        assert_eq!(code(balances(&[&u], id).await), "Argument", "{id}");
    }
    assert!(f.lock().unwrap().heights.is_empty(), "nothing read");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.push(token("1001", "X", 0));
    assert_eq!(
        code(read(p, ALICE).await),
        "Argument",
        "a token not of the form"
    );
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family = Family::Near;
    assert_eq!(code(open(p).await), "Argument", "params of another family");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family_params = None;
    assert_eq!(code(read(p, ALICE).await), "Argument", "no params");
    for (chain_id, denom) in [
        ("", DENOM),
        (CHAIN, "u"),
        (CHAIN, "1scaas"),
        (CHAIN, "u scaas"),
    ] {
        let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
        p.family_params = Some(FamilyParams::Cosmos {
            chain_id: chain_id.into(),
            rest: vec![endpoint(&u)],
            rest_policy: scaas_rpc::Policy::Failover,
            denom: denom.into(),
            prefix: "wasm".into(),
        });
        assert_eq!(code(open(p).await), "Argument", "{chain_id:?} {denom:?}");
    }
    assert_eq!(code(balances(&[&u], ALICE).await), "Ok", "control");
    assert_eq!(
        code(balances(&[&u], USDC).await),
        "Ok",
        "control: a contract holds"
    );
}

/// A balance that is not a decimal string of at most 78 digits within a U256 (a number, a float, a sign, 79 digits, above
/// 2^256 - 1, an answer without the field) is the endpoint's `AnswerMalformed`: alone it fails the read (`EndpointAllFailed`);
/// behind it a good endpoint answers. Control: 2^256 - 1 is read.
#[tokio::test(flavor = "multi_thread")]
async fn cosmos_malformed_answers_are_refused() {
    let good = node();
    let g = up(&good).await;
    let (z79, n78) = ("0".repeat(79), "9".repeat(78));
    for bad in [
        json!(12),
        json!("1.5"),
        json!("-1"),
        json!(""),
        json!("1_000"),
        json!(z79),
        json!(n78),
        json!(null),
    ] {
        let f = node();
        f.lock().unwrap().native.insert(ALICE.into(), bad.clone());
        let u = up(&f).await;
        assert_eq!(
            code(balances(&[&u], ALICE).await),
            "EndpointAllFailed",
            "{bad}"
        );
        let b = balances(&[&u, &g], ALICE).await.unwrap();
        assert_eq!(
            b.native.as_deref(),
            Some("2500000"),
            "the second endpoint's ({bad})"
        );
    }
    let f = node();
    f.lock().unwrap().raw = Some(br#"{"code":2,"message":"x"}"#.to_vec());
    let u = up(&f).await;
    assert_eq!(
        code(balances(&[&u], ALICE).await),
        "EndpointAllFailed",
        "no field"
    );
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let f = node();
    f.lock()
        .unwrap()
        .cw
        .insert((USDC.into(), ALICE.into()), json!(max));
    let u = up(&f).await;
    assert_eq!(
        amounts(&balances(&[&u], ALICE).await.unwrap())[0],
        max,
        "control"
    );
}

/// An answer above the family client's bound (16 MiB) is the endpoint's failure; behind it a good endpoint answers. Control:
/// the same answer padded to 1 KiB is read.
#[tokio::test(flavor = "multi_thread")]
async fn cosmos_oversized_answer_is_refused() {
    let good = node();
    let g = up(&good).await;
    let f = node();
    let mut body =
        serde_json::to_vec(&json!({"balance": {"amount": "3"}, "data": {"balance": "3"}})).unwrap();
    body.resize((16 << 20) + 1, b' ');
    f.lock().unwrap().raw = Some(body.clone());
    let u = up(&f).await;
    assert_eq!(code(balances(&[&u], ALICE).await), "EndpointAllFailed");
    assert_eq!(
        balances(&[&u, &g], ALICE).await.unwrap().native.as_deref(),
        Some("2500000")
    );
    body.truncate(1024);
    f.lock().unwrap().raw = Some(body);
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(
        (b.native.as_deref(), amounts(&b)),
        (Some("3"), vec!["3", "3"]),
        "control"
    );
}

/// ARCH-POS-15 failover with two gateways, one down: either order answers; endpoint 0 answers when it is up.
#[tokio::test(flavor = "multi_thread")]
async fn cosmos_two_endpoints_one_down() {
    let (a, b) = (node(), node());
    b.lock().unwrap().native.insert(ALICE.into(), json!("2"));
    let (ua, ub) = (up(&a).await, up(&b).await);
    let r = balances(&[DOWN, &ub], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2"), "the second endpoint");
    let r = balances(&[&ua, DOWN], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"));
    let r = balances(&[&ua, &ub], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"), "endpoint 0 first");
    assert_eq!(
        code(balances(&[DOWN, "http://127.0.0.1:1"], ALICE).await),
        "EndpointAllFailed"
    );
}

/// The params' chain id is the identity: a gateway naming another network in `node_info` is dropped. Control: the right one
/// behind it answers.
#[tokio::test(flavor = "multi_thread")]
async fn cosmos_endpoint_of_another_chain_id_is_dropped() {
    let (other, good) = (node(), node());
    other.lock().unwrap().network = "other-1";
    other
        .lock()
        .unwrap()
        .native
        .insert(ALICE.into(), json!("666"));
    let (uo, ug) = (up(&other).await, up(&good).await);
    assert_eq!(code(balances(&[&uo], ALICE).await), "EndpointAllFailed");
    let r = balances(&[&uo, &ug], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"));
}

async fn majority(urls: &[&str]) -> Result<Balances, SdkError> {
    read(profile(urls, scaas_rpc::Policy::StrictMajority), ALICE).await
}

/// `strict_majority`: the other gateways read the set at endpoint 0's height (their own head further, Alice's balance moved
/// since: the header pins the old state) and a strict majority must agree; one liar of three is outvoted (control), two
/// disagreeing of three is `EndpointNoMajority`, and a gateway of another chain id repeating endpoint 0's answer does not count.
#[tokio::test(flavor = "multi_thread")]
async fn cosmos_strict_majority_agrees_at_one_height() {
    let (a, b, liar, liar2, other) = (node(), node(), node(), node(), node());
    liar.lock()
        .unwrap()
        .native
        .insert(ALICE.into(), json!("666"));
    liar2
        .lock()
        .unwrap()
        .cw
        .insert((VND.into(), ALICE.into()), json!("1"));
    other.lock().unwrap().network = "other-1";
    b.lock().unwrap().height = H + 5;
    b.lock().unwrap().moved = Some((H + 1, json!("999")));
    let (ua, ub, ul, ul2, uo) = (
        up(&a).await,
        up(&b).await,
        up(&liar).await,
        up(&liar2).await,
        up(&other).await,
    );
    let r = majority(&[&ua, &ul, &ub]).await.unwrap();
    assert_eq!((r.block, r.native.as_deref()), (H, Some("2500000")));
    assert_eq!(
        b.lock().unwrap().heights,
        vec![Some(H); 3],
        "endpoint 0's height"
    );
    assert_eq!(
        code(majority(&[&ua, &ul, &ul2]).await),
        "EndpointNoMajority"
    );
    assert_eq!(code(majority(&[&ua, &uo, &ul]).await), "EndpointNoMajority");
    assert_eq!(code(majority(&[&ua, &uo, &ub]).await), "Ok", "control");
}
