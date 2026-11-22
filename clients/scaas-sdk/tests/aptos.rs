// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.aptos (spec §8.7; decisions CLI-SDK-15's Changes of 2026-11-21): `wallet().balances` on an Aptos profile, against
//! a fake Aptos REST (`tests/common/fake_http.rs`, local only) answering in the fullnode's shapes (ledger info, `POST /view`
//! at `?ledger_version=`), each view answered from the state at the version it names. Every refusal beside its control.
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

const UID: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
const CHAIN: u8 = 4;
fn a(b: &str) -> String {
    format!("0x{}", b.repeat(32))
}
const V: u64 = 90_000;
const HEIGHT: u64 = 3_000;

#[derive(Clone)]
struct Node {
    chain: u8,
    version: u64,
    /// the holder's APT by address (unknown: "0")
    native: HashMap<String, Value>,
    /// an FA balance by (account, metadata) (unknown: "0")
    fa: HashMap<(String, String), Value>,
    /// Alice's native amount from this version on
    moved: Option<(u64, Value)>,
    /// every view answer's body, instead of the state's
    raw: Option<Vec<u8>>,
    /// the versions the views named
    versions: Vec<Option<u64>>,
}

type Fake = Arc<Mutex<Node>>;

fn alice() -> String {
    a("a7")
}
fn bob() -> String {
    a("09")
}
fn pkg() -> String {
    a("5c")
}
fn usdc() -> String {
    a("01")
}
fn vnd() -> String {
    a("02")
}
/// `meta::account_of`: the fake's derivation (the SDK reads it, never derives it)
fn account_of(owner: &str) -> String {
    format!("0xacc{}", &owner[5..])
}

fn node() -> Fake {
    let mut n = Node {
        chain: CHAIN,
        version: V,
        native: HashMap::new(),
        fa: HashMap::new(),
        moved: None,
        raw: None,
        versions: vec![],
    };
    n.native.insert(alice(), json!("2500000"));
    n.fa.insert((account_of(&alice()), usdc()), json!("5000000"));
    n.fa.insert((account_of(&alice()), vnd()), json!("1000"));
    Arc::new(Mutex::new(n))
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap())
}

fn answer(n: &mut Node, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    let (p, q) = path.split_once('?').unwrap_or((path, ""));
    match (method, p) {
        ("GET", "/v1") => ok(json!({
            "chain_id": n.chain,
            "block_height": HEIGHT.to_string(),
            "ledger_version": n.version.to_string(),
        })),
        ("POST", "/v1/view") => {
            let at = q
                .strip_prefix("ledger_version=")
                .map(|v| v.parse::<u64>().unwrap());
            n.versions.push(at);
            if let Some(r) = &n.raw {
                return (200, r.clone());
            }
            let r: Value = serde_json::from_slice(body).unwrap();
            let f = r["function"].as_str().unwrap();
            let args: Vec<String> = r["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_string())
                .collect();
            let v = at.unwrap_or(n.version);
            if f == "0x1::coin::balance" {
                assert_eq!(r["type_arguments"], json!(["0x1::aptos_coin::AptosCoin"]));
                let amount = match &n.moved {
                    Some((from, x)) if args[0] == alice() && v >= *from => x.clone(),
                    _ => n.native.get(&args[0]).cloned().unwrap_or(json!("0")),
                };
                ok(json!([amount]))
            } else if f == format!("{}::meta::account_of", pkg()) {
                ok(json!([account_of(&args[0])]))
            } else if f == "0x1::primary_fungible_store::balance" {
                assert_eq!(
                    r["type_arguments"],
                    json!(["0x1::fungible_asset::Metadata"])
                );
                let b =
                    n.fa.get(&(args[0].clone(), args[1].clone()))
                        .cloned()
                        .unwrap_or(json!("0"));
                ok(json!([b]))
            } else {
                (
                    400,
                    br#"{"message":"no such function","error_code":"invalid_input"}"#.to_vec(),
                )
            }
        }
        _ => (
            404,
            br#"{"message":"not found","error_code":"resource_not_found"}"#.to_vec(),
        ),
    }
}

async fn up(f: &Fake) -> String {
    let f = f.clone();
    let u = serve(Arc::new(move |m: &str, path: &str, body: &[u8]| {
        answer(&mut f.lock().unwrap(), m, path, body)
    }))
    .await
    .0;
    format!("{u}/v1")
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
        key: "aptos-testnet".into(),
        family: Family::Aptos,
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
        tokens: vec![token(&usdc(), "USDC", 6), token(&vnd(), "VND", 0)],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: Some(FamilyParams::Aptos {
            chain_id: CHAIN,
            package: pkg(),
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
        .balances(id.into(), "aptos-testnet".into())
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

/// The positive control: the holder's APT and each FA's balance in the Account `meta::account_of` names, every view at
/// ledger info's `ledger_version`, which is `block`; an owner the chain does not know reads "0" everywhere (the views' own
/// answer).
#[tokio::test(flavor = "multi_thread")]
async fn aptos_balances_at_one_version() {
    let f = node();
    let u = up(&f).await;
    let b = balances(&[&u], &alice()).await.unwrap();
    assert_eq!(b.block, V);
    assert_eq!(b.native.as_deref(), Some("2500000"));
    assert_eq!(amounts(&b), ["5000000", "1000"]);
    assert_eq!(
        (
            b.tokens[0].address.as_str(),
            b.tokens[0].display.as_str(),
            b.tokens[0].decimals
        ),
        (usdc().as_str(), "USDC", 6)
    );
    assert_eq!(
        f.lock().unwrap().versions,
        vec![Some(V); 4],
        "every view pinned"
    );
    let b = balances(&[&u], &bob()).await.unwrap();
    assert_eq!(
        (b.native.as_deref(), amounts(&b)),
        (Some("0"), vec!["0", "0"])
    );
}

/// The holder and the token ids in the long form (`0x` + 64 lowercase hex): a short form, uppercase hex, no `0x`, 63 or 65
/// digits, a token not of the form: `Argument`, nothing read. Params of another family, an Aptos profile without params, a
/// chain id 0, a package out of form: `Argument`. Control: the right forms read.
#[tokio::test(flavor = "multi_thread")]
async fn aptos_holder_and_token_forms() {
    let f = node();
    let u = up(&f).await;
    let al = alice();
    for id in [
        "0x7".to_string(),
        al.to_uppercase().replacen("0X", "0x", 1),
        al[2..].to_string(),
        al[..65].to_string(),
        format!("{al}0"),
    ] {
        assert_eq!(code(balances(&[&u], &id).await), "Argument", "{id}");
    }
    assert!(f.lock().unwrap().versions.is_empty(), "nothing read");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.push(token("0xa", "APT", 8));
    assert_eq!(
        code(read(p, &al).await),
        "Argument",
        "a token not of the form"
    );
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family = Family::Sui;
    assert_eq!(code(open(p).await), "Argument", "params of another family");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family_params = None;
    assert_eq!(code(read(p, &al).await), "Argument", "no params");
    for (chain_id, package) in [
        (0, pkg()),
        (CHAIN, "0x5c".to_string()),
        (CHAIN, pkg().to_uppercase()),
    ] {
        let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
        p.family_params = Some(FamilyParams::Aptos {
            chain_id,
            package: package.clone(),
        });
        assert_eq!(code(open(p).await), "Argument", "{chain_id} {package}");
    }
    assert_eq!(code(balances(&[&u], &al).await), "Ok", "control");
}

/// A view answer that is not one decimal string of at most 78 digits within a U256 (a number, a float, a sign, 79 digits,
/// above 2^256 - 1, two values, not an array) is the endpoint's `AnswerMalformed`: alone it fails the read; behind it a good
/// endpoint answers. Control: 2^256 - 1 is read.
#[tokio::test(flavor = "multi_thread")]
async fn aptos_malformed_answers_are_refused() {
    let good = node();
    let g = up(&good).await;
    let (z79, n78) = ("0".repeat(79), "9".repeat(78));
    for bad in [
        json!(12),
        json!("1.5"),
        json!("-1"),
        json!(""),
        json!(z79),
        json!(n78),
        json!(null),
    ] {
        let f = node();
        f.lock().unwrap().native.insert(alice(), bad.clone());
        let u = up(&f).await;
        assert_eq!(
            code(balances(&[&u], &alice()).await),
            "EndpointAllFailed",
            "{bad}"
        );
        let b = balances(&[&u, &g], &alice()).await.unwrap();
        assert_eq!(
            b.native.as_deref(),
            Some("2500000"),
            "the second endpoint's ({bad})"
        );
    }
    for raw in [&br#"["1","2"]"#[..], br#"{"a":"1"}"#, br#"[]"#] {
        let f = node();
        f.lock().unwrap().raw = Some(raw.to_vec());
        let u = up(&f).await;
        assert_eq!(
            code(balances(&[&u], &alice()).await),
            "EndpointAllFailed",
            "{raw:?}"
        );
    }
    // the native view alone (no token): two values refused, one read (control)
    for (raw, want) in [
        (&br#"["1","2"]"#[..], "EndpointAllFailed"),
        (br#"["1"]"#, "Ok"),
    ] {
        let f = node();
        f.lock().unwrap().raw = Some(raw.to_vec());
        let u = up(&f).await;
        let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
        p.tokens.clear();
        assert_eq!(code(read(p, &alice()).await), want, "{raw:?}");
    }
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let f = node();
    f.lock()
        .unwrap()
        .fa
        .insert((account_of(&alice()), usdc()), json!(max));
    let u = up(&f).await;
    assert_eq!(
        amounts(&balances(&[&u], &alice()).await.unwrap())[0],
        max,
        "control"
    );
}

/// An account `meta::account_of` answers that is no address is the endpoint's `AnswerMalformed`. Control: the fake's.
#[tokio::test(flavor = "multi_thread")]
async fn aptos_account_that_is_no_address_is_refused() {
    let f = node();
    let u = up(&f).await;
    let ff = f.clone();
    let bad = serve(Arc::new(move |m: &str, path: &str, body: &[u8]| {
        let r = answer(&mut ff.lock().unwrap(), m, path, body);
        if String::from_utf8_lossy(body).contains("account_of") {
            return ok(json!(["acc"]));
        }
        r
    }))
    .await
    .0;
    let bad = format!("{bad}/v1");
    assert_eq!(code(balances(&[&bad], &alice()).await), "EndpointAllFailed");
    assert_eq!(code(balances(&[&u], &alice()).await), "Ok", "control");
}

/// An answer above the family client's bound (16 MiB) is the endpoint's failure; behind it a good endpoint answers. Control:
/// the same answer within 1 KiB is read.
#[tokio::test(flavor = "multi_thread")]
async fn aptos_oversized_answer_is_refused() {
    let good = node();
    let g = up(&good).await;
    let f = node();
    let mut body = br#"["3"]"#.to_vec();
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
        Some("2500000")
    );
    body.truncate(1024);
    f.lock().unwrap().raw = Some(body);
    // the account view answers "3" too: not an address, so only the native read of a token-less profile is the control
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.clear();
    assert_eq!(
        read(p, &alice()).await.unwrap().native.as_deref(),
        Some("3"),
        "control"
    );
}

/// ARCH-POS-15 failover with two endpoints, one down: either order answers; endpoint 0 answers when it is up.
#[tokio::test(flavor = "multi_thread")]
async fn aptos_two_endpoints_one_down() {
    let (x, y) = (node(), node());
    y.lock().unwrap().native.insert(alice(), json!("2"));
    let (ux, uy) = (up(&x).await, up(&y).await);
    let r = balances(&[DOWN, &uy], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2"), "the second endpoint");
    let r = balances(&[&ux, DOWN], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"));
    let r = balances(&[&ux, &uy], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"), "endpoint 0 first");
    assert_eq!(
        code(balances(&[DOWN, "http://127.0.0.1:1"], &alice()).await),
        "EndpointAllFailed"
    );
}

/// The params' chain id is the identity: an endpoint naming another chain id is dropped. Control: the right one behind it.
#[tokio::test(flavor = "multi_thread")]
async fn aptos_endpoint_of_another_chain_id_is_dropped() {
    let (other, good) = (node(), node());
    other.lock().unwrap().chain = 2;
    other.lock().unwrap().native.insert(alice(), json!("666"));
    let (uo, ug) = (up(&other).await, up(&good).await);
    assert_eq!(code(balances(&[&uo], &alice()).await), "EndpointAllFailed");
    let r = balances(&[&uo, &ug], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"));
}

async fn majority(urls: &[&str]) -> Result<Balances, SdkError> {
    read(profile(urls, scaas_rpc::Policy::StrictMajority), &alice()).await
}

/// `strict_majority`: the other endpoints read the set at endpoint 0's version (their own further, Alice's balance moved
/// since: the version pins the old state) and a strict majority must agree; one liar of three is outvoted (control), two
/// disagreeing of three is `EndpointNoMajority`, and an endpoint of another chain id repeating the answer does not count.
#[tokio::test(flavor = "multi_thread")]
async fn aptos_strict_majority_agrees_at_one_version() {
    let (x, y, liar, liar2, other) = (node(), node(), node(), node(), node());
    liar.lock().unwrap().native.insert(alice(), json!("666"));
    liar2
        .lock()
        .unwrap()
        .fa
        .insert((account_of(&alice()), vnd()), json!("1"));
    other.lock().unwrap().chain = 2;
    y.lock().unwrap().version = V + 5;
    y.lock().unwrap().moved = Some((V + 1, json!("999")));
    let (ux, uy, ul, ul2, uo) = (
        up(&x).await,
        up(&y).await,
        up(&liar).await,
        up(&liar2).await,
        up(&other).await,
    );
    let r = majority(&[&ux, &ul, &uy]).await.unwrap();
    assert_eq!((r.block, r.native.as_deref()), (V, Some("2500000")));
    assert_eq!(
        y.lock().unwrap().versions,
        vec![Some(V); 4],
        "endpoint 0's version"
    );
    assert_eq!(
        code(majority(&[&ux, &ul, &ul2]).await),
        "EndpointNoMajority"
    );
    assert_eq!(code(majority(&[&ux, &uo, &ul]).await), "EndpointNoMajority");
    assert_eq!(code(majority(&[&ux, &uo, &uy]).await), "Ok", "control");
}

/// The failover's floor is ledger info's `block_height`, not the pinned version: after endpoint 0 answered, a second read
/// fails over to an endpoint at the same height. (The version as the floor would leave it behind.)
#[tokio::test(flavor = "multi_thread")]
async fn aptos_floor_is_the_block_height() {
    let (x, y) = (node(), node());
    y.lock().unwrap().native.insert(alice(), json!("2"));
    let (ux, uy) = (up(&x).await, up(&y).await);
    let sdk = open(profile(&[&ux, &uy], scaas_rpc::Policy::Failover))
        .await
        .unwrap();
    let r = sdk
        .wallet()
        .balances(alice(), "aptos-testnet".into())
        .await
        .unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000"));
    // endpoint 0 now answers no view
    x.lock().unwrap().raw = Some(b"[1]".to_vec());
    let r = sdk
        .wallet()
        .balances(alice(), "aptos-testnet".into())
        .await
        .unwrap();
    assert_eq!(
        r.native.as_deref(),
        Some("2"),
        "the second endpoint, not behind"
    );
}
