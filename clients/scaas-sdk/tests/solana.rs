// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.solana (spec §8.7; decisions CLI-SDK-15's Changes of 2026-11-21): `wallet().balances` on a Solana profile, against
//! a fake JSON-RPC endpoint (`tests/common/fake_http.rs`, local only) answering in Solana's shapes: `getGenesisHash`, `getSlot`
//! and one batch per read set of `getBalance` and `getTokenAccountsByOwner(pda, {mint}, jsonParsed)` at `finalized`, every
//! answer naming its context slot. The Account's address is `ua-rs`'s `["acct", owner]` PDA under the params' program. Every
//! refusal beside its control.
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

/// the cluster's genesis hash: 0x11 × 32 (`chain_uid`), base58 on the wire
const UID: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const SLOT: u64 = 9_000;
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN22: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn b58(b: [u8; 32]) -> String {
    bs58::encode(b).into_string()
}
fn genesis() -> String {
    b58([0x11; 32])
}
fn program() -> [u8; 32] {
    [0x5c; 32]
}
fn alice() -> String {
    b58([0x07; 32])
}
fn bob() -> String {
    b58([0x09; 32])
}
fn usdc() -> String {
    b58([0x01; 32])
}
fn vnd() -> String {
    b58([0x02; 32])
}
/// the owner's SCaaS Account, as ua-rs derives it (the vectors pin it against clientkeys and the node)
fn pda(owner: &str) -> String {
    let o: [u8; 32] = bs58::decode(owner).into_vec().unwrap().try_into().unwrap();
    b58(scaas_ua::families::solana::account_of(&program(), &o).unwrap())
}

/// A token account in `getTokenAccountsByOwner`'s jsonParsed shape.
fn acct(mint: &str, owner: &str, amount: Value, prog: &str) -> Value {
    json!({"pubkey": b58([0xee; 32]), "account": {"owner": prog, "lamports": 2039280, "executable": false,
        "data": {"program": "spl-token", "space": 165, "parsed": {"type": "account", "info": {
            "mint": mint, "owner": owner, "state": "initialized",
            "tokenAmount": {"amount": amount, "decimals": 6, "uiAmountString": "x"}}}}}})
}

/// One fake endpoint's state.
#[derive(Clone)]
struct Node {
    genesis: String,
    slot: u64,
    /// the slot named by the token answers from this call on (a set whose answers name two slots)
    split: Option<u64>,
    lamports: HashMap<String, Value>,
    /// the token accounts by (owner, mint)
    tokens: HashMap<(String, String), Vec<Value>>,
    /// every batch answer's body, instead of the state's
    raw: Option<Vec<u8>>,
    /// each batch's calls: (method, minContextSlot)
    seen: Vec<Vec<(String, Option<u64>)>>,
}

type Fake = Arc<Mutex<Node>>;

fn node() -> Fake {
    let mut n = Node {
        genesis: genesis(),
        slot: SLOT,
        split: None,
        lamports: HashMap::new(),
        tokens: HashMap::new(),
        raw: None,
        seen: vec![],
    };
    n.lamports.insert(alice(), json!(2_500_000_000u64));
    n.tokens.insert(
        (pda(&alice()), usdc()),
        vec![
            acct(&usdc(), &pda(&alice()), json!("4000000"), TOKEN),
            acct(&usdc(), &pda(&alice()), json!("1000000"), TOKEN),
        ],
    );
    n.tokens.insert(
        (pda(&alice()), vnd()),
        vec![acct(&vnd(), &pda(&alice()), json!("1000"), TOKEN22)],
    );
    Arc::new(Mutex::new(n))
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap())
}

fn one(n: &mut Node, c: &Value, k: usize) -> Value {
    let p = &c["params"];
    let cfg = p.as_array().unwrap().last().unwrap();
    assert_eq!(cfg["commitment"], "finalized");
    let min = cfg["minContextSlot"].as_u64();
    let slot = match (n.split, k) {
        (Some(s), k) if k > 0 => s,
        _ => n.slot.max(min.unwrap_or(0)),
    };
    let result = match c["method"].as_str().unwrap() {
        "getBalance" => {
            let v = n.lamports.get(p[0].as_str().unwrap()).cloned().unwrap_or(json!(0));
            json!({"context": {"slot": slot}, "value": v})
        }
        "getTokenAccountsByOwner" => {
            assert_eq!(cfg["encoding"], "jsonParsed");
            let key = (p[0].as_str().unwrap().to_string(), p[1]["mint"].as_str().unwrap().to_string());
            json!({"context": {"slot": slot}, "value": n.tokens.get(&key).cloned().unwrap_or_default()})
        }
        m => panic!("{m}"),
    };
    json!({"jsonrpc": "2.0", "id": c["id"], "result": result})
}

fn answer(n: &mut Node, body: &[u8]) -> (u16, Vec<u8>) {
    let r: Value = serde_json::from_slice(body).unwrap();
    if let Some(calls) = r.as_array() {
        n.seen.push(
            calls
                .iter()
                .map(|c| {
                    let cfg = c["params"].as_array().unwrap().last().unwrap().clone();
                    (c["method"].as_str().unwrap().to_string(), cfg["minContextSlot"].as_u64())
                })
                .collect(),
        );
        if let Some(raw) = &n.raw {
            return (200, raw.clone());
        }
        let out: Vec<Value> = calls.iter().enumerate().map(|(k, c)| one(n, c, k)).collect();
        if n.split.is_some() {
            // the set's next pass names one slot again
            n.slot = n.split.take().unwrap();
        }
        return ok(Value::Array(out));
    }
    let result = match r["method"].as_str().unwrap() {
        "getGenesisHash" => json!(n.genesis),
        "getSlot" => json!(n.slot + 2),
        m => panic!("{m}"),
    };
    ok(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
}

async fn up(f: &Fake) -> String {
    let f = f.clone();
    serve(Arc::new(move |_m: &str, _path: &str, body: &[u8]| {
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

fn profile(rpc: &[&str], policy: scaas_rpc::Policy) -> ChainProfile {
    ChainProfile {
        key: "solana-devnet".into(),
        family: Family::Solana,
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
        family_params: Some(FamilyParams::Solana {
            program: b58(program()),
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
        .balances(id.into(), "solana-devnet".into())
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

/// The positive control: the holder's lamports and each listed mint's token accounts of its Account PDA summed, in one batch
/// at `finalized`, `block` the slot every answer names; an owner the chain does not know reads "0" everywhere.
#[tokio::test(flavor = "multi_thread")]
async fn solana_balances_at_one_slot() {
    let f = node();
    let u = up(&f).await;
    let b = balances(&[&u], &alice()).await.unwrap();
    assert_eq!(b.block, SLOT);
    assert_eq!(b.native.as_deref(), Some("2500000000"));
    assert_eq!(amounts(&b), ["5000000", "1000"]);
    assert_eq!(
        (b.tokens[0].address.as_str(), b.tokens[0].display.as_str(), b.tokens[0].decimals),
        (usdc().as_str(), "USDC", 6)
    );
    let seen = f.lock().unwrap().seen.clone();
    assert_eq!(seen.len(), 1, "one batch");
    assert_eq!(
        seen[0].iter().map(|(m, _)| m.as_str()).collect::<Vec<_>>(),
        ["getBalance", "getTokenAccountsByOwner", "getTokenAccountsByOwner"]
    );
    let b = balances(&[&u], &bob()).await.unwrap();
    assert_eq!((b.native.as_deref(), amounts(&b)), (Some("0"), vec!["0", "0"]));
}

/// A set whose answers name two slots is read again once at the later slot (`minContextSlot`); a set naming two slots twice
/// is the endpoint's `AnswerMalformed`. Control: the second pass at one slot is read, `block` its slot.
#[tokio::test(flavor = "multi_thread")]
async fn solana_two_slots_read_again_once() {
    let f = node();
    f.lock().unwrap().split = Some(SLOT + 3);
    let u = up(&f).await;
    let b = balances(&[&u], &alice()).await.unwrap();
    assert_eq!(b.block, SLOT + 3);
    let seen = f.lock().unwrap().seen.clone();
    assert_eq!(seen.len(), 2);
    assert!(seen[1].iter().all(|(_, m)| *m == Some(SLOT + 3)), "{seen:?}");
    // two passes at two slots each
    let f = node();
    let u = up(&f).await;
    let ff = f.clone();
    let split = serve(Arc::new(move |_m: &str, _p: &str, body: &[u8]| {
        let mut n = ff.lock().unwrap();
        if serde_json::from_slice::<Value>(body).unwrap().is_array() {
            n.split = Some(n.slot + 1);
        }
        answer(&mut n, body)
    }))
    .await
    .0;
    assert_eq!(code(balances(&[&split], &alice()).await), "EndpointAllFailed");
    assert_eq!(code(balances(&[&u], &alice()).await), "Ok", "control");
}

/// A token account of another mint or another owner, or held by a program that is no token program, is the endpoint's
/// `AnswerMalformed`; a lamports figure that is not a u64 integer, an amount out of the amount rule, a sum above 2^256 - 1, an
/// answer that is not one member per call: the same. Controls beside each.
#[tokio::test(flavor = "multi_thread")]
async fn solana_malformed_answers_are_refused() {
    let good = node();
    let g = up(&good).await;
    let al = alice();
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let bad_rows = [
        acct(&vnd(), &pda(&al), json!("1"), TOKEN),
        acct(&usdc(), &pda(&bob()), json!("1"), TOKEN),
        acct(&usdc(), &pda(&al), json!("1"), &b58([0x33; 32])),
        acct(&usdc(), &pda(&al), json!(1), TOKEN),
        acct(&usdc(), &pda(&al), json!("1.5"), TOKEN),
        acct(&usdc(), &pda(&al), json!(max), TOKEN),
    ];
    for bad in bad_rows {
        let f = node();
        f.lock().unwrap().tokens.get_mut(&(pda(&al), usdc())).unwrap().push(bad.clone());
        let u = up(&f).await;
        assert_eq!(code(balances(&[&u], &al).await), "EndpointAllFailed", "{bad}");
        let b = balances(&[&u, &g], &al).await.unwrap();
        assert_eq!(amounts(&b)[0], "5000000", "the second endpoint's ({bad})");
    }
    for lamports in [json!("5"), json!(1.5), json!(-1), json!(null)] {
        let f = node();
        f.lock().unwrap().lamports.insert(al.clone(), lamports.clone());
        let u = up(&f).await;
        assert_eq!(code(balances(&[&u], &al).await), "EndpointAllFailed", "{lamports}");
    }
    for raw in [&br#"[]"#[..], br#"{"jsonrpc":"2.0","id":0,"result":1}"#] {
        let f = node();
        f.lock().unwrap().raw = Some(raw.to_vec());
        let u = up(&f).await;
        assert_eq!(code(balances(&[&u], &al).await), "EndpointAllFailed", "{raw:?}");
    }
    // controls: one account of 2^256 - 1 alone is read; u64::MAX lamports are read
    let f = node();
    f.lock().unwrap().tokens.insert(
        (pda(&al), usdc()),
        vec![acct(&usdc(), &pda(&al), json!(max), TOKEN)],
    );
    f.lock().unwrap().lamports.insert(al.clone(), json!(u64::MAX));
    let u = up(&f).await;
    let b = balances(&[&u], &al).await.unwrap();
    assert_eq!(
        (amounts(&b)[0], b.native.as_deref().unwrap()),
        (max, u64::MAX.to_string().as_str())
    );
}

/// The holder, each token and the program are base58 of 32 bytes: a `0x` UA id, a key of 31 or 33 bytes, a character out of
/// the alphabet: `Argument`, nothing read. Params of another family, a Solana profile without params, a program out of form:
/// `Argument`. Control: the right forms read.
#[tokio::test(flavor = "multi_thread")]
async fn solana_holder_token_and_program_forms() {
    let f = node();
    let u = up(&f).await;
    let al = alice();
    for id in [
        UID.to_string(),
        bs58::encode([7u8; 31]).into_string(),
        bs58::encode([7u8; 33]).into_string(),
        format!("{}0", &al[..al.len() - 1]),
        String::new(),
    ] {
        assert_eq!(code(balances(&[&u], &id).await), "Argument", "{id}");
    }
    assert!(f.lock().unwrap().seen.is_empty(), "nothing read");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.push(token("0xa", "X", 0));
    assert_eq!(code(read(p, &al).await), "Argument", "a token not of the form");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family = Family::Sui;
    assert_eq!(code(open(p).await), "Argument", "params of another family");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family_params = None;
    assert_eq!(code(read(p, &al).await), "Argument", "no params");
    for program in [bs58::encode([5u8; 31]).into_string(), "0".repeat(32), String::new()] {
        let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
        p.family_params = Some(FamilyParams::Solana { program: program.clone() });
        assert_eq!(code(open(p).await), "Argument", "{program}");
    }
    assert_eq!(code(balances(&[&u], &al).await), "Ok", "control");
}

/// ARCH-POS-15 failover with two endpoints, one down: either order answers; endpoint 0 answers when it is up.
#[tokio::test(flavor = "multi_thread")]
async fn solana_two_endpoints_one_down() {
    let (x, y) = (node(), node());
    y.lock().unwrap().lamports.insert(alice(), json!(2));
    let (ux, uy) = (up(&x).await, up(&y).await);
    let r = balances(&[DOWN, &uy], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2"), "the second endpoint");
    let r = balances(&[&ux, DOWN], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"));
    let r = balances(&[&ux, &uy], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"), "endpoint 0 first");
    assert_eq!(
        code(balances(&[DOWN, "http://127.0.0.1:1"], &alice()).await),
        "EndpointAllFailed"
    );
}

/// The genesis hash is the identity: an endpoint of another cluster is dropped. Control: the right one behind it.
#[tokio::test(flavor = "multi_thread")]
async fn solana_endpoint_of_another_cluster_is_dropped() {
    let (other, good) = (node(), node());
    other.lock().unwrap().genesis = b58([0x22; 32]);
    other.lock().unwrap().lamports.insert(alice(), json!(666));
    let (uo, ug) = (up(&other).await, up(&good).await);
    assert_eq!(code(balances(&[&uo], &alice()).await), "EndpointAllFailed");
    let r = balances(&[&uo, &ug], &alice()).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"));
}

async fn majority(urls: &[&str]) -> Result<Balances, SdkError> {
    read(profile(urls, scaas_rpc::Policy::StrictMajority), &alice()).await
}

/// `strict_majority`: the other endpoints read the set with `minContextSlot` = the answering endpoint's slot (Solana reads no
/// past slot: an endpoint further on answers at its own later slot) and a strict majority must agree on the set; one liar of
/// three is outvoted (control), two disagreeing of three is `EndpointNoMajority`, an endpoint of another cluster repeating
/// the answer does not count. `block` is the answering endpoint's slot.
#[tokio::test(flavor = "multi_thread")]
async fn solana_strict_majority_agrees_on_the_set() {
    let (x, y, liar, liar2, other) = (node(), node(), node(), node(), node());
    liar.lock().unwrap().lamports.insert(alice(), json!(666));
    liar2
        .lock()
        .unwrap()
        .tokens
        .insert((pda(&alice()), vnd()), vec![acct(&vnd(), &pda(&alice()), json!("1"), TOKEN)]);
    other.lock().unwrap().genesis = b58([0x22; 32]);
    y.lock().unwrap().slot = SLOT + 5;
    let (ux, uy, ul, ul2, uo) = (
        up(&x).await,
        up(&y).await,
        up(&liar).await,
        up(&liar2).await,
        up(&other).await,
    );
    let r = majority(&[&ux, &ul, &uy]).await.unwrap();
    assert_eq!((r.block, r.native.as_deref()), (SLOT, Some("2500000000")));
    assert!(
        y.lock().unwrap().seen[0].iter().all(|(_, m)| *m == Some(SLOT)),
        "endpoint 0's slot as the floor"
    );
    assert_eq!(code(majority(&[&ux, &ul, &ul2]).await), "EndpointNoMajority");
    assert_eq!(code(majority(&[&ux, &uo, &ul]).await), "EndpointNoMajority");
    assert_eq!(code(majority(&[&ux, &uo, &uy]).await), "Ok", "control");
}
