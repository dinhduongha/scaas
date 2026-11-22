// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.ton (spec §8.7 TON row; decisions CLI-SDK-15's Change of 2026-11-22, T24.ton): `wallet().balances` on a TON
//! profile, against a fake TON Center (`tests/common/fake_http.rs`, local only) answering in the shapes recorded from the public
//! testnet TON Center on 2026-11-21 (`clients/scaas-rpc/tests/fixtures/ton-v2/`, seqno 99410094): v3's `masterchainInfo` and
//! `blocks` (the head and a block's root hash), v2's `getAddressInformation` and `runGetMethod` with `seqno`. The recorded
//! jetton master, its owner and that owner's wallet are the first token's; their getters answer with the recorded stacks. Every
//! refusal beside its control.
#![cfg(feature = "ton")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_http.rs"]
mod fake_http;

use base64::Engine as _;
use fake_http::{serve, DOWN};
use scaas_rpc::boc;
use scaas_sdk::vault::MemoryStore;
use scaas_sdk::wallet::Balances;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, ListedToken, RuntimeChoice, Sdk,
    SdkConfig, SdkError,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const H: u64 = 99_410_094;
/// the recorded testnet jetton master, an owner and that owner's wallet (`get_wallet_address`), active, holding 0x65
const MASTER: &str = "0:4408958692A3C22D3BA0A881503CAFECE8D53E9DFCE42C6D26C5D8AEDA1742C7";
const OWNER: &str = "0:07CB92CC48939C2B257052341FDA2574085F952DAE424BC8C9E1BACFEC182B3B";
const WALLET: &str = "0:0000018DF410923C4A46BB31F7D66F99C099B806D44943F57C57BBE3E83600CF";

fn hex32(b: &str) -> String {
    b.repeat(32)
}
fn master2() -> String {
    format!("0:{}", hex32("a2"))
}
/// a masterchain holder
fn bob() -> String {
    format!("-1:{}", hex32("b0"))
}

fn fixture(name: &str) -> Value {
    let s = match name {
        "address" => {
            include_str!("../../scaas-rpc/tests/fixtures/ton-v2/run_get_wallet_address.json")
        }
        "data" => include_str!("../../scaas-rpc/tests/fixtures/ton-v2/run_get_wallet_data.json"),
        "uninit" => include_str!("../../scaas-rpc/tests/fixtures/ton-v2/run_get_uninit.json"),
        "account" => {
            include_str!("../../scaas-rpc/tests/fixtures/ton-v2/address_information_active.json")
        }
        _ => unreachable!(),
    };
    serde_json::from_str(s).unwrap()
}

fn key(a: &str) -> String {
    a.to_ascii_lowercase()
}

/// A stack cell holding `a`'s `addr_std`.
fn cell(a: &str) -> Value {
    let (wc, h) = scaas_rpc::ton::raw_address(a).unwrap();
    json!(["cell", {"bytes": base64::engine::general_purpose::STANDARD.encode(boc::address_slice(wc, &h))}])
}

/// One fake TON Center's state.
#[derive(Clone)]
struct Node {
    head: u64,
    /// masterchain block `n`'s root hash is `{fork}{n}`: another network has another fork
    fork: &'static str,
    /// accounts by raw address (lowercase): (balance, state); unknown: ("0", "uninitialized")
    accounts: HashMap<String, (String, String)>,
    /// `get_wallet_address(owner)` of a master: (master, owner) → the answer's stack
    wallets: HashMap<(String, String), Vec<Value>>,
    /// `get_wallet_data` of a wallet: its stack
    data: HashMap<String, Vec<Value>>,
    /// one getter's exit code instead of 0: (method, code)
    exit: Option<(&'static str, i64)>,
    /// the holder's balance from this seqno on (the chain moved after the set's block)
    moved: Option<(u64, String)>,
    /// every v2 answer's `block_id.seqno`, instead of the asked one
    block: Option<u64>,
    /// `masterchainInfo`'s answer, instead of the state's
    info: Option<Value>,
    /// every `get_wallet_address` answer's body, instead of the state's
    raw: Option<Vec<u8>>,
    /// every v2 read: (path's method, the asked seqno)
    reads: Vec<(String, u64)>,
}

type Fake = Arc<Mutex<Node>>;
/// One change to a fake's state.
type Change = Box<dyn Fn(&mut Node)>;

fn node() -> Fake {
    let mut n = Node {
        head: H,
        fork: "rh",
        accounts: HashMap::new(),
        wallets: HashMap::new(),
        data: HashMap::new(),
        exit: None,
        moved: None,
        block: None,
        info: None,
        raw: None,
        reads: vec![],
    };
    let active = |b: &str| (b.to_string(), "active".to_string());
    n.accounts.insert(key(OWNER), active("2500000000"));
    n.accounts.insert(key(&bob()), active("7"));
    n.accounts.insert(key(WALLET), active("10000000"));
    let rec = |name: &str| fixture(name)["result"]["stack"].as_array().unwrap().clone();
    n.wallets.insert((key(MASTER), key(OWNER)), rec("address"));
    n.data.insert(key(WALLET), rec("data"));
    // the owner's wallet of the second master is not initialized: 0
    let w2 = format!("0:{}", hex32("c2"));
    n.wallets
        .insert((key(&master2()), key(OWNER)), vec![cell(&w2)]);
    // Bob's two wallets, active
    let code = rec("data")[3].clone();
    for (m, w, b) in [(MASTER.to_string(), "d1", "0x7"), (master2(), "d2", "0x5")] {
        let w = format!("0:{}", hex32(w));
        n.wallets.insert((key(&m), key(&bob())), vec![cell(&w)]);
        n.accounts.insert(key(&w), active("1"));
        n.data.insert(
            key(&w),
            vec![json!(["num", b]), cell(&bob()), cell(&m), code.clone()],
        );
    }
    Arc::new(Mutex::new(n))
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap())
}

fn answer(n: &mut Node, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
    if path.starts_with("/api/v3/masterchainInfo") {
        let v = n.info.clone().unwrap_or_else(
            || json!({"last": {"seqno": n.head, "root_hash": format!("{}{}", n.fork, n.head)}}),
        );
        return ok(v);
    }
    if let Some(s) = path
        .strip_prefix("/api/v3/blocks?")
        .and_then(|q| q.split("seqno=").nth(1))
    {
        return ok(json!({"blocks": [{"root_hash": format!("{}{s}", n.fork)}]}));
    }
    if let Some(q) = path.strip_prefix("/api/v2/getAddressInformation?") {
        let q = q.replace("%3A", ":");
        let field = |k: &str| {
            q.split('&')
                .find_map(|p| p.strip_prefix(&format!("{k}=")))
                .unwrap()
                .to_string()
        };
        let (a, s) = (field("address"), field("seqno").parse::<u64>().unwrap());
        n.reads.push(("account".into(), s));
        let (mut b, state) = n
            .accounts
            .get(&a)
            .cloned()
            .unwrap_or(("0".into(), "uninitialized".into()));
        if let Some((from, x)) = &n.moved {
            if a == key(OWNER) && s >= *from {
                b = x.clone();
            }
        }
        let mut v = fixture("account");
        v["result"]["balance"] = json!(b);
        v["result"]["state"] = json!(state);
        v["result"]["block_id"]["seqno"] = json!(n.block.unwrap_or(s));
        return ok(v);
    }
    if path == "/api/v2/runGetMethod" {
        let r: Value = serde_json::from_slice(body).unwrap();
        let (a, m, s) = (
            key(r["address"].as_str().unwrap()),
            r["method"].as_str().unwrap().to_string(),
            r["seqno"].as_u64().unwrap(),
        );
        n.reads.push((m.clone(), s));
        if let (Some(raw), "get_wallet_address") = (&n.raw, m.as_str()) {
            return (200, raw.clone());
        }
        let stack = match m.as_str() {
            "get_wallet_address" => {
                let b = base64::engine::general_purpose::STANDARD
                    .decode(r["stack"][0][1].as_str().unwrap())
                    .unwrap();
                let owner =
                    scaas_rpc::ton::format_raw(boc::std_address(&boc::parse(&b).unwrap()).unwrap());
                n.wallets.get(&(a, owner)).cloned()
            }
            "get_wallet_data" => n.data.get(&a).cloned(),
            _ => None,
        };
        let mut v = match stack {
            Some(st) => {
                let mut v = fixture("address");
                v["result"]["stack"] = json!(st);
                v
            }
            // recorded: a getter of an account without that method's code
            None => fixture("uninit"),
        };
        if let Some((em, code)) = n.exit {
            if em == m {
                v["result"]["exit_code"] = json!(code);
            }
        }
        v["result"]["block_id"]["seqno"] = json!(n.block.unwrap_or(s));
        return ok(v);
    }
    (404, b"not found".to_vec())
}

async fn up(f: &Fake) -> String {
    let f = f.clone();
    serve(Arc::new(move |_, path: &str, body: &[u8]| {
        answer(&mut f.lock().unwrap(), path, body)
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
        key: "ton-testnet".into(),
        family: Family::Ton,
        chain_id: None,
        chain_uid: format!("0x{}", hex32("03")),
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
        tokens: vec![token(MASTER, "USDT", 6), token(&master2(), "VND", 0)],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: None,
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
        .balances(id.into(), "ton-testnet".into())
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

/// The positive control: the holder's nanoton and each listed jetton's balance (the master's `get_wallet_address`, that
/// wallet's state and its `get_wallet_data`, the recorded answers for the first), every read at the answering endpoint's last
/// masterchain seqno, which is `block`; the tokens as the profile lists them. The holder's wallet of the second master is not
/// initialized: 0 without asking it. A masterchain holder (workchain -1) reads alike.
#[tokio::test(flavor = "multi_thread")]
async fn ton_balances_at_one_masterchain_block() {
    let f = node();
    let u = up(&f).await;
    let b = balances(&[&u], OWNER).await.unwrap();
    assert_eq!(b.block, H);
    assert_eq!(b.native.as_deref(), Some("2500000000"));
    assert_eq!(amounts(&b), ["101", "0"]);
    assert_eq!(
        (
            b.tokens[1].address.as_str(),
            b.tokens[1].display.as_str(),
            b.tokens[1].decimals
        ),
        (master2().as_str(), "VND", 0)
    );
    let reads: Vec<(String, u64)> = [
        "account",
        "get_wallet_address",
        "account",
        "get_wallet_data",
        "get_wallet_address",
        "account",
    ]
    .iter()
    .map(|m| (m.to_string(), H))
    .collect();
    assert_eq!(
        f.lock().unwrap().reads,
        reads,
        "every read pinned at the head"
    );
    let b = balances(&[&u], &bob()).await.unwrap();
    assert_eq!(
        (b.native.as_deref(), amounts(&b)),
        (Some("7"), vec!["7", "5"])
    );
}

/// The holder and the tokens in TON's raw form (`wc:hex`, workchain 0 or -1; TON has no UA ledger): a `0x` id, workchain 1,
/// 63 hex digits, the user-friendly base64 form: `Argument`, nothing read; a token out of form likewise. Control: the
/// uppercase and lowercase raw forms read.
#[tokio::test(flavor = "multi_thread")]
async fn ton_holder_and_token_forms() {
    let f = node();
    let u = up(&f).await;
    for id in [
        format!("0x{}", &OWNER[2..]),
        OWNER.replacen("0:", "1:", 1),
        OWNER[..65].to_string(),
        "EQAHy5LMSJOcKyVwUjQf2iV0CF-VLa5CS8jJ4brP7BgrO2Tn".to_string(),
    ] {
        assert_eq!(code(balances(&[&u], &id).await), "Argument", "{id}");
    }
    assert!(f.lock().unwrap().reads.is_empty(), "nothing read");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.push(token("0x01", "X", 0));
    assert_eq!(
        code(read(p, OWNER).await),
        "Argument",
        "a token not of the form"
    );
    assert!(f.lock().unwrap().reads.is_empty(), "nothing read");
    assert_eq!(
        code(balances(&[&u], &OWNER.to_ascii_lowercase()).await),
        "Ok",
        "control"
    );
    assert_eq!(code(balances(&[&u], OWNER).await), "Ok", "control");
}

/// One change each from the control: the holder's balance above 2^256 - 1, a listed master whose `get_wallet_address` fails,
/// a wallet address that is no `addr_std`, a wallet frozen, `get_wallet_data` failing, a wallet of another owner or another
/// master, a jetton balance that is negative or a cell, an answer of another block, `masterchainInfo` without its root hash:
/// the endpoint's `AnswerMalformed` (alone `EndpointAllFailed`; behind it a good endpoint answers). Controls: exit code 1
/// (TVM's other success) is read, and 2^256 - 1 is.
#[tokio::test(flavor = "multi_thread")]
async fn ton_malformed_answers_are_refused() {
    let good = node();
    let g = up(&good).await;
    let w = key(WALLET);
    let bad_state: Vec<(&str, Change)> = vec![
        (
            "a balance above 2^256 - 1",
            Box::new(|n| {
                n.accounts
                    .insert(key(OWNER), ("9".repeat(78), "active".into()));
            }),
        ),
        (
            "get_wallet_address fails",
            Box::new(|n| n.exit = Some(("get_wallet_address", 11))),
        ),
        ("a wallet address that is a number", {
            Box::new(|n| {
                n.wallets
                    .insert((key(MASTER), key(OWNER)), vec![json!(["num", "0x1"])]);
            })
        }),
        ("a wallet address that is a code cell", {
            let code = fixture("data")["result"]["stack"][3].clone();
            Box::new(move |n| {
                n.wallets
                    .insert((key(MASTER), key(OWNER)), vec![code.clone()]);
            })
        }),
        ("a frozen wallet", {
            let w = w.clone();
            Box::new(move |n| {
                n.accounts.insert(w.clone(), ("1".into(), "frozen".into()));
            })
        }),
        (
            "get_wallet_data fails",
            Box::new(|n| n.exit = Some(("get_wallet_data", 11))),
        ),
        ("another owner", {
            let w = w.clone();
            Box::new(move |n| {
                n.data.get_mut(&w).unwrap()[1] = cell(&bob());
            })
        }),
        ("another master", {
            let w = w.clone();
            Box::new(move |n| {
                n.data.get_mut(&w).unwrap()[2] = cell(&master2());
            })
        }),
        ("a negative jetton balance", {
            let w = w.clone();
            Box::new(move |n| {
                n.data.get_mut(&w).unwrap()[0] = json!(["num", "-0x1"]);
            })
        }),
        ("a jetton balance that is a cell", {
            let w = w.clone();
            Box::new(move |n| {
                n.data.get_mut(&w).unwrap()[0] = cell(OWNER);
            })
        }),
        ("another block", Box::new(|n| n.block = Some(H - 1))),
    ];
    for (why, change) in bad_state {
        let f = node();
        change(&mut f.lock().unwrap());
        let u = up(&f).await;
        assert_eq!(
            code(balances(&[&u], OWNER).await),
            "EndpointAllFailed",
            "{why}"
        );
        let b = balances(&[&u, &g], OWNER).await.unwrap();
        assert_eq!(
            (b.native.as_deref(), amounts(&b)),
            (Some("2500000000"), vec!["101", "0"]),
            "the second endpoint's ({why})"
        );
    }
    let f = node();
    f.lock().unwrap().info = Some(json!({"last": {"seqno": H}}));
    let u = up(&f).await;
    assert_eq!(
        code(balances(&[&u], OWNER).await),
        "EndpointAllFailed",
        "no root hash"
    );
    for m in ["get_wallet_address", "get_wallet_data"] {
        let f = node();
        f.lock().unwrap().exit = Some((m, 1));
        let u = up(&f).await;
        let b = balances(&[&u], OWNER).await.unwrap();
        assert_eq!(amounts(&b), ["101", "0"], "control: exit code 1 of {m}");
    }
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let f = node();
    f.lock()
        .unwrap()
        .accounts
        .insert(key(OWNER), (max.into(), "active".into()));
    let u = up(&f).await;
    assert_eq!(
        balances(&[&u], OWNER).await.unwrap().native.as_deref(),
        Some(max),
        "control"
    );
}

/// An answer above the family client's bound (16 MiB) is the endpoint's failure; behind it a good endpoint answers. Control:
/// the same recorded `get_wallet_address` answer padded to 1 KiB is read.
#[tokio::test(flavor = "multi_thread")]
async fn ton_oversized_answer_is_refused() {
    let good = node();
    let g = up(&good).await;
    let f = node();
    let mut body = serde_json::to_vec(&fixture("address")).unwrap();
    assert!(body.len() < 1024);
    body.resize((16 << 20) + 1, b' ');
    f.lock().unwrap().raw = Some(body.clone());
    let u = up(&f).await;
    let one = |u: &[&str]| {
        let mut p = profile(u, scaas_rpc::Policy::Failover);
        p.tokens.truncate(1);
        p
    };
    assert_eq!(code(read(one(&[&u]), OWNER).await), "EndpointAllFailed");
    let b = read(one(&[&u, &g]), OWNER).await.unwrap();
    assert_eq!(amounts(&b), ["101"], "the second endpoint's");
    body.truncate(1024);
    f.lock().unwrap().raw = Some(body);
    let b = read(one(&[&u]), OWNER).await.unwrap();
    assert_eq!(amounts(&b), ["101"], "control");
}

/// ARCH-POS-15 failover with two TON Centers, one down: endpoint 0 down, the second has no identity reference (endpoint 0's
/// block) and is not read; endpoint 0 answers when it is up; endpoint 0 naming its block and then failing the set, the second
/// answers.
#[tokio::test(flavor = "multi_thread")]
async fn ton_two_endpoints_one_down() {
    let (a, b) = (node(), node());
    b.lock()
        .unwrap()
        .accounts
        .insert(key(OWNER), ("2".into(), "active".into()));
    let (ua, ub) = (up(&a).await, up(&b).await);
    // endpoint 0 down: no block of it names the network, so the second is not identified (fail closed)
    assert_eq!(
        code(balances(&[DOWN, &ub], OWNER).await),
        "EndpointAllFailed"
    );
    assert!(
        b.lock().unwrap().reads.is_empty(),
        "nothing read unidentified"
    );
    let r = balances(&[&ua, DOWN], OWNER).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"));
    let r = balances(&[&ua, &ub], OWNER).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"), "endpoint 0 first");
    // endpoint 0 names its block, then fails the set: the second, of the same network, answers
    a.lock().unwrap().block = Some(H - 1);
    let r = balances(&[&ua, &ub], OWNER).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2"), "the second endpoint");
}

/// Endpoint 0 is this network by the profile constant; a later TON Center whose masterchain block at endpoint 0's seqno has
/// another root hash is another network, dropped, nothing read from it. Control: one of the same network behind it answers.
#[tokio::test(flavor = "multi_thread")]
async fn ton_endpoint_of_another_network_is_dropped() {
    let (first, other, good) = (node(), node(), node());
    // endpoint 0 names its block, then fails every set read
    first.lock().unwrap().block = Some(H - 1);
    other.lock().unwrap().fork = "mainnet";
    other
        .lock()
        .unwrap()
        .accounts
        .insert(key(OWNER), ("666".into(), "active".into()));
    let (uf, uo, ug) = (up(&first).await, up(&other).await, up(&good).await);
    assert_eq!(
        code(balances(&[&uf, &uo], OWNER).await),
        "EndpointAllFailed"
    );
    let r = balances(&[&uf, &uo, &ug], OWNER).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2500000000"));
    assert!(
        other.lock().unwrap().reads.is_empty(),
        "nothing read from another network"
    );
}

async fn majority(urls: &[&str]) -> Result<Balances, SdkError> {
    read(profile(urls, scaas_rpc::Policy::StrictMajority), OWNER).await
}

/// `strict_majority`: the other TON Centers read the set at endpoint 0's seqno (their own head further, the holder's balance
/// moved since: the seqno pins the old state) and a strict majority must agree; one liar of three is outvoted (control), two
/// disagreeing of three is `EndpointNoMajority`, and a TON Center of another network repeating endpoint 0's answer does not
/// count.
#[tokio::test(flavor = "multi_thread")]
async fn ton_strict_majority_agrees_at_one_block() {
    let (a, b, liar, liar2, other) = (node(), node(), node(), node(), node());
    liar.lock()
        .unwrap()
        .accounts
        .insert(key(OWNER), ("666".into(), "active".into()));
    liar2.lock().unwrap().data.get_mut(&key(WALLET)).unwrap()[0] = json!(["num", "0x66"]);
    other.lock().unwrap().fork = "mainnet";
    b.lock().unwrap().head = H + 5;
    b.lock().unwrap().moved = Some((H + 1, "999".into()));
    let (ua, ub, ul, ul2, uo) = (
        up(&a).await,
        up(&b).await,
        up(&liar).await,
        up(&liar2).await,
        up(&other).await,
    );
    let r = majority(&[&ua, &ul, &ub]).await.unwrap();
    assert_eq!((r.block, r.native.as_deref()), (H, Some("2500000000")));
    assert!(
        b.lock().unwrap().reads.iter().all(|(_, s)| *s == H),
        "endpoint 0's seqno"
    );
    assert_eq!(
        code(majority(&[&ua, &ul, &ul2]).await),
        "EndpointNoMajority"
    );
    assert_eq!(code(majority(&[&ua, &uo, &ul]).await), "EndpointNoMajority");
    assert!(
        other.lock().unwrap().reads.is_empty(),
        "nothing read from another network"
    );
    assert_eq!(
        code(majority(&[&ua, &uo, &ub]).await),
        "Ok",
        "control: two of three"
    );
}
