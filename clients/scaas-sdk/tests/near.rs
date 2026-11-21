// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.near (spec §8.7; decisions CLI-SDK-15's Change of 2026-11-21): `wallet().balances` on a NEAR profile, against a
//! fake NEAR JSON-RPC endpoint (`tests/common/fake_http.rs`, local only) answering in the shapes of NEAR's RPC (`status`,
//! `block`, `query` `view_account` / `call_function`). Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_http.rs"]
mod fake_http;

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

/// The network's 32 bytes (`chain_uid`) and their base58 form, the `genesis_hash` NEAR's `status` names.
const UID: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
const GENESIS: &str = "29d2S7vB453rNYFdR5Ycwt7y9haRT5fwVwL9zTmBhfV2";
const OTHER: &str = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
const USDC: &str = "usdc.scaas.testnet";
const VND: &str = "vnd.scaas.testnet";
const ALICE: &str = "alice.testnet";
const FIN: u64 = 180_000_000;

/// One fake NEAR node's state.
#[derive(Clone)]
struct Node {
    genesis: &'static str,
    fin: u64,
    /// `view_account`'s `amount` by account; an account not here is `UNKNOWN_ACCOUNT`
    native: HashMap<String, String>,
    /// `ft_balance_of` by (token, account), `ua_balance_of` by (token, id as 32 numbers); absent: "0"
    ft: HashMap<(String, String), String>,
    ua: HashMap<(String, String), String>,
    /// a query's answer names its block plus this
    skew: u64,
    /// a view's result bytes, replacing the JSON string of the amount
    raw_view: Option<Vec<u8>>,
    /// from this block on, the native amount is this one (the account moved)
    moved: Option<(u64, String)>,
}

type Fake = Arc<Mutex<Node>>;

fn node() -> Fake {
    let mut n = Node {
        genesis: GENESIS,
        fin: FIN,
        native: HashMap::new(),
        ft: HashMap::new(),
        ua: HashMap::new(),
        skew: 0,
        raw_view: None,
        moved: None,
    };
    n.native
        .insert(ALICE.into(), "1250000000000000000000000".into());
    n.ft.insert((USDC.into(), ALICE.into()), "5000000".into());
    n.ft.insert((VND.into(), ALICE.into()), "1000".into());
    n.ua.insert((USDC.into(), ua_args()), "7".into());
    Arc::new(Mutex::new(n))
}

fn ua_id() -> String {
    format!("0x{}", "0b".repeat(32))
}

/// `ua_balance_of`'s `id` as near-sdk reads a `[u8; 32]`: 32 numbers.
fn ua_args() -> String {
    json!(vec![11u8; 32]).to_string()
}

fn rpc_error(cause: &str) -> Value {
    json!({"name": "HANDLER_ERROR", "cause": {"name": cause, "info": {}}, "code": -32000,
           "message": "Server error", "data": cause})
}

fn answer(n: &Node, r: &Value) -> Result<Value, Value> {
    let p = &r["params"];
    match r["method"].as_str().unwrap() {
        "status" => Ok(json!({"chain_id": "testnet", "genesis_hash": n.genesis,
                               "sync_info": {"latest_block_height": n.fin + 3}})),
        "block" => {
            let h = p["block_id"].as_u64().unwrap_or(n.fin);
            Ok(
                json!({"author": "node0", "header": {"height": h, "hash": format!("h{h}"),
                       "prev_hash": format!("h{}", h - 1)}, "chunks": []}),
            )
        }
        "query" => {
            let at = p["block_id"]
                .as_u64()
                .ok_or_else(|| rpc_error("NO_BLOCK_ID"))?;
            let named = at + n.skew;
            let acct = p["account_id"].as_str().unwrap();
            match p["request_type"].as_str().unwrap() {
                "view_account" => match n
                    .moved
                    .as_ref()
                    .filter(|m| at >= m.0)
                    .map(|m| &m.1)
                    .or(n.native.get(acct))
                {
                    Some(a) => Ok(
                        json!({"amount": a, "locked": "0", "code_hash": "11111111111111111111111111111111",
                        "storage_usage": 182, "storage_paid_at": 0, "block_height": named,
                        "block_hash": format!("h{named}")}),
                    ),
                    None => Err(rpc_error("UNKNOWN_ACCOUNT")),
                },
                "call_function" => {
                    let args: Value = serde_json::from_slice(
                        &base64::engine::general_purpose::STANDARD
                            .decode(p["args_base64"].as_str().unwrap())
                            .unwrap(),
                    )
                    .unwrap();
                    let v = match p["method_name"].as_str().unwrap() {
                        "ft_balance_of" => {
                            n.ft.get(&(acct.into(), args["account_id"].as_str().unwrap().into()))
                        }
                        "ua_balance_of" => n.ua.get(&(acct.into(), args["id"].to_string())),
                        _ => return Err(rpc_error("CONTRACT_EXECUTION_ERROR")),
                    };
                    let bytes = n.raw_view.clone().unwrap_or_else(|| {
                        serde_json::to_vec(&json!(v.cloned().unwrap_or_else(|| "0".into())))
                            .unwrap()
                    });
                    Ok(json!({"result": bytes, "logs": [], "block_height": named,
                              "block_hash": format!("h{named}")}))
                }
                _ => Err(rpc_error("UNKNOWN_REQUEST")),
            }
        }
        _ => Err(rpc_error("METHOD_NOT_FOUND")),
    }
}

async fn up(f: &Fake) -> (String, Seen) {
    let f = f.clone();
    serve(Arc::new(move |_, _, body: &[u8]| {
        let r: Value = serde_json::from_slice(body).unwrap();
        let out = match answer(&f.lock().unwrap(), &r) {
            Ok(v) => json!({"jsonrpc": "2.0", "id": r["id"], "result": v}),
            Err(e) => json!({"jsonrpc": "2.0", "id": r["id"], "error": e}),
        };
        (200, serde_json::to_vec(&out).unwrap())
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
        key: "near-testnet".into(),
        family: Family::Near,
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
        tokens: vec![token(USDC, "USDC", 6), token(VND, "VND", 0)],
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

async fn balances(rpc: &[&str], id: &str) -> Result<Balances, SdkError> {
    sdk(profile(rpc, scaas_rpc::Policy::Failover))
        .await
        .wallet()
        .balances(id.into(), "near-testnet".into())
        .await
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn amounts(b: &Balances) -> Vec<&str> {
    b.tokens.iter().map(|t| t.amount.as_str()).collect()
}

/// The positive control: the native balance (`view_account`'s `amount`) and each listed token's (`ft_balance_of`) read at the
/// final block endpoint 0 names, every query pinned to it by `block_id`; the tokens as the profile lists them.
#[tokio::test(flavor = "multi_thread")]
async fn near_balances_at_the_final_block() {
    let f = node();
    let (u, seen) = up(&f).await;
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(b.block, FIN);
    assert_eq!(b.native.as_deref(), Some("1250000000000000000000000"));
    assert_eq!(amounts(&b), ["5000000", "1000"]);
    assert_eq!(
        (
            b.tokens[0].address.as_str(),
            b.tokens[0].display.as_str(),
            b.tokens[0].decimals
        ),
        (USDC, "USDC", 6)
    );
    let queries: Vec<Value> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, body)| serde_json::from_str::<Value>(body).unwrap())
        .filter(|r| r["method"] == "query")
        .collect();
    assert_eq!(queries.len(), 3);
    assert!(
        queries.iter().all(|q| q["params"]["block_id"] == FIN),
        "{queries:?}"
    );
}

/// A `0x` 32-byte UA id reads the token's UA ledger (`ua_balance_of({id: [32 numbers]})`) and holds no native coin; an id the
/// ledger does not know reads 0, as the contract answers.
#[tokio::test(flavor = "multi_thread")]
async fn near_ua_id_reads_the_ua_ledger() {
    let f = node();
    let (u, _) = up(&f).await;
    let b = balances(&[&u], &ua_id()).await.unwrap();
    assert_eq!(b.native, None);
    assert_eq!(amounts(&b), ["7", "0"]);
}

/// An account NEAR does not know at the final block holds nothing: native "0". Control: a known one reads its amount.
#[tokio::test(flavor = "multi_thread")]
async fn near_unknown_account_is_zero() {
    let f = node();
    let (u, _) = up(&f).await;
    let b = balances(&[&u], "bob.testnet").await.unwrap();
    assert_eq!(b.native.as_deref(), Some("0"));
    assert_eq!(amounts(&b), ["0", "0"]);
    f.lock()
        .unwrap()
        .native
        .insert("bob.testnet".into(), "9".into());
    let b = balances(&[&u], "bob.testnet").await.unwrap();
    assert_eq!(b.native.as_deref(), Some("9"), "control");
}

/// A holder or a listed token that is not a NEAR account id (nor a `0x` 32-byte id) is `Argument` before any read; the
/// controls (an implicit 64-hex account, an `0x` + 40 hex one) are read.
#[tokio::test(flavor = "multi_thread")]
async fn near_holder_and_token_forms() {
    let f = node();
    let (u, seen) = up(&f).await;
    let long = "a".repeat(65);
    for bad in [
        "Alice.testnet",
        "a",
        "alice..testnet",
        "-alice.testnet",
        "alice.testnet_",
        "al ice",
        &long,
    ] {
        assert_eq!(code(balances(&[&u], bad).await), "Argument", "{bad}");
    }
    assert!(seen.lock().unwrap().is_empty(), "nothing read");
    for good in [
        "98793cd91a3f870fb126f66285808c7e094afcfc4eda8a970f6648cdf0dbd6de",
        "0x5ca00000000000000000000000000000000000a1",
        "a1",
    ] {
        assert_eq!(code(balances(&[&u], good).await), "Ok", "{good}");
    }
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.push(token("USDT.testnet", "USDT", 6));
    let s = sdk(p).await;
    assert_eq!(
        code(
            s.wallet()
                .balances(ALICE.into(), "near-testnet".into())
                .await
        ),
        "Argument"
    );
}

/// Bounded decode: an amount that is not a decimal string of at most 78 digits within a U256 (a float, a sign, hex, empty, a
/// space, an underscore, 79 digits, above 2^256 - 1; a view's number instead of a string) is the endpoint's `AnswerMalformed`: alone it fails the read
/// (`EndpointAllFailed`); behind it a good endpoint answers. Control: 2^256 - 1 is read.
#[tokio::test(flavor = "multi_thread")]
async fn near_malformed_amount_is_refused() {
    let good = node();
    let (g, _) = up(&good).await;
    // 79 zeros is a U256 (0) refused by its length; 78 nines is above 2^256 - 1; `1_000` is a U256 parser's (it skips `_`)
    let (z79, n78) = ("0".repeat(79), "9".repeat(78));
    for bad in [
        "1.5",
        "-1",
        "0x10",
        "",
        " 1",
        "1_000",
        z79.as_str(),
        n78.as_str(),
    ] {
        let f = node();
        f.lock().unwrap().native.insert(ALICE.into(), bad.into());
        let (u, _) = up(&f).await;
        assert_eq!(
            code(balances(&[&u], ALICE).await),
            "EndpointAllFailed",
            "{bad:?}"
        );
        let b = balances(&[&u, &g], ALICE).await.unwrap();
        assert_eq!(
            amounts(&b),
            ["5000000", "1000"],
            "the second endpoint's ({bad:?})"
        );
    }
    for bad in [json!(12), json!("1.5"), json!(["1"])] {
        let f = node();
        f.lock().unwrap().raw_view = Some(serde_json::to_vec(&bad).unwrap());
        let (u, _) = up(&f).await;
        assert_eq!(
            code(balances(&[&u], ALICE).await),
            "EndpointAllFailed",
            "{bad}"
        );
    }
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let f = node();
    f.lock().unwrap().native.insert(ALICE.into(), max.into());
    let (u, _) = up(&f).await;
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(b.native.as_deref(), Some(max), "control: 2^256 - 1");
}

/// NEAR's view result is at most 128 bytes of JSON holding one string: 129 bytes is the endpoint's failure. Control: 128 bytes
/// (the amount padded with spaces) is read.
#[tokio::test(flavor = "multi_thread")]
async fn near_view_result_above_128_bytes_is_refused() {
    let f = node();
    let (u, _) = up(&f).await;
    let mut v = b"\"5\"".to_vec();
    v.resize(129, b' ');
    f.lock().unwrap().raw_view = Some(v.clone());
    assert_eq!(code(balances(&[&u], ALICE).await), "EndpointAllFailed");
    v.truncate(128);
    f.lock().unwrap().raw_view = Some(v);
    let b = balances(&[&u], ALICE).await.unwrap();
    assert_eq!(amounts(&b), ["5", "5"], "control");
}

/// One height: an answer naming another block than the one the set is read at is the endpoint's failure. Control: no skew.
#[tokio::test(flavor = "multi_thread")]
async fn near_answer_at_another_height_is_refused() {
    let f = node();
    let (u, _) = up(&f).await;
    f.lock().unwrap().skew = 1;
    assert_eq!(code(balances(&[&u], ALICE).await), "EndpointAllFailed");
    f.lock().unwrap().skew = 0;
    assert_eq!(code(balances(&[&u], ALICE).await), "Ok", "control");
}

/// ARCH-POS-15 failover with two endpoints, one down: either order answers. Endpoint 0 answers when it is up (its value, not
/// the second's).
#[tokio::test(flavor = "multi_thread")]
async fn near_two_endpoints_one_down() {
    let (a, b) = (node(), node());
    b.lock().unwrap().native.insert(ALICE.into(), "2".into());
    let ((ua, _), (ub, _)) = (up(&a).await, up(&b).await);
    let r = balances(&[DOWN, &ub], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("2"), "the second endpoint");
    let r = balances(&[&ua, DOWN], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("1250000000000000000000000"));
    let r = balances(&[&ua, &ub], ALICE).await.unwrap();
    assert_eq!(
        r.native.as_deref(),
        Some("1250000000000000000000000"),
        "endpoint 0 first"
    );
    // a list of two distinct endpoints both down (two equal endpoints are refused at open)
    assert_eq!(
        code(balances(&[DOWN, "http://127.0.0.1:1"], ALICE).await),
        "EndpointAllFailed"
    );
}

/// The profile's `chain_uid` is the genesis hash, base58 as `status` names it: an endpoint of another genesis is dropped.
/// Control: the same endpoint list with the right one behind it answers.
#[tokio::test(flavor = "multi_thread")]
async fn near_endpoint_of_another_genesis_is_dropped() {
    let (other, good) = (node(), node());
    other.lock().unwrap().genesis = OTHER;
    other
        .lock()
        .unwrap()
        .native
        .insert(ALICE.into(), "666".into());
    let ((uo, _), (ug, _)) = (up(&other).await, up(&good).await);
    assert_eq!(code(balances(&[&uo], ALICE).await), "EndpointAllFailed");
    let r = balances(&[&uo, &ug], ALICE).await.unwrap();
    assert_eq!(r.native.as_deref(), Some("1250000000000000000000000"));
}

async fn majority(urls: &[&str]) -> Result<Balances, SdkError> {
    sdk(profile(urls, scaas_rpc::Policy::StrictMajority))
        .await
        .wallet()
        .balances(ALICE.into(), "near-testnet".into())
        .await
}

/// `strict_majority`: the other endpoints read the set at endpoint 0's final block and a strict majority must agree; one liar
/// of three is outvoted (control), two disagreeing of three is `EndpointNoMajority`, and an endpoint of another genesis
/// repeating endpoint 0's answer does not count.
#[tokio::test(flavor = "multi_thread")]
async fn near_strict_majority_agrees_at_one_height() {
    let (a, b, liar, liar2, other) = (node(), node(), node(), node(), node());
    liar.lock()
        .unwrap()
        .native
        .insert(ALICE.into(), "666".into());
    liar2
        .lock()
        .unwrap()
        .ft
        .insert((VND.into(), ALICE.into()), "1".into());
    other.lock().unwrap().genesis = OTHER;
    // endpoint 0's final block: the others read at it even when their own final block is further and the account moved since
    b.lock().unwrap().fin = FIN + 5;
    b.lock().unwrap().moved = Some((FIN + 1, "999".into()));
    let (ua, ub, ul, ul2, uo) = (
        up(&a).await.0,
        up(&b).await.0,
        up(&liar).await.0,
        up(&liar2).await.0,
        up(&other).await.0,
    );
    let r = majority(&[&ua, &ul, &ub]).await.unwrap();
    assert_eq!(
        (r.block, r.native.as_deref()),
        (FIN, Some("1250000000000000000000000"))
    );
    assert_eq!(
        code(majority(&[&ua, &ul, &ul2]).await),
        "EndpointNoMajority"
    );
    assert_eq!(code(majority(&[&ua, &uo, &ul]).await), "EndpointNoMajority");
    assert_eq!(code(majority(&[&ua, &uo, &ub]).await), "Ok", "control");
}
