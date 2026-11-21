// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T24.soroban (spec §8.7; decisions CLI-SDK-15's Changes of 2026-11-21): `wallet().balances` on a Soroban profile, against
//! a fake Soroban RPC (`tests/common/fake_http.rs`, local only) answering `getNetwork`, `getLatestLedger` and `getLedgerEntries`
//! from the rows of smartcontracts/vectors/families/soroban.json (clientkeys wrote them): an entry is served only for the key its
//! row names, so a key the SDK builds otherwise reads nothing. Every refusal beside its control.
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

const PASSPHRASE: &str = "Standalone Network ; February 2017";
const L: u64 = 5_000;

fn rows() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../smartcontracts/vectors/families/soroban.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn uid(passphrase: &str) -> String {
    format!("0x{}", hex(&scaas_ua::sha256(passphrase.as_bytes())))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn holder(kind: &str) -> String {
    rows()["holders"][kind].as_str().unwrap().into()
}
/// the entry row of `what`
fn entry(what: &str) -> (String, String) {
    let v = rows();
    let e = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["what"] == what)
        .unwrap()
        .clone();
    (
        e["key"].as_str().unwrap().into(),
        e["xdr"].as_str().unwrap().into(),
    )
}

#[derive(Clone)]
struct Node {
    passphrase: &'static str,
    ledger: u64,
    /// the entries by key: (xdr, liveUntilLedgerSeq)
    entries: HashMap<String, (String, Option<u64>)>,
    /// every entry answer replaced, as `(key, xdr)` pairs listed as given
    raw: Option<Vec<(String, String)>>,
    /// each getLedgerEntries' keys
    seen: Vec<Vec<String>>,
}

type Fake = Arc<Mutex<Node>>;

fn node() -> Fake {
    let mut n = Node {
        passphrase: PASSPHRASE,
        ledger: L,
        entries: HashMap::new(),
        raw: None,
        seen: vec![],
    };
    for what in [
        "an account entry",
        "a token balance of a account holder",
        "a token balance of a contract holder",
        "a token balance of a ua holder",
        "the SAC balance of a C… holder",
    ] {
        let (k, x) = entry(what);
        n.entries.insert(k, (x, Some(L + 100)));
    }
    // the account entry has no TTL
    let (k, _) = entry("an account entry");
    n.entries.get_mut(&k).unwrap().1 = None;
    Arc::new(Mutex::new(n))
}

fn ok(v: Value) -> (u16, Vec<u8>) {
    (200, serde_json::to_vec(&v).unwrap())
}

fn answer(n: &mut Node, body: &[u8]) -> (u16, Vec<u8>) {
    let r: Value = serde_json::from_slice(body).unwrap();
    let result = match r["method"].as_str().unwrap() {
        "getNetwork" => json!({"passphrase": n.passphrase, "protocolVersion": 23}),
        "getLatestLedger" => {
            json!({"sequence": n.ledger, "id": "ab".repeat(32), "protocolVersion": 23})
        }
        "getLedgerEntries" => {
            let keys: Vec<String> = r["params"]["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap().to_string())
                .collect();
            n.seen.push(keys.clone());
            let list: Vec<(String, String, Option<u64>)> = match &n.raw {
                Some(r) => r
                    .iter()
                    .map(|(k, x)| (k.clone(), x.clone(), None))
                    .collect(),
                None => keys
                    .iter()
                    .filter_map(|k| n.entries.get(k).map(|(x, t)| (k.clone(), x.clone(), *t)))
                    .collect(),
            };
            let entries: Vec<Value> = list
                .into_iter()
                .map(|(k, x, t)| {
                    let mut e = json!({"key": k, "xdr": x, "lastModifiedLedgerSeq": L - 10});
                    if let Some(t) = t {
                        e["liveUntilLedgerSeq"] = json!(t);
                    }
                    e
                })
                .collect();
            json!({"entries": entries, "latestLedger": n.ledger})
        }
        m => panic!("{m}"),
    };
    ok(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
}

async fn up(f: &Fake) -> String {
    let f = f.clone();
    serve(Arc::new(move |_m: &str, _p: &str, body: &[u8]| {
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

fn profile(rpc: &[&str], policy: scaas_rpc::Policy) -> ChainProfile {
    let v = rows();
    ChainProfile {
        key: "soroban-local".into(),
        family: Family::Soroban,
        chain_id: None,
        chain_uid: uid(PASSPHRASE),
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
        tokens: vec![ListedToken {
            address: v["token"].as_str().unwrap().into(),
            symbol: "USDC".into(),
            decimals: 7,
        }],
        family_params: Some(FamilyParams::Soroban {
            passphrase: PASSPHRASE.into(),
            xlm_sac: v["sac"].as_str().unwrap().into(),
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
        .balances(id.into(), "soroban-local".into())
        .await
}

async fn balances(rpc: &[&str], id: &str) -> Result<Balances, SdkError> {
    read(profile(rpc, scaas_rpc::Policy::Failover), id).await
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn pair(b: &Balances) -> (Option<&str>, &str) {
    (b.native.as_deref(), b.tokens[0].amount.as_str())
}

/// The positive control: one `getLedgerEntries` per set, `block` its `latestLedger`. A `G…` holder: its account entry's
/// stroops and the token's `Balance(Address)`; a `C…` holder: the XLM SAC's balance entry and the token's; a UA id: no native,
/// the token's `UaBalance`. A holder with no entries reads "0".
#[tokio::test(flavor = "multi_thread")]
async fn soroban_balances_at_one_ledger() {
    let f = node();
    let u = up(&f).await;
    let b = balances(&[&u], &holder("account")).await.unwrap();
    assert_eq!(b.block, L);
    assert_eq!(pair(&b), (Some("1234567"), "1000"));
    let b = balances(&[&u], &holder("contract")).await.unwrap();
    assert_eq!(pair(&b), (Some("70000000"), "2000"));
    let b = balances(&[&u], &holder("ua")).await.unwrap();
    assert_eq!(pair(&b), (None, "3000"));
    let seen = f.lock().unwrap().seen.clone();
    assert_eq!(
        seen.iter().map(Vec::len).collect::<Vec<_>>(),
        [2, 2, 1],
        "one call per set"
    );
    let v = rows();
    let row_keys: Vec<&str> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["key"].as_str().unwrap())
        .collect();
    assert!(
        seen.iter()
            .flatten()
            .all(|k| row_keys.contains(&k.as_str())),
        "the rows' keys"
    );
    let nobody = format!("0x{}", "5".repeat(64));
    let b = balances(&[&u], &nobody).await.unwrap();
    assert_eq!(pair(&b), (None, "0"));
}

/// An entry out of its form (each refused row of the vectors, served for its key) is the endpoint's `AnswerMalformed`; behind it
/// a good endpoint answers. An archived entry is a failure, never 0; an entry not asked or listed twice: the same. Controls:
/// the rows' i64 and i128 maxima and the deauthorized SAC row are read; an entry live at `latestLedger` is read.
#[tokio::test(flavor = "multi_thread")]
async fn soroban_entries_out_of_form_are_refused() {
    let good = node();
    let g = up(&good).await;
    let v = rows();
    for r in v["refusedEntries"].as_array().unwrap() {
        let f = node();
        let k = r["key"].as_str().unwrap().to_string();
        f.lock()
            .unwrap()
            .entries
            .insert(k, (r["xdr"].as_str().unwrap().into(), None));
        let u = up(&f).await;
        let who = if r["form"] == "sac" {
            holder("contract")
        } else {
            holder("account")
        };
        assert_eq!(
            code(balances(&[&u], &who).await),
            "EndpointAllFailed",
            "{}",
            r["why"]
        );
        assert_eq!(code(balances(&[&u, &g], &who).await), "Ok", "{}", r["why"]);
    }
    for (what, who, want) in [
        (
            "an account entry at i64 max",
            "account",
            (Some("9223372036854775807"), "1000"),
        ),
        (
            "a token balance at i128 max",
            "account",
            (Some("1234567"), "170141183460469231731687303715884105727"),
        ),
        (
            "the SAC balance, deauthorized, clawback on",
            "contract",
            (Some("5"), "2000"),
        ),
    ] {
        let f = node();
        let (k, x) = entry(what);
        f.lock().unwrap().entries.insert(k, (x, None));
        let u = up(&f).await;
        assert_eq!(
            pair(&balances(&[&u], &holder(who)).await.unwrap()),
            want,
            "{what}"
        );
    }
    // archived: live until the ledger before; control: live until this ledger
    let (k, _) = entry("a token balance of a account holder");
    for (until, want) in [(L - 1, "EndpointAllFailed"), (L, "Ok")] {
        let f = node();
        f.lock().unwrap().entries.get_mut(&k).unwrap().1 = Some(until);
        let u = up(&f).await;
        assert_eq!(
            code(balances(&[&u], &holder("account")).await),
            want,
            "{until}"
        );
    }
    // an entry not asked, one twice
    let (ka, xa) = entry("an account entry");
    let (kc, xc) = entry("the SAC balance of a C… holder");
    for raw in [vec![(kc, xc)], vec![(ka.clone(), xa.clone()), (ka, xa)]] {
        let f = node();
        f.lock().unwrap().raw = Some(raw);
        let u = up(&f).await;
        assert_eq!(
            code(balances(&[&u], &holder("account")).await),
            "EndpointAllFailed"
        );
    }
}

/// The holder is a `G…`, a `C…` or a `0x` + 64 lowercase hex UA id; each refused strkey of the vectors, upper-case hex, a token
/// that is no `C…`: `Argument`, nothing read. A UA id with no listed token: `Argument`. Params of another family, none, a
/// passphrase whose SHA-256 is not `chain_uid`, an XLM SAC that is no `C…`: `Argument`. Control: the right forms read.
#[tokio::test(flavor = "multi_thread")]
async fn soroban_holder_token_and_params_forms() {
    let f = node();
    let u = up(&f).await;
    let v = rows();
    let mut bad: Vec<String> = v["refusedStrkeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["text"].as_str().unwrap().into())
        .collect();
    bad.push(holder("ua").to_uppercase().replacen("0X", "0x", 1));
    bad.push(holder("ua")[..65].into());
    for id in &bad {
        assert_eq!(code(balances(&[&u], id).await), "Argument", "{id}");
    }
    assert!(f.lock().unwrap().seen.is_empty(), "nothing read");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens[0].address = holder("account");
    assert_eq!(
        code(read(p, &holder("account")).await),
        "Argument",
        "a token that is no contract"
    );
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.tokens.clear();
    assert_eq!(
        code(read(p, &holder("ua")).await),
        "Argument",
        "nothing to read"
    );
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family = Family::Solana;
    assert_eq!(code(open(p).await), "Argument", "params of another family");
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family_params = None;
    assert_eq!(
        code(read(p, &holder("account")).await),
        "Argument",
        "no params"
    );
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.chain_uid = uid("Test SDF Network ; September 2015");
    assert_eq!(
        code(open(p).await),
        "Argument",
        "a passphrase of another network"
    );
    let mut p = profile(&[&u], scaas_rpc::Policy::Failover);
    p.family_params = Some(FamilyParams::Soroban {
        passphrase: PASSPHRASE.into(),
        xlm_sac: holder("account"),
    });
    assert_eq!(
        code(open(p).await),
        "Argument",
        "an XLM SAC that is no contract"
    );
    assert_eq!(
        code(balances(&[&u], &holder("account")).await),
        "Ok",
        "control"
    );
}

/// ARCH-POS-15 failover with two endpoints, one down; an endpoint of another passphrase is dropped.
#[tokio::test(flavor = "multi_thread")]
async fn soroban_two_endpoints_one_down() {
    let (x, y, other) = (node(), node(), node());
    let (ka, _) = entry("an account entry");
    let (_, x2) = entry("an account entry at i64 max");
    y.lock().unwrap().entries.get_mut(&ka).unwrap().0 = x2;
    other.lock().unwrap().passphrase = "Test SDF Network ; September 2015";
    let (ux, uy, uo) = (up(&x).await, up(&y).await, up(&other).await);
    let a = holder("account");
    let max = Some("9223372036854775807");
    assert_eq!(
        balances(&[DOWN, &uy], &a).await.unwrap().native.as_deref(),
        max,
        "the second"
    );
    assert_eq!(
        balances(&[&ux, DOWN], &a).await.unwrap().native.as_deref(),
        Some("1234567")
    );
    assert_eq!(
        balances(&[&ux, &uy], &a).await.unwrap().native.as_deref(),
        Some("1234567"),
        "endpoint 0 first"
    );
    assert_eq!(
        code(balances(&[&uo], &a).await),
        "EndpointAllFailed",
        "another network"
    );
    assert_eq!(
        balances(&[&uo, &uy], &a).await.unwrap().native.as_deref(),
        max
    );
    assert_eq!(
        code(balances(&[DOWN, "http://127.0.0.1:1"], &a).await),
        "EndpointAllFailed"
    );
}

async fn majority(urls: &[&str]) -> Result<Balances, SdkError> {
    read(
        profile(urls, scaas_rpc::Policy::StrictMajority),
        &holder("account"),
    )
    .await
}

/// `strict_majority`: another endpoint's set at its own `latestLedger`, not below the answering one's, is compared; one liar of
/// three is outvoted (control), two disagreeing or behind of three is `EndpointNoMajority`. `block` is endpoint 0's ledger.
#[tokio::test(flavor = "multi_thread")]
async fn soroban_strict_majority_agrees_on_the_set() {
    let (x, y, liar, behind) = (node(), node(), node(), node());
    let (ka, _) = entry("an account entry");
    let (_, x2) = entry("an account entry at i64 max");
    liar.lock().unwrap().entries.get_mut(&ka).unwrap().0 = x2;
    y.lock().unwrap().ledger = L + 5;
    behind.lock().unwrap().ledger = L - 1;
    let (ux, uy, ul, ub) = (
        up(&x).await,
        up(&y).await,
        up(&liar).await,
        up(&behind).await,
    );
    let r = majority(&[&ux, &ul, &uy]).await.unwrap();
    assert_eq!((r.block, r.native.as_deref()), (L, Some("1234567")));
    assert_eq!(code(majority(&[&ux, &ul, &ub]).await), "EndpointNoMajority");
    assert_eq!(code(majority(&[&ux, &uy, &ub]).await), "Ok", "control");
}
