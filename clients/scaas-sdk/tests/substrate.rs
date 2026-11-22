// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T32's read part (decisions CLI-SDK-32's Change of 2026-11-22): `wallet().balances` of an SS58 id on Polkadot Hub's EVM
//! profile reads native DOT from its Substrate side (`FamilyParams::Substrate`), against a fake Substrate JSON-RPC
//! (`tests/common/fake_http.rs`, local only) answering with scaas-rpc's recorded Westend Asset Hub answers
//! (`clients/scaas-rpc/tests/fixtures/substrate/`, 2026-11-22). The id is `ua-rs`'s SS58 form of `bip39_abandon`'s bare account
//! at prefix 42 (`smartcontracts/vectors/native/native.json`). Every refusal beside its control.
#![cfg(feature = "substrate")]
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
    ChainProfile, EndpointConfig, Family, FamilyParams, Finality, Limits, RuntimeChoice, Sdk,
    SdkConfig, SdkError,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const KEY: &str = "polkadot-hub-testnet";
const HUB_GENESIS: &str = "0x67f9723393ef76214df0118c34bbbd3dbebc8ed46a10973a8c969d48fe7598c9";
const RELAY_GENESIS: &str = "0xe143f23803ac50e8f6f8e62695d1ce9e4e1d68aa36c1cd2cfd15340213f3423e";
/// `bip39_abandon`'s bare sr25519 account at prefix 42 and 0 (`ua-rs`'s rows)
const ID: &str = "5EPCUjPxiHAcNooYipQFWr9NmmXJKpNG5RhcntXwbtUySrgH";
const ID_PREFIX_0: &str = "13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo";
/// an account without an entry: `bip39_abandon_trezor`'s bare account at prefix 42
const EMPTY_ID: &str = "5GHRV8fpuNjWCxfoRjCBc1BqY33ddAHs9DVdkhwccAjY71pN";
/// `System.Account`'s key of [`ID`]
const FUNDED_KEY: &str = "26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da985eed350b03894f4ee3db867915c839566933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed7972";
const NUMBER: u64 = 0x12ca1c6;
/// the recorded `free`: 0x424fb28f planck
const FREE: &str = "1112519311";

fn rec(name: &str) -> Value {
    let s = match name {
        "genesis" => include_str!("../../scaas-rpc/tests/fixtures/substrate/hub_genesis.json"),
        "finalized" => include_str!("../../scaas-rpc/tests/fixtures/substrate/hub_finalized.json"),
        "header" => include_str!("../../scaas-rpc/tests/fixtures/substrate/hub_header.json"),
        "funded" => include_str!("../../scaas-rpc/tests/fixtures/substrate/hub_funded.json"),
        "empty" => include_str!("../../scaas-rpc/tests/fixtures/substrate/hub_empty.json"),
        _ => unreachable!(),
    };
    serde_json::from_str::<Value>(s).unwrap()["result"].clone()
}

/// One fake node: the recorded Hub, its genesis and the funded account's storage replaceable; its block at the finalized
/// height is the recorded head unless `hash_at` names another.
#[derive(Clone, Default)]
struct Node {
    genesis: Option<&'static str>,
    storage: Option<Value>,
    hash_at: Option<&'static str>,
}

async fn up(n: Node) -> String {
    let n = Arc::new(Mutex::new(n));
    serve(Arc::new(move |_, _, body: &[u8]| {
        let n = n.lock().unwrap().clone();
        let r: Value = serde_json::from_slice(body).unwrap();
        let (p, fin) = (&r["params"], rec("finalized"));
        let res = match r["method"].as_str().unwrap() {
            "chain_getBlockHash" if p[0] == 0 => {
                Ok(n.genesis.map_or_else(|| rec("genesis"), |g| json!(g)))
            }
            "chain_getBlockHash" if p[0] == NUMBER => {
                Ok(n.hash_at.map_or_else(|| fin.clone(), |h| json!(h)))
            }
            "chain_getFinalizedHead" => Ok(fin.clone()),
            "chain_getHeader" if p[0] == fin => Ok(rec("header")),
            "state_getStorage" if p[1] == fin || n.hash_at.is_some_and(|h| p[1] == h) => {
                if p[0].as_str().unwrap().trim_start_matches("0x") == FUNDED_KEY {
                    Ok(n.storage.clone().unwrap_or_else(|| rec("funded")))
                } else {
                    Ok(rec("empty"))
                }
            }
            _ => Err(json!({"code": 4003, "message": "Client error: UnknownBlock"})),
        };
        let out = match res {
            Ok(v) => json!({"jsonrpc": "2.0", "id": r["id"], "result": v}),
            Err(e) => json!({"jsonrpc": "2.0", "id": r["id"], "error": e}),
        };
        (200, serde_json::to_vec(&out).unwrap())
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

fn params(rpc: &[&str], policy: scaas_rpc::Policy, genesis: &str, prefix: u16) -> FamilyParams {
    FamilyParams::Substrate {
        rpc: rpc.iter().map(|u| endpoint(u)).collect(),
        rpc_policy: policy,
        genesis: genesis.into(),
        ss58_prefix: prefix,
    }
}

/// Polkadot Hub's EVM profile (its EVM endpoint never asked here) with a Substrate side.
fn profile(family: Family, p: Option<FamilyParams>) -> ChainProfile {
    ChainProfile {
        key: KEY.into(),
        family,
        chain_id: Some(420_420_421),
        chain_uid: format!("0x{}", "22".repeat(32)),
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
        tokens: vec![],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: p,
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

async fn balances_on(
    rpc: &[&str],
    policy: scaas_rpc::Policy,
    id: &str,
) -> Result<Balances, SdkError> {
    open(profile(
        Family::Evm,
        Some(params(rpc, policy, HUB_GENESIS, 42)),
    ))
    .await
    .unwrap()
    .wallet()
    .balances(id.into(), KEY.into())
    .await
}

async fn balances(rpc: &[&str], id: &str) -> Result<Balances, SdkError> {
    balances_on(rpc, scaas_rpc::Policy::Failover, id).await
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

/// The positive control: the SS58 id's `free` at the finalized head, the head's number as the block, no tokens; an account
/// without an entry holds 0.
#[tokio::test(flavor = "multi_thread")]
async fn hub_native_dot_at_the_finalized_head() {
    let u = up(Node::default()).await;
    let b = balances(&[&u], ID).await.unwrap();
    assert_eq!(
        b,
        Balances {
            block: NUMBER,
            native: Some(FREE.into()),
            tokens: vec![]
        }
    );
    assert_eq!(
        balances(&[&u], EMPTY_ID).await.unwrap().native.as_deref(),
        Some("0")
    );
}

/// The id must be SS58 at the params' prefix: the same key at prefix 0 is `Argument`, as a changed character; control: prefix 42.
#[tokio::test(flavor = "multi_thread")]
async fn hub_native_id_at_another_prefix_is_refused() {
    let u = up(Node::default()).await;
    assert_eq!(code(balances(&[&u], ID_PREFIX_0).await), "Argument");
    assert_eq!(
        code(balances(&[&u], &format!("{}J", &ID[..ID.len() - 1])).await),
        "Argument"
    );
    assert_eq!(code(balances(&[&u], ID).await), "Ok", "control");
    // a `0x` id on the Hub profile is its EVM side's (its EVM endpoint is down here), never an SS58 refusal
    let evm = format!("0x{}", "11".repeat(20));
    assert_eq!(code(balances(&[&u], &evm).await), "EndpointAllFailed");
}

/// `Sdk::open`'s checks: Substrate params on a non-EVM family, a genesis not of 32 bytes, a reserved prefix are `Argument`;
/// control: the Hub's.
#[tokio::test(flavor = "multi_thread")]
async fn hub_substrate_params_are_checked_at_open() {
    let ok = |g: &str, p: u16| {
        Some(params(
            &["http://127.0.0.1:1"],
            scaas_rpc::Policy::Failover,
            g,
            p,
        ))
    };
    let mut near = profile(Family::Near, ok(HUB_GENESIS, 42));
    near.chain_id = None;
    assert_eq!(code(open(near).await), "Argument", "another family");
    assert_eq!(
        code(open(profile(Family::Evm, ok("0x1234", 42))).await),
        "Argument",
        "genesis"
    );
    assert_eq!(
        code(open(profile(Family::Evm, ok(HUB_GENESIS, 46))).await),
        "Argument",
        "prefix 46"
    );
    assert_eq!(
        code(open(profile(Family::Evm, ok(HUB_GENESIS, 42))).await),
        "Ok",
        "control"
    );
}

/// A malformed `AccountInfo` (81 bytes) is the endpoint's failure, never a balance. Control: the recorded value.
#[tokio::test(flavor = "multi_thread")]
async fn hub_malformed_account_info_is_refused() {
    let r = rec("funded").as_str().unwrap().to_string();
    let bad = up(Node {
        storage: Some(json!(format!("{r}00"))),
        ..Node::default()
    })
    .await;
    assert_eq!(code(balances(&[&bad], ID).await), "EndpointAllFailed");
    let good = up(Node {
        storage: Some(json!(r)),
        ..Node::default()
    })
    .await;
    assert_eq!(code(balances(&[&good], ID).await), "Ok", "control");
}

/// ARCH-POS-15's failover: one endpoint down and one of another genesis (the relay chain's) are passed over.
#[tokio::test(flavor = "multi_thread")]
async fn hub_native_one_down_one_of_another_genesis() {
    let other = up(Node {
        genesis: Some(RELAY_GENESIS),
        ..Node::default()
    })
    .await;
    let good = up(Node::default()).await;
    let b = balances(&[DOWN, &other, &good], ID).await.unwrap();
    assert_eq!(b.native.as_deref(), Some(FREE));
    assert_eq!(
        code(balances(&[DOWN, &other], ID).await),
        "EndpointAllFailed"
    );
}

/// `strict_majority`: the other endpoints read the account at their hash of endpoint 0's finalized height and a strict
/// majority must agree on that hash and the decoded `AccountInfo`. A liar of three is outvoted (control); two of three
/// disagreeing (another `free`, another hash at that height) is `EndpointNoMajority`; a liar whose answer differs only in the
/// JSON's spelling (upper-case hex) agrees.
#[tokio::test(flavor = "multi_thread")]
async fn hub_native_strict_majority_at_one_finalized_hash() {
    let r = rec("funded").as_str().unwrap().to_string();
    let mut other_free = r.clone();
    other_free.replace_range(34..36, "00");
    let (a, b) = (up(Node::default()).await, up(Node::default()).await);
    let liar = up(Node {
        storage: Some(json!(other_free)),
        ..Node::default()
    })
    .await;
    let fork = up(Node {
        hash_at: Some("0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
        ..Node::default()
    })
    .await;
    let upper = up(Node {
        storage: Some(json!(format!("0x{}", r[2..].to_ascii_uppercase()))),
        ..Node::default()
    })
    .await;
    let m = scaas_rpc::Policy::StrictMajority;
    assert_eq!(
        balances_on(&[&a, &liar, &b], m, ID)
            .await
            .unwrap()
            .native
            .as_deref(),
        Some(FREE)
    );
    assert_eq!(
        code(balances_on(&[&a, &liar, &fork], m, ID).await),
        "EndpointNoMajority"
    );
    assert_eq!(
        code(balances_on(&[&a, &fork, &liar], m, ID).await),
        "EndpointNoMajority"
    );
    assert_eq!(
        code(balances_on(&[&a, &upper, &liar], m, ID).await),
        "Ok",
        "the decoded value, not the JSON"
    );
}
