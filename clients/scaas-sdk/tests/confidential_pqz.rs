// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T16: the SDK's PQZ reading layer (spec §9.2, §9.4) against the fake chain of `tests/common/fake_chain.rs` (local only)
//! holding a PQZ token's storage: the factory record, the clone's code, `psid`, slot 0, the registry's `pqzKey` and
//! `pqzVersions`, the account's slots, the pending window and the blobs, written from the shared rows
//! `smartcontracts/vectors/pqz/<set>/wallet_state.json` (`pqz_key_version` of the `pq_kat` mnemonic, the SDK's seed here).
//! Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, hash_of, serve, Fake, CHAIN_ID};
use scaas_sdk::confidential::PqzBalanceRequest;
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig,
    SdkError,
};
use scaas_ua::factory::{clone_runtime, ChainEnv};
use scaas_ua::keccak256;
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const PQ_KAT: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const TOKEN: &str = "0x5ca00000000000000000000000000000000000c2";
const FACTORY: &str = "0x5ca00000000000000000000000000000000000f0";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000e0";
const IMPL: &str = "0x5ca00000000000000000000000000000000000d0";
/// ML-DSA-44, a PQZ-capable UA kind
const KIND: u16 = 0x0130;

type W = [u8; 32];

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

fn w(s: &Value) -> W {
    unhex(s.as_str().unwrap()).try_into().unwrap()
}

fn a20(s: &str) -> [u8; 20] {
    unhex(s).try_into().unwrap()
}

fn add(a: &W, i: u64) -> W {
    let mut o = *a;
    let mut carry = u128::from(i);
    for b in o.iter_mut().rev() {
        let t = u128::from(*b) + (carry & 0xff);
        *b = t as u8;
        carry = (carry >> 8) + (t >> 8);
    }
    o
}

fn be(n: u64) -> W {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&n.to_be_bytes());
    w
}

fn map(key: &W, base: &W) -> W {
    keccak256(&[key.as_slice(), base.as_slice()].concat())
}

/// The ERC-7201 root of `scaas.pqz` (`STATE_LAYOUT`'s namespace).
fn root() -> W {
    let mut m = keccak256(b"scaas.pqz");
    for b in m.iter_mut().rev() {
        let borrow = *b == 0;
        *b = b.wrapping_sub(1);
        if !borrow {
            break;
        }
    }
    let mut r = keccak256(&m);
    r[31] = 0;
    r
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

fn profile(rpc: Vec<EndpointConfig>) -> ChainProfile {
    ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: hash_of(0),
        rpc,
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: Some(FACTORY.into()),
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        gas: Default::default(),
        max_valid_secs: None,
        gas_opt_in: vec![],
        tokens: vec![],
    }
}

async fn sdk(p: ChainProfile) -> (Arc<Sdk>, String) {
    let s = Sdk::open(SdkConfig {
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
    .unwrap();
    let sec = |t: &str| Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(t.as_bytes().to_vec())).unwrap());
    let seed = s
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(PQ_KAT),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (s, seed)
}

fn put(c: &Fake, who: &str, slot: &W, word: &W) {
    c.lock().unwrap().storage.insert((who.to_ascii_lowercase(), hx(slot)), hx(word));
}

/// The shared row `name` of `wallet_state.json` at this build's set.
fn row(name: &str) -> Value {
    let set = scaas_ua::facade::pqz::pqz_set().name;
    let p = format!("{}/../../smartcontracts/vectors/pqz/{set}/wallet_state.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["rows"].as_array().unwrap().iter().find(|r| r["name"].as_str().unwrap().starts_with(name)).unwrap().clone()
}

fn signer(seed: &str, index: u32) -> KeyRef {
    KeyRef::Ua {
        seed: seed.into(),
        kind: KIND,
        account: 0,
        index,
    }
}

fn req(seed: &str, index: u32, version: u64) -> PqzBalanceRequest {
    PqzBalanceRequest {
        signer: signer(seed, index),
        chain: "local".into(),
        token: TOKEN.into(),
        key_version: version,
    }
}

/// The token's state on fake `c` for the UA `ua`: the factory record (class TOKEN, kind NORMAL_PQZ), the clone's code with
/// its `ChainEnv`, and the row's words at their slots (the account of `(ua, keyVersion)`, `sendCounter[ua]`, the window, the
/// registry's `pqzKey[ua][v]` and `pqzVersions[ua]`, every blob's code).
fn pqz_state(c: &Fake, ua: &W, r: &Value) {
    let q = &r["request"];
    let v = q["keyVersion"].as_u64().unwrap();
    let mut rec = [0u8; 32];
    rec[29] = 4;
    rec[31] = 1;
    let t = a20(TOKEN);
    let mut tw = [0u8; 32];
    tw[12..].copy_from_slice(&t);
    put(c, FACTORY, &add(&map(&tw, &be(8)), 1), &rec);
    let env = ChainEnv {
        chain_uid: unhex(&hash_of(0)).try_into().unwrap(),
        registry: a20(REGISTRY),
        gov_router: [0; 20],
        smart_key_account_impl: [0; 20],
        hedera: false,
        deps: vec![],
        params: vec![],
    };
    c.lock().unwrap().code.insert(TOKEN.into(), hx(&clone_runtime(&a20(IMPL), &env)));
    let root = root();
    put(c, TOKEN, &add(&root, 2), &w(&q["psid"]));
    put(c, REGISTRY, &map(&be(v), &map(ua, &be(2))), &w(&q["keyRecord"]));
    put(c, REGISTRY, &map(ua, &be(17)), &w(&q["keyVersions"]));
    let base = map(&be(v), &map(ua, &add(&root, 8)));
    for (i, a) in q["account"].as_array().unwrap().iter().enumerate() {
        put(c, TOKEN, &add(&base, i as u64), &w(a));
    }
    put(c, TOKEN, &map(ua, &add(&root, 12)), &w(&q["sendCounterWord"]));
    for e in q["pending"].as_array().unwrap() {
        put(c, TOKEN, &map(&be(e["index"].as_u64().unwrap()), &add(&base, 4)), &w(&e["word"]));
    }
    for (i, a) in q["accWords"].as_array().unwrap().iter().enumerate() {
        put(c, TOKEN, &add(&add(&base, 5), i as u64), &w(a));
    }
    for b in q["blobs"].as_array().unwrap() {
        c.lock()
            .unwrap()
            .code
            .insert(b["address"].as_str().unwrap().to_ascii_lowercase(), b["code"].as_str().unwrap().into());
    }
}

/// The holder's UA (the signing key's of the `pq_kat` seed, `account` 0, `index`).
async fn ua_of(_: &Arc<Sdk>, _: &str, index: u32) -> W {
    scaas_ua::wallet::Wallet::from_mnemonic(PQ_KAT, "").unwrap().ua_key(KIND, 0, index).unwrap().ua().unwrap()
}

/// One fake holding row `name` for the UA of index `index`.
async fn one(name: &str, index: u32) -> (Arc<Sdk>, String, Fake, Value) {
    let c = fake();
    let url = serve(c.clone()).await;
    let (s, seed) = sdk(profile(vec![endpoint(&url)])).await;
    let r = row(name);
    pqz_state(&c, &ua_of(&s, &seed, index).await, &r);
    (s, seed, c, r)
}

fn log(c: &Fake) -> Vec<Value> {
    c.lock()
        .unwrap()
        .requests
        .iter()
        .flat_map(|r| match serde_json::from_str::<Value>(r).unwrap() {
            Value::Array(a) => a,
            v => vec![v],
        })
        .collect()
}

fn count(c: &Fake, method: &str) -> usize {
    log(c).iter().filter(|r| r["method"] == method).count()
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_balance_of_the_shared_rows() {
    // B: a pending credit and a TRIVIAL entry (index 1); A v1: the migrated credit pending (index 0, key version 1)
    for (name, index) in [("B:", 1), ("A v1", 0)] {
        let (s, seed, c, r) = one(name, index).await;
        let v = r["request"]["keyVersion"].as_u64().unwrap();
        let b = s.confidential().pqz_balance(req(&seed, index, v)).await.unwrap();
        assert_eq!(b.amount, r["value"].to_string(), "{name}");
        assert_eq!(count(&c, "eth_call"), 0, "storage and code only");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn set_mismatch_before_parse() {
    // control
    let (s, seed, c, _) = one("B:", 1).await;
    s.confidential().pqz_balance(req(&seed, 1, 0)).await.unwrap();
    // another set's psid and account words that do not parse: the set's name, and no account word read
    let root = root();
    let mut other = w(&row("B:")["request"]["psid"]);
    other[0] ^= 1;
    put(&c, TOKEN, &add(&root, 2), &other);
    let ua = ua_of(&s, &seed, 1).await;
    put(&c, TOKEN, &map(&be(0), &map(&ua, &add(&root, 8))), &[0xff; 32]);
    c.lock().unwrap().requests.clear();
    assert_eq!(code(s.confidential().pqz_balance(req(&seed, 1, 0)).await), "PqzSetMismatch");
    assert_eq!(count(&c, "eth_getStorageAt"), 2, "the factory record and psid only");
    assert_eq!(count(&c, "eth_getCode"), 1, "the token's code only");
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_token_checks() {
    let (s, seed, c, _) = one("B:", 1).await;
    assert_eq!(s.confidential().pqz_balance(req(&seed, 1, 0)).await.unwrap().amount, "257");
    // R5: not a PQZ token of this factory
    let t = a20(TOKEN);
    let mut tw = [0u8; 32];
    tw[12..].copy_from_slice(&t);
    let slot = add(&map(&tw, &be(8)), 1);
    for (class, kind) in [(0u8, 4u8), (1, 2), (1, 6)] {
        let mut rec = [0u8; 32];
        rec[29] = kind;
        rec[31] = class;
        put(&c, FACTORY, &slot, &rec);
        assert_eq!(code(s.confidential().pqz_balance(req(&seed, 1, 0)).await), "TokenUncatalogued");
    }
    let mut rec = [0u8; 32];
    rec[29] = 12;
    rec[31] = 1;
    put(&c, FACTORY, &slot, &rec);
    assert_eq!(s.confidential().pqz_balance(req(&seed, 1, 0)).await.unwrap().amount, "257", "NORMAL_PQZ_REGULATED");
    // T16-b: `proofStore` read from slot 0's storage word, NONE / LOG; another value is a release before 3h
    let mut slot0 = [0u8; 32];
    slot0[32 - 23 - 1] = 1;
    put(&c, TOKEN, &root(), &slot0);
    assert_eq!(s.confidential().pqz_balance(req(&seed, 1, 0)).await.unwrap().amount, "257", "LOG");
    slot0[32 - 23 - 1] = 2;
    put(&c, TOKEN, &root(), &slot0);
    assert_eq!(code(s.confidential().pqz_balance(req(&seed, 1, 0)).await), "TokenUncatalogued");
    assert_eq!(count(&c, "eth_call"), 0);
    // the module reaches no view
    let src = include_str!("../src/confidential/pqz.rs");
    for v in ["call_at(", "call_tx(", "raw_read", "simulate", "eth_call("] {
        assert!(!src.contains(v), "pqz.rs uses {v}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_leg_of_another_key_refused() {
    let (s, seed, c, r) = one("B:", 1).await;
    assert_eq!(s.confidential().pqz_balance(req(&seed, 1, 0)).await.unwrap().amount, "257");
    let ua = ua_of(&s, &seed, 1).await;
    let slot = map(&be(0), &map(&ua, &be(2)));
    let good = w(&r["request"]["keyRecord"]);
    // not proven; no record; the key of another index (the handle's key is not the registry's)
    let mut k = good;
    k[11] = 0;
    put(&c, REGISTRY, &slot, &k);
    assert_eq!(code(s.confidential().pqz_balance(req(&seed, 1, 0)).await), "LegKeyMismatch");
    put(&c, REGISTRY, &slot, &[0; 32]);
    assert_eq!(code(s.confidential().pqz_balance(req(&seed, 1, 0)).await), "LegKeyMismatch");
    put(&c, REGISTRY, &slot, &good);
    let c2 = fake();
    let url = serve(c2.clone()).await;
    let (s2, seed2) = sdk(profile(vec![endpoint(&url)])).await;
    // index 2's UA holding index 1's account words: its handle (index 2) is not the registered key
    pqz_state(&c2, &ua_of(&s2, &seed2, 2).await, &r);
    assert_eq!(code(s2.confidential().pqz_balance(req(&seed2, 2, 0)).await), "LegKeyMismatch");
    // a signing key that cannot hold a PQZ key
    let mut q = req(&seed, 1, 0);
    q.signer = KeyRef::Ua {
        seed: seed.clone(),
        kind: 0x0108,
        account: 0,
        index: 1,
    };
    assert_eq!(code(s.confidential().pqz_balance(q).await), "Argument");
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_word_failure_never_fails_over() {
    // control: one read's requests
    let (s, seed, c, r) = one("B:", 1).await;
    c.lock().unwrap().requests.clear();
    s.confidential().pqz_balance(req(&seed, 1, 0)).await.unwrap();
    let words = count(&c, "eth_getStorageAt");
    // the first endpoint's pending credit blob is cut short: the facade refuses the words after the pool returned; the
    // second endpoint is never asked
    let (a, b) = (fake(), fake());
    let (ua, ub) = (serve(a.clone()).await, serve(b.clone()).await);
    let (s, seed) = sdk(profile(vec![endpoint(&ua), endpoint(&ub)])).await;
    let holder = ua_of(&s, &seed, 1).await;
    pqz_state(&a, &holder, &r);
    pqz_state(&b, &holder, &r);
    let blob = r["request"]["blobs"][1]["address"].as_str().unwrap().to_string();
    let short = a.lock().unwrap().code[&blob][..200].to_string();
    a.lock().unwrap().code.insert(blob, short);
    a.lock().unwrap().requests.clear();
    assert_eq!(code(s.confidential().pqz_balance(req(&seed, 1, 0)).await), "Argument");
    assert_eq!(b.lock().unwrap().requests.len(), 0, "no request to the next endpoint");
    assert_eq!(count(&a, "eth_getStorageAt"), words, "one read, never a second");
}
