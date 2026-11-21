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
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
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
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
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
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![],
    }
}

async fn sdk(p: ChainProfile) -> (Arc<Sdk>, String) {
    let (s, seed, _) = sdk_with(p).await;
    (s, seed)
}

/// [`sdk`] with its store (the operations' rows).
async fn sdk_with(p: ChainProfile) -> (Arc<Sdk>, String, Arc<MemoryStore>) {
    let store = MemoryStore::new();
    let s = Sdk::open(SdkConfig {
        profiles: vec![p],
        store: store.clone(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let sec = |t: &str| {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(t.as_bytes().to_vec())).unwrap())
    };
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
    (s, seed, store)
}

fn put(c: &Fake, who: &str, slot: &W, word: &W) {
    c.lock()
        .unwrap()
        .storage
        .insert((who.to_ascii_lowercase(), hx(slot)), hx(word));
}

/// The shared row `name` of `wallet_state.json` at this build's set.
fn row(name: &str) -> Value {
    let set = scaas_ua::facade::pqz::pqz_set().name;
    let p = format!(
        "{}/../../smartcontracts/vectors/pqz/{set}/wallet_state.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"].as_str().unwrap().starts_with(name))
        .unwrap()
        .clone()
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
    c.lock()
        .unwrap()
        .code
        .insert(TOKEN.into(), hx(&clone_runtime(&a20(IMPL), &env)));
    let root = root();
    put(c, TOKEN, &add(&root, 2), &w(&q["psid"]));
    put(
        c,
        REGISTRY,
        &map(&be(v), &map(ua, &be(2))),
        &w(&q["keyRecord"]),
    );
    put(c, REGISTRY, &map(ua, &be(17)), &w(&q["keyVersions"]));
    let base = map(&be(v), &map(ua, &add(&root, 8)));
    for (i, a) in q["account"].as_array().unwrap().iter().enumerate() {
        put(c, TOKEN, &add(&base, i as u64), &w(a));
    }
    put(
        c,
        TOKEN,
        &map(ua, &add(&root, 12)),
        &w(&q["sendCounterWord"]),
    );
    for e in q["pending"].as_array().unwrap() {
        put(
            c,
            TOKEN,
            &map(&be(e["index"].as_u64().unwrap()), &add(&base, 4)),
            &w(&e["word"]),
        );
    }
    for (i, a) in q["accWords"].as_array().unwrap().iter().enumerate() {
        put(c, TOKEN, &add(&add(&base, 5), i as u64), &w(a));
    }
    for b in q["blobs"].as_array().unwrap() {
        c.lock().unwrap().code.insert(
            b["address"].as_str().unwrap().to_ascii_lowercase(),
            b["code"].as_str().unwrap().into(),
        );
    }
}

/// The holder's UA (the signing key's of the `pq_kat` seed, `account` 0, `index`).
async fn ua_of(_: &Arc<Sdk>, _: &str, index: u32) -> W {
    scaas_ua::wallet::Wallet::from_mnemonic(PQ_KAT, "")
        .unwrap()
        .ua_key(KIND, 0, index)
        .unwrap()
        .ua()
        .unwrap()
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

/// Review F2 (CTR-UA-70): the reading layers' only `eth_call`s are the line's address reads on the bound registry,
/// `holderOf(bytes32)` and `kindHome(uint16)`; every confidential word stays a storage read.
fn only_line_calls(c: &Fake) {
    for r in log(c).iter().filter(|r| r["method"] == "eth_call") {
        let p = &r["params"][0];
        let data = p["input"]
            .as_str()
            .or(p["data"].as_str())
            .unwrap_or_default();
        assert!(
            data.starts_with("0xfe6a9a8c") || data.starts_with("0x0b2eb5cc"),
            "an eth_call other than holderOf / kindHome: {data}"
        );
        assert_eq!(
            p["to"].as_str().unwrap_or_default().to_ascii_lowercase(),
            REGISTRY
        );
    }
}

/// `holderOf(ua)`'s answer on the bound registry: `(holder, kind, pqzHome)`.
fn holder_answer(c: &Fake, ua: &W, holder: &str, kind: u16, home: &str) {
    let mut a = [0u8; 96];
    a[12..32].copy_from_slice(&a20(holder));
    a[62..64].copy_from_slice(&kind.to_be_bytes());
    a[76..96].copy_from_slice(&a20(home));
    c.lock().unwrap().answers.push((
        REGISTRY.into(),
        format!("0xfe6a9a8c{}", &hx(ua)[2..]),
        hx(&a),
    ));
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
        let b = s
            .confidential()
            .pqz_balance(req(&seed, index, v))
            .await
            .unwrap();
        assert_eq!(b.amount, r["value"].to_string(), "{name}");
        only_line_calls(&c);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn set_mismatch_before_parse() {
    // control
    let (s, seed, c, _) = one("B:", 1).await;
    s.confidential()
        .pqz_balance(req(&seed, 1, 0))
        .await
        .unwrap();
    // another set's psid and account words that do not parse: the set's name, and no account word read
    let root = root();
    let mut other = w(&row("B:")["request"]["psid"]);
    other[0] ^= 1;
    put(&c, TOKEN, &add(&root, 2), &other);
    let ua = ua_of(&s, &seed, 1).await;
    put(
        &c,
        TOKEN,
        &map(&be(0), &map(&ua, &add(&root, 8))),
        &[0xff; 32],
    );
    c.lock().unwrap().requests.clear();
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
        "PqzSetMismatch"
    );
    assert_eq!(
        count(&c, "eth_getStorageAt"),
        2,
        "the factory record and psid only"
    );
    assert_eq!(count(&c, "eth_getCode"), 1, "the token's code only");
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_token_checks() {
    let (s, seed, c, _) = one("B:", 1).await;
    assert_eq!(
        s.confidential()
            .pqz_balance(req(&seed, 1, 0))
            .await
            .unwrap()
            .amount,
        "257"
    );
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
        assert_eq!(
            code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
            "TokenUncatalogued"
        );
    }
    let mut rec = [0u8; 32];
    rec[29] = 12;
    rec[31] = 1;
    put(&c, FACTORY, &slot, &rec);
    assert_eq!(
        s.confidential()
            .pqz_balance(req(&seed, 1, 0))
            .await
            .unwrap()
            .amount,
        "257",
        "NORMAL_PQZ_REGULATED"
    );
    // T15 (review 2026-11-20), R2: a clone of another chain (its `ChainEnv` names another `chain_uid`): `ProfileMismatch`
    let good = c.lock().unwrap().code.get(TOKEN).cloned().unwrap();
    let env = ChainEnv {
        chain_uid: [7; 32],
        registry: a20(REGISTRY),
        gov_router: [0; 20],
        smart_key_account_impl: [0; 20],
        hedera: false,
        deps: vec![],
        params: vec![],
    };
    c.lock()
        .unwrap()
        .code
        .insert(TOKEN.into(), hx(&clone_runtime(&a20(IMPL), &env)));
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
        "ProfileMismatch"
    );
    c.lock().unwrap().code.insert(TOKEN.into(), good);
    // T16-b: `proofStore` read from slot 0's storage word, NONE / LOG; another value is a release before 3h
    let mut slot0 = [0u8; 32];
    slot0[32 - 23 - 1] = 1;
    put(&c, TOKEN, &root(), &slot0);
    assert_eq!(
        s.confidential()
            .pqz_balance(req(&seed, 1, 0))
            .await
            .unwrap()
            .amount,
        "257",
        "LOG"
    );
    slot0[32 - 23 - 1] = 2;
    put(&c, TOKEN, &root(), &slot0);
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
        "TokenUncatalogued"
    );
    only_line_calls(&c);
    // the module reaches no view (the line's address reads are `words.rs`'s two, review F2)
    let src = include_str!("../src/confidential/pqz.rs");
    for v in ["call_at(", "call_tx(", "raw_read", "simulate", "eth_call("] {
        assert!(!src.contains(v), "pqz.rs uses {v}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_leg_of_another_key_refused() {
    let (s, seed, c, r) = one("B:", 1).await;
    assert_eq!(
        s.confidential()
            .pqz_balance(req(&seed, 1, 0))
            .await
            .unwrap()
            .amount,
        "257"
    );
    let ua = ua_of(&s, &seed, 1).await;
    let slot = map(&be(0), &map(&ua, &be(2)));
    let good = w(&r["request"]["keyRecord"]);
    // not proven; no record; the key of another index (the handle's key is not the registry's)
    let mut k = good;
    k[11] = 0;
    put(&c, REGISTRY, &slot, &k);
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
        "LegKeyMismatch"
    );
    put(&c, REGISTRY, &slot, &[0; 32]);
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
        "LegKeyMismatch"
    );
    put(&c, REGISTRY, &slot, &good);
    let c2 = fake();
    let url = serve(c2.clone()).await;
    let (s2, seed2) = sdk(profile(vec![endpoint(&url)])).await;
    // index 2's UA holding index 1's account words: its handle (index 2) is not the registered key
    pqz_state(&c2, &ua_of(&s2, &seed2, 2).await, &r);
    assert_eq!(
        code(s2.confidential().pqz_balance(req(&seed2, 2, 0)).await),
        "LegKeyMismatch"
    );
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
    s.confidential()
        .pqz_balance(req(&seed, 1, 0))
        .await
        .unwrap();
    let words = count(&c, "eth_getStorageAt");
    // the first endpoint's pending credit blob is cut short: the facade refuses the words after the pool returned; the
    // second endpoint is never asked
    let (a, b) = (fake(), fake());
    let (ua, ub) = (serve(a.clone()).await, serve(b.clone()).await);
    let (s, seed) = sdk(profile(vec![endpoint(&ua), endpoint(&ub)])).await;
    let holder = ua_of(&s, &seed, 1).await;
    pqz_state(&a, &holder, &r);
    pqz_state(&b, &holder, &r);
    let blob = r["request"]["blobs"][1]["address"]
        .as_str()
        .unwrap()
        .to_string();
    let short = a.lock().unwrap().code[&blob][..200].to_string();
    a.lock().unwrap().code.insert(blob, short);
    a.lock().unwrap().requests.clear();
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
        "Argument"
    );
    assert_eq!(
        b.lock().unwrap().requests.len(),
        0,
        "no request to the next endpoint"
    );
    assert_eq!(
        count(&a, "eth_getStorageAt"),
        words,
        "one read, never a second"
    );
}

// --- verdicts (spec §9.3; owner 2026-11-19, T16-a, T16-c) ---

/// The verifier's UA key (secp256k1 UA, `pq_kat` account 0, `index`), beside its wallet (a dropped wallet revokes it).
fn verifier_key(index: u32) -> (scaas_ua::wallet::Wallet, scaas_ua::wallet::UaKey) {
    let w = scaas_ua::wallet::Wallet::from_mnemonic(PQ_KAT, "").unwrap();
    let k = w.ua_key(0x0108, 0, index).unwrap();
    (w, k)
}

const VKEYPTR: &str = "0x5ca00000000000000000000000000000000000b9";
const EPOCH: u64 = 3;

/// The token names the verifier of `index` at epoch 3; the registry holds its record (kind 0x0108) and key.
fn name_verifier(c: &Fake, index: u32) {
    let (_w, k) = verifier_key(index);
    let ua = k.ua().unwrap();
    let root = root();
    put(c, TOKEN, &add(&root, 13), &ua);
    put(c, TOKEN, &add(&root, 15), &be(EPOCH));
    let mut r = [0u8; 32];
    r[5..25].copy_from_slice(&a20(VKEYPTR));
    r[30] = 0x01;
    r[31] = 0x08;
    put(c, REGISTRY, &map(&ua, &be(0)), &r);
    let mut code = vec![0u8];
    code.extend(k.key_data());
    c.lock().unwrap().code.insert(VKEYPTR.into(), hx(&code));
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

const STMT: &str = "0x01020304";
const PROOF: &str = "0x0a0b";

/// The verifier's answer: `m` signed by the key of `index` under `pqz-verdict`.
fn answer(m: &Value, index: u32) -> Value {
    let uid: W = unhex(&hash_of(0)).try_into().unwrap();
    // the verdict's own token and chain (a verdict of another token or chain is signed as such: T3)
    let token = a20(m["token"].as_str().unwrap_or(TOKEN));
    let chain = m["chainId"].as_u64().unwrap_or(CHAIN_ID);
    let d = scaas_ua::wallet::pqz_verdict_typed_data(&token, chain, &uid, m)
        .unwrap()
        .digest()
        .unwrap();
    let (_w, k) = verifier_key(index);
    let s = scaas_ua::wallet::ua_sig(&k, None, &scaas_ua::purpose_tag("pqz-verdict").unwrap(), &d)
        .unwrap();
    serde_json::json!({"pqzVerdict": m, "pqzVerdictSig": {"keyData": hx(&s.key_data), "signature": hx(&s.signature), "members": []}})
}

fn verdict_of(psid: &str) -> Value {
    serde_json::json!({"token": TOKEN, "chainId": CHAIN_ID, "proofSystemId": psid,
        "statementHash": hx(&keccak256(&unhex(STMT))), "proofHash": hx(&keccak256(&unhex(PROOF))),
        "pqzVerifierEpoch": EPOCH, "validUntil": now() + 600})
}

fn vreq() -> scaas_sdk::confidential::PqzVerdictRequest {
    scaas_sdk::confidential::PqzVerdictRequest {
        chain: "local".into(),
        token: TOKEN.into(),
        op: serde_json::json!({"entry": "mtxConfidentialTransferSingle", "args": {}}),
        statement: STMT.into(),
        proof: PROOF.into(),
    }
}

/// A fake holding row B and naming the verifier of index 7, an SDK whose profile lists `verifiers` (the fake itself when
/// `None`) under `policy`.
async fn verdict_setup(
    verifiers: Option<Vec<String>>,
    policy: scaas_rpc::Policy,
) -> (Arc<Sdk>, Fake, String) {
    let c = fake();
    let url = serve(c.clone()).await;
    let mut p = profile(vec![endpoint(&url)]);
    p.verifiers = verifiers
        .unwrap_or_else(|| vec![url.clone()])
        .iter()
        .map(|u| endpoint(u))
        .collect();
    p.verifier_policy = policy;
    let (s, seed) = sdk(p).await;
    let r = row("B:");
    pqz_state(&c, &ua_of(&s, &seed, 1).await, &r);
    name_verifier(&c, 7);
    (s, c, r["request"]["psid"].as_str().unwrap().to_string())
}

#[tokio::test(flavor = "multi_thread")]
async fn verdict_checked_before_attach() {
    let (s, c, psid) = verdict_setup(None, scaas_rpc::Policy::Failover).await;
    // control: the token's verifier signs the verdict of this statement and proof
    c.lock().unwrap().verdict = Some((200, answer(&verdict_of(&psid), 7)));
    let v = s.confidential().request_verdict(vreq()).await.unwrap();
    assert_eq!(
        v["pqzVerdict"]["statementHash"],
        serde_json::json!(hx(&keccak256(&unhex(STMT))))
    );
    assert_eq!(v["pqzVerdict"]["pqzVerifierEpoch"], EPOCH);
    assert_eq!(
        v["sig"]["keyData"],
        serde_json::json!(hx(&verifier_key(7).1.key_data()))
    );
    let body: Value = serde_json::from_str(&c.lock().unwrap().verdict_bodies[0]).unwrap();
    assert_eq!(
        body["pqzVerifierEpoch"], EPOCH,
        "the epoch read at the final block"
    );
    assert_eq!(
        (
            body["statement"].as_str(),
            body["proof"].as_str(),
            body["chainId"].as_u64()
        ),
        (Some(STMT), Some(PROOF), Some(CHAIN_ID))
    );
    // signed by another UA; another statement, proof, epoch, token, set; past its validUntil: refused, nothing attached
    let refuse = |m: Value, index: u32| {
        let c = c.clone();
        let s = s.clone();
        async move {
            c.lock().unwrap().verdict = Some((200, answer(&m, index)));
            code(s.confidential().request_verdict(vreq()).await)
        }
    };
    assert_eq!(
        refuse(verdict_of(&psid), 8).await,
        "VerdictRefused",
        "another signer"
    );
    // the verifier's own key, its signature over another verdict
    let mut other = verdict_of(&psid);
    other["validUntil"] = serde_json::json!(now() + 900);
    let mut a = answer(&other, 7);
    a["pqzVerdict"] = verdict_of(&psid);
    c.lock().unwrap().verdict = Some((200, a));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused",
        "a signature over another verdict"
    );
    for (k, v) in [
        ("statementHash", serde_json::json!(hx(&[1; 32]))),
        ("proofHash", serde_json::json!(hx(&[2; 32]))),
        ("pqzVerifierEpoch", serde_json::json!(EPOCH + 1)),
        ("proofSystemId", serde_json::json!(hx(&[3; 32]))),
        ("validUntil", serde_json::json!(now() - 1)),
        // T3 (review 2026-11-20): a verdict of another token or another chain, signed by the verifier's own key
        ("token", serde_json::json!(hx(&[4; 20]))),
        ("chainId", serde_json::json!(CHAIN_ID + 1)),
    ] {
        let mut m = verdict_of(&psid);
        m[k] = v;
        assert_eq!(refuse(m, 7).await, "VerdictRefused", "{k}");
    }
    // a derived-key verifier's signature with members (an `msig` form): refused; the same answer without them is the control
    let mut a = answer(&verdict_of(&psid), 7);
    a["pqzVerdictSig"]["members"] = serde_json::json!([{"index": 0, "members": [], "sig": "0x00"}]);
    c.lock().unwrap().verdict = Some((200, a));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused",
        "members"
    );
    assert_eq!(
        refuse(verdict_of(&psid), 7).await,
        "Ok",
        "control: no members"
    );
    // the right key whose registry record names another kind
    let ua = verifier_key(7).1.ua().unwrap();
    let good: W = w(&serde_json::json!(c.lock().unwrap().storage
        [&(REGISTRY.to_ascii_lowercase(), hx(&map(&ua, &be(0))))]
        .clone()));
    let mut rec = good;
    rec[31] = 0x07;
    put(&c, REGISTRY, &map(&ua, &be(0)), &rec);
    assert_eq!(
        refuse(verdict_of(&psid), 7).await,
        "VerdictRefused",
        "the record's kind"
    );
    put(&c, REGISTRY, &map(&ua, &be(0)), &good);
    // the record's key pointer holding another key: the signer is checked against the registry's record (T16-c)
    let kc = c.lock().unwrap().code[VKEYPTR].clone();
    let mut other = vec![0u8];
    other.extend(verifier_key(8).1.key_data());
    c.lock().unwrap().code.insert(VKEYPTR.into(), hx(&other));
    assert_eq!(
        refuse(verdict_of(&psid), 7).await,
        "VerdictRefused",
        "the record's key"
    );
    // M6 (review 2026-11-20): that other key also signs: the key data matches the pointer and the signature verifies, but
    // the key is not the verifier UA's (its derived id differs): refused
    assert_eq!(
        refuse(verdict_of(&psid), 8).await,
        "VerdictRefused",
        "a key that is not the verifier's"
    );
    c.lock().unwrap().code.insert(VKEYPTR.into(), kc);
    assert_eq!(refuse(verdict_of(&psid), 7).await, "Ok", "control again");
    let cc = c.lock().unwrap();
    assert!(cc.sent.is_empty() && cc.bodies.is_empty(), "nothing sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn verdict_unreachable_sends_nothing() {
    let (s, c, psid) = verdict_setup(None, scaas_rpc::Policy::Failover).await;
    // unreachable (503), a refusal (4xx): VerdictRefused
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused"
    );
    c.lock().unwrap().verdict = Some((
        422,
        serde_json::json!({"error": "PROOF_INVALID", "detail": "x"}),
    ));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused"
    );
    // a token naming no verifier: no verifier is asked
    c.lock().unwrap().verdict = Some((200, answer(&verdict_of(&psid), 7)));
    put(&c, TOKEN, &add(&root(), 13), &[0; 32]);
    let n = c.lock().unwrap().verdict_bodies.len();
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused"
    );
    assert_eq!(c.lock().unwrap().verdict_bodies.len(), n, "no request");
    name_verifier(&c, 7);
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "Ok",
        "control"
    );
    assert!(
        c.lock().unwrap().sent.is_empty() && c.lock().unwrap().bodies.is_empty(),
        "nothing sent"
    );
    // a profile listing no verifier
    let (s2, _, _) = verdict_setup(Some(vec![]), scaas_rpc::Policy::Failover).await;
    assert_eq!(
        code(s2.confidential().request_verdict(vreq()).await),
        "VerdictRefused"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn verdict_verifiers_strict_majority() {
    // T16-a: the verifier list's own policy; two verifiers answering two different verdicts have no majority
    let (a, b) = (fake(), fake());
    let (ua, ub) = (serve(a.clone()).await, serve(b.clone()).await);
    let (s, c, psid) = verdict_setup(Some(vec![ua, ub]), scaas_rpc::Policy::StrictMajority).await;
    let m = verdict_of(&psid);
    a.lock().unwrap().verdict = Some((200, answer(&m, 7)));
    b.lock().unwrap().verdict = Some((200, answer(&m, 7)));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "Ok",
        "control: both agree"
    );
    // F14 (review 2026-11-20): another `validUntil` (each verifier's own clock) is the same verdict: a majority
    let mut m2 = m.clone();
    m2["validUntil"] = serde_json::json!(now() + 900);
    b.lock().unwrap().verdict = Some((200, answer(&m2, 7)));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "Ok",
        "validUntil apart"
    );
    // another verdict (another statement) has no majority
    let mut m3 = m.clone();
    m3["statementHash"] = serde_json::json!(format!("0x{}", "ab".repeat(32)));
    b.lock().unwrap().verdict = Some((200, answer(&m3, 7)));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused"
    );
    assert!(
        c.lock().unwrap().verdict_bodies.is_empty(),
        "the chain's endpoint is no verifier here"
    );
}

// --- the PQZ rows without a proof (spec §9.2, §21) ---

fn env() -> scaas_sdk::wallet::Envelope {
    scaas_sdk::wallet::Envelope {
        valid_until: now() + 3600,
        mode: 0,
        relayer: None,
        fee: "0".into(),
        fee_recipient: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_plain_pairs() {
    use scaas_sdk::confidential::{PqzAccountOp, PqzShield, PqzWrapShield};
    let c = fake();
    let url = serve(c.clone()).await;
    let mut pr = profile(vec![endpoint(&url)]);
    pr.gateways = vec![endpoint(&url)];
    pr.gas = scaas_sdk::GasRows {
        base: ["mtxShield", "mtxPrepareAcc", "mtxRollOver"]
            .iter()
            .flat_map(|e| {
                [true, false].map(|fresh| scaas_sdk::GasBase {
                    entry: (*e).into(),
                    kind: "pqz".into(),
                    fresh,
                    gas: 100_000,
                    per_byte: None,
                    save: None,
                    fee_extra: None,
                    ua_extra: None,
                    per_item: None,
                    regular: None,
                })
            })
            .collect(),
        verify: vec![scaas_sdk::GasVerify {
            line: Default::default(),
            signer: KIND,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        }],
    };
    let (s, seed) = sdk(pr).await;
    {
        let mut cc = c.lock().unwrap();
        cc.timestamp = now();
        cc.domains
            .insert(TOKEN.into(), ("SCaaS PqzToken".into(), hash_of(0)));
    }
    let ua = hx(&ua_of(&s, &seed, 1).await);
    let cf = s.confidential();
    let acct = |value: &str| PqzAccountOp {
        signer: signer(&seed, 1),
        chain: "local".into(),
        token: TOKEN.into(),
        batch: "0".into(),
        ua: ua.clone(),
        key_version: 2,
        value: value.into(),
        envelope: env(),
    };
    let ps = [
        cf.prepare_pqz_shield(PqzShield {
            signer: signer(&seed, 1),
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            to_ua: ua.clone(),
            amount: "4".into(),
            envelope: env(),
        })
        .await
        .unwrap(),
        cf.prepare_pqz_prepare_acc(acct("1")).await.unwrap(),
        cf.prepare_pqz_roll_over(acct("3")).await.unwrap(),
    ];
    for (p, (entry, field)) in ps.iter().zip([
        ("mtxShield", ("amount", "4")),
        ("mtxPrepareAcc", ("half", "1")),
        ("mtxRollOver", ("n", "3")),
    ]) {
        assert_eq!(p.entry(), entry);
        let has = |n: &str, v: &str| p.review().iter().any(|f| f.name == n && f.value == v);
        assert!(has("from", &ua) && has(field.0, field.1), "{entry}");
        if entry != "mtxShield" {
            assert!(has("keyVersion", "2") && has("ua", &ua), "{entry}");
        }
    }
    // each signed under its check by the ML-DSA UA and sent: the gateway receives the entry
    for (n, p) in ps.into_iter().enumerate() {
        let entry = p.entry();
        let q = s
            .op()
            .quote(p.clone(), scaas_sdk::op::SubmitPath::Gateway)
            .await
            .unwrap();
        s.op().submit(p, q).await.unwrap();
        let mut body = Value::Null;
        for _ in 0..100 {
            if let Some(b) = c.lock().unwrap().bodies.get(n) {
                body = serde_json::from_str(b).unwrap();
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(body["op"]["entry"], serde_json::json!(entry));
    }
    let p = cf
        .prepare_pqz_wrap_shield(PqzWrapShield {
            signer: KeyRef::Native {
                seed: seed.clone(),
                network: "evm".into(),
                index: 0,
            },
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            underlying: "0x5ca00000000000000000000000000000000000a1".into(),
            amount_in: "4".into(),
            to_ua: ua.clone(),
            envelope: env(),
        })
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxWrapShield");
    // another domain (a Zether token's) is not a PQZ pair, even for a struct both domains have
    c.lock()
        .unwrap()
        .domains
        .insert(TOKEN.into(), ("SCaaS ZetherToken".into(), hash_of(0)));
    assert_eq!(code(cf.prepare_pqz_roll_over(acct("3")).await), "Argument");
    let shield = PqzShield {
        signer: signer(&seed, 1),
        chain: "local".into(),
        token: TOKEN.into(),
        batch: "0".into(),
        to_ua: ua.clone(),
        amount: "4".into(),
        envelope: env(),
    };
    assert_eq!(code(cf.prepare_pqz_shield(shield).await), "Argument");
}

// --- the PQZ debits (spec §9.2, §9.3; plan T16 part 3) ---

const DEBITS: [&str; 6] = [
    "mtxConfidentialTransferSingle",
    "mtxConfidentialTransferSingleCompact",
    "mtxConfidentialTransfer",
    "mtxConfidentialTransferCompact",
    "mtxUnshield",
    "mtxUnshieldUnwrap",
];

/// The verifier of index 7 answering from the statement and proof it was sent (a verdict over exactly those).
fn verifier_answers(body: &Value) -> (u16, Value) {
    let (st, pr) = (
        unhex(body["statement"].as_str().unwrap()),
        unhex(body["proof"].as_str().unwrap()),
    );
    let m = serde_json::json!({"token": TOKEN, "chainId": CHAIN_ID, "proofSystemId": hx(&st[32..64]),
        "statementHash": hx(&keccak256(&st)), "proofHash": hx(&keccak256(&pr)), "pqzVerifierEpoch": EPOCH,
        "validUntil": now() + 600});
    (200, answer(&m, 7))
}

/// A fake holding B (index 1: 257 units at key version 0) and A (index 0, its current key version 1), a gateway, the PQZ
/// token's domain, the debits' gas rows. `offchain`: the token verifies off chain (`pqzVerifyMode` 1, scope 0), each holder's
/// scoped record holding its key, the verifier of index 7 named and answering from what it is sent.
async fn debit_setup(offchain: bool) -> (Arc<Sdk>, String, Fake, W, W, Arc<MemoryStore>) {
    let c = fake();
    let url = serve(c.clone()).await;
    let mut pr = profile(vec![endpoint(&url)]);
    pr.gateways = vec![endpoint(&url)];
    if offchain {
        pr.verifiers = vec![endpoint(&url)];
    }
    pr.gas = scaas_sdk::GasRows {
        base: DEBITS
            .iter()
            .flat_map(|e| {
                [true, false].map(|fresh| scaas_sdk::GasBase {
                    entry: (*e).into(),
                    kind: "pqz".into(),
                    fresh,
                    gas: 100_000,
                    per_byte: None,
                    save: None,
                    fee_extra: None,
                    ua_extra: None,
                    per_item: None,
                    regular: None,
                })
            })
            .collect(),
        verify: vec![scaas_sdk::GasVerify {
            line: Default::default(),
            signer: KIND,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        }],
    };
    let (s, seed, store) = sdk_with(pr).await;
    let (a, b) = (ua_of(&s, &seed, 0).await, ua_of(&s, &seed, 1).await);
    pqz_state(&c, &a, &row("A v1"));
    pqz_state(&c, &b, &row("B:"));
    {
        let mut cc = c.lock().unwrap();
        cc.timestamp = now();
        cc.domains
            .insert(TOKEN.into(), ("SCaaS PqzToken".into(), hash_of(0)));
    }
    if offchain {
        let mut slot0 = [0u8; 32];
        slot0[32 - 22 - 1] = 1;
        put(&c, TOKEN, &root(), &slot0);
        for (ua, r) in [(&a, row("A v1")), (&b, row("B:"))] {
            let q = &r["request"];
            let v = q["keyVersion"].as_u64().unwrap();
            let scope = [0u8; 32];
            put(
                &c,
                REGISTRY,
                &map(&be(v), &map(&scope, &map(ua, &be(20)))),
                &w(&q["keyRecord"]),
            );
            put(
                &c,
                REGISTRY,
                &map(&scope, &map(ua, &be(24))),
                &w(&q["keyVersions"]),
            );
        }
        name_verifier(&c, 7);
        c.lock().unwrap().verdict_fn = Some(verifier_answers);
    }
    (s, seed, c, a, b, store)
}

/// Submits `p` through the gateway (NODE-GW-08: a PQZ debit fits the job submission's body cap, P-T16-8); the job (`op`) the
/// gateway received, equal to the operation's row in the store, its body within `OP_BODY_MAX`.
async fn relay(
    s: &Arc<Sdk>,
    c: &Fake,
    store: &Arc<MemoryStore>,
    p: Arc<scaas_sdk::op::Prepared>,
) -> (String, Value) {
    use scaas_sdk::vault::SecureStore;
    let before = c.lock().unwrap().bodies.len();
    let q = s
        .op()
        .quote(p.clone(), scaas_sdk::op::SubmitPath::Gateway)
        .await
        .unwrap();
    let op = s.op().submit(p, q).await.unwrap();
    let mut body = None;
    for _ in 0..100 {
        if let Some(b) = c.lock().unwrap().bodies.get(before) {
            body = Some(b.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let body = body.expect("the gateway received the debit");
    assert!(body.len() <= scaas_rpc::node::OP_BODY_MAX);
    let body: Value = serde_json::from_str(&body).unwrap();
    let item = store
        .get("sdk.state".into(), "test".into())
        .await
        .unwrap()
        .unwrap();
    let st: Value = serde_json::from_slice(&item.bytes).unwrap();
    let row = st["ops"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["op"] == serde_json::json!(op))
        .unwrap()
        .clone();
    assert_eq!(
        body["op"], row["op_json"],
        "the row's job is what the gateway took"
    );
    (op, body["op"].clone())
}

/// The reviewed `PqzAuth` message of `p` and its typed digest in the token's domain.
fn auth_of(p: &scaas_sdk::op::Prepared) -> (Value, W) {
    let mut m = serde_json::Map::new();
    for f in p.review() {
        if let Some(k) = f.name.strip_prefix("pqzAuth.") {
            let v = match k {
                "op" => serde_json::json!(f.value.parse::<u64>().unwrap()),
                "auditorOn" => serde_json::json!(f.value == "true"),
                _ => serde_json::json!(f.value),
            };
            m.insert(k.into(), v);
        }
    }
    let m = Value::Object(m);
    let uid: W = unhex(&hash_of(0)).try_into().unwrap();
    let td = scaas_ua::wallet::scaas_typed_data(
        "PqzAuth",
        Some("SCaaS PqzToken"),
        &a20(TOKEN),
        CHAIN_ID,
        &uid,
        &m,
    )
    .unwrap();
    (m, td.digest().unwrap())
}

/// The holder's `pqzAuth` in the job verifies over `digest` under `zether-auth` (P-T16-1), never under `metatx`.
fn pqz_auth_ok(op: &Value, digest: &W) {
    let a = &op["args"]["pqzAuth"];
    // the holder's key (index 1): an ML-DSA UA's signature carries no key data, the registry holds it
    let kd = scaas_ua::wallet::Wallet::from_mnemonic(PQ_KAT, "")
        .unwrap()
        .ua_key(KIND, 0, 1)
        .unwrap()
        .key_data();
    let sig = unhex(a["signature"].as_str().unwrap());
    let ok = |p: &str| {
        let m = scaas_ua::ua_message(KIND, &scaas_ua::purpose_tag(p).unwrap(), digest).unwrap();
        scaas_ua::verify::verify(KIND, &kd, &m, &sig, false, false)
    };
    assert!(ok("zether-auth"), "pqzAuth under zether-auth: {a}");
    assert!(!ok("metatx"), "never metatx");
}

fn transfer(seed: &str, to: &W, amount: &str) -> scaas_sdk::confidential::PqzTransfer {
    scaas_sdk::confidential::PqzTransfer {
        signer: signer(seed, 1),
        chain: "local".into(),
        token: TOKEN.into(),
        batch: "0".into(),
        key_version: 0,
        to_ua: hx(to),
        amount: amount.into(),
        valid_until_block: 1000,
        envelope: env(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_transfer_single_pairs() {
    let (s, seed, c, a, b, store) = debit_setup(false).await;
    let cf = s.confidential();
    // a balance below the amount: refused before anything is signed or sent
    assert_eq!(
        code(cf.prepare_pqz_transfer(transfer(&seed, &a, "258")).await),
        "Argument"
    );
    for (n, compact) in [false, true].into_iter().enumerate() {
        let r = transfer(&seed, &a, "100");
        let p = if compact {
            cf.prepare_pqz_transfer_compact(r).await
        } else {
            cf.prepare_pqz_transfer(r).await
        }
        .unwrap();
        assert_eq!(p.entry(), DEBITS[n]);
        let rv = p.review();
        let req = |k: &str| {
            rv.iter()
                .find(|f| f.name == k)
                .map(|f| (f.value.clone(), f.source))
        };
        assert_eq!(
            req("request.amount"),
            Some(("100".into(), scaas_sdk::op::Source::Request))
        );
        assert_eq!(
            req("request.to"),
            Some((hx(&a), scaas_sdk::op::Source::Request))
        );
        let (m, d) = auth_of(&p);
        assert_eq!(
            (m["from"].as_str(), m["to"].as_str(), m["op"].as_u64()),
            (Some(hx(&b).as_str()), Some(hx(&a).as_str()), Some(1))
        );
        let (_, op) = relay(&s, &c, &store, p).await;
        assert_eq!(op["entry"], serde_json::json!(DEBITS[n]));
        pqz_auth_ok(&op, &d);
        let args = &op["args"]["args"];
        assert_eq!(
            (args["fromUA"].as_str(), args["toUA"].as_str()),
            (Some(hx(&b).as_str()), Some(hx(&a).as_str()))
        );
        assert_eq!(
            args["p"].as_str(),
            Some(m["p"].as_str().unwrap()),
            "the proof's p"
        );
        // commit-reveal keeps the 42-byte sealed memo, the bundle none; no auditor on this token
        let memo = unhex(args["sealedMemo"].as_str().unwrap()).len();
        assert_eq!(memo, if compact { 42 } else { 0 });
        assert_eq!(args["vAuditor"], serde_json::json!("0x"));
        assert!(
            op["args"].get("pqz_verdict").is_none(),
            "no verdict on a PRECOMPILE token"
        );
    }
    // the recipient's key pointer holding another key size: unregistered as the token reads it
    let ar = row("A v1");
    let ptr = format!("0x{}", hex_tail(&w(&ar["request"]["keyRecord"])));
    let good = c.lock().unwrap().code[&ptr].clone();
    c.lock().unwrap().code.insert(ptr.clone(), "0x00".into());
    assert_eq!(
        code(cf.prepare_pqz_transfer(transfer(&seed, &a, "100")).await),
        "ReceiverUnregistered"
    );
    c.lock().unwrap().code.insert(ptr, good);
}

/// The low 20 bytes of a word, hex without `0x`.
fn hex_tail(w: &W) -> String {
    hx(&w[12..])[2..].to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_transfer_multi_pairs() {
    use scaas_sdk::confidential::{PqzLeg, PqzTransferMulti};
    let (s, seed, c, a, b, store) = debit_setup(false).await;
    let cf = s.confidential();
    let r = || PqzTransferMulti {
        signer: signer(&seed, 1),
        chain: "local".into(),
        token: TOKEN.into(),
        batch: "0".into(),
        key_version: 0,
        legs: vec![PqzLeg {
            to_ua: hx(&a),
            amount: "60".into(),
        }],
        decoy_fee: "0".into(),
        valid_until_block: 1000,
        envelope: env(),
    };
    for (n, compact) in [false, true].into_iter().enumerate() {
        let p = if compact {
            cf.prepare_pqz_transfer_multi_compact(r()).await
        } else {
            cf.prepare_pqz_transfer_multi(r()).await
        }
        .unwrap();
        assert_eq!(p.entry(), DEBITS[2 + n]);
        let (m, d) = auth_of(&p);
        assert_eq!(
            (m["from"].as_str(), m["op"].as_u64()),
            (Some(hx(&b).as_str()), Some(7))
        );
        let (_, op) = relay(&s, &c, &store, p).await;
        assert_eq!(op["entry"], serde_json::json!(DEBITS[2 + n]));
        pqz_auth_ok(&op, &d);
        let args = &op["args"]["args"];
        assert_eq!(args["legs"][0]["ua"].as_str(), Some(hx(&a).as_str()));
        assert_eq!(
            args["u"].as_array().unwrap().len(),
            1,
            "one randomness group for one leg"
        );
        // the header's recipients hash is the legs' UAs
        assert_eq!(m["to"].as_str(), Some(hx(&keccak256(&a)).as_str()));
        assert_eq!(
            unhex(args["sealedMemo"].as_str().unwrap()).len(),
            if compact { 42 } else { 0 }
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_unshield_pairs() {
    use scaas_sdk::confidential::{PqzUnshield, PqzUnshieldUnwrap};
    let (s, seed, c, _, b, store) = debit_setup(false).await;
    let cf = s.confidential();
    let to = hx(&[3u8; 32]);
    let p = cf
        .prepare_pqz_unshield(PqzUnshield {
            signer: signer(&seed, 1),
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            key_version: 0,
            recipient: to.clone(),
            amount: "7".into(),
            valid_until_block: 1000,
            envelope: env(),
        })
        .await
        .unwrap();
    let under = "0x5ca00000000000000000000000000000000000a1";
    let pu = cf
        .prepare_pqz_unshield_unwrap(PqzUnshieldUnwrap {
            signer: signer(&seed, 1),
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "1".into(),
            key_version: 0,
            underlying: under.into(),
            recipient: to.clone(),
            amount: "7".into(),
            min_out: "5".into(),
            valid_until_block: 1000,
            envelope: env(),
        })
        .await
        .unwrap();
    for (n, p) in [p, pu].into_iter().enumerate() {
        assert_eq!(p.entry(), DEBITS[4 + n]);
        let (m, d) = auth_of(&p);
        assert_eq!(
            (
                m["from"].as_str(),
                m["recipient"].as_str(),
                m["amount"].as_str(),
                m["op"].as_u64()
            ),
            (Some(hx(&b).as_str()), Some(to.as_str()), Some("7"), Some(2))
        );
        let (_, op) = relay(&s, &c, &store, p).await;
        assert_eq!(op["entry"], serde_json::json!(DEBITS[4 + n]));
        pqz_auth_ok(&op, &d);
        if n == 1 {
            assert_eq!(op["args"]["unwrap"]["minOut"].as_str(), Some("5"), "{op}");
            assert_eq!(op["args"]["unwrap"]["underlying"].as_str(), Some(under));
        }
    }
}

/// The verifier-mode token (round 3f): the facade's statement is the one the verifier sees and the holder's `pqzAuth` signs
/// (its header words, `bodyHash` over its body), the arguments are its parts, the envelope word the binding folded by the
/// form, and the checked verdict is attached.
#[tokio::test(flavor = "multi_thread")]
async fn pqz_auth_attached_by_the_facade() {
    use scaas_ua::facade::pqz::{
        bind_mode, envelope_binding, pqz_set, Mode, PqzEnvelope, Verification, V_BYTES,
    };
    let (s, seed, c, a, b, store) = debit_setup(true).await;
    let p = s
        .confidential()
        .prepare_pqz_transfer(transfer(&seed, &a, "100"))
        .await
        .unwrap();
    let asked = c.lock().unwrap().verdict_bodies.clone();
    assert_eq!(
        asked.len(),
        1,
        "the token's verifier asked for this debit's verdict"
    );
    let body: Value = serde_json::from_str(&asked[0]).unwrap();
    let stmt = unhex(body["statement"].as_str().unwrap());
    let (m, d) = auth_of(&p);
    assert_eq!(
        m["bodyHash"].as_str(),
        Some(hx(&keccak256(&stmt[640..])).as_str()),
        "bodyHash over the statement"
    );
    for (k, i) in [
        ("opTag", 0),
        ("from", 5),
        ("to", 6),
        ("chainUid", 16),
        ("binding", 17),
        ("memoHash", 19),
    ] {
        assert_eq!(
            m[k].as_str(),
            Some(hx(&stmt[i * 32..i * 32 + 32]).as_str()),
            "{k}"
        );
    }
    let (_, op) = relay(&s, &c, &store, p).await;
    pqz_auth_ok(&op, &d);
    // the arguments are the statement's parts: header ‖ pk_f ‖ pk_t ‖ T ‖ u ‖ v_t ‖ v_f
    let (pk, v) = (pqz_set().pk_len, V_BYTES);
    let off = 640 + 2 * pk + pk + v;
    let args = &op["args"]["args"];
    for (k, at, n) in [
        ("u", off, pk),
        ("vTo", off + pk, v),
        ("vFrom", off + pk + v, v),
    ] {
        assert_eq!(
            args[k].as_str(),
            Some(hx(&stmt[at..at + n]).as_str()),
            "{k}"
        );
    }
    assert_eq!(
        args["salt"].as_str(),
        Some(hx(&stmt[18 * 32 + 16..19 * 32]).as_str())
    );
    // the envelope word: the job's envelope bound (`envelope_binding`), then the form's mode folded (BUNDLE, OFFCHAIN fee 0)
    let e = &op["envelope"];
    let word = |x: &Value| -> W {
        let n: u128 = x
            .as_str()
            .map(|s| s.parse().unwrap())
            .unwrap_or_else(|| x.as_u64().unwrap().into());
        be(n as u64)
    };
    let zero = [0u8; 32];
    let pe = PqzEnvelope {
        from: b,
        batch: word(&e["batch"]),
        nonce: word(&e["nonce"]),
        valid_until: word(&e["validUntil"]),
        mode: word(&e["mode"]),
        relayer: zero,
        fee: word(&e["fee"]),
        fee_recipient: zero,
    };
    let uid: W = unhex(&hash_of(0)).try_into().unwrap();
    let binding = envelope_binding(CHAIN_ID, &uid, &a20(TOKEN), &pe);
    let want = bind_mode(
        &binding,
        Mode::Bundle,
        Verification::Offchain { verifier_fee: 0 },
    );
    assert_eq!(
        &stmt[17 * 32..18 * 32],
        &want[..],
        "the header's envelope word"
    );
    // the verdict the token's verifier signed over this statement and proof, checked and attached
    let pv = &op["args"]["pqz_verdict"];
    assert_eq!(pv["pqzVerifierEpoch"], serde_json::json!(EPOCH), "{op}");
    assert_eq!(body["proof"], op["args"]["proof"]);
    // a verifier that signs another statement: refused, nothing sent
    let n = c.lock().unwrap().bodies.len();
    c.lock().unwrap().verdict_fn = None;
    c.lock().unwrap().verdict = Some((200, answer(&verdict_of(&hx(&stmt[32..64])), 7)));
    assert_eq!(
        code(
            s.confidential()
                .prepare_pqz_transfer(transfer(&seed, &a, "100"))
                .await
        ),
        "VerdictRefused"
    );
    let c = c.lock().unwrap();
    assert_eq!((c.sent.len(), c.bodies.len()), (0, n), "nothing more sent");
}

/// The proof runs off the async workers: on a one-worker runtime a `seeds()` call answers at once while the proof runs (the
/// words and the lane's nonce read, then no request while the facade proves).
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn proof_runs_off_the_async_workers() {
    use std::time::{Duration, Instant};
    let (s, seed, c, a, _, _) = debit_setup(false).await;
    let base = c.lock().unwrap().requests.len();
    let (s2, seed2) = (s.clone(), seed.clone());
    let job = tokio::spawn(async move {
        s2.confidential()
            .prepare_pqz_transfer(transfer(&seed2, &a, "100"))
            .await
    });
    let mut last = (base, Instant::now());
    while !job.is_finished() {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let n = c.lock().unwrap().requests.len();
        if n != last.0 {
            last = (n, Instant::now());
        } else if n > base && last.1.elapsed() > Duration::from_millis(150) {
            break;
        }
    }
    // the call on the runtime's one worker (the one the debit's task runs on)
    let t0 = Instant::now();
    let s3 = s.clone();
    tokio::spawn(async move { s3.vault().seeds().await })
        .await
        .unwrap()
        .unwrap();
    let took = t0.elapsed();
    assert!(!job.is_finished(), "the proof was still running");
    assert!(
        took < Duration::from_millis(300),
        "seeds answered while the proof ran: {took:?}"
    );
    job.await.unwrap().unwrap();
}

/// A proof of words the chain moved past (another debit after the read block): the node's refusal leaves the operation in
/// flight, never terminal; the user retries with fresh words.
#[tokio::test(flavor = "multi_thread")]
async fn stale_proof_is_not_terminal() {
    let (s, seed, c, a, _, store) = debit_setup(false).await;
    let p = s
        .confidential()
        .prepare_pqz_transfer(transfer(&seed, &a, "100"))
        .await
        .unwrap();
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let q = s
        .op()
        .quote(p.clone(), scaas_sdk::op::SubmitPath::SelfRelay { payer })
        .await
        .unwrap();
    // the chain moved after the read block: the signed debit's simulation reverts
    c.lock().unwrap().call_revert = true;
    let op = s.op().submit(p, q).await.unwrap();
    let mut st = s.op().state(op.clone()).await.unwrap();
    for _ in 0..100 {
        if st
            != (scaas_sdk::op::OpState::InFlight {
                detail: scaas_sdk::op::InFlight::Signed,
            })
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        st = s.op().state(op.clone()).await.unwrap();
    }
    assert_eq!(
        st,
        scaas_sdk::op::OpState::InFlight {
            detail: scaas_sdk::op::InFlight::SimRefused
        }
    );
    assert!(
        !st.is_terminal() && c.lock().unwrap().sent.is_empty(),
        "in flight, nothing sent"
    );
    let _ = store;
}

/// P-T16-4: a token with the sealed opening (`PQZL_SPLIT_ID`) has its own code, before any account word is read.
#[tokio::test(flavor = "multi_thread")]
async fn opening_token_refused() {
    let (s, seed, c, a, _, _) = debit_setup(false).await;
    put(
        &c,
        TOKEN,
        &add(&root(), 2),
        &scaas_ua::facade::pqz::PQZL_SPLIT_ID,
    );
    c.lock().unwrap().requests.clear();
    assert_eq!(
        code(
            s.confidential()
                .prepare_pqz_transfer(transfer(&seed, &a, "100"))
                .await
        ),
        "PqzOpeningUnsupported"
    );
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, 0)).await),
        "PqzOpeningUnsupported"
    );
    assert_eq!(
        count(&c, "eth_getStorageAt"),
        4,
        "the factory record and psid only, twice"
    );
}

// --- P-T16-3: a native-id verifier; P-T16-5: every key version's balance ---

/// The EVM key `index` of the `pq_kat` seed, its 20-byte address, beside its wallet.
fn native_verifier(
    index: u32,
) -> (
    scaas_ua::wallet::Wallet,
    scaas_ua::wallet::NativeKey,
    [u8; 20],
) {
    use scaas_ua::wallet::Signer;
    let w = scaas_ua::wallet::Wallet::from_mnemonic(PQ_KAT, "").unwrap();
    let k = w
        .native_key(scaas_ua::wallet::Network::Evm, index, None)
        .unwrap();
    let scaas_ua::wallet::KeyRef::Native {
        address: Some(a), ..
    } = k.key_ref()
    else {
        panic!("an EVM key")
    };
    let a = a20(&a.to_ascii_lowercase());
    (w, k, a)
}

/// `m` signed by the EVM key `index` as a native-id verifier: `uaAuthDigest` under the registry's generation-`generation` domain.
fn native_answer(m: &Value, index: u32, generation: u32) -> Value {
    let uid: W = unhex(&hash_of(0)).try_into().unwrap();
    // the verdict's own token and chain (a verdict of another token or chain is signed as such: T3)
    let token = a20(m["token"].as_str().unwrap_or(TOKEN));
    let chain = m["chainId"].as_u64().unwrap_or(CHAIN_ID);
    let d = scaas_ua::wallet::pqz_verdict_typed_data(&token, chain, &uid, m)
        .unwrap()
        .digest()
        .unwrap();
    let (_w, k, _) = native_verifier(index);
    let dom = scaas_ua::Domain {
        generation,
        chain_id: CHAIN_ID,
        registry: a20(REGISTRY),
        chain_uid: uid,
    };
    let s = scaas_ua::wallet::ua_sig(
        &k,
        Some(&dom),
        &scaas_ua::purpose_tag("pqz-verdict").unwrap(),
        &d,
    )
    .unwrap();
    serde_json::json!({"pqzVerdict": m, "pqzVerdictSig": {"keyData": "0x", "signature": hx(&s.signature), "members": []}})
}

#[tokio::test(flavor = "multi_thread")]
async fn verdict_native_verifier() {
    let (s, c, psid) = verdict_setup(None, scaas_rpc::Policy::Failover).await;
    // the token names the EVM address of key 3 (a native id, no registry record)
    let (_w, _k, addr) = native_verifier(3);
    let mut id = [0u8; 32];
    id[12..].copy_from_slice(&addr);
    put(&c, TOKEN, &add(&root(), 13), &id);
    let m = verdict_of(&psid);
    // every generation of the line, 1 to 16 (the round's merge review A2: was 1 and 2 only)
    for g in [1, 2, 3, 16] {
        c.lock().unwrap().verdict = Some((200, native_answer(&m, 3, g)));
        let v = s.confidential().request_verdict(vreq()).await.unwrap();
        assert_eq!(
            (
                v["sig"]["keyData"].as_str(),
                v["sig"]["members"].as_array().map(Vec::len)
            ),
            (Some("0x"), Some(0)),
            "gen {g}"
        );
    }
    // above the line's depth (generation 17): refused
    c.lock().unwrap().verdict = Some((200, native_answer(&m, 3, 17)));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused",
        "gen 17"
    );
    // another EOA's signature; key data beside it; the address holding code (ERC-1271, not checked off chain): refused
    c.lock().unwrap().verdict = Some((200, native_answer(&m, 4, 1)));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused",
        "another key"
    );
    let mut a = native_answer(&m, 3, 1);
    a["pqzVerdictSig"]["keyData"] = serde_json::json!("0x01");
    c.lock().unwrap().verdict = Some((200, a));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused",
        "key data"
    );
    c.lock().unwrap().verdict = Some((200, native_answer(&m, 3, 1)));
    c.lock().unwrap().code.insert(hx(&addr), "0x6000".into());
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused",
        "code at the address"
    );
    c.lock().unwrap().code.remove(&hx(&addr));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "Ok",
        "control again"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn pqz_balance_all_versions() {
    // A holds version 0 (the migration's reference) and version 1 (the migrated credit pending)
    let (s, seed, c, r1) = one("A v1", 0).await;
    let r0 = row("A v0");
    pqz_state(&c, &ua_of(&s, &seed, 0).await, &r0);
    let all = s
        .confidential()
        .pqz_balance_all(req(&seed, 0, 7))
        .await
        .unwrap();
    let (v0, v1) = (
        r0["value"].to_string().parse::<u128>().unwrap(),
        r1["value"].to_string().parse::<u128>().unwrap(),
    );
    assert_eq!(all.versions.len(), 2);
    assert_eq!(
        (
            all.versions[0].amount.clone(),
            all.versions[1].amount.clone()
        ),
        (v0.to_string(), v1.to_string())
    );
    assert_eq!(all.amount, (v0 + v1).to_string());
    only_line_calls(&c);
    // M5 (review 2026-11-20), F3: both versions read at one final block: the block requests of two versions are those of
    // one version's read, and both name the same block
    let blocks = |c: &Fake| count(c, "eth_getBlockByNumber") + count(c, "eth_blockNumber");
    c.lock().unwrap().requests.clear();
    s.confidential()
        .pqz_balance(req(&seed, 0, 0))
        .await
        .unwrap();
    let one = blocks(&c);
    c.lock().unwrap().requests.clear();
    let all = s
        .confidential()
        .pqz_balance_all(req(&seed, 0, 7))
        .await
        .unwrap();
    assert_eq!(blocks(&c), one, "one block read for every version");
    assert_eq!(all.versions[0].block, all.versions[1].block);
}

/// Review F2 (CTR-UA-70, accounts.md "Off-chain readers"): a holder whose key records a predecessor holds, read through the later
/// generation the token binds, is read at the PQZ home `holderOf` names, never the bound registry's storage alone. Control: with
/// no `holderOf` answer (a registry before the line) the bound registry is read and the moved records are not found. The
/// words module calls `eth_call` only in its two line reads.
#[tokio::test(flavor = "multi_thread")]
async fn pqz_holder_in_predecessor_read_at_home() {
    const G1: &str = "0x5ca00000000000000000000000000000000000e1";
    let (s, seed, c, r) = one("B:", 1).await;
    let ua = ua_of(&s, &seed, 1).await;
    let v = r["request"]["keyVersion"].as_u64().unwrap();
    let (rec, ver) = (map(&be(v), &map(&ua, &be(2))), map(&ua, &be(17)));
    put(&c, G1, &rec, &w(&r["request"]["keyRecord"]));
    put(&c, G1, &ver, &w(&r["request"]["keyVersions"]));
    put(&c, REGISTRY, &rec, &[0; 32]);
    put(&c, REGISTRY, &ver, &[0; 32]);
    assert_eq!(
        code(s.confidential().pqz_balance(req(&seed, 1, v)).await),
        "LegKeyMismatch",
        "control: the bound registry alone"
    );
    holder_answer(&c, &ua, G1, 0x0131, G1);
    let b = s
        .confidential()
        .pqz_balance(req(&seed, 1, v))
        .await
        .unwrap();
    assert_eq!(b.amount, r["value"].to_string(), "read at the home");
    only_line_calls(&c);
    // the home another generation than the holder (merge review A4): read at the home, never at the holder
    const G2: &str = "0x5ca00000000000000000000000000000000000e2";
    put(&c, G2, &rec, &w(&r["request"]["keyRecord"]));
    put(&c, G2, &ver, &w(&r["request"]["keyVersions"]));
    put(&c, G1, &rec, &[0; 32]);
    put(&c, G1, &ver, &[0; 32]);
    c.lock().unwrap().answers.clear();
    holder_answer(&c, &ua, G1, 0x0131, G2);
    let b = s
        .confidential()
        .pqz_balance(req(&seed, 1, v))
        .await
        .unwrap();
    assert_eq!(
        b.amount,
        r["value"].to_string(),
        "read at the home, not the holder"
    );
    let words = include_str!("../src/confidential/words.rs");
    assert_eq!(
        words.matches("call_at(").count(),
        2,
        "holderOf and kindHome only"
    );
}

/// Review F2 (CTR-UA-70): the token's verifier UA whose record a predecessor holds is read where `holderOf` names it; control:
/// with no answer the bound registry alone is read and its signature is refused (`VerdictRefused`).
#[tokio::test(flavor = "multi_thread")]
async fn verdict_verifier_in_predecessor_read_at_holder() {
    const G1: &str = "0x5ca00000000000000000000000000000000000e1";
    let (s, c, psid) = verdict_setup(None, scaas_rpc::Policy::Failover).await;
    let ua = verifier_key(7).1.ua().unwrap();
    let slot = map(&ua, &be(0));
    let rec: W = unhex(
        c.lock()
            .unwrap()
            .storage
            .get(&(REGISTRY.into(), hx(&slot)))
            .unwrap(),
    )
    .try_into()
    .unwrap();
    put(&c, G1, &slot, &rec);
    put(&c, REGISTRY, &slot, &[0; 32]);
    c.lock().unwrap().verdict = Some((200, answer(&verdict_of(&psid), 7)));
    assert_eq!(
        code(s.confidential().request_verdict(vreq()).await),
        "VerdictRefused",
        "control: the bound registry alone"
    );
    holder_answer(
        &c,
        &ua,
        G1,
        0x0108,
        "0x0000000000000000000000000000000000000000",
    );
    let v = s.confidential().request_verdict(vreq()).await.unwrap();
    assert_eq!(v["pqzVerdict"]["pqzVerifierEpoch"], EPOCH);
    only_line_calls(&c);
}

/// The round's merge review A4 (CTR-UA-70): a debit's recipient whose key records a predecessor holds is read at its PQZ home
/// (`holderOf` of the recipient on the bound registry); control: with no answer the bound registry alone is read, and the
/// recipient's key is missing there: refused before anything is signed.
#[tokio::test(flavor = "multi_thread")]
async fn pqz_recipient_in_predecessor_read_at_home() {
    const G1: &str = "0x5ca00000000000000000000000000000000000e1";
    let (s, seed, c, a, _b, _store) = debit_setup(false).await;
    let r = row("A v1");
    let v = r["request"]["keyVersion"].as_u64().unwrap();
    let (rec, ver) = (map(&be(v), &map(&a, &be(2))), map(&a, &be(17)));
    put(&c, G1, &rec, &w(&r["request"]["keyRecord"]));
    put(&c, G1, &ver, &w(&r["request"]["keyVersions"]));
    put(&c, REGISTRY, &rec, &[0; 32]);
    put(&c, REGISTRY, &ver, &[0; 32]);
    assert!(
        s.confidential()
            .prepare_pqz_transfer(transfer(&seed, &a, "100"))
            .await
            .is_err(),
        "control: the bound registry alone has no key of the recipient"
    );
    holder_answer(&c, &a, G1, KIND, G1);
    s.confidential()
        .prepare_pqz_transfer(transfer(&seed, &a, "100"))
        .await
        .unwrap();
}
