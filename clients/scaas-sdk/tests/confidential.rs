// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T15: the SDK's reading layer (spec §9.4, requirements 1 to 7) and the Zether operations (spec §9.1), against the fake
//! chain of `tests/common/fake_chain.rs` (local only) holding a Zether token's storage: the factory record, the clone's code,
//! the account words, the registry record and the key pointer's code. Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, hash_of, serve, Fake, CHAIN_ID};
use scaas_sdk::confidential::{ZetherBalanceRequest, ZetherKeyInfo};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::factory::{clone_runtime, ChainEnv};
use scaas_ua::keccak256;
use scaas_ua::wallet::SecretBytes;
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;
use zether_prover::state::ROOT;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
pub const TOKEN: &str = "0x5ca00000000000000000000000000000000000c1";
const FACTORY: &str = "0x5ca00000000000000000000000000000000000f0";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000e0";
const IMPL: &str = "0x5ca00000000000000000000000000000000000d0";
const KEYPTR: &str = "0x5ca00000000000000000000000000000000000b0";

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

fn pad(a: &[u8; 20]) -> W {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

fn map(key: &W, base: &W) -> W {
    keccak256(&[key.as_slice(), base.as_slice()].concat())
}

fn endpoint(url: &str, class: scaas_rpc::Class) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class,
        label: None,
        auth: None,
    }
}

pub fn profile(
    rpc: Vec<EndpointConfig>,
    policy: scaas_rpc::Policy,
    finality: Finality,
) -> ChainProfile {
    ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: hash_of(0),
        rpc,
        rpc_policy: policy,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
        factory: Some(FACTORY.into()),
        router: None,
        finality,
        tx_gas_cap: Some(1 << 24),
        gas: Default::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        tokens: vec![],
        family_params: None,
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
    let sec = |t: &str| {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(t.as_bytes().to_vec())).unwrap())
    };
    let seed = s
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (s, seed)
}

fn put(c: &Fake, who: &str, slot: &W, word: &W) {
    c.lock()
        .unwrap()
        .storage
        .insert((who.to_ascii_lowercase(), hx(slot)), hx(word));
}

/// A stored point (`bytes` of 128) at slot `s`: the length word `2·128 + 1`, the data at `keccak256(s) + i`.
fn put_point(c: &Fake, who: &str, s: &W, p: &[u8]) {
    put(c, who, s, &be(257));
    let d = keccak256(s);
    for (i, chunk) in p.chunks(32).enumerate() {
        put(c, who, &add(&d, i as u64), &chunk.try_into().unwrap());
    }
}

/// The Zether token's state on fake `c` for the holder `k` holding `amount` (its `acc` an encryption to its `Y`, `accSeq`
/// 1): the factory record (class TOKEN, kind NORMAL_ZETHER), the clone's code with its `ChainEnv`, `psid`, the account, the
/// registry record of kind 0x0141 and its key pointer's code `0x00 ‖ Y`.
pub fn zether_state(c: &Fake, k: &ZetherKeyInfo, amount: u64) {
    let (y, ua): (Vec<u8>, W) = (unhex(&k.y), unhex(&k.ua).try_into().unwrap());
    let mut rec = [0u8; 32];
    rec[29] = 2;
    rec[31] = 1;
    put(c, FACTORY, &add(&map(&pad(&a20(TOKEN)), &be(8)), 1), &rec);
    let env = ChainEnv {
        chain_uid: unhex(&hash_of(0)).try_into().unwrap(),
        registry: a20(REGISTRY),
        gov_router: [0; 20],
        smart_key_account_impl: [0; 20],
        hedera: false,
        deps: vec![],
        params: vec![],
    };
    let mut cc = c.lock().unwrap();
    cc.code
        .insert(TOKEN.into(), hx(&clone_runtime(&a20(IMPL), &env)));
    let mut code = vec![0u8];
    code.extend_from_slice(&y);
    cc.code.insert(KEYPTR.into(), hx(&code));
    drop(cc);
    put(
        c,
        TOKEN,
        &add(&ROOT, 6),
        &zether_prover::curve::proof_system_id::<zether_prover::curve::Bls12381>(),
    );
    set_amount(c, k, amount);
    let mut r = [0u8; 32];
    r[5..25].copy_from_slice(&a20(KEYPTR));
    r[30] = 0x01;
    r[31] = 0x41;
    put(c, REGISTRY, &map(&ua, &be(0)), &r);
}

/// The holder's `acc` set to a fresh encryption of `amount` (`accSeq` 1).
pub fn set_amount(c: &Fake, k: &ZetherKeyInfo, amount: u64) {
    let ua: W = unhex(&k.ua).try_into().unwrap();
    let ct: Value = serde_json::from_str(
        &zether_prover::api::call(
            "encrypt",
            &json!({"curve": "bls12381", "Y": k.y, "amount": amount}).to_string(),
        )
        .unwrap(),
    )
    .unwrap();
    let base = map(&ua, &add(&ROOT, 8));
    put_point(c, TOKEN, &base, &unhex(ct["C"].as_str().unwrap()));
    put_point(c, TOKEN, &add(&base, 1), &unhex(ct["D"].as_str().unwrap()));
    put(c, TOKEN, &add(&base, 4), &be(1));
}

fn req(seed: &str) -> ZetherBalanceRequest {
    ZetherBalanceRequest {
        seed: seed.into(),
        account: 0,
        chain: "local".into(),
        token: TOKEN.into(),
        pending: false,
        table_bits: Some(18),
        bound_bits: Some(18),
    }
}

/// One fake with a holder of `amount`, its SDK under `p`'s other fields.
async fn one(amount: u64, finality: Finality) -> (Arc<Sdk>, String, Fake) {
    let c = fake();
    let url = serve(c.clone()).await;
    let (s, seed) = sdk(profile(
        vec![endpoint(&url, scaas_rpc::Class::Named)],
        scaas_rpc::Policy::Failover,
        finality,
    ))
    .await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    zether_state(&c, &k, amount);
    (s, seed, c)
}

/// The JSON-RPC requests a fake received, their ids removed.
fn log(c: &Fake) -> Vec<Value> {
    c.lock()
        .unwrap()
        .requests
        .iter()
        .flat_map(|r| {
            let v: Value = serde_json::from_str(r).unwrap();
            match v {
                Value::Array(a) => a,
                v => vec![v],
            }
        })
        .map(|mut v| {
            v.as_object_mut().unwrap().remove("id");
            v
        })
        .collect()
}

/// The word and code reads of a fake's log.
fn reads(c: &Fake) -> Vec<Value> {
    log(c)
        .into_iter()
        .filter(|r| r["method"] == "eth_getStorageAt" || r["method"] == "eth_getCode")
        .collect()
}

fn count(c: &Fake, method: &str) -> usize {
    log(c).iter().filter(|r| r["method"] == method).count()
}

#[tokio::test(flavor = "multi_thread")]
async fn decryption_reads_skip_discovered() {
    // control: a named endpoint
    let (s, seed, _c) = one(5, Finality::Finalized).await;
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "5"
    );
    // only a discovered endpoint: refused, nothing read
    let c = fake();
    let url = serve(c.clone()).await;
    let (s, seed) = sdk(profile(
        vec![endpoint(&url, scaas_rpc::Class::Discovered)],
        scaas_rpc::Policy::Failover,
        Finality::Finalized,
    ))
    .await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    zether_state(&c, &k, 5);
    assert_eq!(
        code(s.confidential().zether_balance(req(&seed)).await),
        "NoTrustedEndpoint"
    );
    assert_eq!(count(&c, "eth_getStorageAt"), 0);
    // strict_majority over two, one discovered: AgreementNeedsThree
    let (c1, c2) = (fake(), fake());
    let (u1, u2) = (serve(c1.clone()).await, serve(c2.clone()).await);
    let (s, seed) = sdk(profile(
        vec![
            endpoint(&u1, scaas_rpc::Class::Named),
            endpoint(&u2, scaas_rpc::Class::Discovered),
        ],
        scaas_rpc::Policy::StrictMajority,
        Finality::Finalized,
    ))
    .await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    zether_state(&c1, &k, 5);
    zether_state(&c2, &k, 5);
    assert_eq!(
        code(s.confidential().zether_balance(req(&seed)).await),
        "AgreementNeedsThree"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn another_chain_pair_dropped() {
    let (other, right) = (fake(), fake());
    other.lock().unwrap().genesis = hash_of(5);
    let (u1, u2) = (serve(other.clone()).await, serve(right.clone()).await);
    let (s, seed) = sdk(profile(
        vec![
            endpoint(&u1, scaas_rpc::Class::Named),
            endpoint(&u2, scaas_rpc::Class::Named),
        ],
        scaas_rpc::Policy::Failover,
        Finality::Finalized,
    ))
    .await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    zether_state(&other, &k, 7);
    zether_state(&right, &k, 5);
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "5"
    );
    assert_eq!(count(&other, "eth_getStorageAt"), 0);
    assert!(count(&right, "eth_getStorageAt") > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn words_at_one_final_block() {
    for (fin, block) in [(Finality::Finalized, 0x10u64), (Finality::Depth(3), 0x1d)] {
        let (s, seed, c) = one(5, fin).await;
        {
            let mut cc = c.lock().unwrap();
            cc.head = 0x20;
            cc.finalized = 0x10;
        }
        let b = s.confidential().zether_balance(req(&seed)).await.unwrap();
        assert_eq!(b.block, block, "the profile's final block, never Depth(1)");
        let rs = reads(&c);
        assert!(!rs.is_empty());
        for r in rs {
            let at = r["params"].as_array().unwrap().last().unwrap().clone();
            assert_eq!(
                at["blockHash"],
                json!(hash_of(block)),
                "every word by the block's hash: {r}"
            );
            assert_eq!(at["requireCanonical"], json!(true));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn view_never_serves_a_word() {
    // the fake's views answer nothing of the token's; the words come from storage alone
    let (s, seed, c) = one(5, Finality::Finalized).await;
    c.lock().unwrap().call_revert = true;
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "5"
    );
    assert_eq!(count(&c, "eth_call"), 0);
    // the module reaches no view: no call of the pool's that runs `eth_call`
    let src = include_str!("../src/confidential/read.rs");
    for v in ["call_at(", "call_tx(", "raw_read", "simulate"] {
        assert!(!src.contains(v), "read.rs uses {v}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn code_hash_checked() {
    // control
    let (s, seed, c) = one(5, Finality::Finalized).await;
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "5"
    );
    // the token's code not a clone of a release
    let good = c.lock().unwrap().code.get(TOKEN).cloned().unwrap();
    c.lock()
        .unwrap()
        .code
        .insert(TOKEN.into(), format!("{good}00"));
    assert_eq!(
        code(s.confidential().zether_balance(req(&seed)).await),
        "TokenUncatalogued"
    );
    // a clone of another chain
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
        code(s.confidential().zether_balance(req(&seed)).await),
        "ProfileMismatch"
    );
    c.lock().unwrap().code.insert(TOKEN.into(), good);
    // the key pointer's code holds another key
    let other = s.confidential().zether_key(seed.clone(), 1).await.unwrap();
    let mut k = vec![0u8];
    k.extend(unhex(&other.y));
    c.lock().unwrap().code.insert(KEYPTR.into(), hx(&k));
    assert_eq!(
        code(s.confidential().zether_balance(req(&seed)).await),
        "LegKeyMismatch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn uncatalogued_token_refused() {
    let (s, seed, c) = one(5, Finality::Finalized).await;
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "5"
    );
    let slot = add(&map(&pad(&a20(TOKEN)), &be(8)), 1);
    for (class, kind) in [(0u8, 2u8), (1, 1), (1, 6)] {
        let mut rec = [0u8; 32];
        rec[29] = kind;
        rec[31] = class;
        put(&c, FACTORY, &slot, &rec);
        assert_eq!(
            code(s.confidential().zether_balance(req(&seed)).await),
            "TokenUncatalogued",
            "class {class} kind {kind}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn leg_of_another_key_refused() {
    let (s, seed, c) = one(5, Finality::Finalized).await;
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "5"
    );
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    let ua: W = unhex(&k.ua).try_into().unwrap();
    let slot = map(&ua, &be(0));
    let good = c
        .lock()
        .unwrap()
        .storage
        .get(&(REGISTRY.into(), hx(&slot)))
        .cloned()
        .unwrap();
    // no record, a record of another kind
    put(&c, REGISTRY, &slot, &[0; 32]);
    assert_eq!(
        code(s.confidential().zether_balance(req(&seed)).await),
        "LegKeyMismatch"
    );
    let mut r: W = unhex(&good).try_into().unwrap();
    r[31] = 0x40;
    put(&c, REGISTRY, &slot, &r);
    assert_eq!(
        code(s.confidential().zether_balance(req(&seed)).await),
        "LegKeyMismatch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_back_to_the_source() {
    let (s1, seed1, c1) = one(5, Finality::Finalized).await;
    let (s2, seed2, c2) = one(9, Finality::Finalized).await;
    c1.lock().unwrap().requests.clear();
    c2.lock().unwrap().requests.clear();
    assert_eq!(
        s1.confidential()
            .zether_balance(req(&seed1))
            .await
            .unwrap()
            .amount,
        "5"
    );
    assert_eq!(
        s2.confidential()
            .zether_balance(req(&seed2))
            .await
            .unwrap()
            .amount,
        "9"
    );
    assert_eq!(
        log(&c1),
        log(&c2),
        "the requests do not depend on the decrypted value"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn decryption_failure_never_fails_over() {
    // control: one read's requests
    let (s, seed, c) = one(5, Finality::Finalized).await;
    c.lock().unwrap().requests.clear();
    s.confidential().zether_balance(req(&seed)).await.unwrap();
    let words = count(&c, "eth_getStorageAt");
    // the first endpoint's words do not decrypt within the bound; the second is never asked
    let (a, b) = (fake(), fake());
    let (ua, ub) = (serve(a.clone()).await, serve(b.clone()).await);
    let (s, seed) = sdk(profile(
        vec![
            endpoint(&ua, scaas_rpc::Class::Named),
            endpoint(&ub, scaas_rpc::Class::Named),
        ],
        scaas_rpc::Policy::Failover,
        Finality::Finalized,
    ))
    .await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    zether_state(&a, &k, 1 << 19);
    zether_state(&b, &k, 5);
    a.lock().unwrap().requests.clear();
    assert_eq!(
        code(s.confidential().zether_balance(req(&seed)).await),
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

#[tokio::test(flavor = "multi_thread")]
async fn watch_reads_are_fixed() {
    let (s, seed, c) = one(5, Finality::Finalized).await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    c.lock().unwrap().requests.clear();
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "5"
    );
    let first = reads(&c);
    set_amount(&c, &k, 77);
    c.lock().unwrap().requests.clear();
    assert_eq!(
        s.confidential()
            .zether_balance(req(&seed))
            .await
            .unwrap()
            .amount,
        "77"
    );
    assert_eq!(reads(&c), first, "a changed balance changes no read");
}

// --- the Zether pairs (spec §9.1, §21) ---

const KEYPTR2: &str = "0x5ca00000000000000000000000000000000000b2";
const UNDERLYING: &str = "0x5ca00000000000000000000000000000000000a1";

/// `k`'s registry record of kind 0x0141 and its key pointer at `ptr`.
fn register(c: &Fake, k: &ZetherKeyInfo, ptr: &str) {
    let ua: W = unhex(&k.ua).try_into().unwrap();
    let mut r = [0u8; 32];
    r[5..25].copy_from_slice(&a20(ptr));
    r[30] = 0x01;
    r[31] = 0x41;
    put(c, REGISTRY, &map(&ua, &be(0)), &r);
    let mut code = vec![0u8];
    code.extend(unhex(&k.y));
    c.lock().unwrap().code.insert(ptr.into(), hx(&code));
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn env() -> scaas_sdk::wallet::Envelope {
    scaas_sdk::wallet::Envelope {
        valid_until: now() + 3600,
        mode: 0,
        relayer: None,
        fee: "0".into(),
        fee_recipient: None,
    }
}

/// A fake with the holder (account 0, 5 units) and a registered recipient (account 1), a gateway, the Zether token's domain
/// and gas rows for the Zether entries signed by a Zether UA or a native key.
async fn pairs_setup() -> (Arc<Sdk>, String, Fake, ZetherKeyInfo, ZetherKeyInfo) {
    pairs_setup_verify(&[0, 0x0141]).await
}

/// [`pairs_setup`] with verify rows (gas 0) for the signer kinds `verify` only.
async fn pairs_setup_verify(
    verify: &[u16],
) -> (Arc<Sdk>, String, Fake, ZetherKeyInfo, ZetherKeyInfo) {
    let c = fake();
    let url = serve(c.clone()).await;
    let gw = serve(c.clone()).await;
    let mut p = profile(
        vec![endpoint(&url, scaas_rpc::Class::Named)],
        scaas_rpc::Policy::Failover,
        Finality::Finalized,
    );
    p.gateways = vec![endpoint(&gw, scaas_rpc::Class::Named)];
    let entries = [
        "mtxShield",
        "mtxWrapShield",
        "mtxRollOver",
        "mtxRollOverBatch",
        "mtxConfidentialTransferSingle",
        "mtxUnshield",
    ];
    p.gas = scaas_sdk::GasRows {
        base: entries
            .iter()
            .flat_map(|e| {
                [true, false].map(|fresh| scaas_sdk::GasBase {
                    entry: (*e).into(),
                    kind: "zether".into(),
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
        verify: verify
            .iter()
            .map(|&signer| scaas_sdk::GasVerify {
                signer,
                gas: 0,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            })
            .collect(),
    };
    let (s, seed) = sdk(p).await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    let k2 = s.confidential().zether_key(seed.clone(), 1).await.unwrap();
    zether_state(&c, &k, 5);
    register(&c, &k2, KEYPTR2);
    {
        let mut cc = c.lock().unwrap();
        cc.timestamp = now();
        cc.domains
            .insert(TOKEN.into(), ("SCaaS ZetherToken".into(), hash_of(0)));
    }
    (s, seed, c, k, k2)
}

/// The UA signature of the gateway body `n`'s operation verifies under the Zether key over `uaMessage(0x0141, metatx, id)`.
async fn signed_by_zether(c: &Fake, n: usize, id: &str, k: &ZetherKeyInfo) -> Value {
    let mut body = Value::Null;
    for _ in 0..100 {
        if let Some(b) = c.lock().unwrap().bodies.get(n) {
            body = serde_json::from_str(b).unwrap();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let op = &body["op"];
    let sig = op["auth"]["signature"]
        .as_str()
        .or(op["signature"]["signature"].as_str())
        .unwrap_or_else(|| panic!("{op}"));
    let d: W = unhex(id).try_into().unwrap();
    let m = scaas_ua::ua_message(0x0141, &scaas_ua::purpose_tag("metatx").unwrap(), &d).unwrap();
    assert!(
        scaas_ua::verify::verify(0x0141, &unhex(&k.y), &m, &unhex(sig), false, false),
        "the Zether UA's signature"
    );
    body
}

fn zether_signer(seed: &str) -> scaas_sdk::op::KeyRef {
    scaas_sdk::op::KeyRef::Ua {
        seed: seed.into(),
        kind: 0x0141,
        account: 0,
        index: 0,
    }
}

async fn send(s: &Arc<Sdk>, p: Arc<scaas_sdk::op::Prepared>) {
    let q = s
        .op()
        .quote(p.clone(), scaas_sdk::op::SubmitPath::Gateway)
        .await
        .unwrap();
    s.op().submit(p, q).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn zether_transfer_single_pair() {
    use scaas_sdk::confidential::ZetherTransfer;
    let (s, seed, c, k, k2) = pairs_setup().await;
    let t = |amount: &str| ZetherTransfer {
        seed: seed.clone(),
        account: 0,
        chain: "local".into(),
        token: TOKEN.into(),
        batch: "0".into(),
        to_ua: k2.ua.clone(),
        amount: amount.into(),
        valid_until_block: 1000,
        envelope: env(),
        table_bits: Some(18),
        bound_bits: Some(18),
    };
    // a balance below the amount: refused before anything is signed
    assert_eq!(
        code(s.confidential().prepare_zether_transfer(t("6")).await),
        "Argument"
    );
    let p = s
        .confidential()
        .prepare_zether_transfer(t("3"))
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxConfidentialTransferSingle");
    let rv = p.review();
    let req = |n: &str| {
        rv.iter()
            .find(|f| f.name == n)
            .map(|f| (f.value.clone(), f.source))
    };
    assert_eq!(
        req("request.amount"),
        Some(("3".into(), scaas_sdk::op::Source::Request))
    );
    assert_eq!(
        req("request.to"),
        Some((k2.ua.clone(), scaas_sdk::op::Source::Request))
    );
    assert_eq!(req("from").map(|r| r.0), Some(k.ua.clone()));
    send(&s, p.clone()).await;
    let body = signed_by_zether(&c, 0, &p.id(), &k).await;
    assert_eq!(body["op"]["entry"], "mtxConfidentialTransferSingle");
    // the recipient's key pointer holds another key (a third one's): refused, never a proof to it
    let good = c.lock().unwrap().code.get(KEYPTR2).cloned().unwrap();
    let k3 = s.confidential().zether_key(seed.clone(), 2).await.unwrap();
    let mut other = vec![0u8];
    other.extend(unhex(&k3.y));
    c.lock().unwrap().code.insert(KEYPTR2.into(), hx(&other));
    assert_eq!(
        code(s.confidential().prepare_zether_transfer(t("3")).await),
        "LegKeyMismatch"
    );
    c.lock().unwrap().code.insert(KEYPTR2.into(), good);
    // a record of another kind: a key mismatch; no record at all: the recipient is unregistered (owner 2026-11-19, P2)
    let slot = map(&unhex(&k2.ua).try_into().unwrap(), &be(0));
    let rec: W = unhex(
        &c.lock()
            .unwrap()
            .storage
            .get(&(REGISTRY.into(), hx(&slot)))
            .cloned()
            .unwrap(),
    )
    .try_into()
    .unwrap();
    let mut r = rec;
    r[31] = 0x40;
    put(&c, REGISTRY, &slot, &r);
    assert_eq!(
        code(s.confidential().prepare_zether_transfer(t("3")).await),
        "LegKeyMismatch"
    );
    put(&c, REGISTRY, &slot, &[0; 32]);
    assert_eq!(
        code(s.confidential().prepare_zether_transfer(t("3")).await),
        "ReceiverUnregistered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn zether_unshield_pair() {
    use scaas_sdk::confidential::ZetherUnshield;
    let (s, seed, c, k, _) = pairs_setup().await;
    let to = format!("0x{}{}", "00".repeat(12), "11".repeat(20));
    let p = s
        .confidential()
        .prepare_zether_unshield(ZetherUnshield {
            seed: seed.clone(),
            account: 0,
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            recipient: to.clone(),
            amount: "2".into(),
            valid_until_block: 1000,
            envelope: env(),
            table_bits: Some(18),
            bound_bits: Some(18),
        })
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxUnshield");
    let rv = p.review();
    assert!(rv.iter().any(|f| f.name == "amount"
        && f.value == "2"
        && f.source == scaas_sdk::op::Source::Signed));
    assert!(rv.iter().any(|f| f.name == "recipient" && f.value == to));
    send(&s, p.clone()).await;
    let body = signed_by_zether(&c, 0, &p.id(), &k).await;
    assert_eq!(body["op"]["entry"], "mtxUnshield");
}

#[tokio::test(flavor = "multi_thread")]
async fn zether_plain_pairs() {
    use scaas_sdk::confidential::{
        ZetherRollOver, ZetherRollOverBatch, ZetherShield, ZetherWrapShield,
    };
    let (s, seed, c, k, k2) = pairs_setup().await;
    let cf = s.confidential();
    let ps = [
        cf.prepare_zether_shield(ZetherShield {
            signer: zether_signer(&seed),
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            to_ua: k2.ua.clone(),
            amount: "4".into(),
            envelope: env(),
        })
        .await
        .unwrap(),
        cf.prepare_zether_roll_over(ZetherRollOver {
            signer: zether_signer(&seed),
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            ua: k.ua.clone(),
            n: "1".into(),
            envelope: env(),
        })
        .await
        .unwrap(),
        cf.prepare_zether_roll_over_batch(ZetherRollOverBatch {
            signer: zether_signer(&seed),
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            uas: vec![k.ua.clone(), k2.ua.clone()],
            envelope: env(),
        })
        .await
        .unwrap(),
    ];
    for (n, (p, entry)) in ps
        .into_iter()
        .zip(["mtxShield", "mtxRollOver", "mtxRollOverBatch"])
        .enumerate()
    {
        assert_eq!(p.entry(), entry);
        assert!(p
            .review()
            .iter()
            .any(|f| f.name == "from" && f.value == k.ua));
        send(&s, p.clone()).await;
        assert_eq!(
            signed_by_zether(&c, n, &p.id(), &k).await["op"]["entry"],
            entry
        );
    }
    // the wrap-shield's `from` is an address: a native EVM key signs it
    let p = cf
        .prepare_zether_wrap_shield(ZetherWrapShield {
            signer: scaas_sdk::op::KeyRef::Native {
                seed: seed.clone(),
                network: "evm".into(),
                index: 0,
            },
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            underlying: UNDERLYING.into(),
            amount_in: "4".into(),
            to_ua: k.ua.clone(),
            envelope: env(),
        })
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxWrapShield");
    // another domain (a PQZ token's) is not a Zether pair
    c.lock()
        .unwrap()
        .domains
        .insert(TOKEN.into(), ("SCaaS PqzToken".into(), hash_of(0)));
    let r = cf
        .prepare_zether_roll_over(ZetherRollOver {
            signer: zether_signer(&seed),
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            ua: k.ua.clone(),
            n: "1".into(),
            envelope: env(),
        })
        .await;
    assert_eq!(code(r), "Argument");
}

// --- the rest of the Zether pairs (plan T15, second commit) ---

const KEYPTR3: &str = "0x5ca00000000000000000000000000000000000b3";
const KEYPTR4: &str = "0x5ca00000000000000000000000000000000000b4";

/// The registry's `0x0141` list (`UAStore.Layout` slots 4 and 5) holding `uas` in order.
fn list(c: &Fake, uas: &[&ZetherKeyInfo]) {
    let kind = be(0x0141);
    put(c, REGISTRY, &map(&kind, &be(4)), &be(uas.len() as u64));
    for (i, k) in uas.iter().enumerate() {
        let ua: W = unhex(&k.ua).try_into().unwrap();
        put(c, REGISTRY, &map(&be(i as u64), &map(&kind, &be(5))), &ua);
    }
}

/// The holder's counters word: `accSeq`, `pendingSeq`, `lastRolledPendingSeq` (low end first), and `modeNonce`.
fn counters(c: &Fake, k: &ZetherKeyInfo, acc: u64, pending: u64, rolled: u64, mode_nonce: u64) {
    let ua: W = unhex(&k.ua).try_into().unwrap();
    let base = map(&ua, &add(&ROOT, 8));
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&acc.to_be_bytes());
    w[16..24].copy_from_slice(&pending.to_be_bytes());
    w[8..16].copy_from_slice(&rolled.to_be_bytes());
    put(c, TOKEN, &add(&base, 4), &w);
    put(c, TOKEN, &add(&base, 5), &be(mode_nonce));
}

/// The gateway body `n` (waiting for it).
async fn body(c: &Fake, n: usize) -> Value {
    for _ in 0..100 {
        if let Some(b) = c.lock().unwrap().bodies.get(n) {
            return serde_json::from_str(b).unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no gateway body {n}");
}

/// `sig` (a `UASig` JSON) verifies under the Zether key over `uaMessage(0x0141, purpose, digest)`.
fn zether_sig_ok(k: &ZetherKeyInfo, purpose: &str, digest: &str, sig: &Value) -> bool {
    let d: W = unhex(digest).try_into().unwrap();
    let m = scaas_ua::ua_message(0x0141, &scaas_ua::purpose_tag(purpose).unwrap(), &d).unwrap();
    let s = sig["signature"]
        .as_str()
        .unwrap_or_else(|| panic!("no UASig in {sig}"));
    scaas_ua::verify::verify(0x0141, &unhex(&k.y), &m, &unhex(s), false, false)
}

fn rev(p: &scaas_sdk::op::Prepared, n: &str) -> Option<(String, scaas_sdk::op::Source)> {
    p.review()
        .into_iter()
        .find(|f| f.name == n)
        .map(|f| (f.value, f.source))
}

#[tokio::test(flavor = "multi_thread")]
async fn zether_unshield_unwrap_pair() {
    use scaas_sdk::confidential::ZetherUnshieldUnwrap;
    let (s, seed, c, k, _) = pairs_setup().await;
    let to = format!("0x{}{}", "00".repeat(12), "11".repeat(20));
    let p = s
        .confidential()
        .prepare_zether_unshield_unwrap(ZetherUnshieldUnwrap {
            seed: seed.clone(),
            account: 0,
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            underlying: UNDERLYING.into(),
            recipient: to.clone(),
            amount: "2".into(),
            min_out: "1".into(),
            valid_until_block: 1000,
            envelope: env(),
            table_bits: Some(18),
            bound_bits: Some(18),
        })
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxUnshieldUnwrap");
    use scaas_sdk::op::Source::{Derived, Signed};
    assert_eq!(rev(&p, "unwrap.recipient"), Some((to.clone(), Signed)));
    assert_eq!(rev(&p, "unwrap.amount"), Some(("2".into(), Signed)));
    assert_eq!(rev(&p, "unwrap.minOut"), Some(("1".into(), Signed)));
    assert!(p
        .review()
        .iter()
        .any(|f| f.name == "token" && f.value == UNDERLYING && f.source == Derived));
    send(&s, p.clone()).await;
    assert_eq!(
        signed_by_zether(&c, 0, &p.id(), &k).await["op"]["entry"],
        "mtxUnshieldUnwrap"
    );
}

/// M13 (review 2026-11-20), F19: a long `0x0141` list is sampled, not read whole: with 5,000 entries listed, a transfer of
/// two decoys reads the list's length and a sample of `decoys + excluded` (4) words, a few dozen storage reads in all
/// (whatever the draws find there); the whole list would be 5,000.
#[tokio::test(flavor = "multi_thread")]
async fn zether_decoy_list_sampled() {
    use scaas_sdk::confidential::{ZetherLeg, ZetherTransferMulti};
    let (s, seed, c, k, k2) = pairs_setup().await;
    list(&c, &[&k, &k2]);
    put(&c, REGISTRY, &map(&be(0x0141), &be(4)), &be(5_000));
    c.lock().unwrap().requests.clear();
    let _ = s
        .confidential()
        .prepare_zether_transfer_multi(ZetherTransferMulti {
            seed: seed.clone(),
            account: 0,
            chain: "local".into(),
            token: TOKEN.into(),
            batch: "0".into(),
            recipients: vec![ZetherLeg {
                to_ua: k2.ua.clone(),
                amount: "3".into(),
            }],
            decoys: 2,
            decoy_fee: "0".into(),
            ua_signer_gas: 0,
            valid_until_block: 1000,
            envelope: env(),
            table_bits: Some(18),
            bound_bits: Some(18),
        })
        .await;
    let n = log(&c)
        .iter()
        .filter(|r| r["method"] == "eth_getStorageAt")
        .count();
    assert!(n > 0 && n < 100, "{n} storage reads");
}

#[tokio::test(flavor = "multi_thread")]
async fn zether_transfer_multi_pairs() {
    use scaas_sdk::confidential::{ZetherLeg, ZetherTransferMulti};
    let (s, seed, c, k, k2) = pairs_setup().await;
    let k3 = s.confidential().zether_key(seed.clone(), 2).await.unwrap();
    let k4 = s.confidential().zether_key(seed.clone(), 3).await.unwrap();
    register(&c, &k3, KEYPTR3);
    register(&c, &k4, KEYPTR4);
    list(&c, &[&k, &k2, &k3, &k4]);
    let t = |decoys: u32| ZetherTransferMulti {
        seed: seed.clone(),
        account: 0,
        chain: "local".into(),
        token: TOKEN.into(),
        batch: "0".into(),
        recipients: vec![ZetherLeg {
            to_ua: k2.ua.clone(),
            amount: "3".into(),
        }],
        decoys,
        decoy_fee: "0".into(),
        ua_signer_gas: 0,
        valid_until_block: 1000,
        envelope: env(),
        table_bits: Some(18),
        bound_bits: Some(18),
    };
    // more decoys than the list holds besides the holder and the recipient: refused before anything is proved
    assert_eq!(
        code(s.confidential().prepare_zether_transfer_multi(t(3)).await),
        "Argument"
    );
    // the decoys are never the holder or a real recipient: with two eligible UAs, both are drawn every time (three runs: a
    // draw that ignored the exclusions passes all three with probability (1/6)^3)
    let mut p = None;
    for _ in 0..3 {
        c.lock().unwrap().requests.clear();
        let q = s
            .confidential()
            .prepare_zether_transfer_multi(t(2))
            .await
            .unwrap();
        let slots: Vec<String> = reads(&c)
            .iter()
            .filter_map(|r| r["params"][1].as_str().map(String::from))
            .collect();
        for x in [&k3, &k4] {
            let ua: W = unhex(&x.ua).try_into().unwrap();
            assert!(
                slots.contains(&hx(&map(&ua, &be(0)))),
                "each eligible decoy's record is read"
            );
        }
        p = Some(q);
    }
    let p = p.unwrap();
    assert_eq!(p.entry(), "mtxConfidentialTransfer");
    use scaas_sdk::op::Source::{Derived, Request};
    assert_eq!(rev(&p, "request.to[0]"), Some((k2.ua.clone(), Request)));
    assert_eq!(rev(&p, "request.amount[0]"), Some(("3".into(), Request)));
    assert_eq!(rev(&p, "request.decoys"), Some(("2".into(), Derived)));
    send(&s, p.clone()).await;
    assert_eq!(
        signed_by_zether(&c, 0, &p.id(), &k).await["op"]["entry"],
        "mtxConfidentialTransfer"
    );
    let p = s
        .confidential()
        .prepare_zether_transfer_compact(t(1))
        .await
        .unwrap();
    assert_eq!(p.entry(), "mtxConfidentialTransferCompact");
    send(&s, p.clone()).await;
    assert_eq!(
        signed_by_zether(&c, 1, &p.id(), &k).await["op"]["entry"],
        "mtxConfidentialTransferCompact"
    );
    // a listed UA whose record is gone: when it must be drawn, the key read refuses it (R6)
    put(
        &c,
        REGISTRY,
        &map(&unhex(&k4.ua).try_into().unwrap(), &be(0)),
        &[0; 32],
    );
    assert_eq!(
        code(s.confidential().prepare_zether_transfer_multi(t(2)).await),
        "ReceiverUnregistered"
    );
}

/// P1 (owner 2026-11-19): the Zether UA's verify gas the prover adds comes from the gas table's `0x0141` verify row when there
/// is one, else from the request (`ua_signer_gas`, the app's figure). A figure above the transaction cap makes the prover
/// refuse the build, so which figure was used shows.
#[tokio::test(flavor = "multi_thread")]
async fn zether_ua_verify_gas_from_the_table_then_the_request() {
    use scaas_sdk::confidential::{ZetherLeg, ZetherTransferMulti};
    for (verify, app, ok) in [
        (&[0u16, 0x0141][..], 1u64 << 30, true), // the table's row (0) wins over an over-cap request figure
        (&[0u16][..], 1u64 << 30, false), // no row: the request's figure is used, over the cap
        (&[0u16][..], 0, true),           // no row: the request's figure, within the cap (control)
    ] {
        let (s, seed, c, k, k2) = pairs_setup_verify(verify).await;
        let k3 = s.confidential().zether_key(seed.clone(), 2).await.unwrap();
        register(&c, &k3, KEYPTR3);
        list(&c, &[&k, &k2, &k3]);
        let r = s
            .confidential()
            .prepare_zether_transfer_multi(ZetherTransferMulti {
                seed: seed.clone(),
                account: 0,
                chain: "local".into(),
                token: TOKEN.into(),
                batch: "0".into(),
                recipients: vec![ZetherLeg {
                    to_ua: k2.ua.clone(),
                    amount: "3".into(),
                }],
                decoys: 1,
                decoy_fee: "0".into(),
                ua_signer_gas: app,
                valid_until_block: 1000,
                envelope: env(),
                table_bits: Some(18),
                bound_bits: Some(18),
            })
            .await;
        assert_eq!(
            r.is_ok(),
            ok,
            "verify rows {verify:?}, request {app}: {:?}",
            r.err()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn zether_owner_statements() {
    use scaas_sdk::confidential::{OwnerRelay, ZetherOwnerRollOver, ZetherOwnerSetMode};
    let (s, seed, c, k, _) = pairs_setup().await;
    let cf = s.confidential();
    let roll = || ZetherOwnerRollOver {
        seed: seed.clone(),
        account: 0,
        chain: "local".into(),
        token: TOKEN.into(),
        valid_until_block: 1000,
    };
    let mode = |m: u8| ZetherOwnerSetMode {
        seed: seed.clone(),
        account: 0,
        chain: "local".into(),
        token: TOKEN.into(),
        mode: m,
        valid_until_block: 1000,
    };
    let relay = || OwnerRelay {
        batch: "0".into(),
        envelope: env(),
    };
    // nothing pending: refused
    counters(&c, &k, 1, 2, 2, 0);
    assert_eq!(
        code(cf.prepare_zether_owner_roll_over(roll()).await),
        "Argument"
    );
    assert_eq!(
        code(cf.prepare_zether_owner_set_mode(mode(2)).await),
        "Argument"
    );
    counters(&c, &k, 1, 3, 1, 4);
    // the direct forms: the Zether UA signs the owner statement under zether-owner, never metatx
    let p = cf.prepare_zether_owner_roll_over(roll()).await.unwrap();
    assert_eq!(p.entry(), "mtxRollOverSigned");
    assert_eq!(rev(&p, "accSeq").map(|r| r.0), Some("1".into()));
    assert_eq!(rev(&p, "expectedPendingSeq").map(|r| r.0), Some("3".into()));
    send(&s, p.clone()).await;
    let b = body(&c, 0).await;
    let sig = &b["op"]["auth"];
    assert!(zether_sig_ok(&k, "zether-owner", &p.id(), sig), "{b}");
    assert!(!zether_sig_ok(&k, "metatx", &p.id(), sig));
    let p = cf.prepare_zether_owner_set_mode(mode(1)).await.unwrap();
    assert_eq!(p.entry(), "mtxSetRollOverMode");
    assert_eq!(rev(&p, "modeNonce").map(|r| r.0), Some("4".into()));
    send(&s, p.clone()).await;
    let b = body(&c, 1).await;
    let sig = &b["op"]["auth"];
    assert!(zether_sig_ok(&k, "zether-owner", &p.id(), sig), "{b}");
    // the relayed forms: the envelope under metatx, the owner statement's signature (zether-owner) as `ownerSig`
    let uid: W = unhex(&hash_of(0)).try_into().unwrap();
    for (n, (p, inner)) in [
        (cf.prepare_zether_roll_over_signed(roll(), relay()).await.unwrap(),
         json!({"ua": k.ua, "accSeq": "1", "expectedPendingSeq": "3", "validUntilBlock": "1000"})),
        (cf.prepare_zether_set_roll_over_mode(mode(1), relay()).await.unwrap(),
         json!({"ua": k.ua, "mode": 1, "modeNonce": "4", "validUntilBlock": "1000"})),
    ]
    .into_iter()
    .enumerate()
    {
        let name = if n == 0 { "ZetherRollOver" } else { "ZetherSetRollOverMode" };
        let d = scaas_ua::wallet::scaas_typed_data(name, Some("SCaaS ZetherToken"), &a20(TOKEN), CHAIN_ID, &uid, &inner)
            .unwrap()
            .digest()
            .unwrap();
        assert!(p.review().iter().any(|f| f.name.starts_with("owner.")), "the owner statement is reviewed");
        send(&s, p.clone()).await;
        let b = signed_by_zether(&c, 2 + n, &p.id(), &k).await;
        assert!(zether_sig_ok(&k, "zether-owner", &hx(&d), &b["op"]["args"]["ownerSig"]), "{b}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn watch_reads_a_zether_account() {
    let c = fake();
    let url = serve(c.clone()).await;
    let mut p = profile(
        vec![endpoint(&url, scaas_rpc::Class::Named)],
        scaas_rpc::Policy::Failover,
        Finality::Finalized,
    );
    p.tokens = vec![scaas_sdk::ListedToken {
        address: TOKEN.into(),
        symbol: "Z".into(),
        decimals: 0,
    }];
    let (s, seed) = sdk(p).await;
    let k = s.confidential().zether_key(seed.clone(), 0).await.unwrap();
    zether_state(&c, &k, 5);
    {
        let mut g = c.lock().unwrap();
        g.tokens
            .insert(TOKEN.into(), ("Z".into(), "Z".into(), 0, hash_of(0)));
        g.balances.insert(TOKEN.into(), 0);
    }
    // only an account a keystore row names (C2): the Zether UA's row first
    assert_eq!(
        code(s.watch(k.ua.clone(), vec!["local".into()]).await),
        "Argument"
    );
    let row = s
        .account()
        .add_ua(scaas_sdk::account::AddUa {
            seed: seed.clone(),
            name: "z".into(),
            kind: 0x0141,
            account: 0,
            index: 0,
        })
        .await
        .unwrap();
    assert_eq!(row.id_text, k.ua, "the row's UA is the Zether key's");
    let sub = s.subscribe();
    s.watch(k.ua.clone(), vec!["local".into()]).await.unwrap();
    c.lock().unwrap().requests.clear();
    s.poll().await.unwrap();
    let first = reads(&c);
    assert!(!first.is_empty(), "the Zether words are read");
    // the holder's words move: one more poll, the same reads, `BalanceChanged`
    set_amount(&c, &k, 77);
    c.lock().unwrap().requests.clear();
    s.poll().await.unwrap();
    assert_eq!(reads(&c), first, "a changed balance changes no read");
    let mut ev = vec![];
    while let Some(e) = sub.next(50).await {
        ev.push(e);
    }
    assert!(
        ev.contains(&scaas_sdk::Event::BalanceChanged {
            account: k.ua.clone(),
            chain: "local".into(),
            token: TOKEN.into()
        }),
        "{ev:?}"
    );
}

/// Plan T23 (spec §25 Q-K15, owner 2026-11-17: align with the ruling): a 12-word seed's Zether key is available and equals
/// `zether-prover`'s from the same words (`seed_from_mnemonic`, which accepts 12 to 24 words with the short-seed flag); the
/// 24-word control beside it.
#[tokio::test(flavor = "multi_thread")]
async fn short_seed_zether_key_is_the_provers() {
    use zether_prover::curve::{encode_point, Bls12381};
    use zether_prover::keys::{seed_from_mnemonic_warned, ZetherKey};
    const TWELVE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let s = Sdk::open(SdkConfig {
        profiles: vec![],
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
    let sec = |t: &str| {
        Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(t.as_bytes().to_vec())).unwrap())
    };
    for (words, short, label) in [(TWELVE, true, "twelve"), (REPO, false, "repo")] {
        let seed = s
            .vault()
            .import_words(ImportWords {
                label: label.into(),
                words: sec(words),
                vault_passphrase: sec(PASS),
            })
            .await
            .unwrap()
            .id;
        let k = s.confidential().zether_key(seed, 0).await.unwrap();
        let (ps, warned) = seed_from_mnemonic_warned(words, "").unwrap();
        assert_eq!(warned, short);
        let pk = ZetherKey::<Bls12381>::conf(&ps[..], 60, 0).unwrap();
        assert_eq!(
            k.y,
            format!("0x{}", hex_of(&encode_point::<Bls12381>(&pk.y)))
        );
    }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
