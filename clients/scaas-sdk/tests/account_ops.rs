// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T13: the `account` operations (spec §7) against the fake chain of `tests/common/fake_chain.rs` (local only): the
//! registration's arguments and PoP by `scaas-ua`, its writes kept opaque, quoted, submitted and landed by the record; the KEM
//! repair of a hash commit; each refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, keccak_hex, serve, Fake, CHAIN_ID};
use scaas_sdk::account::{Register, RegisterAttrs, RegistrationBlob, BLOB_MAX};
use scaas_sdk::op::{KeyRef, OpState};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::entries::registry_call;
use scaas_ua::wallet::{SecretBytes, Wallet};
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const ED25519: u16 = 0x0102;
const MLDSA44: u16 = 0x0130;

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

fn load(p: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{p}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

struct T {
    sdk: Arc<Sdk>,
    chain: Fake,
    seed: String,
    payer: KeyRef,
}

async fn setup() -> T {
    setup_with(Some(REGISTRY)).await
}

async fn setup_with(registry: Option<&str>) -> T {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: chain.lock().unwrap().genesis.clone(),
        rpc: vec![EndpointConfig {
            url,
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: registry.map(Into::into),
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        tokens: vec![],
        gas: Default::default(),
        max_valid_secs: None,
        gas_opt_in: vec![],
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
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
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    T {
        sdk,
        chain,
        seed,
        payer,
    }
}

fn ua_key(t: &T, kind: u16) -> KeyRef {
    KeyRef::Ua {
        seed: t.seed.clone(),
        kind,
        account: 0,
        index: 0,
    }
}

fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}

fn w(n: u64) -> String {
    format!("{n:064x}")
}

/// The fake registry's answers for `ua`: registered or not, the `attrs.kemPkHash` of its registration, a stored KEM key.
fn registry(t: &T, ua: &str, registered: bool, kem_pk_hash: &str, kem_stored: bool) {
    let mut c = t.chain.lock().unwrap();
    c.answers.retain(|(_, d, _)| !d.contains(&ua[2..]));
    let ua = &ua[2..];
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("isRegistered(bytes32)")),
        format!("0x{}", w(u64::from(registered))),
    ));
    // `(uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop)`: `attrs` at 0xc0 after an empty `keyData`
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("registrationOf(bytes32)")),
        format!(
            "0x{}{}{}{}{}{}{}{}{}{}{}{}",
            w(1),
            w(0xa0),
            w(0xc0),
            w(0x1c0),
            w(0x1e0),
            w(0),
            w(0x80),
            w(0),
            w(0xa0),
            &kem_pk_hash[2..],
            w(0),
            w(0)
        ),
    ));
    // `(address ptr, bytes32 pqzPopHash, bool proven)`: no PQZ key
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("pqzKeyAt(bytes32,uint64)")),
        format!("0x{}{}{}", w(0), w(0), w(0)),
    ));
    // `(KemKey kem, bytes sig)`: the tuple at 0x40, its scheme first
    c.answers.push((
        REGISTRY.into(),
        format!("{}{ua}", sel("kemKeyAt(bytes32,uint64)")),
        format!("0x{}{}{}{}{}{}", w(0x40), w(0xe0), w(u64::from(kem_stored)), w(0x60), w(0), w(0)),
    ));
}

/// The independent build of an ed25519 seed key's registration (`scaas-ua` directly): the calldata.
fn independent_register(kind: u16) -> (String, Vec<u8>, Value) {
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = wallet.ua_key(kind, 0, 0).unwrap();
    let ua = k.ua().unwrap();
    let hp = scaas_ua::holder_pop_message(kind, &ua, &k.key_data(), None, None, None, None).unwrap();
    let pop = k
        .sign_ua(&scaas_ua::ua_portable::pop_v2_tag(), &hp.registration_digest)
        .unwrap();
    scaas_ua::ua_portable::check_registration(kind, &k.key_data(), &Default::default(), &pop, &[], &|_| None)
        .expect("the PoP verifies (the positive control of the independent build)");
    let input = json!({"kind": kind, "keyData": hx(&k.key_data()), "pqzKey": "0x", "pqzPopHash": "0x", "pqzPop": "0x",
        "kemPk": "0x", "pop": hx(&pop)});
    let r: Value =
        serde_json::from_str(&scaas_ua::json::registration_args_json(&input.to_string()).unwrap()).unwrap();
    let args = r["args"].clone();
    (hx(&ua), registry_call("register", &args).unwrap(), args)
}

fn req(t: &T, kind: u16, kem: bool) -> Register {
    Register {
        key: ua_key(t, kind),
        chain: "local".into(),
        attrs: RegisterAttrs { pqz_key: false, kem },
        payer: t.payer.clone(),
    }
}

/// The SDK's registration of a seed key is `scaas-ua`'s, byte for byte (ed25519 signs deterministically), in the named form
/// of `ua/portable.json`'s rows; a KEM key goes in full when it fits.
#[tokio::test(flavor = "multi_thread")]
async fn registration_args_equal_portable_json() {
    let t = setup().await;
    let (ua, calldata, args) = independent_register(ED25519);
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    let ws = t.sdk.account().prepare_register(req(&t, ED25519, false)).await.unwrap();
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].entry(), "register");
    assert_eq!(ws[0].ua(), ua);
    assert_eq!(ws[0].calldata(), hx(&calldata), "the SDK's calldata is scaas-ua's");
    // the named form: the vectors' row of the same entry has the same fields
    let v = load("ua/portable.json");
    let row = v["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kindName"] == "ed25519")
        .unwrap();
    let keys = |o: &Value| {
        let mut k: Vec<String> = o.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(keys(&args), keys(&row["args"]));
    assert_eq!(keys(&args["attrs"]), keys(&row["args"]["attrs"]));
    assert!(ws[0].review().iter().any(|f| f.name == "args.pop"), "every argument reviewed");
    // a KEM holder with its KEM key: in full (it fits one call), scheme 1
    let mldsa = hx(&Wallet::from_mnemonic(REPO, "").unwrap().ua_key(MLDSA44, 0, 0).unwrap().ua().unwrap());
    registry(&t, &mldsa, false, &hx(&[0; 32]), false);
    let ws = t.sdk.account().prepare_register(req(&t, MLDSA44, true)).await.unwrap();
    assert_eq!(ws.len(), 1, "no fill: the full key fits");
    let kem = ws[0].review().into_iter().find(|f| f.name == "args.attrs.kem.scheme").unwrap();
    assert_eq!(kem.value, "1");
    // refusals beside the control: a KEM key on a kind that holds none; a native key; the PQZ key's proof is not built
    assert_eq!(code(t.sdk.account().prepare_register(req(&t, ED25519, true)).await), "KemHolder");
    let mut native = req(&t, ED25519, false);
    native.key = t.payer.clone();
    assert_eq!(code(t.sdk.account().prepare_register(native).await), "Argument");
    let mut pqz = req(&t, ED25519, false);
    pqz.attrs.pqz_key = true;
    assert_eq!(code(t.sdk.account().prepare_register(pqz).await), "Argument", "ed25519 holds no PQZ key");
}

/// The PQZ key attribute (spec §7): the wallet's PQZ key of the same account and index, its `R_REG` proof by `scaas-ua` under
/// the build's PQZL id as `pqzPop`, `pqzPopHash` its hash, and the PoP over all of it verifies (`check_registration`, as the
/// registry checks it); with the KEM key too.
#[cfg(feature = "pqz")]
#[tokio::test(flavor = "multi_thread")]
async fn registration_with_pqz_key() {
    let t = setup().await;
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = wallet.ua_key(MLDSA44, 0, 0).unwrap();
    let ua = hx(&k.ua().unwrap());
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    for kem in [false, true] {
        let mut r = req(&t, MLDSA44, kem);
        r.attrs.pqz_key = true;
        let ws = t.sdk.account().prepare_register(r).await.unwrap();
        assert_eq!(ws.len(), 1, "it fits the fake chain's cap: no split");
        let f = |n: &str| ws[0].review().into_iter().find(|x| x.name == n).unwrap().value;
        let pqz_key = wallet.pqz_key(0, 0).unwrap().pk();
        assert_eq!(f("args.attrs.pqzKey"), hx(&pqz_key));
        let pqz_pop = alloy::hex::decode(&f("args.pqzPop")[2..]).unwrap();
        assert!(pqz_pop.len() > 20_000, "an R_REG proof");
        assert_eq!(f("args.attrs.pqzPopHash"), hx(&scaas_ua::keccak256(&pqz_pop)));
        let kem_pk = if kem { k.kem_key(0).unwrap().kem_pk() } else { vec![] };
        let attrs = scaas_ua::ua_portable::UAAttrs {
            pqz_key: pqz_key.clone(),
            pqz_pop_hash: scaas_ua::keccak256(&pqz_pop),
            kem: if kem {
                scaas_ua::ua_portable::KemKey::from_kem_pk(&kem_pk).unwrap()
            } else {
                Default::default()
            },
            kem_pk_hash: [0; 32],
        };
        let pop = alloy::hex::decode(&f("args.pop")[2..]).unwrap();
        scaas_ua::ua_portable::check_registration(MLDSA44, &k.key_data(), &attrs, &pop, &pqz_pop, &|_| None)
            .expect("the PoP covers the PQZ key, its proof and the KEM key");
    }
}

/// A registry write lands by its record, whoever sent it: no receipt for the payer's transaction, the record present is
/// `Landed`; absent, it stays in flight. A write is submitted once; a registered UA gives no write.
#[tokio::test(flavor = "multi_thread")]
async fn registry_write_landed_by_record() {
    let t = setup().await;
    let (ua, _, _) = independent_register(ED25519);
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    let ws = t.sdk.account().prepare_register(req(&t, ED25519, false)).await.unwrap();
    let q = t.sdk.account().quote_registry_write(ws[0].clone()).await.unwrap();
    let op = t
        .sdk
        .account()
        .submit_registry_write(ws[0].clone(), q.clone())
        .await
        .unwrap();
    assert_eq!(
        code(t.sdk.account().submit_registry_write(ws[0].clone(), q).await),
        "PreparedUnknown",
        "one submit of a write"
    );
    for _ in 0..50 {
        if !t.chain.lock().unwrap().sent.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(t.chain.lock().unwrap().sent.len(), 1, "the payer's transaction sent");
    assert!(
        matches!(t.sdk.op().state(op.clone()).await.unwrap(), OpState::InFlight { .. }),
        "no record yet"
    );
    registry(&t, &ua, true, &hx(&[0; 32]), false);
    assert!(
        matches!(t.sdk.op().state(op).await.unwrap(), OpState::Landed { .. }),
        "the record lands it"
    );
    assert!(
        t.sdk.account().prepare_register(req(&t, ED25519, false)).await.unwrap().is_empty(),
        "a registered UA: nothing to write"
    );
    let s = t.sdk.account().registration_of("local".into(), ua).await.unwrap();
    assert!(s.registered && !s.kem_stored);
}

/// The repair of a front-run hash commit (CTR-UA-07): registered with `kemPkHash` set and no key stored, the fill is
/// `setKemKey(ua, 0, kem, UASig())`; a stored key or no commit is nothing to repair.
#[tokio::test(flavor = "multi_thread")]
async fn kem_repair_after_commit_form() {
    let t = setup().await;
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = wallet.ua_key(MLDSA44, 0, 0).unwrap();
    let ua = hx(&k.ua().unwrap());
    let kem_pk = k.kem_key(0).unwrap().kem_pk();
    let commit = hx(&scaas_ua::keccak256(&kem_pk));
    let acc = t.sdk.account();
    let repair = || acc.prepare_kem_repair(ua_key(&t, MLDSA44), "local".into(), t.payer.clone());
    registry(&t, &ua, true, &commit, false);
    let fix = repair().await.unwrap().expect("an unfilled commit");
    assert_eq!(fix.entry(), "setKemKey");
    let kem = scaas_ua::ua_portable::KemKey::from_kem_pk(&kem_pk).unwrap();
    let want = registry_call(
        "setKemKey",
        &json!({"ua": ua, "version": 0, "kem": {"scheme": kem.scheme, "mlkemEk": hx(&kem.mlkem_ek), "x25519": hx(&kem.x25519)},
            "sig": {"keyData": "0x", "signature": "0x", "members": []}}),
    )
    .unwrap();
    assert_eq!(fix.calldata(), hx(&want));
    registry(&t, &ua, true, &commit, true);
    assert!(repair().await.unwrap().is_none(), "the key stored");
    registry(&t, &ua, true, &hx(&[0; 32]), false);
    assert!(repair().await.unwrap().is_none(), "no commit");
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    assert!(repair().await.unwrap().is_none(), "not registered");
}

// --- plan T13b: sponsored registration (spec §7.1, R16) ---

/// The fake registry's `kindEnabled(kind)`.
fn kind_enabled(t: &T, kind: u16, on: bool) {
    let mut c = t.chain.lock().unwrap();
    let d = format!("{}{}", sel("kindEnabled(uint16)"), w(u64::from(kind)));
    c.answers.retain(|(_, x, _)| *x != d);
    c.answers.push((REGISTRY.into(), d, format!("0x{}", w(u64::from(on)))));
}

/// A blob of `registration_blobs.json` by name.
fn blob(name: &str) -> Value {
    load("ua/registration_blobs.json")["blobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == name)
        .unwrap()["blob"]
        .clone()
}

/// The receiver's blob is clientkeys' form (`registrationBlob`): its fields, the arguments `scaas-ua`'s with their entry; it
/// passes the sender's checks.
#[tokio::test(flavor = "multi_thread")]
async fn registration_blob_is_clientkeys_form() {
    let t = setup().await;
    let (ua, calldata, args) = independent_register(ED25519);
    let blob = t
        .sdk
        .account()
        .registration_blob(ua_key(&t, ED25519), RegisterAttrs::default())
        .await
        .unwrap();
    let text = blob.to_json().unwrap();
    let b: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(RegistrationBlob::from_json(&text).unwrap(), blob, "the text form reads back");
    let mut keys: Vec<&String> = b.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["args", "kem", "kind", "ua", "v"]);
    assert_eq!(b["ua"], json!(ua));
    assert_eq!(b["args"]["entry"], "register");
    assert_eq!(b["args"], args, "the arguments are scaas-ua's");
    assert!(b["kem"].is_null());
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    kind_enabled(&t, ED25519, true);
    let ws = t
        .sdk
        .account()
        .prepare_submit_registration(blob, "local".into(), ua, t.payer.clone())
        .await
        .unwrap();
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].calldata(), hx(&calldata));
}

/// Spec §18 "Sponsored registration": the positive control, then one change at a time, each refused by name before
/// anything is sent (the fake chain counts no transaction).
#[tokio::test(flavor = "multi_thread")]
async fn sponsored_registration_checks() {
    let t = setup().await;
    let acc = t.sdk.account();
    let submit = |b: &Value, expected: &str| {
        let b = RegistrationBlob::from_json(&b.to_string());
        let (acc, expected, payer) = (acc.clone(), expected.to_string(), t.payer.clone());
        async move { acc.prepare_submit_registration(b?, "local".into(), expected, payer).await }
    };
    // every single-key blob of the vectors passes (each kind enabled, none registered), the PQ ones with their PQZ key's
    // proof among them (owner 2026-11-19, R1)
    for b in load("ua/registration_blobs.json")["blobs"].as_array().unwrap() {
        let (name, b) = (b["name"].as_str().unwrap(), &b["blob"]);
        let ua = b["ua"].as_str().unwrap();
        registry(&t, ua, false, &hx(&[0; 32]), false);
        kind_enabled(&t, b["kind"].as_u64().unwrap() as u16, true);
        let ws = submit(b, ua).await.unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let want = if b["kem"].is_null() { 1 } else { 2 };
        assert_eq!(ws.len(), want, "{name}");
        if want == 2 {
            assert_eq!(ws[1].entry(), "setKemKey", "{name}");
        }
    }
    let ed = blob("ed25519");
    let ua = ed["ua"].as_str().unwrap().to_string();
    assert!(submit(&ed, &ua).await.is_ok(), "the control");
    // another receiver than the user means; key data that does not give the UA
    let other = blob("p256")["ua"].as_str().unwrap().to_string();
    assert_eq!(code(submit(&ed, &other).await), "RegistrationUaMismatch");
    let mut forged = ed.clone();
    forged["args"]["keyData"] = blob("bip340")["args"]["keyData"].clone();
    assert_eq!(code(submit(&forged, &ua).await), "RegistrationUaMismatch");
    // the kind disabled on the chain
    kind_enabled(&t, ED25519, false);
    assert_eq!(code(submit(&ed, &ua).await), "RegistrationKindDisabled");
    kind_enabled(&t, ED25519, true);
    // a PoP over another digest, by the right key
    let wallet = Wallet::from_mnemonic(REPO, "").unwrap();
    let k = wallet.ua_key(ED25519, 0, 0).unwrap();
    let mine = t
        .sdk
        .account()
        .registration_blob(ua_key(&t, ED25519), RegisterAttrs::default())
        .await
        .unwrap();
    let mut bad: Value = serde_json::from_str(&mine.to_json().unwrap()).unwrap();
    let mine_ua = bad["ua"].as_str().unwrap().to_string();
    registry(&t, &mine_ua, false, &hx(&[0; 32]), false);
    assert!(submit(&bad, &mine_ua).await.is_ok(), "the control");
    bad["args"]["pop"] = json!(hx(&k.sign_ua(&scaas_ua::ua_portable::pop_v2_tag(), &[7; 32]).unwrap()));
    assert_eq!(code(submit(&bad, &mine_ua).await), "RegistrationPopInvalid");
    // a committed KEM key: missing, or another key than the committed one
    let c = blob("fndsa512/kem-commit");
    let cua = c["ua"].as_str().unwrap().to_string();
    kind_enabled(&t, c["kind"].as_u64().unwrap() as u16, true);
    registry(&t, &cua, false, &hx(&[0; 32]), false);
    assert_eq!(submit(&c, &cua).await.unwrap().len(), 2, "the control");
    let mut missing = c.clone();
    missing["kem"] = Value::Null;
    assert_eq!(code(submit(&missing, &cua).await), "RegistrationKemMissing");
    let mut swapped = c.clone();
    swapped["kem"]["kemPk"] = blob("mldsa87/kem-commit")["kem"]["kemPk"].clone();
    assert_eq!(code(submit(&swapped, &cua).await), "RegistrationKemMissing");
    // already registered: skipped, the KEM key added while missing, nothing once stored
    let hash = c["args"]["attrs"]["kemPkHash"].as_str().unwrap().to_string();
    registry(&t, &cua, true, &hash, false);
    let ws = submit(&c, &cua).await.unwrap();
    assert_eq!(ws.iter().map(|w| w.entry()).collect::<Vec<_>>(), ["setKemKey"]);
    registry(&t, &cua, true, &hash, true);
    assert!(submit(&c, &cua).await.unwrap().is_empty());
    // the blob's bounds: an unknown field, depth 5, another version
    let mut unknown = ed.clone();
    unknown["memo"] = json!("x");
    assert_eq!(code(submit(&unknown, &ua).await), "Argument");
    let mut nested = ed.clone();
    nested["args"]["attrs"]["memo"] = json!("x");
    assert_eq!(code(submit(&nested, &ua).await), "Argument", "an unknown field inside the arguments");
    let mut deep = ed.clone();
    deep["args"]["attrs"]["kem"]["scheme"] = json!({"a": 0});
    assert_eq!(code(submit(&deep, &ua).await), "Argument");
    let mut v2 = ed.clone();
    v2["v"] = json!(2);
    assert_eq!(code(submit(&v2, &ua).await), "Argument");
    assert!(t.chain.lock().unwrap().sent.is_empty(), "nothing sent by any check");
}

/// The blob's size cap (owner 2026-11-19, R1): the largest real blob passes; padded to the cap it still reads, one byte over
/// is `Argument`.
#[tokio::test(flavor = "multi_thread")]
async fn registration_blob_size_cap() {
    let big = blob("mldsa65/n2816-kmax65536/kem-commit").to_string();
    assert!(big.len() > 64 * 1024, "the largest vector blob, above the old 64 KiB");
    assert!(RegistrationBlob::from_json(&big).is_ok());
    let at_cap = format!("{big}{}", " ".repeat(BLOB_MAX - big.len()));
    assert_eq!(at_cap.len(), BLOB_MAX);
    assert!(RegistrationBlob::from_json(&at_cap).is_ok(), "at the cap");
    let over = format!("{at_cap} ");
    assert_eq!(code(RegistrationBlob::from_json(&over)), "Argument", "one byte over the cap");
}

/// A PQ kind's blob split as T13's (spec §7.1): on a chain whose estimate grows with the calldata, the largest set's
/// registration with its PQZ key's proof goes as `register` without `pqzPop`, then `storePqzPop`, then the KEM fill.
#[tokio::test(flavor = "multi_thread")]
async fn sponsored_pq_blob_split() {
    let t = setup().await;
    let b = blob("mldsa65/n2816-kmax65536/kem-commit");
    let ua = b["ua"].as_str().unwrap().to_string();
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    kind_enabled(&t, b["kind"].as_u64().unwrap() as u16, true);
    // 400 gas per calldata byte: the full call (~63 KB) is above the 2^24 cap, the part without `pqzPop` (~28 KB) fits
    t.chain.lock().unwrap().gas_of = Some(|input: &str| input.len() as u64 * 200);
    let blob = RegistrationBlob::from_json(&b.to_string()).unwrap();
    let ws = t
        .sdk
        .account()
        .prepare_submit_registration(blob.clone(), "local".into(), ua.clone(), t.payer.clone())
        .await
        .unwrap();
    let entries: Vec<String> = ws.iter().map(|w| w.entry()).collect();
    assert_eq!(entries, ["register", "storePqzPop", "setKemKey"]);
    // the control: an estimate within the cap sends it whole
    t.chain.lock().unwrap().gas_of = Some(|_| 1_000_000);
    let ws = t
        .sdk
        .account()
        .prepare_submit_registration(blob, "local".into(), ua, t.payer.clone())
        .await
        .unwrap();
    let entries: Vec<String> = ws.iter().map(|w| w.entry()).collect();
    assert_eq!(entries, ["register", "setKemKey"]);
}

/// A failed signing of the payer's transaction leaves the write submittable (owner 2026-11-19, R4): the payer's seed
/// locked, `WalletLocked`; unlocked again, the same write submits.
#[tokio::test(flavor = "multi_thread")]
async fn registry_write_kept_on_signing_failure() {
    use scaas_sdk::vault::Unlock;
    let t = setup().await;
    let (ua, _, _) = independent_register(ED25519);
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    let acc = t.sdk.account();
    let ws = acc.prepare_register(req(&t, ED25519, false)).await.unwrap();
    let q = acc.quote_registry_write(ws[0].clone()).await.unwrap();
    t.sdk.vault().lock(t.seed.clone()).await;
    assert_eq!(code(acc.submit_registry_write(ws[0].clone(), q.clone()).await), "WalletLocked");
    t.sdk
        .vault()
        .unlock(t.seed.clone(), Unlock::Passphrase(sec(PASS.as_bytes())))
        .await
        .unwrap();
    assert!(acc.submit_registry_write(ws[0].clone(), q).await.is_ok(), "the same write, again");
}

/// A pay to an unregistered derived UA is `ReceiverUnregistered` before anything is prepared; a registered one, or a native
/// id, passes that check.
#[tokio::test(flavor = "multi_thread")]
async fn pay_to_unregistered_derived_ua() {
    use scaas_sdk::wallet::{Envelope, Pay, PayBody, PayMeta};
    let t = setup().await;
    let ua = blob("ed25519")["ua"].as_str().unwrap().to_string();
    let pay = |to: &str| Pay {
        signer: t.payer.clone(),
        chain: "local".into(),
        token: format!("0x{}", "7a".repeat(20)),
        to: to.into(),
        value: "1".into(),
        meta: PayMeta {
            salt: None,
            pay_no: None,
            save: false,
            body: PayBody::Note { note: "x".into() },
        },
        envelope: Envelope {
            valid_until: 1_800_000_600,
            mode: 0,
            relayer: None,
            fee: "0".into(),
            fee_recipient: None,
        },
    };
    registry(&t, &ua, false, &hx(&[0; 32]), false);
    assert_eq!(code(t.sdk.wallet().prepare_pay(pay(&ua)).await), "ReceiverUnregistered");
    registry(&t, &ua, true, &hx(&[0; 32]), false);
    assert_ne!(code(t.sdk.wallet().prepare_pay(pay(&ua)).await), "ReceiverUnregistered");
    let native = format!("0x{}{}", "00".repeat(12), "ca".repeat(20));
    assert_ne!(code(t.sdk.wallet().prepare_pay(pay(&native)).await), "ReceiverUnregistered");
    // a profile naming no registry: fail closed for a derived UA (owner 2026-11-19, R3); a native id still passes
    let n = setup_with(None).await;
    let pay = |to: &str| Pay {
        signer: n.payer.clone(),
        ..pay(to)
    };
    assert_eq!(code(n.sdk.wallet().prepare_pay(pay(&ua)).await), "ReceiverUnregistered");
    assert_ne!(code(n.sdk.wallet().prepare_pay(pay(&native)).await), "ReceiverUnregistered");
}
