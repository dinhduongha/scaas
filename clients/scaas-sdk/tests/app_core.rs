// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T21 (spec §12; CLI-SDK-19, CLI-SDK-20): the `app_core` surface. A scope's label prefixes (`AppLabelRefused` for an
//! overlap, either order), handles of one usage that never leave `scaas-ua` (`AppHandleForeign`, `AppKeyUsage`, revoked at the
//! seed's lock), plaintexts as `SecretBytes` only, the KEM wrap to the account's own key and back, the app root key, and app
//! record signing on both paths with the review and each refusal by name beside its control. Local only (no chain is read: a
//! chain-bound UA-key record needs the profile alone).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]
use scaas_sdk::app_core::{AppCore, AppDesc, AppKeyUsage, AppNonce, AppPath};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::{SecretBytes, Signer, Wallet};
use serde_json::json;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const REGISTRY: &str = "0x5ca00000000000000000000000000000000000a1";
const TOKEN: &str = "0x5ca00000000000000000000000000000000000b2";
const APP_CONTRACT: &str = "0x00000000000000000000000000000000000000aa";
const CHAIN_ID: u64 = 31337;
const APP_ID: &str = "0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}
fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}
fn profile() -> ChainProfile {
    ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: format!("0x{}", "60".repeat(32)),
        rpc: vec![EndpointConfig {
            url: "http://127.0.0.1:9".into(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: Some(REGISTRY.into()),
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
        tokens: vec![scaas_sdk::config::ListedToken {
            address: TOKEN.into(),
            symbol: "T".into(),
            decimals: 6,
        }],
        l1_fee: None,
        disabled_kinds: vec![],
        family_params: None,
    }
}
async fn sdk() -> (Arc<Sdk>, String) {
    let s = Sdk::open(SdkConfig {
        profiles: vec![profile()],
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
    let id = s
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO),
            vault_passphrase: sec(PASS),
        })
        .await
        .unwrap()
        .id;
    (s, id)
}
fn desc(app_id: Option<&str>, labels: &[&str]) -> AppDesc {
    AppDesc {
        app_id: app_id.map(str::to_string),
        name: "My App".into(),
        class: None,
        labels: labels.iter().map(|s| s.to_string()).collect(),
    }
}
fn ua(seed: &str, kind: u16) -> KeyRef {
    KeyRef::Ua {
        seed: seed.into(),
        kind,
        account: 0,
        index: 0,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn labels_scope_and_handles() {
    let (s, seed) = sdk().await;
    let a = AppCore::new(s.clone(), desc(Some(APP_ID), &["scaas/appa/v1/"])).unwrap();
    // an overlapping prefix, either order, refused; a disjoint one accepted; after a's drop the overlap is free
    assert_eq!(
        code(AppCore::new(s.clone(), desc(None, &["scaas/appa/"]))),
        "AppLabelRefused"
    );
    assert_eq!(
        code(AppCore::new(s.clone(), desc(None, &["scaas/appa/v1/x/"]))),
        "AppLabelRefused"
    );
    assert_eq!(
        code(AppCore::new(
            s.clone(),
            desc(None, &["scaas/b/", "scaas/b/c/"])
        )),
        "AppLabelRefused"
    );
    let b = AppCore::new(s.clone(), desc(None, &["scaas/appb/v1/"])).unwrap();
    assert_eq!(
        code(AppCore::new(
            s.clone(),
            desc(Some(&format!("0x{}", "00".repeat(32))), &["scaas/z/"])
        )),
        "Argument"
    );
    // handles: a labelled derivation, the label outside the prefix refused
    let k = a.random_key(&seed, AppKeyUsage::Derive).unwrap();
    let data = a
        .derive(
            vec![k.clone()],
            vec![],
            b"scaas/appa/v1/data".to_vec(),
            vec![1, 2],
            AppKeyUsage::Data,
            false,
        )
        .unwrap();
    assert_eq!(
        code(a.derive(
            vec![k.clone()],
            vec![],
            b"scaas/appb/v1/data".to_vec(),
            vec![],
            AppKeyUsage::Data,
            false
        )),
        "AppLabelRefused"
    );
    // seal / open: the plaintext out as SecretBytes only; another usage refused; another core's handle refused
    let ct = a
        .seal(
            data.clone(),
            AppNonce::Random,
            b"aad".to_vec(),
            b"secret note".to_vec(),
        )
        .unwrap();
    let pt = a
        .open(data.clone(), AppNonce::Random, b"aad".to_vec(), ct.clone())
        .unwrap();
    pt.with(|b| assert_eq!(b, b"secret note"));
    assert_eq!(
        code(a.open(k.clone(), AppNonce::Random, b"aad".to_vec(), ct.clone())),
        "AppKeyUsage"
    );
    assert_eq!(
        code(b.open(data.clone(), AppNonce::Random, b"aad".to_vec(), ct.clone())),
        "AppHandleForeign"
    );
    // nor may another core destroy it: the handle stays usable (the control: its own core's open above)
    assert_eq!(code(b.destroy(data.clone())), "AppHandleForeign");
    assert!(a
        .open(data.clone(), AppNonce::Random, b"aad".to_vec(), ct.clone())
        .is_ok());
    // a chain step may not rebuild a labelled key of any core; a plain step is fine
    assert_eq!(
        code(a.mac_derive(
            k.clone(),
            b"scaas/appb/v1/hint".to_vec(),
            AppKeyUsage::Derive
        )),
        "AppLabelRefused"
    );
    assert!(a
        .mac_derive(k.clone(), vec![1], AppKeyUsage::Derive)
        .is_ok());
    // seal_key / open_key keep the usage
    let kw = a.random_key(&seed, AppKeyUsage::KeyWrap).unwrap();
    let wire = a.seal_key(kw.clone(), data.clone(), b"w".to_vec()).unwrap();
    let back = a
        .open_key(kw.clone(), wire.clone(), AppKeyUsage::Data, b"w".to_vec())
        .unwrap();
    assert!(a.same_key(back, data.clone()).unwrap());
    assert_eq!(
        code(a.open_key(kw, wire, AppKeyUsage::Derive, b"w".to_vec())),
        "Aead"
    );
    // destroy, then the seed's lock revokes the rest
    a.destroy(k.clone()).unwrap();
    assert_eq!(
        code(a.mac_derive(k, vec![1], AppKeyUsage::Derive)),
        "KeyRevoked"
    );
    s.vault().lock(seed.clone()).await;
    assert!(matches!(
        code(a.open(data, AppNonce::Random, b"aad".to_vec(), ct)),
        "KeyRevoked" | "WalletLocked"
    ));
    drop(b);
    // the control: once a core is gone, its prefixes are free again
    drop(a);
    assert!(AppCore::new(s.clone(), desc(None, &["scaas/appa/"])).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn kem_wrap_and_app_root() {
    let (s, seed) = sdk().await;
    let a = AppCore::new(s.clone(), desc(Some(APP_ID), &["scaas/appc/v1/"])).unwrap();
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let kem_pk = w.ua_key(0x0131, 0, 0).unwrap().kem_key(0).unwrap().kem_pk();
    let k = a.random_key(&seed, AppKeyUsage::Derive).unwrap();
    let label = b"scaas/appc/v1/wrap".to_vec();
    let wrap = a
        .kem_wrap_to_key(kem_pk, k.clone(), label.clone(), b"ctx".to_vec())
        .unwrap();
    let back = a
        .kem_unwrap(
            ua(&seed, 0x0131),
            0,
            wrap.clone(),
            label.clone(),
            b"ctx".to_vec(),
            AppKeyUsage::Derive,
        )
        .unwrap();
    assert!(a.same_key(back, k).unwrap());
    assert_eq!(
        code(a.kem_unwrap(
            ua(&seed, 0x0131),
            0,
            wrap,
            label,
            b"other".to_vec(),
            AppKeyUsage::Derive
        )),
        "Aead"
    );
    let r1 = a.app_root_key(ua(&seed, 0x0108)).unwrap();
    let r2 = a.app_root_key(ua(&seed, 0x0108)).unwrap();
    let r3 = a.app_root_key(ua(&seed, 0x0101)).unwrap();
    assert!(a.same_key(r1.clone(), r2).unwrap());
    assert!(!a.same_key(r1, r3).unwrap());
    let none = AppCore::new(s.clone(), desc(None, &["scaas/appd/v1/"])).unwrap();
    assert_eq!(code(none.app_root_key(ua(&seed, 0x0108))), "Argument");
}

fn record(domain: serde_json::Value) -> String {
    let mut fields = vec![
        json!({"name": "name", "type": "string"}),
        json!({"name": "version", "type": "string"}),
    ];
    for (k, t) in [
        ("chainId", "uint256"),
        ("verifyingContract", "address"),
        ("salt", "bytes32"),
    ] {
        if domain.get(k).is_some() {
            fields.push(json!({"name": k, "type": t}));
        }
    }
    json!({
        "types": {"EIP712Domain": fields, "Note": [{"name": "id", "type": "bytes32"}, {"name": "body", "type": "string"}]},
        "primaryType": "Note",
        "domain": domain,
        "message": {"id": format!("0x{}", "11".repeat(32)), "body": "hello"},
    })
    .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn app_records_both_paths() {
    let (s, seed) = sdk().await;
    let a = AppCore::new(s.clone(), desc(Some(APP_ID), &["scaas/appe/v1/"])).unwrap();
    let key = ua(&seed, 0x0108);
    let w = Wallet::from_mnemonic(REPO, "").unwrap();
    let scaas_ua::wallet::KeyRef::Ua { key_data, .. } = w.ua_key(0x0108, 0, 0).unwrap().key_ref()
    else {
        panic!()
    };
    // path A: the control signed, reviewed and verified
    let pa = record(json!({"name": "My App", "version": "1", "salt": APP_ID}));
    let signed = a
        .sign_app_record(key.clone(), AppPath::Portable, pa.clone())
        .await
        .unwrap();
    let f = |n: &str| {
        signed
            .review
            .iter()
            .find(|r| r.name == n)
            .map(|r| r.value.clone())
    };
    assert_eq!(f("domain.name").as_deref(), Some("My App"));
    assert_eq!(f("domain.salt").as_deref(), Some(APP_ID));
    assert_eq!(f("message.body").as_deref(), Some("hello"));
    assert!(a
        .verify_app_record_key(
            0x0108,
            key_data.clone(),
            AppPath::Portable,
            None,
            pa,
            signed.signature
        )
        .unwrap());
    // path A refusals
    let other_salt =
        record(json!({"name": "My App", "version": "1", "salt": format!("0x{}", "5b".repeat(32))}));
    assert_eq!(
        code(
            a.sign_app_record(key.clone(), AppPath::Portable, other_salt)
                .await
        ),
        "AppSaltMismatch"
    );
    let scaas = record(json!({"name": "SCaaS UARegistry", "version": "1", "salt": APP_ID}));
    assert_eq!(
        code(
            a.sign_app_record(key.clone(), AppPath::Portable, scaas)
                .await
        ),
        "AppDomainRefused"
    );
    let none = AppCore::new(s.clone(), desc(None, &["scaas/appf/v1/"])).unwrap();
    let pa2 = record(json!({"name": "My App", "version": "1", "salt": APP_ID}));
    assert_eq!(
        code(
            none.sign_app_record(key.clone(), AppPath::Portable, pa2)
                .await
        ),
        "Argument"
    );
    // path B: the control (the app's contract, the profile's chain), then each refusal
    let b = |chain_id: u64, contract: &str| {
        record(
            json!({"name": "My App", "version": "1", "chainId": chain_id.to_string(), "verifyingContract": contract}),
        )
    };
    let cb = AppPath::ChainBound {
        chain: "local".into(),
        purpose: None,
    };
    let signed = a
        .sign_app_record(key.clone(), cb.clone(), b(CHAIN_ID, APP_CONTRACT))
        .await
        .unwrap();
    assert!(a
        .verify_app_record_key(
            0x0108,
            key_data,
            cb.clone(),
            None,
            b(CHAIN_ID, APP_CONTRACT),
            signed.signature
        )
        .unwrap());
    assert_eq!(
        code(
            a.sign_app_record(key.clone(), cb.clone(), b(1, APP_CONTRACT))
                .await
        ),
        "AppDomainRefused"
    );
    assert_eq!(
        code(
            a.sign_app_record(key.clone(), cb.clone(), b(CHAIN_ID, REGISTRY))
                .await
        ),
        "AppDomainRefused"
    );
    assert_eq!(
        code(
            a.sign_app_record(key.clone(), cb.clone(), b(CHAIN_ID, TOKEN))
                .await
        ),
        "AppDomainRefused"
    );
    let scaas_purpose = format!(
        "0x{}",
        hexs(&scaas_ua::keccak256(b"scaas.ua.purpose.metatx.v1"))
    );
    let p = AppPath::ChainBound {
        chain: "local".into(),
        purpose: Some(scaas_purpose),
    };
    assert_eq!(
        code(a.sign_app_record(key, p, b(CHAIN_ID, APP_CONTRACT)).await),
        "AppPurposeRefused"
    );
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Spec §12.1: the SDK depends on no app core and on no Matrix SDK (its lock file names none; the control: it names scaas-ua).
#[test]
fn no_app_core_below_the_sdk() {
    let lock =
        std::fs::read_to_string(format!("{}/Cargo.lock", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let names: Vec<&str> = lock
        .lines()
        .filter_map(|l| l.strip_prefix("name = \""))
        .map(|l| l.trim_end_matches('"'))
        .collect();
    assert!(names.contains(&"scaas-ua"));
    for bad in [
        "pqchat-core",
        "pqvault-core",
        "matrix-sdk",
        "app-core-rust",
        "app-matrix",
    ] {
        assert!(!names.iter().any(|n| n.starts_with(bad)), "{bad}");
    }
}

// --- part 4b on the fake chain (tests/common/fake_chain.rs): the KEM wrap to a UA, record verification, the factory-class
// domain check, prepare_app_call ---

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, keccak_hex, serve, Fake};
use scaas_sdk::app_core::{AppInnerSig, AppMemberSig, AppUaSig};
use scaas_ua::wallet::Network;

const FACTORY: &str = "0x5ca00000000000000000000000000000000000f1";

fn w(n: u64) -> String {
    format!("{n:064x}")
}
fn pad(b: &[u8]) -> String {
    let mut s = hexs(b);
    while !s.len().is_multiple_of(64) {
        s.push('0');
    }
    s
}
fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}
/// The fake contract `to` answers `sig(arg…)` (calldata prefix) with `out` (hex without `0x`).
fn answer(c: &Fake, to: &str, sig: &str, arg: &[u8], out: String) {
    let mut c = c.lock().unwrap();
    let prefix = format!("{}{}", sel(sig), hexs(arg));
    c.answers.retain(|(t, d, _)| !(t == to && *d == prefix));
    c.answers.push((to.into(), prefix, format!("0x{out}")));
}
fn word32(n: u64) -> Vec<u8> {
    let mut v = [0u8; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    v.to_vec()
}

async fn on_fake(factory: Option<&str>, class: scaas_rpc::Class) -> (Arc<Sdk>, String, Fake) {
    let chain = fake();
    let url = serve(chain.clone()).await;
    let mut p = profile();
    p.chain_uid = chain.lock().unwrap().genesis.clone();
    p.rpc[0].url = url;
    p.rpc[0].class = class;
    p.factory = factory.map(Into::into);
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
    (s, seed, chain)
}

/// `kemKeyAt(ua, v)`: `(KemKey(scheme, mlkemEk, x25519), bytes sig)` of the KEM key `scheme ‖ ek ‖ x`.
fn kem_answer(c: &Fake, ua: &[u8; 32], v: u64, scheme: u64, ek: &[u8], x: &[u8]) {
    let sig_at = 0x40 + 0x60 + 0x20 + pad(ek).len() as u64 / 2;
    let out = format!(
        "{}{}{}{}{}{}{}{}",
        w(0x40),
        w(sig_at),
        w(scheme),
        w(0x60),
        hexs(x),
        w(ek.len() as u64),
        pad(ek),
        w(0)
    );
    answer(
        c,
        REGISTRY,
        "kemKeyAt(bytes32,uint64)",
        &[ua.to_vec(), word32(v)].concat(),
        out,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kem_wrap_to_a_ua_reads_its_key_at_the_final_block() {
    let (s, seed, chain) = on_fake(None, scaas_rpc::Class::Named).await;
    let a = AppCore::new(s.clone(), desc(Some(APP_ID), &["scaas/kwua/v1/"])).unwrap();
    let w0 = Wallet::from_mnemonic(REPO, "").unwrap();
    let uk = w0.ua_key(0x0131, 0, 0).unwrap();
    let id = uk.ua().unwrap();
    let pk = uk.kem_key(1).unwrap().kem_pk();
    let (ek, x) = (&pk[1..1 + 1568], &pk[1 + 1568..]);
    kem_answer(&chain, &id, 1, 1, ek, x);
    let label = b"scaas/kwua/v1/wrap".to_vec();
    let k = a.random_key(&seed, AppKeyUsage::Data).unwrap();
    let wrap = |v: u64, l: Vec<u8>| {
        let (a, k) = (a.clone(), k.clone());
        async move {
            a.kem_wrap(
                "local".into(),
                format!("0x{}", hexs(&id)),
                v,
                k,
                l,
                b"ctx".to_vec(),
            )
            .await
        }
    };
    // the control: the account unwraps it at that version
    let wr = wrap(1, label.clone()).await.unwrap();
    let back = a
        .kem_unwrap(
            ua(&seed, 0x0131),
            1,
            wr,
            label.clone(),
            b"ctx".to_vec(),
            AppKeyUsage::Data,
        )
        .unwrap();
    assert!(a.same_key(back, k.clone()).unwrap());
    // the read: by block hash, canonical, at the final block
    let reqs = chain.lock().unwrap().requests.clone();
    let r = reqs
        .iter()
        .find(|r| r.contains(&sel("kemKeyAt(bytes32,uint64)")[2..]))
        .unwrap();
    assert!(
        r.contains("blockHash") && r.contains("requireCanonical"),
        "{r}"
    );
    // one change at a time: no key at that version (scheme 0), another scheme, a short key, a label outside the prefixes
    kem_answer(&chain, &id, 1, 0, ek, x);
    assert_eq!(code(wrap(1, label.clone()).await), "KemCheck");
    kem_answer(&chain, &id, 1, 2, ek, x);
    assert_eq!(code(wrap(1, label.clone()).await), "KemCheck");
    kem_answer(&chain, &id, 1, 1, &ek[..1536], x);
    assert_eq!(code(wrap(1, label.clone()).await), "KemCheck");
    kem_answer(&chain, &id, 1, 1, ek, x);
    assert_eq!(
        code(wrap(1, b"scaas/other/v1/".to_vec()).await),
        "AppLabelRefused"
    );
    assert!(wrap(1, label.clone()).await.is_ok());
    // a list of discovered nodes only: never asked for a read that feeds a decryption (ARCH-POS-15)
    let (s2, seed2, chain2) = on_fake(None, scaas_rpc::Class::Discovered).await;
    kem_answer(&chain2, &id, 1, 1, ek, x);
    let a2 = AppCore::new(s2, desc(Some(APP_ID), &["scaas/kwub/v1/"])).unwrap();
    let k2 = a2.random_key(&seed2, AppKeyUsage::Data).unwrap();
    let r2 = a2
        .kem_wrap(
            "local".into(),
            format!("0x{}", hexs(&id)),
            1,
            k2,
            b"scaas/kwub/v1/w".to_vec(),
            vec![],
        )
        .await;
    assert_eq!(code(r2), "NoTrustedEndpoint");
    assert!(!chain2
        .lock()
        .unwrap()
        .requests
        .iter()
        .any(|r| r.contains(&sel("kemKeyAt(bytes32,uint64)")[2..])));
}

/// `registrationOf(id)`: `(uint16 kind, bytes keyData, …)` (the rest unread here).
fn reg_answer(c: &Fake, id: &[u8; 32], kind: u16, kd: &[u8]) {
    let out = format!(
        "{}{}{}{}{}{}{}",
        w(u64::from(kind)),
        w(0xa0),
        w(0),
        w(0),
        w(0),
        w(kd.len() as u64),
        pad(kd)
    );
    answer(c, REGISTRY, "registrationOf(bytes32)", id, out);
}
fn state_answer(c: &Fake, id: &[u8; 32], enabled: u64, accepted: u64) {
    answer(
        c,
        REGISTRY,
        "msigStateOf(bytes32)",
        id,
        format!("{}{}{}", w(0), w(enabled), w(accepted)),
    );
}
fn app_sig(s: &scaas_ua::ua_portable::UASig) -> AppUaSig {
    AppUaSig {
        key_data: s.key_data.clone(),
        signature: s.signature.clone(),
        members: s
            .members
            .iter()
            .map(|m| AppMemberSig {
                index: m.index,
                members: m
                    .members
                    .iter()
                    .map(|x| AppInnerSig {
                        index: x.index,
                        sig: x.sig.clone(),
                    })
                    .collect(),
                sig: m.sig.clone(),
            })
            .collect(),
    }
}

/// `verify_app_record` against the registry's records (spec §12.2, review r2 R7): a derived key on both paths, a native key on
/// path B, an `msig` of a derived and a native member on both paths; each refusal one change at a time beside its control.
#[tokio::test(flavor = "multi_thread")]
async fn verify_app_record_reads_the_registry() {
    let (s, seed, chain) = on_fake(None, scaas_rpc::Class::Named).await;
    let a = AppCore::new(s.clone(), desc(Some(APP_ID), &["scaas/vfy/v1/"])).unwrap();
    let wl = Wallet::from_mnemonic(REPO, "").unwrap();
    let k1 = wl.ua_key(0x0108, 0, 0).unwrap();
    let scaas_ua::wallet::KeyRef::Ua { key_data: kd1, .. } = k1.key_ref() else {
        panic!()
    };
    let id1 = k1.ua().unwrap();
    let nat = wl.native_key(Network::Evm, 0, None).unwrap();
    let mut nid = [0u8; 32];
    nid[12..].copy_from_slice(
        &alloy::hex::decode(nat.address().unwrap().trim_start_matches("0x")).unwrap(),
    );
    answer(&chain, REGISTRY, "predecessor()", &[], w(0));
    let pa = record(json!({"name": "My App", "version": "1", "salt": APP_ID}));
    let cb = record(
        json!({"name": "My App", "version": "1", "chainId": CHAIN_ID.to_string(), "verifyingContract": APP_CONTRACT}),
    );
    let b = || AppPath::ChainBound {
        chain: "local".into(),
        purpose: None,
    };
    let hx = |b: &[u8; 32]| format!("0x{}", hexs(b));
    let verify = |ua: [u8; 32], p: AppPath, t: String, sig: AppUaSig| {
        let a = a.clone();
        async move {
            a.verify_app_record("local".into(), hx(&ua), p, t, sig)
                .await
                .unwrap()
        }
    };
    let signed = |p: AppPath, t: String, key: KeyRef| {
        let a = a.clone();
        async move {
            let s = a.sign_app_record(key, p, t).await.unwrap();
            AppUaSig {
                key_data: s.key_data,
                signature: s.signature,
                members: vec![],
            }
        }
    };

    // a derived key: unregistered first, then registered
    reg_answer(&chain, &id1, 0, &[]);
    let sa = signed(AppPath::Portable, pa.clone(), ua(&seed, 0x0108)).await;
    assert!(
        !verify(id1, AppPath::Portable, pa.clone(), sa.clone()).await,
        "unregistered"
    );
    reg_answer(&chain, &id1, 0x0108, &kd1);
    assert!(verify(id1, AppPath::Portable, pa.clone(), sa.clone()).await);
    let mut bad = sa.clone();
    bad.signature[5] ^= 1;
    assert!(
        !verify(id1, AppPath::Portable, pa.clone(), bad).await,
        "a changed signature"
    );
    let sb = signed(b(), cb.clone(), ua(&seed, 0x0108)).await;
    assert!(verify(id1, b(), cb.clone(), sb.clone()).await);
    assert!(
        !verify(id1, AppPath::Portable, pa.clone(), sb.clone()).await,
        "another path"
    );
    let other = AppPath::ChainBound {
        chain: "other".into(),
        purpose: None,
    };
    assert_eq!(
        code(
            a.verify_app_record("local".into(), hx(&id1), other, cb.clone(), sb)
                .await
        ),
        "Argument"
    );

    // a native key on path B
    let native = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let sn = signed(b(), cb.clone(), native).await;
    assert!(verify(nid, b(), cb.clone(), sn.clone()).await);
    assert!(
        !verify(nid, AppPath::Portable, pa.clone(), sn.clone()).await,
        "no portable record"
    );
    answer(&chain, REGISTRY, "predecessor()", &[], w(1));
    assert_eq!(
        code(
            a.verify_app_record("local".into(), hx(&nid), b(), cb.clone(), sn)
                .await
        ),
        "Argument",
        "a registry of another generation"
    );
    answer(&chain, REGISTRY, "predecessor()", &[], w(0));

    // an msig {k1, native}, threshold 2, both slots accepted
    let mut m = vec![(0x0108u16, id1, 1u16), (1, nid, 1)];
    m.sort_by_key(|x| x.1);
    let kd = scaas_ua::encode_msig(2, &m);
    let ms = scaas_ua::derive_ua(0x0120, &kd, false).unwrap();
    reg_answer(&chain, &ms, 0x0120, &kd);
    state_answer(&chain, &ms, 0b11, 0b11);
    let (i1, i_n) = if m[0].1 == id1 { (0u16, 1u16) } else { (1, 0) };
    let mut slots = vec![
        (
            i1,
            scaas_ua::wallet::Slot::Member {
                index: i1,
                key: &k1,
            },
        ),
        (
            i_n,
            scaas_ua::wallet::Slot::Member {
                index: i_n,
                key: &nat,
            },
        ),
    ];
    slots.sort_by_key(|x| x.0);
    let slots: Vec<_> = slots.into_iter().map(|x| x.1).collect();
    let app_id: [u8; 32] = alloy::hex::decode(&APP_ID[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let ptd = scaas_ua::wallet::TypedData::from_json(pa.as_bytes()).unwrap();
    let ma =
        scaas_ua::wallet::msig_sig_app(&kd, &|_| None, &|_| None, &app_id, &ptd, &slots).unwrap();
    assert!(verify(ms, AppPath::Portable, pa.clone(), app_sig(&ma)).await);
    state_answer(&chain, &ms, 0b11, 1 << i1);
    assert!(
        !verify(ms, AppPath::Portable, pa.clone(), app_sig(&ma)).await,
        "a slot not accepted"
    );
    state_answer(&chain, &ms, 1 << i1, 0b11);
    assert!(
        !verify(ms, AppPath::Portable, pa.clone(), app_sig(&ma)).await,
        "a slot not enabled"
    );
    state_answer(&chain, &ms, 0b11, 0b11);
    reg_answer(&chain, &id1, 0, &[]);
    assert!(
        !verify(ms, AppPath::Portable, pa.clone(), app_sig(&ma)).await,
        "a member unregistered"
    );
    reg_answer(&chain, &id1, 0x0108, &kd1);
    // path B: k1 under `member`, the native member over UAAuth in the registry's domain
    let ctd = scaas_ua::wallet::TypedData::from_json(cb.as_bytes()).unwrap();
    let purpose = scaas_ua::ua_portable::app_purpose(&app_id).unwrap();
    let md = scaas_ua::member_digest(
        &ms,
        &scaas_ua::ua_message(0x0120, &purpose, &ctd.digest().unwrap()).unwrap(),
    );
    let member = scaas_ua::purpose_tag("member").unwrap();
    let reg: [u8; 20] = alloy::hex::decode(&REGISTRY[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let dom = scaas_ua::Domain {
        generation: 1,
        chain_id: CHAIN_ID,
        registry: reg,
        chain_uid: alloy::hex::decode(&chain.lock().unwrap().genesis[2..])
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let mut mb = vec![
        AppMemberSig {
            index: i1,
            members: vec![],
            sig: scaas_ua::wallet::ua_sig(&k1, None, &member, &md)
                .unwrap()
                .signature,
        },
        AppMemberSig {
            index: i_n,
            members: vec![],
            sig: scaas_ua::wallet::ua_sig(&nat, Some(&dom), &member, &md)
                .unwrap()
                .signature,
        },
    ];
    mb.sort_by_key(|x| x.index);
    let mb = AppUaSig {
        members: mb,
        ..Default::default()
    };
    assert!(verify(ms, b(), cb.clone(), mb.clone()).await);
    assert!(
        !verify(ms, AppPath::Portable, pa.clone(), mb.clone()).await,
        "a path-B signature on path A"
    );
    let mut one = mb.clone();
    one.members.retain(|x| x.index == i1);
    assert!(
        !verify(ms, b(), cb.clone(), one).await,
        "below the threshold"
    );
}

/// Spec §12.4: a chain-bound domain's `verifyingContract` made by the profile's factory is refused unless of the scope's class
/// (the factory's `infoOf` record); a contract the factory did not make (class 0) passes.
#[tokio::test(flavor = "multi_thread")]
async fn factory_instance_of_another_class_refused() {
    let (s, seed, chain) = on_fake(Some(FACTORY), scaas_rpc::Class::Named).await;
    let mut d = desc(Some(APP_ID), &["scaas/fcls/v1/"]);
    d.class = Some(7);
    let a = AppCore::new(s.clone(), d).unwrap();
    let none = AppCore::new(s.clone(), desc(Some(APP_ID), &["scaas/fclt/v1/"])).unwrap();
    let cb = record(
        json!({"name": "My App", "version": "1", "chainId": CHAIN_ID.to_string(), "verifyingContract": APP_CONTRACT}),
    );
    let mut c = [0u8; 32];
    c[12..].copy_from_slice(&alloy::hex::decode(&APP_CONTRACT[2..]).unwrap());
    let info = |class: u64| {
        format!(
            "{}{}{}{}{}{}{}",
            hexs(&c),
            w(9),
            w(class),
            w(1),
            w(1),
            w(1),
            w(1)
        )
    };
    let p = || AppPath::ChainBound {
        chain: "local".into(),
        purpose: None,
    };
    let sign = |core: &Arc<AppCore>| {
        let core = core.clone();
        let key = ua(&seed, 0x0108);
        let cb = cb.clone();
        async move { code(core.sign_app_record(key, p(), cb).await) }
    };
    answer(&chain, FACTORY, "infoOf(address)", &c, info(7));
    assert_eq!(sign(&a).await, "Ok");
    assert_eq!(sign(&none).await, "AppDomainRefused", "a scope of no class");
    answer(&chain, FACTORY, "infoOf(address)", &c, info(3));
    assert_eq!(sign(&a).await, "AppDomainRefused");
    answer(&chain, FACTORY, "infoOf(address)", &c, info(0));
    assert_eq!(sign(&a).await, "Ok");
    assert_eq!(sign(&none).await, "Ok");
}

alloy::sol! {
    struct TInner { uint16 index; bytes sig; }
    struct TMember { uint16 index; TInner[] members; bytes sig; }
    struct TUaSig { bytes keyData; bytes signature; TMember[] members; }
    function putNote(bytes32 id, TUaSig sig, uint64[] tags);
}

/// `prepare_app_call` (spec §12.2): the calldata of the named entry and arguments (a signed record as its `UASig` fields),
/// quoted for the payer and reviewed; each refusal one change at a time.
#[tokio::test(flavor = "multi_thread")]
async fn prepare_app_call_builds_named_calldata() {
    use alloy::sol_types::SolCall;
    let (s, seed, chain) = on_fake(Some(FACTORY), scaas_rpc::Class::Named).await;
    let mut d = desc(Some(APP_ID), &["scaas/call/v1/"]);
    d.class = Some(7);
    let a = AppCore::new(s.clone(), d).unwrap();
    let mut c = [0u8; 32];
    c[12..].copy_from_slice(&alloy::hex::decode(&APP_CONTRACT[2..]).unwrap());
    let info = |class: u64| {
        format!(
            "{}{}{}{}{}{}{}",
            hexs(&c),
            w(9),
            w(class),
            w(1),
            w(1),
            w(1),
            w(1)
        )
    };
    answer(&chain, FACTORY, "infoOf(address)", &c, info(7));
    let payer = KeyRef::Native {
        seed: seed.clone(),
        network: "evm".into(),
        index: 0,
    };
    let inner = json!([{"name": "index", "type": "uint16"}, {"name": "sig", "type": "bytes"}]);
    let member = json!([{"name": "index", "type": "uint16"},
        {"name": "members", "type": "tuple[]", "components": inner}, {"name": "sig", "type": "bytes"}]);
    let entry = json!({"type": "function", "name": "putNote", "stateMutability": "nonpayable", "outputs": [], "inputs": [
        {"name": "id", "type": "bytes32"},
        {"name": "sig", "type": "tuple", "components": [{"name": "keyData", "type": "bytes"},
            {"name": "signature", "type": "bytes"}, {"name": "members", "type": "tuple[]", "components": member}]},
        {"name": "tags", "type": "uint64[]"}]})
    .to_string();
    let entry = entry.as_str();
    let id = format!("0x{}", "11".repeat(32));
    let args = json!({"id": id, "sig": {"keyData": "0x", "signature": "0xabcd",
        "members": [{"index": 1, "members": [{"index": 0, "sig": "0x01"}], "sig": "0x"}]}, "tags": [1, "2"]});
    let call = |contract: &str, args: serde_json::Value| {
        let (a, p, contract) = (a.clone(), payer.clone(), contract.to_string());
        async move {
            a.prepare_app_call("local".into(), contract, entry.into(), args.to_string(), p)
                .await
        }
    };
    let got = call(APP_CONTRACT, args.clone()).await.unwrap();
    let want = putNoteCall {
        id: alloy::primitives::B256::repeat_byte(0x11),
        sig: TUaSig {
            keyData: vec![].into(),
            signature: vec![0xab, 0xcd].into(),
            members: vec![TMember {
                index: 1,
                members: vec![TInner {
                    index: 0,
                    sig: vec![1].into(),
                }],
                sig: vec![].into(),
            }],
        },
        tags: vec![1, 2],
    }
    .abi_encode();
    assert_eq!(got.quote.data, format!("0x{}", hexs(&want)));
    assert_eq!(got.quote.value, "0");
    assert_eq!(got.quote.to, APP_CONTRACT);
    let field = |n: &str| {
        got.review
            .iter()
            .find(|f| f.name == n)
            .map(|f| f.value.clone())
    };
    assert_eq!(field("args.sig.signature").as_deref(), Some("0xabcd"));
    assert_eq!(field("args.id").as_deref(), Some(id.as_str()));
    assert!(field("entry").unwrap().starts_with("putNote(bytes32,"));
    // one change at a time
    assert_eq!(
        code(call(TOKEN, args.clone()).await),
        "AppDomainRefused",
        "a listed token"
    );
    assert_eq!(
        code(call(REGISTRY, args.clone()).await),
        "AppDomainRefused",
        "the registry"
    );
    answer(&chain, FACTORY, "infoOf(address)", &c, info(3));
    assert_eq!(
        code(call(APP_CONTRACT, args.clone()).await),
        "AppDomainRefused",
        "another class"
    );
    answer(&chain, FACTORY, "infoOf(address)", &c, info(7));
    let mut missing = args.clone();
    missing.as_object_mut().unwrap().remove("tags");
    assert_eq!(
        code(call(APP_CONTRACT, missing).await),
        "Argument",
        "a name missing"
    );
    let mut extra = args.clone();
    extra["more"] = json!("1");
    assert_eq!(
        code(call(APP_CONTRACT, extra).await),
        "Argument",
        "a name not the entry's"
    );
    let mut wrong = args.clone();
    wrong["id"] = json!("0x11");
    assert_eq!(
        code(call(APP_CONTRACT, wrong).await),
        "Argument",
        "a value not of its type"
    );
    let mut inner = args.clone();
    inner["sig"].as_object_mut().unwrap().remove("keyData");
    assert_eq!(
        code(call(APP_CONTRACT, inner).await),
        "Argument",
        "a tuple without a component"
    );
    assert!(call(APP_CONTRACT, args).await.is_ok());
}
