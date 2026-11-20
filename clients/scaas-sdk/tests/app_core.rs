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
