// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T5: `vault.derive_child` (BIP-85, spec §6.4): the child of clientkeys' row, `class` and `warnings` inherited,
//! `SeedExists`, the high-water mark never reused after a removal, the parent unlocked.
#![allow(clippy::unwrap_used)]

use scaas_sdk::vault::{
    ConfirmRemove, ConfirmRemoveUnbacked, DeriveChild, ImportWords, MemoryStore, Remove, Unlock,
};
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";

fn sec(s: &str) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(s.as_bytes().to_vec())).unwrap())
}

fn rows() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/keys/bip85.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

async fn sdk() -> Arc<Sdk> {
    Sdk::open(SdkConfig {
        profiles: vec![],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
    })
    .await
    .unwrap()
}

async fn import(s: &Arc<Sdk>, label: &str, words: &str) -> String {
    let req = ImportWords {
        label: label.into(),
        words: sec(words),
        vault_passphrase: sec(PASS),
    };
    s.vault().import_words(req).await.unwrap().id
}

fn child(parent: &str, label: &str) -> DeriveChild {
    DeriveChild {
        parent: parent.into(),
        label: label.into(),
        vault_passphrase: sec(PASS),
    }
}

fn words_of(n: &scaas_sdk::vault::NewSeed) -> String {
    n.backup
        .reveal()
        .unwrap()
        .with(|b| String::from_utf8(b.to_vec()).unwrap())
}

#[tokio::test]
async fn derive_child_is_the_rows_child_and_inherits() {
    let v = rows();
    let s = sdk().await;
    let parent = import(&s, "Parent", v["mnemonic"].as_str().unwrap()).await;
    let c0 = s.vault().derive_child(child(&parent, "C0")).await.unwrap();
    assert_eq!(words_of(&c0), v["children"][0]["words"].as_str().unwrap());
    assert_eq!(
        (
            c0.info.origin.as_str(),
            c0.info.backup.as_str(),
            c0.info.words
        ),
        ("bip85", "pending", 24)
    );
    assert_eq!(c0.info.warnings, Vec::<String>::new());
    // a short_seed parent gives a short_seed child
    let short = import(&s, "Short", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").await;
    let sc = s.vault().derive_child(child(&short, "SC")).await.unwrap();
    assert_eq!(
        (sc.info.warnings, sc.info.words),
        (vec!["short_seed".to_owned()], 24)
    );
}

#[tokio::test]
async fn remove_then_derive_never_reuses() {
    let v = rows();
    let s = sdk().await;
    let parent = import(&s, "Parent", v["mnemonic"].as_str().unwrap()).await;
    let c0 = s.vault().derive_child(child(&parent, "C0")).await.unwrap();
    let r = Remove {
        seed: c0.info.id.clone(),
        confirm: ConfirmRemove,
        unbacked: Some(ConfirmRemoveUnbacked),
    };
    s.vault().remove(r).await.unwrap();
    // lock and unlock the parent: the index comes from the stored manifest, not from memory
    s.vault().lock(parent.clone()).await;
    s.vault()
        .unlock(parent.clone(), Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    let c1 = s.vault().derive_child(child(&parent, "C1")).await.unwrap();
    assert_eq!(
        words_of(&c1),
        v["children"][1]["words"].as_str().unwrap(),
        "index 1, never 0 again"
    );
}

#[tokio::test]
async fn seed_exists_and_the_parent_unlocked() {
    let v = rows();
    let s = sdk().await;
    let parent = import(&s, "Parent", v["mnemonic"].as_str().unwrap()).await;
    // the child's words imported first: its derivation is SeedExists
    let c0 = v["children"][0]["words"].as_str().unwrap();
    import(&s, "C0 imported", c0).await;
    assert_eq!(
        s.vault()
            .derive_child(child(&parent, "C0"))
            .await
            .err()
            .map(|e| e.code()),
        Some("SeedExists")
    );
    s.vault().lock(parent.clone()).await;
    assert_eq!(
        s.vault()
            .derive_child(child(&parent, "X"))
            .await
            .err()
            .map(|e| e.code()),
        Some("WalletLocked")
    );
    // a hidden set's id is no stored seed
    s.vault()
        .unlock(parent.clone(), Unlock::Passphrase(sec(PASS)))
        .await
        .unwrap();
    let h = s
        .vault()
        .open_hidden(parent.clone(), Unlock::Passphrase(sec(PASS)), sec("h"))
        .await
        .unwrap();
    assert_eq!(
        s.vault()
            .derive_child(child(&h.id, "Y"))
            .await
            .err()
            .map(|e| e.code()),
        Some("WalletLocked")
    );
    // control: the next index derives
    let c1 = s.vault().derive_child(child(&parent, "C1")).await.unwrap();
    assert_eq!(words_of(&c1), v["children"][1]["words"].as_str().unwrap());
}
