// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T6 (feature `classical-roots`): `vault.derive_from_signature` (root (c)) and `vault.derive_from_key` (root (d)) over
//! clientkeys' rows (smartcontracts/vectors/keys/roots.json): the words, `class: classical-rooted` MAC'd and inherited by a
//! BIP-85 child, `OriginSignature` per check and `DerivationPassphraseShort`, each with its control.
#![allow(clippy::unwrap_used)]

use scaas_sdk::vault::{DeriveChild, DeriveFromKey, DeriveFromSignature, MemoryStore, Unlock};
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const VAULT_PASS: &str = "river-otter-7 ünï";

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rows() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/keys/roots.json");
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
    })
    .await
    .unwrap()
}

fn words(n: &scaas_sdk::vault::NewSeed) -> String {
    n.backup
        .reveal()
        .unwrap()
        .with(|b| String::from_utf8(b.to_vec()).unwrap())
}

fn by_sig(e: &Value, label: &str, s1: Vec<u8>, s2: Vec<u8>, pass: &str) -> DeriveFromSignature {
    DeriveFromSignature {
        label: label.into(),
        account: e["account"].as_str().unwrap().into(),
        set: 0,
        signature1: sec(&s1),
        signature2: sec(&s2),
        derivation_passphrase: sec(pass.as_bytes()),
        vault_passphrase: sec(VAULT_PASS.as_bytes()),
    }
}

fn code<T>(r: Result<T, scaas_sdk::SdkError>) -> &'static str {
    r.err().map(|e| e.code()).unwrap_or("Ok")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_c_words_class_and_inheritance() {
    let v = rows();
    let e = &v["eoaSig"];
    let s = sdk().await;
    // the typed data the external wallet signs, from scaas-ua
    let td: Value = serde_json::from_str(
        &s.vault()
            .key_derivation_typed_data(e["account"].as_str().unwrap().into(), 0)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(td["domain"]["salt"], e["typedData"]["domain"]["salt"]);
    assert_eq!(td["primaryType"], "KeyDerivation");
    assert!(td["domain"].get("chainId").is_none());
    let sig = unhex(&e["rows"][0]["signature"]);
    let pass = e["passphrase"].as_str().unwrap();
    let n = s
        .vault()
        .derive_from_signature(by_sig(e, "C", sig.clone(), sig.clone(), pass))
        .await
        .unwrap();
    assert_eq!(words(&n), e["rows"][0]["words"].as_str().unwrap());
    assert_eq!(
        (n.info.class.as_str(), n.info.origin.as_str(), n.info.words),
        ("classical-rooted", "eoa-sig", 24)
    );
    // the same root again: SeedExists; the compact form converted explicitly gives the same seed
    let compact = s
        .vault()
        .signature_from_compact(sec(&unhex(&e["rows"][3]["signature"])))
        .unwrap();
    let again = DeriveFromSignature {
        signature1: compact.clone(),
        signature2: compact,
        ..by_sig(e, "C2", vec![], vec![], pass)
    };
    assert_eq!(
        code(s.vault().derive_from_signature(again).await),
        "SeedExists"
    );
    // MAC'd (it survives a lock and unlock) and inherited by a BIP-85 child
    s.vault().lock(n.info.id.clone()).await;
    s.vault()
        .unlock(
            n.info.id.clone(),
            Unlock::Passphrase(sec(VAULT_PASS.as_bytes())),
        )
        .await
        .unwrap();
    let child = s
        .vault()
        .derive_child(DeriveChild {
            parent: n.info.id.clone(),
            label: "C child".into(),
            vault_passphrase: sec(VAULT_PASS.as_bytes()),
        })
        .await
        .unwrap();
    assert_eq!(child.info.class, "classical-rooted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_c_refusals_each_with_its_control() {
    let v = rows();
    let e = &v["eoaSig"];
    let s = sdk().await;
    for r in e["refusals"].as_array().unwrap() {
        let req = by_sig(
            e,
            "R",
            unhex(&r["sig1"]),
            unhex(&r["sig2"]),
            r["passphrase"].as_str().unwrap(),
        );
        assert_eq!(
            code(s.vault().derive_from_signature(req).await),
            r["error"].as_str().unwrap(),
            "{}",
            r["id"]
        );
    }
    // a 64-byte signature through the conversion only; other lengths refused there
    assert_eq!(
        code(s.vault().signature_from_compact(sec(&[1; 65]))),
        "OriginSignature"
    );
    // control: the row opens
    let sig = unhex(&e["rows"][0]["signature"]);
    let ok = by_sig(e, "R", sig.clone(), sig, e["passphrase"].as_str().unwrap());
    assert_eq!(code(s.vault().derive_from_signature(ok).await), "Ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_d_rows_and_refusals() {
    let v = rows();
    let r = &v["rawKey"];
    let s = sdk().await;
    let req = |label: &str, network: &str, pass: &str, index: u32| DeriveFromKey {
        label: label.into(),
        network: network.into(),
        key: sec(&unhex(&r["key"])),
        derivation_passphrase: sec(pass.as_bytes()),
        index,
        vault_passphrase: sec(VAULT_PASS.as_bytes()),
    };
    for (i, row) in r["rows"].as_array().unwrap().iter().enumerate() {
        let n = s
            .vault()
            .derive_from_key(req(
                &format!("D{i}"),
                "evm",
                row["passphrase"].as_str().unwrap(),
                row["index"].as_u64().unwrap() as u32,
            ))
            .await
            .unwrap();
        assert_eq!(words(&n), row["words"].as_str().unwrap(), "{}", row["id"]);
        assert_eq!(
            (n.info.class.as_str(), n.info.origin.as_str()),
            ("classical-rooted", "raw-key")
        );
    }
    assert_eq!(
        code(s.vault().derive_from_key(req("X", "solana", "", 7)).await),
        "Argument"
    );
    assert_eq!(
        code(
            s.vault()
                .derive_from_key(req("X", "evm", "river-ot7", 7))
                .await
        ),
        "DerivationPassphraseShort"
    );
    assert_eq!(
        code(s.vault().derive_from_key(req("X", "evm", "", 7)).await),
        "Ok",
        "control"
    );
}
