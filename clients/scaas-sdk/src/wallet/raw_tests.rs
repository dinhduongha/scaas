// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T19: native keys and the raw entry over `smartcontracts/vectors/native/native.json` (the rows of its mnemonics without a
//! BIP-39 passphrase: the SDK imports none), every refusal beside its control, `scaas-ua`'s sign calls counted ([`CALLS`]).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use super::*;
use crate::vault::{ImportWords, MemoryStore};
use crate::{Limits, RuntimeChoice, Sdk, SdkConfig};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";

/// The raw tests one at a time: [`CALLS`] is shared.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn load() -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/native/native.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

/// An SDK with every passphrase-free mnemonic of the vectors imported: mnemonic id -> seed id.
async fn setup() -> (Arc<Sdk>, HashMap<String, String>, Value) {
    let v = load();
    let sdk = Sdk::open(SdkConfig {
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
    let mut seeds = HashMap::new();
    for m in v["mnemonics"].as_array().unwrap() {
        if m["passphrase"] != "" {
            continue;
        }
        let id = sdk
            .vault()
            .import_words(ImportWords {
                label: m["id"].as_str().unwrap().into(),
                words: sec(m["words"].as_str().unwrap().as_bytes()),
                vault_passphrase: sec(PASS.as_bytes()),
            })
            .await
            .unwrap()
            .id;
        seeds.insert(m["id"].as_str().unwrap().to_string(), id);
    }
    (sdk, seeds, v)
}

fn u(v: &Value) -> Option<u32> {
    v.as_u64().map(|x| x as u32)
}

fn key(seeds: &HashMap<String, String>, r: &Value) -> Option<NativeKeyRef> {
    Some(NativeKeyRef {
        seed: seeds.get(r["mnemonic"].as_str()?)?.clone(),
        network: r["network"].as_str()?.into(),
        index: u(&r["index"]).unwrap_or(0),
        change: u(&r["change"]).filter(|_| {
            r["network"]
                .as_str()
                .is_some_and(|n| n.starts_with("bitcoin_"))
        }),
        coin_type: u(&r["coinType"]),
        path: None,
    })
}

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn calls() -> [u32; 3] {
    [0, 1, 2].map(|i| CALLS[i].load(SeqCst))
}

/// Every address row (Bitcoin with its change chain and coin type, NEAR, Polkadot with its SS58 prefixes) and every Polkadot
/// junction path through the SDK.
#[tokio::test(flavor = "multi_thread")]
async fn native_rows_through_the_sdk() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, v) = setup().await;
    let w = sdk.wallet();
    let mut n = 0;
    for r in v["addresses"].as_array().unwrap() {
        let Some(k) = key(&seeds, r) else { continue };
        let a = w.native_address(k.clone(), None).await.unwrap();
        assert_eq!(a.public_key, r["publicKey"].as_str().unwrap(), "{r}");
        assert_eq!(a.address.as_deref(), r["address"].as_str(), "{r}");
        if let Some(p) = r["witnessProgram"].as_object() {
            assert_eq!(a.witness_version, u(&p["version"]).map(|x| x as u8));
            assert_eq!(a.witness_program.as_deref(), p["program"].as_str());
        }
        for (prefix, addr) in r["ss58"].as_object().into_iter().flatten() {
            let s = w
                .native_address(k.clone(), Some(prefix.parse().unwrap()))
                .await
                .unwrap();
            assert_eq!(s.ss58.as_deref(), addr.as_str(), "{r} {prefix}");
        }
        n += 1;
    }
    for r in v["polkadotPaths"].as_array().unwrap() {
        let Some(seed) = seeds.get(r["mnemonic"].as_str().unwrap()) else {
            continue;
        };
        let k = NativeKeyRef {
            seed: seed.clone(),
            network: "polkadot".into(),
            index: 0,
            change: None,
            coin_type: None,
            path: Some(r["path"].as_str().unwrap().into()),
        };
        let a = w.native_address(k, None).await.unwrap();
        assert_eq!(a.public_key, r["publicKey"].as_str().unwrap(), "{r}");
        assert_eq!(a.address.as_deref(), r["address"].as_str(), "{r}");
        n += 1;
    }
    assert!(n > 100, "{n} rows");
}

/// Rule 1: `evm` and `hedera_ecdsa` keys never sign raw (a NEAR transaction by a NEAR key as control).
#[tokio::test(flavor = "multi_thread")]
async fn raw_refuses_evm_keys() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, _) = setup().await;
    let w = sdk.wallet();
    let k = |network: &str| NativeKeyRef {
        seed: seeds["pq_kat"].clone(),
        network: network.into(),
        index: 0,
        change: None,
        coin_type: None,
        path: None,
    };
    let before = calls();
    for n in ["evm", "hedera_ecdsa"] {
        for req in [
            NativeSignRequest::Digest32 {
                digest: format!("0x{}", "11".repeat(32)),
            },
            NativeSignRequest::Message {
                message: "0x03".into(),
            },
        ] {
            assert_eq!(
                code(w.native_sign(k(n), req, AllowRawNative::new()).await),
                "RawDigestRefused"
            );
        }
    }
    assert_eq!(calls(), before, "scaas-ua never called");
    let near = NativeSignRequest::NearTransaction {
        tx_borsh: "0x03".into(),
    };
    assert_eq!(
        code(w.native_sign(k("near"), near, AllowRawNative::new()).await),
        "Ok"
    );
}

/// A UA or account key cannot be named here: a network that is no native network is refused by the same rule.
#[tokio::test(flavor = "multi_thread")]
async fn raw_refuses_ua_keys() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, _) = setup().await;
    for network in ["ua", "0x0101", "account"] {
        let k = NativeKeyRef {
            seed: seeds["pq_kat"].clone(),
            network: network.into(),
            index: 0,
            change: None,
            coin_type: None,
            path: None,
        };
        let r = sdk
            .wallet()
            .native_sign(
                k,
                NativeSignRequest::Message {
                    message: "0x03".into(),
                },
                AllowRawNative::new(),
            )
            .await;
        assert_eq!(code(r), "RawDigestRefused", "{network}");
    }
}

/// Rule 4: Solana's off-chain envelope and Aptos's `APTOS\n` refused before `scaas-ua` is called (the counting hook sees no
/// call); the same networks' plain messages sign.
#[tokio::test(flavor = "multi_thread")]
async fn raw_refuses_offchain_envelopes_in_the_sdk() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, _) = setup().await;
    let w = sdk.wallet();
    let k = |network: &str| NativeKeyRef {
        seed: seeds["pq_kat"].clone(),
        network: network.into(),
        index: 0,
        change: None,
        coin_type: None,
        path: None,
    };
    let hexs = |b: &[u8]| hex(b);
    for (n, m) in [
        ("solana", &b"\xffsolana offchain\x00"[..]),
        ("aptos", &b"APTOS\nmessage: x"[..]),
    ] {
        let before = calls();
        let r = w
            .native_sign(
                k(n),
                NativeSignRequest::Message { message: hexs(m) },
                AllowRawNative::new(),
            )
            .await;
        assert_eq!(code(r), "RawDigestRefused", "{n}");
        assert_eq!(calls(), before, "{n}: scaas-ua never called");
        let ok = NativeSignRequest::Message {
            message: "0x0a0b".into(),
        };
        assert_eq!(
            code(w.native_sign(k(n), ok, AllowRawNative::new()).await),
            "Ok",
            "{n}"
        );
    }
}

/// The withdrawn first-byte rule stays withdrawn: a Polkadot `0x0500…` payload and a Solana message starting `0x05` sign.
#[tokio::test(flavor = "multi_thread")]
async fn raw_signs_leading_0x05() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, _) = setup().await;
    let w = sdk.wallet();
    for (n, m) in [("polkadot", "substrate_dev"), ("solana", "pq_kat")] {
        let k = NativeKeyRef {
            seed: seeds[m].clone(),
            network: n.into(),
            index: 0,
            change: None,
            coin_type: None,
            path: None,
        };
        let req = NativeSignRequest::Message {
            message: format!("0x0500{}", "07".repeat(30)),
        };
        let s = w.native_sign(k, req, AllowRawNative::new()).await.unwrap();
        assert_eq!(s.len(), 2 + 128, "{n}");
    }
}

/// Rule 2: NEAR, Sui, Stellar and Hedera Ed25519 sign through `scaas-ua`'s envelope calls (each row's signature), never a
/// digest or a bare message (refused, `sign_digest` and `sign_message` never reached); an envelope for another network refused.
#[tokio::test(flavor = "multi_thread")]
async fn raw_envelope_families() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, v) = setup().await;
    let w = sdk.wallet();
    for r in v["envelopes"].as_array().unwrap() {
        let k = key(&seeds, r).unwrap();
        let m = format!("0x{}", r["message"].as_str().unwrap());
        let req = match r["call"].as_str().unwrap() {
            "sign_near_transaction" => NativeSignRequest::NearTransaction { tx_borsh: m },
            "sign_sui_transaction" => NativeSignRequest::SuiTransaction { tx_bcs: m },
            "sign_stellar_transaction" => NativeSignRequest::StellarTransaction {
                network_id: format!("0x{}", r["networkId"].as_str().unwrap()),
                tx_xdr: m,
            },
            _ => NativeSignRequest::HederaTransaction { body_bytes: m },
        };
        let s = w
            .native_sign(k.clone(), req, AllowRawNative::new())
            .await
            .unwrap();
        assert_eq!(s, format!("0x{}", r["signature"].as_str().unwrap()), "{r}");
        let before = calls();
        for bare in [
            NativeSignRequest::Digest32 {
                digest: format!("0x{}", r["signed"].as_str().unwrap()),
            },
            NativeSignRequest::Message {
                message: "0x03".into(),
            },
        ] {
            assert_eq!(
                code(w.native_sign(k.clone(), bare, AllowRawNative::new()).await),
                "RawDigestRefused"
            );
        }
        assert_eq!(
            calls(),
            before,
            "no digest or message call for {}",
            k.network
        );
    }
    let solana = NativeKeyRef {
        seed: seeds["pq_kat"].clone(),
        network: "solana".into(),
        index: 0,
        change: None,
        coin_type: None,
        path: None,
    };
    let near = NativeSignRequest::NearTransaction {
        tx_borsh: "0x03".into(),
    };
    assert_eq!(
        code(w.native_sign(solana, near, AllowRawNative::new()).await),
        "RawDigestRefused"
    );
}

/// Rule 3: a GRAM (`ton`) key is refused whatever the request.
#[tokio::test(flavor = "multi_thread")]
async fn raw_refuses_gram() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, _) = setup().await;
    let k = NativeKeyRef {
        seed: seeds["pq_kat"].clone(),
        network: "ton".into(),
        index: 0,
        change: None,
        coin_type: None,
        path: None,
    };
    let r = sdk
        .wallet()
        .native_sign(
            k,
            NativeSignRequest::Message {
                message: "0x03".into(),
            },
            AllowRawNative::new(),
        )
        .await;
    assert_eq!(code(r), "RawDigestRefused");
}

/// Rule 5: a bare digest only for a Bitcoin key (each P2WPKH row's signature); any other network's `Digest32` refused.
#[tokio::test(flavor = "multi_thread")]
async fn bitcoin_sighash_digest_only() {
    let _one = SERIAL.lock().await;
    let (sdk, seeds, v) = setup().await;
    let w = sdk.wallet();
    let rows: Vec<_> = v["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["network"] == "bitcoin_p2wpkh" && s["mode"] == "deterministic")
        .collect();
    assert!(!rows.is_empty());
    for r in rows {
        let k = key(&seeds, r).unwrap();
        let req = NativeSignRequest::Digest32 {
            digest: format!("0x{}", r["message"].as_str().unwrap()),
        };
        let s = w.native_sign(k, req, AllowRawNative::new()).await.unwrap();
        assert_eq!(s, format!("0x{}", r["signature"].as_str().unwrap()), "{r}");
    }
    for n in ["solana", "polkadot", "aptos", "near"] {
        let m = if n == "polkadot" {
            "substrate_dev"
        } else {
            "pq_kat"
        };
        let k = NativeKeyRef {
            seed: seeds[m].clone(),
            network: n.into(),
            index: 0,
            change: None,
            coin_type: None,
            path: None,
        };
        let req = NativeSignRequest::Digest32 {
            digest: format!("0x{}", "22".repeat(32)),
        };
        assert_eq!(
            code(w.native_sign(k, req, AllowRawNative::new()).await),
            "RawDigestRefused",
            "{n}"
        );
    }
}

/// The default generated surface has no raw call: the Dart binding's generated code names neither the entry nor its marker.
/// Comment lines are not surface: the `compile_fail` doctest of `NativeKeyRef` (the marker's absence without `raw-native`)
/// is copied into its Dart doc comment, and that mention is seen and skipped (controller call (owner auto-run 2026-11-19),
/// 2026-11-20); a code line naming any of them fails.
#[test]
fn raw_absent_from_the_generated_dart() {
    let dir = format!("{}/bindings/dart/lib", env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![std::path::PathBuf::from(dir)];
    let names = [
        "nativeSign",
        "native_sign",
        "AllowRawNative",
        "NativeSignRequest",
    ];
    let (mut seen, mut in_comments) = (0, 0);
    while let Some(p) = files.pop() {
        if p.is_dir() {
            files.extend(std::fs::read_dir(&p).unwrap().map(|e| e.unwrap().path()));
        } else if p.extension().is_some_and(|e| e == "dart") {
            let t = std::fs::read_to_string(&p).unwrap();
            for line in t.lines() {
                let comment = line.trim_start().starts_with("//");
                for name in names {
                    if line.contains(name) {
                        assert!(comment, "{name} in a code line of {}: {line}", p.display());
                        in_comments += 1;
                    }
                }
            }
            seen += 1;
        }
    }
    assert!(seen > 0, "the generated Dart files");
    assert!(
        in_comments > 0,
        "the doc comment's mention is read and skipped"
    );
}
