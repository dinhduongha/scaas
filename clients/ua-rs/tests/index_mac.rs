// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T2a: `Wallet::fingerprint` and `Wallet::index_mac` against clientkeys' rows (smartcontracts/vectors/keystore/
//! index_mac.json), the fingerprint also against BIP-32's published vectors (clients/clientkeys/test/vectors/
//! bip32-fingerprint.json, outside data).
use scaas_ua::wallet::{index_canonical, Error, IndexFields, Wallet};
use serde_json::Value;
use std::path::Path;

fn load(rel: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn wallet(entropy_hex: &str, pass: &str) -> Wallet {
    let e = hex::decode(entropy_hex.trim_start_matches("0x")).unwrap();
    Wallet::from_mnemonic(&bip39::Mnemonic::from_entropy(&e).unwrap().to_string(), pass).unwrap()
}

/// The row's fields as `IndexFields`, the accounts as clientkeys writes them (`JSON.stringify`: insertion order kept).
fn with_fields<R>(f: &Value, g: impl FnOnce(&IndexFields) -> R) -> R {
    let s = |k: &str| f[k].as_str().unwrap();
    let warnings: Vec<String> = f["warnings"].as_array().unwrap().iter().map(|w| w.as_str().unwrap().to_owned()).collect();
    let accounts = serde_json::to_string(&f["accounts"]).unwrap(); // dev serde_json keeps the order (preserve_order)
    g(&IndexFields {
        id: s("id"),
        label: s("label"),
        words: f["words"].as_u64().unwrap() as u32,
        fingerprint: s("fingerprint"),
        origin: s("origin"),
        class: s("class"),
        warnings: &warnings,
        backup: s("backup"),
        accounts_json: &accounts,
    })
}

#[test]
fn fingerprint_of_bip32_published_vectors() {
    let v = load("../clientkeys/test/vectors/bip32-fingerprint.json");
    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for r in rows {
        let child: bip32::XPrv = r["child"].as_str().unwrap().parse().unwrap();
        let seed = hex::decode(r["seed"].as_str().unwrap()).unwrap();
        let fp = bip32::XPrv::new(&seed).unwrap().public_key().fingerprint();
        assert_eq!(fp, child.attrs().parent_fingerprint, "vector {}", r["vector"]);
    }
}

#[test]
fn fingerprint_rows() {
    let v = load("../../smartcontracts/vectors/keystore/index_mac.json");
    let rows = v["fingerprints"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for r in rows {
        let w = wallet(r["entropy"].as_str().unwrap(), r["bip39Passphrase"].as_str().unwrap());
        assert_eq!(hex::encode(w.fingerprint().unwrap()), r["fingerprint"].as_str().unwrap(), "{}", r["id"]);
        w.lock();
        assert_eq!(w.fingerprint().err(), Some(Error::WalletLocked));
    }
}

#[test]
fn index_mac_rows() {
    let v = load("../../smartcontracts/vectors/keystore/index_mac.json");
    let rows = v["macs"].as_array().unwrap();
    assert!(rows.len() >= 11);
    for r in rows {
        let w = wallet(r["entropy"].as_str().unwrap(), "");
        let want: [u8; 32] = hex::decode(r["mac"].as_str().unwrap()).unwrap().try_into().unwrap();
        with_fields(&r["fields"], |f| {
            assert_eq!(index_canonical(f).unwrap(), r["canonical"].as_str().unwrap(), "{}", r["id"]);
            assert_eq!(w.index_mac(f).unwrap(), want, "{}", r["id"]);
            assert_eq!(w.verify_index_mac(f, &want), Ok(true), "{}", r["id"]);
            let mut bad = want;
            bad[31] ^= 1;
            assert_eq!(w.verify_index_mac(f, &bad), Ok(false), "{}", r["id"]);
        });
    }
}

#[test]
fn index_mac_refusals() {
    let v = load("../../smartcontracts/vectors/keystore/index_mac.json");
    let base = &v["macs"][0];
    let w = wallet(base["entropy"].as_str().unwrap(), "");
    with_fields(&base["fields"], |f| {
        assert!(w.index_mac(f).is_ok(), "control");
        let spaced = f.accounts_json.replacen(",", ", ", 1);
        let not_array = "{}".to_string();
        let escaped = f.accounts_json.replacen("Daily", "\\u0044aily", 1);
        for bad in [spaced, not_array, escaped, "[".to_string()] {
            let g = IndexFields { accounts_json: &bad, ..*f };
            assert_eq!(w.index_mac(&g).err(), Some(Error::Argument), "{bad}");
        }
        w.lock();
        assert_eq!(w.index_mac(f).err(), Some(Error::WalletLocked));
    });
}

/// `scaas_ua::sha256` (the keystore anchor's hash): FIPS 180-4's "abc" and empty-message answers.
#[test]
fn sha256_known_answers() {
    assert_eq!(hex::encode(scaas_ua::sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hex::encode(scaas_ua::sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}
