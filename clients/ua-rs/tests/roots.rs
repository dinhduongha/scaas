// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T6: roots (c) and (d) (feature `roots`) both ways against clientkeys' rows (smartcontracts/vectors/keys/roots.json):
//! the derivation message's digest, every root and its 24 words, every refusal by its code, each beside its control.
use scaas_ua::wallet::roots::{
    check_derivation_passphrase, key_derivation_typed_data, root_from_eoa_signature, root_from_key, signature_from_compact,
};
use scaas_ua::wallet::{Error, Wallet};
use serde_json::Value;

fn rows() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../smartcontracts/vectors/keys/roots.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

/// clientkeys' codes as ua-rs's: `OriginSignature` is `ExternalSignature`, `DerivationPassphraseShort` is `Argument`.
fn code(e: &str) -> Error {
    match e {
        "OriginSignature" => Error::ExternalSignature,
        "DerivationPassphraseShort" | "Argument" => Error::Argument,
        other => panic!("{other}"),
    }
}

#[test]
fn derivation_message_digest() {
    let e = &rows()["eoaSig"];
    let account: [u8; 20] = unhex(&e["account"]).try_into().unwrap();
    let td = key_derivation_typed_data(&account, 0).unwrap();
    assert_eq!(hex(&td.digest().unwrap()), e["digest"].as_str().unwrap());
    assert_ne!(td.digest().unwrap(), key_derivation_typed_data(&account, 1).unwrap().digest().unwrap(), "control: set is signed");
}

#[test]
fn root_c_rows_and_refusals() {
    let e = &rows()["eoaSig"];
    let account: [u8; 20] = unhex(&e["account"]).try_into().unwrap();
    let pass = e["passphrase"].as_str().unwrap();
    for r in e["rows"].as_array().unwrap() {
        let mut s = unhex(&r["signature"]);
        if r["compact"] == true {
            s = signature_from_compact(&s.clone().try_into().unwrap()).to_vec();
        }
        let set = r["set"].as_u64().unwrap() as u32;
        let root = root_from_eoa_signature(&account, set, &s, &s.clone(), pass).unwrap();
        assert_eq!(hex(&*root), r["root"].as_str().unwrap(), "{}", r["id"]);
        let (w, mut b) = Wallet::from_eoa_signature(&account, set, &s, &s, pass).unwrap();
        assert_eq!(b.reveal().unwrap().as_str(), r["words"].as_str().unwrap());
        assert_eq!(w.word_count(), Ok(24));
    }
    for r in e["refusals"].as_array().unwrap() {
        let got = root_from_eoa_signature(&account, 0, &unhex(&r["sig1"]), &unhex(&r["sig2"]), r["passphrase"].as_str().unwrap());
        assert_eq!(got.err(), Some(code(r["error"].as_str().unwrap())), "{}", r["id"]);
    }
    // v outside {0, 1, 27, 28}, and a wrong account, each beside the row that opens
    let mut s = unhex(&e["rows"][0]["signature"]);
    assert!(root_from_eoa_signature(&account, 0, &s, &s, pass).is_ok(), "control");
    s[64] = 29;
    assert_eq!(root_from_eoa_signature(&account, 0, &s, &s, pass).err(), Some(Error::ExternalSignature));
    let s = unhex(&e["rows"][0]["signature"]);
    let mut other = account;
    other[0] ^= 1;
    assert_eq!(root_from_eoa_signature(&other, 0, &s, &s, pass).err(), Some(Error::ExternalSignature));
}

#[test]
fn root_d_rows_and_refusals() {
    let r = &rows()["rawKey"];
    let key: [u8; 32] = unhex(&r["key"]).try_into().unwrap();
    for row in r["rows"].as_array().unwrap() {
        let (p, i) = (row["passphrase"].as_str().unwrap(), row["index"].as_u64().unwrap() as u32);
        assert_eq!(hex(&*root_from_key(&key, p, i).unwrap()), row["root"].as_str().unwrap(), "{}", row["id"]);
        let (_, mut b) = Wallet::from_private_key(&key, p, i).unwrap();
        assert_eq!(b.reveal().unwrap().as_str(), row["words"].as_str().unwrap());
    }
    for f in r["refusals"].as_array().unwrap() {
        if f["network"] != "evm" {
            continue; // the network is the SDK's argument; ua-rs takes a secp256k1 key only
        }
        let k: [u8; 32] = unhex(&f["key"]).try_into().unwrap();
        assert_eq!(root_from_key(&k, f["passphrase"].as_str().unwrap(), 0).err(), Some(code(f["error"].as_str().unwrap())), "{}", f["id"]);
    }
}

#[test]
fn passphrase_floor() {
    assert_eq!(check_derivation_passphrase("123456789", false), Err(Error::Argument));
    assert_eq!(check_derivation_passphrase("1234567890", false), Ok(()), "control: 10");
    assert_eq!(check_derivation_passphrase("", false), Err(Error::Argument));
    assert_eq!(check_derivation_passphrase("", true), Ok(()), "root (d): empty allowed");
    // NFKC: U+FB01 (one code point) is "fi" (two)
    assert_eq!(check_derivation_passphrase("\u{fb01}12345678", false), Ok(()));
}
