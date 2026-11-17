// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-native: the native networks of an app's native backend and raw native signing (spec 2026-11-17-ua-rs-native; CLI-UAL-44
//! to CLI-UAL-47) against smartcontracts/vectors/native/native.json (written by clientkeys scripts/native-vectors.mjs first).
//! Every negative row has its accepted neighbour beside it. UNAUDITED.
use scaas_ua::wallet::{sign_message_by, AllowRawDigest, Error, Network, Wallet, MAX_RAW_MESSAGE};
use serde_json::Value;

fn native() -> Value {
    let path = format!("{}/../../smartcontracts/vectors/native/native.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn wallet(v: &Value, id: &str) -> Wallet {
    let m = arr(v, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
fn net(r: &Value) -> Network {
    Network::from_name(r["network"].as_str().unwrap()).unwrap_or_else(|| panic!("network {r}"))
}
fn opt_u32(v: &Value) -> Option<u32> {
    v.as_u64().map(|c| u32::try_from(c).unwrap())
}
/// A row's message: `message` hex, or `messageRepeat` {byte, length}.
fn msg(r: &Value) -> Vec<u8> {
    if let Some(m) = r["messageRepeat"].as_object() {
        let b = u8::from_str_radix(m["byte"].as_str().unwrap(), 16).unwrap();
        vec![b; usize::try_from(m["length"].as_u64().unwrap()).unwrap()]
    } else {
        hex::decode(r["message"].as_str().unwrap()).unwrap()
    }
}

/// The networks this build signs messages on, and the signature rows of native.json over them.
const ED25519_SIX: [&str; 6] = ["hedera_ed25519", "sui", "stellar", "ton", "aptos", "solana"];

#[test]
fn native_json_ed25519_message_rows_byte_equal() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let mut n = 0;
    for r in arr(&v, "signatures").iter().filter(|r| r["call"] == "sign_message" && ED25519_SIX.contains(&r["network"].as_str().unwrap())) {
        assert_eq!(r["mode"], "deterministic", "{}", r["id"]);
        let k = w.native_key(net(r), opt_u32(&r["index"]).unwrap(), opt_u32(&r["coinType"])).unwrap();
        assert_eq!(hex::encode(k.public_key()), r["publicKey"].as_str().unwrap(), "{}", r["id"]);
        let sig = k.sign_message(&msg(r), AllowRawDigest).unwrap();
        assert_eq!(hex::encode(sig), r["signature"].as_str().unwrap(), "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 24, "6 networks x {{1, 32, 1232, 131072}} bytes");
}

#[test]
fn sign_message_bounds_and_envelopes_beside_their_accepted_neighbours() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.native_key(Network::Solana, 0, None).unwrap();
    assert_eq!(MAX_RAW_MESSAGE, 131_072);
    assert_eq!(k.sign_message(&[], AllowRawDigest).err(), Some(Error::Argument), "0 bytes");
    assert!(k.sign_message(&[1], AllowRawDigest).is_ok(), "1 byte");
    assert_eq!(k.sign_message(&vec![0xa5; MAX_RAW_MESSAGE + 1], AllowRawDigest).err(), Some(Error::Argument), "131,073 bytes");
    assert!(k.sign_message(&vec![0xa5; MAX_RAW_MESSAGE], AllowRawDigest).is_ok(), "131,072 bytes");
    let solana = [&b"\xffsolana offchain"[..], &[1, 1]].concat();
    let aptos = b"APTOS\nmessage: scaas".to_vec();
    for env in [solana, aptos] {
        assert_eq!(k.sign_message(&env, AllowRawDigest).err(), Some(Error::Argument), "envelope");
        assert!(k.sign_message(env.get(1..).unwrap(), AllowRawDigest).is_ok(), "without its first byte");
    }
    // a secp256k1 key signs digests only
    let evm = w.native_key(Network::Evm, 0, None).unwrap();
    assert_eq!(evm.sign_message(&[1; 32], AllowRawDigest).err(), Some(Error::Argument), "32 bytes on evm");
    assert!(evm.sign_digest(&[1; 32], AllowRawDigest).is_ok());
}

#[test]
fn native_json_sign_message_refusal_rows_of_the_nine() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let nine = |a: &Value| Network::from_name(a["network"].as_str().unwrap()).filter(|n| n.scheme_kind().is_some());
    let mut n = 0;
    for r in arr(&v, "refusals").iter().filter(|r| r["call"] == "sign_message") {
        let (a, ok) = (&r["args"], &r["accepted"]);
        let (Some(na), Some(nok)) = (nine(a), nine(ok)) else { continue };
        let ka = w.native_key(na, 0, None).unwrap();
        assert_eq!(ka.sign_message(&msg(a), AllowRawDigest).err(), Some(Error::Argument), "{}", r["id"]);
        assert!(w.native_key(nok, 0, None).unwrap().sign_message(&msg(ok), AllowRawDigest).is_ok(), "neighbour of {}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 5, "0 B, 131,073 B, two envelopes on solana, evm");
}

#[test]
fn sign_message_by_a_ua_key_is_refused_a_native_key_accepted() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    for kind in [0x0102u16, 0x0108] {
        let ua = w.ua_key(kind, 0, 0).unwrap();
        assert_eq!(sign_message_by(&ua, &[1, 2, 3], AllowRawDigest).err(), Some(Error::Argument), "kind {kind:#06x}");
    }
    let native = w.native_key(Network::Solana, 0, None).unwrap();
    assert_eq!(sign_message_by(&native, &[1, 2, 3], AllowRawDigest).unwrap(), native.sign_message(&[1, 2, 3], AllowRawDigest).unwrap());
    // the bounds hold for every signer
    assert_eq!(sign_message_by(&native, &[], AllowRawDigest).err(), Some(Error::Argument));
}

#[test]
fn schemes_and_scheme_kinds_of_the_nine() {
    use scaas_ua::wallet::NativeScheme;
    for (name, scheme, kind) in [
        ("evm", NativeScheme::Secp256k1Ecdsa, 0x0108),
        ("cosmos", NativeScheme::Secp256k1Ecdsa, 0x0108),
        ("hedera_ecdsa", NativeScheme::Secp256k1Ecdsa, 0x0108),
        ("hedera_ed25519", NativeScheme::Ed25519, 0x0102),
        ("sui", NativeScheme::Ed25519, 0x0102),
        ("stellar", NativeScheme::Ed25519, 0x0102),
        ("ton", NativeScheme::Ed25519, 0x0102),
        ("aptos", NativeScheme::Ed25519, 0x0102),
        ("solana", NativeScheme::Ed25519, 0x0102),
    ] {
        let n = Network::from_name(name).unwrap();
        assert_eq!((n.scheme(), n.scheme_kind()), (scheme, Some(kind)), "{name}");
    }
}

#[test]
fn errors_name_no_input() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.native_key(Network::Solana, 0, None).unwrap();
    let secret_like = b"APTOS\nmessage: do-not-print-me".to_vec();
    let e = k.sign_message(&secret_like, AllowRawDigest).unwrap_err();
    assert_eq!(e.to_string(), "Argument");
}

/// An external key's raw-message answer is verified with this crate's verifier before it leaves (MD-13, spec §8).
#[cfg(feature = "vectors")]
#[test]
fn external_raw_message_answers_are_verified() {
    use scaas_ua::wallet::{SignRequest, Signer, TestExternalKey};
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.native_key(Network::Solana, 0, None).unwrap();
    let m = [7u8; 40];
    let good = TestExternalKey::new(k.key_ref(), |req| match req {
        SignRequest::RawMessage { message, .. } => k.sign_message(message, AllowRawDigest),
        _ => Err(Error::Argument),
    });
    assert_eq!(sign_message_by(&good, &m, AllowRawDigest).unwrap(), k.sign_message(&m, AllowRawDigest).unwrap());
    let flipped = TestExternalKey::new(k.key_ref(), |_| {
        let mut s = k.sign_message(&m, AllowRawDigest)?;
        s[0] ^= 1;
        Ok(s)
    });
    assert_eq!(sign_message_by(&flipped, &m, AllowRawDigest).err(), Some(Error::ExternalSignature));
    let other = TestExternalKey::new(k.key_ref(), |_| k.sign_message(&[8u8; 40], AllowRawDigest));
    assert_eq!(sign_message_by(&other, &m, AllowRawDigest).err(), Some(Error::ExternalSignature));
}
