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
    assert_eq!(n, 25, "6 networks x {{1, 32, 1232, 131072}} bytes, and a Solana message with five signers (T13 C1)");
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
    // the two EVM-prefix rows on solana left with their rule (T13 C1, the coordinator's one-time exception to append-only)
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

// ------------------------------------------------------------------ T6: NEAR

#[test]
fn native_json_near_addresses_and_signatures() {
    let v = native();
    let mut n = 0;
    for r in arr(&v, "addresses").iter().filter(|r| r["network"] == "near") {
        let k = wallet(&v, r["mnemonic"].as_str().unwrap()).native_key(Network::Near, opt_u32(&r["index"]).unwrap(), None).unwrap();
        assert_eq!(hex::encode(k.public_key()), r["publicKey"].as_str().unwrap(), "{r}");
        assert_eq!(k.address().as_deref(), r["address"].as_str(), "{r}");
        assert_eq!(k.address().unwrap(), hex::encode(k.public_key()), "the implicit account id is hex(pk)");
        n += 1;
    }
    assert_eq!(n, 12, "6 mnemonics x index {{0, 1}}");
    let w = wallet(&v, "pq_kat");
    let mut s = 0;
    for r in arr(&v, "signatures").iter().filter(|r| r["network"] == "near") {
        let k = w.native_key(Network::Near, opt_u32(&r["index"]).unwrap(), None).unwrap();
        let sig = match r["call"].as_str().unwrap() {
            "sign_digest" => k.sign_digest(&msg(r).try_into().unwrap(), AllowRawDigest).unwrap(),
            _ => k.sign_message(&msg(r), AllowRawDigest).unwrap(),
        };
        assert_eq!(hex::encode(sig), r["signature"].as_str().unwrap(), "{}", r["id"]);
        s += 1;
    }
    assert_eq!(s, 5, "four messages and one digest");
}

#[test]
fn near_refusals_beside_their_accepted_neighbours() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    for c in [148, 397, 0] {
        assert_eq!(w.native_key(Network::Near, 0, Some(c)).err(), Some(Error::Argument), "coin {c}");
    }
    assert!(w.native_key(Network::Near, 0, None).is_ok());
    assert!(w.native_key(Network::Stellar, 0, Some(397)).is_ok(), "stellar keeps its override");
    let near = w.native_key(Network::Near, 0, None).unwrap();
    assert_eq!(near.sign_key_proof(&[0; 32]).err(), Some(Error::Argument), "no key proof on near");
    assert!(w.native_key(Network::Solana, 0, None).unwrap().sign_key_proof(&[0; 32]).is_ok());
    assert!(w.native_key(Network::Evm, 0, None).unwrap().sign_key_proof(&[0; 32]).is_ok());
    assert_eq!(w.import_native_key(Network::Near, &[1; 32]).err(), Some(Error::Argument), "no import on near");
    assert_eq!(w.imported_ua_key(Network::Near, 0, 0x0102).err(), Some(Error::Argument));
    assert!(w.import_native_key(Network::Evm, &[1; 32]).is_ok());
}

#[test]
fn near_scheme_and_no_scheme_kind() {
    use scaas_ua::wallet::NativeScheme;
    assert_eq!(Network::from_name("near"), Some(Network::Near));
    assert_eq!(Network::Near.name(), "near");
    assert_eq!((Network::Near.scheme(), Network::Near.scheme_kind()), (NativeScheme::Ed25519, None));
}

// ------------------------------------------------------------------ T6b: spec §8.1 (after the scaas-sdk review)

/// T13 C1 (CLI-UAL-63 (11) withdrawn): no first-byte rule on a native message. `0x05` and `0x19 0x01` sign on an Ed25519 and an
/// sr25519 key; native.json's Polkadot `Balances` row (pallet 5) signs through the release path and verifies.
#[test]
fn sign_message_has_no_evm_prefix_rule() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let sol = w.native_key(Network::Solana, 0, None).unwrap();
    let dot = w.native_key(Network::Polkadot, 0, None).unwrap();
    for m in [&[5u8, 1, 2][..], &[5], &[5, 0, 0], &[0x19, 1, 7], &[0x19, 1]] {
        assert!(scaas_ua::verify::ed25519(&sol.public_key(), m, &sol.sign_message(m, AllowRawDigest).unwrap()), "solana {m:?}");
        assert!(sr_verify(&dot.public_key(), m, &dot.sign_message(m, AllowRawDigest).unwrap()), "polkadot {m:?}");
    }
    let r = arr(&v, "signatures").iter().find(|r| r["id"] == "sr25519-bare-balances-0500").unwrap();
    let dev = wallet(&v, "substrate_dev");
    let k = dev.native_key(Network::Polkadot, 0, None).unwrap();
    assert_eq!(hex::encode(k.public_key()), r["publicKey"].as_str().unwrap());
    assert!(sr_verify(&k.public_key(), &msg(r), &k.sign_message(&msg(r), AllowRawDigest).unwrap()), "the Balances row");
    assert!(sr_verify(&k.public_key(), &msg(r), &hex::decode(r["signature"].as_str().unwrap()).unwrap()), "the row's own signature");
    assert!(w.native_key(Network::Evm, 0, None).unwrap().sign_digest(&[5; 32], AllowRawDigest).is_ok(), "digests untouched");
}

fn envelope(k: &scaas_ua::wallet::NativeKey, call: &str, r: &Value, tx: &[u8]) -> Result<Vec<u8>, Error> {
    match call {
        "sign_near_transaction" => k.sign_near_transaction(tx, AllowRawDigest),
        "sign_sui_transaction" => k.sign_sui_transaction(tx, AllowRawDigest),
        "sign_stellar_transaction" => {
            let id = hex::decode(r["networkId"].as_str().unwrap()).unwrap();
            k.sign_stellar_transaction(&id.try_into().map_err(|_| Error::Argument)?, tx, AllowRawDigest)
        }
        "sign_hedera_transaction" => k.sign_hedera_transaction(tx, AllowRawDigest),
        c => panic!("{c}"),
    }
}

#[test]
fn native_json_envelopes_rows_byte_equal() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let mut n = 0;
    for r in arr(&v, "envelopes") {
        let k = w.native_key(net(r), opt_u32(&r["index"]).unwrap(), None).unwrap();
        let sig = envelope(&k, r["call"].as_str().unwrap(), r, &msg(r)).unwrap();
        assert_eq!(hex::encode(&sig), r["signature"].as_str().unwrap(), "{}", r["id"]);
        let signed = hex::decode(r["signed"].as_str().unwrap()).unwrap();
        assert!(scaas_ua::verify::ed25519(&k.public_key(), &signed, &sig), "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 12, "4 calls x {{1, 200, 1232}} bytes");
}

#[test]
fn native_json_envelope_refusal_rows() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let mut n = 0;
    for r in arr(&v, "refusals").iter().filter(|r| r["call"].as_str().unwrap().ends_with("_transaction")) {
        let call = r["call"].as_str().unwrap();
        let k = w.native_key(net(&r["args"]), 0, None).unwrap();
        assert_eq!(envelope(&k, call, &r["args"], &msg(&r["args"])).err(), Some(Error::Argument), "{}", r["id"]);
        let ok = w.native_key(net(&r["accepted"]), 0, None).unwrap();
        assert!(envelope(&ok, call, &r["accepted"], &msg(&r["accepted"])).is_ok(), "neighbour of {}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 16, "4 calls x {{on solana, 0 B, 131,073 B}}, a 31-byte Stellar network id, three NEP-461 tag rows (T13 C6)");
}

// ------------------------------------------------------------------ T7: Bitcoin P2WPKH and P2TR

fn btc_key(w: &Wallet, r: &Value) -> scaas_ua::wallet::NativeKey {
    w.bitcoin_key(net(r), opt_u32(&r["coinType"]), opt_u32(&r["change"]).unwrap(), opt_u32(&r["index"]).unwrap()).unwrap()
}

#[test]
fn native_json_bitcoin_addresses_both_chains_and_coins() {
    let v = native();
    let mut n = 0;
    for r in arr(&v, "addresses").iter().filter(|r| r["network"].as_str().unwrap().starts_with("bitcoin")) {
        let w = wallet(&v, r["mnemonic"].as_str().unwrap());
        let k = btc_key(&w, r);
        assert_eq!(hex::encode(k.public_key()), r["publicKey"].as_str().unwrap(), "{r}");
        assert_eq!(k.address().as_deref(), r["address"].as_str(), "{r}");
        let (ver, prog) = k.witness_program().unwrap();
        assert_eq!(u64::from(ver), r["witnessProgram"]["version"].as_u64().unwrap(), "{r}");
        assert_eq!(hex::encode(prog), r["witnessProgram"]["program"].as_str().unwrap(), "{r}");
        if r["network"] == "bitcoin_p2tr" {
            let x: [u8; 32] = hex::decode(r["internalKey"].as_str().unwrap()).unwrap().try_into().unwrap();
            assert_eq!(&k.public_key()[1..], &x[..], "publicKey is the compressed internal key");
            assert_eq!(hex::encode(k.witness_program().unwrap().1), r["outputKey"].as_str().unwrap());
        }
        if opt_u32(&r["change"]) == Some(0) {
            let rk = w.native_key(net(r), opt_u32(&r["index"]).unwrap(), opt_u32(&r["coinType"])).unwrap();
            assert_eq!(rk.public_key(), k.public_key(), "bitcoin_key(.., 0, i) is native_key's slot");
        }
        n += 1;
    }
    assert_eq!(n, 96, "6 mnemonics x 2 networks x coin {{0, 1}} x change {{0, 1}} x index {{0, 1}}");
}

#[test]
fn native_json_p2wpkh_signatures_byte_equal_and_bip143() {
    let v = native();
    let w = wallet(&v, "bip39_abandon");
    let mut n = 0;
    for r in arr(&v, "signatures").iter().filter(|r| r["network"] == "bitcoin_p2wpkh") {
        assert_eq!(r["mode"], "deterministic");
        let k = btc_key(&w, r);
        let d: [u8; 32] = msg(r).try_into().unwrap();
        assert_eq!(hex::encode(k.sign_digest(&d, AllowRawDigest).unwrap()), r["signature"].as_str().unwrap(), "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 3);
}

#[test]
fn p2tr_release_signatures_verify_under_the_output_key_and_differ() {
    let v = native();
    let w = wallet(&v, "bip39_abandon");
    for i in [0, 1] {
        let k = w.bitcoin_key(Network::BitcoinP2tr, None, 0, i).unwrap();
        let xq: [u8; 32] = k.witness_program().unwrap().1.try_into().unwrap();
        let d = [9u8; 32];
        let (a, b) = (k.sign_digest(&d, AllowRawDigest).unwrap(), k.sign_digest(&d, AllowRawDigest).unwrap());
        assert_ne!(a, b, "aux from the OS RNG");
        for s in [&a, &b] {
            assert!(scaas_ua::verify::verify(0x0103, &xq, &d, s, false), "index {i}");
        }
    }
}

#[test]
fn bitcoin_refusals_beside_their_accepted_neighbours() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    for n in [Network::BitcoinP2wpkh, Network::BitcoinP2tr] {
        assert_eq!(w.native_key(n, 0, Some(2)).err(), Some(Error::Argument), "coin 2");
        assert!(w.native_key(n, 0, Some(1)).is_ok() && w.native_key(n, 0, Some(0)).is_ok() && w.native_key(n, 0, None).is_ok());
        assert_eq!(w.bitcoin_key(n, None, 2, 0).err(), Some(Error::Argument), "change 2");
        assert!(w.bitcoin_key(n, None, 1, 0).is_ok());
        let k = w.native_key(n, 0, None).unwrap();
        assert_eq!(k.sign_key_proof(&[0; 32]).err(), Some(Error::Argument), "key proof");
        assert_eq!(k.sign_message(&[1; 32], AllowRawDigest).err(), Some(Error::Argument), "message");
        assert!(k.sign_digest(&[1; 32], AllowRawDigest).is_ok());
        assert_eq!(w.import_native_key(n, &[1; 32]).err(), Some(Error::Argument), "import");
    }
    assert_eq!(w.bitcoin_key(Network::Near, None, 0, 0).err(), Some(Error::Argument), "bitcoin_key on near");
    assert_eq!(w.bitcoin_key(Network::Evm, None, 0, 0).err(), Some(Error::Argument), "bitcoin_key on evm");
    assert!(w.native_key(Network::Evm, 0, None).unwrap().sign_key_proof(&[0; 32]).is_ok());
}

#[test]
fn bitcoin_keys_sign_no_evm_record() {
    use scaas_ua::wallet::{AllowAnyTypedData, EvmTx, Expect, TypedData};
    let v = native();
    let w = wallet(&v, "pq_kat");
    let td = TypedData::from_json(&serde_json::to_vec(&v["refusals"].as_array().unwrap().iter().find(|r| r["call"] == "sign_typed").unwrap()["args"]["typedData"]).unwrap()).unwrap();
    let tx = EvmTx::from_json(br#"{"type":2,"chainId":"1","nonce":"0","maxPriorityFeePerGas":"1","maxFeePerGas":"2","gasLimit":"21000","to":"0x1111111111111111111111111111111111111111","value":"0","data":"0x","accessList":[]}"#).unwrap();
    for n in [Network::BitcoinP2wpkh, Network::BitcoinP2tr, Network::Near] {
        let k = w.native_key(n, 0, None).unwrap();
        assert_eq!(k.sign_typed(&td, Expect::Any(AllowAnyTypedData)).err(), Some(Error::Argument), "{n:?} typed");
        assert_eq!(k.sign_transaction(&tx).err(), Some(Error::Argument), "{n:?} transaction");
    }
    let evm = w.native_key(Network::Evm, 0, None).unwrap();
    assert!(evm.sign_typed(&td, Expect::Any(AllowAnyTypedData)).is_ok());
    assert!(evm.sign_transaction(&tx).is_ok());
}

#[test]
fn manifest_change_written_only_when_one() {
    use scaas_ua::wallet::Manifest;
    let v = native();
    let w = wallet(&v, "pq_kat");
    w.bitcoin_key(Network::BitcoinP2wpkh, None, 0, 0).unwrap();
    let j0 = w.manifest().to_json();
    assert!(!j0.contains("\"change\""), "{j0}");
    w.bitcoin_key(Network::BitcoinP2tr, Some(1), 1, 3).unwrap();
    let j1 = w.manifest().to_json();
    assert!(j1.contains("\"network\":\"bitcoin_p2tr\",\"coinType\":1,\"index\":3,\"change\":1"), "{j1}");
    assert_eq!(Manifest::from_json(j1.as_bytes()).unwrap(), w.manifest(), "round trip");
    for bad in ["\"change\":2", "\"change\":0"] {
        let j = j1.replace("\"change\":1", bad);
        assert_eq!(Manifest::from_json(j.as_bytes()).err(), Some(Error::Argument), "{bad}");
    }
}

// ------------------------------------------------------------------ T8a: Polkadot sr25519, the bare account, SS58

#[test]
fn native_json_polkadot_bare_addresses_and_ss58() {
    let v = native();
    let mut n = 0;
    for r in arr(&v, "addresses").iter().filter(|r| r["network"] == "polkadot") {
        let k = wallet(&v, r["mnemonic"].as_str().unwrap()).native_key(Network::Polkadot, 0, None).unwrap();
        assert_eq!(hex::encode(k.public_key()), r["publicKey"].as_str().unwrap(), "{r}");
        assert_eq!(k.address().as_deref(), r["address"].as_str(), "{r}");
        for (p, a) in r["ss58"].as_object().unwrap() {
            assert_eq!(k.ss58_address(p.parse().unwrap()).unwrap(), a.as_str().unwrap(), "{} prefix {p}", r["mnemonic"]);
        }
        n += 1;
    }
    assert_eq!(n, 6);
}

#[cfg(feature = "vectors")]
#[test]
fn native_json_polkadot_mini_secrets() {
    let v = native();
    for r in arr(&v, "addresses").iter().filter(|r| r["network"] == "polkadot") {
        let w = wallet(&v, r["mnemonic"].as_str().unwrap());
        assert_eq!(hex::encode(*w.vectors_substrate_mini().unwrap()), r["miniSecret"].as_str().unwrap(), "{}", r["mnemonic"]);
    }
}

#[test]
fn substrate_known_answers_and_the_passphrase_as_given() {
    let v = native();
    let dev = wallet(&v, "substrate_dev").native_key(Network::Polkadot, 0, None).unwrap();
    let bare = &v["external"]["subkey"]["rows"][0];
    assert_eq!(hex::encode(dev.public_key()), bare["publicKey"].as_str().unwrap());
    assert_eq!(dev.ss58_address(42).unwrap(), bare["ss58"].as_str().unwrap());
    let (nfc, nfd) = (wallet(&v, "non_ascii_nfc"), wallet(&v, "non_ascii_nfd"));
    assert_eq!(nfc.native_key(Network::Evm, 0, None).unwrap().public_key(), nfd.native_key(Network::Evm, 0, None).unwrap().public_key(), "one BIP-39 seed");
    assert_ne!(nfc.native_key(Network::Polkadot, 0, None).unwrap().public_key(), nfd.native_key(Network::Polkadot, 0, None).unwrap().public_key(), "two Polkadot accounts");
}

#[test]
fn polkadot_refusals_beside_their_accepted_neighbours() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    assert_eq!(w.native_key(Network::Polkadot, 1, None).err(), Some(Error::Argument), "index 1");
    for c in [0, 354] {
        assert_eq!(w.native_key(Network::Polkadot, 0, Some(c)).err(), Some(Error::Argument), "coin {c}");
    }
    let k = w.native_key(Network::Polkadot, 0, None).unwrap();
    for p in [46, 47, 16_384] {
        assert_eq!(k.ss58_address(p).err(), Some(Error::Argument), "prefix {p}");
    }
    for p in [0, 42, 64, 16_383] {
        assert!(k.ss58_address(p).is_ok(), "prefix {p}");
    }
    assert_eq!(w.native_key(Network::Solana, 0, None).unwrap().ss58_address(0).err(), Some(Error::Argument), "ss58 off Polkadot");
    assert_eq!(k.sign_key_proof(&[0; 32]).err(), Some(Error::Argument));
    assert_eq!(w.import_native_key(Network::Polkadot, &[1; 32]).err(), Some(Error::Argument));
}

#[test]
fn polkadot_signatures_verify_and_differ_the_polkadot_js_row_verifies() {
    let v = native();
    let w = wallet(&v, "substrate_dev");
    let k = w.native_key(Network::Polkadot, 0, None).unwrap();
    let pk = k.public_key();
    for m in [&[1u8][..], &[2; 32], &[3; 257]] {
        let (a, b) = (k.sign_message(m, AllowRawDigest).unwrap(), k.sign_message(m, AllowRawDigest).unwrap());
        assert_ne!(a, b);
        assert!(sr_verify(&pk, m, &a) && sr_verify(&pk, m, &b));
        assert_eq!(a.last().map(|x| x & 0x80), Some(0x80), "schnorrkel's marker bit");
    }
    let d = k.sign_digest(&[4; 32], AllowRawDigest).unwrap();
    assert!(sr_verify(&pk, &[4; 32], &d));
    let j = &v["external"]["polkadotJsSignature"];
    let h = |k: &str| hex::decode(j[k].as_str().unwrap()).unwrap();
    assert!(sr_verify(&h("publicKey"), &h("message"), &h("signature")));
    assert!(!sr_verify(&h("publicKey"), &[&h("message")[..], &[0]].concat(), &h("signature")), "one byte appended");
}

/// An independent sr25519 verify (schnorrkel, context `substrate`), for the wallet's signatures.
fn sr_verify(pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let (Ok(p), Ok(s)) = (schnorrkel::PublicKey::from_bytes(pk), schnorrkel::Signature::from_bytes(sig)) else { return false };
    p.verify_simple(b"substrate", m, &s).is_ok()
}

#[test]
fn polkadot_handle_after_lock_is_key_revoked() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.native_key(Network::Polkadot, 0, None).unwrap();
    assert!(k.sign_message(&[1], AllowRawDigest).is_ok());
    w.lock();
    assert_eq!(k.sign_message(&[1], AllowRawDigest).err(), Some(Error::KeyRevoked));
    assert_eq!(w.native_key(Network::Polkadot, 0, None).err(), Some(Error::WalletLocked));
}

// ------------------------------------------------------------------ T8b: Polkadot junctions, polkadotPaths

#[test]
fn native_json_polkadot_paths_rows() {
    let v = native();
    let mut n = 0;
    for r in arr(&v, "polkadotPaths") {
        let w = wallet(&v, r["mnemonic"].as_str().unwrap());
        let k = w.polkadot_key(r["path"].as_str().unwrap()).unwrap();
        assert_eq!(hex::encode(k.public_key()), r["publicKey"].as_str().unwrap(), "{} '{}'", r["mnemonic"], r["path"]);
        assert_eq!(k.address().as_deref(), r["address"].as_str());
        n += 1;
    }
    assert_eq!(n, 102);
    let w = wallet(&v, "substrate_dev");
    for r in arr(&v["external"]["subkey"], "rows") {
        assert_eq!(hex::encode(w.polkadot_key(r["path"].as_str().unwrap()).unwrap().public_key()), r["publicKey"].as_str().unwrap());
    }
    assert_eq!(w.polkadot_key("").unwrap().public_key(), w.native_key(Network::Polkadot, 0, None).unwrap().public_key());
}

#[test]
fn native_json_polkadot_key_refusal_rows() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let mut n = 0;
    for r in arr(&v, "refusals").iter().filter(|r| r["call"] == "polkadot_key") {
        assert_eq!(w.polkadot_key(r["args"]["path"].as_str().unwrap()).err(), Some(Error::Argument), "{}", r["id"]);
        assert!(w.polkadot_key(r["accepted"]["path"].as_str().unwrap()).is_ok(), "neighbour of {}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 12);
}

#[test]
fn soft_keys_sign_and_verify() {
    let v = native();
    let w = wallet(&v, "substrate_dev");
    for p in ["/soft", "//Alice/0", "/soft//hard"] {
        let k = w.polkadot_key(p).unwrap();
        let s = k.sign_message(&[1, 2, 3], AllowRawDigest).unwrap();
        assert!(sr_verify(&k.public_key(), &[1, 2, 3], &s), "{p}");
    }
}

#[test]
fn manifest_polkadot_paths_written_only_when_not_empty_bounded_on_read() {
    use scaas_ua::wallet::Manifest;
    let v = native();
    let w = wallet(&v, "pq_kat");
    w.native_key(Network::Polkadot, 0, None).unwrap();
    assert!(!w.manifest().to_json().contains("polkadotPaths"), "the bare key adds no path");
    w.polkadot_key("//polkadot").unwrap();
    w.polkadot_key("/a\"b").unwrap();
    let j = w.manifest().to_json();
    assert!(j.contains("\"polkadotPaths\":[\"//polkadot\",\"/a\\\"b\"]"), "{j}");
    assert_eq!(Manifest::from_json(j.as_bytes()).unwrap(), w.manifest(), "round trip");
    let with = |paths: Vec<String>| {
        let list = paths.iter().map(|p| serde_json::Value::from(p.as_str()).to_string()).collect::<Vec<_>>().join(",");
        j.replace("\"polkadotPaths\":[\"//polkadot\",\"/a\\\"b\"]", &format!("\"polkadotPaths\":[{list}]"))
    };
    let many = |n: usize| (0..n).map(|i| format!("//{i}")).collect::<Vec<_>>();
    assert!(Manifest::from_json(with(many(64)).as_bytes()).is_ok(), "64 paths");
    assert_eq!(Manifest::from_json(with(many(65)).as_bytes()).err(), Some(Error::Argument), "65 paths");
    for bad in ["///pw", "//007", "", "//"] {
        assert_eq!(Manifest::from_json(with(vec![bad.into()]).as_bytes()).err(), Some(Error::Argument), "{bad}");
    }
    assert_eq!(Manifest::from_json(with(vec!["//a".into(), "//a".into()]).as_bytes()).err(), Some(Error::Argument), "duplicate");
}

#[test]
fn a_65th_path_is_refused() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    for i in 0..64 {
        w.polkadot_key(&format!("//{i}")).unwrap();
    }
    assert_eq!(w.polkadot_key("//64").err(), Some(Error::Argument));
    assert!(w.polkadot_key("//63").is_ok(), "a listed path still derives");
}

#[test]
fn junction_handle_after_lock_is_key_revoked() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.polkadot_key("//x/y").unwrap();
    w.lock();
    assert_eq!(k.sign_message(&[1], AllowRawDigest).err(), Some(Error::KeyRevoked));
    assert_eq!(w.polkadot_key("//x").err(), Some(Error::WalletLocked));
}

#[test]
fn network_list_is_native_json_networks() {
    let v = native();
    let names: Vec<&str> = Network::all().iter().map(|n| n.name()).collect();
    let want: Vec<&str> = arr(&v, "networks").iter().map(|n| n.as_str().unwrap()).collect();
    assert_eq!(names, want);
}

// ------------------------------------------------------------------ T9: rs_native.json (both ways)

/// The OS-random rows ua-rs writes for clientkeys to verify (spec §12.1, CLI-UAL-47): release Taproot signatures (receive 0 and 1,
/// change 0) and release sr25519 signatures on the bare, `//Alice` and soft keys. A row that still verifies is kept as it is,
/// so the file moves only when a key or message does.
#[cfg(feature = "vectors")]
#[test]
#[ignore]
fn regenerate() {
    let v = native();
    let path = format!("{}/../../smartcontracts/vectors/native/rs_native.json", env!("CARGO_MANIFEST_DIR"));
    let old = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
    let verifies = |r: &Value| {
        let (pk, m, s) = (hex::decode(r["publicKey"].as_str().unwrap()).unwrap(), hex::decode(r["message"].as_str().unwrap()).unwrap(), hex::decode(r["signature"].as_str().unwrap()).unwrap());
        match r["scheme"].as_str().unwrap() {
            "bip340-taproot" => scaas_ua::verify::verify(0x0103, &pk, &m.try_into().unwrap(), &s, false),
            _ => sr_verify(&pk, &m, &s),
        }
    };
    let mut rows = Vec::new();
    let abandon = wallet(&v, "bip39_abandon");
    for (change, index) in [(0u32, 0u32), (0, 1), (1, 0)] {
        let k = abandon.bitcoin_key(Network::BitcoinP2tr, None, change, index).unwrap();
        let m = [change as u8 * 16 + index as u8 + 1; 32];
        rows.push((serde_json::json!({ "id": format!("p2tr-{change}-{index}"), "scheme": "bip340-taproot", "mnemonic": "bip39_abandon",
            "network": "bitcoin_p2tr", "coinType": null, "change": change, "index": index, "message": hex::encode(m),
            "publicKey": hex::encode(k.witness_program().unwrap().1) }), k.sign_digest(&m, AllowRawDigest).unwrap()));
    }
    let dev = wallet(&v, "substrate_dev");
    for p in ["", "//Alice", "/soft", "//Alice/0"] {
        let k = dev.polkadot_key(p).unwrap();
        let m = format!("scaas ua-rs-native rs_native {p}").into_bytes();
        rows.push((serde_json::json!({ "id": format!("sr25519-{p}"), "scheme": "sr25519", "mnemonic": "substrate_dev", "network": "polkadot",
            "path": p, "message": hex::encode(&m), "publicKey": hex::encode(k.public_key()) }), k.sign_message(&m, AllowRawDigest).unwrap()));
    }
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(row, fresh)| {
            let mut r = row.clone();
            let keep = old.as_ref().and_then(|o| arr(o, "rows").iter().find(|x| {
                let mut y = (*x).clone();
                y.as_object_mut().unwrap().remove("signature");
                y == row && verifies(x)
            }).cloned());
            match keep {
                Some(k) => k,
                None => {
                    r["signature"] = Value::String(hex::encode(fresh));
                    r
                }
            }
        })
        .collect();
    for r in &out {
        assert!(verifies(r), "{}", r["id"]);
    }
    let doc = serde_json::json!({
        "note": "Written by clients/ua-rs/tests/wallet_native.rs regenerate (ua-rs-native T9, feature vectors, ignored) with the release signers \
                 (OS randomness: Taproot aux, sr25519 r and soft nonce halves); read by clientkeys test/native.test.js, which re-derives each \
                 public key from its mnemonic and verifies each signature (CLI-UAL-47: randomized rows both ways). A row that still verifies \
                 is kept. Never edit by hand.",
        "rows": out,
    });
    std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
}

// ------------------------------------------------------------------ T13 C2: sign_digest takes 32 bytes, by type

/// native.json's `sign_digest` refusal rows (clientkeys refuses anything but 32 bytes): here `&[u8; 32]` holds the rule, so each
/// refused length does not fit the type, and each 32-byte neighbour signs on its key.
#[test]
fn native_json_sign_digest_rows_are_32_bytes_by_type() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let mut n = 0;
    for r in arr(&v, "refusals").iter().filter(|r| r["call"] == "sign_digest") {
        assert!(<[u8; 32]>::try_from(msg(&r["args"])).is_err(), "{}", r["id"]);
        let ok: [u8; 32] = msg(&r["accepted"]).try_into().unwrap();
        assert!(w.native_key(net(&r["accepted"]), 0, None).unwrap().sign_digest(&ok, AllowRawDigest).is_ok(), "neighbour of {}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 4, "31 B on solana, the APTOS\\n envelope, 33 B on polkadot, 5 B on bitcoin_p2tr");
}

// ------------------------------------------------------------------ T13 C6: NEAR, no NEP-461 tagged payload

#[test]
fn sign_near_transaction_refuses_nep461_tags_beside_a_transaction() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.native_key(Network::Near, 0, None).unwrap();
    let tail = [0u8; 8];
    for tag in [(1u32 << 31) + 413, (1 << 30) + 366] {
        let tx = [&tag.to_le_bytes()[..], &tail].concat();
        assert_eq!(k.sign_near_transaction(&tx, AllowRawDigest).err(), Some(Error::Argument), "{tag:#x}");
    }
    for len in [0u32, 2, 64, (1 << 31) + 414, (1 << 30) + 365, 0xa5a5_a5a5] {
        assert!(k.sign_near_transaction(&[&len.to_le_bytes()[..], &tail].concat(), AllowRawDigest).is_ok(), "{len}");
    }
    assert!(k.sign_near_transaction(&[0x40, 0, 0], AllowRawDigest).is_ok(), "shorter than four bytes: no tag to read");
}

// ------------------------------------------------------------------ T13 C7: the manifest takes only entries the wallet writes

#[test]
fn manifest_refuses_change_off_bitcoin_and_refused_coin_types() {
    use scaas_ua::wallet::Manifest;
    let v = native();
    let w = wallet(&v, "pq_kat");
    w.bitcoin_key(Network::BitcoinP2tr, Some(1), 1, 3).unwrap();
    w.native_key(Network::Near, 0, None).unwrap();
    w.native_key(Network::Solana, 0, Some(501)).unwrap();
    let j = w.manifest().to_json();
    let (btc, near, sol) = (
        "\"network\":\"bitcoin_p2tr\",\"coinType\":1,\"index\":3,\"change\":1",
        "\"network\":\"near\",\"coinType\":null,\"index\":0",
        "\"network\":\"solana\",\"coinType\":501,\"index\":0",
    );
    for e in [btc, near, sol] {
        assert!(j.contains(e), "{e} in {j}");
    }
    assert_eq!(Manifest::from_json(j.as_bytes()).unwrap(), w.manifest(), "the written manifest reads back");
    for (from, to) in [
        (btc, btc.replace("\"coinType\":1", "\"coinType\":2")),
        (near, near.replace("null", "397")),
        (sol, format!("{sol},\"change\":1")),
        (btc, btc.replace("bitcoin_p2tr", "evm")),
    ] {
        assert_eq!(Manifest::from_json(j.replace(from, &to).as_bytes()).err(), Some(Error::Argument), "{to}");
    }
    for (from, to) in [(btc, btc.replace("\"coinType\":1", "\"coinType\":0")), (sol, sol.replace("501", "1"))] {
        assert!(Manifest::from_json(j.replace(from, &to).as_bytes()).is_ok(), "{to}");
    }
}
