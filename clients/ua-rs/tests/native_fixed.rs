// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-native: the fixed-randomness rows of native.json (test-only, feature `vectors`; CLI-UAL-02: a release build draws the
//! Taproot `aux` and the sr25519 `r` from the OS RNG and never takes them from a caller) and the published Taproot known answers
//! (BIP-340 test-vectors.csv, BIP-341 keyPathSpending with a null Merkle root), through the release signers' own code. UNAUDITED.
use scaas_ua::wallet::{sign, vectors_taproot_sign, vectors_taproot_sign_check, Error, Network, Wallet};
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
fn h(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn h32(v: &Value) -> [u8; 32] {
    h(v).try_into().unwrap()
}
fn opt_u32(v: &Value) -> Option<u32> {
    v.as_u64().map(|c| u32::try_from(c).unwrap())
}
fn msg(r: &Value) -> Vec<u8> {
    if let Some(m) = r["messageRepeat"].as_object() {
        vec![u8::from_str_radix(m["byte"].as_str().unwrap(), 16).unwrap(); usize::try_from(m["length"].as_u64().unwrap()).unwrap()]
    } else {
        h(&r["message"])
    }
}

#[test]
fn native_json_p2tr_fixed_aux_rows_byte_equal() {
    let v = native();
    let w = wallet(&v, "bip39_abandon");
    let mut n = 0;
    for r in arr(&v, "signatures").iter().filter(|r| r["network"] == "bitcoin_p2tr") {
        assert_eq!(r["mode"], "fixed-randomness");
        let k = w.bitcoin_key(Network::BitcoinP2tr, opt_u32(&r["coinType"]), opt_u32(&r["change"]).unwrap(), opt_u32(&r["index"]).unwrap()).unwrap();
        let sig = k.vectors_sign_digest_fixed(&msg(r).try_into().unwrap(), &h32(&r["aux"])).unwrap();
        assert_eq!(hex::encode(sig), r["signature"].as_str().unwrap(), "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 6);
}

#[test]
fn bip341_key_path_spending_null_merkle_root() {
    let v = native();
    let rows = arr(&v["external"]["bip341"], "keyPathSpending");
    assert_eq!(rows.len(), 1);
    for r in rows {
        let sig = vectors_taproot_sign(&h32(&r["internalPrivkey"]), &h32(&r["sigHash"]), &h32(&r["aux"])).unwrap();
        assert_eq!(hex::encode(sig), r["signature"].as_str().unwrap());
    }
}

#[test]
fn taproot_self_check_refuses_a_fault_beside_the_right_key() {
    let v = native();
    let r = &arr(&v["external"]["bip341"], "keyPathSpending")[0];
    let (sk, d, aux) = (h32(&r["internalPrivkey"]), h32(&r["sigHash"]), h32(&r["aux"]));
    let q = h32(&arr(&v["external"]["bip341"], "scriptPubKey")[0]["tweakedPubkey"]);
    assert!(vectors_taproot_sign_check(&sk, &d, &aux, &q).is_ok(), "the right x(Q)");
    let mut wrong = q;
    wrong[31] ^= 1;
    assert_eq!(vectors_taproot_sign_check(&sk, &d, &aux, &wrong).err(), Some(Error::Argument), "a replaced x(Q)");
}

#[test]
fn bip340_csv_signing_rows_through_sign_raw() {
    let v = native();
    let mut n = 0;
    for r in arr(&v["external"]["bip340"], "rows").iter().filter(|r| r["secretKey"].is_string() && r["message"].as_str().unwrap().len() == 64) {
        let m = h(&r["message"]);
        let sig = sign::sign_raw(0x0103, &h(&r["secretKey"]), &m, Some(&h32(&r["aux"]))).unwrap();
        assert_eq!(hex::encode_upper(sig), r["signature"].as_str().unwrap(), "row {}", r["index"]);
        n += 1;
    }
    assert!(n >= 4, "{n}");
}

// ------------------------------------------------------------------ T8a: sr25519 with fixed randomness (test-only)

#[test]
fn native_json_sr25519_fixed_rows_byte_equal_one_read_each() {
    let v = native();
    let w = wallet(&v, "substrate_dev");
    let mut n = 0;
    for r in arr(&v, "signatures").iter().filter(|r| r["network"] == "polkadot" && r["mode"] == "fixed-randomness" && r["path"] == "") {
        let k = w.native_key(Network::Polkadot, 0, None).unwrap();
        let (m, aux) = (msg(r), h32(&r["aux"]));
        let sig = if r["call"] == "sign_digest" {
            k.vectors_sign_digest_fixed(&m.try_into().unwrap(), &aux).unwrap()
        } else {
            k.vectors_sign_message_fixed(&m, &aux).unwrap()
        };
        assert_eq!(hex::encode(sig), r["signature"].as_str().unwrap(), "{}", r["id"]);
        assert_eq!(scaas_ua::wallet::vectors_one_shot_reads(), 1, "{}", r["id"]);
        n += 1;
    }
    assert_eq!(n, 4, "the bare key: three messages and one digest");
}

#[test]
fn a_failing_os_rng_is_error_rng_never_a_panic() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.native_key(Network::Polkadot, 0, None).unwrap();
    let t = w.native_key(Network::BitcoinP2tr, 0, None).unwrap();
    scaas_ua::wallet::vectors_fail_os_rng(true);
    let (a, b) = (k.sign_message(&[1], scaas_ua::wallet::AllowRawDigest), t.sign_digest(&[1; 32], scaas_ua::wallet::AllowRawDigest));
    scaas_ua::wallet::vectors_fail_os_rng(false);
    assert_eq!((a.err(), b.err()), (Some(Error::Rng), Some(Error::Rng)));
    assert!(k.sign_message(&[1], scaas_ua::wallet::AllowRawDigest).is_ok(), "the RNG back");
}

#[test]
fn sr25519_self_verify_refuses_a_wrong_public_key_beside_the_right_one() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    let k = w.native_key(Network::Polkadot, 0, None).unwrap();
    let pk: [u8; 32] = k.public_key().try_into().unwrap();
    assert!(k.vectors_sr25519_sign_check(&[1, 2], &[7; 32], &pk).is_ok());
    let mut wrong = pk;
    wrong[0] ^= 1;
    assert_eq!(k.vectors_sr25519_sign_check(&[1, 2], &[7; 32], &wrong).err(), Some(Error::Argument));
}

#[test]
fn polkadot_slot_in_the_arena() {
    let v = native();
    let w = wallet(&v, "pq_kat");
    assert!(w.native_key(Network::Polkadot, 0, None).unwrap().vectors_secret_in_arena().unwrap());
}
