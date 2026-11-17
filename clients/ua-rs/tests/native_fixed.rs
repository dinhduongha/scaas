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
