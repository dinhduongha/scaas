// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! pay-meta-tax T41: `scaas_ua::pay` against the files forge and clientkeys write: `metatx/paymeta.json` (v2 commitments, the
//! 257-byte refusal), `metatx/paytax.json` (the PERCENT floor, the `UAPayWithTax` digest row with a non-zero unbound
//! `relayer` / `feeRecipient`) and `typed/typed_ops.json`'s `UAPayWithTax` and `UARelayFee` rows (struct hash, digest).
use scaas_ua::pay::{
    check_pay_no, meta_pay_id_v2, pay_with_tax_hash, percent_tax, relay_fee_hash, token_domain_separator, transfer_hash,
    typed_digest, PayError, PayMeta, RelayFee, UAMetaTransfer,
};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn b20(v: &Value) -> [u8; 20] {
    bytes(v).try_into().unwrap()
}
fn num(v: &Value) -> u128 {
    v.as_u64().map(u128::from).unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}
/// A uint of the JSON (a number or a decimal string, up to 256 bits) as its ABI word.
fn uint_word(v: &Value) -> [u8; 32] {
    let s = v.as_u64().map(|n| n.to_string()).unwrap_or_else(|| v.as_str().unwrap().to_string());
    let mut w = [0u8; 32];
    for d in s.bytes() {
        let mut carry = (d - b'0') as u32;
        for b in w.iter_mut().rev() {
            let x = *b as u32 * 10 + carry;
            *b = x as u8;
            carry = x >> 8;
        }
        assert_eq!(carry, 0, "over 256 bits");
    }
    w
}
fn transfer(m: &Value) -> UAMetaTransfer {
    UAMetaTransfer {
        from: b32(&m["from"]),
        to: b32(&m["to"]),
        value: uint_word(&m["value"]),
        entry_ref: b32(&m["entryRef"]),
        batch: uint_word(&m["batch"]),
        nonce: uint_word(&m["nonce"]),
        valid_until: uint_word(&m["validUntil"]),
        mode: num(&m["mode"]) as u32,
        relayer: b20(&m["relayer"]),
        fee: uint_word(&m["fee"]),
        fee_recipient: b20(&m["feeRecipient"]),
    }
}

#[test]
fn paymeta_v2_rows() {
    let rows = load("metatx/paymeta.json");
    assert_eq!(rows.as_array().unwrap().len(), 9);
    for r in rows.as_array().unwrap() {
        let m = PayMeta { salt: b32(&r["salt"]), pay_no: r["payNo"].as_str().unwrap().into(),
            schema: r["schema"].as_u64().unwrap() as u16, body: bytes(&r["body"]) };
        if r["accepted"].as_bool().unwrap() {
            assert_eq!(meta_pay_id_v2(&m).unwrap(), b32(&r["payId"]), "{}", r["name"]);
        } else {
            assert_eq!(meta_pay_id_v2(&m), Err(PayError::PayNoTooLong), "{}", r["name"]);
        }
    }
}

#[test]
fn pay_meta_shape_and_pay_no_text() {
    let m = |salt: u8, schema: u16, body: &[u8]| PayMeta { salt: [salt; 32], pay_no: String::new(), schema, body: body.to_vec() };
    assert_eq!(meta_pay_id_v2(&m(0, 0, b"")), Err(PayError::Shape));
    assert_eq!(meta_pay_id_v2(&m(1, 0, b"x")), Err(PayError::Shape));
    assert_eq!(meta_pay_id_v2(&m(1, 1, b"")), Err(PayError::Shape));
    assert!(meta_pay_id_v2(&m(1, 1, b"x")).is_ok());
    assert_eq!(check_pay_no(&"A".repeat(256)), Ok(()));
    assert_eq!(check_pay_no(&"A".repeat(257)), Err(PayError::PayNoTooLong));
    for bad in ["INV\u{202e}1", "INV\u{2066}x\u{2069}", "INV\n1", "INV\u{85}", "a\u{200f}b", "x\u{61c}"] {
        assert_eq!(check_pay_no(bad), Err(PayError::PayNoText), "{bad:?}");
    }
}

#[test]
fn paytax_rows_and_digest() {
    let v = load("metatx/paytax.json");
    let rows = v.as_array().unwrap();
    assert_eq!(rows.len(), 25);
    for r in rows.iter().filter(|r| r["taxMode"] == 1 && r["refused"] == "") {
        let Ok(amount) = r["amount"].as_str().unwrap().parse::<u128>() else { continue }; // 2^255: past u128
        let rate = r["ratePpm"].as_u64().unwrap() as u32;
        assert_eq!(percent_tax(amount, rate).unwrap().to_string(), r["tax"].as_str().unwrap(), "{}", r["name"]);
    }
    let r = rows.iter().find(|r| r["name"] == "digest_unbound_relayer_fee_recipient").unwrap();
    assert_ne!(b20(&r["relayer"]), [0; 20], "a non-zero unbound relayer in the input");
    let t = transfer(r);
    assert_eq!(transfer_hash(&t), b32(&r["paymentHash"]));
    let sh = pay_with_tax_hash(&t, r["taxMode"].as_u64().unwrap() as u8, &uint_word(&r["tax"])).unwrap();
    assert_eq!(sh, b32(&r["structHash"]));
    let d = &r["domain"];
    let ds = token_domain_separator(d["name"].as_str().unwrap(), d["chainId"].as_u64().unwrap(), &b20(&d["verifyingContract"]),
        &b32(&d["salt"]));
    assert_eq!(typed_digest(&ds, &sh), b32(&r["digest"]));
    assert_eq!(pay_with_tax_hash(&t, 3, &[0; 32]), Err(PayError::Tax));
    let mut over = uint_word(&r["value"]);
    over[31] += 1;
    assert_eq!(pay_with_tax_hash(&t, 2, &over), Err(PayError::Tax), "tax > value");
}

fn domain(d: &Value) -> [u8; 32] {
    token_domain_separator(d["name"].as_str().unwrap(), num(&d["chainId"]) as u64, &b20(&d["verifyingContract"]),
        &b32(&d["salt"]))
}

#[test]
fn typed_ops_pay_with_tax_rows() {
    let v = load("typed/typed_ops.json");
    let r = &v["ops"]["UAPayWithTax"];
    let m = &r["message"];
    let sh = pay_with_tax_hash(&transfer(&m["payment"]), m["taxMode"].as_u64().unwrap() as u8, &uint_word(&m["tax"])).unwrap();
    assert_eq!(sh, b32(&r["structHash"]));
    let mut n = 0;
    for (_, d) in r["domains"].as_object().unwrap() {
        assert_eq!(typed_digest(&domain(&d["domain"]), &sh), b32(&d["digest"]));
        n += 1;
    }
    assert_eq!(n, 3, "token, zether, pqz");
}

#[test]
fn typed_ops_relay_fee_row() {
    let v = load("typed/typed_ops.json");
    let r = &v["ops"]["UARelayFee"];
    let m = &r["message"];
    let sh = relay_fee_hash(&RelayFee { from: b32(&m["from"]), target: b20(&m["target"]), call_data_hash: b32(&m["callDataHash"]),
        payee: b32(&m["payee"]), value: uint_word(&m["value"]), batch: uint_word(&m["batch"]), nonce: uint_word(&m["nonce"]),
        valid_until: uint_word(&m["validUntil"]), relayer: b20(&m["relayer"]) });
    assert_eq!(sh, b32(&r["structHash"]));
    for (_, d) in r["domains"].as_object().unwrap() {
        assert_eq!(typed_digest(&domain(&d["domain"]), &sh), b32(&d["digest"]));
    }
}

/// The wrappers' surface (feature `json`): the same digests from the vector rows' own JSON.
#[cfg(feature = "json")]
#[test]
fn json_surface() {
    use scaas_ua::json::{meta_pay_id_json, pay_digest_json};
    let p = load("metatx/paymeta.json");
    let r = &p[1];
    let got: Value = serde_json::from_str(&meta_pay_id_json(&r.to_string()).unwrap()).unwrap();
    assert_eq!(got["payId"], r["payId"]);
    assert!(meta_pay_id_json(&p[3].to_string()).is_err(), "257 bytes refused");
    let v = load("metatx/paytax.json");
    let r = v.as_array().unwrap().iter().find(|r| r["name"] == "digest_unbound_relayer_fee_recipient").unwrap();
    let mut payment = r.clone();
    for k in ["name", "taxMode", "tax", "domain", "typehash", "paymentHash", "structHash", "digest"] {
        payment.as_object_mut().unwrap().remove(k);
    }
    let input = serde_json::json!({ "struct": "UAPayWithTax", "domain": r["domain"],
        "message": { "payment": payment, "taxMode": r["taxMode"], "tax": r["tax"] } });
    let got: Value = serde_json::from_str(&pay_digest_json(&input.to_string()).unwrap()).unwrap();
    assert_eq!(got["digest"], r["digest"]);
    let ops = load("typed/typed_ops.json");
    let o = &ops["ops"]["UARelayFee"];
    let input = serde_json::json!({ "struct": "UARelayFee", "domain": o["domains"]["token"]["domain"], "message": o["message"] });
    let got: Value = serde_json::from_str(&pay_digest_json(&input.to_string()).unwrap()).unwrap();
    assert_eq!(got["digest"], o["domains"]["token"]["digest"]);
}
