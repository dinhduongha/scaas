// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! pay-meta-tax T41, ua-mtx-merge T83: `scaas_ua::pay` against the files forge and clientkeys write: `metatx/paymeta.json`
//! (v3 commitments, `save` without a `payNo` refused, the UUIDv7 rows), `metatx/payrecords.json` (the calls and return data an
//! ERP reads by `eth_call`), `metatx/paytax.json` (the PERCENT floor, the `UAPayWithTax` digest row with a non-zero unbound
//! `relayer` / `feeRecipient`) and `typed/typed_ops.json`'s `UAPayWithTax` and `UARelayFee` rows (struct hash, digest).
use scaas_ua::pay::{
    decode_pay_records, meta_pay_id_v3, pay_no_from_uuid, pay_no_to_uuid, pay_with_tax_hash, payment_count_call, payments_of_call,
    percent_tax, relay_fee_hash, token_domain_separator, transfer_hash, typed_digest, PayError, PayMeta, PayRecord, RelayFee,
    UAMetaTransfer,
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

fn meta(r: &Value) -> PayMeta {
    PayMeta { salt: b32(&r["salt"]), pay_no: b32(&r["payNo"]), save: r["save"].as_bool().unwrap(),
        schema: r["schema"].as_u64().unwrap() as u16, body: bytes(&r["body"]) }
}

/// T83: every accepted row is `metaPayId(PayMeta)` under the v3 tag; `save` with `payNo == 0` refused; the v2 tag and `save`
/// off give other commitments; the UUIDv7 rows right-aligned both ways, any other id shown as hex.
#[test]
fn paymeta_v3_rows() {
    let rows = load("metatx/paymeta.json");
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 9);
    for r in rows {
        if r["accepted"].as_bool().unwrap() {
            assert_eq!(meta_pay_id_v3(&meta(r)).unwrap(), b32(&r["payId"]), "{}", r["name"]);
        } else {
            assert_eq!(meta_pay_id_v3(&meta(r)), Err(PayError::Shape), "{}", r["name"]);
        }
        match r["payNoUuid"].as_str() {
            Some(u) => {
                assert_eq!(pay_no_from_uuid(u), Some(b32(&r["payNo"])), "{}", r["name"]);
                assert_eq!(pay_no_to_uuid(&b32(&r["payNo"])).as_deref(), Some(u), "{}", r["name"]);
            }
            None => assert_eq!(pay_no_to_uuid(&b32(&r["payNo"])), None, "{}: shown as hex", r["name"]),
        }
    }
    let row = |n: &str| rows.iter().find(|r| r["name"] == n).unwrap();
    let saved = row("payno_uuidv7_save");
    assert_eq!(meta_pay_id_v3(&PayMeta { save: false, ..meta(saved) }).unwrap(), b32(&saved["saveOffPayId"]), "save committed");
    let v2 = row("payno_uuidv7");
    assert_ne!(b32(&v2["v2TagPayId"]), b32(&v2["payId"]), "the v2 tag commits otherwise");
    assert!(rows.iter().any(|r| !r["accepted"].as_bool().unwrap()), "a refused row");
}

/// The shape rules before anything is signed (positive control first).
#[test]
fn pay_meta_shape() {
    let m = |salt: u8, schema: u16, body: &[u8]| PayMeta { salt: [salt; 32], pay_no: [0; 32], save: false, schema, body: body.to_vec() };
    assert!(meta_pay_id_v3(&m(1, 1, b"x")).is_ok());
    assert_eq!(meta_pay_id_v3(&m(0, 0, b"")), Err(PayError::Shape));
    assert_eq!(meta_pay_id_v3(&m(1, 0, b"x")), Err(PayError::Shape));
    assert_eq!(meta_pay_id_v3(&m(1, 1, b"")), Err(PayError::Shape));
    assert_eq!(meta_pay_id_v3(&PayMeta { save: true, ..m(1, 0, b"") }), Err(PayError::Shape), "save needs a payNo");
    assert!(meta_pay_id_v3(&PayMeta { save: true, pay_no: [1; 32], ..m(1, 0, b"") }).is_ok());
}

/// clientkeys `payNoFromUuid` / `payNoToUuid`: UUIDv7 only, right-aligned, any case in, lowercase out.
#[test]
fn pay_no_uuid_helpers() {
    let u = "019a6e3c-5f00-7a3b-8c4d-5e6f708192a3";
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&hex::decode(u.replace('-', "")).unwrap());
    assert_eq!(pay_no_from_uuid(u), Some(w));
    assert_eq!(pay_no_from_uuid(&u.to_uppercase()), Some(w));
    assert_eq!(pay_no_to_uuid(&w).as_deref(), Some(u));
    for bad in ["019a6e3c-5f00-4a3b-8c4d-5e6f708192a3", "019a6e3c-5f00-7a3b-cc4d-5e6f708192a3", "019a6e3c5f007a3b8c4d5e6f708192a3",
        "INV-2026-0042", "019a6e3c-5f00-7a3b-8c4d-5e6f708192a", "019a6e3c-5f00-7a3b-8c4d-5e6f708192a3-", "019a6e3c-5f00-7a3b-8c4d-5e6f708192ag",
        "+19a6e3c-5f00-7a3b-8c4d-5e6f708192a3"]
    {
        assert_eq!(pay_no_from_uuid(bad), None, "{bad}");
    }
    let mut high = w;
    high[0] = 1;
    assert_eq!(pay_no_to_uuid(&high), None, "the high 16 bytes set");
    let mut v4 = w;
    v4[22] = 0x4a;
    assert_eq!(pay_no_to_uuid(&v4), None, "version 4: hex");
    let mut var = w;
    var[24] = 0xcc;
    assert_eq!(pay_no_to_uuid(&var), None, "variant 110: hex");
}

/// T83's records row: the calls an ERP sends by `eth_call` and their answers, read canonical only.
#[test]
fn payrecords_rows() {
    let r = load("metatx/payrecords.json");
    let no = b32(&r["payNo"]);
    assert_eq!(pay_no_from_uuid(r["payNoUuid"].as_str().unwrap()), Some(no));
    assert_eq!(payment_count_call(&no), bytes(&r["paymentCount"]["calldata"]));
    assert_eq!(bytes(&r["paymentCount"]["returndata"]), [[0u8; 31].as_slice(), &[r["length"].as_u64().unwrap() as u8]].concat());
    let recs: Vec<PayRecord> = r["records"].as_array().unwrap().iter().map(|x| PayRecord { to: b32(&x["to"]),
        amount: uint_word(&x["amount"]), block_number: x["blockNumber"].as_u64().unwrap() }).collect();
    for (k, off, limit, want) in [("paymentsOfAll", 0, 10, &recs[..]), ("paymentsOfSecond", 1, 1, &recs[1..]), ("paymentsOfPastEnd", 2, 1, &[])] {
        assert_eq!(payments_of_call(&no, off, limit), bytes(&r[k]["calldata"]), "{k}");
        assert_eq!(decode_pay_records(&bytes(&r[k]["returndata"])).as_deref(), Some(want), "{k}");
    }
    let all = bytes(&r["paymentsOfAll"]["returndata"]);
    let bad = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut b = all.clone();
        f(&mut b);
        decode_pay_records(&b)
    };
    assert!(bad(&|_| ()).is_some(), "positive control");
    assert_eq!(bad(&|b| b.push(0)), None, "a trailing byte");
    assert_eq!(bad(&|b| b.truncate(b.len() - 32)), None, "a record short");
    assert_eq!(bad(&|b| b[31] = 0x40), None, "another offset");
    assert_eq!(bad(&|b| b[63] = 3), None, "a count past the data");
    assert_eq!(bad(&|b| b[32] = 1), None, "a count past 2^64");
    assert_eq!(bad(&|b| b[64 + 32] = 1), None, "amount at 2^192");
    assert_eq!(bad(&|b| b[64 + 64 + 23] = 1), None, "blockNumber at 2^64");
    assert_eq!(decode_pay_records(&[]), None);
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
    for r in p.as_array().unwrap() {
        let got = meta_pay_id_json(&r.to_string());
        if !r["accepted"].as_bool().unwrap() {
            assert!(got.is_err(), "{}: refused", r["name"]);
            continue;
        }
        let got: Value = serde_json::from_str(&got.unwrap()).unwrap();
        assert_eq!(got["payId"], r["payId"], "{}", r["name"]);
        assert_eq!(got["payNo"], r["payNo"], "{}", r["name"]);
        assert_eq!(got["save"], r["save"], "{}", r["name"]);
        assert_eq!(got["payNoUuid"], r.get("payNoUuid").cloned().unwrap_or(Value::Null), "{}: the UUID, else null", r["name"]);
    }
    let salt_only = serde_json::json!({ "salt": p[0]["salt"], "schema": 0, "body": "0x" });
    let got: Value = serde_json::from_str(&meta_pay_id_json(&salt_only.to_string()).unwrap()).unwrap();
    assert_eq!(got["payId"], p[0]["payId"], "payNo and save absent: 0 and false");
    let mut text = p[1].clone();
    text["payNo"] = "INV-2026-0042".into();
    assert!(meta_pay_id_json(&text.to_string()).is_err(), "a text payNo (v2) refused");
    let mut save = p[1].clone();
    save["save"] = "true".into();
    assert!(meta_pay_id_json(&save.to_string()).is_err(), "save not a bool");
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
