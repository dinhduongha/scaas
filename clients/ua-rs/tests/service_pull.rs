// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Service pull (spec 2026-11-09-service-pull §10, §11; CLI-SGN-48; ua-rs-sign T20e2): `servicepull.json` is written by its Python
//! generator (`smartcontracts/vectors/metatx/gen_servicepull.py`) and landed by forge (`test/metatx/ServicePullVectors.t.sol`) on
//! the reference service and a real token; clientkeys' `test/servicepull.test.js` reads the same rows. The builder reproduces
//! every row byte for byte (`Note`'s `string` and `bytes` raw in the calldata, hashed in `entryRef`) and refuses what §3.1 / §10
//! refuse, each one change from a row that builds.
use scaas_ua::json::service_pull_json;
use scaas_ua::verify::native_ecdsa;
use scaas_ua::wallet::{scaas_typed_data, TypedData};
use serde_json::{json, Value};

fn rows() -> Vec<Value> {
    let path = format!("{}/../../smartcontracts/vectors/metatx/servicepull.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    v["rows"].as_array().unwrap().clone()
}
fn b(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn args(r: &Value) -> Value {
    let t = &r["t"];
    json!({"name": r["token"]["name"], "token": r["token"]["address"], "chainId": r["chainId"], "chainUid": r["token"]["salt"],
        "entry": r["entry"], "op": r["typedData"], "from": t["from"], "amount": t["value"], "batch": t["batch"], "nonce": t["nonce"],
        "validUntil": t["validUntil"]})
}
fn build(i: &Value) -> Result<Value, ()> {
    service_pull_json(&i.to_string()).map(|s| serde_json::from_str(&s).unwrap()).map_err(|_| ())
}
fn fee_of(r: &Value, nonce: u64) -> Value {
    let f = &r["relayFee"];
    json!({"feeToken": f["feeToken"], "router": f["router"], "executor": f["executor"], "value": f["value"], "batch": f["batch"],
        "nonce": nonce, "validUntil": f["validUntil"], "feeAuth": {"keyData": "0x", "signature": f["signature"], "members": []}})
}

#[test]
fn every_row_entry_ref_digest_selector_calldata_job() {
    let rows = rows();
    assert_eq!(rows.len(), 3);
    for r in &rows {
        let n = r["name"].as_str().unwrap();
        let got = build(&args(r)).unwrap();
        assert_eq!(got["entryRef"], r["entryRef"], "{n}");
        assert_eq!(got["digest"], r["transferDigest"], "{n}");
        assert_eq!(got["selector"], r["selector"], "{n}");
        assert_eq!(got["service"], r["service"]["address"], "{n}");
        let m = &got["typedData"]["message"];
        assert_eq!((&m["to"], &m["relayer"], &m["feeRecipient"]), (&r["t"]["to"], &r["service"]["address"], &json!(format!("0x{}", "00".repeat(20)))), "{n}");
        assert_eq!(got["prompt"]["serviceName"], r["typedData"]["domain"]["name"], "{n}");
        assert_eq!(got["prompt"]["message"], r["typedData"]["message"], "{n}: every field shown");
        // the payer's signature (the generator's) is over this digest
        assert!(native_ecdsa(&b(&r["signer"]).try_into().unwrap(), &b(&r["transferDigest"]).try_into().unwrap(), &b(&r["auth"]["signature"])), "{n}");
        if r["serviceAccepts"].as_bool().unwrap() {
            let mut i = args(r);
            i["auth"] = r["auth"].clone();
            let s = build(&i).unwrap();
            assert_eq!(s["calldata"], r["calldata"], "{n}");
            assert_eq!(s["job"], r["job"], "{n}");
        }
    }
    assert!(rows.iter().any(|r| r["typedData"]["types"]["Note"].is_array()), "the Note row: a string and a bytes field");
}

/// The unbound `feeRecipient` row: the token's canonical form zeroes it; a client that forgets `canon` gets another digest.
#[test]
fn unbound_fee_recipient_is_canonical() {
    let r = rows().into_iter().find(|x| x["name"] == "deposit_unbound_fee_recipient").unwrap();
    assert_ne!(r["t"]["feeRecipient"], json!(format!("0x{}", "00".repeat(20))));
    let token: [u8; 20] = b(&r["token"]["address"]).try_into().unwrap();
    let uid: [u8; 32] = b(&r["token"]["salt"]).try_into().unwrap();
    let td = scaas_typed_data("UAMetaTransfer", Some("SCaaS MetaToken"), &token, 7622, &uid, &r["t"]).unwrap();
    assert_eq!(format!("0x{}", hex::encode(td.digest().unwrap())), r["transferDigest"].as_str().unwrap());
    let mut raw = td.to_value();
    raw["message"]["feeRecipient"] = r["t"]["feeRecipient"].clone();
    let forgot = TypedData::from_json(raw.to_string().as_bytes()).unwrap();
    assert_eq!(format!("0x{}", hex::encode(forgot.digest().unwrap())), r["transferDigestUncanon"].as_str().unwrap());
    assert_ne!(r["transferDigestUncanon"], r["transferDigest"]);
    assert_eq!(build(&args(&r)).unwrap()["digest"], r["transferDigest"], "the builder never copies a fee recipient");
}

/// §2.4 (b): F = T on the pull's lane at `nonce + 1`, open mode, the router's `relay` calldata.
#[test]
fn relay_fee_wrap() {
    let rows = rows();
    let with_fee: Vec<&Value> = rows.iter().filter(|r| r["relayFee"].is_object()).collect();
    assert_eq!(with_fee.len(), 2);
    for r in with_fee {
        let (n, f) = (r["name"].as_str().unwrap(), &r["relayFee"]);
        let mut i = args(r);
        i["auth"] = r["auth"].clone();
        i["relayFee"] = fee_of(r, r["t"]["nonce"].as_str().unwrap().parse::<u64>().unwrap() + 1);
        let got = build(&i).unwrap();
        let w = &got["relayFee"];
        assert_eq!((&w["relayRef"], &w["callDataHash"], &w["digest"]), (&f["relayRef"], &f["callDataHash"], &f["digest"]), "{n}");
        assert_eq!(w["relayCalldata"], f["relayCalldata"], "{n}");
        assert_eq!(w["typedData"]["message"]["payee"], f["payee"], "{n}: open mode");
        // the fee at the pull's own nonce: the pull spends it first (N19)
        i["relayFee"] = fee_of(r, r["t"]["nonce"].as_str().unwrap().parse().unwrap());
        assert!(build(&i).is_err(), "{n}: the pull's own nonce");
        let mut router = fee_of(r, 1);
        router["router"] = r["service"]["address"].clone();
        i["relayFee"] = router;
        assert!(build(&i).is_err(), "{n}: the router is the target");
        let mut zero = fee_of(r, 1);
        zero["value"] = json!("0");
        i["relayFee"] = zero;
        assert!(build(&i).is_err(), "{n}: a zero fee");
        let mut no_auth = args(r);
        no_auth["relayFee"] = fee_of(r, 1);
        assert!(build(&no_auth).is_err(), "{n}: a fee before the pull is signed");
    }
}

#[test]
fn refusals() {
    let rows = rows();
    let r = &rows[0];
    let ok = args(r);
    assert_eq!(build(&ok).unwrap()["entryRef"], r["entryRef"], "positive control");
    let refused = |i: Value, why: &str| assert!(build(&i).is_err(), "{why}");
    let with = |k: &str, v: Value| {
        let mut i = ok.clone();
        i[k] = v;
        i
    };
    refused(with("from", json!(format!("0x{}", "11".repeat(32)))), "another payer");
    refused(with("chainId", json!(1)), "another chain");
    refused(with("amount", json!("0")), "a zero amount");
    refused(with("entry", json!("deposit(x)")), "not a function name");
    refused(with("extra", json!(1)), "an unknown input field");
    let td = &r["typedData"];
    let p = td["primaryType"].as_str().unwrap();
    let field = |f: Value, v: Value| {
        let mut t = td.clone();
        t["types"][p].as_array_mut().unwrap().push(f.clone());
        t["message"][f["name"].as_str().unwrap()] = v;
        with("op", t)
    };
    refused(field(json!({"name": "xs", "type": "uint256[]"}), json!([])), "an array field");
    refused(field(json!({"name": "n", "type": "int256"}), json!("1")), "an int field");
    let mut nested = field(json!({"name": "inner", "type": "Inner"}), json!({"a": "1"}));
    nested["op"]["types"]["Inner"] = json!([{"name": "a", "type": "uint256"}]);
    refused(nested, "a nested struct");
    let mut big = td.clone();
    for k in 0..13 {
        big["types"][p].as_array_mut().unwrap().push(json!({"name": format!("f{k}"), "type": "uint8"}));
        big["message"][format!("f{k}")] = json!("0");
    }
    assert_eq!(big["types"][p].as_array().unwrap().len(), 17);
    refused(with("op", big.clone()), "more than 16 fields");
    big["types"][p].as_array_mut().unwrap().pop();
    big["message"].as_object_mut().unwrap().remove("f12");
    assert!(build(&with("op", big)).is_ok(), "16 fields: built");
    let mut missing = td.clone();
    missing["message"].as_object_mut().unwrap().remove("salt");
    refused(with("op", missing), "a missing field");
    let mut swapped = td.clone();
    swapped["types"][p].as_array_mut().unwrap().reverse();
    refused(with("op", swapped), "the first field not bytes32 payer");
    let mut other_chain = td.clone();
    other_chain["domain"]["chainId"] = json!(1);
    refused(with("op", other_chain), "the operation's domain on another chain");
    let mut no_service = td.clone();
    no_service["domain"].as_object_mut().unwrap().remove("verifyingContract");
    no_service["types"]["EIP712Domain"].as_array_mut().unwrap().pop();
    refused(with("op", no_service), "no service");
    let mut bad_auth = ok.clone();
    bad_auth["auth"] = json!("0x01");
    refused(bad_auth, "an auth that is no UASig");
}
