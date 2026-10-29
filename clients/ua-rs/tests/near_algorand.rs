//! near-algorand T18: scaas-ua's NEAR and Algorand hashes against smartcontracts/{near,algorand}/vectors/ (every row).
use scaas_ua::{algorand, near, pay_lane, UAError};
use serde_json::Value;

fn load(p: &str) -> Value {
    let path = format!("{}/../../smartcontracts/{p}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

#[test]
fn near_vectors() {
    let d = load("near/vectors/near-vectors.json");
    let rows = d["metaops"]["vectors"].as_array().unwrap();
    assert_eq!(rows.len(), 37);
    for r in rows {
        assert_eq!(near::metaop_digest(&bytes(&r["encoding"])), b32(&r["digest"]), "{}", r["name"]);
    }
    let net = b32(&d["network"]);
    assert_eq!(d["relayRefs"].as_array().unwrap().len(), 6);
    for r in d["relayRefs"].as_array().unwrap() {
        let rf = near::relay_ref(&net, &bytes(&r["targetBytes"]), &bytes(&r["call"]), &b32(&r["salt"]));
        assert_eq!(rf, b32(&r["ref"]), "{}", r["name"]);
        assert_eq!(pay_lane(&rf), b32(&r["lane"]), "{}", r["name"]);
    }
    for r in d["nativeIds"]["rows"].as_array().unwrap() {
        assert_eq!(near::native_id(r["accountId"].as_str().unwrap()).unwrap(), b32(&r["id"]), "{}", r["accountId"]);
    }
    for r in d["nativeIds"]["invalid"].as_array().unwrap() {
        assert_eq!(near::native_id(r["accountId"].as_str().unwrap()), Err(UAError::IdFormat), "{}", r["accountId"]);
    }
}

#[test]
fn algorand_vectors() {
    let d = load("algorand/vectors/algorand-vectors.json");
    let rows = d["metaops"]["vectors"].as_array().unwrap();
    assert_eq!(rows.len(), 33);
    for r in rows {
        assert_eq!(algorand::metaop_digest(&bytes(&r["encoding"])), b32(&r["digest"]), "{}", r["name"]);
    }
    let net = b32(&d["network"]);
    for r in d["relayRefs"].as_array().unwrap() {
        let rf = algorand::relay_ref(&net, &b32(&r["target"]), &bytes(&r["call"]), &b32(&r["salt"]));
        assert_eq!(rf, b32(&r["ref"]), "{}", r["name"]);
        assert_eq!(pay_lane(&rf), b32(&r["lane"]), "{}", r["name"]);
    }
    for r in d["nativeIds"]["rows"].as_array().unwrap() {
        assert_eq!(algorand::address_to_key(r["address"].as_str().unwrap()).unwrap(), b32(&r["key"]), "{}", r["name"]);
    }
    let a = d["keys"]["alice"]["address"].as_str().unwrap();
    let bad = format!("{}A", &a[..57]);
    assert_eq!(algorand::address_to_key(&bad), Err(UAError::IdFormat));
    assert_eq!(algorand::address_to_key("abc"), Err(UAError::IdFormat));
    assert_eq!(algorand::address_to_key(&a.to_lowercase()), Err(UAError::IdFormat));
}
