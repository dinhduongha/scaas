//! scaas-ua's metatx-split hashes (T18) against smartcontracts/vectors/metatx/ (written by forge: PayMeta.t.sol,
//! MtxRelayFee.t.sol): CTR-MTX-26 `meta_pay_id` / `pay_lane`, CTR-MTX-27 `relay_ref` (EVM).
use scaas_ua::{meta_pay_id, pay_lane, relay_ref};
use serde_json::Value;

fn load(name: &str) -> Vec<Value> {
    let path = format!("{}/../../smartcontracts/vectors/metatx/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap().as_array().unwrap().clone()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}

#[test]
fn meta_pay_id_vectors() {
    let rows = load("paymeta.json");
    assert_eq!(rows.len(), 6);
    for r in &rows {
        let id = meta_pay_id(&b32(&r["salt"]), &bytes(&r["meta"]));
        assert_eq!(id, b32(&r["payId"]), "{}", r["name"]);
        assert_eq!(pay_lane(&id), b32(&r["payLane"]), "{}", r["name"]);
    }
}

#[test]
fn relay_ref_matches_vector() {
    let rows = load("relayref.json");
    assert_eq!(rows.len(), 3);
    for r in &rows {
        let target: [u8; 20] = bytes(&r["target"]).try_into().unwrap();
        let rf = relay_ref(r["chainId"].as_u64().unwrap(), &target, &bytes(&r["callData"]));
        assert_eq!(rf, b32(&r["ref"]), "{}", r["name"]);
        assert_eq!(pay_lane(&rf), b32(&r["payLane"]), "{}", r["name"]);
    }
}
