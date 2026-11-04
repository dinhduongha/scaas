// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! typed-signing R2c: the feature `json` shim (src/json.rs) against smartcontracts/vectors/ua/portable.json: every
//! `registrations[i].args` / `kemCommit`, every `kemRecords[i].args` and `pqzKeyRecords[i].args` row, and the refusals.
use scaas_ua::json::{inner_json, registration_args_json, replayed_member_sig_json, set_kem_key_args_json, set_pqz_key_args_json, JsonError};
use scaas_ua::UAError;
use serde_json::{json, Value};

fn portable() -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/portable.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn out(r: Result<String, JsonError>) -> Value {
    serde_json::from_str(&r.unwrap()).unwrap()
}
fn reg_input(r: &Value, commit: Option<bool>) -> String {
    let a = &r["attrs"];
    let mut i = json!({ "kind": r["kind"], "keyData": r["keyData"], "pqzKey": a["pqzKey"], "pqzPopHash": a["pqzPopHash"],
        "pqzPop": r["pqzPop"], "kemPk": a["kemPk"], "pop": r["args"]["pop"] });
    if let Some(c) = commit {
        i["kemCommit"] = json!(c);
    }
    i.to_string()
}
/// A record row's `UASig`: its `sig`, an msig's as the typed member list; absent fields are empty.
fn record_sig(r: &Value) -> Value {
    if r["kind"] == 0x0120 { json!({ "members": r["args"]["sig"]["members"] }) } else { json!({ "signature": r["sig"] }) }
}

/// Nested `msig`: the JSON shim with `inner`, every row of nested.json; without it a nested record's holder check stops at `MemberUnknown`.
#[test]
fn registration_args_nested_rows() {
    let path = format!("{}/../../smartcontracts/vectors/ua/nested.json", env!("CARGO_MANIFEST_DIR"));
    let n: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let rows = n["registrations"].as_array().unwrap();
    let inner: serde_json::Map<String, Value> = rows.iter().filter(|r| r["kind"] == 0x0120).map(|r| (r["ua"].as_str().unwrap().to_string(), r["keyData"].clone())).collect();
    for r in rows.iter().filter(|r| r["kind"] == 0x0120) {
        let mut i: Value = serde_json::from_str(&reg_input(r, Some(false))).unwrap();
        i["inner"] = Value::Object(inner.clone());
        let got = out(registration_args_json(&i.to_string()));
        assert_eq!(got["args"], r["args"], "{}", r["name"]);
    }
}

/// The wrappers' `inner` and replay shims: `inner` is bounded in text, entries and key data; every `memberships` row's `stored` turns back
/// into its slot JSON.
#[test]
fn inner_json_bounded_and_replay_rows() {
    let path = format!("{}/../../smartcontracts/vectors/ua/nested.json", env!("CARGO_MANIFEST_DIR"));
    let n: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let regs = n["registrations"].as_array().unwrap();
    let e = &n["eligibility"][0];
    let (id, d) = e["inner"].as_object().unwrap().iter().next().unwrap();
    let id_b: [u8; 32] = hex::decode(&id[2..]).unwrap().try_into().unwrap();
    assert_eq!(inner_json(&e["inner"].to_string()), Ok(vec![(id_b, hex::decode(&d.as_str().unwrap()[2..]).unwrap())]));
    assert_eq!((inner_json(""), inner_json("null")), (Ok(vec![]), Ok(vec![])));
    let ids = |k: usize| (0..k).map(|i| (format!("0x{i:064x}"), json!("0x00"))).collect::<serde_json::Map<_, _>>();
    assert_eq!(inner_json(&Value::Object(ids(16)).to_string()).map(|v| v.len()), Ok(16));
    assert_eq!(inner_json(&Value::Object(ids(17)).to_string()), Err(JsonError::Argument), "17 entries");
    for (data, ok) in [(580, true), (581, false)] {
        let t = json!({ id: format!("0x{}", "00".repeat(data)) }).to_string();
        assert_eq!(inner_json(&t).is_ok(), ok, "{data} bytes of key data");
    }
    let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
    assert_eq!(inner_json(&deep[..65_536]), Err(JsonError::Argument), "deep");
    assert_eq!(inner_json(&format!("{{\"{id}\": {}}}", " ".repeat(65_536))), Err(JsonError::Argument), "over the text bound");
    for x in ["[]", "{\"0x01\": \"0x\"}", "{\"x\": 1}"] {
        assert_eq!(inner_json(x), Err(JsonError::Argument), "{x}");
    }
    let ms = n["memberships"].as_array().unwrap();
    assert_eq!(ms.len(), 4);
    for m in ms {
        let d = hex::decode(&regs.iter().find(|r| r["ua"] == m["ua"]).unwrap()["keyData"].as_str().unwrap()[2..]).unwrap();
        let index = m["index"].as_u64().unwrap() as u16;
        let stored = hex::decode(&m["stored"].as_str().unwrap()[2..]).unwrap();
        let got = out(replayed_member_sig_json(&d, index, &stored));
        assert_eq!(got, json!({ "index": index, "members": m["members"], "sig": m["sig"] }), "{}", m["name"]);
        assert_eq!(replayed_member_sig_json(&d, 16, &stored), Err(JsonError::Ua(UAError::Unauthorized)), "past the members");
    }
}

#[test]
fn registration_args_rows() {
    let p = portable();
    let mut commits = 0;
    for r in p["registrations"].as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let a = out(registration_args_json(&reg_input(r, Some(false))));
        assert_eq!(a["args"], r["args"], "{name}");
        assert!(a["kemFill"].is_null() && a["kemFillCalldataLength"].is_null(), "{name}");
        assert_eq!(out(registration_args_json(&reg_input(r, None)))["args"], r["args"], "{name}: under the limit");
        if r.get("kemCommit").is_some() {
            let c = out(registration_args_json(&reg_input(r, Some(true))));
            assert_eq!(c["args"], r["kemCommit"]["register"], "{name}");
            assert_eq!(c["kemFill"], r["kemCommit"]["fill"], "{name}");
            assert_eq!(c["kemFillCalldataLength"], 2020, "{name}");
            commits += 1;
        }
    }
    assert_eq!(commits, 11); // + mldsa87, fndsa1024
}

#[test]
fn set_key_args_rows() {
    let p = portable();
    let kem = p["kemRecords"].as_array().unwrap();
    assert_eq!(kem.len(), 15);
    for k in kem {
        let i = json!({ "ua": k["ua"], "version": k["version"], "kemPk": k["kemPk"], "sig": record_sig(k) });
        assert_eq!(out(set_kem_key_args_json(&i.to_string())), k["args"], "{}", k["id"]);
    }
    let pqz = p["pqzKeyRecords"].as_array().unwrap();
    assert_eq!(pqz.len(), 16);
    for r in pqz {
        let i = json!({ "ua": r["ua"], "pqzKey": r["pqzKey"], "pqzPopHash": r["pqzPopHash"], "sig": record_sig(r) });
        assert_eq!(out(set_pqz_key_args_json(&i.to_string())), r["args"], "{}", r["name"]);
    }
    // no `sig`: the version-0 fill of a hash commit
    for r in p["registrations"].as_array().unwrap().iter().filter(|r| r.get("kemCommit").is_some()) {
        let i = json!({ "ua": r["ua"], "version": 0, "kemPk": r["attrs"]["kemPk"] });
        assert_eq!(out(set_kem_key_args_json(&i.to_string())), r["kemCommit"]["fill"], "{}", r["name"]);
    }
}

#[test]
fn refusals() {
    let ua = format!("0x{}", "11".repeat(32));
    let bad_kem = |i: Value| set_kem_key_args_json(&i.to_string()).unwrap_err();
    let bad_pqz = |i: Value| set_pqz_key_args_json(&i.to_string()).unwrap_err();
    assert_eq!(set_kem_key_args_json("not json").unwrap_err(), JsonError::Argument);
    assert_eq!(set_pqz_key_args_json("not json").unwrap_err(), JsonError::Argument);
    assert_eq!(bad_kem(json!({ "ua": "0x11", "version": 1 })), JsonError::Argument);
    assert_eq!(bad_kem(json!({ "ua": ua })), JsonError::Argument, "version is required");
    assert_eq!(bad_kem(json!({ "ua": ua, "version": "1" })), JsonError::Argument);
    assert_eq!(bad_kem(json!({ "ua": ua, "version": 1, "kemPk": "0x0101" })), JsonError::Ua(UAError::KemKeyLength));
    assert_eq!(bad_kem(json!({ "ua": ua, "version": 1 })), JsonError::Ua(UAError::KemKeyLength), "no key is no setKemKey");
    assert_eq!(bad_kem(json!({ "ua": ua, "version": 0 })), JsonError::Ua(UAError::KemKeyLength), "nor a fill");
    let short = format!("0x01{}", "5a".repeat(39));
    assert_eq!(bad_kem(json!({ "ua": ua, "version": 1, "kemPk": short })), JsonError::Ua(UAError::KemKeyLength));
    let pop = format!("0x{}", "22".repeat(32));
    assert_eq!(bad_pqz(json!({ "ua": "0x", "pqzPopHash": pop })), JsonError::Argument);
    assert_eq!(bad_pqz(json!({ "ua": ua, "pqzPopHash": "0x01" })), JsonError::Ua(UAError::PqzPopHash));
    assert_eq!(bad_pqz(json!({ "ua": ua })), JsonError::Ua(UAError::PqzPopHash));
    // a signature in the wrong shape never becomes an empty UASig
    assert_eq!(bad_pqz(json!({ "ua": ua, "pqzPopHash": pop, "sig": "0x01" })), JsonError::Argument);
    assert_eq!(bad_pqz(json!({ "ua": ua, "pqzPopHash": pop, "sig": { "members": "0x" } })), JsonError::Argument);
    assert_eq!(bad_kem(json!({ "ua": ua, "version": 1, "sig": [] })), JsonError::Argument);
}
