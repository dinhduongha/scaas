// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! typed-signing R2c: the feature `json` shim (src/json.rs) against smartcontracts/vectors/ua/portable.json: every
//! `registrations[i].args` / `kemCommit`, every `kemRecords[i].args` and `pqzKeyRecords[i].args` row, and the refusals.
use scaas_ua::json::{registration_args_json, set_kem_key_args_json, set_pqz_key_args_json, JsonError};
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
    assert_eq!(commits, 9);
}

#[test]
fn set_key_args_rows() {
    let p = portable();
    let kem = p["kemRecords"].as_array().unwrap();
    assert_eq!(kem.len(), 9);
    for k in kem {
        let i = json!({ "ua": k["ua"], "version": k["version"], "kemPk": k["kemPk"], "sig": record_sig(k) });
        assert_eq!(out(set_kem_key_args_json(&i.to_string())), k["args"], "{}", k["id"]);
    }
    let pqz = p["pqzKeyRecords"].as_array().unwrap();
    assert_eq!(pqz.len(), 8);
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
    let pop = format!("0x{}", "22".repeat(32));
    assert_eq!(bad_pqz(json!({ "ua": "0x", "pqzPopHash": pop })), JsonError::Argument);
    assert_eq!(bad_pqz(json!({ "ua": ua, "pqzPopHash": "0x01" })), JsonError::Ua(UAError::PqzPopHash));
    assert_eq!(bad_pqz(json!({ "ua": ua })), JsonError::Ua(UAError::PqzPopHash));
    // a signature in the wrong shape never becomes an empty UASig
    assert_eq!(bad_pqz(json!({ "ua": ua, "pqzPopHash": pop, "sig": "0x01" })), JsonError::Argument);
    assert_eq!(bad_pqz(json!({ "ua": ua, "pqzPopHash": pop, "sig": { "members": "0x" } })), JsonError::Argument);
    assert_eq!(bad_kem(json!({ "ua": ua, "version": 1, "sig": [] })), JsonError::Argument);
}
