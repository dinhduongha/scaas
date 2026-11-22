// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan 2026-11-17-scaas-sdk T24.sui: `families::sui::account_of` against every row of smartcontracts/vectors/families/sui.json
//! (written by clientkeys; the first row is the Move test's own `Account<SUI>`), the refused rows' lengths beside a control.
#![cfg(feature = "wallet")]
use scaas_ua::families::sui::account_of;
use serde_json::Value;

fn rows() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../smartcontracts/vectors/families/sui.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn k32(v: &Value) -> [u8; 32] {
    hexb(v).try_into().unwrap()
}

#[test]
fn account_rows() {
    let v = rows();
    let rows = v["account"].as_array().unwrap();
    assert!(rows.len() >= 4);
    for r in rows {
        assert_eq!(
            account_of(&k32(&r["registry"]), &k32(&r["owner"])),
            k32(&r["account"])
        );
    }
    // the Move test's pair (meta_tests.move: alice's Account<SUI>) is the first row
    assert_eq!(
        rows[0]["account"],
        "0xd4793a1919a40ebfe5587a3a49fe89bb64c54bd49c75ab2a08ac0d5636706382"
    );
}

/// The refused rows are inputs that are not 32 bytes: a type error here (`[u8; 32]`); control: the rows' good lengths.
#[test]
fn refused_rows_are_not_32_bytes() {
    for r in rows()["refused"].as_array().unwrap() {
        let (a, b) = (hexb(&r["registry"]), hexb(&r["owner"]));
        assert!(a.len() != 32 || b.len() != 32, "{}", r["why"]);
    }
    assert_eq!(hexb(&rows()["account"][0]["registry"]).len(), 32);
}
