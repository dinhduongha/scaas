//! UA-2b T-FUZZ (accounts.md §1.16): ed25519-dalek `verify_strict` (scaas_ua::verify::ed25519) gives the verdict
//! smartcontracts/vectors/ua/ed25519_fuzz.json records (noble zip215:false + the strict R rules) on every case.
use scaas_ua::verify::ed25519;
use serde_json::Value;
use std::collections::BTreeMap;

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

#[test]
fn dalek_verify_strict_matches_every_case() {
    let path = format!("{}/../../smartcontracts/vectors/ua/ed25519_fuzz.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let cases = v["cases"].as_array().unwrap();
    assert!(cases.len() >= 2000);
    let mut per_class: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut bad = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let class = c["class"].as_str().unwrap();
        let want = c["valid"].as_bool().unwrap();
        let got = ed25519(&bytes(&c["pk"]), &bytes(&c["msg"]), &bytes(&c["sig"]));
        if got != want {
            bad.push(format!("case {i} {class}: dalek {got}, file {want}"));
        }
        let e = per_class.entry(class).or_default();
        e.0 += 1;
        e.1 += got as usize;
    }
    println!("{} cases, per class (cases, dalek-valid): {per_class:?}", cases.len());
    assert!(bad.is_empty(), "{} disagreements:\n{}", bad.len(), bad.join("\n"));
}
