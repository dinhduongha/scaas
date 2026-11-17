// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T2c: every row of smartcontracts/vectors/keystore/keystore.json (clientkeys' rows): the valid containers parse and
//! re-serialise to their bytes, every refused file gives its named error.

use scaas_sdk::vault::Keystore;
use serde_json::Value;

fn rows() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/keystore/keystore.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

#[test]
fn valid_rows_round_trip() {
    let v = rows();
    let valid = v["valid"].as_array().unwrap();
    assert!(valid.len() >= 5);
    for r in valid {
        let text = r["text"].as_str().unwrap();
        let ks = Keystore::parse(text.as_bytes())
            .unwrap_or_else(|e| panic!("{}: {}", r["id"], e.code()));
        assert_eq!(ks.serialize().unwrap(), text, "{}", r["id"]);
        for s in &ks.seeds {
            for t in s.vaults.values() {
                assert!(
                    text.contains(&Value::from(t.as_str()).to_string()),
                    "vault text kept"
                );
            }
        }
    }
}

#[test]
fn refused_rows_by_name() {
    let v = rows();
    let refused = v["refused"].as_array().unwrap();
    assert!(refused.len() >= 19);
    for r in refused {
        let got = Keystore::parse(r["text"].as_str().unwrap().as_bytes())
            .err()
            .map(|e| e.code());
        assert_eq!(got, Some(r["error"].as_str().unwrap()), "{}", r["id"]);
    }
}
