// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CLI-UAL-66: tests/fndsa/rows.rs (every FN-DSA row, `pq::verify_raw`) and tests/fndsa/sign.rs (the wallet's Falcon keys and
//! fixed-randomness signatures, their digest against PQClean's) in wasm32, where ua-rs runs falcon-rs. The vector files are
//! compiled in. `run` returns `ok …` or `FAIL …`; run.cjs prints it and exits non-zero on `FAIL`. UNAUDITED.
#[path = "../rows.rs"]
mod rows;
#[path = "../sign.rs"]
mod sign;

use scaas_ua::pq;
use serde_json::Value;
use wasm_bindgen::prelude::wasm_bindgen;

fn load(name: &str) -> Value {
    macro_rules! file {
        ($f:literal) => {
            include_str!(concat!("../../../../../smartcontracts/vectors/ua/", $f))
        };
    }
    let text = match name {
        "pq_kat.json" => file!("pq_kat.json"),
        "pq_external.json" => file!("pq_external.json"),
        "pq_signatures.json" => file!("pq_signatures.json"),
        "rs_signatures.json" => file!("rs_signatures.json"),
        "sign.json" => file!("sign.json"),
        "keys.json" => file!("keys.json"),
        other => panic!("{other}"),
    };
    serde_json::from_str(text).unwrap()
}

#[wasm_bindgen]
pub fn run() -> String {
    const { assert!(scaas_ua::build::FALCON) };
    let rows = rows::rows(load);
    let (mut acc, mut rej, mut differs) = (0, 0, 0);
    for r in &rows {
        if r.valid {
            acc += 1
        } else {
            rej += 1
        }
        differs += (pq::verify_raw(r.kind, &r.pk, &r.m, &r.sig) != r.valid) as usize;
    }
    let (n, digest) = sign::wallet_digest(load, |_, _, _, _, _, _, _| {});
    let ok = (acc, rej, differs) == (48, 172, 0) && n == sign::CASES && digest == sign::DIGEST;
    format!(
        "{} {} rows: {acc} accept, {rej} refuse, {differs} differ; {n} wallet cases, digest {digest}",
        if ok { "ok" } else { "FAIL" },
        rows.len()
    )
}
