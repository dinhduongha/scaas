//! Smoke test of the C oracle (feature `c-oracle`) and the Rust verifier, on the REGISTER rows of the frozen vectors
//! (smartcontracts/vectors/pqz/proof_pqzl.json, statements from the file each row names).
use pqzl::c_oracle::c_verify;
use pqzl::{Ctx, OP_REGISTER};
use serde_json::Value;
mod common;

fn json(file: &str) -> Value {
    let p = common::vectors_dir().expect("vectors").join(file);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).unwrap()
}

fn hex(s: &Value) -> Vec<u8> {
    let s = s.as_str().expect("hex string").as_bytes();
    s.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).expect("hex")).collect()
}

/// `(stmt, proof)` of every REGISTER row of proof_pqzl.json.
fn register_rows() -> Vec<(Vec<u8>, Vec<u8>)> {
    if common::vectors_dir().is_none() {
        eprintln!("set {}: core_only (set.json): no vectors, no self-test REGISTER rows", pqzl::SET);
        return Vec::new();
    }
    let rows: Vec<_> = json("proof_pqzl.json")["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["form"] == "REGISTER")
        .map(|r| {
            assert_eq!(r["op"], OP_REGISTER);
            let st = &r["statement"];
            let srow = json(st["file"].as_str().unwrap())["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["form"] == st["form"])
                .expect("statement row")
                .clone();
            (hex(&srow["stmt"]), hex(&r["proof"]))
        })
        .collect();
    assert!(!rows.is_empty(), "no REGISTER rows");
    rows
}

#[test]
fn c_core_selftest_proofs_verify() {
    for (stmt, proof) in register_rows() {
        assert!(c_verify(OP_REGISTER, &stmt, &proof), "C core rejects a REGISTER vector");
    }
}

/// the Rust verifier accepts them too (was the Task 1 stub's rejection)
#[test]
fn rust_verify_accepts() {
    for (stmt, proof) in register_rows() {
        assert!(Ctx::new().verify(OP_REGISTER, &stmt, &proof));
    }
}
