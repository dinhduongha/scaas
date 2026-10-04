//! Committed vector files equal a fresh deterministic regeneration, and every proof in them
//! verifies through the JSON API (the same path the CLI and WASM use).

use serde_json::{json, Value};

#[test]
fn committed_vectors_are_current_and_verify() {
    let dir = format!("{}/vectors", env!("CARGO_MANIFEST_DIR"));
    for (name, v) in zether_prover::vectors::generate() {
        let on_disk: Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/{name}"))
                .unwrap_or_else(|_| panic!("{name} missing: run `cargo run --bin zether-cli vectors vectors`")),
        )
        .unwrap();
        assert_eq!(on_disk, v, "{name} drifted: run `cargo run --bin zether-cli vectors vectors`");
        let cmd = if name.starts_with("transfer_") {
            "verifyTransfer"
        } else if name.starts_with("burn_") {
            "verifyBurn"
        } else {
            continue;
        };
        let req = json!({"curve": v["curve"], "statement": v["statement"], "proof": v["proof"]});
        let out: Value = serde_json::from_str(&zether_prover::api::call(cmd, &req.to_string()).unwrap()).unwrap();
        assert_eq!(out["ok"], json!(true), "{name}: {out}");
        // A flipped bit in the proof is rejected.
        let mut p = v["proof"].as_str().unwrap().to_string();
        let i = p.len() - 1;
        p.replace_range(i.., if p.ends_with('0') { "1" } else { "0" });
        let req = json!({"curve": v["curve"], "statement": v["statement"], "proof": p});
        let out: Value = serde_json::from_str(&zether_prover::api::call(cmd, &req.to_string()).unwrap()).unwrap();
        assert_eq!(out["ok"], json!(false), "{name}");
    }
}

#[test]
fn api_roundtrip_mnemonic_keygen_prove_decrypt() {
    let mnemonic = zether_prover::vectors::MNEMONIC;
    let call = |cmd: &str, v: Value| -> Value {
        serde_json::from_str(&zether_prover::api::call(cmd, &v.to_string()).unwrap()).unwrap()
    };
    for curve in ["bn254", "bls12381"] {
        let k0 = json!({"mnemonic": mnemonic, "coin": 60, "account": 0});
        let k1 = json!({"mnemonic": mnemonic, "coin": 60, "account": 1});
        let a = call("keygen", json!({"curve": curve, "key": k0}));
        let b = call("keygen", json!({"curve": curve, "key": k1}));
        let acc = call("encrypt", json!({"curve": curve, "Y": a["Y"], "amount": 5000}));
        let t = call("proveTransfer", json!({
            "curve": curve, "key": k0, "chainId": 31337, "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "sendCounter": 0, "accSeq": 1, "acc": acc, "balance": 5000, "yTo": b["Y"], "amount": 1200,
        }));
        assert!(t.get("witness").is_none(), "secrets must not leave the API unless asked");
        assert!(t["directCalldata"].as_str().unwrap().starts_with("0x7c947e8e"), "RS2-14 direct selector");
        let ok = call("verifyTransfer", json!({"curve": curve, "statement": t["statement"], "proof": t["proof"]}));
        assert_eq!(ok["ok"], json!(true));
        let d = call("decrypt", json!({"curve": curve, "key": k0, "ct": acc}));
        assert_eq!(d["amount"], json!(5000));
        let pop = call("pop", json!({"curve": curve, "key": k0, "registry": "0x".to_string() + &"aa".repeat(20),
                                      "account": "0x".to_string() + &"bb".repeat(20)}));
        assert_eq!(pop["UA"], a["UA"]);
    }
    assert!(zether_prover::api::call("keygen", r#"{"curve":"secp256k1","key":{"x":"0x01"}}"#).is_err());
    // 2^32 + 60 must not silently alias coin 60.
    let wide = json!({"curve": "bn254", "key": {"mnemonic": mnemonic, "coin": 4294967356u64, "account": 0}});
    assert!(zether_prover::api::call("keygen", &wide.to_string()).is_err());
    let bad_y = json!({"curve": "bn254", "Y": "0x".to_string() + &"11".repeat(64), "amount": 1});
    assert!(zether_prover::api::call("fundCalldata", &bad_y.to_string()).is_err());
}
