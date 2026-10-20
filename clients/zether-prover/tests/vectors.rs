//! Committed vector files equal a fresh deterministic regeneration, and every proof in them
//! verifies through the JSON API (the same path the CLI and WASM use).

use serde_json::{json, Value};

#[cfg(not(feature = "bn254"))] // the legacy feature also generates the bn254 files, which now live in vectors/legacy/ua6/
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
        let cmd = if name.starts_with("transfer_multi_") {
            "verifyTransferMulti"
        } else if name.starts_with("transfer_") {
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
    for curve in ["bls12381"] {
        let k0 = json!({"mnemonic": mnemonic, "coin": 60, "account": 0});
        let k1 = json!({"mnemonic": mnemonic, "coin": 60, "account": 1});
        let a = call("keygen", json!({"curve": curve, "key": k0}));
        let b = call("keygen", json!({"curve": curve, "key": k1}));
        let acc = call("encrypt", json!({"curve": curve, "Y": a["Y"], "amount": 5000}));
        let req = json!({
            "curve": curve, "key": k0, "chainId": 31337, "chainUid": "0x".to_string() + &"24".repeat(32),
            "token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
            "sendCounter": 0, "accSeq": 1, "acc": acc, "balance": 5000, "yTo": b["Y"], "amount": 1200,
        });
        let t = call("proveTransfer", req.clone());
        // review T2 M3: `unwrapBinding` only on a burn, never with `envelopeBinding`; an unwrap-bound burn gets no
        // `zetherUnshield` calldata (the token would refuse it).
        let ub = json!("0x".to_string() + &"cd".repeat(32));
        let with = |mut r: Value, k: &str| { r[k] = ub.clone(); r };
        let err = |cmd: &str, r: Value| zether_prover::api::call(cmd, &r.to_string()).unwrap_err();
        assert!(err("proveTransfer", with(req.clone(), "unwrapBinding")).contains("proveBurn"));
        let mut burn = req.clone();
        burn["recipient"] = json!("0x".to_string() + &"ee".repeat(20));
        let ub_burn = with(burn.clone(), "unwrapBinding");
        assert!(call("proveBurn", ub_burn.clone()).get("directCalldata").is_none());
        assert!(call("proveBurn", burn).get("directCalldata").is_some());
        assert!(err("proveBurn", with(ub_burn, "envelopeBinding")).contains("exclusive"));
        assert!(t.get("witness").is_none(), "secrets must not leave the API unless asked");
        let single = hex::encode(zether_prover::envelope::selector("zetherTransferSingle(bytes,bytes,bytes32)"));
        assert!(t["directCalldata"].as_str().unwrap().starts_with(&format!("0x{single}")), "direct selector (CTR-ZTH-45)");
        let ok = call("verifyTransfer", json!({"curve": curve, "statement": t["statement"], "proof": t["proof"]}));
        assert_eq!(ok["ok"], json!(true));
        let d = call("decrypt", json!({"curve": curve, "key": k0, "ct": acc, "tableBits": 18, "boundBits": 20}));
        assert_eq!(d["amount"], json!("5000"), "amounts leave the API as decimal strings (> 2^53)");
        let p = call("decryptPending", json!({"curve": curve, "key": k0, "pending": acc, "tableBits": 18, "boundBits": 20}));
        assert_eq!(p["amount"], json!("5000"));
        assert_eq!(call("checkBalance", json!({"curve": curve, "key": k0, "acc": acc, "balance": 5000}))["ok"], json!(true));
        assert_eq!(call("checkBalance", json!({"curve": curve, "key": k1, "acc": acc, "balance": 5000}))["ok"], json!(false));
        let pop = call("pop", json!({"curve": curve, "key": k0, "registry": "0x".to_string() + &"aa".repeat(20),
                                      "chainId": 31337, "chainUid": "0x".to_string() + &"24".repeat(32)}));
        assert_eq!(pop["UA"], a["UA"]);
        assert_eq!(pop["popDigest"].as_str().unwrap().len(), 66);
        let own = call("ownerAuth", json!({"curve": curve, "key": k0, "digest": "0x".to_string() + &"77".repeat(32)}));
        assert!(own["auth"].as_str().unwrap().len() > 2 + 2 * 128);
        let sig = call("uaSig", json!({"curve": curve, "key": k0, "purpose": "metatx", "digest": "0x".to_string() + &"78".repeat(32)}));
        let digest: [u8; 32] = [0x78; 32];
        let m = zether_prover::schnorr::ua_message::<zether_prover::curve::Bls12381>(&zether_prover::schnorr::purpose_tag("metatx"), &digest);
        assert_eq!(sig["uaMsg"], json!(zether_prover::api::hx(&m)));
        let raw = hex::decode(&sig["sig"].as_str().unwrap()[2..]).unwrap();
        assert_eq!(raw.len(), 128 + 32, "R || z");
        let y = zether_prover::curve::decode_point::<zether_prover::curve::Bls12381>(&hex::decode(&a["Y"].as_str().unwrap()[2..]).unwrap()).unwrap();
        zether_prover::schnorr::verify::<zether_prover::curve::Bls12381>(&y, &m, &raw).unwrap();
        for bad in ["pop", "nope"] {
            let r = json!({"curve": curve, "key": k0, "purpose": bad, "digest": "0x".to_string() + &"78".repeat(32)});
            assert!(zether_prover::api::call("uaSig", &r.to_string()).is_err(), "{bad}");
        }
    }
    assert!(zether_prover::api::call("keygen", r#"{"curve":"secp256k1","key":{"x":"0x01"}}"#).is_err());
    // 2^32 + 60 must not silently alias coin 60.
    let wide = json!({"curve": "bls12381", "key": {"mnemonic": mnemonic, "coin": 4294967356u64, "account": 0}});
    assert!(zether_prover::api::call("keygen", &wide.to_string()).is_err());
    // review L1: a JSON Number above 2^53 − 1 may already be rounded by the JS caller — refuse it and
    // require a decimal string; at or below 2^53 − 1 a Number is exact and accepted.
    let y = call("keygen", json!({"curve": "bls12381", "key": {"mnemonic": mnemonic, "coin": 60, "account": 0}}))["Y"].clone();
    let enc = |amount: Value| zether_prover::api::call("encrypt", &json!({"curve": "bls12381", "Y": y, "amount": amount}).to_string());
    assert!(enc(json!(9007199254740993u64)).unwrap_err().contains("decimal string"));
    assert!(enc(json!(9007199254740991u64)).is_ok());
    assert!(enc(json!("9007199254740993")).is_ok());
    let bad_y = json!({"curve": "bls12381", "Y": "0x".to_string() + &"11".repeat(64), "amount": 1});
    assert!(zether_prover::api::call("shieldCalldata", &bad_y.to_string()).is_err());
}
