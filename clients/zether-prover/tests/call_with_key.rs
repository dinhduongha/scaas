// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `api::call_with_key` (ua-rs-sign T14, spec §10.1): a custodian (ua-rs's Zether facade) hands the key itself, never a `key`
//! object; the request then takes no `key`, `revealSecret` or `includeWitness`. The same request gives the same bytes as the
//! JSON-key path at the same randomness, and `openDisclosure` gives the receiver's and the auditor's openings
//! (CTR-ZTH-43) that verify. No transcript is touched. UNAUDITED.
#![cfg_attr(not(feature = "hazmat"), allow(dead_code, unused_imports))]
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use zether_prover::api::call_with_key;
#[cfg(feature = "hazmat")]
use zether_prover::api::prove_transfer_json;
use zether_prover::bulletproofs::Gens;
use zether_prover::curve::{decode_point, Bls12381};
use zether_prover::keys::{seed_from_mnemonic, ZetherKey};
use zether_prover::schnorr::{verify_opening, Entry, OpeningKind};

fn vector(name: &str) -> Value {
    let p = format!("{}/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn key(account: u32) -> ZetherKey<Bls12381> {
    let seed = seed_from_mnemonic(zether_prover::vectors::MNEMONIC, "").unwrap();
    ZetherKey::conf(&seed[..], 60, account).unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(&v.as_str().unwrap()[2..]).unwrap()
}

/// The transfer vector's request without its key and witness flag.
fn request() -> Value {
    let mut r = vector("transfer_bls12381.json")["request"].clone();
    let o = r.as_object_mut().unwrap();
    o.remove("key");
    o.remove("includeWitness");
    r
}

#[cfg(feature = "hazmat")] // ARCH-POS-13: the raw commands (api::HAZMAT) exist only under `hazmat`
#[test]
fn a_given_key_proves_the_same_bytes_as_the_json_key() {
    let gens = Gens::<Bls12381>::new();
    let with_json = prove_transfer_json::<Bls12381, _>(&gens, &vector("transfer_bls12381.json")["request"], &mut ChaCha20Rng::seed_from_u64(9)).unwrap();
    let given = call_with_key("proveTransfer", &request(), &key(0), &mut ChaCha20Rng::seed_from_u64(9)).unwrap();
    for f in ["statement", "proof", "payload", "entryRef", "salt", "record", "directCalldata"] {
        assert_eq!(given[f], with_json[f], "{f}");
    }
    assert!(given.get("witness").is_none());
}

/// ARCH-POS-13 (ua-rs-sign T15c): without feature `hazmat` every command of `api::HAZMAT` is refused by `call` and
/// `call_with_key`, naming the rule; with it they run (a well-formed `proveTransfer` proves). The other commands run in both.
#[test]
fn release_has_no_raw_decrypt() {
    use zether_prover::api::{call, HAZMAT};
    assert_eq!(HAZMAT, ["decrypt", "decryptPending", "checkBalance", "proveTransfer", "proveTransferMulti", "proveBurn", "openMemo",
        "recoverTransfer", "openDisclosure"]);
    let (k, mut rng) = (key(0), ChaCha20Rng::seed_from_u64(3));
    for cmd in HAZMAT {
        let r = json!({"curve": "bls12381"});
        let (a, b) = (call(cmd, &r.to_string()).unwrap_err(), call_with_key(cmd, &r, &k, &mut rng).unwrap_err());
        for e in [a, b] {
            assert_eq!(e.contains("ARCH-POS-13"), !cfg!(feature = "hazmat"), "{cmd}: {e}");
        }
    }
    assert_eq!(call_with_key("proveTransfer", &request(), &k, &mut rng).is_ok(), cfg!(feature = "hazmat"), "a well-formed proveTransfer");
    assert!(call_with_key("pop", &json!({"curve": "bls12381"}), &k, &mut rng).is_ok(), "positive control");
    assert!(call("encrypt", &json!({"curve": "bls12381", "Y": format!("0x{}", hex::encode(k.encoded_y())), "amount": 1}).to_string()).is_ok());
}

/// `hazmat` is never a default feature, not even through another feature (Codex C7, T15c2): the closure of `default` over
/// the package's feature table as `cargo metadata` parses it, since `cfg!(feature = "hazmat")` in this test would follow a
/// default that turned it on.
#[test]
fn hazmat_is_off_by_default() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--no-deps", "--format-version", "1", "--offline", "--manifest-path", manifest])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let m: Value = serde_json::from_slice(&out.stdout).unwrap();
    let pkg = m["packages"].as_array().unwrap().iter().find(|p| p["name"] == "zether-prover").unwrap();
    let table = pkg["features"].as_object().unwrap();
    assert!(table.contains_key("hazmat"), "the feature exists");
    let (mut seen, mut todo) = (std::collections::BTreeSet::new(), vec!["default".to_string()]);
    while let Some(f) = todo.pop() {
        if seen.insert(f.clone()) {
            // this package's own features ("dep:x" and "x/y" name other crates)
            let next = table.get(&f).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str);
            todo.extend(next.filter(|d| !d.contains(':') && !d.contains('/')).map(String::from));
        }
    }
    assert!(!seen.contains("hazmat"), "hazmat reached from default: {seen:?}");
}

/// Codex C3 (T15c2): the helpers that decrypt or open a caller's ciphertext, entry or memo outside the dispatcher are
/// `pub` only under `hazmat` (the `hazmat_pub!` macro of lib.rs; a source assertion beside the `compile_fail` tests on
/// `api::HAZMAT`).
#[test]
fn hazmat_helpers_are_not_pub() {
    let src = |f: &str| std::fs::read_to_string(format!("{}/src/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    for (file, names) in [
        ("api.rs", &["prove_transfer_json", "prove_transfer_multi_json", "prove_burn_json", "open_memo_json", "recover_transfer_json"][..]),
        ("elgamal.rs", &["decrypt_point", "check_balance", "decrypt_pending", "decrypt"]),
        ("schnorr.rs", &["open_sender", "open_chaum_pedersen", "open_sender_cp"]),
    ] {
        let s = src(file);
        let lines: Vec<&str> = s.lines().map(str::trim).collect();
        for name in names {
            let at: Vec<usize> = (0..lines.len()).filter(|&i| lines[i].starts_with(&format!("fn {name}<")) || lines[i].starts_with(&format!("fn {name}("))).collect();
            assert_eq!(at.len(), 1, "{file}: fn {name}");
            assert!(!s.contains(&format!("pub fn {name}<")) && !s.contains(&format!("pub fn {name}(")), "{file}: pub fn {name}");
            let open = (0..at[0]).rev().find(|&i| !lines[i].starts_with("///")).unwrap();
            assert_eq!(lines[open], "hazmat_pub! {", "{file}: {name} outside hazmat_pub!");
        }
    }
    let lib = src("lib.rs");
    let mac = &lib[lib.find("macro_rules! hazmat_pub").unwrap()..];
    let mac = &mac[..mac.find("\n}\n").unwrap()];
    assert!(mac.contains("#[cfg(not(feature = \"hazmat\"))]") && mac.contains("pub(crate) fn"), "the macro's release arm");
}

#[test]
fn a_given_key_refuses_key_reveal_and_witness_fields() {
    let k = key(0);
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    assert!(call_with_key("pop", &json!({"curve": "bls12381"}), &k, &mut rng).is_ok(), "positive control");
    for (f, x) in [("key", json!({"x": "0x01"})), ("revealSecret", json!(true)), ("includeWitness", json!(true))] {
        let mut r = json!({"curve": "bls12381"});
        r[f] = x.clone();
        assert!(call_with_key("pop", &r, &k, &mut rng).is_err(), "pop with {f}");
        let mut t = request();
        t[f] = x;
        assert!(call_with_key("proveTransfer", &t, &k, &mut rng).is_err(), "proveTransfer with {f}");
    }
}

fn entry(c: &Value) -> Entry<Bls12381> {
    let p = |f: &str| decode_point::<Bls12381>(&h(&c[f])).unwrap();
    Entry {
        chain_id: c["chainId"].as_u64().unwrap(),
        chain_uid: h(&c["chainUid"]).try_into().unwrap(),
        token: h(&c["token"]).try_into().unwrap(),
        entry_ref: h(&c["entryRef"]).try_into().unwrap(),
        index: c["index"].as_u64().unwrap(),
        y_t: p("Yt"),
        c_out: p("Cout"),
        d_out: p("Dout"),
        y_a: p("Ya"),
        c_aud: p("Caud"),
        d_aud: p("Daud"),
    }
}

#[cfg(feature = "hazmat")] // ARCH-POS-13: the raw commands (api::HAZMAT) exist only under `hazmat`
#[test]
fn open_disclosure_gives_the_receiver_and_auditor_openings() {
    let aud = ZetherKey::<Bls12381>::conf(&seed_from_mnemonic(zether_prover::vectors::MNEMONIC, "auditor").unwrap()[..], 60, 0).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let cases = vector("disclosure_bls12381.json")["cases"].as_array().unwrap().clone();
    let mut n = 0;
    for c in &cases {
        let (kind, name, k) = match c["kind"].as_u64().unwrap() {
            1 => (OpeningKind::ReceiverX, "receiver", key(1)),
            2 => (OpeningKind::Auditor, "auditor", aud.clone()),
            _ => continue,
        };
        let mut req = c.clone();
        let o = req.as_object_mut().unwrap();
        for f in ["opening", "expect"] {
            o.remove(f);
        }
        o.insert("kind".into(), json!(name));
        o.insert("curve".into(), json!("bls12381"));
        let out = call_with_key("openDisclosure", &req, &k, &mut rng).unwrap();
        assert_eq!(out["kind"], json!(kind as u8));
        verify_opening(&entry(c), c["amount"].as_u64().unwrap(), kind, &h(&out["opening"])).unwrap();
        // another key, or the sender's kinds, are refused
        assert!(call_with_key("openDisclosure", &req, &key(3), &mut rng).is_err(), "another key");
        let mut s = req.clone();
        s["kind"] = json!("sender");
        assert!(call_with_key("openDisclosure", &s, &k, &mut rng).is_err(), "sender kind");
        n += 1;
    }
    assert_eq!(n, 4, "two transfers, receiver and auditor each");
}
