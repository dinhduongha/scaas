//! T0 spike unit tests (SDK testutils at protocol 30). Each prints the budget of the measured call; the gate figures
//! are the network ones (`run.sh` / `measure.py`), since native test code under-counts the Wasm VM.
extern crate std;
use std::{println, vec::Vec as StdVec};

use serde_json::Value;
use soroban_sdk::{Bytes, BytesN, Env};

use crate::{purpose, tagged, UaSpike, UaSpikeClient, K_MLDSA65, K_MSIG, K_WEBAUTHN};

const PORTABLE: &str = include_str!("../../../../vectors/ua/portable.json");
const SIGNATURES: &str = include_str!("../../../../vectors/ua/signatures.json");
const MSIG3: &str = include_str!("msig3.json"); // `measure.py fixture`: 3 generated ML-DSA-65 members

fn hx(s: &str) -> StdVec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn row(name: &str) -> Value {
    let p: Value = serde_json::from_str(PORTABLE).unwrap();
    p["registrations"].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap().clone()
}

fn setup() -> (Env, UaSpikeClient<'static>) {
    let env = Env::default();
    assert_eq!(env.ledger().protocol_version(), 30);
    let id = env.register(UaSpike, ());
    let c = UaSpikeClient::new(&env, &id);
    (env, c)
}

/// Runs `f` on a fresh unlimited budget and prints CPU / memory.
fn measure<T>(env: &Env, label: &str, f: impl FnOnce() -> T) -> T {
    env.cost_estimate().budget().reset_unlimited();
    let out = f();
    let b = env.cost_estimate().budget();
    println!("BUDGET {label}: cpu={} mem={}", b.cpu_instruction_cost(), b.memory_bytes_cost());
    out
}

fn b(env: &Env, v: &[u8]) -> Bytes {
    Bytes::from_slice(env, v)
}

fn mldsa_case(name: &str, kind: u32, tag: &str) {
    let (env, c) = setup();
    let r = row(name);
    let pk = hx(r["keyData"].as_str().unwrap());
    let sig = hx(r["pop"].as_str().unwrap());
    let msg = b(&env, &hx(r["popMessage"].as_str().unwrap()));
    measure(&env, &std::format!("verify_only {tag}"), || c.verify_only(&kind, &b(&env, &pk), &msg, &b(&env, &sig)));
    let mut bad = sig.clone();
    bad[10] ^= 1;
    assert!(c.try_verify_only(&kind, &b(&env, &pk), &msg, &b(&env, &bad)).is_err());
}

#[test]
fn spike_mldsa44_verify_budget() {
    mldsa_case("mldsa44", 0x0130, "mldsa44");
}

#[test]
fn spike_mldsa65_verify_budget() {
    mldsa_case("mldsa65#1", 0x0131, "mldsa65");
}

#[test]
fn spike_register_mldsa65_model_budget() {
    let (env, c) = setup();
    let r = row("mldsa65#1");
    let pk = BytesN::<1952>::from_array(&env, &hx(r["keyData"].as_str().unwrap()).try_into().unwrap());
    let sig = BytesN::<3309>::from_array(&env, &hx(r["pop"].as_str().unwrap()).try_into().unwrap());
    let msg = b(&env, &hx(r["popMessage"].as_str().unwrap()));
    let id = measure(&env, "register_model mldsa65", || c.register_model(&pk, &msg, &sig));
    assert_eq!(id.to_array().to_vec(), hx(r["ua"].as_str().unwrap()), "the CTR-UA-04 id of the vector");
    assert!(c.try_register_model(&pk, &msg, &sig).is_err(), "already registered");
}

#[test]
fn spike_msig3_mldsa65_model_budget() {
    let (env, c) = setup();
    let f: Value = serde_json::from_str(MSIG3).unwrap();
    let kd = b(&env, &hx(f["key_data"].as_str().unwrap()));
    let msg = BytesN::<32>::from_array(&env, &hx(f["msg"].as_str().unwrap()).try_into().unwrap());
    let pop = hx(f["pop"].as_str().unwrap());
    assert!(c.try_msig_model(&kd, &msg, &b(&env, &pop)).is_err(), "MemberUnknown before the members register");
    for m in f["members"].as_array().unwrap() {
        let pk = b(&env, &hx(m["pk"].as_str().unwrap()));
        c.seed(&K_MLDSA65, &pk, &Some(b(&env, &hx(m["pop"].as_str().unwrap()))));
    }
    let mut bad = pop.clone();
    bad[pop.len() - 100] ^= 1; // inside the last member's signature
    assert!(c.try_msig_model(&kd, &msg, &b(&env, &bad)).is_err(), "a member's bad signature");
    let with_keys = b(&env, &hx(f["pop_with_key_data"].as_str().unwrap()));
    assert!(c.try_msig_model(&kd, &msg, &with_keys).is_err(), "non-empty keyData of a registered member");
    let mut long = pop.clone();
    long.extend_from_slice(&[0; 32]);
    assert!(c.try_msig_model(&kd, &msg, &b(&env, &long)).is_err(), "non-canonical MemberSig[]");
    let id = measure(&env, "msig_model n=3 mldsa65", || c.msig_model(&kd, &msg, &b(&env, &pop)));
    assert_eq!(id, tagged(&env, K_MSIG, &kd));
    assert!(c.try_msig_model(&kd, &msg, &b(&env, &pop)).is_err(), "already registered");
}

#[test]
fn spike_require_authorized_passkey_budget() {
    let (env, c) = setup();
    let s: Value = serde_json::from_str(SIGNATURES).unwrap();
    let r = s["derived"].as_array().unwrap().iter().find(|r| r["kind"] == 256).unwrap();
    let kd = hx(r["keyData"].as_str().unwrap());
    let m = r["sigs"].as_array().unwrap().iter().find(|x| x["purpose"] == "metatx").unwrap();
    let auth = hx(m["sig"].as_str().unwrap()); // abi.encode(bytes authData, string clientDataJSON, uint256 r, uint256 s)
    let digest = BytesN::<32>::from_array(&env, &hx(m["digest"].as_str().unwrap()).try_into().unwrap());
    let ua = c.seed(&K_WEBAUTHN, &b(&env, &kd), &None);
    assert_eq!(ua.to_array().to_vec(), hx(r["ua"].as_str().unwrap()));
    let p = purpose(&env, "scaas.ua.purpose.metatx.v1");
    measure(&env, "require_authorized webauthn-p256", || c.require_authorized(&ua, &p, &digest, &b(&env, &auth)));
    let other = BytesN::from_array(&env, &[7; 32]);
    assert!(c.try_require_authorized(&ua, &p, &other, &b(&env, &auth)).is_err(), "challenge binds the digest");
    let mut bad = auth.clone();
    bad[100] ^= 1; // s
    assert!(c.try_require_authorized(&ua, &p, &digest, &b(&env, &bad)).is_err(), "secp256r1 refuses a bad s");
    assert!(c.receivable(&ua));
    assert!(!c.receivable(&other));
}

#[test]
fn spike_bls_g1_msm_budget() {
    let (env, c) = setup();
    for n in [64u32, 128, 256] {
        measure(&env, &std::format!("bls_g1_msm n={n}"), || c.bls_g1_msm(&n));
    }
}

#[test]
fn spike_bls_g2_msm_budget() {
    let (env, c) = setup();
    for n in [2u32, 8] {
        measure(&env, &std::format!("bls_g2_msm n={n}"), || c.bls_g2_msm(&n));
    }
}

#[test]
fn spike_bls_pairing_budget() {
    let (env, c) = setup();
    assert!(measure(&env, "bls_pairing pairs=2", || c.bls_pairing(&2)), "e(G1,G2)·e(−G1,G2) = 1");
}

#[test]
fn spike_bls_add_mul_fr_budget() {
    let (env, c) = setup();
    measure(&env, "bls_add_mul n=1 (G1 add+mul, G2 add+mul)", || c.bls_add_mul(&1));
    measure(&env, "bls_add_mul n=10", || c.bls_add_mul(&10));
    measure(&env, "bls_fr_ops n=100 (mul+add+inv)", || c.bls_fr_ops(&100));
}

#[test]
fn spike_zether_transfer_model_budget() {
    let (env, c) = setup();
    // An estimate (S13a; Z0 is the Zether gate): lift the testutils mainnet limits so every m prints its figure.
    env.cost_estimate().disable_resource_limits();
    for m in [1u32, 2, 4, 8] {
        let msms = measure(&env, &std::format!("zether_transfer_model m={m}"), || c.zether_transfer_model(&m));
        assert_eq!(msms, if m == 1 { 8 + 2 * 2 } else { 5 + 4 * m + 2 * (m + 1) });
    }
}
