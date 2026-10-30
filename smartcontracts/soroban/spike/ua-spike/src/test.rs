//! T0 spike unit tests (SDK testutils at protocol 30). Each prints the budget of the measured call; the gate figures
//! are the network ones (`run.sh` / `measure.py`), since native test code under-counts the Wasm VM.
extern crate std;
use std::{println, string::String, vec::Vec as StdVec};

use soroban_sdk::{Bytes, BytesN, Env, Vec};
use serde_json::Value;

use crate::{UaSpike, UaSpikeClient};

const PORTABLE: &str = include_str!("../../../../vectors/ua/portable.json");
const SIGNATURES: &str = include_str!("../../../../vectors/ua/signatures.json");

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

fn mldsa65_args(env: &Env) -> (BytesN<1952>, Bytes, BytesN<3309>, StdVec<u8>) {
    let r = row("mldsa65#1");
    let pk = BytesN::<1952>::from_array(env, &hx(r["keyData"].as_str().unwrap()).try_into().unwrap());
    let sig = BytesN::<3309>::from_array(env, &hx(r["pop"].as_str().unwrap()).try_into().unwrap());
    (pk, b(env, &hx(r["popMessage"].as_str().unwrap())), sig, hx(r["ua"].as_str().unwrap()))
}

#[test]
fn spike_register_mldsa65_model_budget() {
    let (env, c) = setup();
    let (pk, msg, sig, ua) = mldsa65_args(&env);
    let id = measure(&env, "register_model mldsa65", || c.register_model(&pk, &msg, &sig));
    assert_eq!(id.to_array().to_vec(), ua, "the model's id is the CTR-UA-04 id of the vector");
    assert!(c.try_register_model(&pk, &msg, &sig).is_err(), "already registered");
}

#[test]
fn spike_msig3_mldsa65_model_budget() {
    let (env, c) = setup();
    let (pk, msg, sig, _) = mldsa65_args(&env);
    let mut ids = Vec::new(&env);
    for i in 1..=3u8 {
        let id = BytesN::from_array(&env, &[i; 32]);
        c.seed(&Some(id.clone()), &0x0131, &pk.clone().into(), &Some(sig.clone().into()));
        ids.push_back(id);
    }
    measure(&env, "msig_model n=3 mldsa65", || c.msig_model(&3, &ids, &pk, &msg, &sig));
}

fn passkey_args(env: &Env) -> (Bytes, BytesN<65>, BytesN<32>, Bytes, Bytes, BytesN<64>, BytesN<32>, StdVec<u8>) {
    let s: Value = serde_json::from_str(SIGNATURES).unwrap();
    let r = s["derived"].as_array().unwrap().iter().find(|r| r["kind"] == 256).unwrap();
    let kd = hx(r["keyData"].as_str().unwrap());
    let m = r["sigs"].as_array().unwrap().iter().find(|x| x["purpose"] == "metatx").unwrap();
    let sig = hx(m["sig"].as_str().unwrap()); // abi.encode(bytes authData, string clientDataJSON, uint256 r, uint256 s)
    let word = |o: usize| usize::from_str_radix(&hex_str(&sig[o + 24..o + 32]), 16).unwrap();
    let (o1, o2) = (word(0), word(32));
    let auth = sig[o1 + 32..o1 + 32 + word(o1)].to_vec();
    let cdj = sig[o2 + 32..o2 + 32 + word(o2)].to_vec();
    let mut key = [4u8; 65];
    key[1..].copy_from_slice(&kd[..64]);
    (
        b(env, &kd),
        BytesN::from_array(env, &key),
        BytesN::from_array(env, &kd[64..96].try_into().unwrap()),
        b(env, &auth),
        b(env, &cdj),
        BytesN::from_array(env, &sig[64..128].try_into().unwrap()),
        BytesN::from_array(env, &hx(m["digest"].as_str().unwrap()).try_into().unwrap()),
        hx(r["ua"].as_str().unwrap()),
    )
}

fn hex_str(v: &[u8]) -> String {
    v.iter().map(|x| std::format!("{x:02x}")).collect()
}

#[test]
fn spike_ua_pay_passkey_model_budget() {
    let (env, c) = setup();
    let (kd, key, rp, auth, cdj, sig, digest, ua) = passkey_args(&env);
    let id = c.seed(&None, &0x0100, &kd, &None);
    assert_eq!(id.to_array().to_vec(), ua);
    measure(&env, "ua_pay_model webauthn-p256", || c.ua_pay_model(&key, &rp, &auth, &cdj, &sig, &digest));
    let other = BytesN::from_array(&env, &[7; 32]);
    assert!(c.try_ua_pay_model(&key, &rp, &auth, &cdj, &sig, &other).is_err(), "challenge binds the digest");
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
