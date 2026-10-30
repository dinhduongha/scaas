//! `ua_pay` across the two spike contracts (spec §5.1): a generated P-256 passkey pays an `mldsa65` UA.
extern crate std;
use std::{format, println, vec::Vec as StdVec};

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use scaas_ua_spike::{b64url32, purpose, tagged, ua_msg, UaSpike, UaSpikeClient, K_MLDSA65, K_WEBAUTHN};
use serde_json::Value;
use soroban_sdk::{Bytes, BytesN, Env};

use crate::{Holder, UaSpikeToken, UaSpikeTokenClient};

const PORTABLE: &str = include_str!("../../../../vectors/ua/portable.json");

fn hx(s: &str) -> StdVec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn w(v: usize) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[24..].copy_from_slice(&(v as u64).to_be_bytes());
    o
}

fn dyn_(b: &[u8]) -> StdVec<u8> {
    let mut o = w(b.len()).to_vec();
    o.extend_from_slice(b);
    o.resize(o.len() + (32 - b.len() % 32) % 32, 0);
    o
}

/// abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s) over ua_msg `m`.
fn webauthn_auth(env: &Env, sk: &SigningKey, rp: &[u8; 32], m: &BytesN<32>) -> StdVec<u8> {
    let ch = b64url32(&m.to_array());
    let ch = std::str::from_utf8(&ch).unwrap();
    let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{ch}","origin":"https://scaas.example","crossOrigin":false}}"#);
    let mut ad = rp.to_vec();
    ad.extend_from_slice(&[5, 0, 0, 0, 1]);
    let mut signed = ad.clone();
    signed.extend_from_slice(&env.crypto().sha256(&Bytes::from_slice(env, cdj.as_bytes())).to_array());
    let sig: Signature = sk.sign(&signed); // ECDSA-P256-SHA256: the host verifies sha256(signed)
    let sig = sig.normalize_s().unwrap_or(sig).to_bytes();
    let (a, c) = (dyn_(&ad), dyn_(cdj.as_bytes()));
    [&w(128)[..], &w(128 + a.len()), &sig[..32], &sig[32..], &a, &c].concat()
}

#[test]
fn spike_ua_pay_passkey_model_budget() {
    let env = Env::default();
    assert_eq!(env.ledger().protocol_version(), 30);
    let reg_id = env.register(UaSpike, ());
    let reg = UaSpikeClient::new(&env, &reg_id);
    let tok = UaSpikeTokenClient::new(&env, &env.register(UaSpikeToken, (&reg_id,)));

    let sk = SigningKey::from_slice(&[0x5a; 32]).unwrap();
    let pt = sk.verifying_key().to_encoded_point(false);
    let rp = env.crypto().sha256(&Bytes::from_slice(&env, b"scaas.example")).to_array();
    let mut kd = pt.as_bytes()[1..].to_vec();
    kd.extend_from_slice(&rp);
    let from = reg.seed(&K_WEBAUTHN, &Bytes::from_slice(&env, &kd), &None);
    assert_eq!(from, tagged(&env, K_WEBAUTHN, &Bytes::from_slice(&env, &kd)));
    // the receiver: the portable.json mldsa65#1 UA (a ≈ 5.3 KB record)
    let p: Value = serde_json::from_str(PORTABLE).unwrap();
    let r = p["registrations"].as_array().unwrap().iter().find(|r| r["name"] == "mldsa65#1").unwrap();
    let to = reg.seed(
        &K_MLDSA65,
        &Bytes::from_slice(&env, &hx(r["keyData"].as_str().unwrap())),
        &Some(Bytes::from_slice(&env, &hx(r["pop"].as_str().unwrap()))),
    );
    tok.mint_ua(&from, &1000);

    let (amount, pay_ref, until) = (7i128, BytesN::from_array(&env, &[9; 32]), 4_102_444_800u64);
    let to_h = Holder::Ua(to.clone());
    let digest = tok.pay_digest(&from, &to_h, &amount, &pay_ref, &until, &None);
    let m = ua_msg(&env, K_WEBAUTHN, &purpose(&env, "scaas.ua.purpose.metatx.v1"), &digest);
    let auth = webauthn_auth(&env, &sk, &rp, &m);

    let mut bad = auth.clone();
    bad[100] ^= 1;
    let bad = Bytes::from_slice(&env, &bad);
    assert!(tok.try_ua_pay_model(&from, &to_h, &amount, &pay_ref, &until, &None, &bad).is_err(), "bad signature");
    let auth = Bytes::from_slice(&env, &auth);
    assert!(tok.try_ua_pay_model(&from, &to_h, &8, &pay_ref, &until, &None, &auth).is_err(), "digest binds amount");

    env.cost_estimate().budget().reset_unlimited();
    tok.ua_pay_model(&from, &to_h, &amount, &pay_ref, &until, &None, &auth);
    let b = env.cost_estimate().budget();
    println!("BUDGET ua_pay_model webauthn-p256 -> mldsa65 UA (token + registry): cpu={} mem={}",
             b.cpu_instruction_cost(), b.memory_bytes_cost());
    assert_eq!((tok.ua_balance(&from), tok.ua_balance(&to)), (993, 7));
    assert!(tok.try_ua_pay_model(&from, &to_h, &amount, &pay_ref, &until, &None, &auth).is_err(), "pay lane is one-shot");
}
