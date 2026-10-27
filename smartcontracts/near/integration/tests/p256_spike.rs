//! Task 1 gate (spec §3.5, R8): P-256 passkey verify in NEAR wasm, measured on near-sandbox.
//! Needs `smartcontracts/scripts/build.sh near` first (the wasm under target/near/).
use near_workspaces::types::Gas;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use scaas_near_common::webauthn::b64url;
use scaas_near_spike_p256::PasskeyCase;
use sha2::{Digest, Sha256};

const WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_spike_p256/scaas_near_spike_p256.wasm");
const VECTOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../evm/test/vectors/webauthn_soft.json");

fn hx(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// The repo's soft WebAuthn vector (low-s form) and its raw high-s signature.
fn vector() -> (PasskeyCase, [u8; 64]) {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).unwrap()).unwrap();
    let der = Signature::from_der(&hx(&v["signatureDer"])).unwrap();
    let low = der.normalize_s().expect("vector DER is high-s");
    let case = PasskeyCase {
        key: [hx(&v["qx"]), hx(&v["qy"])].concat().try_into().unwrap(),
        challenge: hx(&v["challenge"]).try_into().unwrap(),
        authenticator_data: hx(&v["authenticatorData"]),
        client_data_json: v["clientDataJSON"].as_str().unwrap().as_bytes().to_vec(),
        sig: low.to_bytes().into(),
        rp_id_hash: Sha256::digest(v["rpId"].as_str().unwrap()).into(),
        origins: vec![v["origin"].as_str().unwrap().to_string()],
    };
    (case, der.to_bytes().into())
}

/// A second passkey signed here (fixed key), same rp / origin, flags UP|UV.
fn second(challenge: [u8; 32], rp_id_hash: [u8; 32], origin: &str) -> PasskeyCase {
    let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let ad = [rp_id_hash.as_slice(), &[0x05, 0, 0, 0, 1]].concat();
    let cdj = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#, b64url(&challenge));
    let digest = Sha256::digest([ad.as_slice(), &Sha256::digest(cdj.as_bytes())].concat());
    let sig: Signature = sk.sign_prehash(&digest).unwrap();
    PasskeyCase {
        key: sk.verifying_key().to_encoded_point(false).as_bytes()[1..].try_into().unwrap(),
        challenge,
        authenticator_data: ad,
        client_data_json: cdj.into_bytes(),
        sig: sig.normalize_s().unwrap_or(sig).to_bytes().into(),
        rp_id_hash,
        origins: vec![origin.to_string()],
    }
}

async fn deploy() -> near_workspaces::Contract {
    let wasm = std::fs::read(WASM).expect("run smartcontracts/scripts/build.sh near first");
    println!("wasm {} B", wasm.len());
    near_workspaces::sandbox().await.unwrap().dev_deploy(&wasm).await.unwrap()
}

async fn check(c: &near_workspaces::Contract, case: &PasskeyCase) -> String {
    c.view("check").args(borsh::to_vec(case).unwrap()).await.unwrap().json().unwrap()
}

#[tokio::test]
async fn webauthn_vector_accepted() {
    let c = deploy().await;
    let (v, high) = vector();
    assert_eq!(check(&c, &v).await, "ok");
    assert_eq!(check(&c, &second([9; 32], v.rp_id_hash, &v.origins[0])).await, "ok");

    let mut x = v.clone();
    x.sig[31] ^= 1; // r
    assert_eq!(check(&c, &x).await, "BadSignature");
    let mut x = v.clone();
    let n = x.client_data_json.len();
    x.client_data_json[n - 2] ^= 1; // "crossOrigin":fals[e] — fields intact, signature breaks
    assert_eq!(check(&c, &x).await, "BadSignature");
    let mut x = v.clone();
    x.authenticator_data[36] ^= 1; // sign counter
    assert_eq!(check(&c, &x).await, "BadSignature");
    let mut x = v.clone();
    x.sig = high;
    assert_eq!(check(&c, &x).await, "HighS");
    let mut x = v.clone();
    x.challenge[0] ^= 1;
    assert_eq!(check(&c, &x).await, "ClientData");
    let mut x = v.clone();
    x.origins = vec!["https://evil.test".into()];
    assert_eq!(check(&c, &x).await, "ClientData");
    let mut x = v.clone();
    x.rp_id_hash[0] ^= 1;
    assert_eq!(check(&c, &x).await, "AuthenticatorData");
    let mut x = v.clone();
    x.authenticator_data[32] &= !0x01; // UP off
    assert_eq!(check(&c, &x).await, "AuthenticatorData");
}

#[tokio::test]
async fn p256_two_passkey_relay_fee_fits_300_tgas() {
    let c = deploy().await;
    let (a, _) = vector();
    let b = second([0x5a; 32], a.rp_id_hash, &a.origins[0]);
    let call = vec![0xab_u8; 4096];
    let out = c
        .call("two_passkey")
        .args(borsh::to_vec(&(a, b, call)).unwrap())
        .gas(Gas::from_tgas(300))
        .transact()
        .await
        .unwrap();
    let burnt = out.total_gas_burnt;
    let ok = out.is_success();
    println!("success {ok}");
    println!("total_gas_burnt {} gas = {:.3} Tgas (limit 300 Tgas)", burnt.as_gas(), burnt.as_gas() as f64 / 1e12);
    for (i, r) in out.receipt_outcomes().iter().enumerate() {
        println!("receipt {i} (function call) burnt {} gas", r.gas_burnt.as_gas());
    }
    println!("tx -> receipt conversion burnt {} gas", out.outcome().gas_burnt.as_gas());
    assert!(ok, "{:?}", out.failures());
    let per: Vec<u64> = out.json().unwrap();
    for (n, g) in ["a (vector)", "b (generated)"].iter().zip(&per) {
        println!("verify {n}: {g} gas = {:.3} Tgas", *g as f64 / 1e12);
    }
    assert!(burnt <= Gas::from_tgas(300));
}
