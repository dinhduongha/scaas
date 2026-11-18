// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Set-auditor A3 (CTR-ZTH-95, spec §5.2): the auditor's proof of possession. The committed known answers
//! (`smartcontracts/vectors/zether/auditor_pop.json`, `zether-cli auditor-pop`) equal a fresh generation; every row verifies
//! and every refused row is refused; the hedged prover's proofs verify, differ per draw, and bind `d` and the key. UNAUDITED.
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use zether_prover::curve::{decode_point, decode_scalar, Bls12381};
use zether_prover::keys::ZetherKey;
use zether_prover::schnorr::{auditor_pop, verify_auditor_pop};

type C = Bls12381;

fn h(v: &Value) -> Vec<u8> {
    hex::decode(&v.as_str().unwrap()[2..]).unwrap()
}

fn file() -> Value {
    let p = format!("{}/../../smartcontracts/vectors/zether/auditor_pop.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p}: run zether-cli auditor-pop"))).unwrap()
}

#[test]
fn committed_rows_are_current_and_verify() {
    let v = file();
    assert_eq!(v, zether_prover::vectors::auditor_pop(), "auditor_pop.json drifted: run zether-cli auditor-pop");
    for r in v["rows"].as_array().unwrap() {
        let y = decode_point::<C>(&h(&r["y"])).unwrap();
        let d: [u8; 32] = h(&r["d"]).try_into().unwrap();
        verify_auditor_pop::<C>(&y, &d, &h(&r["pop"])).unwrap();
        let mut other = d;
        other[0] ^= 1;
        assert!(verify_auditor_pop::<C>(&y, &other, &h(&r["pop"])).is_err(), "bound to d");
    }
    for r in v["refused"].as_array().unwrap() {
        let y = decode_point::<C>(&h(&r["y"])).unwrap();
        let d: [u8; 32] = h(&r["d"]).try_into().unwrap();
        assert!(verify_auditor_pop::<C>(&y, &d, &h(&r["pop"])).is_err(), "{}", r["name"]);
    }
}

#[test]
fn hedged_proofs_verify_and_bind_the_key() {
    let v = file();
    let r = &v["rows"][0];
    let k = ZetherKey::<C>::from_secret(decode_scalar::<C>(&h(&r["x"])).unwrap()).unwrap();
    let d: [u8; 32] = h(&r["d"]).try_into().unwrap();
    let a = auditor_pop(&k, &d, &mut ChaCha20Rng::seed_from_u64(1));
    let b = auditor_pop(&k, &d, &mut ChaCha20Rng::seed_from_u64(2));
    assert_ne!(a, b, "a fresh nonce per draw");
    verify_auditor_pop::<C>(&k.y, &d, &a).unwrap();
    verify_auditor_pop::<C>(&k.y, &d, &b).unwrap();
    let other = decode_point::<C>(&h(&v["rows"][1]["y"])).unwrap();
    assert!(verify_auditor_pop::<C>(&other, &d, &a).is_err(), "bound to the key");
}
