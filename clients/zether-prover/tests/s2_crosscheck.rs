//! Cross-check against S2's independently generated vectors (py_ecc `kat.py` on branch
//! r3-zether-contracts), copied verbatim into vectors/s2/: generators, proofSystemId,
//! transcript states/challenges, hashToScalar, Schnorr, BLS non-subgroup point.

use serde_json::Value;
use zether_prover::bulletproofs::Gens;
use zether_prover::curve::{
    decode_point, decode_scalar, encode_point, encode_scalar, keccak256, proof_system_id, Bls12381, ZCurve,
};
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;
use zether_prover::schnorr::{sign_with_k, verify};
use zether_prover::transcript::{hash_to_scalar, Transcript};

fn load(name: &str) -> Value {
    let p = format!("{}/vectors/s2/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn generators<C: ZCurve>() {
    let v = load(&format!("generators_{}.json", C::NAME));
    let g = Gens::<C>::new();
    assert_eq!(hx(&v["proofSystemId"]), proof_system_id::<C>());
    assert_eq!(hx(&v["h"]), encode_point::<C>(&g.h));
    assert_eq!(hx(&v["U"]), encode_point::<C>(&g.u));
    for i in 0..64 {
        assert_eq!(hx(&v["G"][i]), encode_point::<C>(&g.gs[i]), "G_{i}");
        assert_eq!(hx(&v["H"][i]), encode_point::<C>(&g.hs[i]), "H_{i}");
    }
    assert_eq!(hx(&v["blobKeccak"]), keccak256(&g.blob()));
}

#[test]
fn generators_match_s2() {
    #[cfg(feature = "bn254")]
    generators::<Bn254>();
    generators::<Bls12381>();
}

fn transcript_case<C: ZCurve>(case: &Value) {
    let mut t = Transcript::new();
    assert_eq!(hx(&case["init"]), t.state());
    let mut ch = 0;
    for (i, op) in case["ops"].as_array().unwrap().iter().enumerate() {
        if let Some(l) = op.get("absorb") {
            t.absorb(l.as_str().unwrap(), &hx(&op["data"]));
        } else {
            let c = t.challenge::<C>(op["challenge"].as_str().unwrap());
            assert_eq!(hx(&case["challenges"][ch]), encode_scalar::<C>(&c));
            ch += 1;
        }
        assert_eq!(hx(&case["states"][i]), t.state(), "state after op {i}");
    }
}

#[test]
fn transcript_matches_s2() {
    let v = load("transcript.json");
    for case in v["cases"].as_array().unwrap() {
        match case["curve"].as_str().unwrap() {
            #[cfg(feature = "bn254")]
            "bn254" => transcript_case::<Bn254>(case),
            "bls12381" => transcript_case::<Bls12381>(case),
            #[cfg(not(feature = "bn254"))]
            "bn254" => {} // S2's file keeps its bn254 case; the curve is off in this build
            c => panic!("curve {c}"),
        }
    }
    for h in v["hashToScalar"].as_array().unwrap() {
        let seed: [u8; 32] = hx(&h["seed"]).try_into().unwrap();
        #[cfg(feature = "bn254")]
        assert_eq!(hx(&h["bn254"]), encode_scalar::<Bn254>(&hash_to_scalar::<Bn254>(&seed)));
        assert_eq!(hx(&h["bls12381"]), encode_scalar::<Bls12381>(&hash_to_scalar::<Bls12381>(&seed)));
    }
}

fn schnorr<C: ZCurve>() {
    let v = load(&format!("schnorr_{}.json", C::NAME));
    let x = decode_scalar::<C>(&hx(&v["x"])).unwrap();
    let k = decode_scalar::<C>(&hx(&v["k"])).unwrap();
    let msg: [u8; 32] = hx(&v["msg"]).try_into().unwrap();
    let (r, e, z) = sign_with_k::<C>(&x, &msg, &k);
    assert_eq!(hx(&v["R"]), encode_point::<C>(&r));
    assert_eq!(hx(&v["e"]), encode_scalar::<C>(&e));
    assert_eq!(hx(&v["z"]), encode_scalar::<C>(&z));
    let y = decode_point::<C>(&hx(&v["Y"])).unwrap();
    verify::<C>(&y, &msg, &hx(&v["sig"])).unwrap();
}

#[test]
fn schnorr_matches_s2() {
    #[cfg(feature = "bn254")]
    schnorr::<Bn254>();
    schnorr::<Bls12381>();
}

#[test]
fn bls_non_subgroup_rejected() {
    let v = load("curve_misc.json");
    assert!(decode_point::<Bls12381>(&hx(&v["blsNonSubgroup"])).is_err());
}
