// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Gate of the wasm32 Falcon path (owner 2026-11-26, CLI-UAL-66), natively: every FN-DSA row of tests/fndsa/rows.rs through
//! PQClean (`pq::verify_raw`) and through src/falcon/soft.rs (falcon-rs 0.4.0's round-3 module, the code wasm32 runs,
//! included here as it is), after src/falcon.rs's length checks; with `vectors`, the wallet cases of tests/fndsa/sign.rs:
//! falcon-rs's key pair of each HKDF seed and its signature with the same fixed randomness byte-equal to PQClean's.
//! falcon-rs's FIPS 206 API (`FnDsaSignature::verify`) is counted too: it hashes `nonce ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ m`, not
//! round 3's `nonce ‖ m`, so it refuses every accept row. fn-dsa-vrfy 0.4.0 failed this gate
//! (clients/runs/2026-11-26-ua-rs-wasm-fndsa-summary.txt). tests/fndsa/wasm runs the same rows and cases in wasm32. UNAUDITED.
#[path = "fndsa/rows.rs"]
mod rows;
#[cfg(feature = "vectors")]
#[path = "fndsa/sign.rs"]
mod sign;
#[path = "../src/falcon/soft.rs"]
mod soft;

use falcon::{DomainSeparation, FnDsaSignature};
use scaas_ua::pq;
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/ua/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// logn, key and padded signature lengths of a Falcon kind (src/falcon.rs `FNDSA512` / `FNDSA1024`).
fn params(kind: u16) -> Option<(u32, usize, usize)> {
    match kind {
        0x0132 => Some((9, 897, 666)),
        0x0135 => Some((10, 1793, 1280)),
        _ => None,
    }
}

/// src/falcon.rs `verify` on wasm32: the kind's exact key and padded signature lengths, then [`soft::verify`].
fn round3(kind: u16, pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
    match params(kind) {
        Some((logn, k, s)) if pk.len() == k && sig.len() == s => soft::verify(logn, pk, m, sig),
        _ => false,
    }
}

#[test]
fn falcon_rs_against_every_falcon_row() {
    let rows = rows::rows(load);
    let (mut acc, mut rej, mut fips_differs) = (0, 0, 0);
    let mut differs = Vec::new();
    for r in &rows {
        let pqclean = pq::verify_raw(r.kind, &r.pk, &r.m, &r.sig);
        assert_eq!(pqclean, r.valid, "PQClean vs the row: {}", r.what);
        if r.valid {
            acc += 1
        } else {
            rej += 1
        }
        if round3(r.kind, &r.pk, &r.m, &r.sig) != pqclean {
            differs.push(&r.what);
        }
        let fips = FnDsaSignature::verify(&r.sig, &r.pk, &r.m, &DomainSeparation::None).is_ok();
        fips_differs += (fips != pqclean) as usize;
    }
    println!(
        "{} rows: {acc} accept, {rej} refuse; falcon-rs round3 differs on {}, its FIPS 206 API on {fips_differs}",
        rows.len(),
        differs.len()
    );
    assert_eq!((acc, rej), (48, 172), "rows");
    assert!(differs.is_empty(), "falcon-rs round3 differs: {differs:?}");
}

#[cfg(feature = "vectors")]
#[test]
fn falcon_rs_keys_and_signs_as_pqclean() {
    use scaas_ua::wallet::derive::ua_secret;
    let (n, digest) = sign::wallet_digest(load, |w, key, (a, i), sk, m, rnd, sig| {
        let (kind, pk) = (key.kind(), key.key_data());
        let (logn, _, _) = params(kind).unwrap();
        let seed = ua_secret(&*w.vectors_seed().unwrap(), kind, a, i).unwrap();
        let (mut spk, mut ssk) = (vec![0u8; pk.len()], vec![0u8; sk.len()]);
        assert!(soft::keypair(logn, &seed, &mut spk, &mut ssk));
        assert_eq!(
            (hex::encode(&spk), hex::encode(&ssk)),
            (hex::encode(&pk), hex::encode(sk)),
            "key pair {kind:#06x} {a}/{i}"
        );
        let mut ssig = vec![0u8; sig.len()];
        assert!(soft::sign(logn, sk, m, rnd, &mut ssig));
        assert_eq!(
            hex::encode(&ssig),
            hex::encode(sig),
            "signature {kind:#06x} {a}/{i}"
        );
        assert!(round3(kind, &pk, m, &ssig));
    });
    println!("{n} wallet cases, falcon-rs = PQClean; digest {digest}");
    assert_eq!((n, digest.as_str()), (sign::CASES, sign::DIGEST));
}
