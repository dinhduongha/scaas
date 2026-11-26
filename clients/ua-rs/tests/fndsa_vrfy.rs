// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Gate of the wasm32 Falcon path (owner 2026-11-26, CLI-UAL-66), natively: every FN-DSA row of tests/fndsa/rows.rs through
//! PQClean (`pq::verify_raw`) and through src/falcon/soft.rs (the vendored falcon-rs 0.3.1, `fpemu`, the code wasm32 runs,
//! included here as it is), after src/falcon.rs's length checks; with `vectors`, the wallet cases of tests/fndsa/sign.rs:
//! falcon-rs's key pair of each HKDF seed and its signature with the same fixed randomness byte-equal to PQClean's, and the key
//! pairs of 1,000 seeds per degree (Fable audit FR-5). Sign-side refusals of soft.rs, and a guard that soft.rs uses falcon-rs's
//! round-3 API only (FR-8).
//! falcon-rs's FIPS 206 API (`FnDsaSignature::verify`, its `safe_api`) is counted too: it hashes `nonce ‖ 0x00 ‖ len(ctx) ‖ ctx ‖ m`, not
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
    assert_eq!((acc, rej), rows::COUNTS, "rows");
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
        assert_eq!(soft::keypair(logn, &seed, &mut spk, &mut ssk), 0);
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

/// FR-5: seed -> key pair, falcon-rs (soft.rs) against PQClean (the wallet's keygen natively), 1,000 seeds per degree; the digest
/// is what tests/fndsa/wasm computes on wasm32. Minutes unoptimised: CI runs it in release (job ua-rs-fndsa-wasm).
#[cfg(feature = "vectors")]
#[test]
#[ignore = "2,000 key generations: cargo test --release --features vectors --test fndsa_vrfy -- --include-ignored"]
fn falcon_rs_key_pairs_equal_pqclean_over_many_seeds() {
    let t = std::time::Instant::now();
    let (n, digest) = sign::keys_digest(|kind, seed, pk, sk| {
        let (logn, _, _) = params(kind).unwrap();
        let (mut spk, mut ssk) = (vec![0u8; pk.len()], vec![0u8; sk.len()]);
        assert_eq!(soft::keypair(logn, seed, &mut spk, &mut ssk), 0);
        assert!(
            spk == pk && ssk == sk,
            "key pair {kind:#06x} seed {}",
            hex::encode(seed)
        );
    });
    println!(
        "{n} key pairs, falcon-rs = PQClean; digest {digest}; {:.1} s",
        t.elapsed().as_secs_f64()
    );
    assert_eq!(
        (n, digest.as_str()),
        (2 * sign::SEEDS as usize, sign::KEYS_DIGEST)
    );
}

/// FR-11, sign side: soft.rs refuses a secret key cut short, a header of another degree, a 512 key at degree 1024, and a
/// signature buffer of the wrong length (src/falcon.rs checks the lengths first; these are falcon-rs's own refusals).
#[cfg(feature = "vectors")]
#[test]
fn soft_sign_refusals() {
    let seed = sign::parity_seed(0x0132, 0);
    let (sk, pk) = scaas_ua::wallet::derive::ua_key(0x0132, zeroize::Zeroizing::new(seed)).unwrap();
    let (m, rnd) = ([7u8; 32], [9u8; 88]);
    let mut sig = vec![0u8; 666];
    assert!(soft::sign(9, &sk, &m, &rnd, &mut sig), "positive control");
    assert!(round3(0x0132, &pk, &m, &sig));
    let mut head = sk.to_vec();
    head[0] ^= 0x01;
    for (what, sk, logn, len) in [
        ("secret key cut short", &sk[..sk.len() - 1], 9, 666),
        ("header of degree 256", &head[..], 9, 666),
        ("degree 1024 with a 512 key", &sk[..], 10, 1280),
        ("signature buffer one short", &sk[..], 9, 665),
    ] {
        let mut sig = vec![0u8; len];
        assert!(!soft::sign(logn, sk, &m, &rnd, &mut sig), "{what}");
    }
}

/// FR-8: soft.rs names no falcon-rs path but `::falcon::falcon` (as `r3`) and the SHAKE context type.
#[test]
fn soft_uses_the_round3_api_only() {
    const ALLOWED: [&str; 2] = [
        "::falcon::falcon as r3",
        "::falcon::shake::InnerShake256Context",
    ];
    let mut code: String = include_str!("../src/falcon/soft.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for a in ALLOWED {
        assert_eq!(code.matches(a).count(), 1, "{a}");
        code = code.replace(a, "");
    }
    let names: Vec<&str> = code
        .split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .collect();
    assert!(
        !names.contains(&"falcon"),
        "soft.rs reaches falcon-rs by another path"
    );
}
