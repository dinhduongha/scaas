// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The verdict key on k256 0.14 (owner 2026-11-28, CTR-PQZ-28 Change): byte-identical to the signature of the alloy path
//! it replaces (`PrivateKeySigner`, k256 0.13) for every prehash below n, so for every keccak256 digest: the contracts'
//! verdict vectors and 2,000 derived keys. A prehash >= n (unreachable for a digest) differs: k256 0.13 fed it unreduced
//! to RFC 6979; the new path's signature there is still valid, low s and recoverable (review VK-4).

use alloy::primitives::{keccak256, Address, Signature, B256, U256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use pqz_ffi::stmt;
use serde_json::Value;
use zeroize::Zeroizing;

use scaas_pqz_verifier::VerdictKey;

fn key(secret: B256) -> VerdictKey {
    VerdictKey::from_secret(Zeroizing::new(secret.to_vec())).unwrap()
}

/// The new path against the old one and against the recovered signer: equal 65 bytes (r ‖ s ‖ 27 + recovery id), low s, the
/// signer's address recovered from the prehash.
fn assert_same(secret: B256, hash: B256, what: &str) -> Vec<u8> {
    let (new, old) = (key(secret), PrivateKeySigner::from_bytes(&secret).unwrap());
    let sig = new.sign_hash(&hash);
    let want = old.sign_hash_sync(&hash).unwrap();
    assert_eq!(new.address(), old.address(), "{what}: address");
    assert_eq!(sig[..], want.as_bytes()[..], "{what}: signature");
    assert_eq!(sig[64], 27 + u8::from(want.v()), "{what}: recovery id");
    let s = U256::from_be_slice(&sig[32..64]);
    let half_n = U256::from_str_radix(
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
        16,
    )
    .unwrap();
    assert!(s <= half_n, "{what}: high s");
    let back = Signature::from_raw(&sig)
        .unwrap()
        .recover_address_from_prehash(&hash)
        .unwrap();
    assert_eq!(back, new.address(), "{what}: recovered address");
    sig.to_vec()
}

/// `smartcontracts/vectors/pqz/<set>/verdict.json`: every row's signature of its `uaAuthDigest` by `verifierKey`, as the
/// contracts' forge writer pinned it.
#[test]
fn verdict_vectors_same_as_alloy_path() {
    let dir = if stmt::SET == "n2048-kmax1024" {
        String::new()
    } else {
        format!("{}/", stmt::SET)
    };
    let path = format!(
        "{}/../smartcontracts/vectors/pqz/{dir}verdict.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let k = &v["verifierKey"];
    let secret = B256::from(
        k.as_u64()
            .map(U256::from)
            .unwrap_or_else(|| k.as_str().unwrap().parse::<U256>().unwrap()),
    );
    let ua: B256 = v["verifierUA"].as_str().unwrap().parse().unwrap();
    assert_eq!(key(secret).address().into_word(), ua);
    let rows = v["rows"].as_array().unwrap();
    assert!(rows.len() > 10);
    for r in rows {
        let auth: B256 = r["uaAuthDigest"].as_str().unwrap().parse().unwrap();
        let sig = assert_same(secret, auth, &r.to_string());
        let want = alloy::primitives::hex::decode(r["signature"].as_str().unwrap()).unwrap();
        assert_eq!(sig, want, "{r}: the pinned signature");
    }
}

/// The property probe: 2,000 keys and prehashes derived by keccak256, the two paths byte-equal.
#[test]
fn two_thousand_keys_same_as_alloy_path() {
    for i in 0..2000u32 {
        let secret = keccak256(format!("scaas-pqz-verifier verdict key {i}"));
        assert_same(
            secret,
            keccak256(format!("prehash {i}")),
            &format!("key {i}"),
        );
    }
}

#[test]
fn refuses_a_secret_that_is_no_key() {
    for bad in [vec![0u8; 32], vec![0xff; 32], vec![1u8; 31], vec![1u8; 33]] {
        let e = VerdictKey::from_secret(Zeroizing::new(bad.clone()))
            .err()
            .unwrap()
            .to_string();
        assert!(
            !e.contains(&alloy::primitives::hex::encode(&bad)),
            "the secret in the error: {e}"
        );
    }
    let _: Address = key(B256::with_last_byte(1)).address();
}

/// A prehash >= n (k256 0.13 and 0.14 differ there, VK-4): the new path's signature is valid, low s, v in {27, 28} and
/// recovers the signer.
#[test]
fn prehash_at_or_above_n_signs_validly() {
    let n = U256::from_str_radix(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let k = key(B256::with_last_byte(0x42));
    for h in [n, n + U256::from(1), U256::MAX] {
        let hash = B256::from(h);
        let sig = k.sign_hash(&hash);
        assert!(sig[64] == 27 || sig[64] == 28);
        assert!(U256::from_be_slice(&sig[32..64]) <= n >> 1, "high s");
        let back = Signature::from_raw(&sig)
            .unwrap()
            .recover_address_from_prehash(&hash)
            .unwrap();
        assert_eq!(back, k.address());
    }
}
