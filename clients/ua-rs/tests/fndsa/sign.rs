// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The signing half of the Falcon gate (CLI-UAL-66): every mnemonic of keys.json, both Falcon kinds, three account / index
//! pairs and two messages each, through the wallet (`ua_key`, its arena secret, `vectors_sign_ua_msg` with fixed randomness):
//! PQClean natively, falcon-rs on wasm32. Each signature must verify (`pq::verify`), and keccak256 over `pk ‖ sk ‖ sig` of
//! every case must equal [`DIGEST`] on both, so a wasm32 key or signature differing in one byte from PQClean's fails.
//! [`keys_digest`]: the key pairs of [`SEEDS`] seeds per degree (Fable audit FR-5), the same digest natively (PQClean) and on
//! wasm32 (falcon-rs). Shared by tests/fndsa_vrfy.rs and tests/fndsa/wasm.
use scaas_ua::pq;
use scaas_ua::wallet::{UaKey, Wallet};
use serde_json::Value;
use sha3::{Digest, Keccak256};

/// keccak256 over every case's `pk ‖ sk ‖ sig`, PQClean's (native).
pub const DIGEST: &str = "aad3af3e3f1fd64839fc3f8e2c018ea112ea7fe03f0cee6db4db63bfb7ab7acd";
pub const CASES: usize = 48;

const PATHS: [(u32, u32); 3] = [(0, 0), (0, 1), (1, 0)];

/// Key pairs per degree of [`keys_digest`].
pub const SEEDS: u32 = 1000;
/// keccak256 over every `pk ‖ sk` of [`keys_digest`], PQClean's (native).
pub const KEYS_DIGEST: &str = "02513c7bc57c8122f13a424fdc30870ca5c1e35ac3c42b9eadc24186bcfebab3";

/// Seed `i` of degree `kind`: SHAKE256 of a label, the kind and `i`, 48 bytes (keygen's seed length).
pub fn parity_seed(kind: u16, i: u32) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(b"ua-rs fndsa keygen parity");
    h.update(&kind.to_be_bytes());
    h.update(&i.to_be_bytes());
    let mut seed = vec![0u8; 48];
    h.finalize_xof().read(&mut seed);
    seed
}

/// The key pair of each [`parity_seed`], `SEEDS` per Falcon kind, through the wallet's keygen (`derive::ua_key`: PQClean
/// natively, falcon-rs on wasm32); `each` sees the kind, the seed and the key pair. Returns the count and keccak256 over every
/// `pk ‖ sk`.
pub fn keys_digest(mut each: impl FnMut(u16, &[u8], &[u8], &[u8])) -> (usize, String) {
    let (mut n, mut d) = (0, Keccak256::new());
    for kind in [0x0132u16, 0x0135] {
        for i in 0..SEEDS {
            let seed = parity_seed(kind, i);
            let (sk, pk) =
                scaas_ua::wallet::derive::ua_key(kind, zeroize::Zeroizing::new(seed.clone()))
                    .unwrap();
            d.update(&pk);
            d.update(&*sk);
            each(kind, &seed, &pk, &sk);
            n += 1;
        }
    }
    (n, hex::encode(d.finalize()))
}

/// The case's message and 88 bytes of randomness (nonce ‖ sampler seed), keccak256 of its labels.
fn inputs(id: &str, kind: u16, account: u32, index: u32, j: u8) -> ([u8; 32], Vec<u8>) {
    let h = |t: u8| -> [u8; 32] {
        Keccak256::new()
            .chain_update([t, j])
            .chain_update(kind.to_be_bytes())
            .chain_update(account.to_be_bytes())
            .chain_update(index.to_be_bytes())
            .chain_update(id.as_bytes())
            .finalize()
            .into()
    };
    let mut rnd = [h(1), h(2), h(3)].concat();
    rnd.truncate(88);
    (h(0), rnd)
}

/// Runs every case; `each` sees the wallet, the key, the case and the wallet's outputs. Returns the count and the digest.
pub fn wallet_digest(
    load: impl Fn(&str) -> Value,
    mut each: impl FnMut(&Wallet, &UaKey, (u32, u32), &[u8], &[u8; 32], &[u8], &[u8]),
) -> (usize, String) {
    let keys = load("keys.json");
    let (mut n, mut d) = (0, Keccak256::new());
    for m in keys["mnemonics"].as_array().unwrap() {
        let id = m["id"].as_str().unwrap();
        let w = Wallet::from_mnemonic(
            m["words"].as_str().unwrap(),
            m["passphrase"].as_str().unwrap(),
        )
        .unwrap();
        for kind in [0x0132u16, 0x0135] {
            for (a, i) in PATHS {
                let key = w.ua_key(kind, a, i).unwrap();
                let pk = key.key_data();
                let sk = key.vectors_with_secret(|s| s.to_vec()).unwrap();
                for j in 0..2 {
                    let (msg, rnd) = inputs(id, kind, a, i, j);
                    let sig = key.vectors_sign_ua_msg(&msg, &rnd).unwrap();
                    assert!(
                        pq::verify(kind, &pk, &msg, &sig),
                        "{id} {kind:#06x} {a}/{i} {j}"
                    );
                    d.update(&pk);
                    d.update(&sk);
                    d.update(&sig);
                    each(&w, &key, (a, i), &sk, &msg, &rnd, &sig);
                    n += 1;
                }
            }
        }
    }
    (n, hex::encode(d.finalize()))
}
