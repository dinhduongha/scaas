// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T15l (Fable P3-1): the holder's sealed balance-cache box as clientkeys `sealBalanceCache` makes it (AES-256-GCM
//! under `HKDF-SHA256(x, no salt, "scaas-zether-balance-cache-v1", 32)`, AAD `zether-cache:bls12381`), for the words commands
//! that take it (`checkBalance`, a debit's hint). The test's own sealer; `state::open_cache_entry` opens it. UNAUDITED.
use serde_json::{json, Value};
use zether_prover::curve::{encode_scalar, Bls12381};
use zether_prover::keys::ZetherKey;

fn b64url(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, x)| a | (u32::from(*x) << (16 - 8 * i)));
        for i in 0..=c.len() {
            s.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    s
}

/// The box `{iv, ct}` of `entries` under `k`'s key.
pub fn seal(k: &ZetherKey<Bls12381>, entries: &Value) -> Value {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let mut ck = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, &encode_scalar::<Bls12381>(&k.x)).expand(b"scaas-zether-balance-cache-v1", &mut ck).unwrap();
    let iv = [7u8; 12];
    let ct = aes_gcm::Aes256Gcm::new_from_slice(&ck)
        .unwrap()
        .encrypt(&aes_gcm::Nonce::from(iv), Payload { msg: entries.to_string().as_bytes(), aad: b"zether-cache:bls12381" })
        .unwrap();
    json!({"iv": b64url(&iv), "ct": b64url(&ct)})
}

/// The box of `k`'s one entry `<UA>:<token>`: `{balance, accSeq}`.
pub fn entry(k: &ZetherKey<Bls12381>, token: &Value, balance: u64, acc_seq: u64) -> Value {
    let id = format!("0x{}:{}", hex::encode(k.ua()), token.as_str().unwrap().to_lowercase());
    seal(k, &json!({ id: {"ua": format!("0x{}", hex::encode(k.ua())), "token": token, "balance": balance.to_string(), "accSeq": acc_seq} }))
}
