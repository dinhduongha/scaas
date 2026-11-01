//! LEGACY (not compiled): the raw portable PoP digests of `schnorr.rs` before typed-signing P4 (main at
//! ref/pre-typed-signing). Replaced by the typed EIP-712 `UARegistration` / `UAPortableRecord` under the "SCaaS UA Portable"
//! name + version domain (TS-D1 / TS-D3); kept for reference, never deleted. Twins: ua-rs legacy/typed-signing/portable_raw.rs,
//! clientkeys legacy/typed-signing/ua-portable-raw.js; the vectors they made are in vectors/legacy/typed-signing/.

/// `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)`, each hash 0 when absent (UA-8 P1; ua-rs `portable_pop_digest`).
pub fn portable_pop_digest(ua: &[u8; 32], pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[pop_tag(), *ua, *pqz_key_hash, *kem_record_hash].concat())
}

/// `keccak256(portablePopDigest ‖ pqzPopHash)`: what `ua_message(kind, POP_V2, ·)` is taken over.
pub fn registration_digest(portable: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[*portable, *pqz_pop_hash].concat())
}

/// The registration digest of a Zether UA: it holds no PQZ key, KEM record or PQZ proof (all hashes 0).
pub fn zether_registration_digest(ua: &[u8; 32]) -> [u8; 32] {
    registration_digest(&portable_pop_digest(ua, &[0u8; 32], &[0u8; 32]), &[0u8; 32])
}

/// The `pop` of `register(0x0141, Y, …)` (UA-8 P1, portable: no chain, chainUid or registry): Schnorr by `x` under the
/// Zether tag over `ua_message(POP_V2, registration_digest(portable_pop_digest(UA(Y), 0, 0), 0))`.
pub fn zether_pop<C: ZCurve, R: RngCore + CryptoRng>(key: &ZetherKey<C>, rng: &mut R) -> Vec<u8> {
    sign(key, &ua_message::<C>(&pop_tag(), &zether_registration_digest(&key.ua())), rng)
}

pub fn verify_pop<C: ZCurve>(y: &G<C>, pop: &[u8]) -> Result<(), ZError> {
    verify(y, &ua_message::<C>(&pop_tag(), &zether_registration_digest(&ua_of::<C>(y))), pop)
}
