//! LEGACY (not compiled): the raw portable-record digests and the EIP-191 `personal_sign` native msig member path of
//! `scaas_ua::ua8` before typed-signing P2 (main at ref/pre-typed-signing). Replaced by the typed EIP-712 records under the
//! name + version domain (TS-D1 … TS-D4); kept for reference, never deleted. The JS twin is clientkeys
//! legacy/typed-signing/ua-portable-raw.js.
use crate::*;

pub fn kem_record_tag() -> [u8; 32] {
    keccak256(b"scaas.ua.kem-record.v1")
}
pub fn pqz_key_record_tag() -> [u8; 32] {
    keccak256(b"scaas.ua.pqz-key-record.v1")
}

/// `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)`, each hash 0 when absent.
pub fn portable_pop_digest(ua: &[u8; 32], pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&pop_v2_tag(), ua, pqz_key_hash, kem_record_hash])
}
/// `keccak256(portablePopDigest ‖ pqzPopHash)`: what the signer's `pop` signs under `ua_message(kind, POP_V2, ·)`.
pub fn registration_digest(portable: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[portable, pqz_pop_hash])
}
/// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kemPk))`: version 1 … 2^64 − 1, `kem_pk` = scheme byte ‖ key (empty:
/// `KemKeyLength`; scheme not enabled: `KemScheme`; another length: `KemKeyLength`).
pub fn kem_record_digest(ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    if version == 0 {
        return Err(UAError::KemVersion);
    }
    match kem_pk.first() {
        None => return Err(UAError::KemKeyLength),
        Some(&KEM_SCHEME_MLKEM1024_X25519) => {}
        Some(_) => return Err(UAError::KemScheme),
    }
    if kem_pk.len() != KEM_PK_LENGTH {
        return Err(UAError::KemKeyLength);
    }
    Ok(keccak(&[&kem_record_tag(), ua, &word(version), &keccak256(kem_pk)]))
}
/// The message `R_REG` proves over: `ua_message(0x0142, POP_V2, portable_pop_digest(ua, key_hash(pqz_key), kem_record_hash))`.
pub fn pqz_reg_message(ua: &[u8; 32], pqz_key: &[u8], kem: Option<(u64, &[u8])>) -> Result<[u8; 32]> {
    let kem = kem.filter(|(v, pk)| *v != 0 || !pk.is_empty());
    let kem_record_hash = kem.map(|(v, pk)| kem_record_digest(ua, v, pk)).transpose()?.unwrap_or([0; 32]);
    ua_message(PQZ_SCHEME, &pop_v2_tag(), &portable_pop_digest(ua, &pqz_key_hash_of(pqz_key)?, &kem_record_hash))
}
/// `keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqzKeyHash)`: what a later PQZ key's `R_REG` proves over (no proof hash: no cycle).
pub fn pqz_key_digest(ua: &[u8; 32], pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&pqz_key_record_tag(), ua, pqz_key_hash])
}
/// `keccak256(pqzKeyDigest ‖ pqzPopHash)`: what `setPqzKey`'s signature signs under `ua_message(kind, PURPOSE_PQZ_KEY, ·)`.
pub fn pqz_key_record_digest(key_digest: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[key_digest, pqz_pop_hash])
}

/// EIP-191 `personal_sign` of a 32-byte digest: `keccak256("\x19Ethereum Signed Message:\n32" ‖ digest)`. What a code-less
/// native (EOA) `msig` member signed over the `member_digest` of a portable record only (POP_V2, KEM, PQZ_KEY; ruling C7)
/// before TS-D4 (it now signs the record's typed digest itself).
pub fn personal_sign_digest(digest: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"\x19Ethereum Signed Message:\n32", digest])
}
