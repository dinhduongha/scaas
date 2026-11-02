//! LEGACY (not compiled): the raw UA-8 portable digests of `src/digest.rs` and the EIP-191 `personal_sign` path of an
//! `evm-eoa` msig member of `src/verify.rs` (`check_msig` on `register`), as they stood before typed-signing P5 (main at
//! ref/pre-typed-signing). Replaced by the typed EIP-712 records under the name + version domain (TS-D1 … TS-D4:
//! `scaas_ua_common::{kem_record_hash, portable_record_hash, registration_digest}`, `verify::check_evm_eoa`); kept for
//! reference, never deleted. The EVM twin is smartcontracts/evm/legacy/typed-signing/UAKindsPortableRaw.sol.

// --- src/digest.rs ---
/// UA8-D1: `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)` (each hash 0 when absent).
pub fn portable_pop_digest(env: &Env, ua: &BytesN<32>, pqz_key_hash: &BytesN<32>, kem_record_hash: &BytesN<32>) -> BytesN<32> {
    keccak(env, &[&PURPOSE_POP_V2, &ua.to_array(), &pqz_key_hash.to_array(), &kem_record_hash.to_array()]).into()
}

/// UA8-D1: `keccak256(portablePopDigest ‖ pqzPopHash)`; the `pop` signs `ua_message(kind, PURPOSE_POP_V2, ·)` of it.
pub fn registration_digest(env: &Env, portable: &BytesN<32>, pqz_pop_hash: &BytesN<32>) -> BytesN<32> {
    keccak(env, &[&portable.to_array(), &pqz_pop_hash.to_array()]).into()
}

// --- src/verify.rs ---
/// S10: an `evm-eoa` member's portable signature, ECDSA over the EIP-191 `personal_sign` hash of `member_digest`
/// (CTR-UA-07); the recovered key's address (last 20 bytes of `keccak256(x ‖ y)`) must be `id20`.
pub fn check_evm_eoa_personal_sign(env: &Env, id20: &BytesN<20>, member_digest: &BytesN<32>, sig: &Bytes) {
    let mut m = Bytes::from_slice(env, b"\x19Ethereum Signed Message:\n32");
    m.append(&member_digest.clone().into());
    let pk = secp256k1_recover(env, &env.crypto().keccak256(&m), sig);
    let pk: Bytes = pk.into();
    let addr = env.crypto().keccak256(&pk.slice(1..65)).to_bytes();
    if Bytes::from(addr).slice(12..32) != Bytes::from(id20.clone()) {
        panic_with_error!(env, Error::Pop);
    }
}

// --- src/lib.rs check_msig, evm-eoa arm ---
//          EVM_EOA if !portable => fail(env, Error::NotVerifiable),
//          EVM_EOA => {
//              let id20: BytesN<20> = Bytes::from_array(env, &id).slice(12..32).try_into().unwrap();
//              verify::check_evm_eoa_personal_sign(env, &id20, &md, &s.sig);
//          }
