//! Feature `pq`: the PQ kinds' verifiers for the off-chain check (`ua8::check_*`, UA8-D24, C14), independent of the JS
//! generator (noble): `ml-dsa`, `slh-dsa`, `pqcrypto-falcon` (PQClean `falcon-padded-512`). ML-DSA and SLH-DSA verify `pq_msg =
//! keccak256(TAG(kind) ‖ ua_msg)` with the empty context, Falcon `ua_msg` itself (CTR-UA-23). A kind whose crate disagrees
//! with a KAT row loses its arm in [`verify_raw`], so it is refused (C14). Signatures and keys are untrusted: anything
//! malformed is `false`, never a panic. UNAUDITED.
use crate::{keccak, tag};
use ml_dsa::{EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsaParams};

pub const FNDSA512_SIG_LENGTH: usize = 666;

/// What the scheme signs: `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` (ML-DSA, SLH-DSA), `ua_msg` (Falcon).
pub fn signed_message(kind: u16, ua_msg: &[u8; 32]) -> Vec<u8> {
    match tag(kind) {
        Ok(t) if kind != 0x0132 => keccak(&[&t, ua_msg]).to_vec(),
        _ => ua_msg.to_vec(),
    }
}

/// The kind's signature over `ua_msg`, under the empty context; `false` for any other kind.
pub fn verify(kind: u16, key: &[u8], ua_msg: &[u8; 32], sig: &[u8]) -> bool {
    let m = signed_message(kind, ua_msg);
    match kind {
        0x0132 => verify_raw(kind, key, &m, sig),
        _ => verify_raw(kind, key, &[&[0, 0], &m[..]].concat(), sig), // M' = 0x00 ‖ ctx length 0 ‖ m
    }
}

/// The core check the published vectors pin: `m` is `M'` for ML-DSA and SLH-DSA (FIPS 204 Algorithm 8, FIPS 205 Algorithm 20),
/// the message for Falcon. Only [`verify`] gives it `pq_msg`, so the KATs run the path it takes.
pub fn verify_raw(kind: u16, key: &[u8], m: &[u8], sig: &[u8]) -> bool {
    match kind {
        0x0130 => mldsa::<MlDsa44>(key, m, sig),
        0x0131 => mldsa::<MlDsa65>(key, m, sig),
        0x0132 => fndsa512(key, m, sig),
        0x0133 => slhdsa128s(key, m, sig),
        _ => false,
    }
}

fn mldsa<P: MlDsaParams>(key: &[u8], m: &[u8], sig: &[u8]) -> bool {
    let (Ok(k), Ok(s)) = (EncodedVerifyingKey::<P>::try_from(key), ml_dsa::Signature::<P>::try_from(sig)) else { return false };
    ml_dsa::VerifyingKey::<P>::decode(&k).verify_internal(m, &s)
}

fn slhdsa128s(key: &[u8], m: &[u8], sig: &[u8]) -> bool {
    use slh_dsa::{Sha2_128s, Signature, VerifyingKey};
    let (Ok(k), Ok(s)) = (VerifyingKey::<Sha2_128s>::try_from(key), Signature::<Sha2_128s>::try_from(sig)) else { return false };
    k.slh_verify_internal(&[m], &s).is_ok()
}

/// Exactly the padded length: PQClean's verifier also takes a shorter `sig` (EIP-8052 is 666 B).
fn fndsa512(key: &[u8], m: &[u8], sig: &[u8]) -> bool {
    use pqcrypto_falcon::falconpadded512 as falcon;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
    if sig.len() != FNDSA512_SIG_LENGTH {
        return false;
    }
    let (Ok(k), Ok(s)) = (falcon::PublicKey::from_bytes(key), falcon::DetachedSignature::from_bytes(sig)) else { return false };
    falcon::verify_detached_signature(&s, m, &k).is_ok()
}
