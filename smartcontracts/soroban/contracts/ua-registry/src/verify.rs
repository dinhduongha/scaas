//! The S3 per-kind checks (spec §3) of `sig` over `ua_msg`, with the signature bytes the EVM vectors carry. Every check
//! panics on failure: `KeyData` for the key, the caller's `e` (`Pop` in `register`, `Unauthorized` in the other entries,
//! as EVM) for the signature where the contract checks itself, a host error where the host verifies (ed25519
//! `verify_strict`, P-256, ML-DSA; plan finding F1).
use scaas_ua_common::h32;
use soroban_sdk::{crypto::Hash, panic_with_error, Bytes, BytesN, Env};

use crate::{digest::*, webauthn, Error};

/// secp256k1 `n / 2`, big-endian.
const HALF_N: [u8; 32] = h32("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

/// The S3 check for a single-key kind (`msig` is checked member by member by the registry, T3).
pub fn check(env: &Env, kind: u32, key_data: &Bytes, msg: &Hash<32>, sig: &Bytes, e: Error) {
    match kind {
        WEBAUTHN_P256 => webauthn::check(env, key_data, msg, sig, e),
        P256 => {
            let key = uncompressed(env, key_data);
            let rs: BytesN<64> = sig.clone().try_into().unwrap_or_else(|_| panic_with_error!(env, e));
            env.crypto().secp256r1_verify(&key, &env.crypto().sha256(&msg.to_bytes().into()), &rs);
        }
        ED25519 => {
            let pk: BytesN<32> = key_data.clone().try_into().unwrap_or_else(|_| panic_with_error!(env, Error::KeyData));
            ed25519(env, &pk, &msg.to_bytes().into(), sig, e);
        }
        SECP256K1 => {
            if secp256k1_recover(env, msg, sig, e) != uncompressed(env, key_data) {
                panic_with_error!(env, e);
            }
        }
        MLDSA44 => {
            let pk: BytesN<1312> = key_data.clone().try_into().unwrap_or_else(|_| panic_with_error!(env, Error::KeyData));
            let s: BytesN<2420> = sig.clone().try_into().unwrap_or_else(|_| panic_with_error!(env, e));
            env.crypto().ml_dsa_44_verify(&pk, &pq_message(env, kind, msg), &s, &Bytes::new(env));
        }
        MLDSA65 => {
            let pk: BytesN<1952> = key_data.clone().try_into().unwrap_or_else(|_| panic_with_error!(env, Error::KeyData));
            let s: BytesN<3309> = sig.clone().try_into().unwrap_or_else(|_| panic_with_error!(env, e));
            env.crypto().ml_dsa_65_verify(&pk, &pq_message(env, kind, msg), &s, &Bytes::new(env));
        }
        _ => panic_with_error!(env, Error::KindDisabled),
    }
}

/// `0x04 ‖ x ‖ y` of 64-byte key data.
fn uncompressed(env: &Env, key_data: &Bytes) -> BytesN<65> {
    let mut k = Bytes::from_array(env, &[4u8]);
    k.append(key_data);
    k.try_into().unwrap_or_else(|_| panic_with_error!(env, Error::KeyData))
}

/// The contract's ed25519 key check (spec §3): `y < p` and none of the small-order encodings, i.e. the eight canonical
/// torsion points plus the two "negative zero" encodings of the `x = 0` points. The host's `verify_strict` refuses
/// small-order keys at verify too, but accepts a non-canonical `y ≥ p` key; a key that is not a point is left to the
/// host (refused at every verify, so it never proves a `pop`).
pub fn ed25519_key_ok(pk: &[u8; 32]) -> bool {
    const SMALL: [[u8; 32]; 10] = [
        h32("0100000000000000000000000000000000000000000000000000000000000000"),
        h32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        h32("0000000000000000000000000000000000000000000000000000000000000000"),
        h32("0000000000000000000000000000000000000000000000000000000000000080"),
        h32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
        h32("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
        h32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
        h32("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
        h32("0100000000000000000000000000000000000000000000000000000000000080"),
        h32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    ];
    // y ≥ p = 2^255 − 19 (little-endian, sign bit masked) iff bytes 1..31 are 0xff, byte 31 is 0x7f and byte 0 ≥ 0xed.
    let y_ge_p = pk[0] >= 0xed && pk[1..31].iter().all(|b| *b == 0xff) && pk[31] & 0x7f == 0x7f;
    !y_ge_p && !SMALL.contains(pk)
}

/// ed25519 over a message of any length (the registry passes `ua_msg`; RFC 8032 vectors pass theirs): the contract's
/// key check, then the host's `verify_strict` (canonical `S`, canonical and not small-order `R`, small-order `A`).
pub fn ed25519(env: &Env, pk: &BytesN<32>, msg: &Bytes, sig: &Bytes, e: Error) {
    if !ed25519_key_ok(&pk.to_array()) {
        panic_with_error!(env, Error::KeyData);
    }
    let s: BytesN<64> = sig.clone().try_into().unwrap_or_else(|_| panic_with_error!(env, e));
    env.crypto().ed25519_verify(pk, msg, &s);
}

/// ECDSA recovery of a 65-byte `r ‖ s ‖ v` over a host hash: `r, s ≠ 0`, `s ≤ n/2`, `v ∈ {27, 28}` (as EVM's
/// `Secp256k1Verifier` and OZ `tryRecover`), else `e`.
fn secp256k1_recover(env: &Env, msg: &Hash<32>, sig: &Bytes, e: Error) -> BytesN<65> {
    if sig.len() != 65 {
        panic_with_error!(env, e);
    }
    let mut a = [0u8; 65];
    sig.copy_into_slice(&mut a);
    let (r, s, v) = (&a[..32], &a[32..64], a[64]);
    if r == [0u8; 32] || s == [0u8; 32] || s > &HALF_N[..] || !(v == 27 || v == 28) {
        panic_with_error!(env, e);
    }
    let rs = BytesN::from_array(env, &a[..64].try_into().unwrap());
    env.crypto().secp256k1_recover(msg, &rs, (v - 27) as u32)
}

/// S10 / TS-D4 (owner decision 4): an `evm-eoa` member's portable signature, ECDSA over the record's typed digest
/// itself (`eth_signTypedData_v4`, no `personal_sign`); the recovered key's address (last 20 bytes of
/// `keccak256(x ‖ y)`) must be `id20`, else `e`.
pub fn check_evm_eoa(env: &Env, id20: &BytesN<20>, typed: &Hash<32>, sig: &Bytes, e: Error) {
    let pk: Bytes = secp256k1_recover(env, typed, sig, e).into();
    let addr = env.crypto().keccak256(&pk.slice(1..65)).to_bytes();
    if Bytes::from(addr).slice(12..32) != Bytes::from(id20.clone()) {
        panic_with_error!(env, e);
    }
}
