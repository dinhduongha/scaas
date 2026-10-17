//! PQZL in pure Rust: the LaZer lattice proof system of SCaaS PQZ (pq-zero-knowledge.md §4, §5, §8), byte-for-byte
//! equal to the C core (`pqz-core/pqzl/src` + `pqzl/lazer`): same proofs for the same `(op, stmt, wit, rnd32)`, same
//! verdicts on every input, same keys / Enc / Dec. The API mirrors the C ABI `pqzl/src/pqz.h` (plan D3); every size,
//! layout and return code is copied from it. No globals: a [`Ctx`] holds what the C core keeps in static storage.
//!
//! Port in progress: a function whose task has not landed yet returns `Err(Error::Internal)` / `false`.
#![no_std]
#![cfg_attr(not(feature = "c-oracle"), forbid(unsafe_code))]
#![cfg_attr(feature = "c-oracle", deny(unsafe_code))] // only the dev-only C oracle module allows it

extern crate alloc;
#[cfg(feature = "c-oracle")]
extern crate std;

use alloc::boxed::Box;
use alloc::vec::Vec;

#[cfg(feature = "c-oracle")]
#[allow(unsafe_code)]
pub mod c_oracle;

// the arithmetic, sampling and codec layers and the generated params serve the proof layers of later tasks; until
// those land, part is unused
#[allow(dead_code)]
mod arith;
#[allow(dead_code)]
mod coder;
#[allow(dead_code)]
mod rand;
mod keys;
#[allow(dead_code)]
mod params; // generated (plan D8): pqzl/params/to_rust.py
#[doc(hidden)]
pub mod testkit;

pub const OP_TRANSFER: u8 = 1;
pub const OP_BURN: u8 = 2;
pub const OP_REGISTER: u8 = 3;
pub const OP_DISCLOSE_SENDER: u8 = 4;
pub const OP_DISCLOSE_RECEIVER: u8 = 5;
pub const OP_TRANSFER_MULTI: u8 = 7;
/// MAX_PROOF (pq-zero-knowledge.md §8)
pub const MAX_PROOF: usize = 98_304;
/// 32 polys x 64 coeffs x be8: a public key or `u`
pub const POLYVEC_BYTES: usize = 16_384;
/// 16 coeffs x be8: one `v`
pub const V_BYTES: usize = 128;
/// ciphertext `u || v`
pub const CT_BYTES: usize = POLYVEC_BYTES + V_BYTES;
/// opTag || proofSystemId
pub const PREFIX_BYTES: usize = 64;
/// debit statement header (pq-zero-knowledge.md §7.7)
pub const HEADER_BYTES: usize = 640;
/// R_TXM legs built (16 only with feature `oversize`, bench builds)
pub const TXM_MAX_LEGS: usize = if cfg!(feature = "oversize") { 16 } else { 8 };
/// keccak256("scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2") (CTR-PQZ-09)
pub const PROOF_SYSTEM_ID: [u8; 32] = [
    0x2e, 0x07, 0xe6, 0xed, 0x1f, 0xd3, 0x03, 0xa0, 0x8c, 0x89, 0xb3, 0xea, 0xb6, 0xe8, 0x42, 0x3f, 0xdf, 0xb8, 0xf3, 0x12,
    0x02, 0x95, 0x8d, 0xd6, 0x82, 0xa0, 0x61, 0x93, 0x13, 0x79, 0x8c, 0x2f,
];

/// The C core's return codes (`pqz_rt.h`, D3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// PQZ_ERR_INTERNAL (1): an upstream ERR / ASSERT condition fired
    Internal,
    /// PQZ_ERR_INPUT (3): malformed input
    Input,
    /// PQZ_ERR_REJECT (4): a rejection-sampling loop hit its cap
    Reject,
    /// an allocation failed (the C core's PQZ_ERR_ARENA, 2: arena exhausted)
    Memory,
}

/// What the C core keeps in static storage (relation keys, specialised-verifier tables), built lazily per op.
#[derive(Default)]
pub struct Ctx {}

impl Ctx {
    pub fn new() -> Ctx {
        Ctx::default()
    }

    /// `pqz_prove`: the proof for `(op, stmt, wit)` with the hedged masks from `rnd32` (CTR-PQZ-19).
    pub fn prove(&mut self, op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let _ = (op, stmt, wit, rnd32);
        Err(Error::Internal)
    }

    /// `pqz_verify` (the generic verifier): true = 1 (valid), false = anything else.
    pub fn verify(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> bool {
        let _ = (op, stmt, proof);
        false
    }

    /// `pqz_verify_fast` (the specialised verifier): accepts exactly the proofs `verify` accepts.
    #[cfg(feature = "sv")]
    pub fn verify_fast(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> bool {
        let _ = (op, stmt, proof);
        false
    }
}

/// A key pair from a seed (pq-zero-knowledge.md §4.2, `pqz_keygen`).
pub struct Key {
    pub pk: Box<[u8; POLYVEC_BYTES]>,
    pub s: Box<[i8; 2048]>,
    pub e: Box<[i16; 2048]>,
    /// the counter of the accepted attempt
    pub ctr: u32,
}

/// One encryption to `vs.len()` recipients (`pqz_enc_seed`'s outputs): `u`, one `v` per recipient, the short vectors.
pub struct Enc {
    pub u: Box<[u8; POLYVEC_BYTES]>,
    pub vs: Vec<[u8; V_BYTES]>,
    pub r: Box<[i8; 2048]>,
    pub e1: Box<[i16; 2048]>,
    pub e2: Vec<[i16; 16]>,
    /// the counter of the accepted attempt
    pub ctr: u32,
}

/// `pqz_keypair_from_secret`: pk = A s + e (no norm check).
pub fn keypair_from_secret(s: &[i8; 2048], e: &[i16; 2048]) -> Result<Box<[u8; POLYVEC_BYTES]>, Error> {
    keys::keypair_from_secret(s, e)
}

/// `pqz_keygen`: SHAKE256("SCAAS-PQZ-KEYGEN-V1" || seed32 || be4(ctr)), s <- CBD_1, e <- CBD_20, pk = A s + e.
pub fn keygen(seed32: &[u8; 32]) -> Result<Key, Error> {
    keys::keygen(seed32, keys::BS, keys::BE)
}

/// `pqz_enc_seed`: one encryption of `msgs[j]` (16 digits < 16) to `pks[j]` from `seed_enc`.
pub fn enc_seed(pks: &[&[u8; POLYVEC_BYTES]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Result<Enc, Error> {
    keys::enc_seed(pks, msgs, seed_enc, (keys::BS, keys::BE, keys::B2))
}

/// `pqz_enc_group_seed`: R_TXM group `g`'s seed (seed_enc for g = 0, else SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" ||
/// seed_enc || be4(g))[0..32)).
pub fn enc_group_seed(seed_enc: &[u8; 32], g: u32) -> [u8; 32] {
    keys::enc_group_seed(seed_enc, g)
}

/// `pqz_encrypt`: encryption with chosen short vectors (no norm check).
pub fn encrypt(
    pks: &[&[u8; POLYVEC_BYTES]],
    msgs: &[[u8; 16]],
    r: &[i8; 2048],
    e1: &[i16; 2048],
    e2: &[[i16; 16]],
) -> Result<Enc, Error> {
    keys::encrypt(pks, msgs, r, e1, e2)
}

/// `pqz_decrypt_raw`: w_i = centre(v_i - (u^T s)_i).
pub fn decrypt_raw(s: &[i8; 2048], u: &[u8; POLYVEC_BYTES], v: &[u8; V_BYTES]) -> Result<[i64; 16], Error> {
    keys::decrypt_raw(s, &u[..], &v[..])
}

/// `pqz_dec` of ct = u || v: the 16 digits M_i = round(w_i / Delta) and their noise w_i - Delta M_i.
pub fn dec(s: &[i8; 2048], ct: &[u8; CT_BYTES]) -> Result<([i64; 16], [i64; 16]), Error> {
    keys::dec(s, ct)
}

/// `pqz_test_mutate` (test hook): decode `proof` for relation `rel` (an op, 0x81 = R_TX0, or an R_TXM shape code),
/// change one field (`kind` 0..13 with `r1` / `r2`; any other kind re-encodes only) and re-encode. `Ok(None)` where
/// C returns 0: an unknown relation, a proof that does not decode, an encoding that does not fit 2 MAX_PROOF bytes.
#[cfg(feature = "test-hooks")]
pub fn test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Result<Option<Vec<u8>>, Error> {
    coder::test_mutate(rel, proof, kind, r1, r2)
}
