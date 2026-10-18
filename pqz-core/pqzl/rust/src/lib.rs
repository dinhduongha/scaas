//! PQZL in pure Rust: the LaZer lattice proof system of SCaaS PQZ (pq-zero-knowledge.md §4, §5, §8), byte-for-byte
//! equal to the C core (`pqz-core/pqzl/src` + `pqzl/lazer`): same proofs for the same `(op, stmt, wit, rnd32)`, same
//! verdicts on every input, same keys / Enc / Dec. The API mirrors the C ABI `pqzl/src/pqz.h` (plan D3); every size,
//! layout and return code is copied from it. No globals: a [`Ctx`] holds what the C core keeps in static storage.
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

// the arithmetic, sampling and codec layers and the generated params serve the prover and the specialised verifier
// of later tasks too; until those land, part is unused
#[allow(dead_code)]
mod arith;
#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench; // pqzl/test/pqz_bench.c's setup and steps (src/bin/bench.rs, wasm/): test entry points, not API
#[allow(dead_code)]
mod coder;
#[allow(dead_code)]
mod rand;
mod keys;
#[allow(dead_code)]
mod params; // generated (plan D8): pqzl/params/to_rust.py
mod proof;
mod rel;
#[cfg(feature = "sv")]
mod sv;
#[cfg(any(feature = "test-hooks", feature = "c-oracle"))]
#[doc(hidden)]
pub mod testkit; // test entry points (kat_dump, keys_kat, the oracle tests), not API

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
/// wasm32: `prove` of op 7 only up to this many legs, M = 8 is `Error::Input` before any work (pqz-ffi's
/// `WASM_PQZL_MAX_LEGS`, the C core's one client arena); verify takes every M. Feature `wasm-m8` (bench builds only,
/// the measurement of port plan Task 12) lifts it to `TXM_MAX_LEGS`
pub const WASM_MAX_LEGS: usize = if cfg!(feature = "wasm-m8") { TXM_MAX_LEGS } else { 4 };
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

/// Clears secret material where the C core calls `explicit_bzero` (the prover's seeds `wh` / `ex`, `pqz_dec`'s `w`;
/// here also the witness vector s1 and the commitment randomness s2). Best effort, not guaranteed: without unsafe
/// code (no volatile write) and without a zeroize crate (D1) the compiler may still elide the stores; `black_box`
/// on the cleared buffer makes that unlikely. Copies the compiler made earlier (moves, registers, spilled stack) and
/// the other intermediate buffers of the prover are not cleared, as in C (STATUS Open 8).
pub(crate) fn wipe<T: Default>(x: &mut [T]) {
    x.iter_mut().for_each(|e| *e = T::default());
    core::hint::black_box(&*x);
}

/// What the C core keeps in static storage (the matrix A, each relation's ABDLOP keys, specialised-verifier tables),
/// built lazily at first use. No globals and no interior mutability: every call takes `&mut self`, so a `Ctx` per
/// thread needs no lock, and one `Ctx` moves between threads (`Send`) behind whatever hands out the `&mut`. A call
/// that fails (also on allocation failure) leaves the caches usable: the next call rebuilds what is missing.
/// With feature `sv` a `Ctx` is about 41 KB inline (the specialised verifier's fixed tables): keep it in a `Box`, a
/// static or a thread-local rather than on a small stack or moved by value.
#[derive(Default)]
pub struct Ctx {
    /// A (K x K, NTT form), expanded at the first relation call
    a: Option<arith::polymat::PolyMat>,
    /// A1, A2', B' (NTT form) per relation (`rel::RELS` order)
    keys: [Option<[arith::polymat::PolyMat; 3]>; rel::NREL],
    /// the specialised verifier's primes and A in its form, built at the first `verify_fast`
    #[cfg(feature = "sv")]
    sv: Option<sv::Ar>,
    /// the specialised verifier's tables per relation (`rel::RELS` order)
    #[cfg(feature = "sv")]
    svrel: [Option<sv::SvRel>; rel::NREL],
}

impl Ctx {
    pub fn new() -> Ctx {
        Ctx::default()
    }

    /// `pqz_prove`: the proof for `(op, stmt, wit)` with the hedged masks from `rnd32` (CTR-PQZ-19). On wasm32, op 7
    /// with more than [`WASM_MAX_LEGS`] legs is `Error::Input`.
    pub fn prove(&mut self, op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, Error> {
        self.prove_rel(op, stmt, wit, rnd32)
    }

    /// `pqz_verify` (the generic verifier): true = 1 (valid), false = anything else (running out of memory too; a
    /// caller that must tell the two apart uses [`Ctx::try_verify`]).
    pub fn verify(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> bool {
        self.verify_rel(op, stmt, proof) == Ok(true)
    }

    /// `pqz_verify_fast` (the specialised verifier): accepts exactly the proofs `verify` accepts. False also when
    /// memory ran out ([`Ctx::try_verify_fast`] tells it apart).
    #[cfg(feature = "sv")]
    pub fn verify_fast(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> bool {
        self.verify_sv(op, stmt, proof) == Ok(true)
    }

    /// [`Ctx::verify`] with out-of-memory kept apart: `Ok(verdict)`, or `Err(Error::Memory)` when an allocation failed
    /// (a fault of the caller's machine, not a property of the input: a node must not report it as invalid, as
    /// pqz-ffi maps the C core's arena exhaustion to a node fault). `Error::Memory` is the only error; every other
    /// failure is `Ok(false)`, the verdict `verify` gives.
    pub fn try_verify(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, Error> {
        only_memory(self.verify_rel(op, stmt, proof))
    }

    /// [`Ctx::verify_fast`] with out-of-memory kept apart, as [`Ctx::try_verify`].
    #[cfg(feature = "sv")]
    pub fn try_verify_fast(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, Error> {
        only_memory(self.verify_sv(op, stmt, proof))
    }

    /// [`keygen`] with this `Ctx`'s A (expanded once, shared with its relations): same arguments, same result.
    pub fn keygen(&mut self, seed32: &[u8; 32]) -> Result<Key, Error> {
        keys::keygen(&mut self.a, seed32, keys::BS, keys::BE)
    }

    /// [`keypair_from_secret`] with this `Ctx`'s A: same arguments, same result.
    pub fn keypair_from_secret(&mut self, s: &[i8; 2048], e: &[i16; 2048]) -> Result<Box<[u8; POLYVEC_BYTES]>, Error> {
        keys::keypair_from_secret(&mut self.a, s, e)
    }

    /// [`encrypt`] with this `Ctx`'s A: same arguments, same result.
    pub fn encrypt(
        &mut self,
        pks: &[&[u8; POLYVEC_BYTES]],
        msgs: &[[u8; 16]],
        r: &[i8; 2048],
        e1: &[i16; 2048],
        e2: &[[i16; 16]],
    ) -> Result<Enc, Error> {
        keys::encrypt(&mut self.a, pks, msgs, r, e1, e2)
    }

    /// [`enc_seed`] with this `Ctx`'s A: same arguments, same result.
    pub fn enc_seed(&mut self, pks: &[&[u8; POLYVEC_BYTES]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Result<Enc, Error> {
        keys::enc_seed(&mut self.a, pks, msgs, seed_enc, (keys::BS, keys::BE, keys::B2))
    }
}

/// A verifier's result with every error but `Error::Memory` folded into the verdict false.
fn only_memory(r: Result<bool, Error>) -> Result<bool, Error> {
    match r {
        Err(Error::Memory) => Err(Error::Memory),
        r => Ok(r == Ok(true)),
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
    keys::keypair_from_secret(&mut None, s, e)
}

/// `pqz_keygen`: SHAKE256("SCAAS-PQZ-KEYGEN-V1" || seed32 || be4(ctr)), s <- CBD_1, e <- CBD_20, pk = A s + e.
pub fn keygen(seed32: &[u8; 32]) -> Result<Key, Error> {
    keys::keygen(&mut None, seed32, keys::BS, keys::BE)
}

/// `pqz_enc_seed`: one encryption of `msgs[j]` (16 digits < 16) to `pks[j]` from `seed_enc`.
pub fn enc_seed(pks: &[&[u8; POLYVEC_BYTES]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Result<Enc, Error> {
    keys::enc_seed(&mut None, pks, msgs, seed_enc, (keys::BS, keys::BE, keys::B2))
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
    keys::encrypt(&mut None, pks, msgs, r, e1, e2)
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
