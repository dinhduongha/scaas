//! PQZL in pure Rust: the LaZer lattice proof system of SCaaS PQZ (pq-zero-knowledge.md §4, §5, §8), byte-for-byte
//! equal to the C core (`pqz-core/pqzl/src` + `pqzl/lazer`): same proofs for the same `(op, stmt, wit, rnd32)`, same
//! verdicts on every input, same keys / Enc / Dec. The API mirrors the C ABI `pqzl/src/pqz.h` (plan D3); every size,
//! layout and return code is copied from it. No globals: a [`Ctx`] holds what the C core keeps in static storage.
#![no_std]
#![cfg_attr(not(any(feature = "c-oracle", feature = "ctgrind")), forbid(unsafe_code))]
// only the dev-only C oracle module and the test-only memcheck client requests (ct.rs, feature ctgrind) allow it
#![cfg_attr(any(feature = "c-oracle", feature = "ctgrind"), deny(unsafe_code))]

extern crate alloc;
#[cfg(any(feature = "c-oracle", feature = "test-hooks"))]
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
#[cfg(feature = "ctgrind")]
#[doc(hidden)]
pub mod ct; // the ctgrind check's `secret` (src/bin/ct.rs): test entry point, not API
#[cfg(not(feature = "ctgrind"))]
mod ct;
#[allow(dead_code)]
mod rand;
mod keys;
#[allow(dead_code)]
mod params; // generated (plan D8): pqzl/params/to_rust.py; the parameter set's modules and `params::set`
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
/// The parameter set of this build (owner 2026-10-21: one per build, cargo feature `set-<set>`; pqz-core/params/sets/)
pub const SET: &str = params::set::SET_NAME;
/// ring dimension n = k d of the set (secret keys and encryption randomness have n coefficients)
pub const N: usize = params::set::N;
/// polys per public key / `u` (k)
pub const K: usize = params::set::K;
/// the modulus q of the set
pub const Q: u64 = params::set::Q;
/// Delta = floor(q / 2^(MBITS + 2)): the plaintext digits' scale
pub const DELTA: i64 = params::set::DELTA;
/// credits per account between refreshes
pub const K_MAX: usize = params::set::K_MAX;
/// the norm bounds ||s||, ||r|| (KeyGen / Enc thresholds) and ||e||, ||e1|| of the set
pub const BETA_S: usize = params::set::BETA_S;
pub const BETA_E: usize = params::set::BETA_E;
/// k polys x 64 coeffs x be8: a public key or `u`
pub const POLYVEC_BYTES: usize = K * 512;
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
/// wasm32: `prove` of op 7 only up to this many legs, more is `Error::Input` before any work (= pqz-ffi's
/// `WASM_PQZL_MAX_LEGS` on this backend); verify takes every M. 8 since port plan Task 12 (owner 2026-10-18, "if it is
/// enough, raise it"; run `d6`: the M = 8 wasm32 prove peaks at 117.4 MiB, under the 255.6 MiB the C core's M = 4
/// takes; the C core keeps 4, CTR-PQZ-09). Feature `wasm-m8` (bench builds only) lifts it to `TXM_MAX_LEGS` (16 with
/// `oversize`)
pub const WASM_MAX_LEGS: usize = if cfg!(feature = "wasm-m8") { TXM_MAX_LEGS } else { 8 };
/// the set's PQZL proofSystemId: keccak256 of its set.toml label `pqzl_id` (gen_set.py, rust/set.rs; plan 5h Task 8d:
/// one id per set, `.../mlwe-d64k<k>-q<log2q>l4/v4`; v3 and v2 are retired, CTR-PQZ-09). The core only hashes it
pub const PROOF_SYSTEM_ID: [u8; 32] = params::set::PQZL_ID;

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
/// here also, through [`Wiped`], the prover's secret copies and mask seeds; the AES-CTR key schedule and the SHAKE
/// sponges are cleared on drop, `rand::aes_ctr` / `rand::shake`, as C's `_aes256ctr_clear` / `_shake128_clear`).
/// Platform boundary (review H-2, 2026-10-19): best effort, not guaranteed. It is plain stores plus `black_box`; a
/// volatile write needs `unsafe` (forbidden outside `c-oracle`) and `zeroize` is a dependency (D1), so the compiler
/// is not bound to keep the stores (`black_box` on the cleared buffer makes eliding them unlikely), and copies it made
/// itself (moves of arrays and `Wiped` values, register spills, stack temporaries) are never cleared. Also cleared,
/// as the C core does since Q-B (`d08e3f9`; review A-3, 2026-10-20): the key helpers' secret key, noise and encryption
/// randomness (`keys::keypair_from_secret`, `encrypt_raw` with each pk^T r, `decrypt_raw`'s key and plaintext, the
/// rejected samples of `keygen` / `enc_seed` on their error exits) and the witness parsing's values (`rel::dec_w`,
/// `debit_witness`, `dr_witness`, `set_upsilon`). Not cleared (C clears them since Q-B with its arena,
/// `pqz_arena_wipe_release`; a gap of this crate): the masks y / y3 / y4 and the z vectors built from them, `r_times`'
/// products R·s3 / R'·s4, and the `coeffvec` copies inside the rejection step.
pub(crate) fn wipe<T: Default>(x: &mut [T]) {
    x.iter_mut().for_each(|e| *e = T::default());
    core::hint::black_box(&*x);
}

/// A prover secret (a witness copy, a mask seed) that [`wipe`]s itself when dropped, so every exit, `?` included,
/// clears it (review G-2 / H-2, fix B). Same best-effort boundary as `wipe`.
pub(crate) struct Wiped<T: Wipe>(pub(crate) T);

pub(crate) trait Wipe {
    fn wipe(&mut self);
}

impl<T: Default, const N: usize> Wipe for [T; N] {
    fn wipe(&mut self) {
        wipe(&mut self[..]);
    }
}

impl<T: Default> Wipe for alloc::vec::Vec<T> {
    fn wipe(&mut self) {
        wipe(&mut self[..]);
    }
}

impl<T: Wipe> Wipe for alloc::boxed::Box<T> {
    fn wipe(&mut self) {
        (**self).wipe();
    }
}

impl Wipe for arith::poly::Poly {
    fn wipe(&mut self) {
        wipe(core::slice::from_mut(self));
    }
}

impl Wipe for arith::polyvec::PolyVec {
    fn wipe(&mut self) {
        wipe(&mut self[..]);
    }
}

impl<T: Wipe> Drop for Wiped<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

impl<T: Wipe> Wiped<T> {
    /// The value, not wiped: its owner now holds the secret (an output); `blank` takes its place (review A-3)
    pub(crate) fn take(mut self, blank: T) -> T {
        core::mem::replace(&mut self.0, blank)
    }
}

impl<T: Wipe> core::ops::Deref for Wiped<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Wipe> core::ops::DerefMut for Wiped<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
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
    pub fn keypair_from_secret(&mut self, s: &[i8; N], e: &[i16; N]) -> Result<Box<[u8; POLYVEC_BYTES]>, Error> {
        keys::keypair_from_secret(&mut self.a, s, e)
    }

    /// [`encrypt`] with this `Ctx`'s A: same arguments, same result.
    pub fn encrypt(
        &mut self,
        pks: &[&[u8; POLYVEC_BYTES]],
        msgs: &[[u8; 16]],
        r: &[i8; N],
        e1: &[i16; N],
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
    pub s: Box<[i8; N]>,
    pub e: Box<[i16; N]>,
    /// the counter of the accepted attempt
    pub ctr: u32,
}

/// One encryption to `vs.len()` recipients (`pqz_enc_seed`'s outputs): `u`, one `v` per recipient, the short vectors.
pub struct Enc {
    pub u: Box<[u8; POLYVEC_BYTES]>,
    pub vs: Vec<[u8; V_BYTES]>,
    pub r: Box<[i8; N]>,
    pub e1: Box<[i16; N]>,
    pub e2: Vec<[i16; 16]>,
    /// the counter of the accepted attempt
    pub ctr: u32,
}

/// `pqz_keypair_from_secret`: pk = A s + e (no norm check).
pub fn keypair_from_secret(s: &[i8; N], e: &[i16; N]) -> Result<Box<[u8; POLYVEC_BYTES]>, Error> {
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
    r: &[i8; N],
    e1: &[i16; N],
    e2: &[[i16; 16]],
) -> Result<Enc, Error> {
    keys::encrypt(&mut None, pks, msgs, r, e1, e2)
}

/// `pqz_decrypt_raw`: w_i = centre(v_i - (u^T s)_i).
pub fn decrypt_raw(s: &[i8; N], u: &[u8; POLYVEC_BYTES], v: &[u8; V_BYTES]) -> Result<[i64; 16], Error> {
    keys::decrypt_raw(s, &u[..], &v[..])
}

/// `pqz_dec` of ct = u || v: the 16 digits M_i = round(w_i / Delta) and their noise w_i - Delta M_i.
pub fn dec(s: &[i8; N], ct: &[u8; CT_BYTES]) -> Result<([i64; 16], [i64; 16]), Error> {
    keys::dec(s, ct)
}

/// `pqz_test_mutate` (test hook): decode `proof` for relation `rel` (an op, 0x81 = R_TX0, or an R_TXM shape code),
/// change one field (`kind` 0..15 with `r1` / `r2`; any other kind re-encodes only) and re-encode. `Ok(None)` where
/// C returns 0: an unknown relation, a proof that does not decode, an encoding that does not fit 2 MAX_PROOF bytes.
#[cfg(feature = "test-hooks")]
pub fn test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Result<Option<Vec<u8>>, Error> {
    coder::test_mutate(rel, proof, kind, r1, r2)
}

/// The P6-FS trace (test hook, lazer#28; = the C core's `pqz_sz_trace_fn` kinds under `PQZ_SZ_TRACE`): which seed
/// each Fiat–Shamir challenge of this thread's `prove` / `verify` / `verify_fast` calls was derived from, as
/// `(kind, seed, dom)`: 2 / 3 = seed and dom of the z4 / z3 matrix V4 / V3, 5 = the seed of mu (and, in the generic
/// code, of the final challenge), dom 0; the specialised verifier (`sv.rs`) records kind + 10. Returns the records since the last call and clears them. Off until this
/// thread's first call (which returns nothing): other test-hooks builds (pqz-ffi `fuzz`, the fault hooks) never call
/// it, so they never record.
#[cfg(feature = "test-hooks")]
pub fn fs_trace_take() -> Vec<fstrace::Rec> {
    fstrace::T.with(|t| t.borrow_mut().replace(Vec::new()).unwrap_or_default())
}

#[cfg(feature = "test-hooks")]
pub mod fstrace {
    use alloc::vec::Vec;
    use core::cell::RefCell;

    /// (kind, seed, dom)
    pub type Rec = (u8, [u8; 32], u64);

    std::thread_local! {
        /// None = off (see `fs_trace_take`)
        pub(crate) static T: RefCell<Option<Vec<Rec>>> = const { RefCell::new(None) };
    }

    /// one record while on; dropped if the allocation fails (tests/memory.rs denies allocations: no abort here, and
    /// fs_bind counts a missing record as a failure)
    pub(crate) fn rec(kind: u8, seed: &[u8; 32], dom: u64) {
        T.with(|t| {
            if let Some(t) = t.borrow_mut().as_mut() {
                if t.try_reserve(1).is_ok() {
                    t.push((kind, *seed, dom));
                }
            }
        });
    }
}

/// Review A's cheating prover (A-1 = review B's B-1; the regression fixture `tests/cheat_b1.rs`, test hook): this
/// thread's `prove` calls, with `mode` 0 honest, 1 `z4[0][0] += 1` cancelled through g, 2 `z3 = y3` (no `β3·R·s3`)
/// cancelled through g, 3 `z4[0][0] += 1` not cancelled (control). The cancellation folds the z3 / z4 error with the V
/// the cheater can know before `tg`, i.e. V seeded from hz (`tbox::prove`); since B-1 V is drawn after `tg`, so the
/// proofs of modes 1 and 2 no longer verify. Never set in a production build (no `test-hooks`: always 0).
#[cfg(feature = "test-hooks")]
pub fn set_cheat(mode: u32) {
    CHEAT.with(|c| c.set(mode))
}

#[cfg(feature = "test-hooks")]
std::thread_local! {
    static CHEAT: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// the mode `set_cheat` gave this thread; only with test-hooks (8a review m3: no production build has it, so no
/// cheating step can be reached from one)
#[cfg(feature = "test-hooks")]
pub(crate) fn cheat() -> u32 {
    CHEAT.with(|c| c.get())
}
