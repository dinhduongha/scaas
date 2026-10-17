//! The C core as the oracle (feature `c-oracle`, dev / test only): safe wrappers over libpqz as build.rs compiles it
//! (build.sh's flags), with this crate's types, so tests compare the two implementations call for call.
//!
//! The C core keeps its arena, sticky error and caches in globals, so every call takes one process-wide lock and runs
//! on a thread with a 16 MiB stack (the prover's frames exceed a test thread's 2 MiB), as `pqz-ffi::pqzl` does. The
//! core is initialised at the first call on a 1 GiB arena (pqz-ffi's prover arena: `R_TXM8` prove peaks at 836 MB)
//! and kept for the process; untouched pages stay unmapped. Setup failures (arena, `pqz_init`, thread) panic: the
//! oracle is test code and must never pass a failure off as a verdict.
use crate::{Enc, Error, Key, CT_BYTES, MAX_PROOF, POLYVEC_BYTES, V_BYTES};
use std::boxed::Box;
use std::sync::Mutex;
use std::vec;
use std::vec::Vec;

extern "C" {
    fn pqz_init(arena: *mut u8, len: usize) -> i32;
    fn pqz_prove(op: u8, stmt: *const u8, stmt_len: usize, wit: *const u8, wit_len: usize, rnd32: *const u8,
                 proof: *mut u8, proof_len: *mut usize) -> i32;
    fn pqz_verify(op: u8, stmt: *const u8, stmt_len: usize, proof: *const u8, proof_len: usize) -> i32;
    fn pqz_verify_fast(op: u8, stmt: *const u8, stmt_len: usize, proof: *const u8, proof_len: usize) -> i32;
    fn pqz_keygen(seed32: *const u8, pk: *mut u8, s: *mut i8, e: *mut i16, ctr: *mut u32) -> i32;
    fn pqz_enc_seed(pks: *const *const u8, npk: u32, msgs: *const [u8; 16], seed_enc: *const u8, u: *mut u8,
                    vs: *mut [u8; V_BYTES], r: *mut i8, e1: *mut i16, e2: *mut [i16; 16], ctr: *mut u32) -> i32;
    fn pqz_dec(s: *const i8, ct: *const u8, m: *mut i64, noise: *mut i64) -> i32;
    fn pqz_ntt_fwd(c: *mut u64);
    fn pqz_ntt_inv(c: *mut u64);
    fn pqz_ntt_basemul(r: *mut u64, a: *const u64, b: *const u64);
    fn pqz_shim_polyvec_ops(input: *const i64, out: *mut u64, n: *mut usize) -> i32;
    fn pqz_shim_int_ops(input: *const u64, out: *mut u64, n: *mut usize) -> i32;
    #[cfg(feature = "test-hooks")]
    fn pqz_test_mutate(op: u8, proof: *const u8, len: usize, kind: u32, r1: u64, r2: u64, out: *mut u8,
                       outlen: *mut usize) -> i32;
}

pub const ARENA: usize = 1 << 30;
pub const STACK: usize = 16 << 20;

/// The arena (capacity only: the C core owns the bytes, Rust never reads them; 16-byte aligned); `None` before the
/// first call.
static CORE: Mutex<Option<Vec<u128>>> = Mutex::new(None);

/// Runs `f` under the lock on a 16 MiB-stack thread with the core initialised.
// ponytail: one thread per call (scoped, so `f` may borrow); a persistent worker as pqz-ffi's if call overhead matters
fn with_core<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    let mut guard = CORE.lock().unwrap_or_else(|e| e.into_inner());
    let core: &mut Option<Vec<u128>> = &mut guard;
    std::thread::scope(|sc| {
        std::thread::Builder::new()
            .name("pqz-oracle".into())
            .stack_size(STACK)
            .spawn_scoped(sc, || {
                if core.is_none() {
                    let mut arena: Vec<u128> = Vec::new();
                    arena.try_reserve_exact(ARENA / 16).expect("c_oracle: arena");
                    // SAFETY: the arena lives in CORE for the rest of the process, and every libpqz call runs under
                    // CORE's lock
                    assert_eq!(unsafe { pqz_init(arena.as_mut_ptr().cast(), ARENA) }, 0, "c_oracle: pqz_init");
                    *core = Some(arena);
                }
                f()
            })
            .expect("c_oracle: thread")
            .join()
            .expect("c_oracle: call panicked")
    })
}

/// A C return code as this crate's `Error` (`pqz_rt.h`).
fn rc(code: i32) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        2 => Err(Error::Memory),
        3 => Err(Error::Input),
        4 => Err(Error::Reject),
        _ => Err(Error::Internal),
    }
}

pub fn c_prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, Error> {
    let mut proof = vec![0u8; MAX_PROOF];
    let mut len = proof.len();
    // SAFETY: every pointer / length pair describes a live buffer; proof has room for MAX_PROOF bytes
    rc(with_core(|| unsafe {
        pqz_prove(op, stmt.as_ptr(), stmt.len(), wit.as_ptr(), wit.len(), rnd32.as_ptr(), proof.as_mut_ptr(), &mut len)
    }))?;
    proof.truncate(len);
    Ok(proof)
}

pub fn c_verify(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    // SAFETY: read-only buffers with their lengths
    with_core(|| unsafe { pqz_verify(op, stmt.as_ptr(), stmt.len(), proof.as_ptr(), proof.len()) }) == 1
}

pub fn c_verify_fast(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    // SAFETY: read-only buffers with their lengths
    with_core(|| unsafe { pqz_verify_fast(op, stmt.as_ptr(), stmt.len(), proof.as_ptr(), proof.len()) }) == 1
}

pub fn c_keygen(seed32: &[u8; 32]) -> Result<Key, Error> {
    let mut k = Key { pk: Box::new([0; POLYVEC_BYTES]), s: Box::new([0; 2048]), e: Box::new([0; 2048]), ctr: 0 };
    // SAFETY: fixed-size outputs of the sizes pqz.h declares
    rc(with_core(|| unsafe {
        pqz_keygen(seed32.as_ptr(), k.pk.as_mut_ptr(), k.s.as_mut_ptr(), k.e.as_mut_ptr(), &mut k.ctr)
    }))?;
    Ok(k)
}

/// `Err(Input)` if `msgs` and `pks` differ in length (the C ABI takes one count for both).
pub fn c_enc_seed(pks: &[&[u8; POLYVEC_BYTES]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Result<Enc, Error> {
    let n = pks.len();
    let npk = u32::try_from(n).map_err(|_| Error::Input)?;
    if msgs.len() != n {
        return Err(Error::Input);
    }
    let mut c = Enc {
        u: Box::new([0; POLYVEC_BYTES]),
        vs: vec![[0; V_BYTES]; n],
        r: Box::new([0; 2048]),
        e1: Box::new([0; 2048]),
        e2: vec![[0; 16]; n],
        ctr: 0,
    };
    let ptrs: Vec<usize> = pks.iter().map(|p| p.as_ptr() as usize).collect(); // usize: Send across the thread
    // SAFETY: n public keys of POLYVEC_BYTES, n messages, n outputs each in vs / e2
    rc(with_core(|| unsafe {
        pqz_enc_seed(ptrs.as_ptr().cast(), npk, msgs.as_ptr(), seed_enc.as_ptr(), c.u.as_mut_ptr(), c.vs.as_mut_ptr(),
                     c.r.as_mut_ptr(), c.e1.as_mut_ptr(), c.e2.as_mut_ptr(), &mut c.ctr)
    }))?;
    Ok(c)
}

pub fn c_dec(s: &[i8; 2048], ct: &[u8; CT_BYTES]) -> Result<([i64; 16], [i64; 16]), Error> {
    let (mut m, mut noise) = ([0i64; 16], [0i64; 16]);
    // SAFETY: fixed-size inputs and outputs of the sizes pqz.h declares
    rc(with_core(|| unsafe { pqz_dec(s.as_ptr(), ct.as_ptr(), m.as_mut_ptr(), noise.as_mut_ptr()) }))?;
    Ok((m, noise))
}

/// `pqz_test_mutate` (C built with PQZ_TEST_HOOKS): `Ok(None)` if the proof does not decode.
#[cfg(feature = "test-hooks")]
pub fn c_test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Result<Option<Vec<u8>>, Error> {
    let mut out = vec![0u8; 2 * MAX_PROOF]; // the hook's own buffer size
    let mut n = out.len();
    // SAFETY: proof with its length; out has room for 2 * MAX_PROOF bytes
    let ok = with_core(|| unsafe {
        pqz_test_mutate(rel, proof.as_ptr(), proof.len(), kind, r1, r2, out.as_mut_ptr(), &mut n)
    });
    out.truncate(n);
    Ok((ok == 1).then_some(out))
}

/// `pqz_ntt_fwd` (no core state: called directly)
pub fn c_ntt_fwd(c: &mut [u64; 64]) {
    // SAFETY: 64 words, as the C function takes
    unsafe { pqz_ntt_fwd(c.as_mut_ptr()) }
}

/// `pqz_ntt_inv`
pub fn c_ntt_inv(c: &mut [u64; 64]) {
    // SAFETY: 64 words
    unsafe { pqz_ntt_inv(c.as_mut_ptr()) }
}

/// `pqz_ntt_basemul`
pub fn c_ntt_basemul(a: &[u64; 64], b: &[u64; 64]) -> [u64; 64] {
    let mut r = [0u64; 64];
    // SAFETY: three 64-word buffers (the C function allows aliasing; these do not)
    unsafe { pqz_ntt_basemul(r.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    r
}

/// `pqz_shim_polyvec_ops` (tests/oracle_shim.c), the C half of `testkit::polyvec_ops`
pub fn c_polyvec_ops(input: &[i64]) -> Result<Vec<u64>, Error> {
    assert_eq!(input.len(), crate::testkit::OPS_IN);
    let mut out = vec![0u64; 1 << 16]; // ~ 140 polys of 66 words
    let mut n = 0usize;
    // SAFETY: input has OPS_IN words; out has room for every word the shim writes
    rc(with_core(|| unsafe { pqz_shim_polyvec_ops(input.as_ptr(), out.as_mut_ptr(), &mut n) }))?;
    out.truncate(n);
    Ok(out)
}

/// `pqz_shim_int_ops` (tests/oracle_shim.c), the C half of `testkit::int_ops`
pub fn c_int_ops(input: &[u64; crate::testkit::INT_OPS_IN]) -> Result<Vec<u64>, Error> {
    let mut out = vec![0u64; 1024];
    let mut n = 0usize;
    // SAFETY: input has INT_OPS_IN words; out has room for every word the shim writes (~ 150)
    rc(with_core(|| unsafe { pqz_shim_int_ops(input.as_ptr(), out.as_mut_ptr(), &mut n) }))?;
    out.truncate(n);
    Ok(out)
}
