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
    fn pqz_keypair_from_secret(s: *const i8, e: *const i16, pk: *mut u8) -> i32;
    fn pqz_encrypt(pks: *const *const u8, npk: u32, msgs: *const [u8; 16], r: *const i8, e1: *const i16,
                   e2: *const [i16; 16], u: *mut u8, vs: *mut [u8; V_BYTES]) -> i32;
    fn pqz_decrypt_raw(s: *const i8, u: *const u8, v: *const u8, w: *mut i64) -> i32;
    fn pqz_enc_group_seed(seed_enc: *const u8, g: u32, out: *mut u8);
    fn pqz_ntt_fwd(c: *mut u64);
    fn pqz_ntt_inv(c: *mut u64);
    fn pqz_ntt_basemul(r: *mut u64, a: *const u64, b: *const u64);
    fn pqz_shim_polyvec_ops(input: *const i64, out: *mut u64, n: *mut usize) -> i32;
    fn pqz_shim_int_ops(input: *const u64, out: *mut u64, n: *mut usize) -> i32;
    fn pqz_shim_rng(seed: *const u8, dom: u64, lens: *const u32, nlens: usize, out: *mut u8) -> i32;
    fn pqz_shim_shake(which: u32, input: *const u8, alens: *const u32, na: usize, slens: *const u32, ns: usize,
                      out: *mut u8) -> i32;
    fn pqz_shim_grandom(seed: *const u8, dom: u32, log2o: u32, n: u32, out: *mut i64) -> i32;
    fn pqz_shim_rej(bimodal: u32, seed: *const u8, dom: u64, z: *const i64, v: *const i64, n: u32, scm: *const u64,
                    s2: *const u64, rej: *mut i32, next8: *mut u8) -> i32;
    fn pqz_shim_urandom(seed: *const u8, dom: u32, n: u32, nl: u32, m: *const u64, log2mod: u32, out: *mut u64,
                        nout: *mut usize) -> i32;
    fn pqz_shim_urandom_bnd(seed: *const u8, dom: u32, n: u32, nl: u32, lo: *const u64, hi: *const u64, out: *mut u64,
                            nout: *mut usize) -> i32;
    fn pqz_shim_autostable(seed: *const u8, dom: u32, bnd: i64, log2: u32, out: *mut u64) -> i32;
    fn pqz_shim_params(i: u32, out: *mut u64, n: *mut usize) -> i32;
    fn pqz_shim_ghint(i: u32, inp: *const i64, out: *mut u64) -> i32;
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

pub fn c_keypair_from_secret(s: &[i8; 2048], e: &[i16; 2048]) -> Result<Box<[u8; POLYVEC_BYTES]>, Error> {
    let mut pk = Box::new([0u8; POLYVEC_BYTES]);
    // SAFETY: fixed-size inputs and output of the sizes pqz.h declares
    rc(with_core(|| unsafe { pqz_keypair_from_secret(s.as_ptr(), e.as_ptr(), pk.as_mut_ptr()) }))?;
    Ok(pk)
}

/// `pqz_encrypt`'s outputs: u and one v per recipient
pub type UVs = (Box<[u8; POLYVEC_BYTES]>, Vec<[u8; V_BYTES]>);

/// `pqz_encrypt` -> (u, vs); `Err(Input)` if `msgs` / `e2` and `pks` differ in length (one count in the C ABI).
pub fn c_encrypt(pks: &[&[u8; POLYVEC_BYTES]], msgs: &[[u8; 16]], r: &[i8; 2048], e1: &[i16; 2048], e2: &[[i16; 16]])
                 -> Result<UVs, Error> {
    let n = pks.len();
    let npk = u32::try_from(n).map_err(|_| Error::Input)?;
    if msgs.len() != n || e2.len() != n {
        return Err(Error::Input);
    }
    let (mut u, mut vs) = (Box::new([0u8; POLYVEC_BYTES]), vec![[0u8; V_BYTES]; n]);
    let ptrs: Vec<usize> = pks.iter().map(|p| p.as_ptr() as usize).collect(); // usize: Send across the thread
    // SAFETY: n public keys of POLYVEC_BYTES, n messages / e2 vectors / vs outputs, fixed-size r, e1, u
    rc(with_core(|| unsafe {
        pqz_encrypt(ptrs.as_ptr().cast(), npk, msgs.as_ptr(), r.as_ptr(), e1.as_ptr(), e2.as_ptr(), u.as_mut_ptr(),
                    vs.as_mut_ptr())
    }))?;
    Ok((u, vs))
}

pub fn c_decrypt_raw(s: &[i8; 2048], u: &[u8; POLYVEC_BYTES], v: &[u8; V_BYTES]) -> Result<[i64; 16], Error> {
    let mut w = [0i64; 16];
    // SAFETY: fixed-size inputs and output of the sizes pqz.h declares
    rc(with_core(|| unsafe { pqz_decrypt_raw(s.as_ptr(), u.as_ptr(), v.as_ptr(), w.as_mut_ptr()) }))?;
    Ok(w)
}

pub fn c_enc_group_seed(seed_enc: &[u8; 32], g: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: 32-byte input and output
    with_core(|| unsafe { pqz_enc_group_seed(seed_enc.as_ptr(), g, out.as_mut_ptr()) });
    out
}

/// `pqz_test_mutate` (C built with PQZ_TEST_HOOKS): `Some` (C returns 1) the mutated proof, `None` (0) if the proof
/// does not decode or the result does not re-encode. The hook clears the sticky error itself and returns only 1 or 0,
/// so there is no error to report; any other return value is a broken contract and panics.
#[cfg(feature = "test-hooks")]
pub fn c_test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 2 * MAX_PROOF]; // the hook's own buffer size
    let mut n = out.len();
    // SAFETY: proof with its length; out has room for 2 * MAX_PROOF bytes
    let ok = with_core(|| unsafe {
        pqz_test_mutate(rel, proof.as_ptr(), proof.len(), kind, r1, r2, out.as_mut_ptr(), &mut n)
    });
    match ok {
        1 => {
            assert!(n <= out.len(), "c_test_mutate: length {n}");
            out.truncate(n);
            Some(out)
        }
        0 => None,
        r => panic!("c_test_mutate: pqz_test_mutate returned {r}"),
    }
}

/// `pqz_shim_ghint`: relation i's (`c_params` order) `poly_dcompress_use_ghint (y, r)` and
/// `poly_dcompress_make_ghint (z, r)` on `inp` = y, z, r (64 coefficients each), as `testkit::ghint` dumps them;
/// `None` past the last relation.
pub fn c_ghint(i: u32, inp: &[i64; 192]) -> Option<Vec<u64>> {
    let mut out = vec![0u64; 2 * 66];
    // SAFETY: 192 input words, 132 output words, as the shim reads / writes
    let r = with_core(|| unsafe { pqz_shim_ghint(i, inp.as_ptr(), out.as_mut_ptr()) });
    match r {
        0 => Some(out),
        -1 => None,
        r => panic!("c_ghint: rc {r}"),
    }
}

/// `pqz_ntt_fwd` (no core state: called directly)
pub fn c_ntt_fwd(c: &mut [u64; 64]) {
    // SAFETY: 64 words, as the C function takes
    unsafe { pqz_ntt_fwd(c.as_mut_ptr()) }
}

/// `pqz_shim_params`: relation `i`'s parameters as the C compiler reads the generated header (`testkit::params_words`'
/// layout); `None` past the last relation. Static data: no core state, no lock.
pub fn c_params(i: u32) -> Option<Vec<u64>> {
    let mut out = vec![0u64; 4096];
    let mut n = 0usize;
    // SAFETY: out has room for 4,096 words (a relation needs about 1,000)
    if unsafe { pqz_shim_params(i, out.as_mut_ptr(), &mut n) } != 0 {
        return None;
    }
    out.truncate(n);
    Some(out)
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

/// `pqz_shim_rng` (tests/oracle_shim.c), the C half of `testkit::rand_rng`; every length > 0 (else C's assert)
pub fn c_rng(seed: &[u8; 32], dom: u64, lens: &[u32]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; lens.iter().map(|&l| l as usize).sum()];
    // SAFETY: out has room for the sum of lens
    rc(with_core(|| unsafe { pqz_shim_rng(seed.as_ptr(), dom, lens.as_ptr(), lens.len(), out.as_mut_ptr()) }))?;
    Ok(out)
}

/// `pqz_shim_shake`, the C half of `testkit::rand_shake`; `alens` sum to `input.len()`
pub fn c_shake(which: u32, input: &[u8], alens: &[u32], slens: &[u32]) -> Result<Vec<u8>, Error> {
    assert_eq!(alens.iter().map(|&l| l as usize).sum::<usize>(), input.len());
    let mut out = vec![0u8; slens.iter().map(|&l| l as usize).sum()];
    // SAFETY: input holds the sum of alens, out the sum of slens
    rc(with_core(|| unsafe {
        pqz_shim_shake(which, input.as_ptr(), alens.as_ptr(), alens.len(), slens.as_ptr(), slens.len(), out.as_mut_ptr())
    }))?;
    Ok(out)
}

/// `pqz_shim_grandom`, the C half of `testkit::rand_grandom` (n >= 1)
pub fn c_grandom(seed: &[u8; 32], dom: u32, log2o: u32, n: u32) -> Result<Vec<i64>, Error> {
    assert!(n >= 1);
    let mut out = vec![0i64; n as usize + 128];
    // SAFETY: out has room for n + 128 values
    rc(with_core(|| unsafe { pqz_shim_grandom(seed.as_ptr(), dom, log2o, n, out.as_mut_ptr()) }))?;
    Ok(out)
}

/// `pqz_shim_rej`, the C half of `testkit::rand_rej`: (reject, the next 8 stream bytes)
pub fn c_rej(bimodal: bool, seed: &[u8; 32], dom: u64, z: &[i64], v: &[i64], scm: &[u64; 3], s2: &[u64; 2])
             -> Result<(bool, [u8; 8]), Error> {
    assert!(!z.is_empty() && z.len() == v.len());
    let (mut rej, mut next8) = (0i32, [0u8; 8]);
    // SAFETY: z and v hold n values, scm 3 and s2 2 limbs; rej and next8 are outputs of their sizes
    rc(with_core(|| unsafe {
        pqz_shim_rej(bimodal as u32, seed.as_ptr(), dom, z.as_ptr(), v.as_ptr(), z.len() as u32, scm.as_ptr(),
                     s2.as_ptr(), &mut rej, next8.as_mut_ptr())
    }))?;
    Ok((rej != 0, next8))
}

/// `pqz_shim_urandom`, the C half of `testkit::rand_urandom` (`m`: 3 limbs, sign, nlimbs 1..=3)
pub fn c_urandom(seed: &[u8; 32], dom: u32, n: u32, nl: u32, m: &[u64; 5], log2mod: u32) -> Result<Vec<u64>, Error> {
    assert!(n >= 1 && (1..=3).contains(&nl) && (1..=3).contains(&m[4]));
    let mut out = vec![0u64; n as usize * 4 + 256];
    let mut len = 0usize;
    // SAFETY: m has 5 words; out has room for n (nl + 1) + 256 words
    rc(with_core(|| unsafe { pqz_shim_urandom(seed.as_ptr(), dom, n, nl, m.as_ptr(), log2mod, out.as_mut_ptr(), &mut len) }))?;
    out.truncate(len);
    Ok(out)
}

/// `pqz_shim_urandom_bnd`, the C half of `testkit::rand_urandom_bnd` (`lo`, `hi` as `m` of [`c_urandom`])
pub fn c_urandom_bnd(seed: &[u8; 32], dom: u32, n: u32, nl: u32, lo: &[u64; 5], hi: &[u64; 5]) -> Result<Vec<u64>, Error> {
    assert!(n >= 1 && (1..=3).contains(&nl) && (1..=3).contains(&lo[4]) && (1..=3).contains(&hi[4]));
    let mut out = vec![0u64; n as usize * 4 + 128];
    let mut len = 0usize;
    // SAFETY: lo and hi have 5 words; out has room for n (nl + 1) + 128 words
    rc(with_core(|| unsafe {
        pqz_shim_urandom_bnd(seed.as_ptr(), dom, n, nl, lo.as_ptr(), hi.as_ptr(), out.as_mut_ptr(), &mut len)
    }))?;
    out.truncate(len);
    Ok(out)
}

/// `pqz_shim_autostable`, the C half of `testkit::rand_autostable`
pub fn c_autostable(seed: &[u8; 32], dom: u32, bnd: i64, log2: u32) -> Result<Vec<u64>, Error> {
    let mut out = vec![0u64; 64];
    // SAFETY: out has room for 64 words
    rc(with_core(|| unsafe { pqz_shim_autostable(seed.as_ptr(), dom, bnd, log2, out.as_mut_ptr()) }))?;
    Ok(out)
}
