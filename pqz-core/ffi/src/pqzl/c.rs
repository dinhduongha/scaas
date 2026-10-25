//! The PQZL C core (libpqz, feature `pqzl-c`; the reference and the differential oracle since the Rust backend became
//! the default, CTR-PQZ-09), behind one process-wide lock (STATUS.md Open 6: the core keeps its arena, base mark,
//! sticky error and the specialised verifier's tables in globals); every libpqz call goes through `with_core`, which
//! takes the lock and runs the call on the worker (`super::on_worker`). The arena is never re-allocated on the verify
//! path.
//!
//! Arenas (allocated once, kept for the process): `ARENA_SMALL` for the precompile path (the specialised verifier of
//! all six forms and every built op 7 shape, keygen / enc / dec, the self-test), measured; `ARENA_BIG` for the prover
//! and the generic verifier. A call that needs `ARENA_BIG` re-initialises the core once on it (the core's caches are
//! rebuilt lazily); the core then stays there. wasm32 (clients) has one arena for both, so linear memory never holds
//! two, and proves PQZL op 7 only up to `WASM_PQZL_MAX_LEGS` legs.
//!
//! Node faults (controller 2026-10-14): a core or worker that cannot be set up (arena allocation, thread creation; `pqz_init`
//! on an undersized arena traps since review Q-C), a worker job that panicked, and the core running out of arena (`pqz_err == PQZ_ERR_ARENA` after a call)
//! are not properties of the input: `with_core` returns `Err(NodeFault)` (and drops the core, re-initialised at the
//! next call), which the precompile entry reports as `PQZ_FFI_NODE_FAULT` with no output. Arena exhaustion is graceful
//! only in the specialised verifier's own allocations; inside LaZer (keys, A, the prover, the generic verifier) the
//! core traps and the process stops (review round 2, Q-C: no write may follow a failed allocation), so the arenas
//! below are sized from measurement with margin.
use std::sync::Mutex;
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering::Relaxed};

use super::{on_worker, Enc, Key, NodeFault, Worker, CT_BYTES, N, PK_BYTES};

const PQZ_ERR_ARENA: i32 = 2; // pqz_rt.h

/// Test hooks (feature `test-hooks`, never in a production build): a fixed arena size for every (re)initialisation,
/// and a byte pattern written over the arena before `pqz_init` (`0x100 | byte`; 0 = none).
#[cfg(feature = "test-hooks")]
pub static TEST_ARENA_BYTES: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-hooks")]
pub static TEST_ARENA_FILL: AtomicU32 = AtomicU32::new(0);

/// Verify-only arena: owner 2026-10-16 (decisions.md CTR-PQZ-10, P6-ANON L-3), 512 MiB once op 7 is in (S3); before
/// it 144 MiB for the six forms (run `ffi1f2`: adversarial peak 95,169,680 B). `tests/verify_only.rs` measures the
/// peak over the whole adversarial corpus with every form's and every op 7 shape's keys and SV tables kept, as in a
/// long-running node, and asserts a margin ≥ 1.5 × (STATUS.md, run `s3a`).
pub const ARENA_SMALL: usize = 512 << 20;
/// Prover and generic-verifier arena: native 1 GiB (controller proposal 2026-10-16, owner may override; was 448 MiB:
/// `R_TXM8` prove peaks at 836 MB with every relation's keys loaded, `rel3/runs/l3a-summary.txt`); wasm32 = `ARENA_SMALL`
/// (one arena, `WASM_PQZL_MAX_LEGS`).
pub const ARENA_BIG: usize = if cfg!(target_arch = "wasm32") { ARENA_SMALL } else { 1 << 30 };

extern "C" {
    /// written by the core (sticky error of the last call); read only through `addr_of!(..).read_volatile()`
    static mut pqz_err: i32;
    fn pqz_init(arena: *mut u8, len: usize) -> i32;
    fn pqz_arena_peak_bytes() -> usize;
    fn pqz_arena_used() -> usize;
    fn pqz_verify(op: u8, stmt: *const u8, stmt_len: usize, proof: *const u8, proof_len: usize) -> i32;
    fn pqz_verify_fast(op: u8, stmt: *const u8, stmt_len: usize, proof: *const u8, proof_len: usize) -> i32;
    fn pqz_keypair_from_secret(s: *const i8, e: *const i16, pk: *mut u8) -> i32;
    fn pqz_keygen(seed32: *const u8, pk: *mut u8, s: *mut i8, e: *mut i16, ctr: *mut u32) -> i32;
    fn pqz_enc_seed_win(
        pks: *const *const u8,
        npk: u32,
        win: *const u8,
        msgs: *const [u8; 16],
        seed_enc: *const u8,
        u: *mut u8,
        vs: *mut [u8; 128],
        r: *mut i8,
        e1: *mut i16,
        e2: *mut [i16; 16],
        ctr: *mut u32,
    ) -> i32;
    #[cfg(feature = "prove")]
    fn pqz_encrypt_win(
        pks: *const *const u8,
        npk: u32,
        win: *const u8,
        msgs: *const [u8; 16],
        r: *const i8,
        e1: *const i16,
        e2: *const [i16; 16],
        u: *mut u8,
        vs: *mut [u8; 128],
    ) -> i32;
    fn pqz_dec_win(s: *const i8, ct: *const u8, win: u32, m: *mut i64, noise: *mut i64) -> i32;
    fn pqz_enc_group_seed(seed_enc: *const u8, g: u32, out: *mut u8);
    #[cfg(feature = "fuzz")]
    fn pqz_test_mutate(op: u8, proof: *const u8, len: usize, kind: u32, r1: u64, r2: u64, out: *mut u8, outlen: *mut usize) -> i32;
    #[cfg(feature = "prove")]
    fn pqz_prove(
        op: u8,
        stmt: *const u8,
        stmt_len: usize,
        wit: *const u8,
        wit_len: usize,
        rnd32: *const u8,
        proof: *mut u8,
        proof_len: *mut usize,
    ) -> i32;
}

struct Core {
    /// capacity only (len 0): the C core owns the bytes, Rust never reads them; 16-byte aligned, as the arena's
    /// blocks are; untouched pages stay unmapped until the core uses them
    arena: Vec<u128>,
}

struct State {
    core: Option<Core>,
    worker: Option<Worker>,
}

static STATE: Mutex<State> = Mutex::new(State { core: None, worker: None });

/// Runs `f` under the lock, on the worker, with the core initialised on an arena of at least `need` bytes.
/// `Err(NodeFault)` if the core or the worker cannot be set up, `f` panicked, or the core ran out of arena; the core is
/// then dropped (re-initialised at the next call). A poisoned lock is recovered and the core re-initialised.
fn with_core<T: Send>(need: usize, f: impl FnOnce() -> T + Send) -> Result<T, NodeFault> {
    let mut g = STATE.lock().unwrap_or_else(|e| {
        STATE.clear_poison();
        let mut g = e.into_inner();
        g.core = None;
        g
    });
    let State { core, worker } = &mut *g;
    let r = on_worker(worker, || -> Option<T> {
        #[cfg(feature = "test-hooks")]
        let need = match TEST_ARENA_BYTES.load(Relaxed) {
            0 => need,
            n => n,
        };
        if core.as_ref().is_none_or(|c| c.arena.capacity() * 16 < need) {
            *core = None; // drop the old arena first
            let mut arena: Vec<u128> = Vec::new();
            arena.try_reserve_exact(need.div_ceil(16)).ok()?;
            #[cfg(feature = "test-hooks")]
            if let f @ 0x100.. = TEST_ARENA_FILL.load(Relaxed) {
                // SAFETY: within the reserved capacity; the bytes stay the core's (Rust never reads them)
                unsafe { arena.as_mut_ptr().cast::<u8>().write_bytes(f as u8, need) };
            }
            // SAFETY: the arena outlives every libpqz call (it is replaced only here, under the lock, after pqz_init
            // on the new one resets every pointer the core held into the old one)
            if unsafe { pqz_init(arena.as_mut_ptr().cast(), need) } != 0 {
                return None;
            }
            *core = Some(Core { arena });
        }
        let out = f();
        // SAFETY: read on the thread that ran the call, under the lock (the core wrote it during `f`)
        (unsafe { std::ptr::addr_of!(pqz_err).read_volatile() } != PQZ_ERR_ARENA).then_some(out)
    });
    if !matches!(r, Some(Some(_))) {
        g.core = None; // any failure (init, worker, arena exhaustion, panic): start over on a fresh core
    }
    r.flatten().ok_or(NodeFault)
}

/// Re-initialise the core on a fresh arena of `bytes` (measurement: the verify-only peak needs a core that has never
/// proved). Test and bench hook.
#[cfg(feature = "test-hooks")]
pub fn reinit(bytes: usize) -> bool {
    STATE.lock().unwrap_or_else(|e| e.into_inner()).core = None;
    with_core(bytes, || ()).is_ok()
}

/// Arena high-water mark since the core was initialised (bytes).
pub fn arena_peak() -> usize {
    with_core(ARENA_SMALL, || unsafe { pqz_arena_peak_bytes() }).unwrap_or(0)
}

/// Arena in use between calls (bytes): the A matrix, and every relation's keys and SV tables built so far, below the
/// base mark; each call releases back to it.
pub fn arena_used() -> usize {
    with_core(ARENA_SMALL, || unsafe { pqz_arena_used() }).unwrap_or(0)
}

/// The size of the arena the core runs on (0 before the first call). Test hook.
#[cfg(feature = "test-hooks")]
pub fn arena_bytes() -> usize {
    STATE.lock().unwrap_or_else(|e| e.into_inner()).core.as_ref().map_or(0, |c| c.arena.capacity() * 16)
}

/// The precompile path (plan R5): the specialised verifier. `stmt` / `proof` are passed through as given; the caller
/// (`crate::verify`) has decoded them.
pub fn verify_fast(op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, NodeFault> {
    with_core(ARENA_SMALL, || unsafe {
        pqz_verify_fast(op, stmt.as_ptr(), stmt.len(), proof.as_ptr(), proof.len())
    })
    .map(|r| r == 1)
}

/// `verify_fast` on the caller's thread, without the worker hop (bench: the FFI's overhead against the bare call;
/// the caller's stack must be large enough). The core must be up (any earlier call). Feature `test-hooks` only: it
/// bypasses the arena-exhaustion → `NodeFault` mapping.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub fn verify_fast_on_caller(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    let g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    g.core.is_some() && unsafe { pqz_verify_fast(op, stmt.as_ptr(), stmt.len(), proof.as_ptr(), proof.len()) } == 1
}

/// `pqz_test_mutate` (pqz_rel.c test hook, feature `fuzz` only): decode `proof` for relation `rel` (an op, or 0x81
/// for `R_TX0`) with the precompile's decoder, change one field (`kind` 0..14 with `r1` / `r2`; any other kind changes
/// nothing) and re-encode. `Ok(None)`: the proof does not decode.
#[cfg(feature = "fuzz")]
pub fn test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Result<Option<Vec<u8>>, NodeFault> {
    let mut out = vec![0u8; 2 * super::MAX_PROOF];
    let mut n = out.len();
    let ok = with_core(ARENA_SMALL, || unsafe {
        pqz_test_mutate(rel, proof.as_ptr(), proof.len(), kind, r1, r2, out.as_mut_ptr(), &mut n)
    })?;
    out.truncate(n);
    Ok((ok == 1).then_some(out))
}

/// The generic verifier (LaZer's), the reference for differential tests; never on the precompile path.
pub fn verify_generic(op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, NodeFault> {
    with_core(ARENA_BIG, || unsafe { pqz_verify(op, stmt.as_ptr(), stmt.len(), proof.as_ptr(), proof.len()) })
        .map(|r| r == 1)
}

/// pk = A·s + e (`pqz_keypair_from_secret`; no norm check): the self-test reads the columns of A with it.
pub fn keypair_from_secret(s: &[i8; N], e: &[i16; N]) -> Option<Box<[u8; PK_BYTES]>> {
    let mut pk = Box::new([0u8; PK_BYTES]);
    let rc = with_core(ARENA_SMALL, || unsafe { pqz_keypair_from_secret(s.as_ptr(), e.as_ptr(), pk.as_mut_ptr()) }).ok()?;
    (rc == 0).then_some(pk)
}

pub fn keygen(seed32: &[u8; 32]) -> Option<Key> {
    let mut k = Key { pk: Box::new([0; PK_BYTES]), s: Box::new([0; N]), e: Box::new([0; N]), ctr: 0 };
    let rc = with_core(ARENA_SMALL, || unsafe {
        pqz_keygen(seed32.as_ptr(), k.pk.as_mut_ptr(), k.s.as_mut_ptr(), k.e.as_mut_ptr(), &mut k.ctr)
    })
    .ok()?;
    (rc == 0).then_some(k)
}

pub fn enc(pks: &[&[u8; PK_BYTES]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Option<Enc> {
    enc_win(pks, None, msgs, seed_enc)
}

/// `pqz_enc_seed_win`: recipient j's v at window `win[j]` < 4 (None: every window 0; R0-1)
pub fn enc_win(pks: &[&[u8; PK_BYTES]], win: Option<&[u8]>, msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Option<Enc> {
    let n = pks.len();
    if n == 0 || msgs.len() != n || win.is_some_and(|w| w.len() != n) {
        return None;
    }
    let mut c = Enc {
        u: Box::new([0; PK_BYTES]),
        vs: vec![[0; 128]; n],
        r: Box::new([0; N]),
        e1: Box::new([0; N]),
        e2: vec![[0; 16]; n],
        ctr: 0,
    };
    let rc = with_core(ARENA_SMALL, || unsafe {
        let ptrs: Vec<*const u8> = pks.iter().map(|p| p.as_ptr()).collect();
        pqz_enc_seed_win(
            ptrs.as_ptr(),
            n as u32,
            win.map_or(std::ptr::null(), |w| w.as_ptr()),
            msgs.as_ptr(),
            seed_enc.as_ptr(),
            c.u.as_mut_ptr(),
            c.vs.as_mut_ptr(),
            c.r.as_mut_ptr(),
            c.e1.as_mut_ptr(),
            c.e2.as_mut_ptr(),
            &mut c.ctr,
        )
    })
    .ok()?;
    (rc == 0).then_some(c)
}

/// `seed_enc_g` of `R_TXM` group `g` (P6-ANON D13, `pqz_enc_group_seed`): `seed_enc` for g = 0, else
/// `SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" ‖ seed_enc ‖ be4(g))[0..32)`. Pure hashing (no core state, no lock).
pub fn enc_group_seed(seed_enc: &[u8; 32], g: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: fixed-size buffers; the function reads 32 bytes and writes 32 bytes, touches no global state
    unsafe { pqz_enc_group_seed(seed_enc.as_ptr(), g as u32, out.as_mut_ptr()) };
    out
}

/// Dec of `ct = u ‖ v` (16,512 B) with `s`: the 16 digits `M` and their noise (§4.2, `pqz_dec`).
pub fn dec(s: &[i8; N], ct: &[u8; CT_BYTES]) -> Option<([i64; 16], [i64; 16])> {
    dec_win(s, ct, 0)
}

/// Dec of a v at window `win` < 4 (`pqz_dec_win`; the auditor's copy of an R_TXM leg j: win = j mod S_AUD, R0-1).
pub fn dec_win(s: &[i8; N], ct: &[u8; CT_BYTES], win: usize) -> Option<([i64; 16], [i64; 16])> {
    let (mut m, mut noise) = ([0i64; 16], [0i64; 16]);
    let w = u32::try_from(win).ok()?;
    let rc = with_core(ARENA_SMALL, || unsafe { pqz_dec_win(s.as_ptr(), ct.as_ptr(), w, m.as_mut_ptr(), noise.as_mut_ptr()) })
        .ok()?;
    (rc == 0).then_some((m, noise))
}

/// `pqz_prove`: the proof, or the core's error code (-1: a node fault, `with_core`).
#[cfg(feature = "prove")]
pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, i32> {
    let mut proof = vec![0u8; super::MAX_PROOF];
    let mut len = proof.len();
    let rc = with_core(ARENA_BIG, || unsafe {
        pqz_prove(op, stmt.as_ptr(), stmt.len(), wit.as_ptr(), wit.len(), rnd32.as_ptr(), proof.as_mut_ptr(), &mut len)
    })
    .unwrap_or(-1);
    if rc != 0 {
        return Err(rc);
    }
    proof.truncate(len);
    Ok(proof)
}

/// Encryption with chosen short vectors (`pqz_encrypt`, no norm check): `u = A^T r + e1`, `v_j = pk_j^T r + e2_j +
/// Delta m_j`. Vectors and tests only (the worst-case noise KAT builds aligned credits with it).
#[cfg(feature = "prove")]
pub fn encrypt(
    pks: &[&[u8; PK_BYTES]],
    msgs: &[[u8; 16]],
    r: &[i8; N],
    e1: &[i16; N],
    e2: &[[i16; 16]],
) -> Option<super::Encrypted> {
    encrypt_win(pks, None, msgs, r, e1, e2)
}

/// `pqz_encrypt_win` (recipient j at window `win[j]`, R0-1)
#[cfg(feature = "prove")]
pub fn encrypt_win(
    pks: &[&[u8; PK_BYTES]],
    win: Option<&[u8]>,
    msgs: &[[u8; 16]],
    r: &[i8; N],
    e1: &[i16; N],
    e2: &[[i16; 16]],
) -> Option<super::Encrypted> {
    let n = pks.len();
    if n == 0 || msgs.len() != n || e2.len() != n || win.is_some_and(|w| w.len() != n) {
        return None;
    }
    let (mut u, mut vs) = (Box::new([0u8; PK_BYTES]), vec![[0u8; 128]; n]);
    let rc = with_core(ARENA_SMALL, || unsafe {
        let ptrs: Vec<*const u8> = pks.iter().map(|p| p.as_ptr()).collect();
        let w = win.map_or(std::ptr::null(), |w| w.as_ptr());
        pqz_encrypt_win(ptrs.as_ptr(), n as u32, w, msgs.as_ptr(), r.as_ptr(), e1.as_ptr(), e2.as_ptr(), u.as_mut_ptr(), vs.as_mut_ptr())
    })
    .ok()?;
    (rc == 0).then_some((u, vs))
}
