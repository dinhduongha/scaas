//! PQZL: the C core (libpqz) behind one process-wide lock (STATUS.md Open 6: the core keeps its arena, base mark,
//! sticky error and the specialised verifier's tables in globals). Every libpqz call goes through `with_core`, which
//! takes the lock, and runs the call on one worker thread with a fixed 16 MiB stack (natively; wasm32 runs it in
//! place, its stack is the module's): the core's stack use (the prover's frames exceed a test thread's 2 MiB) never
//! depends on the caller's thread, e.g. a .NET thread-pool thread of 1.5 MiB. The worker is created at the first
//! call and kept; if it dies (a job panicked past its catch, or the channel broke) the call is a node fault and the
//! next call creates a new one. Per call only the job's box and its channel messages are allocated (small, fixed
//! size); the arena is never re-allocated on the verify path.
//!
//! Arenas (allocated once, kept for the process): `ARENA_SMALL` for the precompile path (the specialised verifier of
//! all six forms, keygen / enc / dec, the self-test), measured; `ARENA_BIG` for the prover and the generic verifier. A
//! call that needs `ARENA_BIG` re-initialises the core once on it (the core's caches are rebuilt lazily); the core
//! then stays there.
//!
//! Node faults (controller 2026-10-14): a core or worker that cannot be set up (arena allocation, `pqz_init`, thread
//! creation), a worker job that panicked, and the core running out of arena (`pqz_err == PQZ_ERR_ARENA` after a call)
//! are not properties of the input: `with_core` returns `Err(NodeFault)` (and drops the core, re-initialised at the
//! next call), which the precompile entry reports as `PQZ_FFI_NODE_FAULT` with no output.
use std::sync::Mutex;
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::Relaxed};

/// A fault of this node, not of the input: no result (the host must not treat the input as invalid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeFault;

const PQZ_ERR_ARENA: i32 = 2; // pqz_rt.h

/// Test hooks (feature `test-hooks`, never in a production build): a fixed arena size for every (re)initialisation, a
/// worker that refuses every job, and a byte pattern written over the arena before `pqz_init` (`0x100 | byte`; 0 = none).
#[cfg(feature = "test-hooks")]
pub static TEST_ARENA_BYTES: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "test-hooks")]
pub static TEST_FAIL_WORKER: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "test-hooks")]
pub static TEST_ARENA_FILL: AtomicU32 = AtomicU32::new(0);

/// Verify-only arena: ≥ 1.5 × the measured peak of the precompile path over the whole adversarial corpus with every
/// form's relation keys and SV tables kept, as in a long-running node (`tests/verify_only.rs`, run `ffi1f`:
/// 95,169,680 B; honest inputs and the self-test alone 94,615,600 B) = 136.1 MiB, rounded up to 144 MiB (1.59 ×).
pub const ARENA_SMALL: usize = 144 << 20;
/// Prover and generic-verifier arena (plan D10: ≥ 320 MiB; R_TX prove peak 304 MB alone, STATUS.md).
pub const ARENA_BIG: usize = 448 << 20;
/// The worker thread's stack (pqz_bench runs the core on an 8 MiB main thread, the wasm builds on an 8 MiB stack).
pub const STACK: usize = 16 << 20;

pub const MAX_PROOF: usize = 98_304;
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
    fn pqz_enc_seed(
        pks: *const *const u8,
        npk: u32,
        msgs: *const [u8; 16],
        seed_enc: *const u8,
        u: *mut u8,
        vs: *mut [u8; 128],
        r: *mut i8,
        e1: *mut i16,
        e2: *mut [i16; 16],
        ctr: *mut u32,
    ) -> i32;
    fn pqz_dec(s: *const i8, ct: *const u8, m: *mut i64, noise: *mut i64) -> i32;
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

type Job = Box<dyn FnOnce() + Send + 'static>;

/// The thread every libpqz call runs on (native): one job at a time, under the lock.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct Worker {
    jobs: std::sync::mpsc::Sender<Job>,
    done: std::sync::mpsc::Receiver<bool>,
}

struct State {
    core: Option<Core>,
    worker: Option<Worker>,
}

static STATE: Mutex<State> = Mutex::new(State { core: None, worker: None });

/// Runs `job` on the worker and waits for it; `None` if the worker cannot be created or the job panicked (the worker
/// survives a panicking job).
#[cfg(not(target_arch = "wasm32"))]
fn on_worker<R: Send>(w: &mut Option<Worker>, f: impl FnOnce() -> R + Send) -> Option<R> {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::mpsc::channel;
    #[cfg(feature = "test-hooks")]
    if TEST_FAIL_WORKER.load(Relaxed) {
        return None;
    }
    if w.is_none() {
        let (jobs, rx) = channel::<Job>();
        let (tx, done) = channel();
        std::thread::Builder::new()
            .name("pqz-core".into())
            .stack_size(STACK)
            .spawn(move || {
                for j in rx {
                    if tx.send(catch_unwind(AssertUnwindSafe(j)).is_ok()).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        *w = Some(Worker { jobs, done });
    }
    let wk = w.as_ref()?;
    let mut out = None;
    let job: Box<dyn FnOnce() + Send + '_> = Box::new(|| out = Some(f()));
    // SAFETY: the job borrows from this frame; it is erased to 'static only to cross the channel, and this function
    // does not return before the worker has finished with it: `done.recv()` returns after the job ran (or was
    // dropped: the worker exited, then `recv` errors after the drop).
    let job: Job = unsafe { std::mem::transmute::<Box<dyn FnOnce() + Send + '_>, Job>(job) };
    if wk.jobs.send(job).is_err() || !wk.done.recv().unwrap_or(false) {
        *w = None;
        return None;
    }
    out
}

#[cfg(target_arch = "wasm32")]
fn on_worker<R: Send>(_: &mut Option<Worker>, f: impl FnOnce() -> R + Send) -> Option<R> {
    Some(f())
}

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
/// the caller's stack must be large enough). The core must be up (any earlier call).
#[doc(hidden)]
pub fn verify_fast_on_caller(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    let g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    g.core.is_some() && unsafe { pqz_verify_fast(op, stmt.as_ptr(), stmt.len(), proof.as_ptr(), proof.len()) } == 1
}

/// The generic verifier (LaZer's), the reference for differential tests; never on the precompile path.
pub fn verify_generic(op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, NodeFault> {
    with_core(ARENA_BIG, || unsafe { pqz_verify(op, stmt.as_ptr(), stmt.len(), proof.as_ptr(), proof.len()) })
        .map(|r| r == 1)
}

pub const PK_BYTES: usize = 16_384;
pub const CT_BYTES: usize = PK_BYTES + 128;

/// pk = A·s + e (`pqz_keypair_from_secret`; no norm check): the self-test reads the columns of A with it.
pub fn keypair_from_secret(s: &[i8; 2048], e: &[i16; 2048]) -> Option<Box<[u8; PK_BYTES]>> {
    let mut pk = Box::new([0u8; PK_BYTES]);
    let rc = with_core(ARENA_SMALL, || unsafe { pqz_keypair_from_secret(s.as_ptr(), e.as_ptr(), pk.as_mut_ptr()) }).ok()?;
    (rc == 0).then_some(pk)
}

/// A key pair from a seed (pq-zether.md §4.2, `pqz_keygen`).
pub struct Key {
    pub pk: Box<[u8; PK_BYTES]>,
    pub s: Box<[i8; 2048]>,
    pub e: Box<[i16; 2048]>,
}

pub fn keygen(seed32: &[u8; 32]) -> Option<Key> {
    let mut k = Key { pk: Box::new([0; PK_BYTES]), s: Box::new([0; 2048]), e: Box::new([0; 2048]) };
    let rc = with_core(ARENA_SMALL, || unsafe {
        pqz_keygen(seed32.as_ptr(), k.pk.as_mut_ptr(), k.s.as_mut_ptr(), k.e.as_mut_ptr(), std::ptr::null_mut())
    })
    .ok()?;
    (rc == 0).then_some(k)
}

/// One encryption to `pks.len()` recipients from `seed_enc` (§4.2, `pqz_enc_seed`): `u`, one `v` per recipient, and
/// the short vectors (the prover's witness).
pub struct Enc {
    pub u: Box<[u8; PK_BYTES]>,
    pub vs: Vec<[u8; 128]>,
    pub r: Box<[i8; 2048]>,
    pub e1: Box<[i16; 2048]>,
    pub e2: Vec<[i16; 16]>,
}

pub fn enc(pks: &[&[u8; PK_BYTES]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Option<Enc> {
    let n = pks.len();
    if n == 0 || msgs.len() != n {
        return None;
    }
    let mut c = Enc {
        u: Box::new([0; PK_BYTES]),
        vs: vec![[0; 128]; n],
        r: Box::new([0; 2048]),
        e1: Box::new([0; 2048]),
        e2: vec![[0; 16]; n],
    };
    let rc = with_core(ARENA_SMALL, || unsafe {
        let ptrs: Vec<*const u8> = pks.iter().map(|p| p.as_ptr()).collect();
        pqz_enc_seed(
            ptrs.as_ptr(),
            n as u32,
            msgs.as_ptr(),
            seed_enc.as_ptr(),
            c.u.as_mut_ptr(),
            c.vs.as_mut_ptr(),
            c.r.as_mut_ptr(),
            c.e1.as_mut_ptr(),
            c.e2.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    })
    .ok()?;
    (rc == 0).then_some(c)
}

/// Dec of `ct = u ‖ v` (16,512 B) with `s`: the 16 digits `M` and their noise (§4.2, `pqz_dec`).
pub fn dec(s: &[i8; 2048], ct: &[u8; CT_BYTES]) -> Option<([i64; 16], [i64; 16])> {
    let (mut m, mut noise) = ([0i64; 16], [0i64; 16]);
    let rc =
        with_core(ARENA_SMALL, || unsafe { pqz_dec(s.as_ptr(), ct.as_ptr(), m.as_mut_ptr(), noise.as_mut_ptr()) }).ok()?;
    (rc == 0).then_some((m, noise))
}

/// `pqz_prove`: the proof, or the core's error code (-1: a node fault, `with_core`).
#[cfg(feature = "prove")]
pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, i32> {
    let mut proof = vec![0u8; MAX_PROOF];
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
