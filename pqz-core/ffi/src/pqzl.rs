//! PQZL: one API over two interchangeable backends (CTR-PQZ-09), byte-for-byte equal (same proofs, same verdicts):
//! - feature `pqzl-rust` (the default since owner 2026-10-18): the crate `pqzl` (`pqz-core/pqzl/rust`, safe Rust),
//!   module [`rust`];
//! - feature `pqzl-c`: the C core (libpqz, built by build.rs), module [`c`]; the backend when `pqzl-rust` is off.
//!   With both features on, `pqzl::` is the Rust backend and `pqzl::c` the C core (the differential tests and the
//!   fuzz mode `pqzl-diff` run both in one binary).
//!
//! Both run every call under one process-wide lock, on one worker thread with a fixed 16 MiB stack (natively; wasm32
//! runs it in place, its stack is the module's): the core's stack use (the prover's frames exceed a test thread's
//! 2 MiB) never depends on the caller's thread, e.g. a .NET thread-pool thread of 1.5 MiB. The worker is created at
//! the first call and kept; if it dies (a job panicked past its catch, or the channel broke) the call is a node fault
//! and the next call creates a new one. Per call only the job's box and its channel messages are allocated (small,
//! fixed size).
//!
//! Node faults (controller 2026-10-14): a core or worker that cannot be set up and a worker job that died are not
//! properties of the input: `Err(NodeFault)`, which the precompile entry reports as `PQZ_FFI_NODE_FAULT` with no
//! output. The backends add their own: running out of memory inside the core (the C core: arena allocation,
//! `pqz_init`, arena exhaustion; the Rust core: `Error::Memory` from a verifier).
#[cfg(feature = "test-hooks")]
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

#[cfg(not(any(feature = "pqzl-rust", feature = "pqzl-c")))]
compile_error!("pqz-ffi needs a PQZL backend: feature `pqzl-rust` (the default) or `pqzl-c`");

#[cfg(feature = "pqzl-c")]
pub mod c;
#[cfg(feature = "pqzl-rust")]
pub mod rust;

#[cfg(not(feature = "pqzl-rust"))]
pub use c::*;
#[cfg(feature = "pqzl-rust")]
pub use rust::*;

/// A fault of this node, not of the input: no result (the host must not treat the input as invalid).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeFault;

/// Test hook (feature `test-hooks`, never in a production build): a worker that refuses every job.
#[cfg(feature = "test-hooks")]
pub static TEST_FAIL_WORKER: AtomicBool = AtomicBool::new(false);

/// The largest PQZL op 7 M that `crate::prove` proves on wasm32; verify has no such limit. C backend 4 (controller
/// proposal 2026-10-16, owner may override: the C core's `R_TXM4_0` with every relation loaded peaks at 432.7 MB in
/// wasm32, M = 8 at 669 MB, `l3a-summary.txt`; M = 8 is for native clients). Rust backend 8 = `pqzl::WASM_MAX_LEGS`
/// (port plan Task 12, owner 2026-10-18 "if it is enough, raise it": run `d6`, the M = 8 wasm32 prove peaks at
/// 117.4 MiB, CTR-PQZ-09).
pub const WASM_PQZL_MAX_LEGS: usize = if cfg!(feature = "pqzl-rust") { 8 } else { 4 };
/// The worker thread's stack (pqz_bench runs the core on an 8 MiB main thread, the wasm builds on an 8 MiB stack).
pub const STACK: usize = 16 << 20;

pub const MAX_PROOF: usize = 98_304;
pub const PK_BYTES: usize = 16_384;
pub const CT_BYTES: usize = PK_BYTES + 128;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// The thread every core call runs on (native): one job at a time, under the backend's lock.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct Worker {
    jobs: std::sync::mpsc::Sender<Job>,
    done: std::sync::mpsc::Receiver<bool>,
}

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

/// `encrypt`'s result: `u` and one `v` per recipient.
#[cfg(feature = "prove")]
pub type Encrypted = (Box<[u8; PK_BYTES]>, Vec<[u8; 128]>);

/// A key pair from a seed (pq-zero-knowledge.md §4.2, `pqz_keygen`).
pub struct Key {
    pub pk: Box<[u8; PK_BYTES]>,
    pub s: Box<[i8; 2048]>,
    pub e: Box<[i16; 2048]>,
    /// the counter of the accepted attempt (§4.2)
    pub ctr: u32,
}

/// One encryption to `pks.len()` recipients from `seed_enc` (§4.2, `pqz_enc_seed`): `u`, one `v` per recipient, and
/// the short vectors (the prover's witness).
pub struct Enc {
    pub u: Box<[u8; PK_BYTES]>,
    pub vs: Vec<[u8; 128]>,
    pub r: Box<[i8; 2048]>,
    pub e1: Box<[i16; 2048]>,
    pub e2: Vec<[i16; 16]>,
    /// the counter of the accepted attempt (§4.2)
    pub ctr: u32,
}

/// One `R_TXM` encryption (P6-ANON §4, D13): per group `g < ⌈M/4⌉` one `enc` from `enc_group_seed(seed_enc, g)` to the
/// group's legs, then (group 0) `pk_f`, then (auditor on) the group's auditor copies; the result re-sorted into the
/// statement's and the witness's leg order.
pub struct EncMulti {
    /// `(u_g, r_g, e1_g)` per group (the `Enc` of group g; its `vs` / `e2` are also in `v`, `e2`, … below)
    pub groups: Vec<Enc>,
    /// `v_j`, `e2_j` per leg
    pub v: Vec<[u8; 128]>,
    pub e2: Vec<[i16; 16]>,
    pub v_f: [u8; 128],
    pub e2_f: [i16; 16],
    /// auditor copies `v_{a,j}`, `e2_{a,j}` per leg (empty with the auditor off)
    pub v_a: Vec<[u8; 128]>,
    pub e2_a: Vec<[i16; 16]>,
}

/// `legs` = `(pk_j, digits of a_j)` in leg order, `d_f` = the new balance's digits.
pub fn enc_multi(
    pk_f: &[u8; PK_BYTES],
    d_f: [u8; 16],
    legs: &[(&[u8; PK_BYTES], [u8; 16])],
    pk_a: Option<&[u8; PK_BYTES]>,
    seed_enc: &[u8; 32],
) -> Option<EncMulti> {
    let m = legs.len();
    let mut out = EncMulti {
        groups: Vec::new(),
        v: Vec::with_capacity(m),
        e2: Vec::with_capacity(m),
        v_f: [0; 128],
        e2_f: [0; 16],
        v_a: Vec::new(),
        e2_a: Vec::new(),
    };
    for (g, grp) in legs.chunks(pqz_stmt::LEGS_PER_GROUP).enumerate() {
        let n = grp.len();
        let (mut pks, mut msgs): (Vec<&[u8; PK_BYTES]>, Vec<[u8; 16]>) = grp.iter().copied().unzip();
        if g == 0 {
            pks.push(pk_f);
            msgs.push(d_f);
        }
        if let Some(a) = pk_a {
            pks.extend(std::iter::repeat_n(a, n));
            msgs.extend(grp.iter().map(|l| l.1));
        }
        let c = enc(&pks, &msgs, &enc_group_seed(seed_enc, g))?;
        out.v.extend_from_slice(&c.vs[..n]);
        out.e2.extend_from_slice(&c.e2[..n]);
        let a0 = n + (g == 0) as usize;
        if g == 0 {
            (out.v_f, out.e2_f) = (c.vs[n], c.e2[n]);
        }
        out.v_a.extend_from_slice(&c.vs[a0..]);
        out.e2_a.extend_from_slice(&c.e2[a0..]);
        out.groups.push(c);
    }
    (m > 0).then_some(out)
}
