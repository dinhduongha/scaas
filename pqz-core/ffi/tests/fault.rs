//! Node faults (controller 2026-10-14): injected through the test hooks, in a process of their own (they disturb
//! every other PQZL call). An unavailable worker (both backends) and arena exhaustion (the C backend) give
//! `Err(NodeFault)` / status 4 with `out` untouched, never …00; after the fault is gone the same inputs verify again.
//! The Rust backend (review round 2, the port's deferred minors): a counting allocator (this test binary's) denies the
//! `Ctx` allocation and, end to end through the precompile, the core's cache allocations (`Error::Memory`): status 4;
//! the panic path (hook `TEST_PANIC`): `…00`, status 3, the `Ctx` dropped and rebuilt.
use std::sync::atomic::Ordering::Relaxed;

use pqz_ffi::*;

/// the graceful band 14–20 MiB of `runs/ffi1d-arena-probe.txt`
#[cfg(not(feature = "pqzl-rust"))]
const ARENA_MIB: usize = 18;

#[test]
fn node_faults_are_status_4() {
    let c = fixture::cases(&PQZL_ID).unwrap().into_iter().find(|c| c.form == stmt::Form::Transfer).unwrap();
    let proof = prove(c.op(), &c.stmt, &c.wit, &[7; 32]).unwrap();
    let input = stmt::input(c.op(), &c.stmt, &proof);
    // PQZH: in the builds of the sets with PQZH (all three with pqz-ffi since plan 5h Task 8c part 2)
    let pqzh_input = PQZH.then(|| {
        let h = fixture::cases(&PQZH_ID).unwrap().into_iter().find(|c| c.form == stmt::Form::Register).unwrap();
        stmt::input(h.op(), &h.stmt, &prove(h.op(), &h.stmt, &h.wit, &[7; 32]).unwrap())
    });
    assert_eq!(precompile(&input), Ok(VALID));

    #[cfg(not(feature = "pqzl-rust"))]
    arena_exhaustion(&input, c.op(), &c.stmt, &proof);
    #[cfg(feature = "pqzl-rust")]
    rust_core_faults(&input);

    // worker unavailable: verify and the (uncached) self-test
    pqzl::TEST_FAIL_WORKER.store(true, Relaxed);
    assert_eq!(precompile(&input), Err(Error::NodeFault));
    assert_eq!(c_abi(&input), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert_eq!(precompile(&[6, 0, 0, 0, 0]), Err(Error::NodeFault));
    assert_eq!(c_abi(&[6, 0, 0, 0, 0]), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert!(pqzl::keygen(&[1; 32]).is_none());
    assert_eq!(prove(c.op(), &c.stmt, &c.wit, &[7; 32]), Err(ProveError::Pqzl(-1)));
    // PQZH needs no core
    if let Some(i) = &pqzh_input {
        assert_eq!(precompile(i), Ok(VALID));
    }
    pqzl::TEST_FAIL_WORKER.store(false, Relaxed);
    assert_eq!(precompile(&input), Ok(VALID));
    let st = precompile(&[6, 0, 0, 0, 0]).unwrap();
    assert_eq!(st, selftest::report().unwrap().hash);
    eprintln!(
        "node faults: {}worker failure → status 4, out untouched; recovered",
        if cfg!(feature = "pqzl-rust") { "Ctx and core allocation failures and " } else { "arena exhaustion and " }
    );
}

/// The process's allocator with two denials for the Rust backend's faults: allocations of exactly `SIZE` bytes, and
/// of at least `FROM` bytes (0 = off).
#[cfg(feature = "pqzl-rust")]
mod deny {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

    pub static SIZE: AtomicUsize = AtomicUsize::new(0);
    pub static FROM: AtomicUsize = AtomicUsize::new(0);
    pub static DENIED: AtomicUsize = AtomicUsize::new(0);

    fn ok(n: usize) -> bool {
        let (s, f) = (SIZE.load(Relaxed), FROM.load(Relaxed));
        let deny = n == s || (f != 0 && n >= f);
        if deny {
            DENIED.fetch_add(1, Relaxed);
        }
        !deny
    }

    struct Deny;
    unsafe impl GlobalAlloc for Deny {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            if ok(l.size()) { unsafe { System.alloc(l) } } else { std::ptr::null_mut() }
        }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            if ok(l.size()) { unsafe { System.alloc_zeroed(l) } } else { std::ptr::null_mut() }
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            unsafe { System.dealloc(p, l) }
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            if ok(n) { unsafe { System.realloc(p, l, n) } } else { std::ptr::null_mut() }
        }
    }

    #[global_allocator]
    static A: Deny = Deny;
}

/// The Rust backend: the fallible `Ctx` allocation, out of memory inside the core end to end, and the panic path.
#[cfg(feature = "pqzl-rust")]
fn rust_core_faults(input: &[u8]) {
    // the Ctx itself (about 41 KB, try_reserve_exact): NodeFault, out untouched; then the same input verifies
    pqzl::drop_ctx();
    deny::SIZE.store(std::mem::size_of::<::pqzl::Ctx>(), Relaxed);
    let d0 = deny::DENIED.load(Relaxed);
    assert_eq!(precompile(input), Err(Error::NodeFault), "Ctx allocation denied");
    assert_eq!(c_abi(input), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert!(deny::DENIED.load(Relaxed) >= d0 + 2);
    deny::SIZE.store(0, Relaxed);
    assert_eq!(precompile(input), Ok(VALID), "after the Ctx denial");
    // a fresh Ctx whose relation keys / SV tables cannot be allocated (every block of 1 MiB or more): the verifier's
    // Error::Memory is NodeFault (status 4, never …00); the Ctx survives and verifies once memory is back
    pqzl::drop_ctx();
    deny::FROM.store(1 << 20, Relaxed);
    let d0 = deny::DENIED.load(Relaxed);
    assert_eq!(precompile(input), Err(Error::NodeFault), "cache allocations denied");
    assert_eq!(c_abi(input), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert!(deny::DENIED.load(Relaxed) > d0);
    deny::FROM.store(0, Relaxed);
    assert_eq!(precompile(input), Ok(VALID), "after the cache denial");
    // a panic inside the core: caught, input-caused (…00, status 3), the Ctx dropped; then rebuilt and VALID
    pqzl::TEST_PANIC.store(true, Relaxed);
    assert_eq!(precompile(input), Ok(INVALID), "panic in the core");
    assert_eq!(c_abi(input), (PQZ_FFI_INTERNAL, INVALID));
    pqzl::TEST_PANIC.store(false, Relaxed);
    assert_eq!(precompile(input), Ok(VALID), "after the panic");
    eprintln!("Rust core faults: Ctx allocation denied → status 4; cache allocations ≥ 1 MiB denied → status 4; \
               panic in the core → …00 status 3; each time the same input VALID afterwards");
}

fn c_abi(inp: &[u8]) -> (i32, [u8; 32]) {
    let mut out = [0xEEu8; 32];
    let rc = unsafe { pqz_precompile(inp.as_ptr(), inp.len(), out.as_mut_ptr(), 32) };
    (rc, out)
}

/// The C backend: arena exhaustion (the Rust backend has no arena; its allocation failures are `pqzl`'s
/// `tests/memory.rs`).
#[cfg(not(feature = "pqzl-rust"))]
fn arena_exhaustion(input: &[u8], op: u8, st: &[u8], proof: &[u8]) {
    let r = fixture::cases(&PQZL_ID).unwrap().into_iter().find(|c| c.form == stmt::Form::Register).unwrap();
    let reg_input = stmt::input(r.op(), &r.stmt, &prove(r.op(), &r.stmt, &r.wit, &[7; 32]).unwrap());
    // arena exhaustion: 18 MiB holds A, R_REG's whole verify, and R_TX's ABDLOP keys but not its whole verify (R_TX
    // alone needs 20–24 MiB);
    // the core then fails gracefully (the specialised verifier's own allocations, pqz_arena_try_alloc). Below 14 MiB
    // the exhaustion is inside the relation's key generation (LaZer), which stops the process (a trap since review
    // round 2, Q-C; before it a SIGSEGV after writing past the shared sink: STATUS.md Open 2), so the probe
    // ffi1d-arena-probe.txt picked the middle of the 14–20 MiB band.
    let mib: usize = std::env::var("PQZ_FAULT_ARENA_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(ARENA_MIB);
    eprintln!("fault arena {mib} MiB");
    pqzl::TEST_ARENA_BYTES.store(mib << 20, Relaxed);
    pqzl::reinit(mib << 20);
    assert_eq!(precompile(input), Err(Error::NodeFault));
    assert_eq!(c_abi(input), (PQZ_FFI_NODE_FAULT, [0xEE; 32]));
    assert_eq!(pqzl::verify_fast(op, st, proof), Err(NodeFault));
    // the decoder's rejections need no core: still …00
    assert_eq!(precompile(&input[..input.len() - proof.len()]), Ok(INVALID));
    // each fault dropped the core (the three calls above each ran on a fresh core and faulted the same way); at the
    // SAME fixed size a fresh core verifies what fits (R_REG): never a stale, half-exhausted core
    assert_eq!(precompile(&reg_input), Ok(VALID), "fresh core at {mib} MiB");
    assert_eq!(precompile(&reg_input), Ok(VALID));
    pqzl::TEST_ARENA_BYTES.store(0, Relaxed);
    assert_eq!(precompile(input), Ok(VALID), "re-initialised after the fault");
}

