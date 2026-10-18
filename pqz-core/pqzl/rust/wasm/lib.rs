//! The pqzl bench steps in wasm32 (`pqzl::bench`, the exports of pqzl/test/pqz_bench.c's PQZ_WASM build), driven
//! by run_wasm.mjs; and the vectors' replay (`prove_v`, `verify_v`, driven by run_vectors.mjs). One instance, one
//! thread: the state lives in thread-locals. `sp` (the address of a local: the shadow stack's current top) lets the
//! runners measure stack use by painting the free stack below it.
use pqzl::bench::{Bench, NREL};
use pqzl::{Ctx, Error};
use std::cell::RefCell;

thread_local! {
    static B: RefCell<Option<Bench>> = const { RefCell::new(None) };
}

fn with<R>(f: impl FnOnce(&mut Bench) -> R) -> R {
    B.with(|b| f(b.borrow_mut().as_mut().expect("step_init first")))
}

/// the C core's return codes (pqz_rt.h)
fn code(e: Error) -> i32 {
    match e {
        Error::Internal => 1,
        Error::Memory => 2,
        Error::Input => 3,
        Error::Reject => 4,
    }
}

/// the statements and witnesses of every relation; 0, or the error code
#[no_mangle]
pub extern "C" fn step_init() -> i32 {
    match Bench::new() {
        Ok(x) => {
            B.with(|b| *b.borrow_mut() = Some(x));
            0
        }
        Err(e) => code(e),
    }
}

#[no_mangle]
pub extern "C" fn step_nrel() -> i32 {
    NREL as i32
}

#[no_mangle]
pub extern "C" fn step_prove(rel: u32, seed: u32) -> i32 {
    with(|b| b.prove(rel as usize, seed).map_or_else(code, |_| 0))
}

#[no_mangle]
pub extern "C" fn step_len(rel: u32) -> u32 {
    with(|b| b.len(rel as usize) as u32)
}

#[no_mangle]
pub extern "C" fn step_verify(rel: u32) -> i32 {
    with(|b| b.verify(rel as usize) as i32)
}

#[no_mangle]
pub extern "C" fn step_verify_bad(rel: u32, kind: u32, seed: u32) -> i32 {
    with(|b| b.verify_bad(rel as usize, kind, seed) as i32)
}

#[no_mangle]
pub extern "C" fn step_hash(rel: u32) -> u32 {
    with(|b| b.hash(rel as usize))
}

/// `PQZ_VERIFY=fast`: the bench verifies with `verify_fast` (C's `step_set_fast`)
#[no_mangle]
pub extern "C" fn step_set_fast(on: u32) {
    with(|b| b.fast = on != 0)
}

/// the address of a local (an export's frame sits at the top of the shadow stack)
#[no_mangle]
pub extern "C" fn sp() -> u32 {
    let x = 0u8;
    std::hint::black_box(&x) as *const u8 as u32
}

// ---- the vectors' replay (run_vectors.mjs): prove and verify given inputs on one Ctx
thread_local! {
    static CTX: RefCell<Ctx> = RefCell::new(Ctx::new());
    static PROOF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn sl<'a>(p: *const u8, n: u32) -> &'a [u8] {
    // SAFETY: the runner passes (pointer, length) pairs inside buffers it got from `alloc`
    unsafe { std::slice::from_raw_parts(p, n as usize) }
}

/// a buffer of `n` bytes in linear memory (leaked; the replay is one short process)
#[no_mangle]
pub extern "C" fn alloc(n: u32) -> *mut u8 {
    Box::leak(vec![0u8; n as usize].into_boxed_slice()).as_mut_ptr()
}

/// `Ctx::prove`: the proof's length, or 0x8000_0000 | the C core's error code
#[no_mangle]
pub extern "C" fn prove_v(op: u32, st: *const u8, sn: u32, wit: *const u8, wn: u32, rnd: *const u8) -> u32 {
    let r: [u8; 32] = sl(rnd, 32).try_into().unwrap();
    match CTX.with(|c| c.borrow_mut().prove(op as u8, sl(st, sn), sl(wit, wn), &r)) {
        Ok(p) => PROOF.with(|o| {
            *o.borrow_mut() = p;
            o.borrow().len() as u32
        }),
        Err(e) => 0x8000_0000 | code(e) as u32,
    }
}

#[no_mangle]
pub extern "C" fn proof_ptr() -> *const u8 {
    PROOF.with(|o| o.borrow().as_ptr())
}

/// `Ctx::verify` (fast = 0) / `Ctx::verify_fast` (fast = 1): 1 valid, 0 not
#[no_mangle]
pub extern "C" fn verify_v(op: u32, st: *const u8, sn: u32, pf: *const u8, pn: u32, fast: u32) -> u32 {
    CTX.with(|c| {
        let mut c = c.borrow_mut();
        let (st, pf) = (sl(st, sn), sl(pf, pn));
        (if fast != 0 { c.verify_fast(op as u8, st, pf) } else { c.verify(op as u8, st, pf) }) as u32
    })
}
