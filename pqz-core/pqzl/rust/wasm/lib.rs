//! The pqzl bench steps in wasm32 (`pqzl::bench`, the exports of pqzl/test/pqz_bench.c's PQZ_WASM build), driven
//! by run_wasm.mjs. One instance, one thread: the bench state lives in a thread-local.
use pqzl::bench::{Bench, NREL};
use pqzl::Error;
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
