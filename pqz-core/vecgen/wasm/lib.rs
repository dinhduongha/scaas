//! PQZH prove / verify for the wasm32 replay of the vectors (../replay_wasm.mjs): THE preset, inputs in buffers from
//! `alloc`, the last proof kept for `out_ptr` / `out_len`.
use std::cell::RefCell;

use pqzh_ligero::{prove, verify, Params};

thread_local! {
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn sl<'a>(p: *const u8, n: u32) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(p, n as usize) }
}

#[no_mangle]
pub extern "C" fn alloc(n: u32) -> *mut u8 {
    Box::leak(vec![0u8; n as usize].into_boxed_slice()).as_mut_ptr()
}

/// proof length (0 = the prover refused)
#[no_mangle]
pub extern "C" fn prove_h(op: u32, st: *const u8, sn: u32, wit: *const u8, wn: u32, rnd: *const u8) -> u32 {
    let r: [u8; 32] = sl(rnd, 32).try_into().unwrap();
    let p = prove(op as u8, sl(st, sn), sl(wit, wn), r, &Params::proven()).unwrap_or_default();
    OUT.with(|o| *o.borrow_mut() = p);
    OUT.with(|o| o.borrow().len() as u32)
}

#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn verify_h(op: u32, st: *const u8, sn: u32, pf: *const u8, pn: u32) -> u32 {
    verify(op as u8, sl(st, sn), sl(pf, pn), &Params::proven()) as u32
}
