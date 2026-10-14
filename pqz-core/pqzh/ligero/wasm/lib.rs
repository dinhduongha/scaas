//! PQZH-Ligero bench steps exported to JS (wasm32-unknown-unknown, single-threaded, panic = abort), as pqzh/wasm.
//! Timing on the JS side (run_wasm.mjs).

use std::cell::RefCell;

use pqzh::client::{KINDS, R, Setup, mutate, setup};
use pqzh_ligero::{OP_REGISTER, OP_TRANSFER, Params, prove, verify};

struct St {
    s: Setup,
    p: [Params; 2],
    proof: [Vec<u8>; 2],
    other: [Vec<u8>; 2],
    r: R,
}

thread_local! {
    static ST: RefCell<Option<St>> = const { RefCell::new(None) };
}

fn op(tx: u32) -> u8 {
    if tx != 0 { OP_TRANSFER } else { OP_REGISTER }
}

fn with<T>(f: impl FnOnce(&mut St) -> T) -> T {
    ST.with(|c| f(c.borrow_mut().as_mut().expect("step_init first")))
}

/// statements and witnesses of pqz_bench.c setup(); the parameter model's presets (proven / conjectured, with or
/// without the radix-431 domains); proven = 2: the Johnson-bound reference preset
#[no_mangle]
pub extern "C" fn step_init(proven: u32, r431: u32) -> u32 {
    let p = [0, 1].map(|tx| if proven == 2 { Params::johnson_preset() } else { Params::preset(op(tx), proven != 0, r431 != 0) });
    ST.with(|c| *c.borrow_mut() = Some(St { s: setup(), p, proof: [vec![], vec![]], other: [vec![], vec![]], r: R(0x9E3779B97F4A7C15) }));
    KINDS.len() as u32
}

fn stmt_wit(st: &St, tx: u32) -> (&[u8], &[u8]) {
    if tx != 0 { (&st.s.tx_stmt, &st.s.tx_wit) } else { (&st.s.reg_stmt, &st.s.reg_wit) }
}

/// prove; returns the proof length, 0 on error
#[no_mangle]
pub extern "C" fn step_prove(tx: u32, seed: u32) -> u32 {
    with(|st| {
        let (s, w) = stmt_wit(st, tx);
        match prove(op(tx), s, w, [seed as u8; 32], &st.p[tx as usize]) {
            Ok(pf) => {
                let n = pf.len() as u32;
                st.proof[tx as usize] = pf;
                n
            }
            Err(_) => 0,
        }
    })
}

/// a valid proof of another statement (prefix byte 0 flipped), for the "other_proof" kind
#[no_mangle]
pub extern "C" fn step_prove_other(tx: u32) -> u32 {
    with(|st| {
        let (s, w) = stmt_wit(st, tx);
        let mut s2 = s.to_vec();
        s2[0] ^= 0x80;
        let pf = prove(op(tx), &s2, w, [9; 32], &st.p[tx as usize]).unwrap_or_default();
        let n = pf.len() as u32;
        st.other[tx as usize] = pf;
        n
    })
}

#[no_mangle]
pub extern "C" fn step_verify(tx: u32) -> u32 {
    with(|st| verify(op(tx), stmt_wit(st, tx).0, &st.proof[tx as usize], &st.p[tx as usize]) as u32)
}

/// mutated input of `kind` (client::KINDS order); 1 = accepted (must not happen)
#[no_mangle]
pub extern "C" fn step_verify_bad(tx: u32, kind: u32) -> u32 {
    with(|st| {
        let stmt = if tx != 0 { &st.s.tx_stmt } else { &st.s.reg_stmt };
        let (s, p) = mutate(kind as usize, op(tx), stmt, &st.proof[tx as usize], &st.other[tx as usize], &mut st.r);
        verify(op(tx), &s, &p, &st.p[tx as usize]) as u32
    })
}

/// FNV-1a of the last proof (native and wasm must agree for the same seed)
#[no_mangle]
pub extern "C" fn step_hash(tx: u32) -> u32 {
    with(|st| st.proof[tx as usize].iter().fold(2166136261u32, |h, &b| (h ^ b as u32).wrapping_mul(16777619)))
}

/// a buffer of `len` bytes in linear memory for step_load (proofs made natively: ligero_bench --dump)
#[no_mangle]
pub extern "C" fn step_alloc(len: u32) -> *mut u8 {
    Box::leak(vec![0u8; len as usize].into_boxed_slice()).as_mut_ptr()
}

/// take the proof (which = 0) or the other statement's proof (which = 1) of relation `tx` from a step_alloc buffer
#[no_mangle]
pub extern "C" fn step_load(tx: u32, which: u32, ptr: *mut u8, len: u32) {
    let v = unsafe { Vec::from_raw_parts(ptr, len as usize, len as usize) };
    with(|st| if which == 0 { st.proof[tx as usize] = v } else { st.other[tx as usize] = v });
}
