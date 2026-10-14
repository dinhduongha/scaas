//! PQZH-Ligero bench steps exported to JS (wasm32-unknown-unknown, single-threaded, panic = abort), as pqzh/wasm.
//! Timing on the JS side (run_wasm.mjs). `rel` indexes RELS: 0 R_REG, 1 R_TX, 2 R_BURN, 3 R_DS, 4 R_DR, 5 R_TX0.

use std::cell::RefCell;

use pqzh_ligero::client::{KINDS, R, Setup, mutate, setup};
use pqzh_ligero::{Form, Params, RELS, prove, verify};

const NREL: usize = RELS.len();

struct St {
    s: Setup,
    p: [Params; NREL],
    proof: [Vec<u8>; NREL],
    other: [Vec<u8>; NREL],
    r: R,
}

thread_local! {
    static ST: RefCell<Option<St>> = const { RefCell::new(None) };
}

fn form(rel: u32) -> Form {
    RELS[rel as usize]
}

fn op(rel: u32) -> u8 {
    form(rel).op()
}

fn with<T>(f: impl FnOnce(&mut St) -> T) -> T {
    ST.with(|c| f(c.borrow_mut().as_mut().expect("step_init first")))
}

/// statements and witnesses of pqz_bench.c setup(); the parameter model's presets (proven / conjectured, with or
/// without the radix-431 domains); proven = 2: the Johnson-bound reference preset
#[no_mangle]
pub extern "C" fn step_init(proven: u32, r431: u32) -> u32 {
    let p = RELS.map(|f| if proven == 2 { Params::johnson_preset() } else { Params::preset(f.op(), proven != 0, r431 != 0) });
    ST.with(|c| {
        *c.borrow_mut() = Some(St { s: setup(), p, proof: Default::default(), other: Default::default(), r: R(0x9E3779B97F4A7C15) })
    });
    KINDS.len() as u32
}

/// prove; returns the proof length, 0 on error
#[no_mangle]
pub extern "C" fn step_prove(rel: u32, seed: u32) -> u32 {
    with(|st| {
        let (s, w) = st.s.rel(form(rel));
        match prove(op(rel), s, w, [seed as u8; 32], &st.p[rel as usize]) {
            Ok(pf) => {
                let n = pf.len() as u32;
                st.proof[rel as usize] = pf;
                n
            }
            Err(_) => 0,
        }
    })
}

/// a valid proof of another statement (byte 64 flipped, hashed only), for the "other_proof" kind
#[no_mangle]
pub extern "C" fn step_prove_other(rel: u32) -> u32 {
    with(|st| {
        let (s, w) = st.s.rel(form(rel));
        let mut s2 = s.to_vec();
        s2[64] ^= 0x80;
        let pf = prove(op(rel), &s2, w, [9; 32], &st.p[rel as usize]).unwrap_or_default();
        let n = pf.len() as u32;
        st.other[rel as usize] = pf;
        n
    })
}

#[no_mangle]
pub extern "C" fn step_verify(rel: u32) -> u32 {
    with(|st| verify(op(rel), st.s.rel(form(rel)).0, &st.proof[rel as usize], &st.p[rel as usize]) as u32)
}

/// mutated input of `kind` (client::KINDS order); 1 = accepted (must not happen)
#[no_mangle]
pub extern "C" fn step_verify_bad(rel: u32, kind: u32) -> u32 {
    with(|st| {
        let stmt = st.s.rel(form(rel)).0;
        let (s, p) = mutate(kind as usize, form(rel), stmt, &st.proof[rel as usize], &st.other[rel as usize], &mut st.r);
        verify(op(rel), &s, &p, &st.p[rel as usize]) as u32
    })
}

/// FNV-1a of the last proof (native and wasm must agree for the same seed)
#[no_mangle]
pub extern "C" fn step_hash(rel: u32) -> u32 {
    with(|st| st.proof[rel as usize].iter().fold(2166136261u32, |h, &b| (h ^ b as u32).wrapping_mul(16777619)))
}

/// a buffer of `len` bytes in linear memory for step_load (proofs made natively: ligero_bench --dump)
#[no_mangle]
pub extern "C" fn step_alloc(len: u32) -> *mut u8 {
    Box::leak(vec![0u8; len as usize].into_boxed_slice()).as_mut_ptr()
}

/// take the proof (which = 0) or the other statement's proof (which = 1) of relation `rel` from a step_alloc buffer
#[no_mangle]
pub extern "C" fn step_load(rel: u32, which: u32, ptr: *mut u8, len: u32) {
    let v = unsafe { Vec::from_raw_parts(ptr, len as usize, len as usize) };
    with(|st| if which == 0 { st.proof[rel as usize] = v } else { st.other[rel as usize] = v });
}
