//! pqz-ffi prove feature in wasm32: `run(sel)` writes the digest lines of `pqz_ffi::fixture::digest_lines` (sel bit 0
//! PQZL, bit 1 PQZH) and the self-test hash; `out_ptr` / return value = the UTF-8 text in linear memory.
use std::cell::RefCell;

use pqz_ffi::{fixture, PQZH_ID, PQZL_ID};

thread_local! {
    static OUT: RefCell<String> = const { RefCell::new(String::new()) };
}

#[no_mangle]
pub extern "C" fn run(sel: u32) -> u32 {
    let mut s = String::new();
    for (bit, id) in [(1, PQZL_ID), (2, PQZH_ID)] {
        if sel & bit != 0 {
            s += &fixture::digest_lines(&id);
        }
    }
    s += &fixture::selftest_line();
    OUT.with(|o| {
        *o.borrow_mut() = s;
        o.borrow().len() as u32
    })
}

#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

// ---- the vectors' wasm32 replay (../vectors/replay_wasm.mjs, P6e Task 11): prove from given inputs, run the
// precompile on a given input
thread_local! {
    static PROOF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn sl<'a>(p: *const u8, n: u32) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(p, n as usize) }
}

/// a buffer of `n` bytes in linear memory (leaked; the replay is one short process)
#[no_mangle]
pub extern "C" fn alloc(n: u32) -> *mut u8 {
    Box::leak(vec![0u8; n as usize].into_boxed_slice()).as_mut_ptr()
}

/// `pqz_ffi::prove` (the statement's id picks PQZL or PQZH); the proof length, 0 if the prover refused
#[no_mangle]
pub extern "C" fn prove_v(op: u32, st: *const u8, sn: u32, wit: *const u8, wn: u32, rnd: *const u8) -> u32 {
    let r: [u8; 32] = sl(rnd, 32).try_into().unwrap();
    let p = pqz_ffi::prove(op as u8, sl(st, sn), sl(wit, wn), &r).unwrap_or_default();
    PROOF.with(|o| {
        *o.borrow_mut() = p;
        o.borrow().len() as u32
    })
}

#[no_mangle]
pub extern "C" fn proof_ptr() -> *const u8 {
    PROOF.with(|o| o.borrow().as_ptr())
}

/// `pqz_ffi::precompile` on the input: 1 = `…01`, 0 = `…00`, 2 = anything else (revert, node fault, self-test hash)
#[no_mangle]
pub extern "C" fn precompile_v(input: *const u8, n: u32) -> u32 {
    match pqz_ffi::precompile(sl(input, n)) {
        Ok(w) if w == pqz_ffi::VALID => 1,
        Ok(w) if w == pqz_ffi::INVALID => 0,
        _ => 2,
    }
}

/// P6-ANON S3: wasm32 refuses to prove PQZL op 7 above `WASM_PQZL_MAX_LEGS` (one client arena): 1 if
/// `prove` of a PQZL (M = 8, auditor on) statement gives `Statement(Legs)` before any core work, 0 otherwise.
#[no_mangle]
pub extern "C" fn m8_refused() -> u32 {
    use pqz_ffi::stmt::{multi_len, Multi, Reject};
    let mut st = vec![0u8; multi_len(8, true)];
    for (i, w) in Multi::header(&PQZL_ID, 8, true).iter().enumerate() {
        st[32 * i..32 * i + 32].copy_from_slice(w);
    }
    (pqz_ffi::prove(7, &st, &[], &[0; 32]) == Err(pqz_ffi::ProveError::Statement(Reject::Legs))) as u32
}
