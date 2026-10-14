//! PQZH bench steps exported to JS (wasm32-unknown-unknown, single-threaded, panic = abort). Timing on the JS side
//! (run_wasm.mjs), as pqz-core's test/run_wasm.mjs does for the C build.

use std::cell::RefCell;

use pqzh::client::{KINDS, R, Setup, mutate, setup};
use pqzh::{OP_REGISTER, OP_TRANSFER, Params, prove, verify};

struct St {
    s: Setup,
    p: Params,
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

/// statements and witnesses of pqz_bench.c setup(); parameters: blowup / queries (0 = default), zk, proof-length
/// limit in bytes (0 = the PQZH kind's 160 KB; larger only to measure proofs above it)
#[no_mangle]
pub extern "C" fn step_init(log_blowup: u32, queries: u32, zk: u32, max_proof: u32) -> u32 {
    step_init2(log_blowup, queries, zk, max_proof, 0, 0, 0, 0)
}

/// step_init plus Goldilocks^5, Merkle cap height, FRI log arity and grinding bits (0 = default)
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn step_init2(log_blowup: u32, queries: u32, zk: u32, max_proof: u32, ext5: u32, cap: u32, arity: u32, pow: u32) -> u32 {
    let mut p = Params::DEFAULT;
    p.ext5 = ext5 != 0;
    p.cap_height = cap as usize;
    if arity != 0 {
        p.max_log_arity = arity as usize;
    }
    if pow != 0 {
        p.query_pow_bits = pow as usize;
    }
    if log_blowup != 0 {
        p.log_blowup = log_blowup as usize;
    }
    if queries != 0 {
        p.num_queries = queries as usize;
    }
    p.zk = zk != 0;
    if max_proof != 0 {
        p.max_proof = max_proof as usize;
    }
    ST.with(|c| *c.borrow_mut() = Some(St { s: setup(), p, proof: [vec![], vec![]], other: [vec![], vec![]], r: R(0x9E3779B97F4A7C15) }));
    KINDS.len() as u32
}

/// zero-knowledge WHIR (src/whirpcs.rs): proof limit, Goldilocks^5, WHIR starting rate, folding factor, grinding
/// bits, per-term target (0 = default)
#[no_mangle]
pub extern "C" fn step_init3(max_proof: u32, ext5: u32, rate: u32, fold: u32, pow: u32, target: u32) -> u32 {
    let n = step_init2(0, 0, 1, max_proof, ext5, 0, 0, 0);
    let d = pqzh::config::WhirParams::DEFAULT;
    let or = |v: u32, d: usize| if v != 0 { v as usize } else { d };
    with(|st| {
        st.p.whir = Some(pqzh::config::WhirParams {
            rate: or(rate, d.rate),
            fold: or(fold, d.fold),
            pow: or(pow, d.pow),
            target: or(target, d.target),
            ..d
        })
    });
    n
}

fn stmt_wit(st: &St, tx: u32) -> (&[u8], &[u8]) {
    if tx != 0 { (&st.s.tx_stmt, &st.s.tx_wit) } else { (&st.s.reg_stmt, &st.s.reg_wit) }
}

/// prove (seeded masks for ZK); returns the proof length, 0 on error
#[no_mangle]
pub extern "C" fn step_prove(tx: u32, seed: u32) -> u32 {
    with(|st| {
        let (s, w) = stmt_wit(st, tx);
        match prove(op(tx), s, w, [seed as u8; 32], &st.p) {
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
        let pf = prove(op(tx), &s2, w, [9; 32], &st.p).unwrap_or_default();
        let n = pf.len() as u32;
        st.other[tx as usize] = pf;
        n
    })
}

#[no_mangle]
pub extern "C" fn step_verify(tx: u32) -> u32 {
    with(|st| verify(op(tx), stmt_wit(st, tx).0, &st.proof[tx as usize], &st.p) as u32)
}

/// mutated input of `kind` (client::KINDS order); 1 = accepted (must not happen)
#[no_mangle]
pub extern "C" fn step_verify_bad(tx: u32, kind: u32) -> u32 {
    with(|st| {
        let stmt = if tx != 0 { &st.s.tx_stmt } else { &st.s.reg_stmt };
        let (s, p) = mutate(kind as usize, op(tx), stmt, &st.proof[tx as usize], &st.other[tx as usize], &mut st.r);
        verify(op(tx), &s, &p, &st.p) as u32
    })
}

/// FNV-1a of the last proof (native and wasm must agree for the same seed)
#[no_mangle]
pub extern "C" fn step_hash(tx: u32) -> u32 {
    with(|st| st.proof[tx as usize].iter().fold(2166136261u32, |h, &b| (h ^ b as u32).wrapping_mul(16777619)))
}

/// a buffer of `len` bytes in linear memory for step_load (proofs made natively: pqzh_bench --dump)
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
