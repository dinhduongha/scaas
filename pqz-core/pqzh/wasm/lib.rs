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
    let mut p = Params::DEFAULT;
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
