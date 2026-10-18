//! The PQZL backend in Rust (feature `pqzl-rust`, the default since owner 2026-10-18, CTR-PQZ-09): the crate `pqzl`
//! (`pqz-core/pqzl/rust`), byte-for-byte equal to the C core (same proofs, verdicts, keys, Enc / Dec); no C, no unsafe
//! code in the core.
//!
//! One `pqzl::Ctx` for the process (A, each relation's keys and the specialised verifier's tables, built at first use;
//! about 41 KB inline, so boxed, never on a caller's stack), behind a `Mutex`, used on the worker (`super::on_worker`):
//! the C core's model without its arena. One locked `Ctx` rather than one per thread: Nethermind calls the precompile
//! from several threads (block processing, the RPC pool); a thread-local `Ctx` would build and keep a full cache set
//! per calling thread (memory × threads) and pay a cold build on each new pool thread, so a verify's time would depend
//! on the thread it lands on instead of the calibrated warm figure. Calls are serialised, as with the C core.
//! ponytail: one verify at a time; a small pool of `Ctx`s if parallel verification ever matters.
//!
//! Faults: the worker unavailable is `NodeFault`, as with the C core. A panic inside the core (the C core cannot
//! panic) is caught on the worker, the `Ctx` is dropped (rebuilt at the next call) and the panic resumes on the
//! caller's thread, where `crate::precompile` classifies it as input-caused (`…00`, status 3). An allocation failure
//! inside the core is a fault of this node, not of the input: the verifiers (`try_verify_fast` / `try_verify`) give
//! `Error::Memory` → `NodeFault` (status 4, as the C backend's arena exhaustion), never `…00`, so a node under memory
//! pressure cannot reject a proof its peers accept; `prove` gives code 2. Every other core error is the verdict
//! false, as the C backend (only `pqz_err == PQZ_ERR_ARENA` is a node fault there).
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Mutex;

use ::pqzl::Ctx;

use super::{on_worker, Enc, Key, NodeFault, Worker, CT_BYTES, PK_BYTES};

const _: () = assert!(
    super::WASM_PQZL_MAX_LEGS == ::pqzl::WASM_MAX_LEGS
        && super::MAX_PROOF == ::pqzl::MAX_PROOF
        && PK_BYTES == ::pqzl::POLYVEC_BYTES
        && CT_BYTES == ::pqzl::CT_BYTES
);

struct State {
    ctx: Option<Box<Ctx>>,
    worker: Option<Worker>,
}

static STATE: Mutex<State> = Mutex::new(State { ctx: None, worker: None });

/// Runs `f` under the lock, on the worker, with the process's `Ctx` (created at the first call). `Err(NodeFault)` if
/// the worker is unavailable; a panic in `f` drops the `Ctx` and resumes on the caller's thread. A poisoned lock is
/// recovered with a fresh `Ctx`.
fn with_ctx<T: Send>(f: impl FnOnce(&mut Ctx) -> T + Send) -> Result<T, NodeFault> {
    let mut g = STATE.lock().unwrap_or_else(|e| {
        STATE.clear_poison();
        let mut g = e.into_inner();
        g.ctx = None;
        g
    });
    let State { ctx, worker } = &mut *g;
    let r = on_worker(worker, || catch_unwind(AssertUnwindSafe(|| f(ctx.get_or_insert_with(|| Box::new(Ctx::new()))))));
    match r {
        Some(Ok(out)) => Ok(out),
        Some(Err(panic)) => {
            g.ctx = None;
            drop(g);
            resume_unwind(panic)
        }
        None => {
            g.ctx = None;
            Err(NodeFault)
        }
    }
}

/// The precompile path (plan R5): the specialised verifier. `stmt` / `proof` are passed through as given; the caller
/// (`crate::verify`) has decoded them.
pub fn verify_fast(op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, NodeFault> {
    verdict(with_ctx(|c| c.try_verify_fast(op, stmt, proof))?)
}

/// A verifier's result: out of memory is a node fault; any other error (`try_verify*` returns none today) is the
/// verdict false, so a future pqzl error can never become an input-reachable node fault.
fn verdict(r: Result<bool, ::pqzl::Error>) -> Result<bool, NodeFault> {
    match r {
        Ok(v) => Ok(v),
        Err(::pqzl::Error::Memory) => Err(NodeFault),
        Err(_) => Ok(false),
    }
}

/// `verify_fast` on the caller's thread, without the worker hop (bench: the FFI's overhead against the bare call;
/// the caller's stack must be large enough). The `Ctx` must exist (any earlier call).
#[doc(hidden)]
pub fn verify_fast_on_caller(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    g.ctx.as_mut().is_some_and(|c| c.verify_fast(op, stmt, proof))
}

/// `pqzl::test_mutate` (feature `fuzz` only): decode `proof` for relation `rel` (an op, 0x81 for `R_TX0`, or an
/// `R_TXM` shape code), change one field (`kind` 0..13 with `r1` / `r2`; any other kind changes nothing) and
/// re-encode. `Ok(None)`: the proof does not decode.
#[cfg(feature = "fuzz")]
pub fn test_mutate(rel: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Result<Option<Vec<u8>>, NodeFault> {
    with_ctx(|_| ::pqzl::test_mutate(rel, proof, kind, r1, r2))?.map_err(|_| NodeFault)
}

/// The generic verifier (LaZer's), the reference for differential tests; never on the precompile path.
pub fn verify_generic(op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, NodeFault> {
    verdict(with_ctx(|c| c.try_verify(op, stmt, proof))?)
}

/// pk = A·s + e (`pqz_keypair_from_secret`; no norm check): the self-test reads the columns of A with it.
pub fn keypair_from_secret(s: &[i8; 2048], e: &[i16; 2048]) -> Option<Box<[u8; PK_BYTES]>> {
    with_ctx(|c| c.keypair_from_secret(s, e)).ok()?.ok()
}

pub fn keygen(seed32: &[u8; 32]) -> Option<Key> {
    let k = with_ctx(|c| c.keygen(seed32)).ok()?.ok()?;
    Some(Key { pk: k.pk, s: k.s, e: k.e, ctr: k.ctr })
}

pub fn enc(pks: &[&[u8; PK_BYTES]], msgs: &[[u8; 16]], seed_enc: &[u8; 32]) -> Option<Enc> {
    if pks.is_empty() {
        return None; // as the C backend (the core takes a count; the lengths it checks)
    }
    let c = with_ctx(|c| c.enc_seed(pks, msgs, seed_enc)).ok()?.ok()?;
    Some(Enc { u: c.u, vs: c.vs, r: c.r, e1: c.e1, e2: c.e2, ctr: c.ctr })
}

/// `seed_enc_g` of `R_TXM` group `g` (P6-ANON D13, `pqz_enc_group_seed`): `seed_enc` for g = 0, else
/// `SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" ‖ seed_enc ‖ be4(g))[0..32)`. Pure hashing (no core state, no lock).
pub fn enc_group_seed(seed_enc: &[u8; 32], g: usize) -> [u8; 32] {
    ::pqzl::enc_group_seed(seed_enc, g as u32)
}

/// Dec of `ct = u ‖ v` (16,512 B) with `s`: the 16 digits `M` and their noise (§4.2, `pqz_dec`).
pub fn dec(s: &[i8; 2048], ct: &[u8; CT_BYTES]) -> Option<([i64; 16], [i64; 16])> {
    with_ctx(|_| ::pqzl::dec(s, ct)).ok()?.ok()
}

/// `pqz_prove`: the proof, or the core's error code (pqz_rt.h: 1 internal, 2 memory, 3 input, 4 rejection cap; -1 a
/// node fault, `with_ctx`).
#[cfg(feature = "prove")]
pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, i32> {
    use ::pqzl::Error::*;
    with_ctx(|c| c.prove(op, stmt, wit, rnd32)).map_err(|NodeFault| -1)?.map_err(|e| match e {
        Internal => 1,
        Memory => 2,
        Input => 3,
        Reject => 4,
    })
}

/// Encryption with chosen short vectors (`pqz_encrypt`, no norm check): `u = A^T r + e1`, `v_j = pk_j^T r + e2_j +
/// Delta m_j`. Vectors and tests only (the worst-case noise KAT builds aligned credits with it).
#[cfg(feature = "prove")]
pub fn encrypt(
    pks: &[&[u8; PK_BYTES]],
    msgs: &[[u8; 16]],
    r: &[i8; 2048],
    e1: &[i16; 2048],
    e2: &[[i16; 16]],
) -> Option<super::Encrypted> {
    if pks.is_empty() {
        return None;
    }
    let c = with_ctx(|c| c.encrypt(pks, msgs, r, e1, e2)).ok()?.ok()?;
    Some((c.u, c.vs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_memory_is_a_node_fault() {
        assert_eq!(verdict(Ok(true)), Ok(true));
        assert_eq!(verdict(Ok(false)), Ok(false));
        assert_eq!(verdict(Err(::pqzl::Error::Memory)), Err(NodeFault));
        for e in [::pqzl::Error::Internal, ::pqzl::Error::Input, ::pqzl::Error::Reject] {
            assert_eq!(verdict(Err(e)), Ok(false));
        }
    }
}
