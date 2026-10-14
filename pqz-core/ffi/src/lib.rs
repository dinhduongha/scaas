//! `pqz-ffi`: the precompile boundary in front of both PQZ verifiers (P6e plan D10, R5; pq-zether.md §9.1,
//! CTR-PQZ-10).
//!
//! Input `u8(op) ‖ be32(len(stmt)) ‖ stmt ‖ proof` → `pqz_stmt::decode_input` (MAX_INPUT, op, opTag, id, the form's
//! length, every D15 / R6 rule, `1 ≤ len(proof) ≤ MAX_PROOF(id)`) → dispatch on the `proofSystemId` word: PQZL to the
//! C core's specialised verifier (`pqzl`, one process-wide lock), PQZH to Ligero (`pqzh`); op 6 to the cached
//! self-test (`selftest`). Output: 32 bytes, `…01` valid, `…00` anything else; the one revert is an input over
//! `MAX_INPUT`. Every entry catches panics; nothing here aborts.
//!
//! Rust API for the node: [`precompile`], [`verify_input`], [`decode`]. C ABI for P6f: [`pqz_precompile`]
//! (`pqz_ffi.h`). Feature `prove` (P6h): [`prove`], keygen / enc / dec in [`pqzl`], witness layouts and test
//! fixtures in [`fixture`].
#![deny(clippy::float_arithmetic)]

use std::panic::{AssertUnwindSafe, catch_unwind};

pub use pqz_stmt::{self as stmt, Input, MAX_INPUT, PQZH_ID, PQZL_ID, Reject, Word};

#[cfg(feature = "prove")]
pub mod fixture;
pub mod pqzh;
pub mod pqzl;
pub mod selftest;

/// The input is longer than `MAX_INPUT`: the precompile reverts (consumes all gas), pq-zether.md §9.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revert;

/// `…01`
pub const VALID: Word = {
    let mut w = [0u8; 32];
    w[31] = 1;
    w
};
/// `…00`
pub const INVALID: Word = [0u8; 32];

/// The precompile decoder (re-exported `pqz_stmt::decode_input`).
pub fn decode(input: &[u8]) -> Result<Input<'_>, Reject> {
    pqz_stmt::decode_input(input)
}

/// Decode and verify one input of op 1..5: true only for a canonical input whose proof the id's verifier accepts.
/// Op 6 (self-test) and anything undecodable is false. Panics propagate (callers: [`precompile`] catches them).
pub fn verify_input(input: &[u8]) -> bool {
    let Ok(inp) = decode(input) else { return false };
    match inp.stmt.proof_system_id() {
        Some(id) if *id == PQZL_ID => pqzl::verify_fast(inp.op, inp.stmt_bytes, inp.proof),
        Some(id) if *id == PQZH_ID => pqzh::verify(inp.op, inp.stmt_bytes, inp.proof),
        _ => false,
    }
}

enum Outcome {
    Word(Word),
    Revert,
    Panic,
}

fn run(input: &[u8]) -> Outcome {
    if input.len() > MAX_INPUT {
        return Outcome::Revert;
    }
    match catch_unwind(|| {
        if input == [6, 0, 0, 0, 0] {
            selftest::selftest()
        } else if verify_input(input) {
            VALID
        } else {
            INVALID
        }
    }) {
        Ok(w) => Outcome::Word(w),
        Err(_) => Outcome::Panic,
    }
}

/// The precompile: `Ok(…01 / …00 / the self-test hash)`, `Err(Revert)` only for an input over `MAX_INPUT`. A panic
/// anywhere below gives `…00` (CTR-PQZ-10).
pub fn precompile(input: &[u8]) -> Result<Word, Revert> {
    match run(input) {
        Outcome::Word(w) => Ok(w),
        Outcome::Revert => Err(Revert),
        Outcome::Panic => Ok(INVALID),
    }
}

/// `out[0..32]` holds the result (`…01`, `…00`, or the self-test hash)
pub const PQZ_FFI_OK: i32 = 0;
/// input longer than `MAX_INPUT`: revert; `out` zeroed
pub const PQZ_FFI_REVERT: i32 = 1;
/// `input` null with `len > 0`, `out` null, or `out_len < 32`; nothing written
pub const PQZ_FFI_BAD_ARGS: i32 = 2;
/// a panic was caught below the entry; `out` = `…00` (the result is invalid, CTR-PQZ-10); worth a log line
pub const PQZ_FFI_INTERNAL: i32 = 3;

/// C ABI for the node (P6f, P/Invoke): see `pqz_ffi.h`. Thread-safe (libpqz calls are serialised inside); never
/// unwinds or aborts.
///
/// # Safety
/// `input` must point to `len` readable bytes (or be null with `len == 0`), `out` to `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pqz_precompile(input: *const u8, len: usize, out: *mut u8, out_len: usize) -> i32 {
    if (input.is_null() && len > 0) || out.is_null() || out_len < 32 {
        return PQZ_FFI_BAD_ARGS;
    }
    let inp = if len == 0 { &[][..] } else { std::slice::from_raw_parts(input, len) };
    let out = std::slice::from_raw_parts_mut(out, 32);
    let (w, rc) = match catch_unwind(AssertUnwindSafe(|| run(inp))).unwrap_or(Outcome::Panic) {
        Outcome::Word(w) => (w, PQZ_FFI_OK),
        Outcome::Revert => (INVALID, PQZ_FFI_REVERT),
        Outcome::Panic => (INVALID, PQZ_FFI_INTERNAL),
    };
    out.copy_from_slice(&w);
    rc
}

/// Why `prove` failed.
#[cfg(feature = "prove")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProveError {
    /// the statement does not decode (`pqz_stmt::parse`)
    Statement(Reject),
    /// PQZL: the core's error code (pqz_rt.h: 3 input, 4 reject, 5 arena, …)
    Pqzl(i32),
    /// PQZH: Ligero's message
    Pqzh(&'static str),
    /// a panic below (caught)
    Panic,
}

/// Prove `stmt` (op `op`) with the prover-API witness `wit` (pqz.h layouts, [`fixture`]) and 32 bytes of CSPRNG
/// output; the proof system is the statement's `proofSystemId`. Deterministic in its inputs (both provers hedge
/// `rnd32` with the statement and the witness, CTR-PQZ-19). Panics are caught.
#[cfg(feature = "prove")]
pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, ProveError> {
    let st = pqz_stmt::parse(op, stmt).map_err(ProveError::Statement)?;
    let id = *st.proof_system_id().ok_or(ProveError::Statement(Reject::Op))?;
    catch_unwind(|| {
        if id == PQZL_ID {
            pqzl::prove(op, stmt, wit, rnd32).map_err(ProveError::Pqzl)
        } else {
            pqzh::prove(op, stmt, wit, rnd32).map_err(ProveError::Pqzh)
        }
    })
    .unwrap_or(Err(ProveError::Panic))
}
