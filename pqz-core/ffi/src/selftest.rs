//! `OP_SELFTEST` (plan D13, pq-zero-knowledge.md §9.1): `keccak256(kat_digest ‖ u8(pqzl_valid) ‖ u8(pqzl_invalid) ‖
//! u8(pqzh_valid) ‖ u8(pqzh_invalid))`, computed at the first call in a process and cached.
//!
//! `kat_digest = keccak256(a_digest ‖ keccak256(pk) ‖ keccak256(u ‖ v) ‖ M ‖ keccak256(fft) ‖ u8(fft_ok))`:
//! - `a_digest` = keccak256 of A as `pqz_kat.py` writes it (A[0][0], A[0][1], …, 64 `be8` coefficients each), read
//!   from the core column by column (`pk = A·e_j`);
//! - `pk` = KeyGen(`SEED_KEY`); `u ‖ v` = Enc(pk, digits(`MSG_VALUE`), `SEED_ENC`); `M` = Dec(s, u ‖ v) as 16 bytes;
//! - `fft` = Ligero's forward FFT of a fixed vector over its 1,634-point domain, `fft_ok` = the inverse gives it back.
//!
//! The four results are the precompile's verify path on compiled-in `R_REG` vectors, one per id: the statement
//! `opTag ‖ id ‖ MESSAGE ‖ pk` (pk from `SEED_KEY`), the proof = the REGISTER row of
//! `smartcontracts/vectors/pqz/proof_<id>.json` (proved with `RND`; build.rs reads it, plan D9: no copy; written by
//! `pqz-vectors`, `tests/ffi.rs` `selftest_vectors` checks a fresh prove equals it); invalid = the same proof under the
//! statement with the last message byte flipped. Frozen with the vectors (`selftest.json`, P6e Task 11).
use std::sync::OnceLock;

use pqz_stmt::{Form, Register, Stmt, Word, PQZH_ID, PQZL_ID};
use sha3::{Digest, Keccak256};

use crate::{pqzh, pqzl};

pub const SEED_KEY: [u8; 32] = [0x51; 32];
pub const SEED_ENC: [u8; 32] = [0x52; 32];
pub const RND: [u8; 32] = [0x53; 32];
pub const MSG_VALUE: u64 = 123_456;
/// the R_REG message word: keccak256("SCAAS-PQZ-SELFTEST-V1")
pub fn message() -> Word {
    keccak(&[b"SCAAS-PQZ-SELFTEST-V1"])
}

static PQZL_PROOF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pqzl_reg.bin"));
static PQZH_PROOF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pqzh_reg.bin"));

/// The compiled-in R_REG proofs (PQZL, PQZH).
pub fn proofs() -> [&'static [u8]; 2] {
    [PQZL_PROOF, PQZH_PROOF]
}

pub fn keccak(parts: &[&[u8]]) -> Word {
    let mut h = Keccak256::new();
    parts.iter().for_each(|p| h.update(p));
    h.finalize().into()
}

pub fn digits(x: u64) -> [u8; 16] {
    core::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}

/// The self-test's `R_REG` statement for `id` (its key: KeyGen(`SEED_KEY`)).
pub fn reg_statement(id: &Word, pk: &[u8]) -> Vec<u8> {
    let r = Register { words: [Form::Register.op_tag(), *id, message()], pk };
    Stmt::Register(r).encode().unwrap_or_default()
}

/// Every input of the self-test hash (tests and `selftest.json` read the parts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub a_digest: Word,
    pub pk_hash: Word,
    pub ct_hash: Word,
    pub m: [u8; 16],
    pub fft_hash: Word,
    pub fft_ok: bool,
    pub kat_digest: Word,
    /// pqzl valid, pqzl invalid, pqzh valid, pqzh invalid
    pub results: [bool; 4],
    pub hash: Word,
}

/// A in `pqz_kat.py`'s order, from 32 calls `pk = A·e_j + 0`.
pub fn a_bytes() -> Option<Vec<u8>> {
    let mut cols = Vec::with_capacity(32);
    for j in 0..32 {
        let mut s = [0i8; 2048];
        s[64 * j] = 1;
        cols.push(pqzl::keypair_from_secret(&s, &[0; 2048])?);
    }
    let mut a = Vec::with_capacity(32 * pqzl::PK_BYTES);
    for i in 0..32 {
        cols.iter().for_each(|c| a.extend_from_slice(&c[512 * i..512 * (i + 1)]));
    }
    Some(a)
}

pub fn report() -> Option<Report> {
    let a_digest = keccak(&[&a_bytes()?]);
    let key = pqzl::keygen(&SEED_KEY)?;
    let c = pqzl::enc(&[&key.pk], &[digits(MSG_VALUE)], &SEED_ENC)?;
    let mut ct = Box::new([0u8; pqzl::CT_BYTES]);
    ct[..pqzl::PK_BYTES].copy_from_slice(&c.u[..]);
    ct[pqzl::PK_BYTES..].copy_from_slice(&c.vs[0]);
    let (m, _) = pqzl::dec(&key.s, &ct)?;
    let m: [u8; 16] = core::array::from_fn(|i| m[i] as u8);
    let (fft, fft_ok) = pqzh::fft_kat();
    let (pk_hash, ct_hash, fft_hash) = (keccak(&[&key.pk[..]]), keccak(&[&ct[..]]), keccak(&[&fft]));
    let kat_digest = keccak(&[&a_digest, &pk_hash, &ct_hash, &m, &fft_hash, &[fft_ok as u8]]);
    let mut results = [false; 4];
    for (i, (id, proof)) in [(PQZL_ID, PQZL_PROOF), (PQZH_ID, PQZH_PROOF)].into_iter().enumerate() {
        let mut st = reg_statement(&id, &key.pk[..]);
        let mut input = pqz_stmt::input(3, &st, proof);
        results[2 * i] = crate::verify_input(&input).ok()?;
        st[95] ^= 1;
        input = pqz_stmt::input(3, &st, proof);
        results[2 * i + 1] = crate::verify_input(&input).ok()?;
    }
    let r = results.map(|b| b as u8);
    let hash = keccak(&[&kat_digest, &r]);
    Some(Report { a_digest, pk_hash, ct_hash, m, fft_hash, fft_ok, kat_digest, results, hash })
}

static CACHE: OnceLock<Word> = OnceLock::new();

/// The `OP_SELFTEST` output, cached for the process. A computation that fails (a core call failed or panicked: its
/// inputs are fixed, so never the caller's input) is a node fault, not cached, retried at the next call.
pub fn selftest() -> Result<Word, crate::NodeFault> {
    if let Some(h) = CACHE.get() {
        return Ok(*h);
    }
    match std::panic::catch_unwind(report) {
        Ok(Some(r)) => Ok(*CACHE.get_or_init(|| r.hash)),
        _ => Err(crate::NodeFault),
    }
}
