//! The generic verifier against the C core (features `c-oracle`, `test-hooks`): `Ctx::verify` = `pqz_verify` on
//! the negative vectors, on proofs whose challenge coefficient is out of range (Review Focus 1), and on
//! `test_mutate` outputs over every relation code. Rust verifies on a second thread while C verifies on its own.
use pqzl::c_oracle::{c_test_mutate, c_verify};
use pqzl::testkit::proof_c_field;
use pqzl::{test_mutate, Ctx};

mod common;

/// xorshift64*
struct Rnd(u64);

impl Rnd {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(2_685_821_657_736_338_717)
    }
}

/// (Rust, C) verdicts, computed concurrently
fn both(ctx: &mut Ctx, op: u8, stmt: &[u8], proof: &[u8]) -> (bool, bool) {
    std::thread::scope(|s| {
        let r = s.spawn(|| ctx.verify(op, stmt, proof));
        let c = c_verify(op, stmt, proof);
        (r.join().unwrap(), c)
    })
}

/// one honest row per relation code (14: the six forms and the eight R_TXM shapes)
fn per_code() -> Vec<common::Row> {
    let mut out: Vec<common::Row> = Vec::new();
    for r in common::pqzl_rows() {
        if !out.iter().any(|x| x.code == r.code) {
            out.push(r);
        }
    }
    assert_eq!(out.len(), 14);
    out
}

#[test]
fn negative_eq_c() {
    let mut ctx = Ctx::new();
    let mut n = 0;
    for (name, b) in common::negative_inputs() {
        if let Some((op, stmt, proof)) = common::split(&b) {
            assert_eq!(both(&mut ctx, op, stmt, proof), (false, false), "{name}");
            n += 1;
        }
    }
    eprintln!("negative_eq_c: {n} rows, Rust = C = reject");
}

/// a challenge coefficient of 2 omega + 1 (the codec's bound) or 2^log2omega - 1: refused by the decoder in both
/// (test_mutate None) and rejected by both verifiers
#[test]
fn c_out_of_range_rejected() {
    let mut ctx = Ctx::new();
    for r in per_code() {
        let (off, bits, omega) = proof_c_field(r.code).unwrap();
        for (k, v) in [(0usize, 2 * omega + 1), (17, (1 << bits) - 1)] {
            let mut p = r.proof.clone();
            for b in 0..bits as usize {
                let i = off + k * bits as usize + b;
                p[i / 8] = (p[i / 8] & !(1 << (i % 8))) | ((((v >> b) & 1) as u8) << (i % 8));
            }
            assert_eq!(test_mutate(r.code, &p, 99, 0, 0), Ok(None), "{} c = {v}", r.name);
            assert_eq!(c_test_mutate(r.code, &p, 99, 0, 0), None, "{} c = {v}", r.name);
            assert_eq!(both(&mut ctx, r.op, &r.stmt, &p), (false, false), "{} c = {v}", r.name);
        }
    }
}

/// `test_mutate` outputs (kinds 0..15 and re-encode only, chained within a seed as in oracle_codec) over every
/// relation code: Rust verdict = C verdict. PQZL_MUTATED_N outputs (default 280, 20 per code; the brief's full
/// sample is 20,000: about 0.3 s per output, so hours; run it as a separate job).
#[test]
fn mutated_eq_c() {
    let n: usize = std::env::var("PQZL_MUTATED_N").ok().and_then(|s| s.parse().ok()).unwrap_or(280);
    let rows = per_code();
    let mut ctx = Ctx::new();
    let mut g = Rnd(0x7E57_5EED);
    let (mut done, mut acc) = (0, 0);
    'outer: for seed in 0.. {
        for r in &rows {
            let mut cur = r.proof.clone();
            let kind = (g.next() % 16) as u32;
            let (r1, r2) = (g.next(), g.next());
            let rust = test_mutate(r.code, &cur, kind, r1, r2).unwrap();
            assert_eq!(rust, c_test_mutate(r.code, &cur, kind, r1, r2), "{} seed {seed} kind {kind}", r.name);
            if let Some(m) = rust {
                cur = m;
            }
            let (a, b) = both(&mut ctx, r.op, &r.stmt, &cur);
            assert_eq!(a, b, "{} seed {seed} kind {kind}", r.name);
            acc += a as usize;
            done += 1;
            if done == n {
                break 'outer;
            }
        }
    }
    eprintln!("mutated_eq_c: {done} outputs, Rust = C ({acc} accepted by both)");
}

#[test]
fn cheating_eq_c() {
    let mut ctx = Ctx::new();
    for (case, op, stmt, proof, honest) in common::cheating() {
        assert_eq!(both(&mut ctx, op, &stmt, &proof), (honest, honest), "{case}");
    }
}

/// fix A (review G-3 / H-4): a statement one byte longer or shorter than its relation's, and a proof one byte over
/// the cap, are rejected by both cores and both verifiers (generic and specialised); `rel.rs`
/// `bad_length_refused_before_caches` and `pqz_sv_diff`'s `bad_length_before_keys` show it happens before any key is
/// built or the statement hashed
#[test]
fn bad_length_eq_c() {
    use pqzl::c_oracle::c_verify_fast;
    let mut ctx = Ctx::new();
    let big = vec![0u8; pqzl::MAX_PROOF + 1];
    for r in per_code() {
        let mut long = r.stmt.clone();
        long.push(0);
        let cases = [(&long[..], &r.proof[..]), (&r.stmt[..r.stmt.len() - 1], &r.proof[..]), (&r.stmt[..], &big[..])];
        for (i, (stmt, proof)) in cases.into_iter().enumerate() {
            assert_eq!(both(&mut ctx, r.op, stmt, proof), (false, false), "{} case {i}", r.name);
            assert!(!ctx.verify_fast(r.op, stmt, proof) && !c_verify_fast(r.op, stmt, proof), "{} fast case {i}", r.name);
        }
    }
}
