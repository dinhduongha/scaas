//! Honest proofs verify; mutated proofs / statements and invalid witnesses do not (run with --release).
use pqzh::client::{KINDS, R, Tweak, digits, mutate, setup, setup_with};
use pqzh_ligero::ligero::VERIFY_PANICS;
use pqzh_ligero::{OP_REGISTER, OP_TRANSFER, Params, prove, prove_unchecked, verify};

fn p(op: u8) -> Params {
    Params::preset(op, true, true)
}

/// a cheating prover gets either no proof or one that does not verify
fn rejected(op: u8, stmt: &[u8], wit: &[u8]) -> bool {
    match std::panic::catch_unwind(|| prove_unchecked(op, stmt, wit, [7; 32], &p(op))) {
        Ok(Ok(pf)) => !verify(op, stmt, &pf, &p(op)),
        _ => true,
    }
}

#[test]
fn honest_all_presets_cross_and_hiding() {
    let s = setup();
    for proven in [true, false] {
        for r431 in [true, false] {
            for (op, st, w) in [(OP_REGISTER, &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, &s.tx_stmt, &s.tx_wit)] {
                let pp = Params::preset(op, proven, r431);
                let t = std::time::Instant::now();
                let a = prove(op, st, w, [1; 32], &pp).unwrap();
                eprintln!("op {op} {pp:?}: {} B, {:?}", a.len(), t.elapsed());
                assert!(verify(op, st, &a, &pp));
                assert!(a.len() <= pp.max_len(op));
            }
        }
    }
    for (op, st, w) in [(OP_REGISTER, &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, &s.tx_stmt, &s.tx_wit)] {
        let pj = Params::johnson_preset();
        let a = prove(op, st, w, [1; 32], &pj).unwrap();
        eprintln!("op {op} {pj:?}: {} B", a.len());
        assert!(verify(op, st, &a, &pj));
        assert!(!verify(op, st, &a, &Params::preset(op, true, false)));
    }
    let (pr, pt) = (p(OP_REGISTER), p(OP_TRANSFER));
    let a = prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [1; 32], &pr).unwrap();
    let b = prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [2; 32], &pr).unwrap();
    let x = prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [1; 32], &pt).unwrap();
    assert_ne!(a, b, "proofs depend on the prover's randomness");
    assert!(verify(OP_REGISTER, &s.reg_stmt, &b, &pr));
    // wrong op / swapped proofs / other parameters
    assert!(!verify(OP_TRANSFER, &s.reg_stmt, &a, &pt));
    assert!(!verify(OP_REGISTER, &s.tx_stmt, &x, &pr));
    assert!(!verify(OP_TRANSFER, &s.tx_stmt, &a, &pt));
    assert!(!verify(OP_REGISTER, &s.reg_stmt, &a, &Params::preset(OP_REGISTER, true, false)));
    assert!(!verify(OP_REGISTER, &s.reg_stmt, &a, &Params::new(32756, 817, false)));
}

#[test]
fn mutations_960_rejected() {
    let s = setup();
    let p0 = VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed);
    let mut total = 0;
    for (op, st, w) in [(OP_REGISTER, &s.reg_stmt, &s.reg_wit), (OP_TRANSFER, &s.tx_stmt, &s.tx_wit)] {
        let pp = p(op);
        let pf = prove(op, st, w, [3; 32], &pp).unwrap();
        let mut st2 = st.clone();
        st2[0] ^= 0x80;
        let other = prove(op, &st2, w, [9; 32], &pp).unwrap();
        assert!(verify(op, &st2, &other, &pp));
        let mut r = R(0x9E3779B97F4A7C15 ^ op as u64);
        for k in 0..KINDS.len() {
            for _ in 0..40 {
                let (ms, mp) = mutate(k, op, st, &pf, &other, &mut r);
                assert!(!verify(op, &ms, &mp, &pp), "op {op} kind {} accepted", KINDS[k]);
                total += 1;
            }
        }
    }
    assert_eq!(total, 960);
    eprintln!("960 mutated inputs rejected, {} verifier panics caught", VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed) - p0);
}

#[test]
fn reg_norm_exceeded_small_coefficients() {
    // every |s_k| <= 1 but ||s||^2 = 1300 > 36^2: only the exact l2 check can catch it
    let mut sv = vec![0i64; 2048];
    for k in 0..1300 {
        sv[k] = if k % 2 == 0 { 1 } else { -1 };
    }
    let s = setup_with(&Tweak { s_f: Some(sv), ..Default::default() });
    assert!(prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [1; 32], &p(OP_REGISTER)).is_err());
    assert!(rejected(OP_REGISTER, &s.reg_stmt, &s.reg_wit));
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &s.tx_wit));
}

#[test]
fn reg_coefficient_out_of_range() {
    let mut sv = vec![0i64; 2048];
    sv[5] = 100; // |s_5| > 36 (and > 64, outside the 7 bits of s + 64)
    let s = setup_with(&Tweak { s_f: Some(sv), ..Default::default() });
    assert!(rejected(OP_REGISTER, &s.reg_stmt, &s.reg_wit));
}

#[test]
fn tx_digit_out_of_range() {
    // amount digits with d_0 = 16 + 7, d_1 = 3 - 1: same value, digit 0 outside 4 bits
    let mut d = digits(123_456);
    d[0] += 16;
    d[1] -= 1;
    let s = setup_with(&Tweak { d: Some(d), ..Default::default() });
    assert!(prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [1; 32], &p(OP_TRANSFER)).is_err());
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &s.tx_wit));
}

#[test]
fn tx_e2_norm_exceeded() {
    let mut e = vec![0i64; 16];
    e[0] = 65; // ||e2_t|| = 65 > 64
    let s = setup_with(&Tweak { e2_t: Some(e), ..Default::default() });
    assert!(prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [1; 32], &p(OP_TRANSFER)).is_err());
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &s.tx_wit));
}

#[test]
fn tx_overspend() {
    // claim new balance digits all 15 (2^64 - 1): the carry chain cannot close
    let s = setup();
    let mut w = s.tx_wit.clone();
    for i in 0..16 {
        w[12400 + i] = 15;
    }
    assert!(prove(OP_TRANSFER, &s.tx_stmt, &w, [1; 32], &p(OP_TRANSFER)).is_err());
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &w));
}

#[test]
fn tx_fee_word_above_2_64() {
    let s = setup();
    let pt = prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [2; 32], &p(OP_TRANSFER)).unwrap();
    let mut st = s.tx_stmt.clone();
    st[pqzh::rel::HDR_FEE + 23] = 1;
    assert!(prove(OP_TRANSFER, &st, &s.tx_wit, [2; 32], &p(OP_TRANSFER)).is_err());
    assert!(!verify(OP_TRANSFER, &st, &pt, &p(OP_TRANSFER)));
}

#[test]
fn tx_wrong_witness_ring_row() {
    // e1 changed in one coefficient (still short): u != A^T r + e1 mod q, the linear test must catch it
    let s = setup();
    let mut w = s.tx_wit.clone();
    w[8192] = w[8192].wrapping_add(1);
    assert!(prove(OP_TRANSFER, &s.tx_stmt, &w, [1; 32], &p(OP_TRANSFER)).is_err());
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &w));
}
