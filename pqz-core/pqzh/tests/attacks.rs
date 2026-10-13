//! Honest proofs verify; mutated proofs / statements and out-of-range witnesses do not (run with --release).
use pqzh::client::{Tweak, digits, setup, setup_with};
use pqzh::rel::{OP_REGISTER, OP_TRANSFER, prove_unchecked};
use pqzh::{Params, prove, verify};

fn p() -> Params {
    Params::DEFAULT
}

/// a cheating prover gets either no proof or one that does not verify
fn rejected(op: u8, stmt: &[u8], wit: &[u8]) -> bool {
    let r = std::panic::catch_unwind(|| prove_unchecked(op, stmt, wit, [7; 32], &p()));
    match r {
        Ok(Ok(pf)) => !verify(op, stmt, &pf, &p()),
        _ => true,
    }
}

#[test]
fn honest_and_cross() {
    let s = setup();
    let pr = prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [1; 32], &p()).unwrap();
    let pt = prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [2; 32], &p()).unwrap();
    assert!(verify(OP_REGISTER, &s.reg_stmt, &pr, &p()));
    assert!(verify(OP_TRANSFER, &s.tx_stmt, &pt, &p()));
    // wrong op / swapped proofs / other parameters
    assert!(!verify(OP_TRANSFER, &s.reg_stmt, &pr, &p()));
    assert!(!verify(OP_REGISTER, &s.tx_stmt, &pt, &p()));
    assert!(!verify(OP_TRANSFER, &s.tx_stmt, &pr, &p()));
    let mut q = p();
    q.num_queries -= 1;
    assert!(!verify(OP_REGISTER, &s.reg_stmt, &pr, &q));
    let mut q = p();
    q.log_blowup -= 1;
    q.num_queries += 10;
    assert!(!verify(OP_REGISTER, &s.reg_stmt, &pr, &q));
}

#[test]
fn reg_norm_exceeded_small_coefficients() {
    // every |s_k| <= 1 but ||s||^2 = 1300 > 36^2: only the exact l2 check can catch it
    let mut sv = vec![0i64; 2048];
    for k in 0..1300 {
        sv[k] = if k % 2 == 0 { 1 } else { -1 };
    }
    let s = setup_with(&Tweak { s_f: Some(sv), ..Default::default() });
    assert!(prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [1; 32], &p()).is_err());
    assert!(rejected(OP_REGISTER, &s.reg_stmt, &s.reg_wit));
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &s.tx_wit));
}

#[test]
fn reg_coefficient_out_of_range() {
    let mut sv = vec![0i64; 2048];
    sv[5] = 100; // |s_5| > 36 (and > 64, the int8 witness still holds it)
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
    assert!(prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [1; 32], &p()).is_err());
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &s.tx_wit));
}

#[test]
fn tx_e2_norm_exceeded() {
    let mut e = vec![0i64; 16];
    e[0] = 65; // ||e2_t|| = 65 > 64
    let s = setup_with(&Tweak { e2_t: Some(e), ..Default::default() });
    assert!(prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [1; 32], &p()).is_err());
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &s.tx_wit));
}

#[test]
fn tx_overspend() {
    // spend 123,456 + 7 from a balance that does not cover it: d' digits of a "negative" new balance
    let s = setup();
    let mut w = s.tx_wit.clone();
    // claim new balance digits all 15 (2^64 - 1): the carry chain cannot close
    for i in 0..16 {
        w[12400 + i] = 15;
    }
    assert!(prove(OP_TRANSFER, &s.tx_stmt, &w, [1; 32], &p()).is_err());
    assert!(rejected(OP_TRANSFER, &s.tx_stmt, &w));
}
