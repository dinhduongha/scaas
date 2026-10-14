//! Honest proofs verify; mutated proofs / statements and invalid witnesses do not (run with --release).
use pqzh_ligero::client::{KINDS, R, Setup, Tweak, digits, mutate, rel_name, setup, setup_with};
use pqzh_ligero::ligero::VERIFY_PANICS;
use pqzh_ligero::stmt::{DISC_AMOUNT, HDR_AMOUNT, HDR_FEE};
use pqzh_ligero::{OP_BURN, OP_DISCLOSE_RECEIVER, OP_DISCLOSE_SENDER, OP_REGISTER, OP_TRANSFER, OPS, Params, prove, prove_unchecked, verify};

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

/// the honest prover refuses and a proof without its checks does not verify
fn refused(op: u8, s: &Setup) -> bool {
    let (st, w) = s.rel(op);
    prove(op, st, w, [1; 32], &p(op)).is_err() && rejected(op, st, w)
}

#[test]
fn honest_all_presets_cross_and_hiding() {
    let s = setup();
    for proven in [true, false] {
        for r431 in [true, false] {
            for op in OPS {
                let (st, w) = s.rel(op);
                let pp = Params::preset(op, proven, r431);
                let t = std::time::Instant::now();
                let a = prove(op, st, w, [1; 32], &pp).unwrap();
                eprintln!("{} {pp:?}: {} B, {:?}", rel_name(op), a.len(), t.elapsed());
                assert!(verify(op, st, &a, &pp));
                assert!(a.len() <= pp.max_len_exact(op) && pp.max_len_exact(op) <= pp.max_len(op));
            }
        }
    }
    for op in OPS {
        let (st, w) = s.rel(op);
        let pj = Params::johnson_preset();
        let a = prove(op, st, w, [1; 32], &pj).unwrap();
        eprintln!("{} {pj:?}: {} B", rel_name(op), a.len());
        assert!(verify(op, st, &a, &pj));
        assert!(!verify(op, st, &a, &Params::preset(op, true, false)));
    }
    let (pr, pt) = (p(OP_REGISTER), p(OP_TRANSFER));
    let a = prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [1; 32], &pr).unwrap();
    let b = prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [2; 32], &pr).unwrap();
    let x = prove(OP_TRANSFER, &s.tx_stmt, &s.tx_wit, [1; 32], &pt).unwrap();
    assert_ne!(a, b, "proofs depend on the prover's randomness");
    assert_eq!(a, prove(OP_REGISTER, &s.reg_stmt, &s.reg_wit, [1; 32], &pr).unwrap(), "deterministic in its inputs");
    assert!(verify(OP_REGISTER, &s.reg_stmt, &b, &pr));
    // wrong op / swapped proofs / other parameters
    assert!(!verify(OP_TRANSFER, &s.reg_stmt, &a, &pt));
    assert!(!verify(OP_REGISTER, &s.tx_stmt, &x, &pr));
    assert!(!verify(OP_TRANSFER, &s.tx_stmt, &a, &pt));
    assert!(!verify(OP_REGISTER, &s.reg_stmt, &a, &Params::preset(OP_REGISTER, true, false)));
    assert!(!verify(OP_REGISTER, &s.reg_stmt, &a, &Params::new(32756, 817, false)));
    // every proof under every other op (R_DS / R_DR share the statement length), and unknown ops
    let proofs: Vec<Vec<u8>> = OPS.iter().map(|&op| prove(op, s.rel(op).0, s.rel(op).1, [4; 32], &p(op)).unwrap()).collect();
    for (i, &op) in OPS.iter().enumerate() {
        for &o2 in OPS.iter().chain(&[0, 6, 255]) {
            if o2 != op {
                assert!(!verify(o2, s.rel(op).0, &proofs[i], &p(op)), "{} proof accepted as op {o2}", rel_name(op));
            }
        }
    }
}

#[test]
fn mutations_960_per_relation_rejected() {
    let s = setup();
    let p0 = VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed);
    for op in OPS {
        let (st, w) = s.rel(op);
        let pp = p(op);
        let pf = prove(op, st, w, [3; 32], &pp).unwrap();
        let mut st2 = st.clone();
        st2[0] ^= 0x80;
        let other = prove(op, &st2, w, [9; 32], &pp).unwrap();
        assert!(verify(op, &st2, &other, &pp));
        let mut r = R(0x9E3779B97F4A7C15 ^ op as u64);
        let mut total = 0;
        for k in 0..KINDS.len() {
            for _ in 0..80 {
                let (ms, mp) = mutate(k, op, st, &pf, &other, &mut r);
                assert!(!verify(op, &ms, &mp, &pp), "{} kind {} accepted", rel_name(op), KINDS[k]);
                total += 1;
            }
        }
        assert_eq!(total, 960);
    }
    eprintln!("5 x 960 mutated inputs rejected, {} verifier panics caught", VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed) - p0);
}

/// every |s_k| <= 1 but ||s||^2 = 1300 > 36^2: only the exact l2 check can catch it
fn small_but_long() -> Vec<i64> {
    let mut sv = vec![0i64; 2048];
    for k in 0..1300 {
        sv[k] = if k % 2 == 0 { 1 } else { -1 };
    }
    sv
}

/// |s_5| = 100 > 36 (and > 64, outside the 7 bits of s + 64)
fn one_large() -> Vec<i64> {
    let mut sv = vec![0i64; 2048];
    sv[5] = 100;
    sv
}

/// d_0 = 16 + 7, d_1 = 3 - 1 of 123,456: same value, digit 0 outside 4 bits
fn bad_digits(x: u64) -> [u8; 16] {
    let mut d = digits(x);
    d[0] += 16;
    d[1] -= 1;
    d
}

/// ||e|| = 65 > 64 with one small coefficient
fn e2_65() -> Vec<i64> {
    let mut e = vec![0i64; 16];
    e[0] = 65;
    e
}

#[test]
fn norm_exceeded_small_coefficients() {
    let s = setup_with(&Tweak { s_f: Some(small_but_long()), ..Default::default() });
    for op in [OP_REGISTER, OP_TRANSFER, OP_BURN] {
        assert!(refused(op, &s), "{}", rel_name(op));
    }
    let s = setup_with(&Tweak { s_t: Some(small_but_long()), ..Default::default() });
    assert!(refused(OP_DISCLOSE_RECEIVER, &s));
}

#[test]
fn coefficient_out_of_range() {
    let s = setup_with(&Tweak { s_f: Some(one_large()), ..Default::default() });
    assert!(rejected(OP_REGISTER, &s.reg_stmt, &s.reg_wit));
    assert!(rejected(OP_BURN, &s.burn_stmt, &s.burn_wit));
    let s = setup_with(&Tweak { s_t: Some(one_large()), ..Default::default() });
    assert!(rejected(OP_DISCLOSE_RECEIVER, &s.dr_stmt, &s.dr_wit));
}

#[test]
fn digit_out_of_range() {
    let s = setup_with(&Tweak { d: Some(bad_digits(123_456)), ..Default::default() });
    assert!(refused(OP_TRANSFER, &s));
    let s = setup_with(&Tweak { burn_dp: Some(bad_digits(1_000_000 - 123_456 - 7)), ..Default::default() });
    assert!(refused(OP_BURN, &s));
}

#[test]
fn e2_norm_exceeded() {
    // R_TX's e2_t is R_DS's e2
    let s = setup_with(&Tweak { e2_t: Some(e2_65()), ..Default::default() });
    assert!(refused(OP_TRANSFER, &s));
    assert!(refused(OP_DISCLOSE_SENDER, &s));
    let s = setup_with(&Tweak { burn_e2: Some(e2_65()), ..Default::default() });
    assert!(refused(OP_BURN, &s));
}

#[test]
fn overspend() {
    // claim new balance digits all 15 (2^64 - 1): the carry chain cannot close
    let s = setup();
    for (op, off) in [(OP_TRANSFER, 12400), (OP_BURN, 12320)] {
        let (st, w) = s.rel(op);
        let mut w = w.clone();
        w[off..off + 16].fill(15);
        assert!(prove(op, st, &w, [1; 32], &p(op)).is_err());
        assert!(rejected(op, st, &w), "{}", rel_name(op));
    }
}

#[test]
fn wrong_public_amount() {
    // the statement claims amount + 1 with the honest witness
    let s = setup();
    for (op, off) in [(OP_BURN, HDR_AMOUNT), (OP_DISCLOSE_SENDER, DISC_AMOUNT), (OP_DISCLOSE_RECEIVER, DISC_AMOUNT)] {
        let (st, w) = s.rel(op);
        let mut st = st.clone();
        st[off + 31] ^= 1; // 123,456 = 0x1e240: + 1
        assert!(prove(op, &st, w, [1; 32], &p(op)).is_err());
        assert!(rejected(op, &st, w), "{}", rel_name(op));
    }
}

#[test]
fn scalar_word_above_2_64() {
    let s = setup();
    for (op, off) in [(OP_TRANSFER, HDR_FEE), (OP_BURN, HDR_FEE), (OP_BURN, HDR_AMOUNT), (OP_DISCLOSE_SENDER, DISC_AMOUNT), (OP_DISCLOSE_RECEIVER, DISC_AMOUNT)] {
        let (st, w) = s.rel(op);
        let pf = prove(op, st, w, [2; 32], &p(op)).unwrap();
        let mut st = st.clone();
        st[off + 23] = 1;
        assert!(prove(op, &st, w, [2; 32], &p(op)).is_err());
        assert!(!verify(op, &st, &pf, &p(op)), "{} word {off}", rel_name(op));
    }
}

#[test]
fn wrong_witness_ring_row() {
    // one coefficient of a CBD(20) vector changed (still short): its R_q row no longer holds mod q
    let s = setup();
    for (op, off) in [(OP_TRANSFER, 8192), (OP_BURN, 8192), (OP_DISCLOSE_SENDER, 2048), (OP_DISCLOSE_RECEIVER, 2048)] {
        let (st, w) = s.rel(op);
        let mut w = w.clone();
        w[off] = w[off].wrapping_add(1);
        assert!(prove(op, st, &w, [1; 32], &p(op)).is_err());
        assert!(rejected(op, st, &w), "{}", rel_name(op));
    }
}

/// the EVM fixtures (ligero_export) verify natively: honest and other-statement proofs accepted, negative witnesses
/// rejected
#[test]
fn evm_fixtures() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../smartcontracts/evm/test/vectors/pqzh-ligero");
    let rd = |n: &str| std::fs::read(format!("{dir}/{n}")).unwrap();
    for (op, rel) in [(OP_REGISTER, "reg"), (OP_TRANSFER, "tx")] {
        for (pre, pp) in [("proven", p(op)), ("conj", Params::preset(op, false, true)), ("johnson", Params::johnson_preset())] {
            let st = rd(&format!("{rel}-{pre}.stmt"));
            assert!(verify(op, &st, &rd(&format!("{rel}-{pre}.proof")), &pp), "{rel}-{pre}");
            let mut st2 = st.clone();
            st2[0] ^= 0x80;
            assert!(verify(op, &st2, &rd(&format!("{rel}-{pre}.other")), &pp), "{rel}-{pre} other");
        }
    }
    for n in ["reg-norm", "reg-coef", "tx-norm", "tx-digit", "tx-e2", "tx-overspend", "tx-ring"] {
        let op = if n.starts_with("reg") { OP_REGISTER } else { OP_TRANSFER };
        assert!(!verify(op, &rd(&format!("neg-{n}.stmt")), &rd(&format!("neg-{n}.proof")), &Params::preset(op, false, true)), "{n}");
    }
}
