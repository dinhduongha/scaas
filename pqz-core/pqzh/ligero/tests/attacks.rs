//! Honest proofs verify; mutated proofs / statements and invalid witnesses do not (run with --release).
//! Needs feature `bench` (default) for the reference presets.
#![cfg(feature = "bench")]
use pqzh_ligero::client::{KINDS, R, Setup, Tweak, digits, mutate, rel_name, setup, setup_with};
use pqzh_ligero::ligero::VERIFY_PANICS;
use pqzh_ligero::ring::{DELTA, Poly, Q, dot_int, modq, rd_polyvec};
use pqzh_ligero::cs;
use pqzh_ligero::stmt::{DISC_AMOUNT, DISC_PK, HDR_AMOUNT, HDR_FEE, PQZH_PROOF_SYSTEM_ID, PQZL_PROOF_SYSTEM_ID, POLYVEC};
use pqzh_ligero::{OP_BURN, OP_DISCLOSE_RECEIVER, OP_DISCLOSE_SENDER, OP_REGISTER, OP_TRANSFER, OPS, Params, prove, prove_unchecked, verify};

fn p(_op: u8) -> Params {
    Params::proven()
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
                assert!(a.len() <= pp.max_proof_len(op) && pp.max_proof_len(op) <= pp.max_len_exact(op));
                assert!(pp.max_len_exact(op) <= pp.max_len(op));
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

/// D3: a statement of any other proofSystemId is no PQZH statement (not parsed, not proved, its proof rejected);
/// Task 9: an honest proof zero-padded to the bound passes the length gate and is rejected as not consumed exactly,
/// one byte more is rejected by the gate
#[test]
fn other_ids_and_length_bound_rejected() {
    let s = setup();
    let stark = [
        0xaa, 0x1f, 0x92, 0xdd, 0xc5, 0x76, 0x32, 0x01, 0xc2, 0x58, 0x2c, 0x83, 0x87, 0xbd, 0x65, 0x13, 0x84, 0x2e, 0x52,
        0x77, 0x93, 0x10, 0xd6, 0xbc, 0xf3, 0x9a, 0x7f, 0xec, 0x99, 0x28, 0x43, 0x04,
    ];
    for op in OPS {
        let (st, w) = s.rel(op);
        let pp = p(op);
        assert_eq!(st[32..64], PQZH_PROOF_SYSTEM_ID);
        let pf = prove(op, st, w, [4; 32], &pp).unwrap();
        assert!(verify(op, st, &pf, &pp));
        for id in [PQZL_PROOF_SYSTEM_ID, stark, [0; 32]] {
            let mut st2 = st.clone();
            st2[32..64].copy_from_slice(&id);
            assert!(cs::parse(op, &st2).is_none());
            assert!(prove(op, &st2, w, [4; 32], &pp).is_err() && prove_unchecked(op, &st2, w, [4; 32], &pp).is_err());
            assert!(!verify(op, &st2, &pf, &pp), "{} proof accepted under another id", rel_name(op));
        }
        let max = pp.max_proof_len(op);
        assert!(pf.len() <= max && pp.proof_len_ok(op, max) && !pp.proof_len_ok(op, max + 1));
        let mut long = pf.clone();
        long.resize(max, 0);
        assert!(!verify(op, st, &long, &pp));
        long.push(0);
        assert!(!verify(op, st, &long, &pp));
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
    assert!(refused(OP_REGISTER, &s));
    assert!(refused(OP_BURN, &s));
    let s = setup_with(&Tweak { s_t: Some(one_large()), ..Default::default() });
    assert!(refused(OP_DISCLOSE_RECEIVER, &s));
}

/// the encryption randomness r (CBD(1), 7 bits, ||r|| <= 36) and e1 (CBD(20), 9 bits, ||e1|| <= 164) of R_TX, R_DS
/// (the transfer's) and R_BURN (the burn's): l2 bound exceeded with in-range coefficients, and one coefficient
/// outside the bit range; ciphertexts re-encrypted, so only the norm / range proofs can catch them
#[test]
fn randomness_norm_and_range() {
    let mut e1_long = vec![0i64; 2048];
    for (k, x) in e1_long.iter_mut().enumerate() {
        *x = if k % 2 == 0 { 4 } else { -4 }; // ||e1||^2 = 32,768 > 164^2 = 26,896
    }
    let mut e1_large = vec![0i64; 2048];
    e1_large[5] = 300; // outside the 9 bits of e1 + 256
    for (name, tw) in [
        ("r l2", Tweak { r: Some(small_but_long()), ..Default::default() }),
        ("r range", Tweak { r: Some(one_large()), ..Default::default() }),
        ("e1 l2", Tweak { e1: Some(e1_long), ..Default::default() }),
        ("e1 range", Tweak { e1: Some(e1_large), ..Default::default() }),
    ] {
        let s = setup_with(&tw);
        for op in [OP_TRANSFER, OP_BURN, OP_DISCLOSE_SENDER] {
            assert!(refused(op, &s), "{} {name}", rel_name(op));
        }
    }
}

/// R_DR's e' range [-2^24, 2^24): v_0 crafted so that e'_0 sits on each side of each edge
#[test]
fn dr_noise_range_edges() {
    let s = setup();
    let (st, w) = s.rel(OP_DISCLOSE_RECEIVER);
    let u = rd_polyvec(&st[DISC_PK + POLYVEC..]).unwrap();
    let sv: Vec<Poly> = w[..2048].chunks(64).map(|c| std::array::from_fn(|i| c[i] as i8 as i64)).collect();
    let y = dot_int(&u.iter().collect::<Vec<_>>(), &sv.iter().collect::<Vec<_>>());
    let d0 = (123_456u64 & 15) as i64;
    for (e, ok) in [((1 << 24) - 1, true), (1 << 24, false), (-(1 << 24), true), (-(1 << 24) - 1, false)] {
        let mut st = st.clone();
        let v0 = modq(y[0] + DELTA * d0 + e).rem_euclid(Q as i64) as u64;
        let o = DISC_PK + 2 * POLYVEC;
        st[o..o + 8].copy_from_slice(&v0.to_be_bytes());
        if ok {
            let pf = prove(OP_DISCLOSE_RECEIVER, &st, w, [1; 32], &p(OP_DISCLOSE_RECEIVER)).unwrap();
            assert!(verify(OP_DISCLOSE_RECEIVER, &st, &pf, &p(OP_DISCLOSE_RECEIVER)), "e' = {e}");
        } else {
            assert!(prove(OP_DISCLOSE_RECEIVER, &st, w, [1; 32], &p(OP_DISCLOSE_RECEIVER)).is_err(), "e' = {e}");
            assert!(rejected(OP_DISCLOSE_RECEIVER, &st, w), "e' = {e}");
        }
    }
}

/// D6 at the proof level: one statement, witnesses differing in one byte, same rnd32 -> the commitments (bytes 0..32)
/// differ; equal inputs -> equal proofs
#[test]
fn hedged_proofs() {
    let s = setup();
    for op in OPS {
        let (st, w) = s.rel(op);
        let mut w2 = w.clone();
        w2[0] ^= 1;
        let a = prove_unchecked(op, st, w, [5; 32], &p(op)).unwrap();
        let b = prove_unchecked(op, st, &w2, [5; 32], &p(op)).unwrap();
        assert_ne!(a[..32], b[..32], "{}", rel_name(op));
        assert_eq!(a, prove_unchecked(op, st, w, [5; 32], &p(op)).unwrap(), "{}", rel_name(op));
    }
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
    // the statement claims amount (or R_BURN's fee) +- 1 with the honest witness; for R_DR, amount - 1 puts +Delta
    // into e'
    let s = setup();
    for (op, off) in [(OP_BURN, HDR_AMOUNT), (OP_BURN, HDR_FEE), (OP_DISCLOSE_SENDER, DISC_AMOUNT), (OP_DISCLOSE_RECEIVER, DISC_AMOUNT)] {
        for delta in [1i64, -1] {
            let (st, w) = s.rel(op);
            let mut st = st.clone();
            let x = u64::from_be_bytes(st[off + 24..off + 32].try_into().unwrap()).wrapping_add_signed(delta);
            st[off + 24..off + 32].copy_from_slice(&x.to_be_bytes());
            assert!(prove(op, &st, w, [1; 32], &p(op)).is_err(), "{} word {off} {delta:+}", rel_name(op));
            assert!(rejected(op, &st, w), "{} word {off} {delta:+}", rel_name(op));
        }
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
        assert_eq!(rd(&format!("neg-{n}.stmt"))[32..64], PQZH_PROOF_SYSTEM_ID, "{n}: D3 id");
        assert!(!verify(op, &rd(&format!("neg-{n}.stmt")), &rd(&format!("neg-{n}.proof")), &Params::preset(op, false, true)), "{n}");
    }
}
