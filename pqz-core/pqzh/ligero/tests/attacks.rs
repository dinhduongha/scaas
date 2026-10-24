//! Honest proofs verify; mutated proofs / statements and invalid witnesses do not (run with --release).
//! Needs feature `bench` (default) for the reference presets.
#![cfg(feature = "bench")]
use pqzh_ligero::client::{DISC_AMOUNT, DISC_PK, HDR_AMOUNT, HDR_AUDITOR_ON, HDR_FEE, KINDS, R, Setup, Tweak, mutate, rel_name, setup, setup_with};
use pqzh_ligero::cs;
use pqzh_ligero::ligero::VERIFY_PANICS;
use pqzh_ligero::pqz_stmt::{FORMS, PK_BYTES, PQZH_ID, PQZL_ID};
use pqzh_ligero::ring::{DELTA, N, Poly, Q, digits, dot_int, modq, polys_of};
use pqzh_ligero::set::{BETA_E, BETA_S, EBITS};
use pqzh_ligero::{Form, OP_DISCLOSE_RECEIVER, OP_REGISTER, OP_TRANSFER, Params, RELS, prove, prove_unchecked, verify};

fn p(_op: u8) -> Params {
    Params::proven()
}

/// the opTags an op accepts (REFRESH shares op 2 with BURN, AUDITOR op 5 with DISCLOSE-RECEIVER)
fn op_tags(op: u8) -> Vec<[u8; 32]> {
    let mut t: Vec<[u8; 32]> = FORMS.iter().filter(|f| f.op() == op).map(|f| f.op_tag()).collect();
    t.dedup();
    t
}

/// a cheating prover (no witness checks) makes a proof and the verifier rejects it. A prover error or panic is NOT a
/// rejection (pre-review H-2): it returns false, so the caller's assert names the case
fn rejected(op: u8, stmt: &[u8], wit: &[u8]) -> bool {
    match std::panic::catch_unwind(|| prove_unchecked(op, stmt, wit, [7; 32], &p(op))) {
        Ok(Ok(pf)) => !verify(op, stmt, &pf, &p(op)),
        Ok(Err(e)) => {
            eprintln!("unchecked prover error: {e}");
            false
        }
        Err(_) => {
            eprintln!("unchecked prover panicked");
            false
        }
    }
}

/// the honest prover refuses and a proof without its checks does not verify
fn refused(f: Form, s: &Setup) -> bool {
    let (op, (st, w)) = (f.op(), s.rel(f));
    prove(op, st, w, [1; 32], &p(op)).is_err() && rejected(op, st, w)
}

#[test]
fn honest_all_presets_cross_and_hiding() {
    let s = setup();
    for proven in [true, false] {
        for r431 in [true, false] {
            for f in RELS {
                let (op, (st, w)) = (f.op(), s.rel(f));
                let pp = Params::preset(op, proven, r431);
                let t = std::time::Instant::now();
                let a = prove(op, st, w, [1; 32], &pp).unwrap();
                eprintln!("{} {pp:?}: {} B, {:?}", rel_name(f), a.len(), t.elapsed());
                assert!(verify(op, st, &a, &pp));
                assert!(a.len() <= pp.max_proof_len(f) && pp.max_proof_len(f) <= pp.max_len_exact(f));
                assert!(pp.max_len_exact(f) <= pp.max_len(f));
            }
        }
    }
    for f in RELS {
        let (op, (st, w)) = (f.op(), s.rel(f));
        let pj = Params::johnson_preset();
        let a = prove(op, st, w, [1; 32], &pj).unwrap();
        eprintln!("{} {pj:?}: {} B", rel_name(f), a.len());
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
    let proofs: Vec<Vec<u8>> = RELS.iter().map(|&f| prove(f.op(), s.rel(f).0, s.rel(f).1, [4; 32], &p(f.op())).unwrap()).collect();
    for (i, &f) in RELS.iter().enumerate() {
        for o2 in RELS.iter().map(|g| g.op()).chain([0, 6, 255]) {
            if o2 != f.op() {
                assert!(!verify(o2, s.rel(f).0, &proofs[i], &p(o2)), "{} proof accepted as op {o2}", rel_name(f));
            }
        }
    }
}

/// D3: a statement of any other proofSystemId, another op's opTag or (R_TX) auditorOn != 1 is no PQZH statement (not
/// parsed, not proved, its proof rejected);
/// Task 9: an honest proof zero-padded to the bound passes the length gate and is rejected as not consumed exactly,
/// one byte more is rejected by the gate
#[test]
fn other_ids_and_length_bound_rejected() {
    let s = setup();
    let stark = [
        0xaa, 0x1f, 0x92, 0xdd, 0xc5, 0x76, 0x32, 0x01, 0xc2, 0x58, 0x2c, 0x83, 0x87, 0xbd, 0x65, 0x13, 0x84, 0x2e, 0x52,
        0x77, 0x93, 0x10, 0xd6, 0xbc, 0xf3, 0x9a, 0x7f, 0xec, 0x99, 0x28, 0x43, 0x04,
    ];
    for f in RELS {
        let (op, (st, w)) = (f.op(), s.rel(f));
        let pp = p(op);
        assert_eq!(st[32..64], PQZH_ID);
        let pf = prove(op, st, w, [4; 32], &pp).unwrap();
        assert!(verify(op, st, &pf, &pp));
        // other ids; byte 0 of the opTag flipped; every other op's opTag; R_TX: auditorOn 0, 2, high byte set
        let mut bad: Vec<(String, Vec<u8>)> = vec![];
        for (i, id) in [PQZL_ID, stark, [0; 32]].iter().enumerate() {
            let mut st2 = st.clone();
            st2[32..64].copy_from_slice(id);
            bad.push((format!("id {i}"), st2));
        }
        let mut st2 = st.clone();
        st2[0] ^= 0x80;
        bad.push(("opTag byte 0".into(), st2));
        for o2 in RELS.iter().map(|g| g.op()).filter(|&o| o != op) {
            for t in op_tags(o2) {
                let mut st2 = st.clone();
                st2[..32].copy_from_slice(&t);
                bad.push((format!("opTag of op {o2}"), st2));
            }
        }
        if op == OP_TRANSFER {
            // R_TX needs 1, R_TX0 0 (R6): the other value, 2, a high byte
            let other = (f == Form::Transfer0) as u8;
            for (i, v) in [(31, other), (31, 2), (0, 1)] {
                let mut st2 = st.clone();
                st2[HDR_AUDITOR_ON + i] = v;
                bad.push((format!("auditorOn byte {i} = {v}"), st2));
            }
        }
        for (what, st2) in &bad {
            assert!(cs::parse(op, st2).is_none(), "{} {what} parsed", rel_name(f));
            assert!(prove(op, st2, w, [4; 32], &pp).is_err() && prove_unchecked(op, st2, w, [4; 32], &pp).is_err());
            assert!(!verify(op, st2, &pf, &pp), "{} proof accepted with {what}", rel_name(f));
        }
        // REFRESH (op 2) and AUDITOR (op 5) share their op's relation (a REFRESH statement has amount and recipient
        // 0: D15 zero words)
        for t in op_tags(op) {
            let mut st2 = st.clone();
            st2[..32].copy_from_slice(&t);
            if t == Form::Refresh.op_tag() {
                st2[HDR_AMOUNT..HDR_AMOUNT + 64].fill(0);
            }
            assert!(cs::parse(op, &st2).is_some(), "{}", rel_name(f));
        }
        let max = pp.max_proof_len(f);
        assert!(pf.len() <= max && pp.proof_len_ok(f, max) && !pp.proof_len_ok(f, max + 1));
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
    for f in RELS {
        let (op, (st, w)) = (f.op(), s.rel(f));
        let pp = p(op);
        let pf = prove(op, st, w, [3; 32], &pp).unwrap();
        let mut st2 = st.clone();
        st2[64] ^= 0x80;
        let other = prove(op, &st2, w, [9; 32], &pp).unwrap();
        assert!(verify(op, &st2, &other, &pp));
        let mut r = R(0x9E3779B97F4A7C15 ^ op as u64);
        let mut total = 0;
        for k in 0..KINDS.len() {
            for _ in 0..80 {
                let (ms, mp) = mutate(k, f, st, &pf, &other, &mut r);
                assert!(!verify(op, &ms, &mp, &pp), "{} kind {} accepted", rel_name(f), KINDS[k]);
                total += 1;
            }
        }
        assert_eq!(total, 960);
    }
    eprintln!("{} x 960 mutated inputs rejected, {} verifier panics caught", RELS.len(), VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed) - p0);
}

/// every |s_k| <= 1 but ||s||^2 = BETA_S^2 + 4 (v3 1300 > 36^2): only the exact l2 check can catch it
fn small_but_long() -> Vec<i64> {
    let mut sv = vec![0i64; N];
    for k in 0..BETA_S * BETA_S + 4 {
        sv[k] = if k % 2 == 0 { 1 } else { -1 };
    }
    sv
}

/// |s_5| = 100 > BETA_S (and > 64, outside the 7 bits of s + 64: BETA_S < 64 in every set)
fn one_large() -> Vec<i64> {
    const { assert!(BETA_S < 64 && BETA_E < 256) };
    let mut sv = vec![0i64; N];
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
    for f in [Form::Register, Form::Transfer, Form::Transfer0, Form::Burn] {
        assert!(refused(f, &s), "{}", rel_name(f));
    }
    let s = setup_with(&Tweak { s_t: Some(small_but_long()), ..Default::default() });
    assert!(refused(Form::DiscloseReceiver, &s));
}

#[test]
fn coefficient_out_of_range() {
    // s_f_5 = 100 (outside the 7 bits of s + 64), e_f_5 = 300 (outside the 9 bits of e + 256); pk_f recomputed
    let mut e_large = vec![0i64; N];
    e_large[5] = 300;
    for tw in [Tweak { s_f: Some(one_large()), ..Default::default() }, Tweak { e_f: Some(e_large), ..Default::default() }] {
        let s = setup_with(&tw);
        for f in [Form::Register, Form::Transfer, Form::Transfer0, Form::Burn] {
            assert!(refused(f, &s), "{} s_f {}", rel_name(f), tw.s_f.is_some());
        }
    }
    let s = setup_with(&Tweak { s_t: Some(one_large()), ..Default::default() });
    assert!(refused(Form::DiscloseReceiver, &s));
}

/// the encryption randomness r (CBD(1), 7 bits, ||r|| <= 36) and e1 (CBD(20), 9 bits, ||e1|| <= 164) of R_TX, R_DS
/// (the transfer's) and R_BURN (the burn's): l2 bound exceeded with in-range coefficients, and one coefficient
/// outside the bit range; ciphertexts re-encrypted, so only the norm / range proofs can catch them
#[test]
fn randomness_norm_and_range() {
    let mut e1_long = vec![0i64; N];
    for (k, x) in e1_long.iter_mut().enumerate() {
        *x = if k % 2 == 0 { 4 } else { -4 }; // ||e1||^2 = 16 N > BETA_E^2 (v3 32,768 > 164^2 = 26,896)
    }
    const { assert!(16 * N > BETA_E * BETA_E) };
    let mut e1_large = vec![0i64; N];
    e1_large[5] = 300; // outside the 9 bits of e1 + 256
    for (name, tw) in [
        ("r l2", Tweak { r: Some(small_but_long()), ..Default::default() }),
        ("r range", Tweak { r: Some(one_large()), ..Default::default() }),
        ("e1 l2", Tweak { e1: Some(e1_long), ..Default::default() }),
        ("e1 range", Tweak { e1: Some(e1_large), ..Default::default() }),
    ] {
        let s = setup_with(&tw);
        for f in [Form::Transfer, Form::Transfer0, Form::Burn, Form::DiscloseSender] {
            assert!(refused(f, &s), "{} {name}", rel_name(f));
        }
    }
}

/// R_DR's e' range [-E, E), E = 2^(EBITS - 1) (v3 2^24): v_0 crafted so that e'_0 sits on each side of each edge
#[test]
fn dr_noise_range_edges() {
    let s = setup();
    let (st, w) = s.rel(Form::DiscloseReceiver);
    let u = polys_of(&st[DISC_PK + PK_BYTES..DISC_PK + 2 * PK_BYTES], 64);
    let sv: Vec<Poly> = w[..N].chunks(64).map(|c| std::array::from_fn(|i| c[i] as i8 as i64)).collect();
    let y = dot_int(&u.iter().collect::<Vec<_>>(), &sv.iter().collect::<Vec<_>>());
    let d0 = (123_456u64 & 15) as i64;
    let big_e: i64 = 1 << (EBITS - 1);
    for (e, ok) in [(big_e - 1, true), (big_e, false), (-big_e, true), (-big_e - 1, false)] {
        let mut st = st.clone();
        let v0 = modq(y[0] + DELTA * d0 + e).rem_euclid(Q as i64) as u64;
        let o = DISC_PK + 2 * PK_BYTES;
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
    for f in RELS {
        let (op, (st, w)) = (f.op(), s.rel(f));
        let mut w2 = w.clone();
        w2[0] ^= 1;
        let a = prove_unchecked(op, st, w, [5; 32], &p(op)).unwrap();
        let b = prove_unchecked(op, st, &w2, [5; 32], &p(op)).unwrap();
        assert_ne!(a[..32], b[..32], "{}", rel_name(f));
        assert_eq!(a, prove_unchecked(op, st, w, [5; 32], &p(op)).unwrap(), "{}", rel_name(f));
    }
}

#[test]
fn digit_out_of_range() {
    let s = setup_with(&Tweak { d: Some(bad_digits(123_456)), ..Default::default() });
    assert!(refused(Form::Transfer, &s));
    assert!(refused(Form::Transfer0, &s));
    let s = setup_with(&Tweak { burn_dp: Some(bad_digits(1_000_000 - 123_456 - 7)), ..Default::default() });
    assert!(refused(Form::Burn, &s));
}

#[test]
fn e2_norm_exceeded() {
    // R_TX's e2_t is R_DS's e2
    let s = setup_with(&Tweak { e2_t: Some(e2_65()), ..Default::default() });
    assert!(refused(Form::Transfer, &s));
    assert!(refused(Form::Transfer0, &s));
    assert!(refused(Form::DiscloseSender, &s));
    let s = setup_with(&Tweak { burn_e2: Some(e2_65()), ..Default::default() });
    assert!(refused(Form::Burn, &s));
    // e2_f, the transfer's sender leg (R_TX, R_TX0)
    let s = setup_with(&Tweak { e2_f: Some(e2_65()), ..Default::default() });
    assert!(refused(Form::Transfer, &s));
    assert!(refused(Form::Transfer0, &s));
}

/// row 6 (u_T^T s_f + Delta M + e_T = v_T) of R_TX, R_TX0, R_BURN: e_T's range [-E, E), E = 2^(EBITS - 1) (v3 2^24);
/// v_T_0 crafted so that
/// e_T_0 sits on each side of each edge with the honest M_0 (rounding keeps M_0: |e_T_0| < Delta / 2)
#[test]
fn debit_noise_range_edges() {
    let s = setup();
    for f in [Form::Transfer, Form::Transfer0, Form::Burn] {
        let (op, (st, w)) = (f.op(), s.rel(f));
        // header || pk_f || [pk_t] || [pk_a] || u_T || v_T || ...
        let npk = match f { Form::Transfer => 3, Form::Transfer0 => 2, _ => 1 };
        let ut_at = 640 + npk * PK_BYTES;
        let vt_at = ut_at + PK_BYTES;
        let ut = polys_of(&st[ut_at..vt_at], 64);
        let sf: Vec<Poly> = w[..N].chunks(64).map(|c| std::array::from_fn(|i| c[i] as i8 as i64)).collect();
        let y = dot_int(&ut.iter().collect::<Vec<_>>(), &sf.iter().collect::<Vec<_>>());
        let v0 = polys_of(&st[vt_at..vt_at + 128], 16)[0][0];
        let wv = modq(v0 - y[0]);
        let m0 = (wv + DELTA / 2).div_euclid(DELTA);
        let big_e: i64 = 1 << (EBITS - 1);
        for (e, ok) in [(big_e - 1, true), (big_e, false), (-big_e, true), (-big_e - 1, false)] {
            let mut st = st.clone();
            let nv = modq(y[0] + DELTA * m0 + e).rem_euclid(Q as i64) as u64;
            st[vt_at..vt_at + 8].copy_from_slice(&nv.to_be_bytes());
            if ok {
                let pf = prove(op, &st, w, [1; 32], &p(op)).unwrap();
                assert!(verify(op, &st, &pf, &p(op)), "{} e_T = {e}", rel_name(f));
            } else {
                assert!(prove(op, &st, w, [1; 32], &p(op)).is_err(), "{} e_T = {e}", rel_name(f));
                assert!(rejected(op, &st, w), "{} e_T = {e}", rel_name(f));
            }
        }
    }
}

#[test]
fn overspend() {
    // claim new balance digits all 15 (2^64 - 1): the carry chain cannot close
    let s = setup();
    // d' after s_f, e_f, r, e1 (6N), the e2 legs and d (v3: 12,400 / 12,368 / 12,320)
    for (f, off) in [(Form::Transfer, 6 * N + 112), (Form::Transfer0, 6 * N + 80), (Form::Burn, 6 * N + 32)] {
        let (op, (st, w)) = (f.op(), s.rel(f));
        let mut w = w.clone();
        w[off..off + 16].fill(15);
        assert!(prove(op, st, &w, [1; 32], &p(op)).is_err());
        assert!(rejected(op, st, &w), "{}", rel_name(f));
    }
}

#[test]
fn wrong_public_amount() {
    // the statement claims amount (or R_BURN's fee) +- 1 with the honest witness; for R_DR, amount - 1 puts +Delta
    // into e'
    let s = setup();
    for (f, off) in [(Form::Burn, HDR_AMOUNT), (Form::Burn, HDR_FEE), (Form::DiscloseSender, DISC_AMOUNT), (Form::DiscloseReceiver, DISC_AMOUNT)] {
        for delta in [1i64, -1] {
            let (op, (st, w)) = (f.op(), s.rel(f));
            let mut st = st.clone();
            let x = u64::from_be_bytes(st[off + 24..off + 32].try_into().unwrap()).wrapping_add_signed(delta);
            st[off + 24..off + 32].copy_from_slice(&x.to_be_bytes());
            assert!(prove(op, &st, w, [1; 32], &p(op)).is_err(), "{} word {off} {delta:+}", rel_name(f));
            assert!(rejected(op, &st, w), "{} word {off} {delta:+}", rel_name(f));
        }
    }
}

#[test]
fn scalar_word_above_2_64() {
    let s = setup();
    for (f, off) in [(Form::Transfer, HDR_FEE), (Form::Transfer0, HDR_FEE), (Form::Burn, HDR_FEE), (Form::Burn, HDR_AMOUNT), (Form::DiscloseSender, DISC_AMOUNT), (Form::DiscloseReceiver, DISC_AMOUNT)] {
        let (op, (st, w)) = (f.op(), s.rel(f));
        let pf = prove(op, st, w, [2; 32], &p(op)).unwrap();
        let mut st = st.clone();
        st[off + 23] = 1;
        assert!(prove(op, &st, w, [2; 32], &p(op)).is_err());
        assert!(!verify(op, &st, &pf, &p(op)), "{} word {off}", rel_name(f));
    }
}

#[test]
fn wrong_witness_ring_row() {
    // one coefficient of a CBD(20) vector changed (still short): its R_q row no longer holds mod q
    let s = setup();
    // e1 at 4N (R_TX, R_TX0, R_BURN), e_f at N (R_REG, R_TX, R_TX0, R_BURN), R_DS's e1 / R_DR's e at N (v3: 8192, 2048)
    for (f, off) in [
        (Form::Transfer, 4 * N),
        (Form::Transfer0, 4 * N),
        (Form::Burn, 4 * N),
        (Form::Register, N),
        (Form::Transfer, N),
        (Form::Transfer0, N),
        (Form::Burn, N),
        (Form::DiscloseSender, N),
        (Form::DiscloseReceiver, N),
    ] {
        let (op, (st, w)) = (f.op(), s.rel(f));
        let mut w = w.clone();
        w[off] = w[off].wrapping_add(1);
        assert!(prove(op, st, &w, [1; 32], &p(op)).is_err());
        assert!(rejected(op, st, &w), "{}", rel_name(f));
    }
}

/// op 1's two forms (R6, D8): an R_TX proof against the R_TX0 statement of the same transfer and vice versa; the
/// R_TX0 statement padded with pk_a / v_a to R_TX's length (auditorOn 1) and R_TX's cut to R_TX0's (auditorOn 0):
/// each is a well-formed statement of the other form, and neither proof verifies against it; a witness of the other
/// form is refused by its length
#[test]
fn transfer_forms_cross_rejected() {
    let s = setup();
    let pp = p(OP_TRANSFER);
    let (tx, tx0) = (&s.tx_stmt, &s.tx0_stmt);
    let a = prove(OP_TRANSFER, tx, &s.tx_wit, [6; 32], &pp).unwrap();
    let b = prove(OP_TRANSFER, tx0, &s.tx0_wit, [6; 32], &pp).unwrap();
    assert!(verify(OP_TRANSFER, tx, &a, &pp) && verify(OP_TRANSFER, tx0, &b, &pp));
    assert!(!verify(OP_TRANSFER, tx0, &a, &pp), "R_TX proof, R_TX0 statement");
    assert!(!verify(OP_TRANSFER, tx, &b, &pp), "R_TX0 proof, R_TX statement");
    // header || pk_f || pk_t || [pk_a] || T || u || v_t || v_f || [v_a]
    let (h, pk) = (640, PK_BYTES);
    let mut up = tx0[..h + 2 * pk].to_vec();
    up.extend_from_slice(&tx[h + 2 * pk..h + 3 * pk]); // pk_a
    up.extend_from_slice(&tx0[h + 2 * pk..]);
    up.extend_from_slice(&tx[tx.len() - 128..]); // v_a
    up[HDR_AUDITOR_ON + 31] = 1;
    assert_eq!(&up, tx, "R_TX0 + pk_a + v_a = R_TX");
    let mut down = tx[..h + 2 * pk].to_vec();
    down.extend_from_slice(&tx[h + 3 * pk..tx.len() - 128]);
    down[HDR_AUDITOR_ON + 31] = 0;
    assert_eq!(&down, tx0, "R_TX - pk_a - v_a = R_TX0");
    assert_eq!(cs::form_of(OP_TRANSFER, tx.len()), Some(Form::Transfer));
    assert_eq!(cs::form_of(OP_TRANSFER, tx0.len()), Some(Form::Transfer0));
    for (st, w) in [(tx, &s.tx0_wit), (tx0, &s.tx_wit)] {
        assert_eq!(prove(OP_TRANSFER, st, w, [6; 32], &pp), Err("length"));
        assert_eq!(prove_unchecked(OP_TRANSFER, st, w, [6; 32], &pp), Err("length"));
    }
    // the length gate is the form's: R_TX0's bound is R_BURN's (same m), below R_TX's
    // (n2304-kmax4096 preset B, l = 831: R_TX0 and R_TX have the same rows, 124; n2560-kmax16384, l = 694: 165; so equal
    // bounds)
    let equal = pqzh_ligero::set::NAME == "n2560-kmax16384"
        || pqzh_ligero::set::NAME == "n2304-kmax4096" && !cfg!(feature = "fallback-retry");
    if equal {
        assert_eq!(pp.max_proof_len(Form::Transfer0), pp.max_proof_len(Form::Transfer));
    } else {
        assert!(pp.max_proof_len(Form::Transfer0) < pp.max_proof_len(Form::Transfer));
    }
}

/// the EVM fixtures (ligero_export) verify natively: honest and other-statement proofs accepted, negative witnesses
/// rejected. The fixtures are n2048-kmax1024's under the retired PQZH v1 id (smartcontracts/evm/test/vectors/pqzh-ligero,
/// with the EVM LigeroVerifier test): regenerated with the contracts in plan 5h Task 8d part 2, ignored until then
#[test]
#[ignore = "the EVM fixtures carry the retired PQZH v1 id (contract vectors: plan 5h Task 8d part 2)"]
fn evm_fixtures() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../smartcontracts/evm/test/vectors/pqzh-ligero");
    let rd = |n: &str| std::fs::read(format!("{dir}/{n}")).unwrap();
    for (op, rel) in [(OP_REGISTER, "reg"), (OP_TRANSFER, "tx")] {
        for (pre, pp) in [("proven", p(op)), ("conj", Params::preset(op, false, true)), ("johnson", Params::johnson_preset())] {
            let st = rd(&format!("{rel}-{pre}.stmt"));
            assert!(verify(op, &st, &rd(&format!("{rel}-{pre}.proof")), &pp), "{rel}-{pre}");
            let mut st2 = st.clone();
            st2[64] ^= 0x80;
            assert!(verify(op, &st2, &rd(&format!("{rel}-{pre}.other")), &pp), "{rel}-{pre} other");
        }
    }
    let st = rd("tx0-proven.stmt");
    assert_eq!(st.len(), Form::Transfer0.stmt_len());
    assert!(verify(OP_TRANSFER, &st, &rd("tx0-proven.proof"), &p(OP_TRANSFER)), "tx0-proven");
    let mut st2 = st.clone();
    st2[64] ^= 0x80;
    assert!(verify(OP_TRANSFER, &st2, &rd("tx0-proven.other"), &p(OP_TRANSFER)), "tx0-proven other");
    for n in ["reg-norm", "reg-coef", "tx-norm", "tx-digit", "tx-e2", "tx-overspend", "tx-ring"] {
        let op = if n.starts_with("reg") { OP_REGISTER } else { OP_TRANSFER };
        assert_eq!(rd(&format!("neg-{n}.stmt"))[32..64], PQZH_ID, "{n}: D3 id");
        assert!(!verify(op, &rd(&format!("neg-{n}.stmt")), &rd(&format!("neg-{n}.proof")), &Params::preset(op, false, true)), "{n}");
    }
}
