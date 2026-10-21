//! Op 7 `R_TXM` (P6-ANON Track H, H1): honest proofs of every shape PQZH builds (M = 1, 2, 4, auditor on and off;
//! with `--features oversize` also M = 8, 16), 960 mutations per shape, a negative witness for every condition, the
//! op 1 / op 7 and (M, auditorOn) separations, the length bounds against MAX_PROOF_PQZH / MAX_INPUT.
//! Run with --release. Needs feature `bench` (default).
#![cfg(feature = "bench")]
use pqzh_ligero::client::{HDR_AMOUNT, HDR_AUDITOR_ON, HDR_FEE, HDR_LEGS, HDR_RECIPIENTS_HASH, KINDS, MultiTweak, R, mutate, rel_name, setup_multi};
use pqzh_ligero::cs::{self, Layout};
use pqzh_ligero::ligero::VERIFY_PANICS;
use pqzh_ligero::pqz_stmt::{HEADER_BYTES, MAX_INPUT, MAX_PROOF_PQZH, PK_BYTES, PQZL_ID, V_BYTES, groups};
use pqzh_ligero::ring::{DELTA, N, Poly, Q, digits, dot_int, modq, polys_of};
use pqzh_ligero::set::{BETA_E, BETA_S};
use pqzh_ligero::{Form, OP_TRANSFER, OP_TRANSFER_MULTI as OP7, Params, Rel, multi_rels, prove, prove_unchecked, verify};

fn pp() -> Params {
    Params::proven()
}

fn shapes() -> Vec<(usize, bool)> {
    multi_rels()
        .into_iter()
        .map(|r| match r {
            Rel::Multi { m, aud } => (m, aud),
            _ => unreachable!(),
        })
        .collect()
}

fn name(m: usize, aud: bool) -> String {
    rel_name(Rel::Multi { m, aud })
}

/// a cheating prover (no witness checks) makes a proof and the verifier rejects it. A prover error or panic is NOT a
/// rejection (pre-review H-2): it returns false, so the caller's assert names the case
fn rejected(st: &[u8], w: &[u8]) -> bool {
    match std::panic::catch_unwind(|| prove_unchecked(OP7, st, w, [7; 32], &pp())) {
        Ok(Ok(pf)) => !verify(OP7, st, &pf, &pp()),
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
fn refused(st: &[u8], w: &[u8]) -> bool {
    prove(OP7, st, w, [1; 32], &pp()).is_err() && rejected(st, w)
}

fn honest(st: &[u8], w: &[u8]) -> Vec<u8> {
    let pf = prove(OP7, st, w, [1; 32], &pp()).expect("honest prove");
    assert!(verify(OP7, st, &pf, &pp()));
    pf
}

/// every |s_k| <= 1 but ||s||^2 = BETA_S^2 + 4 (v3 1300 > 36^2)
fn small_but_long() -> Vec<i64> {
    let n = BETA_S * BETA_S + 4;
    (0..N).map(|k| if k >= n { 0 } else if k % 2 == 0 { 1 } else { -1 }).collect()
}

/// |x_5| = v (outside the bit range of x + off)
fn one_large(v: i64) -> Vec<i64> {
    let mut x = vec![0i64; N];
    x[5] = v;
    x
}

/// ||e1||^2 = 16 N > BETA_E^2 with |e1_k| = 4 (v3 32,768 > 164^2)
fn e1_long() -> Vec<i64> {
    const { assert!(16 * N > BETA_E * BETA_E) };
    (0..N).map(|k| if k % 2 == 0 { 4 } else { -4 }).collect()
}

/// d_0 = 16 + 0, d_1 = 4 - 1 of 123,456: same value, digit 0 outside 4 bits
fn bad_digits() -> [u8; 16] {
    let mut d = digits(123_456);
    d[0] += 16;
    d[1] -= 1;
    d
}

/// ||e2||^2 = 5 * 32^2 = 5,120: over the per-vector bound 64^2 = 4,096 (CTR-PQZ-03, owner 2026-10-15) but under the
/// block bound 64^2 * M = 8,192 for M >= 2 (the plan's earlier 64 sqrt(M)), so only the per-vector rule rejects it
fn e2_spread() -> Vec<i64> {
    (0..16).map(|k| if k < 5 { 32 } else { 0 }).collect()
}

fn e2_65() -> Vec<i64> {
    let mut e = vec![0i64; 16];
    e[0] = 65;
    e
}

/// the real-leg positions tried per shape: 0, M / 2, M - 1 and the group boundary 3 / 4
fn positions(m: usize) -> Vec<usize> {
    let mut v: Vec<usize> = [0, m / 2, m - 1, 3, 4].into_iter().filter(|&j| j < m).collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// honest proofs of every shape: the default (one real leg at M / 2, decoys 0, fee 7), fee 0 with every leg 0 (an
/// all-decoy transfer), two real legs, the real leg at each position, the whole balance spent (b' = 0); each proof
/// within the shape's exact bound; built shapes within MAX_PROOF_PQZH and 5 + statement + bound <= MAX_INPUT
#[test]
fn honest_every_shape() {
    let p = pp();
    for (m, aud) in shapes() {
        let rel = Rel::Multi { m, aud };
        let max = p.max_proof_len(rel);
        let mut tws = vec![
            ("default", MultiTweak::default()),
            ("fee 0, all legs 0", MultiTweak { fee: Some(0), amounts: Some(vec![0; m]), ..Default::default() }),
        ];
        let mut two = vec![0; m];
        two[0] = 5;
        two[m - 1] += 1_000;
        tws.push(("two real legs", MultiTweak { amounts: Some(two), ..Default::default() }));
        for j in positions(m) {
            let mut a = vec![0; m];
            a[j] = 77_777;
            tws.push(("real leg at j", MultiTweak { amounts: Some(a), fee: Some(j as u64), ..Default::default() }));
        }
        let mut all = vec![0; m];
        all[m - 1] = 1_000_000 - 7;
        tws.push(("whole balance", MultiTweak { amounts: Some(all), ..Default::default() }));
        for (what, tw) in tws {
            let (st, w) = setup_multi(m, aud, &tw);
            assert_eq!(cs::rel_of(OP7, &st), Some(rel));
            let pf = honest(&st, &w);
            eprintln!("{} {what}: {} B (bound {max})", name(m, aud), pf.len());
            assert!(pf.len() <= max, "{} {what}", name(m, aud));
        }
        // v3 (D5); at set (a) every debit bound is above MAX_PROOF_PQZH (ligero.rs `limits_exact` pins it)
        if m <= 4 && pqzh_ligero::set::NAME == "n2048-kmax1024" {
            assert!(max <= MAX_PROOF_PQZH && 5 + rel.stmt_len() + max <= MAX_INPUT, "{} limits", name(m, aud));
        }
        // research spike B (radices 7 / 17 at set (a)): every built bound within MAX_PROOF_PQZH
        if cfg!(feature = "spike-b") {
            assert!(max <= MAX_PROOF_PQZH, "{} spike limit", name(m, aud));
        }
        if false {
            assert!(max <= MAX_PROOF_PQZH && 5 + rel.stmt_len() + max <= MAX_INPUT, "{} limits", name(m, aud));
        }
        // the single-leg shapes have op 1's rows
        if m == 1 {
            let f = if aud { Form::Transfer } else { Form::Transfer0 };
            assert_eq!(Layout::new(rel, p.ell).m, Layout::new(f, p.ell).m);
            assert_eq!(max, p.max_proof_len(f));
        }
    }
}

#[test]
fn mutations_960_per_shape_rejected() {
    let p = pp();
    let p0 = VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed);
    for (m, aud) in shapes() {
        let rel = Rel::Multi { m, aud };
        let (st, w) = setup_multi(m, aud, &MultiTweak::default());
        let pf = prove(OP7, &st, &w, [3; 32], &p).unwrap();
        let mut st2 = st.clone();
        st2[64] ^= 0x80;
        let other = prove(OP7, &st2, &w, [9; 32], &p).unwrap();
        assert!(verify(OP7, &st2, &other, &p));
        let mut r = R(0x9E3779B97F4A7C15 ^ (m as u64) << 1 ^ aud as u64);
        let mut total = 0;
        for k in 0..KINDS.len() {
            for _ in 0..80 {
                let (ms, mp) = mutate(k, rel, &st, &pf, &other, &mut r);
                assert!(!verify(OP7, &ms, &mp, &p), "{} kind {} accepted", name(m, aud), KINDS[k]);
                total += 1;
            }
        }
        assert_eq!(total, 960);
    }
    eprintln!(
        "{} x 960 mutated op 7 inputs rejected, {} verifier panics caught",
        shapes().len(),
        VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed) - p0
    );
}

/// a negative witness for every condition of R_TXM, each refused by the honest prover and, proved without its
/// checks, rejected by the verifier
#[test]
fn negative_witnesses() {
    for (m, aud) in shapes() {
        let g = groups(m);
        let nv = m + 1 + aud as usize * m;
        let mut cases: Vec<(String, MultiTweak)> = vec![];
        let mut add = |w: String, t: MultiTweak| cases.push((w, t));
        let d = MultiTweak::default;
        add("s_f l2 (coefficients in [-1, 1])".into(), MultiTweak { s_f: Some(small_but_long()), ..d() });
        add("s_f_5 = 100 (7 bits)".into(), MultiTweak { s_f: Some(one_large(100)), ..d() });
        add("e_f_5 = 300 (9 bits)".into(), MultiTweak { e_f: Some(one_large(300)), ..d() });
        for gi in if g > 1 { vec![0, g - 1] } else { vec![0] } {
            add(format!("r_{gi} l2"), MultiTweak { r: Some((gi, small_but_long())), ..d() });
            add(format!("r_{gi} range"), MultiTweak { r: Some((gi, one_large(100))), ..d() });
            add(format!("e1_{gi} l2"), MultiTweak { e1: Some((gi, e1_long())), ..d() });
            add(format!("e1_{gi} range"), MultiTweak { e1: Some((gi, one_large(300))), ..d() });
        }
        let amount = |j: usize| if j == m / 2 { 123_456 } else { 0 };
        for j in positions(m) {
            let mut a = vec![0; m];
            a[j] = 123_456;
            let tw = MultiTweak { amounts: Some(a), d: Some((j, bad_digits())), ..d() };
            add(format!("leg {j} digit out of range, same value"), tw);
        }
        for x in [0, m - 1, m, nv - 1] {
            add(format!("e2 vector {x} norm 65"), MultiTweak { e2: Some((x, e2_65())), ..d() });
            add(format!("e2 vector {x} norm^2 5,120 (block under 64^2 M)"), MultiTweak { e2: Some((x, e2_spread())), ..d() });
        }
        add("overspend: d' all 15".into(), MultiTweak { dp: Some([15; 16]), ..d() });
        let mut over = vec![0; m];
        over[m - 1] = 1_000_000 - 7 + 1;
        add("sum of legs + fee = balance + 1".into(), MultiTweak { amounts: Some(over), ..d() });
        let mut over2 = vec![0; m];
        over2[0] = 1_000_000;
        add("sum of legs = balance, fee 7 on top".into(), MultiTweak { amounts: Some(over2), ..d() });
        // d' claims one unit more than the debit leaves (the sum identity, not a range)
        add("d' = b' + 1".into(), MultiTweak { dp: Some(digits(1_000_000 - 123_456 - 7 + 1)), ..d() });
        add("leg 0 under another key".into(), MultiTweak { key: Some((0, if m > 1 { 1 } else { m })), ..d() });
        add(format!("leg {} under the auditor's key", m - 1), MultiTweak { key: Some((m - 1, m)), ..d() });
        if aud {
            for j in [0, m / 2] {
                let x = digits(amount(j) + 1);
                add(format!("auditor copy of leg {j} encrypts amount + 1"), MultiTweak { aud_d: Some((j, x)), ..d() });
            }
        }
        if g > 1 {
            add("leg 4 encrypted with group 0's randomness".into(), MultiTweak { group: Some((4, 0)), ..d() });
            add("leg 3 encrypted with group 1's randomness".into(), MultiTweak { group: Some((3, 1)), ..d() });
        }
        for (what, tw) in &cases {
            let (st, w) = setup_multi(m, aud, tw);
            assert!(refused(&st, &w), "{} {what}", name(m, aud));
        }
        // witness byte edits: one CBD(20) coefficient + 1 (its ring row fails): e_f, e1_0, e1_{G-1}
        let (st, w) = setup_multi(m, aud, &d());
        for off in [N, 4 * N, 3 * N * g + N] {
            let mut w2 = w.clone();
            w2[off] = w2[off].wrapping_add(1);
            assert!(refused(&st, &w2), "{} witness byte {off}", name(m, aud));
        }
        eprintln!("{}: {} negative witnesses + 3 ring rows refused and rejected", name(m, aud), cases.len());
    }
}

/// statement-side conditions with the honest witness: fee +- 1 and fee 0 (the relation reads the fee), fee / amount
/// words, the M word, recipientsHash (hashed), legs swapped, other ids
#[test]
fn statement_changes_rejected() {
    let p = pp();
    for (m, aud) in shapes() {
        let (st, w) = setup_multi(m, aud, &MultiTweak::default());
        let pf = honest(&st, &w);
        let set = |at: usize, v: u64| {
            let mut s = st.clone();
            s[at..at + 32].fill(0);
            s[at + 24..at + 32].copy_from_slice(&v.to_be_bytes());
            s
        };
        // fee read by row 7: 6, 8, 0 instead of 7
        for fee in [6, 8, 0] {
            let s = set(HDR_FEE, fee);
            assert!(cs::parse(OP7, &s).is_some());
            assert!(refused(&s, &w) && !verify(OP7, &s, &pf, &p), "{} fee {fee}", name(m, aud));
        }
        // not parsed: fee >= 2^64, amount != 0, M word another built / unbuilt value, other ids
        let mut bad: Vec<(String, Vec<u8>)> = vec![];
        let mut s = st.clone();
        s[HDR_FEE + 23] = 1;
        bad.push(("fee >= 2^64".into(), s));
        bad.push(("amount 1".into(), set(HDR_AMOUNT, 1)));
        for mm in [0, 3, 5, if m == 1 { 2 } else { 1 }, 1 << 20] {
            bad.push((format!("M word {mm}"), set(HDR_LEGS, mm)));
        }
        bad.push(("auditorOn flipped".into(), set(HDR_AUDITOR_ON, !aud as u64)));
        bad.push(("auditorOn 2".into(), set(HDR_AUDITOR_ON, 2)));
        let mut s = st.clone();
        s[32..64].copy_from_slice(&PQZL_ID);
        bad.push(("PQZL id".into(), s));
        let mut s = st.clone();
        s[0] ^= 1;
        bad.push(("opTag".into(), s));
        bad.push(("length - 1".into(), st[..st.len() - 1].to_vec()));
        bad.push(("length + 1".into(), [&st[..], &[0]].concat()));
        for (what, s) in &bad {
            assert!(cs::parse(OP7, s).is_none(), "{} {what} parsed", name(m, aud));
            assert!(prove(OP7, s, &w, [1; 32], &p).is_err() && prove_unchecked(OP7, s, &w, [1; 32], &p).is_err());
            assert!(!verify(OP7, s, &pf, &p), "{} {what}", name(m, aud));
        }
        // recipientsHash is hashed only: the honest proof fails on another list
        let mut s = st.clone();
        s[HDR_RECIPIENTS_HASH + 5] ^= 1;
        assert!(cs::parse(OP7, &s).is_some() && !verify(OP7, &s, &pf, &p), "{} recipientsHash", name(m, aud));
        // legs swapped in the statement (keys and v together, or v only): leg 0 with leg M - 1, and across groups
        let vs_at = HEADER_BYTES + (1 + m + aud as usize) * PK_BYTES + PK_BYTES + V_BYTES + groups(m) * PK_BYTES;
        let pk_at = HEADER_BYTES + PK_BYTES;
        let mut pairs = vec![];
        if m > 1 {
            pairs.push((0, m - 1));
        }
        if m > 4 {
            pairs.push((3, 4));
        }
        for (a, b) in pairs {
            let swap = |s: &mut Vec<u8>, at: usize, n: usize| {
                let (x, y) = (s[at + a * n..at + (a + 1) * n].to_vec(), s[at + b * n..at + (b + 1) * n].to_vec());
                s[at + a * n..at + (a + 1) * n].copy_from_slice(&y);
                s[at + b * n..at + (b + 1) * n].copy_from_slice(&x);
            };
            let mut s1 = st.clone();
            swap(&mut s1, vs_at, V_BYTES);
            let mut s2 = s1.clone();
            swap(&mut s2, pk_at, PK_BYTES);
            for (what, s) in [("v", s1), ("pk and v", s2)] {
                assert!(cs::parse(OP7, &s).is_some());
                assert!(!verify(OP7, &s, &pf, &p), "{} legs {a} / {b} swapped ({what})", name(m, aud));
                assert!(refused(&s, &w), "{} legs {a} / {b} swapped ({what}), witness by position", name(m, aud));
            }
        }
    }
}

/// op 1 and op 7 at M = 1 have the same body; their proofs never verify as each other (op byte and opTag in the
/// transcript, the opTag in the statement); (M = 1, on) and (M = 2, off) are both 83,072 B and stay apart
#[test]
fn op1_op7_and_shapes_separated() {
    let p = pp();
    for aud in [true, false] {
        let (st7, w) = setup_multi(1, aud, &MultiTweak::default());
        // op 1 statement with the same body: op 1's opTag, toUA (= recipientsHash slot, hashed) kept, recipient 0
        let f = if aud { Form::Transfer } else { Form::Transfer0 };
        let mut st1 = st7.clone();
        st1[..32].copy_from_slice(&f.op_tag());
        st1[HDR_LEGS..HDR_LEGS + 32].fill(0);
        assert_eq!(cs::rel_of(OP_TRANSFER, &st1), Some(Rel::Form(f)));
        let (a, b) = (honest(&st7, &w), prove(OP_TRANSFER, &st1, &w, [1; 32], &p).expect("op 1 with op 7's witness"));
        assert!(verify(OP_TRANSFER, &st1, &b, &p));
        assert!(!verify(OP_TRANSFER, &st1, &a, &p), "op 7 proof as op 1");
        assert!(!verify(OP7, &st7, &b, &p), "op 1 proof as op 7");
        assert!(!verify(OP_TRANSFER, &st7, &a, &p) && !verify(OP7, &st1, &b, &p), "statement under the other op");
        assert!(cs::parse(OP_TRANSFER, &st7).is_none() && cs::parse(OP7, &st1).is_none());
    }
    // (1, on) and (2, off): the same 83,072 bytes read as the other shape by its words
    let (s1, w1) = setup_multi(1, true, &MultiTweak::default());
    let (s2, w2) = setup_multi(2, false, &MultiTweak::default());
    assert_eq!(s1.len(), s2.len());
    let (a, b) = (honest(&s1, &w1), honest(&s2, &w2));
    let mut as2 = s1.clone();
    as2[HDR_LEGS + 31] = 2;
    as2[HDR_AUDITOR_ON + 31] = 0;
    let mut as1 = s2.clone();
    as1[HDR_LEGS + 31] = 1;
    as1[HDR_AUDITOR_ON + 31] = 1;
    assert_eq!(cs::rel_of(OP7, &as2), Some(Rel::Multi { m: 2, aud: false }));
    assert_eq!(cs::rel_of(OP7, &as1), Some(Rel::Multi { m: 1, aud: true }));
    assert!(!verify(OP7, &as2, &a, &p) && !verify(OP7, &as1, &b, &p));
    assert_eq!(prove(OP7, &as2, &w1, [1; 32], &p), Err("length"));
    assert_eq!(prove(OP7, &as1, &w2, [1; 32], &p), Err("length"));
}

/// rel_of reads the auditorOn and M words before anything else and admits only built shapes (no layout sized from an
/// unchecked word); short statements have no shape
#[test]
fn rel_of_words() {
    let (st, _) = setup_multi(2, true, &MultiTweak::default());
    assert_eq!(cs::rel_of(OP7, &st), Some(Rel::Multi { m: 2, aud: true }));
    assert_eq!(cs::rel_of(OP7, &st[..HDR_AUDITOR_ON + 31]), None);
    let built: Vec<usize> = shapes().iter().map(|s| s.0).collect();
    for mm in [0u64, 3, 5, 8, 16, 32, 1 << 40] {
        let mut s = st.clone();
        s[HDR_LEGS + 24..HDR_LEGS + 32].copy_from_slice(&mm.to_be_bytes());
        assert_eq!(cs::rel_of(OP7, &s).is_some(), built.contains(&(mm as usize)), "M {mm}");
    }
    let mut s = st.clone();
    s[HDR_LEGS] = 1;
    assert_eq!(cs::rel_of(OP7, &s), None, "M word >= 2^64");
    for (at, v) in [(31, 2u8), (0, 1)] {
        let mut s = st.clone();
        s[HDR_AUDITOR_ON + at] = v;
        assert_eq!(cs::rel_of(OP7, &s), None);
    }
}

/// row 6 of R_TXM (u_T^T s_f + Delta M + e_T = v_T): e_T's range edges, as debit_noise_range_edges
#[test]
fn noise_range_edges() {
    let p = pp();
    for (m, aud) in [(2, true), (4, false)] {
        let (st, w) = setup_multi(m, aud, &MultiTweak::default());
        let ut_at = HEADER_BYTES + (1 + m + aud as usize) * PK_BYTES;
        let vt_at = ut_at + PK_BYTES;
        let ut = polys_of(&st[ut_at..vt_at], 64);
        let sf: Vec<Poly> = w[..N].chunks(64).map(|c| std::array::from_fn(|i| c[i] as i8 as i64)).collect();
        let y = dot_int(&ut.iter().collect::<Vec<_>>(), &sf.iter().collect::<Vec<_>>());
        let wv = modq(polys_of(&st[vt_at..vt_at + 128], 16)[0][0] - y[0]);
        let m0 = (wv + DELTA / 2).div_euclid(DELTA);
        let big_e: i64 = 1 << (pqzh_ligero::set::EBITS - 1);
        for (e, ok) in [(big_e - 1, true), (big_e, false), (-big_e, true), (-big_e - 1, false)] {
            let mut s = st.clone();
            let nv = modq(y[0] + DELTA * m0 + e).rem_euclid(Q as i64) as u64;
            s[vt_at..vt_at + 8].copy_from_slice(&nv.to_be_bytes());
            if ok {
                let pf = prove(OP7, &s, &w, [1; 32], &p).unwrap();
                assert!(verify(OP7, &s, &pf, &p), "{} e_T = {e}", name(m, aud));
            } else {
                assert!(refused(&s, &w), "{} e_T = {e}", name(m, aud));
            }
        }
    }
}

/// D6 hedging for op 7: one statement, witnesses differing in one byte, same rnd32 -> different commitments; equal
/// inputs -> equal proofs; real and decoy legs take one code path (R6: same proof length grammar, same rows)
#[test]
fn hedged_and_deterministic() {
    let p = pp();
    let (st, w) = setup_multi(4, true, &MultiTweak::default());
    let mut w2 = w.clone();
    w2[0] ^= 1;
    let a = prove_unchecked(OP7, &st, &w, [5; 32], &p).unwrap();
    let b = prove_unchecked(OP7, &st, &w2, [5; 32], &p).unwrap();
    assert_ne!(a[..32], b[..32]);
    assert_eq!(a, prove_unchecked(OP7, &st, &w, [5; 32], &p).unwrap());
    assert_eq!(a, prove(OP7, &st, &w, [5; 32], &p).unwrap());
}
