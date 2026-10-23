//! Unit tests: round trip of every form, and one rejection per D15 / R6 rule (P6e plan Task 5).
use super::*;
use alloc::vec;

/// `n` coefficients < q, distinct per `seed`
fn poly_bytes(n: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 * n);
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    for _ in 0..n {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        out.extend_from_slice(&(x.wrapping_mul(2_685_821_657_736_338_717) % Q).to_be_bytes());
    }
    out
}

struct Objs {
    pk: Vec<u8>,
    pk2: Vec<u8>,
    pk3: Vec<u8>,
    ct: Vec<u8>,
    u: Vec<u8>,
    v1: Vec<u8>,
    v2: Vec<u8>,
    v3: Vec<u8>,
}

fn objs() -> Objs {
    Objs {
        pk: poly_bytes(K * D, 1),
        pk2: poly_bytes(K * D, 2),
        pk3: poly_bytes(K * D, 3),
        ct: poly_bytes(K * D + 16, 4),
        u: poly_bytes(K * D, 5),
        v1: poly_bytes(16, 6),
        v2: poly_bytes(16, 7),
        v3: poly_bytes(16, 8),
    }
}

/// A valid statement of `form` (both ids alternate with `id`).
fn build(form: Form, o: &Objs, id: &Word) -> Vec<u8> {
    let s = match form {
        Form::Register => Stmt::Register(Register { words: [form.op_tag(), *id, [7u8; 32]], pk: &o.pk }),
        Form::DiscloseSender | Form::DiscloseReceiver | Form::DiscloseAuditor => {
            let mut words = Disclose::words(form, id);
            words[2] = u64_word(22776);
            words[DW_AMOUNT] = u64_word(123_456);
            words[DW_KIND] = u64_word(2);
            Stmt::Disclose(Disclose { form, words, pk: &o.pk, u: &o.u, v: &o.v1 })
        }
        _ => {
            let mut header = Debit::header(form, id);
            header[H_FEE] = u64_word(7);
            header[H_AMOUNT] = u64_word(if form == Form::Burn { 99 } else { 0 });
            if matches!(form, Form::Transfer | Form::Transfer0) {
                header[H_SALT][16..].copy_from_slice(&[0xA5; 16]);
                header[H_TO] = [0x77; 32];
            } else if form == Form::Burn {
                header[H_RECIPIENT] = u64_word(0xBEEF);
            }
            let (tr, aud) = (matches!(form, Form::Transfer | Form::Transfer0), form == Form::Transfer);
            Stmt::Debit(Debit {
                form,
                header,
                pk_f: &o.pk,
                pk_t: tr.then_some(&o.pk2[..]),
                pk_a: aud.then_some(&o.pk3[..]),
                t: &o.ct,
                u: &o.u,
                v_t: tr.then_some(&o.v1[..]),
                v_f: &o.v2,
                v_a: aud.then_some(&o.v3[..]),
            })
        }
    };
    s.encode().unwrap()
}

#[test]
fn lengths_and_constants() {
    // every set: the lengths from k (PK = 512 k); the v3 set's numbers pinned
    let (pk, v) = (PK_BYTES, V_BYTES);
    assert_eq!((pk, N), (512 * K, 64 * K));
    let want = [640 + 5 * pk + 4 * v, 640 + 4 * pk + 3 * v, 640 + 3 * pk + 2 * v, 640 + 3 * pk + 2 * v, 96 + pk,
                288 + 2 * pk + v, 288 + 2 * pk + v, 288 + 2 * pk + v];
    for (f, n) in FORMS.iter().zip(want) {
        assert_eq!(f.stmt_len(), n, "{f:?}");
    }
    assert_eq!((Form::Transfer0.wit_len(), Form::Transfer.wit_len()), (6 * N + 96, 6 * N + 128));
    assert_eq!((BUNDLE_BYTES, BUNDLE0_BYTES), (16 + pk + 2 * v + 32, 16 + pk + v + 32));
    if SET == "n2048-kmax1024" {
        let want = [83_072, 66_560, 50_048, 50_048, 16_480, 33_184, 33_184, 33_184];
        for (f, n) in FORMS.iter().zip(want) {
            assert_eq!(f.stmt_len(), n, "{f:?}");
        }
        assert_eq!(Form::Transfer0.wit_len(), 12_384);
        assert_eq!(Form::Transfer.wit_len(), 12_416);
        assert_eq!((BUNDLE_BYTES, BUNDLE0_BYTES), (16_688, 16_560));
        assert_eq!(5 + Form::Transfer.stmt_len() + MAX_PROOF_PQZH, 345_221);
    }
    assert!(345_221 <= MAX_INPUT);
    assert_eq!(max_proof(&PQZL_ID), Some(98_304));
    assert_eq!(max_proof(&PQZH_ID), Some(if SET == "n2560-kmax16384" { 327_680 } else { 262_144 }));
    assert_eq!(MAX_INPUT, if SET == "n2048-kmax1024" { 393_216 } else { 524_288 });
    assert_eq!(max_proof(&[0; 32]), None);
    for id in RETIRED {
        assert_eq!(max_proof(&id), None);
    }
}

/// the retired ids (decisions CTR-PQZ-09: PQZL v2, forgeable, lazer#28 / F9; PQZL v3 and PQZH v1, replaced by the per-set
/// ids of plan 5h Task 8d) are unknown ids: refused by every parser, never this set's
const RETIRED: [Word; 3] = [
    hex32("2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f"),
    hex32("8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef"),
    hex32("0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4"),
];

#[test]
fn retired_ids_refused() {
    let o = objs();
    assert!(!RETIRED.contains(&PQZL_ID) && !RETIRED.contains(&PQZH_ID) && PQZL_ID != PQZH_ID);
    for id in RETIRED {
        for f in FORMS {
            assert_eq!(parse(f.op(), &build(f, &o, &id)).err(), Some(Reject::ProofSystemId), "{f:?}");
        }
        for (m, aud) in [(1, true), (4, false)] {
            assert_eq!(parse_multi(&build_multi(&id, m, aud, 0)).err(), Some(Reject::ProofSystemId), "M = {m}");
        }
        assert_eq!(decode_input(&input(3, &build(Form::Register, &o, &id), &[1])).err(), Some(Reject::ProofSystemId));
    }
}

#[test]
fn round_trip_every_form_both_ids() {
    let o = objs();
    for id in [PQZL_ID, PQZH_ID] {
        for f in FORMS {
            let b = build(f, &o, &id);
            assert_eq!(b.len(), f.stmt_len(), "{f:?}");
            let s = parse(f.op(), &b).unwrap_or_else(|e| panic!("{f:?}: {e:?}"));
            assert_eq!(s.form(), Some(f));
            assert_eq!(s.proof_system_id(), Some(&id));
            assert_eq!(s.encode().unwrap(), b, "{f:?}: encode(parse(x)) != x");
        }
    }
}

#[test]
fn fields_land_where_the_spec_says() {
    let o = objs();
    let b = build(Form::Transfer, &o, &PQZL_ID);
    assert_eq!(&b[256 + 24..288], &7u64.to_be_bytes()); // fee word at 256
    assert_eq!(b[448 + 31], 1); // auditorOn at 448
    assert_eq!(&b[640..640 + PK_BYTES], &o.pk[..]); // pk_f
    assert_eq!(&b[640 + 2 * PK_BYTES..640 + 3 * PK_BYTES], &o.pk3[..]); // pk_a
    assert_eq!(&b[b.len() - V_BYTES..], &o.v3[..]); // v_a last
    let b0 = build(Form::Transfer0, &o, &PQZL_ID);
    assert_eq!(b0[448 + 31], 0);
    assert_eq!(&b0[b0.len() - V_BYTES..], &o.v2[..]); // v_f last
    match parse(OP_TRANSFER, &b0).unwrap() {
        Stmt::Debit(d) => {
            assert_eq!((d.fee(), d.amount()), (7, 0));
            assert!(d.pk_a.is_none() && d.v_a.is_none());
            assert_eq!(d.pk_t.unwrap(), &o.pk2[..]);
            assert_eq!(d.t, &o.ct[..]);
        }
        _ => panic!(),
    }
    let d = build(Form::DiscloseAuditor, &o, &PQZL_ID);
    assert_eq!(&d[224 + 24..256], &123_456u64.to_be_bytes()); // amount at 224
    assert_eq!(&d[288..288 + PK_BYTES], &o.pk[..]); // pk at 288
    let r = build(Form::Register, &o, &PQZL_ID);
    assert_eq!(&r[64..96], &[7u8; 32]);
}

fn with(b: &[u8], at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut v = b.to_vec();
    v[at..at + bytes.len()].copy_from_slice(bytes);
    v
}

#[test]
fn every_d15_r6_rule_rejects() {
    let o = objs();
    let t = build(Form::Transfer, &o, &PQZL_ID);
    let t0 = build(Form::Transfer0, &o, &PQZL_ID);
    let bu = build(Form::Burn, &o, &PQZL_ID);
    let rf = build(Form::Refresh, &o, &PQZH_ID);
    let ds = build(Form::DiscloseSender, &o, &PQZL_ID);
    let rg = build(Form::Register, &o, &PQZH_ID);
    let cases: Vec<(&str, u8, Vec<u8>, Reject)> = vec![
        ("coefficient = q", 1, with(&t, 640, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = 2^LOG2Q", 1, with(&t, 640, &(1u64 << LOG2Q).to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in v_a", 1, with(&t, t.len() - 8, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in R_TX0", 1, with(&t0, 700, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in pk (register)", 3, with(&rg, 96, &u64::MAX.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in v (disclose)", 4, with(&ds, ds.len() - 8, &Q.to_be_bytes()), Reject::Coefficient),
        ("fee top byte != 0", 1, with(&t, 256, &[1]), Reject::Fee),
        ("fee = 2^64", 1, with(&t, 256 + 23, &[1]), Reject::Fee),
        ("burn amount >= 2^64", 2, with(&bu, 288 + 5, &[0x80]), Reject::Amount),
        ("disclosure amount >= 2^64", 4, with(&ds, 224, &[1]), Reject::Amount),
        ("transfer amount >= 2^64 (decoder stricter than R_TX)", 1, with(&t, 288, &[1]), Reject::Amount),
        ("salt word top byte set", 1, with(&t, 576, &[1]), Reject::Salt),
        ("salt word byte 15 set (R_TX0)", 1, with(&t0, 591, &[0x80]), Reject::Salt),
        ("burn salt word byte 0 set", 2, with(&bu, 576, &[0xff]), Reject::Salt),
        ("transfer amount != 0", 1, with(&t, 288 + 31, &[1]), Reject::MustBeZero("amount")),
        ("transfer recipient != 0", 1, with(&t, 320 + 12, &[1]), Reject::MustBeZero("recipient")),
        ("R_TX0 recipient != 0", 1, with(&t0, 351, &[1]), Reject::MustBeZero("recipient")),
        ("burn toUA != 0", 2, with(&bu, 192 + 31, &[1]), Reject::MustBeZero("toUA")),
        ("burn auditorOn != 0", 2, with(&bu, 448 + 31, &[1]), Reject::MustBeZero("auditorOn")),
        ("burn salt != 0 (low half)", 2, with(&bu, 607, &[1]), Reject::MustBeZero("salt")),
        ("refresh toUA != 0", 2, with(&rf, 200, &[1]), Reject::MustBeZero("toUA")),
        ("refresh amount != 0", 2, with(&rf, 319, &[1]), Reject::MustBeZero("amount")),
        ("refresh recipient != 0", 2, with(&rf, 340, &[1]), Reject::MustBeZero("recipient")),
        ("refresh auditorOn != 0", 2, with(&rf, 479, &[1]), Reject::MustBeZero("auditorOn")),
        ("refresh salt != 0 (low half)", 2, with(&rf, 600, &[1]), Reject::MustBeZero("salt")),
        ("auditorOn = 2", 1, with(&t, 448 + 31, &[2]), Reject::AuditorOn),
        ("auditorOn = 0 on 83,072 B (dummy auditor)", 1, with(&t, 448 + 31, &[0]), Reject::AuditorOn),
        ("auditorOn = 1 on 66,560 B", 1, with(&t0, 448 + 31, &[1]), Reject::AuditorOn),
        ("auditorOn high byte", 1, with(&t, 448, &[1]), Reject::AuditorOn),
        ("length - 1", 1, t[..t.len() - 1].to_vec(), Reject::Length),
        ("length + 1", 1, [&t[..], &[0]].concat(), Reject::Length),
        ("R_TX0 length + 1", 1, [&t0[..], &[0]].concat(), Reject::Length),
        ("burn length - 1", 2, bu[..bu.len() - 1].to_vec(), Reject::Length),
        ("register length + 1", 3, [&rg[..], &[0]].concat(), Reject::Length),
        ("wrong opTag for op (transfer under op 2)", 2, t.clone(), Reject::OpTag),
        ("REFRESH tag under op 1", 1, with(&t, 0, &Form::Refresh.op_tag()), Reject::OpTag),
        ("AUDITOR tag under op 4", 4, with(&ds, 0, &Form::DiscloseAuditor.op_tag()), Reject::OpTag),
        ("unknown proofSystemId", 1, with(&t, 32, &[0; 32]), Reject::ProofSystemId),
        ("retired STARK id", 3, with(&rg, 32, &[0xaa; 32]), Reject::ProofSystemId),
        ("unknown op 0", 0, t.clone(), Reject::Op),
        ("op 1 statement under op 7", 7, t.clone(), Reject::OpTag),
        ("unknown op 8", 8, t.clone(), Reject::Op),
        ("SELFTEST with a statement", 6, vec![0], Reject::Op),
        ("empty statement op 1", 1, vec![], Reject::OpTag),
    ];
    for (what, op, b, want) in cases {
        assert_eq!(parse(op, &b).err(), Some(want), "{what}");
    }
    assert_eq!(parse(6, &[]), Ok(Stmt::SelfTest));
}

#[test]
fn bundle_and_opening() {
    let o = objs();
    for v_a in [Some(&o.v3[..]), None] {
        let b = Bundle { salt: [3; 16], u: &o.u, v_t: &o.v1, v_a, to_ua: [9; 32] };
        let e = b.encode().unwrap();
        assert_eq!(e.len(), if v_a.is_some() { BUNDLE_BYTES } else { BUNDLE0_BYTES });
        assert_eq!(parse_bundle(&e).unwrap(), b);
        assert_eq!(parse_bundle(&e[1..]).err(), Some(Reject::Length));
        assert_eq!(parse_bundle(&with(&e, 16, &Q.to_be_bytes())).err(), Some(Reject::Coefficient));
        for plen in [0usize, 1, 31, 32, 33, 42_741] {
            let proof: Vec<u8> = (0..plen).map(|i| i as u8).collect();
            let op = opening(&e, &proof);
            assert_eq!(op.len() % 32, 0);
            assert_eq!(parse_opening(&op), Ok((&e[..], &proof[..])));
            assert_eq!(parse_opening(&[&op[..], &[0; 32]].concat()).err(), Some(Reject::Opening), "trailing");
            assert_eq!(parse_opening(&op[..op.len() - 1]).err(), Some(Reject::Opening), "short");
            assert_eq!(parse_opening(&with(&op, 31, &[96])).err(), Some(Reject::Opening), "head offset");
            if plen % 32 != 0 {
                let last = op.len() - 1;
                assert_eq!(parse_opening(&with(&op, last, &[1])).err(), Some(Reject::Opening), "padding");
            }
        }
    }
    // length words near 2^64: rejected, no overflow (debug builds check arithmetic)
    for n in [u64::MAX, u64::MAX - 31, u64::MAX - 63, (usize::MAX - 40) as u64, 1 << 40] {
        let mut op = opening(&[1; 33], &[2; 5]);
        op[64..96].copy_from_slice(&u64_word(n));
        assert_eq!(parse_opening(&op).err(), Some(Reject::Opening), "bundle length {n}");
        let mut op = opening(&[1; 33], &[2; 5]);
        op[160..192].copy_from_slice(&u64_word(n));
        assert_eq!(parse_opening(&op).err(), Some(Reject::Opening), "proof length {n}");
        let mut op = opening(&[1; 33], &[2; 5]);
        op[32..64].copy_from_slice(&u64_word(n));
        assert_eq!(parse_opening(&op).err(), Some(Reject::Opening), "second offset {n}");
    }
    // the opening layout of pqz_kat.py's self-test: bundle 33 B, proof 5 B
    let op = opening(&[1; 33], &[2; 5]);
    assert_eq!(op.len(), 64 + 32 + 64 + 32 + 32);
    assert_eq!(&op[..64], &[u64_word(64), u64_word(160)].concat()[..]);
}

#[test]
fn precompile_input() {
    let o = objs();
    let t0 = build(Form::Transfer0, &o, &PQZL_ID);
    let proof = vec![0x5a; 42_415];
    let inp = input(OP_TRANSFER, &t0, &proof);
    let d = decode_input(&inp).unwrap();
    assert_eq!((d.op, d.stmt.form(), d.proof.len(), d.stmt_bytes), (1, Some(Form::Transfer0), 42_415, &t0[..]));
    assert_eq!(decode_input(&input(OP_TRANSFER, &t0, &[])).err(), Some(Reject::ProofLength));
    let big = vec![1; MAX_PROOF_PQZL + 1];
    assert_eq!(decode_input(&input(OP_TRANSFER, &t0, &big)).err(), Some(Reject::ProofLength));
    let h = build(Form::Transfer, &o, &PQZH_ID);
    assert!(decode_input(&input(OP_TRANSFER, &h, &big)).is_ok()); // PQZH bound is larger
    let max = vec![1; MAX_PROOF_PQZH];
    assert!(decode_input(&input(OP_TRANSFER, &h, &max)).is_ok()); // the largest input: 345,221 B
    assert_eq!(decode_input(&input(OP_TRANSFER, &h, &[max.as_slice(), &[1]].concat())).err(), Some(Reject::ProofLength));
    let mut over = input(OP_TRANSFER, &h, &max);
    over.resize(MAX_INPUT + 1, 0);
    assert_eq!(decode_input(&over).err(), Some(Reject::Input));
    let mut bad_len = inp.clone();
    bad_len[1..5].copy_from_slice(&(inp.len() as u32).to_be_bytes());
    assert_eq!(decode_input(&bad_len).err(), Some(Reject::Input));
    let mut short_len = inp.clone(); // length field one short: the statement is cut, its last byte joins the proof
    short_len[1..5].copy_from_slice(&((t0.len() - 1) as u32).to_be_bytes());
    assert_eq!(decode_input(&short_len).err(), Some(Reject::Length));
    assert_eq!(decode_input(&[6, 0, 0, 0, 0]).map(|d| d.stmt), Ok(Stmt::SelfTest));
    assert_eq!(decode_input(&[6, 0, 0, 0, 0, 1]).err(), Some(Reject::ProofLength));
    assert_eq!(decode_input(&[6, 0, 0, 0, 1, 0]).err(), Some(Reject::Op));
    assert_eq!(decode_input(&[1, 0, 0]).err(), Some(Reject::Input));
}

#[test]
fn coefficient_codec() {
    let c: Vec<u64> = (0..N as u64).map(|i| (i * 2_147_483_647) % Q).collect();
    let mut b = Vec::new();
    write_coeffs(&c, &mut b).unwrap();
    check_pk(&b).unwrap();
    let mut back = vec![0u64; N];
    read_coeffs(&b, &mut back).unwrap();
    assert_eq!(back, c);
    assert_eq!(write_coeffs(&[Q], &mut b).err(), Some(Reject::Coefficient));
    assert_eq!(check_ct(&b).err(), Some(Reject::Length));
    assert_eq!(read_coeffs(&Q.to_be_bytes(), &mut back[..1]).err(), Some(Reject::Coefficient));
    assert_eq!(word_u64(&u64_word(u64::MAX)), Some(u64::MAX));
}

// ---- op 7 `R_TXM` (P6-ANON S2: plan §4, D6, R4)

/// A valid op 7 statement: M keys / legs, G groups, auditor on / off, the given fee.
fn build_multi(id: &Word, m: usize, aud: bool, fee: u64) -> Vec<u8> {
    let g = groups(m);
    let (pks, us, vs, v_as) =
        (poly_bytes(m * K * D, 11), poly_bytes(g * K * D, 12), poly_bytes(16 * m, 13), poly_bytes(16 * m, 14));
    let (pk_f, pk_a, t, v_f) = (poly_bytes(K * D, 1), poly_bytes(K * D, 3), poly_bytes(K * D + 16, 4), poly_bytes(16, 7));
    let mut header = Multi::header(id, m, aud);
    header[H_FEE] = u64_word(fee);
    header[H_RECIPIENTS_HASH] = [0x5c; 32];
    header[H_SALT][16..].copy_from_slice(&[0xA5; 16]);
    let s = Multi {
        header,
        m,
        pk_f: &pk_f,
        pks: &pks,
        pk_a: aud.then_some(&pk_a[..]),
        t: &t,
        us: &us,
        vs: &vs,
        v_f: &v_f,
        v_as: aud.then_some(&v_as[..]),
    };
    s.encode().unwrap()
}

#[test]
fn multi_lengths_and_sets() {
    let want = [
        (1, 83_072, 66_560),
        (2, 99_712, 83_072),
        (4, 132_992, 116_096),
        (8, 215_936, 198_528),
        (16, 381_824, 363_392),
    ];
    for (m, on, off) in want {
        if SET == "n2048-kmax1024" {
            assert_eq!((multi_len(m, true), multi_len(m, false)), (on, off), "M = {m}");
        }
        let (pk, v) = (PK_BYTES, V_BYTES);
        assert_eq!(multi_len(m, true), 640 + 3 * pk + 2 * v + (pk + 2 * v) * m + pk * groups(m));
        assert_eq!(multi_len(m, false), 640 + 2 * pk + 2 * v + (pk + v) * m + pk * groups(m));
    }
    assert_eq!([1, 2, 4, 5, 8, 9, 16].map(groups), [1, 1, 1, 2, 2, 3, 4]);
    // M = 1 has op 1's lengths (F6); the lengths of the union of built sets are distinct except (M = 1, on) =
    // (M = 2, off), whose object counts are equal: the header's M and auditorOn words pick the shape (R4 as built)
    assert_eq!((multi_len(1, true), multi_len(1, false)), (Form::Transfer.stmt_len(), Form::Transfer0.stmt_len()));
    let shapes: Vec<(usize, bool)> = [1, 2, 4, 8, 16].iter().flat_map(|&m| [(m, true), (m, false)]).collect();
    for (i, &a) in shapes.iter().enumerate() {
        for &b in &shapes[i + 1..] {
            let same = multi_len(a.0, a.1) == multi_len(b.0, b.1);
            assert_eq!(same, (a, b) == ((1, true), (2, false)), "{a:?} {b:?}");
        }
    }
    #[cfg(not(feature = "oversize"))]
    assert_eq!((built_legs(&PQZL_ID), built_legs(&PQZH_ID)), (&[1, 2, 4, 8][..], &[1, 2, 4][..]));
    assert!(built_legs(&[0; 32]).is_empty());
    // D8 / D20: every built op 7 shape leaves room for MAX_PROOF(id) within MAX_INPUT, except at n2048-kmax1024 PQZH
    // (4, on): 5 + 132,992 + 262,144 = 395,141 > 393,216 (a PQZH proof over 260,219 B makes that input exceed MAX_INPUT;
    // Ligero's exact bound there is 236,196). The other sets' MAX_INPUT 512 KiB holds every shape (largest: n2560-kmax16384
    // PQZH (4, on), 5 + 165,760 + 327,680 = 493,445; plan 5h Task 8c part 2)
    #[cfg(not(feature = "oversize"))]
    for id in [PQZL_ID, PQZH_ID] {
        for aud in [true, false] {
            for &m in built_legs(&id) {
                let fits = 5 + multi_len(m, aud) + max_proof(&id).unwrap() <= MAX_INPUT;
                assert_eq!(fits, !(SET == "n2048-kmax1024" && id == PQZH_ID && m == 4 && aud), "M = {m}, A = {aud}");
            }
        }
    }
    if SET == "n2048-kmax1024" {
        assert_eq!(MAX_INPUT - 5 - multi_len(4, true), 260_219);
    }
    assert_eq!(OP_TAG_TRANSFER_MULTI[..4], [0x6f, 0x6a, 0x77, 0x3a]);
}

#[test]
fn multi_round_trip_every_built_shape_fee_0() {
    for id in [PQZL_ID, PQZH_ID] {
        for aud in [true, false] {
            for &m in built_legs(&id) {
                for fee in [0, 7, u64::MAX] {
                    let b = build_multi(&id, m, aud, fee);
                    assert_eq!(b.len(), multi_len(m, aud));
                    let s = parse_multi(&b).unwrap_or_else(|e| panic!("M = {m}, A = {aud}: {e:?}"));
                    let g = groups(m);
                    assert_eq!((s.m, s.pk_a.is_some(), s.fee(), s.groups()), (m, aud, fee, g));
                    assert_eq!(s.encode().unwrap(), b, "encode(parse(x)) != x, M = {m}, A = {aud}");
                    // §4 offsets
                    let a = aud as usize;
                    assert_eq!(s.pk(m - 1), &b[640 + PK_BYTES + PK_BYTES * (m - 1)..][..PK_BYTES]);
                    let u0 = 640 + 2 * PK_BYTES + V_BYTES + PK_BYTES * (m + a);
                    assert_eq!(s.u(g - 1), &b[u0 + PK_BYTES * (g - 1)..][..PK_BYTES]);
                    let v0 = u0 + PK_BYTES * g;
                    assert_eq!(s.v(m - 1), &b[v0 + V_BYTES * (m - 1)..][..V_BYTES]);
                    assert_eq!(s.v_f, &b[v0 + V_BYTES * m..][..V_BYTES]);
                    if aud {
                        assert_eq!(s.v_a(m - 1).unwrap(), &b[b.len() - V_BYTES..]);
                    }
                    assert_eq!(&b[H_LEGS * 32..][..32], &u64_word(m as u64));
                    assert_eq!(&b[H_RECIPIENTS_HASH * 32..][..32], &[0x5c; 32]);
                }
            }
        }
    }
}

#[test]
fn multi_m1_body_is_op1_body() {
    // F6: at M = 1, G = 1 the body is op 1's (pk_f ‖ pk_t ‖ [pk_a] ‖ T ‖ u ‖ v_t ‖ v_f ‖ [v_a]); the header differs only
    // in opTag, word 192 (toUA vs recipientsHash) and word 320 (0 vs M)
    for aud in [true, false] {
        let b = build_multi(&PQZL_ID, 1, aud, 7);
        let s = parse_multi(&b).unwrap();
        let mut h = s.header;
        h[H_OPTAG] = Form::Transfer.op_tag();
        h[H_TO] = [0x5c; 32];
        h[H_RECIPIENT] = [0; 32];
        let d = Debit {
            form: if aud { Form::Transfer } else { Form::Transfer0 },
            header: h,
            pk_f: s.pk_f,
            pk_t: Some(s.pk(0)),
            pk_a: s.pk_a,
            t: s.t,
            u: s.u(0),
            v_t: Some(s.v(0)),
            v_f: s.v_f,
            v_a: s.v_a(0),
        };
        let op1 = Stmt::Debit(d).encode().unwrap();
        assert!(parse(OP_TRANSFER, &op1).is_ok());
        assert_eq!(op1[HEADER_BYTES..], b[HEADER_BYTES..], "A = {aud}");
        let diff: Vec<usize> = (0..20).filter(|&i| op1[32 * i..32 * i + 32] != b[32 * i..32 * i + 32]).collect();
        assert_eq!(diff, [H_OPTAG, H_LEGS]); // word 192 equal here by construction
        // the forms never decode as each other
        assert_eq!(parse_multi(&op1).err(), Some(Reject::OpTag));
        assert_eq!(parse(OP_TRANSFER, &b).err(), Some(Reject::OpTag));
    }
}

#[test]
fn multi_every_rule_rejects() {
    let l = build_multi(&PQZL_ID, 2, true, 0);
    let l0 = build_multi(&PQZL_ID, 4, false, 5);
    let h = build_multi(&PQZH_ID, 4, false, 1);
    let word = |x: u64| u64_word(x);
    #[allow(unused_mut)]
    let mut cases: Vec<(&str, Vec<u8>, Reject)> = vec![
        ("length - 1", l[..l.len() - 1].to_vec(), Reject::Length),
        ("length + 1", [&l[..], &[0]].concat(), Reject::Length),
        ("M = 3 length, M word 2", build_multi_len(&l, multi_len(3, true)), Reject::Length),
        ("M = 0 length (50,048 B), M word 2", build_multi_len(&l, multi_len(0, true)), Reject::Length),
        ("header cut (639 B)", l[..639].to_vec(), Reject::Length),
        ("M word 0", with(&build_multi(&PQZL_ID, 1, true, 0), 320, &word(0)), Reject::Legs),
        ("M word 3", with(&l, 320, &word(3)), Reject::Legs),
        ("M word high byte", with(&l, 320, &[1]), Reject::Legs),
        ("M word 4 on the M = 2 length", with(&l, 320, &word(4)), Reject::Length),
        ("M word 1 on the M = 2 length", with(&l, 320, &word(1)), Reject::Length),
        ("auditorOn 0 on an auditor-on statement", with(&l, 448, &word(0)), Reject::Length),
        ("auditorOn 1 on an auditor-off statement", with(&l0, 448, &word(1)), Reject::Length),
        ("auditorOn 2", with(&h, 448, &word(2)), Reject::AuditorOn),
        ("auditorOn high byte", with(&h, 448, &[1]), Reject::AuditorOn),
        ("amount 1", with(&l, 288, &word(1)), Reject::MustBeZero("amount")),
        ("amount >= 2^64", with(&l, 288 + 23, &[1]), Reject::Amount),
        ("fee >= 2^64", with(&l, 256, &[1]), Reject::Fee),
        ("salt word high half", with(&l0, 576 + 3, &[1]), Reject::Salt),
        ("coefficient = q in pk_f", with(&l, 640, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in pk_1", with(&l, 640 + 2 * PK_BYTES, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = 2^LOG2Q in u_0", with(&h, 640 + 2 * PK_BYTES + V_BYTES + 4 * PK_BYTES, &(1u64 << LOG2Q).to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in v_{a,M-1}", with(&l, l.len() - 8, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in v_f (auditor off)", with(&l0, l0.len() - 8, &Q.to_be_bytes()), Reject::Coefficient),
        ("op 1 opTag", with(&l, 0, &Form::Transfer.op_tag()), Reject::OpTag),
        ("opTag bit", with(&l, 31, &[l[31] ^ 1]), Reject::OpTag),
        ("unknown proofSystemId", with(&l, 32, &[0; 32]), Reject::ProofSystemId),
        ("empty", vec![], Reject::OpTag),
    ];
    #[cfg(not(feature = "oversize"))]
    cases.extend([
        ("PQZH M = 8 (not built)", with(&build_multi_len(&h, multi_len(8, false)), 320, &word(8)), Reject::Legs),
        ("PQZL M = 16 (oversize only)", with(&build_multi_len(&l, multi_len(16, true)), 320, &word(16)), Reject::Legs),
        ("PQZH M = 8 length, M word 4", build_multi_len(&h, multi_len(8, false)), Reject::Length),
    ]);
    for (what, b, want) in cases {
        assert_eq!(parse_multi(&b).err(), Some(want), "{what}");
    }
    // 83,072 B: (M = 1, on) relabelled (M = 2, off) is another valid statement; the words decide, the objects shift
    let one = build_multi(&PQZL_ID, 1, true, 0);
    let two = with(&with(&one, 320, &word(2)), 448, &word(0));
    let (a, b) = (parse_multi(&one).unwrap(), parse_multi(&two).unwrap());
    assert_eq!((a.m, a.pk_a.is_some(), b.m, b.pk_a.is_some()), (1, true, 2, false));
    assert_eq!((b.pk(1), b.v(1), b.v_f), (a.pk_a.unwrap(), a.v_f, a.v_a(0).unwrap()));
    assert_eq!(b.encode().unwrap(), two);
    // S3: op 7 goes through parse / decode_input as Stmt::Multi (no Form); the decoder's reasons are parse_multi's
    let s7 = parse(OP_TRANSFER_MULTI, &l).unwrap();
    let want = Stmt::Multi(parse_multi(&l).unwrap());
    assert_eq!((&s7, s7.form(), s7.proof_system_id()), (&want, None, Some(&PQZL_ID)));
    assert_eq!(s7.encode().unwrap(), l);
    let inp = input(OP_TRANSFER_MULTI, &l, &[1; 100]);
    let d = decode_input(&inp).unwrap();
    assert_eq!((d.op, d.stmt_bytes, d.proof.len()), (OP_TRANSFER_MULTI, &l[..], 100));
    assert_eq!(decode_input(&input(OP_TRANSFER_MULTI, &l, &[])).err(), Some(Reject::ProofLength));
    assert_eq!(decode_input(&input(OP_TRANSFER_MULTI, &l, &vec![1; MAX_PROOF_PQZL + 1])).err(), Some(Reject::ProofLength));
    for (what, b, want) in [("M word 3", with(&l, 320, &word(3)), Reject::Legs), ("length + 1", [&l[..], &[0]].concat(), Reject::Length)] {
        assert_eq!(parse(OP_TRANSFER_MULTI, &b).err(), Some(want), "{what}");
        assert_eq!(decode_input(&input(OP_TRANSFER_MULTI, &b, &[1; 100])).err(), Some(want), "{what}");
    }
    // op 7 bytes under op 1 and op 1 bytes under op 7: OpTag both ways
    assert_eq!(parse(OP_TRANSFER, &l).err(), Some(Reject::OpTag));
    // PQZH (4, on) at n2048-kmax1024: a proof of MAX_INPUT − 5 − 132,992 = 260,219 B is exactly MAX_INPUT; one byte more
    // is Input. Every other set (MAX_INPUT 512 KiB): MAX_PROOF_PQZH fits, one byte more is ProofLength
    let h4 = build_multi(&PQZH_ID, 4, true, 0);
    let room = MAX_INPUT - 5 - multi_len(4, true); // v3: 260,219
    let (fit, over) = if room <= MAX_PROOF_PQZH { (room, Reject::Input) } else { (MAX_PROOF_PQZH, Reject::ProofLength) };
    assert_eq!(room <= MAX_PROOF_PQZH, SET == "n2048-kmax1024");
    assert!(decode_input(&input(OP_TRANSFER_MULTI, &h4, &vec![1; fit])).is_ok());
    assert_eq!(decode_input(&input(OP_TRANSFER_MULTI, &h4, &vec![1; fit + 1])).err(), Some(over));
    // an op 1 statement under op 7's decoder
    let o = objs();
    assert_eq!(parse_multi(&build(Form::Transfer, &o, &PQZL_ID)).err(), Some(Reject::OpTag));
    // encode refuses objects that do not fit M / the auditor flag
    let s = parse_multi(&l).unwrap();
    assert_eq!(Multi { m: 3, ..s.clone() }.encode().err(), Some(Reject::Length));
    assert_eq!(Multi { v_as: None, ..s.clone() }.encode().err(), Some(Reject::Length));
    assert_eq!(Multi { us: s.pks, ..s.clone() }.encode().err(), Some(Reject::Length));
    let mut hm = s.header;
    hm[H_LEGS] = word(4);
    assert_eq!(Multi { header: hm, ..s.clone() }.encode().err(), Some(Reject::Legs));
    let mut ha = s.header;
    ha[H_AUDITOR_ON] = word(0);
    assert_eq!(Multi { header: ha, ..s }.encode().err(), Some(Reject::AuditorOn));
}

/// `b`'s header with a body of zeros to length `n` (a statement of another shape, every rule before Length holds)
fn build_multi_len(b: &[u8], n: usize) -> Vec<u8> {
    let mut v = b[..HEADER_BYTES].to_vec();
    v.resize(n, 0);
    v
}

#[cfg(feature = "oversize")]
#[test]
fn multi_oversize_shapes() {
    for id in [PQZL_ID, PQZH_ID] {
        assert_eq!(built_legs(&id), &[1, 2, 4, 8, 16]);
        for aud in [true, false] {
            for m in [4, 8, 16] {
                let b = build_multi(&id, m, aud, 0);
                assert_eq!(parse_multi(&b).unwrap().encode().unwrap(), b);
            }
        }
    }
}
