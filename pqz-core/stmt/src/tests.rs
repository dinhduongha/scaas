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
            header[H_SALT][16..].copy_from_slice(&[0xA5; 16]);
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
    let want = [83_072, 66_560, 50_048, 50_048, 16_480, 33_184, 33_184, 33_184];
    for (f, n) in FORMS.iter().zip(want) {
        assert_eq!(f.stmt_len(), n, "{f:?}");
    }
    assert_eq!(Form::Transfer0.wit_len(), 12_384);
    assert_eq!(Form::Transfer.wit_len(), 12_416);
    assert_eq!((BUNDLE_BYTES, BUNDLE0_BYTES), (16_688, 16_560));
    assert_eq!(5 + Form::Transfer.stmt_len() + MAX_PROOF_PQZH, 345_221);
    assert!(345_221 <= MAX_INPUT);
    assert_eq!(max_proof(&PQZL_ID), Some(98_304));
    assert_eq!(max_proof(&PQZH_ID), Some(262_144));
    assert_eq!(max_proof(&[0; 32]), None);
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
    let ds = build(Form::DiscloseSender, &o, &PQZL_ID);
    let rg = build(Form::Register, &o, &PQZH_ID);
    let cases: Vec<(&str, u8, Vec<u8>, Reject)> = vec![
        ("coefficient = q", 1, with(&t, 640, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = 2^42", 1, with(&t, 640, &(1u64 << 42).to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in v_a", 1, with(&t, t.len() - 8, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in R_TX0", 1, with(&t0, 700, &Q.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in pk (register)", 3, with(&rg, 96, &u64::MAX.to_be_bytes()), Reject::Coefficient),
        ("coefficient = q in v (disclose)", 4, with(&ds, ds.len() - 8, &Q.to_be_bytes()), Reject::Coefficient),
        ("fee top byte != 0", 1, with(&t, 256, &[1]), Reject::Fee),
        ("fee = 2^64", 1, with(&t, 256 + 23, &[1]), Reject::Fee),
        ("burn amount >= 2^64", 2, with(&bu, 288 + 5, &[0x80]), Reject::Amount),
        ("disclosure amount >= 2^64", 4, with(&ds, 224, &[1]), Reject::Amount),
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
        ("unknown op 7", 7, t.clone(), Reject::Op),
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
        assert_eq!(e.len(), if v_a.is_some() { 16_688 } else { 16_560 });
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
    let c: Vec<u64> = (0..2048).map(|i| (i * 2_147_483_647) % Q).collect();
    let mut b = Vec::new();
    write_coeffs(&c, &mut b).unwrap();
    check_pk(&b).unwrap();
    let mut back = vec![0u64; 2048];
    read_coeffs(&b, &mut back).unwrap();
    assert_eq!(back, c);
    assert_eq!(write_coeffs(&[Q], &mut b).err(), Some(Reject::Coefficient));
    assert_eq!(check_ct(&b).err(), Some(Reject::Length));
    assert_eq!(read_coeffs(&Q.to_be_bytes(), &mut back[..1]).err(), Some(Reject::Coefficient));
    assert_eq!(word_u64(&u64_word(u64::MAX)), Some(u64::MAX));
}
