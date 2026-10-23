//! Prover-API witness layouts (pqz.h; plan R3: not consensus) and a fixture with one honest instance of every
//! statement form for a given `proofSystemId`, built from seeds through the core (KeyGen, Enc) and `pqz-stmt` (the
//! statement builder): the tests, the bench and the wasm32 byte-equality run use it, natively and in wasm32 alike.
//!
//! The scenario mirrors `pqz_bench.c` `setup()`: balance 1,000,000 in `T` (to `pk_f`), a transfer of 123,456 with
//! fee 7 (auditor on, and off), a burn of 123,456 with fee 7, a refresh (fee 7), the registration of `pk_f`, and the
//! disclosures of the transfer's receiver leg by the sender, the receiver and the auditor. Op 7 (`multi_cases`, P6-ANON
//! S3): every built `(M, auditorOn)` of the id, the same `T`, the last leg real (123,456), the others decoys (0), fee 7
//! with the auditor and 0 without; `recipientsHash` over the legs' UAs, the sender memo (`crate::memo`) and its hash.
use pqz_stmt::*;

use crate::pqzl::{self, Key};
use crate::selftest::digits;

pub const BALANCE: u64 = 1_000_000;
pub const VALUE: u64 = 123_456;
pub const FEE: u64 = 7;

/// `int8` vector bytes
pub fn put_i8(out: &mut Vec<u8>, v: &[i8]) {
    out.extend(v.iter().map(|&x| x as u8));
}
/// `int16` little-endian vector bytes
pub fn put_i16(out: &mut Vec<u8>, v: &[i16]) {
    v.iter().for_each(|x| out.extend_from_slice(&x.to_le_bytes()));
}

/// Witness of `R_REG` / `R_DR`: `s ‖ e` (6,144 B).
pub fn wit_key(k: &Key) -> Vec<u8> {
    let mut w = Vec::with_capacity(3 * pqzl::N);
    put_i8(&mut w, &k.s[..]);
    put_i16(&mut w, &k.e[..]);
    w
}

/// Witness of a debit (`R_TX`, `R_TX0`, `R_BURN`): `s_f ‖ e_f ‖ r ‖ e1 ‖ e2_j… ‖ digits…` (`R_TX`: e2_t, e2_f, e2_a,
/// d, d'; `R_TX0`: e2_t, e2_f, d, d'; `R_BURN`: e2_f, d').
pub fn wit_debit(kf: &Key, c: &pqzl::Enc, digit_vecs: &[[u8; 16]]) -> Vec<u8> {
    let mut w = wit_key(kf);
    put_i8(&mut w, &c.r[..]);
    put_i16(&mut w, &c.e1[..]);
    c.e2.iter().for_each(|e| put_i16(&mut w, e));
    digit_vecs.iter().for_each(|d| w.extend_from_slice(d));
    w
}

/// Witness of `R_TXM` (pqz.h `PQZ_TXM_WIT_BYTES`): `s_f ‖ e_f ‖ (r_g ‖ e1_g)_{g<G} ‖ e2_j (j < M) ‖ e2_f ‖
/// [e2_{a,j} (j < M)] ‖ d_j (j < M) ‖ d'`.
pub fn wit_multi(kf: &Key, c: &pqzl::EncMulti, d_legs: &[[u8; 16]], d_f: [u8; 16]) -> Vec<u8> {
    let mut w = wit_key(kf);
    for g in &c.groups {
        put_i8(&mut w, &g.r[..]);
        put_i16(&mut w, &g.e1[..]);
    }
    c.e2.iter().chain([&c.e2_f]).chain(&c.e2_a).for_each(|e| put_i16(&mut w, e));
    d_legs.iter().chain([&d_f]).for_each(|d| w.extend_from_slice(d));
    w
}

/// `R_TXM` witness bytes
pub const fn multi_wit_len(m: usize, aud: bool) -> usize {
    3 * pqzl::N * (1 + groups(m)) + 32 * (m + 1 + aud as usize * m) + 16 * (m + 1)
}

/// `recipientsHash = keccak256(UA_0 ‖ … ‖ UA_{M−1})` (32-byte words, leg order; P6-ANON §4)
pub fn recipients_hash(uas: &[Word]) -> Word {
    let parts: Vec<&[u8]> = uas.iter().map(|u| &u[..]).collect();
    crate::selftest::keccak(&parts)
}

/// Witness of `R_DS`: `r ‖ e1 ‖ e2_t`.
pub fn wit_ds(c: &pqzl::Enc) -> Vec<u8> {
    let mut w = Vec::with_capacity(3 * pqzl::N + 32);
    put_i8(&mut w, &c.r[..]);
    put_i16(&mut w, &c.e1[..]);
    put_i16(&mut w, &c.e2[0]);
    w
}

fn pk(k: &Key) -> &[u8] {
    &k.pk[..]
}

pub struct Case {
    pub form: Form,
    pub stmt: Vec<u8>,
    pub wit: Vec<u8>,
}

impl Case {
    pub fn op(&self) -> u8 {
        self.form.op()
    }
}

fn header(form: Form, id: &Word, amount: u64) -> [Word; 20] {
    let mut h = Debit::header(form, id);
    let zero = zero_words(form);
    for (i, w) in h.iter_mut().enumerate().skip(2) {
        if ![H_FEE, H_AMOUNT, H_AUDITOR_ON, H_SALT].contains(&i) && !zero.iter().any(|z| z.0 == i) {
            *w = u64_word(0x2277_6000 + i as u64);
        }
    }
    h[H_FEE] = u64_word(FEE);
    h[H_AMOUNT] = u64_word(amount);
    if matches!(form, Form::Transfer | Form::Transfer0) {
        h[H_SALT][16..].copy_from_slice(&[0xA5; 16]);
    }
    h
}

fn disc(form: Form, id: &Word, kind: u64, pk: &[u8], u: &[u8], v: &[u8]) -> Option<Vec<u8>> {
    let mut words = Disclose::words(form, id);
    for (i, w) in words.iter_mut().enumerate().take(DW_AMOUNT).skip(2) {
        *w = u64_word(0x2277_6100 + i as u64);
    }
    words[DW_AMOUNT] = u64_word(VALUE);
    words[DW_KIND] = u64_word(kind);
    Stmt::Disclose(Disclose { form, words, pk, u, v }).encode().ok()
}

/// One honest case per form, in `pqz_stmt::FORMS` order; `None` if the core fails.
pub fn cases(id: &Word) -> Option<Vec<Case>> {
    let (kf, kt, ka) = (pqzl::keygen(&[0x46; 32])?, pqzl::keygen(&[0x54; 32])?, pqzl::keygen(&[0x41; 32])?);
    let bal = pqzl::enc(&[&kf.pk], &[digits(BALANCE)], &[0x10; 32])?;
    let mut t = bal.u.to_vec();
    t.extend_from_slice(&bal.vs[0]);
    let rest = BALANCE - VALUE - FEE;
    let (dv, dr) = (digits(VALUE), digits(rest));
    let tx = pqzl::enc(&[&kt.pk, &kf.pk, &ka.pk], &[dv, dr, dv], &[0x11; 32])?;
    let tx0 = pqzl::enc(&[&kt.pk, &kf.pk], &[dv, dr], &[0x12; 32])?;
    let burn = pqzl::enc(&[&kf.pk], &[dr], &[0x13; 32])?;
    let refresh = pqzl::enc(&[&kf.pk], &[digits(BALANCE - FEE)], &[0x14; 32])?;
    let debit = |form: Form, amount: u64, c: &pqzl::Enc, pk_t: Option<&[u8]>, pk_a: Option<&[u8]>| {
        let tr = matches!(form, Form::Transfer | Form::Transfer0);
        let d = Debit {
            form,
            header: header(form, id, amount),
            pk_f: pk(&kf),
            pk_t,
            pk_a,
            t: &t,
            u: &c.u[..],
            v_t: tr.then(|| &c.vs[0][..]),
            v_f: &c.vs[tr as usize][..],
            v_a: pk_a.map(|_| &c.vs[2][..]),
        };
        Stmt::Debit(d).encode().ok()
    };
    let reg = Register { words: [Form::Register.op_tag(), *id, [0x37; 32]], pk: pk(&kf) };
    let out = vec![
        Case {
            form: Form::Transfer,
            stmt: debit(Form::Transfer, 0, &tx, Some(pk(&kt)), Some(pk(&ka)))?,
            wit: wit_debit(&kf, &tx, &[dv, dr]),
        },
        Case {
            form: Form::Transfer0,
            stmt: debit(Form::Transfer0, 0, &tx0, Some(pk(&kt)), None)?,
            wit: wit_debit(&kf, &tx0, &[dv, dr]),
        },
        Case { form: Form::Burn, stmt: debit(Form::Burn, VALUE, &burn, None, None)?, wit: wit_debit(&kf, &burn, &[dr]) },
        Case {
            form: Form::Refresh,
            stmt: debit(Form::Refresh, 0, &refresh, None, None)?,
            wit: wit_debit(&kf, &refresh, &[digits(BALANCE - FEE)]),
        },
        Case { form: Form::Register, stmt: Stmt::Register(reg).encode().ok()?, wit: wit_key(&kf) },
        Case { form: Form::DiscloseSender, stmt: disc(Form::DiscloseSender, id, 0, pk(&kt), &tx.u[..], &tx.vs[0])?, wit: wit_ds(&tx) },
        Case { form: Form::DiscloseReceiver, stmt: disc(Form::DiscloseReceiver, id, 1, pk(&kt), &tx.u[..], &tx.vs[0])?, wit: wit_key(&kt) },
        Case { form: Form::DiscloseAuditor, stmt: disc(Form::DiscloseAuditor, id, 2, pk(&ka), &tx.u[..], &tx.vs[2])?, wit: wit_key(&ka) },
    ];
    debug_assert!(out.iter().zip(FORMS).all(|(c, f)| c.form == f && c.stmt.len() == f.stmt_len() && c.wit.len() == f.wit_len()));
    Some(out)
}

/// The fixture's `pqzKeySeed` for the memo
pub const MEMO_KEY_SEED: [u8; 32] = [0x4d; 32];

/// Leg j's UA in the fixture (12 zero bytes ‖ a 20-byte address)
pub fn leg_ua(j: usize) -> Word {
    u64_word(0x2277_7000 + j as u64)
}

/// One honest op 7 statement of `(M, auditorOn)`.
pub struct MultiCase {
    pub m: usize,
    pub aud: bool,
    pub stmt: Vec<u8>,
    pub wit: Vec<u8>,
    /// the sender memo whose keccak256 is the header's `memoHash`
    pub memo: Vec<u8>,
}

impl MultiCase {
    pub fn op(&self) -> u8 {
        OP_TRANSFER_MULTI
    }
    /// `TransferMulti<M>` / `TransferMulti<M>_0` (auditor off)
    pub fn name(&self) -> String {
        format!("TransferMulti{}{}", self.m, if self.aud { "" } else { "_0" })
    }
}

/// The op 7 shapes of `id` with M ≤ `max_m`: auditor on first, M ascending.
pub fn multi_shapes(id: &Word, max_m: usize) -> Vec<(usize, bool)> {
    [true, false].iter().flat_map(|&a| built_legs(id).iter().filter(|&&m| m <= max_m).map(move |&m| (m, a))).collect()
}

/// One honest op 7 case (`None` if the core fails or `(M, auditorOn)` is not built for `id`).
pub fn multi_case(id: &Word, m: usize, aud: bool) -> Option<MultiCase> {
    if !built_legs(id).contains(&m) {
        return None;
    }
    let (kf, ka) = (pqzl::keygen(&[0x46; 32])?, pqzl::keygen(&[0x41; 32])?);
    let keys: Vec<Key> = (0..m).map(|j| pqzl::keygen(&[0x60 + j as u8; 32])).collect::<Option<_>>()?;
    let bal = pqzl::enc(&[&kf.pk], &[digits(BALANCE)], &[0x10; 32])?;
    let mut t = bal.u.to_vec();
    t.extend_from_slice(&bal.vs[0]);
    let fee = if aud { FEE } else { 0 };
    let amounts: Vec<u64> = (0..m).map(|j| if j == m - 1 { VALUE } else { 0 }).collect();
    let d_legs: Vec<[u8; 16]> = amounts.iter().map(|&a| digits(a)).collect();
    let d_f = digits(BALANCE - VALUE - fee);
    let legs: Vec<(&[u8; pqzl::PK_BYTES], [u8; 16])> = keys.iter().map(|k| &*k.pk).zip(d_legs.iter().copied()).collect();
    let seed = [0x70 ^ m as u8 ^ ((aud as u8) << 7); 32];
    let c = pqzl::enc_multi(&kf.pk, d_f, &legs, aud.then_some(&*ka.pk), &seed)?;

    let mut h = Multi::header(id, m, aud);
    for (i, w) in h.iter_mut().enumerate().skip(2) {
        if ![H_FEE, H_AMOUNT, H_AUDITOR_ON, H_SALT, H_LEGS].contains(&i) {
            *w = u64_word(0x2277_6000 + i as u64);
        }
    }
    h[H_FEE] = u64_word(fee);
    h[H_SALT][16..].copy_from_slice(&[0xA5; 16]);
    let uas: Vec<Word> = (0..m).map(leg_ua).collect();
    h[H_RECIPIENTS_HASH] = recipients_hash(&uas);
    let legs_memo: Vec<(u64, Word)> = amounts.iter().copied().zip(uas).collect();
    let memo = crate::memo::seal(&MEMO_KEY_SEED, &h, aud, &legs_memo)?;
    h[H_MEMO_HASH] = crate::selftest::keccak(&[&memo]);

    let pks = keys.iter().map(|k| &k.pk[..]).collect::<Vec<_>>().concat();
    let us = c.groups.iter().map(|g| &g.u[..]).collect::<Vec<_>>().concat();
    let (vs, v_as) = (c.v.concat(), c.v_a.concat());
    let st = Multi {
        header: h,
        m,
        pk_f: &kf.pk[..],
        pks: &pks,
        pk_a: aud.then_some(&ka.pk[..]),
        t: &t,
        us: &us,
        vs: &vs,
        v_f: &c.v_f,
        v_as: aud.then_some(&v_as[..]),
    };
    let stmt = st.encode().ok()?;
    let wit = wit_multi(&kf, &c, &d_legs, d_f);
    debug_assert!(stmt.len() == multi_len(m, aud) && wit.len() == multi_wit_len(m, aud));
    Some(MultiCase { m, aud, stmt, wit, memo })
}

/// Every op 7 shape of `id` with M ≤ `max_m` (`multi_shapes` order).
pub fn multi_cases(id: &Word, max_m: usize) -> Option<Vec<MultiCase>> {
    multi_shapes(id, max_m).into_iter().map(|(m, a)| multi_case(id, m, a)).collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The op 7 shapes of the digest lines: M ≤ 4, the frozen set (`expected-results.json` `ffi.digest_lines`, from when
/// both backends proved M ≤ 4 on wasm32). The Rust backend's wasm32 M = 8 prove is checked by the vectors' wasm32
/// replay (`vectors/replay_wasm.mjs`: proved again, byte-equal).
const DIGEST_MAX_LEGS: usize = 4;

/// One JSON line per form of `id`, then per op 7 shape with M ≤ `DIGEST_MAX_LEGS` (what wasm32 proves on both backends):
/// keccak256 of statement, witness and proof (`rnd32` = 0x33…, the tests' value), the proof length, and the
/// precompile's verdict. Native (test `digest_lines`) and wasm32 (`wasm/`) must print the same lines: byte-equal
/// fixtures and proofs, the same verdicts.
pub fn digest_lines(id: &Word) -> String {
    if *id == crate::PQZH_ID && !crate::PQZH {
        return String::new(); // PQZH not in this build (parameter set without PQZH)
    }
    let sys = if *id == PQZL_ID { "PQZL" } else { "PQZH" };
    let forms = cases(id).unwrap_or_default().into_iter().map(|c| (format!("{:?}", c.form), c.op(), c.stmt, c.wit));
    let multi = multi_cases(id, DIGEST_MAX_LEGS).unwrap_or_default().into_iter().map(|c| (c.name(), c.op(), c.stmt, c.wit));
    let mut s = String::new();
    for (name, op, stmt, wit) in forms.chain(multi) {
        let k = |b: &[u8]| hex(&crate::selftest::keccak(&[b]));
        let (pf, len, ok) = match crate::prove(op, &stmt, &wit, &[0x33; 32]) {
            Ok(p) => (k(&p), p.len(), crate::precompile(&input(op, &stmt, &p)) == Ok(crate::VALID)),
            Err(e) => (format!("{e:?}"), 0, false),
        };
        s += &format!(
            "{{\"sys\": \"{sys}\", \"form\": \"{name}\", \"stmt\": \"{}\", \"wit\": \"{}\", \"proof\": \"{pf}\", \"proof_len\": {len}, \"valid\": {ok}}}\n",
            k(&stmt),
            k(&wit)
        );
    }
    s
}

/// The self-test hash and its parts as one JSON line.
pub fn selftest_line() -> String {
    match crate::selftest::report() {
        Some(r) => format!(
            "{{\"selftest\": \"{}\", \"kat_digest\": \"{}\", \"a_digest\": \"{}\", \"results\": {:?}, \"precompile\": \"{}\"}}\n",
            hex(&r.hash),
            hex(&r.kat_digest),
            hex(&r.a_digest),
            r.results,
            hex(&crate::precompile(&[6, 0, 0, 0, 0]).unwrap_or_default())
        ),
        None => "{\"selftest\": null}\n".into(),
    }
}
