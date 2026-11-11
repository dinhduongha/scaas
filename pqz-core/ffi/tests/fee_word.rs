// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Round 3t (verifier fee spec §15 (9), CTR-PQZ-36): the verifier fee is part of the public `fee` word every debit relation
//! subtracts from the sender's hidden balance (§5.2: no relation, transcript or `proofSystemId` moves). With real proofs of
//! PQZL and, where the set builds it, PQZH: op 1 (`R_TX0`), op 7 with M = 2 (`R_TXM`, auditor off), a burn and a refresh,
//! each proved at `fee = txFee + verifierFee`, verify `01`; the same proofs with the fee word at `fee ± 1` verify `00` (a fee
//! change kills a built proof); an over-spend witness (`balance < v + fee`, `d'` wrapped) never yields a valid proof (the
//! prover refuses or the proof verifies `00`): a sender out of hidden balance cannot transact. The statements are built here
//! from the fixture's building blocks (KeyGen, Enc, `pqz-stmt`), at this test's fee. UNAUDITED.
mod common;

use common::{ids, RND};
use pqz_ffi::fixture::{wit_debit, wit_multi};
use pqz_ffi::pqzl::{self, Key};
use pqz_ffi::selftest::digits;
use pqz_ffi::stmt::{self, u64_word, zero_words, Debit, Form, Multi, Stmt, Word, H_AMOUNT, H_AUDITOR_ON, H_FEE, H_LEGS, H_SALT};
use pqz_ffi::*;

const BALANCE: u64 = 1_000_000;
const VALUE: u64 = 123_456;
const TX_FEE: u64 = 3; // the token's `confidentialFee` with a beneficiary
const VF: u64 = 2; // the verifier fee in force
const FEE: u64 = TX_FEE + VF;

fn key(b: u8) -> Key {
    pqzl::keygen(&[b; 32]).expect("keygen")
}

/// `T` = Enc(pk_f, BALANCE)
fn total(kf: &Key) -> Vec<u8> {
    let bal = pqzl::enc(&[&kf.pk], &[digits(BALANCE)], &[0x10; 32]).expect("enc");
    let mut t = bal.u.to_vec();
    t.extend_from_slice(&bal.vs[0]);
    t
}

fn header(form: Form, id: &Word, amount: u64, fee: u64) -> [Word; 20] {
    let mut h = Debit::header(form, id);
    let zero = zero_words(form);
    for (i, w) in h.iter_mut().enumerate().skip(2) {
        if ![H_FEE, H_AMOUNT, H_AUDITOR_ON, H_SALT].contains(&i) && !zero.iter().any(|z| z.0 == i) {
            *w = u64_word(0x2277_6000 + i as u64);
        }
    }
    h[H_FEE] = u64_word(fee);
    h[H_AMOUNT] = u64_word(amount);
    if matches!(form, Form::Transfer0) {
        h[H_SALT][16..].copy_from_slice(&[0xA5; 16]);
    }
    h
}

/// One debit: (op, statement, witness) of `form` moving `value` (op 1) or `amount` (burn) at `fee`; `rest` the new
/// balance's value as the witness carries it (wrapping on an over-spend).
fn debit(id: &Word, form: Form, value: u64, fee: u64) -> (u8, Vec<u8>, Vec<u8>) {
    let (kf, kt) = (key(0x46), key(0x54));
    let t = total(&kf);
    let rest = BALANCE.wrapping_sub(value).wrapping_sub(fee);
    let (stmt, wit) = match form {
        Form::Transfer0 => {
            let c = pqzl::enc(&[&kt.pk, &kf.pk], &[digits(value), digits(rest)], &[0x12; 32]).expect("enc");
            let d = Debit {
                form,
                header: header(form, id, 0, fee),
                pk_f: &kf.pk[..],
                pk_t: Some(&kt.pk[..]),
                pk_a: None,
                t: &t,
                u: &c.u[..],
                v_t: Some(&c.vs[0][..]),
                v_f: &c.vs[1][..],
                v_a: None,
            };
            (Stmt::Debit(d).encode().expect("encode"), wit_debit(&kf, &c, &[digits(value), digits(rest)]))
        }
        _ => {
            let amount = if matches!(form, Form::Burn) { value } else { 0 };
            let c = pqzl::enc(&[&kf.pk], &[digits(rest)], &[0x13; 32]).expect("enc");
            let d = Debit {
                form,
                header: header(form, id, amount, fee),
                pk_f: &kf.pk[..],
                pk_t: None,
                pk_a: None,
                t: &t,
                u: &c.u[..],
                v_t: None,
                v_f: &c.vs[0][..],
                v_a: None,
            };
            (Stmt::Debit(d).encode().expect("encode"), wit_debit(&kf, &c, &[digits(rest)]))
        }
    };
    (form.op(), stmt, wit)
}

/// Op 7, M = 2, auditor off: leg 0 a decoy (0), leg 1 `value`, at `fee` (`txFee + vf + 2·d`, its split not in the
/// relation).
fn multi(id: &Word, value: u64, fee: u64) -> (u8, Vec<u8>, Vec<u8>) {
    let m = 2;
    let kf = key(0x46);
    let keys: Vec<Key> = (0..m).map(|j| key(0x60 + j as u8)).collect();
    let t = total(&kf);
    let d_legs = [digits(0), digits(value)];
    let d_f = digits(BALANCE.wrapping_sub(value).wrapping_sub(fee));
    let legs: Vec<(&[u8; pqzl::PK_BYTES], [u8; 16])> = keys.iter().map(|k| &*k.pk).zip(d_legs.iter().copied()).collect();
    let c = pqzl::enc_multi(&kf.pk, d_f, &legs, None, &[0x72; 32]).expect("enc_multi");
    let mut h = Multi::header(id, m, false);
    for (i, w) in h.iter_mut().enumerate().skip(2) {
        if ![H_FEE, H_AMOUNT, H_AUDITOR_ON, H_SALT, H_LEGS].contains(&i) {
            *w = u64_word(0x2277_6000 + i as u64);
        }
    }
    h[H_FEE] = u64_word(fee);
    h[H_SALT][16..].copy_from_slice(&[0xA5; 16]);
    let pks = keys.iter().map(|k| &k.pk[..]).collect::<Vec<_>>().concat();
    let us = c.groups.iter().map(|g| &g.u[..]).collect::<Vec<_>>().concat();
    let vs = c.v.concat();
    let st = Multi { header: h, m, pk_f: &kf.pk[..], pks: &pks, pk_a: None, t: &t, us: &us, vs: &vs, v_f: &c.v_f, v_as: None };
    (stmt::OP_TRANSFER_MULTI, st.encode().expect("encode"), wit_multi(&kf, &c, &d_legs, d_f))
}

fn verdict(op: u8, st: &[u8], proof: &[u8]) -> Word {
    precompile(&stmt::input(op, st, proof)).expect("decodes")
}

/// The statement with its fee word replaced (the header word at `32 · H_FEE`).
fn with_fee(st: &[u8], fee: u64) -> Vec<u8> {
    let mut s = st.to_vec();
    s[32 * H_FEE..32 * H_FEE + 32].copy_from_slice(&u64_word(fee));
    s
}

fn cases(id: &Word, value_tx: u64, fee: u64) -> Vec<(&'static str, (u8, Vec<u8>, Vec<u8>))> {
    vec![
        ("op 1", debit(id, Form::Transfer0, value_tx, fee)),
        ("op 7 M=2", multi(id, value_tx, fee)),
        ("burn", debit(id, Form::Burn, value_tx, fee)),
        ("refresh", debit(id, Form::Refresh, 0, fee)),
    ]
}

#[test]
fn fee_word_binds_the_verifier_fee() {
    for id in ids() {
        for (name, (op, st, wit)) in cases(&id, VALUE, FEE) {
            let tag = if id == PQZL_ID { "PQZL" } else { "PQZH" };
            let proof = prove(op, &st, &wit, &RND).unwrap_or_else(|e| panic!("{tag} {name}: prove {e:?}"));
            assert_eq!(verdict(op, &st, &proof), VALID, "{tag} {name}: fee = txFee + vf verifies 01");
            assert_eq!(verdict(op, &with_fee(&st, FEE + 1), &proof), INVALID, "{tag} {name}: fee + 1 verifies 00");
            assert_eq!(verdict(op, &with_fee(&st, FEE - 1), &proof), INVALID, "{tag} {name}: fee - 1 verifies 00");
            assert_eq!(verdict(op, &with_fee(&st, TX_FEE), &proof), INVALID, "{tag} {name}: without vf verifies 00");
            println!("{tag} {name}: 01 at fee {FEE}, 00 at {} / {} / {TX_FEE}", FEE + 1, FEE - 1);
        }
    }
}

/// `balance < v + fee` (the hidden balance short by 1 of the value plus `txFee + vf`): the wrapped `d'` has no valid proof.
#[test]
fn overspend_has_no_valid_proof() {
    for id in ids() {
        let tag = if id == PQZL_ID { "PQZL" } else { "PQZH" };
        for (name, (op, st, wit)) in cases(&id, BALANCE - FEE + 1, FEE) {
            if name == "refresh" {
                continue; // a refresh moves no value; its over-spend is the fee alone (below)
            }
            match prove(op, &st, &wit, &RND) {
                Ok(p) => assert_eq!(verdict(op, &st, &p), INVALID, "{tag} {name}: an over-spend verifies 00"),
                Err(e) => println!("{tag} {name}: the prover refuses the over-spend ({e:?})"),
            }
        }
        // a refresh of a balance below the fee: fee = BALANCE + 1
        let (op, st, wit) = debit(&id, Form::Refresh, 0, BALANCE + 1);
        match prove(op, &st, &wit, &RND) {
            Ok(p) => assert_eq!(verdict(op, &st, &p), INVALID, "{tag} refresh: fee above the balance verifies 00"),
            Err(e) => println!("{tag} refresh: the prover refuses ({e:?})"),
        }
        // the control: one unit less is an exact spend, valid
        let (op, st, wit) = debit(&id, Form::Burn, BALANCE - FEE, FEE);
        let p = prove(op, &st, &wit, &RND).expect("exact spend");
        assert_eq!(verdict(op, &st, &p), VALID, "{tag}: the exact spend (new balance 0) verifies 01");
    }
}
