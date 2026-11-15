// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! R_TXS / R_TXS0 (three-key spec K3-4, CTR-PQZ-04's split randomness; UNAUDITED): op 1 under PQZL_SPLIT_ID, built as
//! a wallet builds it (the leg from `enc_leg_seed`'s seed to pk_t [, pk_a], the sender's own u_f, v_f from seed_enc),
//! proved and verified by the generic and the specialised verifier (and, with feature `c-oracle`, by the C core:
//! same proof bytes, same verdicts). The cheating statements of §14 item 8 (u_f not from (r_f, e1_f), v_f under the
//! leg's r, u and u_f swapped, another proofSystemId in the statement) are refused, each next to its honest control,
//! with the exact outcome (review 3w-delta U1h-2); a cheating prover (test hook) reaches the verifiers with each.
use pqzl::{enc_seed, Ctx, Error, N, POLYVEC_BYTES as PV, PROOF_SYSTEM_ID, PROOF_SYSTEM_SPLIT_ID, V_BYTES as VB};

#[path = "common/split_fx.rs"]
mod split_fx;
use split_fx::*;

/// every verifier's verdict with its errors kept (`try_verify`, `try_verify_fast`; with `c-oracle` C's two, whose
/// boolean must equal it), required equal: Ok(verdict), or Err(Error::Memory), never folded into a rejection
fn verdict(ctx: &mut Ctx, st: &[u8], pf: &[u8]) -> Result<bool, Error> {
    let g = ctx.try_verify(OP_TRANSFER, st, pf);
    #[cfg(feature = "sv")]
    assert_eq!(ctx.try_verify_fast(OP_TRANSFER, st, pf), g, "verify_fast != verify");
    #[cfg(feature = "c-oracle")]
    {
        assert_eq!(Ok(pqzl::c_oracle::c_verify(OP_TRANSFER, st, pf)), g, "C pqz_verify != verify");
        #[cfg(feature = "sv")]
        assert_eq!(Ok(pqzl::c_oracle::c_verify_fast(OP_TRANSFER, st, pf)), g, "C pqz_verify_fast != verify");
    }
    g
}

/// what happened to a statement: the prover refused it (its error), or proved it and every verifier said this
#[derive(Debug, PartialEq)]
enum Out {
    Refused(Error),
    Verdict(Result<bool, Error>),
}
const ACCEPTED: Out = Out::Verdict(Ok(true));
const REJECTED: Out = Out::Verdict(Ok(false));
/// the prover's own relation check (`__check_coeff0` / the h_i asserts: an evaluation equation is false at the witness)
const PROVER_CHECK: Out = Out::Refused(Error::Internal);

/// prove (Rust; with `c-oracle` C must give the same bytes or the same error), then every verifier
fn prove_verdict(ctx: &mut Ctx, st: &[u8], w: &[u8]) -> Out {
    let rnd = [9u8; 32];
    let p = ctx.prove(OP_TRANSFER, st, w, &rnd);
    #[cfg(feature = "c-oracle")]
    assert!(p == pqzl::c_oracle::c_prove(OP_TRANSFER, st, w, &rnd), "C prove != Rust prove");
    match p {
        Ok(pf) => Out::Verdict(verdict(ctx, st, &pf)),
        Err(e) => Out::Refused(e),
    }
}

/// the honest split transfer, with and without the auditor: proved, accepted by every verifier; the proof size
#[test]
fn split_honest_accepted() {
    let x = tx();
    let mut ctx = Ctx::new();
    for aud in [true, false] {
        let (st, w) = (honest_stmt(&x, aud), wit(&x, aud, &x.own));
        assert_eq!(st.len(), HEADER + (if aud { 6 } else { 5 }) * PV + if aud { 4 } else { 3 } * VB);
        let pf = ctx.prove(OP_TRANSFER, &st, &w, &[9; 32]).expect("honest R_TXS prove");
        assert!(pf.len() <= pqzl::MAX_PROOF);
        assert_eq!(verdict(&mut ctx, &st, &pf), Ok(true), "honest R_TXS{}", if aud { "" } else { "0" });
        eprintln!("R_TXS{} ({}): statement {} B, proof {} B", if aud { "" } else { "0" }, pqzl::SET, st.len(), pf.len());
    }
}

/// the statements of one change each: u_f not from (r_f, e1_f) (another sender randomness's u_f: R_TXS's u_f rows
/// alone false), v_f under the leg's r (R_TX's v_f, CTR-PQZ-04's shared randomness; u_f honest: the v_f rows alone
/// false), u and u_f swapped (both groups' u rows false)
fn cheats(x: &Tx, aud: bool) -> [(&'static str, Vec<u8>); 3] {
    let other = enc_seed(&[&x.kf.pk], &[digits(x.bp)], &[8; 32]).unwrap();
    let vf_leg = pqzl::encrypt(&[&x.kf.pk], &[digits(x.bp)], &x.leg.r, &x.leg.e1, &[x.own.e2[0]]).unwrap();
    [
        ("u_f not from (r_f, e1_f)", stmt(x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.leg.u[..], &x.own.vs[0], &other.u[..])),
        ("v_f under the leg's r", stmt(x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.leg.u[..], &vf_leg.vs[0], &x.own.u[..])),
        ("u and u_f swapped", stmt(x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.own.u[..], &x.own.vs[0], &x.leg.u[..])),
    ]
}

/// each cheating statement next to its honest control (one change at a time), with the exact outcome: the honest
/// prover proves a false R_q row (it checks only the evaluation equations) and every verifier rejects the proof; it
/// refuses a false evaluation equation (v_f) itself. The honest proof never verifies against a changed statement.
#[test]
fn split_cheating_refused() {
    let x = tx();
    let mut ctx = Ctx::new();
    for aud in [true, false] {
        let w = wit(&x, aud, &x.own);
        let honest = honest_stmt(&x, aud);
        assert_eq!(prove_verdict(&mut ctx, &honest, &w), ACCEPTED, "control");
        let pf = ctx.prove(OP_TRANSFER, &honest, &w, &[9; 32]).unwrap();
        let [(n1, uf), (n2, vf), (n3, swap)] = cheats(&x, aud);
        assert_eq!(prove_verdict(&mut ctx, &uf, &w), REJECTED, "{n1}");
        assert_eq!(verdict(&mut ctx, &uf, &pf), Ok(false), "{n1}, the honest proof");
        assert_eq!(prove_verdict(&mut ctx, &vf, &w), PROVER_CHECK, "{n2}");
        assert_eq!(verdict(&mut ctx, &vf, &pf), Ok(false), "{n2}, the honest proof");
        // ... and its witness with the leg's (r, e1, e2) as (r_f, e1_f, e2_f): v_f is then not the one encrypted
        let w2 = wit(&x, aud, &x.leg);
        assert_eq!(prove_verdict(&mut ctx, &vf, &w2), PROVER_CHECK, "{n2}, r_f = r");
        assert_eq!(prove_verdict(&mut ctx, &swap, &w), REJECTED, "{n3}");
        assert_eq!(verdict(&mut ctx, &swap, &pf), Ok(false), "{n3}, the honest proof");
        // the proof under PQZL_SPLIT_ID does not verify with another id in the statement (the transcript hashes it)
        let st = stmt(&x, aud, &PROOF_SYSTEM_ID, &x.leg.u[..], &x.own.vs[0], &x.own.u[..]);
        assert_eq!(verdict(&mut ctx, &st, &pf), Ok(false), "another proofSystemId");
    }
}

/// review 3w-delta U1h-2 (U1-01; feature `test-hooks`): a cheating prover that skips its own relation checks (cheat
/// mode 5) reaches the verifiers with each statement of one false equation, u_f's rows or v_f's; every verifier
/// rejects it. Positive control first: mode 5 on the honest statement gives the honest proof, accepted. Removing
/// either equation from a verifier turns this red (research/code-review-2026-11-15/fix-round.md, mutants).
#[cfg(feature = "test-hooks")]
#[test]
fn split_cheating_prover_rejected() {
    let x = tx();
    let mut ctx = Ctx::new();
    let cheat = |ctx: &mut Ctx, st: &[u8], w: &[u8]| {
        pqzl::set_cheat(5);
        let p = ctx.prove(OP_TRANSFER, st, w, &[9; 32]);
        pqzl::set_cheat(0);
        p
    };
    for aud in [true, false] {
        let w = wit(&x, aud, &x.own);
        let honest = honest_stmt(&x, aud);
        let pf = cheat(&mut ctx, &honest, &w).expect("mode 5, honest statement");
        assert_eq!(Ok(&pf), ctx.prove(OP_TRANSFER, &honest, &w, &[9; 32]).as_ref(), "mode 5 changes an honest proof");
        assert_eq!(verdict(&mut ctx, &honest, &pf), Ok(true), "control");
        let [(n1, uf), (n2, vf), _] = cheats(&x, aud);
        for (n, st) in [(n1, uf), (n2, vf)] {
            let pf = cheat(&mut ctx, &st, &w).unwrap_or_else(|e| panic!("{n}: the cheating prover refused ({e:?})"));
            assert_eq!(verdict(&mut ctx, &st, &pf), Ok(false), "{n}: a cheating proof accepted");
        }
    }
}

/// the length picks the relation: an R_TXS witness on R_TX's statement (u_f dropped) and R_TX's witness on R_TXS's
/// statement are refused by the prover (Input), and R_TXS's statement one byte short is no relation
#[test]
fn split_forms_apart() {
    let x = tx();
    let mut ctx = Ctx::new();
    let (st, w) = (honest_stmt(&x, true), wit(&x, true, &x.own));
    let tx_st = &st[..st.len() - PV];
    assert_eq!(ctx.prove(OP_TRANSFER, tx_st, &w, &[9; 32]), Err(Error::Input), "R_TXS witness on R_TX");
    let tx_w: Vec<u8> = [&w[..6 * N], &w[9 * N..]].concat();
    assert_eq!(ctx.prove(OP_TRANSFER, &st, &tx_w, &[9; 32]), Err(Error::Input), "R_TX witness on R_TXS");
    assert_eq!(ctx.prove(OP_TRANSFER, &st[..st.len() - 1], &w, &[9; 32]), Err(Error::Input), "one byte short");
}
