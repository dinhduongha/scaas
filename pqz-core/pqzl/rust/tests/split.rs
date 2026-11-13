// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! R_TXS / R_TXS0 (three-key spec K3-4, CTR-PQZ-04's split randomness; UNAUDITED): op 1 under PQZL_SPLIT_ID, built as
//! a wallet builds it (the leg from `enc_leg_seed`'s seed to pk_t [, pk_a], the sender's own u_f, v_f from seed_enc),
//! proved and verified by the generic and the specialised verifier (and, with feature `c-oracle`, by the C core:
//! same proof bytes, same verdicts). The cheating statements of §14 item 8 (u_f not from (r_f, e1_f), v_f under the
//! leg's r, u and u_f swapped, another proofSystemId in the statement) are refused, each next to its honest control.
use pqzl::{enc_leg_seed, enc_seed, keygen, Ctx, Enc, Error, Key, N, POLYVEC_BYTES as PV, PROOF_SYSTEM_ID, PROOF_SYSTEM_SPLIT_ID, V_BYTES as VB};

const HEADER: usize = 640;
const HDR_FEE: usize = 256;
const HDR_AUDITOR_ON: usize = 448;
const OP_TRANSFER: u8 = 1;

fn digits(x: u64) -> [u8; 16] {
    core::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}

fn i8s(o: &mut Vec<u8>, x: &[i8]) {
    o.extend(x.iter().map(|&v| v as u8));
}

fn le16s(o: &mut Vec<u8>, x: &[i16]) {
    x.iter().for_each(|v| o.extend_from_slice(&v.to_le_bytes()));
}

/// one split transfer: keys, T, the leg, the sender's own ciphertext
struct Tx {
    kf: Key,
    kt: Key,
    ka: Key,
    t: Enc,
    leg: Enc,
    own: Enc,
    v: u64,
    bp: u64,
}

const FEE: u64 = 7;

fn tx() -> Tx {
    let (kf, kt, ka) = (keygen(&[1; 32]).unwrap(), keygen(&[2; 32]).unwrap(), keygen(&[3; 32]).unwrap());
    let (b, v) = (1_000_000u64, 123_456u64);
    let bp = b - v - FEE;
    let t = enc_seed(&[&kf.pk], &[digits(b)], &[4; 32]).unwrap();
    let seed_enc = [5u8; 32];
    let seed_leg = enc_leg_seed(&seed_enc, &[6; 32], &[7; 32]); // pkt_hash: the caller's keccak (opaque here)
    let leg = enc_seed(&[&kt.pk, &ka.pk], &[digits(v), digits(v)], &seed_leg).unwrap();
    let own = enc_seed(&[&kf.pk], &[digits(bp)], &seed_enc).unwrap();
    Tx { kf, kt, ka, t, leg, own, v, bp }
}

/// the statement (header under `id`, auditorOn `aud`) with the given out ciphertexts
fn stmt(x: &Tx, aud: bool, id: &[u8; 32], u: &[u8], vf: &[u8], uf: &[u8]) -> Vec<u8> {
    let mut st = vec![0u8; HEADER];
    st[32..64].copy_from_slice(id);
    st[HDR_FEE + 31] = FEE as u8;
    st[HDR_AUDITOR_ON + 31] = aud as u8;
    st.extend_from_slice(&x.kf.pk[..]);
    st.extend_from_slice(&x.kt.pk[..]);
    if aud {
        st.extend_from_slice(&x.ka.pk[..]);
    }
    st.extend_from_slice(&x.t.u[..]);
    st.extend_from_slice(&x.t.vs[0]);
    st.extend_from_slice(u);
    st.extend_from_slice(&x.leg.vs[0]);
    st.extend_from_slice(vf);
    if aud {
        st.extend_from_slice(&x.leg.vs[1]);
    }
    st.extend_from_slice(uf);
    st
}

fn honest_stmt(x: &Tx, aud: bool) -> Vec<u8> {
    stmt(x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.leg.u[..], &x.own.vs[0], &x.own.u[..])
}

/// s_f || e_f || r || e1 || r_f || e1_f || e2_t || e2_f || [e2_a] || d || d' (pqz.h PQZ_TXS_WIT_BYTES)
fn wit(x: &Tx, aud: bool, own: &Enc) -> Vec<u8> {
    let mut w = Vec::new();
    i8s(&mut w, &x.kf.s[..]);
    le16s(&mut w, &x.kf.e[..]);
    i8s(&mut w, &x.leg.r[..]);
    le16s(&mut w, &x.leg.e1[..]);
    i8s(&mut w, &own.r[..]);
    le16s(&mut w, &own.e1[..]);
    le16s(&mut w, &x.leg.e2[0]);
    le16s(&mut w, &own.e2[0]);
    if aud {
        le16s(&mut w, &x.leg.e2[1]);
    }
    w.extend_from_slice(&digits(x.v));
    w.extend_from_slice(&digits(x.bp));
    assert_eq!(w.len(), 9 * N + if aud { 128 } else { 96 });
    w
}

/// every verifier's verdict (generic, specialised, and with `c-oracle` C's two), required equal
fn verdict(ctx: &mut Ctx, st: &[u8], pf: &[u8]) -> bool {
    let g = ctx.verify(OP_TRANSFER, st, pf);
    #[cfg(feature = "sv")]
    assert_eq!(ctx.verify_fast(OP_TRANSFER, st, pf), g, "verify_fast != verify");
    #[cfg(feature = "c-oracle")]
    {
        assert_eq!(pqzl::c_oracle::c_verify(OP_TRANSFER, st, pf), g, "C pqz_verify != verify");
        #[cfg(feature = "sv")]
        assert_eq!(pqzl::c_oracle::c_verify_fast(OP_TRANSFER, st, pf), g, "C pqz_verify_fast != verify");
    }
    g
}

/// prove (Rust; with `c-oracle` C must give the same bytes or the same error), then the verdict
fn prove_verdict(ctx: &mut Ctx, st: &[u8], w: &[u8]) -> Result<bool, Error> {
    let rnd = [9u8; 32];
    let p = ctx.prove(OP_TRANSFER, st, w, &rnd);
    #[cfg(feature = "c-oracle")]
    assert!(p == pqzl::c_oracle::c_prove(OP_TRANSFER, st, w, &rnd), "C prove != Rust prove");
    p.map(|pf| verdict(ctx, st, &pf))
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
        assert!(verdict(&mut ctx, &st, &pf), "honest R_TXS{}", if aud { "" } else { "0" });
        eprintln!("R_TXS{} ({}): statement {} B, proof {} B", if aud { "" } else { "0" }, pqzl::SET, st.len(), pf.len());
    }
}

/// each cheating statement next to its honest control (one change at a time); a proof is either refused by the prover
/// or rejected by every verifier
#[test]
fn split_cheating_refused() {
    let x = tx();
    let mut ctx = Ctx::new();
    for aud in [true, false] {
        let w = wit(&x, aud, &x.own);
        let honest = honest_stmt(&x, aud);
        assert_eq!(prove_verdict(&mut ctx, &honest, &w), Ok(true), "control");
        let pf = ctx.prove(OP_TRANSFER, &honest, &w, &[9; 32]).unwrap();
        // u_f not from (r_f, e1_f): another sender randomness's u_f, the witness's r_f, e1_f
        let other = enc_seed(&[&x.kf.pk], &[digits(x.bp)], &[8; 32]).unwrap();
        let st = stmt(&x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.leg.u[..], &x.own.vs[0], &other.u[..]);
        assert_ne!(prove_verdict(&mut ctx, &st, &w), Ok(true), "u_f not from (r_f, e1_f)");
        assert!(!verdict(&mut ctx, &st, &pf), "u_f not from (r_f, e1_f), the honest proof");
        // v_f under the leg's r (R_TX's v_f, CTR-PQZ-04's shared randomness), u_f honest
        let vf_leg = pqzl::encrypt(&[&x.kf.pk], &[digits(x.bp)], &x.leg.r, &x.leg.e1, &[x.own.e2[0]]).unwrap();
        let st = stmt(&x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.leg.u[..], &vf_leg.vs[0], &x.own.u[..]);
        assert_ne!(prove_verdict(&mut ctx, &st, &w), Ok(true), "v_f under the leg's r");
        // ... and its witness with the leg's r as r_f: u_f is then not A^T r_f + e1_f
        let w2 = wit(&x, aud, &x.leg);
        assert_ne!(prove_verdict(&mut ctx, &st, &w2), Ok(true), "v_f under the leg's r, r_f = r");
        // u and u_f swapped
        let st = stmt(&x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.own.u[..], &x.own.vs[0], &x.leg.u[..]);
        assert_ne!(prove_verdict(&mut ctx, &st, &w), Ok(true), "u and u_f swapped");
        assert!(!verdict(&mut ctx, &st, &pf), "u and u_f swapped, the honest proof");
        // the proof under PQZL_SPLIT_ID does not verify with another id in the statement (the transcript hashes it)
        let st = stmt(&x, aud, &PROOF_SYSTEM_ID, &x.leg.u[..], &x.own.vs[0], &x.own.u[..]);
        assert!(!verdict(&mut ctx, &st, &pf), "another proofSystemId");
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
