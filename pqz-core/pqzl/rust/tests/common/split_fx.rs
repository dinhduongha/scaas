// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The split transfer fixture (R_TXS / R_TXS0, three-key spec K3-4), shared by tests/split.rs and tests/wipe.rs: keys,
//! T, the leg from `enc_leg_seed`'s seed, the sender's own ciphertext, the statement and the witness.
#![allow(dead_code)]
use pqzl::{enc_leg_seed, enc_seed, keygen, Enc, Key, N, PROOF_SYSTEM_SPLIT_ID};

pub const HEADER: usize = 640;
pub const HDR_FEE: usize = 256;
pub const HDR_AUDITOR_ON: usize = 448;
pub const OP_TRANSFER: u8 = 1;

pub fn digits(x: u64) -> [u8; 16] {
    core::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}

pub fn i8s(o: &mut Vec<u8>, x: &[i8]) {
    o.extend(x.iter().map(|&v| v as u8));
}

pub fn le16s(o: &mut Vec<u8>, x: &[i16]) {
    x.iter().for_each(|v| o.extend_from_slice(&v.to_le_bytes()));
}

/// one split transfer: keys, T, the leg, the sender's own ciphertext
pub struct Tx {
    pub kf: Key,
    pub kt: Key,
    pub ka: Key,
    pub t: Enc,
    pub leg: Enc,
    pub own: Enc,
    pub v: u64,
    pub bp: u64,
}

pub const FEE: u64 = 7;

pub fn tx() -> Tx {
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
pub fn stmt(x: &Tx, aud: bool, id: &[u8; 32], u: &[u8], vf: &[u8], uf: &[u8]) -> Vec<u8> {
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

pub fn honest_stmt(x: &Tx, aud: bool) -> Vec<u8> {
    stmt(x, aud, &PROOF_SYSTEM_SPLIT_ID, &x.leg.u[..], &x.own.vs[0], &x.own.u[..])
}

/// s_f || e_f || r || e1 || r_f || e1_f || e2_t || e2_f || [e2_a] || d || d' (pqz.h PQZ_TXS_WIT_BYTES)
pub fn wit(x: &Tx, aud: bool, own: &Enc) -> Vec<u8> {
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

