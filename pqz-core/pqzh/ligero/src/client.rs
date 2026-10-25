//! Test and bench inputs (feature `bench`): the same keys, ciphertexts, statements and witnesses as pqz-core's
//! test/pqz_bench.c setup() (same xorshift stream, same samplers, all six forms), so the bytes can be compared
//! with pqz-core's (xcheck/ligero.sh); op 7 `R_TXM` statements and witnesses per shape (`setup_multi`; pqz-core has
//! no op 7 yet, so xcheck/kat_multi.py checks them against pqz_kat.py); the mutations of the benches and tests.
//! Layout constants and the coefficient codec are pqz-stmt's.

use pqz_stmt::{
    DISC_WORDS, DW_AMOUNT, DW_KIND, Form, H_AMOUNT, H_AUDITOR_ON, H_FEE, H_LEGS, H_RECIPIENTS_HASH, H_SALT,
    HEADER_BYTES, Multi, PQZH_ID, groups, legs_per_group, u64_word,
};

use crate::cs::Rel;
use crate::ring::*;

/// the l2 bounds of the samplers (KeyGen / Enc's resampling): CBD(1) vectors, CBD(20) vectors, e2 (v3 36 / 164 / 64)
const BS: i64 = crate::set::BETA_S as i64;
const BE: i64 = crate::set::BETA_E as i64;
const B2: i64 = crate::set::BETA_2 as i64;

/// byte offsets of the statement words the tests and mutations touch (pq-zero-knowledge.md §7.7, §7.9)
pub const PREFIX: usize = 64;
pub const HDR_FEE: usize = 32 * H_FEE;
pub const HDR_AMOUNT: usize = 32 * H_AMOUNT;
pub const HDR_AUDITOR_ON: usize = 32 * H_AUDITOR_ON;
/// op 7: the `M` word (op 1's `recipient`) and `recipientsHash` (op 1's `toUA`)
pub const HDR_LEGS: usize = 32 * H_LEGS;
pub const HDR_RECIPIENTS_HASH: usize = 32 * H_RECIPIENTS_HASH;
pub const DISC_AMOUNT: usize = 32 * DW_AMOUNT;
pub const DISC_KIND: usize = 32 * DW_KIND;
pub const DISC_PK: usize = 32 * DISC_WORDS;

pub struct Rng(pub u64);

impl Rng {
    pub fn new() -> Self {
        Rng(0x243F6A8885A308D3)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(2685821657736338717)
    }
    fn cbd(&mut self, eta: u32) -> i64 {
        let r = self.next();
        let (mut a, mut b) = (0i64, 0i64);
        for i in 0..eta {
            a += ((r >> i) & 1) as i64;
            b += ((r >> (32 + i)) & 1) as i64;
        }
        a - b
    }
    /// short vector of n coefficients with l2 bound (resampled as KeyGen / Enc do)
    pub fn short(&mut self, n: usize, eta: u32, bound: i64) -> Vec<i64> {
        loop {
            let x: Vec<i64> = (0..n).map(|_| self.cbd(eta)).collect();
            if x.iter().map(|v| v * v).sum::<i64>() <= bound * bound {
                return x;
            }
        }
    }
}

impl Default for Rng {
    fn default() -> Self {
        Self::new()
    }
}

/// the first n coefficients of each polynomial, canonical, as pqz-stmt writes them (be8 < q)
fn wr(out: &mut Vec<u8>, v: &[Poly], n: usize) {
    for p in v {
        let c: Vec<u64> = p[..n].iter().map(|&x| x.rem_euclid(Q as i64) as u64).collect();
        pqz_stmt::write_coeffs(&c, out).unwrap();
    }
}

fn wr_vec(out: &mut Vec<u8>, v: &[Poly]) {
    wr(out, v, D);
}

fn wr_v(out: &mut Vec<u8>, p: &Poly) {
    wr(out, std::slice::from_ref(p), 16);
}

pub struct Key {
    pub s: Vec<i64>,
    pub e: Vec<i64>,
    pub pk: Vec<Poly>,
}

pub fn keygen(rng: &mut Rng) -> Key {
    let s = rng.short(N, 1, BS);
    let e = rng.short(N, 20, BE);
    let pk = keypair(&polys(&s), &polys(&e));
    Key { s, e, pk }
}

pub struct Setup {
    pub reg_stmt: Vec<u8>,
    pub reg_wit: Vec<u8>,
    pub tx_stmt: Vec<u8>,
    pub tx_wit: Vec<u8>,
    pub tx0_stmt: Vec<u8>,
    pub tx0_wit: Vec<u8>,
    pub burn_stmt: Vec<u8>,
    pub burn_wit: Vec<u8>,
    pub ds_stmt: Vec<u8>,
    pub ds_wit: Vec<u8>,
    pub dr_stmt: Vec<u8>,
    pub dr_wit: Vec<u8>,
}

impl Setup {
    /// (statement, witness) of a relation (REFRESH / AUDITOR: BURN's / DISCLOSE-RECEIVER's, opTag not patched)
    pub fn rel(&self, f: Form) -> (&Vec<u8>, &Vec<u8>) {
        match f {
            Form::Register => (&self.reg_stmt, &self.reg_wit),
            Form::Transfer => (&self.tx_stmt, &self.tx_wit),
            Form::Burn | Form::Refresh => (&self.burn_stmt, &self.burn_wit),
            Form::DiscloseSender => (&self.ds_stmt, &self.ds_wit),
            Form::DiscloseReceiver | Form::DiscloseAuditor => (&self.dr_stmt, &self.dr_wit),
            Form::Transfer0 => (&self.tx0_stmt, &self.tx0_wit),
        }
    }
}

/// relation names as the benches print them (op 7: R_TXM<M> auditor on, R_TXM<M>_0 off)
pub fn rel_name(r: impl Into<Rel>) -> String {
    match r.into() {
        Rel::Form(f) => match f {
            Form::Register => "R_REG",
            Form::Transfer => "R_TX",
            Form::Transfer0 => "R_TX0",
            Form::Burn | Form::Refresh => "R_BURN",
            Form::DiscloseSender => "R_DS",
            Form::DiscloseReceiver | Form::DiscloseAuditor => "R_DR",
        }
        .into(),
        Rel::Multi { m, aud } => format!("R_TXM{m}{}", if aud { "" } else { "_0" }),
    }
}

fn le16(out: &mut Vec<u8>, v: &[i64]) {
    for &x in v {
        out.extend_from_slice(&(x as i16).to_le_bytes());
    }
}

/// Overrides for negative tests (an honest prover refuses these witnesses).
#[derive(Default, Clone)]
pub struct Tweak {
    /// secret of key F (R_REG, R_TX, R_BURN), pk_f recomputed
    pub s_f: Option<Vec<i64>>,
    /// secret of key T (R_DR; the transfer and the disclosures use the recomputed pk_t)
    pub s_t: Option<Vec<i64>>,
    /// encryption randomness r and e1 of the transfer (R_TX, R_DS) and of the burn (R_BURN); ciphertexts re-encrypted
    pub r: Option<Vec<i64>>,
    pub e1: Option<Vec<i64>>,
    /// R_TX amount digits (v_t, v_a)
    pub d: Option<[u8; 16]>,
    /// R_TX e2_t (also R_DS's e2)
    pub e2_t: Option<Vec<i64>>,
    /// R_TX / R_TX0 e2_f (the sender's new-balance leg)
    pub e2_f: Option<Vec<i64>>,
    /// error of key F (R_REG, R_TX, R_TX0, R_BURN), pk_f recomputed
    pub e_f: Option<Vec<i64>>,
    /// R_BURN new-balance digits d' (v_f)
    pub burn_dp: Option<[u8; 16]>,
    /// R_BURN e2_f
    pub burn_e2: Option<Vec<i64>>,
    /// proofSystemId written at statement bytes 32..63 (default PQZH's, D3; any other is rejected by `cs::parse`)
    pub psid: Option<[u8; 32]>,
}

/// pqz_bench.c setup(): R_REG for key F, R_TX = balance 1,000,000 in T, transfer 123,456 with fee 7; R_TX in the
/// §7.7 layout (640-byte header, fee word at 256, the other header words filled as pqz_bench.c does); R_DS / R_DR
/// disclose the transfer's receiver leg (u, v_t) of 123,456 to pk_t; R_BURN burns 123,456 with fee 7 from the same T.
pub fn setup() -> Setup {
    setup_with(&Tweak::default())
}

/// Statements as the precompile takes them (plan D15 / R6): bytes 0..63 = the op's opTag and the id (pqz_bench.c
/// writes filler before the id); the header words D15 pins as pqz_bench.c sets them (R_TX auditorOn 1, recipient 0,
/// salt word 16 zero bytes || salt; R_BURN toUA, auditorOn, salt 0).
/// xcheck/dump_setup.c applies the same patch to pqz_bench.c's statements; pqz_kat.py parses and rebuilds them.
pub fn setup_with(tw: &Tweak) -> Setup {
    let mut rng = Rng::new();
    let mut kf = keygen(&mut rng);
    if let Some(s) = &tw.s_f {
        kf.s = s.clone();
        kf.pk = keypair(&polys(&kf.s), &polys(&kf.e));
    }
    if let Some(e) = &tw.e_f {
        kf.e = e.clone();
        kf.pk = keypair(&polys(&kf.s), &polys(&kf.e));
    }
    let mut kt = keygen(&mut rng);
    if let Some(s) = &tw.s_t {
        kt.s = s.clone();
        kt.pk = keypair(&polys(&kt.s), &polys(&kt.e));
    }
    let ka = keygen(&mut rng);
    let _kx = keygen(&mut rng);

    let psid = tw.psid.unwrap_or(PQZH_ID);
    let mut reg_stmt = Form::Register.op_tag().to_vec();
    reg_stmt.extend_from_slice(&psid);
    reg_stmt.extend((0..32u8).collect::<Vec<_>>());
    wr_vec(&mut reg_stmt, &kf.pk);
    let mut reg_wit: Vec<u8> = kf.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut reg_wit, &kf.e);
    assert_eq!((reg_stmt.len(), reg_wit.len()), (Form::Register.stmt_len(), Form::Register.wit_len()));

    let (bal, v, fee) = (1_000_000u64, 123_456u64, 7u64);
    let bp = bal - v - fee;
    let r0 = rng.short(N, 1, BS);
    let e10 = rng.short(N, 20, BE);
    let e20 = rng.short(16, 20, B2);
    let (ut, vt) = encrypt(&[&kf.pk], &[digits(bal)], &polys(&r0), &polys(&e10), &[e20]);
    let r = rng.short(N, 1, BS);
    let e1 = rng.short(N, 20, BE);
    let r = tw.r.clone().unwrap_or(r);
    let e1 = tw.e1.clone().unwrap_or(e1);
    let mut e2: Vec<Vec<i64>> = (0..3).map(|_| rng.short(16, 20, B2)).collect();
    let mut m = [digits(v), digits(bp), digits(v)];
    if let Some(e) = &tw.e2_t {
        e2[0] = e.clone();
    }
    if let Some(e) = &tw.e2_f {
        e2[1] = e.clone();
    }
    if let Some(d) = tw.d {
        m[0] = d;
        m[2] = d;
    }
    let (u, vs) = encrypt(&[&kt.pk, &kf.pk, &ka.pk], &m, &polys(&r), &polys(&e1), &e2);

    let mut tx: Vec<u8> = (0..HEADER_BYTES).map(|i| if i < PREFIX { 0x5A } else { (i * 3) as u8 }).collect();
    tx[..32].copy_from_slice(&Form::Transfer.op_tag());
    tx[32..64].copy_from_slice(&psid);
    tx[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
    tx[HDR_AUDITOR_ON + 31] = 1;
    tx[HDR_FEE..HDR_FEE + 64].fill(0);
    tx[HDR_FEE + 24..HDR_FEE + 32].copy_from_slice(&fee.to_be_bytes());
    // the canonical header the decoder (pqz-stmt, plan D15) accepts, as pqz_bench.c writes it: recipient (word at
    // 320) 0 on a transfer, salt word (576) = 16 zero bytes || salt
    tx[320..352].fill(0);
    tx[576..592].fill(0);
    for x in [&kf.pk, &kt.pk, &ka.pk, &ut] {
        wr_vec(&mut tx, x);
    }
    wr_v(&mut tx, &vt[0]);
    wr_vec(&mut tx, &u);
    for vk in &vs {
        wr_v(&mut tx, vk);
    }

    let mut w: Vec<u8> = kf.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut w, &kf.e);
    w.extend(r.iter().map(|&x| x as i8 as u8));
    le16(&mut w, &e1);
    for e in &e2 {
        le16(&mut w, e);
    }
    w.extend_from_slice(&m[0]);
    w.extend_from_slice(&m[1]);
    assert_eq!((tx.len(), w.len()), (Form::Transfer.stmt_len(), Form::Transfer.wit_len()));

    // R_TX0 (auditor off, pqz_bench.c): the transfer without pk_a and v_a (same r, e1, e2_t, e2_f, so u, v_t, v_f
    // are R_TX's), R_TX's header with auditorOn 0; witness R_TX's without e2_a
    let mut tx0 = tx[..HEADER_BYTES].to_vec();
    tx0[HDR_AUDITOR_ON + 31] = 0;
    for x in [&kf.pk, &kt.pk, &ut] {
        wr_vec(&mut tx0, x);
    }
    wr_v(&mut tx0, &vt[0]);
    wr_vec(&mut tx0, &u);
    wr_v(&mut tx0, &vs[0]);
    wr_v(&mut tx0, &vs[1]);
    let mut w0 = w[..6 * N + 64].to_vec();
    w0.extend_from_slice(&w[6 * N + 96..]);
    assert_eq!((tx0.len(), w0.len()), (Form::Transfer0.stmt_len(), Form::Transfer0.wit_len()));

    // R_DS / R_DR: header words chainId .. entryRef = (i * 7), amount v, kind 0 / 1; pk_t, u, v_t
    let disc = |k: u8| {
        let mut st = [Form::DiscloseSender, Form::DiscloseReceiver][k as usize].op_tag().to_vec();
        st.extend_from_slice(&psid);
        st.extend((PREFIX..DISC_AMOUNT).map(|i| (i * 7) as u8));
        st.extend([0u8; 64]);
        st[DISC_AMOUNT + 24..DISC_AMOUNT + 32].copy_from_slice(&v.to_be_bytes());
        st[DISC_KIND + 31] = k;
        wr_vec(&mut st, &kt.pk);
        wr_vec(&mut st, &u);
        wr_v(&mut st, &vs[0]);
        st
    };
    let (ds_stmt, dr_stmt) = (disc(0), disc(1));
    let mut ds_wit: Vec<u8> = r.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut ds_wit, &e1);
    le16(&mut ds_wit, &e2[0]);
    let mut dr_wit: Vec<u8> = kt.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut dr_wit, &kt.e);
    let disc_len = Form::DiscloseSender.stmt_len();
    assert_eq!(
        (ds_stmt.len(), dr_stmt.len(), ds_wit.len(), dr_wit.len()),
        (disc_len, disc_len, Form::DiscloseSender.wit_len(), Form::DiscloseReceiver.wit_len())
    );

    // R_BURN: fresh (r, e1, e2_f) for the new balance
    let rb = rng.short(N, 1, BS);
    let e1b = rng.short(N, 20, BE);
    let rb = tw.r.clone().unwrap_or(rb);
    let e1b = tw.e1.clone().unwrap_or(e1b);
    let mut e2b = rng.short(16, 20, B2);
    if let Some(e) = &tw.burn_e2 {
        e2b = e.clone();
    }
    let mb = tw.burn_dp.unwrap_or(digits(bp));
    let (ub, vb) = encrypt(&[&kf.pk], &[mb], &polys(&rb), &polys(&e1b), &[e2b.clone()]);
    let mut burn: Vec<u8> = (0..HEADER_BYTES).map(|i| if i < PREFIX { 0xB2 } else { (i * 5) as u8 }).collect();
    burn[..32].copy_from_slice(&Form::Burn.op_tag());
    burn[32..64].copy_from_slice(&psid);
    burn[HDR_FEE..HDR_FEE + 64].fill(0);
    burn[HDR_FEE + 24..HDR_FEE + 32].copy_from_slice(&fee.to_be_bytes());
    burn[HDR_AMOUNT + 24..HDR_AMOUNT + 32].copy_from_slice(&v.to_be_bytes());
    // canonical (D15, as pqz_bench.c): toUA (192), auditorOn and the whole salt word (576) 0 on a burn
    burn[192..224].fill(0);
    burn[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
    burn[576..608].fill(0);
    wr_vec(&mut burn, &kf.pk);
    wr_vec(&mut burn, &ut);
    wr_v(&mut burn, &vt[0]);
    wr_vec(&mut burn, &ub);
    wr_v(&mut burn, &vb[0]);
    let mut bw = w[..3 * N].to_vec();
    bw.extend(rb.iter().map(|&x| x as i8 as u8));
    le16(&mut bw, &e1b);
    le16(&mut bw, &e2b);
    bw.extend_from_slice(&mb);
    assert_eq!((burn.len(), bw.len()), (Form::Burn.stmt_len(), Form::Burn.wit_len()));

    Setup { reg_stmt, reg_wit, tx_stmt: tx, tx_wit: w, tx0_stmt: tx0, tx0_wit: w0, burn_stmt: burn, burn_wit: bw, ds_stmt, ds_wit, dr_stmt, dr_wit }
}

// ---- op 7 R_TXM ----

/// Overrides of `setup_multi` for negative tests (an honest prover refuses these witnesses). Vectors are indexed in
/// witness order: e2 x < M is leg x, x = M is v_f, x = M + 1 + j the auditor copy of leg j.
#[derive(Default, Clone)]
pub struct MultiTweak {
    /// leg amounts (default: 123,456 on leg M / 2, 0 on every other leg: decoys)
    pub amounts: Option<Vec<u64>>,
    /// the fee word (default 7)
    pub fee: Option<u64>,
    /// leg j's digits (v_j, v_{a,j} and the witness)
    pub d: Option<(usize, [u8; 16])>,
    /// the new-balance digits d' (v_f and the witness); default digits(balance - sum - fee), wrapping
    pub dp: Option<[u8; 16]>,
    /// e2 vector x
    pub e2: Option<(usize, Vec<i64>)>,
    /// r_g, e1_g of group g (ciphertexts re-encrypted)
    pub r: Option<(usize, Vec<i64>)>,
    pub e1: Option<(usize, Vec<i64>)>,
    /// sender key F's secret / error (pk_f recomputed)
    pub s_f: Option<Vec<i64>>,
    pub e_f: Option<Vec<i64>>,
    /// leg j encrypted under recipient k's key (k >= M: the auditor's); the statement keeps pk_j
    pub key: Option<(usize, usize)>,
    /// leg j encrypted with group h's (r_h, e1_h); statement and witness keep group j / s
    pub group: Option<(usize, usize)>,
    /// the auditor copy of leg j encrypts these digits; the witness keeps d_j
    pub aud_d: Option<(usize, [u8; 16])>,
    /// proofSystemId (default PQZH's)
    pub psid: Option<[u8; 32]>,
}

/// UA of recipient j (a 20-byte address as a 32-byte word): 0x1000 + j
pub fn multi_ua(j: usize) -> [u8; 32] {
    u64_word(0x1000 + j as u64)
}

/// v = (pk^T r)_{o + i} + e2 + Delta m (16 coefficients; o = 16 w, the window, R0-1)
fn enc_v(pk: &[Poly], m: &[u8; 16], r: &[i64], e2: &[i64], o: usize) -> Poly {
    let rp = polys(r);
    let y = dot_int(&pk.iter().collect::<Vec<_>>(), &rp.iter().collect::<Vec<_>>());
    std::array::from_fn(|i| if i < 16 { modq(y[o + i] + e2[i] + DELTA * m[i] as i64) } else { 0 })
}

/// An op 7 statement and witness of shape (m, aud): sender F with balance 1,000,000 in T (as `setup`), leg amounts
/// and fee per `tw`, recipients j with UA `multi_ua(j)`, keys and randomness from a deterministic xorshift stream
/// (seed by shape); header words as the contract writes them (P6-ANON §4: recipientsHash, M, auditorOn, amount 0,
/// salt word 16 zero bytes || salt). One code path for real and decoy legs (R6).
pub fn setup_multi(m: usize, aud: bool, tw: &MultiTweak) -> (Vec<u8>, Vec<u8>) {
    let mut rng = Rng(0x243F6A8885A308D3 ^ ((m as u64) << 8 | aud as u64));
    let mut kf = keygen(&mut rng);
    if let Some(s) = &tw.s_f {
        kf.s = s.clone();
    }
    if let Some(e) = &tw.e_f {
        kf.e = e.clone();
    }
    kf.pk = keypair(&polys(&kf.s), &polys(&kf.e));
    let ka = keygen(&mut rng);
    let ks: Vec<Key> = (0..m).map(|_| keygen(&mut rng)).collect();
    let (g, lpg) = (groups(m, aud), legs_per_group(aud));

    let bal = 1_000_000u64;
    let amounts = tw.amounts.clone().unwrap_or_else(|| (0..m).map(|j| if j == m / 2 { 123_456 } else { 0 }).collect());
    let fee = tw.fee.unwrap_or(7);
    let sum: u64 = amounts.iter().sum();
    let mut d: Vec<[u8; 16]> = amounts.iter().map(|&a| digits(a)).collect();
    if let Some((j, x)) = tw.d {
        d[j] = x;
    }
    let dp = tw.dp.unwrap_or(digits(bal.wrapping_sub(sum).wrapping_sub(fee)));
    let r0 = rng.short(N, 1, BS);
    let e10 = rng.short(N, 20, BE);
    let e20 = rng.short(16, 20, B2);
    let (ut, vt) = encrypt(&[&kf.pk], &[digits(bal)], &polys(&r0), &polys(&e10), &[e20]);
    let mut rs: Vec<Vec<i64>> = vec![];
    let mut e1s: Vec<Vec<i64>> = vec![];
    for _ in 0..g {
        rs.push(rng.short(N, 1, BS));
        e1s.push(rng.short(N, 20, BE));
    }
    if let Some((i, x)) = &tw.r {
        rs[*i] = x.clone();
    }
    if let Some((i, x)) = &tw.e1 {
        e1s[*i] = x.clone();
    }
    let nv = m + 1 + aud as usize * m;
    let mut e2: Vec<Vec<i64>> = (0..nv).map(|_| rng.short(16, 20, B2)).collect();
    if let Some((x, v)) = &tw.e2 {
        e2[*x] = v.clone();
    }
    let us: Vec<Vec<Poly>> = (0..g).map(|i| encrypt(&[], &[], &polys(&rs[i]), &polys(&e1s[i]), &[]).0).collect();
    let grp = |j: usize| match tw.group {
        Some((jj, h)) if jj == j => h,
        _ => j / lpg,
    };
    let vs: Vec<Poly> = (0..m)
        .map(|j| {
            let pk = match tw.key {
                Some((jj, k)) if jj == j => ks.get(k).map_or(&ka.pk, |x| &x.pk),
                _ => &ks[j].pk,
            };
            enc_v(pk, &d[j], &rs[grp(j)], &e2[j], 0)
        })
        .collect();
    let vf = enc_v(&kf.pk, &dp, &rs[0], &e2[m], 0);
    let vas: Vec<Poly> = (0..m * aud as usize)
        .map(|j| {
            let x = match tw.aud_d {
                Some((jj, x)) if jj == j => x,
                _ => d[j],
            };
            enc_v(&ka.pk, &x, &rs[j / lpg], &e2[m + 1 + j], 16 * (j % lpg)) // the copy's window (R0-1)
        })
        .collect();

    let mut header = Multi::header(&tw.psid.unwrap_or(PQZH_ID), m, aud);
    let uas: Vec<u8> = (0..m).flat_map(multi_ua).collect();
    for (i, w) in header.iter_mut().enumerate().skip(2) {
        *w = u64_word(0x5A00 + i as u64);
    }
    header[H_RECIPIENTS_HASH] = crate::merkle::keccak(&[&uas]);
    header[H_FEE] = u64_word(fee);
    header[H_AMOUNT] = [0; 32];
    header[H_LEGS] = u64_word(m as u64);
    header[H_AUDITOR_ON] = u64_word(aud as u64);
    header[H_SALT] = [0; 32];
    header[H_SALT][16..].copy_from_slice(&[0xC5; 16]);
    let enc = |v: &[Poly]| {
        let mut o = vec![];
        wr_vec(&mut o, v);
        o
    };
    let enc_vs = |v: &[Poly]| {
        let mut o = vec![];
        v.iter().for_each(|p| wr_v(&mut o, p));
        o
    };
    let (pk_f, pk_a) = (enc(&kf.pk), enc(&ka.pk));
    let pks: Vec<u8> = ks.iter().flat_map(|k| enc(&k.pk)).collect();
    let mut t = enc(&ut);
    wr_v(&mut t, &vt[0]);
    let us_b: Vec<u8> = us.iter().flat_map(|u| enc(u)).collect();
    let (vs_b, vf_b, vas_b) = (enc_vs(&vs), enc_vs(&[vf]), enc_vs(&vas));
    let st = Multi {
        header,
        m,
        pk_f: &pk_f,
        pks: &pks,
        pk_a: aud.then_some(&pk_a[..]),
        t: &t,
        us: &us_b,
        vs: &vs_b,
        v_f: &vf_b,
        v_as: aud.then_some(&vas_b[..]),
    }
    .encode()
    .expect("op 7 statement");

    let mut w: Vec<u8> = kf.s.iter().map(|&x| x as i8 as u8).collect();
    le16(&mut w, &kf.e);
    for i in 0..g {
        w.extend(rs[i].iter().map(|&x| x as i8 as u8));
        le16(&mut w, &e1s[i]);
    }
    for e in &e2 {
        le16(&mut w, e);
    }
    d.iter().for_each(|x| w.extend_from_slice(x));
    w.extend_from_slice(&dp);
    let rel = Rel::Multi { m, aud };
    assert_eq!((st.len(), w.len()), (rel.stmt_len(), rel.wit_len()));
    (st, w)
}

/// (statement, witness) of any relation: the six forms from `setup`, op 7 shapes from `setup_multi` (default tweak)
pub fn inputs(s: &Setup, r: Rel) -> (Vec<u8>, Vec<u8>) {
    match r {
        Rel::Form(f) => {
            let (st, w) = s.rel(f);
            (st.clone(), w.clone())
        }
        Rel::Multi { m, aud } => setup_multi(m, aud, &MultiTweak::default()),
    }
}

// ---- adversarial inputs (bench native and wasm) ----

/// xorshift for mutations (independent of the setup stream)
pub struct R(pub u64);
impl R {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

pub const KINDS: [&str; 12] = [
    "bitflip", "byte_set", "random_bytes", "truncate", "extend", "stmt_coeff", "stmt_oob", "stmt_prefix",
    "stmt_tail", "other_proof", "field_noncanon", "empty",
];

/// mutated (statement, proof) of kind k
pub fn mutate(k: usize, rel: impl Into<Rel>, st: &[u8], pf: &[u8], other: &[u8], r: &mut R) -> (Vec<u8>, Vec<u8>) {
    let (mut s, mut p) = (st.to_vec(), pf.to_vec());
    let rel = rel.into();
    let f = match rel {
        Rel::Form(f) => f,
        Rel::Multi { .. } => Form::Transfer,
    };
    // first coefficient byte; the public scalar the relation reads (low 8 bytes of its word; op 7: the fee)
    let (body, tail) = match f {
        Form::Register => (PREFIX + 32, PREFIX),
        Form::Transfer | Form::Transfer0 => (HEADER_BYTES, HDR_FEE + 24),
        Form::Burn | Form::Refresh => (HEADER_BYTES, HDR_AMOUNT + 24),
        _ => (DISC_PK, DISC_AMOUNT + 24),
    };
    let ncoef = (s.len() - body) / 8;
    match KINDS[k] {
        "bitflip" => {
            let b = (r.next() % (8 * p.len() as u64)) as usize;
            p[b / 8] ^= 1 << (b % 8);
        }
        "byte_set" => {
            let i = (r.next() % p.len() as u64) as usize;
            p[i] = p[i].wrapping_add(1 + (r.next() % 255) as u8);
        }
        "random_bytes" => p.iter_mut().for_each(|b| *b = r.next() as u8),
        "truncate" => p.truncate(p.len() - 1 - (r.next() % 64) as usize),
        "extend" => p.extend((0..1 + r.next() % 64).map(|_| r.next() as u8)),
        "stmt_coeff" => {
            // +1 mod q on one coefficient (stays canonical)
            let o = body + 8 * (r.next() as usize % ncoef);
            let v = u64::from_be_bytes(s[o..o + 8].try_into().unwrap());
            s[o..o + 8].copy_from_slice(&((v + 1) % Q).to_be_bytes());
        }
        "stmt_oob" => {
            let o = body + 8 * (r.next() as usize % ncoef);
            let v = u64::from_be_bytes(s[o..o + 8].try_into().unwrap());
            s[o..o + 8].copy_from_slice(&(v + Q).to_be_bytes());
        }
        "stmt_prefix" => s[(r.next() % PREFIX as u64) as usize] ^= 1 << (r.next() % 8),
        "stmt_tail" => {
            // R_REG: message byte; R_TX, R_TX0, R_TXM: fee; R_BURN, R_DS, R_DR: amount
            let n = if f == Form::Register { 32 } else { 8 };
            s[tail + (r.next() % n) as usize] ^= 1 << (r.next() % 8);
        }
        "other_proof" => p = other.to_vec(),
        "field_noncanon" => {
            // add a large constant to one big-endian word near the end (a field element of an opened column or a
            // multiproof digest)
            let i = p.len() - 8 * (1 + (r.next() % 16) as usize);
            let w = u64::from_be_bytes(p[i..i + 8].try_into().unwrap());
            p[i..i + 8].copy_from_slice(&w.wrapping_add(0xFFFF_FFFF_0000_0001).to_be_bytes());
        }
        _ => p.clear(),
    }
    (s, p)
}
