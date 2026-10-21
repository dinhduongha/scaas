//! `pqzl/test/pqz_bench.c`'s statements, witnesses and steps (test entry points, not API): `src/bin/bench.rs` times
//! them natively, `wasm/` exports them to `wasm/run_wasm.mjs`. Same test RNG, same setup order and same seeds as the C
//! bench, so the same proofs (its `proofs_fnv`). Only the honest R_TXM shapes are built (`txm_build` without the
//! negative-case knobs of `txm_check`, which is not ported).
use crate::rel::{DISC_AMOUNT, DISC_PK, HDR_AMOUNT, HDR_AUDITOR_ON, HDR_FEE, HDR_LEGS};
use crate::{encrypt, keypair_from_secret, Ctx, Error, HEADER_BYTES, PREFIX_BYTES, PROOF_SYSTEM_ID, TXM_MAX_LEGS};
use crate::{POLYVEC_BYTES as PV, V_BYTES};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

const HDR_TO_UA: usize = 192;
const HDR_RECIPIENT: usize = 320;
const HDR_SALT: usize = 576;
const DISC_KIND: usize = DISC_AMOUNT + 32;

/// R_TXM shapes (M, auditorOn) in bench order (`TXB`)
const TXB: &[(usize, usize)] = &[
    (1, 1),
    (2, 1),
    (4, 1),
    (8, 1),
    (1, 0),
    (2, 0),
    (4, 0),
    (8, 0),
    #[cfg(feature = "oversize")]
    (16, 1),
    #[cfg(feature = "oversize")]
    (16, 0),
];

/// bench relations: R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0, then the R_TXM shapes
pub const NREL: usize = 6 + TXB.len();

/// the relations' names as the C bench prints them
pub const NAMES: [&str; NREL] = [
    "R_REG", "R_TX", "R_BURN", "R_DS", "R_DR", "R_TX0", "R_TXM1", "R_TXM2", "R_TXM4", "R_TXM8", "R_TXM1_0", "R_TXM2_0",
    "R_TXM4_0", "R_TXM8_0",
    #[cfg(feature = "oversize")]
    "R_TXM16",
    #[cfg(feature = "oversize")]
    "R_TXM16_0",
];

/// adversarial verify kinds (`step_verify_bad`)
pub const NKIND: u32 = 6;

/// the C bench's xorshift test RNG
struct Xs(u64);

impl Xs {
    fn rnd(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(2685821657736338717)
    }

    fn cbd(&mut self, eta: u32) -> i64 {
        let r = self.rnd();
        (0..eta).map(|i| ((r >> i) & 1) as i64 - ((r >> (32 + i)) & 1) as i64).sum()
    }

    /// a short vector with an l2 bound (resampled as KeyGen / Enc do)
    fn short8(&mut self, x: &mut [i8], eta: u32, bound: i64) {
        loop {
            let mut s = 0;
            for v in x.iter_mut() {
                *v = self.cbd(eta) as i8;
                s += *v as i64 * *v as i64;
            }
            if s <= bound * bound {
                return;
            }
        }
    }

    fn short16(&mut self, x: &mut [i16], eta: u32, bound: i64) {
        loop {
            let mut s = 0;
            for v in x.iter_mut() {
                *v = self.cbd(eta) as i16;
                s += *v as i64 * *v as i64;
            }
            if s <= bound * bound {
                return;
            }
        }
    }

    fn r8(&mut self) -> Box<[i8; crate::N]> {
        let mut x = Box::new([0i8; crate::N]);
        self.short8(&mut x[..], 1, crate::keys::BS);
        x
    }

    fn e16(&mut self) -> Box<[i16; crate::N]> {
        let mut x = Box::new([0i16; crate::N]);
        self.short16(&mut x[..], 20, crate::keys::BE);
        x
    }

    fn e2(&mut self) -> [i16; 16] {
        let mut x = [0i16; 16];
        self.short16(&mut x, 20, 64);
        x
    }
}

fn digits(x: u64) -> [u8; 16] {
    core::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}

fn put_be8(p: &mut [u8], v: u64) {
    p[..8].copy_from_slice(&v.to_be_bytes());
}

/// `wr_word`: a 32-byte word < 2^64
fn wr_word(p: &mut [u8], v: u64) {
    p[..24].fill(0);
    put_be8(&mut p[24..], v);
}

fn le16s(out: &mut Vec<u8>, x: &[i16]) {
    x.iter().for_each(|v| out.extend_from_slice(&v.to_le_bytes()));
}

fn i8s(out: &mut Vec<u8>, x: &[i8]) {
    out.extend(x.iter().map(|&v| v as u8));
}

struct Key {
    s: Box<[i8; crate::N]>,
    e: Box<[i16; crate::N]>,
    pk: Box<[u8; PV]>,
}

fn keygen(xs: &mut Xs) -> Result<Key, Error> {
    let (s, e) = (xs.r8(), xs.e16());
    let pk = keypair_from_secret(&s, &e)?;
    Ok(Key { s, e, pk })
}

/// s (int8) || e (int16 LE)
fn key_wit(out: &mut Vec<u8>, k: &Key) {
    i8s(out, &k.s[..]);
    le16s(out, &k.e[..]);
}

/// `vfy`: the generic verifier, or with `fast` the specialised one (builds with feature `sv`)
fn vfy(ctx: &mut Ctx, fast: bool, op: u8, st: &[u8], pf: &[u8]) -> bool {
    #[cfg(feature = "sv")]
    if fast {
        return ctx.verify_fast(op, st, pf);
    }
    let _ = fast;
    ctx.verify(op, st, pf)
}

/// the bench state (`step_init`'s setup) and the last proof per relation
pub struct Bench {
    ctx: Ctx,
    /// verify with the specialised verifier (`PQZ_VERIFY=fast`, C's `step_set_fast`)
    pub fast: bool,
    xs: Xs,
    ops: [u8; NREL],
    stmt: Vec<Vec<u8>>,
    wit: Vec<Vec<u8>>,
    seedmul: [u32; NREL],
    keyoff: [usize; NREL],
    scaloff: [usize; NREL],
    proofs: Vec<Vec<u8>>,
}

impl Bench {
    /// `step_init`: `setup` and `setup_txm`
    pub fn new() -> Result<Bench, Error> {
        let mut xs = Xs(0x243F6A8885A308D3);
        let (kf, kt, ka, _kx) = (keygen(&mut xs)?, keygen(&mut xs)?, keygen(&mut xs)?, keygen(&mut xs)?);

        // R_REG: prefix || message || pk
        let mut reg = vec![0xA5u8; PREFIX_BYTES];
        reg[32..].copy_from_slice(&PROOF_SYSTEM_ID);
        reg.extend(0..32u8);
        reg.extend_from_slice(&kf.pk[..]);
        let mut reg_wit = Vec::new();
        key_wit(&mut reg_wit, &kf);

        // R_TX: balance 1,000,000 in T (to pk_f), transfer 123,456 with fee 7
        let (b, v, fee) = (1_000_000u64, 123_456u64, 7u64);
        let bp = b - v - fee;
        let (r0, e10, e20) = (xs.r8(), xs.e16(), xs.e2());
        let t = encrypt(&[&kf.pk], &[digits(b)], &r0, &e10, &[e20])?;
        let (ut, vt) = (t.u, t.vs[0]);
        let (r, e1) = (xs.r8(), xs.e16());
        let e2 = [xs.e2(), xs.e2(), xs.e2()];
        let m = [digits(v), digits(bp), digits(v)];
        let c = encrypt(&[&kt.pk, &kf.pk, &ka.pk], &m, &r, &e1, &e2)?;
        let mut tx = vec![0x5Au8; HEADER_BYTES];
        tx[32..64].copy_from_slice(&PROOF_SYSTEM_ID);
        for (i, x) in tx.iter_mut().enumerate().skip(PREFIX_BYTES) {
            *x = (i * 3) as u8;
        }
        tx[HDR_FEE..HDR_FEE + 64].fill(0);
        put_be8(&mut tx[HDR_FEE + 24..], fee);
        tx[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
        tx[HDR_AUDITOR_ON + 31] = 1;
        tx[HDR_SALT..HDR_SALT + 16].fill(0);
        tx[HDR_RECIPIENT..HDR_RECIPIENT + 32].fill(0);
        let header = tx.clone();
        for x in [&kf.pk[..], &kt.pk[..], &ka.pk[..], &ut[..], &vt[..], &c.u[..], &c.vs[0], &c.vs[1], &c.vs[2]] {
            tx.extend_from_slice(x);
        }
        let mut tx_wit = Vec::new();
        key_wit(&mut tx_wit, &kf);
        i8s(&mut tx_wit, &r[..]);
        le16s(&mut tx_wit, &e1[..]);
        e2.iter().for_each(|x| le16s(&mut tx_wit, x));
        tx_wit.extend_from_slice(&m[0]);
        tx_wit.extend_from_slice(&m[1]);

        // R_DS / R_DR: disclose the receiver leg (u, v_t) of amount v to pk_t
        let disc = |k: u8| {
            let mut st = vec![0xD4 + k; PREFIX_BYTES];
            st[32..].copy_from_slice(&PROOF_SYSTEM_ID);
            st.extend((PREFIX_BYTES..DISC_AMOUNT).map(|i| (i * 7) as u8));
            st.resize(DISC_AMOUNT + 64, 0);
            put_be8(&mut st[DISC_AMOUNT + 24..], v);
            st[DISC_KIND + 31] = k;
            debug_assert_eq!(st.len(), DISC_PK);
            for x in [&kt.pk[..], &c.u[..], &c.vs[0]] {
                st.extend_from_slice(x);
            }
            st
        };
        let (ds, dr) = (disc(0), disc(1));
        let mut ds_wit = Vec::new();
        i8s(&mut ds_wit, &r[..]);
        le16s(&mut ds_wit, &e1[..]);
        le16s(&mut ds_wit, &e2[0]);
        let mut dr_wit = Vec::new();
        key_wit(&mut dr_wit, &kt);

        // R_BURN: burn 123,456 with fee 7 from the same T; fresh (r, e1, e2_f) for the new balance
        let (rb, e1b, e2b) = (xs.r8(), xs.e16(), xs.e2());
        let mb = digits(bp);
        let nb = encrypt(&[&kf.pk], &[mb], &rb, &e1b, &[e2b])?;
        let mut burn = vec![0xB2u8; PREFIX_BYTES];
        burn[32..].copy_from_slice(&PROOF_SYSTEM_ID);
        burn.extend((PREFIX_BYTES..HEADER_BYTES).map(|i| (i * 5) as u8));
        burn[HDR_FEE..HDR_FEE + 64].fill(0);
        put_be8(&mut burn[HDR_FEE + 24..], fee);
        put_be8(&mut burn[HDR_AMOUNT + 24..], v);
        burn[HDR_SALT..HDR_SALT + 32].fill(0);
        burn[HDR_TO_UA..HDR_TO_UA + 32].fill(0);
        burn[HDR_AUDITOR_ON..HDR_AUDITOR_ON + 32].fill(0);
        for x in [&kf.pk[..], &ut[..], &vt[..], &nb.u[..], &nb.vs[0]] {
            burn.extend_from_slice(x);
        }
        let mut burn_wit = tx_wit[..3 * crate::N].to_vec();
        i8s(&mut burn_wit, &rb[..]);
        le16s(&mut burn_wit, &e1b[..]);
        le16s(&mut burn_wit, &e2b);
        burn_wit.extend_from_slice(&mb);

        // R_TX0: the R_TX transfer without pk_a and v_a, auditorOn 0
        let mut tx0 = header;
        tx0[HDR_AUDITOR_ON + 31] = 0;
        for x in [&kf.pk[..], &kt.pk[..], &ut[..], &vt[..], &c.u[..], &c.vs[0], &c.vs[1]] {
            tx0.extend_from_slice(x);
        }
        let mut tx0_wit = tx_wit[..6 * crate::N + 64].to_vec();
        tx0_wit.extend_from_slice(&tx_wit[6 * crate::N + 96..6 * crate::N + 128]);

        let mut stmt = vec![reg, tx, burn, ds, dr, tx0];
        let mut wit = vec![reg_wit, tx_wit, burn_wit, ds_wit, dr_wit, tx0_wit];
        let mut ops = [crate::OP_TRANSFER_MULTI; NREL];
        ops[..6].copy_from_slice(&[3, 1, 2, 4, 5, 1]);
        let mut seedmul = [0u32; NREL];
        seedmul[..6].copy_from_slice(&[31, 17, 13, 11, 7, 19]);
        let mut keyoff = [HEADER_BYTES; NREL];
        keyoff[..6].copy_from_slice(&[PREFIX_BYTES + 32, HEADER_BYTES, HEADER_BYTES, DISC_PK, DISC_PK, HEADER_BYTES]);
        let mut scaloff = [HDR_FEE + 31; NREL];
        scaloff[..6].copy_from_slice(&[PREFIX_BYTES + 31, HDR_FEE + 31, HDR_AMOUNT + 31, DISC_AMOUNT + 31, DISC_AMOUNT + 31, HDR_FEE + 31]);

        // setup_txm: the keys from the reseeded test RNG (state saved and restored), one statement per shape
        let xs0 = xs.0;
        xs.0 = 0x7E57AB1EBEEF0001;
        let (kts, kta) = (keygen(&mut xs)?, keygen(&mut xs)?);
        let mut ktr = Vec::new();
        for _ in 0..TXM_MAX_LEGS {
            ktr.push(keygen(&mut xs)?);
        }
        xs.0 = xs0;
        for (t, &(m, a)) in TXB.iter().enumerate() {
            seedmul[6 + t] = 23 + 2 * t as u32;
            let (st, wt) = txm_build(&mut xs, &kts, &kta, &ktr, m, a, t as u8)?;
            stmt.push(st);
            wit.push(wt);
        }
        Ok(Bench { ctx: Ctx::new(), fast: false, xs, ops, stmt, wit, seedmul, keyoff, scaloff, proofs: vec![Vec::new(); NREL] })
    }

    /// `step_prove`: rnd32[i] = seed * SEEDMUL[rel] + i; the proof is kept (none after a failure)
    pub fn prove(&mut self, rel: usize, seed: u32) -> Result<(), Error> {
        let rnd32: [u8; 32] = core::array::from_fn(|i| seed.wrapping_mul(self.seedmul[rel]).wrapping_add(i as u32) as u8);
        let r = self.ctx.prove(self.ops[rel], &self.stmt[rel], &self.wit[rel], &rnd32);
        self.proofs[rel] = r.as_ref().map_or(Vec::new(), Clone::clone);
        r.map(|_| ())
    }

    /// the ctgrind check (src/bin/ct.rs): `prove` with the witness and rnd32 marked secret for memcheck, both and
    /// the proof public again after it
    #[cfg(feature = "ctgrind")]
    pub fn prove_ct(&mut self, rel: usize, seed: u32) -> Result<(), Error> {
        let rnd32: [u8; 32] = core::array::from_fn(|i| seed.wrapping_mul(self.seedmul[rel]).wrapping_add(i as u32) as u8);
        crate::ct::secret(&self.wit[rel][..]);
        crate::ct::secret(&rnd32);
        let r = self.ctx.prove(self.ops[rel], &self.stmt[rel], &self.wit[rel], &rnd32);
        crate::ct::public(&self.wit[rel][..]);
        crate::ct::public(&rnd32);
        crate::ct::public(&r);
        if let Ok(p) = &r {
            crate::ct::public(&p[..]);
        }
        self.proofs[rel] = r.as_ref().map_or(Vec::new(), Clone::clone);
        r.map(|_| ())
    }

    pub fn len(&self, rel: usize) -> usize {
        self.proofs[rel].len()
    }

    /// relation rel's (op, relation code, statement, witness): the oracle tests' honest rows for a parameter set
    /// without committed vectors (tests/common `pqzl_rows`)
    pub fn instance(&self, rel: usize) -> (u8, u8, &[u8], &[u8]) {
        const CODES: [u8; 6] = [3, 1, 2, 4, 5, 0x81];
        let code = if rel < 6 {
            CODES[rel]
        } else {
            let (m, a) = TXB[rel - 6];
            0x70 | (a as u8) << 3 | m.trailing_zeros() as u8
        };
        (self.ops[rel], code, &self.stmt[rel], &self.wit[rel])
    }

    /// `step_verify`
    pub fn verify(&mut self, rel: usize) -> bool {
        vfy(&mut self.ctx, self.fast, self.ops[rel], &self.stmt[rel], &self.proofs[rel])
    }

    /// `step_verify_bad`: kind 0 one random bit flipped in the proof, 1 random bytes of the valid length, 2 one
    /// statement coefficient changed, 3 the proof truncated by one byte, 4 an all-ones tail, 5 a public scalar
    /// changed; deterministic in (kind, seed): the test RNG state is restored
    pub fn verify_bad(&mut self, rel: usize, kind: u32, seed: u32) -> bool {
        let (op, len) = (self.ops[rel], self.proofs[rel].len());
        if len == 0 {
            return false; // no proof (C: undefined for kinds 0 and 3); the test RNG is untouched
        }
        let xs0 = self.xs.0; // step_verify_bad saves and restores it around verify_bad
        self.xs.0 ^= (seed as u64).wrapping_mul(0x9E3779B97F4A7C15);
        let mut bad = self.proofs[rel].clone();
        let r = match kind {
            0 => {
                let b = (self.xs.rnd() % (8 * len as u64)) as usize;
                bad[b >> 3] ^= 1 << (b & 7);
                vfy(&mut self.ctx, self.fast, op, &self.stmt[rel], &bad)
            }
            1 => {
                bad.iter_mut().for_each(|x| *x = self.xs.rnd() as u8);
                vfy(&mut self.ctx, self.fast, op, &self.stmt[rel], &bad)
            }
            2 | 5 => {
                let off = if kind == 2 { self.keyoff[rel] + 8 * (self.xs.rnd() % crate::N as u64) as usize + 7 } else { self.scaloff[rel] };
                self.stmt[rel][off] ^= 1;
                let r = vfy(&mut self.ctx, self.fast, op, &self.stmt[rel], &self.proofs[rel]);
                self.stmt[rel][off] ^= 1;
                r
            }
            3 => vfy(&mut self.ctx, self.fast, op, &self.stmt[rel], &bad[..len - 1]),
            _ => {
                bad[len / 2..].fill(0xff);
                vfy(&mut self.ctx, self.fast, op, &self.stmt[rel], &bad)
            }
        };
        self.xs.0 = xs0;
        r
    }

    /// `step_hash`: FNV-1a of the last proof
    pub fn hash(&self, rel: usize) -> u32 {
        self.proofs[rel].iter().fold(2166136261u32, |h, &b| (h ^ b as u32).wrapping_mul(16777619))
    }
}

/// `txm_build` (honest): sender KTS, leg j to KTR[j] in group j / 4, auditor KTA; one real leg (the last, 123,456),
/// the rest decoys; balance 1,000,000, fee 7 (auditor on) / 0
#[allow(clippy::too_many_arguments)]
fn txm_build(xs: &mut Xs, kts: &Key, kta: &Key, ktr: &[Key], m: usize, a: usize, tag: u8) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let g = m.div_ceil(4);
    let (balance, fee) = (1_000_000u64, if a > 0 { 7u64 } else { 0 });
    let amount = |j: usize| if j == m - 1 { 123_456u64 } else { 0 };
    let dg: Vec<[u8; 16]> = (0..m).map(|j| digits(amount(j))).collect();
    let dpg = digits(balance.wrapping_sub(fee + (0..m).map(amount).sum::<u64>()));
    // T, the group randomness, the e2s from the test RNG reseeded per statement
    let xs0 = xs.0;
    xs.0 = 0x7E57AB1E00000000 ^ (tag as u64).wrapping_mul(0x9E3779B97F4A7C15);
    let (rt, e1t, e2t) = (xs.r8(), xs.e16(), xs.e2());
    let t = encrypt(&[&kts.pk], &[digits(balance)], &rt, &e1t, &[e2t])?;
    let (mut r, mut e1, mut u) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..g {
        let (rg, e1g) = (xs.r8(), xs.e16());
        u.push(encrypt(&[&kts.pk], &[[0; 16]], &rg, &e1g, &[[0; 16]])?.u);
        r.push(rg);
        e1.push(e1g);
    }
    let (mut e2l, mut e2a) = (Vec::new(), Vec::new());
    for _ in 0..m {
        e2l.push(xs.e2());
        e2a.push(xs.e2());
    }
    let e2f = xs.e2();
    xs.0 = xs0;
    let (mut v, mut va) = (Vec::new(), Vec::new());
    for j in 0..m {
        v.push(encrypt(&[&ktr[j].pk], &[dg[j]], &r[j / 4], &e1[j / 4], &[e2l[j]])?.vs[0]);
        if a > 0 {
            va.push(encrypt(&[&kta.pk], &[dg[j]], &r[j / 4], &e1[j / 4], &[e2a[j]])?.vs[0]);
        }
    }
    let vf = encrypt(&[&kts.pk], &[dpg], &r[0], &e1[0], &[e2f])?.vs[0];

    let mut st = vec![0x77u8; PREFIX_BYTES];
    st[32..].copy_from_slice(&PROOF_SYSTEM_ID);
    st.extend((PREFIX_BYTES..HEADER_BYTES).map(|i| (i * 11 + tag as usize) as u8));
    wr_word(&mut st[HDR_FEE..], fee);
    wr_word(&mut st[HDR_AMOUNT..], 0);
    wr_word(&mut st[HDR_LEGS..], m as u64);
    wr_word(&mut st[HDR_AUDITOR_ON..], a as u64);
    st[HDR_SALT..HDR_SALT + 16].fill(0);
    st.extend_from_slice(&kts.pk[..]);
    ktr[..m].iter().for_each(|k| st.extend_from_slice(&k.pk[..]));
    if a > 0 {
        st.extend_from_slice(&kta.pk[..]);
    }
    st.extend_from_slice(&t.u[..]);
    st.extend_from_slice(&t.vs[0]);
    u.iter().for_each(|x| st.extend_from_slice(&x[..]));
    v.iter().for_each(|x| st.extend_from_slice(x));
    st.extend_from_slice(&vf);
    va.iter().for_each(|x: &[u8; V_BYTES]| st.extend_from_slice(x));

    let mut wt = Vec::new();
    key_wit(&mut wt, kts);
    for k in 0..g {
        i8s(&mut wt, &r[k][..]);
        le16s(&mut wt, &e1[k][..]);
    }
    e2l.iter().for_each(|x| le16s(&mut wt, x));
    le16s(&mut wt, &e2f);
    if a > 0 {
        e2a.iter().for_each(|x| le16s(&mut wt, x));
    }
    dg.iter().for_each(|x| wt.extend_from_slice(x));
    wt.extend_from_slice(&dpg);
    if st.len() != crate::rel::txm_stmt(m, a) || wt.len() != (1 + g) * 3 * crate::N + 32 * (m + 1 + a * m) + 16 * m + 16 {
        return Err(Error::Internal);
    }
    Ok((st, wt))
}
