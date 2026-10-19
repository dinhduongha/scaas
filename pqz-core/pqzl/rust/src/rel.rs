//! `pqz_rel.c`: the relation table (the one table of the crate), statement parsing and the relation builders
//! (R_REG, R_TX / R_TX0 / R_BURN / R_TXM, R_DS, R_DR as toolbox statements), the ABDLOP keys per relation, the
//! statement digest, `pqz_verify`'s and `pqz_prove`'s dispatch (op, statement length, the R_TXM header words M /
//! auditorOn), the witness parsers and the hedged prover seeds (CTR-PQZ-19).
//!
//! What C keeps in static storage (A, the keys of each relation, built at first use) lives in the caller's [`Ctx`].
use crate::arith::int::Int;
use crate::arith::poly::Poly;
use crate::arith::polymat::{Pm, PolyMat};
use crate::arith::polyvec::PolyVec;
use crate::arith::spoly::Sparse;
use crate::coder::{decode_proof, encode_proof, ProofParts};
use crate::keys::{a_of, be8, rd_poly, rd_polyvec};
use crate::params::{self, Tbox};
use crate::proof::tbox::{self, Statement};
use crate::proof::{abdlop, Eq};
use crate::rand::shake::shake128;
use crate::rand::urandom::polyvec_urandom_bnd;
use crate::{Ctx, Error, Wiped, HEADER_BYTES, MAX_PROOF, PREFIX_BYTES, POLYVEC_BYTES as PV, V_BYTES};
use alloc::vec::Vec;

const K: usize = 32;
const DELTA: i64 = (1 << 26) - 1;
const D: usize = 64;

/// one relation (`rel_t`): its parameters, the op it serves, its code (the op, 0x81 = R_TX0, or 0x70 | auditorOn << 3
/// | log2 M for R_TXM; the byte of its ABDLOP keys' tag, the test hook's relation name), the debit shape
pub(crate) struct Rel {
    pub(crate) p: &'static Tbox,
    pub(crate) op: u8,
    pub(crate) code: u8,
    pub(crate) legs: usize,
    pub(crate) aud: usize,
    #[allow(dead_code)] // the oracle tests' parameter list (testkit)
    pub(crate) name: &'static str,
}

const fn rel(p: &'static Tbox, op: u8, code: u8, legs: usize, aud: usize, name: &'static str) -> Rel {
    Rel { p, op, code, legs, aud, name }
}

const fn txm(p: &'static Tbox, m: usize, lg: u8, a: usize, name: &'static str) -> Rel {
    rel(p, crate::OP_TRANSFER_MULTI, 0x70 | (a as u8) << 3 | lg, m, a, name)
}

pub(crate) const NREL: usize = if cfg!(feature = "oversize") { 16 } else { 14 };

/// REG, TX, TX0, BURN, DS, DR, then the R_TXM shapes (M = 1 on R_TX's / R_TX0's parameters), as `pqz_rel.c`
pub(crate) static RELS: [Rel; NREL] = [
    rel(&params::reg::pqz_reg, crate::OP_REGISTER, 3, 0, 0, "reg"),
    rel(&params::tx::pqz_tx, crate::OP_TRANSFER, 1, 1, 1, "tx"),
    rel(&params::tx0::pqz_tx0, crate::OP_TRANSFER, 0x81, 1, 0, "tx0"),
    rel(&params::burn::pqz_burn, crate::OP_BURN, 2, 0, 0, "burn"),
    rel(&params::ds::pqz_ds, crate::OP_DISCLOSE_SENDER, 4, 0, 0, "ds"),
    rel(&params::dr::pqz_dr, crate::OP_DISCLOSE_RECEIVER, 5, 0, 0, "dr"),
    txm(&params::tx::pqz_tx, 1, 0, 1, "tx"),
    txm(&params::txm2::pqz_txm2, 2, 1, 1, "txm2"),
    txm(&params::txm4::pqz_txm4, 4, 2, 1, "txm4"),
    txm(&params::txm8::pqz_txm8, 8, 3, 1, "txm8"),
    txm(&params::tx0::pqz_tx0, 1, 0, 0, "tx0"),
    txm(&params::txm20::pqz_txm20, 2, 1, 0, "txm20"),
    txm(&params::txm40::pqz_txm40, 4, 2, 0, "txm40"),
    txm(&params::txm80::pqz_txm80, 8, 3, 0, "txm80"),
    #[cfg(feature = "oversize")]
    txm(&params::txm16::pqz_txm16, 16, 4, 1, "txm16"),
    #[cfg(feature = "oversize")]
    txm(&params::txm160::pqz_txm160, 16, 4, 0, "txm160"),
];
const TXM0: usize = 6;

/// `rel_by_code`
#[allow(dead_code)] // the test hook and the oracle tests
pub(crate) fn by_code(code: u8) -> Option<&'static Rel> {
    RELS.iter().find(|r| r.code == code)
}

/// relation code -> its parameters
#[allow(dead_code)] // the test hook and the oracle tests
pub(crate) fn tbox_by_code(code: u8) -> Option<&'static Tbox> {
    by_code(code).map(|r| r.p)
}

pub(crate) const REG_STMT: usize = PREFIX_BYTES + 32 + PV;
pub(crate) const TX_STMT: usize = HEADER_BYTES + 3 * PV + (PV + V_BYTES) + (PV + 3 * V_BYTES);
pub(crate) const TX0_STMT: usize = HEADER_BYTES + 2 * PV + (PV + V_BYTES) + (PV + 2 * V_BYTES);
pub(crate) const BURN_STMT: usize = HEADER_BYTES + PV + 2 * (PV + V_BYTES);
pub(crate) const DISC_AMOUNT: usize = PREFIX_BYTES + 5 * 32;
pub(crate) const DISC_PK: usize = DISC_AMOUNT + 64;
pub(crate) const DISC_STMT: usize = DISC_PK + 2 * PV + V_BYTES;
pub(crate) const HDR_FEE: usize = 256;
pub(crate) const HDR_AMOUNT: usize = 288;
pub(crate) const HDR_LEGS: usize = 320;
pub(crate) const HDR_AUDITOR_ON: usize = 448;

const fn groups(m: usize) -> usize {
    m.div_ceil(4)
}

/// `PQZ_TXM_STMT_BYTES (m, a)`
pub(crate) const fn txm_stmt(m: usize, a: usize) -> usize {
    HEADER_BYTES + (1 + m + a) * PV + (PV + V_BYTES) + groups(m) * PV + (m + 1 + a * m) * V_BYTES
}

/// the exact statement length of relation r (`pqz_rel.c` `stmt_bytes`)
pub(crate) const fn stmt_bytes(r: &Rel) -> usize {
    match r.code {
        3 => REG_STMT,
        1 => TX_STMT,
        0x81 => TX0_STMT,
        2 => BURN_STMT,
        4 | 5 => DISC_STMT,
        _ => txm_stmt(r.legs, r.aud),
    }
}

/// `rd_word64`: a be32 word that must be < 2^64
pub(crate) fn word64(p: &[u8]) -> (u64, bool) {
    (be8(&p[24..]), p[..24].iter().all(|&b| b == 0))
}

/// `rel_of`: the relation of op (op 1: R_TX0 by the 66,560-byte length, else R_TX; op 7 by its header words), `None`
/// also when the statement is not exactly that relation's length: every entry (prove, verify, verify_fast) checks the
/// length here, before any cache is built or the statement hashed (review G-3 / H-4, fix A)
pub(crate) fn rel_of(op: u8, stmt: &[u8]) -> Option<usize> {
    let ri = match op {
        crate::OP_REGISTER => 0,
        crate::OP_TRANSFER => {
            if stmt.len() == TX0_STMT {
                2
            } else {
                1
            }
        }
        crate::OP_BURN => 3,
        crate::OP_DISCLOSE_SENDER => 4,
        crate::OP_DISCLOSE_RECEIVER => 5,
        crate::OP_TRANSFER_MULTI => {
            if stmt.len() < HEADER_BYTES {
                return None;
            }
            let ((m, ok1), (a, ok2)) = (word64(&stmt[HDR_LEGS..]), word64(&stmt[HDR_AUDITOR_ON..]));
            if !(ok1 && ok2) {
                return None;
            }
            TXM0 + RELS[TXM0..].iter().position(|r| r.legs as u64 == m && r.aud as u64 == a)?
        }
        _ => return None,
    };
    (stmt.len() == stmt_bytes(&RELS[ri])).then_some(ri)
}

/// `pqz_stmt_hash`: SHAKE128("SCAAS-PQZ-TRANSCRIPT-V1" || op || be32(len) || stmt); `Error::Input` for a length that
/// does not fit be32 (unreachable after `rel_of`'s exact length, but never truncated)
pub(crate) fn stmt_hash(op: u8, stmt: &[u8]) -> Result<[u8; 32], Error> {
    let len = u32::try_from(stmt.len()).map_err(|_| Error::Input)?;
    let mut h = [0u8; 32];
    shake128(&[b"SCAAS-PQZ-TRANSCRIPT-V1", &[op], &len.to_be_bytes(), stmt]).squeeze(&mut h);
    Ok(h)
}

/// `rel_keys`: A1, A2', B' from SHAKE128("SCAAS-PQZ-ABDLOP-PP-V1" || code), in NTT form
fn rel_keys(r: &Rel) -> Result<[PolyMat; 3], Error> {
    let mut pp = [0u8; 32];
    shake128(&[b"SCAAS-PQZ-ABDLOP-PP-V1", &[r.code]]).squeeze(&mut pp);
    let (mut a1, mut a2p, mut bp) = abdlop::keygen(&pp, r.p.tbox)?;
    crate::arith::polymat::tocrt(&mut a1);
    crate::arith::polymat::tocrt(&mut a2p);
    crate::arith::polymat::tocrt(&mut bp);
    Ok([a1, a2p, bp])
}

fn set_c(p: &mut Poly, j: usize, v: i64) {
    p.set_coeff(j, &Int::from_i64(1, v));
}

fn cval(p: &mut Poly, k: usize) -> i64 {
    p.get_coeff(k).get_i64()
}

fn digit(x: u64, i: usize) -> i64 {
    ((x >> (4 * i)) & 15) as i64
}

fn vec_try<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Memory)?;
    Ok(v)
}

fn new_vec() -> Result<PolyVec, Error> {
    PolyVec::new(K)
}

/// `new_sel`: rows x cols, ones at (i, off + i)
fn new_sel(rows: usize, cols: usize, off: usize) -> Result<PolyMat, Error> {
    let mut m = PolyMat::new(rows, cols)?;
    for i in 0..rows {
        m.at(i, off + i).set_one();
    }
    Ok(m)
}

/// `sys_t` under construction
struct Sys<'a> {
    p: &'static Tbox,
    a: &'a mut PolyMat,
    quad: Vec<Eq>,
    eval: Vec<Eq>,
    bits: usize,
    nbin: usize,
}

impl Sys<'_> {
    /// `add_lin_row`: sum_j A'[i][j] x[off_x + j] + y[off_y + i] - rhs = 0, A' = A or A^T
    fn lin_row(&mut self, transpose: bool, i: usize, off_x: usize, off_y: usize, rhs: &mut Poly) -> Result<(), Error> {
        let n = 2 * (self.p.tbox.m1 + self.p.quad_eval.quad_many.l) as usize;
        let mut r1 = Sparse::new_vec(n);
        for j in 0..K {
            let e = if transpose { self.a.at(j, i) } else { self.a.at(i, j) };
            r1.insert_elem(2 * (off_x + j))?.clone_from(e);
        }
        r1.insert_elem(2 * (off_y + i))?.set_one();
        r1.sort()?;
        self.quad.try_reserve(1).map_err(|_| Error::Memory)?;
        self.quad.push(Eq { r2: None, r1: Some(r1), r0: Some(Poly::neg(rhs)) });
        Ok(())
    }

    /// `evaleq`: ct(X^-i (pkrow^T x)) + e2_i + sum (bit terms in acc) + rhs = 0
    fn evaleq(
        &mut self,
        pkrow: Option<&mut PolyVec>,
        off_x: usize,
        i: usize,
        e2: Option<usize>,
        acc: &mut [Poly],
        rhs: i64,
    ) -> Result<(), Error> {
        let n = 2 * (self.p.tbox.m1 + self.p.quad_eval.quad_eval.l) as usize;
        let mut r1 = Sparse::new_vec(n);
        if let Some(pk) = pkrow {
            for j in 0..K {
                *r1.insert_elem(2 * (off_x + j))? = mul_xinv(&mut pk[j], i);
            }
        }
        if let Some(e) = e2 {
            let p = r1.insert_elem(2 * e)?;
            p.set_zero();
            if i == 0 {
                set_c(p, 0, 1);
            } else {
                set_c(p, D - i, -1);
            }
        }
        for (b, a) in acc[..self.nbin].iter().enumerate() {
            let mut t = a.clone();
            *r1.insert_elem(2 * (self.bits + b))? = Poly::redc(&mut t);
        }
        r1.sort()?;
        let mut r0 = Poly::ZERO;
        set_c(&mut r0, 0, rhs);
        self.eval.try_reserve(1).map_err(|_| Error::Memory)?;
        self.eval.push(Eq { r2: None, r1: Some(r1), r0: Some(Poly::redc(&mut r0)) });
        Ok(())
    }
}

/// `mul_xinv`: X^-i a (negacyclic)
fn mul_xinv(a: &mut Poly, i: usize) -> Poly {
    a.fromcrt();
    let mut r = Poly::ZERO;
    for m in 0..D {
        let v = a.c(m).get_i64();
        if m >= i {
            set_c(&mut r, m - i, v);
        } else {
            set_c(&mut r, m + D - i, v.wrapping_neg());
        }
    }
    r
}

/// `add_bit`: coef * bit(slot) into the accumulators (ct(X^-a P) = P_a)
fn add_bit(acc: &mut [Poly], slot: usize, coef: i64) {
    let (p, a) = (&mut acc[slot / 64], slot % 64);
    let (k, t) = if a == 0 { (0, coef) } else { (64 - a, -coef) };
    let mut c = p.get_coeff(k);
    c.add(&{ c }, &Int::from_i64(1, t));
    p.set_coeff(k, &c);
}

fn acc_zero(acc: &mut [Poly]) {
    acc.iter_mut().for_each(Poly::set_zero);
}

/// `slot (base, w, i, b)`
fn slot(base: usize, w: usize, i: usize, b: usize) -> usize {
    base + w * i + b
}

fn statement(s: Sys<'_>, es: Vec<PolyMat>, ps: Option<PolyMat>, ds: PolyMat) -> Statement {
    Statement { quad: s.quad, eval: s.eval, es, ps, ds }
}

/// what the witness parsers read from the statement (`txst_t`): the ciphertext the witness decrypts (the debit
/// relations: (u_T, v_T); R_DR: (u, v)), fee, amount
pub(crate) struct Pub {
    u: PolyVec,
    v: Poly,
    fee: u64,
    amount: u64,
}

impl Pub {
    fn none() -> Pub {
        Pub { u: PolyVec(Vec::new()), v: Poly::ZERO, fee: 0, amount: 0 }
    }
}

type Built = Option<(Statement, Pub)>;

/// R_REG: prefix || message || pk; pk = A s + e
fn build_reg(a: &mut PolyMat, stmt: &[u8]) -> Result<Built, Error> {
    let p = RELS[0].p;
    let mut pk = new_vec()?;
    if !rd_polyvec(&mut pk, &stmt[PREFIX_BYTES + 32..]) {
        return Ok(None);
    }
    let mut s = Sys { p, a, quad: vec_try(K)?, eval: Vec::new(), bits: 0, nbin: 0 };
    for i in 0..K {
        s.lin_row(false, i, 0, 32, &mut pk[i])?;
    }
    let mut es = vec_try(2)?;
    es.push(new_sel(32, 64, 0)?);
    es.push(new_sel(32, 64, 32)?);
    Ok(Some((statement(s, es, None, new_sel(1, 64, 0)?), Pub::none())))
}

/// the debit shape (`shape_t`): s1 slots, bit bases, exact-l2 blocks
struct Shape {
    legs: usize,
    groups: usize,
    aud: usize,
    burn: bool,
    txm: bool,
    e: usize,
    e2f: usize,
    bits: usize,
    nbin: usize,
    m1: usize,
    dp: usize,
    m: usize,
    c: usize,
    et: usize,
    blk: Vec<(usize, usize)>,
}

/// `shape_of`
fn shape_of(r: &Rel) -> Result<Shape, Error> {
    let (m, a) = (r.legs, r.aud);
    let g = if r.op == crate::OP_BURN { 1 } else { groups(m) };
    let e = 64 + 64 * g;
    let e2f = e + m;
    let bits = e2f + 1 + a * m;
    let nbin = (853 + 64 * m).div_ceil(64);
    let dp = 64 * m;
    let mut blk = vec_try(2 + 2 * g + m + 1 + a * m)?;
    blk.push((0, 32));
    blk.push((32, 32));
    for g in 0..g {
        blk.push((64 + 64 * g, 32));
        blk.push((96 + 64 * g, 32));
    }
    for k in 0..m + 1 + a * m {
        blk.push((e + k, 1));
    }
    Ok(Shape {
        legs: m,
        groups: g,
        aud: a,
        burn: r.op == crate::OP_BURN,
        txm: r.op == crate::OP_TRANSFER_MULTI,
        e,
        e2f,
        bits,
        nbin,
        m1: bits + nbin,
        dp,
        m: dp + 64,
        c: dp + 288,
        et: dp + 453,
        blk,
    })
}

/// `shape_ok`: the shape agrees with the generated parameters
fn shape_ok(r: &Rel, h: &Shape) -> bool {
    let p = r.p;
    let maxl = crate::TXM_MAX_LEGS;
    h.nbin == p.nbin as usize
        && h.blk.len() == p.z as usize
        && h.m1 + p.z as usize == p.tbox.m1 as usize
        && h.legs <= maxl
        && h.groups <= groups(maxl)
        && 16 * (h.legs + 1 + h.aud * h.legs + 2) <= 16 * (3 + 2 * maxl)
        && h.blk.iter().zip(p.n).all(|(b, &n)| b.1 == n as usize)
}

/// the debit statement (`txst_t`)
struct Debit {
    pkf: PolyVec,
    pk: Vec<PolyVec>,
    pka: PolyVec,
    ut: PolyVec,
    vt: Poly,
    u: Vec<PolyVec>,
    v: Vec<Poly>,
    vf: Poly,
    va: Vec<Poly>,
    fee: u64,
    amount: u64,
}

/// `parse_debit`: header words (fee; amount for R_BURN; auditorOn = A for the transfers; M for R_TXM), then pk_f ||
/// pk_0 .. pk_{M-1} || [pk_a] || u_T || v_T || u_0 .. u_{G-1} || v_0 .. v_{M-1} || v_f || [v_{a,j}]
fn parse_debit(stmt: &[u8], h: &Shape) -> Result<(Debit, bool), Error> {
    let (fee, mut ok) = word64(&stmt[HDR_FEE..]);
    let mut amount = 0;
    if h.burn {
        let (x, o) = word64(&stmt[HDR_AMOUNT..]);
        amount = x;
        ok &= o;
    } else {
        let (on, o) = word64(&stmt[HDR_AUDITOR_ON..]);
        ok &= o & (on == h.aud as u64);
    }
    if h.txm {
        let (m, o) = word64(&stmt[HDR_LEGS..]);
        ok &= o & (m == h.legs as u64);
    }
    let mut at = HEADER_BYTES;
    let mut vec_at = |ok: &mut bool| -> Result<PolyVec, Error> {
        let mut v = new_vec()?;
        *ok &= rd_polyvec(&mut v, &stmt[at..]);
        at += PV;
        Ok(v)
    };
    let pkf = vec_at(&mut ok)?;
    let mut pk = vec_try(h.legs)?;
    for _ in 0..h.legs {
        pk.push(vec_at(&mut ok)?);
    }
    let pka = if h.aud > 0 { vec_at(&mut ok)? } else { PolyVec::new(0)? };
    let ut = vec_at(&mut ok)?;
    let mut vt = Poly::ZERO;
    ok &= rd_poly(&mut vt, &stmt[at..], 16);
    at += V_BYTES;
    let mut vec_at = |ok: &mut bool| -> Result<PolyVec, Error> {
        let mut v = new_vec()?;
        *ok &= rd_polyvec(&mut v, &stmt[at..]);
        at += PV;
        Ok(v)
    };
    let mut u = vec_try(h.groups)?;
    for _ in 0..h.groups {
        u.push(vec_at(&mut ok)?);
    }
    let mut poly_at = |ok: &mut bool| -> Poly {
        let mut p = Poly::ZERO;
        *ok &= rd_poly(&mut p, &stmt[at..], 16);
        at += V_BYTES;
        p
    };
    let mut v = vec_try(h.legs)?;
    for _ in 0..h.legs {
        v.push(poly_at(&mut ok));
    }
    let vf = poly_at(&mut ok);
    let mut va = vec_try(h.aud * h.legs)?;
    for _ in 0..h.aud * h.legs {
        va.push(poly_at(&mut ok));
    }
    Ok((Debit { pkf, pk, pka, ut, vt, u, v, vf, va, fee, amount }, ok))
}

/// `build_debit` (R_TX, R_TX0, R_BURN, R_TXM): rows 1, 2 (R_q-linear), then per coefficient i rows 3-7 as evaluation
/// equations (pq-zero-knowledge.md §7.4 with M legs)
fn build_debit(a: &mut PolyMat, stmt: &[u8], r: &Rel) -> Result<Built, Error> {
    let h = shape_of(r)?;
    if !shape_ok(r, &h) {
        return Ok(None);
    }
    let (m, au, nbin, m1) = (h.legs, h.aud, h.nbin, h.m1);
    let (mut t, ok) = parse_debit(stmt, &h)?;
    if !ok {
        return Ok(None);
    }
    let mut s = Sys { p: r.p, a, quad: vec_try(K * (1 + h.groups))?, eval: vec_try(16 * (m + 1 + au * m + 2))?, bits: h.bits, nbin };
    let mut acc = vec_try(nbin)?;
    acc.resize(nbin, Poly::ZERO);
    for i in 0..K {
        s.lin_row(false, i, 0, 32, &mut t.pkf[i])?;
    }
    for g in 0..h.groups {
        for i in 0..K {
            s.lin_row(true, i, 64 + 64 * g, 96 + 64 * g, &mut t.u[g][i])?;
        }
    }
    for i in 0..16 {
        let dpub = if h.burn { digit(t.amount, i) } else { 0 };
        for j in 0..m {
            acc_zero(&mut acc);
            for b in 0..4 {
                add_bit(&mut acc, slot(64 * j, 4, i, b), DELTA << b);
            }
            let rhs = -cval(&mut t.v[j], i);
            s.evaleq(Some(&mut t.pk[j]), 64 + 64 * (j / 4), i, Some(h.e + j), &mut acc, rhs)?;
        }
        acc_zero(&mut acc);
        for b in 0..4 {
            add_bit(&mut acc, slot(h.dp, 4, i, b), DELTA << b);
        }
        let rhs = -cval(&mut t.vf, i);
        s.evaleq(Some(&mut t.pkf), 64, i, Some(h.e2f), &mut acc, rhs)?;
        for j in 0..au * m {
            acc_zero(&mut acc);
            for b in 0..4 {
                add_bit(&mut acc, slot(64 * j, 4, i, b), DELTA << b);
            }
            let rhs = -cval(&mut t.va[j], i);
            s.evaleq(Some(&mut t.pka), 64 + 64 * (j / 4), i, Some(h.e2f + 1 + j), &mut acc, rhs)?;
        }
        // row 6: (u_T^T s_f)_i + Delta M_i + (e_T,i + 2^24) - 2^24 - v_T,i = 0
        acc_zero(&mut acc);
        for b in 0..14 {
            add_bit(&mut acc, slot(h.m, 14, i, b), DELTA << b);
        }
        for b in 0..25 {
            add_bit(&mut acc, slot(h.et, 25, i, b), 1 << b);
        }
        let rhs = -cval(&mut t.vt, i) - (1 << 24);
        s.evaleq(Some(&mut t.ut), 0, i, None, &mut acc, rhs)?;
        // row 7 (over Z): M_i + c_{i-1} - d'_i - sum_j d_j,i - f_i - 16 c_i = 0, c = cbits - 64
        acc_zero(&mut acc);
        let mut rhs = -digit(t.fee, i) - dpub;
        for b in 0..14 {
            add_bit(&mut acc, slot(h.m, 14, i, b), 1 << b);
        }
        if i >= 1 {
            for b in 0..11 {
                add_bit(&mut acc, slot(h.c, 11, i - 1, b), 1 << b);
            }
            rhs -= 64;
        }
        for b in 0..4 {
            add_bit(&mut acc, slot(h.dp, 4, i, b), -(1 << b));
            for j in 0..m {
                add_bit(&mut acc, slot(64 * j, 4, i, b), -(1 << b));
            }
        }
        if i <= 14 {
            for b in 0..11 {
                add_bit(&mut acc, slot(h.c, 11, i, b), -(16 << b));
            }
            rhs += 16 * 64;
        }
        s.evaleq(None, 0, i, None, &mut acc, rhs)?;
    }
    let mut es = vec_try(h.blk.len())?;
    for &(st, ln) in &h.blk {
        es.push(new_sel(ln, m1, st)?);
    }
    let ps = new_sel(nbin, m1, h.bits)?;
    let ds = new_sel(1, m1, h.e)?;
    let p = Pub { u: t.ut, v: t.vt, fee: t.fee, amount: t.amount };
    Ok(Some((statement(s, es, Some(ps), ds), p)))
}

/// `parse_disc`: amount (a word < 2^64), pk, u, v
fn parse_disc(stmt: &[u8]) -> Result<(u64, PolyVec, PolyVec, Poly, bool), Error> {
    let (amount, mut ok) = word64(&stmt[DISC_AMOUNT..]);
    let (mut pk, mut u, mut v) = (new_vec()?, new_vec()?, Poly::ZERO);
    ok &= rd_polyvec(&mut pk, &stmt[DISC_PK..]);
    ok &= rd_polyvec(&mut u, &stmt[DISC_PK + PV..]);
    ok &= rd_poly(&mut v, &stmt[DISC_PK + 2 * PV..], 16);
    Ok((amount, pk, u, v, ok))
}

/// R_DS: u = A^T r + e1; (pk^T r)_i + e2_i + Delta d_i - v_i = 0
fn build_ds(a: &mut PolyMat, stmt: &[u8]) -> Result<Built, Error> {
    let (amount, mut pk, mut u, mut v, ok) = parse_disc(stmt)?;
    if !ok {
        return Ok(None);
    }
    let mut s = Sys { p: RELS[4].p, a, quad: vec_try(K)?, eval: vec_try(16)?, bits: 65, nbin: 0 };
    for i in 0..K {
        s.lin_row(true, i, 0, 32, &mut u[i])?;
    }
    for i in 0..16 {
        let rhs = DELTA * digit(amount, i) - cval(&mut v, i);
        s.evaleq(Some(&mut pk), 0, i, Some(64), &mut [], rhs)?;
    }
    let mut es = vec_try(3)?;
    es.push(new_sel(32, 65, 0)?);
    es.push(new_sel(32, 65, 32)?);
    es.push(new_sel(1, 65, 64)?);
    Ok(Some((statement(s, es, None, new_sel(1, 65, 64)?), Pub::none())))
}

/// R_DR: pk = A s + e; (u^T s)_i + (e'_i + 2^24) - 2^24 + Delta d_i - v_i = 0
fn build_dr(a: &mut PolyMat, stmt: &[u8]) -> Result<Built, Error> {
    let (amount, mut pk, mut u, mut v, ok) = parse_disc(stmt)?;
    if !ok {
        return Ok(None);
    }
    let mut s = Sys { p: RELS[5].p, a, quad: vec_try(K)?, eval: vec_try(16)?, bits: 64, nbin: 7 };
    let mut acc = vec_try(15)?;
    acc.resize(15, Poly::ZERO);
    for i in 0..K {
        s.lin_row(false, i, 0, 32, &mut pk[i])?;
    }
    for i in 0..16 {
        acc_zero(&mut acc);
        for b in 0..25 {
            add_bit(&mut acc, 25 * i + b, 1 << b);
        }
        let rhs = DELTA * digit(amount, i) - cval(&mut v, i) - (1 << 24);
        s.evaleq(Some(&mut u), 0, i, None, &mut acc, rhs)?;
    }
    let mut es = vec_try(2)?;
    es.push(new_sel(32, 71, 0)?);
    es.push(new_sel(32, 71, 32)?);
    let st = statement(s, es, Some(new_sel(7, 71, 64)?), new_sel(1, 71, 0)?);
    Ok(Some((st, Pub { u, v, fee: 0, amount })))
}

/// `build`: the statement of relation r (its length checked) and what the witness parsers read of it; `None` if
/// malformed
fn build(a: &mut PolyMat, r: &Rel, stmt: &[u8]) -> Result<Built, Error> {
    if stmt.len() != stmt_bytes(r) {
        return Ok(None);
    }
    match r.code {
        3 => build_reg(a, stmt),
        4 => build_ds(a, stmt),
        5 => build_dr(a, stmt),
        _ => build_debit(a, stmt, r),
    }
}

// ---------------------------------------------------------------- witnesses (the prover)

const QI: i64 = crate::arith::ntt::Q as i64;

fn le16(p: &[u8]) -> i64 {
    i16::from_le_bytes([p[0], p[1]]) as i64
}

/// `wit_vec`: 2048 coefficients (int8, or int16 LE if wide) into s1[off .. off + 32); the rest of `w`
fn wit_vec<'a>(s1: &mut PolyVec, off: usize, w: &'a [u8], wide: bool) -> &'a [u8] {
    for j in 0..2048 {
        let v = if wide { le16(&w[2 * j..]) } else { w[j] as i8 as i64 };
        set_c(&mut s1[off + j / 64], j % 64, v);
    }
    &w[if wide { 4096 } else { 2048 }..]
}

/// `dec_w`: w_i = centre(v_i - (u^T s)_i), s = s1[0 .. 32)
/// x / d and x % d as Rust's `/` and `%` (truncated, d > 0) by mpn's fixed-step restoring division (C `ct_sdiv`;
/// review E: the witness values are secret, and wasm32 keeps i64.div_s / i64.rem_s even for a constant d)
fn ct_sdiv(x: i64, d: u64) -> (i64, i64) {
    let s = (x >> 63) as u64;
    let mut n = [(x as u64 ^ s).wrapping_sub(s)];
    let q = crate::arith::mpn::div(None, &mut n, &[d]);
    ((q ^ s).wrapping_sub(s) as i64, (n[0] ^ s).wrapping_sub(s) as i64)
}

fn dec_w(u: &mut PolyVec, v: &mut Poly, s1: &mut PolyVec) -> [i64; 16] {
    let mut acc = crate::arith::polyvec::dot(&mut **u, &mut s1.sub(0, K, 1));
    acc.fromcrt();
    // review E: secret (u^T s); reduced and centred without a branch or a division
    core::array::from_fn(|i| {
        let mut w = ct_sdiv(cval(v, i) - cval(&mut acc, i), QI as u64).1;
        w -= QI & (((QI - 1) / 2 - w) >> 63);
        w += QI & ((w + (QI - 1) / 2) >> 63);
        w
    })
}

/// `debit_witness` (R_TX, R_TX0, R_BURN, R_TXM; pqz.h's layout) into s1, with M_i, e_T (decrypting T with s_f), the
/// carries and the bits; false if inconsistent or out of range
fn debit_witness(t: &mut Pub, w: &[u8], s1: &mut PolyVec, r: &Rel) -> Result<bool, Error> {
    let h = shape_of(r)?;
    let (l, ne2) = (h.legs, h.legs + 1 + h.aud * h.legs);
    let mut p = wit_vec(s1, 0, w, false);
    p = wit_vec(s1, 32, p, true);
    for g in 0..h.groups {
        p = wit_vec(s1, 64 + 64 * g, p, false);
        p = wit_vec(s1, 96 + 64 * g, p, true);
    }
    for i in 0..ne2 {
        for j in 0..16 {
            set_c(&mut s1[h.e + i], j, le16(&p[32 * i + 2 * j..]));
        }
    }
    p = &p[32 * ne2..];
    // the legs' digits (R_BURN: d = digits(amount), public), d'
    let mut d = vec_try(l)?;
    d.resize(l, [0i64; 16]);
    let (mut dsum, mut dp) = ([0i64; 16], [0i64; 16]);
    for i in 0..16 {
        dsum[i] = if h.burn { digit(t.amount, i) } else { 0 };
        for (j, dj) in d.iter_mut().enumerate() {
            dj[i] = p[16 * j + i] as i64;
            dsum[i] += dj[i];
        }
        dp[i] = p[16 * l + i] as i64;
    }
    // decrypt T with s_f: M_i = round(w_i / Delta), e_T = w - Delta M
    let wv = dec_w(&mut t.u, &mut t.v, s1);
    // review E: round half away from zero without a branch
    let mm: [i64; 16] = core::array::from_fn(|i| ct_sdiv(wv[i] + (((DELTA / 2) ^ (wv[i] >> 63)) - (wv[i] >> 63)), DELTA as u64).0);
    let et: [i64; 16] = core::array::from_fn(|i| wv[i] - DELTA * mm[i]);
    // carries: c_i = (M_i + c_{i-1} - d'_i - sum_j d_j,i - f_i) / 16, exact, c_15 = 0
    // review E: the checks run on secret values: collected with '|' (no short-circuit branch), only the verdict
    // (witness consistent; public, the prove fails otherwise) is declassified; the same verdict as early returns
    let mut c = [0i64; 16];
    let mut cprev = 0;
    let mut bad = false;
    for i in 0..16 {
        let s = mm[i] + cprev - dp[i] - dsum[i] - digit(t.fee, i);
        bad |= (s & 15) != 0; // s % 16 != 0
        c[i] = (s + ((s >> 63) & 15)) >> 4; // s / 16 (truncated), no division (review E)
        cprev = c[i];
    }
    bad |= c[15] != 0;
    for i in 0..16 {
        bad |= (dp[i] > 15)
            | (mm[i] < 0)
            | (mm[i] >= 1 << 14)
            | (c[i] < -64)
            | (c[i] >= 1984)
            | (et[i] < -(1 << 24))
            | (et[i] >= 1 << 24);
        for dj in d.iter() {
            bad |= dj[i] > 15;
        }
    }
    let bad = crate::ct::verdict(bad);
    if bad {
        return Ok(false);
    }
    for i in 0..16 {
        let base = [h.dp, h.m, h.c, h.et];
        let vals = [dp[i], mm[i], c[i] + 64, et[i] + (1 << 24)];
        let (widths, n) = ([4, 14, 11, 25], [4, 14, if i < 15 { 11 } else { 0 }, 25]);
        for b in 0..25 {
            for k in 0..4 {
                if b < n[k] {
                    let sl = slot(base[k], widths[k], i, b);
                    set_c(&mut s1[h.bits + sl / 64], sl % 64, (vals[k] >> b) & 1);
                }
            }
            for (j, dj) in d.iter().enumerate().take(if b < 4 { l } else { 0 }) {
                let sl = slot(64 * j, 4, i, b);
                set_c(&mut s1[h.bits + sl / 64], sl % 64, (dj[i] >> b) & 1);
            }
        }
    }
    Ok(true)
}

/// `dr_witness`: s, e and the bits of e'_i + 2^24, e'_i = centre(v_i - (u^T s)_i) - Delta d_i
fn dr_witness(t: &mut Pub, w: &[u8], s1: &mut PolyVec) -> bool {
    let p = wit_vec(s1, 0, w, false);
    wit_vec(s1, 32, p, true);
    let wv = dec_w(&mut t.u, &mut t.v, s1);
    let mut bad = false;
    for (i, &wi) in wv.iter().enumerate() {
        let e = wi - DELTA * digit(t.amount, i);
        bad |= (e + (1 << 24)) as u64 >= 1 << 25; // e outside [-2^24, 2^24); review E: no branch on the secret e
        for b in 0..25 {
            set_c(&mut s1[64 + (25 * i + b) / 64], (25 * i + b) % 64, ((e + (1 << 24)) >> b) & 1);
        }
    }
    let bad = crate::ct::verdict(bad); // review E: the verdict is public (prove fails)
    !bad // bad: not an encryption of amount under this key
}

/// `set_upsilon`: the slack polys upsilon_z = binexp(B_z^2 - ||x_z||^2) of the exact-l2 blocks (s1 slots [st, st +
/// ln)); false if a block is above its bound
fn set_upsilon(p: &Tbox, s1: &mut PolyVec, blocks: &[(usize, usize)]) -> bool {
    let m1 = (p.tbox.m1 - p.z) as usize;
    for (z, &(st, ln)) in blocks.iter().enumerate() {
        let mut n2 = 0i64;
        for x in &mut s1[st..st + ln] {
            n2 += (0..D).map(|k| cval(x, k) * cval(x, k)).sum::<i64>();
        }
        let mut d = Int::new(2);
        d.set(&p.l2bsqr[z]);
        d.sub(&{ d }, &Int::from_i64(2, n2));
        let above = d.sgn() < 0;
        let above = crate::ct::verdict(above); // review E: the witness-valid verdict is public (prove fails)
        if above {
            return false; // witness above its norm bound
        }
        Poly::binexp(Some(&mut s1[m1 + z]), None, &d);
    }
    true
}

/// `witness`: the witness of relation r into s1, then the l2 slack; false if malformed, inconsistent or above a bound
fn witness(t: &mut Pub, r: &Rel, wit: &[u8], s1: &mut PolyVec) -> Result<bool, Error> {
    const REG_WIT: usize = 2048 + 4096;
    let (reg, ds) = ([(0, 32), (32, 32)], [(0, 32), (32, 32), (64, 1)]);
    let h;
    let blocks: &[(usize, usize)] = match r.code {
        3 => {
            if wit.len() != REG_WIT {
                return Ok(false);
            }
            let p = wit_vec(s1, 0, wit, false);
            wit_vec(s1, 32, p, true);
            &reg
        }
        4 => {
            if wit.len() != REG_WIT + 32 {
                return Ok(false);
            }
            let p = wit_vec(s1, 0, wit, false);
            let p = wit_vec(s1, 32, p, true);
            for j in 0..16 {
                set_c(&mut s1[64], j, le16(&p[2 * j..]));
            }
            &ds
        }
        5 => {
            if wit.len() != REG_WIT || !dr_witness(t, wit, s1) {
                return Ok(false);
            }
            &reg
        }
        _ => {
            // the debit relations (R_TX, R_TX0, R_BURN, R_TXM): one l2 slack per block
            h = shape_of(r)?;
            let want = (1 + h.groups) * (2048 + 4096) + 32 * (h.legs + 1 + h.aud * h.legs) + 16 * h.legs + 16;
            if wit.len() != want || !debit_witness(t, wit, s1, r)? {
                return Ok(false);
            }
            &h.blk
        }
    };
    Ok(set_upsilon(r.p, s1, blocks))
}

/// `pqz_prover_seeds` (CTR-PQZ-19, P6e D6): ex[0..32) seeds s2, ex[32..64) every mask of the toolbox proof; each =
/// SHAKE128(tag || rnd32 || wh || hash0), tags "SCAAS-PQZ-PROVER-RND-V2" / "...-SUB-V2", wh = SHAKE128(
/// "SCAAS-PQZ-PROVER-WIT-V2" || wit)[0..32)
fn prover_seeds(rnd32: &[u8; 32], wit: &[u8], hash0: &[u8; 32]) -> (Wiped<[u8; 32]>, Wiped<[u8; 32]>) {
    let mut wh = Wiped([0u8; 32]);
    shake128(&[b"SCAAS-PQZ-PROVER-WIT-V2", wit]).squeeze(&mut *wh);
    let (mut a, mut b) = (Wiped([0u8; 32]), Wiped([0u8; 32]));
    shake128(&[b"SCAAS-PQZ-PROVER-RND-V2", rnd32, &*wh, hash0]).squeeze(&mut *a);
    shake128(&[b"SCAAS-PQZ-PROVER-SUB-V2", rnd32, &*wh, hash0]).squeeze(&mut *b);
    (a, b)
}

impl Ctx {
    /// A and relation ri's keys, built at first use
    pub(crate) fn rel_state(&mut self, ri: usize) -> Result<(&mut [PolyMat; 3], &mut PolyMat), Error> {
        if self.keys[ri].is_none() {
            self.keys[ri] = Some(rel_keys(&RELS[ri])?);
        }
        let a = a_of(&mut self.a)?;
        match &mut self.keys[ri] {
            Some(k) => Ok((k, a)),
            None => Err(Error::Internal),
        }
    }

    /// `pqz_verify`: Ok(true) = 1, Ok(false) = 0; an allocation failure is `Err(Error::Memory)` (C: arena
    /// exhaustion, a node fault in pqz-ffi), which `Ctx::verify` folds into false and `Ctx::try_verify` keeps
    pub(crate) fn verify_rel(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, Error> {
        // the exact statement length (rel_of) and the proof cap before the caches and the hash (fix A)
        let Some(ri) = rel_of(op, stmt) else { return Ok(false) };
        if proof.len() > MAX_PROOF {
            return Ok(false);
        }
        let r = &RELS[ri];
        let (keys, a) = self.rel_state(ri)?;
        let h = stmt_hash(op, stmt)?;
        let Some((mut s, _)) = build(a, r, stmt)? else { return Ok(false) };
        // a proof that does not decode is invalid; running out of memory while decoding is not (Error::Memory)
        let mut f = match decode_proof(r.p, proof) {
            Err(Error::Memory) => return Err(Error::Memory),
            Err(_) => return Ok(false),
            Ok(f) => f,
        };
        let mut hash = h;
        abdlop::hashcomm(&mut hash, &mut f.t_a1, &mut f.t_b, r.p.tbox)?;
        tbox::verify(&mut hash, &mut f, keys, &mut s)
    }

    /// `pqz_prove` + `do_prove`: `Error::Input` for an unknown relation, a malformed statement or witness (also one
    /// inconsistent with the statement, or above a norm bound), an encoding over MAX_PROOF bytes, and on wasm32 an
    /// op 7 statement with more than `WASM_MAX_LEGS` legs
    pub(crate) fn prove_rel(&mut self, op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let ri = rel_of(op, stmt).ok_or(Error::Input)?;
        let r = &RELS[ri];
        if cfg!(target_arch = "wasm32") && r.op == crate::OP_TRANSFER_MULTI && r.legs > crate::WASM_MAX_LEGS {
            return Err(Error::Input);
        }
        let tb = r.p.tbox;
        let (keys, a) = self.rel_state(ri)?;
        let hash0 = stmt_hash(op, stmt)?;
        let mut f = ProofParts::new(r.p)?;
        // do_prove; the seeds, s1, m, s2 and t_a2 are cleared on every path out, `?` included (C: explicit_bzero of
        // ex; Wiped, fix B)
        let mut s1 = Wiped(PolyVec::new(tb.m1 as usize)?);
        let mut m = Wiped(PolyVec::new((tb.l + tb.lext) as usize)?);
        let Some((mut s, mut t)) = build(a, r, stmt)? else { return Err(Error::Input) };
        let mut s2 = Wiped(PolyVec::new(tb.m2 as usize)?);
        if !witness(&mut t, r, wit, &mut s1)? {
            return Err(Error::Input);
        }
        let (ex0, ex1) = prover_seeds(rnd32, wit, &hash0);
        polyvec_urandom_bnd(&mut **s2, &Int::from_i64(1, -tb.nu), &Int::from_i64(1, tb.nu), &ex0, 0)?;
        {
            // t_a2 freed before the encoding, as before (the memory peaks)
            let mut t_a2 = Wiped(PolyVec::new(tb.kmsis as usize)?);
            let mut hash = hash0;
            abdlop::commit(&mut f.t_a1, &mut t_a2, &mut s1, &mut s2, keys, tb)?;
            crate::ct::public(&f.t_a1[..]); // review E: the commitment, hashed and sent (t_a2 stays secret)
            crate::ct::public(&f.t_b[..]);
            abdlop::hashcomm(&mut hash, &mut f.t_a1, &mut f.t_b, tb)?;
            tbox::prove(&mut hash, &mut f, &mut s1, &mut m, &mut s2, &mut t_a2, keys, &mut s, &ex1)?;
        }
        // cap = MAX_PROOF: an over-length proof is Input before any encoder assert (C: encproof's cap, then len >
        // PQZ_MAX_PROOF)
        encode_proof(&f, MAX_PROOF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::ntt::Q;
    use alloc::vec;

    /// an all-zero statement of relation ri with the header words its parser requires (auditorOn, M)
    fn zero_stmt(r: &Rel) -> Vec<u8> {
        let mut st = vec![0u8; stmt_bytes(r)];
        if r.op == crate::OP_TRANSFER || r.op == crate::OP_TRANSFER_MULTI {
            st[HDR_AUDITOR_ON + 31] = r.aud as u8;
        }
        if r.op == crate::OP_TRANSFER_MULTI {
            st[HDR_LEGS + 31] = r.legs as u8;
        }
        st
    }

    /// fix A (review G-3 / H-4): a statement one byte longer or shorter than its relation's, and a proof over the
    /// cap, are refused before A, the relation keys or the specialised verifier's tables are built (so before the
    /// statement is hashed): every cache of the `Ctx` stays empty
    #[test]
    fn bad_length_refused_before_caches() {
        let mut ctx = Ctx::new();
        let big = vec![0u8; MAX_PROOF + 1];
        for r in RELS.iter() {
            let st = zero_stmt(r);
            let mut long = st.clone();
            long.push(0);
            for bad in [&long[..], &st[..st.len() - 1]] {
                assert!(rel_of(r.op, bad).is_none(), "{} len {}", r.name, bad.len());
                assert_eq!(ctx.try_verify(r.op, bad, &[]), Ok(false), "{}", r.name);
                assert_eq!(ctx.prove(r.op, bad, &[], &[0; 32]), Err(Error::Input), "{}", r.name);
                #[cfg(feature = "sv")]
                assert_eq!(ctx.try_verify_fast(r.op, bad, &[]), Ok(false), "{}", r.name);
            }
            assert_eq!(ctx.try_verify(r.op, &st, &big), Ok(false), "{} proof cap", r.name);
            #[cfg(feature = "sv")]
            assert_eq!(ctx.try_verify_fast(r.op, &st, &big), Ok(false), "{} proof cap", r.name);
        }
        assert!(ctx.a.is_none() && ctx.keys.iter().all(Option::is_none));
        #[cfg(feature = "sv")]
        assert!(ctx.sv.is_none() && ctx.svrel.iter().all(Option::is_none));
    }

    /// `build` refuses one non-canonical coefficient (q, `rd_poly`) and one non-canonical header word (a high byte
    /// set, `rd_word64`) per parser, and `prove` gives `Error::Input` for them (tests/vectors.rs
    /// `prove_refuses_noncanonical_statement` shows it is the statement parser that refuses)
    #[test]
    fn build_refuses_noncanonical() {
        let mut a0 = None;
        let a = a_of(&mut a0).unwrap();
        let mut ctx = Ctx::new();
        let cases = [
            (0, PREFIX_BYTES + 32, None),
            (1, HEADER_BYTES, Some(HDR_FEE)),
            (2, HEADER_BYTES + PV, Some(HDR_AUDITOR_ON)),
            (3, HEADER_BYTES, Some(HDR_AMOUNT)),
            (4, DISC_PK, Some(DISC_AMOUNT)),
            (5, DISC_PK + PV, Some(DISC_AMOUNT)),
            (TXM0 + 1, HEADER_BYTES, Some(HDR_LEGS)),
        ];
        for (ri, coef, word) in cases {
            let r = &RELS[ri];
            let st = zero_stmt(r);
            assert!(build(a, r, &st).unwrap().is_some(), "{}", r.name);
            let mut bad = st.clone();
            bad[coef..coef + 8].copy_from_slice(&Q.to_be_bytes());
            assert!(build(a, r, &bad).unwrap().is_none(), "{} coefficient", r.name);
            assert_eq!(ctx.prove(r.op, &bad, &[], &[0; 32]), Err(Error::Input), "{} coefficient", r.name);
            if let Some(w) = word {
                let mut bad = st;
                bad[w] = 1;
                assert!(build(a, r, &bad).unwrap().is_none(), "{} word", r.name);
                assert_eq!(ctx.prove(r.op, &bad, &[], &[0; 32]), Err(Error::Input), "{} word", r.name);
            }
        }
    }
}
