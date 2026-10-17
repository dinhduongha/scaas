//! `pqz_rel.c`: the relation table (the one table of the crate), statement parsing and the relation builders
//! (R_REG, R_TX / R_TX0 / R_BURN / R_TXM, R_DS, R_DR as toolbox statements), the ABDLOP keys per relation, the
//! statement digest and `pqz_verify`'s dispatch (op, statement length, the R_TXM header words M / auditorOn).
//!
//! What C keeps in static storage (A, the keys of each relation, built at first use) lives in the caller's [`Ctx`].
use crate::arith::int::Int;
use crate::arith::poly::Poly;
use crate::arith::polymat::{Pm, PolyMat};
use crate::arith::polyvec::PolyVec;
use crate::arith::spoly::Sparse;
use crate::coder::decode_proof;
use crate::keys::{be8, expand_a, rd_poly, rd_polyvec};
use crate::params::{self, Tbox};
use crate::proof::tbox::{self, Statement};
use crate::proof::{abdlop, Eq};
use crate::rand::shake::shake128;
use crate::{Ctx, Error, HEADER_BYTES, PREFIX_BYTES, POLYVEC_BYTES as PV, V_BYTES};
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
const DISC_AMOUNT: usize = PREFIX_BYTES + 5 * 32;
const DISC_PK: usize = DISC_AMOUNT + 64;
pub(crate) const DISC_STMT: usize = DISC_PK + 2 * PV + V_BYTES;
const HDR_FEE: usize = 256;
const HDR_AMOUNT: usize = 288;
const HDR_LEGS: usize = 320;
const HDR_AUDITOR_ON: usize = 448;

const fn groups(m: usize) -> usize {
    m.div_ceil(4)
}

/// `PQZ_TXM_STMT_BYTES (m, a)`
pub(crate) const fn txm_stmt(m: usize, a: usize) -> usize {
    HEADER_BYTES + (1 + m + a) * PV + (PV + V_BYTES) + groups(m) * PV + (m + 1 + a * m) * V_BYTES
}

/// `rd_word64`: a be32 word that must be < 2^64
fn word64(p: &[u8]) -> (u64, bool) {
    (be8(&p[24..]), p[..24].iter().all(|&b| b == 0))
}

/// `rel_of`: the relation of op (op 1: R_TX0 by the 66,560-byte length, else R_TX; op 7 by its header words)
fn rel_of(op: u8, stmt: &[u8]) -> Option<usize> {
    Some(match op {
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
    })
}

/// `pqz_stmt_hash`: SHAKE128("SCAAS-PQZ-TRANSCRIPT-V1" || op || be32(len) || stmt)
pub(crate) fn stmt_hash(op: u8, stmt: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    shake128(&[b"SCAAS-PQZ-TRANSCRIPT-V1", &[op], &(stmt.len() as u32).to_be_bytes(), stmt]).squeeze(&mut h);
    h
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

/// R_REG: prefix || message || pk; pk = A s + e
fn build_reg(a: &mut PolyMat, stmt: &[u8]) -> Result<Option<Statement>, Error> {
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
    Ok(Some(statement(s, es, None, new_sel(1, 64, 0)?)))
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
fn build_debit(a: &mut PolyMat, stmt: &[u8], r: &Rel) -> Result<Option<Statement>, Error> {
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
    Ok(Some(statement(s, es, Some(ps), ds)))
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
fn build_ds(a: &mut PolyMat, stmt: &[u8]) -> Result<Option<Statement>, Error> {
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
    Ok(Some(statement(s, es, None, new_sel(1, 65, 64)?)))
}

/// R_DR: pk = A s + e; (u^T s)_i + (e'_i + 2^24) - 2^24 + Delta d_i - v_i = 0
fn build_dr(a: &mut PolyMat, stmt: &[u8]) -> Result<Option<Statement>, Error> {
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
    Ok(Some(statement(s, es, Some(new_sel(7, 71, 64)?), new_sel(1, 71, 0)?)))
}

/// `build`: the statement of relation r (its length checked); `None` if malformed
fn build(a: &mut PolyMat, r: &Rel, stmt: &[u8]) -> Result<Option<Statement>, Error> {
    let want = match r.code {
        3 => REG_STMT,
        1 => TX_STMT,
        0x81 => TX0_STMT,
        2 => BURN_STMT,
        4 | 5 => DISC_STMT,
        _ => txm_stmt(r.legs, r.aud),
    };
    if stmt.len() != want {
        return Ok(None);
    }
    match r.code {
        3 => build_reg(a, stmt),
        4 => build_ds(a, stmt),
        5 => build_dr(a, stmt),
        _ => build_debit(a, stmt, r),
    }
}

impl Ctx {
    /// `pqz_verify`: Ok(true) = 1; every failure (also an allocation failure, as C's arena) is 0
    pub(crate) fn verify_rel(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, Error> {
        let Some(ri) = rel_of(op, stmt) else { return Ok(false) };
        let r = &RELS[ri];
        if self.keys[ri].is_none() {
            self.keys[ri] = Some(rel_keys(r)?);
        }
        if self.a.is_none() {
            self.a = Some(expand_a()?);
        }
        let (Some(keys), Some(a)) = (&mut self.keys[ri], &mut self.a) else { return Err(Error::Internal) };
        let h = stmt_hash(op, stmt);
        let Some(mut s) = build(a, r, stmt)? else { return Ok(false) };
        let Ok(mut f) = decode_proof(r.p, proof) else { return Ok(false) };
        let mut hash = h;
        abdlop::hashcomm(&mut hash, &mut f.t_a1, &mut f.t_b, r.p.tbox)?;
        tbox::verify(&mut hash, &mut f, keys, &mut s)
    }
}
