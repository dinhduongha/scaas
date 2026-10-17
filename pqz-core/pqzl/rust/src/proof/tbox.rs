//! `lnp-tbox.c`: `lnp_tbox_prove` (with `_lnp_tbox_compute_z34`, `__evaleq`, `__check_coeff0`) and `lnp_tbox_verify`
//! (with `_lnp_tbox_check_z34`), and the Schwartz–Zippel accumulation of the evaluation equations both run
//! (`__schwartz_zippel_accumulate*`, `_auto`, the beta3 / beta4 / upsilon / binary / exact-l2 / z4 / z3 equations),
//! including the fork's fixes: P6-SZ (the full lambda x M challenge matrix, issue 24) and P6-L2 (one domain per
//! exact-l2 equation, issue 25).
//!
//! The forms `pqz_rel.c` passes only (module doc of `proof`): `tbox->l == 0`, `Em = Pm = Dm = v = f = u = NULL`.
//! `Es[i]` (i < Z) and `Ds` are always given, `Ps` only with binary witness parts. Every equation temporary C keeps
//! across equations (`R2t`, `r1t`, `r0t`) is fully rewritten before each use, so fresh ones are used here. The
//! prover's invariant checks (`__check_coeff0` and the h_i asserts; ASSERT is on in every C build) are kept, with
//! their domain changes: a failed one is `Error::Internal`, C's sticky error.
use super::quad::{self, Opening};
use super::{diag, hash2, Coder, Eq};
use crate::arith::int::{Int, IntVec};
use crate::arith::ntt::{D, Q};
use crate::arith::poly::Poly;
use crate::arith::polymat::{self, Pm, PmRef, PolyMat};
use crate::arith::polyvec::{self, Pv, PvRef, PolyVec};
use crate::arith::spoly::Sparse;
use crate::coder::ProofParts;
use crate::params::{Abdlop, Tbox};
use crate::rand::brandom::brandom;
use crate::rand::grandom::polyvec_grandom;
use crate::rand::rejection::{rej_bimodal, REJ_MAX};
use crate::rand::rng::Rng;
use crate::rand::shake::shake128;
use crate::rand::urandom::urandom_i64;
use crate::Error;
use alloc::vec::Vec;

/// The relation's inputs to the toolbox (`pqz_rel.c`'s `sys_t`): N R_q-linear equations, M evaluation equations
/// (both without quadratic part), the exact-l2 selections `es` (Z of them), the binary selection `ps`, the
/// approximate l_inf selection `ds`.
pub(crate) struct Statement {
    pub(crate) quad: Vec<Eq>,
    pub(crate) eval: Vec<Eq>,
    pub(crate) es: Vec<PolyMat>,
    pub(crate) ps: Option<PolyMat>,
    pub(crate) ds: PolyMat,
}

/// one Schwartz–Zippel accumulator (C's `R2prime_sz[i]`, `r1prime_sz[i]`, `r0prime_sz[i]`)
struct Acc {
    r2: Sparse,
    r1: Sparse,
    r0: Poly,
}

fn vec_of<T>(n: usize, f: impl FnMut(usize) -> T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Memory)?;
    v.extend((0..n).map(f));
    Ok(v)
}

/// `n` uniform values mod q from (seed, dom) (`intvec_urandom (V, q, log2q, seed, dom)`, `dom` not shifted)
fn urandom_q(n: usize, seed: &[u8; 32], dom: u64) -> Result<Vec<i64>, Error> {
    let mut v = vec_of(n, |_| 0i64)?;
    urandom_i64(&mut v, Q as i64, 42, seed, dom)?;
    Ok(v)
}

/// `intmat_urandom (V, q, log2q, seed, dom)`, rows x 256: row i from (seed, dom << 32 | 256 i)
fn intmat_urandom(rows: usize, seed: &[u8; 32], dom: u32) -> Result<Vec<Vec<i64>>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(rows).map_err(|_| Error::Memory)?;
    for i in 0..rows {
        v.push(urandom_q(256, seed, (dom as u64) << 32 | (i * 256) as u32 as u64)?);
    }
    Ok(v)
}

fn int(v: i64) -> Int {
    Int::from_i64(1, v)
}

/// `__schwartz_zippel_accumulate` (`v` = the challenges) / `__schwartz_zippel_accumulate_` (`v = None`: the
/// equations are pre-multiplied): acc += sum_j v_j eqs_j, reduced mod q
fn accumulate(acc: &mut Acc, eqs: &mut [Eq], v: Option<&[i64]>, qe: &Abdlop) -> Result<(), Error> {
    let n = 2 * (qe.m1 + qe.l) as usize;
    let (mut t0, mut t1, mut t2) = (Sparse::new_mat(n, n, diag(n)), Sparse::new_mat(n, n, diag(n)), Sparse::new_mat(n, n, diag(n)));
    Sparse::set(&mut t0, &acc.r2)?;
    for (j, e) in eqs.iter_mut().enumerate() {
        if let Some(r2) = &mut e.r2 {
            r2.fromcrt();
            match v {
                Some(v) => {
                    Sparse::scale(&mut t1, &int(v[j]), r2)?;
                    Sparse::add(&mut t2, &mut t0, &mut t1, false)?;
                }
                None => Sparse::add(&mut t2, &mut t0, r2, false)?,
            }
            Sparse::swap(&mut t0, &mut t2);
        }
    }
    Sparse::mod_(&mut acc.r2, &mut t0)?;
    let (mut u0, mut u1, mut u2) = (Sparse::new_vec(n), Sparse::new_vec(n), Sparse::new_vec(n));
    Sparse::set(&mut u0, &acc.r1)?;
    for (j, e) in eqs.iter_mut().enumerate() {
        if let Some(r1) = &mut e.r1 {
            r1.fromcrt();
            match v {
                Some(v) => {
                    Sparse::scale(&mut u1, &int(v[j]), r1)?;
                    Sparse::add(&mut u2, &mut u0, &mut u1, false)?;
                }
                None => Sparse::add(&mut u2, &mut u0, r1, false)?,
            }
            Sparse::swap(&mut u0, &mut u2);
        }
    }
    Sparse::mod_(&mut acc.r1, &mut u0)?;
    for (j, e) in eqs.iter_mut().enumerate() {
        if let Some(r0) = &mut e.r0 {
            r0.fromcrt();
            match v {
                Some(v) => acc.r0.addscale(&int(v[j]), r0, false),
                None => acc.r0.add_assign(r0, false),
            }
        }
    }
    acc.r0 = Poly::mod_(&mut acc.r0);
    Ok(())
}

/// `__schwartz_zippel_accumulate2` (P6-SZ): Gamma = lambda x M uniform from (seed, dom); rows 2i / 2i + 1 into the
/// accumulator pair i
fn accumulate2(a1: &mut [Acc], a2: &mut [Acc], eqs: &mut [Eq], seed: &[u8; 32], dom: u32, qe: &Abdlop) -> Result<(), Error> {
    let m = eqs.len();
    let v = urandom_q(2 * a1.len() * m, seed, dom as u64)?;
    for i in 0..a1.len() {
        accumulate(&mut a1[i], eqs, Some(&v[2 * i * m..(2 * i + 1) * m]), qe)?;
        accumulate(&mut a2[i], eqs, Some(&v[(2 * i + 1) * m..(2 * i + 2) * m]), qe)?;
    }
    Ok(())
}

/// one equation from its parts
fn eq(r2: Option<Sparse>, r1: Option<Sparse>, r0: Option<Poly>) -> [Eq; 1] {
    [Eq { r2, r1, r0 }]
}

/// a zero poly with coefficient `k` = `c`
fn mono(k: usize, c: &Int) -> Poly {
    let mut p = Poly::ZERO;
    p.set_coeff(k, c);
    p
}

/// `__shuffleautovecsparse`: (a, b) -> auto((b, a)) per pair of entries
fn shuffle_vec(r: &mut Sparse) -> Result<(), Error> {
    for i in 0..r.nelems() {
        r.get_elem(i).auto_self();
        let e = r.elem(i);
        r.set_elem_(i, e ^ 1); // even +1, odd -1
    }
    r.set_sorted(false);
    r.sort()
}

/// `__shuffleauto2x2submatssparse`: [[a, b], [c, d]] -> auto([[d, c], [b, a]]) per 2x2 block on or above the
/// diagonal, kept upper triangular
fn shuffle_mat(a: &mut Sparse) -> Result<(), Error> {
    if !a.is_upperdiag() {
        return Err(Error::Internal);
    }
    for i in 0..a.nelems() {
        let (r, c) = (a.row(i), a.col(i));
        let (nr, nc) = match (r % 2, c % 2) {
            (0, 0) => (r + 1, c + 1),
            (1, 1) => (r - 1, c - 1),
            (1, 0) => (r - 1, c + 1),
            _ if r + 1 > c - 1 => (r, c),
            _ => (r + 1, c - 1),
        };
        a.set_row(i, nr);
        a.set_col(i, nc);
        a.get_elem(i).auto_self();
    }
    a.set_sorted(false);
    a.sort()?;
    if !a.is_upperdiag() {
        return Err(Error::Internal);
    }
    Ok(())
}

/// `__schwartz_zippel_auto`: acc = (acc + U o(acc) U + (acc2 + U o(acc2) U) X^(d/2)) / 2
fn sz_auto(a: &mut Acc, b: &mut Acc, qe: &Abdlop) -> Result<(), Error> {
    let n = 2 * (qe.m1 + qe.l) as usize;
    let inv2 = &qe.ring.inv2;
    let mk = || Sparse::new_mat(n, n, diag(n));
    let (mut t0, mut t1, mut t2) = (mk(), mk(), mk());
    a.r2.fromcrt();
    b.r2.fromcrt();
    Sparse::set(&mut t0, &a.r2)?;
    shuffle_mat(&mut t0)?;
    Sparse::add(&mut t1, &mut a.r2, &mut t0, false)?;
    Sparse::set(&mut t0, &b.r2)?;
    Sparse::lrot(&mut t2, &mut t0, D / 2)?;
    Sparse::add(&mut a.r2, &mut t1, &mut t2, false)?;
    Sparse::set(&mut t0, &b.r2)?;
    shuffle_mat(&mut t0)?;
    Sparse::lrot(&mut t1, &mut t0, D / 2)?;
    Sparse::add(&mut t0, &mut a.r2, &mut t1, false)?;
    Sparse::scale(&mut a.r2, inv2, &mut t0)?;

    let (mut u0, mut u1, mut u2) = (Sparse::new_vec(n), Sparse::new_vec(n), Sparse::new_vec(n));
    a.r1.fromcrt();
    b.r1.fromcrt();
    Sparse::set(&mut u0, &a.r1)?;
    shuffle_vec(&mut u0)?;
    Sparse::add(&mut u1, &mut a.r1, &mut u0, false)?;
    Sparse::set(&mut u0, &b.r1)?;
    Sparse::lrot(&mut u2, &mut u0, D / 2)?;
    Sparse::add(&mut a.r1, &mut u1, &mut u2, false)?;
    Sparse::set(&mut u0, &b.r1)?;
    shuffle_vec(&mut u0)?;
    Sparse::lrot(&mut u1, &mut u0, D / 2)?;
    Sparse::add(&mut u0, &mut a.r1, &mut u1, false)?;
    Sparse::scale(&mut a.r1, inv2, &mut u0)?;

    a.r0.fromcrt();
    b.r0.fromcrt();
    let mut t = Poly::auto(&mut a.r0);
    a.r0.add_assign(&mut t, false);
    let mut t = Poly::lrot(&mut b.r0, D / 2);
    a.r0.add_assign(&mut t, false);
    let mut t = Poly::auto(&mut b.r0);
    let mut t = Poly::lrot(&mut t, D / 2);
    a.r0.add_assign(&mut t, false);
    a.r0 = Poly::scale(inv2, &mut a.r0);
    Ok(())
}

/// `_pqz_zero_cols`: column k < n of `a` is zero (public data)
fn zero_cols(a: &PolyMat, n: usize) -> Result<Vec<bool>, Error> {
    vec_of(n, |k| (0..a.nrows()).all(|i| a.get(i, k).is_zero_pub()))
}

/// `_pqz_dot_pub`: polyvec_dot skipping products with a zero poly (NTT domain, as polyvec_dot leaves it)
fn dot_pub<A: Pv + ?Sized, B: Pv + ?Sized>(a: &mut A, b: &mut B) -> Poly {
    let mut r = Poly { crt: true, ..Poly::ZERO };
    for i in 0..a.len() {
        if a.get(i).is_zero_pub() || b.get(i).is_zero_pub() {
            continue;
        }
        r.add_assign(&mut Poly::mul(a.at(i), b.at(i)), true);
    }
    r
}

/// `_diag`: (min, max)
fn ud(r: usize, c: usize) -> (usize, usize) {
    if r > c { (c, r) } else { (r, c) }
}

/// The Gram part o(s1)^T o(P)^T P s1 of a selection `p` (and its automorphism `op`) into `r2`, column pairs with a
/// zero column skipped (the bin and l2 equations)
fn gram(r2: &mut Sparse, p: &mut PolyMat, op: &mut PolyMat, zs: &[bool]) -> Result<(), Error> {
    let m1 = zs.len();
    for k in 0..m1 {
        for j in 0..m1 {
            if !(zs[k] | zs[j]) {
                let (row, col) = ud(2 * k + 1, 2 * j);
                *r2.insert_rc(row, col)? = dot_pub(&mut op.col(k), &mut p.col(j));
            }
        }
    }
    Ok(())
}

/// `_lnp_tbox_check_z34`: the norm bounds on z3 (l2) and z4 (l_inf), then hash = H(hash || ty3, ty4, tbeta)
fn check_z34(hash: &mut [u8; 32], z3: &mut PolyVec, z4: &mut PolyVec, t_b: &mut PolyVec, p: &Tbox) -> Result<bool, Error> {
    let tb = p.tbox;
    let (q, log2q) = (&tb.ring.q, tb.ring.log2q);
    let (l, w) = (tb.l as usize, 256 / D);
    let mut enc = Coder::new();
    let mut loff = 0;
    let mut sections = Vec::new();
    sections.try_reserve_exact(3).map_err(|_| Error::Memory)?;
    if p.nex > 0 {
        sections.push((l + loff, w));
        loff += w;
    }
    if p.nprime > 0 {
        sections.push((l + loff, w));
        loff += w;
    }
    sections.push((l + loff, 1));
    for &(off, n) in &sections {
        let mut t = t_b.sub(off, n, 1);
        polyvec::mod_self(&mut t);
        polyvec::redp_self(&mut t);
    }
    if p.nex > 0 {
        polyvec::fromcrt(&mut **z3);
        if polyvec::l2sqr(&mut **z3).gt(&p.bz3sqr) {
            return Ok(false);
        }
    }
    if p.nprime > 0 {
        polyvec::fromcrt(&mut **z4);
        if polyvec::linf(&mut **z4).gt(&p.bz4) {
            return Ok(false);
        }
    }
    for &(off, n) in &sections {
        enc.urandom(&mut t_b.sub(off, n, 1), q, log2q)?;
    }
    *hash = hash2(hash, &enc.end()?);
    Ok(true)
}

/// the coefficients of the polys `v` (z3 or z4: 256 of them)
fn coeffs(v: &mut PolyVec) -> Vec<Int> {
    let mut r = Vec::new();
    for p in v.iter_mut() {
        p.fromcrt();
        r.extend((0..D).map(|j| p.c(j)));
    }
    r
}

/// -(<z, V_k> mod q), centred (`intvec_dot`, `int_mod`, `int_neg_self`, `int_redc`)
fn r0_of(z: &[Int], vk: &[i64]) -> Poly {
    let mut t = Int::new(2);
    for (zj, &v) in z.iter().zip(vk) {
        t.addmul(zj, &int(v));
    }
    let mut c = Int::new(1);
    c.mod_(&t, &crate::arith::poly::RING_Q);
    c.neg_self();
    c.redc(&{ c }, &crate::arith::poly::RING_Q);
    mono(0, &c)
}

/// vR = V R mod q as a lambda x ncols/d matrix of polys (R's row i from `_brandom (ncols, 1, seed, roff + i)`);
/// |entries| <= 256 q < 2^51 before the reduction, so i64 holds them (C: int64 for z3, 2-limb ints for z4, whose
/// sign-magnitude sums equal these, the zero signs normalised by `int_mod`)
fn vr_polys(v: &[Vec<i64>], ncols: usize, seed: &[u8; 32], roff: u64) -> Result<PolyMat, Error> {
    let lambda = v.len();
    let mut vr = vec_of(lambda * ncols, |_| 0i64)?;
    let mut ri = vec_of(ncols, |_| 0i8)?;
    for i in 0..256 {
        brandom(&mut ri, 1, seed, roff + i as u64)?;
        for (k, vk) in v.iter().enumerate() {
            let c = vk[i];
            for (j, &r) in ri.iter().enumerate() {
                vr[k * ncols + j] += r as i64 * c;
            }
        }
    }
    let mut m = PolyMat::new(lambda, ncols / D)?;
    for k in 0..lambda {
        for i in 0..ncols / D {
            m.at(k, i).set_i64(&core::array::from_fn::<i64, D, _>(|j| vr[k * ncols + i * D + j] % Q as i64));
        }
    }
    Ok(m)
}

/// The z4 equations (approximate l_inf proof): per row k of V (lambda x 256), y4 - z4 + beta4 (V R' Ds) s1 = 0,
/// pre-multiplied into accumulator k / 2 of the pair k % 2
#[allow(clippy::too_many_arguments)]
fn sz_z4(a1: &mut [Acc], a2: &mut [Acc], ods: &mut PolyMat, z4: &mut PolyVec, seed: &[u8; 32], dom: u32, p: &Tbox) -> Result<(), Error> {
    let tb = p.tbox;
    let (z, m1) = (p.z as usize, (tb.m1 - p.z) as usize);
    let (loff3, loff4) = (if p.nex > 0 { 256 / D } else { 0 }, if p.nprime > 0 { 256 / D } else { 0 });
    let ibeta = (m1 + z + loff3 + loff4) * 2;
    let iy4 = (m1 + z + loff3) * 2;
    let lambda = p.quad_eval.lambda as usize;
    let inv2 = &tb.ring.inv2;
    let n_ = 2 * (tb.m1 + p.quad_eval.quad_eval.l) as usize;
    let v = intmat_urandom(lambda, seed, dom)?;
    let z4_ = coeffs(z4);
    let mut vrpol = vr_polys(&v, p.nprime as usize * D, seed, 256)?;
    let mut vrds = PolyMat::new(lambda, m1)?;
    for k in 0..lambda {
        polyvec::mul2(&mut vrds.row(k), &mut vrpol.row(k), ods);
    }
    for k in 0..lambda {
        for i in 0..m1 {
            let e = vrds.at(k, i);
            *e = Poly::lrot(e, D / 2);
        }
    }
    for k in 0..lambda {
        let mut r2 = Sparse::new_mat(n_, n_, diag(n_));
        for i in 0..m1 {
            let mut p2 = Poly::scale(inv2, vrds.at(k, i));
            let mut p1 = Poly::neg(&mut p2);
            p1 = Poly::redc(&mut p1);
            *r2.insert_rc(1 + 2 * i, ibeta)? = p1;
            *r2.insert_rc(1 + 2 * i, ibeta + 1)? = p2;
        }
        r2.set_sorted(true);
        let mut r1 = Sparse::new_vec(n_);
        for i in 0..loff4 {
            let mut c = Poly::ZERO;
            for j in 0..D {
                let mut x = int(v[k][i * D + j]);
                x.redc(&{ x }, &tb.ring.q);
                c.put(j, &x);
            }
            *r1.insert_elem(iy4 + 1 + 2 * i)? = c;
        }
        r1.set_sorted(true);
        let mut e = eq(Some(r2), Some(r1), Some(r0_of(&z4_, &v[k])));
        let acc = if k % 2 == 0 { &mut a1[k / 2] } else { &mut a2[k / 2] };
        accumulate(acc, &mut e, None, p.quad_eval.quad_eval)?;
    }
    Ok(())
}

/// The z3 equations (approximate l2 proof of the binary and exact-l2 parts and upsilon): per row k of V,
/// y3 - z3 + beta3 (V R (Ps; Es; upsilon)) s1 = 0, pre-multiplied into accumulator k / 2 of the pair k % 2
#[allow(clippy::too_many_arguments)]
fn sz_z3(
    a1: &mut [Acc],
    a2: &mut [Acc],
    oes: &mut [PolyMat],
    ops: Option<&mut PolyMat>,
    z3: &mut PolyVec,
    seed: &[u8; 32],
    dom: u32,
    p: &Tbox,
) -> Result<(), Error> {
    let tb = p.tbox;
    let (z, m1) = (p.z as usize, (tb.m1 - p.z) as usize);
    let (nex, nbin) = (p.nex as usize, p.nbin as usize);
    let (loff3, loff4) = (if p.nex > 0 { 256 / D } else { 0 }, if p.nprime > 0 { 256 / D } else { 0 });
    let ibeta = (m1 + z + loff3 + loff4) * 2;
    let (iupsilon, iy3) = (2 * m1, (m1 + z) * 2);
    let lambda = p.quad_eval.lambda as usize;
    let inv2 = &tb.ring.inv2;
    let n_ = 2 * (tb.m1 + p.quad_eval.quad_eval.l) as usize;
    let v = intmat_urandom(lambda, seed, dom)?;
    let z3_ = coeffs(z3);
    let mut vrpol = vr_polys(&v, nex * D, seed, 0)?;
    let mut vrps = PolyMat::new(lambda, m1)?;
    let has_ps = ops.is_some();
    if let Some(ops) = ops {
        for k in 0..lambda {
            polyvec::mul2(&mut vrps.row(k), &mut vrpol.row(k).sub(0, nbin, 1), ops);
        }
    }
    let mut vres = Vec::new();
    vres.try_reserve_exact(z).map_err(|_| Error::Memory)?;
    let mut off = nbin;
    for (i, oe) in oes.iter_mut().enumerate() {
        let mut m = PolyMat::new(lambda, m1)?;
        for k in 0..lambda {
            polyvec::mul2(&mut m.row(k), &mut vrpol.row(k).sub(off, p.n[i] as usize, 1), oe);
        }
        off += p.n[i] as usize;
        vres.push(m);
    }
    for k in 0..lambda {
        let mut r2 = Sparse::new_mat(n_, n_, diag(n_));
        for i in 0..m1 {
            let mut p2 = if has_ps { vrps.at(k, i).clone() } else { Poly::ZERO };
            for m in vres.iter_mut() {
                p2.add_assign(m.at(k, i), false);
            }
            p2 = Poly::scale(inv2, &mut p2);
            *r2.insert_rc(1 + 2 * i, ibeta)? = p2.clone();
            *r2.insert_rc(1 + 2 * i, ibeta + 1)? = p2;
        }
        for i in 0..z {
            let p2 = Poly::scale(inv2, vrpol.at(k, nex - z + i));
            *r2.insert_rc(iupsilon + 1 + 2 * i, ibeta)? = p2.clone();
            *r2.insert_rc(iupsilon + 1 + 2 * i, ibeta + 1)? = p2;
        }
        r2.set_sorted(true);
        let mut r1 = Sparse::new_vec(n_);
        for i in 0..loff4 {
            let mut c = Poly::ZERO;
            for j in 0..D {
                let mut x = int(v[k][i * D + j]);
                x.redc(&{ x }, &tb.ring.q);
                c.put(j, &x);
            }
            *r1.insert_elem(iy3 + 1 + 2 * i)? = c;
        }
        // <V R, (f; v)> is 0 (no f, no v): both beta coefficients 0
        *r1.insert_elem(ibeta)? = Poly::ZERO;
        *r1.insert_elem(ibeta + 1)? = Poly::ZERO;
        r1.set_sorted(true);
        let mut e = eq(Some(r2), Some(r1), Some(r0_of(&z3_, &v[k])));
        let acc = if k % 2 == 0 { &mut a1[k / 2] } else { &mut a2[k / 2] };
        accumulate(acc, &mut e, None, p.quad_eval.quad_eval)?;
    }
    Ok(())
}

/// `lnp_tbox_verify` (after `abdlop_hashcomm`): false = reject
/// the automorphisms of the selections (`polymat_auto` of Es, Ds, Ps; the prover computes them first, while the
/// selections are still in the coefficient domain)
struct Autos {
    oes: Vec<PolyMat>,
    ods: PolyMat,
    ops: Option<PolyMat>,
}

fn autos(s: &mut Statement, p: &Tbox) -> Result<Autos, Error> {
    let m1 = (p.tbox.m1 - p.z) as usize;
    let mut oes = Vec::new();
    oes.try_reserve_exact(s.es.len()).map_err(|_| Error::Memory)?;
    for (i, e) in s.es.iter_mut().enumerate() {
        let mut o = PolyMat::new(p.n[i] as usize, m1)?;
        polymat::auto(&mut o, e);
        oes.push(o);
    }
    let mut ods = PolyMat::new(p.nprime as usize, m1)?;
    polymat::auto(&mut ods, &mut s.ds);
    let ops = match &mut s.ps {
        Some(ps) => {
            let mut o = PolyMat::new(p.nbin as usize, m1)?;
            polymat::auto(&mut o, ps);
            Some(o)
        }
        None => None,
    };
    Ok(Autos { oes, ods, ops })
}

/// (np, n_): the quadratic proof's and the evaluation equations' dimension
fn dims(p: &Tbox) -> (usize, usize) {
    let m1 = p.tbox.m1 as usize; // m1 + Z
    (2 * (m1 + p.quad_eval.quad_many.l as usize), 2 * (m1 + p.quad_eval.quad_eval.l as usize))
}

/// the lambda / 2 accumulator pairs (C's typo kept: the second set's r1 keeps nelems_max np)
fn accs(p: &Tbox) -> Result<(Vec<Acc>, Vec<Acc>), Error> {
    let (np, n_) = dims(p);
    let mk = |second: bool| -> Acc {
        let mut r2 = Sparse::new_mat(np, np, diag(np));
        r2.set_nelems_max(diag(n_));
        let mut r1 = Sparse::new_vec(np);
        if !second {
            r1.set_nelems_max(n_);
        }
        Acc { r2, r1, r0: Poly::ZERO }
    };
    let h = p.quad_eval.lambda as usize / 2;
    Ok((vec_of(h, |_| mk(false))?, vec_of(h, |_| mk(true))?))
}

/// beta3^2 = 1, beta4^2 = 1 over R_q in (beta, o(beta))
fn beta_eqs(p: &Tbox) -> Result<[Eq; 2], Error> {
    let (np, _) = dims(p);
    let m1 = p.tbox.m1 as usize;
    let loff = if p.nprime > 0 { 256 / D } else { 0 } + if p.nex > 0 { 256 / D } else { 0 };
    let ibeta = (m1 + p.tbox.l as usize + loff) * 2;
    let inv2 = p.tbox.ring.inv2;
    let beta_eq = |sg: u64| -> Result<Eq, Error> {
        let mut r2 = Sparse::new_mat(np, np, diag(np));
        let mut i4 = p.inv4;
        i4.neg ^= sg;
        *r2.insert_rc(ibeta, ibeta)? = mono(0, &i4);
        *r2.insert_rc(ibeta, ibeta + 1)? = mono(0, &inv2);
        *r2.insert_rc(ibeta + 1, ibeta + 1)? = mono(0, &i4);
        r2.set_sorted(true);
        Ok(Eq { r2: Some(r2), r1: None, r0: Some(mono(0, &int(-1))) })
    };
    Ok([beta_eq(0)?, beta_eq(1)?])
}

/// The Schwartz–Zippel accumulation, prover and verifier alike (C: from `__schwartz_zippel_accumulate2` of the
/// relation's evaluation equations to `__schwartz_zippel_auto`): the relation's equations, then the norm proofs'
/// internal ones (beta3, beta4, upsilon, binary, exact l2 with P6-L2's domain per block, z4, z3)
#[allow(clippy::too_many_arguments)]
fn accumulate_all(
    a1: &mut [Acc],
    a2: &mut [Acc],
    s: &mut Statement,
    au: &mut Autos,
    z3: &mut PolyVec,
    z4: &mut PolyVec,
    hash: &[u8; 32],
    hash0: &[u8; 32],
    p: &Tbox,
) -> Result<(), Error> {
    let tb = p.tbox;
    let qe = p.quad_eval.quad_eval;
    let (z, m1) = (p.z as usize, (tb.m1 - p.z) as usize);
    let (nex, nprime, nbin) = (p.nex as usize, p.nprime as usize, p.nbin as usize);
    let q = &tb.ring.q;
    let inv2 = tb.ring.inv2;
    let (_, n_) = dims(p);
    let loff = if nprime > 0 { 256 / D } else { 0 } + if nex > 0 { 256 / D } else { 0 };
    let ibeta = (m1 + z + tb.l as usize + loff) * 2;
    let mm = s.eval.len() as u32;
    let dd = D as u32;

    if mm > 0 {
        accumulate2(a1, a2, &mut s.eval, hash, 0, qe)?;
    }
    if nex > 0 {
        for i in 1..D {
            let mut r1 = Sparse::new_vec(n_);
            *r1.insert_elem(ibeta)? = mono(i, &inv2);
            *r1.insert_elem(ibeta + 1)? = mono(i, &inv2);
            r1.set_sorted(true);
            accumulate2(a1, a2, &mut eq(None, Some(r1), None), hash, mm + i as u32, qe)?;
        }
    }
    if nprime > 0 {
        let ninv2 = Int::neg_of(&inv2);
        for i in 1..D {
            let mut r1 = Sparse::new_vec(n_);
            let (k, a, b) = if i < D / 2 { (i + D / 2, ninv2, inv2) } else { (i + D / 2 - D, inv2, ninv2) };
            *r1.insert_elem(ibeta)? = mono(k, &a);
            *r1.insert_elem(ibeta + 1)? = mono(k, &b);
            r1.set_sorted(true);
            accumulate2(a1, a2, &mut eq(None, Some(r1), None), hash, mm + dd - 1 + i as u32, qe)?;
        }
    }
    if z > 0 {
        // upsilon binary: <upsilon, upsilon - 1> = 0 over Z
        let mut r2 = Sparse::new_mat(n_, n_, diag(n_));
        let mut r1 = Sparse::new_vec(n_);
        for j in 0..z {
            let iu = (m1 + j) * 2;
            let mut one = Poly::ZERO;
            one.set_one();
            *r2.insert_rc(iu, iu + 1)? = one;
            let mut m1s = Poly::ZERO;
            m1s.set_i64(&[-1; D]);
            *r1.insert_elem(iu + 1)? = m1s;
        }
        r2.set_sorted(true);
        r1.set_sorted(true);
        accumulate2(a1, a2, &mut eq(Some(r2), Some(r1), None), hash, mm + 2 * (dd - 1), qe)?;
    }
    if nbin > 0 {
        // Ps s1 binary: <Ps s1, Ps s1 - 1> = 0 over Z
        let (Some(ps), Some(ops)) = (&mut s.ps, &mut au.ops) else { return Err(Error::Internal) };
        let mut f_ = PolyVec::new(nbin)?;
        for x in f_.iter_mut() {
            x.set_i64(&[-1; D]);
        }
        let mut r2 = Sparse::new_mat(n_, n_, diag(n_));
        let mut r1 = Sparse::new_vec(n_);
        let zs = zero_cols(ps, m1)?;
        for k in 0..m1 {
            for j in 0..m1 {
                if !(zs[k] | zs[j]) {
                    let (row, col) = ud(2 * k + 1, 2 * j);
                    *r2.insert_rc(row, col)? = dot_pub(&mut ops.col(k), &mut ps.col(j));
                }
            }
            if !zs[k] {
                *r1.insert_elem(2 * k + 1)? = dot_pub(&mut ops.col(k), &mut *f_);
            }
        }
        r1.sort()?;
        r2.sort()?;
        if !r2.is_upperdiag() {
            return Err(Error::Internal);
        }
        accumulate2(a1, a2, &mut eq(Some(r2), Some(r1), Some(Poly::ZERO)), hash, mm + 2 * (dd - 1) + 1, qe)?;
    }
    // exact l2 (P6-L2: domain dom + i per block): ||Es_i s1||^2 + <pow2, upsilon_i> - B_i^2 = 0 over Z
    #[allow(clippy::needless_range_loop)] // i indexes es, oes, l2bsqr and the domain
    for i in 0..z {
        let mut a_ = Int::new(1);
        a_.sub(&{ a_ }, &p.l2bsqr[i]);
        a_.redc(&{ a_ }, q);
        let mut r2 = Sparse::new_mat(n_, n_, diag(n_));
        let mut r1 = Sparse::new_vec(n_);
        let zs = zero_cols(&s.es[i], m1)?;
        gram(&mut r2, &mut s.es[i], &mut au.oes[i], &zs)?;
        let mut pw = Poly::ZERO;
        Poly::binexp(None, Some(&mut pw), &p.l2bsqr[i]);
        pw.auto_self();
        *r1.insert_elem(2 * (m1 + i))? = pw;
        r1.sort()?;
        r2.sort()?;
        if !r2.is_upperdiag() {
            return Err(Error::Internal);
        }
        accumulate2(a1, a2, &mut eq(Some(r2), Some(r1), Some(mono(0, &a_))), hash, mm + 2 * (dd - 1) + 2 + i as u32, qe)?;
    }
    if nprime > 0 {
        sz_z4(a1, a2, &mut au.ods, z4, hash0, mm + 2 * (dd - 1) + 2 + z as u32, p)?;
    }
    if nex > 0 {
        sz_z3(a1, a2, &mut au.oes, au.ops.as_mut(), z3, hash0, mm + 2 * (dd - 1) + 2 + z as u32 + 256, p)?;
    }
    for (x, y) in a1.iter_mut().zip(a2.iter_mut()) {
        sz_auto(x, y, qe)?;
    }
    Ok(())
}

/// accumulator i as quadratic equation i of the lower protocol: r0 -= h_i, coefficient 1 of g_i in r1, R2 grown to
/// np x np
fn finish(a: &mut Acc, h: &mut Poly, i: usize, p: &Tbox) -> Result<(), Error> {
    let (np, _) = dims(p);
    let qe = p.quad_eval.quad_eval;
    a.r0.sub_assign(h, false);
    a.r1.set_nelems_max(np);
    let mut one = Poly::ZERO;
    one.set_one();
    *a.r1.insert_elem(2 * (qe.m1 + qe.l) as usize + 2 * i)? = one;
    a.r1.set_sorted(true);
    a.r2.set_nelems_max(diag(np));
    Ok(())
}

/// the lower protocol's equations: the accumulators, the two beta equations, the relation's R_q rows (`r0 = false`:
/// without their constant terms, which the prover's `_schwartz_zippel_poly (R2, r1, NULL, ...)` does not combine)
fn quad_eqs(a1: Vec<Acc>, beta: [Eq; 2], quad: &mut Vec<Eq>, p: &Tbox, r0: bool) -> Result<Vec<Eq>, Error> {
    let (np, _) = dims(p);
    let mut eqs = Vec::new();
    eqs.try_reserve_exact(a1.len() + 2 + quad.len()).map_err(|_| Error::Memory)?;
    eqs.extend(a1.into_iter().map(|a| Eq { r2: Some(a.r2), r1: Some(a.r1), r0: Some(a.r0) }));
    eqs.extend(beta);
    for mut e in quad.drain(..) {
        if let Some(r1) = &mut e.r1 {
            r1.set_nelems_max(np);
        }
        eqs.push(e);
    }
    if !r0 {
        eqs.iter_mut().for_each(|e| e.r0 = None);
    }
    Ok(eqs)
}

/// `lnp_tbox_verify` (after `abdlop_hashcomm`): false = reject
pub(crate) fn verify(hash: &mut [u8; 32], f: &mut ProofParts, keys: &mut [PolyMat; 3], s: &mut Statement) -> Result<bool, Error> {
    let p = f.p;
    let tb = p.tbox;
    let qe = p.quad_eval.quad_eval;
    let lambda = p.quad_eval.lambda as usize;
    let (q, log2q) = (&tb.ring.q, tb.ring.log2q);
    if tb.l != 0 || s.es.len() != p.z as usize || f.h.len() != lambda / 2 {
        return Err(Error::Internal); // the forms pqz_rel.c passes (module doc)
    }
    let (mut a1, mut a2) = accs(p)?;
    let mut au = autos(s, p)?;
    let beta = beta_eqs(p)?;

    if !check_z34(hash, &mut f.z3, &mut f.z4, &mut f.t_b, p)? {
        return Ok(false);
    }
    let hash0 = *hash;
    for h in f.h.iter_mut() {
        if !(h.get_coeff(0).eqzero() && h.get_coeff(D / 2).eqzero()) {
            return Ok(false);
        }
    }
    let mut tg = f.t_b.sub(qe.l as usize, lambda / 2, 1);
    polyvec::mod_self(&mut tg);
    polyvec::redp_self(&mut tg);
    let mut enc = Coder::new();
    enc.urandom(&mut tg, q, log2q)?;
    *hash = hash2(hash, &enc.end()?);

    accumulate_all(&mut a1, &mut a2, s, &mut au, &mut f.z3, &mut f.z4, hash, &hash0, p)?;
    for (i, a) in a1.iter_mut().enumerate() {
        finish(a, &mut f.h[i], i, p)?;
    }
    let mut eqs = quad_eqs(a1, beta, &mut s.quad, p, true)?;
    let o = Opening { c: &mut f.c, z1: &mut f.z1, z21: &mut f.z21, hint: &mut f.hint, t_a1: &mut f.t_a1, t_b: &mut f.t_b };
    quad::many_verify(hash, o, keys, &mut eqs, p.quad_eval.quad_many)
}

// ---------------------------------------------------------------- prover

/// `__evaleq`: <s, R2 s> + <r1, s> + r0, coefficients mod q, centred (`R2`'s row count is `s.len()` at every call)
fn evaleq<S: Pv + ?Sized>(r2: Option<&mut Sparse>, r1: Option<&mut Sparse>, r0: Option<&Poly>, s: &mut S) -> Result<Poly, Error> {
    let mut res = r0.cloned().unwrap_or(Poly::ZERO);
    if let Some(r1) = r1 {
        polyvec::adddot2(&mut res, r1, s, false);
    }
    if let Some(r2) = r2 {
        let mut tmp = PolyVec::new(s.len())?;
        polyvec::mulsparse(&mut *tmp, r2, s);
        polyvec::fromcrt(&mut *tmp);
        polyvec::adddot(&mut res, s, &mut *tmp, false);
    }
    res.fromcrt();
    let mut res = Poly::mod_(&mut res);
    Ok(Poly::redc(&mut res))
}

/// `__check_coeff0` (an ASSERT_ERR, on in every build: `Error::Internal`): the equation's value at s has coefficient
/// 0 zero (`all = None`), coefficients 0 and d/2 zero (`Some(false)`), or every coefficient zero (`Some(true)`)
fn check_coeff0<S: Pv + ?Sized>(r2: Option<&mut Sparse>, r1: Option<&mut Sparse>, r0: Option<&Poly>, s: &mut S, all: Option<bool>) -> Result<(), Error> {
    let v = evaleq(r2, r1, r0, s)?;
    let ok = match all {
        None => v.c(0).eqzero(),
        Some(false) => v.c(0).eqzero() && v.c(D / 2).eqzero(),
        Some(true) => (0..D).all(|j| v.c(j).eqzero()),
    };
    if ok { Ok(()) } else { Err(Error::Internal) }
}

/// the coefficients of `v` as i64 (coefficient domain)
fn coeffs_i64(v: &mut PolyVec) -> Result<Vec<i64>, Error> {
    let mut r = Vec::new();
    r.try_reserve_exact(v.len() * D).map_err(|_| Error::Memory)?;
    for p in v.iter_mut() {
        p.fromcrt();
        r.extend((0..D).map(|j| p.c(j).get_i64()));
    }
    Ok(r)
}

/// `n` values as a one-limb `intvec` (the rejection tests' operands)
fn intvec(v: &[i64]) -> Result<IntVec, Error> {
    let mut r = IntVec::new(v.len(), 1)?;
    r.set_i64(v);
    Ok(r)
}

/// R s (s3 by the rows of R, or s4 by those of R': `_brandom (ncols, 1, seed, roff + i)`, i < 256); the C core sums
/// in one-limb ints, here i64: every |s_j| <= 2^15 (witness coefficients, bits, upsilon) and ncols < 2^16, so the
/// sums are the same integers
fn r_times(s: &[i64], seed: &[u8; 32], roff: u64) -> Result<Vec<i64>, Error> {
    let mut ri = vec_of(s.len(), |_| 0i8)?;
    let mut r = vec_of(256, |_| 0i64)?;
    for (i, x) in r.iter_mut().enumerate() {
        brandom(&mut ri, 1, seed, roff + i as u64)?;
        for (&rj, &sj) in ri.iter().zip(s) {
            if rj != 0 {
                *x += rj as i64 * sj;
            }
        }
    }
    Ok(r)
}

/// `_lnp_tbox_compute_z34`: z3 = y3 + beta3 R s3, z4 = y4 + beta4 R' s4 (s3 = (Ps s1, Es s1, upsilon), s4 = Ds s1),
/// with ty3, ty4, tbeta into tB and y3, y4, beta into m, rejection-sampled (bimodal; capped: `Error::Reject`); hash
/// becomes the challenge seed of the accepted round
#[allow(clippy::too_many_arguments)]
fn compute_z34(
    hash: &mut [u8; 32],
    f: &mut ProofParts,
    s1: &mut PolyVec,
    m: &mut PolyVec,
    s2: &mut PolyVec,
    bp: &mut PolyMat,
    s: &mut Statement,
    seed: &[u8; 32],
) -> Result<(), Error> {
    let p = f.p;
    let tb = p.tbox;
    let (q, log2q) = (&tb.ring.q, tb.ring.log2q);
    let (z, m1, l) = (p.z as usize, (tb.m1 - p.z) as usize, tb.l as usize);
    let (nex, nprime, nbin) = (p.nex as usize, p.nprime as usize, p.nbin as usize);
    let m2r = (tb.m2 - tb.kmsis) as usize;
    let w = 256 / D;
    let mut s3 = PolyVec::new(nex)?;
    let mut s4 = PolyVec::new(nprime)?;
    let (mut y3, mut y4) = (PolyVec::new(w)?, PolyVec::new(w)?);
    polyvec::set_zero(&mut m.sub(l + 2 * w, 1, 1)); // beta

    let mut loff = 0;
    if nex > 0 {
        let mut off = 0;
        if nbin > 0 {
            let mut sub = s3.sub(0, nbin, 1);
            polyvec::set_zero(&mut sub); // no f
            if let Some(ps) = &mut s.ps {
                polyvec::addmul(&mut sub, ps, &mut s1.sub(0, m1, 1), false);
                polyvec::fromcrt(&mut sub);
            }
            off += nbin;
        }
        for i in 0..z {
            let n = p.n[i] as usize;
            let mut sub = s3.sub(off, n, 1);
            polyvec::set_zero(&mut sub); // no v
            polyvec::addmul(&mut sub, &mut s.es[i], &mut s1.sub(0, m1, 1), false);
            polyvec::fromcrt(&mut sub);
            off += n;
        }
        if z > 0 {
            polyvec::set(&mut s3.sub(off, z, 1), &s1.sub(m1, z, 1));
        }
        loff += w;
    }
    let oy4 = loff;
    if nprime > 0 {
        polyvec::set_zero(&mut *s4); // no u
        polyvec::addmul(&mut *s4, &mut s.ds, &mut s1.sub(0, m1, 1), false);
        polyvec::fromcrt(&mut *s4);
        loff += w;
    }

    let mut rstate = Rng::new(seed, 0);
    let mut signs = Rng::new(seed, 1);
    let mut dom = 2u32;
    let (mut rbits, mut nrbits) = (0u8, 0u32);
    let (mut beta3, mut beta4) = (0i64, 0i64);
    let (mut z3v, mut z4v) = (Vec::new(), Vec::new());
    let mut tries = 0;
    let cseed = loop {
        if tries >= REJ_MAX {
            return Err(Error::Reject);
        }
        tries += 1;
        if nrbits == 0 {
            signs.urandom(core::slice::from_mut(&mut rbits))?;
            nrbits = 8;
        }
        if nex > 0 {
            polyvec_grandom(&mut *y3, p.log2stdev3, seed, dom)?;
            dom += 1;
            polyvec::set(&mut m.sub(l, w, 1), &*y3);
            let mut ty3 = f.t_b.sub(l, w, 1);
            polyvec::set(&mut ty3, &*y3);
            polyvec::addmul(&mut ty3, &mut bp.sub(l, 0, w, m2r, 1, 1), &mut s2.sub(0, m2r, 1), false);
            polyvec::mod_self(&mut ty3);
            polyvec::redp_self(&mut ty3);
            beta3 = 1 - 2 * ((rbits as i64 >> (8 - nrbits)) & 1);
            nrbits -= 1;
        }
        if nprime > 0 {
            polyvec_grandom(&mut *y4, p.log2stdev4, seed, dom)?;
            dom += 1;
            polyvec::set(&mut m.sub(l + oy4, w, 1), &*y4);
            let mut ty4 = f.t_b.sub(l + oy4, w, 1);
            polyvec::set(&mut ty4, &*y4);
            polyvec::addmul(&mut ty4, &mut bp.sub(l + oy4, 0, w, m2r, 1, 1), &mut s2.sub(0, m2r, 1), false);
            polyvec::mod_self(&mut ty4);
            polyvec::redp_self(&mut ty4);
            beta4 = 1 - 2 * ((rbits as i64 >> (8 - nrbits + 1)) & 1); // C's bit index, as is
            nrbits -= 1;
        }
        // tbeta
        let beta = &mut m[l + 2 * w];
        if nex > 0 {
            beta.set_coeff(0, &int(beta3));
        }
        if nprime > 0 {
            beta.set_coeff(D / 2, &int(beta4));
        }
        let beta = beta.clone();
        let mut tbeta = f.t_b.sub(l + loff, 1, 1);
        tbeta.at(0).clone_from(&beta);
        polyvec::addmul(&mut tbeta, &mut bp.sub(l + loff, 0, 1, m2r, 1, 1), &mut s2.sub(0, m2r, 1), false);
        polyvec::mod_self(&mut tbeta);
        polyvec::redp_self(&mut tbeta);
        // encode ty3, ty4, tbeta: the hash of the encoding seeds the challenges
        let mut enc = Coder::new();
        if nex > 0 {
            enc.urandom(&mut f.t_b.sub(l, w, 1), q, log2q)?;
        }
        if nprime > 0 {
            enc.urandom(&mut f.t_b.sub(l + oy4, w, 1), q, log2q)?;
        }
        enc.urandom(&mut f.t_b.sub(l + loff, 1, 1), q, log2q)?;
        let cseed = hash2(hash, &enc.end()?);

        let mut rs3 = Vec::new();
        if nex > 0 {
            let s3c = coeffs_i64(&mut s3)?;
            z3v = coeffs_i64(&mut y3)?;
            rs3 = r_times(&s3c, &cseed, 0)?;
            z3v.iter_mut().zip(&rs3).for_each(|(z, &r)| *z += beta3 * r);
        }
        let mut rs4 = Vec::new();
        if nprime > 0 {
            let s4c = coeffs_i64(&mut s4)?;
            z4v = coeffs_i64(&mut y4)?;
            rs4 = r_times(&s4c, &cseed, 256)?;
            z4v.iter_mut().zip(&rs4).for_each(|(z, &r)| *z += beta4 * r);
        }
        // rejection sampling (rej3 = rej4 = 2 in every relation: bimodal)
        if nex > 0 && p.rej3 != 0 && rej_bimodal(&mut rstate, &intvec(&z3v)?, &intvec(&rs3)?, &p.scm3, &p.stdev3sqr)? {
            continue;
        }
        if nprime > 0 && p.rej4 != 0 && rej_bimodal(&mut rstate, &intvec(&z4v)?, &intvec(&rs4)?, &p.scm4, &p.stdev4sqr)? {
            continue;
        }
        break cseed;
    };
    *hash = cseed;
    for (k, x) in f.z3.iter_mut().enumerate().take(if nex > 0 { w } else { 0 }) {
        x.set_i64(&z3v[k * D..(k + 1) * D]);
    }
    for (k, x) in f.z4.iter_mut().enumerate().take(if nprime > 0 { w } else { 0 }) {
        x.set_i64(&z4v[k * D..(k + 1) * D]);
    }
    Ok(())
}

/// `lnp_tbox_prove` (after `abdlop_commit` and `abdlop_hashcomm`): the toolbox proof of `s` into `f` (tB's ty3, ty4,
/// tbeta, tg and t; h, c, z1, z21, hint, z3, z4). `s1` = (s1_, upsilon) and `s2` the committed secrets, `m` the
/// l + lext message polys (zero), `t_a2` the commitment's low part; `seed` the masks' seed (CTR-PQZ-19's ex[32..64))
#[allow(clippy::too_many_arguments)]
pub(crate) fn prove(
    hash: &mut [u8; 32],
    f: &mut ProofParts,
    s1: &mut PolyVec,
    m: &mut PolyVec,
    s2: &mut PolyVec,
    t_a2: &mut PolyVec,
    keys: &mut [PolyMat; 3],
    s: &mut Statement,
    seed: &[u8; 32],
) -> Result<(), Error> {
    let p = f.p;
    let tb = p.tbox;
    let qe = p.quad_eval.quad_eval;
    let (z, m1, l) = (p.z as usize, (tb.m1 - p.z) as usize, tb.l as usize);
    let lambda = p.quad_eval.lambda as usize;
    let (q, log2q) = (&tb.ring.q, tb.ring.log2q);
    let m2r = (tb.m2 - tb.kmsis) as usize;
    let (np, n_) = dims(p);
    let loff = if p.nprime > 0 { 256 / D } else { 0 } + if p.nex > 0 { 256 / D } else { 0 };
    if l != 0 || s.es.len() != z || p.nex + p.nprime == 0 {
        return Err(Error::Internal); // the forms pqz_rel.c passes (module doc)
    }

    // the seeds: rejection on z3, z4 | g | the lower protocol
    let mut ex = [0u8; 96];
    shake128(&[seed]).squeeze(&mut ex);
    let seed_rej34: &[u8; 32] = ex[..32].try_into().map_err(|_| Error::Internal)?;
    let seed_cont: &[u8; 32] = ex[32..64].try_into().map_err(|_| Error::Internal)?;
    let seed_cont2: &[u8; 32] = ex[64..].try_into().map_err(|_| Error::Internal)?;

    let mut au = autos(s, p)?;
    compute_z34(hash, f, s1, m, s2, &mut keys[2], s, seed_rej34)?;
    let hash0 = *hash;

    // s = (<s1>, <m>, <y3>, <y4>, <beta>) (and <g> before the last check)
    let mut sv = PolyVec::new(np)?;
    polyvec::set(&mut sv.sub(0, m1 + z, 2), &**s1);
    polyvec::auto(&mut sv.sub(1, m1 + z, 2), &mut **s1);
    polyvec::set(&mut sv.sub((m1 + z) * 2, loff + 1, 2), &m.sub(l, loff + 1, 1));
    polyvec::auto(&mut sv.sub((m1 + z) * 2 + 1, loff + 1, 2), &mut m.sub(l, loff + 1, 1));

    // g = h: uniform with coefficients 0 and d/2 zero, appended to m; tg = B_ext s2 + g, hashed
    for i in 0..lambda / 2 {
        let mut v = urandom_q(D, seed_cont, i as u64)?;
        v[0] = 0;
        v[D / 2] = 0;
        f.h[i].set_i64(&v);
    }
    polyvec::set(&mut m.sub(qe.l as usize, lambda / 2, 1), &*f.h);
    {
        let mut tg = f.t_b.sub(qe.l as usize, lambda / 2, 1);
        polyvec::set(&mut tg, &*f.h);
        polyvec::addmul(&mut tg, &mut keys[2].sub(qe.l as usize, 0, lambda / 2, m2r, 1, 1), &mut s2.sub(0, m2r, 1), false);
        polyvec::mod_self(&mut tg);
        polyvec::redp_self(&mut tg);
        let mut enc = Coder::new();
        enc.urandom(&mut tg, q, log2q)?;
        *hash = hash2(hash, &enc.end()?);
    }
    // the input evaluation equations have constant coefficient 0
    for e in s.eval.iter_mut() {
        check_coeff0(e.r2.as_mut(), e.r1.as_mut(), e.r0.as_ref(), &mut sv.sub(0, (m1 + z) * 2, 1), None)?;
    }

    let (mut a1, mut a2) = accs(p)?;
    let beta = beta_eqs(p)?;
    accumulate_all(&mut a1, &mut a2, s, &mut au, &mut f.z3, &mut f.z4, hash, &hash0, p)?;

    // h_i = g_i + the accumulated evaluation i (coefficients 0 and d/2 zero), then the quadratic equations
    for (i, a) in a1.iter_mut().enumerate() {
        let mut sub = sv.sub(0, n_, 1);
        check_coeff0(Some(&mut a.r2), Some(&mut a.r1), Some(&a.r0), &mut sub, Some(false))?;
        let mut t = evaleq(Some(&mut a.r2), Some(&mut a.r1), Some(&a.r0), &mut sub)?;
        f.h[i].add_assign(&mut t, false);
        if !(f.h[i].get_coeff(0).eqzero() && f.h[i].get_coeff(D / 2).eqzero()) {
            return Err(Error::Internal);
        }
        finish(a, &mut f.h[i], i, p)?;
    }
    // they evaluate to zero at s = (.., <g>)
    let og = (m1 + z + l + loff + 1) * 2;
    polyvec::set(&mut sv.sub(og, lambda / 2, 2), &m.sub(l + loff + 1, lambda / 2, 1));
    polyvec::auto(&mut sv.sub(og + 1, lambda / 2, 2), &mut m.sub(l + loff + 1, lambda / 2, 1));
    for a in a1.iter_mut() {
        check_coeff0(Some(&mut a.r2), Some(&mut a.r1), Some(&a.r0), &mut *sv, Some(true))?;
    }

    let mut eqs = quad_eqs(a1, beta, &mut s.quad, p, false)?;
    quad::many_prove(hash, f, quad::Secret { s1, m, s2, t_a2 }, keys, &mut eqs, seed_cont2, p.quad_eval.quad_many)
}
