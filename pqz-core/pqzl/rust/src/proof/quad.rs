//! `lnp-quad-many.c` (`_schwartz_zippel_poly`, `lnp_quad_many_verify`) and `lnp-quad.c` (`lnp_quad_verify`, with the
//! P6-Z21 bound on the whole z2 = (z21, z22)): verifier side. The operands C converts between domains are converted
//! the same way, in the same order (see `arith::poly`).
use super::{diag, hash2, Coder, Eq};
use crate::arith::int::{int_div, Int};
use crate::arith::poly::Poly;
use crate::arith::polymat::PolyMat;
use crate::arith::polyvec::{self, PolyVec};
use crate::arith::spoly::Sparse;
use crate::params::Abdlop;
use crate::rand::urandom::polyvec_urandom;
use crate::Error;

/// `_schwartz_zippel_poly`: (R2, r1, r0) = sum_i mu_i (R2_i, r1_i, r0_i), mu = N uniform polys from (hash, 0)
fn schwartz_zippel_poly(hash: &[u8; 32], eqs: &mut [Eq], p: &Abdlop) -> Result<(Sparse, Sparse, Poly), Error> {
    let n = 2 * (p.m1 + p.l) as usize;
    let mut mu = PolyVec::new(eqs.len())?;
    polyvec_urandom(&mut *mu, &p.ring.q, p.ring.log2q, hash, 0)?;
    let mut r2 = Sparse::new_mat(n, n, diag(n));
    let mut r1 = Sparse::new_vec(n);
    let mut r0 = Poly::ZERO;
    let (mut r1tmp, mut r1tmp2) = (Sparse::new_vec(n), Sparse::new_vec(n));
    let (mut r2tmp, mut r2tmp2) = (Sparse::new_mat(n, n, diag(n)), Sparse::new_mat(n, n, diag(n)));
    for (mui, e) in mu.iter_mut().zip(eqs.iter_mut()) {
        if let Some(r2i) = &mut e.r2 {
            Sparse::scale2(&mut r2tmp2, mui, r2i)?;
            Sparse::add(&mut r2tmp, &mut r2, &mut r2tmp2, false)?;
            Sparse::set(&mut r2, &r2tmp)?;
        }
        if let Some(r1i) = &mut e.r1 {
            Sparse::scale2(&mut r1tmp2, mui, r1i)?;
            Sparse::add(&mut r1tmp, &mut r1, &mut r1tmp2, false)?;
            Sparse::set(&mut r1, &r1tmp)?;
        }
        if let Some(r0i) = &mut e.r0 {
            r0.addmul(mui, r0i, false);
        }
    }
    r2.fromcrt();
    r1.fromcrt();
    r0.fromcrt();
    if !r2.is_upperdiag() {
        return Err(Error::Internal);
    }
    Ok((r2, r1, r0))
}

/// The proof fields the quadratic proof reads.
pub(crate) struct Opening<'a> {
    pub(crate) c: &'a mut Poly,
    pub(crate) z1: &'a mut PolyVec,
    pub(crate) z21: &'a mut PolyVec,
    pub(crate) hint: &'a mut PolyVec,
    pub(crate) t_a1: &'a mut PolyVec,
    pub(crate) t_b: &'a mut PolyVec,
}

/// `lnp_quad_many_verify`: the N equations combined by `_schwartz_zippel_poly`, then `lnp_quad_verify`
pub(crate) fn many_verify(
    hash: &mut [u8; 32],
    o: Opening<'_>,
    keys: &mut [PolyMat; 3],
    eqs: &mut [Eq],
    p: &Abdlop,
) -> Result<bool, Error> {
    let (mut r2, mut r1, mut r0) = schwartz_zippel_poly(hash, eqs, p)?;
    verify(hash, o, keys, &mut r2, &mut r1, &mut r0, p)
}

/// `lnp_quad_verify`: recover w1 (hint), v and the challenge, then the norm bounds
fn verify(
    hash: &mut [u8; 32],
    o: Opening<'_>,
    [a1, a2p, bp]: &mut [PolyMat; 3],
    r2: &mut Sparse,
    r1: &mut Sparse,
    r0: &mut Poly,
    p: &Abdlop,
) -> Result<bool, Error> {
    let Opening { c, z1, z21, hint: h, t_a1, t_b } = o;
    let dc = p.dcompress;
    let (km, m1, l, lext) = (p.kmsis as usize, p.m1 as usize, p.l as usize, p.lext as usize);
    let m2r = (p.m2 - p.kmsis) as usize;
    let (q, log2q) = (&p.ring.q, p.ring.log2q);
    let mut z = PolyVec::new(2 * (m1 + l))?;
    let mut tmp3 = PolyVec::new(2 * (m1 + l))?;
    let mut w1 = PolyVec::new(km)?;
    let mut tmp1 = PolyVec::new(km)?;
    let mut f = PolyVec::new(1)?;

    // recover w1
    polyvec::mul(&mut *tmp1, a1, &mut **z1);
    polyvec::addmul(&mut *tmp1, a2p, &mut **z21, false);
    let mut tmp2 = Poly::lshift(c, dc.d);
    polyvec::subscale2(&mut *tmp1, &mut tmp2, &mut **t_a1, false);
    polyvec::mod_self(&mut *tmp1);
    polyvec::use_ghint(&mut *w1, &mut **h, &mut *tmp1, dc);

    // recover v
    polyvec::scale2(&mut *f, c, &mut t_b.sub(l, lext, 1));
    polyvec::submul(&mut *f, &mut bp.sub(l, 0, lext, m2r, 1, 1), &mut **z21, false);
    for i in 0..m1 {
        z[2 * i] = z1[i].clone();
        z[2 * i + 1] = Poly::auto(&mut z1[i]);
    }
    if l > 0 {
        let mut subb = PolyVec::new(l)?;
        polyvec::scale2(&mut *subb, c, &mut t_b.sub(0, l, 1));
        polyvec::submul(&mut *subb, &mut bp.sub(0, 0, l, m2r, 1, 1), &mut **z21, false);
        for i in 0..l {
            let a = Poly::auto(&mut subb[i]);
            z[2 * m1 + 2 * i] = subb[i].clone();
            z[2 * m1 + 2 * i + 1] = a;
        }
    }
    let mut v = r0.clone();
    v = Poly::mul(c, &mut v);
    polyvec::adddot2(&mut v, r1, &mut *z, false);
    v.fromcrt();
    v = Poly::mul(c, &mut v);
    v.sub_assign(&mut f[0], false);
    polyvec::mulsparse(&mut *tmp3, r2, &mut *z);
    polyvec::fromcrt(&mut *tmp3);
    polyvec::adddot(&mut v, &mut *z, &mut *tmp3, false);
    v.fromcrt();

    // recover the challenge from t, w1, v
    let mut t = t_b.sub(l, lext, 1);
    polyvec::mod_self(&mut t);
    polyvec::redp_self(&mut t);
    v = Poly::mod_(&mut v);
    v = Poly::redp(&mut v);
    let mut enc = Coder::new();
    enc.urandom(&mut t, q, log2q)?;
    enc.urandom(core::slice::from_mut(&mut v), q, log2q)?;
    enc.urandom(&mut *w1, &dc.m, dc.log2m)?;
    let cseed = hash2(hash, &enc.end()?);
    let mut c2 = Poly::urandom_autostable(p.omega, p.log2omega, &cseed, 0)?;
    let mut ok = Poly::eq(c, &mut c2);

    // l2(z1)^2 <= 1.55^2 2^(2 log2stdev1) 2 m1 d (scaled by 400: 962 / 400)
    let mut bnd = Int::from_i64(2, 2 * m1 as i64 * 64 * 962);
    bnd.lshift(&{ bnd }, 2 * p.log2stdev1);
    let mut tmp = Int::from_i64(1, 400);
    let (a, b) = (bnd, tmp);
    int_div(&mut bnd, &mut tmp, &a, &b);
    ok &= polyvec::l2sqr(&mut **z1).le(&bnd);

    // P6-Z21: ||(z21, w - gamma w1)||^2 <= Bsq
    polyvec::subscale(&mut *tmp1, &dc.gamma, &mut *w1, false);
    let mut l2 = polyvec::l2sqr(&mut *tmp1);
    l2.add(&{ l2 }, &polyvec::l2sqr(&mut **z21));
    ok &= l2.le(&p.bsqr);

    // 2 linf(h) <= m
    ok &= polyvec::linf(&mut **h).le(&dc.m);
    if ok {
        *hash = cseed;
    }
    Ok(ok)
}
