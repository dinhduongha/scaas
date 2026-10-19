//! `lnp-quad-many.c` (`_schwartz_zippel_poly`, `lnp_quad_many_prove` / `_verify`) and `lnp-quad.c`
//! (`lnp_quad_prove`, `lnp_quad_verify` with the P6-Z21 bound on the whole z2 = (z21, z22)). The operands C converts
//! between domains are converted the same way, in the same order (see `arith::poly`).
use super::{diag, hash2, Coder, Eq};
use crate::arith::int::{int_div, Int, IntVec};
use crate::arith::poly::Poly;
use crate::arith::polymat::PolyMat;
use crate::arith::polyvec::{self, Pv, PolyVec};
use crate::arith::spoly::Sparse;
use crate::coder::ProofParts;
use crate::params::Abdlop;
use crate::rand::grandom::polyvec_grandom;
use crate::rand::rejection::{rej_onetime, rej_standard, REJ_MAX};
use crate::rand::rng::Rng;
use crate::rand::urandom::polyvec_urandom;
use crate::{Error, Wiped};

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

// ---------------------------------------------------------------- prover

/// the prover's secrets: s1, the message m (l + lext polys), s2 = (s21, s22), and tA2 (the commitment's low part)
pub(crate) struct Secret<'a> {
    pub(crate) s1: &'a mut PolyVec,
    pub(crate) m: &'a mut PolyVec,
    pub(crate) s2: &'a mut PolyVec,
    pub(crate) t_a2: &'a mut PolyVec,
}

/// `lnp_quad_many_prove`: the N equations combined by `_schwartz_zippel_poly` (their r0 unused: `None` here, NULL
/// in C), then `lnp_quad_prove` into f's t (the last poly of tB), c, z1, z21, hint
pub(crate) fn many_prove(
    hash: &mut [u8; 32],
    f: &mut ProofParts,
    w: Secret<'_>,
    keys: &mut [PolyMat; 3],
    eqs: &mut [Eq],
    seed: &[u8; 32],
    p: &Abdlop,
) -> Result<(), Error> {
    let (mut r2, mut r1, _) = schwartz_zippel_poly(hash, eqs, p)?;
    prove(hash, f, w, keys, &mut r2, &mut r1, seed, p)
}

/// the coefficients of `v` (coefficient domain) as a one-limb `intvec`, as C's `polyvec_set_coeffvec2` views them
fn coeffvec(v: &PolyVec) -> Result<IntVec, Error> {
    let mut r = IntVec::new(v.len() * 64, 1)?;
    for (i, p) in v.iter().enumerate() {
        for j in 0..64 {
            r.set_elem(64 * i + j, &p.c(j));
        }
    }
    Ok(r)
}

/// `lnp_quad_prove`: masks y1, y2 (Gaussian), w = A1 y1 + A2' y21 + y22 = w1 gamma + w0, the garbage terms (t, v), the
/// challenge from (t, v, w1), z = y + c s rejection-sampled (capped: `Error::Reject`), then the hint for w1
#[allow(clippy::too_many_arguments)]
fn prove(
    hash: &mut [u8; 32],
    f: &mut ProofParts,
    w: Secret<'_>,
    [a1, a2p, bp]: &mut [PolyMat; 3],
    r2: &mut Sparse,
    r1: &mut Sparse,
    seed: &[u8; 32],
    p: &Abdlop,
) -> Result<(), Error> {
    let Secret { s1, m, s2, t_a2 } = w;
    let dc = p.dcompress;
    let (km, m1, m2, l, lext) = (p.kmsis as usize, p.m1 as usize, p.m2 as usize, p.l as usize, p.lext as usize);
    let m2r = m2 - km;
    let (q, log2q) = (&p.ring.q, p.ring.log2q);
    let (mut y1, mut y2) = (PolyVec::new(m1)?, PolyVec::new(m2)?);
    let (mut cs1, mut cs2) = (Wiped(PolyVec::new(m1)?), Wiped(PolyVec::new(m2)?));
    let n = 2 * (m1 + l);
    let (mut r2y, mut tmp, mut tmp2) = (PolyVec::new(n)?, PolyVec::new(n)?, PolyVec::new(l)?);
    // s, the mask seed and c s1, c s2 are cleared on every exit (Wiped, fix B)
    let (mut y, mut s) = (PolyVec::new(n)?, Wiped(PolyVec::new(n)?));
    let (mut wv, mut w1, mut w0) = (PolyVec::new(km)?, PolyVec::new(km)?, PolyVec::new(km)?);

    // s = (<s1>, <m>)
    polyvec::set(&mut s.sub(0, m1, 2), &**s1);
    polyvec::auto(&mut s.sub(1, m1, 2), &mut **s1);
    if l > 0 {
        polyvec::set(&mut s.sub(2 * m1, l, 2), &m.sub(0, l, 1));
        polyvec::auto(&mut s.sub(2 * m1 + 1, l, 2), &mut m.sub(0, l, 1));
    }

    let mut st = Rng::new(seed, 0);
    let mut yseed = Wiped([0u8; 32]);
    st.urandom(&mut *yseed)?;
    let mut dom = 0u32;
    let mut tries = 0;
    let cseed = loop {
        if tries >= REJ_MAX {
            return Err(Error::Reject);
        }
        tries += 1;
        polyvec_grandom(&mut *y1, p.log2stdev1, &yseed, dom)?;
        dom += 1;
        polyvec_grandom(&mut *y2, p.log2stdev2, &yseed, dom)?;
        dom += 1;

        // w
        polyvec::set(&mut *wv, &y2.sub(m2r, km, 1));
        polyvec::addmul(&mut *wv, a1, &mut *y1, true);
        polyvec::addmul(&mut *wv, a2p, &mut y2.sub(0, m2r, 1), true);
        polyvec::decompose(&mut *w1, &mut *w0, &mut *wv, dc);

        // y = (<y1>, -<B y21>)
        polyvec::set(&mut y.sub(0, m1, 2), &*y1);
        polyvec::auto(&mut y.sub(1, m1, 2), &mut *y1);
        if l > 0 {
            polyvec::mul(&mut *tmp2, &mut bp.sub(0, 0, l, m2r, 1, 1), &mut y2.sub(0, m2r, 1));
            polyvec::set(&mut y.sub(2 * m1, l, 2), &*tmp2);
            polyvec::auto(&mut y.sub(2 * m1 + 1, l, 2), &mut *tmp2);
            polyvec::neg_self(&mut y.sub(2 * m1, l, 2));
            polyvec::neg_self(&mut y.sub(2 * m1 + 1, l, 2));
        }
        polyvec::fromcrt(&mut *y);

        // g1
        let mut g1 = polyvec::dot2(r1, &mut *y);
        polyvec::mulsparse(&mut *r2y, r2, &mut *y);
        polyvec::fromcrt(&mut *r2y);
        polyvec::adddot(&mut g1, &mut *s, &mut *r2y, false);
        polyvec::mulsparse(&mut *tmp, r2, &mut *s);
        polyvec::fromcrt(&mut *tmp);
        polyvec::adddot(&mut g1, &mut *y, &mut *tmp, false);
        g1.fromcrt();

        // t
        let mut t = f.t_b.sub(l, lext, 1);
        t.at(0).clone_from(&g1);
        polyvec::addmul(&mut t, &mut bp.sub(l, 0, lext, m2r, 1, 1), &mut s2.sub(0, m2r, 1), false);
        polyvec::fromcrt(&mut t);

        // v
        let mut v = polyvec::dot(&mut *y, &mut *r2y);
        polyvec::poly_addmul2(&mut v, &mut bp.sub(l, 0, lext, m2r, 1, 1), &mut y2.sub(0, m2r, 1), false);
        v.fromcrt();

        // encode t, v, w1: the hash of the encoding seeds the challenge
        polyvec::mod_self(&mut t);
        polyvec::redp_self(&mut t);
        let mut v = Poly::mod_(&mut v);
        let mut v = Poly::redp(&mut v);
        let mut enc = Coder::new();
        enc.urandom(&mut t, q, log2q)?;
        enc.urandom(core::slice::from_mut(&mut v), q, log2q)?;
        enc.urandom(&mut *w1, &dc.m, dc.log2m)?;
        let cseed = hash2(hash, &enc.end()?);
        f.c = Poly::urandom_autostable(p.omega, p.log2omega, &cseed, 0)?;

        polyvec::scale2(&mut *cs1, &mut f.c, &mut **s1);
        polyvec::scale2(&mut *cs2, &mut f.c, &mut **s2);
        polyvec::add_assign(&mut *y1, &mut *cs1, false);
        polyvec::add_assign(&mut *y2, &mut *cs2, false);

        if p.rej1 != 0 {
            polyvec::fromcrt(&mut *y1);
            polyvec::fromcrt(&mut *cs1);
            if rej_standard(&mut st, &coeffvec(&y1)?, &coeffvec(&cs1)?, &p.scm1, &p.stdev1sqr)? {
                continue;
            }
        }
        if p.rej2 != 0 {
            polyvec::fromcrt(&mut *y2);
            polyvec::fromcrt(&mut *cs2);
            let (z2, c2) = (coeffvec(&y2)?, coeffvec(&cs2)?);
            // rej2 is 1 or 2 (C's ASSERT; 2 in every relation): 2 is Rej1 with sigma2 (P6-D2; upstream rej_bimodal with
            // stdev1sqr, review D-2)
            let rej = if p.rej2 == 1 {
                rej_standard(&mut st, &z2, &c2, &p.scm2, &p.stdev2sqr)?
            } else {
                rej_onetime(&mut st, &z2, &c2, &p.scm2, &p.stdev2sqr)?
            };
            if rej {
                continue;
            }
        }
        polyvec::subscale2(&mut y2.sub(m2r, km, 1), &mut f.c, &mut **t_a2, false);
        polyvec::sub_assign(&mut y2.sub(m2r, km, 1), &mut *w0, false);
        if polyvec::l2sqr(&mut *y2).gt(&p.bsqr) {
            continue;
        }
        break cseed;
    };
    *hash = cseed;

    polyvec::scale_self(&mut *w1, &dc.gamma);
    polyvec::sub_assign(&mut *w1, &mut y2.sub(m2r, km, 1), false);
    polyvec::set(&mut *f.z1, &*y1);
    polyvec::set(&mut *f.z21, &y2.sub(0, m2r, 1));
    polyvec::mod_self(&mut *w1);
    polyvec::redc_self(&mut *w1);
    polyvec::make_ghint(&mut *f.hint, &mut y2.sub(m2r, km, 1), &mut *w1, dc);
    Ok(())
}
