//! `rejection.c`: the PQZ rejection tests (integer-only, `fixexp`), on scM = round(M * 2^128) and sigma2 = sigma^2:
//!   standard: accept iff u < exp((<v,v> - 2<z,v>) / (2 sigma^2)) / M
//!   bimodal:  accept iff u < 1 / (M exp(-<v,v> / (2 sigma^2)) cosh(<z,v> / sigma^2))
//! with u a 64-bit uniform word from the caller's stream (one per test). `Ok(true)` = reject, as C's 1. C's `ERR`s
//! (an input of 2^126 or more, mismatched vectors) set the sticky internal error and carry on: `Error::Internal`.
use super::fixexp::{bernoulli_fp, ct_sel64, div_q56, exp_fp, X_MAX};
use super::rng::Rng;
use crate::arith::int::{Int, IntVec};
use crate::Error;

/// `_int2i128`: |a| < 2^126, at most 2 limbs used
fn int2i128(a: &Int) -> Result<i128, Error> {
    let mut m = a.l[0] as u128;
    if a.n > 1 {
        m |= (a.l[1] as u128) << 64;
    }
    if a.limbs().iter().skip(2).any(|&x| x != 0) || m >> 126 != 0 {
        return Err(Error::Internal);
    }
    let s = -((a.neg & 1) as i128);
    Ok(((m as i128) ^ s) - s)
}

/// `_quot_q56`: signed a / d in Q56, d > 0, clamped into int64
fn quot_q56(a: i128, d: u64) -> i64 {
    let s = a >> 127;
    let mut mag = ((a ^ s).wrapping_sub(s)) as u128;
    // |a| < 2^70 keeps |a| * 2^56 inside 128 bits; beyond that exp() saturates anyway
    let big = 0u128.wrapping_sub((mag >> 70 != 0) as u128);
    mag = (mag & !big) | (((1u128 << 70) - 1) & big);
    let mut q = div_q56(mag, d);
    let qb = 0u128.wrapping_sub((q >> 63 != 0) as u128);
    q = (q & !qb) | (((1u128 << 63) - 1) & qb);
    let (r, s64) = (q as i64, s as i64);
    (r ^ s64).wrapping_sub(s64)
}

/// `_lnM_q56`: ln M in Q56 from scM, 1 <= M < 64 (public: plain bisection on the fixed-point exp)
fn ln_m_q56(scm: &Int) -> i64 {
    let (mid, hi) = (scm.l[1], if scm.n > 2 { scm.l[2] } else { 0 });
    let m56 = (mid >> 8) | (hi << 56); // M * 2^56
    let mut x = 0i64;
    for b in (0..=58).rev() {
        let t = x + (1i64 << b);
        let (mant, e) = exp_fp(t); // exp(t) = mant * 2^(e - 63), e in [1, 7] here
        if (0..=7).contains(&e) && (mant as u128) << e <= (m56 as u128) << 7 {
            x = t;
        }
    }
    x
}

/// <z,v> and <v,v> as signed 128-bit (`intvec_dot` into 2 nlimbs limbs)
fn dots(z: &IntVec, v: &IntVec) -> Result<(i128, i128), Error> {
    if z.len() != v.len() || z.nlimbs() != v.nlimbs() || 2 * z.nlimbs() > crate::arith::int::MAXL {
        return Err(Error::Internal);
    }
    let (mut t1, mut t2) = (Int::new(2 * z.nlimbs()), Int::new(2 * v.nlimbs()));
    IntVec::dot(&mut t1, z, v);
    IntVec::dot(&mut t2, v, v);
    Ok((int2i128(&t1)?, int2i128(&t2)?))
}

/// `rej_standard`
pub(crate) fn rej_standard(st: &mut Rng, z: &IntVec, v: &IntVec, scm: &Int, sigma2: &Int) -> Result<bool, Error> {
    let (t1, t2) = dots(z, v)?;
    let num = t2.wrapping_sub(t1.wrapping_mul(2));
    let den = (int2i128(sigma2)? as u64).wrapping_mul(2);
    let t = quot_q56(num, den);
    // accept iff u * M * exp(-t) <= 1, i.e. u < exp(t - ln M)
    let (mant, e) = exp_fp(t.wrapping_sub(ln_m_q56(scm)));
    Ok(!bernoulli_fp(st.u64(), mant, e))
}

/// `rej_bimodal`
pub(crate) fn rej_bimodal(st: &mut Rng, z: &IntVec, v: &IntVec, scm: &Int, sigma2: &Int) -> Result<bool, Error> {
    let (t1, t2) = dots(z, v)?;
    let s2 = int2i128(sigma2)? as u64;
    let a = quot_q56(t2, s2.wrapping_mul(2)); // <v,v> / (2 sigma^2) >= 0
    let mut y = quot_q56(t1, s2); // <z,v> / sigma^2
    let ys = y >> 63;
    y = (y ^ ys).wrapping_sub(ys); // |y|
    // p = 2 exp(a - |y|) / (M (1 + exp(-2|y|))); accept iff u (1 + exp(-2|y|)) / 2 < exp(a - |y| - ln M)
    let (m1, e1) = exp_fp(a.wrapping_sub(y).wrapping_sub(ln_m_q56(scm)));
    let yc = ct_sel64(((y > X_MAX / 2) as u64).wrapping_neg(), (X_MAX / 2) as u64, y as u64);
    let (m2, e2) = exp_fp(-2 * yc as i64); // exp(-2|y|) = m2 * 2^(e2 - 63), e2 <= 1
    // as Q63: m2 << 1 if e2 == 1, else m2 >> -e2 (0 below 2^-63)
    let f_hi = m2 << 1;
    let f_lo = (m2 >> (((-e2) as u64) & 63)) & ((-e2 < 64) as u64).wrapping_neg();
    let f = ct_sel64(((e2 >= 1) as u64).wrapping_neg(), f_hi, f_lo);
    // w = (1 + exp(-2|y|)) / 2 in Q63, in (1/2, 1]; u' = u * w (Q64)
    let w = (((1u128 << 63) + f as u128) >> 1) as u64;
    let uw = ((st.u64() as u128 * w as u128) >> 63) as u64;
    Ok(!bernoulli_fp(uw, m1, e1))
}
