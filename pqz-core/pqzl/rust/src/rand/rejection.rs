//! `rejection.c`: the PQZ rejection tests (integer-only, `fixexp`), on scM = round(M * 2^128) and sigma2 = sigma^2:
//!   standard: accept iff u < exp((<v,v> - 2<z,v>) / (2 sigma^2)) / M
//!   bimodal:  accept iff u < 1 / (M exp(-<v,v> / (2 sigma^2)) cosh(<z,v> / sigma^2))
//!   onetime:  reject if <z,v> < 0, else the standard test (Rej1 of LNP22 / LNS21, one-time commitments)
//! with u a 64-bit uniform word from the caller's stream (one per test). `Ok(true)` = reject, as C's 1. C's `ERR`s
//! (an input of 2^126 or more, mismatched vectors) set the sticky internal error and carry on: `Error::Internal`.
//! `t2 - 2 t1`, `t - ln M` and `a - |y| - ln M` saturate (`saturating_sub`; C `pqz_sat_sub64` / `pqz_sat_sub128`):
//! an exponent below -2^63 stays the most negative and rejects, `num` above 2^127 the largest and accepts, as the exact
//! values would. Only dishonest-size inputs get there (honest exponents stay within +-64 in Q56).
use super::fixexp::{bernoulli_fp, ct_sel64, div_q56, exp_fp, X_MAX};
use super::rng::Rng;
use crate::arith::int::{Int, IntVec};
use crate::Error;

/// `PQZ_REJ_MAX` (pqz_rt.h, CTR-PQZ-10): rounds of a rejection loop; the cap is `Error::Reject`
pub(crate) const REJ_MAX: u32 = 1000;

/// `_int2i128`: |a| < 2^126, at most 2 limbs used
fn int2i128(a: &Int) -> Result<i128, Error> {
    let mut m = a.l[0] as u128;
    if a.n > 1 {
        m |= (a.l[1] as u128) << 64;
    }
    // review E: the inputs are secret (<z,v>, <v,v>): the bound is tested without a branch and only the verdict, an
    // error that aborts the proof (public), is declassified (never set for an honest prover)
    let big = a.limbs().iter().skip(2).fold((m >> 126) as u64, |r, &x| r | x);
    let err = big != 0;
    let err = crate::ct::verdict(err);
    if err {
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
    let num = t2.saturating_sub(t1.wrapping_mul(2)); // |t1| < 2^126: 2 t1 is exact
    let den = (int2i128(sigma2)? as u64).wrapping_mul(2);
    let t = quot_q56(num, den);
    // accept iff u * M * exp(-t) <= 1, i.e. u < exp(t - ln M)
    let (mant, e) = exp_fp(t.saturating_sub(ln_m_q56(scm)));
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
    let (m1, e1) = exp_fp(a.saturating_sub(y).saturating_sub(ln_m_q56(scm)));
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

/// `rej_onetime` (PQZ P6-D2, review D-2: Rej1 for z2, rej2 == 2): always one u, as `rej_standard`, also when the sign
/// test rejects, so the stream does not depend on the verdict (C = Rust parity); the sign is read without a branch
pub(crate) fn rej_onetime(st: &mut Rng, z: &IntVec, v: &IntVec, scm: &Int, sigma2: &Int) -> Result<bool, Error> {
    let (t1, _) = dots(z, v)?;
    let neg = (t1 >> 127) != 0;
    Ok(rej_standard(st, z, v, scm, sigma2)? | neg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pqz_ub_test.c part a's `test_onetime` (P6-D2), same inputs: R_REG's scM2 / stdev2sq, z = y + v with y from
    /// `grandom(12, seed, s + 1)`, v = -1100, 1100, ... (||v||^2 below 2 sigma2^2 ln M2). onetime = standard | (<z,v> < 0)
    /// with the same stream offset afterwards; acceptance rate 1/(2 M2) to 5 standard errors of 2^16 samples
    /// (|rate - p| <= 5 sqrt(p (1 - p) / n) ~ 0.0074; fixed seeds, so it only guards the expected value). The counts
    /// equal the C test's (11624 accepted, 5438 with <z,v> < 0, 5417 of them accepted by rej_standard).
    #[test]
    fn onetime_rej1() {
        use crate::params::reg::{pqz_reg_scm2, pqz_reg_stdev2sq};
        use crate::rand::grandom::grandom;
        const N: usize = 64;
        const S: u32 = 1 << 16;
        let seed: [u8; 32] = core::array::from_fn(|i| if i == 0 { 9 } else { 0 });
        let (mut ra, mut rb) = (Rng::new(&seed, 0), Rng::new(&seed, 0));
        let vv: [i64; N] = core::array::from_fn(|i| if i & 1 == 1 { 1100 } else { -1100 });
        let mut v = IntVec::new(N, 1).unwrap();
        v.set_i64(&vv);
        let (mut y, mut z) = ([0i64; N], IntVec::new(N, 1).unwrap());
        let (mut acc, mut neg, mut negstd) = (0u32, 0u32, 0u32);
        for s in 0..S {
            grandom(&mut y, 12, &seed, s as u64 + 1).unwrap();
            let zz: [i64; N] = core::array::from_fn(|i| y[i] + vv[i]);
            z.set_i64(&zz);
            let n = zz.iter().zip(&vv).map(|(a, b)| (a * b) as i128).sum::<i128>() < 0;
            let r1 = rej_onetime(&mut ra, &z, &v, &pqz_reg_scm2, &pqz_reg_stdev2sq).unwrap();
            let r0 = rej_standard(&mut rb, &z, &v, &pqz_reg_scm2, &pqz_reg_stdev2sq).unwrap();
            assert_eq!(r1, r0 | n, "sample {s}");
            neg += n as u32;
            negstd += (n && !r0) as u32;
            acc += !r1 as u32;
        }
        assert_eq!(ra.u64(), rb.u64(), "same stream offset");
        let m2 = pqz_reg_scm2.l[2] as f64 + pqz_reg_scm2.l[1] as f64 / 18446744073709551616.0;
        let (p, rate) = (1.0 / (2.0 * m2), acc as f64 / S as f64);
        assert!((rate - p).abs() <= 5.0 * (p * (1.0 - p) / S as f64).sqrt(), "rate {rate} vs 1/(2 M2) {p}");
        // the C test's counts per parameter set (test/runs/ub-t8b-<set>.txt part a; R_REG's M2 differs per set)
        let want = match crate::SET {
            "n2048-kmax1024" => (11624, 5438, 5417),
            "n2304-kmax4096" => (11294, 5438, 5400),
            "n2560-kmax16384" => (11127, 5438, 5385),
            "n2816-kmax65536" => (10756, 5438, 5355),
            s => panic!("no C counts recorded for set {s}: run test/ub_test.sh with PQZ_SET={s}"),
        };
        assert_eq!((acc, neg, negstd), want, "= the C test's counts");
    }

    /// pqz_ub_test.c part a's rejection cases: exponents near +-2^63, the verdict on 64 draws of u (scM = 1.5 2^128,
    /// sigma^2 = 2^20); below -2^63 saturates and rejects, num above 2^127 saturates and accepts
    #[test]
    fn saturation_near_2_63() {
        const MAX: i64 = i64::MAX;
        let scm = Int::from_limbs(&[0, 1 << 63, 1], 0);
        let s2 = Int::from_limbs(&[1 << 20], 0);
        let one = |x: i64| {
            let mut r = IntVec::new(1, 1).unwrap();
            r.set_i64(&[x]);
            r
        };
        // S3: two-limb entries, t2 = 2, t1 = -(2^126 - 1), num = 2^127
        let (mut z3, mut v3) = (IntVec::new(2, 2).unwrap(), IntVec::new(2, 2).unwrap());
        v3.set_elem(0, &Int::from_limbs(&[1, 0], 0));
        v3.set_elem(1, &Int::from_limbs(&[1, 0], 0));
        z3.set_elem(0, &Int::from_limbs(&[u64::MAX, (1 << 62) - 1], 1));
        let cases: [(&str, bool, IntVec, IntVec, bool); 6] = [
            ("S1 standard, t2 - 2 t1 saturates at 2^127 - 1", false, one(-MAX), one(MAX), false),
            ("S2 standard, t - ln M saturates at -2^63", false, one(1 << 62), one(1), true),
            ("S3 standard, num = 2^127 saturates (two limbs)", false, z3, v3, false),
            ("S4 standard, t - ln M near +2^63", false, one(-(1 << 62)), one(1), false),
            ("B1 bimodal, a - |y| - ln M saturates at -2^63", true, one(1 << 62), one(1), true),
            ("B2 bimodal, a - |y| - ln M near +2^63", true, one(0), one(MAX), false),
        ];
        for (name, bimodal, z, v, want) in cases {
            let mut st = Rng::new(&core::array::from_fn(|i| if i == 0 { 7 } else { 0 }), 0); // C's { 7 }
            for _ in 0..64 {
                let r = if bimodal { rej_bimodal(&mut st, &z, &v, &scm, &s2) } else { rej_standard(&mut st, &z, &v, &scm, &s2) };
                assert_eq!(r, Ok(want), "{name}");
            }
        }
    }
}
