//! `dcompress.c`: Dilithium-style decompose / power2round / hints over the coefficients of R_q (the rest of this file's
//! plan scope, `coder.c` and `bytes.c`, comes with the proof codec). Every C function here is coefficient-wise (each
//! output coefficient depends on the same input coefficients only), so they are ported per coefficient; the poly and
//! polyvec wrappers loop. Not ctime, as in C.
use crate::arith::int::{int_div, Int};

/// `dcompress_params_t`
#[derive(Clone, Copy, Debug)]
pub(crate) struct Dcomp {
    pub(crate) q: Int,
    pub(crate) qminus1: Int,
    pub(crate) m: Int,
    pub(crate) mby2: Int,
    pub(crate) gamma: Int,
    pub(crate) gammaby2: Int,
    pub(crate) pow2d: Int,
    pub(crate) pow2dby2: Int,
    pub(crate) d: u32,
    pub(crate) m_odd: bool,
    pub(crate) log2m: u32,
}

impl Dcomp {
    /// `dcompress_decompose`, one coefficient r in (-q, q): (r1, r0) with r = r1 gamma + r0 mod q,
    /// r0 in (-gamma/2, gamma/2]
    pub(crate) fn decompose(&self, r: &Int) -> (Int, Int) {
        let mut ng = self.gamma.n;
        while ng > 1 && self.gamma.l[ng - 1] == 0 {
            ng -= 1;
        }
        let mut gamma_ = Int::new(ng);
        gamma_.set(&self.gamma);

        let mut r1 = Int::new(r.n);
        r1.redp(r, &self.q);
        let mut t = Int::new(ng);
        t.mod_(&r1, &gamma_);
        let mut r0 = Int::new(r.n);
        r0.set(&t);
        if r0.sgn() == -1 {
            if r0.absle(&self.gammaby2) {
                r0.add(&{ r0 }, &self.gamma);
            }
        } else if r0.absgt(&self.gammaby2) {
            r0.sub(&{ r0 }, &self.gamma);
        }

        r1.sub(&{ r1 }, &r0);
        if r1.eq(&self.qminus1) {
            r1.set_i64(0);
            r0.sub(&{ r0 }, &Int::from_i64(r.n, 1));
        } else {
            let (mut rq, mut rr) = (Int::new(r.n - ng + 1), Int::new(ng));
            int_div(&mut rq, &mut rr, &r1, &gamma_);
            r1.set(&rq);
        }
        (r1, r0)
    }

    /// `dcompress_power2round`, one coefficient in (-q, q)
    pub(crate) fn power2round(&self, a: &Int) -> Int {
        let mut ret = Int::new(a.n);
        ret.redp(a, &self.q);
        let mut r0 = Int::new(a.n);
        r0.rshift(&ret, self.d);
        r0.lshift(&{ r0 }, self.d);
        r0.sub(&ret, &{ r0 });
        if r0.absgt(&self.pow2dby2) {
            r0.sub(&{ r0 }, &self.pow2d);
        }
        ret.sub(&{ ret }, &r0);
        ret.rshift(&{ ret }, self.d);
        ret
    }

    /// `dcompress_use_ghint`, one coefficient: r in (-q, q), y in (-m/2, m/2]; result in [0, m)
    pub(crate) fn use_ghint(&self, y: &Int, r: &Int) -> Int {
        let (mut ret, _) = self.decompose(r);
        ret.add(&{ ret }, y);
        ret.mod_(&{ ret }, &self.m);
        if ret.sgn() == -1 {
            ret.add(&{ ret }, &self.m);
        }
        ret
    }

    /// `dcompress_make_ghint`, one coefficient: r in [-(q-1)/2, (q-1)/2], z in [-gamma/2, gamma/2]
    pub(crate) fn make_ghint(&self, z: &Int, r: &Int) -> Int {
        let mut ret = Int::new(r.n);
        ret.add(r, z);
        let (r1, _) = self.decompose(r);
        let (mut ret, _) = self.decompose(&ret);
        ret.sub(&{ ret }, &r1);
        ret.mod_(&{ ret }, &self.m);
        if self.m_odd {
            ret.redc(&{ ret }, &self.m);
        } else if ret.sgn() == -1 {
            if ret.absge(&self.mby2) {
                ret.add(&{ ret }, &self.m);
            }
        } else if ret.absgt(&self.mby2) {
            ret.sub(&{ ret }, &self.m);
        }
        ret
    }
}
