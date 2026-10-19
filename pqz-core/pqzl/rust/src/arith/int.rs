//! LaZer's `int_t` (sign-magnitude, `n` 64-bit limbs; lazer-in2.h §3.3, int.c), `intvec_t` (intvec.c) and the
//! `pqz_glue.h` reductions, with the C semantics kept exactly: limb arithmetic wraps at `n` limbs, a negative zero is
//! a value (`int_eq` / `int_lt` treat it as zero, `int_sgn` as +1), `int_set` truncates to the destination's limbs.
//!
//! `Int` is a value (`Copy`, at most `MAXL` limbs): where C aliases `r` and `a` (`int_add (r, r, b)`), pass a copy
//! (`r.add(&{ r }, &b)`); every C function reads an operand before it writes the same limb of `r`, so the results
//! agree. Not ported (nothing in the core calls them): `int_invmod`, `int_import` / `int_export`, the `_ct` add / sub
//! / redc variants, `int_mul1`, `intvec_mul` / `div` / `rrot` / `lrot` / `auto` (the poly layer has its own).
//!
//! Constant time (review fix E, 2026-10-19; C the same): add / sub / redc / redp have no branch and no address on the
//! operands' values (the prover runs them on secrets); the results are upstream's, bit for bit.
use super::mpn;
use crate::ct::mask;
use super::ntt::{red128, Q};
use crate::Error;
use alloc::vec::Vec;

/// the most limbs any int of the core has (scaled rejection constants: 3, their products: 6)
pub(crate) const MAXL: usize = 8;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Int {
    /// limbs `l[0..n)`, least significant first; `l[n..]` stay 0
    pub(crate) l: [u64; MAXL],
    pub(crate) n: usize,
    /// 0 or 1
    pub(crate) neg: u64,
}

fn eq_zero_ct(a: &[u64]) -> u64 {
    limb_eq_ct(a.iter().fold(0, |r, x| r | x), 0)
}

fn limb_eq_ct(a: u64, b: u64) -> u64 {
    let t = a ^ b;
    1 ^ ((t | t.wrapping_neg()) >> 63)
}

fn eq_ct(a: &[u64], b: &[u64]) -> u64 {
    limb_eq_ct(a.iter().zip(b).fold(0, |r, (x, y)| r | (x ^ y)), 0)
}

fn limbs_add(r: &mut [u64], a: &[u64], b: &[u64]) -> u64 {
    let mut c = false;
    for i in 0..r.len() {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(c as u64);
        r[i] = s;
        c = c1 | c2;
    }
    c as u64
}

fn limbs_sub(r: &mut [u64], a: &[u64], b: &[u64]) -> u64 {
    let mut c = false;
    for i in 0..r.len() {
        let (s, c1) = a[i].overflowing_sub(b[i]);
        let (s, c2) = s.overflowing_sub(c as u64);
        r[i] = s;
        c = c1 | c2;
    }
    c as u64
}

/// borrow of `a - b` (`limbs_lt_ct`), and whether `a - b` is zero
fn sub_flags(a: &[u64], b: &[u64]) -> (u64, u64) {
    let mut t = [0u64; MAXL];
    let c = limbs_sub(&mut t[..a.len()], a, b);
    (c, eq_zero_ct(&t[..a.len()]))
}

impl Int {
    pub(crate) const fn new(n: usize) -> Int {
        assert!(n >= 1 && n <= MAXL);
        Int { l: [0; MAXL], n, neg: 0 }
    }

    /// a constant (params): `limbs.len()` limbs
    pub(crate) const fn from_limbs(limbs: &[u64], neg: u64) -> Int {
        let mut r = Int::new(limbs.len());
        let mut i = 0;
        while i < limbs.len() {
            r.l[i] = limbs[i];
            i += 1;
        }
        r.neg = neg;
        r
    }

    pub(crate) fn from_i64(n: usize, v: i64) -> Int {
        let mut r = Int::new(n);
        r.set_i64(v);
        r
    }

    pub(crate) fn limbs(&self) -> &[u64] {
        &self.l[..self.n]
    }

    /// `int_set`: zero the limbs above `a`'s, copy the common ones (truncating), copy the sign
    pub(crate) fn set(&mut self, a: &Int) {
        let k = self.n.min(a.n);
        self.l[k..self.n].fill(0);
        self.l[..k].copy_from_slice(&a.l[..k]);
        self.neg = a.neg;
    }

    pub(crate) fn set_i64(&mut self, v: i64) {
        self.neg = (v as u64) >> 63;
        self.l[0] = v.unsigned_abs();
        self.l[1..self.n].fill(0);
    }

    /// `int_get_i64`: ±limb 0, wrapping
    pub(crate) fn get_i64(&self) -> i64 {
        ((1 - 2 * self.neg as i64) as u64).wrapping_mul(self.l[0]) as i64
    }

    pub(crate) fn neg_self(&mut self) {
        self.neg ^= 1;
    }

    /// `int_neg`
    pub(crate) fn neg_of(a: &Int) -> Int {
        let mut r = *a;
        r.neg ^= 1;
        r
    }

    /// `int_sgn`: +1 for any zero (also a negative zero), else the sign
    pub(crate) fn sgn(&self) -> i32 {
        let b = eq_zero_ct(self.limbs()) as i32;
        (-1 + (b << 1)) & (1 - ((self.neg as i32) << 1))
    }

    pub(crate) fn mul_sgn_self(&mut self, sgn: i32) {
        self.neg = ((1 - self.sgn() * sgn) as u64) >> 1;
    }

    pub(crate) fn eqzero(&self) -> bool {
        eq_zero_ct(self.limbs()) != 0
    }

    pub(crate) fn abseq(&self, b: &Int) -> bool {
        eq_ct(self.limbs(), b.limbs()) != 0
    }

    pub(crate) fn abslt(&self, b: &Int) -> bool {
        sub_flags(self.limbs(), b.limbs()).0 != 0
    }

    pub(crate) fn absle(&self, b: &Int) -> bool {
        let (c, z) = sub_flags(self.limbs(), b.limbs());
        (c | z) != 0
    }

    pub(crate) fn absgt(&self, b: &Int) -> bool {
        sub_flags(b.limbs(), self.limbs()).0 != 0
    }

    pub(crate) fn absge(&self, b: &Int) -> bool {
        let (c, z) = sub_flags(b.limbs(), self.limbs());
        (c | z) != 0
    }

    /// signs with negative zeros made positive, |a| == |b|, |a| < |b| (`int_eq` .. `int_ge`)
    fn cmp_parts(&self, b: &Int) -> (u64, u64, u64, u64, u64) {
        let an = self.neg & (1 ^ eq_zero_ct(self.limbs()));
        let bn = b.neg & (1 ^ eq_zero_ct(b.limbs()));
        let eq = eq_ct(self.limbs(), b.limbs());
        let lt = sub_flags(self.limbs(), b.limbs()).0;
        let gt = sub_flags(b.limbs(), self.limbs()).0;
        (an, bn, eq, lt, gt)
    }

    pub(crate) fn eq(&self, b: &Int) -> bool {
        let (an, bn, eq, _, _) = self.cmp_parts(b);
        ((1 ^ an ^ bn) & eq) != 0
    }

    pub(crate) fn lt(&self, b: &Int) -> bool {
        let (an, bn, eq, lt, _) = self.cmp_parts(b);
        (((an ^ bn) & an) | (an & bn & (1 ^ lt) & (1 ^ eq)) | ((1 ^ an) & (1 ^ bn) & lt)) != 0
    }

    pub(crate) fn le(&self, b: &Int) -> bool {
        let (an, bn, eq, lt, _) = self.cmp_parts(b);
        (((an ^ bn) & an) | (an & bn & (1 ^ lt)) | ((1 ^ an) & (1 ^ bn) & (lt | eq))) != 0
    }

    pub(crate) fn gt(&self, b: &Int) -> bool {
        let (an, bn, eq, _, gt) = self.cmp_parts(b);
        (((an ^ bn) & (1 ^ an)) | (an & bn & (1 ^ gt) & (1 ^ eq)) | ((1 ^ an) & (1 ^ bn) & gt)) != 0
    }

    pub(crate) fn ge(&self, b: &Int) -> bool {
        let (an, bn, eq, _, gt) = self.cmp_parts(b);
        (((an ^ bn) & (1 ^ an)) | (an & bn & (1 ^ gt)) | ((1 ^ an) & (1 ^ bn) & (gt | eq))) != 0
    }

    /// `int_rshift` (of the magnitude; the sign is copied)
    pub(crate) fn rshift(&mut self, a: &Int, sh: u32) {
        let (mut nl, mut nb) = ((sh / 64) as usize, sh % 64);
        if nl >= a.n {
            nl = a.n;
            nb = 0;
        }
        let k = self.n.min(a.n - nl);
        self.l[..k].copy_from_slice(&a.l[nl..nl + k]);
        self.l[k..self.n].fill(0);
        if nb > 0 {
            mpn::rshift(&mut self.l[..self.n], nb);
        }
        self.neg = a.neg;
    }

    /// `int_lshift` (of the magnitude, truncated to `n` limbs; the sign is copied)
    pub(crate) fn lshift(&mut self, a: &Int, sh: u32) {
        let (nl, nb) = ((sh / 64) as usize, sh % 64);
        let mut t = [0u64; MAXL];
        let hi = self.n.min(a.n + nl);
        if hi > nl {
            t[nl..hi].copy_from_slice(&a.l[..hi - nl]);
        }
        self.l = t;
        if nb > 0 {
            mpn::lshift(&mut self.l[..self.n], nb);
        }
        self.neg = a.neg;
    }

    /// `int_add` / `int_sub` (C `pqz_int_addsub`): b's sign `bneg`. Upstream's sign-magnitude branches as masks:
    /// same sign: |a| + |b|, sign a; else |a| - |b|, on a borrow negated if its top bit is set (`limbs_from_twoscom`)
    /// and with sign `bneg`, else sign a
    fn addsub(&mut self, a: &Int, b: &Int, bneg: u64) {
        let n = self.n;
        let (mut s, mut d, mut nd) = ([0u64; MAXL], [0u64; MAXL], [0u64; MAXL]);
        limbs_add(&mut s[..n], &a.l[..n], &b.l[..n]);
        let c = limbs_sub(&mut d[..n], &a.l[..n], &b.l[..n]);
        let mut cy = true;
        for i in 0..n {
            (nd[i], cy) = (!d[i]).overflowing_add(cy as u64);
        }
        let diff = mask(1 ^ limb_eq_ct(a.neg, bneg));
        let borrow = mask(c) & diff;
        let flip = borrow & (d[n - 1] >> 63).wrapping_neg();
        for i in 0..n {
            self.l[i] = (s[i] & !diff) | (nd[i] & flip) | (d[i] & diff & !flip);
        }
        self.neg = (bneg & borrow) | (a.neg & !borrow);
    }

    /// `int_add`
    pub(crate) fn add(&mut self, a: &Int, b: &Int) {
        self.addsub(a, b, b.neg);
    }

    /// `int_sub`: a + (-b)
    pub(crate) fn sub(&mut self, a: &Int, b: &Int) {
        self.addsub(a, b, limb_eq_ct(b.neg, 0));
    }

    /// `int_redc`: [-(m-1), m-1] → [-(m-1)/2, (m-1)/2] (constant time since review E; C `limbs_lt` was variable-time)
    pub(crate) fn redc(&mut self, a: &Int, m: &Int) {
        let n = m.n;
        let mut t = [0u64; MAXL];
        limbs_sub(&mut t[..n], &m.l[..n], &a.l[..n]);
        let b = sub_flags(&t[..n], &a.l[..n]).0;
        let k = mask(b);
        for ((r, x), y) in self.l[..n].iter_mut().zip(&a.l).zip(&t) {
            *r = (x & !k) | (y & k);
        }
        self.neg = b ^ a.neg;
    }

    /// `int_redp`: [-(m-1), m-1] → [0, m-1]
    pub(crate) fn redp(&mut self, a: &Int, m: &Int) {
        let n = a.n;
        let mut t = [0u64; MAXL];
        limbs_sub(&mut t[..n], &m.l[..n], &a.l[..n]);
        let b = mask(a.neg & (1 ^ eq_zero_ct(a.limbs())));
        for (i, x) in self.l[..self.n].iter_mut().enumerate() {
            *x = (a.l[i] & !b) | (t[i] & b);
        }
        self.neg = 0;
    }

    /// `int_mul`: `self.n == 2 * a.n`
    pub(crate) fn mul(&mut self, a: &Int, b: &Int) {
        mpn::sec_mul(&mut self.l, a.limbs(), b.limbs());
        self.neg = a.neg ^ b.neg;
    }

    pub(crate) fn sqr(&mut self, a: &Int) {
        mpn::sec_mul(&mut self.l, a.limbs(), a.limbs());
        self.neg = 0;
    }

    pub(crate) fn addmul(&mut self, a: &Int, b: &Int) {
        let mut t = Int::new(self.n);
        t.mul(a, b);
        self.add(&{ *self }, &t);
    }

    pub(crate) fn submul(&mut self, a: &Int, b: &Int) {
        let mut t = Int::new(self.n);
        t.mul(a, b);
        self.sub(&{ *self }, &t);
    }

    pub(crate) fn addsqr(&mut self, a: &Int) {
        let mut t = Int::new(self.n);
        t.sqr(a);
        self.add(&{ *self }, &t);
    }

    pub(crate) fn subsqr(&mut self, a: &Int) {
        let mut t = Int::new(self.n);
        t.sqr(a);
        self.sub(&{ *self }, &t);
    }

    /// `int_mod`: result in [-(m-1), m-1] with the sign of `a`; `self.n == m.n`
    pub(crate) fn mod_(&mut self, a: &Int, m: &Int) {
        if m.n == 1 {
            self.set_i64(int_mod1(a, m.l[0]));
        } else {
            let mut t = a.l;
            mpn::div(None, &mut t[..a.n], m.limbs());
            self.l[..self.n].copy_from_slice(&t[..self.n]);
            self.neg = a.neg;
        }
    }
}

/// `int_div` (divisor public): `rq.n == a.n - nb + 1`, `rr.n == nb` where `nb` = `b`'s limbs without zero top limbs;
/// both get the sign `a.neg ^ b.neg`
pub(crate) fn int_div(rq: &mut Int, rr: &mut Int, a: &Int, b: &Int) {
    let mut nb = b.n;
    while nb > 1 && b.l[nb - 1] == 0 {
        nb -= 1;
    }
    let mut t = a.l;
    let top = mpn::div(Some(&mut rq.l[..a.n - nb]), &mut t[..a.n], &b.l[..nb]);
    rq.l[rq.n - 1] = top;
    rr.l[..nb].copy_from_slice(&t[..nb]);
    rq.neg = a.neg ^ b.neg;
    rr.neg = rq.neg;
}

/// `pqz_absmod1`: |a| mod m for a single-limb m < 2^63 (q: `red128` per limb; else 64 masked shift-subtract steps
/// per limb)
pub(crate) fn absmod1(a: &Int, m: u64) -> u64 {
    let mut r = 0u64;
    if m == Q {
        for k in (0..a.n).rev() {
            r = red128(((r as u128) << 64) | a.l[k] as u128);
        }
        return r;
    }
    for k in (0..a.n).rev() {
        for b in (0..64).rev() {
            r = (r << 1) | ((a.l[k] >> b) & 1);
            let t = r.wrapping_sub(m);
            r = t.wrapping_add(m & ((t as i64 >> 63) as u64));
        }
    }
    r
}

/// `pqz_int_mod1`: result in (-m, m) with the sign of `a`
pub(crate) fn int_mod1(a: &Int, m: u64) -> i64 {
    let r = absmod1(a, m) as i64;
    let s = -((a.neg & 1) as i64);
    (r ^ s).wrapping_sub(s)
}

/// `pqz_int_modq`: a mod q in [0, q)
pub(crate) fn int_modq(a: &Int) -> u64 {
    let r = absmod1(a, Q);
    let neg = (a.neg & 1).wrapping_neg();
    super::ntt::csubq((r & !neg) | (Q.wrapping_sub(r) & neg))
}

/// `intvec_t`: `len` ints of `nlimbs` limbs each, stored flat (`nlimbs` limbs then the sign per element)
#[derive(Clone, Debug)]
pub(crate) struct IntVec {
    nlimbs: usize,
    w: Vec<u64>,
}

impl IntVec {
    /// zero vector; `Error::Memory` if the allocation fails
    pub(crate) fn new(len: usize, nlimbs: usize) -> Result<IntVec, Error> {
        assert!((1..=MAXL).contains(&nlimbs));
        let words = len.checked_mul(nlimbs + 1).ok_or(Error::Memory)?;
        let mut w = Vec::new();
        w.try_reserve_exact(words).map_err(|_| Error::Memory)?;
        w.resize(words, 0);
        Ok(IntVec { nlimbs, w })
    }

    pub(crate) fn len(&self) -> usize {
        self.w.len() / (self.nlimbs + 1)
    }

    pub(crate) fn nlimbs(&self) -> usize {
        self.nlimbs
    }

    pub(crate) fn get(&self, i: usize) -> Int {
        let k = self.nlimbs + 1;
        let e = &self.w[i * k..(i + 1) * k];
        let mut r = Int::new(self.nlimbs);
        r.l[..self.nlimbs].copy_from_slice(&e[..self.nlimbs]);
        r.neg = e[self.nlimbs];
        r
    }

    /// `intvec_set_elem` (`int_set` semantics: truncates / zero-extends to `nlimbs`)
    pub(crate) fn set_elem(&mut self, i: usize, a: &Int) {
        let mut r = Int::new(self.nlimbs);
        r.set(a);
        let k = self.nlimbs + 1;
        let e = &mut self.w[i * k..(i + 1) * k];
        e[..self.nlimbs].copy_from_slice(r.limbs());
        e[self.nlimbs] = r.neg;
    }

    pub(crate) fn get_elem_i64(&self, i: usize) -> i64 {
        self.get(i).get_i64()
    }

    pub(crate) fn set_elem_i64(&mut self, i: usize, v: i64) {
        self.set_elem(i, &Int::from_i64(self.nlimbs, v));
    }

    pub(crate) fn set_zero(&mut self) {
        self.w.fill(0);
    }

    pub(crate) fn set_ones(&mut self) {
        for i in 0..self.len() {
            self.set_elem_i64(i, 1);
        }
    }

    pub(crate) fn set_i64(&mut self, a: &[i64]) {
        for (i, &v) in a[..self.len()].iter().enumerate() {
            self.set_elem_i64(i, v);
        }
    }

    /// `intvec_set`: `self.len() >= a.len()`; elements past `a` become zero
    pub(crate) fn set(&mut self, a: &IntVec) {
        for i in a.len()..self.len() {
            self.set_elem_i64(i, 0);
        }
        for i in 0..a.len() {
            self.set_elem(i, &a.get(i));
        }
    }

    /// `r[i] = f(r[i])`, the result truncated to `nlimbs` (`int_set`)
    fn map(&mut self, mut f: impl FnMut(&mut Int, &Int)) {
        for i in 0..self.len() {
            let a = self.get(i);
            let mut r = a;
            f(&mut r, &a);
            self.set_elem(i, &r);
        }
    }

    /// `intvec_add (r, r, b)`
    pub(crate) fn add_assign(&mut self, b: &IntVec) {
        for i in 0..self.len() {
            let mut r = self.get(i);
            r.add(&{ r }, &b.get(i));
            self.set_elem(i, &r);
        }
    }

    /// `intvec_sub (r, r, b)`
    pub(crate) fn sub_assign(&mut self, b: &IntVec) {
        for i in 0..self.len() {
            let mut r = self.get(i);
            r.sub(&{ r }, &b.get(i));
            self.set_elem(i, &r);
        }
    }

    /// `intvec_mod (r, r, m)`; `nlimbs == m.n`
    pub(crate) fn mod_self(&mut self, m: &Int) {
        self.map(|r, a| r.mod_(a, m));
    }

    pub(crate) fn redc_self(&mut self, m: &Int) {
        self.map(|r, a| r.redc(a, m));
    }

    pub(crate) fn redp_self(&mut self, m: &Int) {
        self.map(|r, a| r.redp(a, m));
    }

    pub(crate) fn rshift_self(&mut self, sh: u32) {
        self.map(|r, a| r.rshift(a, sh));
    }

    pub(crate) fn lshift_self(&mut self, sh: u32) {
        self.map(|r, a| r.lshift(a, sh));
    }

    pub(crate) fn neg_self(&mut self) {
        self.map(|r, _| r.neg_self());
    }

    pub(crate) fn mul_sgn_self(&mut self, sgn: i32) {
        self.map(|r, _| r.mul_sgn_self(sgn));
    }

    /// `intvec_dot`: `r.n == 2 * nlimbs`
    pub(crate) fn dot(r: &mut Int, a: &IntVec, b: &IntVec) {
        r.set_i64(0);
        for i in 0..a.len() {
            r.addmul(&a.get(i), &b.get(i));
        }
    }

    /// `intvec_l2sqr`: `r.n == 2 * nlimbs`
    pub(crate) fn l2sqr(&self, r: &mut Int) {
        r.set_i64(0);
        for i in 0..self.len() {
            r.addsqr(&self.get(i));
        }
    }

    /// `intvec_linf` (variable-time): the first element of largest magnitude, sign cleared
    pub(crate) fn linf(&self, r: &mut Int) {
        let mut max = self.get(0);
        for i in 1..self.len() {
            let a = self.get(i);
            if a.absgt(&max) {
                max = a;
            }
        }
        r.set(&max);
        r.neg = 0;
    }

    pub(crate) fn eq(&self, b: &IntVec) -> bool {
        (0..self.len()).fold(true, |e, i| e & self.get(i).eq(&b.get(i)))
    }

    /// every element `< m` (`intvec_lt`)
    pub(crate) fn lt(&self, m: &Int) -> bool {
        (0..self.len()).fold(true, |e, i| e & self.get(i).lt(m))
    }

    pub(crate) fn le(&self, m: &Int) -> bool {
        (0..self.len()).fold(true, |e, i| e & self.get(i).le(m))
    }

    pub(crate) fn gt(&self, m: &Int) -> bool {
        (0..self.len()).fold(true, |e, i| e & self.get(i).gt(m))
    }

    pub(crate) fn ge(&self, m: &Int) -> bool {
        (0..self.len()).fold(true, |e, i| e & self.get(i).ge(m))
    }
}
