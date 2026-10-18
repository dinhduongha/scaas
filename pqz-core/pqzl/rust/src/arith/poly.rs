//! `poly.c` (+ the poly inlines of lazer-in2.h and `pqz_glue.h`): an element of R_q, either 64 coefficients (sign-
//! magnitude, one limb: the ring's `q` has one limb) or, after `tocrt`, the four NTT residue blocks of `ntt.rs`.
//!
//! Domain changes of operands are part of the C semantics: `poly_add (r, a, b, crt)` moves `a` and `b` to a common
//! domain in place, `poly_mul` moves both factors to the NTT domain, most coefficient operations move their input back.
//! A move there and back is not the identity (it centres the coefficients), so operands that C converts are `&mut`
//! here and are converted the same way. C keeps the stale coefficients while a poly is in the NTT domain and the stale
//! residues while it is not; no code path reads them, so one buffer holds whichever is live.
//!
//! Results are returned by value (`*r = Poly::add(a, b, crt)`): C writes every live word of `r` (domain flag and the
//! whole live representation), so nothing of the old `r` survives in either form, and `r` may be one of the operands
//! (`*a = Poly::add(a, b, crt)`), as in C.
use super::int::{int_modq, Int, IntVec};
use super::ntt::{self, D, Q};
use crate::coder::Dcomp;
use crate::Error;

/// the one ring of every relation (pqz_*_params.h): q, log2 q, 2^-1 mod q as `int_t` (-(q-1)/2)
pub(crate) const RING_Q: Int = Int::from_limbs(&[Q], 0);
pub(crate) const LOG2Q: u32 = 42;
pub(crate) const RING_INV2: Int = Int::from_limbs(&[(Q - 1) / 2], 1);

#[derive(Clone, Debug)]
pub(crate) struct Poly {
    /// coefficient magnitudes, or the NTT residues (in [0, q)) when `crt`
    pub(crate) v: [u64; D],
    /// coefficient signs, bit j for coefficient j (unused when `crt`)
    pub(crate) neg: u64,
    pub(crate) crt: bool,
}

impl Default for Poly {
    fn default() -> Poly {
        Poly::ZERO
    }
}

/// `_to_same_dom`: the domain the operation runs in
fn same_dom(a: &mut Poly, b: &mut Poly, crt: bool) -> bool {
    if a.crt != b.crt {
        if crt {
            a.tocrt();
            b.tocrt();
        } else {
            a.fromcrt();
            b.fromcrt();
        }
        return crt;
    }
    a.crt
}

impl Poly {
    pub(crate) const ZERO: Poly = Poly { v: [0; D], neg: 0, crt: false };

    /// coefficient j (caller ensures the coefficient domain)
    pub(crate) fn c(&self, j: usize) -> Int {
        let mut r = Int::new(1);
        r.l[0] = self.v[j];
        r.neg = (self.neg >> j) & 1;
        r
    }

    /// coefficient j := a (`int_set` into one limb: truncates)
    pub(crate) fn put(&mut self, j: usize, a: &Int) {
        self.v[j] = a.l[0];
        self.neg = (self.neg & !(1 << j)) | ((a.neg & 1) << j);
    }

    /// a poly from a coefficient function (coefficient domain)
    fn from_fn(mut f: impl FnMut(usize) -> Int) -> Poly {
        let mut r = Poly::ZERO;
        for j in 0..D {
            r.put(j, &f(j));
        }
        r
    }

    /// `poly_tocrt`: coefficients → [0, q) → incomplete NTT
    pub(crate) fn tocrt(&mut self) {
        if self.crt {
            return;
        }
        for j in 0..D {
            self.v[j] = int_modq(&self.c(j));
        }
        ntt::fwd(&mut self.v);
        self.crt = true;
    }

    /// `poly_fromcrt`: inverse NTT, then the centred representatives in [-(q-1)/2, (q-1)/2] (`pqz_int_set_centred`)
    pub(crate) fn fromcrt(&mut self) {
        if !self.crt {
            return;
        }
        ntt::inv(&mut self.v);
        self.neg = 0;
        for j in 0..D {
            let v = self.v[j];
            let big = (v > (Q - 1) / 2) as u64;
            let m = big.wrapping_neg();
            self.v[j] = (v & !m) | ((Q - v) & m);
            self.neg |= big << j;
        }
        self.crt = false;
    }

    /// `poly_get_coeff` (moves the poly to the coefficient domain)
    pub(crate) fn get_coeff(&mut self, j: usize) -> Int {
        self.fromcrt();
        self.c(j)
    }

    /// `poly_set_coeff`
    pub(crate) fn set_coeff(&mut self, j: usize, a: &Int) {
        self.fromcrt();
        self.put(j, a);
    }

    pub(crate) fn set_zero(&mut self) {
        *self = Poly::ZERO;
    }

    pub(crate) fn set_one(&mut self) {
        *self = Poly::ZERO;
        self.v[0] = 1;
    }

    /// `poly_set_coeffvec_i64`
    pub(crate) fn set_i64(&mut self, a: &[i64]) {
        *self = Poly::from_fn(|j| Int::from_i64(1, a[j]));
    }

    /// `pqz_poly_is_zero_pub` (variable-time; public data only)
    /// (either domain; a negative zero coefficient is zero, `int_eqzero`)
    pub(crate) fn is_zero_pub(&self) -> bool {
        self.v.iter().all(|&x| x == 0)
    }

    /// coefficient-wise `f(a_j, b_j)` then `int_redc` mod q (`intvec_add` / `intvec_sub` + `intvec_redc`)
    fn coeffwise_redc(a: &Poly, b: &Poly, f: impl Fn(&mut Int, &Int, &Int)) -> Poly {
        Poly::from_fn(|j| {
            let mut t = Int::new(1);
            f(&mut t, &a.c(j), &b.c(j));
            let mut r = Int::new(1);
            r.redc(&t, &RING_Q);
            r
        })
    }

    pub(crate) fn add(a: &mut Poly, b: &mut Poly, crt: bool) -> Poly {
        if same_dom(a, b, crt) {
            Poly { v: ntt::add(&a.v, &b.v), neg: 0, crt: true }
        } else {
            Poly::coeffwise_redc(a, b, Int::add)
        }
    }

    pub(crate) fn sub(a: &mut Poly, b: &mut Poly, crt: bool) -> Poly {
        if same_dom(a, b, crt) {
            Poly { v: ntt::sub(&a.v, &b.v), neg: 0, crt: true }
        } else {
            Poly::coeffwise_redc(a, b, Int::sub)
        }
    }

    /// `poly_add (r, r, b, crt)`
    pub(crate) fn add_assign(&mut self, b: &mut Poly, crt: bool) {
        let mut a = core::mem::take(self);
        *self = Poly::add(&mut a, b, crt);
    }

    /// `poly_sub (r, r, b, crt)`
    pub(crate) fn sub_assign(&mut self, b: &mut Poly, crt: bool) {
        let mut a = core::mem::take(self);
        *self = Poly::sub(&mut a, b, crt);
    }

    /// `poly_neg` (via the coefficient domain)
    pub(crate) fn neg(b: &mut Poly) -> Poly {
        b.fromcrt();
        Poly { v: b.v, neg: !b.neg, crt: false }
    }

    /// `poly_neg_self` (in the domain it is in)
    pub(crate) fn neg_self(&mut self) {
        if self.crt {
            for x in self.v.iter_mut() {
                *x = ntt::csubq(Q - *x);
            }
        } else {
            self.neg = !self.neg;
        }
    }

    /// `poly_scale`: `a.n == 1`; coefficients a * b_j mod q, centred
    pub(crate) fn scale(a: &Int, b: &mut Poly) -> Poly {
        b.fromcrt();
        Poly::from_fn(|j| {
            let mut t = Int::new(2 * a.n);
            t.mul(a, &b.c(j));
            let mut r = Int::new(1);
            r.mod_(&t, &RING_Q);
            r.redc(&{ r }, &RING_Q);
            r
        })
    }

    /// coefficient-wise unary `f(a_j)` after moving `a` to the coefficient domain
    fn coeffwise(a: &mut Poly, f: impl Fn(&mut Int, &Int)) -> Poly {
        a.fromcrt();
        Poly::from_fn(|j| {
            let mut r = Int::new(1);
            f(&mut r, &a.c(j));
            r
        })
    }

    pub(crate) fn rshift(a: &mut Poly, n: u32) -> Poly {
        Poly::coeffwise(a, |r, x| r.rshift(x, n))
    }

    pub(crate) fn lshift(a: &mut Poly, n: u32) -> Poly {
        Poly::coeffwise(a, |r, x| r.lshift(x, n))
    }

    /// `poly_mod`: coefficients in (-q, q) with their signs
    pub(crate) fn mod_(a: &mut Poly) -> Poly {
        Poly::coeffwise(a, |r, x| r.mod_(x, &RING_Q))
    }

    pub(crate) fn redc(a: &mut Poly) -> Poly {
        Poly::coeffwise(a, |r, x| r.redc(x, &RING_Q))
    }

    pub(crate) fn redp(a: &mut Poly) -> Poly {
        Poly::coeffwise(a, |r, x| r.redp(x, &RING_Q))
    }

    /// `poly_rrot` (`intvec_rrot`): multiply by X^-n, n < 64
    pub(crate) fn rrot(a: &mut Poly, n: usize) -> Poly {
        a.fromcrt();
        Poly::from_fn(|i| if i < D - n { a.c(i + n) } else { Int::neg_of(&a.c(i + n - D)) })
    }

    /// `poly_lrot` (`intvec_lrot`): multiply by X^n, n < 64
    pub(crate) fn lrot(a: &mut Poly, n: usize) -> Poly {
        a.fromcrt();
        Poly::from_fn(|i| if i >= n { a.c(i - n) } else { Int::neg_of(&a.c(D - n + i)) })
    }

    /// `poly_eq` (both move to the coefficient domain; `int_eq`: -0 == 0)
    pub(crate) fn eq(a: &mut Poly, b: &mut Poly) -> bool {
        a.fromcrt();
        b.fromcrt();
        (0..D).fold(true, |e, j| e & a.c(j).eq(&b.c(j)))
    }

    /// `poly_mul`: both factors move to the NTT domain; the product is in it
    pub(crate) fn mul(a: &mut Poly, b: &mut Poly) -> Poly {
        a.tocrt();
        b.tocrt();
        Poly { v: ntt::basemul(&a.v, &b.v), neg: 0, crt: true }
    }

    pub(crate) fn addmul(&mut self, a: &mut Poly, b: &mut Poly, crt: bool) {
        self.add_assign(&mut Poly::mul(a, b), crt);
    }

    pub(crate) fn submul(&mut self, a: &mut Poly, b: &mut Poly, crt: bool) {
        self.sub_assign(&mut Poly::mul(a, b), crt);
    }

    pub(crate) fn addscale(&mut self, a: &Int, b: &mut Poly, crt: bool) {
        self.add_assign(&mut Poly::scale(a, b), crt);
    }

    pub(crate) fn subscale(&mut self, a: &Int, b: &mut Poly, crt: bool) {
        self.sub_assign(&mut Poly::scale(a, b), crt);
    }

    /// `poly_tracemap`: coefficients in (-q, q)
    pub(crate) fn tracemap(a: &mut Poly) -> Poly {
        a.fromcrt();
        let h = D / 2;
        let mut r = Poly::ZERO;
        r.put(0, &a.c(0));
        for i in 1..h {
            let mut t = Int::new(1);
            t.sub(&a.c(i), &a.c(D - i));
            let mut prod = Int::new(2);
            prod.mul(&t, &RING_INV2);
            t.mod_(&prod, &RING_Q);
            t.redc(&{ t }, &RING_Q);
            r.put(i, &t);
        }
        r.put(h, &Int::new(1));
        for i in h + 1..D {
            r.put(i, &Int::neg_of(&r.c(2 * h - i)));
        }
        r
    }

    /// `poly_auto`: X → X^-1 (via the coefficient domain)
    pub(crate) fn auto(a: &mut Poly) -> Poly {
        a.fromcrt();
        Poly::from_fn(|i| match i {
            0 => a.c(0),
            _ => Int::neg_of(&a.c(D - i)),
        })
    }

    /// `poly_auto_self`: X → X^-1 in place, via the coefficient domain as `auto` (the NTT branch, reached by no
    /// relation, converts first)
    pub(crate) fn auto_self(&mut self) {
        self.fromcrt();
        let a = self.clone();
        for i in 1..D {
            self.put(i, &Int::neg_of(&a.c(D - i)));
        }
    }

    /// `poly_l2sqr`: two limbs
    pub(crate) fn l2sqr(&mut self) -> Int {
        self.fromcrt();
        let mut r = Int::new(2);
        for j in 0..D {
            r.addsqr(&self.c(j));
        }
        r
    }

    /// `poly_linf` (variable-time)
    pub(crate) fn linf(&mut self) -> Int {
        self.fromcrt();
        let mut max = self.c(0);
        for j in 1..D {
            if self.c(j).absgt(&max) {
                max = self.c(j);
            }
        }
        max.neg = 0;
        max
    }

    /// `int_binexp (upsilon, powB, B)`: the binary expansion of `B` (`upsilon`) and the powers of two `<= B` (`powB`),
    /// over log2 q bits; `B.n == 1`
    pub(crate) fn binexp(mut upsilon: Option<&mut Poly>, mut pow_b: Option<&mut Poly>, b: &Int) {
        let mut b_ = Int::new(1);
        b_.set(b);
        if let Some(u) = upsilon.as_deref_mut() {
            u.set_zero();
        }
        if let Some(p) = pow_b.as_deref_mut() {
            p.set_zero();
        }
        for i in (0..LOG2Q).rev() {
            let mut pow2 = Int::from_i64(1, 1);
            pow2.lshift(&{ pow2 }, i);
            if let Some(p) = pow_b.as_deref_mut() {
                if pow2.le(b) {
                    p.set_coeff(i as usize, &pow2);
                }
            }
            if let Some(u) = upsilon.as_deref_mut() {
                if b_.ge(&pow2) {
                    b_.sub(&{ b_ }, &pow2);
                    u.set_coeff(i as usize, &Int::from_i64(1, 1));
                }
            }
        }
    }

    /// `poly_dcompress_power2round`
    pub(crate) fn power2round(a: &mut Poly, p: &Dcomp) -> Poly {
        Poly::coeffwise(a, |r, x| *r = p.power2round(x))
    }

    /// `poly_dcompress_decompose`: (r1, r0)
    pub(crate) fn decompose(r: &mut Poly, p: &Dcomp) -> (Poly, Poly) {
        r.fromcrt();
        let (mut r1, mut r0) = (Poly::ZERO, Poly::ZERO);
        for j in 0..D {
            let (h, l) = p.decompose(&r.c(j));
            r1.put(j, &h);
            r0.put(j, &l);
        }
        (r1, r0)
    }

    /// `poly_dcompress_use_ghint (ret, y, r)`
    pub(crate) fn use_ghint(y: &mut Poly, r: &mut Poly, p: &Dcomp) -> Poly {
        y.fromcrt();
        r.fromcrt();
        Poly::from_fn(|j| p.use_ghint(&y.c(j), &r.c(j)))
    }

    /// `poly_dcompress_make_ghint (ret, z, r)`
    pub(crate) fn make_ghint(z: &mut Poly, r: &mut Poly, p: &Dcomp) -> Poly {
        z.fromcrt();
        r.fromcrt();
        Poly::from_fn(|j| p.make_ghint(&z.c(j), &r.c(j)))
    }

    /// `poly_urandom (r, mod, log2mod, seed, dom)`: `_urandom` on the 64 one-limb coefficients
    pub(crate) fn urandom(m: &Int, log2mod: u32, seed: &[u8; 32], dom: u64) -> Result<Poly, Error> {
        let mut v = IntVec::new(D, 1)?;
        crate::rand::urandom::urandom(&mut v, m, log2mod, seed, dom)?;
        Ok(Poly::from_fn(|j| v.get(j)))
    }

    /// `poly_urandom_bnd (r, lo, hi, seed, dom)`: coefficients uniform in [lo, hi]
    pub(crate) fn urandom_bnd(lo: &Int, hi: &Int, seed: &[u8; 32], dom: u64) -> Result<Poly, Error> {
        let mut v = IntVec::new(D, 1)?;
        crate::rand::urandom::urandom_bnd(&mut v, lo, hi, seed, dom)?;
        Ok(Poly::from_fn(|j| v.get(j)))
    }

    /// `poly_urandom_autostable (r, bnd, log2, seed, dom)`: a challenge fixed by X -> X^-1
    pub(crate) fn urandom_autostable(bnd: i64, log2: u32, seed: &[u8; 32], dom: u64) -> Result<Poly, Error> {
        let mut v = [0i64; D];
        crate::rand::urandom::urandom_autostable(&mut v, bnd, log2, seed, dom)?;
        let mut r = Poly::ZERO;
        r.set_i64(&v);
        Ok(r)
    }

    /// `poly_grandom (r, log2o, seed, dom)`: discrete Gaussian, sigma = 1.55 * 2^log2o
    pub(crate) fn grandom(log2o: u32, seed: &[u8; 32], dom: u64) -> Result<Poly, Error> {
        let mut v = [0i64; D];
        crate::rand::grandom::grandom(&mut v, log2o, seed, dom)?;
        let mut r = Poly::ZERO;
        r.set_i64(&v);
        Ok(r)
    }

    /// `poly_brandom (r, k, seed, dom)`: centred binomial, parameter k
    pub(crate) fn brandom(k: u32, seed: &[u8; 32], dom: u64) -> Result<Poly, Error> {
        let mut v = [0i8; D];
        crate::rand::brandom::brandom(&mut v, k, seed, dom)?;
        Ok(Poly::from_fn(|j| Int::from_i64(1, v[j] as i64)))
    }
}
