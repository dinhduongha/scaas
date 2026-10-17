//! `polyvec.c` (+ the polyvec inlines of lazer-in2.h and the poly functions over vectors from poly.c): vectors of
//! [`Poly`] as owned [`PolyVec`]s, slices, or strided views [`Sv`] (`polyvec_get_subvec`, matrix rows / columns), all
//! through the [`Pv`] trait. Operands C converts between domains are `&mut`, as for [`Poly`].
//!
//! C's in-place calls (`polyvec_mod (x, x)`, `polyvec_add (r, r, b, crt)`) are the `*_self` / `*_assign` forms. The
//! `add*` / `sub*` accumulations run per element where C fills a temporary vector first: the two phases touch disjoint
//! polys, so the result and every operand's final state are the same, without the temporary.
//! Not ported (nothing in the core calls them): `polyvec_eq`, `rshift`, `rrot`, `muldiag(2)`, `addmul2` / `submul2`,
//! `addrshift` / `subrshift` / `addlshift`, `addscale2`, `elem_mul`, `toisoring` / `fromisoring`; the samplers come
//! with Task 3, `polyvec_set_coeffvec2` (coefficients shared with an `intvec`) with the code that uses it.
use super::int::Int;
use super::poly::Poly;
use super::polymat::Pm;
use super::spoly::Sparse;
use crate::coder::Dcomp;
use crate::Error;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

/// read access to a vector of polys
pub(crate) trait PvRef {
    fn len(&self) -> usize;
    fn get(&self, i: usize) -> &Poly;
}

/// a vector of polys
pub(crate) trait Pv: PvRef {
    fn at(&mut self, i: usize) -> &mut Poly;
}

impl PvRef for [Poly] {
    fn len(&self) -> usize {
        <[Poly]>::len(self)
    }
    fn get(&self, i: usize) -> &Poly {
        &self[i]
    }
}

impl Pv for [Poly] {
    fn at(&mut self, i: usize) -> &mut Poly {
        &mut self[i]
    }
}

/// `polyvec_t` (owned)
#[derive(Clone, Debug)]
pub(crate) struct PolyVec(pub(crate) Vec<Poly>);

impl PolyVec {
    /// `polyvec_alloc` (zero polys); `Error::Memory` if the allocation fails
    pub(crate) fn new(n: usize) -> Result<PolyVec, Error> {
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::Memory)?;
        v.resize(n, Poly::ZERO);
        Ok(PolyVec(v))
    }

    /// `polyvec_get_subvec (sub, self, off, n, stride)`
    pub(crate) fn sub(&mut self, off: usize, n: usize, stride: usize) -> Sv<'_> {
        Sv::new(&mut self.0[off..], n, stride)
    }
}

impl Deref for PolyVec {
    type Target = [Poly];
    fn deref(&self) -> &[Poly] {
        &self.0
    }
}

impl DerefMut for PolyVec {
    fn deref_mut(&mut self) -> &mut [Poly] {
        &mut self.0
    }
}

impl PvRef for PolyVec {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, i: usize) -> &Poly {
        &self.0[i]
    }
}

impl Pv for PolyVec {
    fn at(&mut self, i: usize) -> &mut Poly {
        &mut self.0[i]
    }
}

/// a strided view: element i is `e[i * s]`
pub(crate) struct Sv<'a> {
    e: &'a mut [Poly],
    n: usize,
    s: usize,
}

impl<'a> Sv<'a> {
    pub(crate) fn new(e: &'a mut [Poly], n: usize, s: usize) -> Sv<'a> {
        assert!(n == 0 || (n - 1) * s < e.len(), "view out of range");
        Sv { e, n, s }
    }

    /// `polyvec_get_subvec` of a view
    pub(crate) fn sub(&mut self, off: usize, n: usize, stride: usize) -> Sv<'_> {
        Sv::new(&mut self.e[off * self.s..], n, stride * self.s)
    }
}

impl PvRef for Sv<'_> {
    fn len(&self) -> usize {
        self.n
    }
    fn get(&self, i: usize) -> &Poly {
        assert!(i < self.n);
        &self.e[i * self.s]
    }
}

impl Pv for Sv<'_> {
    fn at(&mut self, i: usize) -> &mut Poly {
        assert!(i < self.n);
        &mut self.e[i * self.s]
    }
}

/// the NTT-domain zero a product accumulates into (`r->crt = 1; memset (r->crtrep, 0, ...)`)
const CRT_ZERO: Poly = Poly { v: [0; super::ntt::D], neg: 0, crt: true };

/// `polyvec_set` (`poly_set`: the source keeps its domain)
pub(crate) fn set<R: Pv + ?Sized, A: PvRef + ?Sized>(r: &mut R, a: &A) {
    for i in 0..r.len() {
        r.at(i).clone_from(a.get(i));
    }
}

pub(crate) fn set_zero<R: Pv + ?Sized>(r: &mut R) {
    for i in 0..r.len() {
        r.at(i).set_zero();
    }
}

pub(crate) fn neg_self<R: Pv + ?Sized>(r: &mut R) {
    for i in 0..r.len() {
        r.at(i).neg_self();
    }
}

pub(crate) fn tocrt<R: Pv + ?Sized>(r: &mut R) {
    for i in 0..r.len() {
        r.at(i).tocrt();
    }
}

pub(crate) fn fromcrt<R: Pv + ?Sized>(r: &mut R) {
    for i in 0..r.len() {
        r.at(i).fromcrt();
    }
}

/// `r[i] = f(a[i])`
fn map<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A, f: impl Fn(&mut Poly) -> Poly) {
    for i in 0..r.len() {
        *r.at(i) = f(a.at(i));
    }
}

/// `r[i] = f(r[i])`
fn map_self<R: Pv + ?Sized>(r: &mut R, f: impl Fn(&mut Poly) -> Poly) {
    for i in 0..r.len() {
        let p = r.at(i);
        *p = f(p);
    }
}

pub(crate) fn mod_<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A) {
    map(r, a, Poly::mod_);
}

pub(crate) fn redc<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A) {
    map(r, a, Poly::redc);
}

pub(crate) fn redp<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A) {
    map(r, a, Poly::redp);
}

/// `polyvec_mod (r, r)`
pub(crate) fn mod_self<R: Pv + ?Sized>(r: &mut R) {
    map_self(r, Poly::mod_);
}

pub(crate) fn redc_self<R: Pv + ?Sized>(r: &mut R) {
    map_self(r, Poly::redc);
}

pub(crate) fn redp_self<R: Pv + ?Sized>(r: &mut R) {
    map_self(r, Poly::redp);
}

/// `polyvec_auto` (X → X^-1 per element; `r` and `a` distinct, as C asserts)
pub(crate) fn auto<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A) {
    map(r, a, Poly::auto);
}

pub(crate) fn auto_self<R: Pv + ?Sized>(r: &mut R) {
    for i in 0..r.len() {
        r.at(i).auto_self();
    }
}

pub(crate) fn lrot<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A, n: usize) {
    map(r, a, |p| Poly::lrot(p, n));
}

pub(crate) fn add<R: Pv + ?Sized, A: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut A, b: &mut B, crt: bool) {
    for i in 0..r.len() {
        *r.at(i) = Poly::add(a.at(i), b.at(i), crt);
    }
}

pub(crate) fn sub<R: Pv + ?Sized, A: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut A, b: &mut B, crt: bool) {
    for i in 0..r.len() {
        *r.at(i) = Poly::sub(a.at(i), b.at(i), crt);
    }
}

/// `polyvec_add (r, r, b, crt)`
pub(crate) fn add_assign<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, b: &mut B, crt: bool) {
    for i in 0..r.len() {
        r.at(i).add_assign(b.at(i), crt);
    }
}

/// `polyvec_sub (r, r, b, crt)`
pub(crate) fn sub_assign<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, b: &mut B, crt: bool) {
    for i in 0..r.len() {
        r.at(i).sub_assign(b.at(i), crt);
    }
}

/// `polyvec_scale (r, a, b)`: `a.n == 1`
pub(crate) fn scale<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &Int, b: &mut B) {
    map(r, b, |p| Poly::scale(a, p));
}

/// `polyvec_scale (r, a, r)`
pub(crate) fn scale_self<R: Pv + ?Sized>(r: &mut R, a: &Int) {
    map_self(r, |p| Poly::scale(a, p));
}

pub(crate) fn addscale<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &Int, b: &mut B, crt: bool) {
    for i in 0..r.len() {
        r.at(i).addscale(a, b.at(i), crt);
    }
}

pub(crate) fn subscale<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &Int, b: &mut B, crt: bool) {
    for i in 0..r.len() {
        r.at(i).subscale(a, b.at(i), crt);
    }
}

/// `polyvec_scale2 (r, a, b)`: r[i] = a * b[i]
pub(crate) fn scale2<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut Poly, b: &mut B) {
    for i in 0..r.len() {
        *r.at(i) = Poly::mul(a, b.at(i));
    }
}

pub(crate) fn subscale2<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut Poly, b: &mut B, crt: bool) {
    for i in 0..r.len() {
        r.at(i).submul(a, b.at(i), crt);
    }
}

/// `polyvec_sublshift (r, a, n)`: r -= a << n (coefficient domain)
pub(crate) fn sublshift<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A, n: u32) {
    for i in 0..r.len() {
        r.at(i).sub_assign(&mut Poly::lshift(a.at(i), n), false);
    }
}

/// sum of `n` products (each moving its factors to the NTT domain), in the NTT domain
fn dot_with(n: usize, mut prod: impl FnMut(usize) -> Poly) -> Poly {
    let mut r = CRT_ZERO;
    for j in 0..n {
        r.add_assign(&mut prod(j), true);
    }
    r
}

/// `polyvec_dot (r, a, b)`
pub(crate) fn dot<A: Pv + ?Sized, B: Pv + ?Sized>(a: &mut A, b: &mut B) -> Poly {
    dot_with(a.len(), |j| Poly::mul(a.at(j), b.at(j)))
}

/// `polyvec_dot2 (r, a, b)`: sparse `a`
pub(crate) fn dot2<B: Pv + ?Sized>(a: &mut Sparse, b: &mut B) -> Poly {
    dot_with(a.nelems(), |j| {
        let e = a.elem(j);
        Poly::mul(a.get_elem(j), b.at(e))
    })
}

/// `poly_adddot (r, a, b, crt)`
pub(crate) fn adddot<A: Pv + ?Sized, B: Pv + ?Sized>(r: &mut Poly, a: &mut A, b: &mut B, crt: bool) {
    r.add_assign(&mut dot(a, b), crt);
}

pub(crate) fn subdot<A: Pv + ?Sized, B: Pv + ?Sized>(r: &mut Poly, a: &mut A, b: &mut B, crt: bool) {
    r.sub_assign(&mut dot(a, b), crt);
}

/// `poly_adddot2 (r, a, b, crt)`
pub(crate) fn adddot2<B: Pv + ?Sized>(r: &mut Poly, a: &mut Sparse, b: &mut B, crt: bool) {
    r.add_assign(&mut dot2(a, b), crt);
}

/// `polyvec_mul (r, a, b)`: matrix times vector
pub(crate) fn mul<R: Pv + ?Sized, M: Pm + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut M, b: &mut B) {
    for i in 0..a.nrows() {
        *r.at(i) = dot_with(a.ncols(), |j| Poly::mul(a.at(i, j), b.at(j)));
    }
}

/// `polyvec_addmul (r, a, b, crt)`: r += a b
pub(crate) fn addmul<R: Pv + ?Sized, M: Pm + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut M, b: &mut B, crt: bool) {
    for i in 0..a.nrows() {
        let mut t = dot_with(a.ncols(), |j| Poly::mul(a.at(i, j), b.at(j)));
        r.at(i).add_assign(&mut t, crt);
    }
}

/// `polyvec_submul (r, a, b, crt)`: r -= a b
pub(crate) fn submul<R: Pv + ?Sized, M: Pm + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut M, b: &mut B, crt: bool) {
    for i in 0..a.nrows() {
        let mut t = dot_with(a.ncols(), |j| Poly::mul(a.at(i, j), b.at(j)));
        r.at(i).sub_assign(&mut t, crt);
    }
}

/// `poly_addmul2 (r, a, b, crt)`: r += a b for a one-row matrix
pub(crate) fn poly_addmul2<M: Pm + ?Sized, B: Pv + ?Sized>(r: &mut Poly, a: &mut M, b: &mut B, crt: bool) {
    let mut t = dot_with(a.ncols(), |j| Poly::mul(a.at(0, j), b.at(j)));
    r.add_assign(&mut t, crt);
}

/// `polyvec_mul2 (r, a, b)`: vector times matrix; a zero column of `b` (public data, `pqz_poly_is_zero_pub`) gives an
/// NTT-domain zero without the products
pub(crate) fn mul2<R: Pv + ?Sized, A: Pv + ?Sized, M: Pm + ?Sized>(r: &mut R, a: &mut A, b: &mut M) {
    for i in 0..b.ncols() {
        *r.at(i) = if (0..b.nrows()).all(|j| b.get(j, i).is_zero_pub()) {
            CRT_ZERO
        } else {
            dot_with(a.len(), |j| Poly::mul(a.at(j), b.at(j, i)))
        };
    }
}

/// `polyvec_mulsparse (r, a, b)`: sparse matrix times vector
pub(crate) fn mulsparse<R: Pv + ?Sized, B: Pv + ?Sized>(r: &mut R, a: &mut Sparse, b: &mut B) {
    for i in 0..r.len() {
        *r.at(i) = CRT_ZERO;
    }
    for i in 0..a.nelems() {
        let (row, col) = (a.row(i), a.col(i));
        r.at(row).addmul(a.get_elem(i), b.at(col), true);
    }
}

/// `polyvec_l2sqr`: two limbs
pub(crate) fn l2sqr<A: Pv + ?Sized>(a: &mut A) -> Int {
    let mut r = Int::new(2);
    for i in 0..a.len() {
        r.add(&{ r }, &a.at(i).l2sqr());
    }
    r
}

/// `polyvec_linf` (variable-time)
pub(crate) fn linf<A: Pv + ?Sized>(a: &mut A) -> Int {
    let mut r = Int::new(1);
    for i in 0..a.len() {
        let t = a.at(i).linf();
        if t.absgt(&r) {
            r.set(&t);
        }
    }
    r
}

pub(crate) fn power2round<R: Pv + ?Sized, A: Pv + ?Sized>(r: &mut R, a: &mut A, p: &Dcomp) {
    map(r, a, |x| Poly::power2round(x, p));
}

pub(crate) fn decompose<R1: Pv + ?Sized, R0: Pv + ?Sized, A: Pv + ?Sized>(r1: &mut R1, r0: &mut R0, r: &mut A, p: &Dcomp) {
    for i in 0..r1.len() {
        let (h, l) = Poly::decompose(r.at(i), p);
        *r1.at(i) = h;
        *r0.at(i) = l;
    }
}

pub(crate) fn use_ghint<R: Pv + ?Sized, Y: Pv + ?Sized, A: Pv + ?Sized>(ret: &mut R, y: &mut Y, r: &mut A, p: &Dcomp) {
    for i in 0..ret.len() {
        *ret.at(i) = Poly::use_ghint(y.at(i), r.at(i), p);
    }
}

pub(crate) fn make_ghint<R: Pv + ?Sized, Z: Pv + ?Sized, A: Pv + ?Sized>(ret: &mut R, z: &mut Z, r: &mut A, p: &Dcomp) {
    for i in 0..ret.len() {
        *ret.at(i) = Poly::make_ghint(z.at(i), r.at(i), p);
    }
}
