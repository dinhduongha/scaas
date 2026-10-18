//! `polymat.c` (+ the polymat inlines of lazer-in2.h): matrices of [`Poly`], owned ([`PolyMat`], row-major) or as
//! strided views [`Sm`] (`polymat_get_submat`), through the [`Pm`] trait; rows and columns are [`Sv`] views.
//! Not ported (nothing in the core calls them): the arithmetic (`polymat_add` .. `subscalediag2`, `rrot`, `mod`,
//! `redc` / `redp`), `subdiags_set_zero`, the `*diag` forms, `set_one` / diagonals; `polymat_urandom` is in `rand::urandom`.
use super::poly::Poly;
use super::polyvec::Sv;
use crate::Error;
use alloc::vec::Vec;

/// read access to a matrix of polys
pub(crate) trait PmRef {
    fn nrows(&self) -> usize;
    fn ncols(&self) -> usize;
    fn get(&self, i: usize, j: usize) -> &Poly;
}

/// a matrix of polys
pub(crate) trait Pm: PmRef {
    fn at(&mut self, i: usize, j: usize) -> &mut Poly;
}

/// `polymat_t` (owned, row-major)
#[derive(Clone, Debug)]
pub(crate) struct PolyMat {
    e: Vec<Poly>,
    nrows: usize,
    ncols: usize,
}

impl PolyMat {
    /// `polymat_alloc` (zero polys); `Error::Memory` if the allocation fails
    pub(crate) fn new(nrows: usize, ncols: usize) -> Result<PolyMat, Error> {
        let n = nrows.checked_mul(ncols).ok_or(Error::Memory)?;
        let mut e = Vec::new();
        e.try_reserve_exact(n).map_err(|_| Error::Memory)?;
        e.resize(n, Poly::ZERO);
        Ok(PolyMat { e, nrows, ncols })
    }

    pub(crate) fn view(&mut self) -> Sm<'_> {
        Sm { e: &mut self.e, nrows: self.nrows, ncols: self.ncols, rs: self.ncols, cs: 1 }
    }

    /// `polymat_get_submat (sub, self, row, col, nrows, ncols, stride_row, stride_col)`
    pub(crate) fn sub(&mut self, row: usize, col: usize, nrows: usize, ncols: usize, sr: usize, sc: usize) -> Sm<'_> {
        self.view().into_sub(row, col, nrows, ncols, sr, sc)
    }

    /// `polymat_get_row`
    pub(crate) fn row(&mut self, i: usize) -> Sv<'_> {
        let n = self.ncols;
        Sv::new(&mut self.e[i * n..], n, 1)
    }

    /// `polymat_get_col`
    pub(crate) fn col(&mut self, j: usize) -> Sv<'_> {
        Sv::new(&mut self.e[j..], self.nrows, self.ncols)
    }
}

impl PmRef for PolyMat {
    fn nrows(&self) -> usize {
        self.nrows
    }
    fn ncols(&self) -> usize {
        self.ncols
    }
    fn get(&self, i: usize, j: usize) -> &Poly {
        assert!(i < self.nrows && j < self.ncols);
        &self.e[i * self.ncols + j]
    }
}

impl Pm for PolyMat {
    fn at(&mut self, i: usize, j: usize) -> &mut Poly {
        assert!(i < self.nrows && j < self.ncols);
        &mut self.e[i * self.ncols + j]
    }
}

/// a strided matrix view: element (i, j) is `e[i * rs + j * cs]`
pub(crate) struct Sm<'a> {
    e: &'a mut [Poly],
    nrows: usize,
    ncols: usize,
    rs: usize,
    cs: usize,
}

impl<'a> Sm<'a> {
    fn new(e: &'a mut [Poly], nrows: usize, ncols: usize, rs: usize, cs: usize) -> Sm<'a> {
        assert!(nrows == 0 || ncols == 0 || (nrows - 1) * rs + (ncols - 1) * cs < e.len(), "view out of range");
        Sm { e, nrows, ncols, rs, cs }
    }

    /// `polymat_get_submat` of a view
    pub(crate) fn sub(&mut self, row: usize, col: usize, nrows: usize, ncols: usize, sr: usize, sc: usize) -> Sm<'_> {
        Sm { e: &mut *self.e, ..*self }.into_sub(row, col, nrows, ncols, sr, sc)
    }

    fn into_sub(self, row: usize, col: usize, nrows: usize, ncols: usize, sr: usize, sc: usize) -> Sm<'a> {
        assert!(nrows == 0 || row + sr * (nrows - 1) < self.nrows, "rows out of range");
        assert!(ncols == 0 || col + sc * (ncols - 1) < self.ncols, "columns out of range");
        let (off, rs, cs) = (row * self.rs + col * self.cs, sr * self.rs, sc * self.cs);
        let e = self.e;
        Sm::new(&mut e[off..], nrows, ncols, rs, cs)
    }

    pub(crate) fn row(&mut self, i: usize) -> Sv<'_> {
        Sv::new(&mut self.e[i * self.rs..], self.ncols, self.cs)
    }

    pub(crate) fn col(&mut self, j: usize) -> Sv<'_> {
        Sv::new(&mut self.e[j * self.cs..], self.nrows, self.rs)
    }
}

impl PmRef for Sm<'_> {
    fn nrows(&self) -> usize {
        self.nrows
    }
    fn ncols(&self) -> usize {
        self.ncols
    }
    fn get(&self, i: usize, j: usize) -> &Poly {
        assert!(i < self.nrows && j < self.ncols);
        &self.e[i * self.rs + j * self.cs]
    }
}

impl Pm for Sm<'_> {
    fn at(&mut self, i: usize, j: usize) -> &mut Poly {
        assert!(i < self.nrows && j < self.ncols);
        &mut self.e[i * self.rs + j * self.cs]
    }
}

fn each<M: Pm + ?Sized>(r: &mut M, mut f: impl FnMut(&mut Poly)) {
    for i in 0..r.nrows() {
        for j in 0..r.ncols() {
            f(r.at(i, j));
        }
    }
}

pub(crate) fn set_zero<M: Pm + ?Sized>(r: &mut M) {
    each(r, Poly::set_zero);
}

pub(crate) fn tocrt<M: Pm + ?Sized>(r: &mut M) {
    each(r, Poly::tocrt);
}

pub(crate) fn fromcrt<M: Pm + ?Sized>(r: &mut M) {
    each(r, Poly::fromcrt);
}

/// `polymat_auto (r, a)`: X → X^-1 per element
pub(crate) fn auto<R: Pm + ?Sized, A: Pm + ?Sized>(r: &mut R, a: &mut A) {
    for i in 0..r.nrows() {
        for j in 0..r.ncols() {
            *r.at(i, j) = Poly::auto(a.at(i, j));
        }
    }
}

/// `polymat_lrot (r, a, n)`
pub(crate) fn lrot<R: Pm + ?Sized, A: Pm + ?Sized>(r: &mut R, a: &mut A, n: usize) {
    for i in 0..r.nrows() {
        for j in 0..r.ncols() {
            *r.at(i, j) = Poly::lrot(a.at(i, j), n);
        }
    }
}

/// `polymat_is_upperdiag` (variable-time; moves every element to the coefficient domain first). C's NULL matrix
/// (upper diagonal) is the caller's `None`.
pub(crate) fn is_upperdiag<M: Pm + ?Sized>(a: &mut M) -> bool {
    fromcrt(a);
    let mut zero = Poly::ZERO;
    for i in 1..a.nrows() {
        for j in 0..i.min(a.ncols()) {
            if !Poly::eq(a.at(i, j), &mut zero) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::polyvec::{PolyVec, PvRef};

    /// views address the elements C's `get_submat` / `get_row` / `get_col` / `get_subvec` do
    #[test]
    fn views() {
        let mut m = PolyMat::new(4, 5).unwrap();
        for i in 0..4 {
            for j in 0..5 {
                m.at(i, j).v[0] = (10 * i + j) as u64;
            }
        }
        let tag = |p: &Poly| p.v[0];
        let mut s = m.sub(1, 1, 2, 2, 2, 3); // rows 1, 3; cols 1, 4
        assert_eq!([tag(s.get(0, 0)), tag(s.get(0, 1)), tag(s.get(1, 0)), tag(s.get(1, 1))], [11, 14, 31, 34]);
        assert_eq!(tag(s.sub(1, 0, 1, 2, 1, 1).get(0, 1)), 34);
        assert_eq!([tag(s.row(1).get(0)), tag(s.row(1).get(1))], [31, 34]);
        assert_eq!([tag(s.col(1).get(0)), tag(s.col(1).get(1))], [14, 34]);
        assert_eq!(tag(m.row(2).get(4)), 24);
        assert_eq!([tag(m.col(3).get(0)), tag(m.col(3).get(3))], [3, 33]);
        let mut v = PolyVec::new(9).unwrap();
        v.iter_mut().enumerate().for_each(|(i, p)| p.v[0] = i as u64);
        let mut w = v.sub(1, 4, 2); // 1, 3, 5, 7
        let w2 = w.sub(1, 2, 2); // 3, 7
        assert_eq!((w2.len(), tag(w2.get(0)), tag(w2.get(1))), (2, 3, 7));
    }
}
