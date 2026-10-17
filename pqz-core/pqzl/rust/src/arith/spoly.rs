//! `spolyvec.c` / `spolymat.c` (+ their inlines in lazer-in2.h): sparse vectors and matrices of [`Poly`]. One type
//! serves both: an entry's key is the vector index (`uint16_t elem`) or `row << 16 | col` (two `uint16_t`), which
//! orders entries exactly as the C comparators do, and the C code of the two is the same up to the key.
//!
//! As in C, entry slots keep their polys across `set_empty` and are reused by the next insertions (each caller then
//! overwrites the poly); a slot is created at its first use. An insertion past `nelems_max`, sorting a sorted list, a
//! repeated key and an operand that should be sorted and is not are C assertion failures (the sticky
//! `PQZ_ERR_INTERNAL`): `Error::Internal` here. Not ported (nothing in the core calls them): `redc` / `redp`,
//! `get_elem2`; the samplers come with Task 3.
use super::int::Int;
use super::poly::Poly;
use crate::Error;
use alloc::vec::Vec;

/// `spolyvec_t` / `spolymat_t`
#[derive(Clone, Debug)]
pub(crate) struct Sparse {
    /// entry slots: (poly, key); `slots[..nelems]` are the entries
    slots: Vec<(Poly, u32)>,
    nelems: usize,
    nelems_max: usize,
    sorted: bool,
    nrows: usize,
    ncols: usize,
}

pub(crate) type SPolyVec = Sparse;
pub(crate) type SPolyMat = Sparse;

impl Sparse {
    /// `spolyvec_alloc (r, ring, nelems, nelems_max)`: empty (and sorted)
    pub(crate) fn new_vec(nelems_max: usize) -> Sparse {
        Sparse { slots: Vec::new(), nelems: 0, nelems_max, sorted: true, nrows: 0, ncols: 0 }
    }

    /// `spolymat_alloc (r, ring, nrows, ncols, nelems_max)`
    pub(crate) fn new_mat(nrows: usize, ncols: usize, nelems_max: usize) -> Sparse {
        Sparse { nrows, ncols, ..Sparse::new_vec(nelems_max) }
    }

    pub(crate) fn nelems(&self) -> usize {
        self.nelems
    }

    pub(crate) fn nrows(&self) -> usize {
        self.nrows
    }

    pub(crate) fn ncols(&self) -> usize {
        self.ncols
    }

    pub(crate) fn sorted(&self) -> bool {
        self.sorted
    }

    /// `r->sorted = s` (lnp-tbox.c sets it after appending in key order, or clears it before a re-sort)
    pub(crate) fn set_sorted(&mut self, s: bool) {
        self.sorted = s;
    }

    /// `r->nelems_max = n` (lnp-tbox.c resizes its accumulators in place)
    pub(crate) fn set_nelems_max(&mut self, n: usize) {
        self.nelems_max = n;
    }

    /// entry i's poly (`spolyvec_get_elem` / `spolymat_get_elem`)
    pub(crate) fn get_elem(&mut self, i: usize) -> &mut Poly {
        &mut self.slots[i].0
    }

    /// entry i's vector index (`spolyvec_get_elem_`)
    pub(crate) fn elem(&self, i: usize) -> usize {
        self.slots[i].1 as usize
    }

    pub(crate) fn set_elem_(&mut self, i: usize, elem: usize) {
        self.slots[i].1 = elem as u16 as u32;
    }

    pub(crate) fn row(&self, i: usize) -> usize {
        (self.slots[i].1 >> 16) as usize
    }

    pub(crate) fn col(&self, i: usize) -> usize {
        (self.slots[i].1 & 0xffff) as usize
    }

    pub(crate) fn set_row(&mut self, i: usize, row: usize) {
        let k = &mut self.slots[i].1;
        *k = (*k & 0xffff) | ((row as u16 as u32) << 16);
    }

    pub(crate) fn set_col(&mut self, i: usize, col: usize) {
        let k = &mut self.slots[i].1;
        *k = (*k & !0xffff) | col as u16 as u32;
    }

    /// `set_empty`: no entries (the sorted flag is kept, as in C)
    pub(crate) fn set_empty(&mut self) {
        self.nelems = 0;
    }

    /// `spolyvec_swap` / `spolymat_swap`
    pub(crate) fn swap(a: &mut Sparse, b: &mut Sparse) {
        core::mem::swap(a, b);
    }

    fn insert(&mut self, key: u32) -> Result<&mut Poly, Error> {
        let n = self.nelems;
        if n >= self.nelems_max {
            return Err(Error::Internal);
        }
        if n == self.slots.len() {
            self.slots.try_reserve(1).map_err(|_| Error::Memory)?;
            self.slots.push((Poly::ZERO, 0));
        }
        self.slots[n].1 = key;
        self.nelems += 1;
        self.sorted = false;
        Ok(&mut self.slots[n].0)
    }

    /// `spolyvec_insert_elem`: the slot's poly (the caller sets it)
    pub(crate) fn insert_elem(&mut self, elem: usize) -> Result<&mut Poly, Error> {
        self.insert(elem as u16 as u32)
    }

    /// `spolymat_insert_elem`
    pub(crate) fn insert_rc(&mut self, row: usize, col: usize) -> Result<&mut Poly, Error> {
        self.insert(((row as u16 as u32) << 16) | col as u16 as u32)
    }

    /// `spolyvec_sort` / `spolymat_sort` (keys unique: every sort gives this order)
    pub(crate) fn sort(&mut self) -> Result<(), Error> {
        if self.sorted {
            return Err(Error::Internal);
        }
        let e = &mut self.slots[..self.nelems];
        e.sort_unstable_by_key(|s| s.1);
        if e.windows(2).any(|w| w[0].1 == w[1].1) {
            return Err(Error::Internal);
        }
        self.sorted = true;
        Ok(())
    }

    /// `spolymat_is_upperdiag` (C's NULL matrix is the caller's `None`)
    pub(crate) fn is_upperdiag(&self) -> bool {
        (0..self.nelems).all(|i| self.row(i) <= self.col(i))
    }

    /// `set (r, a)`: `a` sorted
    pub(crate) fn set(r: &mut Sparse, a: &Sparse) -> Result<(), Error> {
        if r.nelems_max < a.nelems || !a.sorted {
            return Err(Error::Internal);
        }
        r.nelems = 0;
        for i in 0..a.nelems {
            r.insert(a.slots[i].1)?.clone_from(&a.slots[i].0);
        }
        r.sorted = true;
        Ok(())
    }

    /// `add (r, a, b, crt)`: the merge of two sorted operands (`r` distinct from both), equal keys added
    pub(crate) fn add(r: &mut Sparse, a: &mut Sparse, b: &mut Sparse, crt: bool) -> Result<(), Error> {
        if !(a.sorted && b.sorted) {
            return Err(Error::Internal);
        }
        r.nelems = 0;
        let (mut i, mut j) = (0, 0);
        while i < a.nelems && j < b.nelems {
            let (ka, kb) = (a.slots[i].1, b.slots[j].1);
            if ka < kb {
                r.insert(ka)?.clone_from(&a.slots[i].0);
                i += 1;
            } else if kb < ka {
                r.insert(kb)?.clone_from(&b.slots[j].0);
                j += 1;
            } else {
                *r.insert(ka)? = Poly::add(&mut a.slots[i].0, &mut b.slots[j].0, crt);
                i += 1;
                j += 1;
            }
        }
        for (s, k) in [(&*a, i), (&*b, j)] {
            for e in &s.slots[k..s.nelems] {
                r.insert(e.1)?.clone_from(&e.0);
            }
        }
        r.sorted = true;
        Ok(())
    }

    pub(crate) fn fromcrt(&mut self) {
        for s in &mut self.slots[..self.nelems] {
            s.0.fromcrt();
        }
    }

    /// `r[k] = f(b[k])` over `b`'s entries (`r` distinct from `b`, `r.nelems_max >= b.nelems_max`)
    fn map(r: &mut Sparse, b: &mut Sparse, mut f: impl FnMut(&mut Poly) -> Poly) -> Result<(), Error> {
        if r.nelems_max < b.nelems_max {
            return Err(Error::Internal);
        }
        r.nelems = 0;
        for s in &mut b.slots[..b.nelems] {
            *r.insert(s.1)? = f(&mut s.0);
        }
        r.sorted = b.sorted;
        Ok(())
    }

    pub(crate) fn lrot(r: &mut Sparse, b: &mut Sparse, n: usize) -> Result<(), Error> {
        Sparse::map(r, b, |p| Poly::lrot(p, n))
    }

    pub(crate) fn mod_(r: &mut Sparse, b: &mut Sparse) -> Result<(), Error> {
        Sparse::map(r, b, Poly::mod_)
    }

    pub(crate) fn scale(r: &mut Sparse, a: &Int, b: &mut Sparse) -> Result<(), Error> {
        Sparse::map(r, b, |p| Poly::scale(a, p))
    }

    /// `scale2 (r, a, b)`: r[k] = a * b[k]
    pub(crate) fn scale2(r: &mut Sparse, a: &mut Poly, b: &mut Sparse) -> Result<(), Error> {
        Sparse::map(r, b, |p| Poly::mul(a, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C's assertion failures (insertion past nelems_max, sorting twice, a repeated key) are `Error::Internal`
    #[test]
    fn errors_and_order() {
        let mut m = Sparse::new_mat(3, 3, 3);
        for (r, c) in [(2, 0), (0, 2), (0, 1)] {
            m.insert_rc(r, c).unwrap().v[0] = (3 * r + c) as u64;
        }
        assert_eq!(m.insert_rc(1, 1).err(), Some(Error::Internal));
        m.sort().unwrap();
        assert_eq!(m.sort(), Err(Error::Internal));
        assert_eq!((0..3).map(|i| (m.row(i), m.col(i), m.get_elem(i).v[0])).collect::<Vec<_>>(),
                   [(0, 1, 1), (0, 2, 2), (2, 0, 6)]);
        assert!(!m.is_upperdiag());
        m.set_empty();
        m.insert_rc(1, 1).unwrap();
        m.insert_rc(1, 1).unwrap();
        assert_eq!(m.sort(), Err(Error::Internal));
    }
}
