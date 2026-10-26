//! `urandom.c`: uniform samplers, and the vector / matrix forms of `polyvec.c` / `polymat.c` with their domain
//! counters (`union dom`: low 32 bits a per-element counter, high 32 bits the caller's `dom`).
//!
//! `intmat_urandom` (lnp-quad-eval.c, lnp-tbox.c) is [`urandom`] per row with `dom << 32 | i * ncols`; it lands with
//! the int-matrix code of the proof tasks.
use super::rng::Rng;
use crate::arith::int::{Int, IntVec};
use crate::arith::poly::Poly;
use crate::arith::polymat::Pm;
use crate::arith::polyvec::Pv;
use crate::Error;
use alloc::vec::Vec;

/// `_urandom_i64`: `vec.len()` values uniform in [0, m), 2^(log2mod-1) <= m < 2^log2mod, by rejection on
/// log2mod-bit chunks (LSB first) of the `Rng (seed, dom)` stream, refilled per round for the values still missing.
/// C's range asserts set the sticky internal error: `Error::Internal` here.
pub(crate) fn urandom_i64(vec: &mut [i64], m: i64, log2mod: u32, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    if !(1..64).contains(&log2mod) || m < 1 << (log2mod - 1) || m >= 1 << log2mod {
        return Err(Error::Internal);
    }
    let nb = log2mod as usize;
    let mut st = Rng::new(seed, dom);
    let mut out = Vec::new();
    let mut k = 0;
    while k < vec.len() {
        let l = vec.len() - k;
        let outlen = (nb * l).div_ceil(8);
        out.clear();
        out.try_reserve(outlen).map_err(|_| Error::Memory)?;
        out.resize(outlen, 0);
        st.urandom(&mut out)?;
        for i in 0..l {
            let mut t = 0i64;
            for j in 0..nb {
                let bit = i * nb + j;
                t |= (((out[bit >> 3] >> (bit & 7)) & 1) as i64) << j;
            }
            // review E: uniform rejection sampling, the accept bit (and the slot k) is independent of the accepted
            // values: public
            let acc = ((m - 1 - t) >> 63) & 1 == 0;
            let acc = crate::ct::verdict(acc);
            if acc {
                vec[k] = t;
                k += 1;
            }
        }
    }
    Ok(())
}

/// `_urandom_bnd`: elements uniform in [lo, hi]: per element, (8 top + ceil(nbits_top / 8)) stream bytes into the
/// limbs (little-endian), the top limb masked to the bit length of hi - lo, retried while above |hi - lo|, plus lo.
/// C loops forever for hi = lo (the mask search never ends): `Error::Internal` here.
pub(crate) fn urandom_bnd(r: &mut IntVec, lo: &Int, hi: &Int, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    let n = r.nlimbs();
    if lo.n > n || hi.n > n {
        return Err(Error::Internal);
    }
    let (mut l, mut h, mut tmp) = (Int::new(n), Int::new(n), Int::new(n));
    l.set(lo);
    h.set(hi);
    tmp.sub(&h, &l);
    let mut top = n - 1;
    while tmp.l[top] == 0 && top > 0 {
        top -= 1;
    }
    if tmp.l[top] == 0 {
        return Err(Error::Internal);
    }
    let lz = tmp.l[top].leading_zeros();
    let (mask, nbits_top) = (u64::MAX >> lz, 64 - lz as usize);
    let nbytes = 8 * top + nbits_top.div_ceil(8);
    let mut st = Rng::new(seed, dom);
    let mut buf = [0u8; 8 * crate::arith::int::MAXL];
    for i in 0..r.len() {
        let mut e = Int::new(n);
        loop {
            st.urandom(&mut buf[..nbytes])?;
            for (k, w) in e.l[..=top].iter_mut().enumerate() {
                *w = u64::from_le_bytes(buf[8 * k..8 * k + 8].try_into().unwrap_or_default());
            }
            e.l[top] &= mask;
            let again = gt(&e.l[..n], &tmp.l[..n]);
            let again = crate::ct::verdict(again); // review E: the try count of uniform rejection sampling is public
            if !again {
                break;
            }
        }
        let x = e;
        e.add(&x, &l);
        r.set_elem(i, &e);
    }
    Ok(())
}

/// `limbs_gt_ct`: a > b (magnitudes)
fn gt(a: &[u64], b: &[u64]) -> bool {
    let mut r = false;
    for (x, y) in a.iter().zip(b) {
        r = (x > y) | ((x == y) & r); // review E: '&', no short-circuit branch on the sample
    }
    r
}

/// `_urandom` (`intvec_urandom`): uniform in [0, m) for log2mod < 60, else C's multi-limb path, `_urandom_bnd` on
/// [0, (m - 1) >> 1] (as C: half the range; no caller of the core reaches it, every modulus is q, LOG2Q < 60 bits)
pub(crate) fn urandom(r: &mut IntVec, m: &Int, log2mod: u32, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    if log2mod < 60 {
        let mut v = Vec::new();
        v.try_reserve_exact(r.len()).map_err(|_| Error::Memory)?;
        v.resize(r.len(), 0);
        urandom_i64(&mut v, m.get_i64(), log2mod, seed, dom)?;
        r.set_i64(&v);
        return Ok(());
    }
    let n = r.nlimbs();
    let mut hi = Int::new(n);
    hi.set(m);
    let x = hi;
    hi.sub(&x, &Int::from_i64(n, 1));
    let x = hi;
    hi.rshift(&x, 1);
    urandom_bnd(r, &Int::new(n), &hi, seed, dom)
}

/// `_intvec_urandom_autostable`: n / 2 values uniform in [-bnd, bnd] (`_urandom_i64` mod 2 bnd + 1), then 0, then the
/// first half negated in reverse order (a challenge fixed by the automorphism X -> X^-1)
pub(crate) fn urandom_autostable(r: &mut [i64], bnd: i64, log2: u32, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    let n = r.len();
    if n == 0 || !n.is_multiple_of(2) {
        return Err(Error::Internal);
    }
    let h = n / 2;
    urandom_i64(&mut r[..h], 2 * bnd + 1, log2, seed, dom)?;
    for x in &mut r[..h] {
        *x -= bnd;
    }
    r[h] = 0;
    for i in h + 1..n {
        r[i] = -r[n - i];
    }
    Ok(())
}

/// `polyvec_urandom (r, mod, log2mod, seed, dom)`: element i with counter i + 1
pub(crate) fn polyvec_urandom<R: Pv + ?Sized>(r: &mut R, m: &Int, log2mod: u32, seed: &[u8; 32], dom: u32) -> Result<(), Error> {
    for i in 0..r.len() {
        *r.at(i) = Poly::urandom(m, log2mod, seed, (dom as u64) << 32 | (i as u64 + 1))?;
    }
    Ok(())
}

/// `polyvec_urandom_bnd (r, lo, hi, seed, dom)`: element i with counter i + 1
pub(crate) fn polyvec_urandom_bnd<R: Pv + ?Sized>(r: &mut R, lo: &Int, hi: &Int, seed: &[u8; 32], dom: u32) -> Result<(), Error> {
    for i in 0..r.len() {
        *r.at(i) = Poly::urandom_bnd(lo, hi, seed, (dom as u64) << 32 | (i as u64 + 1))?;
    }
    Ok(())
}

/// `polymat_urandom (r, mod, log2mod, seed, dom)`: element (i, j) with counter i ncols + j
pub(crate) fn polymat_urandom<M: Pm + ?Sized>(r: &mut M, m: &Int, log2mod: u32, seed: &[u8; 32], dom: u32) -> Result<(), Error> {
    let nc = r.ncols();
    for i in 0..r.nrows() {
        for j in 0..nc {
            let ctr = (i * nc + j) as u32 as u64;
            *r.at(i, j) = Poly::urandom(m, log2mod, seed, (dom as u64) << 32 | ctr)?;
        }
    }
    Ok(())
}
