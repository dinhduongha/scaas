//! `abdlop.c`, the parts the core uses: `abdlop_keygen` (the public key from a seed), `abdlop_commit`, and
//! `abdlop_hashcomm` (the commitment hashed into the transcript, via `abdlop_enccomm`). The opening proofs
//! `abdlop_prove` / `abdlop_verify` have no caller in the core (the toolbox proves the opening in `lnp_quad_*`).
use super::{hash2, Coder};
use crate::arith::int::Int;
use crate::arith::polymat::PolyMat;
use crate::arith::polyvec::{self, PolyVec};
use crate::params::Abdlop;
use crate::rand::urandom::polymat_urandom;
use crate::Error;

/// `abdlop_keygen`: A1 (kmsis x m1), A2' (kmsis x (m2 - kmsis)), B' ((l + lext) x (m2 - kmsis)) uniform mod q from
/// `seed` with domains 0, 1, 2
pub(crate) fn keygen(seed: &[u8; 32], p: &Abdlop) -> Result<(PolyMat, PolyMat, PolyMat), Error> {
    let (q, log2q) = (&p.ring.q, p.ring.log2q);
    let (km, m1, m2r, lt) = (p.kmsis as usize, p.m1 as usize, (p.m2 - p.kmsis) as usize, (p.l + p.lext) as usize);
    let mut a1 = PolyMat::new(km, m1)?;
    let mut a2p = PolyMat::new(km, m2r)?;
    let mut bp = PolyMat::new(lt, m2r)?;
    if m1 > 0 {
        polymat_urandom(&mut a1, q, log2q, seed, 0)?;
        polymat_urandom(&mut a2p, q, log2q, seed, 1)?;
    }
    if lt > 0 {
        polymat_urandom(&mut bp, q, log2q, seed, 2)?;
    }
    Ok((a1, a2p, bp))
}

/// `abdlop_hashcomm`: hash = H(hash || enc(tA1, tB_)), tA1 in log2q - D bits (`redp` in place), tB_ = the first l
/// polys of tB in log2q bits
pub(crate) fn hashcomm(hash: &mut [u8; 32], t_a1: &mut PolyVec, t_b: &mut PolyVec, p: &Abdlop) -> Result<(), Error> {
    let (log2q, d) = (p.ring.log2q, p.dcompress.d);
    let mut c = Coder::new();
    if p.m1 > 0 {
        crate::arith::polyvec::redp_self(&mut **t_a1);
        c.urandom(&mut **t_a1, &Int::from_limbs(&[1 << (log2q - d)], 0), log2q - d)?;
    }
    if p.l > 0 {
        let mut tb_ = t_b.sub(0, p.l as usize, 1);
        crate::arith::polyvec::redp_self(&mut tb_);
        c.urandom(&mut tb_, &p.ring.q, log2q)?;
    }
    *hash = hash2(hash, &c.end()?);
    Ok(())
}

/// `abdlop_commit` (m1 > 0, l = 0: every relation's form): tA2 = A1 s1 + A2' s21 + s22, then tA1 = power2round(tA2),
/// tA2 -= tA1 2^D, both `mod`; tB_ is empty
pub(crate) fn commit(
    t_a1: &mut PolyVec,
    t_a2: &mut PolyVec,
    s1: &mut PolyVec,
    s2: &mut PolyVec,
    [a1, a2p, _]: &mut [PolyMat; 3],
    p: &Abdlop,
) -> Result<(), Error> {
    let (km, m1, m2r) = (p.kmsis as usize, p.m1 as usize, (p.m2 - p.kmsis) as usize);
    if p.l > 0 || m1 == 0 {
        return Err(Error::Internal); // not a form the core passes
    }
    polyvec::set(&mut **t_a2, &s2.sub(m2r, km, 1));
    polyvec::addmul(&mut **t_a2, a1, &mut **s1, false);
    polyvec::addmul(&mut **t_a2, a2p, &mut s2.sub(0, m2r, 1), false);
    polyvec::power2round(&mut **t_a1, &mut **t_a2, p.dcompress);
    polyvec::sublshift(&mut **t_a2, &mut **t_a1, p.dcompress.d);
    polyvec::mod_self(&mut **t_a1);
    polyvec::mod_self(&mut **t_a2);
    Ok(())
}
