//! `abdlop.c`, the parts the verifier uses: `abdlop_keygen` (the public key from a seed) and `abdlop_hashcomm` (the
//! commitment hashed into the transcript, via `abdlop_enccomm`). The opening proof `abdlop_verify` has no caller in
//! the core (the toolbox checks the opening inside `lnp_quad_verify`).
use super::{hash2, Coder};
use crate::arith::int::Int;
use crate::arith::polymat::PolyMat;
use crate::arith::polyvec::PolyVec;
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
