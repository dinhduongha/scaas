//! The LaZer proof layers the relations use: `abdlop.c` (keys, commitment, commitment hash), `lnp-quad.c` /
//! `lnp-quad-many.c` (the quadratic-equation proof) and `lnp-tbox.c` (the toolbox: evaluation equations and the norm
//! proofs, with the P6-SZ / P6-L2 Schwartz–Zippel fixes and the P6-Z21 norm check), prover and verifier.
//!
//! Only the forms the C core calls are ported: `pqz_rel.c` passes `lnp_tbox_prove` / `_verify` no quadratic parts in
//! its own equations (every R2 is NULL), no message part (`tbox->l == 0`, so `Em`, `Pm`, `Dm` are NULL) and no constant
//! vectors (`v`, `f`, `u` NULL); the branches for those are left out.
pub(crate) mod abdlop;
pub(crate) mod quad;
pub(crate) mod tbox;

use crate::arith::int::Int;
use crate::arith::poly::Poly;
use crate::arith::polyvec::Pv;
use crate::arith::spoly::Sparse;
use crate::rand::shake::shake128;
use crate::Error;
use alloc::vec::Vec;

/// `NELEMS_DIAG(n)`: entries of an n x n upper triangular matrix
pub(crate) const fn diag(n: usize) -> usize {
    (n * n - n) / 2 + n
}

/// One equation `<s, R2 s> + <r1, s> + r0` (lnp-tbox.h's `R2[i], r1[i], r0[i]`); `None` is C's NULL.
pub(crate) struct Eq {
    pub(crate) r2: Option<Sparse>,
    pub(crate) r1: Option<Sparse>,
    pub(crate) r0: Option<Poly>,
}

/// LSB-first bit writer: `coder_enc_begin`, `coder_enc_urandom(2|3)`, `coder_enc_grandom3`, `coder_enc_end` as the
/// verifiers use them to hash (urandom sections are 64 x nbits bits, grandom sections vary; `end` returns
/// floor(bits / 8) + 1 bytes, C's `coder_get_offset >> 3` after `coder_enc_end`). `grandom` repeats
/// `coder::encode_proof`'s z loop on this writer (same `split` / `nones`).
pub(crate) struct Coder {
    b: Vec<u8>,
    pos: usize,
}

impl Coder {
    pub(crate) fn new() -> Coder {
        Coder { b: Vec::new(), pos: 0 }
    }

    /// `coder_enc_urandom3 (v, m, nbits)`: every coefficient (after `poly_get_coeffvec`'s `fromcrt`) in [0, m), its
    /// low `nbits` bits; a value out of range is `_uencode`'s ASSERT_ERR (the sticky error): `Error::Internal`
    pub(crate) fn urandom<V: Pv + ?Sized>(&mut self, v: &mut V, m: &Int, nbits: u32) -> Result<(), Error> {
        let more = (v.len() * 64 * nbits as usize).div_ceil(8) + 1;
        self.b.try_reserve(more).map_err(|_| Error::Memory)?;
        let zero = Int::new(1);
        for i in 0..v.len() {
            let p = v.at(i);
            p.fromcrt();
            for j in 0..64 {
                let x = p.c(j);
                if !(x.ge(&zero) && x.lt(m)) {
                    return Err(Error::Internal);
                }
                for k in 0..nbits {
                    self.bit((x.l[0] >> k) & 1);
                }
            }
        }
        Ok(())
    }

    /// `coder_enc_grandom3 (v, log2o)` of centred copies of v's polys (`fromcrt`, `mod`, `redc`: `encproof`'s
    /// encoding of z3 / z4; P6-FS, lazer#28). The callers pass norm-bounded vectors (|z| < q / 2 after the copy's
    /// reduction in any case), so the unary parts are short; the length is summed first and reserved fallibly.
    pub(crate) fn grandom(&mut self, v: &[Poly], log2o: u32) -> Result<(), Error> {
        use crate::coder::{nones, reduced, split};
        let la = log2o + 1;
        let mut bits = 0u64;
        for x in v {
            let x = reduced(x, true);
            for j in 0..64 {
                bits = bits.saturating_add(nones(split(x.c(j).get_i64(), la).1) + 1 + la as u64);
            }
        }
        let more = usize::try_from(bits / 8 + 1).map_err(|_| Error::Memory)?;
        self.b.try_reserve(more).map_err(|_| Error::Memory)?;
        for x in v {
            let x = reduced(x, true);
            for j in 0..64 {
                let (z0, z1) = split(x.c(j).get_i64(), la);
                for _ in 0..nones(z1) {
                    self.bit(1);
                }
                self.bit(0);
                for k in 0..la {
                    self.bit((z0 as u64 >> k) & 1);
                }
            }
        }
        Ok(())
    }

    fn bit(&mut self, x: u64) {
        if self.pos & 7 == 0 {
            self.b.push(0);
        }
        if let Some(y) = self.b.last_mut() {
            *y |= (x as u8) << (self.pos & 7);
        }
        self.pos += 1;
    }

    /// `coder_enc_end`: a one, then the bytes up to it
    pub(crate) fn end(mut self) -> Result<Vec<u8>, Error> {
        self.b.try_reserve(1).map_err(|_| Error::Memory)?;
        self.bit(1);
        Ok(self.b)
    }
}

/// `shake128 (hash || out)` squeezed to 32 bytes (every Fiat-Shamir step)
pub(crate) fn hash2(hash: &[u8; 32], out: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    shake128(&[hash, out]).squeeze(&mut h);
    h
}
