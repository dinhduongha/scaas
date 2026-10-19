//! `dcompress.c` (Dilithium-style decompose / power2round / hints over the coefficients of R_q) and the proof codec:
//! `coder.c`'s bounded decoder and encoder as `pqz_rel.c` drives them (`encproof`, `pqz_decproof`, serialization v1,
//! pq-zero-knowledge.md §8.1) and the test hook `pqz_test_mutate`. `bytes.c` (hex / raw stdio I/O, getentropy) has no
//! caller in the core and no counterpart.
//!
//! Every dcompress function is coefficient-wise (each output coefficient depends on the same input coefficients only),
//! so they are ported per coefficient; the poly and polyvec wrappers loop. Not ctime, as in C.
use crate::arith::int::{int_div, Int};
use crate::arith::ntt::D;
use crate::arith::poly::{Poly, RING_Q};
use crate::arith::polyvec::{self, PolyVec};
use crate::params::Tbox;
use crate::{Error, MAX_PROOF};
use alloc::vec::Vec;

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

/// `r += c ? a : 0` (`sub`: `-=`), c in {0, 1}, without a branch: a masked-out 0 leaves r as it was, sign included
/// (C dcompress.c `_cnd_addsub`; review E)
fn cnd_addsub(r: &mut Int, a: &Int, c: u64, sub: bool) {
    let k = crate::ct::mask(c);
    let mut t = Int::new(r.n);
    t.set(a);
    for x in &mut t.l[..t.n] {
        *x &= k;
    }
    t.neg &= k;
    if sub {
        r.sub(&{ *r }, &t);
    } else {
        r.add(&{ *r }, &t);
    }
}

/// upstream's centring branches as masks (C `_centre`): r negative and |r| <= g/2 (>= if `geq`): r += g; r
/// non-negative and |r| > g/2: r -= g (both tests on the input r)
fn centre(r: &mut Int, g: &Int, gby2: &Int, geq: bool) {
    let neg = (r.sgn() == -1) as u64;
    let lo = if geq { r.absge(gby2) } else { r.absle(gby2) } as u64;
    let hi = r.absgt(gby2) as u64;
    cnd_addsub(r, g, neg & lo, false);
    cnd_addsub(r, g, (neg ^ 1) & hi, true);
}

/// The prover decomposes secret-derived values (w = A1 y1 + A2 y2, the hint inputs): decompose, power2round and
/// make_ghint have no branch on the values (review E); same results as upstream's branches.
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
        centre(&mut r0, &self.gamma, &self.gammaby2, false);

        r1.sub(&{ r1 }, &r0);
        // r1 == q - 1 ? (0, r0 - 1) : (r1 / gamma, r0); the division always runs (public divisor, fixed steps)
        let eq = r1.eq(&self.qminus1) as u64;
        let keep = crate::ct::mask(eq ^ 1);
        let (mut rq, mut rr) = (Int::new(r.n - ng + 1), Int::new(ng));
        int_div(&mut rq, &mut rr, &r1, &gamma_);
        let mut q1 = Int::new(r1.n);
        q1.set(&rq);
        for (x, y) in r1.l[..r1.n].iter_mut().zip(&q1.l) {
            *x = y & keep;
        }
        r1.neg = q1.neg & keep;
        cnd_addsub(&mut r0, &Int::from_i64(r.n, 1), eq, true);
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
        let hi = r0.absgt(&self.pow2dby2) as u64;
        cnd_addsub(&mut r0, &self.pow2d, hi, true);
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
        } else {
            centre(&mut ret, &self.m, &self.mby2, true);
        }
        ret
    }
}

// ---------------------------------------------------------------- the proof codec

/// The fields of a proof (`pqz_rel.c`'s `pf_t` that the encoding carries), sized for relation `p` as `pf_alloc`.
pub(crate) struct ProofParts {
    pub(crate) p: &'static Tbox,
    /// kmsis polys, coefficients in [0, 2^(log2q - D))
    pub(crate) t_a1: PolyVec,
    /// l + lext polys
    pub(crate) t_b: PolyVec,
    /// lambda / 2 polys
    pub(crate) h: PolyVec,
    pub(crate) c: Poly,
    /// m1 polys
    pub(crate) z1: PolyVec,
    /// m2 - kmsis polys
    pub(crate) z21: PolyVec,
    /// kmsis polys
    pub(crate) hint: PolyVec,
    /// 256 / d polys
    pub(crate) z3: PolyVec,
    pub(crate) z4: PolyVec,
}

impl ProofParts {
    /// zero polys
    pub(crate) fn new(p: &'static Tbox) -> Result<ProofParts, Error> {
        let tb = p.tbox;
        let n = |k: u32| PolyVec::new(k as usize);
        Ok(ProofParts {
            p,
            t_a1: n(tb.kmsis)?,
            t_b: n(tb.l + tb.lext)?,
            h: n(p.quad_eval.lambda / 2)?,
            c: Poly::ZERO,
            z1: n(tb.m1)?,
            z21: n(tb.m2 - tb.kmsis)?,
            hint: n(tb.kmsis)?,
            z3: n(256 / D as u32)?,
            z4: n(256 / D as u32)?,
        })
    }

    /// the Gaussian parts and their log2 stdev, in encoding order
    fn zs(&self) -> [(&PolyVec, u32); 4] {
        let qm = self.p.quad_eval.quad_many;
        [(&self.z1, qm.log2stdev1), (&self.z21, qm.log2stdev2), (&self.z3, self.p.log2stdev3), (&self.z4, self.p.log2stdev4)]
    }
}

/// LSB-first bit reader: coder.c's bounded decoder (a read at or past the end sets the sticky error, which fails the
/// decoding, so the first such read can fail it here)
struct Rd<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Rd<'_> {
    fn bit(&mut self) -> Result<u64, Error> {
        let x = *self.b.get(self.pos >> 3).ok_or(Error::Input)?;
        let r = (x >> (self.pos & 7)) & 1;
        self.pos += 1;
        Ok(r as u64)
    }

    fn bits(&mut self, n: u32) -> Result<u64, Error> {
        let mut v = 0;
        for k in 0..n {
            v |= self.bit()? << k;
        }
        Ok(v)
    }

    /// `coder_dec_urandom3`: n-bit values, each < m (`_udecode`; the length pre-check is the bounded read)
    fn urandom(&mut self, v: &mut [Poly], m: u64, n: u32) -> Result<(), Error> {
        for p in v {
            for j in 0..D {
                let x = self.bits(n)?;
                if x >= m {
                    return Err(Error::Input);
                }
                p.put(j, &Int::from_limbs(&[x], 0));
            }
        }
        Ok(())
    }

    /// `coder_dec_ghint3`: 00 -> 0, 01 -> 1, 10 -> -1, 11 0^j 1 -> (j + 4) / 2 (j even), -(j + 3) / 2 (j odd)
    fn ghint(&mut self, v: &mut [Poly]) -> Result<(), Error> {
        for p in v {
            for j in 0..D {
                let e = match (self.bit()?, self.bit()?) {
                    (0, 0) => 0,
                    (0, 1) => 1,
                    (1, 0) => -1,
                    _ => {
                        let mut z = 0i64;
                        while self.bit()? == 0 {
                            z += 1;
                        }
                        if z % 2 == 0 { (z + 4) / 2 } else { -(z + 3) / 2 }
                    }
                };
                p.put(j, &Int::from_i64(1, e));
            }
        }
        Ok(())
    }

    /// `coder_dec_grandom3`: z1 unary (nones ones, a zero), z0 in log2o + 1 bits two's complement, z = ao z1 + z0
    fn grandom(&mut self, v: &mut [Poly], log2o: u32) -> Result<(), Error> {
        let la = log2o + 1;
        let ao = 1i64 << la;
        for p in v {
            for j in 0..D {
                let mut nones = 0i64;
                while self.bit()? == 1 {
                    nones += 1;
                }
                let z1 = if nones % 2 == 0 { -nones / 2 } else { (nones + 1) / 2 };
                let mut z0 = self.bits(la)? as i64;
                if z0 & (1 << (la - 1)) != 0 {
                    z0 |= !0i64 << la; // sign-extend
                }
                p.put(j, &Int::from_i64(1, ao.wrapping_mul(z1).wrapping_add(z0)));
            }
        }
        Ok(())
    }
}

/// The proof of relation `p` from `b`, with the reductions every C caller applies after `pqz_decproof` (`do_verify`,
/// `pqz_sv_verify`, `pqz_test_mutate`: the length cap MAX_PROOF before it; h, c, z1, z21, z3, z4 to centred
/// representatives mod q after it). `Err(Input)` where C's decoding fails: a read past the end, a fixed-width value
/// >= its modulus, a missing pad one or nonzero bits after it, trailing bytes, more than MAX_PROOF bytes.
pub(crate) fn decode_proof(p: &'static Tbox, b: &[u8]) -> Result<ProofParts, Error> {
    if b.len() > MAX_PROOF {
        return Err(Error::Input);
    }
    let qm = p.quad_eval.quad_many;
    let (q, log2q) = (p.tbox.ring.q.l[0], p.tbox.ring.log2q);
    let mt = log2q - qm.dcompress.d;
    let mut f = ProofParts::new(p)?;
    let mut r = Rd { b, pos: 0 };
    r.urandom(&mut f.t_b, q, log2q)?;
    r.urandom(&mut f.h, q, log2q)?;
    r.urandom(&mut f.t_a1, 1 << mt, mt)?;
    let m = Int::from_i64(1, 2 * qm.omega + 1);
    r.urandom(core::slice::from_mut(&mut f.c), m.l[0], qm.log2omega)?;
    for j in 0..D {
        let mut x = Int::new(1);
        x.redc(&f.c.c(j), &m);
        f.c.put(j, &x);
    }
    r.ghint(&mut f.hint)?;
    r.grandom(&mut f.z1, qm.log2stdev1)?;
    r.grandom(&mut f.z21, qm.log2stdev2)?;
    r.grandom(&mut f.z3, p.log2stdev3)?;
    r.grandom(&mut f.z4, p.log2stdev4)?;
    // coder_dec_end: a one, zeros to the end of its byte, and that byte the last one
    let (i, k) = (r.pos >> 3, r.pos & 7);
    if i + 1 != b.len() || b[i] >> k != 1 {
        return Err(Error::Input);
    }
    for v in [&mut f.h, &mut f.z1, &mut f.z21, &mut f.z3, &mut f.z4] {
        polyvec::mod_self(v);
        polyvec::redc_self(v);
    }
    f.c = Poly::mod_(&mut f.c);
    f.c = Poly::redc(&mut f.c);
    Ok(f)
}

/// LSB-first bit writer into a zeroed buffer of the predicted length (coder.c's encoder: `_inc_idx_zero` zeroes each
/// byte it enters, `coder_enc_end` pads with a one)
struct Wr {
    b: Vec<u8>,
    pos: usize,
}

impl Wr {
    fn bit(&mut self, x: u64) {
        if let Some(y) = self.b.get_mut(self.pos >> 3) {
            *y |= ((x & 1) as u8) << (self.pos & 7);
        }
        self.pos += 1;
    }

    fn bits(&mut self, x: u64, n: u32) {
        for k in 0..n {
            self.bit(x >> k);
        }
    }

    /// `coder_enc_urandom` of coefficients already in [0, m): `false` if one is not (`_uencode`'s ASSERT_ERR; its
    /// low n bits are written all the same)
    fn urandom(&mut self, x: &Int, m: &Int, n: u32) -> bool {
        self.bits(x.l[0], n);
        x.lt(m) // and >= 0: the reductions before leave no sign
    }
}

/// `poly_fromcrt`, `poly_mod`, then `poly_redc` / `poly_redp` (`encproof`'s reductions, on a copy)
pub(crate) fn reduced(a: &Poly, centred: bool) -> Poly {
    let mut t = a.clone();
    let mut t = Poly::mod_(&mut t);
    if centred { Poly::redc(&mut t) } else { Poly::redp(&mut t) }
}

/// `coder_enc_grandom`'s split of z: (z0 in [-ao/2, ao/2), z1) with z = ao z1 + z0, ao = 2^la
pub(crate) fn split(z: i64, la: u32) -> (i64, i64) {
    let ao = 1i64 << la;
    let mut z0 = z & (ao - 1); // z - (z & (~0 << la))
    if z0 >= ao / 2 {
        z0 -= ao;
    }
    (z0, (z - z0) >> la)
}

/// the unary length of z1 (`nones`)
pub(crate) fn nones(z1: i64) -> u64 {
    if z1 <= 0 { (-2 * z1) as u64 } else { (2 * z1 - 1) as u64 }
}

/// bits of `coder_enc_ghint` for e
fn ghint_bits(e: i64) -> u64 {
    if (-1..=1).contains(&e) {
        2
    } else if e >= 2 {
        (2 * e - 1) as u64
    } else {
        (-2 * e) as u64
    }
}

/// `encproof`: the encoding of `f`, `Err(Input)` if it would exceed `cap` bytes (checked on the predicted length
/// before anything is written, as C), `Err(Internal)` if a fixed-width value is outside its range (C's ASSERT_ERR:
/// the sticky error; the bytes are still emitted there, the callers discard them). The C caller's own limits
/// (MAX_PROOF, the output buffer) are the caller's.
pub(crate) fn encode_proof(f: &ProofParts, cap: usize) -> Result<Vec<u8>, Error> {
    let p = f.p;
    let qm = p.quad_eval.quad_many;
    let log2q = p.tbox.ring.log2q;
    let mt = log2q - qm.dcompress.d;
    let d = D as u64;
    let hint = |h: &Poly| {
        let mut h = h.clone();
        h.fromcrt();
        h
    };
    let mut bits =
        d * ((f.t_b.len() + f.h.len()) as u64 * log2q as u64 + f.t_a1.len() as u64 * mt as u64 + qm.log2omega as u64);
    for h in f.hint.iter() {
        let h = hint(h);
        bits += (0..D).map(|j| ghint_bits(h.c(j).get_i64())).sum::<u64>();
    }
    for (z, log2o) in f.zs() {
        for x in z.iter() {
            let x = reduced(x, true);
            bits += (0..D).map(|j| nones(split(x.c(j).get_i64(), log2o + 1).1) + 1 + log2o as u64 + 1).sum::<u64>();
        }
    }
    if bits / 8 + 1 > cap as u64 {
        return Err(Error::Input);
    }
    let mut b = Vec::new();
    b.try_reserve_exact(bits as usize / 8 + 1).map_err(|_| Error::Memory)?;
    b.resize(bits as usize / 8 + 1, 0);
    let mut w = Wr { b, pos: 0 };
    let mut ok = true;
    for (v, m, n) in [(&f.t_b, RING_Q, log2q), (&f.h, RING_Q, log2q), (&f.t_a1, Int::from_limbs(&[1 << mt], 0), mt)] {
        for x in v.iter() {
            let x = reduced(x, false);
            for j in 0..D {
                ok &= w.urandom(&x.c(j), &m, n);
            }
        }
    }
    let m = Int::from_i64(1, 2 * qm.omega + 1);
    let mut c = f.c.clone();
    c.fromcrt();
    for j in 0..D {
        let mut x = Int::new(1);
        x.redp(&c.c(j), &m);
        ok &= w.urandom(&x, &m, qm.log2omega);
    }
    for h in f.hint.iter() {
        let h = hint(h);
        for j in 0..D {
            let e = h.c(j).get_i64();
            match e {
                0 => w.bits(0b00, 2),
                1 => w.bits(0b10, 2),
                -1 => w.bits(0b01, 2),
                _ => {
                    w.bits(0b11, 2);
                    w.pos += (ghint_bits(e) - 3) as usize; // zeros
                    w.bit(1);
                }
            }
        }
    }
    for (z, log2o) in f.zs() {
        let la = log2o + 1;
        for x in z.iter() {
            let x = reduced(x, true);
            for j in 0..D {
                let (z0, z1) = split(x.c(j).get_i64(), la);
                // C counts the ones in an unsigned int; a count >= 2^32 is over every cap, refused above
                for _ in 0..nones(z1) {
                    w.bit(1);
                }
                w.bit(0);
                w.bits(z0 as u64, la);
            }
        }
    }
    if w.pos as u64 != bits {
        return Err(Error::Input); // encproof: the length differs from the predicted one
    }
    w.bit(1);
    if !ok {
        return Err(Error::Internal);
    }
    Ok(w.b)
}

/// `pqz_test_mutate` (test hook): decode `proof` as relation `code`, change one field (`kind` 0..14 with `r1`, `r2`;
/// any other kind re-encodes only) and re-encode. `Ok(None)` where C returns 0: an unknown code, a proof that does
/// not decode, an encoding over 2 MAX_PROOF bytes (the hook's buffer) or a fixed-width value out of range.
#[cfg(feature = "test-hooks")]
pub(crate) fn test_mutate(code: u8, proof: &[u8], kind: u32, r1: u64, r2: u64) -> Result<Option<Vec<u8>>, Error> {
    use crate::arith::ntt::Q;
    let Some(p) = crate::rel::tbox_by_code(code) else { return Ok(None) };
    let mut f = match decode_proof(p, proof) {
        Err(Error::Input) => return Ok(None),
        r => r?,
    };
    let tb = p.tbox;
    let (m1, m2r, km) = (tb.m1 as u64, (tb.m2 - tb.kmsis) as u64, tb.kmsis as u64);
    let c64 = (r2 % D as u64) as usize;
    let sg: i64 = if (r2 >> 8) & 1 == 1 { 1 } else { -1 };
    let ix = |n: u64| (r1 % n) as usize;
    // cval / set_c
    let get = |x: &Poly, j: usize| x.c(j).get_i64();
    let set = |x: &mut Poly, j: usize, v: i64| x.put(j, &Int::from_i64(1, v));
    let add = |x: &mut Poly, j: usize, v: i64| set(x, j, get(x, j) + v);
    match kind {
        0 => f.z1.swap(ix(m1), ((r1 / m1 + 1 + r1 % m1) % m1) as usize),
        1 => f.z21.swap(ix(m2r), ((r1 / m2r + 1 + r1 % m2r) % m2r) as usize),
        2 => core::mem::swap(&mut f.z3[ix(4)], &mut f.z4[((r1 >> 8) % 4) as usize]),
        3 => add(&mut f.z1[ix(m1)], c64, sg),
        4 => set(&mut f.z1[ix(m1)], c64, sg * ((1 << 25) + (r1 % 1000) as i64)),
        5 => set(&mut f.z4[ix(4)], c64, sg * (p.bz4.get_i64() + ((r1 >> 8) as i64) % 2)),
        6 => add(&mut f.z3[ix(4)], c64, sg * (1 << 20)),
        7 => add(&mut f.h[ix(2)], if r1 & 4 != 0 { 0 } else if r1 & 8 != 0 { D / 2 } else { c64 }, sg),
        8 => add(&mut f.hint[ix(km)], c64, sg * (1 + ((r1 >> 9) as i64) % 1000)),
        9 => {
            let v = (get(&f.c, c64) + 8 + 1 + (r1 % 16) as i64) % 17 - 8;
            set(&mut f.c, c64, v)
        }
        10 => set(&mut f.t_b[ix((tb.l + tb.lext) as u64)], c64, (r1 % Q) as i64),
        11 => set(&mut f.t_a1[ix(km)], c64, ((r1 >> 8) % (1 << (42 - p.quad_eval.quad_many.dcompress.d))) as i64),
        12 => add(&mut f.z21[ix(m2r)], c64, sg),
        13 => f.h.swap(0, 1),
        14 => add(&mut f.z3[ix(4)], c64, sg),
        _ => {}
    }
    match encode_proof(&f, 2 * MAX_PROOF) {
        Ok(v) => Ok(Some(v)),
        Err(Error::Input | Error::Internal) => Ok(None),
        Err(e) => Err(e),
    }
}
