//! `pqz_ntt.c`: ring arithmetic for R_q = Z_q[X]/(X^64 + 1), q = 2^42 - 215 (CTR-PQZ-03).
//!
//! q = 9 mod 16, so X^64 + 1 = prod_{j<4} (X^16 - rho_j) with rho_j the primitive 8th roots of unity (incomplete NTT,
//! two layers). The "NTT domain" is the four residues (16 coefficients each, in [0, q)); addition is coefficient-wise,
//! multiplication a 16 x 16 schoolbook product mod X^16 - rho_j per block. Integer-only, constant-time; every
//! reduction is to the canonical residue, so the C core's 21-bit-limb path (wasm32) and its 128-bit path give the same
//! values, and so does this port (u128 on every target).
pub(crate) const Q: u64 = 4_398_046_510_889; // 2^42 - 215
pub(crate) const D: usize = 64;

const MASK42: u64 = (1 << 42) - 1;
/// primitive 8th root of unity mod q
const ZETA: u64 = 3_367_489_746_414;
/// zeta^2, a square root of -1
const IROOT: u64 = 2_273_236_395_452;
const ZETA3: u64 = 969_320_936_632;
const INV2: u64 = 2_199_023_255_445;
const INVZ: u64 = 3_428_725_574_257;
const INVI: u64 = 2_124_810_115_437;
const INVZ3: u64 = 1_030_556_764_475;

/// a in [0, 2q) → a mod q
#[inline]
pub(crate) fn csubq(a: u64) -> u64 {
    let t = a.wrapping_sub(Q);
    t.wrapping_add(Q & ((t as i64 >> 63) as u64))
}

/// x < 2^128 → x mod q (x = l + 2^42 y0 + 2^84 y1, 2^42 = 215 mod q)
#[inline]
pub(crate) fn red128(x: u128) -> u64 {
    let (lo, hi) = (x as u64, (x >> 64) as u64);
    let y0 = ((lo >> 42) | (hi << 22)) & MASK42;
    let y1 = hi >> 20;
    let u = (lo & MASK42) + 215 * y0 + (215 * 215) * y1;
    let u = (u >> 42) * 215 + (u & MASK42);
    csubq(u)
}

#[inline]
fn mulq(a: u64, b: u64) -> u64 {
    red128(a as u128 * b as u128)
}

#[inline]
fn addq(a: u64, b: u64) -> u64 {
    csubq(a + b)
}

#[inline]
fn subq(a: u64, b: u64) -> u64 {
    csubq(a + Q - b)
}

/// `pqz_ntt_fwd`: c in [0, q) → residues mod X^16 - zeta, X^16 + zeta, X^16 - zeta^3, X^16 + zeta^3
pub(crate) fn fwd(c: &mut [u64; D]) {
    for k in 0..32 {
        let t = mulq(IROOT, c[k + 32]);
        c[k + 32] = subq(c[k], t);
        c[k] = addq(c[k], t);
    }
    for k in 0..16 {
        let t = mulq(ZETA, c[k + 16]);
        c[k + 16] = subq(c[k], t);
        c[k] = addq(c[k], t);
        let t = mulq(ZETA3, c[k + 48]);
        c[k + 48] = subq(c[k + 32], t);
        c[k + 32] = addq(c[k + 32], t);
    }
}

/// `pqz_ntt_inv`
pub(crate) fn inv(c: &mut [u64; D]) {
    for k in 0..16 {
        let (x, y) = (c[k], c[k + 16]);
        c[k] = addq(x, y);
        c[k + 16] = mulq(subq(x, y), INVZ);
        let (x, y) = (c[k + 32], c[k + 48]);
        c[k + 32] = addq(x, y);
        c[k + 48] = mulq(subq(x, y), INVZ3);
    }
    for k in 0..32 {
        let (x, y) = (c[k], c[k + 32]);
        c[k] = addq(x, y);
        c[k + 32] = mulq(subq(x, y), INVI);
    }
    let inv4 = mulq(INV2, INV2);
    for x in c.iter_mut() {
        *x = mulq(*x, inv4);
    }
}

/// r = a * b mod X^16 - rho: with bb[16 + m] = b[m], bb[16 - m] = rho b[16 - m], r[k] = sum_i a[i] bb[16 + k - i]
fn basemul16(r: &mut [u64], a: &[u64], b: &[u64], rho: u64) {
    let mut bb = [0u64; 32];
    for j in 1..16 {
        bb[j] = mulq(rho, b[j]);
    }
    bb[16..].copy_from_slice(&b[..16]);
    for k in 0..16 {
        let mut acc = 0u128; // < 16 q^2 < 2^88
        for i in 0..16 {
            acc += a[i] as u128 * bb[16 + k - i] as u128;
        }
        r[k] = red128(acc);
    }
}

/// `pqz_ntt_basemul`: r = a * b in the NTT domain
pub(crate) fn basemul(a: &[u64; D], b: &[u64; D]) -> [u64; D] {
    let mut t = [0u64; D];
    for (j, rho) in [ZETA, Q - ZETA, ZETA3, Q - ZETA3].into_iter().enumerate() {
        let s = 16 * j..16 * j + 16;
        basemul16(&mut t[s.clone()], &a[s.clone()], &b[s], rho);
    }
    t
}

/// `pqz_ntt_add` (residues in [0, q))
pub(crate) fn add(a: &[u64; D], b: &[u64; D]) -> [u64; D] {
    core::array::from_fn(|k| csubq(a[k] + b[k]))
}

/// `pqz_ntt_sub`
pub(crate) fn sub(a: &[u64; D], b: &[u64; D]) -> [u64; D] {
    core::array::from_fn(|k| csubq(a[k] + Q - b[k]))
}
