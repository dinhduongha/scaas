//! R_q = Z_q[X]/(X^64 + 1) as pqz-core uses it (pqz_rel.c), and its negacyclic NTT over Goldilocks.
//!
//! Every PQZ identity stays below 2^55 as an integer once its witness is range-checked (pqzh-design.md §3.1), so it
//! holds over Z iff it holds in Goldilocks; X^64 + 1 splits in Goldilocks (128 | p - 1), so ring products are
//! pointwise at the 64 points w_k = psi^(2k+1), psi a primitive 128th root of unity.

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::sync::OnceLock;

pub type F = Goldilocks;
pub const Q: u64 = (1 << 42) - 215;
pub const D: usize = 64;
pub const K: usize = 32;
pub const DELTA: i64 = (1 << 26) - 1;

pub type Poly = [i64; D];

#[inline]
pub fn fi(v: i64) -> F {
    if v >= 0 { F::from_u64(v as u64) } else { -F::from_u64(v.unsigned_abs()) }
}

/// Centred integer of a field element (|v| < p/2).
#[inline]
pub fn centre(x: F) -> i64 {
    let v = x.as_canonical_u64();
    if v > F::ORDER_U64 / 2 { -((F::ORDER_U64 - v) as i64) } else { v as i64 }
}

struct Tw {
    /// psi^m (twist), g^k tables for the 64-point DFT with g = psi^2
    psi: [F; D],
    psi_inv: [F; D],
    roots: [F; D / 2],
    roots_inv: [F; D / 2],
    n_inv: F,
}

fn tw() -> &'static Tw {
    static T: OnceLock<Tw> = OnceLock::new();
    T.get_or_init(|| {
        let psi = F::two_adic_generator(7);
        let g = psi * psi;
        let mut t = Tw {
            psi: [F::ONE; D],
            psi_inv: [F::ONE; D],
            roots: [F::ONE; D / 2],
            roots_inv: [F::ONE; D / 2],
            n_inv: F::from_u64(D as u64).inverse(),
        };
        for m in 1..D {
            t.psi[m] = t.psi[m - 1] * psi;
            t.psi_inv[m] = t.psi[m].inverse();
        }
        for m in 1..D / 2 {
            t.roots[m] = t.roots[m - 1] * g;
            t.roots_inv[m] = t.roots[m].inverse();
        }
        t
    })
}

/// in-place radix-2 DFT of size 64 (natural order in and out) with the given half-size root table
fn dft64(a: &mut [F; D], roots: &[F; D / 2]) {
    // bit-reverse permutation
    for i in 0..D {
        let j = (i as u32).reverse_bits() >> (32 - 6);
        if (j as usize) > i {
            a.swap(i, j as usize);
        }
    }
    let mut len = 2;
    while len <= D {
        let step = D / len;
        for s in (0..D).step_by(len) {
            for t in 0..len / 2 {
                let w = roots[t * step];
                let u = a[s + t];
                let v = a[s + t + len / 2] * w;
                a[s + t] = u + v;
                a[s + t + len / 2] = u - v;
            }
        }
        len <<= 1;
    }
}

/// Negacyclic NTT: out[k] = sum_m a[m] w_k^m with w_k = psi^(2k+1).
pub fn ntt(a: &[F; D]) -> [F; D] {
    let t = tw();
    let mut b = [F::ZERO; D];
    for m in 0..D {
        b[m] = a[m] * t.psi[m];
    }
    dft64(&mut b, &t.roots);
    b
}

pub fn ntt_i(a: &Poly) -> [F; D] {
    let mut b = [F::ZERO; D];
    for m in 0..D {
        b[m] = fi(a[m]);
    }
    ntt(&b)
}

pub fn intt(a: &[F; D]) -> [F; D] {
    let t = tw();
    let mut b = *a;
    dft64(&mut b, &t.roots_inv);
    for m in 0..D {
        b[m] *= t.n_inv * t.psi_inv[m];
    }
    b
}

/// w_k^e for the k-th NTT point (used for the in-trace evaluation weights)
pub fn point_pow(k: usize, e: usize) -> F {
    F::two_adic_generator(7).exp_u64(((2 * k + 1) * e) as u64)
}

/// A[i][j] from SHAKE128("SCAAS-PQZ-A-V2" || u8(i) || u8(j)): 8-byte BE words, low 42 bits, accept if < q, centred
/// (pqz_rel.c expand_A).
pub fn a_matrix() -> &'static Vec<Poly> {
    static A: OnceLock<Vec<Poly>> = OnceLock::new();
    A.get_or_init(|| {
        let mut out = vec![[0i64; D]; K * K];
        for i in 0..K {
            for j in 0..K {
                let mut h = sha3::Shake128::default();
                h.update(b"SCAAS-PQZ-A-V2");
                h.update(&[i as u8, j as u8]);
                let mut r = h.finalize_xof();
                let mut k = 0;
                while k < D {
                    let mut w = [0u8; 8];
                    r.read(&mut w);
                    let v = u64::from_be_bytes(w) & ((1u64 << 42) - 1);
                    if v < Q {
                        out[i * K + j][k] = if v > (Q - 1) / 2 { v as i64 - Q as i64 } else { v as i64 };
                        k += 1;
                    }
                }
            }
        }
        out
    })
}

/// NTT(A[i][j]) for all i, j (row-major), fixed for the proof system.
pub fn a_hat() -> &'static Vec<[F; D]> {
    static AH: OnceLock<Vec<[F; D]>> = OnceLock::new();
    AH.get_or_init(|| a_matrix().iter().map(ntt_i).collect())
}

/// coefficients (be8, each < q) into a centred polynomial; None if a value is >= q (pqz_rel.c rd_poly)
pub fn rd_poly(b: &[u8], n: usize) -> Option<Poly> {
    let mut p = [0i64; D];
    for k in 0..n {
        let v = u64::from_be_bytes(b[8 * k..8 * k + 8].try_into().unwrap());
        if v >= Q {
            return None;
        }
        p[k] = if v > (Q - 1) / 2 { v as i64 - Q as i64 } else { v as i64 };
    }
    Some(p)
}

pub fn rd_polyvec(b: &[u8]) -> Option<Vec<Poly>> {
    (0..K).map(|i| rd_poly(&b[i * 512..], D)).collect()
}

pub fn wr_poly(out: &mut [u8], p: &Poly, n: usize) {
    for k in 0..n {
        let v = p[k].rem_euclid(Q as i64) as u64;
        out[8 * k..8 * k + 8].copy_from_slice(&v.to_be_bytes());
    }
}

/// exact integer negacyclic product sum: sum_j a[j] * b[j] in Z[X]/(X^64 + 1) (|result| < 2^63 assumed)
pub fn dot_int(a: &[&Poly], b: &[&Poly]) -> Poly {
    let mut acc = [0i128; D];
    for (x, y) in a.iter().zip(b) {
        for m in 0..D {
            if y[m] == 0 {
                continue;
            }
            for n in 0..D {
                let v = x[n] as i128 * y[m] as i128;
                if m + n < D { acc[m + n] += v } else { acc[m + n - D] -= v }
            }
        }
    }
    acc.map(|v| v as i64)
}

pub fn modq(v: i64) -> i64 {
    let r = v.rem_euclid(Q as i64);
    if r > (Q as i64 - 1) / 2 { r - Q as i64 } else { r }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_matches_naive_and_inverts() {
        let mut a = [0i64; D];
        for m in 0..D {
            a[m] = (m as i64 * 7919) % 201 - 100;
        }
        let h = ntt_i(&a);
        for k in 0..D {
            let mut s = F::ZERO;
            for m in 0..D {
                s += fi(a[m]) * point_pow(k, m);
            }
            assert_eq!(s, h[k]);
        }
        let back = intt(&h);
        for m in 0..D {
            assert_eq!(centre(back[m]), a[m]);
        }
    }

    #[test]
    fn ntt_is_negacyclic_product() {
        let mut a = [0i64; D];
        let mut b = [0i64; D];
        for m in 0..D {
            a[m] = (m as i64 * 31) % 17 - 8;
            b[m] = (m as i64 * 13) % 11 - 5;
        }
        let c = dot_int(&[&a], &[&b]);
        let (ha, hb, hc) = (ntt_i(&a), ntt_i(&b), ntt_i(&c));
        for k in 0..D {
            assert_eq!(ha[k] * hb[k], hc[k]);
        }
    }
}
