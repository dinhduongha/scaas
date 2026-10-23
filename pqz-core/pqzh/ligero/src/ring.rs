//! R_q = Z_q[X]/(X^64 + 1) as pqz-core uses it (pqz_rel.c): the public matrix A, exact integer products, and the
//! honest prover's key / ciphertext equations. The statement codec is `pqz-stmt` (plan R2, P6e Task 6); this module
//! only turns its canonical coefficients into centred polynomials.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::sync::OnceLock;

use crate::Wiped;

pub use crate::fq::Q;
pub use pqz_stmt::{D, K};
/// floor(q / 2^(MBITS + 2)), the plaintext digits' scale (v3 2^26 - 1)
pub const DELTA: i64 = crate::set::DELTA;
/// ring dimension k d (v3 2048)
pub const N: usize = K * D;

// pqz-stmt is built for the same parameter set (feature set-<set> forwarded)
const _: () = assert!(pqz_stmt::Q == Q && crate::set::K == K && crate::set::N == N);

pub type Poly = [i64; D];

/// a canonical coefficient (< q) centred into (-q/2, q/2]
pub fn centre(v: u64) -> i64 {
    if v > (Q - 1) / 2 { v as i64 - Q as i64 } else { v as i64 }
}

/// A[i][j] from SHAKE128("SCAAS-PQZ-A-V2" || u8(i) || u8(j)): 8-byte BE words, low LOG2Q bits (v3 42), accept if < q,
/// centred (pqz_rel.c expand_A, pqzl/rust keys.rs).
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
                    let v = u64::from_be_bytes(w) & crate::fq::MASK;
                    if v < Q {
                        out[i * K + j][k] = centre(v);
                        k += 1;
                    }
                }
            }
        }
        out
    })
}

/// The centred polynomials of a statement object already checked by `pqz_stmt::parse` (`n` coefficients per
/// polynomial: 64 for pk / u, 16 for v): pk or u (8 N B) gives K, v (128 B) one with 16 coefficients.
pub fn polys_of(b: &[u8], n: usize) -> Vec<Poly> {
    b.chunks(8 * n)
        .map(|c| {
            let mut v = [0u64; D];
            pqz_stmt::read_coeffs(c, &mut v[..n]).expect("pqz_stmt::parse checked the coefficients");
            v.map(centre)
        })
        .collect()
}

pub fn polys(v: &[i64]) -> Vec<Poly> {
    v.chunks(D).map(|c| c.try_into().unwrap()).collect()
}

/// exact integer negacyclic product sum: sum_j a[j] * b[j] in Z[X]/(X^64 + 1) (|result| < 2^63 assumed). Review P-B:
/// the same work for every value of b (a secret: s, r), no zero skip; the wrap split by index, not by a branch.
pub fn dot_int(a: &[&Poly], b: &[&Poly]) -> Poly {
    let mut acc = Wiped([0i128; D]);
    for (x, y) in a.iter().zip(b) {
        for m in 0..D {
            let ym = y[m] as i128;
            for n in 0..D - m {
                acc[m + n] += x[n] as i128 * ym;
            }
            for n in D - m..D {
                acc[m + n - D] -= x[n] as i128 * ym;
            }
        }
    }
    acc.map(|v| v as i64)
}

/// v mod q centred into (-q/2, q/2]: no division, the centring by a mask (review P-B: v is secret-derived in the
/// honest prover's checks and decryptions)
pub fn modq(v: i64) -> i64 {
    let r = crate::fq::Fq::from_i64(v).0 as i64;
    r - (Q & crate::ct::mask((((Q as i64 - 1) / 2 - r) as u64) >> 63)) as i64
}

/// pk = A s + e mod q
pub fn keypair(s: &[Poly], e: &[Poly]) -> Vec<Poly> {
    let a = a_matrix();
    (0..K)
        .map(|i| {
            let row: Vec<&Poly> = (0..K).map(|j| &a[i * K + j]).collect();
            let y = Wiped(dot_int(&row, &s.iter().collect::<Vec<_>>()));
            std::array::from_fn(|m| modq(y[m] + e[i][m]))
        })
        .collect()
}

/// u = A^T r + e1; v_k[i] = (pk_k^T r)[i] + e2_k[i] + Delta m_k[i] (i < 16)
pub fn encrypt(pks: &[&Vec<Poly>], msgs: &[[u8; 16]], r: &[Poly], e1: &[Poly], e2: &[Vec<i64>]) -> (Vec<Poly>, Vec<Poly>) {
    let a = a_matrix();
    let rr: Vec<&Poly> = r.iter().collect();
    let u = (0..K)
        .map(|i| {
            let col: Vec<&Poly> = (0..K).map(|j| &a[j * K + i]).collect();
            let y = Wiped(dot_int(&col, &rr));
            std::array::from_fn(|m| modq(y[m] + e1[i][m]))
        })
        .collect();
    let vs = pks
        .iter()
        .zip(msgs)
        .zip(e2)
        .map(|((pk, msg), e2)| {
            let y = Wiped(dot_int(&pk.iter().collect::<Vec<_>>(), &rr));
            std::array::from_fn(|i| if i < 16 { modq(y[i] + e2[i] + DELTA * msg[i] as i64) } else { 0 })
        })
        .collect();
    (u, vs)
}

/// the 16 base-16 digits of x, least significant first
pub fn digits(x: u64) -> [u8; 16] {
    std::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}
