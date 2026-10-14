//! R_q = Z_q[X]/(X^64 + 1) as pqz-core uses it (pqz_rel.c): the public matrix A, exact integer products, and the
//! honest prover's key / ciphertext equations. The statement codec is `pqz-stmt` (plan R2, P6e Task 6); this module
//! only turns its canonical coefficients into centred polynomials.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::sync::OnceLock;

pub use crate::fq::Q;
pub use pqz_stmt::{D, K};
pub const DELTA: i64 = (1 << 26) - 1;

const _: () = assert!(pqz_stmt::Q == Q);

pub type Poly = [i64; D];

/// a canonical coefficient (< q) centred into (-q/2, q/2]
pub fn centre(v: u64) -> i64 {
    if v > (Q - 1) / 2 { v as i64 - Q as i64 } else { v as i64 }
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
/// polynomial: 64 for pk / u, 16 for v): pk or u (16,384 B) gives 32, v (128 B) one with 16 coefficients.
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

/// pk = A s + e mod q
pub fn keypair(s: &[Poly], e: &[Poly]) -> Vec<Poly> {
    let a = a_matrix();
    (0..K)
        .map(|i| {
            let row: Vec<&Poly> = (0..K).map(|j| &a[i * K + j]).collect();
            let y = dot_int(&row, &s.iter().collect::<Vec<_>>());
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
            let y = dot_int(&col, &rr);
            std::array::from_fn(|m| modq(y[m] + e1[i][m]))
        })
        .collect();
    let vs = pks
        .iter()
        .zip(msgs)
        .zip(e2)
        .map(|((pk, msg), e2)| {
            let y = dot_int(&pk.iter().collect::<Vec<_>>(), &rr);
            std::array::from_fn(|i| if i < 16 { modq(y[i] + e2[i] + DELTA * msg[i] as i64) } else { 0 })
        })
        .collect();
    (u, vs)
}

/// the 16 base-16 digits of x, least significant first
pub fn digits(x: u64) -> [u8; 16] {
    std::array::from_fn(|i| ((x >> (4 * i)) & 15) as u8)
}
