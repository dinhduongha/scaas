//! R_q = Z_q[X]/(X^64 + 1) as pqz-core uses it (pqz_rel.c): the public matrix A, the statement coefficient codec and
//! exact integer products. Copied from the Plonky3 crate's `pqzh/src/ring.rs` without its Goldilocks NTT (P6e Task 6
//! prep: no path dependency on that crate; the copy there stays). Moves to `pqz-stmt` with Task 5 / 6.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::sync::OnceLock;

pub use crate::fq::Q;
pub const D: usize = 64;
pub const K: usize = 32;
pub const DELTA: i64 = (1 << 26) - 1;

pub type Poly = [i64; D];

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
