//! `pqz_sv.c`: the specialised verifier (`pqz_verify_fast`) for R_REG, R_TX, R_TX0, R_BURN, R_DS, R_DR and R_TXM
//! (spike P6-SV, docs/research/pqz-specialised-verifier.md).
//!
//! It accepts exactly the proofs the generic verifier accepts: the same decoder (with the cap and the reductions of
//! `do_verify`), the same Fiat-Shamir transcript (statement digest, commitments, z3 / z4 round, tg round, the final
//! t || v || w1 round), the same challenges and the same checks (every norm, the P6-Z21 bound on ||(z21, w - gamma
//! w1)||). Only the verifier's polynomial v is computed differently: every equation is evaluated on z directly and
//! combined with the same scalars, instead of building the sparse quadratic forms of `lnp_tbox_verify`.
//!
//! Ring products: complete negacyclic NTT of degree 64 over NP = 4 NTT-friendly 30-bit primes (product P ~ 2^120),
//! Montgomery form throughout. An integer polynomial is exact while its coefficients stay below P/2 in absolute
//! value; it is then CRT-reconstructed and reduced mod q (`red`). Inputs enter below 2^42 in absolute value; the
//! largest sum formed is < 2^106 (bounds next to each sum, as in C), so no input, honest or adversarial, overflows it.
//!
//! PRG: LaZer's AES-256-CTR (`rand::rng`, the `aes` crate of D1; C uses a table AES here, the stream is the same) and
//! LaZer's `_urandom_i64` (`rand::urandom`, which C's local copy reproduces).
//!
//! What C keeps in static storage (the prime tables, A in this form, the per-relation tables) lives in the caller's
//! [`Ctx`], built at the relation's first `verify_fast`. Working memory is `Vec` with `try_reserve`; every failure (also
//! an allocation failure, C's arena) is a reject.
#![allow(clippy::needless_range_loop)] // the index loops follow pqz_sv.c's loops line for line
use crate::arith::int::{int_modq, Int};
use crate::arith::ntt::{self, csubq, Q};
use crate::arith::poly::Poly;
use crate::arith::polymat::{PmRef, PolyMat};
use crate::arith::polyvec::{self, PolyVec};
use crate::coder::decode_proof;
use crate::keys::be8;
use crate::params::Tbox;
use crate::proof::{abdlop, hash2, Coder};
use crate::rand::rng::Rng;
use crate::rand::urandom::urandom_i64;
use crate::rel::{self, Rel, RELS};
use crate::{Ctx, Error, HEADER_BYTES, MAX_PROOF, POLYVEC_BYTES, PREFIX_BYTES, V_BYTES};
use alloc::vec::Vec;

const NP: usize = 4;
const DEG: usize = 64;
const LAMBDA: usize = 4;
/// quad_many l: y3 (4), y4 (4), beta, g (2)
const NQL: usize = 11;
/// quad_eval l: y3, y4, beta
const NQEL: usize = 9;
/// polys per public key / ciphertext vector
const NPK: usize = 32;
/// JL rows
const JLR: usize = 256;
const M30: u64 = (1 << 30) - 1;
const M42: u64 = (1 << 42) - 1;
const M21: u64 = (1 << 21) - 1;

/// NTT domain, Montgomery form, entries in [0, 2p)
type Nt = [[u32; DEG]; NP];
/// lazy sum of fewer than 2^31 terms in [0, 2p)
type Acc = [[u64; DEG]; NP];
/// coefficients
type Cp = [i64; DEG];

const NT0: Nt = [[0; DEG]; NP];
const ACC0: Acc = [[0; DEG]; NP];

// ---------------------------------------------------------------- arithmetic mod q (values in [0, q))

#[inline]
fn addq(a: u64, b: u64) -> u64 {
    csubq(a + b)
}
#[inline]
fn subq(a: u64, b: u64) -> u64 {
    csubq(a + Q - b)
}
#[inline]
fn negq(a: u64) -> u64 {
    csubq(Q - a)
}
/// a, b < 2^42: 21-bit limbs, 64-bit products only (wasm32 has no 64 x 64 -> 128)
#[inline]
fn mulq(a: u64, b: u64) -> u64 {
    let (a0, a1, b0, b1) = (a & M21, a >> 21, b & M21, b >> 21);
    let (l, m, h) = (a0 * b0, a0 * b1 + a1 * b0, a1 * b1);
    let x = (l & M42) + ((m & M21) << 21) + 215 * ((l >> 42) + (m >> 21) + h); // < 2^51
    let x = (x >> 42) * 215 + (x & M42);
    csubq(x)
}
/// -q 2^20 <= x < 2^62 -> [0, q); every caller passes |x| < 2^51
#[inline]
fn modq(x: i64) -> u64 {
    let u = (x + ((Q as i64) << 20)) as u64; // in [0, 2^63) by the precondition
    let u = (u & M42) + 215 * (u >> 42); // < 2^42 + 2^31
    let u = (u & M42) + 215 * (u >> 42);
    csubq(u)
}
/// [0, q) -> (-q/2, q/2]
#[inline]
fn centre(a: u64) -> i64 {
    if a > (Q - 1) / 2 {
        a as i64 - Q as i64
    } else {
        a as i64
    }
}

/// o(a) = a(X^-1), coefficients mod q
fn cp_auto(a: &[i64]) -> Cp {
    let mut r = [0i64; DEG];
    r[0] = a[0];
    r[DEG / 2] = negq(a[DEG / 2] as u64) as i64;
    for i in 1..DEG / 2 {
        r[i] = negq(a[DEG - i] as u64) as i64;
        r[DEG - i] = negq(a[i] as u64) as i64;
    }
    r
}
/// X^n a, n < 64, coefficients mod q
fn cp_mulx(a: &[i64], n: usize) -> Cp {
    let mut r = [0i64; DEG];
    for i in 0..DEG {
        r[(i + n) % DEG] = if i + n < DEG { a[i] } else { negq(a[i] as u64) as i64 };
    }
    r
}

// ---------------------------------------------------------------- CRT / NTT over NP primes

#[derive(Clone, Copy)]
struct Prime {
    p: u32,
    /// -p^-1 mod 2^32
    pinv: u32,
    /// 2^64 mod p
    r2: u32,
    /// 64^-1 and 64^-1 2^32 mod p: inverse-NTT scale for Montgomery / plain inputs
    f1: u32,
    f2: u32,
    /// 2^30 - p
    delta: u32,
    /// a multiple of p >= 2^42 (lifts signed inputs)
    k: u64,
    /// Garner: p_j^-1 2^32 mod p, j < this prime's index
    g: [u32; NP],
    /// psi^brv(k) 2^32 mod p, psi a primitive 128th root of unity
    zetas: [u32; DEG],
    /// automorphism X -> X^-1 in the NTT domain: o(a)[s] = a[perm[s]]
    perm: [u8; DEG],
}

const PRIME0: Prime = Prime { p: 0, pinv: 0, r2: 0, f1: 0, f2: 0, delta: 0, k: 0, g: [0; NP], zetas: [0; DEG], perm: [0; DEG] };

/// t < p 2^32 -> t 2^-32 mod p, in [0, 2p)
#[inline]
fn mred(t: u64, p: &Prime) -> u32 {
    let m = (t as u32).wrapping_mul(p.pinv);
    ((t + m as u64 * p.p as u64) >> 32) as u32
}
/// a b < p 2^32
#[inline]
fn mmul(a: u32, b: u32, p: &Prime) -> u32 {
    mred(a as u64 * b as u64, p)
}
/// x < 2m < 2^32 -> x mod m
#[inline]
fn csub(x: u32, m: u32) -> u32 {
    let t = x.wrapping_sub(m);
    t.wrapping_add(m & (t >> 31).wrapping_neg())
}
/// |x| < 2^42 -> x 2^32 mod p in [0, 2p)
#[inline]
fn lift(x: i64, p: &Prime) -> u32 {
    let u = (x + p.k as i64) as u64; // < 2^44
    let u = (u & M30) + (u >> 30) * p.delta as u64; // < 2^30 + 2^14 delta < 2^31
    let u = (u & M30) + (u >> 30) * p.delta as u64;
    mmul(u as u32, p.r2, p)
}

/// init only, m < 2^32
fn powm(b: u64, mut e: u64, m: u64) -> u64 {
    let (mut r, mut b) = (1, b % m);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % m;
        }
        e >>= 1;
        b = b * b % m;
    }
    r
}
fn isprime(n: u32) -> bool {
    let mut d = 2u32;
    while d * d <= n {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 1;
    }
    n > 1
}
fn brv6(x: usize) -> u64 {
    (0..6).fold(0, |r, b| r | (((x >> b) & 1) << (5 - b))) as u64
}

/// in, out in [0, 2p)
fn ntt_fwd(a: &mut [u32; DEG], p: &Prime) {
    let p2 = 2 * p.p;
    let mut k = 1;
    let mut len = 32;
    while len >= 1 {
        for s in (0..DEG).step_by(2 * len) {
            let z = p.zetas[k];
            k += 1;
            for j in s..s + len {
                let (t, x) = (mmul(z, a[j + len], p), a[j]);
                a[j + len] = csub(x + p2 - t, p2);
                a[j] = csub(x + t, p2);
            }
        }
        len >>= 1;
    }
}
/// in [0, 2p) -> F 64 a 2^-32 ... in [0, p)
fn ntt_inv(a: &mut [u32; DEG], p: &Prime, f: u32) {
    let p2 = 2 * p.p;
    let mut k = DEG;
    let mut len = 1;
    while len < DEG {
        for s in (0..DEG).step_by(2 * len) {
            k -= 1;
            let z = p.p - p.zetas[k];
            for j in s..s + len {
                let (x, y) = (a[j], a[j + len]);
                a[j] = csub(x + y, p2);
                a[j + len] = mmul(z, x + p2 - y, p);
            }
        }
        len <<= 1;
    }
    for x in a.iter_mut() {
        *x = csub(mmul(*x, f, p), p.p);
    }
}

#[inline]
fn nt_mul(a: &Nt, b: &Nt, pr: &[Prime; NP]) -> Nt {
    let mut r = NT0;
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] = mmul(a[i][j], b[i][j], &pr[i]);
        }
    }
    r
}
#[inline]
fn nt_add(a: &Nt, b: &Nt, pr: &[Prime; NP]) -> Nt {
    let mut r = NT0;
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] = csub(a[i][j] + b[i][j], 2 * pr[i].p);
        }
    }
    r
}
#[inline]
fn nt_sub(a: &Nt, b: &Nt, pr: &[Prime; NP]) -> Nt {
    let mut r = NT0;
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] = csub(a[i][j] + 2 * pr[i].p - b[i][j], 2 * pr[i].p);
        }
    }
    r
}
/// o(a)
#[inline]
fn nt_auto(a: &Nt, pr: &[Prime; NP]) -> Nt {
    let mut r = NT0;
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] = a[i][pr[i].perm[j] as usize];
        }
    }
    r
}
/// r += a b
#[inline]
fn acc_mul(r: &mut Acc, a: &Nt, b: &Nt, pr: &[Prime; NP]) {
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] += mmul(a[i][j], b[i][j], &pr[i]) as u64;
        }
    }
}
/// r -= a b
#[inline]
fn acc_mulsub(r: &mut Acc, a: &Nt, b: &Nt, pr: &[Prime; NP]) {
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] += (2 * pr[i].p - mmul(a[i][j], b[i][j], &pr[i])) as u64;
        }
    }
}
#[inline]
fn acc_add(r: &mut Acc, a: &Nt) {
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] += a[i][j] as u64;
        }
    }
}
#[inline]
fn acc_sub(r: &mut Acc, a: &Nt, pr: &[Prime; NP]) {
    for i in 0..NP {
        for j in 0..DEG {
            r[i][j] += (2 * pr[i].p - a[i][j]) as u64;
        }
    }
}
/// r += / -= s a, s < 2^42
#[inline]
fn acc_scal(r: &mut Acc, a: &Nt, s: u64, sub: bool, pr: &[Prime; NP]) {
    for i in 0..NP {
        let p = &pr[i];
        let sm = lift(s as i64, p);
        for j in 0..DEG {
            let t = mmul(a[i][j], sm, p);
            r[i][j] += (if sub { 2 * p.p - t } else { t }) as u64;
        }
    }
}

/// What C keeps in static storage for every relation: the primes, the mod-q images of the CRT weights, the all-ones
/// polynomial, and A (32 x 32) in this form.
pub(crate) struct Ar {
    pr: [Prime; NP],
    /// p_0 ... p_{i-1} mod q, P mod q
    mq: [u64; NP],
    pq: u64,
    /// mixed-radix digits of (P - 1) / 2
    hd: [u32; NP],
    /// the all-ones polynomial
    nj: Nt,
    /// A (NPK x NPK), shared by all relations
    sa: Vec<Nt>,
}

impl Ar {
    /// |a_j| < 2^42
    fn fwd(&self, a: &[i64]) -> Nt {
        let mut r = NT0;
        for i in 0..NP {
            let p = &self.pr[i];
            for j in 0..DEG {
                r[i][j] = lift(a[j], p);
            }
            ntt_fwd(&mut r[i], p);
        }
        r
    }

    /// residues in [0, p_i) of an integer polynomial with |coefficients| < P/2 -> coefficients mod q in [0, q)
    fn crt(&self, x: &[[u32; DEG]; NP]) -> Cp {
        let mut r = [0i64; DEG];
        for j in 0..DEG {
            let mut a = [0u32; NP];
            for i in 0..NP {
                let p = &self.pr[i];
                let mut y = x[i][j];
                for k in 0..i {
                    // Garner: a_i = ((x_i - a_0) / p_0 - a_1) / p_1 ... mod p_i
                    y = mmul(y + 2 * p.p - a[k], p.g[k], p);
                }
                a[i] = csub(y, p.p);
            }
            // x > (P - 1) / 2: the integer is x - P
            let (mut neg, mut decided) = (false, false);
            for i in (0..NP).rev() {
                if decided {
                    break;
                }
                if a[i] != self.hd[i] {
                    neg = a[i] > self.hd[i];
                    decided = true;
                }
            }
            let mut v = 0;
            for i in 0..NP {
                v = addq(v, mulq(a[i] as u64, self.mq[i]));
            }
            r[j] = (if neg { subq(v, self.pq) } else { v }) as i64;
        }
        r
    }

    /// Montgomery form -> coefficients mod q
    fn red_nt(&self, a: &Nt) -> Cp {
        let mut x = *a;
        for i in 0..NP {
            ntt_inv(&mut x[i], &self.pr[i], self.pr[i].f1);
        }
        self.crt(&x)
    }

    /// accumulator -> coefficients mod q
    fn red(&self, a: &Acc) -> Cp {
        let mut x = [[0u32; DEG]; NP];
        for i in 0..NP {
            for j in 0..DEG {
                x[i][j] = mred(a[i][j], &self.pr[i]); // plain form, [0, 2p)
            }
            ntt_inv(&mut x[i], &self.pr[i], self.pr[i].f2);
        }
        self.crt(&x)
    }

    /// accumulator -> Montgomery form, same integer polynomial
    fn acc_nt(&self, a: &Acc) -> Nt {
        let mut r = NT0;
        for i in 0..NP {
            let p = &self.pr[i];
            for j in 0..DEG {
                r[i][j] = mmul(mred(a[i][j], p), p.r2, p);
            }
        }
        r
    }

    /// NTT of c0 + ck X^k
    fn fwd_small(&self, c0: i64, ck: i64, k: usize) -> Nt {
        let mut a = [0i64; DEG];
        a[0] += c0;
        a[k] += ck;
        self.fwd(&a)
    }

    /// `primes_init` (with `aes_tables`'s place taken by the `aes` crate) and A in this form (`lz_mat (A, 32, 32)`)
    fn new(a: &PolyMat) -> Result<Ar, Error> {
        let mut ar = Ar { pr: [PRIME0; NP], mq: [0; NP], pq: 0, hd: [0; NP], nj: NT0, sa: Vec::new() };
        let mut p: u32 = (1 << 30) - 127; // = 1 mod 128
        let mut n = 0;
        while n < NP {
            if isprime(p) {
                let mut x = p; // Newton: p^-1 mod 2^32
                for _ in 0..5 {
                    x = x.wrapping_mul(2u32.wrapping_sub(p.wrapping_mul(x)));
                }
                let pp = p as u64;
                let mut pm = PRIME0;
                pm.p = p;
                pm.pinv = x.wrapping_neg();
                pm.delta = (1 << 30) - p;
                if pm.delta >= 1 << 16 {
                    return Err(Error::Internal);
                }
                pm.k = ((1u64 << 42) / pp + 1) * pp;
                let r = (1u64 << 32) % pp;
                let mut g = 2;
                let psi = loop {
                    let psi = powm(g, (pp - 1) / 128, pp);
                    if powm(psi, 64, pp) == pp - 1 {
                        break psi;
                    }
                    g += 1;
                };
                for k in 0..DEG {
                    pm.zetas[k] = (powm(psi, brv6(k), pp) * r % pp) as u32;
                }
                pm.r2 = (r * r % pp) as u32;
                pm.f1 = powm(64, pp - 2, pp) as u32;
                pm.f2 = (pm.f1 as u64 * r % pp) as u32;
                for k in 0..n {
                    pm.g[k] = (powm(ar.pr[k].p as u64, pp - 2, pp) * r % pp) as u32;
                }
                ar.pr[n] = pm;
                n += 1;
            }
            p -= 128;
        }
        // automorphism as a permutation of the evaluation points: NTT(X) holds the points, NTT(-X^63) their inverses
        for i in 0..NP {
            let pm = ar.pr[i];
            let (mut x, mut y) = ([0u32; DEG], [0u32; DEG]);
            x[1] = mmul(1, pm.r2, &pm);
            y[DEG - 1] = mmul(pm.p - 1, pm.r2, &pm);
            ntt_fwd(&mut x, &pm);
            ntt_fwd(&mut y, &pm);
            for s in 0..DEG {
                let t = (0..DEG).position(|t| csub(x[t], pm.p) == csub(y[s], pm.p)).ok_or(Error::Internal)?;
                ar.pr[i].perm[s] = t as u8;
            }
        }
        // mod-q images of the mixed-radix weights, P mod q, (P - 1) / 2 in mixed radix
        ar.mq[0] = 1;
        for i in 1..NP {
            ar.mq[i] = mulq(ar.mq[i - 1], ar.pr[i - 1].p as u64);
        }
        ar.pq = mulq(ar.mq[NP - 1], ar.pr[NP - 1].p as u64);
        let mut carry = 0u64;
        for i in (0..NP).rev() {
            let v = carry * ar.pr[i].p as u64 + (ar.pr[i].p as u64 - 1); // digits of P - 1 are p_i - 1
            ar.hd[i] = (v / 2) as u32;
            carry = v % 2;
        }
        ar.nj = ar.fwd(&[1; DEG]);
        // self-check: (1 + X)(1 - X^63) = 2 + X - X^63 (negacyclic), through every step; o(1 + X) = 1 - X^63
        let (ta, tb) = (ar.fwd_small(1, 1, 1), ar.fwd_small(1, -1, DEG - 1));
        let r = ar.red_nt(&nt_mul(&ta, &tb, &ar.pr));
        let want = |j: usize| if j == 0 { 2 } else if j == 1 { 1 } else if j == DEG - 1 { Q - 1 } else { 0 };
        if (0..DEG).any(|j| r[j] as u64 != want(j)) {
            return Err(Error::Internal);
        }
        let r = ar.red_nt(&nt_auto(&ta, &ar.pr));
        let want = |j: usize| if j == 0 { 1 } else if j == DEG - 1 { Q - 1 } else { 0 };
        if (0..DEG).any(|j| r[j] as u64 != want(j)) {
            return Err(Error::Internal);
        }
        ar.sa = ar.lz_mat(a, NPK, NPK)?;
        Ok(ar)
    }

    /// a LaZer poly (either domain) -> NTT form here
    fn lz_fwd(&self, p: &Poly) -> Nt {
        let mut a = lz_coeffs(p);
        for x in a.iter_mut() {
            *x = modq(*x) as i64;
        }
        self.fwd(&a)
    }

    fn lz_mat(&self, a: &PolyMat, rows: usize, cols: usize) -> Result<Vec<Nt>, Error> {
        let mut r = vz(rows * cols, NT0)?;
        if a.nrows() != rows || a.ncols() != cols {
            return Err(Error::Internal);
        }
        for i in 0..rows {
            for j in 0..cols {
                r[i * cols + j] = self.lz_fwd(a.get(i, j));
            }
        }
        Ok(r)
    }
}

/// a LaZer poly (either domain) -> coefficients, as LaZer holds them (NTT domain: the inverse NTT's [0, q))
fn lz_coeffs(p: &Poly) -> Cp {
    let mut r = [0i64; DEG];
    if p.crt {
        let mut t = p.v;
        ntt::inv(&mut t);
        for j in 0..DEG {
            r[j] = t[j] as i64;
        }
    } else {
        for j in 0..DEG {
            r[j] = p.c(j).get_i64();
        }
    }
    r
}

/// n polys -> coefficients (r.len() = 64 n)
fn lz_get(r: &mut [i64], v: &[Poly]) {
    for (i, p) in v.iter().enumerate() {
        r[DEG * i..DEG * (i + 1)].copy_from_slice(&lz_coeffs(p));
    }
}

/// a vector of n copies of x, `Error::Memory` if the allocation fails
fn vz<T: Clone>(n: usize, x: T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Memory)?;
    v.resize(n, x);
    Ok(v)
}

// ---------------------------------------------------------------- PRG

/// `urandom_q (v, n, seed, dom)`: LaZer `_urandom_i64`, n values mod q in 42-bit fields
fn urandom_q(v: &mut [u64], seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    let mut t = vz(v.len(), 0i64)?;
    urandom_i64(&mut t, Q as i64, 42, seed, dom)?;
    for (x, y) in v.iter_mut().zip(t) {
        *x = y as u64;
    }
    Ok(())
}

/// `intmat_urandom`: row i from (dom << 32 | i * ncols)
fn urandom_mat(v: &mut [[u64; JLR]; LAMBDA], seed: &[u8; 32], dom: u32) -> Result<(), Error> {
    for (i, row) in v.iter_mut().enumerate() {
        urandom_q(row, seed, (dom as u64) << 32 | (i * JLR) as u64)?;
    }
    Ok(())
}

/// transpose the 8 x 8 bit matrix (byte b, bit t) -> (byte t, bit b)
#[inline]
fn tr8(mut x: u64) -> u64 {
    let mut t = (x ^ (x >> 7)) & 0x00AA_00AA_00AA_00AA;
    x ^= t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000_CCCC_0000_CCCC;
    x ^= t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x0000_0000_F0F0_F0F0;
    x ^= t ^ (t << 28);
    x
}

/// acc[4 j + k] = sum_{i < 256} V[k][i] R_i[j], j < ncols, R_i = LaZer `_brandom` (k = 1) of ncols entries from
/// (seed, dom0 + i): ncols plus bits then ncols minus bits, LSB first. Eight rows at a time: T[x] = sum of the eight
/// rows' challenges selected by the bits of x, indexed by each column's transposed plus / minus bits.
/// |acc| < 256 q < 2^50. rows: scratch of 8 ncols / 4 bytes.
fn jl_fold(acc: &mut [i64], ncols: usize, v: &[[u64; JLR]; LAMBDA], seed: &[u8; 32], dom0: u64, rows: &mut [u8]) -> Result<(), Error> {
    let (rb, half) = (ncols / 4, ncols / 8);
    let mut t = [[0i64; LAMBDA]; 256];
    acc[..LAMBDA * ncols].fill(0);
    for i0 in (0..JLR).step_by(8) {
        for b in 0..8 {
            Rng::new(seed, dom0 + (i0 + b) as u64).urandom(&mut rows[b * rb..(b + 1) * rb])?;
        }
        t[0] = [0; LAMBDA];
        for x in 1..256usize {
            for k in 0..LAMBDA {
                t[x][k] = t[x & (x - 1)][k] + v[k][i0 + x.trailing_zeros() as usize] as i64;
            }
        }
        for c in 0..half {
            let (mut xp, mut xm) = (0u64, 0u64);
            for b in 0..8 {
                xp |= (rows[b * rb + c] as u64) << (8 * b);
                xm |= (rows[b * rb + half + c] as u64) << (8 * b);
            }
            let (xp, xm) = (tr8(xp), tr8(xm));
            let a = &mut acc[LAMBDA * 8 * c..LAMBDA * 8 * (c + 1)];
            for (tt, a) in a.chunks_exact_mut(LAMBDA).enumerate() {
                let (tp, tm) = (&t[((xp >> (8 * tt)) & 255) as usize], &t[((xm >> (8 * tt)) & 255) as usize]);
                for k in 0..LAMBDA {
                    a[k] += tp[k] - tm[k];
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- per-relation tables

/// legs of R_TXM (the oversize M = 16 included)
const SVL: usize = 16;
/// randomness groups
const SVG: usize = 4;
/// exact l2 blocks: s_f, e_f, r_g, e1_g, one per e2 vector (X-1)
const SVZ: usize = 3 + 2 * SVG + 2 * SVL;
/// evaluation-equation products
const SVPR: usize = 2 + 2 * SVL;
/// binary polys
const SVBIN: usize = (853 + 64 * SVL).div_ceil(64);

/// an R_q-linear row block of 32: (A or A^T) x[ox..] + y[oy + i] = vec[rhs][i]
#[derive(Clone, Copy, Default)]
struct Rb {
    tr: bool,
    ox: usize,
    oy: usize,
    rhs: usize,
}

/// an evaluation-equation product: vec[v]^T x[ox..] (+ the e2 slot)
#[derive(Clone, Copy, Default)]
struct Pr {
    v: usize,
    ox: usize,
    e2: Option<usize>,
}

/// One relation's tables (`svrel_t`).
pub(crate) struct SvRel {
    p: &'static Tbox,
    mq: usize,
    m1s: usize,
    z: usize,
    kmsis: usize,
    m2r: usize,
    nbin: usize,
    nex: usize,
    n: usize,
    /// evaluation equations
    m: usize,
    /// debit relations: the shape of pqz_rel.c shape_t
    debit: bool,
    legs: usize,
    groups: usize,
    aud: usize,
    burn: bool,
    txm: bool,
    /// statement vectors held (stmt_t.vec)
    nvec: usize,
    /// Es selections: s1 slots [bstart, bstart + blen) (pqz_rel.c new_sel)
    nblk: usize,
    bstart: [usize; SVZ],
    blen: [usize; SVZ],
    /// Ps: slots [pstart, pstart + nbin)
    pstart: usize,
    /// Ds: slot dsel
    dsel: usize,
    nrb: usize,
    rb: [Rb; 1 + SVG],
    nprod: usize,
    pr: [Pr; SVPR],
    /// kmsis x mq, kmsis x m2r, 12 x m2r
    a1: Vec<Nt>,
    a2p: Vec<Nt>,
    bp: Vec<Nt>,
    /// o(sum_{2^i <= B_k^2} 2^i X^i), exact l2 bound k
    opow: Vec<Nt>,
    /// B_k^2
    b2: [u64; SVZ],
    z1bnd: u64,
    bz3sqr: u64,
    bz4: u64,
    bsq: u64,
    inv2: u64,
    inv4: u64,
    gamma: u64,
    gammaby2: u64,
    /// the dcompress modulus m
    dm: u64,
    qm1: u64,
    d: u32,
    log2m: u32,
}

// statement vectors (stmt_t.vec)
/// R_REG, R_DR: pk
const V_PK: usize = 0;
const V_PKF: usize = 1;
/// R_DS: pk
const V_PKT: usize = 2;
const V_PKA: usize = 3;
const V_UT: usize = 4;
/// R_DS, R_DR: u
const V_U: usize = 5;
/// debit: pk_j (j >= 1) at NVEC + j - 1, u_g (g >= 1) at NVEC + legs - 1 + g - 1
const NVEC: usize = 6;

impl SvRel {
    /// leg j's key (R_TX: pk_t)
    fn v_pk(&self, j: usize) -> usize {
        if j == 0 {
            V_PKT
        } else {
            NVEC + j - 1
        }
    }
    /// group g's u (R_TX: u)
    fn v_u(&self, g: usize) -> usize {
        if g == 0 {
            V_U
        } else {
            NVEC + self.legs.saturating_sub(1) + g - 1
        }
    }
}

/// a non-negative `int_t` below 2^63
fn int_u64(a: &Int) -> Option<u64> {
    (a.l[1..a.n].iter().all(|&x| x == 0) && a.neg == 0 && a.l[0] < 1 << 63).then_some(a.l[0])
}

/// `pqz_sv_setup` for relation r: the statement's layout (pqz_rel.c build_reg / build_debit / build_ds / build_dr), the
/// checks that the generated parameters are the ones this file is written for, the constants, A1, A2', B' in this form
fn setup(ar: &Ar, r: &Rel, keys: &[PolyMat; 3]) -> Result<SvRel, Error> {
    let p = r.p;
    let (tb, qm) = (p.tbox, p.quad_eval.quad_many);
    let dc = qm.dcompress;
    let mut s = SvRel {
        p,
        mq: tb.m1 as usize,
        m1s: (tb.m1 - p.z) as usize,
        z: p.z as usize,
        kmsis: tb.kmsis as usize,
        m2r: (tb.m2 - tb.kmsis) as usize,
        nbin: p.nbin as usize,
        nex: p.nex as usize,
        n: 0,
        m: 0,
        debit: false,
        legs: 0,
        groups: 0,
        aud: 0,
        burn: false,
        txm: false,
        nvec: NVEC,
        nblk: 0,
        bstart: [0; SVZ],
        blen: [0; SVZ],
        pstart: 0,
        dsel: 0,
        nrb: 0,
        rb: [Rb::default(); 1 + SVG],
        nprod: 0,
        pr: [Pr::default(); SVPR],
        a1: Vec::new(),
        a2p: Vec::new(),
        bp: Vec::new(),
        opow: Vec::new(),
        b2: [0; SVZ],
        z1bnd: 0,
        bz3sqr: 0,
        bz4: 0,
        bsq: 0,
        inv2: 0,
        inv4: 0,
        gamma: 0,
        gammaby2: 0,
        dm: 0,
        qm1: 0,
        d: 0,
        log2m: 0,
    };
    let mut ok = true;
    match r.code {
        3 => {
            (s.n, s.m, s.nblk, s.dsel, s.pstart) = (32, 0, 2, 0, 0);
            s.nrb = 1;
            s.rb[0] = Rb { tr: false, ox: 0, oy: 32, rhs: V_PK };
        }
        4 => {
            // u = A^T r + e1; pk^T r + e2_t
            (s.n, s.m, s.nblk, s.dsel, s.pstart) = (32, 16, 3, 64, 65);
            s.nrb = 1;
            s.rb[0] = Rb { tr: true, ox: 0, oy: 32, rhs: V_U };
            s.nprod = 1;
            s.pr[0] = Pr { v: V_PKT, ox: 0, e2: Some(64) };
        }
        5 => {
            // pk = A s + e; u^T s
            (s.n, s.m, s.nblk, s.dsel, s.pstart) = (32, 16, 2, 0, 64);
            s.nrb = 1;
            s.rb[0] = Rb { tr: false, ox: 0, oy: 32, rhs: V_PK };
            s.nprod = 1;
            s.pr[0] = Pr { v: V_U, ox: 0, e2: None };
        }
        _ => {
            // the debit relations R_TX, R_TX0, R_BURN, R_TXM (pqz_rel.c shape_t): rows 1, 2 per group; products
            // pk_j^T r_g(j) + e2_j (row 3, leg j), pk_f^T r_0 + e2_f (row 4), pk_a^T r_g(j) + e2_{a,j} (row 5),
            // u_T^T s_f (row 6), in that order. M legs and auditor copies on / off: R_TX (1, 1), R_TX0 (1, 0),
            // R_BURN (0, 0), R_TXM (the code's 2^(code & 7), (code >> 3) & 1): rel.rs's table
            let (m, a) = (r.legs, r.aud);
            s.burn = r.code == crate::OP_BURN;
            s.txm = r.op == crate::OP_TRANSFER_MULTI;
            let g = if s.burn { 1 } else { m.div_ceil(4) };
            let (e, e2f) = (64 + 64 * g, 64 + 64 * g + m);
            (s.debit, s.legs, s.groups, s.aud) = (true, m, g, a);
            s.nvec = NVEC + m.saturating_sub(1) + (g - 1);
            s.n = 32 * (1 + g);
            s.m = 16 * (m + 1 + a * m + 2);
            s.nblk = 2 + 2 * g + m + 1 + a * m;
            s.dsel = e;
            s.pstart = e2f + 1 + a * m;
            s.nrb = 1 + g;
            ok &= m <= SVL && g <= SVG && m + 1 + a * m < SVPR;
            if !ok {
                return Err(Error::Internal);
            }
            s.rb[0] = Rb { tr: false, ox: 0, oy: 32, rhs: V_PKF };
            for gi in 0..g {
                s.rb[1 + gi] = Rb { tr: true, ox: 64 + 64 * gi, oy: 96 + 64 * gi, rhs: s.v_u(gi) };
            }
            let mut k = 0;
            for j in 0..m {
                s.pr[k] = Pr { v: s.v_pk(j), ox: 64 + 64 * (j / 4), e2: Some(e + j) };
                k += 1;
            }
            s.pr[k] = Pr { v: V_PKF, ox: 64, e2: Some(e2f) };
            k += 1;
            for j in 0..a * m {
                s.pr[k] = Pr { v: V_PKA, ox: 64 + 64 * (j / 4), e2: Some(e2f + 1 + j) };
                k += 1;
            }
            s.pr[k] = Pr { v: V_UT, ox: 0, e2: None };
            k += 1;
            s.nprod = k;
        }
    }
    ok &= s.nblk == s.z && s.z <= SVZ && s.nrb * NPK == s.n && s.nprod <= SVPR && s.nbin <= SVBIN;
    let mut tot = s.nbin;
    if ok {
        for i in 0..s.nblk {
            s.blen[i] = p.n[i] as usize;
            s.bstart[i] = tot - s.nbin;
            tot += p.n[i] as usize;
        }
    }
    ok &= s.nbin == 0 || s.pstart == tot - s.nbin;
    ok &= tot + s.z == s.nex && tot == s.m1s && s.nex == s.mq;
    let (qe, ring) = (p.quad_eval.quad_eval, tb.ring);
    ok &= p.nprime == 1
        && p.quad_eval.lambda as usize == LAMBDA
        && ring.d as usize == DEG
        && tb.l == 0
        && tb.lext as usize == NQL + 1
        && qm.l as usize == NQL
        && qe.l as usize == NQEL
        && qm.m1 as usize == s.mq
        && qe.m1 as usize == s.mq
        && qm.kmsis as usize == s.kmsis
        && ring.log2q == 42
        && qm.omega == 8
        && qm.log2omega == 5;
    if !ok {
        return Err(Error::Internal);
    }
    // constants
    let u = |a: &Int| int_u64(a).ok_or(Error::Internal);
    (s.bz3sqr, s.bz4, s.bsq) = (u(&p.bz3sqr)?, u(&p.bz4)?, u(&qm.bsqr)?);
    (s.gamma, s.gammaby2, s.dm, s.qm1) = (u(&dc.gamma)?, u(&dc.gammaby2)?, u(&dc.m)?, u(&dc.qminus1)?);
    (s.d, s.log2m) = (dc.d, dc.log2m);
    ok &= s.log2m <= 42;
    s.inv2 = int_modq(&ring.inv2);
    s.inv4 = int_modq(&p.inv4);
    ok &= mulq(s.inv2, 2) == 1 && mulq(s.inv4, 4) == 1 && s.qm1 == Q - 1;
    // lnp_quad_verify: ||z1||^2 <= floor(2 m1 d 962 2^(2 log2stdev1) / 400) = floor(t 2^(2 log2stdev1 - 4) / 25)
    // (400 = 2^4 25; exact); the 2^-4 keeps t 2^(2 log2stdev1 - 4) < 2^63 at log2stdev1 19 (R_TXM M = 8, 16)
    let t = 2 * s.mq as u64 * DEG as u64 * 962;
    let l1 = qm.log2stdev1;
    ok &= (2..=20).contains(&l1) && t < 1 << (67 - 2 * l1);
    if !ok {
        return Err(Error::Internal);
    }
    s.z1bnd = (t << (2 * l1 - 4)) / 25;
    // l2_le / l2_sum need bnd < 2^62 (no wrap of the running sum)
    ok &= s.bz3sqr < 1 << 62 && s.bsq < 1 << 62 && s.z1bnd < 1 << 62;
    if !ok {
        return Err(Error::Internal);
    }
    s.opow = vz(s.z, NT0)?;
    for i in 0..s.z {
        s.b2[i] = u(&p.l2bsqr[i])?;
        if s.b2[i] >= 1 << 42 {
            return Err(Error::Internal);
        }
        let mut a = [0i64; DEG];
        for k in 0..42 {
            // int_binexp (NULL, powB, B^2)
            if 1u64 << k <= s.b2[i] {
                a[k] = 1 << k;
            }
        }
        let mut o = cp_auto(&a);
        for x in o.iter_mut() {
            *x = centre(*x as u64);
        }
        s.opow[i] = ar.fwd(&o);
    }
    s.a1 = ar.lz_mat(&keys[0], s.kmsis, s.mq)?;
    s.a2p = ar.lz_mat(&keys[1], s.kmsis, s.m2r)?;
    s.bp = ar.lz_mat(&keys[2], NQL + 1, s.m2r)?;
    Ok(s)
}

// ---------------------------------------------------------------- statement

/// the statement (`stmt_t`)
struct Stmt {
    /// V_PK .. V_U, then the debit's further legs and groups
    vec: Vec<[Cp; NPK]>,
    /// debit: legs, auditor copies; R_DS / R_DR: v[0] = v
    vt: [i64; 16],
    vf: [i64; 16],
    v: [[i64; 16]; SVL],
    va: [[i64; 16]; SVL],
    fee: u64,
    amount: u64,
}

/// pqz_rel.c rd_poly: every value < q
fn rd_coeffs(r: &mut [i64], inp: &[u8]) -> bool {
    let mut ok = true;
    for (k, x) in r.iter_mut().enumerate() {
        let v = be8(&inp[8 * k..]);
        ok &= v < Q;
        *x = v as i64;
    }
    ok
}

fn rd_vec(r: &mut [Cp; NPK], inp: &[u8]) -> bool {
    let mut ok = true;
    for (i, x) in r.iter_mut().enumerate() {
        ok &= rd_coeffs(x, &inp[i * 512..]);
    }
    ok
}

/// pqz_rel.c parse_debit / build_reg / parse_disc: the statement of relation `code` (its length checked); false if
/// malformed. Debit: header || pk_f || pk_j (legs) || [pk_a] || u_T || v_T || u_g (groups) || v_j (legs) || v_f ||
/// [v_{a,j}], fee (and the R_BURN amount, the transfers' auditorOn word, R_TXM's M word) from the header.
fn parse_stmt(t: &mut Stmt, s: &SvRel, code: u8, stmt: &[u8]) -> bool {
    let len = stmt.len();
    let mut ok = true;
    if s.debit {
        let (m, a) = (s.legs, s.aud);
        let want = match code {
            crate::OP_BURN => rel::BURN_STMT,
            crate::OP_TRANSFER => rel::TX_STMT,
            0x81 => rel::TX0_STMT,
            _ => rel::txm_stmt(m, a),
        };
        if len != want {
            return false;
        }
        let o;
        (t.fee, o) = rel::word64(&stmt[rel::HDR_FEE..]);
        ok &= o;
        t.amount = 0;
        if s.burn {
            let o;
            (t.amount, o) = rel::word64(&stmt[rel::HDR_AMOUNT..]);
            ok &= o;
        } else {
            // P6e R6: 1 with pk_a and v_a, 0 without
            let (on, o) = rel::word64(&stmt[rel::HDR_AUDITOR_ON..]);
            ok &= o;
            ok &= on == a as u64;
        }
        if s.txm {
            // R4
            let (legs, o) = rel::word64(&stmt[rel::HDR_LEGS..]);
            ok &= o;
            ok &= legs == m as u64;
        }
        let mut p = HEADER_BYTES;
        ok &= rd_vec(&mut t.vec[V_PKF], &stmt[p..]);
        p += POLYVEC_BYTES;
        for j in 0..m {
            ok &= rd_vec(&mut t.vec[s.v_pk(j)], &stmt[p..]);
            p += POLYVEC_BYTES;
        }
        if a > 0 {
            ok &= rd_vec(&mut t.vec[V_PKA], &stmt[p..]);
            p += POLYVEC_BYTES;
        }
        ok &= rd_vec(&mut t.vec[V_UT], &stmt[p..]);
        p += POLYVEC_BYTES;
        ok &= rd_coeffs(&mut t.vt, &stmt[p..]);
        p += V_BYTES;
        for g in 0..s.groups {
            ok &= rd_vec(&mut t.vec[s.v_u(g)], &stmt[p..]);
            p += POLYVEC_BYTES;
        }
        for j in 0..m {
            ok &= rd_coeffs(&mut t.v[j], &stmt[p..]);
            p += V_BYTES;
        }
        ok &= rd_coeffs(&mut t.vf, &stmt[p..]);
        p += V_BYTES;
        for j in 0..a * m {
            ok &= rd_coeffs(&mut t.va[j], &stmt[p..]);
            p += V_BYTES;
        }
        return ok;
    }
    match code {
        crate::OP_REGISTER => len == rel::REG_STMT && rd_vec(&mut t.vec[V_PK], &stmt[PREFIX_BYTES + 32..]),
        crate::OP_DISCLOSE_SENDER | crate::OP_DISCLOSE_RECEIVER => {
            if len != rel::DISC_STMT {
                return false;
            }
            let o;
            (t.amount, o) = rel::word64(&stmt[rel::DISC_AMOUNT..]);
            ok &= o;
            let mut p = rel::DISC_PK;
            ok &= rd_vec(&mut t.vec[if code == crate::OP_DISCLOSE_SENDER { V_PKT } else { V_PK }], &stmt[p..]);
            p += POLYVEC_BYTES;
            ok &= rd_vec(&mut t.vec[V_U], &stmt[p..]);
            p += POLYVEC_BYTES;
            ok &= rd_coeffs(&mut t.v[0], &stmt[p..]);
            ok
        }
        _ => false,
    }
}

// evaluation equations (pqz_rel.c build_debit / build_ds / build_dr, in their order e = 0, 1, ...) folded with
// weights g[M]: sum_e g_e E_e(s) = sum_k Gm[k] P_k + sum_b Ab[b] bits_b + rho, P_k the products of SvRel.pr
// (vec^T x (+ e2)), Gm[k] = sum over the equations on product k of g_e X^-i, Ab the weighted bit coefficients
// (add_bit: coef X^-(slot % 64) on bit poly slot / 64), rho the weighted constants

const TX_DELTA: i64 = (1 << 26) - 1;

fn slot(base: usize, w: usize, i: usize, b: usize) -> usize {
    base + w * i + b
}

fn tx_bit(ab: &mut [Cp], slot: usize, coef: i64, g: u64) {
    let w = mulq(g, modq(coef));
    let a = slot % DEG;
    let p = &mut ab[slot / DEG];
    if a == 0 {
        p[0] = addq(p[0] as u64, w) as i64;
    } else {
        p[DEG - a] = subq(p[DEG - a] as u64, w) as i64;
    }
}

/// G += g X^-i
fn tx_xinv(gm: &mut Cp, i: usize, g: u64) {
    if i == 0 {
        gm[0] = addq(gm[0] as u64, g) as i64;
    } else {
        gm[DEG - i] = subq(gm[DEG - i] as u64, g) as i64;
    }
}

fn digit(x: u64, i: usize) -> i64 {
    ((x >> (4 * i)) & 15) as i64
}

/// the debit relations (pqz_rel.c build_debit, its equation order): M legs (R_TX, R_TX0: 1; R_BURN: 0 with d =
/// digits(amount) public; R_TXM: M), auditor copies on / off; bit slots d_j at 64 j, d' at 64 M, M_i at 64 M + 64,
/// c_i + 64 at 64 M + 288, e_T + 2^24 at 64 M + 453; products as SvRel.pr (legs, pk_f, auditor copies, u_T)
fn debit_eval_fold(gm: &mut [Cp], ab: &mut [Cp], g: &[u64], t: &Stmt, s: &SvRel) -> u64 {
    let (m, a) = (s.legs, s.aud);
    let dp = 64 * m;
    let (mb, cb, eb) = (dp + 64, dp + 288, dp + 453);
    let (kf, kt) = (m, m + 1 + a * m);
    let mut e = 0;
    let mut r = 0u64;
    gm[..s.nprod].fill([0; DEG]);
    ab[..s.nbin].fill([0; DEG]);
    for i in 0..16 {
        let dpub = if s.burn { digit(t.amount, i) } else { 0 };
        // rows 3-5: (pk^T r)_i + e2_i + Delta digit_i - v_i
        for j in 0..m {
            tx_xinv(&mut gm[j], i, g[e]);
            for b in 0..4 {
                tx_bit(ab, slot(64 * j, 4, i, b), TX_DELTA << b, g[e]);
            }
            r = addq(r, mulq(g[e], negq(t.v[j][i] as u64)));
            e += 1;
        }
        tx_xinv(&mut gm[kf], i, g[e]);
        for b in 0..4 {
            tx_bit(ab, slot(dp, 4, i, b), TX_DELTA << b, g[e]);
        }
        r = addq(r, mulq(g[e], negq(t.vf[i] as u64)));
        e += 1;
        for j in 0..a * m {
            tx_xinv(&mut gm[kf + 1 + j], i, g[e]);
            for b in 0..4 {
                tx_bit(ab, slot(64 * j, 4, i, b), TX_DELTA << b, g[e]);
            }
            r = addq(r, mulq(g[e], negq(t.va[j][i] as u64)));
            e += 1;
        }
        // row 6: (u_T^T s_f)_i + Delta M_i + (e_T,i + 2^24) - 2^24 - v_T,i
        tx_xinv(&mut gm[kt], i, g[e]);
        for b in 0..14 {
            tx_bit(ab, slot(mb, 14, i, b), TX_DELTA << b, g[e]);
        }
        for b in 0..25 {
            tx_bit(ab, slot(eb, 25, i, b), 1 << b, g[e]);
        }
        r = addq(r, mulq(g[e], modq(-t.vt[i] - (1 << 24))));
        e += 1;
        // row 7: M_i + c_{i-1} - d'_i - sum_j d_j,i - f_i - 16 c_i (c = cbits - 64)
        let mut rhs = -digit(t.fee, i) - dpub;
        for b in 0..14 {
            tx_bit(ab, slot(mb, 14, i, b), 1 << b, g[e]);
        }
        if i >= 1 {
            for b in 0..11 {
                tx_bit(ab, slot(cb, 11, i - 1, b), 1 << b, g[e]);
            }
            rhs -= 64;
        }
        for b in 0..4 {
            tx_bit(ab, slot(dp, 4, i, b), -(1 << b), g[e]);
            for j in 0..m {
                tx_bit(ab, slot(64 * j, 4, i, b), -(1 << b), g[e]);
            }
        }
        if i <= 14 {
            for b in 0..11 {
                tx_bit(ab, slot(cb, 11, i, b), -(16 << b), g[e]);
            }
            rhs += 16 * 64;
        }
        r = addq(r, mulq(g[e], modq(rhs)));
        e += 1;
    }
    r
}

/// R_DS: (pk^T r)_i + e2_i + Delta d_i - v_i; R_DR: (u^T s)_i + (e'_i + 2^24) - 2^24 + Delta d_i - v_i
fn disc_eval_fold(gm: &mut [Cp], ab: &mut [Cp], g: &[u64], t: &Stmt, recv: bool) -> u64 {
    let mut r = 0u64;
    gm[..1].fill([0; DEG]);
    ab[..7].fill([0; DEG]);
    for i in 0..16 {
        tx_xinv(&mut gm[0], i, g[i]);
        if recv {
            for b in 0..25 {
                tx_bit(ab, 25 * i + b, 1 << b, g[i]);
            }
        }
        let c = TX_DELTA * digit(t.amount, i) - t.v[0][i] - if recv { 1 << 24 } else { 0 };
        r = addq(r, mulq(g[i], modq(c)));
    }
    r
}

fn eval_fold(s: &SvRel, code: u8, gm: &mut [Cp], ab: &mut [Cp], g: &[u64], t: &Stmt) -> u64 {
    if s.debit {
        debit_eval_fold(gm, ab, g, t, s)
    } else {
        disc_eval_fold(gm, ab, g, t, code == crate::OP_DISCLOSE_RECEIVER)
    }
}

// ---------------------------------------------------------------- verify

/// sum a_i^2 if <= bnd, else bnd + 1; bnd < 2^62, |a_i| < 2^62
fn l2_sum(a: &[i64], bnd: u64) -> u64 {
    let mut s = 0u64;
    for &x in a {
        let x = x.unsigned_abs();
        if x >= 1 << 31 {
            // x^2 >= 2^62 > bnd
            return bnd + 1;
        }
        s += x * x;
        if s > bnd {
            return bnd + 1;
        }
    }
    s
}

/// sum a_i^2 <= bnd < 2^62, |a_i| < 2^62
fn l2_le(a: &[i64], bnd: u64) -> bool {
    l2_sum(a, bnd) <= bnd
}

/// hash = SHAKE128(hash || enc(v)): one Fiat-Shamir round over urandom-coded polys mod q
fn hash_enc(hash: &[u8; 32], v: &mut polyvec::Sv<'_>) -> Result<[u8; 32], Error> {
    let mut c = Coder::new();
    c.urandom(v, &crate::arith::poly::RING_Q, 42)?;
    Ok(hash2(hash, &c.end()?))
}

/// `verify_body` (with `pqz_sv_verify`'s frame): false = reject; `Err` is C's sticky error (also a reject)
fn verify_body(ar: &Ar, s: &SvRel, code: u8, hash_stmt: &[u8; 32], stmt: &[u8], proof: &[u8]) -> Result<bool, Error> {
    let pr = &ar.pr;
    let p = s.p;
    let (mq, m1s, z, km, m2r, mm) = (s.mq, s.m1s, s.z, s.kmsis, s.m2r, s.m);
    let (nq, iy3, ibeta, ig) = (mq + NQL, mq, mq + 8, mq + NQEL);
    let ntot = LAMBDA / 2 + 2 + s.n;

    // statement (pqz_rel.c build_reg / parse_debit / parse_disc: every coefficient < q)
    let mut t = Stmt { vec: vz(s.nvec, [[0; DEG]; NPK])?, vt: [0; 16], vf: [0; 16], v: [[0; 16]; SVL], va: [[0; 16]; SVL], fee: 0, amount: 0 };
    if !parse_stmt(&mut t, s, code, stmt) {
        return Ok(false);
    }

    // proof: the generic decoder with the cap and the reductions of pqz_rel.c do_verify (h, c, z1, z21, z3, z4)
    if proof.len() > MAX_PROOF {
        return Ok(false);
    }
    // a proof that does not decode is invalid; running out of memory while decoding is not (Error::Memory)
    let mut f = match decode_proof(p, proof) {
        Err(Error::Memory) => return Err(Error::Memory),
        Err(_) => return Ok(false),
        Ok(f) => f,
    };

    // working memory
    let mut wz = vz(nq, NT0)?;
    let mut wsz = vz(nq, NT0)?;
    let mut zc = vz(DEG * nq, 0i64)?;
    let mut wz21 = vz(m2r, NT0)?;
    let mut wtb = vz(NQL + 1, NT0)?;
    let mut vr = vz(LAMBDA * s.nex * DEG, 0i64)?;
    let mut rows = vz(8 * s.nex * DEG / 4, 0u8)?;
    let (mut z3c, mut z4c, mut hc) = ([0i64; JLR], [0i64; JLR], [0i64; DEG * LAMBDA / 2]);
    let mut hint = vz(DEG * km, 0i64)?;
    let mut ta1 = vz(DEG * km, 0i64)?;
    let mut z21 = vz(DEG * m2r, 0i64)?;
    let mut tbc = vz(DEG * (NQL + 1), 0i64)?;

    // Fiat-Shamir round 1: statement digest, tA1 (abdlop_hashcomm, as pqz_rel.c do_verify)
    let mut hash = *hash_stmt;
    abdlop::hashcomm(&mut hash, &mut f.t_a1, &mut f.t_b, p.tbox)?;

    // _lnp_tbox_check_z34: ||z3||^2 <= Bz3sqr, ||z4||_inf <= Bz4, then the round over ty3 || ty4 || tbeta
    lz_get(&mut z3c, &f.z3);
    lz_get(&mut z4c, &f.z4);
    if !l2_le(&z3c, s.bz3sqr) {
        return Ok(false);
    }
    if z4c.iter().any(|x| x.unsigned_abs() > s.bz4) {
        return Ok(false);
    }
    let hash0 = {
        let mut c = Coder::new();
        for (off, n) in [(0, 4), (4, 4), (8, 1)] {
            let mut tv = f.t_b.sub(off, n, 1);
            polyvec::mod_self(&mut tv);
            polyvec::redp_self(&mut tv);
        }
        for (off, n) in [(0, 4), (4, 4), (8, 1)] {
            c.urandom(&mut f.t_b.sub(off, n, 1), &crate::arith::poly::RING_Q, 42)?;
        }
        hash2(&hash, &c.end()?)
    };
    // h: coefficients 0 and d/2 are zero
    lz_get(&mut hc, &f.h);
    for i in 0..LAMBDA / 2 {
        if hc[DEG * i] != 0 || hc[DEG * i + DEG / 2] != 0 {
            return Ok(false);
        }
    }
    // round over tg
    let hash1 = {
        let mut tg = f.t_b.sub(NQEL, LAMBDA / 2, 1);
        polyvec::mod_self(&mut tg);
        polyvec::redp_self(&mut tg);
        hash_enc(&hash0, &mut tg)?
    };

    // checks that need only the proof (lnp_quad_verify checks them after the challenge; any order gives the same
    // accept / reject): ||z1||^2, ||hint||_inf
    lz_get(&mut zc[..DEG * mq], &f.z1);
    if !l2_le(&zc[..DEG * mq], s.z1bnd) {
        return Ok(false);
    }
    lz_get(&mut hint, &f.hint);
    if hint.iter().any(|x| x.unsigned_abs() > s.dm) {
        return Ok(false);
    }

    // proof values in the NTT domain
    let cc = lz_coeffs(&f.c);
    if cc.iter().any(|&x| !(-8..=8).contains(&x)) {
        return Ok(false); // the challenge c2 has coefficients in [-8, 8]; c differs from it
    }
    let wc = ar.fwd(&cc);
    let wc2 = nt_mul(&wc, &wc, pr); // |c^2| <= 64 * 64
    let mut a = [0i64; DEG];
    for j in 0..DEG {
        a[j] = cc[j] * (1i64 << s.d);
    }
    let wcd = ar.fwd(&a); // c 2^D
    let wcj = nt_mul(&wc, &ar.nj, pr);
    lz_get(&mut z21, &f.z21);
    for j in 0..m2r {
        wz21[j] = ar.fwd(&z21[DEG * j..]);
    }
    lz_get(&mut tbc, &f.t_b);
    for j in 0..NQL + 1 {
        wtb[j] = ar.fwd(&tbc[DEG * j..]);
    }
    for i in 0..mq {
        wz[i] = ar.fwd(&zc[DEG * i..]);
        wsz[i] = nt_auto(&wz[i], pr);
    }
    // slots mq.. (y3, y4, beta, g): c tB_i - B'_i z21  (|.| < 46 2^90)
    for i in 0..NQL {
        let mut acc = ACC0;
        acc_mul(&mut acc, &wc, &wtb[i], pr);
        for j in 0..m2r {
            acc_mulsub(&mut acc, &s.bp[i * m2r + j], &wz21[j], pr);
        }
        let r = ar.red(&acc);
        zc[DEG * (mq + i)..DEG * (mq + i + 1)].copy_from_slice(&r);
        wz[mq + i] = ar.fwd(&r);
        wsz[mq + i] = nt_auto(&wz[mq + i], pr);
    }
    let zb: Cp = zc[DEG * ibeta..DEG * (ibeta + 1)].try_into().map_err(|_| Error::Internal)?;
    let bp_ = nt_add(&wz[ibeta], &wsz[ibeta], pr); // beta + o(beta)
    let bm_ = nt_sub(&wsz[ibeta], &wz[ibeta], pr); // o(beta) - beta
    let cbp = nt_mul(&wc, &bp_, pr); // |.| < 2^52
    let cbm = nt_mul(&wc, &bm_, pr);

    // challenges: the PRG seeds
    let (g0, g1) = (&hash0, &hash1);

    // ---- the evaluation-equation polynomials that do not depend on the challenges ----
    // upsilon: sum_j o(u_j) (u_j - c J)   (Z <= 43 terms with X-1: |.| < 43 * 2^91)
    let mut acc = ACC0;
    for j in 0..z {
        let t1 = nt_sub(&wz[m1s + j], &wcj, pr);
        acc_mul(&mut acc, &wsz[m1s + j], &t1, pr);
    }
    let eu = ar.red(&acc);
    // binary: sum_b o(b) (b - c J)
    let mut acc = ACC0;
    for j in 0..s.nbin {
        let t1 = nt_sub(&wz[s.pstart + j], &wcj, pr);
        acc_mul(&mut acc, &wsz[s.pstart + j], &t1, pr);
    }
    let eb = ar.red(&acc);
    // exact l2, block i: sum o(x) x + c o(powB_i) upsilon_i - B_i^2 c^2   (|.| < 2^96 + 2^98)
    let mut el = vz(z, [0i64; DEG])?;
    for i in 0..z {
        let mut acc = ACC0;
        for j in 0..s.blen[i] {
            acc_mul(&mut acc, &wsz[s.bstart[i] + j], &wz[s.bstart[i] + j], pr);
        }
        let t1 = nt_mul(&wc, &s.opow[i], pr);
        acc_mul(&mut acc, &t1, &wz[m1s + i], pr);
        acc_scal(&mut acc, &wc2, s.b2[i], true, pr);
        el[i] = ar.red(&acc);
    }
    // evaluation-equation products: vec^T x (+ e2), e.g. R_TX pk_t^T r + e2_t (t < 3), u_T^T s_f
    let mut pke = vz(s.nprod.max(1), NT0)?;
    for k in 0..s.nprod {
        let pk = &s.pr[k];
        let mut acc = ACC0;
        for j in 0..NPK {
            let t1 = ar.fwd(&t.vec[pk.v][j]);
            acc_mul(&mut acc, &t1, &wz[pk.ox + j], pr);
        }
        if let Some(e2) = pk.e2 {
            acc_add(&mut acc, &wz[e2]);
        }
        pke[k] = ar.fwd(&ar.red(&acc));
    }

    // ---- z3 / z4 (JL) rows: V from (hash0, dom), R / R' rows from (hash0, i) / (hash0, 256 + i) ----
    let mut v3 = vz(1, [[0u64; JLR]; LAMBDA])?;
    let mut v4 = vz(1, [[0u64; JLR]; LAMBDA])?;
    let (v3, v4) = (&mut v3[0], &mut v4[0]);
    let mut gz = [NT0; LAMBDA]; // z3 + z4 term of accumulator half k (reduced)
    let dom_z4 = (mm + 2 * (DEG - 1) + 2 + z) as u32;
    let dom_z3 = dom_z4 + 256;
    urandom_mat(v4, g0, dom_z4)?;
    urandom_mat(v3, g0, dom_z3)?;
    {
        let mut ga = [ACC0; LAMBDA];
        // inv2 (beta + o(beta)), inv2 X^32 (o(beta) - beta) as coefficients mod q
        let ab = cp_auto(&zb);
        let mut b = [0i64; DEG];
        for j in 0..DEG {
            b[j] = mulq(s.inv2, addq(zb[j] as u64, ab[j] as u64)) as i64;
        }
        let bh = ar.fwd(&b);
        let mut r = [0i64; DEG];
        for j in 0..DEG {
            r[j] = subq(ab[j] as u64, zb[j] as u64) as i64;
        }
        let mut b = cp_mulx(&r, DEG / 2);
        for x in b.iter_mut() {
            *x = mulq(s.inv2, *x as u64) as i64;
        }
        let bm = ar.fwd(&b);
        let t1 = nt_mul(&wsz[s.dsel], &bm, pr);
        let p4 = ar.fwd(&ar.red_nt(&t1)); // o(s_D) inv2 X^32 (o(beta) - beta), reduced
        let mut cy = [NT0; 8];
        for i in 0..8 {
            cy[i] = nt_mul(&wc, &wsz[iy3 + i], pr); // c o(y3_i), c o(y4_i): |.| < 2^51
        }

        // z4: inv2 X^32 W4_k o(s_D) (o(beta) - beta) + c sum_i V4_k,i o(y4_i) - <z4, V4_k> c^2
        jl_fold(&mut vr, DEG, v4, g0, 256, &mut rows)?;
        for k in 0..LAMBDA {
            let mut a = [0i64; DEG];
            for j in 0..DEG {
                a[j] = modq(vr[LAMBDA * j + k]) as i64;
            }
            let t1 = ar.fwd(&a);
            acc_mul(&mut ga[k], &t1, &p4, pr);
            for i in 0..JLR / DEG {
                for j in 0..DEG {
                    a[j] = v4[k][DEG * i + j] as i64;
                }
                let t1 = ar.fwd(&a);
                acc_mul(&mut ga[k], &t1, &cy[4 + i], pr);
            }
            let mut sk = 0;
            for j in 0..JLR {
                sk = addq(sk, mulq(modq(z4c[j]), v4[k][j]));
            }
            acc_scal(&mut ga[k], &wc2, sk, true, pr);
        }
        // z3: inv2 (beta + o(beta)) sum_p o(s_p) W3_k,col(p) + c sum_i V3_k,i o(y3_i) - <z3, V3_k> c^2
        jl_fold(&mut vr, s.nex * DEG, v3, g0, 0, &mut rows)?;
        for k in 0..LAMBDA {
            let mut col = 0;
            let mut acc = ACC0; // nex <= 426 terms (R_TXM, 16 legs, X-1 blocks): |.| < 426 2^90
            let mut w3mac = |sl: usize, acc: &mut Acc| {
                let mut a = [0i64; DEG];
                for j in 0..DEG {
                    a[j] = modq(vr[LAMBDA * (DEG * col + j) + k]) as i64;
                }
                let t1 = ar.fwd(&a);
                acc_mul(acc, &wsz[sl], &t1, pr);
                col += 1;
            };
            // the columns of vR: Ps rows, then each Es_i's rows, then upsilon
            for i in 0..s.nbin {
                w3mac(s.pstart + i, &mut acc);
            }
            for h in 0..s.nblk {
                for i in 0..s.blen[h] {
                    w3mac(s.bstart[h] + i, &mut acc);
                }
            }
            for i in 0..z {
                w3mac(m1s + i, &mut acc);
            }
            let t1 = ar.fwd(&ar.red(&acc));
            acc_mul(&mut ga[k], &bh, &t1, pr);
            let mut a = [0i64; DEG];
            for i in 0..JLR / DEG {
                for j in 0..DEG {
                    a[j] = v3[k][DEG * i + j] as i64;
                }
                let t1 = ar.fwd(&a);
                acc_mul(&mut ga[k], &t1, &cy[i], pr);
            }
            let mut sk = 0;
            for j in 0..JLR {
                sk = addq(sk, mulq(modq(z3c[j]), v3[k][j]));
            }
            acc_scal(&mut ga[k], &wc2, sk, true, pr);
            gz[k] = ar.acc_nt(&ga[k]); // the k-th z3 + z4 terms, |.| < 2^102, Montgomery form
        }
    }

    // ---- the Schwartz-Zippel accumulators: half k' = 2 i + h of pair i ----
    let nsz = 2 * (DEG - 1) + 2 + z; // beta3 (63), beta4 (63), upsilon, binary, l2 (Z)
    let mut gsz = vz(LAMBDA * nsz, 0u64)?;
    let mut gin = vz(LAMBDA * mm.max(1), 0u64)?;
    let mut hh = [[0i64; DEG]; LAMBDA];
    {
        let mut e = 0;
        if mm > 0 {
            // sz_eval_challenges: LAMBDA M values mod q from (seed, dom), as __schwartz_zippel_accumulate2
            urandom_q(&mut gin[..LAMBDA * mm], g1, 0)?;
        }
        let mut one = |dom: usize, e: &mut usize| -> Result<(), Error> {
            let mut gb = [0u64; LAMBDA];
            urandom_q(&mut gb, g1, dom as u64)?;
            for k in 0..LAMBDA {
                gsz[k * nsz + *e] = gb[k];
            }
            *e += 1;
            Ok(())
        };
        for i in 1..DEG {
            one(mm + i, &mut e)?; // beta3: dom M + i
        }
        for i in 1..DEG {
            one(mm + DEG - 1 + i, &mut e)?; // beta4: dom M + d - 1 + i
        }
        one(mm + 2 * (DEG - 1), &mut e)?; // upsilon
        if s.nbin > 0 {
            one(mm + 2 * (DEG - 1) + 1, &mut e)?; // binary
        } else {
            e += 1;
        }
        for i in 0..z {
            one(mm + 2 * (DEG - 1) + 2 + i, &mut e)?; // l2: one call per equation, dom + i (P6-L2)
        }
    }
    let (mut gm, mut abits) = (vz(SVPR, [0i64; DEG])?, vz(SVBIN, [0i64; DEG])?);
    for k in 0..LAMBDA {
        let g = &gsz[k * nsz..(k + 1) * nsz];
        let mut acc = ACC0;
        acc_add(&mut acc, &gz[k]);
        // beta3: c inv2 (beta + o(beta)) sum_i g_i X^i ; beta4: c inv2 X^32 (o(beta) - beta) sum_i g_i X^i
        let mut a = [0i64; DEG];
        for i in 1..DEG {
            a[i] = mulq(s.inv2, g[i - 1]) as i64;
        }
        acc_mul(&mut acc, &cbp, &ar.fwd(&a), pr); // |.| < 2^100
        let mut r = [0i64; DEG];
        for i in 1..DEG {
            r[i] = mulq(s.inv2, g[DEG - 1 + i - 1]) as i64;
        }
        acc_mul(&mut acc, &cbm, &ar.fwd(&cp_mulx(&r, DEG / 2)), pr);
        if mm > 0 {
            // c (sum_k Gm_k P_k + sum_b Ab_b bits_b) + rho c^2, e.g. R_TX P = pk_t^T r + e2_t, .., u_T^T s_f
            let rho = eval_fold(s, code, &mut gm, &mut abits, &gin[k * mm..(k + 1) * mm], &t);
            let mut br = ACC0; // nprod + nbin <= 34 + 30 terms: |.| < 64 2^90
            for i in 0..s.nprod {
                acc_mul(&mut br, &ar.fwd(&gm[i]), &pke[i], pr);
            }
            for i in 0..s.nbin {
                acc_mul(&mut br, &ar.fwd(&abits[i]), &wz[s.pstart + i], pr);
            }
            acc_mul(&mut acc, &wc, &ar.acc_nt(&br), pr); // |.| < 2^105
            acc_scal(&mut acc, &wc2, rho, false, pr);
        }
        let mut gg = ar.red(&acc);
        // + g_ups E_ups + g_bin E_bin + sum_i g_l2 E_l2,i (coefficients mod q)
        for j in 0..DEG {
            let mut x = addq(gg[j] as u64, mulq(g[2 * (DEG - 1)], eu[j] as u64));
            if s.nbin > 0 {
                x = addq(x, mulq(g[2 * (DEG - 1) + 1], eb[j] as u64));
            }
            for i in 0..z {
                x = addq(x, mulq(g[2 * (DEG - 1) + 2 + i], el[i][j] as u64));
            }
            gg[j] = x as i64;
        }
        hh[k] = gg;
    }
    // __schwartz_zippel_auto: pair i -> inv2 (G1 + o(G1) + X^32 (G2 + o(G2)))
    for i in 0..LAMBDA / 2 {
        let (g1p, g2p) = (hh[2 * i], hh[2 * i + 1]);
        let a = cp_auto(&g2p);
        let mut r = [0i64; DEG];
        for j in 0..DEG {
            r[j] = addq(g2p[j] as u64, a[j] as u64) as i64;
        }
        let b = cp_mulx(&r, DEG / 2);
        let a = cp_auto(&g1p);
        for j in 0..DEG {
            hh[2 * i + 1][j] = mulq(s.inv2, addq(addq(g1p[j] as u64, a[j] as u64), b[j] as u64)) as i64;
        }
    }

    // ---- lnp_quad_many_verify / lnp_quad_verify: v = sum_k mu_k E_k(z) - f, grouped by the power of c ----
    let (mut qa, mut la, mut ra) = (ACC0, ACC0, ACC0);
    for k in 0..ntot {
        let mut mu = [0u64; DEG];
        urandom_q(&mut mu, g1, (k + 1) as u64)?; // polyvec_urandom (mu, q, log2q, hash, 0)
        let mut a = [0i64; DEG];
        for j in 0..DEG {
            a[j] = mu[j] as i64;
        }
        let mn = ar.fwd(&a);
        if k < LAMBDA / 2 {
            // accumulator pair k: E = H_k + c g_k - c^2 h_k
            acc_mul(&mut qa, &mn, &ar.fwd(&hh[2 * k + 1]), pr);
            acc_mul(&mut la, &mn, &wz[ig + k], pr);
            acc_mulsub(&mut ra, &mn, &ar.fwd(&hc[DEG * k..]), pr);
        } else if k < LAMBDA / 2 + 2 {
            // beta3^2 - 1, beta4^2 - 1
            let pos = k == LAMBDA / 2;
            let sq = ar.red_nt(&nt_mul(&wz[ibeta], &wz[ibeta], pr));
            let x = ar.red_nt(&nt_mul(&wz[ibeta], &wsz[ibeta], pr));
            let osq = cp_auto(&sq);
            for j in 0..DEG {
                let y = mulq(s.inv4, addq(sq[j] as u64, osq[j] as u64));
                a[j] = addq(if pos { y } else { negq(y) }, mulq(s.inv2, x[j] as u64)) as i64;
            }
            acc_mul(&mut qa, &mn, &ar.fwd(&a), pr);
            acc_sub(&mut ra, &mn, pr);
        } else {
            // input row i: c (A' x + y)_i - c^2 rhs_i
            let row = k - (LAMBDA / 2 + 2);
            let (blk, ii) = (row / NPK, row % NPK);
            let rb = s.rb[blk];
            let mut acc = ACC0; // |.| < 33 2^90
            for j in 0..NPK {
                let aij = if rb.tr { &ar.sa[j * NPK + ii] } else { &ar.sa[ii * NPK + j] };
                acc_mul(&mut acc, aij, &wz[rb.ox + j], pr);
            }
            acc_add(&mut acc, &wz[rb.oy + ii]);
            acc_mul(&mut la, &mn, &ar.fwd(&ar.red(&acc)), pr);
            acc_mulsub(&mut ra, &mn, &ar.fwd(&t.vec[rb.rhs][ii]), pr);
        }
    }
    // - f = - c t + B'_ext z21
    for j in 0..m2r {
        acc_mul(&mut qa, &s.bp[NQL * m2r + j], &wz21[j], pr);
    }
    acc_sub(&mut la, &wtb[NQL], pr);
    acc_mul(&mut qa, &wc, &ar.fwd(&ar.red(&la)), pr);
    acc_mul(&mut qa, &wc2, &ar.fwd(&ar.red(&ra)), pr);
    let v = ar.red(&qa); // |.| < 2^97

    // ---- w = A1 z1 + A2' z21 - c 2^D tA1 (|.| < (mq + m2r + 1) 2^90 <= 472 2^90), w1 = UseHint (hint, w) ----
    let mut w1 = vz(DEG * km, 0i64)?;
    let mut wl = vz(DEG * km, 0i64)?;
    lz_get(&mut ta1, &f.t_a1);
    for i in 0..km {
        let mut acc = ACC0;
        for j in 0..mq {
            acc_mul(&mut acc, &s.a1[i * mq + j], &wz[j], pr);
        }
        for j in 0..m2r {
            acc_mul(&mut acc, &s.a2p[i * m2r + j], &wz21[j], pr);
        }
        acc_mulsub(&mut acc, &wcd, &ar.fwd(&ta1[DEG * i..]), pr);
        let r = ar.red(&acc);
        for j in 0..DEG {
            // dcompress_use_ghint (r in [0, q))
            let r1 = r[j] as u64;
            let mut r0 = (r1 % s.gamma) as i64;
            if r0 as u64 > s.gammaby2 {
                r0 -= s.gamma as i64;
            }
            let hi = (r1 as i64 - r0) as u64;
            let hi = if hi == s.qm1 { 0 } else { hi / s.gamma };
            let mut y = (hi as i64 + hint[DEG * i + j]) % s.dm as i64;
            if y < 0 {
                y += s.dm as i64;
            }
            w1[DEG * i + j] = y;
            // lnp_quad_verify norm term: centre (w - gamma w1)
            wl[DEG * i + j] = centre(subq(r1, mulq(s.gamma % Q, y as u64)));
        }
    }

    // ---- final round: c' = H(hash1 || t || v || w1) must give c ----
    {
        let mut w1v = PolyVec::new(km)?;
        for (i, x) in w1v.iter_mut().enumerate() {
            x.set_i64(&w1[DEG * i..DEG * (i + 1)]);
        }
        let mut vv = Poly::ZERO;
        vv.set_i64(&v); // [0, q), as poly_mod + poly_redp leave it
        let mut tt = f.t_b.sub(NQL, 1, 1);
        polyvec::mod_self(&mut tt);
        polyvec::redp_self(&mut tt);
        let mut c = Coder::new();
        c.urandom(&mut tt, &crate::arith::poly::RING_Q, 42)?;
        c.urandom(core::slice::from_mut(&mut vv), &crate::arith::poly::RING_Q, 42)?;
        c.urandom(&mut *w1v, &Int::from_i64(1, s.dm as i64), s.log2m)?;
        let cseed = hash2(&hash1, &c.end()?);
        let mut c2 = Poly::urandom_autostable(8, 5, &cseed, 0)?;
        if !Poly::eq(&mut f.c, &mut c2) {
            return Ok(false);
        }
    }
    // ||(z21, w - gamma w1)||^2 <= B^2: the whole z2, as LNP22 Fig. 18 and the honest prover (P6-Z21, lazer#26;
    // lnp_quad_verify does the same). Upstream bounded only the w - gamma w1 (z22) part.
    let s21 = l2_sum(&z21, s.bsq);
    if s21 > s.bsq || !l2_le(&wl, s.bsq - s21) {
        return Ok(false);
    }
    Ok(true)
}

impl Ctx {
    /// `pqz_verify_fast`: Ok(true) = 1; every failure (also an allocation failure, as C's arena) is 0. The relation's
    /// keys and A (shared with `verify`) and its tables here are built at first use.
    pub(crate) fn verify_sv(&mut self, op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, Error> {
        let Some(ri) = rel::rel_of(op, stmt) else { return Ok(false) };
        let r = &RELS[ri];
        self.rel_state(ri)?;
        let (Some(keys), Some(a)) = (&self.keys[ri], &self.a) else { return Err(Error::Internal) };
        if self.sv.is_none() {
            self.sv = Some(Ar::new(a)?);
        }
        let Some(ar) = &self.sv else { return Err(Error::Internal) };
        if self.svrel[ri].is_none() {
            self.svrel[ri] = Some(setup(ar, r, keys)?);
        }
        let Some(s) = &self.svrel[ri] else { return Err(Error::Internal) };
        let h = rel::stmt_hash(op, stmt);
        verify_body(ar, s, r.code, &h, stmt, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// verify_body's hint bound (|hint_j| <= m) is unreachable by encoding: the ghint coder spends 2 e - 1 bits on a
    /// coefficient e >= 2 and -2 e on e <= -2 (`coder::ghint_bits`), so one coefficient with |e| > m costs at least
    /// 2 m + 1 bits; with 2 m - 1 > 8 MAX_PROOF no proof that passes the length cap carries one. A parameter change
    /// that makes the bound reachable (and so worth a cheating-prover fixture) fails here.
    #[test]
    fn hint_bound_unreachable_by_encoding() {
        for r in RELS.iter() {
            let m = int_u64(&r.p.quad_eval.quad_many.dcompress.m).unwrap();
            assert!(2 * m - 1 > 8 * MAX_PROOF as u64, "{}: m = {m}", r.name);
        }
    }
}
