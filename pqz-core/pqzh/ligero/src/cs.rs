//! R_REG, R_TX, R_BURN, R_DS and R_DR as Ligero constraint systems over F_q (docs/research/pqzh-ligero.md §3, §12):
//! statement parsing (the same bytes and checks as pqz-core's pqz_rel.c), the row layout, the witness rows, the
//! quadratic triples and the linear test's combination vectors.
//!
//! Relations (pqz_rel.c, pq-zether.md §7.4 / §7.5 / §7.9; d = digits(amount) public where marked):
//!   R_REG  pk = A s + e
//!   R_TX   rows 1-7: pk_f = A s_f + e_f; u = A^T r + e1; v_x = pk_x^T r + e2_x + Delta digit_x (x = t, f, a; digits
//!          d, d', d); u_T^T s_f + Delta M + e_T = v_T; M_i + c_{i-1} - d'_i - d_i - 16 c_i = fee_i, c_15 = 0
//!   R_BURN R_TX rows 1, 2, 4, 6, 7 with d public (one leg: pk_f, v_f, e2_f, d')
//!   R_DS   u = A^T r + e1; pk^T r + e2 = v - Delta d (k < 16)
//!   R_DR   pk = A s + e; u^T s + e' = v - Delta d (k < 16), e' + 2^24 in 25 bits
//! with every exact l2 bound of pqz-core (36 / 164 for CBD(1) / CBD(20) vectors, 64 for e2) and the bit ranges.
//!
//! Layout (§3.3). Rows have l slots. A big group (2048 values of one short vector) has value rows, slot-aligned square
//! rows and one row per bit of x + off (off = 2^(bits-1)); the bit decomposition covers every slot of the group's rows
//! (padding slots hold 0, its square 0 and the bits of off). The small values (e2, digits, M, carries, e_T, e', the l2
//! slacks) are packed in small value rows, aligned small square rows, and small bit rows that hold their bits
//! back to back.
//!
//! Linear test (§3.4). Constraint c gets weight rho^(e_c) with distinct exponents e_c >= 1 (a committed blind with a
//! nonzero sum over H_k then cannot cancel a violated constraint: the combination is a non-constant polynomial in rho).
//! Ring rows use the tensor weights w(i, k) = w0 G^i rho^k (G = rho^K), so the coefficient of x_{j,m} is
//! f_m(a_j) = sum_k rho^k (X^m a_j mod X^64 + 1)_k with a_j = sum_i w0 G^i M_ij, computed by a 64-step recurrence.
//! Bit decompositions of big rows use lambda_r rho^c, so every bit / value row's vector is a multiple of the one
//! shared vector beta = (rho^c)_c; the l2 norms use the all-ones vector on the square rows. The verifier interpolates
//! only the "own" vectors (big value rows, small rows) and the two shared ones.

use crate::client::{digits, encrypt, keypair, polys};
use crate::ring::{D, DELTA, Poly, a_matrix, dot_int, modq, rd_poly, rd_polyvec};
use crate::stmt::*;

use crate::fq::{Acc4, F4, Fq};

const BS: i64 = 36 * 36;
const BE: i64 = 164 * 164;
const B2: i64 = 64 * 64;
const N: usize = 2048;

pub struct Big {
    pub bits: usize,
    pub off: i64,
    pub b2: i64,
    pub base: usize,
    pub nr: usize,
}

impl Big {
    pub fn vrow(&self, r: usize) -> usize {
        self.base + r
    }
    pub fn srow(&self, r: usize) -> usize {
        self.base + self.nr + r
    }
    pub fn brow(&self, j: usize, r: usize) -> usize {
        self.base + (2 + j) * self.nr + r
    }
}

pub struct Item {
    pub count: usize,
    pub bits: usize,
    pub off: i64,
    /// first small-value index, first small-bit index
    pub v0: usize,
    pub b0: usize,
}

pub struct Layout {
    pub ell: usize,
    pub m: usize,
    pub big: Vec<Big>,
    pub small: Vec<Item>,
    /// index of the first l2 slack item: big group g's at sig + g, then e2 leg x's at sig + #big + x
    pub sig: usize,
    pub sv: usize,
    pub ss: usize,
    pub sb: usize,
    pub nsv: usize,
    pub nsb: usize,
    /// (x, y, z): row x times row y equals row z in every slot
    pub triples: Vec<(usize, usize, usize)>,
}

// debit small items (indices into Layout::small): e2 legs, d (R_TX only), d', M, carries, e_T, then the slacks
const E2: usize = 0;
/// R_DR's e' (item 0)
const EP: usize = 0;

/// (d, d', M, c, e_T) item indices of a debit layout; d is None for R_BURN (public)
fn debit_items(burn: bool) -> (Option<usize>, usize, usize, usize, usize) {
    if burn { (None, 1, 2, 3, 4) } else { (Some(1), 2, 3, 4, 5) }
}

impl Layout {
    pub fn new(op: u8, ell: usize) -> Layout {
        assert!(ell >= 1);
        // big groups (bits, off, B^2) of a CBD(1) / CBD(20) pair; small items (count, bits, off)
        let se = [(7, 64, BS), (9, 256, BE)];
        let sl = [(1, 11, 0), (1, 15, 0)];
        let e2 = |legs: usize| (16 * legs, 8, 128);
        let debit = |legs: usize, d: bool| -> Vec<(usize, usize, i64)> {
            let mut v = vec![e2(legs)];
            if d {
                v.push((16, 4, 0));
            }
            v.extend([(16, 4, 0), (16, 14, 0), (16, 11, 64), (16, 25, 1 << 24)]);
            v.extend(sl);
            v.extend(sl);
            v.extend(vec![(1, 13, 0); legs]);
            v
        };
        let (bigs, smalls, sig): (Vec<(usize, i64, i64)>, Vec<(usize, usize, i64)>, usize) = match op {
            OP_REGISTER => (se.to_vec(), sl.to_vec(), 0),
            OP_TRANSFER => ([se, se].concat(), debit(3, true), 6),
            OP_BURN => ([se, se].concat(), debit(1, false), 5),
            OP_DISCLOSE_SENDER => (se.to_vec(), [vec![e2(1)], sl.to_vec(), vec![(1, 13, 0)]].concat(), 1),
            OP_DISCLOSE_RECEIVER => (se.to_vec(), [vec![(16, 25, 1 << 24)], sl.to_vec()].concat(), 1),
            _ => panic!("no relation for op {op}"),
        };
        let mut cur = 0;
        let nr = N.div_ceil(ell);
        let big: Vec<Big> = bigs
            .into_iter()
            .map(|(bits, off, b2)| {
                let g = Big { bits, off, b2, base: cur, nr };
                cur += nr * (2 + bits);
                g
            })
            .collect();
        let (mut v0, mut b0) = (0, 0);
        let small: Vec<Item> = smalls
            .into_iter()
            .map(|(count, bits, off)| {
                let it = Item { count, bits, off, v0, b0 };
                v0 += count;
                b0 += count * bits;
                it
            })
            .collect();
        let nsv = v0.div_ceil(ell);
        let nsb = b0.div_ceil(ell);
        let (sv, ss, sb) = (cur, cur + nsv, cur + 2 * nsv);
        let m = sb + nsb;
        let mut triples = Vec::new();
        for g in &big {
            for r in 0..nr {
                triples.push((g.vrow(r), g.vrow(r), g.srow(r)));
                for j in 0..g.bits {
                    triples.push((g.brow(j, r), g.brow(j, r), g.brow(j, r)));
                }
            }
        }
        for r in 0..nsv {
            triples.push((sv + r, sv + r, ss + r));
        }
        for r in 0..nsb {
            triples.push((sb + r, sb + r, sb + r));
        }
        Layout { ell, m, big, small, sig, sv, ss, sb, nsv, nsb, triples }
    }

    pub fn bpos(&self, g: usize, v: usize) -> (usize, usize) {
        (self.big[g].base + v / self.ell, v % self.ell)
    }
    /// small value `idx` of item `it`
    pub fn spos(&self, it: usize, idx: usize) -> (usize, usize) {
        let v = self.small[it].v0 + idx;
        (self.sv + v / self.ell, v % self.ell)
    }
    pub fn sqpos(&self, it: usize, idx: usize) -> (usize, usize) {
        let v = self.small[it].v0 + idx;
        (self.ss + v / self.ell, v % self.ell)
    }
    pub fn bitpos(&self, it: usize, idx: usize, j: usize) -> (usize, usize) {
        let b = self.small[it].b0 + idx * self.small[it].bits + j;
        (self.sb + b / self.ell, b % self.ell)
    }
}

// ---- statement ----

/// one ciphertext leg of a debit statement: v = pk^T r + e2 + Delta digits
pub struct Leg {
    pub pk: Vec<Poly>,
    pub v: Poly,
    /// the leg carries d' (the new balance); otherwise d (the amount)
    pub dp: bool,
}

/// R_TX (legs t, f, a) and R_BURN (leg f only, amount public)
pub struct Debit {
    pub burn: bool,
    pub pkf: Vec<Poly>,
    pub legs: Vec<Leg>,
    pub ut: Vec<Poly>,
    pub vt: Poly,
    pub u: Vec<Poly>,
    pub fee: u64,
    pub amount: u64,
}

/// R_DS / R_DR: one ciphertext (u, v) of `amount` under pk
pub struct Disc {
    pub pk: Vec<Poly>,
    pub u: Vec<Poly>,
    pub v: Poly,
    pub amount: u64,
}

pub enum Stmt {
    Reg(Vec<Poly>),
    Debit(Debit),
    Ds(Disc),
    Dr(Disc),
}

/// a be32 statement word that must be < 2^64 (pqz_rel.c rd_word64)
fn word64(stmt: &[u8], off: usize) -> Option<u64> {
    let w = &stmt[off..off + 32];
    if w[..24].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(w[24..].try_into().unwrap()))
}

struct Rd<'a>(&'a [u8], usize);
impl Rd<'_> {
    fn vec(&mut self) -> Option<Vec<Poly>> {
        self.1 += POLYVEC;
        rd_polyvec(&self.0[self.1 - POLYVEC..])
    }
    fn v(&mut self) -> Option<Poly> {
        self.1 += VB;
        rd_poly(&self.0[self.1 - VB..], 16)
    }
}

/// pqz-core's statement checks: exact length, canonical coefficients, read words < 2^64 (pqz_rel.c build)
pub fn parse(op: u8, stmt: &[u8]) -> Option<Stmt> {
    match op {
        OP_REGISTER if stmt.len() == REG_STMT => Some(Stmt::Reg(rd_polyvec(&stmt[PREFIX + 32..])?)),
        OP_TRANSFER | OP_BURN if stmt.len() == (if op == OP_BURN { BURN_STMT } else { TX_STMT }) => {
            let burn = op == OP_BURN;
            let fee = word64(stmt, HDR_FEE)?;
            let amount = if burn { word64(stmt, HDR_AMOUNT)? } else { 0 };
            let mut r = Rd(stmt, HEADER);
            let pkf = r.vec()?;
            let (pkt, pka) = if burn { (vec![], vec![]) } else { (r.vec()?, r.vec()?) };
            let (ut, vt, u) = (r.vec()?, r.v()?, r.vec()?);
            let legs = if burn {
                vec![Leg { pk: pkf.clone(), v: r.v()?, dp: true }]
            } else {
                let (vt_, vf, va) = (r.v()?, r.v()?, r.v()?);
                vec![Leg { pk: pkt, v: vt_, dp: false }, Leg { pk: pkf.clone(), v: vf, dp: true }, Leg { pk: pka, v: va, dp: false }]
            };
            Some(Stmt::Debit(Debit { burn, pkf, legs, ut, vt, u, fee, amount }))
        }
        OP_DISCLOSE_SENDER | OP_DISCLOSE_RECEIVER if stmt.len() == DISC_STMT => {
            let amount = word64(stmt, DISC_AMOUNT)?;
            let mut r = Rd(stmt, DISC_PK);
            let d = Disc { pk: r.vec()?, u: r.vec()?, v: r.v()?, amount };
            Some(if op == OP_DISCLOSE_SENDER { Stmt::Ds(d) } else { Stmt::Dr(d) })
        }
        _ => None,
    }
}

/// v - Delta digits(amount) (the public side of R_DS / R_DR's evaluation rows)
fn v_minus(v: &Poly, amount: u64) -> Poly {
    let d = digits(amount);
    std::array::from_fn(|k| if k < 16 { v[k] - DELTA * d[k] as i64 } else { v[k] })
}

// ---- witness ----

pub struct Wit {
    pub big: Vec<Vec<i64>>,
    pub small: Vec<i64>,
}

fn rd_i8(b: &[u8], n: usize) -> Vec<i64> {
    b[..n].iter().map(|&x| x as i8 as i64).collect()
}
fn rd_i16(b: &[u8], n: usize) -> Vec<i64> {
    (0..n).map(|i| i16::from_le_bytes([b[2 * i], b[2 * i + 1]]) as i64).collect()
}
fn l2(v: &[i64]) -> i64 {
    v.iter().map(|x| x * x).sum()
}

/// Witness values from pqz-core's witness bytes. `check` = the honest prover's checks (as pqz_rel.c's witness
/// builders plus the key / ciphertext equations); without them an invalid witness is laid out anyway (bits wrap), for
/// the negative tests.
pub fn witness(st: &Stmt, wit: &[u8], check: bool) -> Result<Wit, &'static str> {
    match st {
        Stmt::Reg(pk) => {
            if wit.len() != REG_WIT {
                return Err("length");
            }
            let s = rd_i8(wit, N);
            let e = rd_i16(&wit[N..], N);
            if check && (l2(&s) > BS || l2(&e) > BE) {
                return Err("witness norm");
            }
            if check && keypair(&polys(&s), &polys(&e)) != *pk {
                return Err("pk != A s + e");
            }
            let small = vec![BS - l2(&s), BE - l2(&e)];
            Ok(Wit { big: vec![s, e], small })
        }
        Stmt::Debit(t) => {
            let want = if t.burn { BURN_WIT } else { TX_WIT };
            if wit.len() != want {
                return Err("length");
            }
            let nl = t.legs.len();
            let sf = rd_i8(wit, N);
            let ef = rd_i16(&wit[2048..], N);
            let r = rd_i8(&wit[6144..], N);
            let e1 = rd_i16(&wit[8192..], N);
            let e2: Vec<Vec<i64>> = (0..nl).map(|x| rd_i16(&wit[12288 + 32 * x..], 16)).collect();
            let p = 12288 + 32 * nl;
            let (d, dp): ([u8; 16], [u8; 16]) = if t.burn {
                (digits(t.amount), wit[p..p + 16].try_into().unwrap())
            } else {
                (wit[p..p + 16].try_into().unwrap(), wit[p + 16..p + 32].try_into().unwrap())
            };
            if check && (l2(&sf) > BS || l2(&ef) > BE || l2(&r) > BS || l2(&e1) > BE || e2.iter().any(|x| l2(x) > B2)) {
                return Err("witness norm");
            }
            if check && keypair(&polys(&sf), &polys(&ef)) != t.pkf {
                return Err("pk_f != A s_f + e_f");
            }
            if check {
                let pks: Vec<&Vec<Poly>> = t.legs.iter().map(|l| &l.pk).collect();
                let msgs: Vec<[u8; 16]> = t.legs.iter().map(|l| if l.dp { dp } else { d }).collect();
                let (u, vs) = encrypt(&pks, &msgs, &polys(&r), &polys(&e1), &e2);
                if u != t.u || vs.iter().zip(&t.legs).any(|(v, l)| *v != l.v) {
                    return Err("ciphertext");
                }
            }
            // M, e_T by rounding, carries (pqz_rel.c debit_witness)
            let y = dot_int(&t.ut.iter().collect::<Vec<_>>(), &polys(&sf).iter().collect::<Vec<_>>());
            let (mut mv, mut et, mut cv) = (vec![0i64; 16], vec![0i64; 16], vec![0i64; 16]);
            let mut cprev = 0i64;
            for i in 0..16 {
                let wv = modq(t.vt[i] - y[i]);
                let m = (if wv >= 0 { wv + DELTA / 2 } else { wv - DELTA / 2 }) / DELTA;
                let e = wv - DELTA * m;
                let s = m + cprev - dp[i] as i64 - d[i] as i64 - ((t.fee >> (4 * i)) & 15) as i64;
                if check
                    && (s % 16 != 0 || d[i] > 15 || dp[i] > 15 || !(0..1 << 14).contains(&m) || !(-(1 << 24)..1 << 24).contains(&e))
                {
                    return Err("digits");
                }
                let c = s.div_euclid(16);
                if check && !(-64..1984).contains(&c) {
                    return Err("carry");
                }
                (mv[i], et[i], cv[i]) = (m, e, c);
                cprev = c;
            }
            if check && cprev != 0 {
                return Err("carry out");
            }
            let mut small: Vec<i64> = e2.iter().flatten().copied().collect();
            if !t.burn {
                small.extend(d.iter().map(|&x| x as i64));
            }
            small.extend(dp.iter().map(|&x| x as i64));
            small.extend(mv);
            small.extend(cv);
            small.extend(et);
            small.extend([BS - l2(&sf), BE - l2(&ef), BS - l2(&r), BE - l2(&e1)]);
            small.extend(e2.iter().map(|x| B2 - l2(x)));
            Ok(Wit { big: vec![sf, ef, r, e1], small })
        }
        Stmt::Ds(t) => {
            if wit.len() != DS_WIT {
                return Err("length");
            }
            let r = rd_i8(wit, N);
            let e1 = rd_i16(&wit[2048..], N);
            let e2 = rd_i16(&wit[6144..], 16);
            if check && (l2(&r) > BS || l2(&e1) > BE || l2(&e2) > B2) {
                return Err("witness norm");
            }
            if check {
                let (u, vs) = encrypt(&[&t.pk], &[digits(t.amount)], &polys(&r), &polys(&e1), &[e2.clone()]);
                if u != t.u || vs[0] != t.v {
                    return Err("ciphertext");
                }
            }
            let mut small = e2.clone();
            small.extend([BS - l2(&r), BE - l2(&e1), B2 - l2(&e2)]);
            Ok(Wit { big: vec![r, e1], small })
        }
        Stmt::Dr(t) => {
            if wit.len() != DR_WIT {
                return Err("length");
            }
            let s = rd_i8(wit, N);
            let e = rd_i16(&wit[N..], N);
            if check && (l2(&s) > BS || l2(&e) > BE) {
                return Err("witness norm");
            }
            if check && keypair(&polys(&s), &polys(&e)) != t.pk {
                return Err("pk != A s + e");
            }
            // e'_i = centre(v_i - (u^T s)_i) - Delta d_i (pqz_rel.c dr_witness)
            let y = dot_int(&t.u.iter().collect::<Vec<_>>(), &polys(&s).iter().collect::<Vec<_>>());
            let d = digits(t.amount);
            let mut small: Vec<i64> = (0..16).map(|i| modq(t.v[i] - y[i]) - DELTA * d[i] as i64).collect();
            if check && small.iter().any(|e| !(-(1 << 24)..1 << 24).contains(e)) {
                return Err("not an encryption of amount");
            }
            small.extend([BS - l2(&s), BE - l2(&e)]);
            Ok(Wit { big: vec![s, e], small })
        }
    }
}

/// bits j of (x + off) as an unsigned word (an out-of-range value wraps: its decomposition then fails)
fn bit(x: i64, off: i64, j: usize) -> Fq {
    Fq(((x + off) as u64 >> j) & 1)
}

/// the m x l witness matrix
pub fn rows(lay: &Layout, w: &Wit) -> Vec<Vec<Fq>> {
    let ell = lay.ell;
    let mut u = vec![vec![Fq::ZERO; ell]; lay.m];
    for (g, b) in lay.big.iter().enumerate() {
        for v in 0..b.nr * ell {
            let x = if v < N { w.big[g][v] } else { 0 };
            let (r, c) = (v / ell, v % ell);
            u[b.vrow(r)][c] = Fq::from_i64(x);
            u[b.srow(r)][c] = Fq::from_i64(x * x);
            for j in 0..b.bits {
                u[b.brow(j, r)][c] = bit(x, b.off, j);
            }
        }
    }
    for (it, s) in lay.small.iter().enumerate() {
        for i in 0..s.count {
            let x = w.small[s.v0 + i];
            let (r, c) = lay.spos(it, i);
            u[r][c] = Fq::from_i64(x);
            let (r, c) = lay.sqpos(it, i);
            u[r][c] = Fq::from_i64(x.wrapping_mul(x));
            for j in 0..s.bits {
                let (r, c) = lay.bitpos(it, i, j);
                u[r][c] = bit(x, s.off, j);
            }
        }
    }
    u
}

// ---- linear test: combination vectors ----

pub struct Comb {
    /// per row: own vector (length l) or none
    pub own: Vec<Option<Vec<F4>>>,
    /// per row: coefficient of the shared vectors beta = (rho^c)_c and ones
    pub beta: Vec<F4>,
    pub ones: Vec<F4>,
    pub rhs: F4,
    /// largest weight exponent + 1 (Schwartz–Zippel degree of the linear test)
    pub nweights: u64,
}

struct Bld<'a> {
    lay: &'a Layout,
    c: Comb,
    rho: F4,
    rp: Vec<F4>,
    next: u64,
}

impl Bld<'_> {
    fn take(&mut self, size: usize) -> F4 {
        let w = self.rho.pow(self.next);
        self.next += size as u64;
        w
    }
    fn add(&mut self, (r, s): (usize, usize), w: F4) {
        let ell = self.lay.ell;
        self.c.own[r].get_or_insert_with(|| vec![F4::ZERO; ell])[s] += w;
    }
    /// constraints sum_j (M_ij x_j)_k (+ terms the caller adds) = b_ik for i < nout, k < kk, x_j = 64 values of big
    /// group g starting at 64 j; returns gamma_i = w0 G^i (weight of (i, k) = gamma_i rho^k)
    fn ring<'p>(&mut self, mat: &dyn Fn(usize, usize) -> &'p Poly, nout: usize, nin: usize, kk: usize, g: usize) -> Vec<F4> {
        let w0 = self.take(nout * kk);
        let gk = self.rp[kk];
        let mut gam = Vec::with_capacity(nout);
        let mut x = w0;
        for _ in 0..nout {
            gam.push(x);
            x = x * gk;
        }
        let rho = self.rho;
        for j in 0..nin {
            let mut acc = [Acc4::default(); D];
            for (i, gi) in gam.iter().enumerate() {
                let mp = mat(i, j);
                for idx in 0..D {
                    acc[idx].add(gi, Fq::from_i64(mp[idx]));
                }
            }
            let a: [F4; D] = acc.map(|a| a.get());
            let mut f = F4::ZERO;
            for k in 0..kk {
                f += self.rp[k] * a[k];
            }
            for m in 0..D {
                let pos = self.lay.bpos(g, D * j + m);
                self.add(pos, f);
                // (X^m a)_idx; f_{m+1} = rho f_m - rho^K (X^m a)_{K-1} - (X^m a)_63
                let b = |idx: usize| if idx >= m { a[idx - m] } else { -a[idx + D - m] };
                f = rho * f - self.rp[kk] * b(kk - 1) - b(D - 1);
            }
        }
        gam
    }
    /// sum_k rho^k p_k for k < kk
    fn rsum(&self, p: &Poly, kk: usize) -> F4 {
        let mut a = Acc4::default();
        for k in 0..kk {
            a.add(&self.rp[k], Fq::from_i64(p[k]));
        }
        a.get()
    }
}

impl Bld<'_> {
    /// R_q rows rhs_i = sum_j M_ij x_j + y_i for all 64 coefficients, M = A (tr = false) or A^T, x = big group gx,
    /// y = big group gy
    fn ring_rows(&mut self, tr: bool, gx: usize, gy: usize, rhs: &[Poly]) {
        let a = a_matrix();
        let gam = if tr { self.ring(&|i, j| &a[j * 32 + i], 32, 32, D, gx) } else { self.ring(&|i, j| &a[i * 32 + j], 32, 32, D, gx) };
        for i in 0..32 {
            for k in 0..D {
                let w = gam[i] * self.rp[k];
                self.add(self.lay.bpos(gy, D * i + k), w);
            }
            self.c.rhs += gam[i] * self.rsum(&rhs[i], D);
        }
    }
}

/// The verifier's combination of all linear constraints for challenge rho, and the right-hand side.
pub fn comb(lay: &Layout, st: &Stmt, rho: F4) -> Comb {
    let mut rp = vec![F4::ONE; D + 1];
    for k in 1..=D {
        rp[k] = rp[k - 1] * rho;
    }
    let m = lay.m;
    let c = Comb { own: vec![None; m], beta: vec![F4::ZERO; m], ones: vec![F4::ZERO; m], rhs: F4::ZERO, nweights: 0 };
    let mut b = Bld { lay, c, rho, rp, next: 1 };
    let delta = Fq(DELTA as u64);
    match st {
        Stmt::Reg(pk) => b.ring_rows(false, 0, 1, pk), // pk = A s + e
        Stmt::Debit(t) => {
            let (dd, dp, mm, cc, et) = debit_items(t.burn);
            // row 1: pk_f = A s_f + e_f; row 2: u = A^T r + e1
            b.ring_rows(false, 0, 1, &t.pkf);
            b.ring_rows(true, 2, 3, &t.u);
            // rows 3-5 (R_BURN: row 4 only): v_x = pk_x^T r + e2_x + Delta digit_x (k < 16)
            for (x, leg) in t.legs.iter().enumerate() {
                let gam = b.ring(&|_, j| &leg.pk[j], 1, 32, 16, 2);
                for k in 0..16 {
                    let w = gam[0] * b.rp[k];
                    b.add(lay.spos(E2, 16 * x + k), w);
                    b.add(lay.spos(if leg.dp { dp } else { dd.expect("R_TX d") }, k), w * delta);
                }
                b.c.rhs += gam[0] * b.rsum(&leg.v, 16);
            }
            // row 6: u_T^T s_f + Delta M + e_T = v_T (k < 16)
            let gam = b.ring(&|_, j| &t.ut[j], 1, 32, 16, 0);
            for k in 0..16 {
                let w = gam[0] * b.rp[k];
                b.add(lay.spos(mm, k), w * delta);
                b.add(lay.spos(et, k), w);
            }
            b.c.rhs += gam[0] * b.rsum(&t.vt, 16);
            // row 7 (integers): M_k + c_{k-1} - d'_k - d_k - 16 c_k = fee digit k (+ d_k if public); c_15 = 0
            let w0 = b.take(16);
            let dpub = if t.burn { digits(t.amount) } else { [0; 16] };
            for k in 0..16 {
                let w = w0 * b.rp[k];
                b.add(lay.spos(mm, k), w);
                if k > 0 {
                    b.add(lay.spos(cc, k - 1), w);
                }
                b.add(lay.spos(dp, k), -w);
                if let Some(dd) = dd {
                    b.add(lay.spos(dd, k), -w);
                }
                b.add(lay.spos(cc, k), -(w * Fq(16)));
                b.c.rhs += w * Fq(((t.fee >> (4 * k)) & 15) + dpub[k] as u64);
            }
            let w = b.take(1);
            b.add(lay.spos(cc, 15), w);
            // ||e2_x||^2 + slack = 64^2
            for x in 0..t.legs.len() {
                let w = b.take(1);
                for k in 0..16 {
                    b.add(lay.sqpos(E2, 16 * x + k), w);
                }
                b.add(lay.spos(lay.sig + 4 + x, 0), w);
                b.c.rhs += w * Fq(B2 as u64);
            }
        }
        Stmt::Ds(t) => {
            // u = A^T r + e1; pk^T r + e2 = v - Delta d (k < 16); ||e2||^2 + slack = 64^2
            b.ring_rows(true, 0, 1, &t.u);
            let gam = b.ring(&|_, j| &t.pk[j], 1, 32, 16, 0);
            for k in 0..16 {
                let w = gam[0] * b.rp[k];
                b.add(lay.spos(E2, k), w);
            }
            b.c.rhs += gam[0] * b.rsum(&v_minus(&t.v, t.amount), 16);
            let w = b.take(1);
            for k in 0..16 {
                b.add(lay.sqpos(E2, k), w);
            }
            b.add(lay.spos(lay.sig + 2, 0), w);
            b.c.rhs += w * Fq(B2 as u64);
        }
        Stmt::Dr(t) => {
            // pk = A s + e; u^T s + e' = v - Delta d (k < 16)
            b.ring_rows(false, 0, 1, &t.pk);
            let gam = b.ring(&|_, j| &t.u[j], 1, 32, 16, 0);
            for k in 0..16 {
                let w = gam[0] * b.rp[k];
                b.add(lay.spos(EP, k), w);
            }
            b.c.rhs += gam[0] * b.rsum(&v_minus(&t.v, t.amount), 16);
        }
    }
    // big groups: x - sum_j 2^j bit_j = -off in every slot; ||x||^2 + slack = B^2 (squares summed over all slots)
    let ell = lay.ell;
    let mut sum_beta = F4::ZERO;
    let mut pw = F4::ONE;
    for _ in 0..ell {
        sum_beta += pw;
        pw = pw * rho;
    }
    for (g, big) in lay.big.iter().enumerate() {
        for r in 0..big.nr {
            let l = b.take(ell);
            b.c.beta[big.vrow(r)] += l;
            for j in 0..big.bits {
                b.c.beta[big.brow(j, r)] -= l * Fq(1 << j);
            }
            b.c.rhs -= l * sum_beta * Fq(big.off as u64);
        }
        let w = b.take(1);
        for r in 0..big.nr {
            b.c.ones[big.srow(r)] += w;
        }
        b.add(lay.spos(lay.sig + g, 0), w);
        b.c.rhs += w * Fq(big.b2 as u64);
    }
    // small values: x - sum_j 2^j bit_j = -off
    for (it, s) in lay.small.iter().enumerate() {
        for i in 0..s.count {
            let w = b.take(1);
            b.add(lay.spos(it, i), w);
            for j in 0..s.bits {
                b.add(lay.bitpos(it, i, j), -(w * Fq(1 << j)));
            }
            b.c.rhs -= w * Fq(s.off as u64);
        }
    }
    b.c.nweights = b.next;
    b.c
}

#[cfg(test)]
mod tests {
    use super::*;

    /// f_m(a) recurrence against sum_k rho^k (X^m a mod X^64 + 1)_k, for K = 64 and K = 16
    #[test]
    fn ring_recurrence_matches_naive() {
        let lay = Layout::new(OP_REGISTER, 700);
        let rho = F4([Fq(3), Fq(5), Fq(7), Fq(11)]);
        let mut rp = vec![F4::ONE; D + 1];
        for k in 1..=D {
            rp[k] = rp[k - 1] * rho;
        }
        let p: Poly = std::array::from_fn(|i| (i as i64 * 7919) % 1000 - 500);
        for kk in [16, 64] {
            let c = Comb { own: vec![None; lay.m], beta: vec![F4::ZERO; lay.m], ones: vec![F4::ZERO; lay.m], rhs: F4::ZERO, nweights: 0 };
            let mut b = Bld { lay: &lay, c, rho, rp: rp.clone(), next: 1 };
            let gam = b.ring(&|_, _| &p, 1, 1, kk, 0);
            let own = b.c.own[0].as_ref().unwrap();
            for m in 0..D {
                // X^m p, negacyclic
                let mut s = F4::ZERO;
                for k in 0..kk {
                    let v = if k >= m { p[k - m] } else { -p[k + D - m] };
                    s += rp[k] * Fq::from_i64(v);
                }
                assert_eq!(own[m], gam[0] * s, "m = {m}, K = {kk}");
            }
        }
    }
}
