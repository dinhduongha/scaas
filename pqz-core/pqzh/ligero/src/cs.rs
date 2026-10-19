//! R_REG, R_TX, R_TX0, R_BURN, R_DS, R_DR and R_TXM (op 7) as Ligero constraint systems over F_q
//! (docs/research/pqzh-ligero.md §3, §12, §15):
//! statement parsing (`pqz-stmt`'s decoder with every D15 / R6 rule, then PQZH's id), the row layout, the witness
//! rows, the quadratic triples and the linear test's combination vectors.
//!
//! Relations (pqz_rel.c, pq-zero-knowledge.md §7.4 / §7.5 / §7.9; d = digits(amount) public where marked):
//!   R_REG  pk = A s + e
//!   R_TX   rows 1-7: pk_f = A s_f + e_f; u = A^T r + e1; v_x = pk_x^T r + e2_x + Delta digit_x (x = t, f, a; digits
//!          d, d', d); u_T^T s_f + Delta M + e_T = v_T; M_i + c_{i-1} - d'_i - d_i - 16 c_i = fee_i, c_15 = 0
//!   R_TX0  R_TX without the auditor (CTR-PQZ-24, plan D8): rows 1-4, 6, 7, legs t and f only (no pk_a, v_a, e2_a)
//!   R_BURN R_TX rows 1, 2, 4, 6, 7 with d public (one leg: pk_f, v_f, e2_f, d')
//!   R_DS   u = A^T r + e1; pk^T r + e2 = v - Delta d (k < 16)
//!   R_DR   pk = A s + e; u^T s + e' = v - Delta d (k < 16), e' + 2^24 in 25 bits
//!   R_TXM  op 7 (P6-ANON plan §3): R_TX with M receiver legs j (digits d_j) and one randomness group (r_g, e1_g, u_g)
//!          per 4 legs, g(j) = j / 4, v_f in group 0; auditor on: one copy v_{a,j} of every leg under pk_a (digits d_j,
//!          group g(j)); row 7 with sum_j d_j. R_TX is R_TXM's M = 1 (one builder; op 1 keeps its own bytes).
//! with every exact l2 bound of pqz-core (36 / 164 for CBD(1) / CBD(20) vectors, 64 for e2) and the bit ranges. R_TXM
//! bounds every e2 vector by 64 (legs, v_f, auditor copies), as R_TX's legs: the owner's rule for op 7 (2026-10-15,
//! decisions.md CTR-PQZ-03, pre-review X-1; the plan's first draft had one block bound 64 sqrt(M), which this implies).
//! Honest encryptions (CTR-PQZ-19 resamples each e2 to <= 64) meet it.
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

use pqz_stmt::{
    Form, H_AUDITOR_ON, H_LEGS, OP_BURN, OP_DISCLOSE_RECEIVER, OP_DISCLOSE_SENDER, OP_REGISTER, OP_TRANSFER,
    OP_TRANSFER_MULTI, PK_BYTES, PQZH_ID, V_BYTES, built_legs, groups, multi_len, word_u64,
};

use crate::ring::{D, DELTA, Poly, a_matrix, digits, dot_int, encrypt, keypair, modq, polys, polys_of};

use crate::fq::{Acc4, F4, Fq};
use crate::{Oom, Wipe, Wiped, ct, try_vec};

const BS: i64 = 36 * 36;
const BE: i64 = 164 * 164;
const B2: i64 = 64 * 64;
const N: usize = 2048;

/// A relation the crate proves: a pqz-stmt form (ops 1-5) or an op 7 `R_TXM` shape (M legs, auditor on / off; the
/// header words pick it, plan R4: the length alone does not).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rel {
    Form(Form),
    Multi { m: usize, aud: bool },
}

impl From<Form> for Rel {
    fn from(f: Form) -> Rel {
        Rel::Form(f)
    }
}

impl Rel {
    pub fn op(self) -> u8 {
        match self {
            Rel::Form(f) => f.op(),
            Rel::Multi { .. } => OP_TRANSFER_MULTI,
        }
    }
    pub fn stmt_len(self) -> usize {
        match self {
            Rel::Form(f) => f.stmt_len(),
            Rel::Multi { m, aud } => multi_len(m, aud),
        }
    }
    /// witness bytes (prover API, not consensus, plan §4 / R3): R_TX's layout with (r_g, e1_g) per group after e1_0
    /// and the leg digits in leg order: s_f (i8) || e_f (le16) || (r_g (i8) || e1_g (le16))_g || e2_j (le16, j < M) ||
    /// e2_f || [e2_{a,j}, j < M] || d_j (j < M, 16 digits each) || d'. M = 1 is R_TX's (R_TX0's) witness.
    pub fn wit_len(self) -> usize {
        match self {
            Rel::Form(f) => f.wit_len(),
            Rel::Multi { m, aud } => 6144 * (1 + groups(m)) + 32 * (m + 1 + aud as usize * m) + 16 * (m + 1),
        }
    }
}

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
    /// the layout of a relation (REFRESH = BURN, AUDITOR = DISCLOSE-RECEIVER)
    pub fn new(rel: impl Into<Rel>, ell: usize) -> Layout {
        assert!(ell >= 1);
        // big groups (bits, off, B^2) of a CBD(1) / CBD(20) pair; small items (count, bits, off)
        let se = [(7, 64, BS), (9, 256, BE)];
        let sl = [(1, 11, 0), (1, 15, 0)];
        let e2 = |legs: usize| (16 * legs, 8, 128);
        // a debit with `legs` e2 vectors, `nd` secret digit vectors (d_j; R_BURN 0: d public) and `pairs` big pairs
        // (s_f, e_f) and (r_g, e1_g)
        let debit = |legs: usize, nd: usize, pairs: usize| -> Vec<(usize, usize, i64)> {
            let mut v = vec![e2(legs)];
            if nd > 0 {
                v.push((16 * nd, 4, 0));
            }
            v.extend([(16, 4, 0), (16, 14, 0), (16, 11, 64), (16, 25, 1 << 24)]);
            for _ in 0..pairs {
                v.extend(sl);
            }
            v.extend(vec![(1, 13, 0); legs]);
            v
        };
        let (bigs, smalls, sig): (Vec<(usize, i64, i64)>, Vec<(usize, usize, i64)>, usize) = match rel.into() {
            Rel::Form(Form::Register) => (se.to_vec(), sl.to_vec(), 0),
            Rel::Form(Form::Transfer) => ([se, se].concat(), debit(3, 1, 2), 6),
            Rel::Form(Form::Transfer0) => ([se, se].concat(), debit(2, 1, 2), 6),
            Rel::Form(Form::Burn | Form::Refresh) => ([se, se].concat(), debit(1, 0, 2), 5),
            Rel::Form(Form::DiscloseSender) => (se.to_vec(), [vec![e2(1)], sl.to_vec(), vec![(1, 13, 0)]].concat(), 1),
            Rel::Form(Form::DiscloseReceiver | Form::DiscloseAuditor) => {
                (se.to_vec(), [vec![(16, 25, 1 << 24)], sl.to_vec()].concat(), 1)
            }
            // legs j, f, [a_j]; pairs (s_f, e_f), (r_g, e1_g) for g < G
            Rel::Multi { m, aud } => {
                let pairs = 1 + groups(m);
                (vec![se; pairs].concat(), debit(m + 1 + aud as usize * m, m, pairs), 6)
            }
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

/// one ciphertext leg of a debit statement: v = pk^T r_g + e2 + Delta digits
pub struct Leg {
    pub pk: Vec<Poly>,
    pub v: Poly,
    /// the digits it carries: None = d' (the new balance), Some(j) = d_j (leg j's amount)
    pub dig: Option<usize>,
    /// its randomness group g (r_g, e1_g, u_g)
    pub g: usize,
}

/// R_TX (legs t, f, a), R_TX0 (t, f), R_BURN (leg f only, amount public) and R_TXM (legs 0..M, f, [a_0..a_M])
pub struct Debit {
    pub burn: bool,
    pub pkf: Vec<Poly>,
    pub legs: Vec<Leg>,
    pub ut: Vec<Poly>,
    pub vt: Poly,
    /// u_g per randomness group
    pub us: Vec<Vec<Poly>>,
    /// secret digit vectors d_j (R_TX 1, R_TXM M, R_BURN 0)
    pub nd: usize,
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

/// Every relation the crate proves, in pqz_bench.c's order (R_REG, R_TX, R_BURN, R_DS, R_DR, R_TX0).
pub const RELS: [Form; 6] =
    [Form::Register, Form::Transfer, Form::Burn, Form::DiscloseSender, Form::DiscloseReceiver, Form::Transfer0];

/// The op 7 `R_TXM` shapes PQZH builds (P6-ANON D3 / D20: M in {1, 2, 4}, auditor on and off; feature `oversize`,
/// bench only, adds M = 8, 16), auditor on first.
pub fn multi_rels() -> Vec<Rel> {
    let legs = built_legs(&PQZH_ID);
    [true, false].iter().flat_map(|&aud| legs.iter().map(move |&m| Rel::Multi { m, aud })).collect()
}

/// The relation a statement of `op` with `len` bytes is proved in, from the op and the length alone (op 1: R_TX0 by
/// length, R6; REFRESH and AUDITOR, other opTags of op 2 / op 5, share BURN's and DISCLOSE-RECEIVER's). The verifier
/// takes its length bound from it before anything is parsed; `parse` then checks the statement.
pub fn form_of(op: u8, len: usize) -> Option<Form> {
    Some(match op {
        OP_TRANSFER if len == Form::Transfer0.stmt_len() => Form::Transfer0,
        OP_TRANSFER => Form::Transfer,
        OP_BURN => Form::Burn,
        OP_REGISTER => Form::Register,
        OP_DISCLOSE_SENDER => Form::DiscloseSender,
        OP_DISCLOSE_RECEIVER => Form::DiscloseReceiver,
        _ => return None,
    })
}

/// The relation of a statement of `op`: `form_of` for ops 1-5; op 7 from its auditorOn and `M` words (plan R4; read
/// without validation, as the gas schedule does, D19), `M` in PQZH's built set, so no layout is sized from an
/// unchecked word. The verifier takes its length bound from it before anything is parsed; `parse` then checks the
/// statement, its length = multi_len(M, auditorOn) included.
pub fn rel_of(op: u8, stmt: &[u8]) -> Option<Rel> {
    if op != OP_TRANSFER_MULTI {
        return form_of(op, stmt.len()).map(Rel::Form);
    }
    let word = |i: usize| word_u64(stmt.get(32 * i..32 * i + 32)?.try_into().ok()?);
    let aud = match word(H_AUDITOR_ON)? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let m = word(H_LEGS)?;
    let m = built_legs(&PQZH_ID).iter().copied().find(|&b| b as u64 == m)?;
    Some(Rel::Multi { m, aud })
}

/// `pqz_stmt::parse` (every D15 / R6 rule: length, the op's opTag, a known id, fee / amount < 2^64, the salt form,
/// auditorOn by length, the zero words, coefficients < q), op 7: `pqz_stmt::parse_multi` (every D15 / R4 rule: opTag,
/// id, auditorOn and M words, length, fee / amount < 2^64, salt form, amount 0, coefficients), then PQZH's own check
/// (D3): the id is PQZH's, not PQZL's. Prover and verifier call it first.
pub fn parse(op: u8, stmt: &[u8]) -> Option<Stmt> {
    if op == OP_TRANSFER_MULTI {
        return parse_multi(stmt);
    }
    let s = pqz_stmt::parse(op, stmt).ok()?;
    if *s.proof_system_id()? != PQZH_ID {
        return None;
    }
    let vec = |b: &[u8]| polys_of(b, D);
    let v = |b: &[u8]| polys_of(b, 16)[0];
    Some(match s {
        pqz_stmt::Stmt::Register(r) => Stmt::Reg(vec(r.pk)),
        pqz_stmt::Stmt::Debit(d) => {
            let burn = matches!(d.form, Form::Burn | Form::Refresh);
            let pkf = vec(d.pk_f);
            // legs in witness order: t (d), f (d'), a (d; R_TX only); one group
            let mut legs = vec![];
            if let (Some(pk), Some(vt)) = (d.pk_t, d.v_t) {
                legs.push(Leg { pk: vec(pk), v: v(vt), dig: Some(0), g: 0 });
            }
            legs.push(Leg { pk: pkf.clone(), v: v(d.v_f), dig: None, g: 0 });
            if let (Some(pk), Some(va)) = (d.pk_a, d.v_a) {
                legs.push(Leg { pk: vec(pk), v: v(va), dig: Some(0), g: 0 });
            }
            let (ut, vt) = d.t.split_at(PK_BYTES);
            let amount = if burn { d.amount() } else { 0 };
            let nd = !burn as usize;
            Stmt::Debit(Debit { burn, pkf, legs, ut: vec(ut), vt: v(vt), us: vec![vec(d.u)], nd, fee: d.fee(), amount })
        }
        pqz_stmt::Stmt::Disclose(d) => {
            let x = Disc { pk: vec(d.pk), u: vec(d.u), v: v(d.v), amount: d.amount() };
            if d.form == Form::DiscloseSender { Stmt::Ds(x) } else { Stmt::Dr(x) }
        }
        // op 7 returned above (parse_multi); op 6 has no relation
        pqz_stmt::Stmt::Multi(_) | pqz_stmt::Stmt::SelfTest => return None,
    })
}

/// op 7: legs 0..M (d_j, group j / 4), f (d', group 0), auditor copies a_j (d_j, group j / 4), in witness order
fn parse_multi(stmt: &[u8]) -> Option<Stmt> {
    let s = pqz_stmt::parse_multi(stmt).ok()?;
    if s.header[1] != PQZH_ID {
        return None;
    }
    let vec = |b: &[u8]| polys_of(b, D);
    let v = |b: &[u8]| polys_of(b, 16)[0];
    let g = |j: usize| j / pqz_stmt::LEGS_PER_GROUP;
    let pkf = vec(s.pk_f);
    let mut legs: Vec<Leg> = (0..s.m).map(|j| Leg { pk: vec(s.pk(j)), v: v(s.v(j)), dig: Some(j), g: g(j) }).collect();
    legs.push(Leg { pk: pkf.clone(), v: v(s.v_f), dig: None, g: 0 });
    if let Some(pk_a) = s.pk_a {
        let pka = vec(pk_a);
        for j in 0..s.m {
            legs.push(Leg { pk: pka.clone(), v: v(s.v_a(j)?), dig: Some(j), g: g(j) });
        }
    }
    let (ut, vt) = s.t.split_at(PK_BYTES);
    let us = (0..s.groups()).map(|i| vec(s.u(i))).collect();
    debug_assert_eq!(s.vs.len(), s.m * V_BYTES);
    Some(Stmt::Debit(Debit { burn: false, pkf, legs, ut: vec(ut), vt: v(vt), us, nd: s.m, fee: s.fee(), amount: 0 }))
}

/// v - Delta digits(amount) (the public side of R_DS / R_DR's evaluation rows)
fn v_minus(v: &Poly, amount: u64) -> Poly {
    let d = digits(amount);
    std::array::from_fn(|k| if k < 16 { v[k] - DELTA * d[k] as i64 } else { v[k] })
}

// ---- witness ----

/// The witness values. Wiped when dropped (review P-C).
pub struct Wit {
    pub big: Vec<Vec<i64>>,
    pub small: Vec<i64>,
}

impl Drop for Wit {
    fn drop(&mut self) {
        self.big.wipe();
        self.small.wipe();
    }
}

fn rd_i8(b: &[u8], n: usize) -> Wiped<Vec<i64>> {
    Wiped(b[..n].iter().map(|&x| x as i8 as i64).collect())
}
fn rd_i16(b: &[u8], n: usize) -> Wiped<Vec<i64>> {
    Wiped((0..n).map(|i| i16::from_le_bytes([b[2 * i], b[2 * i + 1]]) as i64).collect())
}
fn l2(v: &[i64]) -> i64 {
    v.iter().map(|x| x * x).sum()
}

// Review P-B: the honest prover's checks run on secret values, so each is a 0 / 1 (or nonzero) word without a branch,
// OR-ed into one verdict per error, declassified there (`ct::verdict`: the error is the API's public output).

/// 1 if x > b (|x|, |b| < 2^62)
fn gt(x: i64, b: i64) -> u64 {
    ((b - x) >> 63) as u64 & 1
}
/// nonzero if the polynomials differ
fn diff1(x: &Poly, y: &Poly) -> i64 {
    x.iter().zip(y).fold(0, |d, (u, v)| d | (u ^ v))
}
/// nonzero if the polynomial vectors differ (equal lengths: K polynomials, public)
fn diff(a: &[Poly], b: &[Poly]) -> i64 {
    a.iter().zip(b).fold(0, |d, (x, y)| d | diff1(x, y))
}
/// Wiped polynomials of a secret vector
fn wpolys(v: &[i64]) -> Wiped<Vec<Poly>> {
    Wiped(polys(v))
}

/// x / d (d < 2^62) by a fixed 64-step restoring division: no branch, no division instruction (review P-B; PQZL's
/// `ct_sdiv` idea: wasm32 compiles `/` by a constant to `i64.div_s`, whose latency depends on the operands)
fn ct_udiv(x: u64, d: u64) -> u64 {
    let (mut q, mut r) = (0u64, 0u64);
    for i in (0..64).rev() {
        r = (r << 1) | (x >> i & 1); // < 2d
        let t = r.wrapping_sub(d);
        let ge = (t >> 63) ^ 1; // r >= d
        r = r.wrapping_sub(d & ge.wrapping_neg());
        q |= ge << i;
    }
    q
}

/// round(w / Delta), halves away from zero (pqz_rel.c debit_witness), by sign and magnitude (|w| < 2^62)
fn round_delta(w: i64) -> i64 {
    let s = w >> 63;
    let a = ((w ^ s) - s) as u64;
    (ct_udiv(a + (DELTA / 2) as u64, DELTA as u64) as i64 ^ s) - s
}

/// Witness values from pqz-core's witness bytes (`form`'s length, pqz.h). `check` = the honest prover's checks (as
/// pqz_rel.c's witness builders plus the key / ciphertext equations); without them an invalid witness is laid out
/// anyway (bits wrap), for the negative tests. Every secret buffer is wiped on every exit (review P-C).
pub fn witness(rel: impl Into<Rel>, st: &Stmt, wit: &[u8], check: bool) -> Result<Wit, &'static str> {
    if wit.len() != rel.into().wit_len() {
        return Err("length");
    }
    let take = std::mem::take::<Vec<i64>>;
    match st {
        Stmt::Reg(pk) => {
            let (mut s, mut e) = (rd_i8(wit, N), rd_i16(&wit[N..], N));
            if check && ct::verdict(gt(l2(&s), BS) | gt(l2(&e), BE) != 0) {
                return Err("witness norm");
            }
            if check && ct::verdict(diff(&Wiped(keypair(&wpolys(&s), &wpolys(&e))), pk) != 0) {
                return Err("pk != A s + e");
            }
            let small = vec![BS - l2(&s), BE - l2(&e)];
            Ok(Wit { big: vec![take(&mut s), take(&mut e)], small })
        }
        Stmt::Debit(t) => {
            let (nl, ng, nd) = (t.legs.len(), t.us.len(), t.nd);
            let mut sf = rd_i8(wit, N);
            let mut ef = rd_i16(&wit[2048..], N);
            // (r_g, e1_g) per group
            let mut rs: Wiped<Vec<Vec<i64>>> =
                Wiped((0..ng).map(|g| take(&mut rd_i8(&wit[6144 * (1 + g)..], N))).collect());
            let mut e1s: Wiped<Vec<Vec<i64>>> =
                Wiped((0..ng).map(|g| take(&mut rd_i16(&wit[6144 * (1 + g) + 2048..], N))).collect());
            let p0 = 6144 * (1 + ng);
            let e2: Wiped<Vec<Vec<i64>>> = Wiped((0..nl).map(|x| take(&mut rd_i16(&wit[p0 + 32 * x..], 16))).collect());
            let p = p0 + 32 * nl;
            // d_j (R_BURN: digits(amount), public) and d'
            let ds: Wiped<Vec<[u8; 16]>> = Wiped(if t.burn {
                vec![digits(t.amount)]
            } else {
                (0..nd).map(|j| wit[p + 16 * j..p + 16 * j + 16].try_into().unwrap()).collect()
            });
            let q = p + 16 * nd;
            let dp: Wiped<[u8; 16]> = Wiped(wit[q..q + 16].try_into().unwrap());
            let norm = gt(l2(&sf), BS)
                | gt(l2(&ef), BE)
                | rs.iter().fold(0, |a, r| a | gt(l2(r), BS))
                | e1s.iter().fold(0, |a, e| a | gt(l2(e), BE))
                | e2.iter().fold(0, |a, x| a | gt(l2(x), B2));
            if check && ct::verdict(norm != 0) {
                return Err("witness norm");
            }
            if check && ct::verdict(diff(&Wiped(keypair(&wpolys(&sf), &wpolys(&ef))), &t.pkf) != 0) {
                return Err("pk_f != A s_f + e_f");
            }
            if check {
                // every group's legs encrypted under its (r_g, e1_g)
                for g in 0..ng {
                    let x: Vec<usize> = (0..nl).filter(|&x| t.legs[x].g == g).collect();
                    let pks: Vec<&Vec<Poly>> = x.iter().map(|&x| &t.legs[x].pk).collect();
                    let msgs: Wiped<Vec<[u8; 16]>> =
                        Wiped(x.iter().map(|&x| t.legs[x].dig.map_or(*dp, |j| ds[j])).collect());
                    let e2g: Wiped<Vec<Vec<i64>>> = Wiped(x.iter().map(|&x| e2[x].clone()).collect());
                    let (u, vs) = encrypt(&pks, &msgs, &wpolys(&rs[g]), &wpolys(&e1s[g]), &e2g);
                    let (u, vs) = (Wiped(u), Wiped(vs));
                    let d = vs.iter().zip(&x).fold(diff(&u, &t.us[g]), |d, (v, &x)| d | diff1(v, &t.legs[x].v));
                    if ct::verdict(d != 0) {
                        return Err("ciphertext");
                    }
                }
            }
            // M, e_T by rounding, carries (pqz_rel.c debit_witness), with the leg sum sum_j d_j
            let y = Wiped(dot_int(&t.ut.iter().collect::<Vec<_>>(), &wpolys(&sf).iter().collect::<Vec<_>>()));
            let (mut mv, mut et, mut cv) = (Wiped(vec![0i64; 16]), Wiped(vec![0i64; 16]), Wiped(vec![0i64; 16]));
            let (mut cprev, mut bad_d, mut bad_c) = (0i64, 0u64, 0u64);
            for i in 0..16 {
                let wv = modq(t.vt[i] - y[i]);
                let m = round_delta(wv);
                let e = wv - DELTA * m;
                let dsum: i64 = ds.iter().map(|d| d[i] as i64).sum();
                let s = m + cprev - dp[i] as i64 - dsum - ((t.fee >> (4 * i)) & 15) as i64;
                // s % 16 != 0, a digit > 15, M outside [0, 2^14), e_T outside [-2^24, 2^24)
                bad_d |= (s & 15) as u64
                    | ds.iter().fold(0, |a, d| a | d[i] >> 4) as u64
                    | (dp[i] >> 4) as u64
                    | (m as u64) >> 14
                    | ((e + (1 << 24)) as u64) >> 25;
                let c = s >> 4; // = s.div_euclid(16)
                bad_c |= ((c + 64) as u64) >> 11; // c outside [-64, 1984)
                (mv[i], et[i], cv[i]) = (m, e, c);
                cprev = c;
            }
            if check && ct::verdict(bad_d != 0) {
                return Err("digits");
            }
            if check && ct::verdict(bad_c != 0) {
                return Err("carry");
            }
            if check && ct::verdict(cprev != 0) {
                return Err("carry out");
            }
            let mut small = Vec::with_capacity(16 * nl + 16 * nd + 64 + 2 * (1 + ng) + nl); // no reallocation
            small.extend(e2.iter().flatten());
            if !t.burn {
                small.extend(ds.iter().flatten().map(|&x| x as i64));
            }
            small.extend(dp.iter().map(|&x| x as i64));
            small.extend_from_slice(&mv);
            small.extend_from_slice(&cv);
            small.extend_from_slice(&et);
            small.extend([BS - l2(&sf), BE - l2(&ef)]);
            for g in 0..ng {
                small.extend([BS - l2(&rs[g]), BE - l2(&e1s[g])]);
            }
            small.extend(e2.iter().map(|x| B2 - l2(x)));
            let mut w = Wit { big: Vec::with_capacity(2 * (1 + ng)), small };
            w.big.extend([take(&mut sf), take(&mut ef)]);
            for (r, e1) in rs.iter_mut().zip(e1s.iter_mut()) {
                w.big.extend([take(r), take(e1)]);
            }
            Ok(w)
        }
        Stmt::Ds(t) => {
            let (mut r, mut e1, e2) = (rd_i8(wit, N), rd_i16(&wit[2048..], N), rd_i16(&wit[6144..], 16));
            if check && ct::verdict(gt(l2(&r), BS) | gt(l2(&e1), BE) | gt(l2(&e2), B2) != 0) {
                return Err("witness norm");
            }
            if check {
                let e2v = Wiped(vec![e2.to_vec()]);
                let (u, vs) = encrypt(&[&t.pk], &[digits(t.amount)], &wpolys(&r), &wpolys(&e1), &e2v);
                let (u, vs) = (Wiped(u), Wiped(vs));
                if ct::verdict(diff(&u, &t.u) | diff1(&vs[0], &t.v) != 0) {
                    return Err("ciphertext");
                }
            }
            let mut small = Vec::with_capacity(16 + 3);
            small.extend_from_slice(&e2);
            small.extend([BS - l2(&r), BE - l2(&e1), B2 - l2(&e2)]);
            Ok(Wit { big: vec![take(&mut r), take(&mut e1)], small })
        }
        Stmt::Dr(t) => {
            let (mut s, mut e) = (rd_i8(wit, N), rd_i16(&wit[N..], N));
            if check && ct::verdict(gt(l2(&s), BS) | gt(l2(&e), BE) != 0) {
                return Err("witness norm");
            }
            if check && ct::verdict(diff(&Wiped(keypair(&wpolys(&s), &wpolys(&e))), &t.pk) != 0) {
                return Err("pk != A s + e");
            }
            // e'_i = centre(v_i - (u^T s)_i) - Delta d_i (pqz_rel.c dr_witness)
            let y = Wiped(dot_int(&t.u.iter().collect::<Vec<_>>(), &wpolys(&s).iter().collect::<Vec<_>>()));
            let d = digits(t.amount);
            let mut small = Wiped(Vec::with_capacity(16 + 2));
            small.extend((0..16).map(|i| modq(t.v[i] - y[i]) - DELTA * d[i] as i64));
            // e' outside [-2^24, 2^24)
            let bad = small.iter().fold(0u64, |a, &e| a | ((e + (1 << 24)) as u64) >> 25);
            if check && ct::verdict(bad != 0) {
                return Err("not an encryption of amount");
            }
            small.extend([BS - l2(&s), BE - l2(&e)]);
            Ok(Wit { big: vec![take(&mut s), take(&mut e)], small: take(&mut small) })
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
    /// an own vector could not be reserved (review P-D)
    oom: bool,
}

impl Bld<'_> {
    fn take(&mut self, size: usize) -> F4 {
        let w = self.rho.pow(self.next);
        self.next += size as u64;
        w
    }
    fn add(&mut self, (r, s): (usize, usize), w: F4) {
        let ell = self.lay.ell;
        if self.c.own[r].is_none() {
            match try_vec(ell) {
                Ok(mut v) => {
                    v.resize(ell, F4::ZERO);
                    self.c.own[r] = Some(v);
                }
                Err(Oom) => {
                    self.oom = true;
                    return;
                }
            }
        }
        if let Some(v) = &mut self.c.own[r] {
            v[s] += w;
        }
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

/// The verifier's combination of all linear constraints for challenge rho, and the right-hand side; `Oom` if an own
/// vector (l F_q^4 values per row) could not be reserved (review P-D).
pub fn comb(lay: &Layout, st: &Stmt, rho: F4) -> Result<Comb, Oom> {
    let mut rp = vec![F4::ONE; D + 1];
    for k in 1..=D {
        rp[k] = rp[k - 1] * rho;
    }
    let m = lay.m;
    let c = Comb { own: vec![None; m], beta: vec![F4::ZERO; m], ones: vec![F4::ZERO; m], rhs: F4::ZERO, nweights: 0 };
    let mut b = Bld { lay, c, rho, rp, next: 1, oom: false };
    let delta = Fq(DELTA as u64);
    match st {
        Stmt::Reg(pk) => b.ring_rows(false, 0, 1, pk), // pk = A s + e
        Stmt::Debit(t) => {
            let (dd, dp, mm, cc, et) = debit_items(t.burn);
            // row 1: pk_f = A s_f + e_f; row 2: u_g = A^T r_g + e1_g (big groups 2 + 2g, 3 + 2g)
            b.ring_rows(false, 0, 1, &t.pkf);
            for (g, u) in t.us.iter().enumerate() {
                b.ring_rows(true, 2 + 2 * g, 3 + 2 * g, u);
            }
            // rows 3-5 (R_BURN: row 4 only): v_x = pk_x^T r_g(x) + e2_x + Delta digit_x (k < 16)
            for (x, leg) in t.legs.iter().enumerate() {
                let gam = b.ring(&|_, j| &leg.pk[j], 1, 32, 16, 2 + 2 * leg.g);
                for k in 0..16 {
                    let w = gam[0] * b.rp[k];
                    b.add(lay.spos(E2, 16 * x + k), w);
                    let at = match leg.dig {
                        None => lay.spos(dp, k),
                        Some(j) => lay.spos(dd.expect("R_TX d"), 16 * j + k),
                    };
                    b.add(at, w * delta);
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
            // row 7 (integers): M_k + c_{k-1} - d'_k - sum_j d_{j,k} - 16 c_k = fee digit k (+ d_k if public); c_15 = 0
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
                    for j in 0..t.nd {
                        b.add(lay.spos(dd, 16 * j + k), -w);
                    }
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
                b.add(lay.spos(lay.sig + lay.big.len() + x, 0), w);
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
    if b.oom {
        return Err(Oom);
    }
    Ok(b.c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D3: PQZH's id is the keccak256 of its string, and it is pqz-stmt's
    #[test]
    fn pqzh_id_d3() {
        let h = crate::merkle::keccak(&[b"scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1"]);
        assert_eq!(h, PQZH_ID);
    }

    /// pqz-stmt's opTags are the keccak256 of their names
    #[test]
    fn op_tags_hash() {
        for (f, n) in [
            (Form::Transfer, "TRANSFER"),
            (Form::Transfer0, "TRANSFER"),
            (Form::Burn, "BURN"),
            (Form::Refresh, "REFRESH"),
            (Form::Register, "REGISTER"),
            (Form::DiscloseSender, "DISCLOSE-SENDER"),
            (Form::DiscloseReceiver, "DISCLOSE-RECEIVER"),
            (Form::DiscloseAuditor, "DISCLOSE-AUDITOR"),
        ] {
            assert_eq!(f.op_tag(), crate::merkle::keccak(&[b"SCAAS-PQZ-OP-", n.as_bytes(), b"-V1"]), "{n}");
        }
    }

    /// review P-B: the branch-free rounding, division and centring give the reference values (`/`, the sign branch,
    /// `rem_euclid` and the centring branch)
    #[test]
    fn branch_free_rounding_matches_reference() {
        let reference = |w: i64| (if w >= 0 { w + DELTA / 2 } else { w - DELTA / 2 }) / DELTA;
        let modq_ref = |v: i64| {
            let r = v.rem_euclid(crate::fq::Q as i64);
            if r > (crate::fq::Q as i64 - 1) / 2 { r - crate::fq::Q as i64 } else { r }
        };
        let half = (crate::fq::Q as i64 - 1) / 2;
        let mut xs = vec![0, 1, -1, DELTA / 2, -(DELTA / 2), DELTA / 2 + 1, -(DELTA / 2) - 1, DELTA, -DELTA];
        xs.extend([half, -half]);
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        xs.extend((0..100_000).map(|i| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            if i % 2 == 0 { (s % crate::fq::Q) as i64 - half } else { (s as i64) >> (i % 64) }
        }));
        for &w in &xs {
            assert_eq!(modq(w), modq_ref(w), "{w}");
            if w.abs() <= half {
                assert_eq!(round_delta(w), reference(w), "{w}");
            }
        }
        let divs = [(0u64, 1u64), (12_345_678_901, DELTA as u64), (u64::MAX >> 2, 3), (u64::MAX >> 2, (1 << 61) + 5)];
        for (x, d) in divs {
            assert_eq!(ct_udiv(x, d), x / d, "{x} / {d}");
        }
    }

    /// f_m(a) recurrence against sum_k rho^k (X^m a mod X^64 + 1)_k, for K = 64 and K = 16
    #[test]
    fn ring_recurrence_matches_naive() {
        let lay = Layout::new(Form::Register, 700);
        let rho = F4([Fq(3), Fq(5), Fq(7), Fq(11)]);
        let mut rp = vec![F4::ONE; D + 1];
        for k in 1..=D {
            rp[k] = rp[k - 1] * rho;
        }
        let p: Poly = std::array::from_fn(|i| (i as i64 * 7919) % 1000 - 500);
        for kk in [16, 64] {
            let c = Comb { own: vec![None; lay.m], beta: vec![F4::ZERO; lay.m], ones: vec![F4::ZERO; lay.m], rhs: F4::ZERO, nweights: 0 };
            let mut b = Bld { lay: &lay, c, rho, rp: rp.clone(), next: 1, oom: false };
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
