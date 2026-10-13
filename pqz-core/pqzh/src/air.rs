//! The four AIRs of PQZH design D1 (pqzh-design.md §3, prototype layout in pqzh-prototype.md §3).
//!
//! - `Poly`: one 64-row block per witness polynomial w. Row k holds the negacyclic rotation X^-k w in 64 columns, so
//!   column 0 is the coefficient w[k] (range-checked once per coefficient) and `ev` = NTT(w)[k] is a fixed linear form
//!   of the row (periodic weights). Exact l2 norms accumulate column 0 squared per group.
//! - `Mv`: rows (k, j): the NTT values of the inputs at point k arrive on the `ntt` bus one per row; one accumulator per
//!   output sums M_oj[k] x_j[k] and must reach the public target at the block end. Ring identities are pointwise here.
//! - `Range`: the table 0..8191 for the `range` bus.
//! - `Digit`: R_TX rows 3-7 per digit index i (statement-product coefficients arrive on the `coef` bus).
//!
//! Public data (A, the statement) live in periodic columns: both sides compute them, the verifier evaluates them at the
//! out-of-domain point itself, nothing of them is in the proof.

use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder, LookupBus, PermutationCheckBus};
use p3_matrix::dense::RowMajorMatrix;

use crate::ring::{D, DELTA, F, Q, fi, point_pow};

pub const RANGE: LookupBus<'static> = LookupBus::new("range");
pub const NTT: PermutationCheckBus<'static> = PermutationCheckBus::new("ntt");
pub const COEF: PermutationCheckBus<'static> = PermutationCheckBus::new("coef");

pub const RANGE_BITS: usize = 13;
pub const RANGE_N: usize = 1 << RANGE_BITS;
pub const COEF_OFF: i64 = 4096; // coefficients and quotients: c + 4096 in [0, 8192)

#[derive(Clone, Copy, Debug, Default)]
pub struct PolySpec {
    pub range: bool,
    pub group: Option<usize>,
    /// how many MV groups read this poly's NTT values
    pub ntt: u32,
    pub coef16: bool,
}

#[derive(Clone, Debug)]
pub struct PolyAir {
    pub height: usize,
    pub specs: Vec<PolySpec>,
    pub bsq: Vec<i64>,
    inc0: F,
    max_ntt: u32,
    /// period 64: the NTT weights W_0..63 and the block-end selector
    periodic: Vec<Vec<F>>,
    /// full height, statement-independent: committed once in the preprocessed tree (PR_* columns)
    pre: Vec<Vec<F>>,
}

// Poly columns
const PC_EV: usize = 64;
const PC_NRM: usize = 65;
const PC_SLO: usize = 66;
const PC_SHI: usize = 67;
const PC_W: usize = 68;
// Poly periodic columns: W_0..63 (period 64), then
const PP_BE: usize = 64;
// Poly preprocessed columns
const PR_IDX: usize = 0;
const PR_NTT: usize = 1;
const PR_RC: usize = 2;
const PR_COEF: usize = 3;
const PR_GEND: usize = 4;
const PR_INCN: usize = 5;
const PR_BSQ: usize = 6;

fn rows_of(cols: &[Vec<F>]) -> RowMajorMatrix<F> {
    let h = cols[0].len();
    RowMajorMatrix::new((0..h).flat_map(|r| cols.iter().map(move |c| c[r])).collect(), cols.len())
}

impl PolyAir {
    pub fn new(specs: Vec<PolySpec>, bsq: Vec<i64>) -> Self {
        let height = (specs.len() * D).next_power_of_two();
        let mut per: Vec<Vec<F>> = (0..D).map(|m| (0..D).map(|k| point_pow(k, m + k)).collect()).collect();
        per.push((0..D).map(|k| F::from_bool(k == D - 1)).collect());
        let spec = |r: usize| specs.get(r / D).copied();
        let col = |f: &dyn Fn(usize) -> bool| -> Vec<F> { (0..height).map(|r| F::from_bool(f(r))).collect() };
        let gend = |r: usize| -> Option<usize> {
            let g = spec(r)?.group?;
            let last = r % D == D - 1 && spec(r + 1).and_then(|s| s.group) != Some(g);
            last.then_some(g)
        };
        let inc = |r: usize| spec(r).is_some_and(|s| s.group.is_some());
        let pre = vec![
            (0..height).map(F::from_usize).collect(),
            (0..height).map(|r| F::from_u32(spec(r).map_or(0, |s| s.ntt))).collect(),
            col(&|r| spec(r).is_some_and(|s| s.range)),
            col(&|r| spec(r).is_some_and(|s| s.coef16) && r % D < 16),
            col(&|r| gend(r).is_some()),
            col(&|r| r + 1 < height && inc(r + 1)),
            (0..height).map(|r| gend(r).map_or(F::ZERO, |g| fi(bsq[g]))).collect(),
        ];
        PolyAir { height, inc0: F::from_bool(inc(0)), max_ntt: specs.iter().map(|s| s.ntt).max().unwrap_or(1).max(1), specs, bsq, periodic: per, pre }
    }

    /// Trace for the coefficient vectors `w` (one per spec) and their NTTs; range keys are counted into `rc`.
    pub fn trace(&self, w: &[[i64; D]], what: &[[F; D]], rc: &mut [u32]) -> RowMajorMatrix<F> {
        let mut v = F::zero_vec(self.height * PC_W);
        let mut nrm: i64 = 0;
        for r in 0..self.height {
            let row = &mut v[r * PC_W..(r + 1) * PC_W];
            let (b, k) = (r / D, r % D);
            let p = |c: usize| self.pre[c][r];
            if b < w.len() {
                for m in 0..D {
                    row[m] = fi(if m + k < D { w[b][m + k] } else { -w[b][m + k - D] });
                }
                row[PC_EV] = what[b][k];
            }
            let c0 = if b < w.len() { w[b][k] } else { 0 };
            if b < w.len() && self.specs[b].group.is_some() {
                nrm += c0 * c0;
            }
            row[PC_NRM] = fi(nrm);
            if p(PR_GEND) == F::ONE {
                let g = self.specs[b].group.unwrap();
                let slack = self.bsq[g] - nrm;
                // an honest prover has slack >= 0; a cheating one gets a field element no lookup accepts
                let s = fi(slack).as_canonical();
                row[PC_SLO] = F::from_u64(s % RANGE_N as u64);
                row[PC_SHI] = F::from_u64(s / RANGE_N as u64);
                nrm = 0;
            }
            count(rc, row[PC_SLO]);
            count(rc, row[PC_SHI]);
            if p(PR_RC) == F::ONE {
                count(rc, fi(c0 + COEF_OFF));
            }
        }
        RowMajorMatrix::new(v, PC_W)
    }

    fn eval<AB: InteractionBuilder<F = F>>(&self, b: &mut AB) {
        let main = b.main();
        let c: Vec<AB::Expr> = main.current_slice().iter().map(|&x| x.into()).collect();
        let n: Vec<AB::Expr> = main.next_slice().iter().map(|&x| x.into()).collect();
        let per: Vec<AB::Expr> = b.periodic_values().iter().map(|&x| x.into()).collect();
        let pr: Vec<AB::Expr> = b.preprocessed().current_slice().iter().map(|&x| x.into()).collect();
        let notbe = AB::Expr::ONE - per[PP_BE].clone();
        for m in 0..D - 1 {
            b.when_transition().assert_zero(notbe.clone() * (n[m].clone() - c[m + 1].clone()));
        }
        b.when_transition().assert_zero(notbe * (n[D - 1].clone() + c[0].clone()));
        let mut ev = AB::Expr::ZERO;
        for m in 0..D {
            ev += per[m].clone() * c[m].clone();
        }
        b.assert_eq(c[PC_EV].clone(), ev);
        b.when_first_row().assert_eq(c[PC_NRM].clone(), c[0].clone() * c[0].clone() * self.inc0);
        b.when_transition().assert_eq(
            n[PC_NRM].clone(),
            (AB::Expr::ONE - pr[PR_GEND].clone()) * c[PC_NRM].clone() + pr[PR_INCN].clone() * n[0].clone() * n[0].clone(),
        );
        b.assert_zero(
            pr[PR_GEND].clone()
                * (pr[PR_BSQ].clone() - c[PC_NRM].clone() - c[PC_SLO].clone() - c[PC_SHI].clone() * F::from_usize(RANGE_N)),
        );
        RANGE.lookup_key(b, [c[0].clone() + fi(COEF_OFF)], Count::bounded(pr[PR_RC].clone(), 1));
        // slack limbs: bound by the group-end constraint, range-checked on every row (zero elsewhere)
        RANGE.lookup_key(b, [c[PC_SLO].clone()], 1);
        RANGE.lookup_key(b, [c[PC_SHI].clone()], 1);
        NTT.send(b, [pr[PR_IDX].clone(), c[PC_EV].clone()], Count::bounded(pr[PR_NTT].clone(), self.max_ntt));
        COEF.send(b, [pr[PR_IDX].clone(), c[0].clone()], Count::bounded(pr[PR_COEF].clone(), 1));
    }
}

fn count(rc: &mut [u32], key: F) {
    let k = key.as_canonical() as usize;
    if k < rc.len() {
        rc[k] += 1;
    }
}

trait Canon {
    fn as_canonical(&self) -> u64;
}
impl Canon for F {
    fn as_canonical(&self) -> u64 {
        p3_field::PrimeField64::as_canonical_u64(self)
    }
}

/// One output of a matrix-vector block: sum_j coef[j][k] * x_j[k] = target[k] for every NTT point k.
#[derive(Clone, Debug)]
pub struct MvOut {
    pub coef: Vec<[F; D]>,
    pub target: [F; D],
    /// the coefficients of the first `stmt_lead` candidates are statement data (else fixed: NTT(A), constants)
    pub stmt_lead: usize,
}

/// Matrix-vector AIR: outputs in groups of `n_out`, groups stacked vertically (rows (group, k, j)), so the opened
/// width is 2 + n_out however many outputs there are. A group's block is its input rows (x = NTT value from the bus),
/// then one target row per output (x = target, coefficient -1 for that output), then padding.
///
/// Statement-independent columns (NTT(A), the constants, the selectors and bus keys) are preprocessed (committed once,
/// root a verifier constant); statement data (the targets, the statement-product coefficients of R_TX) are periodic
/// columns of full height, only for the output columns that have any.
#[derive(Clone, Debug)]
pub struct MvAir {
    pub height: usize,
    pub block: usize,
    n_out: usize,
    m0: Vec<F>,
    /// output columns with statement coefficients; periodic column MP_S + i belongs to output scol[i]
    scol: Vec<usize>,
    /// per row: Some(poly) = x is NTT(poly)[k] from the bus
    src: Vec<Option<usize>>,
    periodic: Vec<Vec<F>>,
    pre: Vec<Vec<F>>,
}

const MC_X: usize = 0;
const MC_ACC: usize = 1;
const MP_BE: usize = 0;
const MP_T: usize = 1;
const MP_S: usize = 2;
const MR_TR: usize = 0; // target row
const MR_MM: usize = 1; // bus multiplicity
const MR_ID: usize = 2; // bus key
const MR_P: usize = 3; // fixed coefficient of output o at the next row: MR_P + o

impl MvAir {
    /// `lists`: (candidate input polys, outputs) with `outs[o].coef[c]` the coefficient of candidate c. Each list is
    /// cut into groups of `n_out` outputs; a group reads only the candidates it uses. Returns the AIR and every
    /// (poly, 1) read, so the Poly AIR can send each NTT value as often as it is read.
    pub fn new(lists: &[(Vec<usize>, Vec<MvOut>)], n_out: usize) -> (Self, Vec<(usize, u32)>) {
        let groups: Vec<(&[MvOut], Vec<(usize, usize)>)> = lists
            .iter()
            .flat_map(|(cands, outs)| {
                outs.chunks(n_out).map(move |g| {
                    let used = (0..cands.len())
                        .filter(|&c| g.iter().any(|o| o.coef[c] != [F::ZERO; D]))
                        .map(|c| (c, cands[c]))
                        .collect();
                    (g, used)
                })
            })
            .collect();
        let block = groups.iter().map(|(g, u)| (u.len() + g.len()).next_power_of_two()).max().unwrap();
        let gh = D * block;
        let height = (groups.len() * gh).next_power_of_two();
        let mut reads = Vec::new();
        for (_, u) in &groups {
            for &(_, p) in u {
                reads.push((p, 1));
            }
        }
        // row r -> (group, k, j)
        let pos = |r: usize| (r / gh, (r % gh) / block, r % block);
        // (fixed, statement) coefficient of output o at row r
        let coef = |o: usize, r: usize| -> (F, F) {
            let (g, k, j) = pos(r);
            let Some((outs_g, used)) = groups.get(g) else { return (F::ZERO, F::ZERO) };
            let Some(out) = outs_g.get(o) else { return (F::ZERO, F::ZERO) };
            if j < used.len() {
                let (c, _) = used[j];
                let v = out.coef[c][k];
                if c < out.stmt_lead { (F::ZERO, v) } else { (v, F::ZERO) }
            } else if j == used.len() + o {
                (-F::ONE, F::ZERO)
            } else {
                (F::ZERO, F::ZERO)
            }
        };
        let target = |r: usize| -> Option<F> {
            let (g, k, j) = pos(r);
            let (outs_g, used) = groups.get(g)?;
            let o = j.checked_sub(used.len())?;
            outs_g.get(o).map(|out| out.target[k])
        };
        let src: Vec<Option<usize>> = (0..height)
            .map(|r| {
                let (g, _, j) = pos(r);
                groups.get(g).and_then(|(_, u)| u.get(j)).map(|&(_, p)| p)
            })
            .collect();
        let scol: Vec<usize> = (0..n_out)
            .filter(|&o| groups.iter().any(|(g, u)| g.get(o).is_some_and(|out| u.iter().any(|&(c, _)| c < out.stmt_lead))))
            .collect();
        let next = |o: usize, r: usize, s: bool| -> F {
            if r + 1 < height {
                let (f, st) = coef(o, r + 1);
                if s { st } else { f }
            } else {
                F::ZERO
            }
        };
        let mut per = vec![
            (0..block).map(|j| F::from_bool(j == block - 1)).collect::<Vec<_>>(),
            (0..height).map(|r| target(r).unwrap_or(F::ZERO)).collect(),
        ];
        for &o in &scol {
            per.push((0..height).map(|r| next(o, r, true)).collect());
        }
        let mut pre = vec![
            (0..height).map(|r| F::from_bool(target(r).is_some())).collect::<Vec<_>>(),
            (0..height).map(|r| F::from_bool(src[r].is_some())).collect(),
            (0..height).map(|r| src[r].map_or(F::ZERO, |p| F::from_usize(p * D + pos(r).1))).collect(),
        ];
        for o in 0..n_out {
            pre.push((0..height).map(|r| next(o, r, false)).collect());
        }
        let m0 = (0..n_out).map(|o| coef(o, 0).0 + coef(o, 0).1).collect();
        (MvAir { height, block, n_out, m0, scol, src, periodic: per, pre }, reads)
    }

    /// coefficient of output o at row r >= 1 (stored one row up)
    fn m(&self, o: usize, r: usize) -> F {
        let s = self.scol.iter().position(|&c| c == o).map_or(F::ZERO, |i| self.periodic[MP_S + i][r - 1]);
        self.pre[MR_P + o][r - 1] + s
    }

    /// `what[p]` = NTT of poly p (indexed like the Poly AIR blocks)
    pub fn trace(&self, what: &[[F; D]]) -> RowMajorMatrix<F> {
        let w = MC_ACC + self.n_out;
        let mut v = F::zero_vec(self.height * w);
        let mut acc = vec![F::ZERO; self.n_out];
        for r in 0..self.height {
            let (k, j) = ((r / self.block) % D, r % self.block);
            let row = &mut v[r * w..(r + 1) * w];
            row[MC_X] = match self.src[r] {
                Some(p) => what[p][k],
                None => self.periodic[MP_T][r],
            };
            for o in 0..self.n_out {
                let m = if r == 0 { self.m0[o] } else { self.m(o, r) };
                acc[o] = if j == 0 { F::ZERO } else { acc[o] } + m * row[MC_X];
                row[MC_ACC + o] = acc[o];
            }
        }
        RowMajorMatrix::new(v, w)
    }

    fn eval<AB: InteractionBuilder<F = F>>(&self, b: &mut AB) {
        let main = b.main();
        let c: Vec<AB::Expr> = main.current_slice().iter().map(|&x| x.into()).collect();
        let n: Vec<AB::Expr> = main.next_slice().iter().map(|&x| x.into()).collect();
        let per: Vec<AB::Expr> = b.periodic_values().iter().map(|&x| x.into()).collect();
        let pr: Vec<AB::Expr> = b.preprocessed().current_slice().iter().map(|&x| x.into()).collect();
        let be = per[MP_BE].clone();
        for o in 0..self.n_out {
            let a = MC_ACC + o;
            let mut m = pr[MR_P + o].clone();
            if let Some(i) = self.scol.iter().position(|&s| s == o) {
                m += per[MP_S + i].clone();
            }
            b.when_first_row().assert_eq(c[a].clone(), c[MC_X].clone() * self.m0[o]);
            b.when_transition().assert_eq(n[a].clone(), (AB::Expr::ONE - be.clone()) * c[a].clone() + m * n[MC_X].clone());
            b.assert_zero(be.clone() * c[a].clone());
        }
        b.assert_zero(pr[MR_TR].clone() * (c[MC_X].clone() - per[MP_T].clone()));
        NTT.receive(b, [pr[MR_ID].clone(), c[MC_X].clone()], Count::bounded(pr[MR_MM].clone(), 1));
    }
}

#[derive(Clone, Debug)]
pub struct RangeAir;

impl RangeAir {
    pub fn trace(rc: &[u32]) -> RowMajorMatrix<F> {
        let mut v = Vec::with_capacity(2 * RANGE_N);
        for (i, &m) in rc.iter().enumerate() {
            v.push(F::from_usize(i));
            v.push(F::from_u32(m));
        }
        RowMajorMatrix::new(v, 2)
    }

    fn eval<AB: InteractionBuilder<F = F>>(&self, b: &mut AB) {
        let main = b.main();
        let (c0, c1) = (main.current_slice()[0], main.current_slice()[1]);
        let n0 = main.next_slice()[0];
        b.when_first_row().assert_zero(c0);
        b.when_transition().assert_eq(n0, c0 + F::ONE);
        RANGE.table_entry(b, [c0], c1);
    }
}

/// R_TX rows 3-7, one row per digit index i < 16 (rows >= 16: zero padding, needed by the hiding PCS's budget).
#[derive(Clone, Debug)]
pub struct DigitAir {
    pub height: usize,
    ids: [usize; 4],
    periodic: Vec<Vec<F>>,
}

pub mod dc {
    pub const YT: usize = 0; // yt, yf, ya, yT: coefficients i of pk_t^T r, pk_f^T r, pk_a^T r, u_T^T s_f
    pub const E2: usize = 4; // e2_t, e2_f, e2_a
    pub const DD: usize = 7;
    pub const DP: usize = 8;
    pub const MLO: usize = 9;
    pub const MHI: usize = 10;
    pub const C: usize = 11;
    pub const ETLO: usize = 12;
    pub const ETHI: usize = 13;
    pub const TAU: usize = 14; // tau_t, tau_f, tau_a, tau_T
    pub const NRM: usize = 18; // 3 running norms
    pub const SL: usize = 21; // 3 x (lo, hi)
    pub const RI: usize = 27; // row index (coef-bus key)
    pub const MLAST: usize = 28;
    pub const MACT: usize = 29;
    pub const W: usize = 30;
}
// periodic: V_t, V_f, V_a, V_T, FEE, FEE of the next row, LAST, ACT, END (digit row 15)
const DP_V: usize = 0;
const DP_FEE: usize = 4;
const DP_FEEN: usize = 5;
const DP_LAST: usize = 6;
const DP_ACT: usize = 7;
const DP_END: usize = 8;
pub const E2_BSQ: i64 = 64 * 64;

impl DigitAir {
    /// `v[x][i]` centred statement coefficients (x = t, f, a, T), `ids[x]` = Poly row index of y_x's coefficient 0
    pub fn new(height: usize, v: [[i64; 16]; 4], fee: u64, ids: [usize; 4]) -> Self {
        let nib = |i: usize| if i < 16 { F::from_u64((fee >> (4 * i)) & 15) } else { F::ZERO };
        let mut per = Vec::new();
        for x in 0..4 {
            per.push((0..height).map(|i| if i < 16 { fi(v[x][i]) } else { F::ZERO }).collect());
        }
        per.push((0..height).map(nib).collect());
        per.push((0..height).map(|i| nib(i + 1)).collect());
        per.push((0..height).map(|i| F::from_bool(i == height - 1)).collect());
        per.push((0..height).map(|i| F::from_bool(i < 16)).collect());
        per.push((0..height).map(|i| F::from_bool(i == 15)).collect());
        DigitAir { height, ids, periodic: per }
    }

    /// `rows[i]`: the prover's integer cells for digit index i < 16 (norm, slack, index and pin cells are filled here)
    pub fn trace(&self, rows: &[[i64; dc::W]; 16], rc: &mut [u32]) -> RowMajorMatrix<F> {
        let mut v = F::zero_vec(self.height * dc::W);
        let mut nrm = [0i64; 3];
        for r in 0..self.height {
            let mut cells = if r < 16 { rows[r] } else { [0i64; dc::W] };
            if r >= 16 {
                cells[dc::ETHI] = (1 << 24) / RANGE_N as i64; // padding row: e_T = 0 satisfies row 6 with v = y = 0
            }
            for x in 0..3 {
                nrm[x] += cells[dc::E2 + x] * cells[dc::E2 + x];
                cells[dc::NRM + x] = nrm[x];
            }
            cells[dc::RI] = r as i64;
            let row = &mut v[r * dc::W..(r + 1) * dc::W];
            for c in 0..dc::W {
                row[c] = fi(cells[c]);
            }
            if r == self.height - 1 {
                for x in 0..3 {
                    let s = fi(E2_BSQ - nrm[x]).as_canonical();
                    row[dc::SL + 2 * x] = F::from_u64(s % RANGE_N as u64);
                    row[dc::SL + 2 * x + 1] = F::from_u64(s / RANGE_N as u64);
                }
                for c in dc::SL..dc::SL + 6 {
                    count(rc, row[c]);
                }
            }
            row[dc::MLAST] = self.periodic[DP_LAST][r];
            row[dc::MACT] = self.periodic[DP_ACT][r];
            for key in Self::keys(row) {
                count(rc, key);
            }
        }
        RowMajorMatrix::new(v, dc::W)
    }

    fn keys<E: Clone + PrimeCharacteristicRing + std::ops::Add<F, Output = E>>(r: &[E]) -> Vec<E> {
        let mut k = Vec::new();
        for x in 0..3 {
            k.push(r[dc::E2 + x].clone() + fi(COEF_OFF));
        }
        k.push(r[dc::DD].clone());
        k.push(r[dc::DD].clone() + F::from_usize(RANGE_N - 16));
        k.push(r[dc::DP].clone());
        k.push(r[dc::DP].clone() + F::from_usize(RANGE_N - 16));
        k.push(r[dc::MLO].clone());
        k.push(r[dc::C].clone() + F::from_u64(64));
        k.push(r[dc::C].clone() + F::from_usize(64 + RANGE_N - 2048));
        k.push(r[dc::ETLO].clone());
        k.push(r[dc::ETHI].clone());
        k.push(r[dc::ETHI].clone() + F::from_usize(RANGE_N - 4096));
        for x in 0..4 {
            k.push(r[dc::TAU + x].clone() + fi(COEF_OFF));
        }
        k
    }

    fn eval<AB: InteractionBuilder<F = F>>(&self, b: &mut AB) {
        use dc::*;
        let main = b.main();
        let c: Vec<AB::Expr> = main.current_slice().iter().map(|&x| x.into()).collect();
        let n: Vec<AB::Expr> = main.next_slice().iter().map(|&x| x.into()).collect();
        let per: Vec<AB::Expr> = b.periodic_values().iter().map(|&x| x.into()).collect();
        let (q, dl, rn) = (F::from_u64(Q), fi(DELTA), F::from_usize(RANGE_N));
        let mm = |r: &[AB::Expr]| r[MLO].clone() + r[MHI].clone() * rn;
        // rows 3-5: y_x + e2_x + Delta * digit - v_x = q tau_x
        for (x, dig) in [(0, DD), (1, DP), (2, DD)] {
            b.assert_zero(
                c[YT + x].clone() + c[E2 + x].clone() + c[dig].clone() * dl - per[DP_V + x].clone() - c[TAU + x].clone() * q,
            );
        }
        // row 6: v_T - y_T = Delta M + e_T + q tau_T, e_T + 2^24 = etlo + 8192 ethi
        b.assert_zero(
            per[DP_V + 3].clone() - c[YT + 3].clone() - mm(&c) * dl
                - (c[ETLO].clone() + c[ETHI].clone() * rn - F::from_u64(1 << 24))
                - c[TAU + 3].clone() * q,
        );
        // row 7 over Z: M_i + c_{i-1} = d'_i + d_i + f_i + 16 c_i (c_{-1} = 0, c_15 = 0)
        let sixteen = F::from_u64(16);
        b.when_first_row()
            .assert_zero(mm(&c) - c[DP].clone() - c[DD].clone() - per[DP_FEE].clone() - c[C].clone() * sixteen);
        b.when_transition().assert_zero(
            mm(&n) + c[C].clone() - n[DP].clone() - n[DD].clone() - per[DP_FEEN].clone() - n[C].clone() * sixteen,
        );
        // carry out of digit 15 is zero; padding rows (ZK mode) must not extend the chain
        b.assert_zero(per[DP_END].clone() * c[C].clone());
        b.assert_bool(c[MHI].clone());
        for x in 0..3 {
            let (nr, e) = (NRM + x, E2 + x);
            b.when_first_row().assert_eq(c[nr].clone(), c[e].clone() * c[e].clone());
            b.when_transition().assert_eq(n[nr].clone(), c[nr].clone() + n[e].clone() * n[e].clone());
            b.when_last_row().assert_zero(
                AB::Expr::from(fi(E2_BSQ)) - c[nr].clone() - c[SL + 2 * x].clone() - c[SL + 2 * x + 1].clone() * rn,
            );
        }
        b.when_first_row().assert_zero(c[RI].clone());
        b.when_transition().assert_eq(n[RI].clone(), c[RI].clone() + AB::Expr::ONE);
        b.assert_eq(c[MLAST].clone(), per[DP_LAST].clone());
        b.assert_eq(c[MACT].clone(), per[DP_ACT].clone());
        for k in Self::keys(&c) {
            RANGE.lookup_key(b, [k], 1);
        }
        for s in SL..SL + 6 {
            RANGE.lookup_key(b, [c[s].clone()], Count::bounded(c[MLAST].clone(), 1));
        }
        for x in 0..4 {
            COEF.receive(
                b,
                [c[RI].clone() + F::from_usize(self.ids[x]), c[YT + x].clone()],
                Count::bounded(c[MACT].clone(), 1),
            );
        }
    }
}

#[derive(Clone, Debug)]
pub enum PqzhAir {
    Poly(PolyAir),
    Mv(MvAir),
    Range(RangeAir),
    Digit(DigitAir),
}

impl BaseAir<F> for PqzhAir {
    fn width(&self) -> usize {
        match self {
            PqzhAir::Poly(_) => PC_W,
            PqzhAir::Mv(a) => MC_ACC + a.n_out,
            PqzhAir::Range(_) => 2,
            PqzhAir::Digit(_) => dc::W,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.pre().map(rows_of)
    }
    fn preprocessed_width(&self) -> usize {
        self.pre().map_or(0, |p| p.len())
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_periodic_columns(&self) -> usize {
        self.periodic().len()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Borrowed(self.periodic())
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            PqzhAir::Poly(_) => (0..D).chain([PC_NRM]).collect(),
            PqzhAir::Mv(a) => [MC_X].into_iter().chain(MC_ACC..MC_ACC + a.n_out).collect(),
            PqzhAir::Range(_) => vec![0],
            PqzhAir::Digit(_) => vec![dc::NRM, dc::NRM + 1, dc::NRM + 2, dc::E2, dc::E2 + 1, dc::E2 + 2, dc::MLO, dc::MHI, dc::C, dc::DD, dc::DP, dc::RI],
        }
    }
}

impl PqzhAir {
    fn pre(&self) -> Option<&[Vec<F>]> {
        match self {
            PqzhAir::Poly(a) => Some(&a.pre),
            PqzhAir::Mv(a) => Some(&a.pre),
            _ => None,
        }
    }
    fn periodic(&self) -> &[Vec<F>] {
        match self {
            PqzhAir::Poly(a) => &a.periodic,
            PqzhAir::Mv(a) => &a.periodic,
            PqzhAir::Range(_) => &[],
            PqzhAir::Digit(a) => &a.periodic,
        }
    }
}

impl<AB: InteractionBuilder<F = F>> Air<AB> for PqzhAir {
    fn eval(&self, b: &mut AB) {
        match self {
            PqzhAir::Poly(a) => a.eval(b),
            PqzhAir::Mv(a) => a.eval(b),
            PqzhAir::Range(a) => a.eval(b),
            PqzhAir::Digit(a) => a.eval(b),
        }
    }
}

#[allow(unused_imports)]
use AirBuilder as _;
