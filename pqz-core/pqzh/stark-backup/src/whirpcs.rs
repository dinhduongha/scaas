//! Zero-knowledge WHIR for the univariate batch STARK (docs/research/pqzh-zk-whir.md §5): a `UnivariateStarkPcs`
//! whose commitments and openings are p3-whir's `HidingWhirPcs` (HVZK-WHIR, ePrint 2026/391). Plonky3's hiding batch
//! STARK (`ZK = true`, ePrint 2024/1037 trace / quotient masking) runs unchanged on top.
//!
//! - Commit: every column is stored in coefficient form; the columns of one commitment round are stacked (height
//!   descending, column-major) into one multilinear polynomial over F of 2^N coefficients, committed by
//!   `HidingWhirPcs` over a salted Keccak-256 Merkle tree.
//!   - trace / permutation (n rows on a 2n domain): `t + Z_H·r`, `r` uniform of degree < n (2024/1037 §3);
//!   - quotient chunks: `q_i + v_{H_i}·t_i`, the masks cancelling in the verifier's recombination (2024/1037 §4.2);
//!   - preprocessed: `t`, zero-padded, committed with fixed randomness (the root is a verifier constant);
//!   - the STARK's randomisation polynomial `R` is not needed by WHIR: a fixed all-zero commitment opened to zeros.
//! - Open: all opened values `p(z)` are absorbed, one β is drawn; per round, every aligned block of `2^k` columns of
//!   one matrix at one point gives one claim `Σ_c β^c col_c(z) = S · f(prefix, p)` of the stacked polynomial, with
//!   `p_j = a_j / (1 + a_j)`, `a = (β^{2^{k-1}}, …, β, z^{2^{m-1}}, …, z)`, `S = Π (1 + a_j)` (exact: `eq(p, x) =
//!   Π a_j^{x_j} / (1 + a_j)`). The verifier recomputes every claim from the opened values and checks it against the
//!   proof's `evals` before `HidingWhirPcs::verify`.

use std::sync::Mutex;

use p3_challenger::FieldChallenger;
use p3_commit::{
    CommitmentOpening, MultilinearPcs, OpenedValues, OpeningRequest, Pcs, PolynomialSpace, UnivariateStarkPcs,
};
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_symmetric::MerkleCap;
use p3_whir::{
    FoldingFactor, HidingWhirPcs, HidingWhirProverData, ProtocolParameters, SecurityAssumption, ZkParameters,
    ZkWhirConfig, ZkWhirProof,
};
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

use crate::config::{BeChallenger, BeKeccak, Compress, HidingValMmcs, WhirParams};
use crate::ring::F;

pub type WDft = Radix2DFTSmallBatch<F>;
pub type Cap = MerkleCap<F, [u8; 32]>;
pub type Hw<EF> = HidingWhirPcs<EF, F, WDft, HidingValMmcs, BeChallenger, StdRng>;
type Domain = TwoAdicMultiplicativeCoset<F>;

/// fixed randomness of the preprocessed commitment (public data; prover and verifier reproduce its root)
const PRE_SEED: [u8; 32] = [0x5e; 32];
/// largest committed stacked polynomial (2^MAX_VARS coefficients); bounds a malicious proof's shapes
const MAX_VARS: usize = 26;

pub struct WhirUniPcs<EF> {
    pub w: WhirParams,
    dft: WDft,
    rng: Mutex<StdRng>,
    _ef: core::marker::PhantomData<EF>,
}

/// a clone forks the mask stream (as p3-fri's HidingFriPcs)
impl<EF> Clone for WhirUniPcs<EF> {
    fn clone(&self) -> Self {
        WhirUniPcs { w: self.w, dft: self.dft.clone(), rng: Mutex::new(self.fresh_rng()), _ef: Default::default() }
    }
}

fn hmmcs(rng: &mut StdRng) -> HidingValMmcs {
    HidingValMmcs::new(BeKeccak, Compress::new(Keccak256Hash {}), 0, StdRng::from_rng(rng))
}

impl<EF> WhirUniPcs<EF> {
    fn fresh_rng(&self) -> StdRng {
        StdRng::from_rng(&mut *self.rng.lock().unwrap())
    }

    /// `rnd` seeds every mask and salt of the proofs made with this PCS (prover randomness; a verifier passes anything)
    pub fn new(w: WhirParams, rnd: [u8; 32]) -> Self {
        WhirUniPcs { w, dft: WDft::default(), rng: Mutex::new(StdRng::from_seed(rnd)), _ef: Default::default() }
    }
}

/// Prover data of one commitment round.
pub struct WhirData<EF: ExtensionField<F>> {
    /// (coefficient height, width) per matrix, in commit order
    shapes: Vec<(usize, usize)>,
    /// element offset of each matrix in the stacked polynomial
    offs: Vec<usize>,
    n_vars: usize,
    /// stacked coefficients (column-major per matrix); empty for the zero round
    msg: Vec<F>,
    /// None: the randomisation round (all-zero commitment, nothing committed)
    commit: Option<Cap>,
    /// HVZK-WHIR prover data, single use (taken at open); None for preprocessed data (recommitted at open)
    inner: Mutex<Option<HidingWhirProverData<F, EF, HidingValMmcs>>>,
}

pub fn zero_cap() -> Cap {
    Cap::from(vec![[0u8; 32]])
}

/// Stacking: matrices by coefficient height descending (stable), each column-major; returns offsets (commit order)
/// and the number of variables (at least `min_vars`).
fn layout(shapes: &[(usize, usize)]) -> (Vec<usize>, usize) {
    let mut idx: Vec<usize> = (0..shapes.len()).collect();
    idx.sort_by_key(|&i| std::cmp::Reverse(shapes[i].0));
    let mut offs = vec![0; shapes.len()];
    let mut off = 0usize;
    for i in idx {
        offs[i] = off;
        off += shapes[i].0 * shapes[i].1;
    }
    (offs, off.max(1).next_power_of_two().trailing_zeros() as usize)
}

/// value of a coefficient column at z (Horner)
fn horner<EF: ExtensionField<F>>(c: &[F], z: EF) -> EF {
    c.iter().rev().fold(EF::ZERO, |acc, &x| acc * z + x)
}

/// The claims of one matrix (offset `off`, height `h` = 2^m, `w` columns) at point z: per aligned dyadic block of
/// `2^k` columns, (point of the stacked polynomial, scale S, block's first column). None if some 1 + a_j = 0.
fn claims<EF: ExtensionField<F>>(n: usize, off: usize, h: usize, w: usize, z: EF, beta: EF) -> Option<Vec<(Point<EF>, EF, usize, usize)>> {
    let m = h.trailing_zeros() as usize;
    let u0 = off / h;
    let mut out = Vec::new();
    let mut c = 0;
    while c < w {
        // largest aligned block at unit u0 + c within the matrix
        let u = u0 + c;
        let kmax = (w - c).ilog2() as usize;
        let k = if u == 0 { kmax } else { (u.trailing_zeros() as usize).min(kmax) };
        let mut a: Vec<EF> = Vec::with_capacity(k + m);
        let mut b = beta;
        let mut pb = Vec::with_capacity(k);
        for _ in 0..k {
            pb.push(b);
            b = b.square();
        }
        a.extend(pb.into_iter().rev());
        let mut zz = z;
        let mut pz = Vec::with_capacity(m);
        for _ in 0..m {
            pz.push(zz);
            zz = zz.square();
        }
        a.extend(pz.into_iter().rev());
        let pre = n - k - m;
        let prefix = u >> k;
        let mut coords: Vec<EF> = (0..pre).map(|i| if (prefix >> (pre - 1 - i)) & 1 == 1 { EF::ONE } else { EF::ZERO }).collect();
        let mut s = EF::ONE;
        for &x in &a {
            let d = EF::ONE + x;
            let di = d.try_inverse()?;
            coords.push(x * di);
            s *= d;
        }
        out.push((Point::new(coords), s, c, 1 << k));
        c += 1 << k;
    }
    Some(out)
}

impl<EF: ExtensionField<F> + TwoAdicField> WhirUniPcs<EF>
where
    StandardUniform: Distribution<EF>,
{
    fn hw(&self, n: usize, rng: StdRng) -> Result<Hw<EF>, String> {
        let w = &self.w;
        let params = ProtocolParameters {
            security_level: w.target,
            pow_bits: w.pow,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(w.fold),
            soundness_type: if w.unique { SecurityAssumption::UniqueDecoding } else { SecurityAssumption::JohnsonBound },
            starting_log_inv_rate: w.rate,
        };
        let cfg = ZkWhirConfig::new(n, params, ZkParameters { ell_zk: w.ell_zk, mask_log_inv_rate: w.mask_rate })
            .map_err(|e| format!("whir config (n = {n}): {e}"))?;
        let mut rng = rng;
        let mmcs = hmmcs(&mut rng);
        Ok(HidingWhirPcs::new(cfg, self.dft.clone(), mmcs, rng))
    }

    fn fresh(&self) -> StdRng {
        self.fresh_rng()
    }

    /// Smallest variable count ≥ the stacked size that HVZK-WHIR accepts (its randomness must fit the codeword
    /// slack, which small polynomials miss); a pure function of the shapes, so prover and verifier agree.
    pub fn n_vars(&self, n: usize) -> Result<usize, String> {
        let mut last = String::new();
        for v in n.max(self.w.fold + 1)..=MAX_VARS {
            match self.hw(v, StdRng::from_seed([0; 32])) {
                Ok(_) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Stack coefficient matrices and commit them.
    fn stack_commit(&self, mats: Vec<RowMajorMatrix<F>>, public: bool) -> Result<(Cap, WhirData<EF>), String> {
        let shapes: Vec<(usize, usize)> = mats.iter().map(|m| (m.height(), m.width())).collect();
        let (offs, n0) = layout(&shapes);
        let n = self.n_vars(n0)?;
        let mut msg = vec![F::ZERO; 1 << n];
        for (m, &off) in mats.iter().zip(&offs) {
            let (h, w) = (m.height(), m.width());
            for r in 0..h {
                for c in 0..w {
                    msg[off + c * h + r] = m.values[r * w + c];
                }
            }
        }
        let rng = if public { StdRng::from_seed(PRE_SEED) } else { self.fresh() };
        let hw = self.hw(n, rng)?;
        let (commit, data) =
            hw.commit(Poly::new(msg.clone()), &mut BeChallenger::new(&[0; 32])).map_err(|e| format!("{e:?}"))?;
        let inner = if public { None } else { Some(data) };
        Ok((commit.clone(), WhirData { shapes, offs, n_vars: n, msg, commit: Some(commit), inner: Mutex::new(inner) }))
    }

    /// coefficients of the column polynomials given by evaluations on the subgroup of size `h = mat.height()`, of
    /// degree < `size`; with `rng`, masked as `t + Z_H·r`, `deg r < size - h` (needs size ≤ 2h)
    fn trace_coeffs(&self, mat: RowMajorMatrix<F>, size: usize, rng: Option<&mut StdRng>) -> RowMajorMatrix<F> {
        let (h, w) = (mat.height(), mat.width());
        assert!(size >= h && size <= 2 * h);
        let mut c = self.dft.idft_batch(mat);
        c.values.resize(size * w, F::ZERO);
        if let Some(rng) = rng {
            for i in 0..(size - h) * w {
                let r = rng.random::<F>();
                c.values[i] -= r;
                c.values[h * w + i] += r;
            }
        }
        c
    }
}

impl<EF: ExtensionField<F> + TwoAdicField> Pcs<EF, BeChallenger> for WhirUniPcs<EF>
where
    StandardUniform: Distribution<EF>,
{
    type Domain = Domain;
    type Commitment = Cap;
    type ProverData = WhirData<EF>;
    type Proof = Vec<ZkWhirProof<F, EF, HidingValMmcs>>;
    type Error = String;
    type ProverError = String;

    fn natural_domain_for_degree(&self, degree: usize) -> Domain {
        Domain::new(F::ONE, degree.trailing_zeros() as usize).unwrap()
    }

    fn commit(&self, evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<F>)>) -> Result<(Cap, WhirData<EF>), String> {
        let mut rng = self.fresh();
        let mats = evaluations
            .into_iter()
            .map(|(d, m)| {
                if d.shift() != F::ONE || d.size() > 2 * m.height() || d.size() < m.height() {
                    return Err("commit: unsupported domain".to_string());
                }
                Ok(self.trace_coeffs(m, d.size(), Some(&mut rng)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.stack_commit(mats, false)
    }

    fn open(
        &self,
        rounds: Vec<OpeningRequest<'_, WhirData<EF>, EF>>,
        ch: &mut BeChallenger,
    ) -> Result<(OpenedValues<EF>, Self::Proof), String> {
        self.open_with_preprocessing(rounds, ch, None)
    }

    fn verify(
        &self,
        rounds: Vec<CommitmentOpening<EF, Cap, Domain>>,
        proof: &Self::Proof,
        ch: &mut BeChallenger,
    ) -> Result<(), String> {
        self.verify_with_preprocessing(rounds, proof, ch, None)
    }
}

impl<EF: ExtensionField<F> + TwoAdicField> UnivariateStarkPcs<EF, BeChallenger> for WhirUniPcs<EF>
where
    StandardUniform: Distribution<EF>,
{
    type EvaluationsOnDomain<'a> = RowMajorMatrix<F>;
    const ZK: bool = true;

    fn log_max_trace_height(&self) -> usize {
        20
    }

    fn log_min_trace_height(&self) -> usize {
        0
    }

    fn commit_preprocessing(
        &self,
        evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<F>)>,
    ) -> Result<(Cap, WhirData<EF>), String> {
        let mats = evaluations
            .into_iter()
            .map(|(d, m)| {
                if d.shift() != F::ONE || d.size() > 2 * m.height() || d.size() < m.height() {
                    return Err("commit_preprocessing: unsupported domain".to_string());
                }
                Ok(self.trace_coeffs(m, d.size(), None))
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.stack_commit(mats, true)
    }

    /// Chunk i on the coset `s_i·H` (|H| = h): `q'_i = q_i + ((X/s_i)^h − 1)·t_i`, `deg t_i < h`, the last `t`
    /// chosen so the masks cancel in the recombination (as p3-fri's `HidingFriPcs::get_quotient_ldes`); returns
    /// coefficient matrices of height 2h.
    fn get_quotient_ldes(
        &self,
        evaluations: impl IntoIterator<Item = (Domain, RowMajorMatrix<F>)>,
        num_chunks: usize,
    ) -> Result<Vec<RowMajorMatrix<F>>, String> {
        if num_chunks < 2 {
            return Err("quotient: fewer than 2 chunks is not hiding".into());
        }
        let (domains, evals): (Vec<Domain>, Vec<RowMajorMatrix<F>>) = evaluations.into_iter().unzip();
        let cis = zp_cis(&domains);
        let last = domains.len() - 1;
        let (h, w) = (evals[0].height(), evals[0].width());
        let mut rng = self.fresh();
        let mut t: Vec<Vec<F>> = (0..last).map(|_| (0..h * w).map(|_| rng.random::<F>()).collect()).collect();
        let mut tl = vec![F::ZERO; h * w];
        for (j, tj) in t.iter().enumerate() {
            let mc = cis[j] * cis[last].inverse();
            for k in 0..h * w {
                tl[k] -= tj[k] * mc;
            }
        }
        t.push(tl);
        Ok(domains
            .into_iter()
            .zip(evals)
            .zip(t)
            .map(|((d, e), t)| {
                assert_eq!((e.height(), e.width()), (h, w));
                let mut c = self.dft.coset_idft_batch(e, d.shift());
                c.values.resize(2 * h * w, F::ZERO);
                let sinv = d.shift().inverse().exp_u64(h as u64);
                for k in 0..h * w {
                    c.values[k] -= t[k];
                    c.values[h * w + k] += sinv * t[k];
                }
                c
            })
            .collect())
    }

    fn commit_ldes(&self, ldes: Vec<RowMajorMatrix<F>>) -> Result<(Cap, WhirData<EF>), String> {
        self.stack_commit(ldes, false)
    }

    /// the committed polynomial of matrix `idx` evaluated on `domain` (natural order)
    fn get_evaluations_on_domain<'a>(&self, d: &'a WhirData<EF>, idx: usize, domain: Domain) -> RowMajorMatrix<F> {
        let (h, w) = d.shapes[idx];
        let off = d.offs[idx];
        let n = domain.size();
        assert!(n >= h);
        let mut v = vec![F::ZERO; n * w];
        for c in 0..w {
            for r in 0..h {
                v[r * w + c] = d.msg[off + c * h + r];
            }
        }
        self.dft.coset_dft_batch(RowMajorMatrix::new(v, w), domain.shift()).to_row_major_matrix()
    }

    fn open_with_preprocessing(
        &self,
        rounds: Vec<OpeningRequest<'_, WhirData<EF>, EF>>,
        ch: &mut BeChallenger,
        _pre: Option<usize>,
    ) -> Result<(OpenedValues<EF>, Self::Proof), String> {
        let ov: OpenedValues<EF> = rounds
            .iter()
            .map(|r| {
                let d = r.prover_data;
                r.points
                    .iter()
                    .enumerate()
                    .map(|(m, pts)| {
                        let (h, w) = d.shapes[m];
                        pts.iter()
                            .map(|&z| {
                                (0..w)
                                    .map(|c| match d.commit {
                                        None => EF::ZERO,
                                        Some(_) => horner(&d.msg[d.offs[m] + c * h..d.offs[m] + (c + 1) * h], z),
                                    })
                                    .collect()
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();
        for v in ov.iter().flatten().flatten().flatten() {
            ch.observe_algebra_element(*v);
        }
        let beta: EF = ch.sample_algebra_element();
        LAST_OPENINGS.lock().unwrap().clear();
        let mut proofs = Vec::new();
        for r in &rounds {
            let d = r.prover_data;
            let Some(commit) = &d.commit else { continue };
            let mut pts = Vec::new();
            for (m, zs) in r.points.iter().enumerate() {
                for &z in zs {
                    let cl = claims(d.n_vars, d.offs[m], d.shapes[m].0, d.shapes[m].1, z, beta).ok_or("degenerate point")?;
                    pts.extend(cl.into_iter().map(|c| c.0));
                }
            }
            let hw = self.hw(d.n_vars, self.fresh())?;
            let data = match d.inner.lock().unwrap().take() {
                Some(x) => x,
                None => {
                    // preprocessed (public): recommit with the fixed randomness, same root
                    let pre = self.hw(d.n_vars, StdRng::from_seed(PRE_SEED))?;
                    let (c2, x) = pre
                        .commit(Poly::new(d.msg.clone()), &mut BeChallenger::new(&[0; 32]))
                        .map_err(|e| format!("{e:?}"))?;
                    if c2.roots() != commit.roots() {
                        return Err("private round opened twice".into());
                    }
                    x
                }
            };
            LAST_OPENINGS.lock().unwrap().push((d.n_vars, pts.len(), r.points.iter().zip(&d.shapes).map(|(z, s)| z.len() * s.1).sum()));
            hw.observe_commitment(commit, ch);
            proofs.push(hw.open(data, pts, ch).map_err(|e| format!("{e:?}"))?);
        }
        Ok((ov, proofs))
    }

    fn verify_with_preprocessing(
        &self,
        rounds: Vec<CommitmentOpening<EF, Cap, Domain>>,
        proof: &Self::Proof,
        ch: &mut BeChallenger,
        _pre: Option<usize>,
    ) -> Result<(), String> {
        for r in &rounds {
            for m in &r.matrices {
                for p in &m.points {
                    for v in &p.values {
                        ch.observe_algebra_element(*v);
                    }
                }
            }
        }
        let beta: EF = ch.sample_algebra_element();
        // the ZK layout puts the randomisation round first: nothing committed, everything zero
        let (r0, rest) = rounds.split_first().ok_or("no rounds")?;
        if r0.commitment.roots() != zero_cap().roots()
            || r0.matrices.iter().flat_map(|m| &m.points).flat_map(|p| &p.values).any(|v| !v.is_zero())
        {
            return Err("randomisation round must be zero".into());
        }
        if proof.len() != rest.len() {
            return Err("proof count".into());
        }
        for (r, pf) in rest.iter().zip(proof) {
            let mut shapes = Vec::new();
            for m in &r.matrices {
                let w = m.points.first().ok_or("matrix without points")?.values.len();
                if m.points.iter().any(|p| p.values.len() != w) {
                    return Err("ragged opening".into());
                }
                shapes.push((m.domain.size(), w));
            }
            let (offs, n0) = layout(&shapes);
            if n0 > MAX_VARS {
                return Err("too large".into());
            }
            let n = self.n_vars(n0)?;
            let mut pts = Vec::new();
            let mut want = Vec::new();
            for (m, mat) in r.matrices.iter().enumerate() {
                for p in &mat.points {
                    for (pt, s, c0, len) in
                        claims(n, offs[m], shapes[m].0, shapes[m].1, p.point, beta).ok_or("degenerate point")?
                    {
                        let mut acc = EF::ZERO;
                        for v in p.values[c0..c0 + len].iter().rev() {
                            acc = acc * beta + *v;
                        }
                        want.push(acc * s.inverse());
                        pts.push(pt);
                    }
                }
            }
            if pf.evals != want {
                return Err("claimed evaluations do not match the opened values".into());
            }
            let hw = self.hw(n, StdRng::from_seed([0; 32]))?;
            hw.verify(&r.commitment, pf, ch, pts).map_err(|e| format!("{e:?}"))?;
        }
        Ok(())
    }

    /// Periodic columns on the quotient domain by DFT, as p3-fri's PCSs do. The trait default interpolates point by
    /// point (O(quotient size × period)): 164 of the 206 s of an `R_TX` proof (docs/research/pqzh-zk-whir.md §10.3).
    fn build_periodic_lde_table(
        &self,
        periodic_cols: &[Vec<F>],
        trace_domain: Domain,
        quotient_domain: Domain,
    ) -> p3_commit::PeriodicLdeTable<F> {
        p3_fri::build_periodic_lde_table_two_adic(&self.dft, periodic_cols, &trace_domain, &quotient_domain)
    }

    fn get_opt_randomization_poly_commitment(
        &self,
        domains: impl IntoIterator<Item = Domain>,
    ) -> Result<Option<(Cap, WhirData<EF>)>, String> {
        let shapes: Vec<(usize, usize)> = domains.into_iter().map(|d| (d.size(), EF::DIMENSION)).collect();
        let offs = vec![0; shapes.len()];
        Ok(Some((zero_cap(), WhirData { shapes, offs, n_vars: 0, msg: vec![], commit: None, inner: Mutex::new(None) })))
    }
}

/// (variables, claims, opened column values) of each HVZK-WHIR opening of the last proof opened by this process (bits report only)
pub static LAST_OPENINGS: Mutex<Vec<(usize, usize, usize)>> = Mutex::new(Vec::new());

impl<EF: ExtensionField<F> + TwoAdicField> WhirUniPcs<EF>
where
    StandardUniform: Distribution<EF>,
{
    /// Soundness terms (bits) of one HVZK-WHIR opening of `n` variables with `claims` claims, from p3-whir's round
    /// configuration with p3-security's formulas (as p3-whir's crate-private `prescribed_security` composes them for
    /// plain WHIR; no commitment out-of-domain term, as HVZK-WHIR has none), plus the masked base case's
    /// round-by-round bits (`hiding_base_case_security_report`, p3-whir: "diagnostic only").
    pub fn opening_terms(&self, n: usize, claims: usize) -> Result<Vec<(String, f64)>, String> {
        let hw = self.hw(n, StdRng::from_seed([0; 32]))?;
        let c = &hw.config;
        let a = c.soundness_type;
        let fb = EF::bits() - 1;
        let mut t: Vec<(String, f64)> = vec![("initial-claims".into(), c.initial_claims_error(claims))];
        let jr = if a == SecurityAssumption::JohnsonBound { 1.0 } else { 0.0 };
        let folds = |t: &mut Vec<(String, f64)>, r: usize, nv: usize, rate: usize, k: usize, pow: usize| {
            let gap = a.prox_gaps_error(nv, rate, fb, 2) - jr;
            let sc = a.fold_sumcheck_error(fb, nv, rate);
            for _ in 0..k {
                t.push((format!("r{r}-fold-gap"), gap + pow as f64));
                t.push((format!("r{r}-fold-sumcheck"), sc + pow as f64));
            }
        };
        folds(&mut t, 0, c.num_variables(), c.starting_log_inv_rate, c.folding_schedule()[0], c.starting_folding_pow_bits());
        let mut old = c.starting_log_inv_rate;
        for (i, r) in c.round_parameters().iter().enumerate() {
            if a != SecurityAssumption::UniqueDecoding {
                t.push((format!("r{}-ood", i + 1), a.ood_error(r.num_variables, r.log_inv_rate, fb, r.ood_samples)));
            }
            t.push((format!("r{}-queries", i + 1), a.queries_error(old, r.num_queries) + r.pow_bits as f64));
            t.push((
                format!("r{}-queries-combination", i + 1),
                a.queries_combination_error(fb, r.num_variables, r.log_inv_rate, r.ood_samples, r.num_queries) + r.pow_bits as f64,
            ));
            folds(&mut t, i + 1, r.num_variables, r.log_inv_rate, c.folding_schedule()[i + 1], r.folding_pow_bits);
            old = r.log_inv_rate;
        }
        let rt = c.randomized_terminal();
        t.push((
            format!(
                "shape: rounds {} queries {:?} ood {:?} terminal {}q/{}pow mask_queries {} randomness {:?} final_vars {}",
                c.n_rounds(),
                c.round_parameters().iter().map(|r| r.num_queries).collect::<Vec<_>>(),
                c.round_parameters().iter().map(|r| r.ood_samples).collect::<Vec<_>>(),
                rt.num_queries,
                rt.pow_bits,
                c.mask_queries(),
                c.oracle_randomness(),
                c.final_round_config().num_variables
            ),
            f64::INFINITY,
        ));
        let b = c.hiding_base_case_security_report();
        t.push(("base-case-gamma".into(), b.gamma_round.combined.bits.unwrap_or(0.0)));
        t.push(("base-case-queries".into(), b.query_round.with_pow.bits.unwrap_or(0.0)));
        Ok(t)
    }
}

/// union bound of terms given in bits
pub fn union_bits(t: impl IntoIterator<Item = f64>) -> f64 {
    -t.into_iter().map(|b| (-b).exp2()).sum::<f64>().log2()
}

/// Lagrange normalising constants of the quotient chunk domains, inverted (p3-fri `hiding_pcs.rs` `get_zp_cis`)
fn zp_cis(ds: &[Domain]) -> Vec<F> {
    ds.iter()
        .enumerate()
        .map(|(i, d)| {
            ds.iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, o)| o.vanishing_poly_at_point(d.first_point()))
                .product::<F>()
                .inverse()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::BasedVectorSpace;
    use crate::config::Challenge5;
    type EF = Challenge5;

    fn rnd(r: &mut StdRng) -> EF {
        EF::from_basis_coefficients_fn(|_| r.random::<F>())
    }

    /// §5.2: a block claim times S equals the β-combination of the univariate column values
    #[test]
    fn embedding_matches_direct_evaluation() {
        let mut r = StdRng::from_seed([3; 32]);
        let shapes = [(16usize, 5usize), (64, 3), (16, 2), (8, 7)];
        let (offs, n) = layout(&shapes);
        let msg: Vec<F> = (0..1usize << n).map(|_| r.random()).collect();
        let poly = Poly::new(msg.clone());
        let (z, beta) = (rnd(&mut r), rnd(&mut r));
        for (m, &(h, w)) in shapes.iter().enumerate() {
            let cl = claims(n, offs[m], h, w, z, beta).unwrap();
            assert_eq!(cl.iter().map(|c| c.3).sum::<usize>(), w);
            for (pt, s, c0, len) in cl {
                let mut want = EF::ZERO;
                for c in (c0..c0 + len).rev() {
                    want = want * beta + horner(&msg[offs[m] + c * h..offs[m] + (c + 1) * h], z);
                }
                assert_eq!(poly.eval_base(&pt) * s, want);
            }
        }
    }

    fn pcs() -> WhirUniPcs<EF> {
        WhirUniPcs::new(WhirParams { target: 64, pow: 0, ..WhirParams::DEFAULT }, [4; 32])
    }

    /// trace masking agrees with the trace on H; quotient masks keep each chunk's values on its domain
    #[test]
    fn coefficient_forms() {
        let p = pcs();
        let mut r = StdRng::from_seed([5; 32]);
        let tr = RowMajorMatrix::new((0..16 * 3).map(|_| r.random()).collect::<Vec<F>>(), 3);
        let c = p.trace_coeffs(tr.clone(), 32, Some(&mut r));
        let g = F::two_adic_generator(4);
        for row in 0..16 {
            for col in 0..3 {
                let x = g.exp_u64(row as u64);
                let col_c: Vec<F> = (0..32).map(|i| c.values[i * 3 + col]).collect();
                assert_eq!(horner::<EF>(&col_c, EF::from(x)), EF::from(tr.values[row * 3 + col]));
            }
        }
        // quotient: chunk domains of a disjoint coset split in 4, the masks cancel in the Lagrange recombination
        let qd = Domain::new(F::GENERATOR, 6).unwrap();
        let ds = qd.split_domains(4);
        let ev: Vec<(Domain, RowMajorMatrix<F>)> =
            ds.iter().map(|d| (*d, RowMajorMatrix::new((0..16 * 2).map(|_| r.random()).collect(), 2))).collect();
        let ldes = p.get_quotient_ldes(ev.clone(), 4).unwrap();
        let zeta = rnd(&mut r);
        let cis = zp_cis(&ds);
        let mut lhs = [EF::ZERO; 2];
        let mut rhs = [EF::ZERO; 2];
        for (i, ((d, e), l)) in ev.iter().zip(&ldes).enumerate() {
            let plain = p.dft.coset_idft_batch(e.clone(), d.shift());
            let zp: EF = ds.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, o)| o.vanishing_poly_at_point(zeta)).product::<EF>()
                * cis[i];
            for col in 0..2 {
                let lc: Vec<F> = (0..32).map(|k| l.values[k * 2 + col]).collect();
                let pc: Vec<F> = (0..16).map(|k| plain.values[k * 2 + col]).collect();
                lhs[col] += zp * horner::<EF>(&lc, zeta);
                rhs[col] += zp * horner::<EF>(&pc, zeta);
                // on its own domain the masked chunk equals the chunk
                let x = d.first_point() * F::two_adic_generator(4);
                assert_eq!(horner::<EF>(&lc, EF::from(x)), horner::<EF>(&pc, EF::from(x)));
            }
        }
        assert_eq!(lhs, rhs);
    }

    fn round_trip(tamper: impl Fn(&mut OpenedValues<EF>, &mut Vec<ZkWhirProof<F, EF, HidingValMmcs>>)) -> bool {
        let p = pcs();
        let mut r = StdRng::from_seed([6; 32]);
        let dom = |n: usize| p.natural_domain_for_degree(n);
        let m1 = RowMajorMatrix::new((0..64 * 9).map(|_| r.random()).collect::<Vec<F>>(), 9);
        let m2 = RowMajorMatrix::new((0..16 * 4).map(|_| r.random()).collect::<Vec<F>>(), 4);
        let (c, d) = p.commit(vec![(dom(128), m1), (dom(32), m2)]).unwrap();
        let (rc, rd) = p.get_opt_randomization_poly_commitment([dom(128), dom(32)]).unwrap().unwrap();
        let (z, z2) = (rnd(&mut r), rnd(&mut r));
        let req = vec![
            OpeningRequest { prover_data: &rd, points: vec![vec![z], vec![z]] },
            OpeningRequest { prover_data: &d, points: vec![vec![z, z2], vec![z]] },
        ];
        let mut ch = BeChallenger::new(&[1; 32]);
        let (mut ov, mut pf) = p.open(req, &mut ch).unwrap();
        tamper(&mut ov, &mut pf);
        let rounds = vec![
            CommitmentOpening::from((rc, vec![(dom(128), vec![(z, ov[0][0][0].clone())]), (dom(32), vec![(z, ov[0][1][0].clone())])])),
            CommitmentOpening::from((
                c,
                vec![(dom(128), vec![(z, ov[1][0][0].clone()), (z2, ov[1][0][1].clone())]), (dom(32), vec![(z, ov[1][1][0].clone())])],
            )),
        ];
        let v = WhirUniPcs::<EF>::new(p.w, [0; 32]);
        v.verify(rounds, &pf, &mut BeChallenger::new(&[1; 32])).is_ok()
    }

    #[test]
    fn open_verify_and_rejections() {
        assert!(round_trip(|_, _| {}));
        assert!(!round_trip(|ov, _| ov[1][0][1][3] += EF::ONE), "wrong opened value");
        assert!(!round_trip(|ov, _| ov[0][1][0][0] = EF::ONE), "nonzero randomisation value");
        assert!(!round_trip(|_, pf| pf[0].evals[0] += EF::ONE), "wrong evals entry");
        assert!(!round_trip(|_, pf| pf.clear()), "missing opening");
    }
}
