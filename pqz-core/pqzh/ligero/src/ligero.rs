//! Ligero prover and verifier over F_q with F_q^4 challenges (docs/research/pqzh-ligero.md §4): one Keccak-256 Merkle
//! commitment to the m witness rows and 12 blinding rows (u_0, u_lin, u_quad in F_q^4, full degree < 2k - 1, all
//! inside the one proximity test: owner decision 2026-10-14, the modified ZK construction), three test polynomials
//! w, q, h, grinding, t column queries.
//!
//! Proof bytes: root (32) | w: 2k-1 F_q^4 coefficients | q: 2k-1 | h: 2k-1-l | nonce (be64) | per distinct opened
//! column in increasing index order: salt (32) and m + 12 F_q values | pruned multiproof digests. F_q^4 = 4 F_q
//! elements, F_q = 6 bytes big-endian, canonical. Every length follows from the parameters and the transcript.

use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::cs::{self, Comb, Layout, Rel};
use crate::fft::{Domain, GEN, smooth};
use crate::fq::{Acc4, EB, F4, Fq, batch_inv};
use crate::merkle::{H, Tree, depth, keccak, root_from};
use crate::transcript::Tr;
use crate::{Oom, Wiped, ct, try_vec};
#[cfg(feature = "bench")]
use pqz_stmt::{OP_DISCLOSE_RECEIVER, OP_DISCLOSE_SENDER, OP_REGISTER};

#[cfg(feature = "bench")]
pub const LAMBDA: f64 = 128.0;
pub const POW_BITS: u32 = 16;
const FB: usize = 4 * EB; // bytes per F_q^4 element
const BLIND: usize = 12;
/// prover attempts before "proof length" (see `prove_inner`); one in practice: no proof exceeds max_proof_len.
/// Fallback A (feature `fallback-retry`): 32, the limit is MAX_PROOF_PQZH and op 7 M = 4 with the auditor re-proves in
/// 27.6 % of the attempts (failure after 32: ~ 10^-18 per proof; docs/research/pqzh-set-a-proof-limit.md)
const ATTEMPTS: usize = if cfg!(feature = "fallback-retry") { 32 } else { 16 };

/// Fixed per proofSystemId; never read from the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Params {
    pub n: usize,
    pub k: usize,
    pub ell: usize,
    pub t: usize,
    pub pow_bits: u32,
    pub proven: bool,
    /// Johnson-bound proven regime (reference only, owner 2026-10-14 (b)): t from `factor_johnson`
    pub johnson: bool,
}

/// BCIKS20 list-decoding parameter m (m = 3: the smallest the theorem allows, the best field term)
#[cfg(feature = "bench")]
pub const JOHNSON_M: usize = 3;

/// Johnson regime, RS[n, 2k-1] of rate r = (2k-1)/n: delta = 1 - sqrt(r) - eta, eta = sqrt(r)/(2m); per query
/// max(1 - delta, (2k-2)/n) (assumes mutual correlated agreement up to delta for the consistency tests,
/// docs/research/pqzh-ligero.md §5.3). Returns (factor, BCIKS20 error eps = (m+1/2)^7/(3 r^1.5) n^2 / |F| as log2 bits).
#[cfg(feature = "bench")]
pub fn factor_johnson(n: usize, k: usize) -> (f64, f64) {
    let r = (2 * k - 1) as f64 / n as f64;
    let m = JOHNSON_M as f64;
    let omd = r.sqrt() * (1.0 + 1.0 / (2.0 * m));
    let f = f64::max(omd, (2 * k - 2) as f64 / n as f64);
    let eps = (m + 0.5).powi(7) / (3.0 * r.powf(1.5)) * (n as f64).powi(2);
    (f, 4.0 * (crate::fq::Q as f64).log2() - eps.log2())
}

/// Per-query acceptance of a cheating prover. Proven: one proximity test over RS[n, 2k-1] at its unique-decoding
/// radius e and consistency terms (e + 2k - 2)/n (Ligero Thm 4.7 / App. C form). Conjectured: (2k - 1)/n, the rate
/// of RS[n, 2k-1] (ethSTARK-style), reported only for comparison with the STARK's conjectured numbers.
#[cfg(feature = "bench")]
pub fn factor(n: usize, k: usize, proven: bool) -> f64 {
    if proven {
        let e = (n - 2 * k + 1) / 2;
        f64::max(1.0 - e as f64 / n as f64, (e + 2 * k - 2) as f64 / n as f64)
    } else {
        (2 * k - 1) as f64 / n as f64
    }
}

impl Params {
    /// t from 112 query bits + 16 grinding bits; l = k - t - 1 (zero knowledge: t openings < k - l). The parameter
    /// model (floats): feature `bench`; production takes `proven()`.
    #[cfg(feature = "bench")]
    pub fn new(n: usize, k: usize, proven: bool) -> Params {
        let f = factor(n, k, proven);
        let t = ((LAMBDA - POW_BITS as f64) / -f.log2()).ceil() as usize;
        assert!(k > t + 1 && smooth(n) && smooth(k) && n >= 4 * k, "bad parameters n {n} k {k} t {t}");
        Params { n, k, ell: k - t - 1, t, pow_bits: POW_BITS, proven, johnson: false }
    }

    /// Johnson-bound proven parameters (reference only); requires (1 - delta) n >= 3k - 2 (degree correction)
    #[cfg(feature = "bench")]
    pub fn johnson(n: usize, k: usize) -> Params {
        let (f, _) = factor_johnson(n, k);
        let t = ((LAMBDA - POW_BITS as f64) / -f.log2()).ceil() as usize;
        assert!(k > t + 1 && smooth(n) && smooth(k) && n >= 4 * k && f * n as f64 >= (3 * k - 2) as f64);
        Params { n, k, ell: k - t - 1, t, pow_bits: POW_BITS, proven: true, johnson: true }
    }

    /// THE preset (owner 2026-10-14 (a)): proven, radix 431, n = 32,756, k = 817, t = 121, l = 695, every op, the same
    /// in every parameter set (pqzh_set.rs; plan 5h Task 8c: the domains exist for every set's q and the soundness
    /// depends on n, k only); the parameter model's `Params::new(32756, 817, true)` (unit test `proven_is_the_model`),
    /// written out so that the production build has no float code
    pub const fn proven() -> Params {
        use crate::set::{PRESET_K, PRESET_N, PRESET_T};
        Params { n: PRESET_N, k: PRESET_K, ell: PRESET_K - PRESET_T - 1, t: PRESET_T, pow_bits: POW_BITS, proven: true, johnson: false }
    }

    /// the model's smallest Johnson preset with the field term >= 128 bits (charged once): runs/p1-params.txt.
    /// Reference only (owner 2026-10-14 (b)): feature `bench`.
    #[cfg(feature = "bench")]
    pub fn johnson_preset() -> Params {
        Params::johnson(6536, 862)
    }

    /// the parameter model's choice (ligero_params.py, runs/p1-params.txt); r431 = false: radices 2/19/43 only.
    /// Proven with radix 431 = `proven()`. The other three (proven 2/19/43, conjectured with and without 431) are
    /// reference only, so the whole function is behind feature `bench` (production code takes `proven()`).
    /// Conjectured: R_REG's for the disclosures (about R_REG's size), R_TX's for R_BURN; the model was not rerun.
    #[cfg(feature = "bench")]
    pub fn preset(op: u8, proven: bool, r431: bool) -> Params {
        let small = matches!(op, OP_REGISTER | OP_DISCLOSE_SENDER | OP_DISCLOSE_RECEIVER);
        let (n, k) = match (proven, r431, small) {
            (true, true, _) => return Params::proven(),
            (true, false, _) => (6536, 817),
            (false, true, true) => (18533, 172),
            (false, true, false) => (18533, 344),
            (false, false, true) => (6536, 172),
            (false, false, false) => (6536, 344),
        };
        Params::new(n, k, proven)
    }

    pub fn n2(&self) -> usize {
        (2 * self.k - 1..).find(|&x| smooth(x)).unwrap()
    }

    fn poly_bytes(&self) -> usize {
        (2 * (2 * self.k - 1) + (2 * self.k - 1 - self.ell)) * FB
    }

    /// loose upper bound on the proof length (t distinct columns, full paths): the verifier's check before Task 9,
    /// kept for the bench's comparison
    pub fn max_len(&self, rel: impl Into<Rel>) -> usize {
        let m = Layout::new(rel, self.ell).m;
        32 + self.poly_bytes() + 8 + self.t * (32 + (m + BLIND) * EB) + self.t * depth(self.n) * 32
    }

    /// The largest proof the verifier can parse (G7): t distinct columns (a
    /// column costs more than any number of digests it saves) and the largest pruned multiproof for t leaves of the
    /// first n in a depth-d tree. With a_l distinct nodes on level l (a_0 = t, a_d = 1), level l sends 2 a_(l+1) - a_l
    /// siblings, so the total is sum_(0 < l < d) a_l + 2 - t, maximal at a_l = min(t, ceil(n / 2^l)).
    pub fn max_len_exact(&self, rel: impl Into<Rel>) -> usize {
        let m = Layout::new(rel, self.ell).m;
        let d = depth(self.n);
        let mid: usize = (1..d).map(|l| self.t.min(self.n.div_ceil(1 << l))).sum();
        32 + self.poly_bytes() + 8 + self.t * (32 + (m + BLIND) * EB) + (mid + 2 - self.t) * 32
    }

    /// The verifier's length bound (plan Task 9): the exact maximum. At THE preset (the D3 id) and the v3 set it is
    /// <= pqz_stmt::MAX_PROOF_PQZH (D5) for every relation: the six forms (R_TX 235,470 B) and every built op 7 R_TXM
    /// shape (largest (M = 4, auditor on) 236,196 B, 5 + statement + bound 369,193 B <= MAX_INPUT); at set (a) the
    /// debit forms are above it (R_TX 264,510 B, plan 5h Task 8c); unit test `limits_exact` pins all of them per set. Not capped at MAX_PROOF_PQZH: the reference
    /// presets are not the id, proven without radix 431 has every R_TX / R_BURN proof above it, and the bench-only
    /// oversize R_TXM shapes (M = 8, 16) are above it by design.
    pub fn max_proof_len(&self, rel: impl Into<Rel>) -> usize {
        self.max_len_exact(rel)
    }

    /// The verifier's first check, before the statement or the proof is parsed: 1 <= len <= max_proof_len(rel)
    pub fn proof_len_ok(&self, rel: impl Into<Rel>, len: usize) -> bool {
        (1..=self.max_proof_len(rel)).contains(&len)
    }
}

/// prover randomness, hedged with the witness (plan D6, CTR-PQZ-19): SHAKE256("SCAAS-PQZH-LIGERO-RNG-V2" || rnd32 ||
/// u8(op) || be32(len(stmt)) || stmt || wit). A repeated rnd32 with another witness gives unrelated masks.
/// Its state yields every mask and salt (Keccak-f is a permutation), so it is replaced in place on drop (review P-C):
/// sha3 0.10.8 has no `zeroize` feature and no `Drop`, and access to the state would need `unsafe`; the hasher's state
/// before `finalize_xof` (moved by value) is not cleared (the platform boundary of `crate::Wipe`).
struct Rng(sha3::Shake256Reader);
impl Drop for Rng {
    fn drop(&mut self) {
        self.0 = sha3::Shake256::default().finalize_xof();
        std::hint::black_box(&self.0);
    }
}
impl Rng {
    fn new(rnd: [u8; 32], op: u8, stmt: &[u8], wit: &[u8]) -> Rng {
        let mut h = sha3::Shake256::default();
        h.update(b"SCAAS-PQZH-LIGERO-RNG-V2");
        h.update(&rnd);
        h.update(&[op]);
        h.update(&(stmt.len() as u32).to_be_bytes());
        h.update(stmt);
        h.update(wit);
        Rng(h.finalize_xof())
    }
    fn fq(&mut self) -> Fq {
        loop {
            let mut w = [0u8; 8];
            self.0.read(&mut w);
            let v = u64::from_be_bytes(w) & crate::fq::MASK;
            // uniform rejection sampling: the try count is independent of the accepted value (public, review P-B)
            if ct::verdict(v < crate::fq::Q) {
                return Fq(v);
            }
        }
    }
    fn vec(&mut self, n: usize) -> Wiped<Vec<Fq>> {
        Wiped((0..n).map(|_| self.fq()).collect())
    }
    fn salt(&mut self) -> H {
        let mut s = [0u8; 32];
        self.0.read(&mut s);
        s
    }
}

type P4 = [Vec<Fq>; 4]; // F_q^4 polynomial, component-major

fn get4(p: &P4, i: usize) -> F4 {
    F4([p[0][i], p[1][i], p[2][i], p[3][i]])
}

/// Z_zeta = prod_{c < l} (X - omega_k^c), monic, l + 1 coefficients
fn zeta_poly(hk: &Domain, ell: usize) -> Vec<Fq> {
    let mut z = vec![Fq::ONE];
    for c in 0..ell {
        let r = hk.w[c];
        let mut nz = vec![Fq::ZERO; z.len() + 1];
        for (i, &v) in z.iter().enumerate() {
            nz[i + 1] += v;
            nz[i] -= v * r;
        }
        z = nz;
    }
    z
}

fn mul_poly(a: &[Fq], b: &[Fq]) -> Vec<Fq> {
    let mut out = vec![Fq::ZERO; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] += x * y;
        }
    }
    out
}

/// interpolant (degree < k, F_q^4) of v on the first l points of H_k and 0 on the other k - l
fn interp(hk: &Domain, v: &[F4]) -> P4 {
    std::array::from_fn(|s| {
        let mut e: Vec<Fq> = v.iter().map(|x| x.0[s]).collect();
        e.resize(hk.n, Fq::ZERO);
        hk.ifft(&e)
    })
}

type Draw = (Vec<F4>, Vec<F4>, F4, F4, F4, Vec<F4>);
fn draw(tr: &mut Tr, m: usize, ntri: usize) -> Result<Draw, Oom> {
    fn f4s(tr: &mut Tr, n: usize) -> Result<Vec<F4>, Oom> {
        let mut v = try_vec(n)?;
        v.extend((0..n).map(|_| tr.f4()));
        Ok(v)
    }
    let (a, b) = (f4s(tr, m)?, f4s(tr, m)?);
    let (cl, cq, rho) = (tr.f4(), tr.f4(), tr.f4());
    let r = f4s(tr, ntri)?;
    Ok((a, b, cl, cq, rho, r))
}

pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd: [u8; 32], p: &Params) -> Result<Vec<u8>, &'static str> {
    let rel = cs::rel_of(op, stmt).ok_or("op")?;
    prove_inner(op, stmt, wit, rnd, p, true, prover_limit(p, rel))
}

/// The prover's length limit: the verifier's bound; fallback A (feature `fallback-retry`, set (a) with THE preset): also
/// at most MAX_PROOF_PQZH, so the prover re-proves (fresh masks and salts) while a proof is longer. The length is a
/// function of the transcript's query indices alone, so the rejection keeps zero knowledge (the simulator rejection-
/// samples the same public event): docs/research/pqzh-set-a-proof-limit.md.
fn prover_limit(p: &Params, rel: Rel) -> usize {
    if cfg!(feature = "fallback-retry") {
        p.max_proof_len(rel).min(pqz_stmt::MAX_PROOF_PQZH)
    } else {
        p.max_proof_len(rel)
    }
}

/// Test hook: skips the honest prover's checks so that invalid witnesses reach the proof system (tests and `bench`
/// only: not in the production build).
#[cfg(any(test, feature = "bench"))]
pub fn prove_unchecked(op: u8, stmt: &[u8], wit: &[u8], rnd: [u8; 32], p: &Params) -> Result<Vec<u8>, &'static str> {
    let rel = cs::rel_of(op, stmt).ok_or("op")?;
    prove_inner(op, stmt, wit, rnd, p, false, p.max_proof_len(rel))
}

/// Proves; if the proof is longer than `limit` (the verifier's bound) it proves again with the RNG stream continued
/// (fresh masks and salts, so a fresh commitment, columns and multiproof), up to ATTEMPTS times (plan Task 9). A guard:
/// every proof is <= max_len_exact by construction (fixed polynomials, <= t distinct columns, the largest multiproof),
/// so with `limit` = max_proof_len the first attempt always returns; the unit test forces a lower limit.
fn prove_inner(op: u8, stmt: &[u8], wit: &[u8], rnd: [u8; 32], p: &Params, check: bool, limit: usize) -> Result<Vec<u8>, &'static str> {
    let mut rng = Rng::new(rnd, op, stmt, wit);
    for _ in 0..ATTEMPTS {
        let pf = prove_once(op, stmt, wit, p, check, &mut rng)?;
        if pf.len() <= limit {
            return Ok(pf);
        }
    }
    Err("proof length")
}

/// Every secret buffer is wiped on every exit (review P-C); the values that become public by design are marked for
/// the constant-time check where they do (review P-B, `ct::public`): the root, w, q, h, the opened columns.
fn prove_once(op: u8, stmt: &[u8], wit: &[u8], p: &Params, check: bool, rng: &mut Rng) -> Result<Vec<u8>, &'static str> {
    let st = cs::parse(op, stmt).ok_or("statement")?;
    let rel = cs::rel_of(op, stmt).ok_or("op")?;
    let lay = Layout::new(rel, p.ell);
    let w = cs::witness(rel, &st, wit, check)?;
    let rows = Wiped(cs::rows(&lay, &w));
    let (n, k, ell, m) = (p.n, p.k, p.ell, lay.m);
    let (hk, hn, h2) = (Domain::new(k), Domain::new(n), Domain::new(p.n2()));

    // witness rows: message on the first l points of H_k, uniform on the other k - l
    let pc = Wiped(
        rows.iter()
            .map(|r| {
                let mut v = Wiped(Vec::with_capacity(k));
                v.extend_from_slice(r);
                v.extend((ell..k).map(|_| rng.fq()));
                hk.ifft(&v)
            })
            .collect::<Vec<_>>(),
    );
    // blinding rows: u_0 uniform; u_lin uniform with sum over H_k = k (c_0 + c_k) = 0; u_quad = Z_zeta h_0
    let d2 = 2 * k - 1;
    let z = zeta_poly(&hk, ell);
    let take = |mut v: Wiped<Vec<Fq>>| std::mem::take(&mut *v);
    let u0: Wiped<P4> = Wiped(std::array::from_fn(|_| take(rng.vec(d2))));
    let ul: Wiped<P4> = Wiped(std::array::from_fn(|_| {
        let mut v = rng.vec(d2);
        v[0] = -v[k];
        take(v)
    }));
    let h0: Wiped<P4> = Wiped(std::array::from_fn(|_| take(rng.vec(d2 - ell))));
    let uq: Wiped<P4> = Wiped(std::array::from_fn(|s| mul_poly(&z, &h0[s])));

    // commit: rows evaluated on the coset 3 H_n; leaf j = keccak(salt_j || column j)
    let enc =
        Wiped(pc.iter().chain(u0.iter()).chain(ul.iter()).chain(uq.iter()).map(|c| hn.coset_fft(c, GEN)).collect::<Vec<_>>());
    let salts: Wiped<Vec<H>> = Wiped((0..n).map(|_| rng.salt()).collect());
    let col = |j: usize| {
        let mut b = Wiped(Vec::with_capacity((m + BLIND) * EB));
        for r in enc.iter() {
            r[j].put(&mut b);
        }
        b
    };
    let tree = Tree::new((0..n).map(|j| keccak(&[&salts[j], &col(j)])).collect());
    let root = tree.root();
    ct::public(&root); // the commitment (b1)

    let mut tr = Tr::new(op, stmt);
    tr.absorb(&root);
    let (ca, cb, cl, cq, rho, rq) = draw(&mut tr, m, lay.triples.len()).map_err(|_| "memory")?;

    // proximity: w = sum_i (a_i + b_i X^(k-1)) p_i + c_lin u_lin + c_quad u_quad + u_0
    let mut wp: Vec<F4> = (0..d2).map(|i| cl * get4(&ul, i) + cq * get4(&uq, i) + get4(&u0, i)).collect();
    for i in 0..m {
        for c in 0..k {
            wp[c] += ca[i] * pc[i][c];
            wp[c + k - 1] += cb[i] * pc[i][c];
        }
    }
    ct::public(&wp[..]); // a proof field (b2)

    // linear: q = sum_i R_i p_i + u_lin, products on H_N2 (N2 >= 2k - 1)
    let comb = cs::comb(&lay, &st, rho).map_err(|_| "memory")?;
    let n2 = h2.n;
    let pe = Wiped(pc.iter().map(|c| h2.fft(c)).collect::<Vec<_>>());
    let mut qe = Wiped(vec![Acc4::default(); n2]);
    let fft4 = |c: &P4| -> P4 { std::array::from_fn(|s| h2.fft(&c[s])) };
    for i in 0..m {
        if let Some(v) = &comb.own[i] {
            let re = fft4(&interp(&hk, v));
            for x in 0..n2 {
                qe[x].add(&get4(&re, x), pe[i][x]);
            }
        }
    }
    let mut beta = vec![F4::ONE; ell];
    for c in 1..ell {
        beta[c] = beta[c - 1] * rho;
    }
    let mut qe = Wiped(qe.iter().map(|a| a.get()).collect::<Vec<F4>>());
    for (vec, sc) in [(beta, &comb.beta), (vec![F4::ONE; ell], &comb.ones)] {
        let re = fft4(&interp(&hk, &vec));
        let mut s = Wiped(vec![Acc4::default(); n2]);
        for i in (0..m).filter(|&i| sc[i] != F4::ZERO) {
            for x in 0..n2 {
                s[x].add(&sc[i], pe[i][x]);
            }
        }
        for x in 0..n2 {
            qe[x] += get4(&re, x) * s[x].get();
        }
    }
    let ifft4 = |e: &[F4]| -> Wiped<P4> {
        Wiped(std::array::from_fn(|s| h2.ifft(&Wiped(e.iter().map(|v| v.0[s]).collect::<Vec<_>>()))))
    };
    let qc = ifft4(&qe);
    let qp: Vec<F4> = (0..d2).map(|i| get4(&qc, i) + get4(&ul, i)).collect();
    ct::public(&qp[..]); // a proof field (b2)
    if check && (qp[0] + qp[k]) * Fq(k as u64) != comb.rhs {
        return Err("linear constraints");
    }

    // quadratic: (sum_t r_t (p_x p_y - p_z) + u_quad) / Z_zeta = h' + h_0
    let mut pq = Wiped(vec![Acc4::default(); n2]);
    for (t, &(x, y, zr)) in lay.triples.iter().enumerate() {
        for i in 0..n2 {
            pq[i].add(&rq[t], pe[x][i] * pe[y][i] - pe[zr][i]);
        }
    }
    let pq = Wiped(pq.iter().map(|a| a.get()).collect::<Vec<F4>>());
    let pc0 = ifft4(&pq);
    let mut rem = Wiped((0..d2).map(|i| get4(&pc0, i)).collect::<Vec<F4>>());
    let mut hp = vec![F4::ZERO; d2 - ell];
    for i in (0..d2 - ell).rev() {
        let c = rem[i + ell];
        hp[i] = c + get4(&h0, i);
        for (j, &zj) in z.iter().enumerate() {
            rem[i + j] -= c * zj;
        }
    }
    ct::public(&hp[..]); // a proof field (b2)
    // the prover's self-check: zero for every valid witness (b5)
    if check && ct::verdict(rem.iter().fold(0, |a, v| v.0.iter().fold(a, |a, c| a | c.0)) != 0) {
        return Err("quadratic constraints");
    }

    let mut out = root.to_vec();
    for v in wp.iter().chain(&qp).chain(&hp) {
        v.put(&mut out);
    }
    tr.absorb(&out[32..]);
    let nonce = (0u64..).find(|&x| tr.pow_ok(x, p.pow_bits)).unwrap();
    out.extend_from_slice(&nonce.to_be_bytes());
    tr.absorb(&nonce.to_be_bytes());
    let mut idx: Vec<usize> = (0..p.t).map(|_| tr.index(n)).collect();
    idx.sort_unstable();
    idx.dedup();
    for &j in &idx {
        out.extend_from_slice(&salts[j]);
        out.extend_from_slice(&col(j));
    }
    for h in tree.multiproof(&idx) {
        out.extend_from_slice(&h);
    }
    ct::public(&out[..]); // the opened columns, their salts and the multiproof (b3)
    Ok(out)
}

struct Rd<'a>(&'a [u8]);
impl<'a> Rd<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    /// n F_q^4 elements: Ok(None) if malformed (the buffer reserved fallibly, review P-D)
    fn f4s(&mut self, n: usize) -> Result<Option<Vec<F4>>, Oom> {
        let mut v = try_vec(n)?;
        for _ in 0..n {
            match self.take(FB).and_then(F4::get) {
                Some(x) => v.push(x),
                None => return Ok(None),
            }
        }
        Ok(Some(v))
    }
}

/// Panics caught by `verify` (diagnostics; wasm32 aborts on panic instead).
pub static VERIFY_PANICS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// true = valid; anything else (malformed, wrong length, failed check, panic, out of memory) = false
pub fn verify(op: u8, stmt: &[u8], proof: &[u8], p: &Params) -> bool {
    try_verify(op, stmt, proof, p) == Ok(true)
}

/// [`verify`] with out-of-memory kept apart (review P-D, as PQZL's `Ctx::try_verify`): `Ok(verdict)`, or `Err(Oom)`
/// when one of the verifier's buffers sized by the parameters and the relation (the decoded proof, the opened columns,
/// the domains, the challenges, the linear test's combination vectors, the per-column evaluation buffers) could not
/// be reserved: a fault of the machine, not of the input, which pqz-ffi reports as `NodeFault`. Not covered (still an
/// abort on allocation failure): the decoded statement polynomials (no larger than the statement the caller already
/// holds), the layout tables (a few KB), the shared matrix A (512 KiB, built once per process at first use, `cs.rs`), and allocations
/// inside std / sha3.
pub fn try_verify(op: u8, stmt: &[u8], proof: &[u8], p: &Params) -> Result<bool, Oom> {
    std::panic::catch_unwind(|| verify_inner(op, stmt, proof, p)).unwrap_or_else(|_| {
        VERIFY_PANICS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(false)
    })
}

/// the value, or the verdict false
macro_rules! ok {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => return Ok(false),
        }
    };
}

/// evaluations at x of polynomials with F_q^4 coefficients, lazily accumulated against the powers of x
fn eval4(c: &[F4], xp: &[Fq]) -> F4 {
    let mut a = Acc4::default();
    for (v, &x) in c.iter().zip(xp) {
        a.add(v, x);
    }
    a.get()
}

fn verify_inner(op: u8, stmt: &[u8], proof: &[u8], p: &Params) -> Result<bool, Oom> {
    let rel = ok!(cs::rel_of(op, stmt));
    if !p.proof_len_ok(rel, proof.len()) {
        return Ok(false);
    }
    let st = ok!(cs::parse(op, stmt));
    let lay = Layout::new(rel, p.ell);
    let (n, k, ell, m) = (p.n, p.k, p.ell, lay.m);
    let d2 = 2 * k - 1;
    let mut rd = Rd(proof);
    let root: H = ok!(ok!(rd.take(32)).try_into().ok());
    let polys = &proof[32..32 + p.poly_bytes().min(proof.len() - 32)];
    let wp = ok!(rd.f4s(d2)?);
    let qp = ok!(rd.f4s(d2)?);
    let hp = ok!(rd.f4s(d2 - ell)?);
    let nonce = ok!(rd.take(8));

    let mut tr = Tr::new(op, stmt);
    tr.absorb(&root);
    let (ca, cb, cl, cq, rho, rq) = draw(&mut tr, m, lay.triples.len())?;
    tr.absorb(polys);
    if !tr.pow_ok(u64::from_be_bytes(ok!(nonce.try_into().ok())), p.pow_bits) {
        return Ok(false);
    }
    tr.absorb(nonce);
    let mut idx: Vec<usize> = (0..p.t).map(|_| tr.index(n)).collect();
    idx.sort_unstable();
    idx.dedup();

    let w = m + BLIND;
    let mut cols = try_vec(idx.len())?;
    let mut leaves = Vec::with_capacity(idx.len());
    for &j in &idx {
        let salt = ok!(rd.take(32));
        let b = ok!(rd.take(w * EB));
        let mut c = try_vec(w)?;
        for e in b.chunks(EB) {
            c.push(ok!(Fq::get(e)));
        }
        leaves.push((j, keccak(&[salt, b])));
        cols.push(c);
    }
    if ok!(root_from(leaves, depth(n), || rd.take(32).map(|h| h.try_into().unwrap()))) != root || !rd.0.is_empty() {
        return Ok(false);
    }

    // linear test: sum over H_k of q = k (q_0 + q_k) = r^T b
    let comb: Comb = cs::comb(&lay, &st, rho)?;
    if (qp[0] + qp[k]) * Fq(k as u64) != comb.rhs {
        return Ok(false);
    }
    let (hk, hn) = (Domain::try_new(k)?, Domain::try_new(n)?);
    let own: Vec<(usize, &Vec<F4>)> = comb.own.iter().enumerate().filter_map(|(i, v)| v.as_ref().map(|v| (i, v))).collect();
    let mut beta = try_vec(ell)?;
    beta.push(F4::ONE);
    for c in 1..ell {
        beta.push(beta[c - 1] * rho);
    }
    let k_inv = Fq(k as u64).inv();
    // per-column buffers, reserved once
    let (mut xp, mut dif, mut lc) = (try_vec(d2)?, try_vec(ell)?, try_vec(ell)?);
    for (&j, u) in idx.iter().zip(&cols) {
        let eta = GEN * hn.w[j];
        xp.clear();
        let mut x = Fq::ONE;
        for _ in 0..d2 {
            xp.push(x);
            x = x * eta;
        }
        let (we, qe, he) = (eval4(&wp, &xp), eval4(&qp, &xp), eval4(&hp, &xp));
        let blind = |b: usize| F4([u[m + 4 * b], u[m + 4 * b + 1], u[m + 4 * b + 2], u[m + 4 * b + 3]]);
        let (b0, bl, bq) = (blind(0), blind(1), blind(2));

        // proximity
        let (mut sa, mut sb) = (Acc4::default(), Acc4::default());
        for i in 0..m {
            sa.add(&ca[i], u[i]);
            sb.add(&cb[i], u[i]);
        }
        if we != sa.get() + sb.get() * xp[k - 1] + cl * bl + cq * bq + b0 {
            return Ok(false);
        }

        // Lagrange basis of H_k at eta: L_c = omega^c (eta^k - 1) / (k (eta - omega^c)); Z_zeta(eta) on the way
        dif.clear();
        dif.extend((0..ell).map(|c| eta - hk.w[c]));
        let (inv, zeta) = batch_inv(&dif)?;
        let s = (xp[k] - Fq::ONE) * k_inv;
        lc.clear();
        lc.extend((0..ell).map(|c| hk.w[c] * inv[c] * s));
        let r_at = |v: &[F4]| {
            let mut a = Acc4::default();
            for (x, &l) in v.iter().zip(&lc) {
                a.add(x, l);
            }
            a.get()
        };
        let mut acc = F4::ZERO;
        for &(i, v) in &own {
            acc += r_at(v) * u[i];
        }
        let (mut sbeta, mut sones) = (Acc4::default(), Acc4::default());
        for i in 0..m {
            sbeta.add(&comb.beta[i], u[i]);
            sones.add(&comb.ones[i], u[i]);
        }
        let ones_at = lc.iter().fold(Fq::ZERO, |a, &l| a + l);
        if qe != acc + r_at(&beta) * sbeta.get() + sones.get() * ones_at + bl {
            return Ok(false);
        }

        // quadratic
        let mut qa = Acc4::default();
        for (t, &(x, y, z)) in lay.triples.iter().enumerate() {
            qa.add(&rq[t], u[x] * u[y] - u[z]);
        }
        if he * zeta != qa.get() + bq {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---- research spike (plan 5h Task 8c spike A, 2026-10-22; throwaway, kept as the record): a prover limit below the
// verifier's bound (MAX_PROOF_PQZH at set (a)) and what the proof length depends on. Feature `bench` only. ----

/// honest proving with `limit` (as `prove_inner`), returning every attempt's proof (the last one is the accepted one
/// when it is <= limit)
#[cfg(feature = "bench")]
pub fn spike_prove_attempts(op: u8, stmt: &[u8], wit: &[u8], rnd: [u8; 32], p: &Params, limit: usize) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut rng = Rng::new(rnd, op, stmt, wit);
    let mut out = Vec::new();
    for _ in 0..ATTEMPTS {
        let pf = prove_once(op, stmt, wit, p, true, &mut rng)?;
        let ok = pf.len() <= limit;
        out.push(pf);
        if ok {
            return Ok(out);
        }
    }
    Err("proof length")
}

/// the query indices a proof's transcript draws (`verify_inner`'s first steps: statement, root, the challenges, the
/// test polynomials, the nonce), sorted and distinct
#[cfg(feature = "bench")]
pub fn spike_query_indices(op: u8, stmt: &[u8], proof: &[u8], p: &Params) -> Vec<usize> {
    let rel = cs::rel_of(op, stmt).expect("op");
    let lay = Layout::new(rel, p.ell);
    let mut tr = Tr::new(op, stmt);
    tr.absorb(&proof[..32]);
    let _ = draw(&mut tr, lay.m, lay.triples.len()).expect("memory");
    tr.absorb(&proof[32..32 + p.poly_bytes()]);
    let nonce = &proof[32 + p.poly_bytes()..40 + p.poly_bytes()];
    tr.absorb(nonce);
    let mut idx: Vec<usize> = (0..p.t).map(|_| tr.index(p.n)).collect();
    idx.sort_unstable();
    idx.dedup();
    idx
}

/// the proof length as a function of the sorted distinct query indices only: root, test polynomials, nonce, one salt
/// and column per index, and the pruned multiproof's digest count (merkle.rs: one sibling per node whose sibling is
/// not itself on the path)
#[cfg(feature = "bench")]
pub fn spike_len_of(rel: impl Into<Rel>, idx: &[usize], p: &Params) -> usize {
    let m = Layout::new(rel, p.ell).m;
    let mut cur = idx.to_vec();
    let mut sib = 0;
    for _ in 0..depth(p.n) {
        let mut next = Vec::with_capacity(cur.len());
        let mut i = 0;
        while i < cur.len() {
            let x = cur[i];
            if x % 2 == 0 && i + 1 < cur.len() && cur[i + 1] == x + 1 {
                i += 2;
            } else {
                sib += 1;
                i += 1;
            }
            next.push(x / 2);
        }
        cur = next;
    }
    32 + p.poly_bytes() + 8 + idx.len() * (32 + (m + BLIND) * EB) + 32 * sib
}

/// soundness bits per term: (name, bits); "total" combines them
#[cfg(feature = "bench")]
pub fn soundness(op: u8, stmt: &[u8], p: &Params) -> Vec<(&'static str, f64)> {
    let lay = Layout::new(cs::rel_of(op, stmt).expect("op"), p.ell);
    let nw = cs::parse(op, stmt).map(|st| cs::comb(&lay, &st, F4::ONE).expect("memory").nweights).unwrap_or(0);
    let fbits = 4.0 * ((crate::fq::Q) as f64).log2();
    let (f, prox) = if p.johnson {
        let (f, jb) = factor_johnson(p.n, p.k);
        (f, jb) // BCIKS20 list-decoding error charged once for the affine space (per word: jb - log2(2m + 3))
    } else {
        (factor(p.n, p.k, p.proven), fbits - ((2 * lay.m + 3) as f64 * p.n as f64).log2())
    };
    let q = p.t as f64 * -f.log2() + p.pow_bits as f64;
    let terms = vec![
        ("query", q),
        ("proximity_field", prox),
        ("linear_field", fbits - (nw as f64).log2()),
        ("quadratic_field", fbits),
        ("keccak_collision", 128.0),
    ];
    let tot = -terms.iter().map(|(_, b)| (-b).exp2()).sum::<f64>().log2();
    let mut out = terms;
    out.push(("total", tot));
    out
}

/// byte breakdown of a proof
#[cfg(feature = "bench")]
pub fn breakdown(rel: impl Into<Rel>, proof: &[u8], p: &Params) -> Vec<(&'static str, usize)> {
    let m = Layout::new(rel, p.ell).m;
    let polys = p.poly_bytes();
    let rest = proof.len().saturating_sub(32 + polys + 8);
    let cw = 32 + (m + BLIND) * EB;
    // columns are a multiple of cw, the multiproof of 32: d columns with d cw + 32 s = rest, d <= t
    let d = (0..=p.t).rev().find(|&d| d * cw <= rest && (rest - d * cw) % 32 == 0 && (rest - d * cw) / 32 <= p.t * depth(p.n)).unwrap_or(0);
    vec![
        ("total", proof.len()),
        ("root_nonce", 40),
        ("test_polys", polys),
        ("columns", d * cw),
        ("distinct_columns", d),
        ("rows_m", m),
        ("merkle", rest - d * cw),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cs::RELS;
    use pqz_stmt::Form;

    /// THE preset written out is the parameter model's
    #[cfg(feature = "bench")]
    #[test]
    fn proven_is_the_model() {
        // the model's t (128 bits of query and grinding) is the least; a set may take more (set (a) preset B: 120 over
        // the model's 119, owner 2026-10-22)
        let m = Params::new(crate::set::PRESET_N, crate::set::PRESET_K, true);
        let t = crate::set::PRESET_T;
        assert_eq!(Params::proven(), Params { t, ell: m.k - t - 1, ..m });
        assert!(m.t <= t);
        assert_eq!(m.t == t, crate::set::NAME == "n2048-kmax1024" || cfg!(feature = "fallback-retry"));
    }

    /// D6: the same rnd32, op and statement with another witness give unrelated masks; equal inputs, equal masks
    #[test]
    fn rng_hedged_with_witness() {
        let (st, w) = (vec![7u8; 100], vec![1u8; 64]);
        let mut w2 = w.clone();
        w2[63] ^= 1;
        let draw = |w: &[u8]| Rng::new([3; 32], 1, &st, w).vec(256).to_vec();
        let (a, b) = (draw(&w), draw(&w2));
        assert_eq!(a, draw(&w));
        // no position agrees (each with probability 1/q)
        assert!(a.iter().zip(&b).all(|(x, y)| x != y));
        // the statement length is framed: moving a byte from the statement to the witness changes the stream
        assert_ne!(Rng::new([3; 32], 1, &st[..99], &[&st[99..], &w[..]].concat()).vec(4)[..], draw(&w)[..4]);
    }

    /// max_len_exact: the multiproof term is reached (evenly spread columns) and never exceeded (random sets)
    #[test]
    fn max_len_exact_multiproof_tight() {
        let p = Params::proven();
        let (n, t) = (p.n, p.t);
        let tree = Tree::new((0..n as u32).map(|i| keccak(&[&i.to_be_bytes()])).collect());
        let worst = (1..depth(n)).map(|l| t.min(n.div_ceil(1 << l))).sum::<usize>() + 2 - t;
        // evenly spread columns from the left or (set (a) preset B, n 45,752: the left spread reaches worst - 1) from the
        // right
        let left: Vec<usize> = (0..t).map(|i| i * n / t).collect();
        let mut right: Vec<usize> = (0..t).map(|i| n - 1 - i * n / t).collect();
        right.sort_unstable();
        let spread = if tree.multiproof(&right).len() > tree.multiproof(&left).len() { right } else { left };
        assert_eq!(tree.multiproof(&spread).len(), worst);
        let mut x = 0x9E3779B97F4A7C15u64;
        for _ in 0..300 {
            let mut idx: Vec<usize> = (0..t)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (x % n as u64) as usize
                })
                .collect();
            idx.sort_unstable();
            idx.dedup();
            assert!(tree.multiproof(&idx).len() <= worst);
        }
        for f in RELS {
            assert!(p.max_len_exact(f) < p.max_len(f));
            // the bound is the proof grammar at t evenly spread columns: root, polynomials, nonce, t columns, the
            // spread set's multiproof
            let cw = 32 + (Layout::new(f, p.ell).m + BLIND) * EB;
            assert_eq!(32 + p.poly_bytes() + 8 + t * cw + 32 * tree.multiproof(&spread).len(), p.max_len_exact(f));
        }
    }

    /// Task 9 / D5: the verifier's bound is the exact maximum, the length gate admits MAX and rejects MAX + 1 (and 0)
    /// before the statement or the proof is parsed; ops without a relation have no form. Per parameter set (plan 5h
    /// Task 8c): v3 every built relation within MAX_PROOF_PQZH and MAX_INPUT (D5); set (a) R_REG / R_DS / R_DR within,
    /// every debit form's bound above MAX_PROOF_PQZH 262,144 (owner 2026-10-21: it stays; PQZH is a backup, its debit
    /// inputs exceed one transaction's calldata anyway: ligero_params.py --set, PQZH.md of the set)
    #[test]
    fn limits_exact() {
        use pqz_stmt::{MAX_INPUT, MAX_PROOF_PQZH};
        let p = Params::proven();
        let v3 = crate::set::NAME == "n2048-kmax1024";
        // (form, exact bound, within MAX_PROOF_PQZH and MAX_INPUT)
        // set (a) with preset B (n 45,752, k 952, t 120; owner 2026-10-22); the fallback build keeps THE preset
        let b = !v3 && !cfg!(feature = "fallback-retry");
        let expect = if b {
            [
                (Form::Register, 207_688, true),
                (Form::Transfer, 251_608, true),
                (Form::Burn, 251_608, true),
                (Form::DiscloseSender, 207_688, true),
                (Form::DiscloseReceiver, 207_688, true),
                (Form::Transfer0, 251_608, true),
            ]
        } else if v3 {
            [
                (Form::Register, 190_458, true),
                (Form::Transfer, 235_470, true),
                (Form::Burn, 234_744, true),
                (Form::DiscloseSender, 190_458, true),
                (Form::DiscloseReceiver, 190_458, true),
                (Form::Transfer0, 234_744, true),
            ]
        } else {
            [
                (Form::Register, 204_978, true),
                (Form::Transfer, 264_510, false),
                (Form::Burn, 263_784, false),
                (Form::DiscloseSender, 204_978, true),
                (Form::DiscloseReceiver, 204_978, true),
                (Form::Transfer0, 263_784, false),
            ]
        };
        assert_eq!(expect.map(|e| e.0), RELS);
        for (f, max, fits) in expect {
            assert_eq!((p.max_len_exact(f), p.max_proof_len(f)), (max, max));
            assert_eq!(max <= MAX_PROOF_PQZH && 5 + f.stmt_len() + max <= MAX_INPUT, fits, "{f:?}");
            assert!(p.proof_len_ok(f, max) && p.proof_len_ok(f, 1));
            assert!(!p.proof_len_ok(f, max + 1) && !p.proof_len_ok(f, 0));
            assert_eq!(cs::form_of(f.op(), f.stmt_len()), Some(f));
        }
        assert!([0, 6, 7, 255].iter().all(|&op| cs::form_of(op, 0).is_none()));
        // op 7 R_TXM, (M, auditorOn): exact bounds and inputs 5 + statement + bound (v3 = the pre-review H-3 table,
        // measured max_len_exact in runs/l16-txm-*; set (a): runs/c8-a-sizes.jsonl); v3's built shapes (M <= 4)
        // within MAX_PROOF_PQZH and MAX_INPUT, the oversize ones above; set (a): every shape above MAX_PROOF_PQZH
        let multi = if b {
            [
                ((1, true), 251_608, 344_925),
                ((1, false), 251_608, 326_365),
                ((2, true), 252_328, 364_333),
                ((2, false), 251_608, 344_925),
                ((4, true), 253_048, 402_429),
                ((4, false), 252_328, 382_765),
                ((8, true), 296_968, 539_533),
                ((8, false), 296_248, 519_357),
                ((16, true), 387_688, 816_621),
                ((16, false), 384_088, 792_541),
            ]
        } else if v3 {
            [
                ((1, true), 235_470, 318_547),
                ((1, false), 234_744, 301_309),
                ((2, true), 235_470, 335_187),
                ((2, false), 235_470, 318_547),
                ((4, true), 236_196, 369_193),
                ((4, false), 235_470, 351_571),
                ((8, true), 281_208, 497_149),
                ((8, false), 279_756, 478_289),
                ((16, true), 372_684, 754_513),
                ((16, false), 369_054, 732_451),
            ]
        } else {
            [
                ((1, true), 264_510, 357_827),
                ((1, false), 263_784, 338_541),
                ((2, true), 264_510, 376_515),
                ((2, false), 264_510, 357_827),
                ((4, true), 265_236, 414_617),
                ((4, false), 264_510, 394_947),
                ((8, true), 324_768, 567_333),
                ((8, false), 324_042, 547_151),
                ((16, true), 445_284, 874_217),
                ((16, false), 441_654, 850_107),
            ]
        };
        for ((m, aud), max, input) in multi {
            let r = Rel::Multi { m, aud };
            assert_eq!((p.max_len_exact(r), p.max_proof_len(r), 5 + r.stmt_len() + max), (max, max, input), "M {m} {aud}");
            // preset B: every built shape within MAX_PROOF_PQZH; M = 4 auditor on above today's MAX_INPUT (512 KiB in 8d)
            let fits = if b { m <= 4 && !(m == 4 && aud) } else { v3 && m <= 4 };
            assert_eq!(max <= MAX_PROOF_PQZH && input <= MAX_INPUT, fits, "M {m} {aud}");
            assert!(p.proof_len_ok(r, max) && !p.proof_len_ok(r, max + 1) && !p.proof_len_ok(r, 0));
        }
        let built = cs::multi_rels();
        let want: Vec<Rel> = multi
            .iter()
            .filter(|e| e.0.0 <= 4 || cfg!(feature = "oversize"))
            .map(|&((m, aud), _, _)| Rel::Multi { m, aud })
            .collect();
        assert!(built.len() == want.len() && want.iter().all(|r| built.contains(r)));
    }

    /// Task 9: a proof over the limit is proved again from the continued RNG stream; the first attempt is `prove`'s
    #[cfg(feature = "bench")]
    #[test]
    fn prover_retries_over_limit() {
        let s = crate::client::setup();
        let (op, st, w, p) = (pqz_stmt::OP_REGISTER, &s.reg_stmt, &s.reg_wit, Params::proven());
        // the seed (of 1..=4) with the longest proof, so that a shorter one is a likely retry (v3: seed 1 already is;
        // set (a)'s seed 1 proof was shorter than its 16 retries)
        let rnd = (1..=4u8).max_by_key(|&x| prove(op, st, w, [x; 32], &p).unwrap().len()).unwrap();
        let a = prove_inner(op, st, w, [rnd; 32], &p, true, p.max_proof_len(Form::Register)).unwrap();
        assert_eq!(a, prove(op, st, w, [rnd; 32], &p).unwrap());
        let b = prove_inner(op, st, w, [rnd; 32], &p, true, a.len() - 1).unwrap();
        assert!(b.len() < a.len() && b[..32] != a[..32]);
        assert!(verify(op, st, &a, &p) && verify(op, st, &b, &p));
        assert_eq!(prove_inner(op, st, w, [rnd; 32], &p, true, 32), Err("proof length"));
    }
}
