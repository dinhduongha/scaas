//! Bulletproofs range proof (Bünz et al. 2018 §4.2 + inner-product argument), byte-exact per
//! zether-design §8–§9. Proves `V = [v]G + [γ]Hb` with `v ∈ [0, 2^n)`, `n ∈ {32, 64}`.
//! Challenges come from the caller's transcript so Sigma + both range proofs share one.

use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};

use crate::curve::{decode_point, decode_scalar, encode_point, encode_scalar, generator, point_len, Fr, ZCurve, G};
use crate::nonce::Nonces;
use crate::transcript::Transcript;
use crate::ZError;

pub const NMAX: usize = 64;

/// Generators (zether-design §3): `g` = curve generator, `h` = `Hb` (label `"h"`), `u` = `U`,
/// `gs`/`hs` = `G_i`/`H_i`, `i < 64`; `n = 32` uses the prefix.
#[derive(Clone)]
pub struct Gens<C: ZCurve> {
    pub g: G<C>,
    pub h: G<C>,
    pub u: G<C>,
    pub gs: Vec<G<C>>,
    pub hs: Vec<G<C>>,
}

impl<C: ZCurve> Gens<C> {
    pub fn new() -> Self {
        Self {
            g: generator::<C>(),
            h: C::gen(b"h", 0),
            u: C::gen(b"U", 0),
            gs: (0..NMAX as u32).map(|i| C::gen(b"G", i)).collect(),
            hs: (0..NMAX as u32).map(|i| C::gen(b"H", i)).collect(),
        }
    }

    /// `Hb ‖ U ‖ G_0 … G_63 ‖ H_0 … H_63` — the verifier's SSTORE2 blob.
    pub fn blob(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(130 * point_len::<C>());
        for p in [&self.h, &self.u].into_iter().chain(&self.gs).chain(&self.hs) {
            b.extend_from_slice(&encode_point::<C>(p));
        }
        b
    }
}

impl<C: ZCurve> Default for Gens<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RangeProof<C: ZCurve> {
    pub a: G<C>,
    pub s: G<C>,
    pub t1: G<C>,
    pub t2: G<C>,
    pub ls: Vec<G<C>>,
    pub rs: Vec<G<C>>,
    pub taux: Fr<C>,
    pub mu: Fr<C>,
    pub t_hat: Fr<C>,
    pub ipa_a: Fr<C>,
    pub ipa_b: Fr<C>,
}

impl<C: ZCurve> RangeProof<C> {
    /// `A ‖ S ‖ T1 ‖ T2 ‖ L_1 ‖ R_1 ‖ … ‖ L_k ‖ R_k ‖ τ_x ‖ μ ‖ t̂ ‖ a ‖ b`.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        for p in [&self.a, &self.s, &self.t1, &self.t2] {
            b.extend_from_slice(&encode_point::<C>(p));
        }
        for (l, r) in self.ls.iter().zip(&self.rs) {
            b.extend_from_slice(&encode_point::<C>(l));
            b.extend_from_slice(&encode_point::<C>(r));
        }
        for s in [&self.taux, &self.mu, &self.t_hat, &self.ipa_a, &self.ipa_b] {
            b.extend_from_slice(&encode_scalar::<C>(s));
        }
        b
    }

    pub fn wire_len(n: usize) -> usize {
        (4 + 2 * n.trailing_zeros() as usize) * point_len::<C>() + 160
    }

    pub fn decode(n: usize, b: &[u8]) -> Result<Self, ZError> {
        if b.len() != Self::wire_len(n) {
            return Err(ZError::BadProof("range proof length"));
        }
        let pl = point_len::<C>();
        let pt = |i: usize| decode_point::<C>(&b[i * pl..(i + 1) * pl]);
        let k = n.trailing_zeros() as usize;
        let off = (4 + 2 * k) * pl;
        let sc = |i: usize| decode_scalar::<C>(&b[off + 32 * i..off + 32 * i + 32]);
        Ok(Self {
            a: pt(0)?,
            s: pt(1)?,
            t1: pt(2)?,
            t2: pt(3)?,
            ls: (0..k).map(|j| pt(4 + 2 * j)).collect::<Result<_, _>>()?,
            rs: (0..k).map(|j| pt(5 + 2 * j)).collect::<Result<_, _>>()?,
            taux: sc(0)?,
            mu: sc(1)?,
            t_hat: sc(2)?,
            ipa_a: sc(3)?,
            ipa_b: sc(4)?,
        })
    }
}

fn powers<C: ZCurve>(x: Fr<C>, n: usize) -> Vec<Fr<C>> {
    let mut v = Vec::with_capacity(n);
    let mut cur = Fr::<C>::one();
    for _ in 0..n {
        v.push(cur);
        cur *= x;
    }
    v
}

fn inner<C: ZCurve>(a: &[Fr<C>], b: &[Fr<C>]) -> Fr<C> {
    a.iter().zip(b).map(|(x, y)| *x * y).sum()
}

pub(crate) fn msm<C: ZCurve>(bases: &[G<C>], scalars: &[Fr<C>]) -> G<C> {
    G::<C>::msm(&G::<C>::normalize_batch(bases), scalars).expect("equal lengths")
}

/// Challenge that the verifier rejects when zero; the prover fails the same way
/// (probability ~2^-254, the caller retries with fresh nonces).
pub(crate) fn nz_challenge<C: ZCurve>(tr: &mut Transcript, label: &str) -> Result<Fr<C>, ZError> {
    let c = tr.challenge::<C>(label);
    if c.is_zero() {
        return Err(ZError::Verify("zero challenge"));
    }
    Ok(c)
}

/// `v < 2^n` as a field element.
pub fn in_range<C: ZCurve>(v: &Fr<C>, n: usize) -> bool {
    v.into_bigint().to_bits_le().iter().skip(n).all(|b| !b)
}

/// Prove `v ∈ [0, 2^n)`. Refuses an out-of-range witness.
pub fn prove<C: ZCurve>(
    tr: &mut Transcript,
    gens: &Gens<C>,
    n: usize,
    v: &Fr<C>,
    gamma: &Fr<C>,
    nonces: &mut Nonces,
) -> Result<RangeProof<C>, ZError> {
    if !in_range::<C>(v, n) {
        return Err(ZError::OutOfRange);
    }
    prove_unchecked(tr, gens, n, v, gamma, nonces)
}

/// [`prove`] without the witness range check: the bits are the low `n` bits of `v`.
/// Exists so tests can show that a cheating prover's proof is rejected.
#[doc(hidden)]
pub fn prove_unchecked<C: ZCurve>(
    tr: &mut Transcript,
    gens: &Gens<C>,
    n: usize,
    v: &Fr<C>,
    gamma: &Fr<C>,
    nonces: &mut Nonces,
) -> Result<RangeProof<C>, ZError> {
    assert!(n == 32 || n == 64);
    let one = Fr::<C>::one();
    let bits = v.into_bigint().to_bits_le();
    let a_l: Vec<Fr<C>> = (0..n).map(|i| if bits[i] { one } else { Fr::<C>::zero() }).collect();
    let a_r: Vec<Fr<C>> = a_l.iter().map(|b| *b - one).collect();
    let (gs, hs) = (&gens.gs[..n], &gens.hs[..n]);

    let alpha = nonces.next::<C>();
    let rho = nonces.next::<C>();
    let tau1 = nonces.next::<C>();
    let tau2 = nonces.next::<C>();
    let s_l: Vec<Fr<C>> = (0..n).map(|_| nonces.next::<C>()).collect();
    let s_r: Vec<Fr<C>> = (0..n).map(|_| nonces.next::<C>()).collect();
    let a = gens.h * alpha + msm(gs, &a_l) + msm(hs, &a_r);
    let s = gens.h * rho + msm(gs, &s_l) + msm(hs, &s_r);
    let mut d = (n as u32).to_be_bytes().to_vec();
    d.extend(encode_point::<C>(&a));
    d.extend(encode_point::<C>(&s));
    tr.absorb("bp.AS", &d);
    let y = nz_challenge::<C>(tr, "bp.y")?;
    let z = nz_challenge::<C>(tr, "bp.z")?;

    let yn = powers::<C>(y, n);
    let twon = powers::<C>(Fr::<C>::from(2u64), n);
    let z2 = z * z;
    let l0: Vec<Fr<C>> = a_l.iter().map(|x| *x - z).collect();
    let l1 = s_l;
    let r0: Vec<Fr<C>> = (0..n).map(|i| yn[i] * (a_r[i] + z) + z2 * twon[i]).collect();
    let r1: Vec<Fr<C>> = (0..n).map(|i| yn[i] * s_r[i]).collect();
    let t1 = inner::<C>(&l0, &r1) + inner::<C>(&l1, &r0);
    let t2 = inner::<C>(&l1, &r1);
    let t1p = gens.g * t1 + gens.h * tau1;
    let t2p = gens.g * t2 + gens.h * tau2;
    let mut d = encode_point::<C>(&t1p);
    d.extend(encode_point::<C>(&t2p));
    tr.absorb("bp.T", &d);
    let x = nz_challenge::<C>(tr, "bp.x")?;

    let l: Vec<Fr<C>> = (0..n).map(|i| l0[i] + l1[i] * x).collect();
    let r: Vec<Fr<C>> = (0..n).map(|i| r0[i] + r1[i] * x).collect();
    let t_hat = inner::<C>(&l, &r);
    let taux = tau2 * x * x + tau1 * x + z2 * gamma;
    let mu = alpha + rho * x;
    let mut d = encode_scalar::<C>(&taux).to_vec();
    d.extend(encode_scalar::<C>(&mu));
    d.extend(encode_scalar::<C>(&t_hat));
    tr.absorb("bp.t", &d);
    let w = nz_challenge::<C>(tr, "bp.w")?;
    let q = gens.u * w;

    // IPA with H'_i = [y^{-i}]H_i.
    let yinvn = powers::<C>(y.inverse().expect("y != 0"), n);
    let mut gv: Vec<G<C>> = gs.to_vec();
    let mut hv: Vec<G<C>> = hs.iter().zip(&yinvn).map(|(h, s)| *h * s).collect();
    let (mut av, mut bv) = (l, r);
    let (mut ls, mut rs) = (vec![], vec![]);
    while av.len() > 1 {
        let m = av.len() / 2;
        let (a_lo, a_hi) = av.split_at(m);
        let (b_lo, b_hi) = bv.split_at(m);
        let (g_lo, g_hi) = gv.split_at(m);
        let (h_lo, h_hi) = hv.split_at(m);
        let lp = msm(g_hi, a_lo) + msm(h_lo, b_hi) + q * inner::<C>(a_lo, b_hi);
        let rp = msm(g_lo, a_hi) + msm(h_hi, b_lo) + q * inner::<C>(a_hi, b_lo);
        let mut d = encode_point::<C>(&lp);
        d.extend(encode_point::<C>(&rp));
        tr.absorb("ipa.LR", &d);
        let u = nz_challenge::<C>(tr, "ipa.u")?;
        let ui = u.inverse().expect("u != 0");
        let na = (0..m).map(|i| a_lo[i] * u + a_hi[i] * ui).collect();
        let nb = (0..m).map(|i| b_lo[i] * ui + b_hi[i] * u).collect();
        let ng = (0..m).map(|i| g_lo[i] * ui + g_hi[i] * u).collect();
        let nh = (0..m).map(|i| h_lo[i] * u + h_hi[i] * ui).collect();
        ls.push(lp);
        rs.push(rp);
        (av, bv, gv, hv) = (na, nb, ng, nh);
    }
    Ok(RangeProof { a, s, t1: t1p, t2: t2p, ls, rs, taux, mu, t_hat, ipa_a: av[0], ipa_b: bv[0] })
}

/// Verify against commitment `v_com` (BP-1 and BP-2 of §8.2). Absorbs exactly what the
/// prover absorbed.
pub fn verify<C: ZCurve>(
    tr: &mut Transcript,
    gens: &Gens<C>,
    n: usize,
    v_com: &G<C>,
    p: &RangeProof<C>,
) -> Result<(), ZError> {
    let k = n.trailing_zeros() as usize;
    if !(n == 32 || n == 64) || p.ls.len() != k || p.rs.len() != k {
        return Err(ZError::Verify("range proof shape"));
    }
    let mut d = (n as u32).to_be_bytes().to_vec();
    d.extend(encode_point::<C>(&p.a));
    d.extend(encode_point::<C>(&p.s));
    tr.absorb("bp.AS", &d);
    let y = nz_challenge::<C>(tr, "bp.y")?;
    let z = nz_challenge::<C>(tr, "bp.z")?;
    let mut d = encode_point::<C>(&p.t1);
    d.extend(encode_point::<C>(&p.t2));
    tr.absorb("bp.T", &d);
    let x = nz_challenge::<C>(tr, "bp.x")?;
    let mut d = encode_scalar::<C>(&p.taux).to_vec();
    d.extend(encode_scalar::<C>(&p.mu));
    d.extend(encode_scalar::<C>(&p.t_hat));
    tr.absorb("bp.t", &d);
    let w = nz_challenge::<C>(tr, "bp.w")?;
    let mut us = Vec::with_capacity(k);
    for j in 0..k {
        let mut d = encode_point::<C>(&p.ls[j]);
        d.extend(encode_point::<C>(&p.rs[j]));
        tr.absorb("ipa.LR", &d);
        us.push(nz_challenge::<C>(tr, "ipa.u")?);
    }

    let yn = powers::<C>(y, n);
    let twon = powers::<C>(Fr::<C>::from(2u64), n);
    let z2 = z * z;
    let sum_y: Fr<C> = yn.iter().sum();
    let sum_2: Fr<C> = twon.iter().sum();
    let delta = (z - z2) * sum_y - z2 * z * sum_2;

    // BP-1  [t̂ − δ]G + [τ_x]Hb − [z²]V − [x]T1 − [x²]T2 == O
    let bp1 = msm::<C>(
        &[gens.g, gens.h, *v_com, p.t1, p.t2],
        &[p.t_hat - delta, p.taux, -z2, -x, -(x * x)],
    );
    if !bp1.is_zero() {
        return Err(ZError::Verify("range proof: BP-1 (t_hat)"));
    }

    // BP-2  A + [x]S + Σ[−z − a·s_i]G_i + Σ[z + y^{-i}(z²2^i − b·s_i⁻¹)]H_i − [μ]Hb
    //       + [w(t̂ − ab)]U + Σ[u_j²]L_j + Σ[u_j⁻²]R_j == O
    let uinv: Vec<Fr<C>> = us.iter().map(|v| v.inverse().expect("u != 0")).collect();
    let mut s = vec![Fr::<C>::one(); n];
    for (i, si) in s.iter_mut().enumerate() {
        for j in 0..k {
            *si *= if (i >> (k - 1 - j)) & 1 == 1 { us[j] } else { uinv[j] };
        }
    }
    let yinvn = powers::<C>(y.inverse().expect("y != 0"), n);
    let mut bases: Vec<G<C>> = Vec::with_capacity(2 * n + 2 * k + 4);
    let mut scalars: Vec<Fr<C>> = Vec::with_capacity(2 * n + 2 * k + 4);
    for i in 0..n {
        bases.push(gens.gs[i]);
        scalars.push(-z - p.ipa_a * s[i]);
        bases.push(gens.hs[i]);
        // s_i^{-1} = s_{n-1-i}
        scalars.push(z + yinvn[i] * (z2 * twon[i] - p.ipa_b * s[n - 1 - i]));
    }
    bases.extend([p.a, p.s, gens.h, gens.u]);
    scalars.extend([Fr::<C>::one(), x, -p.mu, w * (p.t_hat - p.ipa_a * p.ipa_b)]);
    for j in 0..k {
        bases.push(p.ls[j]);
        scalars.push(us[j] * us[j]);
        bases.push(p.rs[j]);
        scalars.push(uinv[j] * uinv[j]);
    }
    if !msm(&bases, &scalars).is_zero() {
        return Err(ZError::Verify("range proof: BP-2 (inner product)"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Bls12381, Bn254};
    use ark_ff::UniformRand;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn stmt<C: ZCurve>(vc: &G<C>, tag: &[u8]) -> Transcript {
        let mut tr = Transcript::new();
        tr.absorb("statement", tag);
        tr.absorb("V", &encode_point::<C>(vc));
        tr
    }

    fn setup<C: ZCurve>(gens: &Gens<C>, n: usize, v: Fr<C>) -> (G<C>, RangeProof<C>) {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let gamma = Fr::<C>::rand(&mut rng);
        let vc = gens.g * v + gens.h * gamma;
        let mut nonces = Nonces::new(b"t", &mut rng);
        (vc, prove_unchecked(&mut stmt::<C>(&vc, b"s"), gens, n, &v, &gamma, &mut nonces).unwrap())
    }

    fn check<C: ZCurve>(gens: &Gens<C>, n: usize, vc: &G<C>, p: &RangeProof<C>) -> Result<(), ZError> {
        verify(&mut stmt::<C>(vc, b"s"), gens, n, vc, p)
    }

    fn suite<C: ZCurve>() {
        let g = Gens::<C>::new();
        for n in [32usize, 64] {
            let max = if n == 32 { u32::MAX as u64 } else { u64::MAX };
            for v in [0u64, 1, 12345, max] {
                let (vc, p) = setup::<C>(&g, n, Fr::<C>::from(v));
                check(&g, n, &vc, &p).unwrap();
                let enc = p.encode();
                assert_eq!(enc.len(), RangeProof::<C>::wire_len(n));
                assert!(RangeProof::<C>::decode(n, &enc).unwrap() == p);
            }
            // >= 2^n and negative: the honest prover refuses, a cheating proof fails.
            for bad in [Fr::<C>::from(1u128 << n), -Fr::<C>::one()] {
                let mut rng = ChaCha20Rng::seed_from_u64(1);
                let mut nn = Nonces::new(b"t", &mut rng);
                let r = prove(&mut Transcript::new(), &g, n, &bad, &Fr::<C>::one(), &mut nn);
                assert!(matches!(r, Err(ZError::OutOfRange)));
                let (vc, p) = setup::<C>(&g, n, bad);
                assert!(check(&g, n, &vc, &p).is_err());
            }
        }
        // Tampering: every element of the proof.
        let (vc, p) = setup::<C>(&g, 32, Fr::<C>::from(77u64));
        let (gen, one) = (g.g, Fr::<C>::one());
        let tampers: Vec<fn(&mut RangeProof<C>, G<C>, Fr<C>)> = vec![
            |t, p, _| t.a += p,
            |t, p, _| t.s += p,
            |t, p, _| t.t1 += p,
            |t, p, _| t.t2 += p,
            |t, _, s| t.taux += s,
            |t, _, s| t.mu += s,
            |t, _, s| t.t_hat += s,
            |t, p, _| t.ls[2] += p,
            |t, p, _| t.rs[4] += p,
            |t, _, s| t.ipa_a += s,
            |t, _, s| t.ipa_b += s,
        ];
        for f in tampers {
            let mut t = p.clone();
            f(&mut t, gen, one);
            assert!(check(&g, 32, &vc, &t).is_err());
        }
        // Tampered commitment; proof bound to a different statement; wrong n.
        assert!(check(&g, 32, &(vc + gen), &p).is_err());
        assert!(verify(&mut stmt::<C>(&vc, b"other"), &g, 32, &vc, &p).is_err());
        assert!(check(&g, 64, &vc, &p).is_err());
    }

    #[test]
    fn bulletproofs_bn254() {
        suite::<Bn254>();
    }

    #[test]
    fn bulletproofs_bls12_381() {
        suite::<Bls12381>();
    }
}
