// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `secret_mul` (spec §12, ua-rs-sign T3c): the blinded ladder's product equals arkworks' plain product on G1 and G2 of
//! bn254 and BLS12-381, for edge scalars and random ones; the masked swap swaps exactly when asked; under `vectors` the
//! ladder's record shows the blinding: per call an integer `k' ≥ r` with `k' ≡ k (mod r)`, 384 iterations, a new `k'` for
//! the same `k`. UNAUDITED.
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ec::PrimeGroup;
use ark_ff::{PrimeField, UniformRand};
use rand_chacha::rand_core::SeedableRng;
use scaas_ct::{secret_mul, CtSwap, LADDER_BITS};
use subtle::Choice;

fn edge_and_random<F: PrimeField>(rng: &mut rand_chacha::ChaCha20Rng) -> Vec<F> {
    let mut v = vec![F::zero(), F::one(), F::from(2u64), -F::one(), -F::from(2u64)];
    v.extend((0..12).map(|_| F::rand(rng)));
    v
}

fn products_equal<P: SWCurveConfig>(name: &str)
where
    P::BaseField: CtSwap,
{
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let other = Projective::<P>::generator() * P::ScalarField::rand(&mut rng);
    for base in [Projective::<P>::generator(), other] {
        for s in edge_and_random::<P::ScalarField>(&mut rng) {
            assert_eq!(secret_mul(base, &s).unwrap(), base * s, "{name}");
        }
    }
}

#[test]
fn blinded_and_plain_products_equal() {
    products_equal::<ark_bn254::g1::Config>("bn254 G1");
    products_equal::<ark_bn254::g2::Config>("bn254 G2");
    products_equal::<ark_bls12_381::g1::Config>("bls12-381 G1");
    products_equal::<ark_bls12_381::g2::Config>("bls12-381 G2");
}

#[test]
fn ladder_is_384_bits_wide() {
    assert_eq!(LADDER_BITS, 384);
}

#[test]
fn masked_swap_swaps_exactly_when_asked() {
    let (a0, b0) = (ark_bls12_381::Fq2::from(3u64), ark_bls12_381::Fq2::new(5u64.into(), 7u64.into()));
    let (mut a, mut b) = (a0, b0);
    CtSwap::ct_swap(&mut a, &mut b, Choice::from(0));
    assert_eq!((a, b), (a0, b0));
    CtSwap::ct_swap(&mut a, &mut b, Choice::from(1));
    assert_eq!((a, b), (b0, a0));
    let (c0, d0) = (ark_bn254::Fq::from(11u64), ark_bn254::Fq::from(13u64));
    let (mut c, mut d) = (c0, d0);
    CtSwap::ct_swap(&mut c, &mut d, Choice::from(1));
    assert_eq!((c, d), (d0, c0));
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use ark_ff::BigInteger;
    use scaas_ct::trace;

    /// `k'` as big-endian bytes.
    fn be(k: &[u64; 6]) -> Vec<u8> {
        k.iter().rev().flat_map(|l| l.to_be_bytes()).collect()
    }

    fn at_least<F: PrimeField>(k: &[u64; 6]) -> bool {
        let r = F::MODULUS.to_bytes_be();
        let k = be(k);
        let (hi, lo) = k.split_at(k.len() - r.len());
        hi.iter().any(|b| *b != 0) || lo >= &r[..]
    }

    fn blinded<P: SWCurveConfig>(name: &str)
    where
        P::BaseField: CtSwap,
    {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(9);
        let k = P::ScalarField::rand(&mut rng);
        let g = Projective::<P>::generator();
        trace::take();
        let (a, b) = (secret_mul(g, &k).unwrap(), secret_mul(g, &k).unwrap());
        assert_eq!(a, b, "{name}: same point");
        let t = trace::take();
        assert_eq!(t.len(), 2, "{name}");
        let (x, y) = (&t[0], &t[1]);
        assert_ne!(x.k, y.k, "{name}: a new blinder per call");
        for e in [x, y] {
            assert_eq!(e.iterations, 384, "{name}");
            assert!(at_least::<P::ScalarField>(&e.k), "{name}: k' ≥ r");
            assert_eq!(P::ScalarField::from_be_bytes_mod_order(&be(&e.k)), k, "{name}: k' ≡ k (mod r)");
        }
        assert!(trace::take().is_empty());
    }

    #[test]
    fn every_call_blinds_with_a_new_integer() {
        blinded::<ark_bn254::g1::Config>("bn254 G1");
        blinded::<ark_bn254::g2::Config>("bn254 G2");
        blinded::<ark_bls12_381::g1::Config>("bls12-381 G1");
        blinded::<ark_bls12_381::g2::Config>("bls12-381 G2");
    }
}
