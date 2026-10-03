//! One generic code path over bn254 G1 and BLS12-381 G1.
//!
//! Wire encodings follow the EVM precompiles: bn254 = 64 B `x‖y` (32 B BE each, EIP-196),
//! BLS12-381 = 128 B `x‖y` (each 16 zero bytes + 48 B BE, EIP-2537). Identity = all zeros.
//! Scalars are 32 B big-endian. Decoding is strict: canonical coordinates, on curve, in the
//! prime-order subgroup (BLS12-381 G1 has a cofactor).

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::ZError;

pub type G<C> = Projective<C>;
pub type Fr<C> = <C as CurveConfig>::ScalarField;

pub trait ZCurve: SWCurveConfig<BaseField = <Self as ZCurve>::Fq> + Send + Sync + 'static {
    type Fq: PrimeField;
    /// `"bn254"` / `"bls12_381"`.
    const NAME: &'static str;
    /// Padded byte length of one coordinate on the wire.
    const COORD_LEN: usize;
    /// EIP-2333 `HKDF_mod_r` salt (R33).
    const KEYGEN_SALT: &'static [u8];
    /// First path component of the R33 tree (`m/<root>/<coin>/<account>/<use>`).
    const PATH_ROOT: u32;
}

impl ZCurve for ark_bn254::g1::Config {
    type Fq = ark_bn254::Fq;
    const NAME: &'static str = "bn254";
    const COORD_LEN: usize = 32;
    const KEYGEN_SALT: &'static [u8] = b"BAMBOO-ZETHER-BN254-v1";
    const PATH_ROOT: u32 = 254;
}

impl ZCurve for ark_bls12_381::g1::Config {
    type Fq = ark_bls12_381::Fq;
    const NAME: &'static str = "bls12_381";
    const COORD_LEN: usize = 64;
    const KEYGEN_SALT: &'static [u8] = b"BLS-SIG-KEYGEN-SALT-";
    const PATH_ROOT: u32 = 12381;
}

pub type Bn254 = ark_bn254::g1::Config;
pub type Bls12381 = ark_bls12_381::g1::Config;

pub fn generator<C: ZCurve>() -> G<C> {
    C::GENERATOR.into()
}

pub fn point_len<C: ZCurve>() -> usize {
    2 * C::COORD_LEN
}

fn put_be(dst: &mut [u8], src: &[u8]) {
    let off = dst.len() - src.len();
    dst[off..].copy_from_slice(src);
}

pub fn encode_point<C: ZCurve>(p: &G<C>) -> Vec<u8> {
    let a = p.into_affine();
    let l = C::COORD_LEN;
    let mut out = vec![0u8; 2 * l];
    if a.infinity {
        return out;
    }
    put_be(&mut out[..l], &a.x.into_bigint().to_bytes_be());
    put_be(&mut out[l..], &a.y.into_bigint().to_bytes_be());
    out
}

fn decode_fq<C: ZCurve>(b: &[u8]) -> Result<C::Fq, ZError> {
    let x = C::Fq::from_be_bytes_mod_order(b);
    let mut canon = vec![0u8; b.len()];
    put_be(&mut canon, &x.into_bigint().to_bytes_be());
    if canon != b {
        return Err(ZError::BadPoint("coordinate not canonical (>= p or bad padding)"));
    }
    Ok(x)
}

pub fn decode_point<C: ZCurve>(b: &[u8]) -> Result<G<C>, ZError> {
    let l = C::COORD_LEN;
    if b.len() != 2 * l {
        return Err(ZError::BadPoint("wrong length"));
    }
    if b.iter().all(|&v| v == 0) {
        return Ok(G::<C>::zero());
    }
    let a = Affine::<C>::new_unchecked(decode_fq::<C>(&b[..l])?, decode_fq::<C>(&b[l..])?);
    if !a.is_on_curve() {
        return Err(ZError::BadPoint("not on curve"));
    }
    if !a.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ZError::BadPoint("not in prime-order subgroup"));
    }
    Ok(a.into())
}

pub fn encode_scalar<C: ZCurve>(s: &Fr<C>) -> [u8; 32] {
    let mut out = [0u8; 32];
    put_be(&mut out, &s.into_bigint().to_bytes_be());
    out
}

/// Strict: rejects values >= r.
pub fn decode_scalar<C: ZCurve>(b: &[u8]) -> Result<Fr<C>, ZError> {
    if b.len() != 32 {
        return Err(ZError::BadScalar);
    }
    let s = Fr::<C>::from_be_bytes_mod_order(b);
    if encode_scalar::<C>(&s) != b {
        return Err(ZError::BadScalar);
    }
    Ok(s)
}

/// Order r of the scalar field as 32 B big-endian.
pub fn order_be<C: ZCurve>() -> [u8; 32] {
    let mut out = [0u8; 32];
    put_be(&mut out, &Fr::<C>::MODULUS.to_bytes_be());
    out
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(data).into()
}

/// keccak256 of the encoded point — `ZetherTypes.toUA`.
pub fn ua_of<C: ZCurve>(y: &G<C>) -> [u8; 32] {
    keccak256(&encode_point::<C>(y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;
    use ark_ff::UniformRand;

    fn roundtrip<C: ZCurve>() {
        let mut rng = ark_std::test_rng();
        for _ in 0..8 {
            let p = G::<C>::generator() * Fr::<C>::rand(&mut rng);
            let e = encode_point::<C>(&p);
            assert_eq!(e.len(), point_len::<C>());
            assert_eq!(decode_point::<C>(&e).unwrap(), p);
        }
        assert_eq!(decode_point::<C>(&vec![0u8; point_len::<C>()]).unwrap(), G::<C>::zero());
        let mut bad = encode_point::<C>(&generator::<C>());
        *bad.last_mut().unwrap() ^= 1;
        assert!(decode_point::<C>(&bad).is_err());
        assert!(decode_scalar::<C>(&order_be::<C>()).is_err());
    }

    #[test]
    fn point_roundtrip_bn254() {
        roundtrip::<Bn254>();
        // bn254 G1 generator is (1, 2).
        let e = encode_point::<Bn254>(&generator::<Bn254>());
        assert_eq!(e[31], 1);
        assert_eq!(e[63], 2);
    }

    #[test]
    fn point_roundtrip_bls() {
        roundtrip::<Bls12381>();
        // EIP-2537: top 16 bytes of each 64-byte coordinate are zero.
        let e = encode_point::<Bls12381>(&generator::<Bls12381>());
        assert!(e[..16].iter().all(|&b| b == 0) && e[64..80].iter().all(|&b| b == 0));
    }

    #[test]
    fn bls_rejects_point_outside_subgroup() {
        // A point on E(Fq) with x = smallest x giving a curve point is (with overwhelming
        // probability) not in the r-torsion: search for one and confirm it is rejected.
        use ark_ff::Field;
        let mut x = ark_bls12_381::Fq::from(1u64);
        loop {
            let rhs = x * x * x + ark_bls12_381::Fq::from(4u64);
            if let Some(y) = rhs.sqrt() {
                let a = Affine::<Bls12381>::new_unchecked(x, y);
                if !a.is_in_correct_subgroup_assuming_on_curve() {
                    let mut enc = vec![0u8; 128];
                    put_be(&mut enc[..64], &x.into_bigint().to_bytes_be());
                    put_be(&mut enc[64..], &y.into_bigint().to_bytes_be());
                    assert!(matches!(decode_point::<Bls12381>(&enc), Err(ZError::BadPoint(_))));
                    return;
                }
            }
            x += ark_bls12_381::Fq::from(1u64);
        }
    }
}
