//! One generic code path over bn254 G1 and BLS12-381 G1.
//!
//! Wire encodings follow the EVM precompiles: bn254 = 64 B `x‖y` (32 B BE each, EIP-196),
//! BLS12-381 = 128 B `x‖y` (each 16 zero bytes + 48 B BE, EIP-2537). Identity = all zeros.
//! Scalars are 32 B big-endian. Decoding is strict: canonical coordinates, on curve, in the
//! prime-order subgroup (BLS12-381 G1 has a cofactor).

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::elgamal::BsgsSlot;
use crate::ZError;

pub type G<C> = Projective<C>;
pub type Fr<C> = <C as CurveConfig>::ScalarField;

pub trait ZCurve: SWCurveConfig<BaseField = <Self as ZCurve>::Fq> + Clone + PartialEq + Eq {
    type Fq: PrimeField;
    /// `"bn254"` / `"bls12381"` (the curve key used in vector files).
    const NAME: &'static str;
    /// Padded byte length of one coordinate on the wire.
    const COORD_LEN: usize;
    /// EIP-2333 `HKDF_mod_r` salt (R33).
    const KEYGEN_SALT: &'static [u8];
    /// First path component of the R33 tree (`m/<root>/<coin>/<account>/<use>`).
    const PATH_ROOT: u32;
    /// Preimage of `proofSystemId` (zether-design §2).
    const PROOF_SYSTEM_LABEL: &'static [u8];
    /// NUMS generator `gen(label, index)` (zether-design §3).
    fn gen(label: &[u8], index: u32) -> G<Self>;
    /// Storage of the process-wide BSGS table ([`crate::elgamal::cached_table`]).
    fn bsgs_slot() -> &'static BsgsSlot<Self>;
}

fn gen_msg(label: &[u8], index: u32) -> Vec<u8> {
    let mut m = vec![label.len() as u8];
    m.extend_from_slice(label);
    m.extend_from_slice(&index.to_be_bytes());
    m
}

impl ZCurve for ark_bn254::g1::Config {
    type Fq = ark_bn254::Fq;
    const NAME: &'static str = "bn254";
    const COORD_LEN: usize = 32;
    const KEYGEN_SALT: &'static [u8] = b"SCAAS-ZETHER-BN254-v1";
    const PATH_ROOT: u32 = 254;
    const PROOF_SYSTEM_LABEL: &'static [u8] = b"scaas/zether/sigma-bullets/bn254/n64-n64/v2";

    fn bsgs_slot() -> &'static BsgsSlot<Self> {
        static T: BsgsSlot<ark_bn254::g1::Config> = BsgsSlot::new(None);
        &T
    }

    /// Try-and-increment, even `y` (zether-design §3.1).
    fn gen(label: &[u8], index: u32) -> G<Self> {
        use ark_ff::Field;
        let mut prefix = b"SCAAS-ZETHER-GEN-BN254-V1".to_vec();
        prefix.extend_from_slice(&gen_msg(label, index));
        for ctr in 0u32.. {
            let mut buf = prefix.clone();
            buf.extend_from_slice(&ctr.to_be_bytes());
            let x = ark_bn254::Fq::from_be_bytes_mod_order(&keccak256(&buf));
            let rhs = x * x * x + ark_bn254::Fq::from(3u64);
            if let Some(y) = rhs.sqrt() {
                let y = if y.into_bigint().is_odd() { -y } else { y };
                return Affine::<Self>::new(x, y).into();
            }
        }
        unreachable!()
    }
}

impl ZCurve for ark_bls12_381::g1::Config {
    type Fq = ark_bls12_381::Fq;
    const NAME: &'static str = "bls12381";
    const COORD_LEN: usize = 64;
    const KEYGEN_SALT: &'static [u8] = b"BLS-SIG-KEYGEN-SALT-";
    const PATH_ROOT: u32 = 12381;
    const PROOF_SYSTEM_LABEL: &'static [u8] = b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v2";

    fn bsgs_slot() -> &'static BsgsSlot<Self> {
        static T: BsgsSlot<ark_bls12_381::g1::Config> = BsgsSlot::new(None);
        &T
    }

    /// RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` (zether-design §3.2).
    fn gen(label: &[u8], index: u32) -> G<Self> {
        hash_to_g1_bls(&gen_msg(label, index), b"SCAAS-ZETHER-GEN-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_")
    }
}

/// RFC 9380 hash_to_curve, suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`.
pub fn hash_to_g1_bls(msg: &[u8], dst: &[u8]) -> G<Bls12381> {
    use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
    use ark_ff::field_hashers::DefaultFieldHasher;
    let h = MapToCurveBasedHasher::<G<Bls12381>, DefaultFieldHasher<sha2::Sha256, 128>, WBMap<Bls12381>>::new(dst)
        .expect("valid DST");
    h.hash(msg).expect("hash_to_curve").into()
}

pub fn proof_system_id<C: ZCurve>() -> [u8; 32] {
    keccak256(C::PROOF_SYSTEM_LABEL)
}

/// The multi-recipient transfer's id: the single label plus `/multi` (the statement layouts differ).
pub fn proof_system_id_multi<C: ZCurve>() -> [u8; 32] {
    keccak256(&[C::PROOF_SYSTEM_LABEL, b"/multi"].concat())
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

    /// RFC 9380 Appendix J.9.1 (BLS12381G1_XMD:SHA-256_SSWU_RO_).
    #[test]
    fn rfc9380_bls12_381_g1_vectors() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
        for (msg, x, y) in [
            ("", "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
             "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"),
            ("abc", "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
             "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"),
        ] {
            let e = encode_point::<Bls12381>(&hash_to_g1_bls(msg.as_bytes(), dst));
            assert_eq!(hex::encode(&e[16..64]), x);
            assert_eq!(hex::encode(&e[80..128]), y);
        }
    }

    #[test]
    fn bn254_gen_even_y_and_distinct() {
        let a = <Bn254 as ZCurve>::gen(b"G", 0);
        let b = <Bn254 as ZCurve>::gen(b"G", 1);
        let h = <Bn254 as ZCurve>::gen(b"h", 0);
        assert!(a != b && a != h && a != generator::<Bn254>());
        let e = encode_point::<Bn254>(&a);
        assert_eq!(e[63] & 1, 0);
        assert_eq!(decode_point::<Bn254>(&e).unwrap(), a);
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
