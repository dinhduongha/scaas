//! Lifted (exponential) ElGamal on G1: `Enc_y(b; r) = (C, D) = (g^b · y^r, g^r)`.
//! Decryption recovers `g^b = C · D^{-x}`, then `b` by baby-step giant-step over
//! `[0, DECRYPT_BOUND)`, `DECRYPT_BOUND = 2^40` (client-only constant, canon §C6.2).

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::curve::{generator, Fr, ZCurve, G};
use crate::ZError;

pub const DECRYPT_BOUND_BITS: u32 = 40;
pub const DECRYPT_BOUND: u64 = 1 << DECRYPT_BOUND_BITS;
const BABY: u64 = 1 << (DECRYPT_BOUND_BITS / 2);

#[derive(PartialEq, Eq)]
pub struct Ciphertext<C: ZCurve> {
    pub c: G<C>,
    pub d: G<C>,
}

impl<C: ZCurve> Clone for Ciphertext<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: ZCurve> Copy for Ciphertext<C> {}

impl<C: ZCurve> Ciphertext<C> {
    pub fn zero() -> Self {
        Self { c: G::<C>::zero(), d: G::<C>::zero() }
    }
    pub fn add(&self, o: &Self) -> Self {
        Self { c: self.c + o.c, d: self.d + o.d }
    }
    pub fn sub(&self, o: &Self) -> Self {
        Self { c: self.c - o.c, d: self.d - o.d }
    }
    /// Homomorphic subtraction of a public scalar (the fee path: `C' = C · g^{-fee}`).
    pub fn sub_plain(&self, v: u64) -> Self {
        Self { c: self.c - generator::<C>() * Fr::<C>::from(v), d: self.d }
    }
}

pub fn encrypt<C: ZCurve>(y: &G<C>, b: u64, r: &Fr<C>) -> Ciphertext<C> {
    let g = generator::<C>();
    Ciphertext { c: g * Fr::<C>::from(b) + *y * r, d: g * r }
}

/// `g^b` from a ciphertext.
pub fn decrypt_point<C: ZCurve>(ct: &Ciphertext<C>, x: &Fr<C>) -> G<C> {
    ct.c - ct.d * x
}

/// Baby-step table `{g^j : 0 <= j < 2^20}`, a sorted `(x-limb key, j)` array: 2^20 × 16 B =
/// 16 MiB, built in chunks so no full projective/affine copy is ever held. Costs 2^20
/// additions: use the per-curve cached one, [`ZCurve::bsgs`].
pub struct BsgsTable<C: ZCurve> {
    baby: Vec<(u64, u32)>,
    giant: G<C>, // g^{-2^20}
}

fn key<C: ZCurve>(p: &ark_ec::short_weierstrass::Affine<C>) -> u64 {
    // 64-bit x-limb key; a colliding key is resolved by the equality check in `dlog`.
    let b = p.x.into_bigint().to_bytes_le();
    u64::from_le_bytes(b[..8].try_into().unwrap()) ^ (p.infinity as u64)
}

impl<C: ZCurve> BsgsTable<C> {
    pub fn new() -> Self {
        const CHUNK: usize = 1 << 12;
        let g = generator::<C>();
        let mut baby = Vec::with_capacity(BABY as usize);
        let mut pts = Vec::with_capacity(CHUNK);
        let mut acc = G::<C>::zero();
        for j in 0..BABY as u32 {
            pts.push(acc);
            acc += g;
            if pts.len() == CHUNK {
                let base = j + 1 - CHUNK as u32;
                baby.extend(G::<C>::normalize_batch(&pts).iter().zip(base..).map(|(p, i)| (key::<C>(p), i)));
                pts.clear();
            }
        }
        baby.sort_unstable();
        Self { baby, giant: -(g * Fr::<C>::from(BABY)) }
    }

    /// Discrete log of `target` base g in `[0, DECRYPT_BOUND)`, or `ZError::DecryptBound`.
    pub fn dlog(&self, target: &G<C>) -> Result<u64, ZError> {
        let g = generator::<C>();
        let mut cur = *target;
        for i in 0..BABY {
            let a = cur.into_affine();
            let k = key::<C>(&a);
            let from = self.baby.partition_point(|e| e.0 < k);
            for &(_, j) in self.baby[from..].iter().take_while(|e| e.0 == k) {
                let v = i * BABY + j as u64;
                if g * Fr::<C>::from(v) == *target {
                    return Ok(v);
                }
            }
            cur += self.giant;
        }
        Err(ZError::DecryptBound)
    }

    pub fn decrypt(&self, ct: &Ciphertext<C>, x: &Fr<C>) -> Result<u64, ZError> {
        self.dlog(&decrypt_point(ct, x))
    }
}

impl<C: ZCurve> Default for BsgsTable<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Bls12381, Bn254};
    use ark_ff::UniformRand;

    fn keypair<C: ZCurve>(rng: &mut impl rand_core::RngCore) -> (Fr<C>, G<C>) {
        let x = Fr::<C>::rand(rng);
        (x, generator::<C>() * x)
    }

    fn homomorphic<C: ZCurve>() {
        let mut rng = ark_std::test_rng();
        let (x, y) = keypair::<C>(&mut rng);
        let t = C::bsgs();
        // Built once per curve, and the size the doc comment states.
        assert!(std::ptr::eq(t, C::bsgs()));
        assert_eq!(std::mem::size_of_val(&t.baby[..]), 16 << 20);
        let a = encrypt(&y, 1_000_000, &Fr::<C>::rand(&mut rng));
        let b = encrypt(&y, 234_567, &Fr::<C>::rand(&mut rng));
        assert_eq!(t.decrypt(&a, &x).unwrap(), 1_000_000);
        assert_eq!(t.decrypt(&a.add(&b), &x).unwrap(), 1_234_567);
        assert_eq!(t.decrypt(&a.sub(&b), &x).unwrap(), 765_433);
        assert_eq!(t.decrypt(&a.sub_plain(300), &x).unwrap(), 999_700);
        assert_eq!(t.decrypt(&Ciphertext::zero(), &x).unwrap(), 0);
        // Negative plaintext (b - a) is outside [0, 2^40): a clear error, never a wrap.
        assert_eq!(t.decrypt(&b.sub(&a), &x), Err(ZError::DecryptBound));
        // Wrong key does not decrypt to the value.
        let (x2, _) = keypair::<C>(&mut rng);
        assert_ne!(t.decrypt(&a, &x2).ok(), Some(1_000_000));
        // Bound: 2^40 - 1 decrypts (worst case for giant steps), 2^40 fails.
        let r = Fr::<C>::rand(&mut rng);
        assert_eq!(t.decrypt(&encrypt(&y, DECRYPT_BOUND - 1, &r), &x).unwrap(), DECRYPT_BOUND - 1);
        assert_eq!(t.decrypt(&encrypt(&y, DECRYPT_BOUND, &r), &x), Err(ZError::DecryptBound));
    }

    #[test]
    fn elgamal_bn254() {
        homomorphic::<Bn254>();
    }

    #[test]
    fn elgamal_bls12_381() {
        homomorphic::<Bls12381>();
    }
}
