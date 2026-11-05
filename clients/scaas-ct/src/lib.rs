// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `secret_mul(base, secret)`: the one way a secret scalar multiplies a point on an arkworks short-Weierstrass curve (G1 and
//! G2 of bn254 and BLS12-381), spec `2026-11-05-ua-rs-sign.md` §12. arkworks has no constant-time path for these curves:
//! `Projective * Fr` reduces a wide integer back to `k` (G1's GLV path), and the unreduced `sw_double_and_add_*` skip leading
//! zeros and branch per bit. So this function draws `ρ` (128 bits, OS RNG), forms `k' = k + ρ·r` as a 384-bit integer by limb
//! arithmetic (never a field element), runs a Montgomery ladder of exactly [`LADDER_BITS`] iterations whose branches are
//! picked by a masked conditional swap of the point coordinates ([`CtSwap`], no branch on a bit of `k'`), and wipes `ρ`,
//! `k'` and the ladder's swap state before it returns.
//!
//! **Residual, stated:** arkworks field arithmetic (conditional final subtraction, normalisation), the identity and doubling
//! cases of point addition (which also show the ladder's leading zero bits of `k'`), and the reduction of `k` out of
//! Montgomery form branch on values; blinding randomises the operand per call, it does not make these constant time.
//! Owner 2026-11-05 (option (c)): shared here, used by `scaas-ua`; `zether-prover` moves onto it in a separate task after
//! the ua-rs-sign round. Feature `vectors` (tests only): [`trace`] records every ladder's `k'` and iteration count, per
//! thread. UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]
use ark_ec::short_weierstrass::{Projective, SWCurveConfig};
use ark_ff::{AdditiveGroup, Fp, FpConfig, PrimeField, QuadExtConfig, QuadExtField, Zero};
use rand_core::{OsRng, RngCore};
use subtle::{Choice, ConditionallySelectable};
use zeroize::{Zeroize, Zeroizing};

/// The ladder's width: `k' < r·2^128 + r < 2^384` for both curves' `r` (< 2^255).
pub const LADDER_BITS: usize = 384;
const LIMBS: usize = LADDER_BITS / 64;

/// The OS random number generator failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RngError;

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OS RNG")
    }
}

impl std::error::Error for RngError {}

/// A masked swap of two field elements: both swapped when `c` is 1, both kept when 0, the same instructions either way.
pub trait CtSwap {
    fn ct_swap(a: &mut Self, b: &mut Self, c: Choice);
}

impl<P: FpConfig<N>, const N: usize> CtSwap for Fp<P, N> {
    fn ct_swap(a: &mut Self, b: &mut Self, c: Choice) {
        // the Montgomery-form limbs; any bit pattern swapped whole is the other valid element
        for (x, y) in a.0 .0.iter_mut().zip(b.0 .0.iter_mut()) {
            u64::conditional_swap(x, y, c);
        }
    }
}

impl<P: QuadExtConfig> CtSwap for QuadExtField<P>
where
    P::BaseField: CtSwap,
{
    fn ct_swap(a: &mut Self, b: &mut Self, c: Choice) {
        CtSwap::ct_swap(&mut a.c0, &mut b.c0, c);
        CtSwap::ct_swap(&mut a.c1, &mut b.c1, c);
    }
}

fn swap_points<P: SWCurveConfig>(a: &mut Projective<P>, b: &mut Projective<P>, c: Choice)
where
    P::BaseField: CtSwap,
{
    CtSwap::ct_swap(&mut a.x, &mut b.x, c);
    CtSwap::ct_swap(&mut a.y, &mut b.y, c);
    CtSwap::ct_swap(&mut a.z, &mut b.z, c);
}

/// `k + ρ·r` over little-endian limbs (`k < r`, both at most 4 limbs, `ρ` 2 limbs): fixed loops, no reduction.
fn blind(k: &[u64], r: &[u64], rho: &[u64; 2]) -> Zeroizing<[u64; LIMBS]> {
    let mut out = Zeroizing::new([0u64; LIMBS]);
    for (i, a) in rho.iter().enumerate() {
        let mut carry = 0u128;
        for (o, b) in out.iter_mut().skip(i).zip(r.iter().map(Some).chain(core::iter::once(None))) {
            let t = u128::from(*o) + u128::from(*a) * u128::from(b.copied().unwrap_or(0)) + carry;
            *o = t as u64;
            carry = t >> 64;
        }
    }
    let mut carry = 0u128;
    for (o, b) in out.iter_mut().zip(k.iter().copied().chain(core::iter::repeat(0))) {
        let t = u128::from(*o) + u128::from(b) + carry;
        *o = t as u64;
        carry = t >> 64;
    }
    out
}

/// `secret · base`, blinded and by the fixed-width ladder (module doc). `RngError` if the OS RNG fails.
pub fn secret_mul<P: SWCurveConfig>(base: Projective<P>, secret: &P::ScalarField) -> Result<Projective<P>, RngError>
where
    P::BaseField: CtSwap,
{
    let mut rho = Zeroizing::new([0u64; 2]);
    while rho.iter().all(|l| *l == 0) {
        let mut b = Zeroizing::new([0u8; 16]);
        OsRng.try_fill_bytes(&mut b[..]).map_err(|_| RngError)?;
        for (l, c) in rho.iter_mut().zip(b.chunks_exact(8)) {
            *l = u64::from_le_bytes(c.try_into().map_err(|_| RngError)?);
        }
    }
    let mut k = secret.into_bigint();
    let kp = blind(k.as_ref(), P::ScalarField::MODULUS.as_ref(), &rho);
    k.zeroize();
    let (mut r0, mut r1) = (Projective::<P>::zero(), base);
    let mut swap = Zeroizing::new(0u8);
    let mut iterations = 0usize;
    for limb in kp.iter().rev() {
        for j in (0..64).rev() {
            let bit = ((limb >> j) & 1) as u8;
            swap_points(&mut r0, &mut r1, Choice::from(bit ^ *swap));
            *swap = bit;
            r1 += &r0;
            r0.double_in_place();
            iterations += 1;
        }
    }
    swap_points(&mut r0, &mut r1, Choice::from(*swap));
    r1.zeroize();
    #[cfg(feature = "vectors")]
    trace::record(&kp, iterations);
    let _ = iterations;
    Ok(r0)
}

/// Test-only (feature `vectors`, never in a release build): the ladder's record on this thread, secrets included.
#[cfg(feature = "vectors")]
pub mod trace {
    use std::cell::RefCell;

    /// One `secret_mul` call: the integer that entered the ladder (little-endian limbs) and the iterations it ran.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Entry {
        pub k: [u64; super::LIMBS],
        pub iterations: usize,
    }

    thread_local!(static TRACE: RefCell<Vec<Entry>> = const { RefCell::new(Vec::new()) });

    pub(crate) fn record(k: &[u64; super::LIMBS], iterations: usize) {
        TRACE.with(|t| t.borrow_mut().push(Entry { k: *k, iterations }));
    }

    /// This thread's records since the last call, in call order.
    pub fn take() -> Vec<Entry> {
        TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::blind;

    #[test]
    fn blind_is_k_plus_rho_r() {
        // r = 2^64 + 3 (two limbs), ρ = 2^64 + 5, k = 7: ρ·r + k = 2^128 + 8·2^64 + 22
        assert_eq!(*blind(&[7], &[3, 1], &[5, 1]), [22, 8, 1, 0, 0, 0]);
        // carries through every limb: r = ρ = 2^128 − 1, k = 1 → 2^256 − 2^129 + 2
        let m = u64::MAX;
        assert_eq!(*blind(&[1], &[m, m], &[m, m]), [2, 0, m - 1, m, 0, 0]);
    }
}
