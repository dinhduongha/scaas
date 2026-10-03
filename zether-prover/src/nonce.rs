//! Hedged prover nonces (canon §3.1.4): `k_i = SHA-512(tag ‖ secrets ‖ rng32 ‖ i) mod r`.
//! A broken RNG degrades to deterministic-per-(secret, statement) nonces instead of reuse
//! across statements, which is what leaks `x` (`x = (s1 - s2)/(c1 - c2)`).

use ark_ff::PrimeField;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::curve::{Fr, ZCurve};

pub struct Nonces {
    seed: [u8; 64],
    ctr: u64,
}

impl Nonces {
    /// `secrets` = the witness bytes plus anything statement-specific (e.g. transcript state).
    pub fn new<R: RngCore + CryptoRng>(secrets: &[u8], rng: &mut R) -> Self {
        let mut r = [0u8; 32];
        rng.fill_bytes(&mut r);
        let mut h = Sha512::new();
        h.update(b"ZETHER-NONCE-v1");
        h.update((secrets.len() as u64).to_be_bytes());
        h.update(secrets);
        h.update(r);
        r.zeroize();
        Self { seed: h.finalize().into(), ctr: 0 }
    }

    pub fn next<C: ZCurve>(&mut self) -> Fr<C> {
        self.ctr += 1;
        let mut h = Sha512::new();
        h.update(self.seed);
        h.update(self.ctr.to_be_bytes());
        Fr::<C>::from_be_bytes_mod_order(&h.finalize())
    }
}

impl Drop for Nonces {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}
