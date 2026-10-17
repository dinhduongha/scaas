//! `rng.c` (RNG = AES256CTR): `rng_init (state, seed, dom)` keys AES-256-CTR with the seed, nonce le64(dom) || 0^8.
use super::aes_ctr::AesCtr;

pub(crate) struct Rng(AesCtr);

impl Rng {
    pub(crate) fn new(seed: &[u8; 32], dom: u64) -> Rng {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&dom.to_le_bytes());
        Rng(AesCtr::new(seed, &nonce))
    }

    /// `rng_urandom`
    pub(crate) fn urandom(&mut self, out: &mut [u8]) {
        self.0.stream(out);
    }
}
