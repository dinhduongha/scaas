//! `rng.c` (RNG = AES256CTR): `rng_init (state, seed, dom)` keys AES-256-CTR with the seed, nonce le64(dom) || 0^8.
use super::aes_ctr::AesCtr;
use crate::Error;

pub(crate) struct Rng(AesCtr);

impl Rng {
    pub(crate) fn new(seed: &[u8; 32], dom: u64) -> Rng {
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&dom.to_le_bytes());
        Rng(AesCtr::new(seed, &nonce))
    }

    /// `rng_urandom`: the next `out.len()` stream bytes; an empty request is C's `ASSERT_ERR (outlen > 0)`
    pub(crate) fn urandom(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.is_empty() {
            return Err(Error::Internal);
        }
        self.0.stream(out);
        Ok(())
    }

    /// 8 stream bytes as a little-endian u64 (`_u64` of rejection.c, the word loads of grandom.c)
    pub(crate) fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.stream(&mut b);
        u64::from_le_bytes(b)
    }
}
