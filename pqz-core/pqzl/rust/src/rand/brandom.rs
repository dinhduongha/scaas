//! `brandom.c`: the centred binomial sampler.
use super::rng::Rng;
use crate::Error;
use alloc::vec::Vec;

/// `_brandom`: vec[i] = (sum of k bits) - (sum of k bits) from one `Rng (seed, dom)` draw of 2 k len bits (LSB first;
/// the positive halves first, then the negative halves)
pub(crate) fn brandom(vec: &mut [i8], k: u32, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    let (k, n) = (k as usize, vec.len());
    let mut out = Vec::new();
    let outlen = (2 * k * n).div_ceil(8);
    out.try_reserve_exact(outlen).map_err(|_| Error::Memory)?;
    out.resize(outlen, 0);
    Rng::new(seed, dom).urandom(&mut out)?;
    let bit = |b: usize| ((out[b >> 3] >> (b & 7)) & 1) as i8;
    for (i, v) in vec.iter_mut().enumerate() {
        *v = 0;
        for j in 0..k {
            *v = v.wrapping_add(bit(i * k + j));
        }
    }
    for (i, v) in vec.iter_mut().enumerate() {
        for j in 0..k {
            *v = v.wrapping_sub(bit(k * n + i * k + j));
        }
    }
    Ok(())
}
