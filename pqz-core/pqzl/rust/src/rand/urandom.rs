//! `urandom.c`: uniform samplers. Task 2: `_urandom_i64` (moduli below 2^60, the poly samplers); the multi-limb
//! `_urandom_bnd` comes with Task 3.
use super::rng::Rng;
use crate::Error;
use alloc::vec::Vec;

/// `_urandom_i64`: `vec.len()` values uniform in [0, m), 2^(log2mod-1) <= m < 2^log2mod, by rejection on
/// log2mod-bit chunks (LSB first) of the `Rng (seed, dom)` stream, refilled per round for the values still missing
pub(crate) fn urandom_i64(vec: &mut [i64], m: i64, log2mod: u32, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    let nb = log2mod as usize;
    let mut st = Rng::new(seed, dom);
    let mut out = Vec::new();
    let mut k = 0;
    while k < vec.len() {
        let l = vec.len() - k;
        let outlen = (nb * l).div_ceil(8);
        out.clear();
        out.try_reserve(outlen).map_err(|_| Error::Memory)?;
        out.resize(outlen, 0);
        st.urandom(&mut out);
        for i in 0..l {
            let mut t = 0i64;
            for j in 0..nb {
                let bit = i * nb + j;
                t |= (((out[bit >> 3] >> (bit & 7)) & 1) as i64) << j;
            }
            if ((m - 1 - t) >> 63) & 1 == 0 {
                vec[k] = t;
                k += 1;
            }
        }
    }
    Ok(())
}
