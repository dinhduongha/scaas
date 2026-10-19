//! `grandom.c`: the PQZ discrete Gaussian sampler (integer-only, `fixexp`). A sample of D_{Z, 1.55 * 2^s} is
//! k * 2^s - u, u uniform in [0, 2^s) from the head of the `Rng (seed, dom)` stream, k from D_{Z, 1.55, c = u / 2^s}
//! by the bimodal half-Gaussian CDF table and an exp(-x) acceptance, 32 stream bytes per try, at most 256 tries.
use super::fixexp::{bernoulli_fp, exp_fp};
use super::rng::Rng;
use crate::arith::poly::Poly;
use crate::arith::polyvec::Pv;
use crate::Error;
use alloc::vec::Vec;

/// P(reject) <= 0.6 per try; 256 tries fail with probability < 2^-180
const MAX_TRIES: usize = 256;

/// CDF155 as (hi, lo) halves of 128-bit thresholds (decreasing)
const CDF155: [(u64, u64); 21] = [
    (10894764499197476522, 10804844707381617341),
    (4761708367981796450, 6209732027000382074),
    (1476784279527800432, 14108379346150813303),
    (316388870594767345, 17827298407763885637),
    (46043503515468600, 18385899657892021654),
    (4503729779335039, 3860889375818664979),
    (294122444862326, 13947176349836216550),
    (12769598070895, 14321894682751135119),
    (367552986472, 10286761328368440884),
    (7001273393, 2287787188970898528),
    (88153536, 17843977990435837663),
    (733119, 12174894787802692461),
    (4024, 18067426722645776197),
    (14, 10764017821655913055),
    (0, 643125733022530080),
    (0, 1014291014134832),
    (0, 1055215183460),
    (0, 724109373),
    (0, 327744),
    (0, 98),
    (0, 0),
];

/// 2^62 / (2 * 1.55^2) = 2^62 * 200 / 961
const DSS_Q62: u64 = 959_768_162_003_618_710;

/// `gaussian155`: k from D_{Z, 1.55, c = u / 2^s} (s <= 56); C's cap sets PQZ_ERR_REJECT: `Error::Reject`
fn gaussian155(st: &mut Rng, u: u64, s: u32) -> Result<i64, Error> {
    for _ in 0..MAX_TRIES {
        let w: [u64; 4] = core::array::from_fn(|_| st.u64());
        // k0 = #{z : (hi, lo) < CDF155[z]}
        let x128 = (w[0] as u128) << 64 | w[1] as u128;
        let k0: i64 = CDF155.iter().map(|&(h, l)| (x128 < ((h as u128) << 64 | l as u128)) as i64).sum();
        let b = (w[3] & 1) as i64;
        let k = (b.wrapping_neg() & (2 * k0)) - k0 + b; // bimodal: b ? k0 + 1 : -k0
        // x = (b - c)(2k - b - c) / (2 * 1.55^2), in Q56
        let f1 = (b * (1i64 << s) - u as i64) * (1i64 << (56 - s));
        let f2 = ((2 * k - b) * (1i64 << s) - u as i64) * (1i64 << (56 - s));
        let x56 = (f1 as i128 * f2 as i128) >> 56;
        let x = ((x56 as u128).wrapping_mul(DSS_Q62 as u128) >> 62) as i64;
        let (mant, e) = exp_fp(x.wrapping_neg());
        // review E: the try count is public (class b): P(accept) per try is independent of the centre c up to 2^-68
        // (C grandom.c)
        let acc = bernoulli_fp(w[2], mant, e);
        let acc = crate::ct::verdict(acc);
        if acc {
            return Ok(k);
        }
    }
    Err(Error::Reject)
}

/// `_grandom_sample_i32`: `ret.len()` samples, sigma = 1.55 * 2^log2o (log2o < 24): u from log2o-bit chunks (LSB
/// first) of one leading stream read, the tries from the stream after it; each sample as C's int32 cast
fn sample_i32(ret: &mut [i64], log2o: u32, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    let nb = log2o as usize;
    let outlen = (nb * ret.len()).div_ceil(8);
    let mut out = Vec::new();
    out.try_reserve_exact(outlen).map_err(|_| Error::Memory)?;
    out.resize(outlen, 0);
    let mut st = Rng::new(seed, dom);
    st.urandom(&mut out)?;
    for (i, r) in ret.iter_mut().enumerate() {
        let mut u = 0u64;
        for j in 0..nb {
            let bit = i * nb + j;
            u |= (((out[bit >> 3] >> (bit & 7)) & 1) as u64) << j;
        }
        let k = gaussian155(&mut st, u, log2o)?;
        *r = (k * (1i64 << log2o) - u as i64) as i32 as i64;
    }
    Ok(())
}

/// `_grandom_sample`: one sample, sigma = 1.55 * 2^log2o (log2o <= 56, else C's ERR: `Error::Internal`)
fn sample(log2o: u32, seed: &[u8; 32], dom: u64) -> Result<i64, Error> {
    if log2o > 56 {
        return Err(Error::Internal);
    }
    let mut st = Rng::new(seed, dom);
    let mut buf = [0u8; 8];
    st.urandom(&mut buf[..log2o.div_ceil(8) as usize])?;
    let u = u64::from_le_bytes(buf) & ((1u64 << log2o) - 1);
    let k = gaussian155(&mut st, u, log2o)?;
    Ok(k * (1i64 << log2o) - u as i64)
}

/// `_intvec_grandom`: log2o < 24 the batch sampler, else `_grandom_sample` per element, each from the same
/// `(seed, dom)` (so all equal, as C)
pub(crate) fn grandom(r: &mut [i64], log2o: u32, seed: &[u8; 32], dom: u64) -> Result<(), Error> {
    if log2o < 24 {
        return sample_i32(r, log2o, seed, dom);
    }
    for x in r {
        *x = sample(log2o, seed, dom)?;
    }
    Ok(())
}

/// `polyvec_grandom (r, log2o, seed, dom)`: element i with counter i + 1
pub(crate) fn polyvec_grandom<R: Pv + ?Sized>(r: &mut R, log2o: u32, seed: &[u8; 32], dom: u32) -> Result<(), Error> {
    for i in 0..r.len() {
        *r.at(i) = Poly::grandom(log2o, seed, (dom as u64) << 32 | (i as u64 + 1))?;
    }
    Ok(())
}
