//! `pqz_fixexp.h`: the integer fixed-point exp of the Gaussian sampler and the rejection tests (no float), with C's
//! masked selects and fixed loop counts. Unsigned C arithmetic wraps here too (`wrapping_*`).
//!
//! One deliberate difference: C clamps x into [-64, 64] (Q56) through `x - X_MAX` and `x + X_MAX`, which overflow
//! (undefined behaviour) exactly when x is outside [-X_MAX, X_MAX); there the compiled C depends on the compiler's
//! reading of the overflow. This port forms both comparisons in 128 bits, so it equals C on [-X_MAX, X_MAX) and
//! saturates as intended outside. Only a rejection exponent beyond +-64 reaches that range (an acceptance
//! probability above 2^92 or below 2^-92), which no honest input produces; the build's C (clang -O2) saturates
//! there too on the oracle test's huge-exponent inputs (`oracle_rand::rejection_eq_c`).

pub(crate) const LN2_Q56: i64 = 49_946_518_145_322_874;
const INVLN2_Q60: u64 = 1_663_314_137_230_540_311;
/// |x| <= 64 in Q56
pub(crate) const X_MAX: i64 = 1 << 62;

/// 2^63 / k!
const EXP_C: [u64; 21] = [
    9223372036854775808, 9223372036854775808, 4611686018427387904, 1537228672809129301, 384307168202282325,
    76861433640456465, 12810238940076078, 1830034134296583, 228754266787073, 25417140754119, 2541714075412,
    231064915947, 19255409662, 1481185359, 105798954, 7053264, 440829, 25931, 1441, 76, 4,
];

/// `pqz_ct_sel64`: mask ? a : b (mask all ones or zero)
pub(crate) fn ct_sel64(mask: u64, a: u64, b: u64) -> u64 {
    (a & mask) | (b & !mask)
}

/// `pqz_expneg_q63`: exp(-s) in Q63 for s in [0, ln 2] in Q56
fn expneg_q63(s: u64) -> u64 {
    let mut y = EXP_C[20];
    for k in (0..20).rev() {
        y = EXP_C[k].wrapping_sub(((s as u128 * y as u128) >> 56) as u64);
    }
    y
}

/// `pqz_exp_fp`: exp(x) = mant * 2^(e - 63), mant in (2^62, 2^63], x in Q56 clamped to [-64, 64]
pub(crate) fn exp_fp(x: i64) -> (u64, i32) {
    let hi = !(((x as i128 - X_MAX as i128) >> 127) as u64); // x >= X_MAX
    let x = ct_sel64(hi, X_MAX as u64, x as u64) as i64;
    let lo = ((x as i128 + X_MAX as i128) >> 127) as u64; // x < -X_MAX
    let x = ct_sel64(lo, X_MAX.wrapping_neg() as u64, x as u64) as i64;
    // n = floor(x / ln 2)
    let mut n = ((x as i128 * INVLN2_Q60 as i128) >> 116) as i64;
    let mut r = x.wrapping_sub(n.wrapping_mul(LN2_Q56));
    // rounding of 1/ln2: bring r into [0, ln 2)
    let m1 = r >> 63;
    n = n.wrapping_add(m1);
    r = r.wrapping_add(LN2_Q56 & m1);
    let m2 = (r.wrapping_sub(LN2_Q56) >> 63) ^ -1;
    n = n.wrapping_sub(m2);
    r = r.wrapping_sub(LN2_Q56 & m2);
    // exp(r) = 2 * exp(-(ln 2 - r))
    (expneg_q63(LN2_Q56.wrapping_sub(r) as u64), n.wrapping_add(1) as i32)
}

/// `pqz_bernoulli_fp`: u / 2^64 < mant * 2^(e - 63), u uniform 64-bit
pub(crate) fn bernoulli_fp(u: u64, mant: u64, e: i32) -> bool {
    let sh = e as i64 + 1; // threshold = mant * 2^sh, compared with u
    let neg = (sh >> 63) as u64; // sh < 0
    let far = ((sh + 63) >> 63) as u64; // sh < -63: threshold 0
    let always = ((1 - sh) >> 63) as u64; // sh >= 2: threshold >= 2^64 > u
    let mut tneg = (mant >> ((sh.wrapping_neg() as u64) & 63)) as u128;
    tneg &= !(far as u128);
    let tpos = (mant as u128) << ((sh as u64) & 1);
    let nm = 0u128.wrapping_sub((neg & 1) as u128);
    let thr = (tneg & nm) | (tpos & !nm);
    (always & 1) | ((u as u128) < thr) as u64 != 0
}

/// `pqz_div_q56`: floor(a * 2^56 / d) for a < 2^70, d < 2^64 (128-step masked long division)
pub(crate) fn div_q56(a: u128, d: u64) -> u128 {
    let (n, mut rem, mut q) = (a << 56, 0u128, 0u128);
    for b in (0..128).rev() {
        rem = (rem << 1) | ((n >> b) & 1);
        let t = rem.wrapping_sub(d as u128);
        let ge = 0u128.wrapping_sub(((t >> 127) & 1) ^ 1); // rem >= d
        rem = (t & ge) | (rem & !ge);
        q |= (ge & 1) << b;
    }
    q
}
