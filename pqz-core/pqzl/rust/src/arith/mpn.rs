//! `pqz_mpn.h`: the GMP mpn limb operations the ported int code calls (in-place forms, as every caller passes
//! `r == a`). Constant-time in the operand values: loops run over the full limb counts, conditional steps use masks;
//! division is bitwise restoring division. `mpn_sec_invert`, `mpn_com` / `cnd_swap` / `sec_add_1` and `mpn_mul_1`
//! serve only C functions nothing in the core calls (`int_invmod`, `int_add_ct`, `int_mul1`) and are not ported.
use super::int::MAXL;

/// `r <<= cnt` for 0 < cnt < 64; returns the bits shifted out
pub(crate) fn lshift(r: &mut [u64], cnt: u32) -> u64 {
    let n = r.len();
    let out = r[n - 1] >> (64 - cnt);
    for i in (1..n).rev() {
        r[i] = (r[i] << cnt) | (r[i - 1] >> (64 - cnt));
    }
    r[0] <<= cnt;
    out
}

/// `r >>= cnt` for 0 < cnt < 64; returns the bits shifted out (at the top of the limb)
pub(crate) fn rshift(r: &mut [u64], cnt: u32) -> u64 {
    let n = r.len();
    let out = r[0] << (64 - cnt);
    for i in 0..n - 1 {
        r[i] = (r[i] >> cnt) | (r[i + 1] << (64 - cnt));
    }
    r[n - 1] >>= cnt;
    out
}

/// `r[0..an+bn) = a * b` (schoolbook)
pub(crate) fn sec_mul(r: &mut [u64], a: &[u64], b: &[u64]) {
    let (an, bn) = (a.len(), b.len());
    r[..an + bn].fill(0);
    for j in 0..bn {
        let mut c = 0u64;
        for i in 0..an {
            let p = a[i] as u128 * b[j] as u128 + r[i + j] as u128 + c as u128;
            r[i + j] = p as u64;
            c = (p >> 64) as u64;
        }
        r[an + j] = c;
    }
}

/// `r -= m` (masked) when `top` or `r >= m`
fn cnd_sub_ge(r: &mut [u64], m: &[u64], top: u64) {
    let mut t = [0u64; MAXL];
    let mut br = 0u64;
    for i in 0..r.len() {
        let d = r[i].wrapping_sub(m[i]);
        let b1 = (r[i] < m[i]) as u64;
        t[i] = d.wrapping_sub(br);
        br = b1 | (d < br) as u64;
    }
    let take = ((top | (br ^ 1)) & 1).wrapping_neg();
    for i in 0..r.len() {
        r[i] = (r[i] & !take) | (t[i] & take);
    }
}

/// `pqz__div`: restoring division, one bit at a time over all `nn * 64` bits: `np / dp` → quotient
/// `qp[0..nn-dn)` plus the returned limb `q[nn-dn]`, remainder in `np[0..dn)`; `dp[dn-1] != 0`
pub(crate) fn div(qp: Option<&mut [u64]>, np: &mut [u64], dp: &[u64]) -> u64 {
    let (nn, dn) = (np.len(), dp.len());
    let mut rem = [0u64; MAXL];
    let mut q = [0u64; MAXL];
    for bit in (0..nn * 64).rev() {
        let top = rem[dn - 1] >> 63;
        lshift(&mut rem[..dn], 1);
        rem[0] |= (np[bit >> 6] >> (bit & 63)) & 1;
        let mut br = 0u64;
        for i in 0..dn {
            let d = rem[i].wrapping_sub(dp[i]);
            br = (rem[i] < dp[i]) as u64 | (d < br) as u64;
        }
        let ge = (top | (br ^ 1)) & 1;
        cnd_sub_ge(&mut rem[..dn], dp, top);
        q[bit >> 6] |= ge << (bit & 63);
    }
    np[..dn].copy_from_slice(&rem[..dn]);
    if let Some(qp) = qp {
        qp[..nn - dn].copy_from_slice(&q[..nn - dn]);
    }
    q[nn - dn]
}
