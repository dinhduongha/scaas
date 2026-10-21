//! Mixed-radix FFT over F_q on subgroups H_n of order n | 4 * 2 * 19 * 43 * 431 (the set's radices, pqzh_set.rs: 2, 19,
//! 43 and 431 in every set so far, all dividing q - 1; owner decision 2026-10-14: the radix-431 stage for longer codes). Each radix-r stage is a direct r-point DFT with lazy
//! u128 accumulation (r + 1 products per point and stage), decimation in time, natural order in and out.

use crate::Wiped;
use crate::fq::{Fq, Q, red};

/// the set's generator of F_q^* (3 in every set so far)
pub const GEN: Fq = Fq(crate::set::GEN);
/// stage order, outermost first: the largest radix is the deepest stage (it sees the zero padding)
pub const RADICES: [usize; 4] = crate::set::RADICES;
/// the largest domain: 2^3 * 19 * 43 * 431 (4 * the product of the radices)
const NMAX: usize = 4 * RADICES[0] * RADICES[1] * RADICES[2] * RADICES[3];
const _: () = assert!((Q - 1).is_multiple_of(NMAX as u64));

pub fn smooth(n: usize) -> bool {
    let mut m = n;
    for r in RADICES {
        while m % r == 0 {
            m /= r;
        }
    }
    m == 1 && NMAX % n == 0
}

pub struct Domain {
    pub n: usize,
    pub radices: Vec<usize>,
    /// w[i] = omega^i, omega = 3^((q-1)/n) (primitive n-th root)
    pub w: Vec<Fq>,
    pub n_inv: Fq,
}

impl Domain {
    pub fn new(n: usize) -> Domain {
        Domain::try_new(n).expect("out of memory")
    }

    /// `new` with the table reserved fallibly (the verifier's domains, review P-D)
    pub fn try_new(n: usize) -> Result<Domain, crate::Oom> {
        assert!(n >= 1 && smooth(n), "domain size {n} not 2^a 19^b 43^c 431^d dividing q - 1");
        let mut radices = Vec::new();
        let mut m = n;
        for r in RADICES {
            while m % r == 0 {
                radices.push(r);
                m /= r;
            }
        }
        let om = GEN.pow((Q - 1) / n as u64);
        let mut w = crate::try_vec(n)?;
        let mut x = Fq::ONE;
        for _ in 0..n {
            w.push(x);
            x = x * om;
        }
        Ok(Domain { n, radices, w, n_inv: Fq(n as u64).inv() })
    }

    /// omega^e for any (possibly negative) exponent
    pub fn pw(&self, e: i64) -> Fq {
        self.w[e.rem_euclid(self.n as i64) as usize]
    }

    /// evaluations at omega^0..omega^(n-1) of the polynomial with coefficients `a` (len <= n, zero-padded)
    pub fn fft(&self, a: &[Fq]) -> Vec<Fq> {
        let mut inp = Wiped(Vec::with_capacity(self.n)); // the prover's secret coefficients (review P-C)
        inp.extend_from_slice(&a[..a.len().min(self.n)]);
        inp.resize(self.n, Fq::ZERO);
        let mut out = vec![Fq::ZERO; self.n];
        self.rec(&inp, a.len(), 1, &mut out, 0, 1, false);
        out
    }

    /// coefficients (len n) of the polynomial with evaluations `v` on H_n
    pub fn ifft(&self, v: &[Fq]) -> Vec<Fq> {
        assert_eq!(v.len(), self.n);
        let mut out = vec![Fq::ZERO; self.n];
        self.rec(v, self.n, 1, &mut out, 0, 1, true);
        out.iter_mut().for_each(|x| *x = *x * self.n_inv);
        out
    }

    /// evaluations on the coset g H_n
    pub fn coset_fft(&self, a: &[Fq], g: Fq) -> Vec<Fq> {
        let mut s = Fq::ONE;
        let b: Wiped<Vec<Fq>> = Wiped(
            a.iter()
                .map(|&c| {
                    let v = c * s;
                    s = s * g;
                    v
                })
                .collect(),
        );
        self.fft(&b)
    }

    /// DIT on inp[0], inp[stride], ... (size n / tstep), root omega^tstep; result in out (natural order). `len`: inp[j]
    /// is zero for every j >= len (the zero padding of `fft`: structural, public).
    #[allow(clippy::too_many_arguments)]
    fn rec(&self, inp: &[Fq], len: usize, stride: usize, out: &mut [Fq], level: usize, tstep: usize, inv: bool) {
        let size = out.len();
        if size == 1 {
            out[0] = inp[0];
            return;
        }
        let r = self.radices[level];
        let m = size / r;
        for s in 0..r {
            let ls = len.saturating_sub(s * stride);
            self.rec(&inp[s * stride..], ls, stride * r, &mut out[s * m..(s + 1) * m], level + 1, tstep * r, inv);
        }
        let n = self.n;
        let w = &self.w;
        let ix = |e: usize| if inv { (n - e % n) % n } else { e % n };
        if r == 2 {
            for k in 0..m {
                let t = w[ix(tstep * k)] * out[m + k];
                let a = out[k];
                out[k] = a + t;
                out[m + k] = a - t;
            }
            return;
        }
        // eps = omega^(tstep m), a primitive r-th root: eps^x = w[tstep m (x mod r)]
        let eps: Vec<u128> = (0..r).map(|x| w[ix(tstep * m * x)].0 as u128).collect();
        // deepest stage of a zero-padded input (encoding k coefficients on n points): sub-transform s is all zero when
        // its first input index s * stride >= len, so only the first ns are nonzero, and the r-point DFT costs r per
        // nonzero input instead of r^2. Decided by the structure, never by the values (review P-A: the values are the
        // prover's witness in `ifft`, which has no padding and is always dense); the outputs are the same either way.
        let ns = len.div_ceil(stride).min(r);
        let mut t = Wiped(vec![0u128; r]);
        for k in 0..m {
            for s in 0..r {
                let v = out[s * m + k];
                t[s] = if s == 0 { v.0 as u128 } else { red(w[ix(tstep * s * k)].0 as u128 * v.0 as u128) as u128 };
            }
            if ns * 4 < r {
                for u in 0..r {
                    let acc: u128 = (0..ns).map(|s| t[s] * eps[s * u % r]).sum();
                    out[k + u * m] = Fq(red(acc));
                }
                continue;
            }
            for u in 0..r {
                let mut acc = 0u128;
                let mut e = 0;
                for &ts in t.iter() {
                    acc += ts * eps[e];
                    e += u;
                    if e >= r {
                        e -= r;
                    }
                }
                out[k + u * m] = Fq(red(acc));
            }
        }
    }
}

/// evaluate a polynomial with F_q coefficients at x (Horner)
pub fn eval(c: &[Fq], x: Fq) -> Fq {
    c.iter().rev().fold(Fq::ZERO, |acc, &v| acc * x + v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(a: &[Fq], om: Fq) -> Vec<Fq> {
        (0..a.len()).map(|k| eval(a, om.pow(k as u64))).collect()
    }

    #[test]
    fn fft_matches_naive_all_radices() {
        for n in [1usize, 2, 4, 8, 19, 38, 43, 86, 152, 431, 862, 817, 1634, 3448, 18533, 32756] {
            let d = Domain::new(n);
            let a: Vec<Fq> = (0..n as u64).map(|i| Fq((i * 7919 + 13) * 1_000_003 % Q)).collect();
            let f = d.fft(&a);
            if n <= 1634 {
                assert_eq!(f, naive(&a, d.w[1 % n]), "n = {n}");
            }
            assert_eq!(d.ifft(&f), a, "n = {n}");
            // zero-padded input (the sparse path of the deepest stage)
            let sp = &a[..(n / 40).max(1)];
            let fs = d.fft(sp);
            for k in [0, 1, n / 3, n - 1].into_iter().filter(|&k| k < n) {
                assert_eq!(fs[k], eval(sp, d.w[k]), "sparse n = {n}");
            }
            let g = Fq(3);
            let c = d.coset_fft(&a, g);
            for k in [0, n / 2, n - 1] {
                assert_eq!(c[k], eval(&a, g * d.w[k]));
            }
        }
        assert!(smooth(32756) && smooth(18533) && !smooth(431 * 431) && !smooth(16));
        // the domains exist in F_q^* (q - 1 = 2^3 * 19 * 43 * 431 * ... in every set) and GEN H_n misses H_k for THE
        // preset (the Lagrange denominators eta - omega_k^c of the verifier are nonzero): GEN^lcm(n, k) != 1
        let (n, k) = (crate::set::PRESET_N, crate::set::PRESET_K);
        assert!(smooth(n) && smooth(k));
        let lcm = n / (1..=k).rev().find(|d| n % d == 0 && k % d == 0).unwrap() * k;
        assert!((Q - 1).is_multiple_of(lcm as u64) && GEN.pow(lcm as u64) != Fq::ONE);
    }
}
