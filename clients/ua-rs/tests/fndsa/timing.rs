// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A timing measurement of falcon-rs 0.3.1 under `fpemu` (the Fable audit's list, docs/audit/audited/vendor-falcon-rs.md), in
//! the style of dudect: for each function, inputs of a fixed class and of a random class, interleaved at random, each sample
//! timed over `reps` calls; Welch's t between the classes, the largest |t| over dudect's percentile crops. |t| above 4.5 is
//! evidence that the time depends on the input. A measurement tool, not a gate (no timing run without the owner's word):
//! tests/fndsa_timing.rs natively (`--ignored`), tests/fndsa/wasm `timing` under Node (timing.cjs). Degree 512 only.
//! Rejection loops are variable time by design (the sampler's accept count, `sign_dyn`'s norm retries, `soft::sign`'s padded
//! retry): their rows mix that in, read them with it. `ber_exp`, `ff_sampling_fft_dyntree` and `do_sign_dyn` are private:
//! measured through `sampler`, `sign_dyn` and `soft::sign`. Keygen (variable time by design) is not measured. UNAUDITED.
use super::soft;
use core::hint::black_box;
use falcon::codec::{trim_i8_decode, MAX_FG_BITS, MAX_FG_BITS_UPPER};
use falcon::fft;
use falcon::fpr::*;
use falcon::rng::{prng_init, prng_refill, Prng};
use falcon::shake::{i_shake256_flip, i_shake256_init, i_shake256_inject, InnerShake256Context};
use falcon::sign::{gaussian0_sampler, sampler, sign_dyn, SamplerContext};
use falcon::vrfy::complete_private;

const LOGN: u32 = 9;
const N: usize = 512;
const THRESHOLD: f64 = 4.5;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn bit(&mut self) -> bool {
        self.next() >> 63 != 0
    }
    /// In [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// A finite value with a random sign, mantissa and exponent in [-40, 40] (exponent gaps 0 to 80 between two of them).
    fn fpr(&mut self) -> Fpr {
        let s = if self.bit() { -1.0 } else { 1.0 };
        Fpr::new(s * (1.0 + self.unit()) * 2f64.powi((self.next() % 81) as i32 - 40))
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn welch(a: &[f64], b: &[f64]) -> f64 {
    let stats = |v: &[f64]| {
        let m = v.iter().sum::<f64>() / v.len() as f64;
        (
            m,
            v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0),
        )
    };
    let ((ma, va), (mb, vb)) = (stats(a), stats(b));
    let d = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if d == 0.0 {
        0.0
    } else {
        (ma - mb) / d
    }
}

/// The largest |t| over the samples below dudect's percentile crops (the tail is preemption, not the code).
fn max_t(c0: &[f64], c1: &[f64]) -> f64 {
    let mut all: Vec<f64> = c0.iter().chain(c1).copied().collect();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut best: f64 = 0.0;
    for q in [1.0, 0.9, 0.8, 0.7, 0.6, 0.5] {
        let cut = all[((all.len() - 1) as f64 * q) as usize];
        let (a, b): (Vec<f64>, Vec<f64>) = (
            c0.iter().copied().filter(|x| *x <= cut).collect(),
            c1.iter().copied().filter(|x| *x <= cut).collect(),
        );
        if a.len() > 10 && b.len() > 10 {
            best = best.max(welch(&a, &b).abs());
        }
    }
    best
}

/// |t| of `run` over `n` samples; `prep` builds the sample's input of its class (false: fixed, true: random), untimed.
fn measure<I>(
    now: &dyn Fn() -> f64,
    n: usize,
    reps: usize,
    rng: &mut Rng,
    mut prep: impl FnMut(bool, &mut Rng) -> I,
    mut run: impl FnMut(&mut I),
) -> f64 {
    let (mut c0, mut c1) = (Vec::new(), Vec::new());
    for i in 0..n + n / 10 {
        let class = rng.bit();
        let mut x = prep(class, rng);
        let t = now();
        for _ in 0..reps {
            run(&mut x);
        }
        let dt = now() - t;
        if i >= n / 10 {
            // the first tenth warms up
            let v = if class { &mut c1 } else { &mut c0 };
            v.push(dt);
        }
    }
    max_t(&c0, &c1)
}

fn shake(seed: &[u8]) -> InnerShake256Context {
    let mut sc = InnerShake256Context::new();
    i_shake256_init(&mut sc);
    i_shake256_inject(&mut sc, seed);
    i_shake256_flip(&mut sc);
    sc
}

fn prng(seed: &[u8]) -> Prng {
    let mut p = Prng::new();
    prng_init(&mut p, &mut shake(seed));
    p
}

/// A buffer aligned for `Fpr` (falcon-rs's low-level functions check alignment in debug builds only, FR-8).
struct Tmp(Vec<u64>);

impl Tmp {
    fn new(bytes: usize) -> Self {
        Tmp(vec![0u64; bytes.div_ceil(8)])
    }
    fn get(&mut self) -> &mut [u8] {
        // SAFETY: a u64 buffer seen as its bytes, its full length
        unsafe { core::slice::from_raw_parts_mut(self.0.as_mut_ptr() as *mut u8, self.0.len() * 8) }
    }
}

/// A secret key's f, g, F, G (round 3's encoding, `complete_private` for G).
struct Key {
    sk: Vec<u8>,
    fg: [Vec<i8>; 4],
}

fn key(seed: &[u8]) -> Key {
    let (mut pk, mut sk) = (vec![0u8; 897], vec![0u8; 1281]);
    assert_eq!(soft::keypair(LOGN, seed, &mut pk, &mut sk), 0);
    let mut fg = [vec![0i8; N], vec![0i8; N], vec![0i8; N], vec![0i8; N]];
    let mut u = 1;
    for (i, bits) in [MAX_FG_BITS[9], MAX_FG_BITS[9], MAX_FG_BITS_UPPER[9]]
        .iter()
        .enumerate()
    {
        let v = trim_i8_decode(&mut fg[i], LOGN, *bits as u32, &sk[u..]);
        assert!(v != 0);
        u += v;
    }
    let [f, g, big_f, big_g] = &mut fg;
    assert!(complete_private(
        big_g,
        f,
        g,
        big_f,
        LOGN,
        Tmp::new(8 * N).get()
    ));
    Key { sk, fg }
}

/// Every row `name |t|`, a `<- above 4.5` mark where the classes differ; `scale` multiplies the sample counts.
pub fn run(now: &dyn Fn() -> f64, scale: usize) -> String {
    let mut rng = Rng(0x5ca5_fa1c_0000_0001);
    let mut out = Vec::new();
    let mut row = |name: &str, t: f64| {
        let mark = if t > THRESHOLD { "  <- above 4.5" } else { "" };
        out.push(format!("{name:<28} |t| = {t:6.2}{mark}"));
    };
    let ns = 4000 * scale;
    let fixed = (Fpr::new(1.25), Fpr::new(-3.375));
    let pair = |r: &mut Rng, c: bool| if c { (r.fpr(), r.fpr()) } else { fixed };
    macro_rules! binary {
        ($($name:literal: $f:expr),* $(,)?) => {$(
            row($name, measure(now, ns, 64, &mut rng, |c, r| pair(r, c), |(x, y)| {
                black_box($f(black_box(*x), black_box(*y)));
            }));
        )*};
    }
    binary!(
        "fpr_add": fpr_add, "fpr_sub": fpr_sub, "fpr_mul": fpr_mul, "fpr_div": fpr_div,
        "fpr_lt": fpr_lt,
    );
    // BerExp's domain: x in [0, ln 2), ccs in [0, 1]
    row(
        "fpr_expm_p63",
        measure(
            now,
            ns,
            64,
            &mut rng,
            |c, r| {
                if c {
                    (Fpr::new(r.unit() * 0.69), Fpr::new(r.unit()))
                } else {
                    (Fpr::new(0.25), Fpr::new(0.75))
                }
            },
            |(x, y)| {
                black_box(fpr_expm_p63(black_box(*x), black_box(*y)));
            },
        ),
    );
    macro_rules! unary {
        ($($name:literal: $f:expr),* $(,)?) => {$(
            row($name, measure(now, ns, 64, &mut rng, |c, r| pair(r, c).0, |x| {
                black_box($f(black_box(*x)));
            }));
        )*};
    }
    unary!(
        "fpr_sqr": fpr_sqr, "fpr_inv": fpr_inv, "fpr_half": fpr_half, "fpr_double": fpr_double,
        "fpr_rint": fpr_rint, "fpr_floor": fpr_floor, "fpr_trunc": fpr_trunc,
    );
    row(
        "fpr_sqrt",
        measure(
            now,
            ns,
            64,
            &mut rng,
            |c, r| Fpr(pair(r, c).0 .0 & !(1 << 63)),
            |x| {
                black_box(fpr_sqrt(black_box(*x)));
            },
        ),
    );
    let int = |r: &mut Rng, c: bool| if c { (r.next() as i64) >> 12 } else { 12289 };
    row(
        "fpr_of",
        measure(
            now,
            ns,
            64,
            &mut rng,
            |c, r| int(r, c),
            |i| {
                black_box(fpr_of(black_box(*i)));
            },
        ),
    );
    row(
        "fpr_scaled",
        measure(
            now,
            ns,
            64,
            &mut rng,
            |c, r| (int(r, c), (r.next() % 64) as i32 - 32),
            |(i, s)| {
                black_box(fpr_scaled(black_box(*i), black_box(*s)));
            },
        ),
    );
    let seed = |r: &mut Rng, c: bool| if c { r.bytes(48) } else { vec![7u8; 48] };
    row(
        "gaussian0_sampler",
        measure(
            now,
            ns,
            8,
            &mut rng,
            |c, r| prng(&seed(r, c)),
            |p| {
                black_box(gaussian0_sampler(p));
            },
        ),
    );
    row(
        "sampler (centre, sigma)",
        measure(
            now,
            ns / 4,
            8,
            &mut rng,
            |c, r| {
                let (mu, s) = if c {
                    (r.unit() * 200.0 - 100.0, 1.28 + r.unit() * 0.54)
                } else {
                    (0.5, 1.5)
                };
                (
                    SamplerContext {
                        p: prng(&[7u8; 48]),
                        sigma_min: FPR_SIGMA_MIN[9],
                    },
                    Fpr::new(mu),
                    Fpr::new(1.0 / s),
                )
            },
            |(ctx, mu, is)| {
                black_box(sampler(ctx, *mu, *is));
            },
        ),
    );
    row(
        "prng_init",
        measure(
            now,
            ns,
            1,
            &mut rng,
            |c, r| shake(&seed(r, c)),
            |sc| {
                let mut p = Prng::new();
                prng_init(&mut p, sc);
                black_box(&p);
            },
        ),
    );
    row(
        "prng_refill",
        measure(
            now,
            ns,
            4,
            &mut rng,
            |c, r| prng(&seed(r, c)),
            |p| {
                prng_refill(p);
                black_box(&*p);
            },
        ),
    );
    let poly_fixed: Vec<Fpr> = (0..N).map(|_| rng.fpr()).collect();
    let poly = |r: &mut Rng, c: bool| -> Vec<Fpr> {
        if c {
            (0..N).map(|_| r.fpr()).collect()
        } else {
            poly_fixed.clone()
        }
    };
    let np = 400 * scale;
    row(
        "fft",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| poly(r, c),
            |a| fft::fft(a, LOGN),
        ),
    );
    row(
        "ifft",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| poly(r, c),
            |a| fft::ifft(a, LOGN),
        ),
    );
    row(
        "poly_mul_fft",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| (poly(r, c), poly(r, c)),
            |(a, b)| fft::poly_mul_fft(a, b, LOGN),
        ),
    );
    row(
        "poly_ldl_fft",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| (poly(r, c), poly(r, c), poly(r, c)),
            |(a, b, d)| fft::poly_ldl_fft(a, b, d, LOGN),
        ),
    );
    row(
        "poly_split_fft",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| poly(r, c),
            |f| {
                let (mut f0, mut f1) = (vec![Fpr::new(0.0); N / 2], vec![Fpr::new(0.0); N / 2]);
                fft::poly_split_fft(&mut f0, &mut f1, f, LOGN);
                black_box((f0, f1));
            },
        ),
    );
    row(
        "poly_merge_fft",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| poly(r, c),
            |f| {
                let mut out = vec![Fpr::new(0.0); N];
                fft::poly_merge_fft(&mut out, &f[..N / 2], &f[N / 2..], LOGN);
                black_box(out);
            },
        ),
    );
    // key load and signing: a fixed key against seven others
    let keys: Vec<Key> = (0..8u8).map(|i| key(&[i; 48])).collect();
    let pick = |r: &mut Rng, c: bool| if c { 1 + (r.next() % 7) as usize } else { 0 };
    let nk = 200 * scale;
    row(
        "trim_i8_decode (f)",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| (pick(r, c), vec![0i8; N]),
            |(k, f)| {
                black_box(trim_i8_decode(
                    f,
                    LOGN,
                    MAX_FG_BITS[9] as u32,
                    &keys[*k].sk[1..],
                ));
            },
        ),
    );
    row(
        "complete_private",
        measure(
            now,
            np,
            1,
            &mut rng,
            |c, r| (pick(r, c), vec![0i8; N], Tmp::new(8 * N)),
            |(k, g, t)| {
                let [f, gg, big_f, _] = &keys[*k].fg;
                black_box(complete_private(g, f, gg, big_f, LOGN, t.get()));
            },
        ),
    );
    let mut hm = vec![0u16; N];
    falcon::common::hash_to_point_vartime(&mut shake(b"ua-rs fndsa timing"), &mut hm, LOGN);
    row(
        "sign_dyn (key)",
        measure(
            now,
            nk,
            1,
            &mut rng,
            |c, r| (pick(r, c), shake(&[9u8; 48]), Tmp::new(80 * N)),
            |(k, sc, t)| {
                let [f, g, big_f, big_g] = &keys[*k].fg;
                let mut sig = vec![0i16; N];
                sign_dyn(&mut sig, sc, f, g, big_f, big_g, &hm, LOGN, t.get());
                black_box(sig);
            },
        ),
    );
    row(
        "soft::sign (key)",
        measure(
            now,
            nk,
            1,
            &mut rng,
            |c, r| pick(r, c),
            |k| {
                let mut sig = vec![0u8; 666];
                assert!(soft::sign(
                    LOGN,
                    &keys[*k].sk,
                    &[3u8; 32],
                    &[5u8; 88],
                    &mut sig
                ));
                black_box(sig);
            },
        ),
    );
    let above = out.iter().filter(|l| l.ends_with("4.5")).count();
    out.push(format!(
        "{} rows, {above} above {THRESHOLD} (scale {scale})",
        out.len()
    ));
    out.join("\n")
}
