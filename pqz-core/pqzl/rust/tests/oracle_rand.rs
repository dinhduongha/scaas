//! Hashing, the rng and the samplers against the C core (feature `c-oracle`) and the frozen CBD vectors: 1,000
//! seeded inputs per oracle test, Rust = C (outputs and error codes). The C halves are `pqz_shim_*` in
//! tests/oracle_shim.c, the Rust halves `testkit::rand_*`.
use pqzl::c_oracle::{c_autostable, c_grandom, c_rej, c_rej_limbs, c_rng, c_shake, c_urandom, c_urandom_bnd};
use pqzl::testkit::{rand_autostable, rand_cbd, rand_grandom, rand_rej, rand_rej_limbs, rand_rng, rand_shake,
                    rand_urandom, rand_urandom_bnd};

const N: usize = 1_000;

/// xorshift64*
struct Rnd(u64);

impl Rnd {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(2_685_821_657_736_338_717)
    }

    /// uniform in [lo, hi]
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }

    fn seed(&mut self) -> [u8; 32] {
        core::array::from_fn(|_| self.next() as u8)
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn cbd_eq_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../smartcontracts/vectors/pqz/cbd.json");
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut parts = 0;
    for row in doc["rows"].as_array().unwrap() {
        let input = hex(row["stream"].as_str().unwrap());
        for p in row["parts"].as_array().unwrap() {
            let want: Vec<i32> = p["samples"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap() as i32).collect();
            let (eta, off) = (p["eta"].as_u64().unwrap() as u32, p["bit_offset"].as_u64().unwrap() as usize);
            assert_eq!(rand_cbd(&input, eta, off, want.len()), want, "{}", p["what"]);
            parts += 1;
        }
    }
    assert_eq!(parts, 12);
}

#[test]
fn aes_ctr_eq_c() {
    let mut g = Rnd(0x5EED_0101);
    for t in 0..N {
        let (seed, dom) = (g.seed(), [0, g.next() % 1000, g.next()][t % 3]);
        // pieces across and on the 64-byte cache boundary of the C stream
        let lens: Vec<u32> = (0..g.range(1, 24)).map(|_| [g.range(1, 200), 64, 128, g.range(1, 7)][(g.next() % 4) as usize] as u32).collect();
        let c = c_rng(&seed, dom, &lens);
        assert!(c.is_ok(), "C shim, input {t}");
        assert_eq!(rand_rng(&seed, dom, &lens), c, "input {t}: {lens:?}");
    }
}

#[test]
fn shake_eq_c() {
    let mut g = Rnd(0x5EED_0102);
    for t in 0..N {
        let which = [128, 256][t % 2];
        let input: Vec<u8> = (0..g.range(0, 600)).map(|_| g.next() as u8).collect();
        let mut alens = Vec::new();
        let mut left = input.len() as u64;
        while left > 0 {
            let l = g.range(0, left.min(200));
            alens.push(l as u32);
            left -= l;
        }
        // pieces of 0, 1..7, a rate (168 / 136) and odd lengths, so squeezes start at every lane offset
        let slens: Vec<u32> = (0..g.range(1, 12)).map(|_| [0, g.range(1, 7), 168, 136, g.range(1, 400)][(g.next() % 5) as usize] as u32).collect();
        let c = c_shake(which, &input, &alens, &slens);
        assert!(c.is_ok(), "C shim, input {t}");
        assert_eq!(Ok(rand_shake(which, &input, &alens, &slens)), c, "input {t}: {alens:?} {slens:?}");
    }
}

#[test]
fn grandom_eq_c() {
    let mut g = Rnd(0x5EED_0103);
    let mut ok = 0;
    for t in 0..N {
        let (seed, dom) = (g.seed(), g.next() as u32);
        // the relations' 12, 14, 18; the batch path below 24; the per-element path 24..=56; 0 (C's assert)
        let log2o = match t % 8 {
            0 => 0,
            1 | 2 => g.range(24, 56),
            3 => g.range(1, 23),
            _ => [12, 14, 18][(g.next() % 3) as usize],
        } as u32;
        let n = g.range(1, 64) as u32;
        let (r, c) = (rand_grandom(&seed, dom, log2o, n), c_grandom(&seed, dom, log2o, n));
        assert_eq!(r, c, "input {t}: log2o {log2o}, n {n}");
        ok += c.is_ok() as usize;
    }
    assert_eq!(ok, N - N / 8, "only log2o = 0 fails");
}

/// the relations' scaled rejection constants (scM1..4 of the generated params) and sigma^2 values
const SCM: [[u64; 3]; 6] = [
    [8572305810566612808, 7388047769732707509, 3],
    [4108071457691967674, 16250232613065535289, 2],
    [11899225040202848731, 340872919609692453, 1],
    [1655797669362676316, 318580927907168899, 1],
    [16069742532520767656, 5509346396741098414, 2],
    [17541772227239051601, 15429691808631841182, 2],
];
const SIGMA2: [u64; 5] = [165098542858, 40307261, 644916183, 161229046, 9841];

#[test]
fn rejection_eq_c() {
    let mut g = Rnd(0x5EED_0104);
    let (mut rejects, mut accepts, mut errors) = (0, 0, 0);
    for t in 0..N {
        let (seed, dom) = (g.seed(), g.next());
        let scm = SCM[(g.next() % 6) as usize];
        let s2 = SIGMA2[(g.next() % 5) as usize];
        let n = 64 * g.range(1, 8) as usize;
        let (z, v): (Vec<i64>, Vec<i64>) = if t % 10 == 9 {
            // near 2^62: the dot products wrap or reach 2^126 (C's ERR)
            (0..n).map(|_| ((g.next() >> 1) as i64 >> g.range(0, 3), (g.next() >> 1) as i64 >> g.range(0, 3))).unzip()
        } else if t % 10 == 8 {
            // exponents far beyond +-64 (z up to 2^50, v up to 2^12, either sign)
            (0..n).map(|_| ((g.next() >> 13) as i64 - (1 << 50), (g.next() >> 51) as i64 - (1 << 12))).unzip()
        } else {
            // |v|^2 / sigma^2 ~ c in [0.01, 4], y uniform with deviation sigma, z = y + v: exponents of a few units
            let c100 = g.range(1, 400);
            let b = (3 * s2 * c100 / (100 * n as u64)).isqrt().max(1);
            let a = (3 * s2).isqrt();
            (0..n)
                .map(|_| {
                    let v = g.range(0, 2 * b) as i64 - b as i64;
                    (g.range(0, 2 * a) as i64 - a as i64 + v, v)
                })
                .unzip()
        };
        for bimodal in [false, true] {
            let (r, c) = (rand_rej(bimodal, &seed, dom, &z, &v, &scm, &[s2, 0]), c_rej(bimodal, &seed, dom, &z, &v, &scm, &[s2, 0]));
            assert_eq!(r, c, "input {t}, bimodal {bimodal}");
            match c {
                Ok((true, _)) => rejects += 1,
                Ok((false, _)) => accepts += 1,
                Err(_) => errors += 1,
            }
        }
    }
    eprintln!("rejection_eq_c: {rejects} rejects, {accepts} accepts, {errors} errors, all equal");
    assert!(rejects > N / 5 && accepts > N / 5 && errors > 0);
}

/// pqz_ub_test.c part a's rejection cases (exponents near +-2^63) on 200 streams: C = Rust, and the expected verdict
/// (below -2^63 saturates and rejects, num above 2^127 saturates and accepts); the one-limb cases through
/// `pqz_shim_rej`, S3 (two-limb entries, num = 2^127; review round 2, the port's deferred minor) through
/// `pqz_shim_rej_limbs`
#[test]
fn rejection_saturation_eq_c() {
    const MAX: i64 = i64::MAX;
    let (scm, s2) = ([0, 1 << 63, 1], [1 << 20, 0]);
    let cases = [
        (false, -MAX, MAX, false),     // S1 t2 - 2 t1 saturates at 2^127 - 1
        (false, 1 << 62, 1, true),     // S2 t - ln M saturates at -2^63
        (false, -(1 << 62), 1, false), // S4 t - ln M near +2^63
        (true, 1 << 62, 1, true),      // B1 a - |y| - ln M saturates at -2^63
        (true, 0, MAX, false),         // B2 a - |y| - ln M near +2^63
    ];
    let mut g = Rnd(0x5EED_010B);
    for t in 0..200 {
        let (seed, dom) = (g.seed(), g.next());
        for (k, &(bimodal, z, v, want)) in cases.iter().enumerate() {
            let (r, c) = (rand_rej(bimodal, &seed, dom, &[z], &[v], &scm, &s2), c_rej(bimodal, &seed, dom, &[z], &[v], &scm, &s2));
            assert_eq!(r, c, "stream {t}, case {k}");
            assert_eq!(c.map(|x| x.0), Ok(want), "stream {t}, case {k}");
        }
        // S3: z = (-(2^126 - 1), 0), v = (1, 1) in two limbs: t2 = 2, t1 = -(2^126 - 1), num = 2^127 saturates, accepts
        let (z3, v3) = ([u64::MAX, (1 << 62) - 1, 1, 0, 0, 0], [1, 0, 0, 1, 0, 0]);
        let (r, c) = (rand_rej_limbs(false, &seed, dom, &z3, &v3, 2, &scm, &s2),
                      c_rej_limbs(false, &seed, dom, &z3, &v3, 2, &scm, &s2));
        assert_eq!(r, c, "stream {t}, case S3");
        assert_eq!(c.map(|x| x.0), Ok(false), "stream {t}, case S3");
    }
}

/// an int as 5 words: limbs, sign, nlimbs; limbs below 2^62 (hi - lo never wraps to 0)
fn int5(g: &mut Rnd, nlimbs: u64, small: bool) -> [u64; 5] {
    let mut w = [0u64; 5];
    for x in &mut w[..nlimbs as usize] {
        *x = if small { g.range(0, 1000) } else { g.next() >> 2 };
    }
    w[3] = g.next().is_multiple_of(4) as u64;
    w[4] = nlimbs;
    w
}

#[test]
fn urandom_eq_c() {
    let mut g = Rnd(0x5EED_0105);
    let mut ok = 0;
    for t in 0..N {
        let (seed, dom) = (g.seed(), g.next() as u32);
        let (n, nl) = (g.range(1, 64) as u32, g.range(1, 3) as u32);
        // uniform mod m: the 64-bit path (log2mod < 60; every 16th m one above or below its range: C's assert), the
        // multi-limb path (log2mod >= 60, m >= 4)
        let (m, log2mod) = if t % 2 == 0 {
            let l = g.range(2, 59);
            let m = match t % 32 {
                0 => (1 << (l - 1)) - 1,
                16 => 1 << l,
                _ => g.range(1 << (l - 1), (1 << l) - 1),
            };
            ([m, 0, 0, 0, 1], l as u32)
        } else {
            let nm = g.range(1, 3);
            let mut m = int5(&mut g, nm, false);
            m[0] |= 4;
            (m, g.range(60, 191) as u32)
        };
        let (r, c) = (rand_urandom(&seed, dom, n, nl, &m, log2mod), c_urandom(&seed, dom, n, nl, &m, log2mod));
        assert_eq!(r, c, "urandom, input {t}: m {m:?}, log2mod {log2mod}, nl {nl}");
        ok += c.is_ok() as usize;

        // uniform in [lo, hi] (either order, either sign, lo / hi wider than the vector: C's assert)
        let small = g.next().is_multiple_of(2);
        let (nlo, nhi) = (g.range(1, 3), g.range(1, 3));
        let (lo, mut hi) = (int5(&mut g, nlo, small), int5(&mut g, nhi, small));
        if hi[0] == lo[0] {
            hi[0] ^= 1;
        }
        let (r, c) = (rand_urandom_bnd(&seed, dom, n, nl, &lo, &hi), c_urandom_bnd(&seed, dom, n, nl, &lo, &hi));
        assert_eq!(r, c, "urandom_bnd, input {t}: lo {lo:?}, hi {hi:?}, nl {nl}");
        ok += c.is_ok() as usize;

        // the autostable challenge: 2 bnd + 1 in [2^(log2-1), 2^log2), every 8th one too wide (C's assert)
        let log2 = g.range(1, 20);
        let bnd = match t % 8 {
            0 => 1 << (log2 - 1),
            _ => g.range((1 << (log2 - 1)) / 2, ((1 << log2) - 2) / 2),
        } as i64;
        let (r, c) = (rand_autostable(&seed, dom, bnd, log2 as u32), c_autostable(&seed, dom, bnd, log2 as u32));
        assert_eq!(r, c, "autostable, input {t}: bnd {bnd}, log2 {log2}");
        ok += c.is_ok() as usize;
    }
    assert!(ok > 2 * N, "{ok} of {} succeed", 3 * N);
}
