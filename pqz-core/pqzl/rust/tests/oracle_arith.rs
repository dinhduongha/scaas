//! The arithmetic layer against the C core (feature `c-oracle`): 10,000 seeded random inputs per test, Rust output =
//! C output word for word. NTT entry points of `pqz_ntt.c` are called directly; the vector / matrix / sparse sequence
//! runs through `pqz_shim_polyvec_ops` (tests/oracle_shim.c) and its mirror `testkit::polyvec_ops`, the multi-limb
//! int / int-vector sequence through `pqz_shim_int_ops` and `testkit::int_ops`.
use pqzl::c_oracle::{c_int_ops, c_ntt_basemul, c_ntt_fwd, c_ntt_inv, c_polyvec_ops};
use pqzl::testkit::{int_ops, ntt_basemul, ntt_fwd, ntt_inv, polyvec_ops, INT_OPS_IN, OPS_IN};

const Q: u64 = 4_398_046_510_889;
const H: i64 = ((Q - 1) / 2) as i64;
const N: usize = 10_000;

/// xorshift64*
struct Rnd(u64);

impl Rnd {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(2_685_821_657_736_338_717)
    }

    /// residues in [0, q); every 16th vector all q - 1 or all 0 (the edges)
    fn residues(&mut self, t: usize) -> [u64; 64] {
        match t % 16 {
            0 => [Q - 1; 64],
            1 => [0; 64],
            _ => core::array::from_fn(|_| self.next() % Q),
        }
    }

    /// coefficients of one kind per poly: centred, [0, q), ternary, out of range (|v| < 2^50), ±(q-1)/2
    fn coeffs(&mut self, out: &mut [i64]) {
        let kind = self.next() % 5;
        for v in out {
            let r = self.next();
            *v = match kind {
                0 => (r % Q) as i64 - H,
                1 => (r % Q) as i64,
                2 => (r % 3) as i64 - 1,
                3 => (r % (1 << 51)) as i64 - (1 << 50),
                _ => [H, -H][(r & 1) as usize],
            };
        }
    }
}

#[test]
fn ntt_roundtrip_eq_c() {
    let mut g = Rnd(0x5EED_0001);
    for t in 0..N {
        let a = g.residues(t);
        let (mut r, mut c) = (a, a);
        ntt_fwd(&mut r);
        c_ntt_fwd(&mut c);
        assert_eq!(r, c, "fwd, input {t}");
        ntt_inv(&mut r);
        c_ntt_inv(&mut c);
        assert_eq!(r, c, "inv, input {t}");
        assert_eq!(r, a, "inv(fwd(a)) != a, input {t}");
    }
}

#[test]
fn basemul_eq_c() {
    let mut g = Rnd(0x5EED_0002);
    for t in 0..N {
        let (a, b) = (g.residues(t), g.residues(t / 16 * 16 + 2));
        assert_eq!(ntt_basemul(&a, &b), c_ntt_basemul(&a, &b), "input {t}");
    }
}

#[test]
fn polyvec_ops_eq_c() {
    let mut g = Rnd(0x5EED_0003);
    let mut inp = vec![0i64; OPS_IN];
    for t in 0..N {
        for p in inp[..OPS_IN - 1].chunks_mut(64) {
            g.coeffs(p);
        }
        inp[OPS_IN - 1] = (g.next() % Q) as i64 - H;
        let (r, c) = (polyvec_ops(&inp), c_polyvec_ops(&inp));
        // 131 polys x 66 words, two ints x 4 words, one flag
        assert_eq!(c.as_ref().map(Vec::len), Ok(131 * 66 + 2 * 4 + 1), "C shim");
        assert_eq!(r, c, "input {t}");
    }
}

#[test]
fn int_ops_eq_c() {
    let mut g = Rnd(0x5EED_0004);
    for t in 0..N {
        // limbs: full width, small, or zero (carries, borrows, zero tops, negative zeros)
        let inp: [u64; INT_OPS_IN] = core::array::from_fn(|i| {
            let r = g.next();
            match (i, g.next() % 4) {
                (10..=17, 0) => ((r % Q) as i64 - H) as u64,
                (10..=17, _) => r % (1 << 40),
                (_, 0) => 0,
                (_, 1) => r % 1000,
                _ => r,
            }
        });
        let (r, c) = (int_ops(&inp), c_int_ops(&inp));
        assert!(c.as_ref().is_ok_and(|c| c.len() > 100), "C shim: {:?}", c.as_ref().err());
        assert_eq!(r, c, "input {t}: {inp:?}");
    }
}
