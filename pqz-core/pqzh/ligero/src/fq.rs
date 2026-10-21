//! F_q, q of the parameter set (`crate::set`, one per build; v3: q = 2^42 - 215), and F_q^4 = F_q[X]/(X^4 - NR) (NR the
//! set's smallest non-square: 3 in every set so far). Elements are canonical u64 (< q < 2^L, L = LOG2Q of the set). A
//! product (< 2^(2L)) is reduced by Barrett (`redx`, PQZL's arith/ntt.rs: x < 2^(2L + 4)); any u128, the lazy sums of
//! hot loops (at most 2^(128 - 2L) products: 2^44 at v3, 2^28 at L = 50), by `red` (two Barretts).
//! wasm32 has no 64 x 64 -> 128 multiply (u128 products become `__multi3` calls), so there products, F_q^4 products and
//! the lazy sums use NL limbs of W bits in u64 (`limb`: two 21-bit limbs at L = 42, as before; three of ceil(L / 3)
//! bits above, 16 at set (a), 17 at 50 bits); the results are the same canonical values, so proofs stay byte-identical
//! with native (unit test `limb_matches_u128`, and the wasm32 runs' FNV). Every reduction is branch-free (review P-B).

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

use crate::set;

pub const Q: u64 = set::Q;
/// bits of q - 1 (v3 42)
pub(crate) const L: u32 = set::LOG2Q;
const X: u32 = set::BARX;
const _: () = assert!(2 * L + 4 == X && L <= 59 && (1u64 << (L - 1)) < Q && Q < (1u64 << L));
/// bytes per F_q element in proofs (big-endian, canonical): ceil(L / 8), v3 42 bits in 6, set (a) 46 in 6, 50 in 7
pub const EB: usize = (L as usize).div_ceil(8);
/// a uniform sample is a word masked to L bits, rejected if >= q (transcript, prover rng, as expand_A)
pub(crate) const MASK: u64 = (1 << L) - 1;
/// F_q^4 non-residue; the native F_q^4 product sums (1 + 3 NR) q^2 < 2^X before `redx`
const NR: u64 = set::NR;
const _: () = assert!(NR >= 2 && NR <= 5);

/// x - q if x >= q, else x (x < 2^63), by a mask instead of a branch (review P-B: the prover's arithmetic runs on
/// secret values)
#[inline(always)]
fn csub(x: u64) -> u64 {
    let y = x.wrapping_sub(Q);
    y.wrapping_add(Q & (y >> 63).wrapping_neg())
}

/// r < 3q -> r mod q
#[inline(always)]
fn red3q(r: u64) -> u64 {
    let t = r.wrapping_sub(2 * Q);
    csub(t.wrapping_add((2 * Q) & (t >> 63).wrapping_neg()))
}

/// x < 2^X -> x mod q (Barrett, PQZL's `redx`): qh = floor(floor(x / 2^(L-1)) MUX / 2^(X-L+1)) is at most 2 below
/// floor(x / q), so x - qh q < 3q
#[inline(always)]
fn redx(x: u128) -> u64 {
    let qh = (((x >> (L - 1)) * set::MUX as u128) >> (X - L + 1)) as u64;
    red3q((x as u64).wrapping_sub(qh.wrapping_mul(Q)))
}

/// reduce any u128 to [0, q): x = hi 2^64 + lo, (hi mod q)(2^64 mod q) + lo < q^2 + 2^64 < 2^X
#[inline(always)]
pub fn red(x: u128) -> u64 {
    redx(redx(x >> 64) as u128 * set::R64 as u128 + (x as u64) as u128)
}

/// NL-limb arithmetic for wasm32 (compiled everywhere so the native tests check it against the u128 path): a product
/// is NC = 2 NL - 1 columns of u64, sum_c col_c 2^(W c); `red` normalises them to W-bit digits, folds the digits at
/// positions >= NL with 2^(W i) mod q (in limbs), and finishes with a Barrett step whose product fits u64. Only u64
/// products; u128 only for shifts and adds.
pub(crate) mod limb {
    use super::{L, NR, Q, red3q};

    /// limbs per element: two (21 bits at L = 42, today's split), three above 42 bits
    pub const NL: usize = if L <= 42 { 2 } else { 3 };
    /// limb width: ceil(L / NL)
    pub const W: u32 = L.div_ceil(NL as u32);
    /// columns of a product
    pub const NC: usize = 2 * NL - 1;
    const MW: u64 = (1 << W) - 1;
    /// digits of the carry out of the last column (< 2^(65 - W))
    const CD: usize = (65 - W as usize).div_ceil(W as usize);
    /// digits folded: positions NL .. NC + CD
    const NH: usize = NC + CD - NL;
    /// the Barrett step: x < 2^XB (asserted below), MU = floor(2^XB / q) < 2^32, floor(x / 2^(L-1)) < 2^32
    const XB: u32 = L + 31;
    const MU: u64 = ((1u128 << XB) / Q as u128) as u64;
    // a lazy accumulator holds at most 2^20 unit products (sum of the multipliers k): NL (2^W - 1)^2 2^20 < 2^64 per
    // column; the folded value sum_j (2^W + NH 2^(2W)) 2^(W j) < (NH + 1) 2^(W (NL + 1) + 1) <= 2^XB
    const _: () = assert!(
        NL as u32 * W >= L
            && ((NL as u128) * (MW as u128) * (MW as u128)) << 20 < 1u128 << 64
            && (((NH + 1) as u128) << (W * (NL as u32 + 1) + 1)) <= 1u128 << XB
    );

    /// RT[h][j]: limb j of 2^(W (NL + h)) mod q
    const RT: [[u64; NL]; NH] = {
        let mut t = [[0u64; NL]; NH];
        let mut h = 0;
        while h < NH {
            let mut r: u128 = 1;
            let mut i = 0;
            while i < W as usize * (NL + h) {
                r = r * 2 % Q as u128;
                i += 1;
            }
            let mut j = 0;
            while j < NL {
                t[h][j] = (r as u64 >> (W * j as u32)) & MW;
                j += 1;
            }
            h += 1;
        }
        t
    };

    #[inline(always)]
    fn split(a: u64) -> [u64; NL] {
        std::array::from_fn(|i| (a >> (W * i as u32)) & MW)
    }

    /// a b = sum_c col_c 2^(W c) for a, b < 2^(NL W): col_c < NL 2^(2W)
    #[inline(always)]
    pub fn mul(a: u64, b: u64) -> [u64; NC] {
        let (x, y) = (split(a), split(b));
        let mut c = [0u64; NC];
        for i in 0..NL {
            for j in 0..NL {
                c[i + j] += x[i] * y[j];
            }
        }
        c
    }

    /// sum_c col_c 2^(W c) mod q, canonical, for any u64 columns
    #[inline(always)]
    pub fn red(col: [u64; NC]) -> u64 {
        // W-bit digits d_0 .. d_(NC + CD - 1), carry kept split so nothing overflows
        let mut d = [0u64; NC + CD];
        let mut c = 0u64;
        for i in 0..NC {
            let t = (col[i] & MW) + (c & MW);
            d[i] = t & MW;
            c = (col[i] >> W) + (c >> W) + (t >> W);
        }
        for x in d.iter_mut().skip(NC) {
            *x = c & MW;
            c >>= W;
        }
        // fold: e_j = d_j + sum_h d_(NL + h) RT[h][j] < 2^W + NH 2^(2W)
        let mut e: [u64; NL] = std::array::from_fn(|j| d[j]);
        for h in 0..NH {
            for j in 0..NL {
                e[j] += d[NL + h] * RT[h][j];
            }
        }
        let mut x = 0u128;
        for (j, &v) in e.iter().enumerate() {
            x += (v as u128) << (W * j as u32);
        }
        let qh = (((x >> (L - 1)) as u64) * MU) >> (XB - L + 1);
        red3q((x as u64).wrapping_sub(qh.wrapping_mul(Q)))
    }

    /// w += k a b (a, b < q; the sum of k over all terms of one accumulator at most 2^20)
    #[inline(always)]
    pub fn mac(w: &mut [u64; NC], a: u64, b: u64, k: u64) {
        let p = mul(a, b);
        for i in 0..NC {
            w[i] += k * p[i];
        }
    }

    /// F_q^4 product, X^4 = NR (as `Mul for F4`)
    #[inline(always)]
    pub fn f4_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut c = [[0u64; NC]; 4];
        for i in 0..4 {
            for j in 0..4 {
                if i + j < 4 { mac(&mut c[i + j], a[i], b[j], 1) } else { mac(&mut c[i + j - 4], a[i], b[j], NR) }
            }
        }
        c.map(red)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fq(pub u64);

impl Fq {
    pub const ZERO: Fq = Fq(0);
    pub const ONE: Fq = Fq(1);
    /// v mod q (= `v.rem_euclid(q)`) without a division or a branch (review P-B: on wasm32 `rem_euclid` is
    /// `i64.rem_s`, whose latency depends on the operands): |v| (<= 2^63 < 2^X) by Barrett, then negated by a mask
    pub fn from_i64(v: i64) -> Fq {
        let s = (v >> 63) as u64; // all ones if v < 0
        let a = (v as u64 ^ s).wrapping_sub(s); // |v| (2^63 for i64::MIN)
        let r = redx(a as u128);
        let n = (Fq::ZERO - Fq(r)).0;
        Fq(r ^ ((r ^ n) & s))
    }
    pub fn pow(self, mut e: u64) -> Fq {
        let (mut b, mut r) = (self, Fq::ONE);
        while e > 0 {
            if e & 1 == 1 {
                r = r * b;
            }
            b = b * b;
            e >>= 1;
        }
        r
    }
    pub fn inv(self) -> Fq {
        self.pow(Q - 2)
    }
    pub fn put(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_be_bytes()[8 - EB..]);
    }
    /// EB bytes big-endian, None unless canonical
    pub fn get(b: &[u8]) -> Option<Fq> {
        let mut w = [0u8; 8];
        w[8 - EB..].copy_from_slice(&b[..EB]);
        let v = u64::from_be_bytes(w);
        (v < Q).then_some(Fq(v))
    }
}

impl Add for Fq {
    type Output = Fq;
    #[inline(always)]
    fn add(self, o: Fq) -> Fq {
        Fq(csub(self.0 + o.0))
    }
}
impl Sub for Fq {
    type Output = Fq;
    #[inline(always)]
    fn sub(self, o: Fq) -> Fq {
        let d = self.0.wrapping_sub(o.0); // review P-B: a mask, not a branch
        Fq(d.wrapping_add(Q & (d >> 63).wrapping_neg()))
    }
}
impl Neg for Fq {
    type Output = Fq;
    fn neg(self) -> Fq {
        Fq::ZERO - self
    }
}
impl Mul for Fq {
    type Output = Fq;
    #[inline(always)]
    fn mul(self, o: Fq) -> Fq {
        if cfg!(target_arch = "wasm32") {
            return Fq(limb::red(limb::mul(self.0, o.0)));
        }
        Fq(redx(self.0 as u128 * o.0 as u128))
    }
}
impl AddAssign for Fq {
    fn add_assign(&mut self, o: Fq) {
        *self = *self + o;
    }
}
impl SubAssign for Fq {
    fn sub_assign(&mut self, o: Fq) {
        *self = *self - o;
    }
}

/// a_0 + a_1 Y + a_2 Y^2 + a_3 Y^3 with Y^4 = NR (NR a non-square mod q and q = 1 mod 4: X^4 - NR is irreducible)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct F4(pub [Fq; 4]);

impl F4 {
    pub const ZERO: F4 = F4([Fq::ZERO; 4]);
    pub const ONE: F4 = F4([Fq::ONE, Fq::ZERO, Fq::ZERO, Fq::ZERO]);
    pub fn base(x: Fq) -> F4 {
        F4([x, Fq::ZERO, Fq::ZERO, Fq::ZERO])
    }
    pub fn pow(self, mut e: u64) -> F4 {
        let (mut b, mut r) = (self, F4::ONE);
        while e > 0 {
            if e & 1 == 1 {
                r = r * b;
            }
            b = b * b;
            e >>= 1;
        }
        r
    }
    pub fn put(self, out: &mut Vec<u8>) {
        for c in self.0 {
            c.put(out);
        }
    }
    pub fn get(b: &[u8]) -> Option<F4> {
        Some(F4([Fq::get(b)?, Fq::get(&b[EB..])?, Fq::get(&b[2 * EB..])?, Fq::get(&b[3 * EB..])?]))
    }
}

impl Add for F4 {
    type Output = F4;
    #[inline(always)]
    fn add(self, o: F4) -> F4 {
        F4(std::array::from_fn(|i| self.0[i] + o.0[i]))
    }
}
impl Sub for F4 {
    type Output = F4;
    #[inline(always)]
    fn sub(self, o: F4) -> F4 {
        F4(std::array::from_fn(|i| self.0[i] - o.0[i]))
    }
}
impl Neg for F4 {
    type Output = F4;
    fn neg(self) -> F4 {
        F4::ZERO - self
    }
}
impl AddAssign for F4 {
    fn add_assign(&mut self, o: F4) {
        *self = *self + o;
    }
}
impl SubAssign for F4 {
    fn sub_assign(&mut self, o: F4) {
        *self = *self - o;
    }
}
impl Mul<Fq> for F4 {
    type Output = F4;
    #[inline(always)]
    fn mul(self, o: Fq) -> F4 {
        F4(self.0.map(|c| c * o))
    }
}
impl Mul for F4 {
    type Output = F4;
    #[inline(always)]
    fn mul(self, o: F4) -> F4 {
        if cfg!(target_arch = "wasm32") {
            return F4(limb::f4_mul(self.0.map(|x| x.0), o.0.map(|x| x.0)).map(Fq));
        }
        let a = self.0.map(|x| x.0 as u128);
        let b = o.0.map(|x| x.0 as u128);
        let nr = NR as u128;
        let c0 = a[0] * b[0] + nr * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]);
        let c1 = a[0] * b[1] + a[1] * b[0] + nr * (a[2] * b[3] + a[3] * b[2]);
        let c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + nr * (a[3] * b[3]);
        let c3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0];
        F4([Fq(redx(c0)), Fq(redx(c1)), Fq(redx(c2)), Fq(redx(c3))])
    }
}

/// lazy sum of F4 x Fq products (at most 2^(128 - 2L) terms; wasm32: 2^20, `limb::mac`)
#[cfg(not(target_arch = "wasm32"))]
#[derive(Default, Clone, Copy)]
pub struct Acc4([u128; 4]);
#[cfg(not(target_arch = "wasm32"))]
impl Acc4 {
    #[inline(always)]
    pub fn add(&mut self, a: &F4, x: Fq) {
        let x = x.0 as u128;
        for i in 0..4 {
            self.0[i] += a.0[i].0 as u128 * x;
        }
    }
    pub fn get(&self) -> F4 {
        F4(self.0.map(|v| Fq(red(v))))
    }
}

/// wasm32: the NC limb columns per component, x split once
#[cfg(target_arch = "wasm32")]
#[derive(Default, Clone, Copy)]
pub struct Acc4([[u64; limb::NC]; 4]);
#[cfg(target_arch = "wasm32")]
impl Acc4 {
    #[inline(always)]
    pub fn add(&mut self, a: &F4, x: Fq) {
        for i in 0..4 {
            limb::mac(&mut self.0[i], a.0[i].0, x.0, 1);
        }
    }
    pub fn get(&self) -> F4 {
        F4(self.0.map(|w| Fq(limb::red(w))))
    }
}

/// x_i^{-1} for all i (Montgomery's trick); also returns the product of all x_i. Every x_i must be nonzero. The
/// verifier's buffers, so reserved fallibly (review P-D).
pub fn batch_inv(x: &[Fq]) -> Result<(Vec<Fq>, Fq), crate::Oom> {
    let mut pre = crate::try_vec(x.len())?;
    let mut acc = Fq::ONE;
    for &v in x {
        pre.push(acc);
        acc = acc * v;
    }
    let total = acc;
    let mut inv = acc.inv();
    let mut out = crate::try_vec(x.len())?;
    out.resize(x.len(), Fq::ZERO);
    for i in (0..x.len()).rev() {
        out[i] = inv * pre[i];
        inv = inv * x[i];
    }
    Ok((out, total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_and_red_match_naive() {
        let mut s = 0x1234_5678_9abc_def0u64;
        for _ in 0..10_000 {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let a = s % Q;
            let b = (s >> 7) % Q;
            assert_eq!((Fq(a) * Fq(b)).0 as u128, a as u128 * b as u128 % Q as u128);
            let big = (s as u128) << 64 | (s.rotate_left(17)) as u128;
            assert_eq!(red(big) as u128, big % Q as u128);
            let x = big >> (128 - X);
            assert_eq!(redx(x) as u128, x % Q as u128);
        }
        assert_eq!(red(u128::MAX) as u128, u128::MAX % Q as u128);
        assert_eq!(redx((1 << X) - 1) as u128, ((1u128 << X) - 1) % Q as u128);
        assert_eq!(Fq(12345).inv() * Fq(12345), Fq::ONE);
    }

    /// review P-B: the branch-free from_i64 / add / sub / csub give the reference values (rem_euclid, the branches)
    #[test]
    fn branch_free_matches_reference() {
        let mut s = 0x2545_f491_4f6c_dd1du64;
        let q = Q as i64;
        let mut edge = vec![0i64, 1, -1, q, -q, q - 1, 1 - q, i64::MIN, i64::MAX, i64::MIN + 1];
        edge.extend((0..100_000).map(|i| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s as i64) >> (i % 64)
        }));
        for &v in &edge {
            assert_eq!(Fq::from_i64(v).0, v.rem_euclid(Q as i64) as u64, "{v}");
        }
        for w in edge.windows(2) {
            let (a, b) = (Fq::from_i64(w[0]), Fq::from_i64(w[1]));
            let sum = a.0 + b.0;
            assert_eq!((a + b).0, if sum >= Q { sum - Q } else { sum });
            assert_eq!((a - b).0, if a.0 >= b.0 { a.0 - b.0 } else { a.0 + Q - b.0 });
        }
        for x in [0, 1, Q - 1, Q, Q + 1, 2 * Q - 1, (1 << L) + (1 << 30)] {
            assert_eq!(csub(x), if x >= Q { x - Q } else { x });
        }
        for r in [0, 1, Q - 1, Q, 2 * Q - 1, 2 * Q, 3 * Q - 1] {
            assert_eq!(red3q(r), r % Q);
        }
    }

    /// the wasm32 limb arithmetic gives the u128 path's values (products, F_q^4 products, long lazy sums, edges)
    #[test]
    fn limb_matches_u128() {
        use limb::{NC, W};
        let mut s = 0x0fed_cba9_8765_4321u64;
        let mut nx = || {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            match s % 5 {
                0 => Q - 1 - (s >> 60),
                1 => s >> 60,
                _ => (s >> 3) % Q,
            }
        };
        for _ in 0..20_000 {
            let (a, b) = (nx(), nx());
            assert_eq!(limb::red(limb::mul(a, b)), red(a as u128 * b as u128));
            let (x, y) = (F4([Fq(nx()), Fq(nx()), Fq(nx()), Fq(nx())]), F4([Fq(nx()), Fq(nx()), Fq(nx()), Fq(nx())]));
            assert_eq!(F4(limb::f4_mul(x.0.map(|v| v.0), y.0.map(|v| v.0)).map(Fq)), x * y);
        }
        for n in [1usize, 1000, 1 << 20] {
            let (mut w, mut u) = ([0u64; NC], 0u128);
            for _ in 0..n {
                let (a, b) = (nx(), nx());
                limb::mac(&mut w, a, b, 1);
                u += a as u128 * b as u128;
            }
            assert_eq!(limb::red(w), red(u), "{n} terms");
        }
        let m = Q - 1;
        let mut w = [0u64; NC];
        for _ in 0..1 << 18 {
            limb::mac(&mut w, m, m, 4);
        }
        assert_eq!(limb::red(w), red(4 * (1u128 << 18) * (m as u128 * m as u128)));
        // any u64 columns: sum_c (2^64 - 1) 2^(W c) mod q
        let pw = |e: u32| Fq(2).pow(e as u64);
        let want = (0..NC as u32).fold(Fq::ZERO, |a, c| a + Fq(red(u64::MAX as u128)) * pw(W * c));
        assert_eq!(Fq(limb::red([u64::MAX; NC])), want);
        assert_eq!(limb::red([0; NC]), 0);
    }

    #[test]
    fn field_facts_and_ext() {
        // the set's q - 1 factorisation (pqzh_set.rs), GEN generates F_q^*, NR is a non-square, q = 1 mod 4
        assert_eq!(set::QM1.iter().product::<u64>(), Q - 1);
        for &p in set::QM1 {
            assert!((2..p).take_while(|d| d * d <= p).all(|d| p % d != 0), "{p} prime");
            assert_ne!(Fq(set::GEN).pow((Q - 1) / p), Fq::ONE);
        }
        assert_eq!(Q % 4, 1);
        assert_eq!(Fq(NR).pow((Q - 1) / 2), -Fq::ONE, "NR is a non-square");
        // the smallest: 2 is a square (q = 1 mod 8), so neither a generator nor a non-residue
        assert_eq!((Q % 8, Fq(2).pow((Q - 1) / 2)), (1, Fq::ONE));
        assert_eq!((set::GEN, NR), (3, 3));
        let y = F4([Fq(0), Fq(1), Fq(0), Fq(0)]);
        assert_eq!(y.pow(4), F4::base(Fq(NR)));
        let a = F4([Fq(5), Fq(Q - 7), Fq(11), Fq(1 << (L - 2))]);
        let b = F4([Fq(13), Fq(17), Fq(Q - 19), Fq(23)]);
        let c = F4([Fq(29), Fq(31), Fq(37), Fq(41)]);
        assert_eq!((a * b) * c, a * (b * c));
        assert_eq!(a * (b + c), a * b + a * c);
        // the multiplicative group of F_q^4 has order q^4 - 1: a^(q^4 - 1) = 1, via a^(q^4) = a with 4 Frobenius
        let mut f = a;
        for _ in 0..4 {
            f = f.pow(Q);
        }
        assert_eq!(f, a);
        // and a is not in a proper subfield (F_q^2: a^(q^2) != a), so X^4 - NR really gives F_q^4
        assert_ne!(a.pow(Q).pow(Q), a);
        let (inv, prod) = batch_inv(&[Fq(2), Fq(3), Fq(5)]).unwrap();
        assert_eq!(prod, Fq(30));
        assert_eq!(inv[2] * Fq(5), Fq::ONE);
        // element bytes: canonical round trip, non-canonical rejected
        let mut v = vec![];
        Fq(Q - 1).put(&mut v);
        assert_eq!((v.len(), Fq::get(&v)), (EB, Some(Fq(Q - 1))));
        let mut w = [0u8; 8];
        w.copy_from_slice(&Q.to_be_bytes());
        assert_eq!(Fq::get(&w[8 - EB..]), None);
    }
}
