//! F_q, q = 2^42 - 215 (the PQZ modulus), and F_q^4 = F_q[X]/(X^4 - 3). Elements are canonical u64 (< q); a
//! product (< 2^84) and sums of up to 2^44 products are reduced once from u128 (lazy accumulation in hot loops).
//! wasm32 has no 64 x 64 -> 128 multiply (u128 products become `__multi3` calls), so there products, F_q^4 products and
//! the lazy sums use 21-bit pieces in u64 (`limb`); the results are the same canonical values, so proofs stay
//! byte-identical with native (unit test `limb_matches_u128`, and the wasm32 runs' FNV).

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

pub const Q: u64 = (1 << 42) - 215;
const M42: u64 = (1 << 42) - 1;
/// bytes per F_q element in proofs (big-endian, 42 bits in 6 bytes, canonical)
pub const EB: usize = 6;

/// x - q if x >= q, else x (x < 2^63), by a mask instead of a branch (review P-B: the prover's arithmetic runs on
/// secret values)
#[inline(always)]
fn csub(x: u64) -> u64 {
    let y = x.wrapping_sub(Q);
    y.wrapping_add(Q & (y >> 63).wrapping_neg())
}

/// 21-bit-piece arithmetic for wasm32 (compiled everywhere so the native tests check it against the u128 path)
pub(crate) mod limb {
    use super::{M42, csub};
    const M21: u64 = (1 << 21) - 1;

    /// a b = h 2^42 + m 2^21 + l for a, b < 2^42: l, h < 2^42, m < 2^43
    #[inline(always)]
    pub fn mul3(a: u64, b: u64) -> [u64; 3] {
        let (a0, a1, b0, b1) = (a & M21, a >> 21, b & M21, b >> 21);
        [a0 * b0, a0 * b1 + a1 * b0, a1 * b1]
    }

    #[inline(always)]
    fn fold(x: u64) -> u64 {
        (x & M42) + (x >> 42) * 215 // < 2^42 + 2^30
    }

    /// h 2^42 + m 2^21 + l mod q, canonical, for any u64 l, m, h
    #[inline(always)]
    pub fn red3([l, m, h]: [u64; 3]) -> u64 {
        let (l, m, h) = (fold(l), fold(m), fold(h));
        // m 2^21 = (m >> 21) 2^42 + (m & M21) 2^21; 2^42 = 215: s < 2^42 + 2^43 + 2^51
        csub(fold(l + ((m & M21) << 21) + ((m >> 21) + h) * 215)) // < 2^42 + 2^18 before csub
    }

    /// w += k a b (a, b < q; the sum of k over all terms of one accumulator at most 2^20)
    #[inline(always)]
    pub fn mac(w: &mut [u64; 3], a: u64, b: u64, k: u64) {
        let p = mul3(a, b);
        for i in 0..3 {
            w[i] += k * p[i];
        }
    }

    /// F_q^4 product, X^4 = 3 (as `Mul for F4`)
    #[inline(always)]
    pub fn f4_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
        let mut c = [[0u64; 3]; 4];
        for i in 0..4 {
            for j in 0..4 {
                if i + j < 4 { mac(&mut c[i + j], a[i], b[j], 1) } else { mac(&mut c[i + j - 4], a[i], b[j], 3) }
            }
        }
        c.map(red3)
    }
}

/// reduce any u128 to [0, q): 2^42 = 215 mod q, folded three times
#[inline(always)]
pub fn red(x: u128) -> u64 {
    let x = (x & M42 as u128) + (x >> 42) * 215; // < 2^95
    let x = (x & M42 as u128) + (x >> 42) * 215; // < 2^61
    let x = x as u64;
    csub((x & M42) + (x >> 42) * 215) // < 2^42 + 2^28 before csub
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fq(pub u64);

impl Fq {
    pub const ZERO: Fq = Fq(0);
    pub const ONE: Fq = Fq(1);
    /// v mod q (= `v.rem_euclid(q)`) without a division or a branch (review P-B: on wasm32 `rem_euclid` is
    /// `i64.rem_s`, whose latency depends on the operands): |v| folded at 2^42 = 215 (mod q), then negated by a mask
    pub fn from_i64(v: i64) -> Fq {
        let s = (v >> 63) as u64; // all ones if v < 0
        let a = (v as u64 ^ s).wrapping_sub(s); // |v| (2^63 for i64::MIN)
        let a = (a & M42) + (a >> 42) * 215; // < 2^42 + 2^30
        let r = csub((a & M42) + (a >> 42) * 215); // < 2^42 + 215 before csub
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
        out.extend_from_slice(&self.0.to_be_bytes()[2..]);
    }
    /// 6 bytes big-endian, None unless canonical
    pub fn get(b: &[u8]) -> Option<Fq> {
        let mut w = [0u8; 8];
        w[2..].copy_from_slice(&b[..EB]);
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
            return Fq(limb::red3(limb::mul3(self.0, o.0)));
        }
        Fq(red(self.0 as u128 * o.0 as u128))
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

/// a_0 + a_1 Y + a_2 Y^2 + a_3 Y^3 with Y^4 = 3 (3 is a non-square mod q and q = 1 mod 4: X^4 - 3 is irreducible)
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
        let c0 = a[0] * b[0] + 3 * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]);
        let c1 = a[0] * b[1] + a[1] * b[0] + 3 * (a[2] * b[3] + a[3] * b[2]);
        let c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + 3 * (a[3] * b[3]);
        let c3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0];
        F4([Fq(red(c0)), Fq(red(c1)), Fq(red(c2)), Fq(red(c3))])
    }
}

/// lazy sum of F4 x Fq products (at most 2^40 terms; wasm32: 2^20, `limb::mac`)
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

/// wasm32: (l, m, h) pieces per component, x split once
#[cfg(target_arch = "wasm32")]
#[derive(Default, Clone, Copy)]
pub struct Acc4([[u64; 3]; 4]);
#[cfg(target_arch = "wasm32")]
impl Acc4 {
    #[inline(always)]
    pub fn add(&mut self, a: &F4, x: Fq) {
        for i in 0..4 {
            limb::mac(&mut self.0[i], a.0[i].0, x.0, 1);
        }
    }
    pub fn get(&self) -> F4 {
        F4(self.0.map(|w| Fq(limb::red3(w))))
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
        }
        assert_eq!(red(u128::MAX) as u128, u128::MAX % Q as u128);
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
        for x in [0, 1, Q - 1, Q, Q + 1, 2 * Q - 1, (1 << 42) + (1 << 30)] {
            assert_eq!(csub(x), if x >= Q { x - Q } else { x });
        }
    }

    /// the wasm32 piece arithmetic gives the u128 path's values (products, F_q^4 products, long lazy sums, edges)
    #[test]
    fn limb_matches_u128() {
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
            assert_eq!(limb::red3(limb::mul3(a, b)), red(a as u128 * b as u128));
            let (x, y) = (F4([Fq(nx()), Fq(nx()), Fq(nx()), Fq(nx())]), F4([Fq(nx()), Fq(nx()), Fq(nx()), Fq(nx())]));
            assert_eq!(F4(limb::f4_mul(x.0.map(|v| v.0), y.0.map(|v| v.0)).map(Fq)), x * y);
        }
        for n in [1usize, 1000, 1 << 20] {
            let (mut w, mut u) = ([0u64; 3], 0u128);
            for _ in 0..n {
                let (a, b) = (nx(), nx());
                limb::mac(&mut w, a, b, 1);
                u += a as u128 * b as u128;
            }
            assert_eq!(limb::red3(w), red(u), "{n} terms");
        }
        let m = Q - 1;
        let mut w = [0u64; 3];
        for _ in 0..1 << 18 {
            limb::mac(&mut w, m, m, 3);
        }
        assert_eq!(limb::red3(w), red(3 * (1u128 << 18) * (m as u128 * m as u128)));
        assert_eq!(limb::red3([u64::MAX; 3]), red((u64::MAX as u128) * ((1 << 42) + (1 << 21) + 1)));
    }

    #[test]
    fn field_facts_and_ext() {
        // 3 generates F_q^*: q - 1 = 2^3 * 19 * 43 * 431 * 1561243
        for p in [2u64, 19, 43, 431, 1561243] {
            assert_ne!(Fq(3).pow((Q - 1) / p), Fq::ONE);
        }
        assert_eq!(Fq(3).pow((Q - 1) / 2), -Fq::ONE, "3 is a non-square");
        let y = F4([Fq(0), Fq(1), Fq(0), Fq(0)]);
        assert_eq!(y.pow(4), F4::base(Fq(3)));
        let a = F4([Fq(5), Fq(Q - 7), Fq(11), Fq(1 << 40)]);
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
        let (inv, prod) = batch_inv(&[Fq(2), Fq(3), Fq(5)]).unwrap();
        assert_eq!(prod, Fq(30));
        assert_eq!(inv[2] * Fq(5), Fq::ONE);
    }
}
