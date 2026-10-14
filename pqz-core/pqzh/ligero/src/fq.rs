//! F_q, q = 2^42 - 215 (the PQZ modulus), and F_q^4 = F_q[X]/(X^4 - 3). Elements are canonical u64 (< q); a
//! product (< 2^84) and sums of up to 2^44 products are reduced once from u128 (lazy accumulation in hot loops).

use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

pub const Q: u64 = (1 << 42) - 215;
const M42: u64 = (1 << 42) - 1;
/// bytes per F_q element in proofs (big-endian, 42 bits in 6 bytes, canonical)
pub const EB: usize = 6;

/// reduce any u128 to [0, q): 2^42 = 215 mod q, folded three times
#[inline(always)]
pub fn red(x: u128) -> u64 {
    let x = (x & M42 as u128) + (x >> 42) * 215; // < 2^95
    let x = (x & M42 as u128) + (x >> 42) * 215; // < 2^61
    let x = x as u64;
    let x = (x & M42) + (x >> 42) * 215; // < 2^42 + 2^28
    if x >= Q { x - Q } else { x }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fq(pub u64);

impl Fq {
    pub const ZERO: Fq = Fq(0);
    pub const ONE: Fq = Fq(1);
    pub fn from_i64(v: i64) -> Fq {
        Fq(v.rem_euclid(Q as i64) as u64)
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
        let s = self.0 + o.0;
        Fq(if s >= Q { s - Q } else { s })
    }
}
impl Sub for Fq {
    type Output = Fq;
    #[inline(always)]
    fn sub(self, o: Fq) -> Fq {
        Fq(if self.0 >= o.0 { self.0 - o.0 } else { self.0 + Q - o.0 })
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
        let a = self.0.map(|x| x.0 as u128);
        let b = o.0.map(|x| x.0 as u128);
        let c0 = a[0] * b[0] + 3 * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]);
        let c1 = a[0] * b[1] + a[1] * b[0] + 3 * (a[2] * b[3] + a[3] * b[2]);
        let c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + 3 * (a[3] * b[3]);
        let c3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0];
        F4([Fq(red(c0)), Fq(red(c1)), Fq(red(c2)), Fq(red(c3))])
    }
}

/// lazy sum of F4 x Fq products (at most 2^40 terms)
#[derive(Default, Clone, Copy)]
pub struct Acc4([u128; 4]);
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

/// x_i^{-1} for all i (Montgomery's trick); also returns the product of all x_i. Every x_i must be nonzero.
pub fn batch_inv(x: &[Fq]) -> (Vec<Fq>, Fq) {
    let mut pre = Vec::with_capacity(x.len());
    let mut acc = Fq::ONE;
    for &v in x {
        pre.push(acc);
        acc = acc * v;
    }
    let total = acc;
    let mut inv = acc.inv();
    let mut out = vec![Fq::ZERO; x.len()];
    for i in (0..x.len()).rev() {
        out[i] = inv * pre[i];
        inv = inv * x[i];
    }
    (out, total)
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
        let (inv, prod) = batch_inv(&[Fq(2), Fq(3), Fq(5)]);
        assert_eq!(prod, Fq(30));
        assert_eq!(inv[2] * Fq(5), Fq::ONE);
    }
}
