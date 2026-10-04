//! Lifted (exponential) ElGamal on G1: `Enc_y(b; r) = (C, D) = (g^b · y^r, g^r)`.
//! Decryption recovers `g^b = C · D^{-x}`, then `b` by baby-step giant-step with a
//! client-chosen table size and bound (zether-limits §4, D4): `table_bits` 18–27, `bound_bits`
//! ≤ 54 (`MAX_TOTAL_SHIELDED`), `2^(bound_bits − table_bits)` giant steps. The baby table is
//! public data (multiples of `G`, the same for every key): generate it, or load a saved one
//! ([`BsgsTable::from_bytes`] verifies it). A wallet with a cached balance validates it with
//! [`check_balance`] (one point comparison) and never needs BSGS on `acc` (limits §5).

use std::sync::{Arc, Mutex};

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::curve::{generator, Fr, ZCurve, G};
use crate::ZError;

pub const TABLE_BITS_MIN: u32 = 18;
pub const TABLE_BITS_MAX: u32 = 27;
/// `MAX_TOTAL_SHIELDED = 2^54`: no balance can be larger.
pub const BOUND_BITS_MAX: u32 = 54;
/// wasm32: a `Vec` holds at most `isize::MAX` bytes, so the 2 GiB (2^27) table cannot exist there.
pub const WASM_TABLE_BITS_MAX: u32 = 26;
/// One baby-table entry in memory: `(u64 x-limb key, u32 j)` padded to 16 bytes.
pub const ENTRY_BYTES: u64 = 16;

/// Table memory in bytes for `table_bits`.
pub fn table_bytes(table_bits: u32) -> u64 {
    ENTRY_BYTES << table_bits
}

/// `(table_bits, bound_bits)` — the two knobs of zether-limits §4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BsgsParams {
    pub table_bits: u32,
    pub bound_bits: u32,
}

impl BsgsParams {
    /// Mobile / wasm default: 64 MiB table, balances and `pending` up to 2^44.
    pub const MOBILE: Self = Self { table_bits: 22, bound_bits: 44 };

    pub fn new(table_bits: u32, bound_bits: u32) -> Result<Self, ZError> {
        check_table_bits(table_bits)?;
        if !(1..=BOUND_BITS_MAX).contains(&bound_bits) {
            return Err(ZError::Bsgs("bound_bits must be in 1..=54"));
        }
        Ok(Self { table_bits, bound_bits })
    }

    /// Desktop default from available RAM: `bound_bits 54`, the largest `table_bits` in 24–26
    /// whose table takes at most a quarter of `available` bytes (24 below that).
    pub fn desktop(available: u64) -> Self {
        let table_bits = (24..=26).rev().find(|&b| table_bytes(b) * 4 <= available).unwrap_or(24);
        Self { table_bits, bound_bits: BOUND_BITS_MAX }
    }

    /// wasm → [`Self::MOBILE`]; native → [`Self::desktop`] of `MemAvailable`.
    pub fn for_target() -> Self {
        if cfg!(target_arch = "wasm32") {
            Self::MOBILE
        } else {
            Self::desktop(mem_available().unwrap_or(0))
        }
    }

    /// Giant steps of a worst-case search.
    pub fn giant_steps(&self) -> u64 {
        1u64 << self.bound_bits.saturating_sub(self.table_bits)
    }
}

pub fn check_table_bits(table_bits: u32) -> Result<(), ZError> {
    if !(TABLE_BITS_MIN..=TABLE_BITS_MAX).contains(&table_bits) {
        return Err(ZError::Bsgs("table_bits must be in 18..=27"));
    }
    if cfg!(target_arch = "wasm32") && table_bits > WASM_TABLE_BITS_MAX {
        return Err(ZError::Bsgs("table too large for wasm (2 GiB); use the native zether-read-balance"));
    }
    Ok(())
}

/// Refuse a table that would not fit: it needs twice its size free (the table, plus the file
/// buffer when it is saved). Unknown RAM (`None`, non-Linux) is not a refusal.
pub fn check_ram(table_bits: u32, available: Option<u64>) -> Result<(), ZError> {
    match available {
        Some(a) if a < 2 * table_bytes(table_bits) => {
            Err(ZError::Bsgs("not enough free RAM for this table_bits; pick a smaller one"))
        }
        _ => Ok(()),
    }
}

/// `MemAvailable` from `/proc/meminfo` (Linux); `None` elsewhere.
pub fn mem_available() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = s.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

#[derive(PartialEq, Eq)]
pub struct Ciphertext<C: ZCurve> {
    pub c: G<C>,
    pub d: G<C>,
}

impl<C: ZCurve> Clone for Ciphertext<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C: ZCurve> Copy for Ciphertext<C> {}

impl<C: ZCurve> Ciphertext<C> {
    pub fn zero() -> Self {
        Self { c: G::<C>::zero(), d: G::<C>::zero() }
    }
    pub fn add(&self, o: &Self) -> Self {
        Self { c: self.c + o.c, d: self.d + o.d }
    }
    pub fn sub(&self, o: &Self) -> Self {
        Self { c: self.c - o.c, d: self.d - o.d }
    }
    /// Homomorphic subtraction of a public scalar (the fee path: `C' = C · g^{-fee}`).
    pub fn sub_plain(&self, v: u64) -> Self {
        Self { c: self.c - generator::<C>() * Fr::<C>::from(v), d: self.d }
    }
}

pub fn encrypt<C: ZCurve>(y: &G<C>, b: u64, r: &Fr<C>) -> Ciphertext<C> {
    let g = generator::<C>();
    Ciphertext { c: g * Fr::<C>::from(b) + *y * r, d: g * r }
}

/// `g^b` from a ciphertext.
pub fn decrypt_point<C: ZCurve>(ct: &Ciphertext<C>, x: &Fr<C>) -> G<C> {
    ct.c - ct.d * x
}

/// Cache validation (limits §5): `[b]G == C − [x]D`. A stale or wrong cached balance fails here,
/// and a proof built on it would be refused by the prover and the contract anyway.
pub fn check_balance<C: ZCurve>(acc: &Ciphertext<C>, x: &Fr<C>, b: u64) -> bool {
    decrypt_point(acc, x) == generator::<C>() * Fr::<C>::from(b)
}

/// `pending` with the device bound of zether-limits §2.2 (2^44, table 2^22): what a wallet adds
/// to its cached balance on rollOver. Larger incoming amounts need desktop/CLI.
pub fn decrypt_pending<C: ZCurve>(pending: &Ciphertext<C>, x: &Fr<C>) -> Result<u64, ZError> {
    let p = BsgsParams::MOBILE;
    cached_table::<C>(p.table_bits)?.decrypt(pending, x, p.bound_bits)
}

/// The process-wide table for `table_bits` (one slot per curve: asking for another size drops the
/// old one, so a wasm instance never holds two).
pub fn cached_table<C: ZCurve>(table_bits: u32) -> Result<Arc<BsgsTable<C>>, ZError> {
    let mut slot = C::bsgs_slot().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(t) = slot.as_ref().filter(|t| t.bits == table_bits) {
        return Ok(t.clone());
    }
    *slot = None;
    let t = Arc::new(BsgsTable::new(table_bits)?);
    *slot = Some(t.clone());
    Ok(t)
}

/// Per-curve storage behind [`cached_table`].
pub type BsgsSlot<C> = Mutex<Option<Arc<BsgsTable<C>>>>;

/// Baby-step table `{g^j : 0 <= j < 2^table_bits}` as a sorted `(x-limb key, j)` array, built in
/// chunks so no full projective/affine copy is ever held.
pub struct BsgsTable<C: ZCurve> {
    bits: u32,
    baby: Vec<(u64, u32)>,
    giant: G<C>, // g^{-2^bits}
}

fn key<C: ZCurve>(p: &ark_ec::short_weierstrass::Affine<C>) -> u64 {
    // 64-bit x-limb key; a colliding key is resolved by the equality check in `dlog`.
    let b = p.x.into_bigint().to_bytes_le();
    u64::from_le_bytes(b[..8].try_into().unwrap()) ^ (p.infinity as u64)
}

const CHUNK: usize = 1 << 12;
const MAGIC: &[u8; 8] = b"BZBSGS1\0";

impl<C: ZCurve> BsgsTable<C> {
    pub fn new(table_bits: u32) -> Result<Self, ZError> {
        check_table_bits(table_bits)?;
        let n = 1u32 << table_bits;
        let g = generator::<C>();
        let mut baby = Vec::with_capacity(n as usize);
        let mut pts = Vec::with_capacity(CHUNK);
        let mut acc = G::<C>::zero();
        for j in 0..n {
            pts.push(acc);
            acc += g;
            if pts.len() == CHUNK || j + 1 == n {
                let base = j + 1 - pts.len() as u32;
                baby.extend(G::<C>::normalize_batch(&pts).iter().zip(base..).map(|(p, i)| (key::<C>(p), i)));
                pts.clear();
            }
        }
        baby.sort_unstable();
        Ok(Self::with_baby(table_bits, baby))
    }

    fn with_baby(bits: u32, baby: Vec<(u64, u32)>) -> Self {
        Self { bits, baby, giant: -(generator::<C>() * Fr::<C>::from(1u64 << bits)) }
    }

    pub fn table_bits(&self) -> u32 {
        self.bits
    }

    /// Discrete log of `target` base g in `[0, 2^bound_bits)`, or `ZError::DecryptBound`. Giant
    /// steps go in batches of 4096 sharing one inversion. A table entry only proposes `v`; the
    /// answer is `v` only when `[v]G == target`, so a bad table can miss but never lie.
    pub fn dlog(&self, target: &G<C>, bound_bits: u32) -> Result<u64, ZError> {
        if !(1..=BOUND_BITS_MAX).contains(&bound_bits) {
            return Err(ZError::Bsgs("bound_bits must be in 1..=54"));
        }
        let g = generator::<C>();
        let (bound, m) = (1u64 << bound_bits, 1u64 << self.bits);
        let steps = 1u64 << bound_bits.saturating_sub(self.bits);
        let mut cur = *target;
        let mut pts = Vec::with_capacity(CHUNK);
        let mut i = 0u64;
        while i < steps {
            pts.clear();
            for _ in 0..(CHUNK as u64).min(steps - i) {
                pts.push(cur);
                cur += self.giant;
            }
            for (t, a) in G::<C>::normalize_batch(&pts).iter().enumerate() {
                let k = key::<C>(a);
                let from = self.baby.partition_point(|e| e.0 < k);
                for &(_, j) in self.baby[from..].iter().take_while(|e| e.0 == k) {
                    let v = (i + t as u64) * m + j as u64;
                    if v < bound && g * Fr::<C>::from(v) == *target {
                        return Ok(v);
                    }
                }
            }
            i += pts.len() as u64;
        }
        Err(ZError::DecryptBound)
    }

    pub fn decrypt(&self, ct: &Ciphertext<C>, x: &Fr<C>, bound_bits: u32) -> Result<u64, ZError> {
        self.dlog(&decrypt_point(ct, x), bound_bits)
    }

    /// `MAGIC ‖ u8 len ‖ curve name ‖ u8 table_bits ‖ (u64 key LE ‖ u32 j LE)*` — 12 B per entry.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        b.push(C::NAME.len() as u8);
        b.extend_from_slice(C::NAME.as_bytes());
        b.push(self.bits as u8);
        b.reserve(12 * self.baby.len());
        for &(k, j) in &self.baby {
            b.extend_from_slice(&k.to_le_bytes());
            b.extend_from_slice(&j.to_le_bytes());
        }
        b
    }

    /// Load a saved/downloaded table and verify it: header, size, sorted, every `j` exactly once,
    /// and 64 random entries recomputed (`key == key([j]G)`). With `dlog`'s final equality check
    /// a table that slips through can only make a search miss, never return a wrong balance.
    pub fn from_bytes(b: &[u8]) -> Result<Self, ZError> {
        let bad = |w| Err(ZError::Bsgs(w));
        let name = C::NAME.as_bytes();
        let head = MAGIC.len() + 1 + name.len() + 1;
        if b.len() < head || &b[..8] != MAGIC || b[8] as usize != name.len() || &b[9..9 + name.len()] != name {
            return bad("not a BSGS table for this curve");
        }
        let bits = b[head - 1] as u32;
        check_table_bits(bits)?;
        let n = 1usize << bits;
        if b.len() != head + 12 * n {
            return bad("table length does not match table_bits");
        }
        let mut baby = Vec::with_capacity(n);
        let mut seen = vec![0u64; n / 64];
        for e in b[head..].chunks_exact(12) {
            let (k, j) = (u64::from_le_bytes(e[..8].try_into().unwrap()), u32::from_le_bytes(e[8..].try_into().unwrap()));
            let ju = j as usize;
            if ju >= n || seen[ju / 64] >> (ju % 64) & 1 == 1 || baby.last().is_some_and(|&p| p > (k, j)) {
                return bad("table entries are not a sorted permutation of 0..2^table_bits");
            }
            seen[ju / 64] |= 1 << (ju % 64);
            baby.push((k, j));
        }
        let g = generator::<C>();
        let mut rnd = [0u8; 8 * 64];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut rnd);
        for c in rnd.chunks_exact(8) {
            let (k, j) = baby[(u64::from_le_bytes(c.try_into().unwrap()) as usize) % n];
            if key::<C>(&(g * Fr::<C>::from(j as u64)).into_affine()) != k {
                return bad("table entry does not match its multiple of G");
            }
        }
        Ok(Self::with_baby(bits, baby))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Bls12381, Bn254};
    use ark_ff::UniformRand;

    fn keypair<C: ZCurve>(rng: &mut impl rand_core::RngCore) -> (Fr<C>, G<C>) {
        let x = Fr::<C>::rand(rng);
        (x, generator::<C>() * x)
    }

    fn homomorphic<C: ZCurve>() {
        let mut rng = ark_std::test_rng();
        let (x, y) = keypair::<C>(&mut rng);
        let t = cached_table::<C>(18).unwrap();
        // Cached per curve, and the size `table_bytes` states.
        assert!(Arc::ptr_eq(&t, &cached_table::<C>(18).unwrap()));
        assert_eq!(std::mem::size_of_val(&t.baby[..]) as u64, table_bytes(18));
        let a = encrypt(&y, 1_000_000, &Fr::<C>::rand(&mut rng));
        let b = encrypt(&y, 234_567, &Fr::<C>::rand(&mut rng));
        assert_eq!(t.decrypt(&a, &x, 24).unwrap(), 1_000_000);
        assert_eq!(t.decrypt(&a.add(&b), &x, 24).unwrap(), 1_234_567);
        assert_eq!(t.decrypt(&a.sub(&b), &x, 24).unwrap(), 765_433);
        assert_eq!(t.decrypt(&a.sub_plain(300), &x, 24).unwrap(), 999_700);
        assert_eq!(t.decrypt(&Ciphertext::zero(), &x, 24).unwrap(), 0);
        // Negative plaintext (b - a) is outside the bound: a clear error, never a wrap.
        assert_eq!(t.decrypt(&b.sub(&a), &x, 24), Err(ZError::DecryptBound));
        // Wrong key does not decrypt to the value.
        let (x2, _) = keypair::<C>(&mut rng);
        assert_ne!(t.decrypt(&a, &x2, 24).ok(), Some(1_000_000));
        // Bound edges, giant steps crossing a 4096 batch: 2^26 − 1 decrypts, 2^26 does not.
        let r = Fr::<C>::rand(&mut rng);
        assert_eq!(t.decrypt(&encrypt(&y, (1 << 26) - 1, &r), &x, 26).unwrap(), (1 << 26) - 1);
        assert_eq!(t.decrypt(&encrypt(&y, 1 << 26, &r), &x, 26), Err(ZError::DecryptBound));
        // bound < table: values the table would find but the bound excludes are refused.
        assert_eq!(t.decrypt(&encrypt(&y, 1 << 12, &r), &x, 12), Err(ZError::DecryptBound));
        assert_eq!(t.decrypt(&encrypt(&y, (1 << 12) - 1, &r), &x, 12).unwrap(), (1 << 12) - 1);
        // check_balance: one comparison, any size.
        let big = encrypt(&y, (1 << 54) - 3, &r);
        assert!(check_balance(&big, &x, (1 << 54) - 3));
        assert!(!check_balance(&big, &x, (1 << 54) - 2));
        assert!(!check_balance(&big, &x2, (1 << 54) - 3));
        assert!(check_balance(&Ciphertext::<C>::zero(), &x, 0));
    }

    #[test]
    fn elgamal_bn254() {
        homomorphic::<Bn254>();
    }

    #[test]
    fn elgamal_bls12_381() {
        homomorphic::<Bls12381>();
    }

    #[test]
    fn knobs() {
        // Sizes of zether-limits §4: 22 → 64 MiB, 24 → 256 MiB, 27 → 2 GiB.
        assert_eq!(table_bytes(22), 64 << 20);
        assert_eq!(table_bytes(24), 256 << 20);
        assert_eq!(table_bytes(27), 2 << 30);
        assert_eq!(BsgsParams::MOBILE.giant_steps(), 1 << 22);
        assert_eq!(BsgsParams::new(24, 54).unwrap().giant_steps(), 1 << 30);
        assert_eq!(BsgsParams::new(27, 54).unwrap().giant_steps(), 1 << 27);
        assert_eq!(BsgsParams::new(22, 20).unwrap().giant_steps(), 1);
        for (t, b) in [(17, 40), (28, 40), (22, 55), (22, 0)] {
            assert!(matches!(BsgsParams::new(t, b), Err(ZError::Bsgs(_))), "{t}/{b}");
        }
        // Desktop: largest of 24..=26 using at most a quarter of RAM.
        assert_eq!(BsgsParams::desktop(0), BsgsParams { table_bits: 24, bound_bits: 54 });
        assert_eq!(BsgsParams::desktop(2 << 30).table_bits, 25);
        assert_eq!(BsgsParams::desktop(64 << 30).table_bits, 26);
        assert_eq!(BsgsParams::for_target().bound_bits, 54); // native test target
        assert!(BsgsTable::<Bn254>::new(17).is_err());
        assert!(check_ram(24, Some(512 << 20)).is_ok());
        assert!(check_ram(24, Some((512 << 20) - 1)).is_err());
        assert!(check_ram(27, None).is_ok());
    }

    #[test]
    fn table_save_load_verify() {
        let t = BsgsTable::<Bn254>::new(18).unwrap();
        let bytes = t.to_bytes();
        assert_eq!(bytes.len(), 15 + (12 << 18));
        let u = BsgsTable::<Bn254>::from_bytes(&bytes).unwrap();
        assert_eq!(u.table_bits(), 18);
        assert!(u.baby == t.baby && u.giant == t.giant);
        // Other curve, truncated, duplicated j, unsorted, wrong key: refused.
        assert!(BsgsTable::<Bls12381>::from_bytes(&bytes).is_err());
        assert!(BsgsTable::<Bn254>::from_bytes(&bytes[..bytes.len() - 12]).is_err());
        let head = 15;
        let mut dup = bytes.clone();
        dup.copy_within(head + 8..head + 12, head + 12 + 8);
        assert!(BsgsTable::<Bn254>::from_bytes(&dup).is_err());
        let mut swap = bytes.clone();
        swap.copy_within(head..head + 12, head + 12 * 5);
        assert!(BsgsTable::<Bn254>::from_bytes(&swap).is_err());
        // Every key replaced by a sorted fake: the sampled recomputation catches it.
        let mut fake = bytes.clone();
        for (i, e) in fake[head..].chunks_exact_mut(12).enumerate() {
            e[..8].copy_from_slice(&(i as u64).to_le_bytes());
            e[8..].copy_from_slice(&(i as u32).to_le_bytes());
        }
        assert!(BsgsTable::<Bn254>::from_bytes(&fake).is_err());
    }
}
