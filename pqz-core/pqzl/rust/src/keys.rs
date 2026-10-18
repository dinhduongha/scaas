//! `pqz_keys.c` (KeyGen, Enc from seeds, Dec, the R_TXM group seed; pq-zero-knowledge.md §4.2) and the ring work of
//! `pqz_rel.c` it calls: `expand_A`, `pqz_keypair_from_secret`, `pqz_encrypt`, `pqz_decrypt_raw`, with `rd_poly` /
//! `wr_poly` (be8 coefficients) and `set_short`.
//!
//! Each KeyGen / Enc attempt reads one SHAKE256 stream, tag || seed || be4(ctr), bits LSB first: s then e (KeyGen),
//! r, e1, then e2_j in recipient order (Enc); an attempt above a norm threshold is resampled with the next counter,
//! counter 64 is `Error::Reject`. The C core expands A once in `pqz_init`; there is no init here (no globals): the
//! ring calls take A as `&mut Option<PolyMat>` and expand it at the point C would first read it ([`a_of`]). The
//! free functions pass a fresh `None` (A is expanded per call, ~3 ms); the `Ctx` methods pass the `Ctx`'s cached A,
//! the one its relations use (A is only read: every product moves it to the NTT domain, where it already is).
use crate::arith::int::Int;
use crate::arith::ntt::{D, Q};
use crate::arith::poly::Poly;
use crate::arith::polymat::{Pm, PolyMat};
use crate::arith::polyvec::{self, PolyVec};
use crate::rand::shake::{cbd, shake128, Stream};
use crate::{Enc, Error, Key, CT_BYTES, POLYVEC_BYTES, V_BYTES};
use alloc::boxed::Box;
use alloc::vec::Vec;

const N: usize = 2048;
const K: usize = 32;
const DELTA: i64 = (1 << 26) - 1;
const MAXCTR: u32 = 64;
/// the norm thresholds ‖s‖, ‖e‖ (KeyGen; Enc's r, e1) and ‖e2_j‖ (Enc)
pub(crate) const BS: i64 = 36;
pub(crate) const BE: i64 = 164;
pub(crate) const B2: i64 = 64;

/// `set_c`: coefficient j of p := v (via the coefficient domain)
fn set_c(p: &mut Poly, j: usize, v: i64) {
    p.set_coeff(j, &Int::from_i64(1, v));
}

/// `cval`
fn cval(p: &mut Poly, j: usize) -> i64 {
    p.get_coeff(j).get_i64()
}

/// `expand_A`: A[i][j] from SHAKE128("SCAAS-PQZ-A-V2" || u8(i) || u8(j)), 8-byte BE words, low 42 bits, accept if < q
/// (centred), then NTT form
fn expand_a() -> Result<PolyMat, Error> {
    let mut a = PolyMat::new(K, K)?;
    for i in 0..K {
        for j in 0..K {
            let p = a.at(i, j);
            let mut st = shake128(&[b"SCAAS-PQZ-A-V2", &[i as u8, j as u8]]);
            let mut k = 0;
            while k < D {
                let mut w = [0u8; 8];
                st.squeeze(&mut w);
                let v = u64::from_be_bytes(w) & ((1 << 42) - 1);
                if v < Q {
                    set_c(p, k, if v > (Q - 1) / 2 { v as i64 - Q as i64 } else { v as i64 });
                    k += 1;
                }
            }
            p.tocrt();
        }
    }
    Ok(a)
}

/// A, expanded at first use (`None` -> `Some`)
pub(crate) fn a_of(a: &mut Option<PolyMat>) -> Result<&mut PolyMat, Error> {
    if a.is_none() {
        *a = Some(expand_a()?);
    }
    a.as_mut().ok_or(Error::Internal)
}

/// `rd_be8`
pub(crate) fn be8(p: &[u8]) -> u64 {
    p[..8].iter().fold(0, |v, &b| (v << 8) | b as u64)
}

/// `rd_poly`: n be8 coefficients into p, centred, the rest zero; false if a value is >= q (C's `ok`). Such a value
/// is read as C reads it; `(int64_t)v - q` wraps as the compiled C does.
pub(crate) fn rd_poly(p: &mut Poly, inp: &[u8], n: usize) -> bool {
    p.set_zero();
    let mut ok = true;
    for k in 0..n {
        let v = be8(&inp[8 * k..]);
        ok &= v < Q;
        set_c(p, k, if v > (Q - 1) / 2 { (v as i64).wrapping_sub(Q as i64) } else { v as i64 });
    }
    ok
}

/// `rd_polyvec`: K polys of D coefficients; false if a value is >= q
pub(crate) fn rd_polyvec(v: &mut PolyVec, inp: &[u8]) -> bool {
    let mut ok = true;
    for (i, p) in v.iter_mut().enumerate() {
        ok &= rd_poly(p, &inp[512 * i..], D);
    }
    ok
}

/// `wr_poly`: p to [0, q) (`poly_redp`), its first n coefficients as be8
fn wr_poly(out: &mut [u8], p: &mut Poly, n: usize) {
    let mut r = Poly::redp(p);
    for k in 0..n {
        out[8 * k..8 * k + 8].copy_from_slice(&(cval(&mut r, k) as u64).to_be_bytes());
    }
}

/// `set_short`: 2048 small coefficients into K polys
fn set_short(f: impl Fn(usize) -> i64) -> Result<PolyVec, Error> {
    let mut v = PolyVec::new(K)?;
    for j in 0..N {
        set_c(&mut v[j / D], j % D, f(j));
    }
    Ok(v)
}

/// `canonical`: every be8 coefficient < q (pq-zero-knowledge.md §5)
fn canonical(p: &[u8]) -> bool {
    p.chunks(8).fold(true, |ok, c| ok & (be8(c) < Q))
}

/// `cbd8`: CBD_1 samples, their squared norm
fn cbd8(b: &mut Stream, x: &mut [i8]) -> i64 {
    x.iter_mut().fold(0, |s, x| {
        *x = cbd(1, b) as i8;
        s + (*x as i64) * (*x as i64)
    })
}

/// `cbd16`: CBD_20 samples, their squared norm
fn cbd16(b: &mut Stream, x: &mut [i16]) -> i64 {
    x.iter_mut().fold(0, |s, x| {
        *x = cbd(20, b) as i16;
        s + (*x as i64) * (*x as i64)
    })
}

/// n copies of x, `Error::Memory` if the allocation fails
fn filled<T: Copy>(n: usize, x: T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Memory)?;
    v.resize(n, x);
    Ok(v)
}

/// a boxed array of `M` copies of x, `Error::Memory` if the allocation fails (no `Box::try_new` on stable)
fn boxed<T: Copy, const M: usize>(x: T) -> Result<Box<[T; M]>, Error> {
    filled(M, x)?.into_boxed_slice().try_into().map_err(|_| Error::Internal)
}

/// `pqz_keypair_from_secret`: pk = A s + e
pub(crate) fn keypair_from_secret(
    a: &mut Option<PolyMat>,
    s: &[i8; N],
    e: &[i16; N],
) -> Result<Box<[u8; POLYVEC_BYTES]>, Error> {
    let a = a_of(a)?;
    let mut sv = set_short(|j| s[j] as i64)?;
    let mut ev = set_short(|j| e[j] as i64)?;
    let mut t = PolyVec::new(K)?;
    polyvec::mul(&mut *t, a, &mut *sv);
    polyvec::fromcrt(&mut *t);
    polyvec::add_assign(&mut *t, &mut *ev, false);
    let mut pk = boxed(0u8)?;
    for (i, p) in t.iter_mut().enumerate() {
        wr_poly(&mut pk[512 * i..], p, D);
    }
    Ok(pk)
}

/// `pqz_keygen` with the norm thresholds `bs`, `be` (`BS`, `BE`; lowered only by the keys KAT's test hooks)
pub(crate) fn keygen(a: &mut Option<PolyMat>, seed32: &[u8; 32], bs: i64, be: i64) -> Result<Key, Error> {
    let (mut s, mut e) = (boxed(0i8)?, boxed(0i16)?);
    for ctr in 0..MAXCTR {
        let mut b = Stream::keys(b"SCAAS-PQZ-KEYGEN-V1", seed32, ctr);
        let (ns, ne) = (cbd8(&mut b, &mut s[..]), cbd16(&mut b, &mut e[..]));
        if ns <= bs * bs && ne <= be * be {
            let pk = keypair_from_secret(a, &s, &e)?;
            return Ok(Key { pk, s, e, ctr });
        }
    }
    Err(Error::Reject)
}


/// `pqz_encrypt`'s outputs: u and one v per recipient
type UVs = (Box<[u8; POLYVEC_BYTES]>, Vec<[u8; V_BYTES]>);

/// `pqz_encrypt`: u = A^T r + e1, v_j = pk_j^T r + e2_j + Delta msgs_j (no input checks, as C)
fn encrypt_raw(
    a: &mut Option<PolyMat>,
    pks: &[&[u8; POLYVEC_BYTES]],
    msgs: &[[u8; 16]],
    r: &[i8; N],
    e1: &[i16; N],
    e2: &[[i16; 16]],
) -> Result<UVs, Error> {
    if msgs.len() != pks.len() || e2.len() != pks.len() {
        return Err(Error::Input); // the C ABI takes one count for all three
    }
    let a = a_of(a)?;
    let mut rv = set_short(|j| r[j] as i64)?;
    let mut ev = set_short(|j| e1[j] as i64)?;
    let mut t = PolyVec::new(K)?;
    for i in 0..K {
        t[i] = polyvec::dot(&mut a.col(i), &mut *rv); // C copies column i into `row` first: same polys, same values
    }
    polyvec::fromcrt(&mut *t);
    polyvec::add_assign(&mut *t, &mut *ev, false);
    let mut u = boxed(0u8)?;
    for (i, p) in t.iter_mut().enumerate() {
        wr_poly(&mut u[512 * i..], p, D);
    }
    let mut vs = filled(pks.len(), [0u8; V_BYTES])?;
    let mut pk = PolyVec::new(K)?;
    for k in 0..pks.len() {
        rd_polyvec(&mut pk, &pks[k][..]);
        let mut acc = polyvec::dot(&mut *pk, &mut *rv);
        acc.fromcrt();
        for i in 0..16 {
            let c = cval(&mut acc, i) + e2[k][i] as i64 + DELTA * msgs[k][i] as i64;
            set_c(&mut acc, i, c);
        }
        wr_poly(&mut vs[k], &mut Poly::redc(&mut acc), 16);
    }
    Ok((u, vs))
}

/// `pqz_encrypt` (public form: the short vectors come back in the `Enc`, ctr 0)
pub(crate) fn encrypt(
    a: &mut Option<PolyMat>,
    pks: &[&[u8; POLYVEC_BYTES]],
    msgs: &[[u8; 16]],
    r: &[i8; N],
    e1: &[i16; N],
    e2: &[[i16; 16]],
) -> Result<Enc, Error> {
    let (u, vs) = encrypt_raw(a, pks, msgs, r, e1, e2)?;
    let mut e2v = filled(e2.len(), [0i16; 16])?;
    e2v.copy_from_slice(e2);
    let (mut rb, mut e1b) = (boxed(0i8)?, boxed(0i16)?);
    rb.copy_from_slice(r);
    e1b.copy_from_slice(e1);
    Ok(Enc { u, vs, r: rb, e1: e1b, e2: e2v, ctr: 0 })
}

/// `pqz_enc_seed` with the norm thresholds `bs`, `be`, `b2` (`BS`, `BE`, `B2`; lowered only by the test hooks)
pub(crate) fn enc_seed(
    a: &mut Option<PolyMat>,
    pks: &[&[u8; POLYVEC_BYTES]],
    msgs: &[[u8; 16]],
    seed_enc: &[u8; 32],
    (bs, be, b2): (i64, i64, i64),
) -> Result<Enc, Error> {
    if msgs.len() != pks.len() {
        return Err(Error::Input);
    }
    for (pk, m) in pks.iter().zip(msgs) {
        if !canonical(&pk[..]) || m.iter().any(|&d| d > 15) {
            return Err(Error::Input);
        }
    }
    let (mut r, mut e1, mut e2) = (boxed(0i8)?, boxed(0i16)?, filled(pks.len(), [0i16; 16])?);
    for ctr in 0..MAXCTR {
        let mut b = Stream::keys(b"SCAAS-PQZ-ENC-V1", seed_enc, ctr);
        let mut ok = cbd8(&mut b, &mut r[..]) <= bs * bs;
        ok &= cbd16(&mut b, &mut e1[..]) <= be * be;
        for x in e2.iter_mut() {
            ok &= cbd16(&mut b, x) <= b2 * b2;
        }
        if ok {
            let (u, vs) = encrypt_raw(a, pks, msgs, &r, &e1, &e2)?;
            return Ok(Enc { u, vs, r, e1, e2, ctr });
        }
    }
    Err(Error::Reject)
}

/// `pqz_enc_group_seed`: g = 0 -> seed_enc, else SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" || seed_enc || be4(g))[0..32)
pub(crate) fn enc_group_seed(seed_enc: &[u8; 32], g: u32) -> [u8; 32] {
    if g == 0 {
        return *seed_enc;
    }
    let mut out = [0u8; 32];
    Stream::keys(b"SCAAS-PQZ-ENC-GROUP-V1", seed_enc, g).squeeze(&mut out);
    out
}

/// `pqz_decrypt_raw`: w_i = centre(v_i - (u^T s)_i) (no canonical check, as C)
/// (`u`: POLYVEC_BYTES, `v`: V_BYTES)
pub(crate) fn decrypt_raw(s: &[i8; N], u: &[u8], v: &[u8]) -> Result<[i64; 16], Error> {
    let mut sv = set_short(|j| s[j] as i64)?;
    let mut uv = PolyVec::new(K)?;
    rd_polyvec(&mut uv, u);
    let mut vv = Poly::ZERO;
    rd_poly(&mut vv, v, 16);
    let mut acc = polyvec::dot(&mut *uv, &mut *sv);
    acc.fromcrt();
    vv.sub_assign(&mut acc, false);
    Ok(core::array::from_fn(|i| cval(&mut vv, i)))
}

/// `pqz_dec`: M_i = round(w_i / Delta) = floor((2 w_i + Delta) / (2 Delta)) (no ties: Delta odd), noise
/// w_i - Delta M_i; C's branch-free form: t = 2w + Delta + 2 Delta 2^17 > 0 (|w| < q/2 < 2^41), floor(t / (2 Delta))
/// = M + 2^17
pub(crate) fn dec(s: &[i8; N], ct: &[u8; CT_BYTES]) -> Result<([i64; 16], [i64; 16]), Error> {
    if !canonical(&ct[..]) {
        return Err(Error::Input);
    }
    let (u, v) = ct.split_at(POLYVEC_BYTES);
    let mut w = decrypt_raw(s, u, v)?;
    let (mut m, mut noise) = ([0i64; 16], [0i64; 16]);
    for i in 0..16 {
        let t = (2 * w[i] + DELTA + 2 * DELTA * (1 << 17)) as u64;
        m[i] = (t / (2 * DELTA) as u64) as i64 - (1 << 17);
        noise[i] = w[i] - DELTA * m[i];
    }
    crate::wipe(&mut w);
    Ok((m, noise))
}
