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
use crate::{Enc, Error, Key, Wiped, CT_BYTES, POLYVEC_BYTES, V_BYTES};
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::params::set;
const N: usize = set::N;
const K: usize = set::K;
const DELTA: i64 = set::DELTA;
const MAXCTR: u32 = 64;
/// the norm thresholds ‖s‖, ‖e‖ (KeyGen; Enc's r, e1) and ‖e2_j‖ (Enc): the set's
pub(crate) const BS: i64 = set::BETA_S as i64;
pub(crate) const BE: i64 = set::BETA_E as i64;
pub(crate) const B2: i64 = set::BETA_2 as i64;

/// `set_c`: coefficient j of p := v (via the coefficient domain)
fn set_c(p: &mut Poly, j: usize, v: i64) {
    p.set_coeff(j, &Int::from_i64(1, v));
}

/// `cval`
fn cval(p: &mut Poly, j: usize) -> i64 {
    p.get_coeff(j).get_i64()
}

/// `expand_A`: A[i][j] from SHAKE128("SCAAS-PQZ-A-V2" || u8(i) || u8(j)), 8-byte BE words, low LOG2Q bits (the set's),
/// accept if < q
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
                let v = u64::from_be_bytes(w) & ((1 << set::LOG2Q) - 1);
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

/// `wr_poly`: p to [0, q) (`poly_redp`), its first n coefficients as be8 (the reduced copy wiped: `encrypt_raw`'s
/// pk^T r passes through it, review A-3 P2-1)
fn wr_poly(out: &mut [u8], p: &mut Poly, n: usize) {
    let mut r = Wiped(Poly::redp(p));
    for k in 0..n {
        out[8 * k..8 * k + 8].copy_from_slice(&(cval(&mut r, k) as u64).to_be_bytes());
    }
}

/// `set_short`: n small coefficients into K polys
fn set_short(f: impl Fn(usize) -> i64) -> Result<PolyVec, Error> {
    let mut v = PolyVec::new(K)?;
    for j in 0..N {
        set_c(&mut v[j / D], j % D, f(j));
    }
    Ok(v)
}

/// `canonical`: every be8 coefficient < q (pq-zero-knowledge.md §5)
fn canonical(p: &[u8]) -> bool {
    // chunks_exact: a short last chunk is refused, never passed to be8 (review H-1, fix C)
    let c = p.chunks_exact(8);
    c.remainder().is_empty() & c.fold(true, |ok, c| ok & (be8(c) < Q))
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
    // Q-B (review A-3): the secret key and its noise, wiped on every exit (C `wipe_vec (sv), wipe_vec (ev)`)
    let mut sv = Wiped(set_short(|j| s[j] as i64)?);
    let mut ev = Wiped(set_short(|j| e[j] as i64)?);
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
    // Q-B (review A-3): s, e are wiped on the error exits (`?`, `Reject`); only the accepted pair leaves
    // (the blanks `take` leaves in their place are allocated first: no allocation failure after the key is computed)
    let (mut s, mut e) = (Wiped(boxed(0i8)?), Wiped(boxed(0i16)?));
    let blank = (boxed(0i8)?, boxed(0i16)?);
    for ctr in 0..MAXCTR {
        let mut b = Stream::keys_set(b"SCAAS-PQZ-KEYGEN-V2", seed32, ctr); // the set's name in it (review R2-C3)
        let (ns, ne) = (cbd8(&mut b, &mut s[..]), cbd16(&mut b, &mut e[..]));
        // review E: the resample verdict is public (the counter is an output); the norms are not
        if crate::ct::verdict((ns <= bs * bs) & (ne <= be * be)) {
            let pk = keypair_from_secret(a, &s, &e)?;
            return Ok(Key { pk, s: s.take(blank.0), e: e.take(blank.1), ctr });
        }
    }
    Err(Error::Reject)
}


/// `pqz_encrypt`'s outputs: u and one v per recipient
type UVs = (Box<[u8; POLYVEC_BYTES]>, Vec<[u8; V_BYTES]>);

/// `pqz_encrypt_win`: u = A^T r + e1, v_j = (pk_j^T r)_{16 win_j + i} + e2_j + Delta msgs_j (win: None = all 0;
/// R0-1; no other input checks, as C)
fn encrypt_raw(
    a: &mut Option<PolyMat>,
    pks: &[&[u8; POLYVEC_BYTES]],
    win: Option<&[u8]>,
    msgs: &[[u8; 16]],
    r: &[i8; N],
    e1: &[i16; N],
    e2: &[[i16; 16]],
) -> Result<UVs, Error> {
    if msgs.len() != pks.len() || e2.len() != pks.len() || win.is_some_and(|w| w.len() != pks.len()) {
        return Err(Error::Input); // the C ABI takes one count for all three
    }
    if win.is_some_and(|w| w.iter().any(|&x| x >= 4)) {
        return Err(Error::Input);
    }
    let a = a_of(a)?;
    // Q-B (review A-3): the encryption randomness, wiped on every exit (C `wipe_vec (rv), wipe_vec (ev)`)
    let mut rv = Wiped(set_short(|j| r[j] as i64)?);
    let mut ev = Wiped(set_short(|j| e1[j] as i64)?);
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
        // Q-B (review A-3 P2-1): pk^T r and its reduced copy, wiped (C clears acc with its arena)
        let mut acc = Wiped(polyvec::dot(&mut *pk, &mut *rv));
        acc.fromcrt();
        let o = win.map_or(0, |w| 16 * w[k] as usize);
        for i in 0..16 {
            let c = cval(&mut acc, o + i) + e2[k][i] as i64 + DELTA * msgs[k][i] as i64;
            set_c(&mut acc, i, c);
        }
        let mut vr = Wiped(Poly::redc(&mut acc));
        wr_poly(&mut vs[k], &mut vr, 16);
    }
    Ok((u, vs))
}

/// `pqz_encrypt_win` (public form: the short vectors come back in the `Enc`, ctr 0)
pub(crate) fn encrypt(
    a: &mut Option<PolyMat>,
    pks: &[&[u8; POLYVEC_BYTES]],
    win: Option<&[u8]>,
    msgs: &[[u8; 16]],
    r: &[i8; N],
    e1: &[i16; N],
    e2: &[[i16; 16]],
) -> Result<Enc, Error> {
    let (u, vs) = encrypt_raw(a, pks, win, msgs, r, e1, e2)?;
    let (mut rb, mut e1b) = (boxed(0i8)?, boxed(0i16)?);
    let mut e2v = filled(e2.len(), [0i16; 16])?; // last: no allocation fails after the e2 copy (review A-3 Minor-3)
    e2v.copy_from_slice(e2);
    rb.copy_from_slice(r);
    e1b.copy_from_slice(e1);
    Ok(Enc { u, vs, r: rb, e1: e1b, e2: e2v, ctr: 0 })
}

/// `pqz_enc_seed_win` with the norm thresholds `bs`, `be`, `b2` (`BS`, `BE`, `B2`; lowered only by the test hooks);
/// recipient j at window win[j] (None = all 0, `pqz_enc_seed`; R0-1)
pub(crate) fn enc_seed(
    a: &mut Option<PolyMat>,
    pks: &[&[u8; POLYVEC_BYTES]],
    win: Option<&[u8]>,
    msgs: &[[u8; 16]],
    seed_enc: &[u8; 32],
    (bs, be, b2): (i64, i64, i64),
) -> Result<Enc, Error> {
    if msgs.len() != pks.len() || win.is_some_and(|w| w.len() != pks.len() || w.iter().any(|&x| x >= 4)) {
        return Err(Error::Input);
    }
    let mut bad = false;
    for (pk, m) in pks.iter().zip(msgs) {
        if !canonical(&pk[..]) {
            return Err(Error::Input);
        }
        bad |= m.iter().fold(false, |r, &d| r | (d > 15)); // review E: the digits are secret, the verdict public
    }
    if crate::ct::verdict(bad) {
        return Err(Error::Input);
    }
    // Q-B (review A-3): r, e1, e2 are wiped on the error exits (`?`, `Reject`); only the accepted ones leave
    let (mut r, mut e1, mut e2) = (Wiped(boxed(0i8)?), Wiped(boxed(0i16)?), Wiped(filled(pks.len(), [0i16; 16])?));
    let blank = (boxed(0i8)?, boxed(0i16)?); // allocated first, as in keygen
    for ctr in 0..MAXCTR {
        let mut b = Stream::keys(b"SCAAS-PQZ-ENC-V1", seed_enc, ctr);
        let mut ok = cbd8(&mut b, &mut r[..]) <= bs * bs;
        ok &= cbd16(&mut b, &mut e1[..]) <= be * be;
        for x in e2.iter_mut() {
            ok &= cbd16(&mut b, x) <= b2 * b2;
        }
        if crate::ct::verdict(ok) {
            // review E: the resample verdict is public
            let (u, vs) = encrypt_raw(a, pks, win, msgs, &r, &e1, &e2)?;
            return Ok(Enc { u, vs, r: r.take(blank.0), e1: e1.take(blank.1), e2: e2.take(Vec::new()), ctr });
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

/// `pqz_decrypt_raw_win`: w_i = centre(v_i - (u^T s)_{16 win + i}) (no canonical check, as C; win < 4, R0-1)
/// (`u`: POLYVEC_BYTES, `v`: V_BYTES)
pub(crate) fn decrypt_raw(s: &[i8; N], u: &[u8], v: &[u8], win: usize) -> Result<[i64; 16], Error> {
    if win >= 4 {
        return Err(Error::Input);
    }
    // Q-B (review A-3): the secret key, u^T s and the plaintext, wiped on every exit (C `wipe_vec (sv)`, the arena)
    let mut sv = Wiped(set_short(|j| s[j] as i64)?);
    let mut uv = PolyVec::new(K)?;
    rd_polyvec(&mut uv, u);
    let mut vv = Wiped(Poly::ZERO);
    rd_poly(&mut vv, v, 16);
    let mut acc = Wiped(polyvec::dot(&mut *uv, &mut *sv));
    acc.fromcrt();
    let mut aw = Wiped(Poly::ZERO); // (u^T s) at window win into coefficients 0 .. 15
    for i in 0..16 {
        let c = cval(&mut acc, 16 * win + i);
        set_c(&mut aw, i, c);
    }
    vv.sub_assign(&mut aw, false);
    Ok(core::array::from_fn(|i| cval(&mut vv, i)))
}

/// `pqz_dec`: M_i = round(w_i / Delta) = floor((2 w_i + Delta) / (2 Delta)) (ties up: v3's Delta is odd, no ties;
/// an encryption's |noise| < Delta / 2 never ties), noise w_i - Delta M_i; C's branch-free form with SH = MBITS + 3:
/// t = 2w + Delta + 2 Delta 2^SH > 0 (|w| < q/2, 2 Delta 2^SH ~ 4q), floor(t / (2 Delta)) = M + 2^SH
/// (`pqz_dec_win`: a v at window win < 4, the auditor's copy of an R_TXM leg j: win = j mod S_AUD; R0-1)
pub(crate) fn dec(s: &[i8; N], ct: &[u8; CT_BYTES], win: usize) -> Result<([i64; 16], [i64; 16]), Error> {
    if !canonical(&ct[..]) || win >= 4 {
        return Err(Error::Input);
    }
    let (u, v) = ct.split_at(POLYVEC_BYTES);
    let mut w = decrypt_raw(s, u, v, win)?;
    let (mut m, mut noise) = ([0i64; 16], [0i64; 16]);
    for i in 0..16 {
        // review E: the fixed-step restoring division (w is secret; wasm32 keeps a 64-bit '/' as i64.div_u)
        const SH: u32 = set::MBITS + 3;
        let mut t = [(2 * w[i] + DELTA + 2 * DELTA * (1 << SH)) as u64];
        m[i] = crate::arith::mpn::div(None, &mut t, &[(2 * DELTA) as u64]) as i64 - (1 << SH);
        noise[i] = w[i] - DELTA * m[i];
    }
    crate::wipe(&mut w);
    Ok((m, noise))
}

#[cfg(test)]
mod tests {
    /// fix C: a length that is not a multiple of 8 is not canonical (and does not panic)
    #[test]
    fn canonical_short_chunk() {
        assert!(super::canonical(&[0; 16]));
        assert!(!super::canonical(&[0; 15]));
        assert!(!super::canonical(&[0; 7]));
    }
}
