// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `bls12381-multi` (`0x0121`, spec 2026-11-19-bls12381-multi): weighted t-of-n BLS12-381 same-message multi-signature with a
//! signer bitmap. Key data `d = apk (256) ‖ u16 t ‖ u16 n ‖ n × (pk_i (256) ‖ u16 w_i)` (EIP-2537 G2 encoding); the EVM key
//! pointer stores `p = ua ‖ s`, `s` = `d` with 48-byte limbs ([`compress`] / [`expand`]). Off chain the key data is `d`
//! (owner ruling 2026-11-19) and the id is computed here. Members sign `memberDigest(ua, ua_msg)` under [`DST_MULTI_SIG`];
//! the registration `pop` is the sum of the members' proofs over `m_i = keccak256(popMsg ‖ pk_i)` under [`DST_MULTI_POP`].
//! Untrusted input: anything malformed is `false` or an error, never a panic. UNAUDITED (the batched PoP is an external
//! audit item, spec §4).
use crate::verify::hash_to_g1_bls12381;
use crate::{keccak, tag, Result, UAError};
use ark_bls12_381::{Bls12_381, Fq, Fq2, G1Affine, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};

/// The kind number.
pub const KIND: u16 = 0x0121;
/// Signing (spec §3, owner ruling Q11): what every member signs `memberDigest(ua, ua_msg)` under.
pub const DST_MULTI_SIG: &[u8; 53] = b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_SIG_";
/// Proof of possession (spec §4): the registration `pop` only, nothing else is signed or checked under it.
pub const DST_MULTI_POP: &[u8; 53] = b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_POP_";
/// The member cap (owner ruling Q4).
pub const MAX_N: usize = 64;
/// The signature ABI: `σ (128) ‖ signers (32, uint256 big-endian)`.
pub const SIG_LEN: usize = 160;

/// Parsed, validated key data `d`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsMultiKeyData {
    pub apk: [u8; 256],
    pub threshold: u16,
    pub members: Vec<([u8; 256], u16)>,
}

fn need(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(UAError::KeyData(reason))
    }
}

fn u16_at(b: &[u8], o: usize) -> Option<usize> {
    b.get(o..o + 2)
        .map(|s| ((s[0] as usize) << 8) | s[1] as usize)
}

/// A 64-byte EIP-2537 limb: 16 zero bytes, then 48 bytes `< p`.
fn fp(b: &[u8]) -> Option<Fq> {
    if b[..16].iter().any(|x| *x != 0) {
        return None;
    }
    let f = Fq::from_be_bytes_mod_order(&b[16..64]);
    (f.into_bigint().to_bytes_be() == b[16..64]).then_some(f)
}

/// A 256-byte EIP-2537 G2 point, canonical and on the curve; all zero = the identity (as the precompile reads it). No
/// subgroup check (G2ADD has none either).
pub(crate) fn g2_decode(b: &[u8]) -> Option<G2Affine> {
    if b.len() != 256 {
        return None;
    }
    let (x0, x1, y0, y1) = (
        fp(&b[..64])?,
        fp(&b[64..128])?,
        fp(&b[128..192])?,
        fp(&b[192..])?,
    );
    if x0.is_zero() && x1.is_zero() && y0.is_zero() && y1.is_zero() {
        return Some(G2Affine::identity());
    }
    let p = G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)); // c0 first
    p.is_on_curve().then_some(p)
}

fn limb(f: &Fq, out: &mut [u8]) {
    let b = f.into_bigint().to_bytes_be();
    out[..16].fill(0);
    out[64 - b.len()..].copy_from_slice(&b);
}

/// The EIP-2537 encoding of a G2 point (the identity as 256 zero bytes).
pub fn g2_encode(p: &G2Affine) -> [u8; 256] {
    let mut out = [0u8; 256];
    if let Some((x, y)) = p.xy() {
        for (i, f) in [x.c0, x.c1, y.c0, y.c1].iter().enumerate() {
            limb(f, &mut out[64 * i..64 * i + 64]);
        }
    }
    out
}

/// The EIP-2537 encoding of a G1 point (128 bytes; the identity as zeros).
pub fn g1_encode(p: &G1Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        limb(&x, &mut out[..64]);
        limb(&y, &mut out[64..]);
    }
    out
}

/// A G1 point: canonical, on the curve, in the subgroup, not the identity.
fn g1_valid(b: &[u8]) -> Option<G1Affine> {
    crate::verify::g1::<ark_bls12_381::g1::Config>(b, 64)
}

/// `p_381 − y` on one 64-byte limb, **except `0 ↦ 0`** (spec §5.2, N3): the G2 negation `(x, y) ↦ (x, −y)` the subtract path
/// applies to the non-signers' sum, per Fp component of `y`, so the identity maps to itself and a zero component stays
/// canonical. Operates on bytes as the EVM verifier does.
pub fn neg_g2(p: &[u8; 256]) -> [u8; 256] {
    let mut out = *p;
    let modulus = Fq::MODULUS.to_bytes_be(); // 48 bytes
    for o in [128usize, 192] {
        let y = &p[o + 16..o + 64];
        if y.iter().all(|x| *x == 0) {
            continue; // fneg(0) = 0
        }
        let mut borrow = 0i16;
        for i in (0..48).rev() {
            let d = modulus[i] as i16 - y[i] as i16 - borrow;
            borrow = (d < 0) as i16;
            out[o + 16 + i] = d.rem_euclid(256) as u8;
        }
    }
    out
}

/// Spec §2: length, `n`, weights and `t`; every `pk_i` canonical, on the curve, in G2, not the identity; strictly increasing
/// as 256-byte strings; `apk` byte-equal to `Σ pk_i` and not the identity. Anything else is `UAKeyData`.
pub fn parse(d: &[u8]) -> Result<BlsMultiKeyData> {
    let n = u16_at(d, 258).ok_or(UAError::KeyData("length"))?;
    need((2..=MAX_N).contains(&n), "n")?;
    need(d.len() == 260 + 258 * n, "length")?;
    let threshold = u16_at(d, 256).expect("length checked") as u16;
    let mut total = 0u32; // Σ w_i: at least 32 bits (Review Focus 1)
    for i in 0..n {
        let w = u16_at(d, 260 + 258 * i + 256).expect("length checked") as u32;
        need(w >= 1, "weight")?;
        total += w;
    }
    need(threshold >= 1 && u32::from(threshold) <= total, "threshold")?;
    let mut members = Vec::with_capacity(n);
    let mut sum = G2Projective::zero();
    for i in 0..n {
        let o = 260 + 258 * i;
        let key = &d[o..o + 256];
        let pk = g2_decode(key).ok_or(UAError::KeyData("range"))?;
        need(!pk.is_zero(), "identity")?;
        need(pk.is_in_correct_subgroup_assuming_on_curve(), "subgroup")?;
        if i > 0 {
            need(d[o - 258..o - 2] < *key, "order")?;
        }
        sum += pk;
        let w = u16_at(d, o + 256).expect("length checked") as u16;
        members.push((key.try_into().expect("256 bytes"), w));
    }
    let sum = sum.into_affine();
    need(!sum.is_zero(), "identity")?;
    need(g2_encode(&sum)[..] == d[..256], "apk")?;
    Ok(BlsMultiKeyData {
        apk: d[..256].try_into().expect("256 bytes"),
        threshold,
        members,
    })
}

/// The `0x0121` id, `keccak256(TAG(0x0121) ‖ d)` (no validation).
pub fn ua_of(d: &[u8]) -> [u8; 32] {
    keccak(&[&tag(KIND).expect("table kind"), d])
}

/// `d` → `s`: each 64-byte limb loses its 16 zero bytes (a non-zero one is `UAKeyData`). Structure only, no curve check.
pub fn compress(d: &[u8]) -> Result<Vec<u8>> {
    let n = u16_at(d, 258).ok_or(UAError::KeyData("length"))?;
    need((2..=MAX_N).contains(&n), "n")?;
    need(d.len() == 260 + 258 * n, "length")?;
    let mut s = Vec::with_capacity(196 + 194 * n);
    let point = |b: &[u8], s: &mut Vec<u8>| -> Result<()> {
        for l in b.chunks(64) {
            need(l[..16].iter().all(|x| *x == 0), "padding")?;
            s.extend_from_slice(&l[16..]);
        }
        Ok(())
    };
    point(&d[..256], &mut s)?;
    s.extend_from_slice(&d[256..260]);
    for i in 0..n {
        let o = 260 + 258 * i;
        point(&d[o..o + 256], &mut s)?;
        s.extend_from_slice(&d[o + 256..o + 258]);
    }
    Ok(s)
}

/// `s` → `d`: a 16-byte zero prefix per 48-byte limb.
pub fn expand(s: &[u8]) -> Result<Vec<u8>> {
    let n = u16_at(s, 194).ok_or(UAError::KeyData("length"))?;
    need((2..=MAX_N).contains(&n), "n")?;
    need(s.len() == 196 + 194 * n, "length")?;
    let mut d = Vec::with_capacity(260 + 258 * n);
    let point = |b: &[u8], d: &mut Vec<u8>| {
        for l in b.chunks(48) {
            d.extend_from_slice(&[0u8; 16]);
            d.extend_from_slice(l);
        }
    };
    point(&s[..192], &mut d);
    d.extend_from_slice(&s[192..196]);
    for i in 0..n {
        let o = 196 + 194 * i;
        point(&s[o..o + 192], &mut d);
        d.extend_from_slice(&s[o + 192..o + 194]);
    }
    Ok(d)
}

/// The EVM key pointer `p = ua ‖ compress(d)` (EVM storage only; spec §2).
pub fn stored(d: &[u8]) -> Result<Vec<u8>> {
    Ok([&ua_of(d)[..], &compress(d)?].concat())
}

/// `W(S) = Σ_{i∈S} w_i` (32 bits) and `min_{i∈S} w_i`, `None` unless `signers` is non-empty, strictly increasing and `< n`.
fn weights(kd: &BlsMultiKeyData, signers: &[u8]) -> Option<(u32, u32)> {
    if signers.is_empty() || signers.windows(2).any(|w| w[0] >= w[1]) {
        return None;
    }
    let mut sum = 0u32;
    let mut min = u32::MAX;
    for i in signers {
        let w = u32::from(kd.members.get(*i as usize)?.1);
        sum += w;
        min = min.min(w);
    }
    Some((sum, min))
}

/// The stored form (spec §5.3): `W(S) ≥ t` and every signer necessary, `W(S) − min_{i∈S} w_i < t`.
pub fn minimal(kd: &BlsMultiKeyData, signers: &[u8]) -> bool {
    let t = u32::from(kd.threshold);
    weights(kd, signers).is_some_and(|(w, min)| w >= t && w - min < t)
}

/// The member indices of a 32-byte big-endian bitmap (bit 0 = member 0), `None` if a bit at or above `n` is set or none is.
pub fn bitmap_indices(bitmap: &[u8], n: usize) -> Option<Vec<u8>> {
    if bitmap.len() != 32 {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..256usize {
        if bitmap[31 - i / 8] >> (i % 8) & 1 == 1 {
            if i >= n {
                return None;
            }
            out.push(i as u8);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The 32-byte bitmap of member indices (each `< 256`).
pub fn indices_bitmap(signers: &[u8]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in signers {
        b[31 - *i as usize / 8] |= 1 << (i % 8);
    }
    b
}

/// `apk(S)` on the pinned path (spec §5.2, F13): all n → the stored `apk`; `2k ≤ n + 1` → `Σ_{i∈S} pk_i`; otherwise
/// `apk + neg(Σ_{i∉S} pk_i)`, the negation on bytes ([`neg_g2`]) and decoded back as the precompile would read it.
fn apk_of(kd: &BlsMultiKeyData, signers: &[u8]) -> Option<G2Affine> {
    let (n, k) = (kd.members.len(), signers.len());
    let point = |b: &[u8; 256]| g2_decode(b);
    if k == n {
        return point(&kd.apk);
    }
    let on: Vec<bool> = (0..n).map(|i| signers.contains(&(i as u8))).collect();
    let sum = |want: bool| -> Option<G2Projective> {
        let mut s = G2Projective::zero();
        for (i, m) in kd.members.iter().enumerate() {
            if on[i] == want {
                s += point(&m.0)?;
            }
        }
        Some(s)
    };
    if 2 * k <= n + 1 {
        return Some(sum(true)?.into_affine());
    }
    let neg = point(&neg_g2(&g2_encode(&sum(false)?.into_affine())))?;
    Some((point(&kd.apk)?.into_group() + neg).into_affine())
}

/// `verify` (`minimal = false`, `W(S) ≥ t`) / `verifyMinimal` (`minimal = true`) of `sig = σ ‖ signers` over `ua_msg`
/// against key data `d` (spec §5.2): `m = keccak256(ua ‖ ua_msg)`, `e(σ, g2) == e(H_G1(m, DST_MULTI_SIG), apk(S))`.
pub fn verify_sig(d: &[u8], ua_msg: &[u8; 32], sig: &[u8], minimal_form: bool) -> bool {
    let Ok(kd) = parse(d) else {
        return false;
    };
    if sig.len() != SIG_LEN {
        return false;
    }
    let Some(sigma) = g1_valid(&sig[..128]) else {
        return false; // malformed, off the subgroup, or the identity
    };
    let Some(signers) = bitmap_indices(&sig[128..], kd.members.len()) else {
        return false;
    };
    let Some((w, min)) = weights(&kd, &signers) else {
        return false;
    };
    let t = u32::from(kd.threshold);
    if w < t || (minimal_form && w - min >= t) {
        return false;
    }
    let Some(apk_s) = apk_of(&kd, &signers) else {
        return false;
    };
    if apk_s.is_zero() {
        return false;
    }
    let m = keccak(&[&ua_of(d), ua_msg]);
    let h = hash_to_g1_bls12381(&m, DST_MULTI_SIG);
    Bls12_381::pairing(sigma, G2Affine::generator()) == Bls12_381::pairing(h, apk_s)
}

/// `m_i = keccak256(popMsg ‖ pk_i)` (spec §4).
pub fn pop_member_message(pop_msg: &[u8; 32], pk: &[u8; 256]) -> [u8; 32] {
    keccak(&[pop_msg, pk])
}

/// `verifyPop` (spec §4): `pop ≠ O` and `e(pop, −g2) · Π_i e(H_G1(m_i, DST_MULTI_POP), pk_i) == 1` over validated `d`.
pub fn verify_pop(d: &[u8], pop_msg: &[u8; 32], pop: &[u8]) -> bool {
    let Ok(kd) = parse(d) else {
        return false;
    };
    let Some(p) = g1_valid(pop) else {
        return false;
    };
    let mut a: Vec<G1Affine> = vec![p];
    let mut b: Vec<G2Affine> = vec![-G2Affine::generator()];
    for (pk, _) in &kd.members {
        a.push(hash_to_g1_bls12381(
            &pop_member_message(pop_msg, pk),
            DST_MULTI_POP,
        ));
        b.push(g2_decode(pk).expect("parsed"));
    }
    Bls12_381::multi_pairing(a, b).is_zero() // the identity of G_T
}

/// `verify::verify`'s `0x0121` arm: `pop` → [`verify_pop`] (`key_data` = `d`, `message` = `popMsg`, `sig` = the `pop`), else
/// [`verify_sig`] in its `minimal` form.
pub(crate) fn verify(
    key_data: &[u8],
    message: &[u8; 32],
    sig: &[u8],
    pop: bool,
    minimal: bool,
) -> bool {
    if pop {
        verify_pop(key_data, message, sig)
    } else {
        verify_sig(key_data, message, sig, minimal)
    }
}
