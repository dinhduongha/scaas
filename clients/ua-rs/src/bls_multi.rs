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

// --- partials, aggregation, PoP parts, builder (spec §4, §5.4; plan Task 2) ---

/// Why a member operation or an aggregation was refused (spec §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The key data is not valid `0x0121` key data (or the builder's input does not make any).
    KeyData(UAError),
    /// The partial (or PoP part) of member `index` does not verify against its key: named, and dropped where the rest suffice.
    BadPartial { index: u8 },
    /// An index given twice, or at or above n.
    Index(u8),
    /// Member `index` gave no PoP part: registration needs all n (spec §4).
    Missing(u8),
    /// The accepted partials weigh less than `t`.
    BelowThreshold,
    /// The signer's key is not listed in the key data.
    NotMember,
    /// The secret is not a canonical non-zero scalar.
    Secret,
    /// The sum is the identity.
    Identity,
}

impl From<UAError> for Error {
    fn from(e: UAError) -> Self {
        Error::KeyData(e)
    }
}

/// An aggregate with its named fields (spec §5.1): `signature` σ (128 B), `signers` the strictly increasing member indices;
/// `dropped` the partials refused as invalid and left out (spec §5.4: named and dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlsMultiSig {
    pub signature: [u8; 128],
    pub signers: Vec<u8>,
    pub dropped: Vec<u8>,
}

impl BlsMultiSig {
    /// The ABI object `σ ‖ signers` (uint256 big-endian bitmap), what `UASig.signature` carries.
    pub fn to_abi(&self) -> [u8; 160] {
        let mut out = [0u8; 160];
        out[..128].copy_from_slice(&self.signature);
        out[128..].copy_from_slice(&indices_bitmap(&self.signers));
        out
    }
}

/// `popMsg = uaMessage(0x0121, PURPOSE_POP_V2, registrationDigest(UAPortableRecord{ua, 0x0121, 0, UAKemRecord{ua, 0, 0, 0}},
/// 0))`, derived from `d` (spec §4, §6; N5).
pub fn pop_message(d: &[u8]) -> Result<[u8; 32]> {
    Ok(crate::ua_portable::holder_pop_message(KIND, &ua_of(d), d, None, None, None, None)?.message)
}

fn partial_ok(sig: &[u8; 128], pk: &[u8; 256], msg: &[u8; 32], dst: &[u8]) -> Option<G1Affine> {
    let s = g1_valid(sig)?;
    let pk =
        g2_decode(pk).filter(|p| !p.is_zero() && p.is_in_correct_subgroup_assuming_on_curve())?;
    (Bls12_381::pairing(s, G2Affine::generator())
        == Bls12_381::pairing(hash_to_g1_bls12381(msg, dst), pk))
    .then_some(s)
}

/// One member part as an external key returns it (`wallet::SignRequest::BlsMultiMember`): `pk` listed in `d`; `pop` the PoP
/// part over `keccak256(message ‖ pk)` under [`DST_MULTI_POP`] (`message` = `popMsg`), else the partial over
/// `keccak256(ua ‖ message)` under [`DST_MULTI_SIG`] (`message` = `ua_msg`).
pub fn part_ok(d: &[u8], pk: &[u8], message: &[u8; 32], pop: bool, sig: &[u8]) -> bool {
    let (Ok(kd), Ok(pk), Ok(sig)) = (
        parse(d),
        <&[u8; 256]>::try_from(pk),
        <&[u8; 128]>::try_from(sig),
    ) else {
        return false;
    };
    if !kd.members.iter().any(|m| m.0 == *pk) {
        return false;
    }
    if pop {
        partial_ok(sig, pk, &pop_member_message(message, pk), DST_MULTI_POP).is_some()
    } else {
        partial_ok(sig, pk, &keccak(&[&ua_of(d), message]), DST_MULTI_SIG).is_some()
    }
}

/// Spec §5.4: each partial checked against its member key on `m = keccak256(ua ‖ ua_msg)` under [`DST_MULTI_SIG`]; a
/// duplicate index or one at or above n refused; an invalid partial named in `dropped` and left out; below `t` refused
/// (naming the first bad partial when there is one). A minimal set unless `surplus` (N6): the heaviest accepted members
/// first (ties by index) until `t`, so the last one taken is the lightest and every signer is necessary.
pub fn aggregate(
    d: &[u8],
    ua_msg: &[u8; 32],
    partials: &[(u8, [u8; 128])],
    surplus: bool,
) -> core::result::Result<BlsMultiSig, Error> {
    let kd = parse(d)?;
    let n = kd.members.len();
    let m = keccak(&[&ua_of(d), ua_msg]);
    let mut seen = [false; MAX_N];
    let (mut ok, mut dropped) = (Vec::new(), Vec::new());
    for (i, s) in partials {
        let idx = *i as usize;
        if idx >= n || seen[idx] {
            return Err(Error::Index(*i));
        }
        seen[idx] = true;
        match partial_ok(s, &kd.members[idx].0, &m, DST_MULTI_SIG) {
            Some(p) => ok.push((*i, kd.members[idx].1, p)),
            None => dropped.push(*i),
        }
    }
    dropped.sort_unstable();
    let t = u32::from(kd.threshold);
    if ok.iter().map(|x| u32::from(x.1)).sum::<u32>() < t {
        return Err(dropped
            .first()
            .map_or(Error::BelowThreshold, |i| Error::BadPartial { index: *i }));
    }
    if !surplus {
        ok.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut w = 0u32;
        let take = ok
            .iter()
            .position(|x| {
                w += u32::from(x.1);
                w >= t
            })
            .expect("total ≥ t");
        ok.truncate(take + 1);
    }
    ok.sort_by_key(|x| x.0);
    let sigma: ark_bls12_381::G1Projective = ok.iter().map(|x| x.2.into_group()).sum();
    Ok(BlsMultiSig {
        signature: g1_encode(&sigma.into_affine()),
        signers: ok.iter().map(|x| x.0).collect(),
        dropped,
    })
}

/// The registration `pop` from all n members' parts (spec §4): each `π_i` checked against `pk_i` on
/// `m_i = keccak256(popMsg ‖ pk_i)` under [`DST_MULTI_POP`] (`popMsg` from [`pop_message`]), a bad one named; every index
/// once; the sum not the identity.
pub fn aggregate_pop(
    d: &[u8],
    parts: &[(u8, [u8; 128])],
) -> core::result::Result<[u8; 128], Error> {
    let kd = parse(d)?;
    let n = kd.members.len();
    let pm = pop_message(d)?;
    let mut seen = [false; MAX_N];
    let mut sum = ark_bls12_381::G1Projective::zero();
    for (i, s) in parts {
        let idx = *i as usize;
        if idx >= n || seen[idx] {
            return Err(Error::Index(*i));
        }
        seen[idx] = true;
        let pk = &kd.members[idx].0;
        sum += partial_ok(s, pk, &pop_member_message(&pm, pk), DST_MULTI_POP)
            .ok_or(Error::BadPartial { index: *i })?;
    }
    if let Some(i) = (0..n).find(|i| !seen[*i]) {
        return Err(Error::Missing(i as u8));
    }
    let sum = sum.into_affine();
    if sum.is_zero() {
        return Err(Error::Identity);
    }
    Ok(g1_encode(&sum))
}

/// The key data of a group (spec §2): members `(pk, weight)` in the caller's order, sorted here by key with each weight
/// travelling with its key, `apk = Σ pk_i`; returns `d` and the map caller index → key-data index (Review Focus 2). The result
/// is validated as the registry would.
pub fn build_key_data(
    members: &[([u8; 256], u16)],
    threshold: u16,
) -> Result<(Vec<u8>, Vec<usize>)> {
    need((2..=MAX_N).contains(&members.len()), "n")?;
    let mut order: Vec<usize> = (0..members.len()).collect();
    order.sort_by(|a, b| members[*a].0.cmp(&members[*b].0));
    let mut apk = G2Projective::zero();
    for (k, _) in members {
        apk += g2_decode(k).ok_or(UAError::KeyData("range"))?;
    }
    let mut d = g2_encode(&apk.into_affine()).to_vec();
    d.extend_from_slice(&threshold.to_be_bytes());
    d.extend_from_slice(&(members.len() as u16).to_be_bytes());
    let mut map = vec![0usize; members.len()];
    for (pos, i) in order.iter().enumerate() {
        d.extend_from_slice(&members[*i].0);
        d.extend_from_slice(&members[*i].1.to_be_bytes());
        map[*i] = pos;
    }
    parse(&d)?;
    Ok((d, map))
}

/// [`build_key_data`] with every weight 1 (the typed API's default).
pub fn build_key_data_unweighted(
    keys: &[[u8; 256]],
    threshold: u16,
) -> Result<(Vec<u8>, Vec<usize>)> {
    build_key_data(&keys.iter().map(|k| (*k, 1)).collect::<Vec<_>>(), threshold)
}

#[cfg(feature = "signers")]
mod member {
    use super::*;
    use ark_ec::short_weierstrass::Projective;
    use zeroize::Zeroizing;

    fn scalar(sk: &[u8; 32]) -> core::result::Result<Zeroizing<ark_bls12_381::Fr>, Error> {
        let f = Zeroizing::new(ark_bls12_381::Fr::from_be_bytes_mod_order(sk));
        let back = Zeroizing::new(f.into_bigint().to_bytes_be());
        if back.as_slice() != sk || f.is_zero() {
            return Err(Error::Secret);
        }
        Ok(f)
    }

    fn mul<P: ark_ec::short_weierstrass::SWCurveConfig>(
        base: Projective<P>,
        s: &P::ScalarField,
    ) -> core::result::Result<Projective<P>, Error>
    where
        P::BaseField: scaas_ct::CtSwap,
    {
        scaas_ct::secret_mul(base, s).map_err(|_| Error::Secret)
    }

    /// The member's key (EIP-2537 G2) from its secret, through `secret_mul` only (spec §12 of ua-rs-sign).
    pub fn member_key(sk: &[u8; 32]) -> core::result::Result<[u8; 256], Error> {
        let s = scalar(sk)?;
        Ok(g2_encode(
            &mul(G2Affine::generator().into_group(), &*s)?.into_affine(),
        ))
    }

    /// `(scalar, index of the member's own key in d)`, `NotMember` unless `d` lists it.
    fn listed(
        sk: &[u8; 32],
        kd: &BlsMultiKeyData,
    ) -> core::result::Result<(Zeroizing<ark_bls12_381::Fr>, usize), Error> {
        let pk = member_key(sk)?;
        let i = kd
            .members
            .iter()
            .position(|m| m.0 == pk)
            .ok_or(Error::NotMember)?;
        Ok((scalar(sk)?, i))
    }

    /// Member `sk`'s partial over `memberDigest(ua, ua_msg)` under [`DST_MULTI_SIG`], `ua` derived from `d` (spec §5.4, N5).
    pub fn member_sign(
        sk: &[u8; 32],
        d: &[u8],
        ua_msg: &[u8; 32],
    ) -> core::result::Result<[u8; 128], Error> {
        let kd = parse(d)?;
        let (s, _) = listed(sk, &kd)?;
        let h = hash_to_g1_bls12381(&keccak(&[&ua_of(d), ua_msg]), DST_MULTI_SIG);
        Ok(g1_encode(&mul(h.into_group(), &*s)?.into_affine()))
    }

    /// Member `sk`'s PoP part `π_i` over `m_i = keccak256(popMsg ‖ pk_i)` under [`DST_MULTI_POP`]: the record, the
    /// registration digest and `popMsg` derived from `d` (never a coordinator's `popMsg`), `pk_i` the signer's own key found in
    /// `d` (spec §4, N5).
    pub fn member_pop(sk: &[u8; 32], d: &[u8]) -> core::result::Result<[u8; 128], Error> {
        let kd = parse(d)?;
        let (s, i) = listed(sk, &kd)?;
        let h = hash_to_g1_bls12381(
            &pop_member_message(&pop_message(d)?, &kd.members[i].0),
            DST_MULTI_POP,
        );
        Ok(g1_encode(&mul(h.into_group(), &*s)?.into_affine()))
    }
}
#[cfg(feature = "signers")]
pub use member::{member_key, member_pop, member_sign};
