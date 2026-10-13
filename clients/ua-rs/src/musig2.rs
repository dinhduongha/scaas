//! BIP-327 MuSig2 (accounts.md §1.6.1), one algorithm over two curves: [`Secp256k1`] is BIP-327 itself (checked against
//! the official vectors, `tests/groups.rs`); [`Bn254`] is the scaas port: points 64-byte EIP-196 `x ‖ y` (aggregate nonce
//! halves at infinity = 64 zero bytes), scalar hashes widened to 512 bits (`tagged(x ‖ 0x00) ‖ tagged(x ‖ 0x01)` mod r),
//! no x-only key or parity negation, challenge = the scaas Schnorr challenge, signature `R (64) ‖ s (32)` (verifies as
//! `schnorr-bn254`). `L = hash_{KeyAgg list}(pk_1 ‖ … ‖ pk_n)` is the plain 32-byte tagged hash on both curves (it is a
//! byte string, not a scalar). No tweaks (the registry has none). Feature `signers`: malformed input is an error, never a
//! panic; not side-channel hardened (secret nonces are plain bytes). UNAUDITED.
use crate::keccak;
use core::ops::{Add, Mul, Neg};
use sha2::{Digest, Sha256};

/// BIP-340 tagged hash `sha256(sha256(tag) ‖ sha256(tag) ‖ parts…)`.
pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(t);
    h.update(t);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// BIP-327 error kinds, named as in the official vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// `invalid_contribution`: `signer` (None for the aggregate nonce) sent a bad `contrib`.
    Contribution(Option<usize>, &'static str),
    /// `value`: an out-of-range input.
    Value(&'static str),
}

pub trait Curve {
    type S: Copy + PartialEq + Add<Output = Self::S> + Mul<Output = Self::S> + Neg<Output = Self::S>;
    type P: Copy + PartialEq + Add<Output = Self::P> + Mul<Self::S, Output = Self::P> + Neg<Output = Self::P>;
    /// Serialized point length.
    const PLEN: usize;
    /// `agg_bytes` length (the aggregate key as NonceGen takes it).
    const ALEN: usize;
    fn g() -> Self::P;
    fn inf() -> Self::P;
    fn one() -> Self::S;
    fn zero_s() -> Self::S;
    /// A tagged hash reduced to a scalar.
    fn hash_s(tag: &str, parts: &[&[u8]]) -> Self::S;
    fn s_bytes(s: &Self::S) -> [u8; 32];
    /// Canonical (< order) 32 bytes.
    fn s_parse(b: &[u8]) -> Option<Self::S>;
    /// The point, the identity as `PLEN` zero bytes (BIP-327 `cbytes_ext`).
    fn ser(p: &Self::P) -> Vec<u8>;
    /// A valid non-identity point.
    fn parse(b: &[u8]) -> Option<Self::P>;
    /// BIP-327 `has_even_y`; always true on bn254 (no parity rules).
    fn even(p: &Self::P) -> bool;
    /// The aggregate key as hashed into the nonce coefficient: `xbytes(Q)` (secp256k1) or `Q` (bn254).
    fn agg_bytes(q: &Self::P) -> Vec<u8>;
    fn challenge(r: &Self::P, q: &Self::P, msg: &[u8]) -> Self::S;
    fn sig(r: &Self::P, s: &Self::S) -> Vec<u8>;
}

/// BIP-327 over secp256k1.
pub struct Secp256k1;
/// The scaas bn254 port.
pub struct Bn254;

impl Curve for Secp256k1 {
    type S = k256::Scalar;
    type P = k256::ProjectivePoint;
    const PLEN: usize = 33;
    const ALEN: usize = 32;
    fn g() -> Self::P {
        k256::ProjectivePoint::GENERATOR
    }
    fn inf() -> Self::P {
        k256::ProjectivePoint::IDENTITY
    }
    fn one() -> Self::S {
        k256::Scalar::ONE
    }
    fn zero_s() -> Self::S {
        k256::Scalar::ZERO
    }
    fn hash_s(tag: &str, parts: &[&[u8]]) -> Self::S {
        use k256::elliptic_curve::ops::Reduce;
        <k256::Scalar as Reduce<k256::U256>>::reduce_bytes(&tagged(tag, parts).into())
    }
    fn s_bytes(s: &Self::S) -> [u8; 32] {
        s.to_bytes().into()
    }
    fn s_parse(b: &[u8]) -> Option<Self::S> {
        use k256::elliptic_curve::PrimeField;
        let b: [u8; 32] = b.try_into().ok()?;
        k256::Scalar::from_repr(b.into()).into()
    }
    fn ser(p: &Self::P) -> Vec<u8> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        if *p == Self::inf() {
            return vec![0; 33];
        }
        p.to_affine().to_encoded_point(true).as_bytes().to_vec()
    }
    fn parse(b: &[u8]) -> Option<Self::P> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        if b.len() != 33 || !(b[0] == 2 || b[0] == 3) {
            return None;
        }
        let ep = k256::EncodedPoint::from_bytes(b).ok()?;
        Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(&ep)).map(Into::into)
    }
    fn even(p: &Self::P) -> bool {
        use k256::elliptic_curve::point::AffineCoordinates;
        !bool::from(p.to_affine().y_is_odd())
    }
    fn agg_bytes(q: &Self::P) -> Vec<u8> {
        Self::ser(q)[1..].to_vec()
    }
    fn challenge(r: &Self::P, q: &Self::P, msg: &[u8]) -> Self::S {
        Self::hash_s("BIP0340/challenge", &[&Self::ser(r)[1..], &Self::ser(q)[1..], msg])
    }
    fn sig(r: &Self::P, s: &Self::S) -> Vec<u8> {
        [&Self::ser(r)[1..], &Self::s_bytes(s)[..]].concat()
    }
}

/// `x ‖ y`, 32-byte big-endian each; the identity as 64 zero bytes.
pub fn bn_ser(p: &ark_bn254::G1Projective) -> Vec<u8> {
    use ark_ec::CurveGroup;
    use ark_ff::{BigInteger, PrimeField};
    let a = p.into_affine();
    if a.infinity {
        return vec![0; 64];
    }
    [a.x.into_bigint().to_bytes_be(), a.y.into_bigint().to_bytes_be()].concat()
}

/// Canonical coordinates, on the curve, not the identity (bn254 G1 has cofactor 1).
pub fn bn_parse(b: &[u8]) -> Option<ark_bn254::G1Projective> {
    use ark_ff::{BigInteger, PrimeField, Zero};
    if b.len() != 64 {
        return None;
    }
    let fe = |s: &[u8]| {
        let f = ark_bn254::Fq::from_be_bytes_mod_order(s);
        (f.into_bigint().to_bytes_be() == s).then_some(f)
    };
    let (x, y) = (fe(&b[..32])?, fe(&b[32..])?);
    let p = ark_bn254::G1Affine::new_unchecked(x, y);
    (!(x.is_zero() && y.is_zero()) && p.is_on_curve()).then(|| p.into())
}

/// The scaas Schnorr challenge `(keccak(s ‖ 2) · 2^256 + keccak(s ‖ 3)) mod r`, `s = keccak(tag ‖ m)`.
pub fn bn_schnorr_challenge(m: &[u8]) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    let seed = keccak(&[crate::verify::SCHNORR_TAG, m]);
    ark_bn254::Fr::from_be_bytes_mod_order(&[keccak(&[&seed, &[2]]), keccak(&[&seed, &[3]])].concat())
}

impl Curve for Bn254 {
    type S = ark_bn254::Fr;
    type P = ark_bn254::G1Projective;
    const PLEN: usize = 64;
    const ALEN: usize = 64;
    fn g() -> Self::P {
        use ark_ec::PrimeGroup;
        ark_bn254::G1Projective::generator()
    }
    fn inf() -> Self::P {
        use ark_ff::Zero;
        ark_bn254::G1Projective::zero()
    }
    fn one() -> Self::S {
        ark_bn254::Fr::from(1u64)
    }
    fn zero_s() -> Self::S {
        ark_bn254::Fr::from(0u64)
    }
    fn hash_s(tag: &str, parts: &[&[u8]]) -> Self::S {
        use ark_ff::PrimeField;
        let wide = |b: u8| tagged(tag, &[parts, &[&[b][..]]].concat());
        ark_bn254::Fr::from_be_bytes_mod_order(&[wide(0), wide(1)].concat())
    }
    fn s_bytes(s: &Self::S) -> [u8; 32] {
        use ark_ff::{BigInteger, PrimeField};
        s.into_bigint().to_bytes_be().try_into().expect("32 bytes")
    }
    fn s_parse(b: &[u8]) -> Option<Self::S> {
        use ark_ff::{BigInteger, PrimeField};
        let f = ark_bn254::Fr::from_be_bytes_mod_order(b);
        (b.len() == 32 && f.into_bigint().to_bytes_be() == b).then_some(f)
    }
    fn ser(p: &Self::P) -> Vec<u8> {
        bn_ser(p)
    }
    fn parse(b: &[u8]) -> Option<Self::P> {
        bn_parse(b)
    }
    fn even(_: &Self::P) -> bool {
        true
    }
    fn agg_bytes(q: &Self::P) -> Vec<u8> {
        bn_ser(q)
    }
    fn challenge(r: &Self::P, q: &Self::P, msg: &[u8]) -> Self::S {
        bn_schnorr_challenge(&[&bn_ser(r)[..], &bn_ser(q), msg].concat())
    }
    fn sig(r: &Self::P, s: &Self::S) -> Vec<u8> {
        [bn_ser(r), Self::s_bytes(s).to_vec()].concat()
    }
}

/// KeyAgg output: `Q`, `L` and the second distinct key (BIP-327 `get_second_key`, all zero if none).
pub struct KeyAgg<C: Curve> {
    pub q: C::P,
    pub l: [u8; 32],
    pub second: Vec<u8>,
}

impl<C: Curve> KeyAgg<C> {
    /// `a_i`: 1 for the second distinct key, else `hash_{KeyAgg coefficient}(L ‖ pk) mod order`.
    pub fn coef(&self, pk: &[u8]) -> C::S {
        if pk == self.second.as_slice() { C::one() } else { C::hash_s("KeyAgg coefficient", &[&self.l, pk]) }
    }
}

/// BIP-327 KeySort: lexicographic byte order.
pub fn key_sort(pks: &mut [Vec<u8>]) {
    pks.sort();
}

/// BIP-327 KeyAgg (no tweaks).
pub fn key_agg<C: Curve>(pks: &[Vec<u8>]) -> Result<KeyAgg<C>, Error> {
    let parts: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
    let l = tagged("KeyAgg list", &parts);
    let second = pks.iter().find(|p| **p != pks[0]).cloned().unwrap_or_else(|| vec![0; C::PLEN]);
    let mut ka = KeyAgg::<C> { q: C::inf(), l, second };
    for (i, pk) in pks.iter().enumerate() {
        let p = C::parse(pk).ok_or(Error::Contribution(Some(i), "pubkey"))?;
        ka.q = ka.q + p * ka.coef(pk);
    }
    if ka.q == C::inf() {
        return Err(Error::Value("The result of KeyAgg cannot be infinity."));
    }
    Ok(ka)
}

/// BIP-327 NonceGen: `(secnonce = k1 ‖ k2 ‖ pk, pubnonce = R1 ‖ R2)`. `aggpk` is `xbytes(Q)` / `Q`. `sk` must be 32 bytes
/// (never truncated), `pk` `PLEN`, `aggpk` `ALEN` (BIP-327's length checks).
pub fn nonce_gen<C: Curve>(
    rand_: &[u8; 32],
    sk: Option<&[u8]>,
    pk: &[u8],
    aggpk: Option<&[u8]>,
    msg: Option<&[u8]>,
    extra_in: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if sk.is_some_and(|sk| sk.len() != 32) {
        return Err(Error::Value("The optional byte array sk must have length 32."));
    }
    if pk.len() != C::PLEN {
        return Err(Error::Value("The pk has the wrong length."));
    }
    if aggpk.is_some_and(|a| a.len() != C::ALEN) {
        return Err(Error::Value("The optional byte array aggpk has the wrong length."));
    }
    let rand: Vec<u8> = match sk {
        Some(sk) => sk.iter().zip(tagged("MuSig/aux", &[rand_])).map(|(a, b)| a ^ b).collect(),
        None => rand_.to_vec(),
    };
    let aggpk = aggpk.unwrap_or(&[]);
    let msg_prefixed = match msg {
        None => vec![0u8],
        Some(m) => [&[1u8][..], &(m.len() as u64).to_be_bytes(), m].concat(),
    };
    let extra = extra_in.unwrap_or(&[]);
    let k = |i: u8| {
        C::hash_s(
            "MuSig/nonce",
            &[&rand, &[pk.len() as u8], pk, &[aggpk.len() as u8], aggpk, &msg_prefixed, &(extra.len() as u32).to_be_bytes(), extra, &[i]],
        )
    };
    let (k1, k2) = (k(0), k(1));
    let secnonce = [&C::s_bytes(&k1)[..], &C::s_bytes(&k2), pk].concat();
    Ok((secnonce, [C::ser(&(C::g() * k1)), C::ser(&(C::g() * k2))].concat()))
}

/// A point or, for `PLEN` zero bytes, the identity (BIP-327 `cpoint_ext`).
fn parse_ext<C: Curve>(b: &[u8]) -> Option<C::P> {
    if b.iter().all(|x| *x == 0) { Some(C::inf()) } else { C::parse(b) }
}

/// BIP-327 NonceAgg.
pub fn nonce_agg<C: Curve>(pubnonces: &[Vec<u8>]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for j in 0..2 {
        let mut r = C::inf();
        for (i, pn) in pubnonces.iter().enumerate() {
            let p = pn.get(j * C::PLEN..(j + 1) * C::PLEN).and_then(C::parse);
            r = r + p.ok_or(Error::Contribution(Some(i), "pubnonce"))?;
        }
        out.extend(C::ser(&r));
    }
    Ok(out)
}

/// KeyAgg, `b`, `R`, `e`.
pub type Session<C> = (KeyAgg<C>, <C as Curve>::S, <C as Curve>::P, <C as Curve>::S);

/// BIP-327 GetSessionValues (no tweaks).
pub fn session<C: Curve>(aggnonce: &[u8], pks: &[Vec<u8>], msg: &[u8]) -> Result<Session<C>, Error> {
    let ka = key_agg::<C>(pks)?;
    let b = C::hash_s("MuSig/noncecoef", &[aggnonce, &C::agg_bytes(&ka.q), msg]);
    let bad = Error::Contribution(None, "aggnonce");
    if aggnonce.len() != 2 * C::PLEN {
        return Err(bad);
    }
    let r1 = parse_ext::<C>(&aggnonce[..C::PLEN]).ok_or(bad.clone())?;
    let r2 = parse_ext::<C>(&aggnonce[C::PLEN..]).ok_or(bad)?;
    let r_ = r1 + r2 * b;
    let r = if r_ == C::inf() { C::g() } else { r_ };
    let e = C::challenge(&r, &ka.q, msg);
    Ok((ka, b, r, e))
}

fn sign_g<C: Curve>(q: &C::P) -> C::S {
    if C::even(q) { C::one() } else { -C::one() }
}

/// BIP-327 Sign: the partial signature `s` (32 bytes).
pub fn sign<C: Curve>(secnonce: &[u8], sk: &[u8], aggnonce: &[u8], pks: &[Vec<u8>], msg: &[u8]) -> Result<[u8; 32], Error> {
    if secnonce.len() != 64 + C::PLEN {
        return Err(Error::Value("The secnonce must be k1 ‖ k2 ‖ pk."));
    }
    let (ka, b, r, e) = session::<C>(aggnonce, pks, msg)?;
    let nonzero = |s: Option<C::S>| s.filter(|s| *s != C::zero_s());
    let k1 = nonzero(C::s_parse(&secnonce[..32])).ok_or(Error::Value("first secnonce value is out of range."))?;
    let k2 = nonzero(C::s_parse(&secnonce[32..64])).ok_or(Error::Value("second secnonce value is out of range."))?;
    let (k1, k2) = if C::even(&r) { (k1, k2) } else { (-k1, -k2) };
    let d_ = nonzero(C::s_parse(sk)).ok_or(Error::Value("The secret key must be in the range 0 < sk < n."))?;
    let pk = C::ser(&(C::g() * d_));
    if pk != secnonce[64..] {
        return Err(Error::Value("Public key does not match nonce_gen argument"));
    }
    if !pks.contains(&pk) {
        return Err(Error::Value("The signer's pubkey must be included in the list of pubkeys."));
    }
    let d = sign_g::<C>(&ka.q) * d_;
    Ok(C::s_bytes(&(k1 + b * k2 + e * ka.coef(&pk) * d)))
}

/// BIP-327 PartialSigVerifyInternal.
pub fn partial_sig_verify_internal<C: Curve>(
    psig: &[u8],
    pubnonce: &[u8],
    pk: &[u8],
    aggnonce: &[u8],
    pks: &[Vec<u8>],
    msg: &[u8],
) -> Result<bool, Error> {
    if pubnonce.len() != 2 * C::PLEN {
        return Err(Error::Value("The pubnonce has the wrong length."));
    }
    let (ka, b, r, e) = session::<C>(aggnonce, pks, msg)?;
    let Some(s) = C::s_parse(psig) else { return Ok(false) };
    let (Some(r1), Some(r2), Some(p)) = (C::parse(&pubnonce[..C::PLEN]), C::parse(&pubnonce[C::PLEN..]), C::parse(pk)) else {
        return Ok(false);
    };
    let re = r1 + r2 * b;
    let re = if C::even(&r) { re } else { -re };
    Ok(C::g() * s == re + p * (e * ka.coef(pk) * sign_g::<C>(&ka.q)))
}

/// BIP-327 PartialSigVerify: signer `i`'s `psig` against all public nonces.
pub fn partial_sig_verify<C: Curve>(psig: &[u8], pubnonces: &[Vec<u8>], pks: &[Vec<u8>], msg: &[u8], i: usize) -> Result<bool, Error> {
    let (Some(pubnonce), Some(pk)) = (pubnonces.get(i), pks.get(i)) else {
        return Err(Error::Value("The signer index is out of range."));
    };
    let aggnonce = nonce_agg::<C>(pubnonces)?;
    partial_sig_verify_internal::<C>(psig, pubnonce, pk, &aggnonce, pks, msg)
}

/// BIP-327 PartialSigAgg (no tweaks): the final signature.
pub fn partial_sig_agg<C: Curve>(psigs: &[[u8; 32]], aggnonce: &[u8], pks: &[Vec<u8>], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let (_, _, r, _) = session::<C>(aggnonce, pks, msg)?;
    let mut s = C::zero_s();
    for (i, p) in psigs.iter().enumerate() {
        s = s + C::s_parse(p).ok_or(Error::Contribution(Some(i), "psig"))?;
    }
    Ok(C::sig(&r, &s))
}

/// The whole n-of-n protocol for one message, every signer simulated: `rands[i]` is signer i's NonceGen `rand'`.
/// Returns the signature; every partial signature is verified on the way.
pub fn sign_all<C: Curve>(sks: &[Vec<u8>], pks: &[Vec<u8>], msg: &[u8], rands: &[[u8; 32]]) -> Result<Vec<u8>, Error> {
    if pks.len() != sks.len() || rands.len() != sks.len() {
        return Err(Error::Value("One pk and one rand per sk."));
    }
    let ka = key_agg::<C>(pks)?;
    let agg = C::agg_bytes(&ka.q);
    let nonces = (0..sks.len()).map(|i| nonce_gen::<C>(&rands[i], Some(&sks[i]), &pks[i], Some(&agg), Some(msg), None)).collect::<Result<Vec<_>, _>>()?;
    let pubnonces: Vec<Vec<u8>> = nonces.iter().map(|n| n.1.clone()).collect();
    let aggnonce = nonce_agg::<C>(&pubnonces)?;
    let mut psigs = Vec::new();
    for (i, (sec, _)) in nonces.iter().enumerate() {
        let p = sign::<C>(sec, &sks[i], &aggnonce, pks, msg)?;
        if !partial_sig_verify::<C>(&p, &pubnonces, pks, msg, i)? {
            return Err(Error::Value("partial signature does not verify"));
        }
        psigs.push(p);
    }
    partial_sig_agg::<C>(&psigs, &aggnonce, pks, msg)
}
