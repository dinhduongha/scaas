// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The pairing-curve kinds and the group sessions (spec §3, §8.2, §9.1, §9.4, §12; T3c). Every multiplication by a secret
//! on an arkworks curve goes through `scaas_ct::secret_mul` (blinded integer, fixed 384-step ladder): the public keys of
//! `0x0104`–`0x0107` and `0x0112`, the scaas Schnorr nonce point, the BLS signature `sk·H(m)`; MuSig2-bn254 through
//! `musig2::Curve::secret_g`, FROST-BN254 through `frost::Bn254Element`. `mul_bigint` is denied here
//! (`clippy::disallowed_methods`); the operator form is covered by the structural test (feature `vectors`).
//!
//! - scaas Schnorr `0x0104` / `0x0105` (`scaas.ua.schnorr.v1`): `k = hashToScalar(keccak256("scaas.ua.schnorr.nonce.v1" ‖
//!   be32(sk) ‖ Y ‖ ua_msg ‖ aux))` with the verifier's one 512-bit map (`verify::hash_to_scalar`), `aux` 32 bytes from the
//!   OS RNG (redrawn if `k = 0`), `R = k·G`, `e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ ua_msg))`, signature `R ‖ k + e·sk`.
//! - BLS min-sig `0x0106` / `0x0107`: `sk·H(ua_msg)` under the domain of the request's [`SigRole`] (`verify.rs`'s DSTs and
//!   labels: SIG for `Authorization`, POP for `Pop`).
//! - [`Musig2Session`]: a wallet participant key's BIP-327 session, its secret nonce in the wallet's arena, wiped by the first
//!   `sign`; [`FrostSession`]: RFC 9591 round 1 / round 2 over a caller's key package, its nonces used once.
//!
//! Residual (spec §12): arkworks field arithmetic, point-addition special cases and the signature's scalar arithmetic
//! (`k + e·sk mod r`) branch on values. UNAUDITED.
use super::signer::SigRole;
use super::store::Handle;
use super::{Error, Result, UaKey};
use crate::keccak;
use crate::musig2::{self, Bn254, Curve, Secp256k1};
use crate::verify::{hash_to_g1_bls12381, hash_to_scalar, map_to_g1_bn254};
use crate::verify::{BLS12381_DST_POP, BLS12381_DST_SIG, BN254_LABEL_POP, BN254_LABEL_SIG, SCHNORR_TAG};
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use frost_core::keys::KeyPackage;
use frost_core::round1::{SigningCommitments, SigningNonces};
use frost_core::round2::SignatureShare;
use frost_core::{Ciphersuite, SigningPackage};
use rand_core::{CryptoRng, OsRng, RngCore};
use scaas_ct::CtSwap;
use zeroize::Zeroizing;

const NONCE_TAG: &[u8] = b"scaas.ua.schnorr.nonce.v1";
type Bn1 = ark_bn254::g1::Config;
type Bls1 = ark_bls12_381::g1::Config;

/// The kinds this module signs through `sign_ua` (the MuSig2 participants sign through [`Musig2Session`]).
pub(crate) fn is_pairing(kind: u16) -> bool {
    matches!(kind, 0x0104..=0x0107)
}

/// `secret · base`, the only multiplication by a secret in this module (spec §12).
fn mul<P: SWCurveConfig>(base: Projective<P>, secret: &P::ScalarField) -> Result<Projective<P>>
where
    P::BaseField: CtSwap,
{
    scaas_ct::secret_mul(base, secret).map_err(|_| Error::Rng)
}

/// The scalar of a 32-byte big-endian secret: canonical (`< r`) and non-zero, else `Argument`.
fn scalar<F: PrimeField>(s: &[u8]) -> Result<Zeroizing<F>> {
    let f = Zeroizing::new(F::from_be_bytes_mod_order(s));
    let back = Zeroizing::new(f.into_bigint().to_bytes_be());
    if s.len() != 32 || back.as_slice() != s || f.is_zero() {
        return Err(Error::Argument);
    }
    Ok(f)
}

/// `f` big-endian, left-padded to `width` bytes.
fn be<F: PrimeField>(f: &F, width: usize, out: &mut Vec<u8>) {
    let b = f.into_bigint().to_bytes_be();
    out.extend(std::iter::repeat_n(0, width.saturating_sub(b.len())));
    out.extend_from_slice(&b);
}

/// A G1 point as `x ‖ y`, each `w` bytes (bn254 32, BLS12-381 64); the identity is `Argument`.
fn g1_bytes<P: SWCurveConfig>(p: &Projective<P>, w: usize, out: &mut Vec<u8>) -> Result<()>
where
    P::BaseField: PrimeField,
{
    let a: Affine<P> = p.into_affine();
    let (x, y) = a.xy().ok_or(Error::Argument)?;
    be(&x, w, out);
    be(&y, w, out);
    Ok(())
}

/// `sk·G1`, `x ‖ y` `w` bytes each.
fn g1_key<P: SWCurveConfig>(s: &[u8], w: usize) -> Result<Vec<u8>>
where
    P::BaseField: PrimeField + CtSwap,
{
    let mut out = Vec::new();
    g1_bytes(&mul(Projective::<P>::generator(), &*scalar::<P::ScalarField>(s)?)?, w, &mut out)?;
    Ok(out)
}

/// `sk·G2` in affine form (the two curves encode it apart).
fn g2_point<P: SWCurveConfig>(s: &[u8]) -> Result<Affine<P>>
where
    P::BaseField: CtSwap,
{
    let p = mul(Projective::<P>::generator(), &*scalar::<P::ScalarField>(s)?)?.into_affine();
    if p.infinity {
        return Err(Error::Argument);
    }
    Ok(p)
}

/// The key data of a pairing kind or a MuSig2-bn254 participant from its 32-byte secret (accounts.md §1.6 forms): bn254 G1
/// `x ‖ y` (`0x0104`, `0x0112`), BLS12-381 G1 64-byte coordinates (`0x0105`), BLS12-381 G2 `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`
/// 64 bytes each (`0x0106`, EIP-2537), bn254 G2 `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0` (`0x0107`, EIP-197).
pub(crate) fn key_data(kind: u16, s: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match kind {
        0x0104 | 0x0112 => return g1_key::<Bn1>(s, 32),
        0x0105 => return g1_key::<Bls1>(s, 64),
        0x0106 => {
            let p = g2_point::<ark_bls12_381::g2::Config>(s)?;
            for f in [&p.x.c0, &p.x.c1, &p.y.c0, &p.y.c1] {
                be(f, 64, &mut out);
            }
        }
        0x0107 => {
            let p = g2_point::<ark_bn254::g2::Config>(s)?;
            for f in [&p.x.c1, &p.x.c0, &p.y.c1, &p.y.c0] {
                be(f, 32, &mut out);
            }
        }
        _ => return Err(Error::Argument),
    }
    Ok(out)
}

/// The scaas Schnorr nonce `hashToScalar(keccak256("scaas.ua.schnorr.nonce.v1" ‖ be32(sk) ‖ Y ‖ ua_msg ‖ aux))`.
fn nonce<F: PrimeField>(sk: &[u8], y: &[u8], ua_msg: &[u8; 32], aux: &[u8; 32]) -> F {
    hash_to_scalar(&keccak(&[NONCE_TAG, sk, y, ua_msg, aux]))
}

/// scaas Schnorr of `ua_msg` by the secret `sk` whose key data is `y`; `fixed` replaces the OS `aux` (feature `vectors`,
/// `Argument` if it gives `k = 0`).
fn schnorr<P: SWCurveConfig>(sk_bytes: &[u8], y: &[u8], ua_msg: &[u8; 32], fixed: Option<&[u8; 32]>, w: usize) -> Result<Vec<u8>>
where
    P::BaseField: PrimeField + CtSwap,
{
    let sk = scalar::<P::ScalarField>(sk_bytes)?;
    loop {
        let aux = match fixed {
            Some(a) => *a,
            None => super::sign::os_aux()?,
        };
        let k: Zeroizing<P::ScalarField> = Zeroizing::new(nonce(sk_bytes, y, ua_msg, &aux));
        if k.is_zero() {
            if fixed.is_some() {
                return Err(Error::Argument);
            }
            continue;
        }
        let mut sig = Vec::new();
        g1_bytes(&mul(Projective::<P>::generator(), &k)?, w, &mut sig)?;
        let e: P::ScalarField = hash_to_scalar(&keccak(&[SCHNORR_TAG, &sig, y, ua_msg]));
        if e.is_zero() {
            return Err(Error::Argument);
        }
        let z = Zeroizing::new(*k + e * *sk);
        be(&*z, 32, &mut sig);
        return Ok(sig);
    }
}

/// The signature of `ua_msg` by the pairing kind `kind` with its secret and key data; `role` picks the BLS domain;
/// `fixed`: scaas Schnorr's `aux` (32 bytes, feature `vectors`), none for BLS (deterministic).
pub(crate) fn sign(kind: u16, secret: &[u8], key_data: &[u8], ua_msg: &[u8; 32], role: SigRole, fixed: Option<&[u8]>) -> Result<Vec<u8>> {
    let pop = role == SigRole::Pop;
    let aux = fixed.map(<&[u8; 32]>::try_from).transpose().map_err(|_| Error::Argument)?;
    let mut out = Vec::new();
    match (kind, aux) {
        (0x0104, _) => return schnorr::<Bn1>(secret, key_data, ua_msg, aux, 32),
        (0x0105, _) => return schnorr::<Bls1>(secret, key_data, ua_msg, aux, 64),
        (0x0106, None) => {
            let h = hash_to_g1_bls12381(ua_msg, if pop { BLS12381_DST_POP } else { BLS12381_DST_SIG });
            g1_bytes(&mul(h.into_group(), &*scalar(secret)?)?, 64, &mut out)?;
        }
        (0x0107, None) => {
            let h = map_to_g1_bn254(&[if pop { BN254_LABEL_POP } else { BN254_LABEL_SIG }, &ua_msg[..]].concat());
            g1_bytes(&mul(h.into_group(), &*scalar(secret)?)?, 32, &mut out)?;
        }
        _ => return Err(Error::Argument),
    }
    Ok(out)
}

fn musig2_error(e: musig2::Error) -> Error {
    if e == musig2::Error::Value("OS RNG") {
        Error::Rng
    } else {
        Error::Argument
    }
}

/// A BIP-327 MuSig2 signing session of one wallet participant key (`0x0110` secp256k1, `0x0112` bn254) over one key list and
/// one message (NonceGen binds both). Its secret nonce lives in the wallet's arena (spec §8.2) and is wiped by the first
/// [`Musig2Session::sign`]; a second `sign` is `Argument`. After the wallet's `lock()`: `KeyRevoked`. No `Clone`.
pub struct Musig2Session {
    kind: u16,
    pk: Vec<u8>,
    pks: Vec<Vec<u8>>,
    msg: Vec<u8>,
    pubnonce: Vec<u8>,
    key: Handle,
    nonce: Option<Handle>,
}

impl Musig2Session {
    pub fn kind(&self) -> u16 {
        self.kind
    }
    /// The public nonce `R1 ‖ R2` to send to the other signers.
    pub fn pubnonce(&self) -> Vec<u8> {
        self.pubnonce.clone()
    }
    /// The partial signature (BIP-327 Sign) under the aggregate nonce; spends the secret nonce first, so a second call (or a
    /// call after a failed one) is `Argument`.
    pub fn sign(&mut self, aggnonce: &[u8]) -> Result<[u8; 32]> {
        let k = self.nonce.take().ok_or(Error::Argument)?.take()?;
        let sec = Zeroizing::new([&k[..], &self.pk].concat());
        let (pks, msg) = (&self.pks, &self.msg);
        let r = match self.kind {
            0x0110 => self.key.with(|sk| musig2::sign::<Secp256k1>(&sec, sk, aggnonce, pks, msg))?,
            _ => self.key.with(|sk| musig2::sign::<Bn254>(&sec, sk, aggnonce, pks, msg))?,
        };
        r.map_err(musig2_error)
    }
}

impl UaKey {
    /// A MuSig2 session of this participant key (`0x0110`, `0x0112`; else `Argument`) over `pks` (its own key among them,
    /// in the order the group signs) and `msg`, its `rand'` from the OS RNG.
    pub fn musig2_session(&self, pks: &[Vec<u8>], msg: &[u8]) -> Result<Musig2Session> {
        let mut rand = Zeroizing::new([0u8; 32]);
        OsRng.try_fill_bytes(&mut rand[..]).map_err(|_| Error::Rng)?;
        self.musig2_session_with(pks, msg, &rand)
    }

    fn musig2_session_with(&self, pks: &[Vec<u8>], msg: &[u8], rand: &[u8; 32]) -> Result<Musig2Session> {
        match self.kind {
            0x0110 => self.session::<Secp256k1>(pks, msg, rand),
            0x0112 => self.session::<Bn254>(pks, msg, rand),
            _ => Err(Error::Argument),
        }
    }

    fn session<C: Curve>(&self, pks: &[Vec<u8>], msg: &[u8], rand: &[u8; 32]) -> Result<Musig2Session> {
        if !pks.contains(&self.key_data) {
            return Err(Error::Argument);
        }
        let agg = C::agg_bytes(&musig2::key_agg::<C>(pks).map_err(musig2_error)?.q);
        let pk = &self.key_data;
        let (sec, pubnonce) =
            self.secret.with(|sk| musig2::nonce_gen::<C>(rand, Some(sk), pk, Some(&agg), Some(msg), None))?.map_err(musig2_error)?;
        let sec = Zeroizing::new(sec);
        let nonce = self.secret.put(sec.get(..64).ok_or(Error::Argument)?)?;
        Ok(Musig2Session {
            kind: self.kind,
            pk: self.key_data.clone(),
            pks: pks.to_vec(),
            msg: msg.to_vec(),
            pubnonce,
            key: self.secret.dup(),
            nonce: Some(nonce),
        })
    }
}

/// An RFC 9591 FROST signing session (round 1 → round 2) of one participant's key package, either ciphersuite: its nonces
/// (OS RNG) sign once; a second [`FrostSession::sign`] is `Argument`. No `Clone`.
// ponytail: the nonces live in this object (frost-core's `SigningNonces`, zeroized on drop), not in a wallet arena: the share
// itself is the caller's `KeyPackage` until the vault (T9) keeps FROST shares; both move into the store then.
pub struct FrostSession<C: Ciphersuite> {
    nonces: Option<SigningNonces<C>>,
    commitments: SigningCommitments<C>,
}

impl<C: Ciphersuite> FrostSession<C> {
    pub fn new(key: &KeyPackage<C>) -> FrostSession<C> {
        FrostSession::with_rng(key, &mut OsRng)
    }

    fn with_rng(key: &KeyPackage<C>, rng: &mut (impl RngCore + CryptoRng)) -> FrostSession<C> {
        let (n, c) = frost_core::round1::commit(key.signing_share(), rng);
        FrostSession { nonces: Some(n), commitments: c }
    }

    /// Round 1's commitments, for the coordinator.
    pub fn commitments(&self) -> SigningCommitments<C> {
        self.commitments
    }

    /// Round 2's signature share; spends the nonces first.
    pub fn sign(&mut self, package: &SigningPackage<C>, key: &KeyPackage<C>) -> Result<SignatureShare<C>> {
        let n = self.nonces.take().ok_or(Error::Argument)?;
        frost_core::round2::sign(package, &n, key).map_err(|_| Error::Argument)
    }
}

/// Test-only entry points (feature `vectors`, never in a release build): fixed randomness, the nonce map.
#[cfg(feature = "vectors")]
mod vectors {
    use super::*;

    impl UaKey {
        /// `musig2_session` with a fixed `rand'`.
        pub fn vectors_musig2_session(&self, pks: &[Vec<u8>], msg: &[u8], rand: &[u8; 32]) -> Result<Musig2Session> {
            self.musig2_session_with(pks, msg, rand)
        }
    }

    impl<C: Ciphersuite> FrostSession<C> {
        /// `new` with the caller's RNG.
        pub fn vectors_with_rng(key: &KeyPackage<C>, rng: &mut (impl RngCore + CryptoRng)) -> FrostSession<C> {
            FrostSession::with_rng(key, rng)
        }
    }
}

/// The scaas Schnorr nonce `k` of `0x0104` / `0x0105` (32 bytes big-endian) for the secret `sk`, key data `y`, `ua_msg`
/// and `aux` (feature `vectors`: the nonce-map rows).
#[cfg(feature = "vectors")]
pub fn schnorr_nonce(kind: u16, sk: &[u8; 32], y: &[u8], ua_msg: &[u8; 32], aux: &[u8; 32]) -> Result<[u8; 32]> {
    let mut out = Vec::new();
    match kind {
        0x0104 => be(&nonce::<ark_bn254::Fr>(sk, y, ua_msg, aux), 32, &mut out),
        0x0105 => be(&nonce::<ark_bls12_381::Fr>(sk, y, ua_msg, aux), 32, &mut out),
        _ => return Err(Error::Argument),
    }
    out.try_into().map_err(|_| Error::Argument)
}
