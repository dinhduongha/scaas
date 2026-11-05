// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Key derivation exactly as clientkeys (spec §4; `seed.js`, `uakey.js`, `zether.js`, `pq.js`), held to keys.json: BIP-32
//! secp256k1 (`bip32`), SLIP-10 ed25519 (hardened steps only) and nist256p1 (non-hardened steps and both retries, as
//! slip-0010.md), EIP-2333 with the curve order and salt as parameters, and the PQ seeds `HKDF-SHA256(seed, "scaas.ua.pq.v1",
//! utf8(tag) ‖ be32(account) ‖ be32(index))`. The UA tree is `m/22776'/0'/<account>'/<kindNo>'/<i>'`; the EIP-2333 UA paths
//! `m/254/0/<account>/<kindNo>` (salt `SCAAS-UA-BN254-v1`) and `m/12381/0/<account>/<kindNo>` have no index level: index 0
//! only. `account`, `index` and `coinType` are below 2^31 (`Argument`). Public only under feature `vectors` (each returns a
//! secret). The pairing kinds' public keys use arkworks' variable-time multiplication until T3c's `secret_mul`. UNAUDITED.
use super::{Error, Network, Result};
use crate::kind_tag_string;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::ff::{Field, PrimeField as _};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

pub const HARDENED: u32 = 0x8000_0000;
/// The UA tree's purpose (owner 2026-11-05).
pub const UA_PURPOSE: u32 = 22776;
pub const BN254_SALT: &[u8] = b"SCAAS-UA-BN254-v1";
pub const BLS_SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
const PQ_SALT: &[u8] = b"scaas.ua.pq.v1";

/// A SLIP-10 curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    Ed25519,
    Nist256p1,
}

fn range(v: u32) -> Result<u32> {
    if v < HARDENED {
        Ok(v)
    } else {
        Err(Error::Argument)
    }
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Result<Zeroizing<[u8; 64]>> {
    let mut m = Hmac::<Sha512>::new_from_slice(key).map_err(|_| Error::Argument)?;
    for p in parts {
        m.update(p);
    }
    let mut r = m.finalize().into_bytes();
    let out = Zeroizing::new(AsRef::<[u8]>::as_ref(&r).try_into().map_err(|_| Error::Argument)?);
    AsMut::<[u8]>::as_mut(&mut r).zeroize();
    Ok(out)
}

fn halves(i: &[u8; 64]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let (mut l, mut r) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
    for (n, b) in i.iter().enumerate() {
        if let Some(x) = if n < 32 { l.get_mut(n) } else { r.get_mut(n - 32) } {
            *x = *b;
        }
    }
    (l, r)
}

/// A P-256 scalar in `[1, n)`, else `None` (`0` or `≥ n`).
fn p256_key(b: &[u8; 32]) -> Option<p256::Scalar> {
    Option::<p256::Scalar>::from(p256::Scalar::from_repr((*b).into())).filter(|s| !bool::from(s.is_zero()))
}

fn p256_compressed(k: &[u8; 32]) -> Result<Vec<u8>> {
    let sk = p256::SecretKey::from_slice(k).map_err(|_| Error::Argument)?;
    Ok(sk.public_key().to_encoded_point(true).as_bytes().to_vec())
}

/// SLIP-10 `(key ‖ chainCode)` at `path` (hardened steps carry [`HARDENED`]). ed25519: hardened steps only (`Argument`).
/// nist256p1: master `IL = 0 or ≥ n` → `I = HMAC(key, I)`; child `IL ≥ n or k = 0` → `data = 0x01 ‖ IR ‖ ser32(i)`; a
/// non-hardened step hashes the parent's compressed public key.
pub fn slip10(curve: Curve, seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 64]>> {
    let key: &[u8] = match curve {
        Curve::Ed25519 => b"ed25519 seed",
        Curve::Nist256p1 => b"Nist256p1 seed",
    };
    let mut i = hmac512(key, &[seed])?;
    while curve == Curve::Nist256p1 && p256_key(&halves(&i).0).is_none() {
        i = hmac512(key, &[&i[..]])?;
    }
    for &c in path {
        let ser = c.to_be_bytes();
        let (k, cc) = halves(&i);
        let mut data = Zeroizing::new(if c & HARDENED != 0 {
            [&[0u8][..], &k[..], &ser].concat()
        } else if curve == Curve::Nist256p1 {
            [&p256_compressed(&k)?[..], &ser].concat()
        } else {
            return Err(Error::Argument);
        });
        i = loop {
            let next = hmac512(&cc[..], &[&data])?;
            if curve == Curve::Ed25519 {
                break next;
            }
            let (il, ir) = halves(&next);
            let child = p256_key(&il).zip(p256_key(&k)).map(|(a, b)| a + b).filter(|s| !bool::from(s.is_zero()));
            if let Some(s) = child {
                let mut out = Zeroizing::new([0u8; 64]);
                for (n, b) in s.to_repr().iter().chain(ir.iter()).enumerate() {
                    if let Some(x) = out.get_mut(n) {
                        *x = *b;
                    }
                }
                break out;
            }
            *data = [&[1u8][..], &ir[..], &ser].concat();
        };
    }
    Ok(i)
}

/// BIP-32 secp256k1 private key at `path`.
pub fn bip32(seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 32]>> {
    let mut p = ::bip32::DerivationPath::default();
    for &c in path {
        p.push(::bip32::ChildNumber(c));
    }
    let x = ::bip32::XPrv::derive_from_path(seed, &p).map_err(|_| Error::Argument)?;
    Ok(Zeroizing::new(x.to_bytes()))
}

fn scalar32<F: PrimeField>(f: &F) -> Result<Zeroizing<[u8; 32]>> {
    let v = Zeroizing::new(f.into_bigint().to_bytes_be());
    Ok(Zeroizing::new(v.as_slice().try_into().map_err(|_| Error::Argument)?))
}

/// EIP-2333 `HKDF_mod_r(IKM)` with the curve order of `F` and the salt `salt0`.
fn hkdf_mod_r<F: PrimeField>(ikm: &[u8], salt0: &[u8]) -> Result<F> {
    let ikm0 = Zeroizing::new([ikm, &[0u8]].concat());
    let mut salt = Sha256::digest(salt0);
    loop {
        let mut okm = Zeroizing::new([0u8; 48]);
        Hkdf::<Sha256>::new(Some(&salt), &ikm0).expand(&[0, 48], &mut okm[..]).map_err(|_| Error::Argument)?;
        let sk = F::from_be_bytes_mod_order(&okm[..]);
        if !sk.is_zero() {
            return Ok(sk);
        }
        salt = Sha256::digest(salt);
    }
}

/// EIP-2333 `parent_SK_to_lamport_PK`.
fn lamport_pk<F: PrimeField>(parent: &F, index: u32) -> Result<[u8; 32]> {
    let ikm = scalar32(parent)?;
    let not_ikm = Zeroizing::new(ikm.map(|b| !b));
    let mut h = Sha256::new();
    for k in [&ikm[..], &not_ikm[..]] {
        let mut okm = Zeroizing::new(vec![0u8; 255 * 32]);
        Hkdf::<Sha256>::new(Some(&index.to_be_bytes()), k).expand(&[], &mut okm).map_err(|_| Error::Argument)?;
        for c in okm.chunks(32) {
            h.update(Sha256::digest(c));
        }
    }
    Ok(h.finalize().into())
}

/// EIP-2333: the key at `path` (no hardened steps) from `seed` (≥ 32 bytes), over the order of `F` with `salt`; 32 bytes
/// big-endian.
pub fn eip2333<F: PrimeField>(seed: &[u8], path: &[u32], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if seed.len() < 32 {
        return Err(Error::Argument);
    }
    let mut sk = hkdf_mod_r::<F>(seed, salt)?;
    for &i in path {
        let child = hkdf_mod_r::<F>(&lamport_pk(&sk, i)?, salt)?;
        sk.zeroize();
        sk = child;
    }
    let out = scalar32(&sk);
    sk.zeroize();
    out
}

/// The PQ seed of `tag` (pq.js `pqSeed`).
pub fn hkdf_pq(seed: &[u8], tag: &str, account: u32, index: u32, len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let info = [tag.as_bytes(), &account.to_be_bytes(), &index.to_be_bytes()].concat();
    let mut out = Zeroizing::new(vec![0u8; len]);
    Hkdf::<Sha256>::new(Some(PQ_SALT), seed).expand(&info, &mut out).map_err(|_| Error::Argument)?;
    Ok(out)
}

fn head(s: Zeroizing<[u8; 64]>) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.iter().take(32).copied().collect())
}

/// The secret of UA kind `kind` at `account` / `index` from the 64-byte seed: 32 bytes (the curve kinds), the 32- or 48-byte
/// HKDF seed (the PQ kinds). `Argument` for a kind not derived from the seed (a native kind, `webauthn-p256`, FROST shares,
/// `msig`, `zether-bls12381`), an out-of-range value, or index ≠ 0 on an EIP-2333 kind.
pub fn ua_secret(seed: &[u8], kind: u16, account: u32, index: u32) -> Result<Zeroizing<Vec<u8>>> {
    range(account)?;
    range(index)?;
    crate::kind_info(kind)?;
    let tree = [UA_PURPOSE | HARDENED, HARDENED, account | HARDENED, u32::from(kind) | HARDENED, index | HARDENED];
    let eip = |root: u32| if index == 0 { Ok([root, 0, account, u32::from(kind)]) } else { Err(Error::Argument) };
    Ok(match kind {
        0x0101 => head(slip10(Curve::Nist256p1, seed, &tree)?),
        0x0102 => head(slip10(Curve::Ed25519, seed, &tree)?),
        0x0103 | 0x0108 | 0x0110 => Zeroizing::new(bip32(seed, &tree)?.to_vec()),
        0x0104 | 0x0107 | 0x0112 => Zeroizing::new(eip2333::<ark_bn254::Fr>(seed, &eip(254)?, BN254_SALT)?.to_vec()),
        0x0105 | 0x0106 => Zeroizing::new(eip2333::<ark_bls12_381::Fr>(seed, &eip(12381)?, BLS_SALT)?.to_vec()),
        0x0130 | 0x0131 | 0x0134 => hkdf_pq(seed, &kind_tag_string(kind)?, account, index, 32)?,
        0x0132 | 0x0133 | 0x0135 => hkdf_pq(seed, &kind_tag_string(kind)?, account, index, 48)?,
        _ => return Err(Error::Argument),
    })
}

fn be<F: PrimeField>(f: &F, width: usize, out: &mut Vec<u8>) {
    let b = f.into_bigint().to_bytes_be();
    out.extend(std::iter::repeat_n(0, width.saturating_sub(b.len())));
    out.extend_from_slice(&b);
}

fn tail(b: &[u8]) -> Result<Vec<u8>> {
    b.get(1..).map(<[u8]>::to_vec).ok_or(Error::Argument)
}

fn arr32(s: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(s.try_into().map_err(|_| Error::Argument)?))
}

fn ed25519_public(s: &[u8]) -> Result<Vec<u8>> {
    Ok(ed25519_dalek::SigningKey::from_bytes(&*arr32(s)?).verifying_key().to_bytes().to_vec())
}

fn secp_public(s: &[u8], compressed: bool) -> Result<Vec<u8>> {
    let sk = k256::SecretKey::from_slice(s).map_err(|_| Error::Argument)?;
    Ok(sk.public_key().to_encoded_point(compressed).as_bytes().to_vec())
}

fn mldsa<P: ml_dsa::MlDsaParams>(s: &[u8]) -> Result<Vec<u8>> {
    use ml_dsa::Keypair;
    let seed = Zeroizing::new(ml_dsa::Seed::try_from(s).map_err(|_| Error::Argument)?);
    Ok(ml_dsa::SigningKey::<P>::from_seed(&seed).verifying_key().encode().to_vec())
}

fn slhdsa128s(s: &[u8]) -> Result<Vec<u8>> {
    let part = |r: std::ops::Range<usize>| s.get(r).ok_or(Error::Argument);
    let sk = slh_dsa::SigningKey::<slh_dsa::Sha2_128s>::slh_keygen_internal(part(0..16)?, part(16..32)?, part(32..48)?);
    Ok(AsRef::<slh_dsa::VerifyingKey<_>>::as_ref(&sk).to_bytes().to_vec())
}

/// The key data of UA kind `kind` from its secret (accounts.md §1.6 forms; a MuSig2 participant: its individual key).
pub fn ua_key_data(kind: u16, s: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match kind {
        0x0101 => {
            let sk = p256::SecretKey::from_slice(s).map_err(|_| Error::Argument)?;
            out = tail(sk.public_key().to_encoded_point(false).as_bytes())?;
        }
        0x0102 => out = ed25519_public(s)?,
        0x0103 => out = k256::schnorr::SigningKey::from_bytes(s).map_err(|_| Error::Argument)?.verifying_key().to_bytes().to_vec(),
        0x0108 => out = tail(&secp_public(s, false)?)?,
        0x0110 => out = secp_public(s, true)?,
        0x0104 | 0x0112 => {
            let p = (ark_bn254::G1Affine::generator() * ark_bn254::Fr::from_be_bytes_mod_order(s)).into_affine();
            be(&p.x, 32, &mut out);
            be(&p.y, 32, &mut out);
        }
        0x0105 => {
            let p = (ark_bls12_381::G1Affine::generator() * ark_bls12_381::Fr::from_be_bytes_mod_order(s)).into_affine();
            be(&p.x, 64, &mut out);
            be(&p.y, 64, &mut out);
        }
        0x0106 => {
            let p = (ark_bls12_381::G2Affine::generator() * ark_bls12_381::Fr::from_be_bytes_mod_order(s)).into_affine();
            for f in [&p.x.c0, &p.x.c1, &p.y.c0, &p.y.c1] {
                be(f, 64, &mut out);
            }
        }
        0x0107 => {
            let p = (ark_bn254::G2Affine::generator() * ark_bn254::Fr::from_be_bytes_mod_order(s)).into_affine();
            for f in [&p.x.c1, &p.x.c0, &p.y.c1, &p.y.c0] {
                be(f, 32, &mut out);
            }
        }
        0x0130 => out = mldsa::<ml_dsa::MlDsa44>(s)?,
        0x0131 => out = mldsa::<ml_dsa::MlDsa65>(s)?,
        0x0134 => out = mldsa::<ml_dsa::MlDsa87>(s)?,
        0x0133 => out = slhdsa128s(s)?,
        // PQClean's seeded Falcon keygen (MD-8, equal to clientkeys' per T0) is vendored in T3b
        0x0132 | 0x0135 => return Err(Error::KindUnavailable),
        _ => return Err(Error::Argument),
    }
    Ok(out)
}

/// The secret of `network`'s key `index` (clientkeys `deriveKey`): BIP-32 or SLIP-10 ed25519 at the network's SLIP-44 path,
/// `coin_type` in place of the network's coin type.
pub fn native_secret(seed: &[u8], network: Network, index: u32, coin_type: Option<u32>) -> Result<Zeroizing<Vec<u8>>> {
    let mut path = network.path(range(index)?);
    if let (Some(c), Some(p)) = (coin_type, path.get_mut(1)) {
        *p = range(c)? | HARDENED;
    }
    Ok(if network.ed25519() {
        head(slip10(Curve::Ed25519, seed, &path)?)
    } else {
        Zeroizing::new(bip32(seed, &path)?.to_vec())
    })
}

/// The public key of a native key: the compressed secp256k1 key or the ed25519 key (clientkeys `publicKey`).
pub fn native_public(network: Network, s: &[u8]) -> Result<Vec<u8>> {
    if network.ed25519() {
        ed25519_public(s)
    } else {
        secp_public(s, true)
    }
}
