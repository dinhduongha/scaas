//! UA-2a signature verification (accounts.md §1.9) on curve code independent of the JS generator: p256 (P-256, WebAuthn),
//! k256 (BIP-340, native ECDSA), arkworks (scaas Schnorr on bn254 / BLS12-381; BLS min-sig on both curves, with an own
//! port of the bn254 `mapToG1` and arkworks' RFC 9380 hasher for BLS12-381), ed25519-dalek (`verify_strict`). Key data is assumed validated
//! ([`crate::validate_key_data`]) and matched against the id; signatures are untrusted: anything malformed is `false`,
//! never a panic. UNAUDITED.
use crate::keccak;
use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use sha2::{Digest, Sha256};

pub use crate::groups::{dkg_transcript_ok, frost_secp256k1};

pub const SCHNORR_TAG: &[u8] = b"scaas.ua.schnorr.v1";
/// The Zether UA's Schnorr (0x0141): the same scheme under the prover's tag.
pub const ZETHER_SCHNORR_TAG: &[u8] = b"SCAAS-ZETHER-SCHNORR-V1";
pub const BLS12381_DST_SIG: &[u8] = b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_";
pub const BLS12381_DST_POP: &[u8] = b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
pub const BN254_LABEL_SIG: &[u8] = b"SCAAS-UA-BLS-BN254-SIG-V1";
pub const BN254_LABEL_POP: &[u8] = b"SCAAS-UA-BLS-BN254-POP-V1";

/// `IUAKindVerifier.verify` (`pop = false`) / `IUAPopVerifier.verifyPop` (`pop = true`) for the UA-2a kinds; `pop` only
/// changes the BLS kinds' domain. The group kinds 0x0110–0x0113 (UA-2c, `groups.rs`): `pop = false` takes the stored `vk`
/// (`Q`/`Y`: 33 bytes SEC1 compressed or 64 bytes bn254) and checks a group signature; `pop = true` takes the full key
/// data and the registration `pop` blob and runs the whole group check. Other kinds: `false`.
pub fn verify(kind: u16, key_data: &[u8], message: &[u8; 32], sig: &[u8], pop: bool) -> bool {
    match kind {
        0x0100 => webauthn_p256(key_data, message, sig),
        0x0101 => sig.len() == 64 && key_data.len() == 64 && p256_ok(key_data, &sha256(&[message]), sig),
        0x0102 => ed25519(key_data, message, sig),
        0x0103 => bip340(key_data, message, sig),
        0x0104 => schnorr::<ark_bn254::g1::Config>(key_data, message, sig, 32),
        0x0105 => schnorr::<ark_bls12_381::g1::Config>(key_data, message, sig, 64),
        0x0141 => schnorr_tagged::<ark_bls12_381::g1::Config>(ZETHER_SCHNORR_TAG, key_data, message, sig, 64),
        0x0106 => bls12381_minsig(key_data, message, sig, pop),
        0x0107 => bls_bn254_minsig(key_data, message, sig, pop),
        0x0108 => key_data.len() == 64 && native_ecdsa(keccak(&[key_data])[12..].try_into().unwrap(), message, sig),
        0x0110..=0x0113 => crate::groups::verify(kind, key_data, message, sig, pop),
        _ => false,
    }
}

/// A native EOA: low-s ECDSA `r ‖ s ‖ v` (v ∈ {27, 28}) over `digest` (the registry's `uaAuthDigest`) recovering `address`.
pub fn native_ecdsa(address: &[u8; 20], digest: &[u8; 32], sig: &[u8]) -> bool {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    if sig.len() != 65 || !(sig[64] == 27 || sig[64] == 28) {
        return false;
    }
    let Ok(s) = Signature::from_slice(&sig[..64]) else { return false };
    if s.normalize_s().is_some() {
        return false; // high s
    }
    let Some(rec) = RecoveryId::from_byte(sig[64] - 27) else { return false };
    let Ok(vk) = VerifyingKey::recover_from_prehash(digest, &s, rec) else { return false };
    let pt = vk.to_encoded_point(false);
    keccak(&[&pt.as_bytes()[1..]])[12..] == address[..]
}

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// ECDSA-P256 over the 32-byte `hash`, `xy` the uncompressed key without its prefix; high s refused.
fn p256_ok(xy: &[u8], hash: &[u8; 32], rs: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let mut sec1 = [4u8; 65];
    sec1[1..].copy_from_slice(xy);
    let (Ok(vk), Ok(s)) = (VerifyingKey::from_sec1_bytes(&sec1), Signature::from_slice(rs)) else { return false };
    s.normalize_s().is_none() && vk.verify_prehash(hash, &s).is_ok()
}

// --- WebAuthn ---

fn word_usize(b: &[u8], o: usize) -> Option<usize> {
    let w = b.get(o..o.checked_add(32)?)?;
    w[..24].iter().all(|x| *x == 0).then(|| w[24..].iter().fold(0usize, |a, x| (a << 8) | *x as usize))
}
/// `(authenticatorData, clientDataJSON)` of the WebAuthn blob, only if `sig` is their canonical
/// `abi.encode(authenticatorData, clientDataJSON, r, s)` (owner 2026-10-30, CTR-UA-33 C; `WebAuthnP256Verifier._fields`):
/// heads 0x80 and 0xa0 + pad32(len a), each field its length word ‖ data ‖ zero padding, no trailing bytes.
fn webauthn_fields(sig: &[u8]) -> Option<(&[u8], &[u8])> {
    let pad = |n: usize| n.checked_add(31).map(|x| x / 32 * 32);
    let n = sig.len();
    let la = word_usize(sig, 0x80).filter(|x| *x <= n)?;
    let oc = 0xa0 + pad(la)?;
    let lc = word_usize(sig, oc).filter(|x| *x <= n)?;
    let (ea, ec) = (0xa0 + la, oc + 32 + lc);
    let canonical = n == oc + 32 + pad(lc)?
        && word_usize(sig, 0) == Some(0x80)
        && word_usize(sig, 32) == Some(oc)
        && sig[ea..oc].iter().chain(&sig[ec..]).all(|x| *x == 0);
    canonical.then(|| (&sig[0xa0..ea], &sig[oc + 32..ec]))
}

fn base64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, x)| a | (*x as u32) << (16 - 8 * i));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// `SmartKeyAccount._clientDataOk` without the origin comparison: the fixed prefix with type and challenge, any origin up
/// to the next `"`, then `}` at the end, or `,"crossOrigin":false` followed by `}` at the end or by `,`.
fn client_data_ok(cd: &[u8], challenge: &[u8; 32]) -> bool {
    let prefix = format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"", base64url(challenge));
    let (p, n) = (prefix.len(), cd.len());
    if n < p + 2 || &cd[..p] != prefix.as_bytes() {
        return false;
    }
    let Some(end) = cd[p..].iter().position(|c| *c == b'"').map(|i| p + i) else { return false };
    if end + 1 >= n {
        return false;
    }
    if cd[end + 1] == b'}' {
        return end + 2 == n;
    }
    let cross = b",\"crossOrigin\":false";
    let after = end + 1 + cross.len();
    if after >= n || &cd[end + 1..after] != cross {
        return false;
    }
    if cd[after] == b'}' { after + 1 == n } else { cd[after] == b',' }
}

/// `abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s)`, canonical only (checked first).
fn webauthn_p256(key_data: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
    let Some((auth, cd)) = webauthn_fields(sig) else { return false };
    if key_data.len() != 96 || auth.len() < 37 || auth[..32] != key_data[64..96] || auth[32] & 0x05 != 0x05 {
        return false;
    }
    client_data_ok(cd, message) && p256_ok(&key_data[..64], &sha256(&[auth, &sha256(&[cd])]), &sig[64..128])
}

// --- ed25519 ---

/// RFC 8032 strict (§1.9) over a message of any length: ed25519-dalek `verify_strict` (S < L, canonical R, R and A not small
/// order, cofactorless `[S]B == R + [k]A`) and a canonical `A` encoding, which `verify_strict` leaves unchecked
/// (dalek-cryptography/curve25519-dalek#626; such keys have no known discrete log, so no vector can tell the difference).
pub fn ed25519(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk), ed25519_dalek::Signature::from_slice(sig)) else { return false };
    let canonical = CompressedEdwardsY(pk).decompress().is_some_and(|p| p.compress().to_bytes() == pk);
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk) else { return false };
    canonical && vk.verify_strict(message, &sig).is_ok()
}

// --- BIP-340 ---

pub(crate) fn bip340(key_data: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(vk), Ok(s)) = (k256::schnorr::VerifyingKey::from_bytes(key_data), k256::schnorr::Signature::try_from(sig)) else {
        return false;
    };
    vk.verify_raw(message, &s).is_ok()
}

// --- arkworks points ---

/// Big-endian bytes → the element, `None` unless canonical (< modulus).
fn fe<F: PrimeField>(b: &[u8]) -> Option<F> {
    let f = F::from_be_bytes_mod_order(b);
    (f.into_bigint().to_bytes_be() == b).then_some(f)
}
/// A coordinate `w` bytes wide: bn254 32, BLS12-381 64 (16 zero bytes, then 48).
fn coord<F: PrimeField>(b: &[u8], w: usize) -> Option<F> {
    if w == 64 && b[..16].iter().any(|x| *x != 0) {
        return None;
    }
    fe(&b[w - F::MODULUS.to_bytes_be().len()..w])
}
/// `x ‖ y`, on the curve, in the prime-order subgroup, not the identity.
pub(crate) fn g1<P: SWCurveConfig>(b: &[u8], w: usize) -> Option<Affine<P>>
where
    P::BaseField: PrimeField,
{
    if b.len() != 2 * w {
        return None;
    }
    let p = Affine::<P>::new_unchecked(coord(&b[..w], w)?, coord(&b[w..], w)?);
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

/// scaas Schnorr: `R ‖ z`, `e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m))` with hashToScalar(s) =
/// `(keccak(s ‖ 0x02) · 2^256 + keccak(s ‖ 0x03)) mod r`; accept iff `z < r`, `R ≠ O`, `e ≠ 0`, `[z]G == R + [e]Y`.
pub(crate) fn schnorr<P: SWCurveConfig>(key_data: &[u8], message: &[u8; 32], sig: &[u8], w: usize) -> bool
where
    P::BaseField: PrimeField,
{
    schnorr_tagged::<P>(SCHNORR_TAG, key_data, message, sig, w)
}

fn schnorr_tagged<P: SWCurveConfig>(tag: &[u8], key_data: &[u8], message: &[u8; 32], sig: &[u8], w: usize) -> bool
where
    P::BaseField: PrimeField,
{
    if sig.len() != 2 * w + 32 {
        return false;
    }
    let (rb, zb) = sig.split_at(2 * w);
    let (Some(r), Some(y), Some(z)) = (g1::<P>(rb, w), g1::<P>(key_data, w), fe::<P::ScalarField>(zb)) else { return false };
    let seed = keccak(&[tag, rb, key_data, message]);
    let e = P::ScalarField::from_be_bytes_mod_order(&[keccak(&[&seed, &[2]]), keccak(&[&seed, &[3]])].concat());
    !e.is_zero() && Affine::<P>::generator() * z == r.into_group() + y * e
}

// --- BLS min-sig ---

/// Port of ZetherCurves.sol `G1Bn254.mapToG1`: `x = keccak256(prefix ‖ uint32 ctr) mod p`, the first `x` with
/// `x³ + 3` a square, `y = (x³ + 3)^((p+1)/4)` made even.
pub fn map_to_g1_bn254(prefix: &[u8]) -> ark_bn254::G1Affine {
    use ark_bn254::Fq;
    let mut exp = Fq::MODULUS;
    exp.add_with_carry(&1u64.into());
    exp.div2();
    exp.div2();
    for ctr in 0u32.. {
        let x = Fq::from_be_bytes_mod_order(&keccak(&[prefix, &ctr.to_be_bytes()]));
        let rhs = x * x * x + Fq::from(3u64);
        let y = rhs.pow(exp);
        if y.square() == rhs {
            return ark_bn254::G1Affine::new_unchecked(x, if y.into_bigint().is_odd() { -y } else { y });
        }
    }
    unreachable!("half of all x lift")
}

fn bls_bn254_minsig(key_data: &[u8], message: &[u8; 32], sig: &[u8], pop: bool) -> bool {
    use ark_bn254::{Bn254, Fq, Fq2, G2Affine};
    let Some(s) = g1::<ark_bn254::g1::Config>(sig, 32) else { return false };
    if key_data.len() != 128 {
        return false;
    }
    let w: Vec<Option<Fq>> = (0..4).map(|i| fe(&key_data[32 * i..32 * i + 32])).collect();
    let (Some(xi), Some(xr), Some(yi), Some(yr)) = (w[0], w[1], w[2], w[3]) else { return false };
    let pk = G2Affine::new_unchecked(Fq2::new(xr, xi), Fq2::new(yr, yi)); // EIP-197: imaginary part first
    if !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
        return false;
    }
    let h = map_to_g1_bn254(&[if pop { BN254_LABEL_POP } else { BN254_LABEL_SIG }, message].concat());
    Bn254::pairing(s, G2Affine::generator()) == Bn254::pairing(h, pk)
}

/// RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` with the given DST.
pub fn hash_to_g1_bls12381(msg: &[u8], dst: &[u8]) -> ark_bls12_381::G1Affine {
    MapToCurveBasedHasher::<ark_bls12_381::G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<ark_bls12_381::g1::Config>>::new(dst)
        .and_then(|h| h.hash(msg))
        .expect("RFC 9380 hasher")
}

fn bls12381_minsig(key_data: &[u8], message: &[u8; 32], sig: &[u8], pop: bool) -> bool {
    use ark_bls12_381::{Bls12_381, Fq, Fq2, G2Affine};
    let Some(s) = g1::<ark_bls12_381::g1::Config>(sig, 64) else { return false };
    if key_data.len() != 256 {
        return false;
    }
    let w: Vec<Option<Fq>> = (0..4).map(|i| coord(&key_data[64 * i..64 * i + 64], 64)).collect();
    let (Some(x0), Some(x1), Some(y0), Some(y1)) = (w[0], w[1], w[2], w[3]) else { return false };
    let pk = G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)); // EIP-2537: c0 first
    if !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
        return false;
    }
    let h = hash_to_g1_bls12381(message, if pop { BLS12381_DST_POP } else { BLS12381_DST_SIG });
    Bls12_381::pairing(s, G2Affine::generator()) == Bls12_381::pairing(h, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_unpadded() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    /// RFC 9380 Appendix J.9.1 (BLS12381G1_XMD:SHA-256_SSWU_RO_), msg = "": pins the arkworks hasher to the RFC.
    #[test]
    fn rfc9380_g1_ro_empty_message() {
        let p = hash_to_g1_bls12381(b"", b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_");
        let x = p.x().unwrap().into_bigint().to_bytes_be();
        assert_eq!(
            hex(&x),
            "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
