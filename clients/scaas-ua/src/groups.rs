//! The registry's checks for the group kinds 0x0110–0x0113 (accounts.md §1.6.1, §1.9), written from the spec as the EVM
//! verifiers apply them, independent of the signers (`musig2.rs`, frost-core): `verify(vk, msg, sig)` against the stored
//! group key, `verifyPop(keyData, msg, pop)` = the whole group check + the group signature. MuSig2-secp256k1 hints are
//! checked the way the `ecrecover` trick does (`x(P_i) < N`, recovered point `(a_i·x · x⁻¹)·lift(x, parity)` compared by
//! address). Untrusted input: anything malformed is `false`, never a panic. UNAUDITED.
use crate::verify::{bip340, schnorr, sha256};
use crate::{keccak, validate_key_data};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use k256::elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::PrimeField as _;
use k256::{AffinePoint, ProjectivePoint, Scalar};

pub const FROST_SECP256K1_CONTEXT: &[u8] = b"FROST-secp256k1-SHA256-v1";
pub const FROST_BN254_CONTEXT: &[u8] = b"FROST-BN254-KECCAK256-SCAAS-v1";

type Bn = ark_bn254::g1::Config;

/// `verify` (`pop = false`: `key` = the stored `vk`) / `verifyPop` (`pop = true`: `key` = the key data).
pub(crate) fn verify(kind: u16, key: &[u8], msg: &[u8; 32], sig: &[u8], pop: bool) -> bool {
    if pop {
        return validate_key_data(kind, key, false).is_ok()
            && match kind {
                0x0110 => musig2_secp256k1_pop(key, msg, sig),
                0x0111 => dkg_check(key, 33, secp_point, compressed, secp_pok) && frost_secp256k1(&key[..33], msg, sig),
                0x0112 => musig2_bn254_pop(key, msg, sig),
                _ => dkg_check(key, 64, bn_point, bn_bytes, bn_pok) && schnorr::<Bn>(&key[..64], msg, sig, 32),
            };
    }
    match kind {
        0x0110 => key.len() == 33 && (key[0] == 2 || key[0] == 3) && bip340(&key[1..], msg, sig),
        0x0111 => frost_secp256k1(key, msg, sig),
        _ => schnorr::<Bn>(key, msg, sig, 32),
    }
}

/// The FROST registration check without the signature: every PoK and `Y == Σ C_i0` (key data validated first).
pub fn dkg_transcript_ok(kind: u16, kd: &[u8]) -> bool {
    validate_key_data(kind, kd, false).is_ok()
        && match kind {
            0x0111 => dkg_check(kd, 33, secp_point, compressed, secp_pok),
            0x0113 => dkg_check(kd, 64, bn_point, bn_bytes, bn_pok),
            _ => false,
        }
}

fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let t = sha256(&[tag.as_bytes()]);
    sha256(&[&[&t[..], &t[..]], parts].concat())
}

fn u16_at(d: &[u8], o: usize) -> usize {
    ((d[o] as usize) << 8) | d[o + 1] as usize
}

// --- secp256k1 ---

fn secp_point(b: &[u8]) -> Option<ProjectivePoint> {
    if b.len() != 33 || !(b[0] == 2 || b[0] == 3) {
        return None;
    }
    let ep = k256::EncodedPoint::from_bytes(b).ok()?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)).map(Into::into)
}
fn secp_scalar(b: &[u8]) -> Option<Scalar> {
    Scalar::from_repr(<[u8; 32]>::try_from(b).ok()?.into()).into()
}
/// SEC1 compressed; the identity as 33 zero bytes (never equal to valid key data).
fn compressed(p: &ProjectivePoint) -> Vec<u8> {
    if *p == ProjectivePoint::IDENTITY {
        return vec![0; 33];
    }
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}
fn address(xy: &[u8]) -> [u8; 20] {
    keccak(&[xy])[12..].try_into().expect("20")
}

/// RFC 9591 `hash_to_field` (`expand_message_xmd` SHA-256, 48 bytes, mod N) with DST `contextString ‖ label`.
fn secp_h(label: &[u8], m: &[u8]) -> Scalar {
    let mut u = [Scalar::ZERO];
    hash_to_field::<ExpandMsgXmd<sha2::Sha256>, Scalar>(&[m], &[FROST_SECP256K1_CONTEXT, label], &mut u).expect("xmd");
    u[0]
}

/// RFC 9591 FROST(secp256k1, SHA-256) verify: `Y` and `R` SEC1 compressed, `z < N`, `z·G == R + H2(R ‖ Y ‖ msg)·Y`.
pub fn frost_secp256k1(y: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 65 {
        return false;
    }
    let (Some(yp), Some(r), Some(z)) = (secp_point(y), secp_point(&sig[..33]), secp_scalar(&sig[33..])) else { return false };
    let c = secp_h(b"chal", &[&sig[..33], y, msg].concat());
    ProjectivePoint::GENERATOR * z == r + yp * c
}

/// `pop = sig (64) ‖ n × H_i (64, x ‖ y)`: KeyAgg recomputed, each `H_i = a_i·P_i` checked as `ecrecover` would,
/// `Σ H_i == Q` (x and parity), then BIP-340 by `x(Q)`.
fn musig2_secp256k1_pop(kd: &[u8], msg: &[u8; 32], pop: &[u8]) -> bool {
    let n = u16_at(kd, 33);
    if pop.len() != 64 + 64 * n {
        return false;
    }
    let pks: Vec<&[u8]> = kd[35..].chunks(33).collect();
    let l = tagged("KeyAgg list", &pks);
    let second = pks.iter().find(|p| **p != pks[0]);
    let mut sum = ProjectivePoint::IDENTITY;
    for (i, pk) in pks.iter().enumerate() {
        let a = if Some(pk) == second {
            Scalar::ONE
        } else {
            <Scalar as Reduce<k256::U256>>::reduce_bytes(&tagged("KeyAgg coefficient", &[&l, pk]).into())
        };
        // ecrecover(0, v, r = x(P_i), s = a·r mod N) = r⁻¹·s·R: needs r < N; R = lift(r, v) = P_i
        let (Some(r), Some(p)) = (secp_scalar(&pk[1..]), secp_point(pk)) else { return false };
        let Some(r_inv) = Option::<Scalar>::from(r.invert()) else { return false }; // ecrecover refuses r = 0
        let rec = p * (a * r * r_inv);
        let h = &pop[64 + 64 * i..128 + 64 * i];
        if address(&rec.to_affine().to_encoded_point(false).as_bytes()[1..]) != address(h) {
            return false;
        }
        sum += rec; // = H_i (address match); the EVM adds H_i in affine coordinates
    }
    compressed(&sum) == kd[..33] && bip340(&kd[1..33], msg, &pop[..64])
}

fn secp_pok(id: u16, c0: &[u8], r: &[u8], mu: &[u8]) -> bool {
    let (Some(c0p), Some(rp), Some(mu)) = (secp_point(c0), secp_point(r), secp_scalar(mu)) else { return false };
    let c = secp_h(b"dkg", &[&Scalar::from(id as u64).to_bytes()[..], c0, r].concat());
    rp == ProjectivePoint::GENERATOR * mu - c0p * c
}

// --- bn254 ---

fn bn_point(b: &[u8]) -> Option<ark_bn254::G1Projective> {
    crate::verify::g1::<Bn>(b, 32).map(Into::into)
}
fn bn_bytes(p: &ark_bn254::G1Projective) -> Vec<u8> {
    use ark_ff::BigInteger;
    let a = p.into_affine();
    match a.xy() {
        Some((x, y)) => [x.into_bigint().to_bytes_be(), y.into_bigint().to_bytes_be()].concat(),
        None => vec![0; 64],
    }
}
fn fr(b: &[u8]) -> Option<ark_bn254::Fr> {
    use ark_ff::BigInteger;
    let f = ark_bn254::Fr::from_be_bytes_mod_order(b);
    (b.len() == 32 && f.into_bigint().to_bytes_be() == b).then_some(f)
}
fn fr_wide(h: impl Fn(u8) -> [u8; 32]) -> ark_bn254::Fr {
    ark_bn254::Fr::from_be_bytes_mod_order(&[h(0), h(1)].concat())
}

/// KeyAgg of the bn254 port (no hints: `ECMUL`/`ECADD`), `Q` equal, then scaas Schnorr by `Q`.
fn musig2_bn254_pop(kd: &[u8], msg: &[u8; 32], pop: &[u8]) -> bool {
    let pks: Vec<&[u8]> = kd[66..].chunks(64).collect();
    let l = tagged("KeyAgg list", &pks);
    let second = pks.iter().find(|p| **p != pks[0]);
    let mut q = ark_bn254::G1Projective::default();
    for pk in &pks {
        let a = if Some(pk) == second {
            ark_bn254::Fr::from(1u64)
        } else {
            fr_wide(|b| tagged("KeyAgg coefficient", &[&l, pk, &[b]]))
        };
        let Some(p) = bn_point(pk) else { return false };
        q += p * a;
    }
    bn_bytes(&q) == kd[..64] && schnorr::<Bn>(&kd[..64], msg, pop, 32)
}

fn bn_pok(id: u16, c0: &[u8], r: &[u8], mu: &[u8]) -> bool {
    let (Some(c0p), Some(rp), Some(mu)) = (bn_point(c0), bn_point(r), fr(mu)) else { return false };
    let mut idb = [0u8; 32];
    idb[30..].copy_from_slice(&id.to_be_bytes());
    let c = fr_wide(|b| keccak(&[FROST_BN254_CONTEXT, b"dkg", &idb, c0, r, &[b]]));
    rp == ark_bn254::G1Affine::generator() * mu - c0p * c
}

// --- FROST DKG transcript ---

/// Every PoK `R_i == μ_i·G − c_i·C_i0`, `c_i = H_dkg(id_i ‖ C_i0 ‖ R_i)`, and `Y == Σ C_i0` (compared as encodings).
fn dkg_check<P: core::ops::Add<Output = P> + Copy>(
    kd: &[u8],
    w: usize,
    point: fn(&[u8]) -> Option<P>,
    enc: fn(&P) -> Vec<u8>,
    pok: fn(u16, &[u8], &[u8], &[u8]) -> bool,
) -> bool {
    let (t, n) = (u16_at(kd, w), u16_at(kd, w + 2));
    let per = (t + 1) * w + 32;
    let mut sum: Option<P> = None;
    for i in 0..n {
        let b = &kd[w + 4 + i * per..w + 4 + (i + 1) * per];
        if !pok(i as u16 + 1, &b[..w], &b[t * w..(t + 1) * w], &b[(t + 1) * w..]) {
            return false;
        }
        let Some(c0) = point(&b[..w]) else { return false };
        sum = Some(sum.map_or(c0, |s| s + c0));
    }
    sum.is_some_and(|s| enc(&s) == kd[..w])
}
