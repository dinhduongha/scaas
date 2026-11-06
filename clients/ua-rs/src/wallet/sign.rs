// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The classic-curve signers (spec §3, §5.1; T3a), on k256 / p256 0.14 (`crypto-bigint` 0.7, RUSTSEC-2026-0387 fixed):
//! `0x0101` ECDSA P-256 over `sha256(ua_msg)`, RFC 6979 (no extra entropy), low-s, `r ‖ s`; `0x0102` ed25519 over `ua_msg`;
//! `0x0103` BIP-340 over `ua_msg`, `aux` 32 bytes from the OS RNG; `0x0108` ECDSA secp256k1 over `ua_msg` with no prehash,
//! RFC 6979, low-s, `r ‖ s ‖ v` (v ∈ {27, 28}). Native keys: secp256k1 `r ‖ s ‖ v` or ed25519 over the key-proof digest or a
//! raw digest behind [`AllowRawDigest`]. A UA key signs only the `ua_msg` it builds itself from a purpose of `PURPOSES` (or
//! `pop` v2) and its own kind (CLI-SGN-29). Every operation reads its secret through `Handle::with`, under the store's read
//! guard with the generation check (spec §8.2). The PQ kinds sign through `pqsign` (T3b), the pairing kinds through
//! `pairing` (T3c). UNAUDITED.
use super::signer::{AllowRawDigest, KeyRef, SigRole, SignRequest, Signer};
use super::{derive, pairing, pqsign, Error, NativeKey, Result, UaKey};
use crate::{keccak256, member_digest, purpose_tag, ua_message, ua8::pop_v2_tag, UAError, PURPOSES};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const KEY_PROOF_PREFIX: &[u8] = b"scaas-subject-key-proof-v1";

/// A signature scheme of T3a.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// secp256k1 ECDSA over a 32-byte digest, `r ‖ s ‖ v`.
    Secp256k1,
    /// P-256 ECDSA over `sha256(message)`, `r ‖ s`.
    P256,
    Ed25519,
    Bip340,
}

/// The scheme of UA kind `kind`: `Argument` for a MuSig2 participant (it signs through its session), every kind with no key
/// of its own, the PQ kinds (`pqsign`) and the pairing kinds (`pairing`).
fn ua_scheme(kind: u16) -> Result<Scheme> {
    match kind {
        0x0101 => Ok(Scheme::P256),
        0x0102 => Ok(Scheme::Ed25519),
        0x0103 => Ok(Scheme::Bip340),
        0x0108 => Ok(Scheme::Secp256k1),
        _ => Err(Error::Argument),
    }
}

fn arr32(s: &[u8]) -> Result<&[u8; 32]> {
    s.try_into().map_err(|_| Error::Argument)
}

/// The scheme's signature of `msg` with the 32-byte `secret`; `aux` for BIP-340 only (required there).
fn sign_scheme(scheme: Scheme, secret: &[u8], msg: &[u8], aux: Option<&[u8; 32]>) -> Result<Vec<u8>> {
    match scheme {
        Scheme::Secp256k1 => {
            let sk = k256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::Argument)?;
            // RFC 6979 with no additional data; k256 normalises to low-s and flips the recovery id with it
            let (sig, rec) = sk.sign_prehash_recoverable(arr32(msg)?);
            let mut out = sig.to_bytes().to_vec();
            out.push(27 + rec.to_byte());
            Ok(out)
        }
        Scheme::P256 => {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sk = p256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::Argument)?;
            let sig: p256::ecdsa::Signature = sk.sign_prehash(&Sha256::digest(msg)).map_err(|_| Error::Argument)?;
            // p256 does not normalise (NORMALIZE_S = false); the chains refuse high s
            Ok(sig.normalize_s().to_bytes().to_vec())
        }
        Scheme::Ed25519 => {
            use ed25519_dalek::Signer as _;
            Ok(ed25519_dalek::SigningKey::from_bytes(arr32(secret)?).sign(msg).to_bytes().to_vec())
        }
        Scheme::Bip340 => {
            let sk = k256::schnorr::SigningKey::from_slice(secret).map_err(|_| Error::Argument)?;
            let sig = sk.sign_raw(msg, aux.ok_or(Error::Argument)?).map_err(|_| Error::Argument)?;
            Ok(sig.to_bytes().to_vec())
        }
    }
}

/// 32 bytes of the OS RNG (`rand_core` 0.6 `OsRng`).
pub(super) fn os_aux() -> Result<[u8; 32]> {
    let mut aux = [0u8; 32];
    OsRng.try_fill_bytes(&mut aux).map_err(|_| Error::Rng)?;
    Ok(aux)
}

/// The registry's role of a purpose: `verifyPop` for the portable purposes.
fn role_of(purpose: &[u8; 32]) -> SigRole {
    let pop = *purpose == pop_v2_tag() || ["kem", "pqz-key"].iter().any(|p| purpose_tag(p).is_ok_and(|t| t == *purpose));
    if pop {
        SigRole::Pop
    } else {
        SigRole::Authorization
    }
}

/// `purpose` a tag of `PURPOSES` (v1) or `pop` v2, else `UAPurposeUnknown`.
pub(super) fn check_purpose(purpose: &[u8; 32]) -> Result<()> {
    let known = *purpose == pop_v2_tag() || PURPOSES.iter().any(|p| purpose_tag(p).is_ok_and(|t| t == *purpose));
    if !known {
        return Err(Error::Ua(UAError::PurposeUnknown));
    }
    Ok(())
}

/// The request of `sign_ua` for a key of `kind` (the `UASig` builder's too); `0x0100` (an authenticator) is asked
/// `WebAuthn` with the same `ua_msg`.
pub(super) fn ua_request(kind: u16, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<SignRequest> {
    check_purpose(purpose)?;
    Ok(request(kind, ua_message(kind, purpose, digest)?, role_of(purpose)))
}

fn request(kind: u16, ua_msg: [u8; 32], role: SigRole) -> SignRequest {
    if kind == 0x0100 {
        SignRequest::WebAuthn { challenge: ua_msg }
    } else {
        SignRequest::UaMsg { kind, ua_msg, role }
    }
}

/// The request of a sealed container's sender of `kind` (spec §6.3, MD-10): `uaMessage(kind, seal, digest)` under the off-chain
/// purpose, role `Authorization`; only the container builder (`seal`) asks it: `check_purpose` refuses that purpose everywhere else.
pub(super) fn seal_request(kind: u16, digest: &[u8; 32]) -> Result<SignRequest> {
    Ok(request(kind, ua_message(kind, &crate::seal_purpose_tag(), digest)?, SigRole::Authorization))
}

/// The request of `sign_member` for a key of `kind` (the `msig` builder's too): always `Authorization`.
pub(super) fn member_request(kind: u16, structure_ua: &[u8; 32], structure_ua_msg: &[u8; 32]) -> Result<SignRequest> {
    let digest = member_digest(structure_ua, structure_ua_msg);
    Ok(request(kind, ua_message(kind, &purpose_tag("member")?, &digest)?, SigRole::Authorization))
}

impl UaKey {
    fn ua_request(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<SignRequest> {
        ua_request(self.kind, purpose, digest)
    }

    fn member_request(&self, structure_ua: &[u8; 32], structure_ua_msg: &[u8; 32]) -> Result<SignRequest> {
        member_request(self.kind, structure_ua, structure_ua_msg)
    }

    /// The signature of `req` (a `UaMsg` of this key's kind); the randomness fixed only by the `vectors` entry points (BIP-340
    /// and scaas Schnorr `aux`, the PQ kinds' `rnd` / `opt_rand` / Falcon's 88 bytes), else from the OS RNG. The BLS kinds
    /// sign under the domain of the request's role.
    fn sign_ua_msg(&self, req: &SignRequest, fixed: Option<&[u8]>) -> Result<Vec<u8>> {
        let SignRequest::UaMsg { kind, ua_msg, role } = req else { return Err(Error::Argument) };
        if *kind != self.kind {
            return Err(Error::Argument);
        }
        if pqsign::is_pq(self.kind) {
            return self.secret.with(|s| pqsign::sign(self.kind, s, ua_msg, fixed))?;
        }
        if pairing::is_pairing(self.kind) {
            return self.secret.with(|s| pairing::sign(self.kind, s, &self.key_data, ua_msg, *role, fixed))?;
        }
        let scheme = ua_scheme(self.kind)?;
        let aux = match (scheme, fixed) {
            (Scheme::Bip340, None) => Some(os_aux()?),
            (_, f) => f.map(arr32).transpose()?.copied(),
        };
        self.secret.with(|s| sign_scheme(scheme, s, ua_msg, aux.as_ref()))?
    }

    /// The signature of `ua_msg = uaMessage(kind, purpose, digest)`; `purpose` a tag of `PURPOSES` or `pop` v2.
    pub fn sign_ua(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<Vec<u8>> {
        self.sign_ua_msg(&self.ua_request(purpose, digest)?, None)
    }

    /// As an `msig` member: the signature of `uaMessage(kind, member, memberDigest(structure_ua, structure_ua_msg))`.
    pub fn sign_member(&self, structure_ua: &[u8; 32], structure_ua_msg: &[u8; 32]) -> Result<Vec<u8>> {
        self.sign_ua_msg(&self.member_request(structure_ua, structure_ua_msg)?, None)
    }
}

impl Signer for UaKey {
    fn key_ref(&self) -> KeyRef {
        KeyRef::Ua { kind: self.kind, key_data: self.key_data.clone() }
    }
    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {
        self.sign_ua_msg(req, None)
    }
}

impl NativeKey {
    /// The address as the network prints it (clientkeys `describe`); `None` for `ton` and `hedera_ed25519`.
    pub fn address(&self) -> Option<String> {
        derive::native_address(self.network, &self.public_key)
    }

    /// The key proof: the signature of `keccak256("scaas-subject-key-proof-v1" ‖ challenge)`.
    pub fn sign_key_proof(&self, challenge: &[u8]) -> Result<Vec<u8>> {
        sign_key_proof_by(self, challenge)
    }

    /// A raw 32-byte digest, only with the marker value (CLI-SGN-40).
    pub fn sign_digest(&self, digest: &[u8; 32], allow: AllowRawDigest) -> Result<Vec<u8>> {
        sign_digest_by(self, digest, allow)
    }
}

/// [`NativeKey::sign_key_proof`] by any [`Signer`] (spec §9.4).
pub fn sign_key_proof_by(key: &dyn Signer, challenge: &[u8]) -> Result<Vec<u8>> {
    key.sign_request(&SignRequest::KeyProof { digest: keccak256(&[KEY_PROOF_PREFIX, challenge].concat()) })
}

/// [`NativeKey::sign_digest`] by any [`Signer`] (spec §9.4), only with the marker value (CLI-SGN-40).
pub fn sign_digest_by(key: &dyn Signer, digest: &[u8; 32], _: AllowRawDigest) -> Result<Vec<u8>> {
    key.sign_request(&SignRequest::RawDigest { digest: *digest })
}

/// The 32 bytes a native key signs for `req`: a key proof's or raw digest; on a secp256k1 key also an EIP-712 digest or a
/// transaction's sighash. `Argument` for any other request.
pub(super) fn native_digest(req: &SignRequest, secp256k1: bool) -> Result<[u8; 32]> {
    match req {
        SignRequest::KeyProof { digest } | SignRequest::RawDigest { digest } => Ok(*digest),
        SignRequest::Eip712 { domain_separator, struct_hash, .. } if secp256k1 => {
            Ok(super::eip712::eip712_digest(domain_separator, struct_hash))
        }
        SignRequest::Transaction { sighash, .. } if secp256k1 => Ok(*sighash),
        _ => Err(Error::Argument),
    }
}

impl Signer for NativeKey {
    fn key_ref(&self) -> KeyRef {
        KeyRef::Native {
            network: self.network,
            coin_type: self.coin_type,
            address: self.address(),
            public_key: self.public_key.clone(),
        }
    }
    /// A key proof, a raw digest, or (secp256k1 networks only) an EIP-712 digest or a transaction's sighash, `r ‖ s ‖ v`.
    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {
        let scheme = if self.network.ed25519() { Scheme::Ed25519 } else { Scheme::Secp256k1 };
        let digest = native_digest(req, scheme == Scheme::Secp256k1)?;
        self.secret.with(|s| sign_scheme(scheme, s, &digest, None))?
    }
}

/// Test-only entry points (feature `vectors`, never in a release build): fixed `aux`, the requests, a raw secret.
#[cfg(feature = "vectors")]
mod vectors {
    use super::*;

    impl UaKey {
        /// `sign_ua` with fixed randomness: BIP-340 and scaas Schnorr `aux` (32 B), ML-DSA `rnd` (32 B, zero = deterministic), SLH-DSA
        /// `opt_rand` (16 B, `PK.seed` = deterministic), Falcon nonce ‖ sampler seed (88 B).
        pub fn vectors_sign_ua_fixed(&self, purpose: &[u8; 32], digest: &[u8; 32], fixed: &[u8]) -> Result<Vec<u8>> {
            self.sign_ua_msg(&self.ua_request(purpose, digest)?, Some(fixed))
        }
        /// A raw `ua_msg` of this key's kind with fixed randomness (pq_kat.json signs a `pop` v1 message `sign_ua` refuses).
        pub fn vectors_sign_ua_msg(&self, ua_msg: &[u8; 32], fixed: &[u8]) -> Result<Vec<u8>> {
            let req = SignRequest::UaMsg { kind: self.kind, ua_msg: *ua_msg, role: SigRole::Authorization };
            self.sign_ua_msg(&req, Some(fixed))
        }
        /// The request `sign_ua` signs.
        pub fn vectors_request(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<SignRequest> {
            self.ua_request(purpose, digest)
        }
        /// The request `sign_member` signs.
        pub fn vectors_member_request(&self, structure_ua: &[u8; 32], structure_ua_msg: &[u8; 32]) -> Result<SignRequest> {
            self.member_request(structure_ua, structure_ua_msg)
        }
    }
}

/// The scheme primitive of `kind` over `msg` with a raw `secret` (feature `vectors`: the external answers): `0x0101` signs
/// `sha256(msg)`; `0x0108` and the native EVM kind `0x0001` sign the 32-byte `msg` as it is; `0x0102` ed25519; `0x0103`
/// BIP-340 with `aux` (required).
#[cfg(feature = "vectors")]
pub fn sign_raw(kind: u16, secret: &[u8], msg: &[u8], aux: Option<&[u8; 32]>) -> Result<Vec<u8>> {
    let scheme = if kind == 0x0001 { Scheme::Secp256k1 } else { ua_scheme(kind)? };
    sign_scheme(scheme, secret, msg, aux)
}
