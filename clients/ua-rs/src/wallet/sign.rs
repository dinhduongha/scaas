// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The classic-curve signers (spec §3, §5.1; T3a), on k256 / p256 0.14 (`crypto-bigint` 0.7, RUSTSEC-2026-0387 fixed):
//! `0x0101` ECDSA P-256 over `sha256(ua_msg)`, RFC 6979 (no extra entropy), low-s, `r ‖ s`; `0x0102` ed25519 over `ua_msg`;
//! `0x0103` BIP-340 over `ua_msg`, `aux` 32 bytes from the OS RNG; `0x0108` ECDSA secp256k1 over `ua_msg` with no prehash,
//! RFC 6979, low-s, `r ‖ s ‖ v` (v ∈ {27, 28}). Native keys: secp256k1 `r ‖ s ‖ v` or ed25519 over the key-proof digest or a
//! raw digest behind [`AllowRawDigest`]. A UA key signs only the `ua_msg` it builds itself from a purpose of `PURPOSES` (or
//! `pop` v2) and its own kind (CLI-SGN-29). Every operation reads its secret through `Handle::with`, under the store's read
//! guard with the generation check (spec §8.2). The PQ kinds sign through `pqsign` (T3b); the pairing kinds come with T3c
//! (`KindUnavailable`). UNAUDITED.
use super::signer::{AllowRawDigest, KeyRef, SigRole, SignRequest, Signer};
use super::{derive, pqsign, Error, NativeKey, Result, UaKey};
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

/// The scheme of UA kind `kind`: `KindUnavailable` for the pairing kinds (T3c), `Argument` for a MuSig2 participant (it
/// signs through its session), every kind with no key of its own and the PQ kinds (`pqsign`).
fn ua_scheme(kind: u16) -> Result<Scheme> {
    match kind {
        0x0101 => Ok(Scheme::P256),
        0x0102 => Ok(Scheme::Ed25519),
        0x0103 => Ok(Scheme::Bip340),
        0x0108 => Ok(Scheme::Secp256k1),
        0x0104..=0x0107 => Err(Error::KindUnavailable),
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
fn os_aux() -> Result<[u8; 32]> {
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

impl UaKey {
    /// The request of `sign_ua`: `purpose` a tag of `PURPOSES` (v1) or `pop` v2, else `UAPurposeUnknown`.
    fn ua_request(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<SignRequest> {
        let known = *purpose == pop_v2_tag() || PURPOSES.iter().any(|p| purpose_tag(p).is_ok_and(|t| t == *purpose));
        if !known {
            return Err(Error::Ua(UAError::PurposeUnknown));
        }
        Ok(SignRequest::UaMsg { kind: self.kind, ua_msg: ua_message(self.kind, purpose, digest)?, role: role_of(purpose) })
    }

    fn member_request(&self, structure_ua: &[u8; 32], structure_ua_msg: &[u8; 32]) -> Result<SignRequest> {
        let digest = member_digest(structure_ua, structure_ua_msg);
        let ua_msg = ua_message(self.kind, &purpose_tag("member")?, &digest)?;
        Ok(SignRequest::UaMsg { kind: self.kind, ua_msg, role: SigRole::Authorization })
    }

    /// The signature of `req` (a `UaMsg` of this key's kind); the randomness fixed only by the `vectors` entry points (BIP-340
    /// `aux`, the PQ kinds' `rnd` / `opt_rand` / Falcon's 88 bytes), else from the OS RNG.
    fn sign_ua_msg(&self, req: &SignRequest, fixed: Option<&[u8]>) -> Result<Vec<u8>> {
        let SignRequest::UaMsg { kind, ua_msg, .. } = req else { return Err(Error::Argument) };
        if *kind != self.kind {
            return Err(Error::Argument);
        }
        if pqsign::is_pq(self.kind) {
            return self.secret.with(|s| pqsign::sign(self.kind, s, ua_msg, fixed))?;
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
        let digest = keccak256(&[KEY_PROOF_PREFIX, challenge].concat());
        self.sign_request(&SignRequest::KeyProof { digest })
    }

    /// A raw 32-byte digest, only with the marker value (CLI-SGN-40).
    pub fn sign_digest(&self, digest: &[u8; 32], _: AllowRawDigest) -> Result<Vec<u8>> {
        self.sign_request(&SignRequest::RawDigest { digest: *digest })
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
    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {
        let (SignRequest::KeyProof { digest } | SignRequest::RawDigest { digest }) = req else { return Err(Error::Argument) };
        let scheme = if self.network.ed25519() { Scheme::Ed25519 } else { Scheme::Secp256k1 };
        self.secret.with(|s| sign_scheme(scheme, s, digest, None))?
    }
}

/// Test-only entry points (feature `vectors`, never in a release build): fixed `aux`, the requests, a raw secret.
#[cfg(feature = "vectors")]
mod vectors {
    use super::*;

    impl UaKey {
        /// `sign_ua` with fixed randomness: BIP-340 `aux` (32 B), ML-DSA `rnd` (32 B, zero = deterministic), SLH-DSA
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
