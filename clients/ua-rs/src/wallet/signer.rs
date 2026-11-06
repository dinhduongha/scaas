// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The one signing interface (spec §9.4, MD-13): every handle implements [`Signer`], and every signing path builds a
//! [`SignRequest`] inside `ua-rs` (no public constructor: each variant is `#[non_exhaustive]`) and hands it to
//! [`Signer::sign_request`]. Phase 2's external keys (enclave, keystore, Ledger, passkey) add an implementation, not a
//! signature. The [`SigRole`] of a UA message is set by the builder from the registry's rule (`UARegistryLib._sigOk`): the
//! portable purposes `pop` v2, `kem` and `pqz-key` → [`SigRole::Pop`], every other purpose and an `msig` member slot →
//! [`SigRole::Authorization`]; no public call takes a role. T3a builds `UaMsg`, `KeyProof`, `RawDigest`; T4 `Eip712` (the
//! policy's `sign_typed`, a native key's `UASig` and `msig` slot); T5 `Transaction` (`sign_transaction`); T6 `WebAuthn` (a
//! `0x0100` key's request from `sign_ua`'s and the `msig` builder's paths: the passkey of phase 2). UNAUDITED.
//!
//! A request is read, never built, outside `ua-rs`:
//! ```
//! use scaas_ua::wallet::{SigRole, SignRequest};
//! fn role_of(r: &SignRequest) -> Option<SigRole> {
//!     match r {
//!         SignRequest::UaMsg { role, .. } => Some(*role),
//!         _ => None,
//!     }
//! }
//! ```
//! ```compile_fail,E0639
//! use scaas_ua::wallet::{SigRole, SignRequest};
//! let _ = SignRequest::UaMsg { kind: 0x0106, ua_msg: [0; 32], role: SigRole::Pop };
//! ```
//! `sign_ua` and `sign_member` take no role (positive control first):
//! ```no_run
//! fn f(key: &scaas_ua::wallet::UaKey) {
//!     let _ = key.sign_ua(&[0; 32], &[0; 32]);
//! }
//! ```
//! ```compile_fail,E0061
//! fn f(key: &scaas_ua::wallet::UaKey) {
//!     let _ = key.sign_ua(&[0; 32], &[0; 32], scaas_ua::wallet::SigRole::Pop);
//! }
//! ```
//! A raw digest needs the marker value (CLI-SGN-40):
//! ```no_run
//! fn f(key: &scaas_ua::wallet::NativeKey) {
//!     let _ = key.sign_digest(&[0; 32], scaas_ua::wallet::AllowRawDigest);
//! }
//! ```
//! ```compile_fail,E0061
//! fn f(key: &scaas_ua::wallet::NativeKey) {
//!     let _ = key.sign_digest(&[0; 32]);
//! }
//! ```
use super::eip712::TypedData;
use super::tx::EvmTx;
use super::{Error, Network, Result};
use crate::verify::verify;

/// Which verifier entry a signature is for: `verify` ([`SigRole::Authorization`]) or `verifyPop` ([`SigRole::Pop`]); the
/// BLS kinds sign under that role's domain (T3c).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigRole {
    Authorization,
    Pop,
}

/// The key behind a [`Signer`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRef {
    Ua { kind: u16, key_data: Vec<u8> },
    /// `address` as the network prints it (`None`: `ton`, `hedera_ed25519`); `public_key` compressed secp256k1 or ed25519.
    Native { network: Network, coin_type: Option<u32>, address: Option<String>, public_key: Vec<u8> },
}

/// A request for one signature, built only inside `ua-rs` after its checks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignRequest {
    /// `ua_msg = uaMessage(kind, purpose, digest)` after the purpose and kind checks; `role` from the purpose.
    #[non_exhaustive]
    UaMsg { kind: u16, ua_msg: [u8; 32], role: SigRole },
    /// `keccak256(0x1901 ‖ domain_separator ‖ struct_hash)`, the hashes of `typed_data`, the value shown to a clear-signing device:
    /// on the checked path after the policy (a non-zero unbound `relayer` / `feeRecipient` refused, never zeroed), through `Any`
    /// as supplied, a SCaaS builder's value as built; a native key's `UAAuth` or portable record (CTR-UA-07, CTR-UA-24).
    #[non_exhaustive]
    Eip712 { domain_separator: [u8; 32], struct_hash: [u8; 32], typed_data: Box<TypedData> },
    /// An EVM transaction of type 0-3 (spec §5.5; never type 4): `sighash` of `tx`, the transaction readable for a
    /// clear-signing device; a secp256k1 native key signs it.
    #[non_exhaustive]
    Transaction { tx_type: u8, sighash: [u8; 32], tx: Box<EvmTx> },
    /// `keccak256("scaas-subject-key-proof-v1" ‖ challenge)`.
    #[non_exhaustive]
    KeyProof { digest: [u8; 32] },
    /// Only behind [`AllowRawDigest`].
    #[non_exhaustive]
    RawDigest { digest: [u8; 32] },
    /// A `webauthn-p256` (`0x0100`) key's `ua_msg` in place of a `UaMsg` (the authenticator's challenge, spec §5.6, §9.4): the
    /// response is the assertion encoding of [`super::webauthn_assertion`] against this challenge.
    #[non_exhaustive]
    WebAuthn { challenge: [u8; 32] },
}

/// The explicit opt-in of a raw-digest signature (CLI-SGN-40): for Merkle roots and family envelopes the caller built from a
/// checked message, never a transaction or an EIP-7702 authorization.
#[derive(Clone, Copy, Debug)]
pub struct AllowRawDigest;

/// A key that signs [`SignRequest`]s: the wallet's handles now, external keys in phase 2.
pub trait Signer: Send + Sync {
    fn key_ref(&self) -> KeyRef;
    /// The kind's signature bytes as the chain takes them; `Argument` for a request this key does not sign.
    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>>;
}

/// An external key's answer to `req` (phase 2, spec §9.4, MD-13): normalised (P-256 and secp256k1 low-s; `v` 0 / 1 → 27 / 28,
/// flipped with `s`), then verified against `key` with this crate's verifier under the request's role; `ExternalSignature` when
/// it does not verify, `Argument` for a request `key` does not sign. Every external key returns only what passes here.
#[cfg_attr(not(feature = "vectors"), allow(dead_code))]
pub(crate) fn external_answer(key: &KeyRef, req: &SignRequest, sig: Vec<u8>) -> Result<Vec<u8>> {
    let (ok, sig) = match (key, req) {
        (KeyRef::Ua { kind, key_data }, SignRequest::UaMsg { kind: k, ua_msg, role }) if k == kind => {
            let sig = low_s(*kind, sig);
            (verify(*kind, key_data, ua_msg, &sig, *role == SigRole::Pop), sig)
        }
        (KeyRef::Ua { kind: 0x0100, key_data }, SignRequest::WebAuthn { challenge }) => (verify(0x0100, key_data, challenge, &sig, false), sig),
        (KeyRef::Native { network, public_key, .. }, req) if network.ed25519() => {
            (verify(0x0102, public_key, &super::sign::native_digest(req, false)?, &sig, false), sig)
        }
        (KeyRef::Native { public_key, .. }, req) => {
            let digest = super::sign::native_digest(req, true)?;
            let pk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| Error::Argument)?;
            let (pt, sig) = (pk.to_sec1_point(false), low_s(0x0108, sig));
            (verify(0x0108, pt.as_bytes().get(1..).ok_or(Error::Argument)?, &digest, &sig, false), sig)
        }
        _ => return Err(Error::Argument),
    };
    if ok {
        Ok(sig)
    } else {
        Err(Error::ExternalSignature)
    }
}

/// Low-s for the ECDSA forms: P-256 `r ‖ s` (`0x0101`), secp256k1 `r ‖ s ‖ v` (`0x0108`, native keys; `v` 0 / 1 read as
/// 27 / 28 and flipped with `s`). Any other kind or length unchanged (the verifier refuses what is malformed).
fn low_s(kind: u16, mut sig: Vec<u8>) -> Vec<u8> {
    match (kind, sig.len()) {
        (0x0101, 64) => {
            if let Ok(s) = p256::ecdsa::Signature::from_slice(&sig) {
                sig = s.normalize_s().to_bytes().to_vec();
            }
        }
        (0x0108, 65) => {
            if let Some((v, rs)) = sig.split_last_mut() {
                if *v < 2 {
                    *v += 27;
                }
                if let Ok(s) = k256::ecdsa::Signature::from_slice(rs) {
                    let n = s.normalize_s();
                    if n != s && matches!(*v, 27 | 28) {
                        rs.copy_from_slice(&n.to_bytes());
                        *v = 55 - *v;
                    }
                }
            }
        }
        _ => {}
    }
    sig
}

/// A test external key (feature `vectors`, MD-13; phase 2 adds the device constructors): `device` answers each request, read
/// only; [`external_answer`] checks the answer before it leaves.
#[cfg(feature = "vectors")]
pub struct TestExternalKey<'a> {
    key_ref: KeyRef,
    device: Device<'a>,
}
#[cfg(feature = "vectors")]
type Device<'a> = Box<dyn Fn(&SignRequest) -> Result<Vec<u8>> + Send + Sync + 'a>;

#[cfg(feature = "vectors")]
impl<'a> TestExternalKey<'a> {
    pub fn new(key_ref: KeyRef, device: impl Fn(&SignRequest) -> Result<Vec<u8>> + Send + Sync + 'a) -> Self {
        TestExternalKey { key_ref, device: Box::new(device) }
    }
}

#[cfg(feature = "vectors")]
impl Signer for TestExternalKey<'_> {
    fn key_ref(&self) -> KeyRef {
        self.key_ref.clone()
    }
    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {
        external_answer(&self.key_ref, req, (self.device)(req)?)
    }
}
