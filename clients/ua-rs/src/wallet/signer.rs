// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The one signing interface (spec §9.4, MD-13): every handle implements [`Signer`], and every signing path builds a
//! [`SignRequest`] inside `ua-rs` (no public constructor: each variant is `#[non_exhaustive]`) and hands it to
//! [`Signer::sign_request`]. Phase 2's external keys (enclave, keystore, Ledger, passkey) add an implementation, not a
//! signature. The [`SigRole`] of a UA message is set by the builder from the registry's rule (`UARegistryLib._sigOk`): the
//! portable purposes `pop` v2, `kem` and `pqz-key` → [`SigRole::Pop`], every other purpose and an `msig` member slot →
//! [`SigRole::Authorization`]; no public call takes a role. T3a builds `UaMsg`, `KeyProof`, `RawDigest`; `Eip712`,
//! `Transaction` and `WebAuthn` come with T4, T5, T6. UNAUDITED.
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
use super::{Network, Result};

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
    /// `keccak256("scaas-subject-key-proof-v1" ‖ challenge)`.
    #[non_exhaustive]
    KeyProof { digest: [u8; 32] },
    /// Only behind [`AllowRawDigest`].
    #[non_exhaustive]
    RawDigest { digest: [u8; 32] },
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
