// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The platform's authenticator (spec §6.10): passkeys, a platform secret behind a biometric policy, secure-element P-256
//! keys. Implemented by the app (a foreign interface across a binding); every answer is checked by the SDK through `scaas-ua`,
//! never trusted for policy. A PRF output or platform secret is written by the app into the `SecretBytes` the SDK passes in.

use async_trait::async_trait;
use scaas_ua::wallet::SecretBytes;
use std::sync::Arc;

/// An authenticator's failure; `Unexpected` is a foreign exception inside the app's implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum AuthError {
    Refused,
    Cancelled,
    Unavailable,
    Unexpected,
}

/// A WebAuthn get-assertion request: the RP ID (the deployment's), a 32-byte challenge, the allowed credentials, the PRF salt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct AssertionRequest {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub allow: Vec<Vec<u8>>,
    pub prf_salt: Option<Vec<u8>>,
}

/// A WebAuthn assertion as the platform returns it; `prf` says whether a PRF output was written.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub prf: bool,
}

/// A new passkey: its credential id and its key data (`webauthn-p256` 0x0100).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct PasskeyCreated {
    pub credential_id: Vec<u8>,
    pub key_data: Vec<u8>,
}

/// A secure-element key's handle and public key data (`p256` 0x0101).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct SePublic {
    pub handle: String,
    pub key_data: Vec<u8>,
}

/// A platform key's access policy (biometry of the current enrollment, invalidated by a new one: research decision 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct KeyPolicy {
    pub biometry_current_set: bool,
    pub invalidated_by_enrollment: bool,
}

#[async_trait]
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub trait Authenticator: Send + Sync {
    async fn create_passkey(
        &self,
        rp_id: String,
        user_name: String,
        exclude: Vec<Vec<u8>>,
    ) -> Result<PasskeyCreated, AuthError>;
    /// UV required; the PRF output (when `prf_salt` is set) written into `prf_out`.
    async fn get_assertion(
        &self,
        req: AssertionRequest,
        prf_out: Arc<SecretBytes>,
    ) -> Result<Assertion, AuthError>;
    /// HMAC(platform key, `salt`) of a Keychain / Android Keystore key, written into `out`. `policy` is `Some` when the SDK
    /// enables platform unlock: the key `handle` is made (or checked) under that policy; `None` at an unlock: the existing key
    /// (closing review P2-8; spec §6.10).
    async fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        reason: String,
        policy: Option<KeyPolicy>,
        out: Arc<SecretBytes>,
    ) -> Result<(), AuthError>;
    async fn p256_generate(&self, policy: KeyPolicy) -> Result<SePublic, AuthError>;
    /// A signature in MESSAGE mode over the 32-byte `ua_msg`.
    async fn p256_sign(
        &self,
        handle: String,
        ua_msg: Vec<u8>,
        reason: String,
    ) -> Result<Vec<u8>, AuthError>;
}
