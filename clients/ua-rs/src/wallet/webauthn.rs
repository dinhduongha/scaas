// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! WebAuthn (`0x0100`, spec §5.6, C-07; T6): the authenticator signs, `ua-rs` builds its challenge and the assertion encoding
//! the chains take. [`webauthn_challenge`] is the `ua_msg` of `0x0100` (clientkeys `webauthnChallenge`); the caller keeps it and
//! hands it back to [`webauthn_assertion`] as the only reference: the challenge inside the untrusted clientDataJSON never is.
//! A passkey behind the [`super::Signer`] trait (phase 2) is asked [`super::SignRequest::WebAuthn`] by the `UASig` builder.
//! UNAUDITED.
use super::sign::ua_request;
use super::{Error, Result, SignRequest};
use crate::verify::{client_data_ok, verify};

/// The authenticator's challenge for `purpose` (a tag of `PURPOSES` or `pop` v2, else `UAPurposeUnknown`) and `digest`:
/// `uaMessage(0x0100, purpose, digest)`.
pub fn webauthn_challenge(purpose: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 32]> {
    match ua_request(0x0100, purpose, digest)? {
        SignRequest::WebAuthn { challenge } => Ok(challenge),
        _ => Err(Error::Argument),
    }
}

/// The `webauthn-p256` signature `abi.encode(authData, clientDataJSON, r, s)` of an assertion, against `expected_challenge`,
/// the challenge the caller asked for. In order: `0 < r < n` and `0 < s < n`; `s` made low; `client_data_json` UTF-8, kept
/// as the signed bytes and accepted only by the chains' rule (`verify.rs` `client_data_ok`: `type`, `challenge` =
/// `expected_challenge`, `origin`, then `}` or `,"crossOrigin":false`); then the whole encoding verified with
/// `verify(0x0100, key_data, expected_challenge, …)` (flags, `rpIdHash`, P-256) before it is returned. Any failure:
/// `WebAuthnAssertion`, nothing returned.
pub fn webauthn_assertion(
    key_data: &[u8], expected_challenge: &[u8; 32], auth_data: &[u8], client_data_json: &[u8], r: &[u8; 32], s: &[u8; 32],
) -> Result<Vec<u8>> {
    let sig = p256::ecdsa::Signature::from_scalars(*r, *s).map_err(|_| Error::WebAuthnAssertion)?.normalize_s();
    if core::str::from_utf8(client_data_json).is_err() || !client_data_ok(client_data_json, expected_challenge) {
        return Err(Error::WebAuthnAssertion);
    }
    let mut blob = [crate::word(0x80), crate::word(0xa0 + auth_data.len().next_multiple_of(32) as u64)].concat();
    blob.extend_from_slice(&sig.to_bytes());
    crate::ua8::abi_bytes(&mut blob, auth_data);
    crate::ua8::abi_bytes(&mut blob, client_data_json);
    if !verify(0x0100, key_data, expected_challenge, &blob, false) {
        return Err(Error::WebAuthnAssertion);
    }
    Ok(blob)
}
