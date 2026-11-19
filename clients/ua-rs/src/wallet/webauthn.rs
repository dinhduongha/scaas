// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! WebAuthn (`0x0100`, spec §5.6, C-07; T6): the authenticator signs, `ua-rs` builds its challenge and the assertion encoding
//! the chains take. [`webauthn_challenge`] is the `ua_msg` of `0x0100` (clientkeys `webauthnChallenge`); the caller keeps it and
//! hands it back to [`webauthn_assertion`] as the only reference: the challenge inside the untrusted clientDataJSON never is.
//! A passkey behind the [`super::Signer`] trait (phase 2) is asked [`super::SignRequest::WebAuthn`] by the `UASig` builder.
//! UNAUDITED.
use super::sign::ua_request;
use super::{Error, Result, SignRequest, Signer};
use crate::verify::{client_data_ok, verify};

/// The longest assertion `ua-rs` encodes or accepts from an authenticator: `authData` and `clientDataJSON` together, 1,024
/// bytes (owner 2026-11-19, G3). Real assertions: `authData` 37 bytes (`rpIdHash`, flags, `signCount`) plus at most an
/// extension's CBOR (`hmac-secret` / PRF output, `credBlob`: about 100); `clientDataJSON` 113 bytes of fixed members plus the
/// origin (an `https` DNS name with a port at most 267, an Android `apk-key-hash` origin 64) plus a browser's extra members
/// (Chrome's `other_keys_can_be_added_here`, 113; a `tokenBinding`, about 75): about 770 at worst; the vectors' longest is
/// 206 (608 signature bytes in the gas table's verify row). 1,024 leaves about a third above that worst case. Longer:
/// `WebAuthnTooLong`, nothing returned (the chains take any length; the cap bounds what this client signs and the gas a
/// quote assumes).
pub const WEBAUTHN_MAX_ASSERTION: usize = 1_024;

/// `WebAuthnTooLong` when `authData` and `clientDataJSON` together exceed [`WEBAUTHN_MAX_ASSERTION`].
pub(crate) fn capped(auth_data: usize, client_data_json: usize) -> Result<()> {
    match auth_data.checked_add(client_data_json) {
        Some(n) if n <= WEBAUTHN_MAX_ASSERTION => Ok(()),
        _ => Err(Error::WebAuthnTooLong),
    }
}

/// `key`'s answer to `req` for a `UASig` builder (owner 2026-11-19, Q3): a [`SignRequest::WebAuthn`] answer, from any
/// [`Signer`] (a third party's too, which may skip [`webauthn_assertion`]), must be the canonical encoding with `authData` and
/// `clientDataJSON` at most [`WEBAUTHN_MAX_ASSERTION`] together: above, `WebAuthnTooLong`; not canonical (its length cannot be
/// read), `WebAuthnAssertion`; nothing returned. Any other request: the answer as given.
pub(crate) fn answer(key: &dyn Signer, req: &SignRequest) -> Result<Vec<u8>> {
    let sig = key.sign_request(req)?;
    if let SignRequest::WebAuthn { .. } = req {
        let (a, c) = crate::verify::webauthn_fields(&sig).ok_or(Error::WebAuthnAssertion)?;
        capped(a.len(), c.len())?;
    }
    Ok(sig)
}

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
/// `WebAuthnAssertion`, nothing returned; first, `authData` and `clientDataJSON` above [`WEBAUTHN_MAX_ASSERTION`] together:
/// `WebAuthnTooLong`.
pub fn webauthn_assertion(
    key_data: &[u8],
    expected_challenge: &[u8; 32],
    auth_data: &[u8],
    client_data_json: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<u8>> {
    capped(auth_data.len(), client_data_json.len())?;
    let sig = p256::ecdsa::Signature::from_scalars(*r, *s)
        .map_err(|_| Error::WebAuthnAssertion)?
        .normalize_s();
    if core::str::from_utf8(client_data_json).is_err()
        || !client_data_ok(client_data_json, expected_challenge)
    {
        return Err(Error::WebAuthnAssertion);
    }
    let mut blob = [
        crate::word(0x80),
        crate::word(0xa0 + auth_data.len().next_multiple_of(32) as u64),
    ]
    .concat();
    blob.extend_from_slice(&sig.to_bytes());
    crate::ua_portable::abi_bytes(&mut blob, auth_data);
    crate::ua_portable::abi_bytes(&mut blob, client_data_json);
    if !verify(0x0100, key_data, expected_challenge, &blob, false, false) {
        return Err(Error::WebAuthnAssertion);
    }
    Ok(blob)
}
