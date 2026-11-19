// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Passkey and secure-element signing (spec §7 "Passkey keys", "Secure-element keys"; owner 2026-11-19, S1, P1): a stored key
//! row (`AccountRow::Key`) signs a typed SCaaS struct through `scaas-ua`'s `ExternalKey`. First `sign_scaas` runs through an
//! `ExternalKey` that only refuses, so the policy check passes before the user is asked; then the SDK computes what the device
//! signs from `scaas_purpose(td)` and the digest (a passkey's challenge by `webauthn_challenge`, a secure element's `ua_msg` by
//! `ua_message`, signed in MESSAGE mode), asks the app's `Authenticator`, and signs through an `ExternalKey` whose device returns
//! that answer: `scaas-ua` verifies it against the row's key data before use (`ExternalSignature` otherwise). A passkey's
//! assertion is first built and verified by `webauthn_assertion` (UV, rpIdHash, the challenge): `AuthenticatorRefused` when it
//! does not verify or the platform refuses. UNAUDITED.
use crate::{Sdk, SdkError};
use scaas_ua::ua_portable::UASig;
use scaas_ua::wallet::{
    scaas_purpose, sign_scaas, webauthn_assertion, webauthn_challenge, Error as UaError, Expect,
    ExternalKey, KeyRef as UaKeyRef, SecretBytes, TypedData,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// `webauthn-p256` and `p256` (spec §5.6).
pub(crate) const PASSKEY: u16 = 0x0100;
pub(crate) const SECURE_ELEMENT: u16 = 0x0101;

/// A stored key row's public parts.
#[derive(Debug, Clone)]
pub(crate) struct ExternalRow {
    pub kind: u16,
    pub key_data: Vec<u8>,
    pub ua: [u8; 32],
    pub credential_id: Option<Vec<u8>>,
    pub handle: Option<String>,
}

impl ExternalRow {
    pub(crate) fn key_ref(&self) -> UaKeyRef {
        UaKeyRef::Ua {
            kind: self.kind,
            key_data: self.key_data.clone(),
        }
    }
}

/// `r ‖ s` of a signature as 64 bytes, or as DER `SEQUENCE { INTEGER r, INTEGER s }` (what WebAuthn and the platforms return).
pub(crate) fn rs(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if sig.len() == 64 {
        return Some((
            sig.get(..32)?.try_into().ok()?,
            sig.get(32..)?.try_into().ok()?,
        ));
    }
    let (&[0x30, n], body) = sig.split_first_chunk::<2>()? else {
        return None;
    };
    if usize::from(n) != body.len() {
        return None;
    }
    let int = |b: &[u8]| -> Option<([u8; 32], usize)> {
        let (&[0x02, l], rest) = b.split_first_chunk::<2>()? else {
            return None;
        };
        let v = rest.get(..usize::from(l))?;
        let v = match v {
            [0, x, ..] if *x >= 0x80 => v.get(1..)?,
            [x, ..] if *x < 0x80 => v,
            _ => return None,
        };
        let mut w = [0u8; 32];
        w.get_mut(32usize.checked_sub(v.len())?..)?
            .copy_from_slice(v);
        Some((w, 2 + usize::from(l)))
    };
    let (r, a) = int(body)?;
    let (s, b) = int(body.get(a..)?)?;
    (a + b == body.len()).then_some((r, s))
}

/// The `UASig` of `td` by `row` under `expect` (module doc).
pub(crate) async fn sign(
    sdk: &Sdk,
    row: &ExternalRow,
    td: &TypedData,
    expect: &Expect,
) -> Result<UASig, SdkError> {
    let asked = AtomicBool::new(false);
    let refuse = ExternalKey::new(row.key_ref(), |_| {
        asked.store(true, Ordering::SeqCst);
        Err(UaError::ExternalSignature)
    });
    let dry = sign_scaas(&refuse, td, expect.clone());
    if !asked.load(Ordering::SeqCst) {
        // refused before any device would be asked: the policy's (or the typed data's) own error
        return Err(dry.err().map_or(SdkError::Internal, SdkError::from));
    }
    let answer = answer(sdk, row, &scaas_purpose(td)?, &td.digest()?).await?;
    let device = ExternalKey::new(row.key_ref(), move |_| Ok(answer.clone()));
    Ok(sign_scaas(&device, td, expect.clone())?)
}

/// The device's answer for `uaMessage(kind, purpose, digest)`: a passkey's assertion (built and verified by
/// `webauthn_assertion`; `AuthenticatorRefused` otherwise), a secure element's `r ‖ s` over the `ua_msg` (MESSAGE mode). The
/// caller signs through an `ExternalKey` returning it, which `scaas-ua` verifies again.
pub(crate) async fn answer(
    sdk: &Sdk,
    row: &ExternalRow,
    purpose: &[u8; 32],
    digest: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    let (purpose, digest) = (*purpose, *digest);
    let auth = sdk
        .authenticator
        .clone()
        .ok_or(SdkError::AuthenticatorRefused)?;
    let answer = match row.kind {
        PASSKEY => {
            let challenge = webauthn_challenge(&purpose, &digest)?;
            let req = crate::platform::AssertionRequest {
                rp_id: sdk.rp_id.clone().ok_or(SdkError::AuthenticatorRefused)?,
                challenge: challenge.to_vec(),
                allow: vec![row.credential_id.clone().ok_or(SdkError::Argument)?],
                prf_salt: None,
            };
            let a = auth
                .get_assertion(req, Arc::new(SecretBytes::new(32)?))
                .await
                .map_err(|_| SdkError::AuthenticatorRefused)?;
            let (r, s) = rs(&a.signature).ok_or(SdkError::AuthenticatorRefused)?;
            webauthn_assertion(
                &row.key_data,
                &challenge,
                &a.authenticator_data,
                &a.client_data_json,
                &r,
                &s,
            )
            .map_err(|_| SdkError::AuthenticatorRefused)?
        }
        SECURE_ELEMENT => {
            let ua_msg =
                scaas_ua::ua_message(SECURE_ELEMENT, &purpose, &digest).map_err(UaError::from)?;
            let handle = row.handle.clone().ok_or(SdkError::Argument)?;
            let sig = auth
                .p256_sign(handle, ua_msg.to_vec(), "Sign a SCaaS operation".into())
                .await
                .map_err(|_| SdkError::AuthenticatorRefused)?;
            let (r, s) = rs(&sig).ok_or(SdkError::AuthenticatorRefused)?;
            [r, s].concat()
        }
        _ => return Err(SdkError::Argument),
    };
    Ok(answer)
}
