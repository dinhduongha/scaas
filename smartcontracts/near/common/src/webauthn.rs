//! NET-ALL-04 passkey check in wasm (RustCrypto `p256`; NEP-635 `p256_verify` is not used, spec §3.5).
//! clientDataJSON: `type == "webauthn.get"`, challenge = b64url(challenge), origin ∈ origins;
//! authenticatorData: rpIdHash, UP flag; signature r ‖ s with s ≤ n/2 over sha256(authenticatorData ‖ sha256(clientDataJSON)).
use near_sdk::env;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;

const FLAG_UP: u8 = 0x01;

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    ClientData,
    AuthenticatorData,
    HighS,
    BadKey,
    BadSignature,
}

/// `key` = x ‖ y (uncompressed, untagged), `sig` = r ‖ s.
pub fn verify(
    key: &[u8; 64],
    challenge: &[u8; 32],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    sig: &[u8; 64],
    rp_id_hash: &[u8; 32],
    origins: &[String],
) -> Result<(), AuthError> {
    let cd = client_data_json;
    if !has_field(cd, b"type", b"webauthn.get")
        || !has_field(cd, b"challenge", b64url(challenge).as_bytes())
        || !origins.iter().any(|o| has_field(cd, b"origin", o.as_bytes()))
    {
        return Err(AuthError::ClientData);
    }
    let ad = authenticator_data;
    if ad.len() < 37 || &ad[..32] != rp_id_hash || ad[32] & FLAG_UP == 0 {
        return Err(AuthError::AuthenticatorData);
    }
    let sig = Signature::from_slice(sig).map_err(|_| AuthError::BadSignature)?;
    if sig.normalize_s().is_some() {
        return Err(AuthError::HighS);
    }
    let point = EncodedPoint::from_untagged_bytes(key.into());
    let vk = VerifyingKey::from_encoded_point(&point).map_err(|_| AuthError::BadKey)?;
    let mut msg = Vec::with_capacity(ad.len() + 32);
    msg.extend_from_slice(ad);
    msg.extend_from_slice(&env::sha256_array(cd));
    vk.verify_prehash(&env::sha256_array(&msg), &sig).map_err(|_| AuthError::BadSignature)
}

/// The first `"origin":"…"` value of clientDataJSON (the origin a lazily opened passkey account starts with); `None`
/// when absent or escaped (an origin never contains `\` or `"`).
pub fn origin(client_data_json: &[u8]) -> Option<String> {
    const PAT: &[u8] = b"\"origin\":\"";
    let at = client_data_json.windows(PAT.len()).position(|w| w == PAT)? + PAT.len();
    let rest = &client_data_json[at..];
    let v = &rest[..rest.iter().position(|c| *c == b'"')?];
    (!v.contains(&b'\\')).then(|| String::from_utf8(v.to_vec()).ok()).flatten()
}

/// `"<field>":"<value>"` present verbatim. The browser JSON-escapes values, so a value cannot forge another pair.
fn has_field(hay: &[u8], field: &[u8], value: &[u8]) -> bool {
    let mut pat = Vec::with_capacity(field.len() + value.len() + 5);
    pat.push(b'"');
    pat.extend_from_slice(field);
    pat.extend_from_slice(b"\":\"");
    pat.extend_from_slice(value);
    pat.push(b'"');
    hay.windows(pat.len()).any(|w| w == pat.as_slice())
}

/// Unpadded base64url.
pub fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}
