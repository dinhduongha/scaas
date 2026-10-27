//! NET-ALL-04 passkey check in wasm (RustCrypto `p256`; NEP-635 `p256_verify` is not used, spec §3.5), in its order:
//! authenticatorData ≥ 37 B, rpIdHash, flags UP and UV; clientDataJSON in the bounded grammar (`origin_of`), its
//! origin exactly one of `origins`; s ≤ n/2; P-256 over sha256(authenticatorData ‖ sha256(clientDataJSON)).
use near_sdk::env;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;

/// UP (0x01) and UV (0x04).
const FLAGS_UP_UV: u8 = 0x05;

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
    let (ad, cd) = (authenticator_data, client_data_json);
    if ad.len() < 37 || &ad[..32] != rp_id_hash || ad[32] & FLAGS_UP_UV != FLAGS_UP_UV {
        return Err(AuthError::AuthenticatorData);
    }
    let origin = origin_of(cd, challenge).ok_or(AuthError::ClientData)?;
    if !origins.iter().any(|o| o.as_bytes() == origin) {
        return Err(AuthError::ClientData);
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

/// NET-ALL-04 item 4 (WebAuthn L3 §5.8.1.2 bounded parse): clientDataJSON is exactly
/// `{"type":"webauthn.get","challenge":"<b64url(challenge)>","origin":"` ‖ origin ‖ `"` followed by `}` (end) or
/// `,"crossOrigin":false` then `}` (end) or `,`; no whitespace, no member before `crossOrigin`, and neither a
/// `topOrigin` nor a second `crossOrigin` anywhere after. Returns the origin bytes (never containing `\`).
pub fn origin_of<'a>(cd: &'a [u8], challenge: &[u8; 32]) -> Option<&'a [u8]> {
    let prefix = format!(r#"{{"type":"webauthn.get","challenge":"{}","origin":""#, b64url(challenge));
    let rest = cd.strip_prefix(prefix.as_bytes())?;
    let end = rest.iter().position(|c| *c == b'"')?;
    let (origin, tail) = (&rest[..end], &rest[end + 1..]);
    let ok = match tail.strip_prefix(br#","crossOrigin":false"#) {
        _ if tail == b"}" => true,
        Some(t) => t == b"}" || (t.starts_with(b",") && !has(t, br#""topOrigin""#) && !has(t, br#""crossOrigin""#)),
        None => false,
    };
    (ok && !origin.is_empty() && !origin.contains(&b'\\')).then_some(origin)
}

/// The origin a lazily opened passkey account starts with: `origin_of` as a string.
pub fn origin(client_data_json: &[u8], challenge: &[u8; 32]) -> Option<String> {
    String::from_utf8(origin_of(client_data_json, challenge)?.to_vec()).ok()
}

fn has(hay: &[u8], pat: &[u8]) -> bool {
    hay.windows(pat.len()).any(|w| w == pat)
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
