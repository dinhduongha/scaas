// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! AEAD, HKDF, HMAC (spec §7; T8): thin wrappers of `aes-gcm` =0.10.3 (`Aes256Gcm`), `aes-gcm-siv` =0.11.1 (`Aes256GcmSiv`),
//! both on the one `aes` 0.8.4, and `hkdf` =0.12.4 / `hmac` 0.12. The keys are caller-held session keys (PqChat's `K`, `mk_i`),
//! not UA secrets; nonce uniqueness is the caller's. A bad tag returns [`Error::Aead`] and no plaintext. UNAUDITED.
use super::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// An AEAD algorithm: an enum, never a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Aes256Gcm,
    Aes256GcmSiv,
}

/// The largest HKDF-SHA256 output (RFC 5869: `255 × HashLen`).
const HKDF_MAX: usize = 255 * 32;

/// `ct ‖ tag` (16 bytes) of `data` under `key` and `nonce`, `aad` authenticated.
pub fn aead_seal(alg: Alg, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let p = Payload { msg: data, aad };
    let out = match alg {
        Alg::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| Error::Argument)?.encrypt(nonce.into(), p),
        Alg::Aes256GcmSiv => aes_gcm_siv::Aes256GcmSiv::new_from_slice(key).map_err(|_| Error::Argument)?.encrypt(nonce.into(), p),
    };
    out.map_err(|_| Error::Argument)
}

/// The plaintext of `ct ‖ tag`: `Aead` for a bad tag (or an input shorter than the tag), and no plaintext.
pub fn aead_open(alg: Alg, key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let p = Payload { msg: data, aad };
    let out = match alg {
        Alg::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| Error::Argument)?.decrypt(nonce.into(), p),
        Alg::Aes256GcmSiv => aes_gcm_siv::Aes256GcmSiv::new_from_slice(key).map_err(|_| Error::Argument)?.decrypt(nonce.into(), p),
    };
    out.map(Zeroizing::new).map_err(|_| Error::Aead)
}

/// HKDF-SHA256 (RFC 5869) of `ikm` with `salt` (empty: the RFC's zero salt) and `info`: `len ≤ 255 × 32`, else `Argument`.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    expand(&Hkdf::<Sha256>::new(Some(salt), ikm), info, len)
}

/// HKDF-Expand-SHA256 of a PRK (at least 32 bytes): `len ≤ 255 × 32`, else `Argument`.
pub fn hkdf_expand_sha256(prk: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    expand(&Hkdf::<Sha256>::from_prk(prk).map_err(|_| Error::Argument)?, info, len)
}

fn expand(h: &Hkdf<Sha256>, info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if len > HKDF_MAX {
        return Err(Error::Argument);
    }
    let mut okm = Zeroizing::new(vec![0u8; len]);
    h.expand(info, &mut okm).map_err(|_| Error::Argument)?;
    Ok(okm)
}

/// HMAC-SHA256 (RFC 2104) of `data` under `key`.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC takes a key of any length: `new_from_slice` cannot fail here
    let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(key) else { return [0; 32] };
    m.update(data);
    m.finalize().into_bytes().into()
}
