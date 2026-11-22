// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqChat's `file` content (UA-7 §6.4.1 with its 2026-11-21 Change; pqchat-core T10b, owner 2026-11-22 "2 hàm mới + app_id
//! PqChat"; feature `app-core`, with or without `fam-arweave`: the `ar://` form is `crate::file`'s): the two calls that keep
//! a file key inside `ua-rs`.
//!
//! - **(a)** [`AppKeys::pqchat_seal_file_message`]: the sealer is given every field of the content but `key` and the file
//!   key's `File` handle (from `seal_for_arweave`); the key enters the content here, the content is checked
//!   ([`check_file`]) and sealed as S5 seals any content. A content that holds a `key` already, or of another type:
//!   `PqChatContent`; a handle of another usage: `AppKeyUsage`.
//! - **(b)** [`pqchat_open_file`]: the file of an object named by an opened content (K4's canonical JSON): the content checked,
//!   then before any decryption the object's exact length (`FileLength`) and SHA-256 equal to `ctSha256`
//!   (`FileHashMismatch`), then the tag, the frame and `sha256` (`open_file`'s checks); only the file leaves.
//!
//! The form (controller calls of T10b): `type` "file"; `mediaType` 1–64 B; `name` 1–255 B; `size` an integer in
//! [1, 2^36 − 32]; `sha256`, `ctSha256` and `key` lower-case `0x` hex of 32 B; `url` an `ar://<id>` (the framed object, the
//! padding inside the AEAD); `store`, optional, `{kind 1–32 B, locator 1–2,048 B}`; another field ignored. Byte formats:
//! clientkeys `src/pqchat.js` (`checkFileContent`, `sealFileContent`, `openFileContent`),
//! `smartcontracts/vectors/pqchat/messages.json` (`fileMessage` and its refusal rows). UNAUDITED.
use super::bounded;
use super::file::open_object;
use super::pqchat_keys::{canonical_zeroizing, Header, SealedMessage, JSON_DEPTH, PT_MAX};
use super::signer::Signer;
use super::{AppKeys, Error, KeyHandle, KeyUsage, Result};
use crate::file::ar_url;
use serde_json::Value;
use zeroize::Zeroizing;

/// A `file`'s largest `size` (UA-7 §6.4.1).
pub const SIZE_MAX: u64 = (1 << 36) - 32;

/// The fields of a checked `file` content the reader uses.
pub struct FileFields {
    pub size: u64,
    pub sha256: [u8; 32],
    pub ct_sha256: [u8; 32],
    key: Zeroizing<[u8; 32]>,
}

fn text(v: Option<&Value>, lo: usize, hi: usize) -> Result<&str> {
    v.and_then(Value::as_str)
        .filter(|s| (lo..=hi).contains(&s.len()))
        .ok_or(Error::PqChatContent)
}

/// 32 bytes of lower-case `0x` hex.
fn hex32(v: Option<&Value>) -> Result<[u8; 32]> {
    let s = text(v, 66, 66)?
        .strip_prefix("0x")
        .ok_or(Error::PqChatContent)?;
    let mut out = [0u8; 32];
    for (o, p) in out.iter_mut().zip(s.as_bytes().chunks(2)) {
        let d = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Error::PqChatContent),
        };
        let (hi, lo) = (p.first().copied(), p.get(1).copied());
        *o = (d(hi.ok_or(Error::PqChatContent)?)? << 4) | d(lo.ok_or(Error::PqChatContent)?)?;
    }
    Ok(out)
}

/// A `file` content's form (the module's list): its size, hashes and key; anything else `PqChatContent`.
pub fn check_file(v: &Value) -> Result<FileFields> {
    let o = v.as_object().ok_or(Error::PqChatContent)?;
    if text(o.get("type"), 1, 32)? != "file" {
        return Err(Error::PqChatContent);
    }
    text(o.get("mediaType"), 1, 64)?;
    text(o.get("name"), 1, 255)?;
    let size = o
        .get("size")
        .and_then(Value::as_u64)
        .filter(|s| (1..=SIZE_MAX).contains(s))
        .ok_or(Error::PqChatContent)?;
    ar_url(text(o.get("url"), 1, 2048)?).ok_or(Error::PqChatContent)?;
    if let Some(st) = o.get("store") {
        text(st.get("kind"), 1, 32)?;
        text(st.get("locator"), 1, 2048)?;
    }
    Ok(FileFields {
        size,
        sha256: hex32(o.get("sha256"))?,
        ct_sha256: hex32(o.get("ctSha256"))?,
        key: Zeroizing::new(hex32(o.get("key"))?),
    })
}

fn hex0x(b: &[u8]) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(2 + 2 * b.len()));
    s.push_str("0x");
    for x in b {
        for n in [x >> 4, x & 15] {
            s.push(char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 }));
        }
    }
    s
}

/// (b): the file of `object` named by the opened content `content` (see the module).
pub fn pqchat_open_file(content: &[u8], object: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut v = bounded::json(content, PT_MAX, JSON_DEPTH).map_err(|_| Error::PqChatContent)?;
    let r =
        check_file(&v).and_then(|f| open_object(&f.key, object, f.size, &f.sha256, &f.ct_sha256));
    bounded::wipe(&mut v);
    r
}

impl AppKeys {
    #[allow(clippy::too_many_arguments)]
    fn seal_file_message_with(
        &self,
        k: &KeyHandle,
        pos: &KeyHandle,
        h: &Header,
        fields_json: &[u8],
        file_key: &KeyHandle,
        signer: &dyn Signer,
        env_nonce: &[u8; 12],
    ) -> Result<SealedMessage> {
        self.check_usage(file_key, KeyUsage::File)?;
        let mut v =
            bounded::json(fields_json, PT_MAX, JSON_DEPTH).map_err(|_| Error::PqChatContent)?;
        let r = (|| {
            let o = v.as_object_mut().ok_or(Error::PqChatContent)?;
            if o.get("type").and_then(Value::as_str) != Some("file") || o.contains_key("key") {
                return Err(Error::PqChatContent);
            }
            let key = hex0x(&self.bytes(file_key)?[..]);
            o.insert("key".into(), Value::String(key.to_string()));
            check_file(&v)?;
            let canon = canonical_zeroizing(&v, fields_json.len() + key.len() + 8)?;
            self.seal_canonical(k, pos, h, canon.as_bytes(), signer, env_nonce)
        })();
        bounded::wipe(&mut v);
        r
    }

    /// (a): the `file` content `fields_json` (every field but `key`) with the key of the `File` handle `file_key` entered,
    /// checked and sealed as S5 (see the module), at `pos`, signed by `signer`, the envelope under `k` with a random nonce.
    pub fn pqchat_seal_file_message(
        &self,
        k: &KeyHandle,
        pos: &KeyHandle,
        h: &Header,
        fields_json: &[u8],
        file_key: &KeyHandle,
        signer: &dyn Signer,
    ) -> Result<SealedMessage> {
        let mut n = [0u8; 12];
        super::appkey::rng(&mut n)?;
        self.seal_file_message_with(k, pos, h, fields_json, file_key, signer, &n)
    }
}

/// Test-only entry points (feature `vectors`, never in a release build).
#[cfg(feature = "vectors")]
impl AppKeys {
    /// [`AppKeys::pqchat_seal_file_message`] with a fixed envelope nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn pqchat_vectors_seal_file_message(
        &self,
        k: &KeyHandle,
        pos: &KeyHandle,
        h: &Header,
        fields_json: &[u8],
        file_key: &KeyHandle,
        signer: &dyn Signer,
        env_nonce: &[u8; 12],
    ) -> Result<SealedMessage> {
        self.seal_file_message_with(k, pos, h, fields_json, file_key, signer, env_nonce)
    }
}
