// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Attachments (plan T10b; owner 2026-11-21 O9 (b) and 2026-11-22, two new calls and an app id for PqChat; UA-7 §6.4.1 with its
//! 2026-11-21 Change; CLI-PQC-02): a `file` content sent and read. The crate holds no file key and no cryptography: the SDK's
//! `seal_for_arweave` (under PqChat's app id, [`crate::APP_ID`]) frames the file to its power-of-two bucket and seals it
//! under a fresh key handle, `pqchat_seal_file_message` enters that key into the content inside `scaas-ua`, and
//! `pqchat_open_file` checks the object's length and `ctSha256` before any decryption, reading the key from the opened
//! content inside `scaas-ua`. The signed item is returned for the app to post and keep (`ArweaveFiles::upload_file`,
//! `keep_up`); the crate posts nothing to Arweave. The reader fetches the object on its user's action only, with
//! [`FileInfo`]'s `url`, `size` and `ct_sha256` (`ArweaveFiles::fetch_file`); a failed file is shown on the device only and
//! nothing sent depends on it (ARCH-POS-13).
use crate::content::Content;
use crate::model::hex;
use crate::reads::SessionRef;
use crate::session::Me;
use crate::stores::{Body, SendOpts, SendReport};
use crate::{PqChat, PqChatError};
use scaas_sdk::app_core::AppKey;
use scaas_sdk::SecretBytes;
use serde_json::Value;
use std::sync::Arc;

/// The upload key's ANS-104 signature type: ed25519 (controller call of T10b).
pub const SIGNATURE_TYPE: u16 = 2;

/// A file to send: its bytes, its media type (1–64 B) and display name (1–255 B), and the bundler profile's largest single
/// request (`FileTooLarge` above its bucket).
#[derive(Clone)]
pub struct FileToSend {
    pub file: Vec<u8>,
    pub media_type: String,
    pub name: String,
    pub max_object: u64,
}

/// The sealed file for the app to post to Arweave and keep until settlement: the signed ANS-104 item (its data the object,
/// exactly `bucket(size) + 16` B) and the content's public fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUpload {
    pub url: String,
    pub item: Vec<u8>,
    pub size: u64,
    /// `0x` hex
    pub ct_sha256: String,
}

/// A received `file`'s public fields: what the app shows and fetches by (no key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub media_type: String,
    /// display only: never a path without making it safe
    pub name: String,
    pub size: u64,
    /// `ar://<id>`
    pub url: String,
    /// `0x` hex
    pub ct_sha256: String,
}

impl FileToSend {
    /// The content it will be, with placeholder hashes and url: its bounds checked before anything is sealed.
    pub(crate) fn check(&self, ts: Option<u64>) -> Result<(), PqChatError> {
        let z = format!("0x{}", "00".repeat(32));
        Content::File {
            media_type: self.media_type.clone(),
            name: self.name.clone(),
            size: (self.file.len() as u64).max(1),
            sha256: z.clone(),
            ct_sha256: z,
            url: format!("ar://{}", "A".repeat(43)),
        }
        .value(ts)
        .map(|_| ())
    }
}

impl PqChat {
    /// `f` sent by `me` to every store of `s` as a `file` content (the rules of [`PqChat::send`]), and its sealed item
    /// returned for the app to post; nothing is posted here.
    pub async fn send_file(
        &self,
        s: &SessionRef,
        me: &Me,
        f: &FileToSend,
        ts: Option<u64>,
        o: &SendOpts,
    ) -> Result<(SendReport, FileUpload), PqChatError> {
        let (r, up) = self.send_with(s, me, Body::File(f), ts, o).await?;
        Ok((r, up.ok_or(PqChatError::Internal)?))
    }

    /// The `file` content's value (no key), the file key's handle and the upload, sealed by the SDK under PqChat's app id.
    pub(crate) fn seal_file_for(
        &self,
        me: &Me,
        f: &FileToSend,
        ts: Option<u64>,
    ) -> Result<(Value, Arc<AppKey>, FileUpload), PqChatError> {
        let a = self.app.seal_for_arweave(
            me.key.clone(),
            f.file.clone(),
            SIGNATURE_TYPE,
            f.max_object,
        )?;
        let c = Content::File {
            media_type: f.media_type.clone(),
            name: f.name.clone(),
            size: a.size,
            sha256: hex(&a.sha256),
            ct_sha256: hex(&a.ct_sha256),
            url: a.url.clone(),
        };
        let v = match c.value(ts) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.app.destroy(a.key);
                return Err(e);
            }
        };
        let up = FileUpload {
            url: a.url,
            item: a.item,
            size: a.size,
            ct_sha256: hex(&a.ct_sha256),
        };
        Ok((v, a.key, up))
    }

    /// A received content's `file` fields (no key), or `None` for another content.
    pub fn file_info(&self, content: Arc<SecretBytes>) -> Option<FileInfo> {
        match content.with(Content::parse).content {
            Content::File {
                media_type,
                name,
                size,
                url,
                ct_sha256,
                ..
            } => Some(FileInfo {
                media_type,
                name,
                size,
                url,
                ct_sha256,
            }),
            _ => None,
        }
    }

    /// The file of `object` (fetched by the app on its user's action) named by the received `content`: the SDK checks the
    /// object's length (`FileLength`) and `ctSha256` (`FileHashMismatch`) before any decryption, then the tag, the frame and
    /// `sha256`; only the file comes back, as a handle. A failure is the device's to show; nothing is sent.
    pub fn open_file(
        &self,
        content: Arc<SecretBytes>,
        object: Vec<u8>,
    ) -> Result<Arc<SecretBytes>, PqChatError> {
        Ok(Arc::new(self.app.pqchat_open_file(content, object)?))
    }
}
