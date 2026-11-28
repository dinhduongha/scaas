// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `file` items on Arweave (owner 2026-11-28; spec 2026-11-21-avax-polkadot-arweave §7.10, C14; PqVault spec §6.8): the file goes
//! off chain, the item names it by `url = ar://<id>`. The crate holds no file key and no cryptography of its own: the SDK's
//! `seal_for_arweave` (under the vault account's PqVault app root key) frames the file to its power-of-two bucket, seals it under
//! a fresh `File` key handle and builds the signed ANS-104 item; [`crate::keys::seal_file_key`] seals that handle under the
//! item's `kFile` into `keyWrap` inside `scaas-ua`; the SDK's `open_file` checks the object's length and `ctSha256` before any
//! decryption. Order (C14): the record is prepared (nothing signed), the app posts the item (`ArweaveFiles::upload_file`, kept
//! until settled with `keep_up`), [`PqVault::check_uploaded`] reads the object back once through the gateway list and checks
//! its `ctSha256`, and only then [`PqVault::confirm_file`] signs it: a vault never names an object nobody can read. A reader
//! fetches the object on its user's action only (CLI-PQV-05) and opens it with [`PqVault::open_file`]; a failure is the
//! device's to show and nothing sent depends on it (ARCH-POS-13). UNAUDITED.
use crate::item::{Field, Item};
use crate::keys;
use crate::records::{hex, unhex, ItemRecord, B32};
use crate::vault::{Confirmed, ItemVersion, Prepared, Unlocked};
use crate::{Error, PqVault, Result};
use scaas_sdk::app_core::SecretBytes;
use scaas_sdk::arweave::ArweaveFiles;
use scaas_sdk::op::KeyRef;
use serde_json::{json, Value};
use std::sync::Arc;

/// The upload key's ANS-104 signature type: ed25519 (as PqChat's, pqchat-core T10b).
pub const SIGNATURE_TYPE: u16 = 2;

/// A file to save in a vault: its bytes, the item's title (1–256 B), its media type (1–64 B) and display name (1–255 B), and
/// the bundler profile's largest single request (`FileTooLarge` above its bucket).
#[derive(Clone)]
pub struct FileToSave {
    pub file: Vec<u8>,
    pub title: String,
    pub media_type: String,
    pub name: String,
    pub max_object: u64,
}

/// The sealed file for the app to post to Arweave and keep until settlement: the signed ANS-104 item (its data the object,
/// exactly `bucket(size) + 16` B) and the item's public fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUpload {
    pub url: String,
    pub item: Vec<u8>,
    pub size: u64,
    pub ct_sha256: [u8; 32],
}

/// A `file` item built for the review and not signed (CLI-SDK-36), with its upload. [`PqVault::confirm_file`] signs it only
/// once [`PqVault::check_uploaded`] read the object back (C14).
#[derive(Debug)]
pub struct PreparedFile {
    prepared: Prepared<ItemRecord>,
    upload: FileUpload,
    read: bool,
}

impl PreparedFile {
    /// The prepared record and its quote, for the review.
    pub fn prepared(&self) -> &Prepared<ItemRecord> {
        &self.prepared
    }
    /// The upload the app posts.
    pub fn upload(&self) -> &FileUpload {
        &self.upload
    }
    /// Whether one gateway read of the object passed.
    pub fn read_back(&self) -> bool {
        self.read
    }
}

/// A `file` item's public fields, as the app shows and fetches by (`name` display only, never a path without making it safe).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub media_type: String,
    pub name: String,
    pub size: u64,
    pub url: String,
    pub sha256: [u8; 32],
    pub ct_sha256: [u8; 32],
}

fn b32_of(v: Option<&Value>) -> Option<[u8; 32]> {
    unhex(v?.as_str()?, 32)?.try_into().ok()
}

/// The public fields of a `file` item, else `None` (another type, a field missing or of another shape).
pub fn file_info(item: &Item) -> Option<FileInfo> {
    if item.ty != "file" {
        return None;
    }
    let s = |k: &str| item.plain(k).and_then(Value::as_str).map(String::from);
    Some(FileInfo {
        media_type: s("mediaType")?,
        name: s("name")?,
        size: item.plain("size").and_then(Value::as_u64)?,
        url: s("url")?,
        sha256: b32_of(item.plain("sha256"))?,
        ct_sha256: b32_of(item.plain("ctSha256"))?,
    })
}

impl PqVault {
    /// `f` as a new `file` item of `v` (version 1 under the newest epoch), prepared for the review and paid by `payer`, with its
    /// upload: the SDK's `seal_for_arweave` under `v`'s account, the file key sealed under the item's `kFile` (the handle wiped
    /// here), the item checked by the writer's bounds. Nothing is signed or posted.
    pub async fn prepare_file(
        &self,
        v: &Unlocked,
        f: &FileToSave,
        payer: KeyRef,
    ) -> Result<PreparedFile> {
        self.p1(&v.account).await?;
        let e = v.write_epoch()?.id;
        let nonce = self.item_nonce(v)?;
        let iid = crate::records::item_id(v.state.vault_id, v.state.me, nonce);
        let a = self.core.seal_for_arweave(
            v.account.clone(),
            f.file.clone(),
            SIGNATURE_TYPE,
            f.max_object,
        )?;
        let x = v.at(e, iid, 1, v.state.me);
        let kv = v.keys.get(&e).ok_or(Error::Unreadable)?;
        let wrap = keys::seal_file_key(&self.core, kv, &x, a.key.clone());
        let _ = self.core.destroy(a.key);
        let ct_sha256: [u8; 32] = a.ct_sha256.try_into().map_err(|_| Error::Shape)?;
        let mut item = Item::new("file");
        let p = |v: Value| Field::Plain(v);
        item.set("title", p(json!(f.title)))
            .set("mediaType", p(json!(f.media_type)))
            .set("name", p(json!(f.name)))
            .set("size", p(json!(a.size)))
            .set("sha256", p(json!(hex(&a.sha256))))
            .set("ctSha256", p(json!(hex(&ct_sha256))))
            .set("url", p(json!(a.url)))
            .set("keyWrap", p(json!(hex(&wrap?))));
        item.check()?;
        let rec = self.item_record_at(v, &item, nonce)?;
        let prepared = self.prepare_in(v, rec, payer).await?;
        Ok(PreparedFile {
            prepared,
            upload: FileUpload {
                url: a.url,
                item: a.item,
                size: a.size,
                ct_sha256,
            },
            read: false,
        })
    }

    /// C14: one read of the object through the gateway list (`ArweaveFiles::fetch_file`: the exact length, marked as feeding a
    /// decryption, its SHA-256 the item's `ctSha256`); on a pass the prepared item may be confirmed. The bytes read are dropped.
    pub async fn check_uploaded(&self, p: &mut PreparedFile, files: &ArweaveFiles) -> Result<()> {
        let u = &p.upload;
        files.fetch_file(&u.url, u.size, u.ct_sha256).await?;
        p.read = true;
        Ok(())
    }

    /// Signs a prepared `file` item on the user's confirm ([`PqVault::confirm`]), only after [`PqVault::check_uploaded`]
    /// passed; before it, `FileNotRead` and nothing is signed.
    pub async fn confirm_file(&self, p: PreparedFile) -> Result<Confirmed<ItemRecord>> {
        if !p.read {
            return Err(Error::FileNotRead);
        }
        self.confirm(p.prepared).await
    }

    /// The file of `object` (fetched by the app on its user's action, `ArweaveFiles::fetch_file` with [`file_info`]'s `url`,
    /// `size` and `ctSha256`) named by the opened `version` of a `file` item of `v`: the file key opened under that version's
    /// `kFile` inside `scaas-ua`, then the SDK's `open_file` checks the object's length and `ctSha256` before any decryption, the
    /// tag, the frame and `sha256`; only the file comes back, as a handle. Every failure is local (`Unreadable` for an item that
    /// is no readable `file` item or whose key does not open; the SDK's `FileLength` / `FileHashMismatch` otherwise).
    pub fn open_file(
        &self,
        v: &Unlocked,
        version: &ItemVersion,
        object: Vec<u8>,
    ) -> Result<Arc<SecretBytes>> {
        let item = version.value.as_ref().map_err(|_| Error::Unreadable)?;
        let info = file_info(item).ok_or(Error::Unreadable)?;
        let wire = item
            .plain("keyWrap")
            .and_then(Value::as_str)
            .and_then(|h| unhex(h, 60))
            .ok_or(Error::Unreadable)?;
        let kv = v.keys.get(&version.epoch_id).ok_or(Error::Unreadable)?;
        let x = v.at(
            version.epoch_id,
            version.item_id,
            version.version,
            version.author,
        );
        let key = keys::open_file_key(&self.core, kv, &x, &wire)?;
        let opened = self.core.open_file(
            key,
            object,
            info.size,
            info.sha256.to_vec(),
            info.ct_sha256.to_vec(),
        );
        Ok(Arc::new(opened?))
    }

    /// `value` with a `file` item's `keyWrap` re-sealed from `base`'s version (its epoch, item, version) to `version` under
    /// `epoch` (an edit's new version: `kFile` binds both); any other item unchanged. A wrap that does not open: `Unreadable`.
    pub(crate) fn rewrap_file(
        &self,
        v: &Unlocked,
        base: &ItemVersion,
        epoch: B32,
        version: u32,
        value: &Item,
    ) -> Result<Item> {
        let Some(wire) = (value.ty == "file")
            .then(|| value.plain("keyWrap"))
            .flatten()
            .and_then(Value::as_str)
            .and_then(|h| unhex(h, 60))
        else {
            return Ok(value.clone());
        };
        let old = v.at(base.epoch_id, base.item_id, base.version, base.author);
        let kv_old = v.keys.get(&base.epoch_id).ok_or(Error::Unreadable)?;
        let key = keys::open_file_key(&self.core, kv_old, &old, &wire)?;
        let new = v.at(epoch, base.item_id, version, v.state.me);
        let kv_new = v.keys.get(&epoch).ok_or(Error::Unreadable)?;
        let sealed = keys::seal_file_key(&self.core, kv_new, &new, key.clone());
        let _ = self.core.destroy(key);
        let mut out = value.clone();
        out.set("keyWrap", Field::Plain(json!(hex(&sealed?))));
        Ok(out)
    }
}
