// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Export and import of a whole profile (spec §10.1; CLI-UPR-17, CLI-UPR-18, CLI-UPR-27): [`OpenProfile::export`],
//! [`Profiles::import_preview`], [`Profiles::import`]. The file (rows: smartcontracts/vectors/profile/export.json):
//! `"SCAASPX1" ‖ be32(header_len) ‖ header ‖ chunk_0 ‖ … ‖ chunk_last`, each chunk sealed in `scaas-ua` (`ExportKey`) under
//! `K_x` from the export passphrase; the payload `be32(len) ‖ label JSON ‖ be32(len) ‖ settings JSON ‖ be16(count) ‖
//! (lp(name) ‖ be32(len) ‖ bytes)*`, the items `keystore` then `sdk.state`, each at most once.
//!
//! - **Export** needs the profile protected, its name typed again (`ConfirmationMissing`), the export passphrase under the
//!   profile passphrase's rule (`ProfilePassphraseWeak`) and the profile passphrase checked against the `pass` wrap
//!   (`ProfileOpen`); the payload holds the label (no id), the settings without credential references and the two items,
//!   nothing else; above 64 MiB `ProfileExportTooLarge`; the file created new, mode `0600`, never through an existing file or a
//!   symlink (`Argument`).
//! - **Preview** checks the header and the length before the KDF (no lock is taken), verifies every chunk before any payload
//!   byte is parsed, and holds the payload in `Zeroizing` memory only: nothing is written. Every refusal is
//!   `ProfileImportOpen` but parameters above this device's maximum (`ProfileKdfTooLarge`) and argon2's allocation failure
//!   (`ProfileKdfOutOfMemory`); its local reason is kept for a log line ([`Profiles::last_import_refusal`]). The items are
//!   checked here by name, order, size and their JSON `rev`: the SDK checks their bytes with its own parsers.
//! - **Import** seals a new profile (a new UUIDv7) under the new passphrase from its first byte in `p/.tmp-<random>/` under its
//!   `build.lock`, with the settings the review's filter keeps, and commits as a create (the journal, one rename, the row; none
//!   for a hidden profile, whose duplicate search runs first).
use crate::envelope::{self, label_json, Envelope, Kdf, KdfParams, Label, State, B64};
use crate::file::{self, lock_file, read_bounded, rev_of, MAX_BYTES};
use crate::hidden::{seal_label, search, taken};
use crate::names::{check_name, new_id, random, same_name};
use crate::profile::{
    read_envelope, remove_dir, Heavy, OpenProfile, ProfileInfo, Profiles, BUILD_LOCK,
};
use crate::reseal::{check_passphrase, kdf_code};
use crate::settings::{self, ProfileSettings, ReviewItem};
use crate::store::{Core, CoreOpen, ProfilePart};
use crate::{Error, Head, Step};
use base64::Engine;
use scaas_ua::wallet::{Argon2Params, ExportKey, ProfileKeys};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, PoisonError};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"SCAASPX1";
const FORMAT: &str = "scaas.profile-export";
const CHUNK: usize = ExportKey::CHUNK;
/// A sealed chunk's length on disk (its 16-byte tag).
const STEP: usize = CHUNK + 16;
/// The payload's bound (spec §10.1): 64 MiB.
const PAYLOAD_MAX: usize = 64 * CHUNK;
/// The longest file: the header's bound and 64 full chunks.
pub const FILE_MAX: usize = 12 + ExportKey::HEADER_MAX + 64 * STEP;
/// The items of an export, in their order (spec §10.1).
const ITEMS: [&str; 2] = ["keystore", "sdk.state"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    format: String,
    v: u64,
    kdf: Kdf,
    nonce_prefix: String,
    chunk: u64,
}

/// An import's file: a path (read up to [`FILE_MAX`]) or its bytes.
pub enum ImportSource<'a> {
    Path(&'a Path),
    Bytes(&'a [u8]),
}

/// An opened export (spec §10.1 "Import is two calls"): its label, its settings and its items, held in memory only and wiped
/// at drop. No `Debug`.
pub struct ImportReview {
    name: Zeroizing<String>,
    hidden: bool,
    /// the settings JSON as the file holds it (checked by `ProfileSettings::parse` at the preview), wiped at drop
    settings: Zeroizing<Vec<u8>>,
    items: Vec<(&'static str, Zeroizing<Vec<u8>>)>,
}

impl ImportReview {
    /// The profile's name as the file holds it.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn hidden(&self) -> bool {
        self.hidden
    }

    /// Every setting, each with its item id and whether it is kept without a confirm (credential references never listed).
    pub fn settings(&self) -> Vec<ReviewItem> {
        ProfileSettings::parse(&self.settings)
            .map(|s| settings::review(&s))
            .unwrap_or_default()
    }

    /// The item `name` (`keystore`, `sdk.state`) when the file holds it.
    pub fn item(&self, name: &str) -> Option<&[u8]> {
        self.items
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| &b[..])
    }

    /// Replaces the bytes of an item the file holds (the SDK's `sdk.state` with its operations marked `imported`); `Argument`
    /// for an item it does not hold, above 16 MiB or without a JSON `rev`.
    pub fn set_item(&mut self, name: &str, bytes: Zeroizing<Vec<u8>>) -> Result<(), Error> {
        let at = self.items.iter_mut().find(|(n, _)| *n == name);
        match at {
            Some((_, b)) if bytes.len() <= MAX_BYTES && rev_of(&bytes) != u64::MAX => {
                *b = bytes;
                Ok(())
            }
            _ => Err(Error::Argument),
        }
    }
}

/// A refusal and its local reason (the reasons of clientkeys `importFile`, plus `settings`).
type Refusal = (Error, &'static str);

fn no(reason: &'static str) -> Refusal {
    (Error::ProfileImportOpen, reason)
}

fn be32(n: usize) -> Result<[u8; 4], Error> {
    u32::try_from(n)
        .map(u32::to_be_bytes)
        .map_err(|_| Error::Argument)
}

fn header_bytes(kdf: &Kdf, prefix: &[u8; 7]) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&Header {
        format: FORMAT.into(),
        v: 1,
        kdf: kdf.clone(),
        nonce_prefix: B64.encode(prefix),
        chunk: CHUNK as u64,
    })
    .map_err(|_| Error::Argument)
}

/// The payload of `label`, `settings` and `items` (spec §10.1), in one allocation.
fn payload(
    label: &[u8],
    settings: &[u8],
    items: &[(&str, &[u8])],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let len = items
        .iter()
        .fold(10 + label.len() + settings.len(), |a, (n, b)| {
            a.saturating_add(6 + n.len() + b.len())
        });
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(&be32(label.len())?);
    out.extend_from_slice(label);
    out.extend_from_slice(&be32(settings.len())?);
    out.extend_from_slice(settings);
    let count = u16::try_from(items.len()).map_err(|_| Error::Argument)?;
    out.extend_from_slice(&count.to_be_bytes());
    for (n, b) in items {
        let nl = u16::try_from(n.len()).map_err(|_| Error::Argument)?;
        out.extend_from_slice(&nl.to_be_bytes());
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(&be32(b.len())?);
        out.extend_from_slice(b);
    }
    Ok(out)
}

/// The file of `payload` under `pass` at `kdf` (its salt in `kdf`) and nonce prefix `prefix`: above 64 MiB
/// `ProfileExportTooLarge` before the KDF; the KDF in the heavy limiter.
fn seal_file(
    heavy: &Heavy,
    payload: &[u8],
    pass: &[u8],
    kdf: &Kdf,
    argon: Argon2Params,
    salt: &[u8],
    prefix: &[u8; 7],
) -> Result<Vec<u8>, Error> {
    if payload.len() > PAYLOAD_MAX {
        return Err(Error::ProfileExportTooLarge);
    }
    if payload.is_empty() {
        return Err(Error::Argument);
    }
    let header = header_bytes(kdf, prefix)?;
    let kx = {
        let _h = heavy.acquire();
        ExportKey::derive(pass, salt, argon).map_err(kdf_code)?
    };
    let n = payload.len().div_ceil(CHUNK);
    let mut out = Vec::with_capacity(12 + header.len() + payload.len() + 16 * n);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&be32(header.len())?);
    out.extend_from_slice(&header);
    for (i, pt) in payload.chunks(CHUNK).enumerate() {
        let k = u32::try_from(i).map_err(|_| Error::Argument)?;
        let c = kx
            .seal_chunk(prefix, k, i + 1 == n, &header, pt)
            .map_err(kdf_code)?;
        out.extend_from_slice(&c);
    }
    Ok(out)
}

/// The payload of `file` under `pass` (spec §10.1): the header and the length before the KDF, then every chunk verified
/// before the caller parses any byte.
fn open_file(
    heavy: &Heavy,
    max_kib: u32,
    file: &[u8],
    pass: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    if file.len() < 12 {
        return Err(no("truncated"));
    }
    if file.get(..8) != Some(&MAGIC[..]) {
        return Err(no("magic"));
    }
    let hl: [u8; 4] = file
        .get(8..12)
        .and_then(|b| b.try_into().ok())
        .ok_or(no("truncated"))?;
    let hl = u32::from_be_bytes(hl) as usize;
    if hl > ExportKey::HEADER_MAX {
        return Err(no("header_len"));
    }
    let header = file.get(12..12 + hl).ok_or(no("truncated"))?;
    if scaas_ua::json::depth_within(header, 2).is_err() {
        return Err(no("header"));
    }
    let h: Header = serde_json::from_slice(header).map_err(|_| no("header"))?;
    if h.format != FORMAT {
        return Err(no("format"));
    }
    if h.v != 1 {
        return Err(no("version"));
    }
    if h.chunk != CHUNK as u64 {
        return Err(no("chunk"));
    }
    let (argon, salt) = h.kdf.check(max_kib).map_err(|e| match e {
        Error::ProfileKdfTooLarge => (e, "kdf"),
        _ => no("kdf"),
    })?;
    let prefix: [u8; 7] = B64
        .decode(&h.nonce_prefix)
        .ok()
        .and_then(|p| p.try_into().ok())
        .ok_or(no("header"))?;
    if header_bytes(&h.kdf, &prefix).ok().as_deref() != Some(header) {
        return Err(no("header"));
    }
    let body = file.get(12 + hl..).unwrap_or_default();
    if body.len() > 64 * STEP {
        return Err(no("size"));
    }
    let n = body.len().div_ceil(STEP);
    if n == 0 || body.len() - (n - 1) * STEP < 17 {
        return Err(no("truncated"));
    }
    let kx = {
        let _h = heavy.acquire();
        ExportKey::derive(pass, &salt, argon).map_err(|e| match e {
            scaas_ua::wallet::Error::KdfOutOfMemory => (Error::ProfileKdfOutOfMemory, "kdf"),
            _ => no("kdf"),
        })?
    };
    let mut pl = Zeroizing::new(Vec::with_capacity(body.len()));
    for (i, c) in body.chunks(STEP).enumerate() {
        let k = u32::try_from(i).map_err(|_| no("size"))?;
        let pt = kx
            .open_chunk(&prefix, k, i + 1 == n, header, c)
            .map_err(|_| no("tag"))?;
        pl.extend_from_slice(&pt);
    }
    Ok(pl)
}

/// A reader over the payload: a read past its end is `payload`.
struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let end = self.o.checked_add(n).ok_or(no("payload"))?;
        let s = self.b.get(self.o..end).ok_or(no("payload"))?;
        self.o = end;
        Ok(s)
    }

    fn be(&mut self, n: usize) -> Result<usize, Refusal> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0usize, |a, c| (a << 8) | usize::from(*c)))
    }

    fn field(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let len = self.be(n)?;
        self.take(len)
    }
}

/// The opened payload as a review: the label canonical (`label`), the items by name and order (`item`), no byte after the
/// last (`payload`); the settings parse and their shown strings pass the name helper (`settings`), each item at most 16 MiB
/// with a top-level JSON `rev` (`item`).
fn parse_payload(pl: &[u8]) -> Result<ImportReview, Refusal> {
    let mut r = Reader { b: pl, o: 0 };
    let label = r.field(4)?;
    let l: Label = serde_json::from_slice(label).map_err(|_| no("label"))?;
    let name = Zeroizing::new(l.name);
    let canonical = label_json(&name, l.hidden);
    let ok =
        canonical.is_ok_and(|c| c[..] == *label) && check_name(&name).is_ok_and(|n| n == *name);
    if !ok {
        return Err(no("label"));
    }
    let settings = r.field(4)?;
    let count = r.be(2)?;
    let (mut items, mut next) = (Vec::new(), 0);
    for _ in 0..count {
        let n = std::str::from_utf8(r.field(2)?).map_err(|_| no("item"))?;
        let at = ITEMS
            .get(next..)
            .and_then(|rest| rest.iter().position(|i| *i == n))
            .ok_or(no("item"))?;
        next += at + 1;
        let b = r.field(4)?;
        let name = ITEMS.get(next - 1).copied().ok_or(no("item"))?;
        items.push((name, Zeroizing::new(b.to_vec())));
    }
    if r.o != pl.len() {
        return Err(no("payload"));
    }
    ProfileSettings::parse(settings)
        .and_then(|s| s.check_shown())
        .map_err(|_| no("settings"))?;
    // an item the store cannot keep: above 16 MiB, or without a top-level JSON `rev` (review A-17)
    if items
        .iter()
        .any(|(_, b)| b.len() > MAX_BYTES || rev_of(b) == u64::MAX)
    {
        return Err(no("item"));
    }
    // spec §10.1: operations in flight are imported marked `imported`, followed only on the user's word (review E-3: here,
    // so an app without the SDK imports them so too)
    for (n, b) in &mut items {
        if *n == "sdk.state" {
            *b = mark_imported(b)?;
        }
    }
    Ok(ImportReview {
        name,
        hidden: l.hidden,
        settings: Zeroizing::new(settings.to_vec()),
        items,
    })
}

/// A JSON value whose objects keep their keys' order as read (serde_json's `Map` sorts them unless its `preserve_order`
/// feature is on, which would reach the SDK's graph), so `sdk.state` is written back in the SDK's own order (controller call
/// 2026-11-28). A key twice is written back as read (the SDK's parser of the item refuses a field twice).
enum Ordered {
    Object(Vec<(String, Ordered)>),
    Array(Vec<Ordered>),
    Leaf(serde_json::Value),
}

impl<'de> serde::Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(v.into()))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(v.into()))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(v.into()))
            }
            fn visit_str<E>(self, v: &str) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(v.into()))
            }
            fn visit_unit<E>(self) -> Result<Ordered, E> {
                Ok(Ordered::Leaf(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Ordered, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element()? {
                    v.push(x);
                }
                Ok(Ordered::Array(v))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Ordered, A::Error> {
                let mut v = Vec::new();
                while let Some(e) = a.next_entry()? {
                    v.push(e);
                }
                Ok(Ordered::Object(v))
            }
        }
        d.deserialize_any(V)
    }
}

impl serde::Serialize for Ordered {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            Ordered::Leaf(v) => v.serialize(s),
            Ordered::Array(v) => s.collect_seq(v),
            Ordered::Object(v) => {
                let mut m = s.serialize_map(Some(v.len()))?;
                for (k, x) in v {
                    m.serialize_entry(k, x)?;
                }
                m.end()
            }
        }
    }
}

/// The field `key` of an object.
fn field<'a>(v: &'a mut Ordered, key: &str) -> Option<&'a mut Ordered> {
    match v {
        Ordered::Object(f) => f.iter_mut().find(|(k, _)| k == key).map(|(_, x)| x),
        _ => None,
    }
}

/// `sdk.state` with every operation a chain fact has not ended (`landed`, `reverted`, `consumed`, `expired`) marked
/// `imported` in its `state`: none is sent or followed without the user's word. Its keys keep their order (the SDK's own:
/// `rev` first). A state of no such form (`ops`, each with a string `state`) is refused (`item`).
// ponytail: the parsed strings are plain heap copies, freed unwiped, as the SDK's parse of the same item
fn mark_imported(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    use serde_json::Value;
    if scaas_ua::json::depth_within(bytes, 64).is_err() {
        return Err(no("item"));
    }
    let mut v: Ordered = serde_json::from_slice(bytes).map_err(|_| no("item"))?;
    let Some(Ordered::Array(ops)) = field(&mut v, "ops") else {
        return Err(no("item"));
    };
    for op in ops {
        let Some(Ordered::Leaf(Value::String(s))) = field(op, "state") else {
            return Err(no("item"));
        };
        match s.as_str() {
            "landed" | "reverted" | "consumed" | "expired" => {}
            _ => *s = "imported".into(),
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() + 64 * 8));
    serde_json::to_writer(&mut *out, &v).map_err(|_| no("item"))?;
    Ok(out)
}

/// `bytes` to a new file `target` (`O_CREAT | O_EXCL`, mode `0600`): an existing file or a symlink there is `Argument`; the
/// file removed on a failure.
fn write_new(target: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = match o.open(target) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(Error::Argument),
        Err(_) => return Err(Error::VaultIo),
    };
    if f.write_all(bytes).and_then(|()| f.sync_all()).is_err() {
        drop(f);
        let _ = std::fs::remove_file(target);
        return Err(Error::VaultIo);
    }
    Ok(())
}

/// A new `kdf` with a fresh salt.
fn fresh_kdf(kdf: Option<KdfParams>) -> Result<Kdf, Error> {
    let k = kdf.unwrap_or(KdfParams::DEFAULT);
    Ok(Kdf {
        alg: "argon2id".into(),
        v: 1,
        m: k.m_kib.into(),
        t: k.t.into(),
        p: 4,
        salt: B64.encode(random::<16>()?),
    })
}

impl OpenProfile {
    /// Exports this profile to a new file at `target` (spec §10.1): protected (`ProfilePassphraseRequired`), `confirm_name` its
    /// name typed again (`ConfirmationMissing`), `export_pass` under the profile passphrase's rule (`ProfilePassphraseWeak`),
    /// `kdf` (default 64 MiB / 3) within the bounds (`ProfileFormat`, `ProfileKdfTooLarge`), all before any KDF; then
    /// `profile_pass` checked against the `pass` wrap (`ProfileOpen`). The payload: the label (name, hidden flag), the
    /// settings without credential references, `keystore` and `sdk.state`.
    pub fn export(
        &self,
        confirm_name: &[u8],
        profile_pass: &[u8],
        export_pass: &[u8],
        kdf: Option<KdfParams>,
        target: &Path,
    ) -> Result<(), Error> {
        self.core.live()?;
        let info = self.info();
        if !info.protected {
            return Err(Error::ProfilePassphraseRequired);
        }
        if !std::str::from_utf8(confirm_name).is_ok_and(|t| same_name(&info.name, t)) {
            return Err(Error::ConfirmationMissing);
        }
        check_passphrase(export_pass)?;
        let k = fresh_kdf(kdf)?;
        let (argon, salt) = k.check(self.kdf_max_kib)?;
        let (env, _) = read_envelope(self.core.dir(), &info.id)?.ok_or(Error::ProfileFormat)?;
        self.check_pass(&env, profile_pass)?;
        let label = label_json(&info.name, info.hidden)?;
        let mut s = self.settings()?;
        s.credentials.clear();
        let mut items = Vec::new();
        for n in ITEMS {
            if let Some((pt, _)) = self.core.get(ProfilePart::Sdk, n)? {
                items.push((n, pt));
            }
        }
        let refs: Vec<(&str, &[u8])> = items.iter().map(|(n, b)| (*n, &b[..])).collect();
        let pl = payload(&label, &s.json()?, &refs)?;
        let bytes = seal_file(&self.heavy, &pl, export_pass, &k, argon, &salt, &random()?)?;
        write_new(target, &bytes)
    }
}

impl Profiles {
    /// Opens an export (spec §10.1, the first call): read and verified whole in memory, nothing written, no lock taken. Every
    /// refusal is `ProfileImportOpen` (its reason: [`Profiles::last_import_refusal`]) but `ProfileKdfTooLarge` and
    /// `ProfileKdfOutOfMemory`; a path that does not exist `Argument`.
    pub fn import_preview(
        &self,
        source: ImportSource<'_>,
        export_pass: &[u8],
    ) -> Result<ImportReview, Error> {
        let r = self.preview(source, export_pass);
        *self.refusal.lock().unwrap_or_else(PoisonError::into_inner) =
            r.as_ref().err().map(|(_, why)| *why);
        r.map_err(|(e, _)| e)
    }

    fn preview(&self, source: ImportSource<'_>, pass: &[u8]) -> Result<ImportReview, Refusal> {
        let read;
        let file = match source {
            ImportSource::Bytes(b) => b,
            ImportSource::Path(p) => {
                read = read_bounded(p, FILE_MAX)
                    .map_err(|e| (e, "read"))?
                    .ok_or((Error::Argument, "read"))?
                    .ok_or(no("size"))?;
                &read[..]
            }
        };
        let pl = open_file(&self.heavy, self.kdf_max_kib, file, pass)?;
        parse_payload(&pl)
    }

    /// The local reason of the last refused `import_preview` (a log line's; never shown to the user).
    pub fn last_import_refusal(&self) -> Option<&'static str> {
        *self.refusal.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Imports the reviewed profile (spec §10.1, the second call): `name` (default the file's), `passphrase` under its rule
    /// (`ProfilePassphraseWeak`), `kdf` (default 64 MiB / 3) and room (`ProfileLimit`, `ProfileHiddenLimit`) before any KDF; a
    /// hidden one's duplicate search (`ProfileNameTaken`); then a new profile sealed from its first byte in `p/.tmp-<random>/`
    /// (its `build.lock` held) with the settings [`settings::filter`] keeps of `confirmed` and the items, committed under the
    /// root lock (`ProfileNameTaken` for a visible name taken). Returns it, not open.
    pub fn import(
        &self,
        review: &ImportReview,
        confirmed: &[u32],
        passphrase: &[u8],
        name: Option<&[u8]>,
        kdf: Option<KdfParams>,
    ) -> Result<ProfileInfo, Error> {
        let name = Zeroizing::new(match name {
            Some(n) => check_name(std::str::from_utf8(n).map_err(|_| Error::ProfileNameInvalid)?)?,
            None => review.name.to_string(),
        });
        let hidden = review.hidden;
        check_passphrase(passphrase)?;
        let k = fresh_kdf(kdf)?;
        let (argon, salt) = k.check(self.kdf_max_kib)?;
        self.room(true, hidden)?;
        if hidden {
            taken(
                search(&self.p, &self.heavy, self.kdf_max_kib, &name, passphrase)?,
                "",
            )?;
        }
        let settings =
            settings::filter(&ProfileSettings::parse(&review.settings)?, confirmed).json()?;
        let id = new_id()?;
        let mut env = Envelope {
            state: State::Protected,
            gen: 1,
            name: (!hidden).then(|| name.to_string()),
            kdf: Some(k),
            ..Envelope::unprotected(&id, "")
        };
        let keys = Arc::new(ProfileKeys::new());
        let built = (|| {
            keys.create_dek().map_err(kdf_code)?;
            env.label = Some(seal_label(&keys, &id, env.rev, &name, hidden)?);
            let wrap = {
                let _h = self.heavy.acquire();
                keys.wrap_pass(passphrase, &salt, argon, &env.public_json()?)
                    .map_err(kdf_code)?
            };
            env.pass = Some(B64.encode(wrap));
            env.json()
        })();
        let bytes = built.inspect_err(|_| keys.lock())?;
        let tmp = self.new_tmp()?;
        let build = lock_file(&tmp.join(BUILD_LOCK));
        let written = build.and_then(|build| {
            file::write(&tmp, &tmp.join(envelope::FILE), &bytes)?;
            let core = Core::open(CoreOpen {
                dir: tmp.clone(),
                id: id.clone(),
                gen: 1,
                keys: Some(keys.clone()),
                keychain: None,
                envelope: Head::of(env.rev, &bytes),
                migration_pending: false,
            })?;
            core.put_if(ProfilePart::Sdk, settings::ITEM, None, &settings)?;
            for (n, b) in &review.items {
                core.put_if(ProfilePart::Sdk, n, None, b)?;
            }
            Ok(build)
        });
        keys.lock();
        let build = written.inspect_err(|_| {
            let _ = remove_dir(&tmp);
        })?;
        // a test's stop here leaves the directory as a crash would (its `build.lock` released with the process)
        self.died(Step::ImportBuilt)?;
        let committed = self
            .root_lock()
            .and_then(|_root| self.commit_create(&tmp, &id, (!hidden).then_some(name.as_str())));
        drop(build);
        committed.inspect_err(|_| {
            let _ = remove_dir(&tmp);
        })?;
        Ok(ProfileInfo {
            id,
            name: name.to_string(),
            protected: true,
            hidden,
        })
    }
}

/// Test-only entry points (feature `test-hooks`, never in a release build): a file of a given payload, salt and nonce prefix
/// (the vectors' rows), and a file's payload.
#[cfg(feature = "test-hooks")]
impl Profiles {
    /// The payload of `label` (its bytes as given), `settings` and `items`.
    pub fn test_payload(
        label: &[u8],
        settings: &[u8],
        items: &[(&str, &[u8])],
    ) -> Result<Vec<u8>, Error> {
        payload(label, settings, items).map(|p| p.to_vec())
    }

    /// The file of `payload` under `pass` at `kdf` with `salt` and `prefix`.
    pub fn test_export(
        &self,
        payload: &[u8],
        pass: &[u8],
        kdf: KdfParams,
        salt: &[u8; 16],
        prefix: &[u8; 7],
    ) -> Result<Vec<u8>, Error> {
        let k = Kdf {
            salt: B64.encode(salt),
            ..fresh_kdf(Some(kdf))?
        };
        let (argon, salt) = k.check(self.kdf_max_kib)?;
        seal_file(&self.heavy, payload, pass, &k, argon, &salt, prefix)
    }

    /// The payload of `file` under `pass` (no parse).
    pub fn test_open(&self, file: &[u8], pass: &[u8]) -> Result<Vec<u8>, Error> {
        open_file(&self.heavy, self.kdf_max_kib, file, pass)
            .map(|p| p.to_vec())
            .map_err(|(e, _)| e)
    }
}
