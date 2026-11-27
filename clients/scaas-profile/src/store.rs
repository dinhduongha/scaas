// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The sealed store of one open profile (spec §5, §7.1 "Refusals by state", §7.2, §7.3 step 1; plan pinned formats 6 to 8):
//! one synchronous [`Core`] (file I/O and AEAD are blocking work) holding the store write lock, the manifests of every part
//! and the anchor; the SDK puts its `SecureStore` face over it (on `spawn_blocking`).
//!
//! - A protected profile's generation `g<N>/` holds `<64 hex>` (an item or a manifest: `{"rev":N,"sealed":"<base64>"}`,
//!   sealed in `scaas-ua` under `K_item`, AD over (part, name, rev); the name `hex(HMAC(K_name, lp(part) ‖ lp(name)))`),
//!   `<64 hex>.lock` and `<64 hex>.tmp.<pid>.<n>` (removed at open); any other file is `VaultFormat`.
//! - Each part's manifest is the item `manifest:<part>` of the reserved part `profile`: every `(name, rev)` and a tombstone
//!   per deleted name. The stored rev is the tombstone's plus the caller's revision (the plaintext's JSON `rev`, which the
//!   face shows), so a re-created item is never a false rollback.
//! - A write takes the store write lock (at most 120 s, then `ProfileBusy`, nothing written), writes the item (`put_if`), the
//!   manifest (`put_if` at its read rev, three tries, then `StoreConflict`), then the anchor; a delete writes the tombstone
//!   first, then removes the file.
//! - A read below its manifest, or at or below its tombstone, is `ProfileRollback` (writes to it too; the event is the
//!   caller's); above it, a crash between the two writes, and the manifest is brought forward; listed but missing is
//!   `ProfileDamaged`. At open the anchor (`profile.head`, and the keychain's `scaas.profile.<id>.head`) is compared with
//!   what is stored: `follow` rewrites it, `rollback` refuses the open (`ProfileRollback`).
//! - The unprotected `g0/` has no key: plain names, part `sdk`, `settings` only (`keystore`, `keystore.prev`, `sdk.state` as
//!   well under `migration: pending`), no manifest; a sealed item in it is `ProfileFormat`, a write of anything else
//!   `ProfilePassphraseRequired`.
//! - A re-seal (spec §7.3, `reseal.rs`) holds the store write lock for its whole run (it is not re-entrant: the new
//!   generation's files and manifests are written directly, not through `put_if`), and its commit swaps the generation and
//!   its keys behind an `RwLock`: a writer that waited then writes into `g<N+1>/` under the new keys; a reader holds the
//!   generation for its whole call, so none reads from a `g<N>/` being removed.
//!
//! The core's codes are [`Error`]s, each the SDK's code of the same name; the SDK's face gives the store's (CLI-UPR-22).
use crate::anchor::{Anchor, Head, Verdict};
use crate::file::{self, lock_file, rev_of, sealed_form, MAX_BYTES, REV_MAX, SEALED_MAX};
use crate::{keychain_name, Error, ProfileKeychain};
use base64::Engine;
use scaas_ua::wallet::ProfileKeys;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock, RwLockReadGuard};
use std::time::Duration;
use zeroize::Zeroizing;

/// An item's plaintext, wiped at drop.
pub type Plain = Zeroizing<Vec<u8>>;
/// An item's plaintext and the caller's revision of it (its JSON `rev`).
pub type Item = (Plain, u64);

/// The reserved part of the manifests; no store may use it.
const PROFILE: &str = "profile";
/// Entries of one part's manifest, tombstones included (`ProfilePartFull` above).
pub const PART_MAX: usize = 65_536;
const TRIES: usize = 3;
/// A writer's wait for the store write lock (spec §7.3 step 1).
const WAIT: Duration = Duration::from_secs(120);
pub(crate) const ANCHOR_FILE: &str = "profile.head";
const MANIFEST_FORMAT: &str = "scaas.profile-manifest";
/// The items of an unprotected `g0` outside `settings`: a migrated "default" only (spec §5, §12).
const LEGACY: [&str; 3] = ["keystore", "keystore.prev", "sdk.state"];
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A store part (spec §7.2): `profile`, the manifests' part, is none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePart {
    Sdk,
    PqChat,
    PqVault,
}

impl ProfilePart {
    pub const ALL: [ProfilePart; 3] = [ProfilePart::Sdk, ProfilePart::PqChat, ProfilePart::PqVault];

    pub fn name(self) -> &'static str {
        match self {
            ProfilePart::Sdk => "sdk",
            ProfilePart::PqChat => "pqchat",
            ProfilePart::PqVault => "pqvault",
        }
    }
}

/// A part's manifest (pinned format 7): every item's stored rev and every deleted name's last rev; a name in one list at most.
/// No `Debug`: the names are private.
#[derive(Default, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub rev: u64,
    pub items: BTreeMap<String, u64>,
    pub tombstones: BTreeMap<String, u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestJson {
    format: String,
    v: u64,
    part: String,
    rev: u64,
    items: Vec<(String, u64)>,
    tombstones: Vec<(String, u64)>,
}

impl Manifest {
    /// From its lists: a name twice is `ProfileFormat`, more than 65,536 entries `ProfilePartFull`.
    pub fn from_lists(
        rev: u64,
        items: Vec<(String, u64)>,
        tombstones: Vec<(String, u64)>,
    ) -> Result<Manifest, Error> {
        if items.len() + tombstones.len() > PART_MAX {
            return Err(Error::ProfilePartFull);
        }
        let mut m = Manifest {
            rev,
            ..Manifest::default()
        };
        for (n, r) in items {
            if m.items.insert(n, r).is_some() {
                return Err(Error::ProfileFormat);
            }
        }
        for (n, r) in tombstones {
            if m.items.contains_key(&n) || m.tombstones.insert(n, r).is_some() {
                return Err(Error::ProfileFormat);
            }
        }
        Ok(m)
    }

    fn len(&self) -> usize {
        self.items.len() + self.tombstones.len()
    }

    /// The canonical plaintext of part `part`'s manifest; each list sorted by the name's UTF-8 bytes.
    pub fn json(&self, part: &str) -> Result<Vec<u8>, Error> {
        if self.len() > PART_MAX {
            return Err(Error::ProfilePartFull);
        }
        let list = |m: &BTreeMap<String, u64>| m.iter().map(|(n, r)| (n.clone(), *r)).collect();
        serde_json::to_vec(&ManifestJson {
            format: MANIFEST_FORMAT.into(),
            v: 1,
            part: part.into(),
            rev: self.rev,
            items: list(&self.items),
            tombstones: list(&self.tombstones),
        })
        .map_err(|_| Error::Argument)
    }

    /// The opened plaintext of part `part`'s manifest item at stored rev `rev`: anything else is `VaultFormat`.
    pub fn parse(part: &str, rev: u64, pt: &[u8]) -> Result<Manifest, Error> {
        if scaas_ua::json::depth_within(pt, 3).is_err() {
            return Err(Error::VaultFormat);
        }
        let j: ManifestJson = serde_json::from_slice(pt).map_err(|_| Error::VaultFormat)?;
        if j.format != MANIFEST_FORMAT || j.v != 1 || j.part != part || j.rev != rev || rev > REV_MAX
        {
            return Err(Error::VaultFormat);
        }
        Manifest::from_lists(rev, j.items, j.tombstones).map_err(|_| Error::VaultFormat)
    }
}

/// An item file (pinned format 6).
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemJson {
    rev: u64,
    sealed: String,
}

fn item_json(rev: u64, sealed: &[u8]) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&ItemJson {
        rev,
        sealed: B64.encode(sealed),
    })
    .map_err(|_| Error::Argument)
}

/// A sealed item file's rev and `sealed` bytes; `None` when absent; a file of any other form `VaultFormat`.
fn read_sealed(p: &Path) -> Result<Option<(u64, Vec<u8>)>, Error> {
    let Some((_, bytes)) = file::read(p)? else {
        return Ok(None);
    };
    if bytes.len() > SEALED_MAX || scaas_ua::json::depth_within(&bytes, 1).is_err() {
        return Err(Error::VaultFormat);
    }
    let j: ItemJson = serde_json::from_slice(&bytes).map_err(|_| Error::VaultFormat)?;
    let sealed = B64.decode(j.sealed).map_err(|_| Error::VaultFormat)?;
    Ok(Some((j.rev, sealed)))
}

/// The SDK FileStore's `put_if` on one file: replaced only at the expected rev (`None`: absent), else `StoreConflict`.
fn put_file_if(dir: &Path, p: &Path, prev: Option<u64>, bytes: &[u8]) -> Result<(), Error> {
    if file::read(p)?.map(|(rev, _)| rev) != prev {
        return Err(Error::StoreConflict);
    }
    file::write(dir, p, bytes)
}

/// The profile arena's refusal: locked is `ProfileLocked`, a seal that does not open `VaultFormat`.
fn ua(e: scaas_ua::wallet::Error) -> Error {
    match e {
        scaas_ua::wallet::Error::WalletLocked => Error::ProfileLocked,
        scaas_ua::wallet::Error::Argument => Error::Argument,
        _ => Error::VaultFormat,
    }
}

fn manifest_name(part: ProfilePart) -> String {
    format!("manifest:{}", part.name())
}

/// What a protected generation may hold (spec §5).
enum Kind {
    Item,
    Lock,
    Temp,
}

fn kind(name: &str) -> Option<Kind> {
    let (hex, rest) = (name.get(..64)?, name.get(64..)?);
    if !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    match rest {
        "" => Some(Kind::Item),
        ".lock" => Some(Kind::Lock),
        _ => {
            let (pid, n) = rest.strip_prefix(".tmp.")?.split_once('.')?;
            (digits(pid) && digits(n)).then_some(Kind::Temp)
        }
    }
}

/// Open-time check of a protected generation (under the instance lock): temporaries removed, any other name `VaultFormat`.
fn scan(gdir: &Path) -> Result<(), Error> {
    for e in std::fs::read_dir(gdir).map_err(|_| Error::VaultIo)? {
        let e = e.map_err(|_| Error::VaultIo)?;
        let file = e.file_type().map_err(|_| Error::VaultIo)?.is_file();
        match e.file_name().to_str().and_then(kind) {
            Some(Kind::Temp) if file => {
                std::fs::remove_file(e.path()).map_err(|_| Error::VaultIo)?
            }
            Some(Kind::Item | Kind::Lock) if file => {}
            _ => return Err(Error::VaultFormat),
        }
    }
    Ok(())
}

struct WriteLock {
    held: Mutex<bool>,
    free: Condvar,
    wait_ms: AtomicU64,
}

/// The store write lock, held until drop (spec §7.3 step 1: a re-seal holds it for its whole run).
pub struct WriteGuard(Arc<WriteLock>);

impl Drop for WriteGuard {
    fn drop(&mut self) {
        *self.0.held.lock().unwrap_or_else(PoisonError::into_inner) = false;
        self.0.free.notify_one();
    }
}

/// What [`Core::open`] takes: the profile's directory (`p/<id>/`, under its instance lock), its id (the keychain's names
/// only), the envelope's `gen`, rev and hash, the profile arena (`None`: unprotected, `g0`), the keychain, and whether the
/// envelope says `migration: pending`.
pub struct CoreOpen {
    pub dir: PathBuf,
    pub id: String,
    pub gen: u64,
    pub keys: Option<Arc<ProfileKeys>>,
    pub keychain: Option<Arc<dyn ProfileKeychain>>,
    pub envelope: Head,
    pub migration_pending: bool,
}

/// The generation the store reads and writes: its number, directory and keys (`None`: the unprotected `g0`). A re-seal's
/// commit swaps it under the store write lock (spec §7.3 step 4), so a writer that waited on that lock writes into the new
/// generation under the new keys; a reader holds it for its whole call, so no read meets a generation being removed.
pub(crate) struct Gen {
    pub(crate) gen: u64,
    pub(crate) gdir: PathBuf,
    pub(crate) keys: Option<Arc<ProfileKeys>>,
}

impl Gen {
    fn file(&self, keys: &ProfileKeys, part: &str, name: &str) -> Result<PathBuf, Error> {
        Ok(self.gdir.join(keys.item_file(part, name).map_err(ua)?))
    }
}

/// The sealed store core of one open profile. Every call is blocking work (files, AEAD, the keychain): run it on a blocking
/// thread. No `Debug`.
pub struct Core {
    dir: PathBuf,
    cur: RwLock<Gen>,
    keychain: Option<(Arc<dyn ProfileKeychain>, String)>,
    envelope: Mutex<Head>,
    migration_pending: bool,
    lock: Arc<WriteLock>,
    /// set at the profile's lock: every later call is `ProfileLocked`
    closed: AtomicBool,
    #[cfg(feature = "test-hooks")]
    hook: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(feature = "test-hooks")]
    calls: AtomicU64,
}

impl Core {
    /// Opens the generation (created, `0700`, if missing), checks a protected one's files, and compares the anchor: `follow`
    /// rewrites it, `rollback` is `ProfileRollback`. An unprotected profile with a generation other than `g0`, or a protected
    /// one with `g0`, is `ProfileFormat`.
    pub fn open(o: CoreOpen) -> Result<Core, Error> {
        if o.keys.is_some() == (o.gen == 0) {
            return Err(Error::ProfileFormat);
        }
        let gdir = o.dir.join(format!("g{}", o.gen));
        file::mkdir(&gdir)?;
        if o.keys.is_some() {
            scan(&gdir)?;
        }
        let core = Core {
            cur: RwLock::new(Gen {
                gen: o.gen,
                gdir,
                keys: o.keys,
            }),
            keychain: o.keychain.map(|k| (k, keychain_name(&o.id, "head"))),
            envelope: Mutex::new(o.envelope),
            migration_pending: o.migration_pending,
            dir: o.dir,
            lock: Arc::new(WriteLock {
                held: Mutex::new(false),
                free: Condvar::new(),
                wait_ms: AtomicU64::new(WAIT.as_secs() * 1000),
            }),
            closed: AtomicBool::new(false),
            #[cfg(feature = "test-hooks")]
            hook: Mutex::new(None),
            #[cfg(feature = "test-hooks")]
            calls: AtomicU64::new(0),
        };
        core.check_anchor()?;
        Ok(core)
    }

    fn cur(&self) -> RwLockReadGuard<'_, Gen> {
        self.cur.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The profile's directory (`p/<id>/`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether the profile is protected now (a sealed generation): an unprotected one becomes so at `set_passphrase`'s commit.
    pub fn protected(&self) -> bool {
        self.cur().keys.is_some()
    }

    /// Whether the profile was opened with `migration: pending` (spec §12: a migrated "default" until its seal).
    pub fn migration_pending(&self) -> bool {
        self.migration_pending
    }

    /// The current generation's number.
    pub(crate) fn gen(&self) -> u64 {
        self.cur().gen
    }

    /// The profile arena of the current generation; `None` while unprotected.
    pub fn keys(&self) -> Option<Arc<ProfileKeys>> {
        self.cur().keys.clone()
    }

    /// Closes the store for good (the profile's lock, spec §10): every later call is `ProfileLocked`.
    pub fn close(&self) {
        self.closed.store(true, SeqCst);
    }

    /// `ProfileLocked` once the store is closed (the SDK's face checks it on the `keystore.head` it passes through).
    pub fn live(&self) -> Result<(), Error> {
        #[cfg(feature = "test-hooks")]
        self.calls.fetch_add(1, SeqCst);
        match self.closed.load(SeqCst) {
            true => Err(Error::ProfileLocked),
            false => Ok(()),
        }
    }

    /// The store write lock, which every writer of every part takes: waits at most 120 s, then `ProfileBusy`.
    pub fn write_lock(&self) -> Result<WriteGuard, Error> {
        self.live()?;
        let l = &self.lock;
        let wait = Duration::from_millis(l.wait_ms.load(SeqCst));
        let held = l.held.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut held, _) = l
            .free
            .wait_timeout_while(held, wait, |h| *h)
            .unwrap_or_else(PoisonError::into_inner);
        if *held {
            return Err(Error::ProfileBusy);
        }
        *held = true;
        Ok(WriteGuard(l.clone()))
    }

    /// The item `name` of `part` and the caller's revision (its JSON `rev`), `None` when absent.
    pub fn get(&self, part: ProfilePart, name: &str) -> Result<Option<Item>, Error> {
        self.live()?;
        {
            let g = self.cur();
            let Some(keys) = &g.keys else {
                return self.plain_get(&g, part, name);
            };
            let m = self.read_manifest(&g, keys, part)?.0;
            match self.item(&g, keys, part, name, &m)? {
                None => return Ok(None),
                Some((rev, pt)) if m.items.get(name) == Some(&rev) => {
                    let caller = rev_of(&pt);
                    return Ok(Some((pt, caller)));
                }
                Some(_) => {}
            }
        }
        // above its manifest: a crash between the item's write and the manifest's; the manifest brought forward under the
        // write lock (the generation read again there: a re-seal may have committed meanwhile)
        let _w = self.write_lock()?;
        let g = self.cur();
        let keys = g.keys.as_ref().ok_or(Error::ProfileFormat)?;
        let m = self.read_manifest(&g, keys, part)?.0;
        let Some((rev, pt)) = self.item(&g, keys, part, name, &m)? else {
            return Ok(None);
        };
        if m.items.get(name) != Some(&rev) {
            self.update_manifest(&g, keys, part, |m| {
                m.tombstones.remove(name);
                let r = m.items.entry(name.to_string()).or_insert(rev);
                *r = (*r).max(rev);
            })?;
            self.write_anchor(&g)?;
        }
        let caller = rev_of(&pt);
        Ok(Some((pt, caller)))
    }

    /// Replaces (or creates) the item only when the caller's revision of it is `prev` (`None`: absent), else
    /// `StoreConflict`. `bytes` carry their own JSON `rev` (else, or above 16 MiB, `Argument`).
    pub fn put_if(
        &self,
        part: ProfilePart,
        name: &str,
        prev: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let caller = rev_of(bytes);
        if bytes.len() > MAX_BYTES || caller == u64::MAX {
            return Err(Error::Argument);
        }
        let _w = self.write_lock()?;
        let g = self.cur();
        let Some(keys) = &g.keys else {
            return self.plain_put(&g, part, name, prev, bytes);
        };
        let (m, _) = self.read_manifest(&g, keys, part)?;
        let cur = self.item(&g, keys, part, name, &m)?;
        if cur.as_ref().map(|(_, pt)| rev_of(pt)) != prev {
            return Err(Error::StoreConflict);
        }
        let base = match &cur {
            Some((rev, pt)) => rev.checked_sub(rev_of(pt)).ok_or(Error::VaultFormat)?,
            None => m.tombstones.get(name).copied().unwrap_or(0),
        };
        let rev = base.checked_add(caller).ok_or(Error::Argument)?;
        if !m.items.contains_key(name) && !m.tombstones.contains_key(name) && m.len() >= PART_MAX {
            return Err(Error::ProfilePartFull);
        }
        let p = g.file(keys, part.name(), name)?;
        let sealed = keys.seal_item(part.name(), name, rev, bytes).map_err(ua)?;
        put_file_if(&g.gdir, &p, cur.map(|(r, _)| r), &item_json(rev, &sealed)?)?;
        self.update_manifest(&g, keys, part, |m| {
            m.tombstones.remove(name);
            m.items.insert(name.to_string(), rev);
        })?;
        self.write_anchor(&g)
    }

    /// Deletes the item: its tombstone in the manifest first, then the file.
    pub fn delete(&self, part: ProfilePart, name: &str) -> Result<(), Error> {
        let _w = self.write_lock()?;
        let g = self.cur();
        let Some(keys) = &g.keys else {
            let p = self.plain_writable(&g, part, name)?;
            return remove(&p);
        };
        let p = g.file(keys, part.name(), name)?;
        let on_disk = file::read(&p)?
            .map(|(rev, _)| rev)
            .filter(|r| *r != u64::MAX);
        let (m, _) = self.read_manifest(&g, keys, part)?;
        if on_disk.is_some() || m.items.contains_key(name) {
            self.update_manifest(&g, keys, part, |m| {
                let last = [
                    m.items.remove(name),
                    m.tombstones.get(name).copied(),
                    on_disk,
                ]
                .into_iter()
                .flatten()
                .max();
                if let Some(last) = last {
                    m.tombstones.insert(name.to_string(), last);
                }
            })?;
            self.write_anchor(&g)?;
        }
        remove(&p)
    }

    /// Part `part`'s manifest as stored (an unprotected profile has none: empty).
    pub fn manifest(&self, part: ProfilePart) -> Result<Manifest, Error> {
        self.live()?;
        let g = self.cur();
        match &g.keys {
            Some(keys) => Ok(self.read_manifest(&g, keys, part)?.0),
            None => Ok(Manifest::default()),
        }
    }

    /// After an envelope write (UP6: rename, `hide`, `show`, platform unlock): its new rev and hash; the anchor follows.
    pub fn set_envelope(&self, envelope: Head) -> Result<(), Error> {
        let w = self.write_lock()?;
        self.envelope_written(&w, envelope)
    }

    /// The same, for a caller that holds the store write lock `_w` (a rename, `hide`, `show`: spec §8, §10).
    pub(crate) fn envelope_written(&self, _w: &WriteGuard, envelope: Head) -> Result<(), Error> {
        *self.envelope.lock().unwrap_or_else(PoisonError::into_inner) = envelope;
        self.write_anchor(&self.cur())
    }

    /// The item's lock (`<its file>.lock`), held while the returned file lives (defence in depth beside the store
    /// write lock).
    pub fn lock_item(&self, part: ProfilePart, name: &str) -> Result<std::fs::File, Error> {
        self.live()?;
        let g = self.cur();
        let p = match &g.keys {
            Some(keys) => g.file(keys, part.name(), name)?,
            None => self.plain_writable(&g, part, name)?,
        };
        let mut l = p.into_os_string();
        l.push(".lock");
        lock_file(Path::new(&l))
    }

    /// Re-seal step 3 (spec §7.3), under the store write lock the caller holds: every item of the current generation sealed
    /// under `keys` into `g<gen>/` (made by the caller), with new manifests and no tombstone (spec §7.2: the new key opens no
    /// item of the old generation, so nothing deleted can be put back). A protected generation's items are the ones its
    /// manifests list, opened under the old keys by the read rules (stored revs kept, each manifest's rev raised by one, so
    /// the anchor follows); the unprotected `g0`'s are `settings` (the caller's `settings` instead of the stored one: `None`
    /// drops it) and, under `migration: pending`, the legacy items, read in plain form, in part `sdk`. Each file `fsync`ed and
    /// renamed, the directory `fsync`ed.
    pub(crate) fn reseal_into(
        &self,
        gen: u64,
        keys: &ProfileKeys,
        settings: Option<&[u8]>,
    ) -> Result<(), Error> {
        let g = self.cur();
        let new = Gen {
            gen,
            gdir: self.dir.join(format!("g{gen}")),
            keys: None,
        };
        let put = |part: &str, name: &str, rev: u64, pt: &[u8]| -> Result<(), Error> {
            let sealed = keys.seal_item(part, name, rev, pt).map_err(ua)?;
            file::write(
                &new.gdir,
                &new.file(keys, part, name)?,
                &item_json(rev, &sealed)?,
            )
        };
        let mut parts: Vec<(ProfilePart, Manifest)> = Vec::new();
        match &g.keys {
            None => {
                let mut m = Manifest {
                    rev: 1,
                    ..Manifest::default()
                };
                let legacy = LEGACY.iter().filter(|_| self.migration_pending);
                for name in std::iter::once(&"settings").chain(legacy) {
                    let pt = match (*name, settings) {
                        ("settings", Some(b)) => Some(Zeroizing::new(b.to_vec())),
                        ("settings", None) => None,
                        _ => self
                            .plain_get(&g, ProfilePart::Sdk, name)?
                            .map(|(pt, _)| pt),
                    };
                    if let Some(pt) = pt {
                        let rev = rev_of(&pt);
                        if pt.len() > MAX_BYTES || rev == u64::MAX {
                            return Err(Error::Argument);
                        }
                        put("sdk", name, rev, &pt)?;
                        m.items.insert(name.to_string(), rev);
                    }
                }
                if !m.items.is_empty() {
                    parts.push((ProfilePart::Sdk, m));
                }
            }
            Some(old) => {
                for part in ProfilePart::ALL {
                    let (m, at) = self.read_manifest(&g, old, part)?;
                    let Some(at) = at else { continue };
                    let mut n = Manifest {
                        rev: at.checked_add(1).ok_or(Error::Argument)?,
                        ..Manifest::default()
                    };
                    for name in m.items.keys() {
                        let (rev, pt) = self
                            .item(&g, old, part, name, &m)?
                            .ok_or(Error::ProfileDamaged)?;
                        put(part.name(), name, rev, &pt)?;
                        n.items.insert(name.clone(), rev);
                    }
                    parts.push((part, n));
                }
            }
        }
        for (part, m) in parts {
            let pt = Zeroizing::new(m.json(part.name())?);
            put(PROFILE, &manifest_name(part), m.rev, &pt)?;
        }
        Ok(())
    }

    /// Re-seal step 4's swap (spec §7.3), under the store write lock the caller holds, after the envelope's rename: the store
    /// moves to generation `gen` under `keys` with the envelope `envelope`, the old keys are wiped, and the anchor is written
    /// for the new generation.
    pub(crate) fn commit(
        &self,
        gen: u64,
        keys: Arc<ProfileKeys>,
        envelope: Head,
    ) -> Result<(), Error> {
        let old = std::mem::replace(
            &mut *self.cur.write().unwrap_or_else(PoisonError::into_inner),
            Gen {
                gen,
                gdir: self.dir.join(format!("g{gen}")),
                keys: Some(keys),
            },
        );
        if let Some(k) = old.keys {
            k.lock();
        }
        *self.envelope.lock().unwrap_or_else(PoisonError::into_inner) = envelope;
        self.write_anchor(&self.cur())
    }

    /// The item as stored (its rev and plaintext) after spec §7.2's read rules against its manifest `m`.
    fn item(
        &self,
        g: &Gen,
        keys: &ProfileKeys,
        part: ProfilePart,
        name: &str,
        m: &Manifest,
    ) -> Result<Option<(u64, Plain)>, Error> {
        let Some((rev, sealed)) = read_sealed(&g.file(keys, part.name(), name)?)? else {
            return match m.items.contains_key(name) {
                true => Err(Error::ProfileDamaged),
                false => Ok(None),
            };
        };
        let below = m.items.get(name).is_some_and(|l| rev < *l);
        if below || m.tombstones.get(name).is_some_and(|t| rev <= *t) {
            return Err(Error::ProfileRollback);
        }
        let pt = keys
            .open_item(part.name(), name, rev, &sealed)
            .map_err(ua)?;
        Ok(Some((rev, pt)))
    }

    /// Part `part`'s manifest and its stored rev (`None`: no manifest yet, an empty one).
    fn read_manifest(
        &self,
        g: &Gen,
        keys: &ProfileKeys,
        part: ProfilePart,
    ) -> Result<(Manifest, Option<u64>), Error> {
        let name = manifest_name(part);
        let Some((rev, sealed)) = read_sealed(&g.file(keys, PROFILE, &name)?)? else {
            return Ok((Manifest::default(), None));
        };
        let pt = keys.open_item(PROFILE, &name, rev, &sealed).map_err(ua)?;
        Ok((Manifest::parse(part.name(), rev, &pt)?, Some(rev)))
    }

    /// `change` applied to the manifest as read and written at its read rev + 1 (`put_if`); a conflict reads it again, three
    /// tries, then `StoreConflict`.
    fn update_manifest(
        &self,
        g: &Gen,
        keys: &ProfileKeys,
        part: ProfilePart,
        mut change: impl FnMut(&mut Manifest),
    ) -> Result<(), Error> {
        let name = manifest_name(part);
        let p = g.file(keys, PROFILE, &name)?;
        for _ in 0..TRIES {
            let (mut m, at) = self.read_manifest(g, keys, part)?;
            change(&mut m);
            m.rev = at.unwrap_or(0).checked_add(1).ok_or(Error::Argument)?;
            let pt = Zeroizing::new(m.json(part.name())?);
            let sealed = keys.seal_item(PROFILE, &name, m.rev, &pt).map_err(ua)?;
            let bytes = item_json(m.rev, &sealed)?;
            #[cfg(feature = "test-hooks")]
            {
                let hook = self
                    .hook
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(f) = hook {
                    f();
                }
            }
            match put_file_if(&g.gdir, &p, at, &bytes) {
                Err(Error::StoreConflict) => continue,
                r => return r,
            }
        }
        Err(Error::StoreConflict)
    }

    /// What is stored, in the anchor's form: `gen`, the envelope, each part's manifest file.
    fn stored(&self, g: &Gen) -> Result<Anchor, Error> {
        let mut parts = BTreeMap::new();
        if let Some(keys) = &g.keys {
            for part in ProfilePart::ALL {
                let p = g.file(keys, PROFILE, &manifest_name(part))?;
                if let Some((rev, bytes)) = file::read(&p)? {
                    parts.insert(part.name().to_string(), Head::of(rev, &bytes));
                }
            }
        }
        let envelope = self
            .envelope
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        Ok(Anchor {
            gen: g.gen,
            envelope,
            parts,
        })
    }

    /// The anchor of what is stored, to `profile.head` and the keychain.
    fn write_anchor(&self, g: &Gen) -> Result<(), Error> {
        let a = self.stored(g)?.json()?;
        file::write(&self.dir, &self.dir.join(ANCHOR_FILE), &a)?;
        if let Some((kc, name)) = &self.keychain {
            kc.put(name, &a)?;
        }
        Ok(())
    }

    /// Open-time: each anchor present against what is stored (one rule); one that does not parse is `ProfileRollback`; a
    /// missing or followed one rewritten.
    fn check_anchor(&self) -> Result<(), Error> {
        let g = self.cur();
        let stored = self.stored(&g)?;
        // read bounded at the anchor's size: a larger file is an anchor that does not parse
        let in_file = file::read_bounded(&self.dir.join(ANCHOR_FILE), crate::anchor::MAX)?
            .map(Option::unwrap_or_default);
        let kept = match &self.keychain {
            Some((kc, name)) => Some(kc.get(name)?),
            None => None,
        };
        let mut write = in_file.is_none() || matches!(kept, Some(None));
        for a in [in_file, kept.flatten()].into_iter().flatten() {
            match Anchor::parse(&a).map(|a| stored.compare(&a)) {
                Some(Verdict::Same) => {}
                Some(Verdict::Follow) => write = true,
                None | Some(Verdict::Rollback) => return Err(Error::ProfileRollback),
            }
        }
        if write {
            self.write_anchor(&g)?;
        }
        Ok(())
    }

    /// An unprotected profile's item path: part `sdk`, `settings` or a legacy item; else `ProfilePassphraseRequired`.
    fn plain_path(&self, g: &Gen, part: ProfilePart, name: &str) -> Result<PathBuf, Error> {
        match part == ProfilePart::Sdk && (name == "settings" || LEGACY.contains(&name)) {
            true => Ok(g.gdir.join(name)),
            false => Err(Error::ProfilePassphraseRequired),
        }
    }

    /// The same, for a write: a legacy item only under `migration: pending`.
    fn plain_writable(&self, g: &Gen, part: ProfilePart, name: &str) -> Result<PathBuf, Error> {
        match name == "settings" || self.migration_pending {
            true => self.plain_path(g, part, name),
            false => Err(Error::ProfilePassphraseRequired),
        }
    }

    fn plain_get(&self, g: &Gen, part: ProfilePart, name: &str) -> Result<Option<Item>, Error> {
        let Some((rev, bytes)) = file::read(&self.plain_path(g, part, name)?)? else {
            return Ok(None);
        };
        if bytes.len() > MAX_BYTES {
            return Err(Error::VaultFormat);
        }
        // a sealed item, or a legacy item without `migration: pending` (spec §7.1)
        if sealed_form(&bytes) || (name != "settings" && !self.migration_pending) {
            return Err(Error::ProfileFormat);
        }
        Ok(Some((Zeroizing::new(bytes), rev)))
    }

    fn plain_put(
        &self,
        g: &Gen,
        part: ProfilePart,
        name: &str,
        prev: Option<u64>,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let p = self.plain_writable(g, part, name)?;
        if sealed_form(bytes) {
            return Err(Error::ProfileFormat);
        }
        put_file_if(&g.gdir, &p, prev, bytes)
    }
}

fn remove(p: &Path) -> Result<(), Error> {
    match std::fs::remove_file(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(Error::VaultIo),
    }
}

/// Test-only hooks (feature `test-hooks`, never in a release build).
#[cfg(feature = "test-hooks")]
impl Core {
    /// A writer's wait for the store write lock (120 s), shortened.
    pub fn set_write_wait(&self, wait: Duration) {
        let ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        self.lock.wait_ms.store(ms, SeqCst);
    }

    /// `f` runs once, between the next manifest write's read and its `put_if` (another writer landing in between).
    pub fn before_manifest_write(&self, f: Box<dyn FnOnce() + Send>) {
        *self.hook.lock().unwrap_or_else(PoisonError::into_inner) = Some(f);
    }

    /// The store calls so far (each check of [`Core::live`]): a test's proof that a refused call did no store work.
    pub fn calls(&self) -> u64 {
        self.calls.load(SeqCst)
    }
}
