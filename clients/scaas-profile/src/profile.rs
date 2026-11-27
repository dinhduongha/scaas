// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The profile root and the lifecycle of spec §5, §6, §9, §10 (start, first run, create, open, list, lock): [`Profiles`] over
//! one root directory, [`OpenProfile`] holding a profile's store core, its arena and its instance lock.
//!
//! - **Root** (`ProfileRoot::Dir` on every platform): a symlink or a non-directory is `ProfileRootUnsafe`; a mode wider than
//!   `0700` is tightened only when the root holds `profiles.json` or `p/` (or this crate made it), else `ProfileRootUnsafe`.
//! - **Root lock** `profiles.json.lock`: held only around short root steps (the journal, a rename, an index write, the start's
//!   clean-up), never across a KDF run.
//! - **Instance lock** `p/<id>/instance.lock`: `File::try_lock` before the envelope is read (`ProfileInUse` when held), kept
//!   until [`OpenProfile::lock`] or the process ends; nothing written into it. Start takes no live profile's lock.
//! - Every Argon2id run goes through the profiles' heavy limiter (`max_concurrent_heavy`, 1 by default).
//!
//! Events ([`ProfileEvent`]) carry no id and no name; the caller drains them ([`Profiles::drain_events`]).
use crate::envelope::{self, Envelope, KdfParams, Label, State, B64};
use crate::file::{self, lock_file, mkdir, read_bounded, try_lock_file};
use crate::index::{self, Index, Journal, Row};
use crate::names::{check_name, is_id, new_id, random, random_vec, same_name};
use crate::reseal;
use crate::store::{Core, CoreOpen, ProfilePart};
use crate::{keychain_name, Error, Head, ProfileKeychain};
use base64::Engine;
use scaas_ua::wallet::ProfileKeys;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use zeroize::Zeroizing;

const ROOT_LOCK: &str = "profiles.json.lock";
pub(crate) const INSTANCE_LOCK: &str = "instance.lock";
pub(crate) const BUILD_LOCK: &str = "build.lock";
pub(crate) const TOMBSTONE: &str = ".deleted";
/// At most 32 profile directories under `p/` (spec §6).
pub(crate) const DIRS_MAX: usize = 32;
/// The keychain items of a profile (spec §5, §7.1, §7.2, §7.6), removed with its tombstone.
const KEYCHAIN_ITEMS: [&str; 4] = ["head", "protected", "keystore.head", "unlock"];
/// The Matrix store key's item in part `sdk` (spec §7.2, CLI-UPR-29).
const MATRIX_KEY: &str = "matrix.store-key";

/// What [`Profiles::new`] takes.
pub struct ProfilesConfig {
    /// the profile root (a directory on every platform; on mobile the app's private directory)
    pub root: PathBuf,
    /// the app's keychain: anchors and the `protected` marker; `None`: files beside the profile
    pub keychain: Option<Arc<dyn ProfileKeychain>>,
    /// this device's largest Argon2id memory in KiB (spec §7.5): 1 GiB on desktop, a lower value on mobile
    pub kdf_max_kib: u32,
    /// Argon2id runs at once (the heavy limiter of the profiles)
    pub max_concurrent_heavy: usize,
    /// the CLI's data directory of today's single store (spec §12), migrated into "default" at start; the caller computes it
    /// (`--data-dir`, `$XDG_DATA_HOME/scaas`, `$HOME/.local/share/scaas`): this crate reads no environment
    pub legacy: Option<PathBuf>,
    /// test-only (feature `test-hooks`): called after each step of a delete and a migration; `true` stops there as if the
    /// process died (`VaultIo`, the files left as they are)
    #[cfg(feature = "test-hooks")]
    pub hook: Option<Box<dyn FnMut(crate::Step) -> bool + Send>>,
}

impl ProfilesConfig {
    pub fn new(root: PathBuf) -> ProfilesConfig {
        ProfilesConfig {
            root,
            keychain: None,
            kdf_max_kib: KdfParams::MAX_KIB,
            max_concurrent_heavy: 1,
            legacy: None,
            #[cfg(feature = "test-hooks")]
            hook: None,
        }
    }
}

/// A visible profile as listed. Its `Debug` shows neither the id nor the name.
#[derive(Clone, PartialEq, Eq)]
pub struct ProfileInfo {
    pub id: String,
    pub name: String,
    pub protected: bool,
}

impl std::fmt::Debug for ProfileInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileInfo")
            .field("id", &"<redacted>")
            .field("name", &"<redacted>")
            .field("protected", &self.protected)
            .finish()
    }
}

/// What the profiles report (spec §6, §7.2, §10); no id, no name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileEvent {
    /// a row or a name hint differed from the label (rewritten), or two envelopes share one visible name
    ProfileIndexMismatch,
    ProfileRollback,
    /// a UUID-named directory without a usable envelope (never removed)
    ProfileDamaged,
}

/// The heavy limiter: at most `max` Argon2id runs at once.
pub(crate) struct Heavy {
    running: Mutex<usize>,
    free: Condvar,
    max: usize,
}

pub(crate) struct HeavyGuard<'a>(&'a Heavy);

impl Heavy {
    pub(crate) fn acquire(&self) -> HeavyGuard<'_> {
        let n = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let mut n = self
            .free
            .wait_while(n, |n| *n >= self.max)
            .unwrap_or_else(PoisonError::into_inner);
        *n += 1;
        HeavyGuard(self)
    }
}

impl Drop for HeavyGuard<'_> {
    fn drop(&mut self) {
        let mut n = self
            .0
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *n = n.saturating_sub(1);
        self.0.free.notify_one();
    }
}

/// The profiles of one root. Every call is blocking work (files, Argon2id): run it on a blocking thread. No `Debug`.
pub struct Profiles {
    root: PathBuf,
    pub(crate) p: PathBuf,
    pub(crate) keychain: Option<Arc<dyn ProfileKeychain>>,
    pub(crate) kdf_max_kib: u32,
    pub(crate) heavy: Arc<Heavy>,
    events: Mutex<Vec<ProfileEvent>>,
    #[cfg(feature = "test-hooks")]
    before_kdf: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    #[cfg(feature = "test-hooks")]
    hook: Mutex<Option<crate::reseal::Hook>>,
}

/// The root's own checks (spec §5 "Modes"): made `0700` when missing; a symlink or not a directory refused; a wider mode
/// tightened only when it holds `profiles.json` or `p/`, else `ProfileRootUnsafe`.
fn prepare_root(root: &Path) -> Result<(), Error> {
    let m = match std::fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = root.parent() {
                std::fs::create_dir_all(parent).map_err(|_| Error::VaultIo)?;
            }
            return mkdir(root);
        }
        Err(_) => return Err(Error::VaultIo),
        Ok(m) => m,
    };
    if m.file_type().is_symlink() || !m.is_dir() {
        return Err(Error::ProfileRootUnsafe);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            let ours = root.join(index::FILE).exists() || root.join("p").exists();
            if !ours {
                return Err(Error::ProfileRootUnsafe);
            }
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| Error::ProfileRootUnsafe)?;
        }
    }
    Ok(())
}

pub(crate) fn remove_dir(p: &Path) -> Result<(), Error> {
    match std::fs::remove_dir_all(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::VaultIo),
        _ => Ok(()),
    }
}

pub(crate) fn remove_file(p: &Path) -> Result<(), Error> {
    match std::fs::remove_file(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::VaultIo),
        _ => Ok(()),
    }
}

pub(crate) fn sync_dir(p: &Path) -> Result<(), Error> {
    File::open(p)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error::VaultIo)
}

/// The envelope of directory `dir` (named `id`), read bounded: `Ok(None)` when absent.
pub(crate) fn read_envelope(dir: &Path, id: &str) -> Result<Option<(Envelope, Vec<u8>)>, Error> {
    match read_bounded(&dir.join(envelope::FILE), envelope::MAX)? {
        None => Ok(None),
        Some(None) => Err(Error::ProfileFormat),
        Some(Some(bytes)) => Ok(Some((Envelope::parse(&bytes, id)?, bytes))),
    }
}

/// The index file's rev for `put_if` (`u64::MAX` for one above its bound).
fn rev_at(bytes: &Option<Option<Vec<u8>>>) -> Option<u64> {
    bytes
        .as_ref()
        .map(|b| b.as_deref().map_or(u64::MAX, file::rev_of))
}

/// The UUID-named directories of `p/` by id, each with its envelope and its bytes (`None`: missing or not usable).
pub(crate) type Scan = Vec<(String, Option<(Envelope, Vec<u8>)>)>;

/// Every UUID-named directory of `p` and its envelope and bytes, sorted by id.
pub(crate) fn scan(p: &Path) -> Result<Scan, Error> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(p).map_err(|_| Error::VaultIo)? {
        let e = e.map_err(|_| Error::VaultIo)?;
        let Some(id) = e
            .file_name()
            .to_str()
            .filter(|n| is_id(n))
            .map(str::to_string)
        else {
            continue;
        };
        if !e.file_type().map_err(|_| Error::VaultIo)?.is_dir() {
            continue;
        }
        let env = read_envelope(&e.path(), &id).ok().flatten();
        out.push((id, env));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// A profile arena's refusal at open: a wrong passphrase or an altered wrap `ProfileOpen`, argon2's allocation failure
/// `ProfileKdfOutOfMemory`.
pub(crate) fn open_code(e: scaas_ua::wallet::Error) -> Error {
    match e {
        scaas_ua::wallet::Error::KdfOutOfMemory => Error::ProfileKdfOutOfMemory,
        scaas_ua::wallet::Error::WalletLocked => Error::ProfileLocked,
        _ => Error::ProfileOpen,
    }
}

impl Profiles {
    /// Start (spec §10): the root checked, then under the root lock the journal finished or undone, each `p/.tmp-*` whose
    /// `build.lock` is free removed, each tombstone whose instance lock is free removed with its keychain items, each
    /// UUID-named directory without a usable envelope reported (`ProfileDamaged`, never removed), the index rebuilt when it
    /// is missing or does not parse while `p/` holds a profile, then the migration from `legacy` (spec §12, `migrate.rs`). No
    /// live profile's lock is taken. First run (no profile directory, nothing migrated): "default" created unprotected.
    pub fn new(config: ProfilesConfig) -> Result<Profiles, Error> {
        prepare_root(&config.root)?;
        let pr = Profiles {
            p: config.root.join("p"),
            root: config.root,
            keychain: config.keychain,
            kdf_max_kib: config.kdf_max_kib,
            heavy: Arc::new(Heavy {
                running: Mutex::new(0),
                free: Condvar::new(),
                max: config.max_concurrent_heavy.max(1),
            }),
            events: Mutex::new(Vec::new()),
            #[cfg(feature = "test-hooks")]
            before_kdf: Mutex::new(None),
            #[cfg(feature = "test-hooks")]
            hook: Mutex::new(config.hook),
        };
        mkdir(&pr.p)?;
        let first_run = {
            let _root = pr.root_lock()?;
            let first_run = pr.start()?;
            match &config.legacy {
                Some(src) => pr.migrate(src, first_run)?,
                None => first_run,
            }
        };
        if first_run {
            // a second instance's first run at once: its commit finds the name taken
            match pr.create("default") {
                Ok(_) | Err(Error::ProfileNameTaken) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(pr)
    }

    /// The events since the last call.
    pub fn drain_events(&self) -> Vec<ProfileEvent> {
        std::mem::take(&mut *self.events.lock().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn event(&self, e: ProfileEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(e);
    }

    pub(crate) fn root_lock(&self) -> Result<File, Error> {
        lock_file(&self.root.join(ROOT_LOCK))
    }

    /// The keychain items of profile `id` removed (spec §10: a tombstone's).
    pub(crate) fn remove_keychain(&self, id: &str) -> Result<(), Error> {
        if let Some(kc) = &self.keychain {
            for what in KEYCHAIN_ITEMS {
                kc.delete(&keychain_name(id, what))?;
            }
        }
        Ok(())
    }

    /// The index file's path.
    pub(crate) fn index_file(&self) -> PathBuf {
        self.root.join(index::FILE)
    }

    /// The start's steps under the root lock; whether this is a first run.
    fn start(&self) -> Result<bool, Error> {
        self.finish_journal()?;
        for e in std::fs::read_dir(&self.p).map_err(|_| Error::VaultIo)? {
            let e = e.map_err(|_| Error::VaultIo)?;
            let (path, name) = (e.path(), e.file_name());
            let Some(name) = name.to_str() else { continue };
            if !e.file_type().map_err(|_| Error::VaultIo)?.is_dir() {
                continue;
            }
            if name.starts_with(".tmp-") {
                if try_lock_file(&path.join(BUILD_LOCK))?.is_some() {
                    remove_dir(&path)?;
                }
            } else if let Some(id) = name.strip_suffix(TOMBSTONE).filter(|id| is_id(id)) {
                if try_lock_file(&path.join(INSTANCE_LOCK))?.is_some() {
                    remove_dir(&path)?;
                    self.remove_keychain(id)?;
                }
            }
        }
        let scan = self.scan()?;
        for (_, env) in &scan {
            if env.is_none() {
                self.event(ProfileEvent::ProfileDamaged);
            }
        }
        if scan.is_empty() {
            return Ok(true);
        }
        self.index_locked()?;
        Ok(false)
    }

    /// `p/.journal` at start: a create whose directory is in place gets its row; then the journal goes.
    fn finish_journal(&self) -> Result<(), Error> {
        let path = self.p.join(index::JOURNAL);
        let Some(bytes) = read_bounded(&path, 256)? else {
            return Ok(());
        };
        let j = bytes.and_then(|b| serde_json::from_slice::<Journal>(&b).ok());
        if let Some(j) = j.filter(|j| j.op == "create" && is_id(&j.id)) {
            let dir = self.p.join(&j.id);
            if let Ok(Some((env, _))) = read_envelope(&dir, &j.id) {
                if let Some(name) = env.name {
                    let (mut ix, at) = self.index_locked()?;
                    if !ix.profiles.iter().any(|r| r.id == j.id) && ix.profiles.len() < index::ROWS
                    {
                        ix.profiles.push(Row { id: j.id, name });
                        self.write_index(&mut ix, at)?;
                    }
                }
            }
        }
        remove_file(&path)?;
        sync_dir(&self.p)
    }

    /// Every UUID-named directory of `p/` and its envelope (`None`: missing or not usable), by id.
    pub(crate) fn scan(&self) -> Result<Vec<(String, Option<Envelope>)>, Error> {
        Ok(scan(&self.p)?
            .into_iter()
            .map(|(id, e)| (id, e.map(|(e, _)| e)))
            .collect())
    }

    /// The index under the root lock and its file's rev for `put_if`: rows of missing directories dropped; rebuilt from the
    /// envelopes (and written) when it is missing or does not parse while `p/` holds a profile, one row per envelope with a
    /// public name, protected or not; two with one `name_key` both listed, with `ProfileIndexMismatch`.
    pub(crate) fn index_locked(&self) -> Result<(Index, Option<u64>), Error> {
        let bytes = read_bounded(&self.root.join(index::FILE), index::MAX)?;
        let at = rev_at(&bytes);
        let parsed = bytes.flatten().and_then(|b| Index::parse(&b));
        if let Some(mut ix) = parsed {
            ix.profiles.retain(|r| self.p.join(&r.id).is_dir());
            return Ok((ix, at));
        }
        let scan = self.scan()?;
        if scan.is_empty() {
            return Ok((Index::new(Vec::new()), at));
        }
        let mut rows: Vec<Row> = Vec::new();
        for (id, env) in scan {
            if let Some(name) = env.and_then(|e| e.name) {
                if rows.iter().any(|r| same_name(&r.name, &name)) {
                    self.event(ProfileEvent::ProfileIndexMismatch);
                }
                rows.push(Row { id, name });
            }
        }
        rows.truncate(index::ROWS);
        let mut ix = Index::new(rows);
        let at = self.write_index(&mut ix, at)?;
        Ok((ix, at))
    }

    /// `ix` written at the file's read rev `at` (`put_if`; under the root lock), its rev raised; the new rev.
    pub(crate) fn write_index(
        &self,
        ix: &mut Index,
        at: Option<u64>,
    ) -> Result<Option<u64>, Error> {
        let path = self.root.join(index::FILE);
        if rev_at(&read_bounded(&path, index::MAX)?) != at {
            return Err(Error::StoreConflict);
        }
        ix.rev = ix.rev.checked_add(1).ok_or(Error::Argument)?;
        file::write(&self.root, &path, &ix.json()?)?;
        Ok(Some(ix.rev))
    }

    /// `change` applied to the index under the root lock; written when it says so.
    fn update_index(&self, change: impl FnOnce(&mut Index) -> bool) -> Result<(), Error> {
        let _root = self.root_lock()?;
        let (mut ix, at) = self.index_locked()?;
        if change(&mut ix) {
            self.write_index(&mut ix, at)?;
        }
        Ok(())
    }

    /// The visible profiles: `{id, name, protected}` (reads no instance lock).
    pub fn list(&self) -> Result<Vec<ProfileInfo>, Error> {
        let ix = {
            let _root = self.root_lock()?;
            self.index_locked()?.0
        };
        Ok(ix
            .profiles
            .into_iter()
            .filter_map(|r| {
                let (env, _) = read_envelope(&self.p.join(&r.id), &r.id).ok()??;
                env.name.as_ref()?;
                Some(ProfileInfo {
                    protected: env.state == State::Protected,
                    id: r.id,
                    name: r.name,
                })
            })
            .collect())
    }

    /// A new unprotected profile named `name` (spec §10 "create"): built in `p/.tmp-<random>/` under its `build.lock`, then
    /// under the root lock the journal, the rename, the row, the journal removed. `ProfileNameInvalid`, `ProfileNameTaken`
    /// (a visible name of one `name_key`), `ProfileLimit` (32 directories).
    pub fn create(&self, name: &str) -> Result<ProfileInfo, Error> {
        let name = check_name(name)?;
        let id = new_id()?;
        let tmp = self.new_tmp()?;
        let r = (|| {
            let _build = lock_file(&tmp.join(BUILD_LOCK))?;
            let env = Envelope::unprotected(&id, &name).json()?;
            file::write(&tmp, &tmp.join(envelope::FILE), &env)?;
            mkdir(&tmp.join("g0"))?;
            let _root = self.root_lock()?;
            self.commit_create(&tmp, &id, Some(&name))
        })();
        if r.is_err() {
            let _ = remove_dir(&tmp);
        }
        r?;
        Ok(ProfileInfo {
            id,
            name,
            protected: false,
        })
    }

    /// Under the root lock: room checked, the journal, `tmp` renamed to `p/<id>/`, its row added (`row`: the visible name;
    /// `None` for a hidden profile, which reads and writes no index byte), the journal removed.
    pub(crate) fn commit_create(
        &self,
        tmp: &Path,
        id: &str,
        row: Option<&str>,
    ) -> Result<(), Error> {
        self.room(true, row.is_none())?;
        let ix = match row {
            Some(name) => {
                let (ix, at) = self.index_locked()?;
                if ix.profiles.iter().any(|r| same_name(&r.name, name)) {
                    return Err(Error::ProfileNameTaken);
                }
                Some((ix, at, name))
            }
            None => None,
        };
        let journal = Journal {
            op: "create".into(),
            id: id.into(),
        };
        let jpath = self.p.join(index::JOURNAL);
        let jbytes = serde_json::to_vec(&journal).map_err(|_| Error::Argument)?;
        file::write(&self.p, &jpath, &jbytes)?;
        let dir = self.p.join(id);
        std::fs::rename(tmp, &dir).map_err(|_| Error::VaultIo)?;
        sync_dir(&self.p)?;
        remove_file(&dir.join(BUILD_LOCK))?;
        if let Some((mut ix, at, name)) = ix {
            ix.profiles.push(Row {
                id: id.into(),
                name: name.into(),
            });
            self.write_index(&mut ix, at)?;
        }
        remove_file(&jpath)?;
        sync_dir(&self.p)
    }

    /// A new `p/.tmp-<random>/` to build a profile in (spec §5, §10).
    pub(crate) fn new_tmp(&self) -> Result<PathBuf, Error> {
        let tag: String = random::<8>()?.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = self.p.join(format!(".tmp-{tag}"));
        mkdir(&tmp)?;
        Ok(tmp)
    }

    /// Room for one more profile directory (`new_dir`; `ProfileLimit` at 32) and one more hidden profile (`hidden`;
    /// `ProfileHiddenLimit` at 16, spec §8: an envelope without a public name).
    pub(crate) fn room(&self, new_dir: bool, hidden: bool) -> Result<(), Error> {
        let scan = self.scan()?;
        if new_dir && scan.len() >= DIRS_MAX {
            return Err(Error::ProfileLimit);
        }
        let n = scan
            .iter()
            .filter(|(_, e)| e.as_ref().is_some_and(|e| e.name.is_none()))
            .count();
        match hidden && n >= crate::hidden::HIDDEN_MAX {
            true => Err(Error::ProfileHiddenLimit),
            false => Ok(()),
        }
    }

    /// Opens profile `id` (spec §10 "open"): its instance lock (`ProfileInUse` when held) before its envelope is read; the
    /// envelope refused by state (§7.1) and by the keychain marker; a protected one's KDF bounds (`ProfileFormat`,
    /// `ProfileKdfTooLarge`) before its Argon2id run through the heavy limiter (never under the root lock), its wrap opened
    /// (`ProfileOpen` for a wrong passphrase or an altered wrap; `ProfileKdfOutOfMemory`), its label compared with the hint and
    /// the row (`ProfileIndexMismatch`, both rewritten); the store core opened against the anchor; `last` written when it
    /// changes. `passphrase` (UTF-8, typed) is needed for a protected profile (`Argument` without it), ignored for an
    /// unprotected one. A profile with no public name (hidden) is not opened by id: `ProfileOpen`, its row dropped, and a
    /// planted hint on it removed.
    pub fn open(&self, id: &str, passphrase: Option<&[u8]>) -> Result<OpenProfile, Error> {
        let dir = self.p.join(id);
        let is_dir = std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir());
        if !is_id(id) || !is_dir {
            return Err(Error::ProfileUnknown);
        }
        let instance = try_lock_file(&dir.join(INSTANCE_LOCK))?.ok_or(Error::ProfileInUse)?;
        let (env, bytes) = read_envelope(&dir, id)?.ok_or(Error::ProfileFormat)?;
        let lower = self.generations(&dir, id, env.gen)?;
        self.check_marker(id, env.state)?;
        let Some(hint) = env.name.clone() else {
            self.drop_row(id)?;
            return Err(Error::ProfileOpen);
        };
        let keys = match env.state {
            State::Protected => Some(self.unwrap(&env, passphrase.ok_or(Error::Argument)?)?),
            State::Unprotected => None,
        };
        let mut name = hint.clone();
        if let Some(keys) = &keys {
            let label = open_label(keys, &env).inspect_err(|_| keys.lock())?;
            if label.hidden {
                // a planted hint on a hidden profile: removed, its row dropped, nothing else written (spec §6)
                keys.lock();
                let mut e = env.clone();
                e.name = None;
                e.rev = e.rev.checked_add(1).ok_or(Error::ProfileFormat)?;
                file::write(&dir, &dir.join(envelope::FILE), &e.json()?)?;
                self.drop_row(id)?;
                return Err(Error::ProfileOpen);
            }
            name = label.name.to_string();
        }
        let opened = self.finish(instance, &env, &bytes, keys, &name, &lower)?;
        if name != hint {
            let mut e = env;
            e.name = Some(name.clone());
            e.rev = e.rev.checked_add(1).ok_or(Error::ProfileFormat)?;
            let b = e.json()?;
            file::write(&dir, &dir.join(envelope::FILE), &b)?;
            opened.core.set_envelope(Head::of(e.rev, &b))?;
        }
        if self.after_open(id, &name)? || name != hint {
            self.event(ProfileEvent::ProfileIndexMismatch);
        }
        Ok(opened)
    }

    /// An open's end, under the instance lock `instance` of `p/<env.id>/`, after the envelope's checks and its wrap and label opened: the store
    /// core opened against the anchor, a lower generation removed (spec §7.3), the keychain's `protected` marker written when
    /// missing. `keys` are locked on a failure.
    pub(crate) fn finish(
        &self,
        instance: File,
        env: &Envelope,
        bytes: &[u8],
        keys: Option<Arc<ProfileKeys>>,
        name: &str,
        lower: &[PathBuf],
    ) -> Result<OpenProfile, Error> {
        let core = Core::open(CoreOpen {
            dir: self.p.join(&env.id),
            id: env.id.clone(),
            gen: env.gen,
            keys: keys.clone(),
            keychain: self.keychain.clone(),
            envelope: Head::of(env.rev, bytes),
            migration_pending: env.migration.is_some(),
        });
        let core = Arc::new(core.inspect_err(|_| {
            if let Some(k) = &keys {
                k.lock()
            }
        })?);
        let opened = OpenProfile {
            info: Mutex::new(ProfileInfo {
                id: env.id.clone(),
                name: name.into(),
                protected: keys.is_some(),
            }),
            core,
            instance: Mutex::new(Some(instance)),
            heavy: self.heavy.clone(),
            kdf_max_kib: self.kdf_max_kib,
            keychain: self.keychain.clone(),
            #[cfg(feature = "test-hooks")]
            hook: Mutex::new(None),
        };
        // spec §7.3: a lower generation (a crash between a re-seal's commit and its clean-up) only now, after the wrap opened
        // and the anchor check, beside the live `g<gen>/`
        for g in lower {
            remove_dir(g)?;
        }
        if let (Some(kc), true) = (&self.keychain, opened.core.protected()) {
            let marker = keychain_name(&env.id, "protected");
            if kc.get(&marker)?.is_none() {
                kc.put(&marker, b"1")?;
            }
        }
        Ok(opened)
    }

    /// Spec §7.3 at the profile's own open, under its instance lock: a journal (`profile.envelope.next`) rolls the re-seal back,
    /// `g<gen+1>/` removed first, then the journal; then a generation above `gen` is `ProfileDamaged` (`ProfileRollback` where
    /// an anchor names a higher `gen`: the envelope is old), never removed; a generation below `gen` is `ProfileDamaged` without
    /// `g<gen>/`, else returned, to be removed once the wrap has opened.
    pub(crate) fn generations(
        &self,
        dir: &Path,
        id: &str,
        gen: u64,
    ) -> Result<Vec<PathBuf>, Error> {
        let next = gen.checked_add(1).ok_or(Error::ProfileFormat)?;
        if std::fs::symlink_metadata(dir.join(reseal::NEXT)).is_ok() {
            remove_dir(&dir.join(format!("g{next}")))?;
            remove_file(&dir.join(reseal::NEXT))?;
            sync_dir(dir)?;
        }
        let (mut lower, mut higher) = (Vec::new(), false);
        for e in std::fs::read_dir(dir).map_err(|_| Error::VaultIo)? {
            let e = e.map_err(|_| Error::VaultIo)?;
            let k = e.file_name().to_str().and_then(|n| {
                let k = n.strip_prefix('g')?.parse::<u64>().ok()?;
                (n == format!("g{k}")).then_some(k)
            });
            match k {
                Some(k) if k > gen => higher = true,
                Some(k) if k < gen => lower.push(e.path()),
                _ => {}
            }
        }
        if higher {
            let anchored = self.anchor_gen(dir, id)?;
            let e = match anchored > gen {
                true => (ProfileEvent::ProfileRollback, Error::ProfileRollback),
                false => (ProfileEvent::ProfileDamaged, Error::ProfileDamaged),
            };
            self.event(e.0);
            return Err(e.1);
        }
        if !lower.is_empty() && !dir.join(format!("g{gen}")).is_dir() {
            self.event(ProfileEvent::ProfileDamaged);
            return Err(Error::ProfileDamaged);
        }
        Ok(lower)
    }

    /// The highest `gen` an anchor of the profile names (`profile.head`, the keychain's), 0 without one.
    fn anchor_gen(&self, dir: &Path, id: &str) -> Result<u64, Error> {
        let in_file = read_bounded(&dir.join(crate::store::ANCHOR_FILE), 2560)?.flatten();
        let kept = match &self.keychain {
            Some(kc) => kc.get(&keychain_name(id, "head"))?,
            None => None,
        };
        Ok([in_file, kept]
            .into_iter()
            .flatten()
            .filter_map(|a| crate::Anchor::parse(&a))
            .map(|a| a.gen)
            .max()
            .unwrap_or(0))
    }

    /// The keychain marker's rules (spec §7.1): an unprotected envelope beside it `ProfileFormat`; a protected one beside it
    /// without its keychain anchor `ProfileRollback`.
    pub(crate) fn check_marker(&self, id: &str, state: State) -> Result<(), Error> {
        let Some(kc) = &self.keychain else {
            return Ok(());
        };
        if kc.get(&keychain_name(id, "protected"))?.is_none() {
            return Ok(());
        }
        match state {
            State::Unprotected => Err(Error::ProfileFormat),
            State::Protected if kc.get(&keychain_name(id, "head"))?.is_none() => {
                Err(Error::ProfileRollback)
            }
            State::Protected => Ok(()),
        }
    }

    /// The protected envelope's `pass` opened with `passphrase`: the bounds first, then one Argon2id run in the heavy limiter.
    fn unwrap(&self, env: &Envelope, passphrase: &[u8]) -> Result<Arc<ProfileKeys>, Error> {
        let kdf = env.kdf.as_ref().ok_or(Error::ProfileFormat)?;
        let (params, salt) = kdf.check(self.kdf_max_kib)?;
        let wrap = B64
            .decode(env.pass.as_deref().unwrap_or_default())
            .map_err(|_| Error::ProfileFormat)?;
        if wrap.len() != 60 {
            return Err(Error::ProfileFormat);
        }
        let public = env.public_json()?;
        let _heavy = self.heavy.acquire();
        #[cfg(feature = "test-hooks")]
        {
            let hook = self
                .before_kdf
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(f) = hook {
                f();
            }
        }
        let keys = ProfileKeys::new();
        keys.open_pass(passphrase, &salt, params, &public, &wrap)
            .map_err(open_code)?;
        Ok(Arc::new(keys))
    }
}

/// The sealed label of a protected envelope: `{name, hidden}`, the name as stored; anything else (a hidden label beside a
/// platform wrap included) `ProfileFormat`.
pub(crate) fn open_label(keys: &ProfileKeys, env: &Envelope) -> Result<OpenLabel, Error> {
    let sealed = B64
        .decode(env.label.as_deref().unwrap_or_default())
        .map_err(|_| Error::ProfileFormat)?;
    let pt = keys
        .open_label(&env.id, &sealed)
        .map_err(|_| Error::ProfileFormat)?;
    let l: Label = serde_json::from_slice(&pt).map_err(|_| Error::ProfileFormat)?;
    let name = Zeroizing::new(l.name);
    if check_name(&name).ok().as_deref() != Some(name.as_str())
        || (l.hidden && env.platform.is_some())
    {
        return Err(Error::ProfileFormat);
    }
    Ok(OpenLabel {
        name,
        hidden: l.hidden,
    })
}

impl Profiles {
    /// After an open: the row checked against the name (rewritten; whether it differed), `last` written when it changes.
    fn after_open(&self, id: &str, name: &str) -> Result<bool, Error> {
        let mut mismatch = false;
        self.update_index(|ix| {
            let mut changed = ix.last.as_deref() != Some(id);
            ix.last = Some(id.into());
            let room = ix.profiles.len() < index::ROWS;
            match ix.profiles.iter_mut().find(|r| r.id == id) {
                Some(r) if r.name == name => {}
                Some(r) => {
                    r.name = name.into();
                    (changed, mismatch) = (true, true);
                }
                None if room => {
                    ix.profiles.push(Row {
                        id: id.into(),
                        name: name.into(),
                    });
                    (changed, mismatch) = (true, true);
                }
                None => {}
            }
            changed
        })?;
        Ok(mismatch)
    }

    pub(crate) fn drop_row(&self, id: &str) -> Result<(), Error> {
        self.update_index(|ix| without(ix, id))
    }
}

/// `ix` without the row of `id` and without `last` naming it; whether it changed.
pub(crate) fn without(ix: &mut Index, id: &str) -> bool {
    let n = ix.profiles.len();
    ix.profiles.retain(|r| r.id != id);
    let last = ix.last.as_deref() == Some(id);
    if last {
        ix.last = None;
    }
    last || n != ix.profiles.len()
}

pub(crate) struct OpenLabel {
    pub(crate) name: Zeroizing<String>,
    pub(crate) hidden: bool,
}

/// The profile's Matrix store (spec §5, §7.2; CLI-UPR-29): its directory `p/<id>/matrix/` and its store key, the one key that
/// leaves the arena (matrix-rust-sdk needs its bytes). No `Debug`.
pub struct MatrixStore {
    pub dir: PathBuf,
    pub key: Zeroizing<Vec<u8>>,
}

/// An open profile: its store core, its arena and its instance lock, until [`OpenProfile::lock`] or drop. No `Debug`.
pub struct OpenProfile {
    info: Mutex<ProfileInfo>,
    pub(crate) core: Arc<Core>,
    instance: Mutex<Option<File>>,
    /// the profiles' heavy limiter, this device's KDF maximum and the keychain: a re-seal's (spec §7.3)
    pub(crate) heavy: Arc<Heavy>,
    pub(crate) kdf_max_kib: u32,
    pub(crate) keychain: Option<Arc<dyn ProfileKeychain>>,
    #[cfg(feature = "test-hooks")]
    pub(crate) hook: Mutex<Option<crate::reseal::Hook>>,
}

impl OpenProfile {
    /// The profile's id, name and whether it is protected now.
    pub fn info(&self) -> ProfileInfo {
        ProfileInfo {
            protected: self.core.protected(),
            ..self
                .info
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    /// A rename's new name (spec §10).
    pub(crate) fn set_name(&self, name: &str) {
        self.info
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .name = name.into();
    }

    /// The store core (the SDK's faces go over it).
    pub fn core(&self) -> &Arc<Core> {
        &self.core
    }

    /// The profile arena of the current generation; `None` for an unprotected profile.
    pub fn keys(&self) -> Option<Arc<ProfileKeys>> {
        self.core.keys()
    }

    /// The Matrix store's directory and key: the key a sealed item of part `sdk`, made with 32 random bytes on the first
    /// request. An unprotected profile has none (`ProfilePassphraseRequired`).
    pub fn matrix_store(&self) -> Result<MatrixStore, Error> {
        const HEAD: &[u8] = br#"{"rev":1,"key":""#;
        const TAIL: &[u8] = br#""}"#;
        for _ in 0..2 {
            if let Some((pt, _)) = self.core.get(ProfilePart::Sdk, MATRIX_KEY)? {
                let b64 = pt
                    .strip_prefix(HEAD)
                    .and_then(|r| r.strip_suffix(TAIL))
                    .ok_or(Error::VaultFormat)?;
                let mut key = Zeroizing::new(vec![0u8; 32]);
                match B64.decode_slice(b64, &mut key[..]) {
                    Ok(32) => return self.matrix_dir(key),
                    _ => return Err(Error::VaultFormat),
                }
            }
            let key = Zeroizing::new(random_vec(32)?);
            let b64 = Zeroizing::new(B64.encode(&key[..]));
            let pt = Zeroizing::new([HEAD, b64.as_bytes(), TAIL].concat());
            match self.core.put_if(ProfilePart::Sdk, MATRIX_KEY, None, &pt) {
                Ok(()) => return self.matrix_dir(key),
                Err(Error::StoreConflict) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::StoreConflict)
    }

    fn matrix_dir(&self, key: Zeroizing<Vec<u8>>) -> Result<MatrixStore, Error> {
        let dir = self.core.dir().join("matrix");
        mkdir(&dir)?;
        Ok(MatrixStore { dir, key })
    }

    /// Locks the profile (spec §10 "lock"): the stores refuse every later call (`ProfileLocked`), the arena is destroyed, the
    /// instance lock released. Again: nothing.
    pub fn lock(&self) {
        drop(self.release());
    }

    /// The lock's steps but the instance lock, which is returned (`None` when already locked): a delete keeps it across the
    /// tombstone's rename.
    pub(crate) fn release(&self) -> Option<File> {
        self.core.close();
        if let Some(k) = self.core.keys() {
            k.lock();
        }
        self.instance
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl Drop for OpenProfile {
    fn drop(&mut self) {
        self.lock();
    }
}

impl Profiles {
    /// Whether the test hook stops a delete or a migration after `step` (as if the process died there: `VaultIo`).
    #[cfg(feature = "test-hooks")]
    pub(crate) fn died(&self, step: crate::Step) -> Result<(), Error> {
        let mut h = self.hook.lock().unwrap_or_else(PoisonError::into_inner);
        match h.as_mut().is_some_and(|f| f(step)) {
            true => Err(Error::VaultIo),
            false => Ok(()),
        }
    }

    #[cfg(not(feature = "test-hooks"))]
    pub(crate) fn died(&self, _: crate::Step) -> Result<(), Error> {
        Ok(())
    }
}

/// Test-only hooks (feature `test-hooks`, never in a release build).
#[cfg(feature = "test-hooks")]
impl Profiles {
    /// `f` runs once, inside the heavy limiter just before the next Argon2id run of an open (a KDF held there).
    pub fn before_kdf(&self, f: Box<dyn FnOnce() + Send>) {
        *self
            .before_kdf
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(f);
    }
}
