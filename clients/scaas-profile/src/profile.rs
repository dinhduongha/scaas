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
use crate::store::{Core, CoreOpen, ProfilePart};
use crate::{keychain_name, Error, Head, ProfileKeychain};
use base64::Engine;
use scaas_ua::wallet::ProfileKeys;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use zeroize::Zeroizing;

const ROOT_LOCK: &str = "profiles.json.lock";
const INSTANCE_LOCK: &str = "instance.lock";
const BUILD_LOCK: &str = "build.lock";
const TOMBSTONE: &str = ".deleted";
/// At most 32 profile directories under `p/` (spec §6).
const DIRS_MAX: usize = 32;
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
}

impl ProfilesConfig {
    pub fn new(root: PathBuf) -> ProfilesConfig {
        ProfilesConfig {
            root,
            keychain: None,
            kdf_max_kib: KdfParams::MAX_KIB,
            max_concurrent_heavy: 1,
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
struct Heavy {
    running: Mutex<usize>,
    free: Condvar,
    max: usize,
}

struct HeavyGuard<'a>(&'a Heavy);

impl Heavy {
    fn acquire(&self) -> HeavyGuard<'_> {
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
    p: PathBuf,
    keychain: Option<Arc<dyn ProfileKeychain>>,
    kdf_max_kib: u32,
    heavy: Heavy,
    events: Mutex<Vec<ProfileEvent>>,
    #[cfg(feature = "test-hooks")]
    before_kdf: Mutex<Option<Box<dyn FnOnce() + Send>>>,
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

fn remove_dir(p: &Path) -> Result<(), Error> {
    match std::fs::remove_dir_all(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::VaultIo),
        _ => Ok(()),
    }
}

fn remove_file(p: &Path) -> Result<(), Error> {
    match std::fs::remove_file(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::VaultIo),
        _ => Ok(()),
    }
}

fn sync_dir(p: &Path) -> Result<(), Error> {
    File::open(p)
        .and_then(|d| d.sync_all())
        .map_err(|_| Error::VaultIo)
}

/// The envelope of directory `dir` (named `id`), read bounded: `Ok(None)` when absent.
fn read_envelope(dir: &Path, id: &str) -> Result<Option<(Envelope, Vec<u8>)>, Error> {
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

/// A profile arena's refusal at open: a wrong passphrase or an altered wrap `ProfileOpen`, argon2's allocation failure
/// `ProfileKdfOutOfMemory`.
fn open_code(e: scaas_ua::wallet::Error) -> Error {
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
    /// is missing or does not parse while `p/` holds a profile. No live profile's lock is taken. First run (no profile
    /// directory): "default" created unprotected.
    pub fn new(config: ProfilesConfig) -> Result<Profiles, Error> {
        prepare_root(&config.root)?;
        let pr = Profiles {
            p: config.root.join("p"),
            root: config.root,
            keychain: config.keychain,
            kdf_max_kib: config.kdf_max_kib,
            heavy: Heavy {
                running: Mutex::new(0),
                free: Condvar::new(),
                max: config.max_concurrent_heavy.max(1),
            },
            events: Mutex::new(Vec::new()),
            #[cfg(feature = "test-hooks")]
            before_kdf: Mutex::new(None),
        };
        mkdir(&pr.p)?;
        let first_run = {
            let _root = pr.root_lock()?;
            pr.start()?
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

    fn event(&self, e: ProfileEvent) {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(e);
    }

    fn root_lock(&self) -> Result<File, Error> {
        lock_file(&self.root.join(ROOT_LOCK))
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
                    if let Some(kc) = &self.keychain {
                        for what in KEYCHAIN_ITEMS {
                            kc.delete(&keychain_name(id, what))?;
                        }
                    }
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
    fn scan(&self) -> Result<Vec<(String, Option<Envelope>)>, Error> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.p).map_err(|_| Error::VaultIo)? {
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
            let env = read_envelope(&e.path(), &id).ok().flatten().map(|(e, _)| e);
            out.push((id, env));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// The index under the root lock and its file's rev for `put_if`: rows of missing directories dropped; rebuilt from the
    /// envelopes (and written) when it is missing or does not parse while `p/` holds a profile, one row per envelope with a
    /// public name, protected or not; two with one `name_key` both listed, with `ProfileIndexMismatch`.
    fn index_locked(&self) -> Result<(Index, Option<u64>), Error> {
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
    fn write_index(&self, ix: &mut Index, at: Option<u64>) -> Result<Option<u64>, Error> {
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
        let tag: String = random::<8>()?.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = self.p.join(format!(".tmp-{tag}"));
        mkdir(&tmp)?;
        let r = (|| {
            let _build = lock_file(&tmp.join(BUILD_LOCK))?;
            let env = Envelope::unprotected(&id, &name).json()?;
            file::write(&tmp, &tmp.join(envelope::FILE), &env)?;
            mkdir(&tmp.join("g0"))?;
            let _root = self.root_lock()?;
            self.commit_create(&tmp, &id, &name)
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

    fn commit_create(&self, tmp: &Path, id: &str, name: &str) -> Result<(), Error> {
        if self.scan()?.len() >= DIRS_MAX {
            return Err(Error::ProfileLimit);
        }
        let (mut ix, at) = self.index_locked()?;
        if ix.profiles.iter().any(|r| same_name(&r.name, name)) {
            return Err(Error::ProfileNameTaken);
        }
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
        ix.profiles.push(Row {
            id: id.into(),
            name: name.into(),
        });
        self.write_index(&mut ix, at)?;
        remove_file(&jpath)?;
        sync_dir(&self.p)
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
        // UP7: the profile's own clean-up (spec §7.3: `profile.envelope.next` rolled back, lower generations) runs here, under
        // the instance lock and before the envelope is read
        let (env, bytes) = read_envelope(&dir, id)?.ok_or(Error::ProfileFormat)?;
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
            let label = self.label(keys, &env).inspect_err(|_| keys.lock())?;
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
        let core = Core::open(CoreOpen {
            dir: dir.clone(),
            id: id.into(),
            gen: env.gen,
            keys: keys.clone(),
            keychain: self.keychain.clone(),
            envelope: Head::of(env.rev, &bytes),
            migration_pending: env.migration.is_some(),
        });
        let core = Arc::new(core.inspect_err(|_| {
            if let Some(k) = &keys {
                k.lock()
            }
        })?);
        let opened = OpenProfile {
            info: ProfileInfo {
                id: id.into(),
                name: name.clone(),
                protected: keys.is_some(),
            },
            core,
            keys,
            instance: Mutex::new(Some(instance)),
        };
        if name != hint {
            let mut e = env;
            e.name = Some(name.clone());
            e.rev = e.rev.checked_add(1).ok_or(Error::ProfileFormat)?;
            let b = e.json()?;
            file::write(&dir, &dir.join(envelope::FILE), &b)?;
            opened.core.set_envelope(Head::of(e.rev, &b))?;
        }
        if let (Some(kc), true) = (&self.keychain, opened.info.protected) {
            let marker = keychain_name(id, "protected");
            if kc.get(&marker)?.is_none() {
                kc.put(&marker, b"1")?;
            }
        }
        if self.after_open(id, &name)? || name != hint {
            self.event(ProfileEvent::ProfileIndexMismatch);
        }
        Ok(opened)
    }

    /// The keychain marker's rules (spec §7.1): an unprotected envelope beside it `ProfileFormat`; a protected one beside it
    /// without its keychain anchor `ProfileRollback`.
    fn check_marker(&self, id: &str, state: State) -> Result<(), Error> {
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

    /// The sealed label of a protected envelope: `{name, hidden}`, the name as stored; anything else `ProfileFormat`.
    fn label(&self, keys: &ProfileKeys, env: &Envelope) -> Result<OpenLabel, Error> {
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

    fn drop_row(&self, id: &str) -> Result<(), Error> {
        self.update_index(|ix| {
            let n = ix.profiles.len();
            ix.profiles.retain(|r| r.id != id);
            let last = ix.last.as_deref() == Some(id);
            if last {
                ix.last = None;
            }
            last || n != ix.profiles.len()
        })
    }
}

struct OpenLabel {
    name: Zeroizing<String>,
    hidden: bool,
}

/// The profile's Matrix store (spec §5, §7.2; CLI-UPR-29): its directory `p/<id>/matrix/` and its store key, the one key that
/// leaves the arena (matrix-rust-sdk needs its bytes). No `Debug`.
pub struct MatrixStore {
    pub dir: PathBuf,
    pub key: Zeroizing<Vec<u8>>,
}

/// An open profile: its store core, its arena and its instance lock, until [`OpenProfile::lock`] or drop. No `Debug`.
pub struct OpenProfile {
    info: ProfileInfo,
    core: Arc<Core>,
    keys: Option<Arc<ProfileKeys>>,
    instance: Mutex<Option<File>>,
}

impl OpenProfile {
    pub fn info(&self) -> &ProfileInfo {
        &self.info
    }

    /// The store core (the SDK's faces go over it).
    pub fn core(&self) -> &Arc<Core> {
        &self.core
    }

    /// The profile arena; `None` for an unprotected profile.
    pub fn keys(&self) -> Option<&Arc<ProfileKeys>> {
        self.keys.as_ref()
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
        self.core.close();
        if let Some(k) = &self.keys {
            k.lock();
        }
        drop(
            self.instance
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take(),
        );
    }
}

impl Drop for OpenProfile {
    fn drop(&mut self) {
        self.lock();
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
