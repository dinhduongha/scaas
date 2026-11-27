// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Hidden profiles (spec §8, §6, §10; CLI-UPR-13, CLI-UPR-14): [`Profiles::create_hidden`], [`Profiles::open_hidden`] (the
//! counted search), [`Profiles::hide`], [`Profiles::show`], [`Profiles::rename`].
//!
//! - **The search** reads `p/` without any instance lock and without the root lock: the candidates are the UUID-named
//!   directories whose envelope has no public name or is missing or unusable (never the index, never `.tmp-*`, tombstones or
//!   `.journal`); more than 32 is `ProfileSearchTooLarge` before any run. It makes max(candidates, 4) Argon2id runs: each
//!   usable candidate at its own parameters (its wrap, then its sealed name against the typed one by `name_key`, in constant
//!   time), each unusable one a dummy run, dummy runs up to four; no early stop. Each candidate has its own arena.
//! - **No duplicate**: `create_hidden`, `hide()`, a hidden rename and a hidden passphrase change first run the search with the
//!   resulting (name, passphrase); a match other than the profile itself is `ProfileNameTaken`.
//! - At most 16 hidden profiles (`ProfileHiddenLimit`); a hidden profile writes no index byte and never `last`.
use crate::envelope::{self, label_json, Envelope, Kdf, KdfParams, State, B64};
use crate::file::{self, lock_file, mkdir, try_lock_file};
use crate::index::{self, Row};
use crate::names::{check_name, new_id, random_vec, same_name};
use crate::profile::{
    open_label, read_envelope, remove_dir, scan, Heavy, OpenProfile, ProfileEvent, Profiles,
    BUILD_LOCK, INSTANCE_LOCK,
};
use crate::reseal::{check_passphrase, kdf_code};
use crate::store::{Core, WriteGuard};
use crate::{keychain_name, Error, Head};
use base64::Engine;
use scaas_ua::wallet::{Argon2Params, ProfileKeys};
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// At most 16 hidden profiles per root (spec §8).
pub(crate) const HIDDEN_MAX: usize = 16;
/// At most 32 candidates (the directory limit) for one search.
const SEARCH_MAX: usize = 32;
/// The fewest Argon2id runs of a search.
const RUNS_MIN: usize = 4;

/// A dummy run's parameters: the default set. Controller call (UP8): under `test-hooks` the test set, at which the tests'
/// profiles are, so a test search costs one test-set run per candidate as a release search costs one default run.
#[cfg(not(feature = "test-hooks"))]
const DUMMY: Argon2Params = ProfileKeys::KDF_DEFAULT;
#[cfg(feature = "test-hooks")]
const DUMMY: Argon2Params = ProfileKeys::KDF_TEST;

/// A candidate that matched: its id, its envelope's bytes as the search read them, its arena holding `DEK_p`.
pub(crate) struct Found {
    id: String,
    bytes: Vec<u8>,
    keys: Arc<ProfileKeys>,
}

fn lock_all(found: Vec<Found>) {
    for f in found {
        f.keys.lock();
    }
}

/// `ProfileNameTaken` when a match other than profile `me` is found; every matched arena wiped.
pub(crate) fn taken(found: Vec<Found>, me: &str) -> Result<(), Error> {
    let other = found.iter().any(|f| f.id != me);
    lock_all(found);
    match other {
        true => Err(Error::ProfileNameTaken),
        false => Ok(()),
    }
}

/// One dummy run, in the heavy limiter.
fn dummy(heavy: &Heavy) -> Result<(), Error> {
    let _h = heavy.acquire();
    ProfileKeys::dummy_kdf(DUMMY).map_err(kdf_code)
}

/// One candidate, one run: its arena when its wrap opens under `pass` and its sealed name has `name`'s `name_key`. A candidate
/// without a usable envelope (missing, unprotected, a public name, parameters out of bounds or above `max_kib`, a wrap not of
/// its form) costs a dummy run.
fn try_one(
    heavy: &Heavy,
    max_kib: u32,
    env: Option<&Envelope>,
    name: &str,
    pass: &[u8],
) -> Result<Option<Arc<ProfileKeys>>, Error> {
    let usable = env
        .filter(|e| e.state == State::Protected && e.name.is_none())
        .and_then(|e| {
            let (a, salt) = e.kdf.as_ref()?.check(max_kib).ok()?;
            let wrap = B64
                .decode(e.pass.as_deref()?)
                .ok()
                .filter(|w| w.len() == 60)?;
            Some((e, a, salt, wrap, e.public_json().ok()?))
        });
    let Some((e, a, salt, wrap, public)) = usable else {
        dummy(heavy)?;
        return Ok(None);
    };
    let keys = Arc::new(ProfileKeys::new());
    let opened = {
        let _h = heavy.acquire();
        keys.open_pass(pass, &salt, a, &public, &wrap)
    };
    match opened {
        Err(scaas_ua::wallet::Error::KdfOutOfMemory) => return Err(Error::ProfileKdfOutOfMemory),
        Err(_) => return Ok(None),
        Ok(()) => {}
    }
    match open_label(&keys, e) {
        Ok(l) if same_name(&l.name, name) => Ok(Some(keys)),
        _ => {
            keys.lock();
            Ok(None)
        }
    }
}

/// The search of spec §8 steps 1 and 2 over `p/`: every match (none, one, or more). Reads no lock. A failed run
/// (`ProfileKdfOutOfMemory`) is returned only after every run.
pub(crate) fn search(
    p: &Path,
    heavy: &Heavy,
    max_kib: u32,
    name: &str,
    pass: &[u8],
) -> Result<Vec<Found>, Error> {
    let candidates: Vec<_> = scan(p)?
        .into_iter()
        .filter(|(_, e)| e.as_ref().is_none_or(|(e, _)| e.name.is_none()))
        .collect();
    if candidates.len() > SEARCH_MAX {
        return Err(Error::ProfileSearchTooLarge);
    }
    // a passphrase that is no OpaqueString (empty, a control character) opens nothing, and still costs every run: each
    // candidate a dummy (spec §8 step 2, review F-1)
    let usable = scaas_ua::wallet::passphrase_bytes(pass).is_ok();
    let (mut found, mut failed) = (Vec::new(), None);
    for (id, env) in &candidates {
        let e = env.as_ref().map(|(e, _)| e).filter(|_| usable);
        match try_one(heavy, max_kib, e, name, pass) {
            Ok(Some(keys)) => found.push(Found {
                id: id.clone(),
                bytes: env.as_ref().map(|(_, b)| b.clone()).unwrap_or_default(),
                keys,
            }),
            Ok(None) => {}
            Err(e) => {
                failed.get_or_insert(e);
            }
        }
    }
    for _ in candidates.len()..RUNS_MIN {
        if let Err(e) = dummy(heavy) {
            failed.get_or_insert(e);
        }
    }
    if let Some(e) = failed {
        lock_all(found);
        return Err(e);
    }
    Ok(found)
}

/// The label `{name, hidden}` sealed under the held `DEK_p`, base64.
pub(crate) fn seal_label(
    keys: &ProfileKeys,
    id: &str,
    name: &str,
    hidden: bool,
) -> Result<String, Error> {
    let pt = label_json(name, hidden)?;
    let sealed = keys.seal_label(id, &pt).map_err(kdf_code)?;
    Ok(B64.encode(sealed))
}

/// The envelope read again under the store write lock: `StoreConflict` when it is not `bytes`, as read before the lock
/// (another write landed while a KDF ran outside it, review F-5).
pub(crate) fn unchanged(core: &Core, id: &str, bytes: &[u8]) -> Result<Envelope, Error> {
    match read_envelope(core.dir(), id)?.ok_or(Error::ProfileFormat)? {
        (env, b) if b == bytes => Ok(env),
        _ => Err(Error::StoreConflict),
    }
}

/// `env` written with its rev raised, under the store write lock `w`; the anchor follows.
fn write_envelope(core: &Core, w: &WriteGuard, env: &mut Envelope) -> Result<(), Error> {
    env.rev = env.rev.checked_add(1).ok_or(Error::ProfileFormat)?;
    let b = env.json()?;
    file::write(core.dir(), &core.dir().join(envelope::FILE), &b)?;
    core.envelope_written(w, Head::of(env.rev, &b))
}

fn utf8(name: &[u8]) -> Result<&str, Error> {
    std::str::from_utf8(name).map_err(|_| Error::ProfileNameInvalid)
}

impl Profiles {
    /// A new hidden profile (spec §8, §10 "create hidden"): `name` (UTF-8, typed) and `passphrase`, the passphrase rule
    /// (`ProfilePassphraseWeak`) and `kdf` (default 64 MiB / 3; `ProfileFormat`, `ProfileKdfTooLarge`) and room (`ProfileLimit`
    /// at 32 directories, `ProfileHiddenLimit` at 16 hidden) before any KDF; then the duplicate search (`ProfileNameTaken`);
    /// then built protected in `p/.tmp-<random>/` (no public name, its label sealed hidden) and committed as a create, with no
    /// index byte read or written. Returns it open (its instance lock taken before the rename).
    pub fn create_hidden(
        &self,
        name: &[u8],
        passphrase: &[u8],
        kdf: Option<KdfParams>,
    ) -> Result<OpenProfile, Error> {
        let name = Zeroizing::new(check_name(utf8(name)?)?);
        check_passphrase(passphrase)?;
        let params = kdf.unwrap_or(KdfParams::DEFAULT);
        let k = Kdf {
            alg: "argon2id".into(),
            v: 1,
            m: params.m_kib.into(),
            t: params.t.into(),
            p: 4,
            salt: B64.encode(&random_vec(16)?[..]),
        };
        let (argon, salt) = k.check(self.kdf_max_kib)?;
        self.room(true, true)?;
        taken(
            search(&self.p, &self.heavy, self.kdf_max_kib, &name, passphrase)?,
            "",
        )?;
        let id = new_id()?;
        let mut env = Envelope {
            state: State::Protected,
            gen: 1,
            name: None,
            kdf: Some(k),
            ..Envelope::unprotected(&id, "")
        };
        let keys = Arc::new(ProfileKeys::new());
        let built = (|| {
            keys.create_dek().map_err(kdf_code)?;
            env.label = Some(seal_label(&keys, &id, &name, true)?);
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
        let r = (|| {
            let _build = lock_file(&tmp.join(BUILD_LOCK))?;
            file::write(&tmp, &tmp.join(envelope::FILE), &bytes)?;
            mkdir(&tmp.join("g1"))?;
            let instance = try_lock_file(&tmp.join(INSTANCE_LOCK))?.ok_or(Error::VaultIo)?;
            let _root = self.root_lock()?;
            self.commit_create(&tmp, &id, None)?;
            Ok(instance)
        })();
        if r.is_err() {
            let _ = remove_dir(&tmp);
            keys.lock();
        }
        let instance = r?;
        self.finish(instance, &env, &bytes, Some(keys), &name, true, &[])
    }

    /// Opens a hidden profile by its `name` and `passphrase`, both typed (spec §8): the search; on exactly one match its
    /// instance lock (`ProfileInUse`), its envelope read again under it (another than the search opened: `ProfileOpen`), the
    /// open-time rules of spec §7.3, the store opened. Zero or several matches, and every other failure of the search,
    /// `ProfileOpen`. Writes no index byte (never `last`).
    pub fn open_hidden(&self, name: &[u8], passphrase: &[u8]) -> Result<OpenProfile, Error> {
        let name = std::str::from_utf8(name).map_err(|_| Error::ProfileOpen)?;
        let mut found = search(&self.p, &self.heavy, self.kdf_max_kib, name, passphrase)?;
        let f = match found.len() {
            1 => found.pop().ok_or(Error::ProfileOpen)?,
            _ => {
                lock_all(found);
                return Err(Error::ProfileOpen);
            }
        };
        self.open_found(&f).inspect_err(|_| f.keys.lock())
    }

    fn open_found(&self, f: &Found) -> Result<OpenProfile, Error> {
        let dir = self.p.join(&f.id);
        let instance = try_lock_file(&dir.join(INSTANCE_LOCK))?.ok_or(Error::ProfileInUse)?;
        let (env, bytes) = read_envelope(&dir, &f.id)?.ok_or(Error::ProfileOpen)?;
        if bytes != f.bytes {
            return Err(Error::ProfileOpen);
        }
        let lower = self.generations(&dir, &f.id, env.gen)?;
        self.check_marker(&f.id, env.state)?;
        let label = open_label(&f.keys, &env)?;
        let opened = self.finish(
            instance,
            &env,
            &bytes,
            Some(f.keys.clone()),
            &label.name,
            label.hidden,
            &lower,
        )?;
        // spec §6: a visible label beside no hint (a stripped hint): the hint and the row rewritten from the label
        if !label.hidden {
            self.rewrite_hint(&opened, env, &label.name)?;
            self.update_index(|ix| {
                let add =
                    !ix.profiles.iter().any(|r| r.id == f.id) && ix.profiles.len() < index::ROWS;
                if add {
                    ix.profiles.push(Row {
                        id: f.id.clone(),
                        name: label.name.to_string(),
                    });
                }
                add
            })?;
            self.event(ProfileEvent::ProfileIndexMismatch);
        }
        Ok(opened)
    }

    /// `o` is a profile of this root.
    fn mine(&self, o: &OpenProfile) -> Result<(), Error> {
        match o.core().dir().parent() == Some(self.p.as_path()) {
            true => Ok(()),
            false => Err(Error::Argument),
        }
    }

    /// Under the root lock: `name` free among the other rows (`ProfileNameTaken`), then the row of `id` written with it.
    fn put_row(&self, id: &str, name: &str) -> Result<(), Error> {
        let _root = self.root_lock()?;
        let (mut ix, at) = self.index_locked()?;
        if ix
            .profiles
            .iter()
            .any(|r| r.id != id && same_name(&r.name, name))
        {
            return Err(Error::ProfileNameTaken);
        }
        let room = ix.profiles.len() < index::ROWS;
        match ix.profiles.iter_mut().find(|r| r.id == id) {
            Some(r) => r.name = name.into(),
            None if room => ix.profiles.push(Row {
                id: id.into(),
                name: name.into(),
            }),
            None => return Err(Error::ProfileLimit),
        }
        self.write_index(&mut ix, at).map(drop)
    }

    /// Hides the open, protected, visible profile `o` (spec §8): room for one more hidden (`ProfileHiddenLimit`) before any
    /// KDF; `passphrase` (typed) checked against its wrap (`ProfileOpen`), then the duplicate search with (its name,
    /// `passphrase`) (`ProfileNameTaken`); then one envelope write under the store write lock: the public name and the
    /// platform wrap removed, the label re-sealed hidden under `DEK_p`, the wraps untouched; the anchor rewritten; the
    /// platform key removed from the keychain; its row and `last` dropped. Unprotected: `ProfilePassphraseRequired`; hidden:
    /// `Argument`.
    pub fn hide(&self, o: &OpenProfile, passphrase: &[u8]) -> Result<(), Error> {
        self.mine(o)?;
        let (core, info) = (o.core(), o.info());
        core.live()?;
        let keys = core.keys().ok_or(Error::ProfilePassphraseRequired)?;
        if info.hidden {
            return Err(Error::Argument);
        }
        self.room(false, true)?;
        // the wrap check and the duplicate search before the store write lock (review F-5)
        let (env, bytes) = read_envelope(core.dir(), &info.id)?.ok_or(Error::ProfileFormat)?;
        o.check_pass(&env, passphrase)?;
        let found = search(
            &self.p,
            &self.heavy,
            self.kdf_max_kib,
            &info.name,
            passphrase,
        )?;
        taken(found, &info.id)?;
        let w = core.write_lock()?;
        let mut env = unchanged(core, &info.id, &bytes)?;
        // the row first, then the envelope (review A-7): a crash between them leaves no row naming a hidden profile
        self.drop_row(&info.id)?;
        env.label = Some(seal_label(&keys, &info.id, &info.name, true)?);
        env.name = None;
        env.platform = None;
        write_envelope(core, &w, &mut env)?;
        if let Some(kc) = &self.keychain {
            kc.delete(&keychain_name(&info.id, "unlock"))?;
        }
        drop(w);
        o.set_hidden(true);
        Ok(())
    }

    /// Shows the open, hidden profile `o` (spec §8): its name free among the visible ones (`ProfileNameTaken`), its row
    /// written first (a crash before the envelope leaves a row on an envelope without a public name, which the next open
    /// drops), then the public name and the label re-sealed visible, one envelope write; the anchor rewritten. No passphrase.
    pub fn show(&self, o: &OpenProfile) -> Result<(), Error> {
        self.mine(o)?;
        let (core, info) = (o.core(), o.info());
        let w = core.write_lock()?;
        let (mut env, _) = read_envelope(core.dir(), &info.id)?.ok_or(Error::ProfileFormat)?;
        let keys = core.keys().ok_or(Error::ProfilePassphraseRequired)?;
        if !info.hidden {
            return Err(Error::Argument);
        }
        env.label = Some(seal_label(&keys, &info.id, &info.name, false)?);
        env.name = Some(info.name.clone());
        self.put_row(&info.id, &info.name)?;
        write_envelope(core, &w, &mut env)?;
        o.set_hidden(false);
        Ok(())
    }

    /// Renames the open profile `o` (spec §10 "rename"): the label re-sealed under `DEK_p` (a protected profile), the wraps
    /// untouched. A visible profile: no passphrase, its name free among the visible ones (`ProfileNameTaken`), its row and its
    /// hint. A hidden profile: `passphrase` needed (`Argument` without), checked against its wrap (`ProfileOpen`), then the
    /// duplicate search with (the new name, `passphrase`) (`ProfileNameTaken`); no row. `ProfileNameInvalid` first.
    pub fn rename(
        &self,
        o: &OpenProfile,
        name: &[u8],
        passphrase: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.mine(o)?;
        let name = Zeroizing::new(check_name(utf8(name)?)?);
        let (core, info) = (o.core(), o.info());
        core.live()?;
        // hidden is the sealed label's flag, never the hint on disk (review G-2)
        let hidden = info.hidden;
        // a hidden profile: the wrap check and the duplicate search before the store write lock (review F-5)
        let seen = match (core.keys(), hidden) {
            (Some(_), true) => {
                let pass = passphrase.ok_or(Error::Argument)?;
                let (env, bytes) =
                    read_envelope(core.dir(), &info.id)?.ok_or(Error::ProfileFormat)?;
                o.check_pass(&env, pass)?;
                taken(
                    search(&self.p, &self.heavy, self.kdf_max_kib, &name, pass)?,
                    &info.id,
                )?;
                Some(bytes)
            }
            _ => None,
        };
        let w = core.write_lock()?;
        let mut env = match &seen {
            Some(b) => unchanged(core, &info.id, b)?,
            None => {
                read_envelope(core.dir(), &info.id)?
                    .ok_or(Error::ProfileFormat)?
                    .0
            }
        };
        if let Some(keys) = core.keys() {
            env.label = Some(seal_label(&keys, &info.id, &name, hidden)?);
        }
        match hidden {
            false => {
                self.put_row(&info.id, &name)?;
                env.name = Some(name.to_string());
            }
            // a hint planted on a hidden profile goes
            true => env.name = None,
        }
        write_envelope(core, &w, &mut env)?;
        o.set_name(&name);
        Ok(())
    }
}
