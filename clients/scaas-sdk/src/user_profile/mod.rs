// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `user_profile` (feature `user-profile`; spec docs/superpowers/specs/2026-11-27-user-profiles.md, rules CLI-UPR-* of
//! docs/clients/scaas-sdk.md §12): many protected local profiles. The store is the crate `scaas-profile` (owner
//! 2026-11-27, CLI-UPR-02's Change: an app's build without the SDK holds a profile with it); this module adds what needs the
//! SDK. Built so far: the store's `SecureStore` face ([`PartStore`]) and the mapping of its codes (plan UP5); the profiles
//! over the crate ([`UserProfiles`]), an open profile's `Sdk`, stores and lock ([`UserProfile`]), `Sdk::close` at lock, the
//! events (plan UP6); the re-seal's calls and the refusal of every secret-creating call on an unprotected profile's `Sdk`
//! (plan UP7); hidden profiles: `create_hidden`, `open_hidden`, `hide`, `show`, `rename` (plan UP8); delete with the seeds'
//! backups checked, `delete_locked`, `rebuild_index`, the migration of the CLI's store into "default" and the refusal of
//! every vault call on it until it is sealed (plan UP9); the settings with the rule of spec §7.7, export, and import in two
//! calls with the keystore checked by the SDK's parser and `sdk.state`'s operations marked `imported` (plan UP10). Outside the
//! binding surface in wave 1. UNAUDITED.
pub use scaas_profile::settings::{
    Caps, ChainSettings, CredentialKind, CredentialRef, Endpoint, EndpointList, ReviewItem, Setting,
};
pub use scaas_profile::{
    check_name, keychain_name, name_key, same_name, Anchor, ConfirmDeleteUnreadable,
    ConfirmPurgeTombstones, ConfirmRebuildIndex, Core, CoreOpen, Error, Head, Item, KdfParams,
    Manifest, MatrixStore, Plain, ProfileEvent, ProfileInfo as UserProfileInfo, ProfileKeychain,
    ProfilePart, ProfileSettings, Verdict, WriteGuard, PART_MAX,
};

use crate::error::SdkError;
use crate::platform::Authenticator;
use crate::vault::store::blocking;
use crate::vault::{
    FileStore, Keystore, SecureStore, StoreError, StoreLock, StorePolicy, StoredItem, HEAD,
    KEYSTORE,
};
use crate::{ChainProfile, Clock, Event, GasTable, Limits, RuntimeChoice, Sdk, SdkConfig};
use async_trait::async_trait;
use scaas_profile::{OpenProfile, Profiles};
use scaas_ua::wallet::SecretBytes;
use std::sync::Arc;
use zeroize::Zeroizing;

/// What [`UserProfiles::new`] takes (spec §11).
pub struct ProfilesConfig {
    /// the profile root, a directory on every platform (on mobile the app's private directory)
    pub root: String,
    /// anchors and the `protected` marker; `None`: files beside the profile (spec §7.2)
    pub keychain: Option<Arc<dyn ProfileKeychain>>,
    /// the authenticator every profile's `Sdk` gets
    pub authenticator: Option<Arc<dyn Authenticator>>,
    /// every profile's `Sdk` limits; `max_concurrent_heavy` is also the profiles' own Argon2id limiter
    pub limits: Limits,
    /// this device's largest Argon2id memory in KiB (spec §7.5): 1 GiB by default, lower on mobile
    pub kdf_max_kib: u32,
    /// the CLI's data directory of today's single store (spec §12), migrated into "default" at start; the caller computes it
    /// (the SDK reads no environment)
    pub legacy: Option<String>,
    /// the CLI's overlay (`$XDG_CONFIG_HOME/scaas/overlay.json`, else `~/.config/scaas/overlay.json`), moved into "default"'s
    /// settings by the migration; the caller computes it
    pub legacy_overlay: Option<String>,
    /// whether an open writes the index's `last` (spec §6, §13; review E-5): true by default (an app, a TUI instance); the CLI
    /// sets false (it never follows `last`, so it never writes it)
    pub write_last: bool,
}

impl ProfilesConfig {
    /// `root` with no keychain, no authenticator, the default limits and the desktop KDF maximum.
    pub fn new(root: String) -> ProfilesConfig {
        ProfilesConfig {
            root,
            keychain: None,
            authenticator: None,
            limits: Limits::default(),
            kdf_max_kib: KdfParams::MAX_KIB,
            legacy: None,
            legacy_overlay: None,
            write_last: true,
        }
    }
}

/// `delete`'s name typed again (spec §10), compared by `name_key`.
pub struct ConfirmDeleteProfile {
    pub name: Arc<SecretBytes>,
}

/// The second marker of `delete`, for a profile holding a seed whose backup is `pending` (the crate's: the store refuses a
/// delete of a profile holding a keystore without it, review E-3).
pub use scaas_profile::ConfirmDeleteUnbacked;

/// What a delete loses (spec §10): the seeds of the profile's keystore and how many have no backup (`backup: pending`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeletePreview {
    pub seeds: u32,
    pub unbacked: u32,
}

/// `export`'s name typed again (spec §10.1), compared by `name_key`.
pub struct ConfirmExportProfile {
    pub name: Arc<SecretBytes>,
}

/// Where an export goes (spec §10.1): a new file at a path (native); the share sheet of mobile and wasm is wave 2.
pub enum ExportTarget {
    Path(String),
}

/// An import's file: a path, or its bytes (at most the file bound, [`scaas_profile::FILE_MAX`]).
pub enum ImportSource {
    Path(String),
    Bytes(Vec<u8>),
}

/// What [`UserProfiles::import`] applies: the review's settings confirmed by item id, and the new passphrase's KDF
/// parameters (`None`: 64 MiB / 3).
pub struct ImportChoices {
    pub confirm: Vec<u32>,
    pub kdf: Option<KdfParams>,
}

/// An opened export (spec §10.1): the store's review (its payload in memory only, wiped at drop) with the seed and account
/// counts of its keystore. No `Debug`.
pub struct ImportReview {
    review: scaas_profile::ImportReview,
    pub seeds: u32,
    pub accounts: u32,
}

impl ImportReview {
    pub fn name(&self) -> &str {
        self.review.name()
    }

    pub fn hidden(&self) -> bool {
        self.review.hidden()
    }

    /// Every setting with its item id; the kept ones marked (credential references are never listed).
    pub fn settings(&self) -> Vec<ReviewItem> {
        self.review.settings()
    }
}

const STATE: &str = "sdk.state";

/// How a protected profile opens (spec §11; the platform unlock is wave 2).
pub enum ProfileUnlock {
    Passphrase(Arc<SecretBytes>),
}

/// What [`UserProfile::sdk`] takes: the store, the authenticator and the limits are the profile's.
pub struct ProfileSdkConfig {
    pub chain_profiles: Vec<ChainProfile>,
    pub rp_id: Option<String>,
    pub runtime: RuntimeChoice,
    pub clock: Option<Clock>,
    pub gas_tables: Vec<GasTable>,
}

/// A crate call on a blocking thread, its code the SDK's.
async fn run<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, SdkError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| SdkError::Internal)?
        .map_err(SdkError::from)
}

/// A crate event as the SDK's of the same name.
fn event(e: ProfileEvent) -> Event {
    match e {
        ProfileEvent::ProfileIndexMismatch => Event::ProfileIndexMismatch,
        ProfileEvent::ProfileRollback => Event::ProfileRollback,
        ProfileEvent::ProfileDamaged => Event::ProfileDamaged,
    }
}

/// The profiles of one root (spec §10, §11). No `Debug`.
pub struct UserProfiles {
    profiles: Arc<Profiles>,
    authenticator: Option<Arc<dyn Authenticator>>,
    limits: Limits,
}

impl UserProfiles {
    /// Start (spec §10): the root checked, the journal, the clean-up, the index rebuilt when lost; first run "default".
    pub async fn new(config: ProfilesConfig) -> Result<Arc<UserProfiles>, SdkError> {
        let mut c = scaas_profile::ProfilesConfig::new(config.root.into());
        c.keychain = config.keychain;
        c.kdf_max_kib = config.kdf_max_kib;
        c.max_concurrent_heavy = config.limits.max_concurrent_heavy as usize;
        c.legacy = config.legacy.map(Into::into);
        c.legacy_overlay = config.legacy_overlay.map(Into::into);
        c.write_last = config.write_last;
        let profiles = Arc::new(run(move || Profiles::new(c)).await?);
        Ok(Arc::new(UserProfiles {
            profiles,
            authenticator: config.authenticator,
            limits: config.limits,
        }))
    }

    /// The visible profiles.
    pub async fn list(&self) -> Result<Vec<UserProfileInfo>, SdkError> {
        let p = self.profiles.clone();
        run(move || p.list()).await
    }

    /// A new unprotected profile.
    pub async fn create(&self, name: String) -> Result<UserProfileInfo, SdkError> {
        let p = self.profiles.clone();
        run(move || p.create(&name)).await
    }

    /// Opens profile `id` (spec §10 "open"): a protected one with its passphrase (`Argument` without one).
    pub async fn open(
        &self,
        id: String,
        unlock: Option<ProfileUnlock>,
    ) -> Result<Arc<UserProfile>, SdkError> {
        let p = self.profiles.clone();
        let open = run(move || match unlock {
            Some(ProfileUnlock::Passphrase(pass)) => pass.with(|b| p.open(&id, Some(b))),
            None => p.open(&id, None),
        })
        .await?;
        Ok(self.profile(open))
    }

    /// A new hidden profile, open (spec §8): its name and passphrase typed; `kdf` `None` the default (64 MiB / 3).
    /// `ProfileNameTaken` (a hidden profile with this name and passphrase), `ProfileHiddenLimit`, `ProfileLimit`,
    /// `ProfilePassphraseWeak`, `ProfileNameInvalid`. Writes no index byte.
    pub async fn create_hidden(
        &self,
        name: Arc<SecretBytes>,
        passphrase: Arc<SecretBytes>,
        kdf: Option<KdfParams>,
    ) -> Result<Arc<UserProfile>, SdkError> {
        let p = self.profiles.clone();
        let open = run(move || name.with2(&passphrase, |n, s| p.create_hidden(n, s, kdf))).await?;
        Ok(self.profile(open))
    }

    /// Opens a hidden profile by its name and passphrase (spec §8): the counted search over the profile directories;
    /// `ProfileOpen` for every failure but `ProfileInUse`, `ProfileSearchTooLarge`, `ProfileKdfOutOfMemory`.
    pub async fn open_hidden(
        &self,
        name: Arc<SecretBytes>,
        passphrase: Arc<SecretBytes>,
    ) -> Result<Arc<UserProfile>, SdkError> {
        let p = self.profiles.clone();
        let open = run(move || name.with2(&passphrase, |n, s| p.open_hidden(n, s))).await?;
        Ok(self.profile(open))
    }

    /// Deletes the visible profile `id` without opening it (spec §10, a lost passphrase): its name typed again and
    /// `ConfirmDeleteUnreadable` (the client said the data cannot be opened and is lost). `ProfileInUse`, `ProfileUnknown`
    /// (also a hidden profile: no call deletes it by id), `ConfirmationMissing`.
    pub async fn delete_locked(
        &self,
        id: String,
        confirm: ConfirmDeleteProfile,
        unreadable: ConfirmDeleteUnreadable,
    ) -> Result<(), SdkError> {
        let p = self.profiles.clone();
        run(move || confirm.name.with(|n| p.delete_locked(&id, n, unreadable))).await
    }

    /// The index rebuilt from the envelopes on demand (spec §6).
    pub async fn rebuild_index(&self, confirm: ConfirmRebuildIndex) -> Result<(), SdkError> {
        let p = self.profiles.clone();
        run(move || p.rebuild_index(confirm)).await
    }

    /// Every tombstone marker removed (owner 2026-11-28, review G-1): a profile directory put back under a deleted id is
    /// refused (`ProfileRollback`) until this call, after which it opens again.
    pub async fn purge_tombstones(&self, confirm: ConfirmPurgeTombstones) -> Result<(), SdkError> {
        let p = self.profiles.clone();
        run(move || p.purge_tombstones(confirm)).await
    }

    /// Opens an export (spec §10.1, the first call): read and verified whole in memory, nothing written; its keystore checked
    /// by the SDK's parser and its seeds and accounts counted; its `sdk.state`, whose operations the store marked `imported`,
    /// read by the SDK's own parser of the item (review C-5). Every refusal is
    /// `ProfileImportOpen` (the store's local reason: `last_import_refusal`), but `ProfileKdfTooLarge` and
    /// `ProfileKdfOutOfMemory`.
    pub async fn import_preview(
        &self,
        source: ImportSource,
        export_passphrase: Arc<SecretBytes>,
    ) -> Result<Arc<ImportReview>, SdkError> {
        let p = self.profiles.clone();
        let r = run(move || {
            export_passphrase.with(|e| match &source {
                ImportSource::Path(s) => {
                    p.import_preview(scaas_profile::ImportSource::Path(s.as_ref()), e)
                }
                ImportSource::Bytes(b) => {
                    p.import_preview(scaas_profile::ImportSource::Bytes(b), e)
                }
            })
        })
        .await?;
        let ks = match r.item(KEYSTORE) {
            Some(b) => Keystore::parse(b).map_err(|_| SdkError::ProfileImportOpen)?,
            None => Keystore::default(),
        };
        if let Some(b) = r.item(STATE) {
            crate::op::state::check(b).map_err(|_| SdkError::ProfileImportOpen)?;
        }
        let n = |c: usize| u32::try_from(c).unwrap_or(u32::MAX);
        Ok(Arc::new(ImportReview {
            seeds: n(ks.seeds.len()),
            accounts: n(ks.seeds.iter().map(|s| s.accounts.len()).sum()),
            review: r,
        }))
    }

    /// Imports a reviewed export (spec §10.1, the second call) as a new protected profile under `profile_passphrase` (a new
    /// id; `name` `None`: the file's), with the settings kept without a confirm and those `choices` confirms by item id, never
    /// a credential reference. Not opened. `ProfilePassphraseWeak`, `ProfileNameTaken`, `ProfileLimit`, `ProfileHiddenLimit`.
    pub async fn import(
        &self,
        review: Arc<ImportReview>,
        choices: ImportChoices,
        profile_passphrase: Arc<SecretBytes>,
        name: Option<String>,
    ) -> Result<UserProfileInfo, SdkError> {
        let p = self.profiles.clone();
        run(move || {
            profile_passphrase.with(|s| {
                let name = name.as_deref().map(str::as_bytes);
                p.import(&review.review, &choices.confirm, s, name, choices.kdf)
            })
        })
        .await
    }

    fn profile(&self, open: OpenProfile) -> Arc<UserProfile> {
        Arc::new(UserProfile {
            open: Arc::new(open),
            profiles: self.profiles.clone(),
            sdk: tokio::sync::Mutex::new(None),
            authenticator: self.authenticator.clone(),
            limits: self.limits.clone(),
        })
    }

    /// The events since the last call (no id, no name).
    pub fn events(&self) -> Vec<Event> {
        self.profiles
            .drain_events()
            .into_iter()
            .map(event)
            .collect()
    }
}

/// An open profile (spec §11): its `Sdk`, its stores, its lock. No `Debug`.
pub struct UserProfile {
    open: Arc<OpenProfile>,
    profiles: Arc<Profiles>,
    sdk: tokio::sync::Mutex<Option<Arc<Sdk>>>,
    authenticator: Option<Arc<dyn Authenticator>>,
    limits: Limits,
}

impl UserProfile {
    /// The `Sdk` on this profile (its part `sdk` the store); a second call returns the same `Sdk`. `ProfileLocked` after lock.
    pub async fn sdk(&self, config: ProfileSdkConfig) -> Result<Arc<Sdk>, SdkError> {
        let mut held = self.sdk.lock().await;
        self.open.core().live()?;
        if let Some(s) = held.as_ref() {
            return Ok(s.clone());
        }
        let s = Sdk::open(SdkConfig {
            profiles: config.chain_profiles,
            store: PartStore::new(self.open.core().clone(), ProfilePart::Sdk)?,
            authenticator: self.authenticator.clone(),
            rp_id: config.rp_id,
            runtime: config.runtime,
            limits: self.limits.clone(),
            clock: config.clock,
            gas_tables: config.gas_tables,
        })
        .await?;
        // the gate of spec §7.6: while the profile is unprotected, every secret-creating call is `ProfilePassphraseRequired`;
        // the `Sdk` holds the open profile, so its instance lock lives as long as the `Sdk` (review C-4)
        let _ = s.profile.set(self.open.clone());
        *held = Some(s.clone());
        Ok(s)
    }

    /// Protects this unprotected profile under `passphrase` (spec §7.3, §7.6): `kdf` `None` the default (64 MiB / 3);
    /// `keep_settings` the `settings` item's bytes to seal (what the user kept of the settings shown), `None` drops them. From
    /// the commit on, this profile's `Sdk` creates secrets. `ProfilePassphraseWeak`, `ProfileFormat` / `ProfileKdfTooLarge`
    /// (the parameters), `Argument` on a protected profile, `ProfileBusy`, `ProfileKdfOutOfMemory`.
    pub async fn set_passphrase(
        &self,
        passphrase: Arc<SecretBytes>,
        kdf: Option<KdfParams>,
        keep_settings: Option<Vec<u8>>,
    ) -> Result<(), SdkError> {
        let open = self.open.clone();
        let keep = keep_settings.map(Zeroizing::new);
        run(move || {
            passphrase.with(|p| open.set_passphrase(p, kdf, keep.as_deref().map(|k| &k[..])))
        })
        .await
    }

    /// A new passphrase (and a new `DEK_p`) on this protected profile (spec §7.3): `old` checked against the wrap
    /// (`ProfileOpen`); `kdf` `None` keeps the parameters, the same passphrase with new parameters raises them. Writers of
    /// every part wait for the commit, then write into the new generation. `Argument` on an unprotected profile.
    pub async fn change_passphrase(
        &self,
        old: Arc<SecretBytes>,
        new: Arc<SecretBytes>,
        kdf: Option<KdfParams>,
    ) -> Result<(), SdkError> {
        let open = self.open.clone();
        run(move || old.with2(&new, |o, n| open.change_passphrase(o, n, kdf))).await
    }

    /// Hides this protected, visible profile (spec §8): `passphrase` typed, checked against its wrap and used for the
    /// duplicate search (controller call UP8: the spec's `hide()` runs that search with the resulting name and passphrase);
    /// the public name and its row dropped, the label re-sealed hidden, the wraps untouched.
    pub async fn hide(&self, passphrase: Arc<SecretBytes>) -> Result<(), SdkError> {
        let (p, open) = (self.profiles.clone(), self.open.clone());
        run(move || passphrase.with(|s| p.hide(&open, s))).await
    }

    /// Shows this hidden profile (spec §8): its public name and row written (`ProfileNameTaken` when a visible profile has
    /// the name). No passphrase.
    pub async fn show(&self) -> Result<(), SdkError> {
        let (p, open) = (self.profiles.clone(), self.open.clone());
        run(move || p.show(&open)).await
    }

    /// Renames this profile (spec §10): the label re-sealed, the wraps untouched; a visible one's hint and row (no
    /// passphrase); a hidden one needs `passphrase` (`Argument` without) for its duplicate search.
    pub async fn rename(
        &self,
        name: Arc<SecretBytes>,
        passphrase: Option<Arc<SecretBytes>>,
    ) -> Result<(), SdkError> {
        let (p, open) = (self.profiles.clone(), self.open.clone());
        run(move || {
            name.with(|n| match &passphrase {
                Some(s) => s.with(|s| p.rename(&open, n, Some(s))),
                None => p.rename(&open, n, None),
            })
        })
        .await
    }

    /// The seeds a delete loses (spec §10), from the keystore as stored (no unlock; a migrated "default"'s too).
    pub async fn delete_preview(&self) -> Result<DeletePreview, SdkError> {
        let core = self.open.core().clone();
        let ks = match run(move || core.get(ProfilePart::Sdk, KEYSTORE)).await? {
            Some((pt, _)) => Keystore::parse(&pt)?,
            None => Keystore::default(),
        };
        let n = |c: usize| u32::try_from(c).unwrap_or(u32::MAX);
        Ok(DeletePreview {
            seeds: n(ks.seeds.len()),
            unbacked: n(ks.seeds.iter().filter(|e| e.backup == "pending").count()),
        })
    }

    /// Deletes this profile (spec §10): with a seed whose backup is `pending` `unbacked` is required, and the name typed again
    /// (`ConfirmationMissing` for either, nothing changed); then the profile is locked as by [`UserProfile::lock`] (its `Sdk`
    /// closed) and removed by tombstone. The keychain items go with it.
    pub async fn delete(
        self: Arc<Self>,
        confirm: ConfirmDeleteProfile,
        unbacked: Option<ConfirmDeleteUnbacked>,
    ) -> Result<(), SdkError> {
        let held = self.sdk.lock().await;
        if self.delete_preview().await?.unbacked > 0 && unbacked.is_none() {
            return Err(SdkError::ConfirmationMissing);
        }
        let name = self.open.info().name;
        let typed = confirm
            .name
            .with(|t| std::str::from_utf8(t).is_ok_and(|t| scaas_profile::same_name(&name, t)));
        if !typed {
            return Err(SdkError::ConfirmationMissing);
        }
        if let Some(s) = held.as_ref() {
            s.close().await;
        }
        let (p, open) = (self.profiles.clone(), self.open.clone());
        // the backups checked above: the store's own refusal of a profile holding a keystore is passed
        run(move || {
            confirm
                .name
                .with(|n| p.delete(&open, n, Some(ConfirmDeleteUnbacked {})))
        })
        .await
    }

    /// The profile's settings (spec §5): none stored, the defaults.
    pub async fn settings(&self) -> Result<ProfileSettings, SdkError> {
        let open = self.open.clone();
        run(move || open.settings()).await
    }

    /// Replaces the settings (spec §7.7): on a protected profile a change that could weaken it needs `passphrase`, typed
    /// (`Argument` without it, `ProfileOpen` when wrong); a change that only strengthens needs none. Applying them to the
    /// chain profiles is the CLI's and the TUI's (wave 2).
    pub async fn set_settings(
        &self,
        s: ProfileSettings,
        passphrase: Option<Arc<SecretBytes>>,
    ) -> Result<(), SdkError> {
        let open = self.open.clone();
        run(move || match &passphrase {
            Some(p) => p.with(|p| open.set_settings(&s, Some(p))),
            None => open.set_settings(&s, None),
        })
        .await
    }

    /// Exports this protected profile to a new file (spec §10.1): its name typed again (`ConfirmationMissing`), the export
    /// passphrase under the profile passphrase's rule (`ProfilePassphraseWeak`), the profile passphrase (`ProfileOpen`); an
    /// existing file or a symlink at the path `Argument`.
    pub async fn export(
        &self,
        confirm: ConfirmExportProfile,
        profile_passphrase: Arc<SecretBytes>,
        export_passphrase: Arc<SecretBytes>,
        kdf: Option<KdfParams>,
        target: ExportTarget,
    ) -> Result<(), SdkError> {
        let open = self.open.clone();
        let ExportTarget::Path(t) = target;
        run(move || {
            confirm.name.with(|n| {
                profile_passphrase.with2(&export_passphrase, |pp, xp| {
                    open.export(n, pp, xp, kdf, t.as_ref())
                })
            })
        })
        .await
    }

    /// The `SecureStore` face of part `part` for an app core (the part `profile` is the manifests' and no `ProfilePart`). The part
    /// `sdk` is the profile's own `Sdk`'s, reached only through [`UserProfile::sdk`]: `Argument` (review C-6).
    pub fn part_store(&self, part: ProfilePart) -> Result<Arc<dyn SecureStore>, SdkError> {
        if part == ProfilePart::Sdk {
            return Err(SdkError::Argument);
        }
        self.open.core().live()?;
        Ok(PartStore::new(self.open.core().clone(), part)?)
    }

    /// Accepts the item `name` of `part` as it is stored after `Event::ProfileRollback` (spec §7.2: it reads, and writes to
    /// it are refused until the user accepts, as the keystore's `accept_rollback`): its manifest entry re-anchored at its
    /// current rev. An item not rolled back: nothing.
    pub async fn accept_rollback(&self, part: ProfilePart, name: String) -> Result<(), SdkError> {
        let core = self.open.core().clone();
        run(move || core.accept_rollback(part, &name)).await
    }

    /// The Matrix store's directory and key (CLI-UPR-29).
    pub fn matrix_store(&self) -> Result<MatrixStore, SdkError> {
        Ok(self.open.matrix_store()?)
    }

    /// Locks the profile (spec §10 "lock"): `Sdk::close` (its closed flag first, then every seed and hidden set locked: review
    /// C-1), then the stores closed, the arena destroyed and the instance lock released. Returns the abandoned hidden
    /// operations. Again: nothing more.
    pub async fn lock(self: Arc<Self>) -> Vec<String> {
        let held = self.sdk.lock().await;
        let mut out = vec![];
        if let Some(s) = held.as_ref() {
            out = s.close().await;
        }
        self.open.lock();
        out
    }
}

/// Test-only (feature `test-hooks`, never in a release build).
#[cfg(feature = "test-hooks")]
impl UserProfile {
    /// The profile's store core (its call counter, its hooks).
    pub fn core(&self) -> Arc<Core> {
        self.open.core().clone()
    }
}

/// Test-only (feature `test-hooks`): `hook` called at the named points of `sdk`'s unlocks and hidden opens (`unlock` after the
/// KDF, `unlock.done` after the wallet kept or refused) and of its `close` (`close` between the closed flag and the seeds'
/// lock), to drive review C-1's race.
#[cfg(feature = "test-hooks")]
pub fn set_sdk_hook(sdk: &Sdk, hook: Arc<dyn Fn(&'static str) + Send + Sync>) {
    *sdk.test_hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
}

/// Test-only (feature `test-hooks`): the seeds and hidden sets open in `sdk`'s session.
#[cfg(feature = "test-hooks")]
pub fn open_sets(sdk: &Sdk) -> usize {
    use std::sync::PoisonError;
    let open = sdk
        .open
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len();
    open + sdk
        .hidden
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len()
}

/// A store code as the SDK's: the code of the same name.
impl From<Error> for SdkError {
    fn from(e: Error) -> SdkError {
        match e {
            Error::Argument => SdkError::Argument,
            Error::VaultIo => SdkError::VaultIo,
            Error::VaultFormat => SdkError::VaultFormat,
            Error::StoreConflict => SdkError::StoreConflict,
            Error::ProfileFormat => SdkError::ProfileFormat,
            Error::ProfileLocked => SdkError::ProfileLocked,
            Error::ProfilePassphraseRequired => SdkError::ProfilePassphraseRequired,
            Error::ProfileRollback => SdkError::ProfileRollback,
            Error::ProfileDamaged => SdkError::ProfileDamaged,
            Error::ProfileBusy => SdkError::ProfileBusy,
            Error::ProfilePartFull => SdkError::ProfilePartFull,
            Error::ProfileInUse => SdkError::ProfileInUse,
            Error::ProfileOpen => SdkError::ProfileOpen,
            Error::ProfileUnknown => SdkError::ProfileUnknown,
            Error::ProfileNameTaken => SdkError::ProfileNameTaken,
            Error::ProfileNameInvalid => SdkError::ProfileNameInvalid,
            Error::ProfileLimit => SdkError::ProfileLimit,
            Error::ProfileRootUnsafe => SdkError::ProfileRootUnsafe,
            Error::ProfileVersion => SdkError::ProfileVersion,
            Error::ProfileKdfTooLarge => SdkError::ProfileKdfTooLarge,
            Error::ProfileKdfOutOfMemory => SdkError::ProfileKdfOutOfMemory,
            Error::ProfilePassphraseWeak => SdkError::ProfilePassphraseWeak,
            Error::ProfileHiddenLimit => SdkError::ProfileHiddenLimit,
            Error::ProfileSearchTooLarge => SdkError::ProfileSearchTooLarge,
            Error::ConfirmationMissing => SdkError::ConfirmationMissing,
            Error::ProfileImportOpen => SdkError::ProfileImportOpen,
            Error::ProfileExportTooLarge => SdkError::ProfileExportTooLarge,
        }
    }
}

/// A store code as the face's (CLI-UPR-22 names `StoreError`'s codes): `ProfileFormat` is `VaultFormat` at the store;
/// `ProfileBusy` and `ProfilePartFull`, which `StoreError` does not name, are `Unavailable` (the write is not taken now).
fn store_code(e: Error) -> StoreError {
    match e {
        Error::StoreConflict => StoreError::Conflict,
        Error::VaultFormat | Error::ProfileFormat => StoreError::VaultFormat,
        Error::ProfileLocked => StoreError::ProfileLocked,
        Error::ProfilePassphraseRequired => StoreError::ProfilePassphraseRequired,
        Error::ProfileRollback => StoreError::ProfileRollback,
        Error::ProfileDamaged => StoreError::ProfileDamaged,
        Error::ProfileBusy | Error::ProfilePartFull => StoreError::Unavailable,
        // the profile-level codes never come from a store call: `Io`
        Error::Argument
        | Error::VaultIo
        | Error::ProfileInUse
        | Error::ProfileOpen
        | Error::ProfileUnknown
        | Error::ProfileNameTaken
        | Error::ProfileNameInvalid
        | Error::ProfileLimit
        | Error::ProfileRootUnsafe
        | Error::ProfileVersion
        | Error::ProfileKdfTooLarge
        | Error::ProfileKdfOutOfMemory
        | Error::ProfilePassphraseWeak
        | Error::ProfileHiddenLimit
        | Error::ProfileSearchTooLarge
        | Error::ConfirmationMissing
        | Error::ProfileImportOpen
        | Error::ProfileExportTooLarge => StoreError::Io,
    }
}

/// The SDK's `SecureStore` over one part of the core (spec §7.2 "One store core, two faces"), each call on `spawn_blocking`.
/// In part `sdk`, `keystore.head` passes through unsealed to the profile directory (public by contract).
pub struct PartStore {
    core: Arc<Core>,
    part: ProfilePart,
    head: Option<Arc<FileStore>>,
}

impl PartStore {
    pub fn new(core: Arc<Core>, part: ProfilePart) -> Result<Arc<PartStore>, SdkError> {
        let head = match part {
            ProfilePart::Sdk => Some(FileStore::new(core.dir()).map_err(crate::vault::io)?),
            _ => None,
        };
        Ok(Arc::new(PartStore { core, part, head }))
    }

    /// Spec §12: a migrated "default" (unprotected, `migration: pending`) holds the CLI's keystore in clear, so every call of
    /// part `sdk` but `settings` is `ProfilePassphraseRequired` until `set_passphrase` seals it. Every vault call reads or
    /// writes the keystore through here, so each is refused before any store call (controller call UP9).
    fn gate(&self, name: &str) -> Result<(), StoreError> {
        let migrated = self.core.migration_pending() && !self.core.protected();
        match migrated && self.part == ProfilePart::Sdk && name != "settings" {
            true => Err(StoreError::ProfilePassphraseRequired),
            false => Ok(()),
        }
    }

    /// `keystore.head`'s pass-through in part `sdk`, refused once the store is closed.
    fn head(&self, name: &str) -> Result<Option<&Arc<FileStore>>, StoreError> {
        match self.head.as_ref().filter(|_| name == HEAD) {
            Some(h) => self.core.live().map(|()| Some(h)).map_err(store_code),
            None => Ok(None),
        }
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Core, ProfilePart) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, StoreError> {
        let (core, part) = (self.core.clone(), self.part);
        blocking(move || f(&core, part).map_err(store_code)).await
    }
}

#[async_trait]
impl SecureStore for PartStore {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError> {
        self.gate(&name)?;
        if let Some(h) = self.head(&name)? {
            return h.get(name, reason).await;
        }
        let got = self.run(move |c, p| c.get(p, &name)).await?;
        Ok(got.map(|(pt, rev)| StoredItem {
            bytes: pt.to_vec(),
            rev,
        }))
    }

    async fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError> {
        self.gate(&name)?;
        if let Some(h) = self.head(&name)? {
            return h.put_if(name, prev_rev, bytes, policy).await;
        }
        let bytes = Zeroizing::new(bytes);
        self.run(move |c, p| c.put_if(p, &name, prev_rev, &bytes))
            .await
    }

    async fn delete(&self, name: String) -> Result<(), StoreError> {
        self.gate(&name)?;
        if let Some(h) = self.head(&name)? {
            return h.delete(name).await;
        }
        self.run(move |c, p| c.delete(p, &name)).await
    }

    async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError> {
        self.gate(&name)?;
        if let Some(h) = self.head(&name)? {
            return h.lock(name).await;
        }
        let f = self.run(move |c, p| c.lock_item(p, &name)).await?;
        Ok(StoreLock::new(Box::new(f)))
    }
}
