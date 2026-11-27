// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-profile` (spec docs/superpowers/specs/2026-11-27-user-profiles.md, rules CLI-UPR-* of
//! docs/clients/scaas-sdk.md §12): the local store of many protected profiles, without the SDK (owner 2026-11-27, CLI-UPR-02's
//! Change); the SDK (feature `user-profile`) builds on it. Every KDF, AEAD and MAC runs in `scaas-ua`'s profile arena
//! (`ProfileKeys`); this crate holds handles, public bytes and files. Synchronous: run every call on a blocking thread. Built so
//! far (plan UP5 to UP10): the sealed store core of one open profile ([`Core`]), the manifests and the anchor; the profile
//! root, the index, the envelope, the instance lock, start, create, open, list and lock ([`Profiles`], [`OpenProfile`]); the
//! re-seal (`set_passphrase`, `change_passphrase`, spec §7.3); hidden profiles (`create_hidden`, `open_hidden`, `hide`, `show`,
//! `rename`, spec §8); delete, `delete_locked`, `rebuild_index` (spec §6, §10) and the migration of the CLI's single store into
//! "default" (spec §12); the settings' storage and rules, export and import (spec §7.7, §10.1, plan UP10). UNAUDITED.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

// user-profiles spec §7.5: the test KDF set and the store's hooks never reach a release build
#[cfg(all(feature = "test-hooks", not(debug_assertions)))]
compile_error!("scaas-profile's feature `test-hooks` is test-only: never in a release build");

pub mod anchor;
pub mod envelope;
mod export;
mod file;
mod hidden;
mod index;
mod lifecycle;
mod migrate;
pub mod names;
mod profile;
mod reseal;
pub mod settings;
pub mod store;

pub use anchor::{Anchor, Head, Verdict};
pub use envelope::{Envelope, Kdf, KdfParams, State};
pub use export::{ImportReview, ImportSource, FILE_MAX};
pub use file::rev_of;
pub use hidden::HiddenMatch;
pub use lifecycle::{
    ConfirmDeleteUnbacked, ConfirmDeleteUnreadable, ConfirmPurgeTombstones, ConfirmRebuildIndex,
};
pub use names::{check_name, name_key, same_name, uuid7};
pub use profile::{MatrixStore, OpenProfile, ProfileEvent, ProfileInfo, Profiles, ProfilesConfig};
pub use reseal::{ConfirmMigratedKeystore, Step};
pub use settings::ProfileSettings;
pub use store::{Core, CoreOpen, Item, Manifest, Plain, ProfilePart, WriteGuard, PART_MAX};

macro_rules! codes {
    ($($(#[$m:meta])* $v:ident,)*) => {
        /// The store's refusals; each code is the SDK's `SdkError` of the same name (the SDK maps them one to one). No field:
        /// no id, name or path in an error.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Error {
            $($(#[$m])* $v,)*
        }

        impl Error {
            /// Every code, for the tests of the mapping.
            pub const ALL: &'static [Error] = &[$(Error::$v,)*];

            /// The stable code: the variant's name.
            pub fn code(&self) -> &'static str {
                match self {
                    $(Error::$v => stringify!($v),)*
                }
            }
        }
    };
}

codes! {
    /// an input out of its form or bounds (bytes without a JSON `rev`, above 16 MiB)
    Argument,
    /// a file system or keychain failure
    VaultIo,
    /// a stored file of no form the store writes; a sealed item that does not open
    VaultFormat,
    /// a `put_if` at a revision that is not the item's
    StoreConflict,
    /// the profile's own form refused (spec §7.1): a sealed item in an unprotected profile, a manifest's duplicate name
    ProfileFormat,
    /// the profile arena is locked
    ProfileLocked,
    /// an unprotected profile holds `settings` only (spec §7.1)
    ProfilePassphraseRequired,
    /// a value below the anchor, its manifest or its tombstone (spec §7.2)
    ProfileRollback,
    /// an item its manifest lists is missing
    ProfileDamaged,
    /// the store write lock held past the writer's wait (spec §7.3 step 1)
    ProfileBusy,
    /// a part's manifest at 65,536 entries
    ProfilePartFull,
    /// the profile's instance lock is held by another instance (spec §9)
    ProfileInUse,
    /// a wrong passphrase, an altered wrap, or a profile that does not open this way (a hidden one by id)
    ProfileOpen,
    /// no profile directory of that id
    ProfileUnknown,
    /// a visible name of the same `name_key` exists
    ProfileNameTaken,
    /// a name not 1 to 64 bytes after NFC, or holding a control or format character
    ProfileNameInvalid,
    /// 32 profile directories under `p/`
    ProfileLimit,
    /// a symlinked root, not a directory, or a wider mode on a directory that holds no profiles (spec §5)
    ProfileRootUnsafe,
    /// a format version this build does not read
    ProfileVersion,
    /// KDF parameters within the general bounds but above this device's maximum (spec §7.5)
    ProfileKdfTooLarge,
    /// argon2 could not allocate its memory
    ProfileKdfOutOfMemory,
    /// a new profile passphrase under its rule (spec §7.6): fewer than 8 characters, or digits only, on its OpaqueString form
    ProfilePassphraseWeak,
    /// 16 hidden profiles under `p/` (spec §8): `create_hidden`, `hide()`
    ProfileHiddenLimit,
    /// more than 32 candidates for a hidden search (spec §8 step 1), before any KDF run
    ProfileSearchTooLarge,
    /// a delete's or an export's name typed again that is not the profile's (spec §10, §10.1)
    ConfirmationMissing,
    /// an export file that does not open: a wrong passphrase, a changed, cut or extended file, a refused header or item
    /// (spec §10.1; the reason only in the local log)
    ProfileImportOpen,
    /// an export's payload above 64 MiB (spec §10.1)
    ProfileExportTooLarge,
    /// a hidden name and passphrase that open two or more hidden profiles (owner 2026-11-28): never one picked silently;
    /// `hidden_matches` lists them, `open_hidden_match` opens the chosen one
    ProfileHiddenAmbiguous,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}

/// The app's keychain (spec §11): small items only (at most 2,560 bytes), named by the store (`scaas.profile.<id>.<what>`): the
/// anchors, the `protected` marker, the unlock key. Synchronous, as the core that calls it; a failure is `VaultIo`.
pub trait ProfileKeychain: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, Error>;
    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), Error>;
    fn delete(&self, name: &str) -> Result<(), Error>;
}

/// The keychain item `what` of profile `id`: `scaas.profile.<id>.<what>` (spec §5, §7.1, §7.2).
pub fn keychain_name(id: &str, what: &str) -> String {
    format!("scaas.profile.{id}.{what}")
}
