// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Delete and the index rebuilt on demand (spec §6, §10; CLI-UPR-15): [`Profiles::delete`] (an open profile),
//! [`Profiles::delete_locked`] (a visible profile whose passphrase is lost), [`Profiles::rebuild_index`].
//!
//! - **Delete by tombstone**: the name typed again (`name_key`, else `ConfirmationMissing`); under the root lock `p/<id>/` renamed
//!   to `p/<id>.deleted/` (one atomic step) and the row dropped; then the keychain items removed, then the tombstone. A crash at
//!   any step leaves a tombstone, which start removes with its keychain items once its instance lock is free.
//! - **The instance lock is kept across the rename** (controller call UP9): the held `instance.lock` moves with its directory
//!   (a rename keeps open files on Unix), so no other instance opens the profile, and no start removes the tombstone, before
//!   the delete has finished or died; it is released last.
//! - No call deletes an unlisted (hidden) directory by id, nor a directory without a usable envelope (spec §10, Q-UP10).
use crate::file::try_lock_file;
use crate::names::{is_id, same_name};
use crate::profile::{
    read_envelope, remove_dir, remove_file, sync_dir, without, OpenProfile, Profiles,
    INSTANCE_LOCK, TOMBSTONE,
};
use crate::{Error, Step};
use std::fs::File;

/// The marker of [`Profiles::delete_locked`] (spec §10): the user was told that this profile's data cannot be opened and will
/// be lost, and that seeds return only from their words or their sealed backups.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmDeleteUnreadable {}

/// The marker of [`Profiles::rebuild_index`] (spec §6: on demand with a typed confirm).
#[derive(Debug, Clone, Copy)]
pub struct ConfirmRebuildIndex {}

impl Profiles {
    /// Deletes the open profile `open` (spec §10 "delete"): `confirm_name` its name typed again. The profile is locked first
    /// (its stores closed, its arena wiped); then the tombstone's steps. The caller (the SDK) has checked the seeds' backups.
    pub fn delete(&self, open: &OpenProfile, confirm_name: &[u8]) -> Result<(), Error> {
        let info = open.info();
        confirm(&info.name, confirm_name)?;
        let instance = open.release().ok_or(Error::ProfileLocked)?;
        self.entomb(&info.id, instance)
    }

    /// Deletes the visible profile `id` without opening it (spec §10, a lost passphrase): its instance lock
    /// (`ProfileInUse`), its envelope's public name typed again; the same steps. `ProfileUnknown` for no such directory or a
    /// profile with no public name (hidden), `ProfileFormat` for a directory without a usable envelope (never removed).
    pub fn delete_locked(
        &self,
        id: &str,
        confirm_name: &[u8],
        _: ConfirmDeleteUnreadable,
    ) -> Result<(), Error> {
        let dir = self.p.join(id);
        if !is_id(id) || !std::fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
            return Err(Error::ProfileUnknown);
        }
        let instance = try_lock_file(&dir.join(INSTANCE_LOCK))?.ok_or(Error::ProfileInUse)?;
        let (env, _) = read_envelope(&dir, id)?.ok_or(Error::ProfileFormat)?;
        confirm(&env.name.ok_or(Error::ProfileUnknown)?, confirm_name)?;
        self.entomb(id, instance)
    }

    /// The index rebuilt from the envelopes (spec §6, on demand): every visible profile listed, `last` dropped.
    pub fn rebuild_index(&self, _: ConfirmRebuildIndex) -> Result<(), Error> {
        let _root = self.root_lock()?;
        remove_file(&self.index_file())?;
        self.index_locked().map(drop)
    }

    /// The tombstone's steps for profile `id`, its instance lock `instance` held: under the root lock the rename and the row
    /// dropped (the index read before the rename, so a row is dropped, and written, only where it was), then the keychain items,
    /// then the tombstone; the lock released last.
    fn entomb(&self, id: &str, instance: File) -> Result<(), Error> {
        let tomb = self.p.join(format!("{id}{TOMBSTONE}"));
        {
            let _root = self.root_lock()?;
            let (mut ix, at) = self.index_locked()?;
            std::fs::rename(self.p.join(id), &tomb).map_err(|_| Error::VaultIo)?;
            sync_dir(&self.p)?;
            self.died(Step::Tombstone)?;
            if without(&mut ix, id) {
                self.write_index(&mut ix, at)?;
            }
        }
        self.died(Step::RowDropped)?;
        self.remove_keychain(id)?;
        self.died(Step::KeychainRemoved)?;
        remove_dir(&tomb)?;
        drop(instance);
        sync_dir(&self.p)
    }
}

/// The name typed again against the profile's (`name_key`, constant time): else `ConfirmationMissing`.
fn confirm(name: &str, typed: &[u8]) -> Result<(), Error> {
    match std::str::from_utf8(typed).is_ok_and(|t| same_name(name, t)) {
        true => Ok(()),
        false => Err(Error::ConfirmationMissing),
    }
}
