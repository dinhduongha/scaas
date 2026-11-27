// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The migration of the CLI's single store into "default" (spec §12; CLI-UPR-11), at start, under the root lock and the legacy
//! store's `keystore.lock` (the SDK `FileStore`'s lock of item `keystore`, which a running old binary holds while it writes).
//!
//! - **When**: a legacy item (`keystore`, `keystore.prev`, `sdk.state`) at the source and no profile directory under `p/`; once
//!   started, it resumes only into the profile whose envelope says `migration: pending` (`keystore.head` also counts there).
//!   Legacy items at a source whose root has profiles, none pending, are reported (`ProfileDamaged`), never migrated.
//! - **Steps**: (1) "default" created unprotected with `migration: pending`, as at create (its row written); (2) each item
//!   moved into its `g0/` (`keystore.head` beside the envelope, where the SDK's store reads it) by `rename(2)`, or across
//!   file systems copied, `fsync`ed, then removed at the source. Each step is idempotent: a moved item is absent at the source;
//!   an item at both places with the same bytes (a copy whose source removal did not happen) is removed at the source; with
//!   other bytes (a later write of an old binary) it is reported and left at both.
//! - **Step (3), `migration` cleared, is the commit of `set_passphrase`** (controller call UP9): spec §5 and §7.1 accept the
//!   legacy items in an unprotected `g0/` only under `migration: pending`, and §7.3 / §12 seal them there; clearing it at the
//!   end of the move would make the moved keystore `ProfileFormat` and leave it out of the seal.
//! - The CLI has no keychain item (its anchor is the file `keystore.head`): re-naming keychain items is the app's (wave 2).
//!   The overlay (`overlay.json`) goes into `settings` with the settings' format (UP10).
use crate::envelope::{self, Envelope, State};
use crate::file::{self, lock_file, mkdir, read_bounded, MAX_BYTES};
use crate::names::new_id;
use crate::profile::{remove_dir, remove_file, sync_dir, ProfileEvent, Profiles, BUILD_LOCK};
use crate::{Error, Step};
use std::path::Path;
use zeroize::Zeroizing;

/// The legacy items in the order they move: the anchor last, so a crash never leaves an anchor beside no container.
const ITEMS: [&str; 4] = ["keystore.prev", "sdk.state", "keystore", "keystore.head"];
const HEAD: &str = "keystore.head";

impl Profiles {
    /// Under the root lock, after the start's clean-up (`first_run`: `p/` holds no profile directory): the migration from
    /// `src`; whether this is still a first run.
    pub(crate) fn migrate(&self, src: &Path, first_run: bool) -> Result<bool, Error> {
        let at = |n: &&str| std::fs::symlink_metadata(src.join(n)).is_ok();
        if !ITEMS.iter().any(at) {
            return Ok(first_run);
        }
        let _legacy = lock_file(&src.join("keystore.lock"))?;
        let pending = self.scan()?.into_iter().find_map(|(id, e)| {
            e.filter(|e| e.state == State::Unprotected && e.migration.is_some())
                .map(|_| id)
        });
        let id = match pending {
            Some(id) => id,
            None if first_run && ITEMS.iter().take(3).any(at) => {
                self.died(Step::Migrating)?;
                let id = self.create_migrated()?;
                self.died(Step::MigrationCreated)?;
                id
            }
            None => {
                if !first_run {
                    self.event(ProfileEvent::ProfileDamaged);
                }
                return Ok(first_run);
            }
        };
        let dir = self.p.join(&id);
        for name in ITEMS {
            let to = match name {
                HEAD => dir.clone(),
                _ => dir.join("g0"),
            };
            self.move_item(src, name, &to)?;
            self.died(Step::MigrationMoved)?;
        }
        Ok(false)
    }

    /// Step 1 under the root lock: "default", unprotected, `migration: pending`, built in `p/.tmp-*` and committed as at create.
    fn create_migrated(&self) -> Result<String, Error> {
        let id = new_id()?;
        let tmp = self.new_tmp()?;
        let r = (|| {
            let _build = lock_file(&tmp.join(BUILD_LOCK))?;
            let env = Envelope {
                migration: Some("pending".into()),
                ..Envelope::unprotected(&id, "default")
            };
            file::write(&tmp, &tmp.join(envelope::FILE), &env.json()?)?;
            mkdir(&tmp.join("g0"))?;
            self.commit_create(&tmp, &id, Some("default"))
        })();
        if r.is_err() {
            let _ = remove_dir(&tmp);
        }
        r.map(|()| id)
    }

    /// The legacy item `name` of `src` moved into the directory `to` (step 2): absent at the source, nothing; absent at `to`,
    /// renamed (across file systems copied, `fsync`ed, then removed); at both with the same bytes, removed at the source; with
    /// other bytes, reported and left.
    fn move_item(&self, src: &Path, name: &str, to: &Path) -> Result<(), Error> {
        let (from, dest) = (src.join(name), to.join(name));
        let Some(bytes) = read_bounded(&from, MAX_BYTES)? else {
            return Ok(());
        };
        let bytes = Zeroizing::new(bytes.ok_or(Error::VaultFormat)?);
        match read_bounded(&dest, MAX_BYTES)?.map(|d| d.map(Zeroizing::new)) {
            None => match std::fs::rename(&from, &dest) {
                Ok(()) => return sync_dir(to).and_then(|()| sync_dir(src)),
                Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
                    file::write(to, &dest, &bytes)?
                }
                Err(_) => return Err(Error::VaultIo),
            },
            Some(Some(d)) if d == bytes => {}
            Some(_) => {
                self.event(ProfileEvent::ProfileDamaged);
                return Ok(());
            }
        }
        remove_file(&from)?;
        sync_dir(src)
    }
}
