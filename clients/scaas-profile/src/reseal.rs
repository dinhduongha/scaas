// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The re-seal (spec §7.3, §7.6; CLI-UPR-20, CLI-UPR-25): `set_passphrase` (unprotected to protected), `change_passphrase` (a
//! new `DEK_p` under the new passphrase) and a raise of the KDF parameters (`change_passphrase` with the same passphrase and
//! the new parameters: a new `DEK_p` too) are one procedure, under the instance lock (the open profile holds it) and the
//! store write lock, held for the whole run:
//!
//! 1. the store write lock: every writer waits (at most 120 s, then `ProfileBusy`), then writes into the new generation;
//! 2. `profile.envelope.next` (the journal): `protected`, `gen` N+1, the new `kdf` and salt, the `pass` wrap of a new
//!    `DEK_p`, its `label`, no `platform`;
//! 3. every item of `g<N>/` sealed into `g<N+1>/` under the new keys, new manifests, tombstones dropped, all `fsync`ed;
//! 4. commit: the journal renamed over `profile.envelope`, the directory `fsync`ed, the store moved to `g<N+1>/` and its new
//!    keys (the old ones wiped), the anchor written, on a first protection the keychain's `protected` marker; the lock
//!    released;
//! 5. `g<N>/` removed (a migrated "default"'s plain `g0` too, only now).
//!
//! A failure before the commit removes `g<N+1>/`, then the journal; a crash there is rolled back at the next open (§7.3, in
//! `Profiles::open`). Under `test-hooks` a hook after each step can stop the run as if the process died.
use crate::envelope::{self, Envelope, Kdf, KdfParams, Label, State, B64};
use crate::file::{self, mkdir, rev_of, MAX_BYTES};
use crate::names::random_vec;
use crate::profile::{open_code, read_envelope, remove_dir, remove_file, sync_dir, OpenProfile};
use crate::{keychain_name, Error, Head};
use base64::Engine;
use scaas_ua::wallet::ProfileKeys;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The journal of a re-seal (spec §5, §7.3).
pub(crate) const NEXT: &str = "profile.envelope.next";

/// The re-seal's steps, after each of which a `test-hooks` hook may stop it (spec §17 G4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `profile.envelope.next` written
    Journal,
    /// `g<N+1>/` complete
    Generation,
    /// the journal renamed over `profile.envelope`
    Renamed,
    /// the store moved, the anchor and the marker written; `g<N>/` not yet removed
    Committed,
}

/// A test hook: called after each step; `true` stops the re-seal there, the files left as they are.
#[cfg(feature = "test-hooks")]
pub(crate) type Hook = Box<dyn FnMut(Step) -> bool + Send>;

/// The profile passphrase's rule (spec §7.6), counted on its OpaqueString form, the one that is keyed: at least 8 characters,
/// not digits only (`ProfilePassphraseWeak`); not UTF-8, empty or holding a control character `Argument`.
fn check_passphrase(p: &[u8]) -> Result<(), Error> {
    let b = scaas_ua::wallet::passphrase_bytes(p).map_err(|_| Error::Argument)?;
    let s = std::str::from_utf8(&b).map_err(|_| Error::Argument)?;
    if s.chars().count() < 8 || s.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::ProfilePassphraseWeak);
    }
    Ok(())
}

/// A KDF run's refusal: argon2's allocation failure `ProfileKdfOutOfMemory`, a wrong passphrase `ProfileOpen`.
fn kdf_code(e: scaas_ua::wallet::Error) -> Error {
    match e {
        scaas_ua::wallet::Error::Argument => Error::Argument,
        e => open_code(e),
    }
}

impl OpenProfile {
    /// Protects an unprotected profile under `passphrase` (spec §7.3, §7.6): `kdf` (default 64 MiB / 3) within the bounds
    /// (`ProfileFormat`) and this device's maximum (`ProfileKdfTooLarge`) and the passphrase rule (`ProfilePassphraseWeak`),
    /// both before any KDF; `keep_settings` the `settings` item's bytes to seal (what the user kept of the shown settings; the
    /// SDK computes them), `None` drops it. A protected profile is `Argument` (it never returns to unprotected).
    pub fn set_passphrase(
        &self,
        passphrase: &[u8],
        kdf: Option<KdfParams>,
        keep_settings: Option<&[u8]>,
    ) -> Result<(), Error> {
        if let Some(b) = keep_settings {
            if b.len() > MAX_BYTES || rev_of(b) == u64::MAX {
                return Err(Error::Argument);
            }
        }
        self.reseal(None, passphrase, kdf, keep_settings)
    }

    /// A new passphrase on a protected profile (spec §7.3): `old` checked against the `pass` wrap (`ProfileOpen`), then every
    /// item re-sealed under a new `DEK_p`. `kdf` `None` keeps the parameters; the same passphrase with new parameters is the
    /// raise of the KDF parameters. An unprotected profile is `Argument`.
    pub fn change_passphrase(
        &self,
        old: &[u8],
        new: &[u8],
        kdf: Option<KdfParams>,
    ) -> Result<(), Error> {
        self.reseal(Some(old), new, kdf, None)
    }

    fn reseal(
        &self,
        old: Option<&[u8]>,
        pass: &[u8],
        kdf: Option<KdfParams>,
        keep: Option<&[u8]>,
    ) -> Result<(), Error> {
        let core = &self.core;
        let dir = core.dir().to_path_buf();
        let w = core.write_lock()?;
        let (env, _) = read_envelope(&dir, &self.info.id)?.ok_or(Error::ProfileFormat)?;
        if (env.state == State::Protected) != old.is_some() || env.gen != core.gen() {
            return Err(Error::Argument);
        }
        check_passphrase(pass)?;
        let params = match (kdf, &env.kdf) {
            (Some(k), _) => k,
            (None, Some(k)) => KdfParams {
                m_kib: u32::try_from(k.m).map_err(|_| Error::ProfileFormat)?,
                t: u32::try_from(k.t).map_err(|_| Error::ProfileFormat)?,
            },
            (None, None) => KdfParams::DEFAULT,
        };
        let new_kdf = Kdf {
            alg: "argon2id".into(),
            v: 1,
            m: params.m_kib.into(),
            t: params.t.into(),
            p: 4,
            salt: B64.encode(random_vec(16)?),
        };
        let (argon, salt) = new_kdf.check(self.kdf_max_kib)?;
        if let Some(old) = old {
            let k = env.kdf.as_ref().ok_or(Error::ProfileFormat)?;
            let (a, s) = k.check(self.kdf_max_kib)?;
            let wrap = B64
                .decode(env.pass.as_deref().unwrap_or_default())
                .map_err(|_| Error::ProfileFormat)?;
            let keys = core.keys().ok_or(Error::ProfileFormat)?;
            let _heavy = self.heavy.acquire();
            keys.check_pass(old, &s, a, &env.public_json()?, &wrap)
                .map_err(kdf_code)?;
        }
        let gen = env.gen.checked_add(1).ok_or(Error::ProfileFormat)?;
        let mut next = Envelope {
            state: State::Protected,
            rev: env.rev.checked_add(1).ok_or(Error::ProfileFormat)?,
            gen,
            kdf: Some(new_kdf),
            platform: None,
            ..env.clone()
        };
        let keys = Arc::new(ProfileKeys::new());
        keys.create_dek().map_err(kdf_code)?;
        let label = Zeroizing::new(
            serde_json::to_vec(&Label {
                name: self.info.name.clone(),
                hidden: env.name.is_none(),
            })
            .map_err(|_| Error::Argument)?,
        );
        let sealed = keys.seal_label(&self.info.id, &label).map_err(kdf_code)?;
        next.label = Some(B64.encode(sealed));
        let wrap = {
            let _heavy = self.heavy.acquire();
            keys.wrap_pass(pass, &salt, argon, &next.public_json()?)
                .map_err(kdf_code)?
        };
        next.pass = Some(B64.encode(wrap));
        let bytes = next.json()?;
        let gdir = dir.join(format!("g{gen}"));
        if std::fs::symlink_metadata(&gdir).is_ok() {
            return Err(Error::ProfileDamaged);
        }
        // steps 2 and 3; a failure removes `g<N+1>/`, then the journal (a stop by the test hook leaves them)
        let staged = (|| {
            file::write(&dir, &dir.join(NEXT), &bytes)?;
            if self.died(Step::Journal) {
                return Ok(true);
            }
            mkdir(&gdir)?;
            core.reseal_into(gen, &keys, keep)?;
            Ok(self.died(Step::Generation))
        })();
        match staged {
            Ok(false) => {}
            Ok(true) => return Err(Error::VaultIo),
            Err(e) => {
                let _ = remove_dir(&gdir).and_then(|()| remove_file(&dir.join(NEXT)));
                keys.lock();
                return Err(e);
            }
        }
        // step 4: the commit
        std::fs::rename(dir.join(NEXT), dir.join(envelope::FILE)).map_err(|_| Error::VaultIo)?;
        sync_dir(&dir)?;
        if self.died(Step::Renamed) {
            return Err(Error::VaultIo);
        }
        core.commit(gen, keys, Head::of(next.rev, &bytes))?;
        if let (Some(kc), State::Unprotected) = (&self.keychain, env.state) {
            kc.put(&keychain_name(&self.info.id, "protected"), b"1")?;
        }
        if self.died(Step::Committed) {
            return Err(Error::VaultIo);
        }
        drop(w);
        // step 5
        remove_dir(&dir.join(format!("g{}", env.gen)))?;
        sync_dir(&dir)
    }

    #[cfg(feature = "test-hooks")]
    fn died(&self, step: Step) -> bool {
        let mut h = self
            .hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        h.as_mut().is_some_and(|f| f(step))
    }

    #[cfg(not(feature = "test-hooks"))]
    fn died(&self, _: Step) -> bool {
        false
    }
}

/// Test-only hooks (feature `test-hooks`, never in a release build).
#[cfg(feature = "test-hooks")]
impl OpenProfile {
    /// `f` runs after each step of the next re-seals; `true` stops the re-seal there as if the process died (it returns
    /// `VaultIo`, the files left as they are). It may also block (a stalled re-seal holding the store write lock).
    pub fn reseal_hook(&self, f: Box<dyn FnMut(Step) -> bool + Send>) {
        *self
            .hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(f);
    }
}
