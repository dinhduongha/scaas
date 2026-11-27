// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md §6, §7.3, §10, §12; §17 G4 migration and delete, G10,
//! G12 migration source paths), UP9: delete by tombstone, `delete_locked`, `rebuild_index`, the migration of the CLI's single
//! store into "default". Crash points under `test-hooks` (`ProfilesConfig::hook`, `OpenProfile::reseal_hook`). Each negative
//! test with its positive control.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::{
    keychain_name, uuid7, ConfirmDeleteUnreadable, ConfirmMigratedKeystore, ConfirmRebuildIndex,
    Error, ProfileEvent, ProfileKeychain, ProfilePart, Profiles, ProfilesConfig,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SDK: ProfilePart = ProfilePart::Sdk;
const KC_ITEMS: [&str; 4] = ["head", "protected", "keystore.head", "unlock"];
/// The legacy items and their bytes as the CLI's `FileStore` leaves them (the moves keep the bytes).
const LEGACY: [(&str, &str); 4] = [
    ("keystore.prev", r#"{"rev":2,"prev":true}"#),
    ("sdk.state", r#"{"rev":5,"ops":[]}"#),
    ("keystore", r#"{"rev":3,"seeds":[]}"#),
    (
        "keystore.head",
        r#"{"rev":3,"sha256":"00112233445566778899aabbccddeeff"}"#,
    ),
];

fn rnd(n: u8) -> [u8; 10] {
    use std::hash::{BuildHasher, RandomState};
    let s = RandomState::new();
    let mut r = [0u8; 10];
    r[..8].copy_from_slice(&s.hash_one(n).to_le_bytes());
    r[8..].copy_from_slice(&s.hash_one(n ^ 0xff).to_le_bytes()[..2]);
    r
}

/// A fresh path (not created) under `base`.
fn tmp_in(base: &Path) -> PathBuf {
    base.join(format!(
        "scaas-profile-up9-{}-{}",
        std::process::id(),
        uuid7(0, &rnd(1))
    ))
}

fn tmp() -> PathBuf {
    tmp_in(&std::env::temp_dir())
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

#[derive(Default)]
struct Keychain(Mutex<HashMap<String, Vec<u8>>>);

impl ProfileKeychain for Keychain {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.lock().unwrap().get(name).cloned())
    }
    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        self.0.lock().unwrap().insert(name.into(), bytes.to_vec());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), Error> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
}

impl Keychain {
    /// Every keychain item of profile `id` planted.
    fn plant(&self, id: &str) {
        for w in KC_ITEMS {
            self.put(&keychain_name(id, w), b"x").unwrap();
        }
    }
    fn has_any(&self, id: &str) -> bool {
        KC_ITEMS
            .iter()
            .any(|w| self.0.lock().unwrap().contains_key(&keychain_name(id, w)))
    }
}

fn cfg(root: &Path, kc: &Arc<Keychain>) -> ProfilesConfig {
    let mut c = ProfilesConfig::new(root.to_path_buf());
    c.keychain = Some(kc.clone() as Arc<dyn ProfileKeychain>);
    c
}

fn names(p: &Profiles) -> Vec<String> {
    let mut v: Vec<String> = p.list().unwrap().into_iter().map(|i| i.name).collect();
    v.sort();
    v
}

fn id_of(p: &Profiles, name: &str) -> String {
    p.list()
        .unwrap()
        .into_iter()
        .find(|i| i.name == name)
        .unwrap()
        .id
}

fn envelope(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir.join("profile.envelope")).unwrap()).unwrap()
}

/// Delete of an open profile (spec §10, §17 G10): the name typed again by `name_key` (a wrong one `ConfirmationMissing`, the
/// profile untouched and still open); then the directory, the row and every keychain item of the profile are gone, nothing
/// of another profile is touched, and the deleted profile's store is locked.
#[test]
fn delete_open_profile() {
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    let (a, b) = (p.create("Alpha").unwrap().id, id_of(&p, "default"));
    let o = p.open(&a, None).unwrap();
    // planted after the open (an unprotected profile beside a `protected` marker does not open)
    kc.plant(&a);
    kc.put(&keychain_name(&b, "keystore.head"), b"x").unwrap();
    o.core()
        .put_if(SDK, "settings", None, br#"{"rev":1}"#)
        .unwrap();
    assert_eq!(code(p.delete(&o, b"Alpha2", None)), "ConfirmationMissing");
    assert_eq!(code(p.delete(&o, b"default", None)), "ConfirmationMissing");
    assert_eq!(names(&p), ["Alpha", "default"]);
    assert!(kc.has_any(&a));
    assert_eq!(code(o.core().get(SDK, "settings")), "ok", "still open");
    // the positive control: the name by name_key
    p.delete(&o, "ALPHA".as_bytes(), None).unwrap();
    assert_eq!(names(&p), ["default"]);
    assert!(!root.join("p").join(&a).exists());
    assert!(!root.join("p").join(format!("{a}.deleted")).exists());
    assert!(!kc.has_any(&a));
    assert!(kc.has_any(&b), "another profile's items kept");
    let ix = std::fs::read_to_string(root.join("profiles.json")).unwrap();
    assert!(!ix.contains(&a), "the row dropped");
    assert_eq!(code(o.core().get(SDK, "settings")), "ProfileLocked");
    assert_eq!(code(p.delete(&o, b"Alpha", None)), "ProfileLocked");
    assert_eq!(code(p.open(&b, None)), "ok");
}

/// The last profile may be deleted; the next start creates "default" again (spec §10, O5).
#[test]
fn delete_last_profile() {
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    let id = id_of(&p, "default");
    p.delete(&p.open(&id, None).unwrap(), b"default", None)
        .unwrap();
    assert!(names(&p).is_empty());
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    assert_eq!(names(&p), ["default"]);
    assert_ne!(id_of(&p, "default"), id);
}

/// A locked visible profile deletes with its name typed and `ConfirmDeleteUnreadable` (spec §10, §17 G10), without opening:
/// held by an instance `ProfileInUse`; a wrong name `ConfirmationMissing`; an unknown id `ProfileUnknown`; a directory without
/// an envelope `ProfileFormat` and kept. Each with the profile still there, then the positive control.
#[test]
fn delete_locked_visible() {
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    let a = p.create("lost").unwrap().id;
    let held = p.open(&a, None).unwrap();
    let c = ConfirmDeleteUnreadable {};
    assert_eq!(code(p.delete_locked(&a, b"lost", c)), "ProfileInUse");
    held.lock();
    kc.plant(&a);
    assert_eq!(code(p.delete_locked(&a, b"lo", c)), "ConfirmationMissing");
    let unknown = uuid7(1, &rnd(9));
    assert_eq!(
        code(p.delete_locked(&unknown, b"lost", c)),
        "ProfileUnknown"
    );
    let damaged = uuid7(2, &rnd(8));
    std::fs::create_dir_all(root.join("p").join(&damaged)).unwrap();
    assert_eq!(code(p.delete_locked(&damaged, b"lost", c)), "ProfileFormat");
    assert!(root.join("p").join(&damaged).is_dir(), "never removed");
    assert_eq!(names(&p), ["default", "lost"]);
    p.delete_locked(&a, b"Lost", c).unwrap();
    assert_eq!(names(&p), ["default"]);
    assert!(!root.join("p").join(&a).exists());
    assert!(!kc.has_any(&a));
}

/// A UUID-named directory without a usable envelope is reported at start (`ProfileDamaged`) and never removed, by start, by a
/// delete of another profile, or by `rebuild_index` (spec §10, §17 G10). Control: the same start removes a tombstone whose
/// instance lock is free.
#[test]
fn damaged_directory_reported_never_removed() {
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    let b = p.create("b").unwrap().id;
    let damaged = uuid7(3, &rnd(7));
    let d = root.join("p").join(&damaged);
    std::fs::create_dir_all(d.join("g0")).unwrap();
    std::fs::write(d.join("g0").join("settings"), b"{}").unwrap();
    let tomb = format!("{}.deleted", uuid7(4, &rnd(6)));
    std::fs::create_dir_all(root.join("p").join(&tomb)).unwrap();
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    assert!(p.drain_events().contains(&ProfileEvent::ProfileDamaged));
    assert!(
        !root.join("p").join(&tomb).exists(),
        "the control: a tombstone removed"
    );
    p.delete(&p.open(&b, None).unwrap(), b"b", None).unwrap();
    p.rebuild_index(ConfirmRebuildIndex {}).unwrap();
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    assert!(p.drain_events().contains(&ProfileEvent::ProfileDamaged));
    assert!(d.join("g0").join("settings").is_file(), "never removed");
    assert_eq!(names(&p), ["default"]);
}

/// `rebuild_index` on demand (spec §6): the rebuild lists every visible profile from its envelope; a parsable index with a
/// wrong name is reconciled with the envelopes at its next read (review G-10: the index is a cache, never the truth).
/// Control: an intact index lists as before.
#[test]
fn rebuild_index_on_demand() {
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let p = Profiles::new(cfg(&root, &kc)).unwrap();
    let a = p.create("a").unwrap().id;
    p.rebuild_index(ConfirmRebuildIndex {}).unwrap();
    assert_eq!(names(&p), ["a", "default"], "intact: as before");
    let ix = std::fs::read_to_string(root.join("profiles.json")).unwrap();
    std::fs::write(
        root.join("profiles.json"),
        ix.replace(
            &format!(r#""id":"{a}","name":"a""#),
            &format!(r#""id":"{a}","name":"planted""#),
        ),
    )
    .unwrap();
    assert_eq!(names(&p), ["a", "default"]);
    p.rebuild_index(ConfirmRebuildIndex {}).unwrap();
    assert_eq!(names(&p), ["a", "default"]);
}

/// A legacy source holding the CLI's items (`keystore`, `keystore.prev`, `sdk.state`, `keystore.head`), made `0700`.
fn legacy(src: &Path) {
    std::fs::create_dir_all(src).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(src, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    for (n, b) in LEGACY {
        std::fs::write(src.join(n), b).unwrap();
    }
}

fn migrating(root: &Path, src: &Path) -> ProfilesConfig {
    let mut c = ProfilesConfig::new(root.to_path_buf());
    c.legacy = Some(src.to_path_buf());
    c
}

/// Every legacy item moved into "default" (its `g0/`, `keystore.head` beside the envelope) and gone at the source.
fn moved(root: &Path, src: &Path, id: &str) {
    let dir = root.join("p").join(id);
    for (n, b) in LEGACY {
        let at = match n {
            "keystore.head" => dir.join(n),
            _ => dir.join("g0").join(n),
        };
        assert_eq!(std::fs::read_to_string(&at).unwrap(), b, "{n}");
        assert!(!src.join(n).exists(), "{n} at the source");
    }
}

/// Migration (spec §12, §17 G12 source paths): from a source beside the root (macOS, Windows: another directory), from the root
/// itself (Linux: the same directory) and from another file system where the test machine has one (a copy, `fsync`, then
/// the source removed): "default" created unprotected with `migration: pending`, listed, the items moved by their bytes; the
/// store reads them under `migration: pending`; a second start changes nothing.
#[test]
fn migration_moves_into_default() {
    let base = tmp();
    let other = tmp_in(Path::new(env!("CARGO_TARGET_TMPDIR")));
    for (root, src) in [
        (base.join("a").join("root"), base.join("a").join("cli")),
        (base.join("b"), base.join("b")),
        (base.join("c").join("root"), other.join("cli")),
    ] {
        legacy(&src);
        let p = Profiles::new(migrating(&root, &src)).unwrap();
        assert_eq!(names(&p), ["default"]);
        let id = id_of(&p, "default");
        moved(&root, &src, &id);
        let env = envelope(&root.join("p").join(&id));
        assert_eq!(env["migration"], "pending");
        assert_eq!(env["state"], "unprotected");
        let o = p.open(&id, None).unwrap();
        let (ks, _) = o.core().get(SDK, "keystore").unwrap().unwrap();
        assert_eq!(&ks[..], LEGACY[2].1.as_bytes());
        drop(o);
        let p = Profiles::new(migrating(&root, &src)).unwrap();
        assert_eq!(
            (names(&p), id_of(&p, "default")),
            (vec!["default".to_string()], id.clone())
        );
        moved(&root, &src, &id);
    }
}

/// Legacy items at a source whose root already has profiles (none `migration: pending`) are reported (`ProfileDamaged`) and
/// never migrated (spec §12, §17 G10). Control: [`migration_moves_into_default`].
#[test]
fn legacy_beside_profiles_reported() {
    let base = tmp();
    let (root, src) = (base.join("root"), base.join("cli"));
    let p = Profiles::new(ProfilesConfig::new(root.clone())).unwrap();
    let id = id_of(&p, "default");
    legacy(&src);
    let p = Profiles::new(migrating(&root, &src)).unwrap();
    assert!(p.drain_events().contains(&ProfileEvent::ProfileDamaged));
    assert_eq!(
        (names(&p), id_of(&p, "default")),
        (vec!["default".to_string()], id.clone())
    );
    for (n, b) in LEGACY {
        assert_eq!(std::fs::read_to_string(src.join(n)).unwrap(), b, "{n} kept");
    }
    assert!(!root
        .join("p")
        .join(&id)
        .join("g0")
        .join("keystore")
        .exists());
    assert!(envelope(&root.join("p").join(&id))
        .get("migration")
        .is_none());
}

#[cfg(feature = "test-hooks")]
mod hooks {
    use super::*;
    use scaas_profile::{KdfParams, Step};
    use std::fs::File;
    use std::sync::mpsc;
    use std::time::Duration;

    const PASS: &[u8] = b"correct horse battery staple";
    const TEST: KdfParams = KdfParams { m_kib: 8192, t: 1 };

    /// The entries of `p/` (sorted), the root lock and the index excluded.
    fn entries(root: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(root.join("p"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    /// Holds `p/<name>/instance.lock` (a live instance's lock, or a deleting process still alive) while the file lives.
    fn hold(root: &Path, name: &str) -> File {
        let f = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("p").join(name).join("instance.lock"))
            .unwrap();
        f.lock().unwrap();
        f
    }

    /// A crash at each step of a delete leaves a tombstone, which start finishes: the tombstone, the row and the keychain items
    /// gone (spec §10, §17 G10). Control: a start while the tombstone's instance lock is held (the deleting process alive)
    /// leaves it.
    #[test]
    fn g10_crash_at_each_delete_step() {
        for stop in [Step::Tombstone, Step::RowDropped, Step::KeychainRemoved] {
            let (root, kc) = (tmp(), Arc::new(Keychain::default()));
            let p = Profiles::new(cfg(&root, &kc)).unwrap();
            let a = p.create("a").unwrap().id;
            let mut c = cfg(&root, &kc);
            c.hook = Some(Box::new(move |s| s == stop));
            let p = Profiles::new(c).unwrap();
            let o = p.open(&a, None).unwrap();
            kc.plant(&a);
            assert_eq!(code(p.delete(&o, b"a", None)), "VaultIo", "{stop:?}");
            drop(o);
            let tomb = format!("{a}.deleted");
            assert!(root.join("p").join(&tomb).is_dir(), "{stop:?}");
            assert!(!root.join("p").join(&a).exists(), "{stop:?}");
            let held = hold(&root, &tomb);
            let p = Profiles::new(cfg(&root, &kc)).unwrap();
            assert!(root.join("p").join(&tomb).is_dir(), "{stop:?}: held, kept");
            drop(held);
            let p2 = Profiles::new(cfg(&root, &kc)).unwrap();
            assert!(!root.join("p").join(&tomb).exists(), "{stop:?}");
            assert!(!kc.has_any(&a), "{stop:?}");
            assert_eq!(names(&p2), ["default"], "{stop:?}");
            assert_eq!(names(&p), ["default"], "{stop:?}");
        }
    }

    /// No call deletes an unlisted (hidden) profile by id (spec §10, Q-UP10): `delete_locked` of a hidden profile's directory
    /// `ProfileUnknown`, the directory kept; its open twin deletes it (the name and passphrase found it).
    #[test]
    fn hidden_not_deleted_by_id() {
        let (root, kc) = (tmp(), Arc::new(Keychain::default()));
        let p = Profiles::new(cfg(&root, &kc)).unwrap();
        let h = p.create_hidden(b"secret", PASS, Some(TEST)).unwrap();
        let id = h.info().id;
        h.lock();
        let c = ConfirmDeleteUnreadable {};
        assert_eq!(code(p.delete_locked(&id, b"secret", c)), "ProfileUnknown");
        assert!(root.join("p").join(&id).join("profile.envelope").is_file());
        let h = p.open_hidden(b"secret", PASS).unwrap();
        p.delete(&h, b"secret", None).unwrap();
        assert!(!root.join("p").join(&id).exists());
    }

    /// A crash at each step of the migration resumes into the same "default" (spec §12, §17 G4): stopped before step 1, after
    /// it, and after each item moved; the next start finishes, one profile, every item moved once.
    #[test]
    fn g4_crash_at_each_migration_step() {
        for k in 0..6 {
            let base = tmp();
            let (root, src) = (base.join("root"), base.join("cli"));
            legacy(&src);
            let mut c = migrating(&root, &src);
            let mut n = 0;
            c.hook = Some(Box::new(move |_| {
                n += 1;
                n == k + 1
            }));
            assert_eq!(code(Profiles::new(c)), "VaultIo", "{k}");
            let before: Vec<String> = entries(&root)
                .into_iter()
                .filter(|e| !e.starts_with('.'))
                .collect();
            assert_eq!(before.len(), usize::from(k > 0), "{k}: {before:?}");
            let p = Profiles::new(migrating(&root, &src)).unwrap();
            assert_eq!(names(&p), ["default"], "{k}");
            let id = id_of(&p, "default");
            if k > 0 {
                assert_eq!(before, [id.as_str()], "{k}: the same default");
            }
            assert_eq!(entries(&root), [id.as_str()], "{k}");
            moved(&root, &src, &id);
            assert_eq!(envelope(&root.join("p").join(&id))["migration"], "pending");
        }
    }

    /// Two migrations at once make one "default" (spec §12, §17 G4): the second waits on the root lock while the first is held
    /// before its step 1. And a start without a legacy source beside a migration waits too, so its first run never makes a
    /// second "default" (the root lock at migration).
    #[test]
    fn concurrent_starts_make_one_default() {
        for second_migrates in [true, false] {
            let base = tmp();
            let (root, src) = (base.join("root"), base.join("cli"));
            legacy(&src);
            let (at, wait) = (mpsc::channel(), mpsc::channel::<()>());
            let (at_tx, go_rx) = (Mutex::new(at.0), Mutex::new(wait.1));
            let mut c = migrating(&root, &src);
            c.hook = Some(Box::new(move |s| {
                if s == Step::Migrating {
                    at_tx.lock().unwrap().send(()).unwrap();
                    go_rx.lock().unwrap().recv().unwrap();
                }
                false
            }));
            let a = std::thread::spawn(move || Profiles::new(c).map(drop));
            at.1.recv().unwrap();
            let (done_tx, done) = mpsc::channel();
            let (r2, s2) = (root.clone(), src.clone());
            let b = std::thread::spawn(move || {
                let c = match second_migrates {
                    true => migrating(&r2, &s2),
                    false => ProfilesConfig::new(r2),
                };
                let r = Profiles::new(c).map(drop);
                done_tx.send(()).unwrap();
                r
            });
            let waited = done.recv_timeout(Duration::from_secs(2)).is_err();
            wait.0.send(()).unwrap();
            assert_eq!(code(a.join().unwrap()), "ok", "{second_migrates}");
            assert_eq!(code(b.join().unwrap()), "ok", "{second_migrates}");
            assert!(
                waited,
                "{second_migrates}: the second start waited on the root lock"
            );
            let p = Profiles::new(ProfilesConfig::new(root.clone())).unwrap();
            assert_eq!(names(&p), ["default"], "{second_migrates}");
            let id = id_of(&p, "default");
            assert_eq!(entries(&root), [id.as_str()], "{second_migrates}");
            moved(&root, &src, &id);
        }
    }

    /// `set_passphrase` seals a migrated "default" (spec §7.3, §12): its legacy items sealed into part `sdk`, `migration`
    /// cleared by the commit, and the plain `g0/` removed only after the commit: a stop after the generation rolls back to the
    /// migrated profile whole; a stop after the commit leaves `g0/` until the next open; the store reads the keystore under the
    /// passphrase; `keystore.head` stays beside the envelope. G-3 (owner 2026-11-28): without the caller's confirm of the
    /// migrated keystore (`ConfirmMigratedKeystore`, the SDK's after the user confirmed its seeds) it is
    /// `ConfirmationMissing`, before any KDF and with nothing written.
    #[test]
    fn migrated_default_sealed_after_commit() {
        let base = tmp();
        let (root, src) = (base.join("root"), base.join("cli"));
        legacy(&src);
        let p = Profiles::new(migrating(&root, &src)).unwrap();
        let id = id_of(&p, "default");
        let dir = root.join("p").join(&id);
        let ks = LEGACY[2].1.as_bytes();
        for (stop, sealed) in [(Step::Generation, false), (Step::Committed, true)] {
            let o = p.open(&id, None).unwrap();
            let runs = scaas_ua::wallet::ProfileKeys::kdf_runs();
            assert_eq!(
                code(o.set_passphrase(PASS, Some(TEST), None, None)),
                "ConfirmationMissing"
            );
            assert_eq!(scaas_ua::wallet::ProfileKeys::kdf_runs(), runs, "no KDF");
            assert!(
                !dir.join("g1").exists() && !o.info().protected,
                "nothing written"
            );
            o.reseal_hook(Box::new(move |s| s == stop));
            let confirmed = Some(ConfirmMigratedKeystore {});
            assert_eq!(
                code(o.set_passphrase(PASS, Some(TEST), None, confirmed)),
                "VaultIo"
            );
            assert!(
                dir.join("g0").join("keystore").is_file(),
                "{stop:?}: g0 kept"
            );
            drop(o);
            let o = match sealed {
                false => p.open(&id, None).unwrap(),
                true => p.open(&id, Some(PASS)).unwrap(),
            };
            assert_eq!(dir.join("g0").exists(), !sealed, "{stop:?}");
            assert_eq!(o.info().protected, sealed, "{stop:?}");
            assert_eq!(&o.core().get(SDK, "keystore").unwrap().unwrap().0[..], ks);
            assert_eq!(envelope(&dir).get("migration").is_some(), !sealed);
        }
        let o = p.open(&id, Some(PASS)).unwrap();
        assert_eq!(
            &o.core().get(SDK, "sdk.state").unwrap().unwrap().0[..],
            LEGACY[1].1.as_bytes()
        );
        assert_eq!(
            &o.core().get(SDK, "keystore.prev").unwrap().unwrap().0[..],
            LEGACY[0].1.as_bytes()
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("keystore.head")).unwrap(),
            LEGACY[3].1
        );
    }
}
