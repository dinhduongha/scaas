// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles wave-1 code review, task R1 (scratchpad review STATUS rows; spec
//! docs/superpowers/specs/2026-11-27-user-profiles.md): each test names its review row and holds its positive control.
//! Protected profiles run Argon2id at the test set (feature `test-hooks`); every test that runs or counts a KDF holds [`KDF`]
//! (`kdf_runs` is process-wide).
#![cfg(feature = "test-hooks")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::{
    keychain_name, uuid7, Error, KdfParams, OpenProfile, ProfileEvent, ProfileKeychain, Profiles,
    ProfilesConfig,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex, MutexGuard};

const PASS: &[u8] = b"correct horse battery staple";
const PASS2: &[u8] = b"another passphrase, longer";
const TEST: KdfParams = KdfParams { m_kib: 8192, t: 1 };

static KDF: Mutex<()> = Mutex::new(());

fn kdf_lock() -> MutexGuard<'static, ()> {
    KDF.lock().unwrap_or_else(|e| e.into_inner())
}

fn tmp() -> PathBuf {
    use std::hash::{BuildHasher, RandomState};
    let mut r = [0u8; 10];
    r[..8].copy_from_slice(&RandomState::new().hash_one(11u8).to_le_bytes());
    std::env::temp_dir().join(format!(
        "scaas-profile-r1-{}-{}",
        std::process::id(),
        uuid7(0, &r)
    ))
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "ok")
}

/// A keychain whose `put` and `delete` fail (`VaultIo`) while their flag is set.
#[derive(Default)]
struct Keychain {
    items: Mutex<HashMap<String, Vec<u8>>>,
    fail_put: AtomicBool,
    fail_delete: AtomicBool,
}

impl ProfileKeychain for Keychain {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.items.lock().unwrap().get(name).cloned())
    }
    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), Error> {
        if self.fail_put.load(SeqCst) {
            return Err(Error::VaultIo);
        }
        self.items.lock().unwrap().insert(name.into(), bytes.to_vec());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), Error> {
        if self.fail_delete.load(SeqCst) {
            return Err(Error::VaultIo);
        }
        self.items.lock().unwrap().remove(name);
        Ok(())
    }
}

impl Keychain {
    fn has(&self, id: &str, what: &str) -> bool {
        self.items
            .lock()
            .unwrap()
            .contains_key(&keychain_name(id, what))
    }
}

fn cfg(root: &Path, kc: Option<&Arc<Keychain>>) -> ProfilesConfig {
    let mut c = ProfilesConfig::new(root.to_path_buf());
    c.keychain = kc.map(|k| k.clone() as Arc<dyn ProfileKeychain>);
    c
}

/// A fresh root whose "default" is protected under `PASS` (generation 1), open; its id and directory.
fn protected(root: &Path, kc: Option<&Arc<Keychain>>) -> (Profiles, OpenProfile, String, PathBuf) {
    let p = Profiles::new(cfg(root, kc)).unwrap();
    let id = p.list().unwrap()[0].id.clone();
    let o = p.open(&id, None).unwrap();
    o.set_passphrase(PASS, Some(TEST), None).unwrap();
    let dir = o.core().dir().to_path_buf();
    (p, o, id, dir)
}

/// G-1: a tombstone planted beside a live profile directory is removed alone at start; the live profile's keychain items
/// (anchor, marker) stay and it opens; `ProfileDamaged` is reported. Control: a tombstone without a live directory goes with
/// its keychain items (`start_cleans_up`, lifecycle tests).
#[test]
fn g1_tombstone_beside_live_profile() {
    let _k = kdf_lock();
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let (p, o, id, dir) = protected(&root, Some(&kc));
    o.lock();
    drop(p);
    assert!(kc.has(&id, "head") && kc.has(&id, "protected"), "control");
    let tomb = dir.with_file_name(format!("{id}.deleted"));
    std::fs::create_dir(&tomb).unwrap();
    let p = Profiles::new(cfg(&root, Some(&kc))).unwrap();
    assert!(!tomb.exists(), "the tombstone removed");
    assert!(kc.has(&id, "head"), "the live anchor kept");
    assert!(kc.has(&id, "protected"), "the live marker kept");
    assert!(p.drain_events().contains(&ProfileEvent::ProfileDamaged));
    p.open(&id, Some(PASS)).unwrap();
}

/// A-1 / G-8: an older envelope put back with a journal beside it, while the anchor names the live generation above it, is
/// `ProfileRollback` and removes nothing (the live `g2/` stays). Control: the live envelope put back opens.
#[test]
fn a1_journal_beside_an_older_envelope() {
    let _k = kdf_lock();
    let root = tmp();
    let (p, o, id, dir) = protected(&root, None);
    let old = std::fs::read(dir.join("profile.envelope")).unwrap();
    o.change_passphrase(PASS, PASS2, None).unwrap();
    let live = std::fs::read(dir.join("profile.envelope")).unwrap();
    o.lock();
    std::fs::write(dir.join("profile.envelope"), &old).unwrap();
    std::fs::write(dir.join("profile.envelope.next"), b"x").unwrap();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileRollback");
    assert!(dir.join("g2").is_dir(), "the live generation kept");
    std::fs::write(dir.join("profile.envelope"), &live).unwrap();
    std::fs::remove_file(dir.join("profile.envelope.next")).unwrap();
    p.open(&id, Some(PASS2)).unwrap();
}

/// A-5 / A-6: a tombstone whose keychain items cannot be removed (the keychain fails) is reported (`ProfileDamaged`) and
/// kept, start succeeds; once the keychain works, the next start removes the items, then the tombstone.
#[test]
fn a5_tombstone_kept_until_its_keychain_items_go() {
    let _k = kdf_lock();
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let (p, o, id, dir) = protected(&root, Some(&kc));
    o.lock();
    drop(p);
    let tomb = dir.with_file_name(format!("{id}.deleted"));
    std::fs::rename(&dir, &tomb).unwrap();
    kc.fail_delete.store(true, SeqCst);
    let p = Profiles::new(cfg(&root, Some(&kc))).unwrap();
    assert!(tomb.exists(), "kept while its keychain items stay");
    assert!(p.drain_events().contains(&ProfileEvent::ProfileDamaged));
    kc.fail_delete.store(false, SeqCst);
    drop(Profiles::new(cfg(&root, Some(&kc))).unwrap());
    assert!(!tomb.exists());
    assert!(!kc.has(&id, "head") && !kc.has(&id, "protected"));
}

/// A-6: a legacy item start cannot move (a directory where the keystore was) is reported, never fatal; the others move.
#[test]
fn a6_legacy_item_unmovable_reported() {
    let (root, src) = (tmp(), tmp().with_extension("legacy"));
    std::fs::create_dir_all(src.join("keystore")).unwrap();
    std::fs::write(src.join("sdk.state"), br#"{"rev":1,"ops":[]}"#).unwrap();
    let mut c = cfg(&root, None);
    c.legacy = Some(src.clone());
    let p = Profiles::new(c).unwrap();
    assert!(p.drain_events().contains(&ProfileEvent::ProfileDamaged));
    assert!(!src.join("sdk.state").exists(), "the other item moved");
    assert!(src.join("keystore").is_dir(), "left as it is");
}

/// A-16 / G-12: start removes a `p/.tmp-*` only when its `build.lock` exists and is free: one without it (a builder between
/// its `mkdir` and its lock) is left. Control: one whose `build.lock` is free is removed.
#[test]
fn a16_tmp_without_build_lock_left() {
    let root = tmp();
    drop(Profiles::new(cfg(&root, None)).unwrap());
    let (bare, free) = (root.join("p/.tmp-0001"), root.join("p/.tmp-0002"));
    std::fs::create_dir(&bare).unwrap();
    std::fs::create_dir(&free).unwrap();
    std::fs::write(free.join("build.lock"), b"").unwrap();
    drop(Profiles::new(cfg(&root, None)).unwrap());
    assert!(!free.exists(), "control: a free build.lock");
    assert!(bare.exists(), "no build.lock yet: left");
}

/// G-11: a protected profile whose `g<gen>/` is missing (and its file anchor with it) is `ProfileDamaged`, never created
/// empty. Control: it opens before.
#[test]
fn g11_missing_generation_damaged() {
    let _k = kdf_lock();
    let root = tmp();
    let (p, o, id, dir) = protected(&root, None);
    o.lock();
    p.open(&id, Some(PASS)).unwrap().lock();
    std::fs::remove_dir_all(dir.join("g1")).unwrap();
    std::fs::remove_file(dir.join("profile.head")).unwrap();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileDamaged");
    assert!(!dir.join("g1").exists(), "never created");
}
