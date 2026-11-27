// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md),
//! UP7: the re-seal (§7.3, §7.6; §17 G4 for `set_passphrase` and `change_passphrase`, re-seal writes, generations, G5's
//! passphrase change, re-created items and tombstones). Profiles start as the first run's unprotected "default" and are
//! protected by `set_passphrase` at the test KDF set (feature `test-hooks`); every test holds [`KDF`] (`kdf_runs` is
//! process-wide). Crash points: `OpenProfile::reseal_hook` stops the re-seal after a step as if the process died.
#![cfg(feature = "test-hooks")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::{
    uuid7, Error, KdfParams, OpenProfile, ProfileKeychain, ProfilePart, Profiles, ProfilesConfig,
    Step,
};
use scaas_ua::wallet::ProfileKeys;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::Duration;

const SDK: ProfilePart = ProfilePart::Sdk;
const PQCHAT: ProfilePart = ProfilePart::PqChat;
const PASS: &[u8] = b"correct horse battery staple";
const PASS2: &[u8] = b"another passphrase, longer";
const TEST: KdfParams = KdfParams { m_kib: 8192, t: 1 };
const NEXT: &str = "profile.envelope.next";

static KDF: Mutex<()> = Mutex::new(());

fn kdf_lock() -> MutexGuard<'static, ()> {
    KDF.lock().unwrap_or_else(|e| e.into_inner())
}

fn tmp() -> PathBuf {
    use std::hash::{BuildHasher, RandomState};
    let mut r = [0u8; 10];
    r[..8].copy_from_slice(&RandomState::new().hash_one(7u8).to_le_bytes());
    std::env::temp_dir().join(format!(
        "scaas-profile-up7-{}-{}",
        std::process::id(),
        uuid7(0, &r)
    ))
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

fn item(rev: u64, body: &str) -> Vec<u8> {
    format!(r#"{{"rev":{rev},"body":"{body}"}}"#).into_bytes()
}

/// Settings bytes for `set_passphrase` to keep (they must parse as settings, review E-4); `idle` tells copies apart.
fn settings(rev: u64, idle: u64) -> Vec<u8> {
    format!(r#"{{"rev":{rev},"idle_lock_s":{idle}}}"#).into_bytes()
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "ok")
}

fn get(o: &OpenProfile, part: ProfilePart, name: &str) -> Option<Vec<u8>> {
    o.core().get(part, name).unwrap().map(|(pt, _)| pt.to_vec())
}

/// The generation directories of the profile directory `dir`, sorted.
fn gens(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with('g') && n[1..].bytes().all(|b| b.is_ascii_digit()))
        .collect();
    v.sort();
    v
}

/// A fresh root's "default" (unprotected), opened, holding `settings` at rev 1; its directory.
fn fresh_with(kc: Option<Arc<Keychain>>) -> (Profiles, String, OpenProfile, PathBuf) {
    let mut c = ProfilesConfig::new(tmp());
    c.keychain = kc.map(|k| k as Arc<dyn ProfileKeychain>);
    let p = Profiles::new(c).unwrap();
    let id = p.list().unwrap()[0].id.clone();
    let o = p.open(&id, None).unwrap();
    o.core()
        .put_if(SDK, "settings", None, &settings(1, 1))
        .unwrap();
    let dir = o.core().dir().to_path_buf();
    (p, id, o, dir)
}

fn fresh() -> (Profiles, String, OpenProfile, PathBuf) {
    fresh_with(None)
}

/// The same, protected under `PASS` (generation 1) and holding `a` in part `sdk` and `c` in part `pqchat`.
fn protected() -> (Profiles, String, OpenProfile, PathBuf) {
    let (p, id, o, dir) = fresh();
    o.set_passphrase(PASS, Some(TEST), Some(&settings(1, 1)), None)
        .unwrap();
    o.core().put_if(SDK, "a", None, &item(1, "a")).unwrap();
    o.core().put_if(PQCHAT, "c", None, &item(1, "c")).unwrap();
    (p, id, o, dir)
}

fn envelope(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(dir.join("profile.envelope")).unwrap()).unwrap()
}

/// Every item of [`protected`] readable.
fn whole(o: &OpenProfile) {
    assert_eq!(get(o, SDK, "settings"), Some(settings(1, 1)));
    assert_eq!(get(o, SDK, "a"), Some(item(1, "a")));
    assert_eq!(get(o, PQCHAT, "c"), Some(item(1, "c")));
}

/// `set_passphrase` (spec §7.3, §7.6; §17 G3's settings): the passphrase rule on the OpaqueString form and the KDF bounds
/// before any KDF; an unprotected profile's `change_passphrase` is `Argument`; the kept settings sealed into `g1/` (dropped
/// without `keep`), `g0/` removed, the keychain's `protected` marker written; a protected profile never returns
/// (`Argument`); the profile reopens under the passphrase.
#[test]
fn set_passphrase_seals_and_keeps() {
    let _k = kdf_lock();
    let kc = Arc::new(Keychain::default());
    let (p, id, o, dir) = fresh_with(Some(kc.clone()));
    let runs = ProfileKeys::kdf_runs();
    // 7 characters; digits only; 4 characters in NFC though 8 code points as typed (NFD)
    for weak in ["abcdefg", "12345678", "e\u{301}e\u{301}e\u{301}e\u{301}"] {
        assert_eq!(
            code(o.set_passphrase(weak.as_bytes(), Some(TEST), None, None)),
            "ProfilePassphraseWeak",
            "{weak:?}"
        );
    }
    let low = KdfParams { m_kib: 4096, t: 1 };
    assert_eq!(
        code(o.set_passphrase(PASS, Some(low), None, None)),
        "ProfileFormat"
    );
    assert_eq!(ProfileKeys::kdf_runs(), runs, "refused before any KDF");
    assert_eq!(
        code(o.change_passphrase(PASS, PASS2, Some(TEST))),
        "Argument"
    );
    assert_eq!(gens(&dir), ["g0"]);
    assert!(!o.info().protected);
    assert_eq!(
        code(o.core().put_if(SDK, "x", None, &item(1, "x"))),
        "ProfilePassphraseRequired"
    );
    // the rule's positive twin: 8 characters of NFC
    o.set_passphrase(PASS, Some(TEST), Some(&settings(2, 2)), None)
        .unwrap();
    assert!(o.info().protected);
    assert_eq!(get(&o, SDK, "settings"), Some(settings(2, 2)));
    assert_eq!(gens(&dir), ["g1"]);
    assert!(!dir.join(NEXT).exists());
    let e = envelope(&dir);
    assert_eq!(
        (e["state"].as_str(), e["gen"].as_u64(), e["rev"].as_u64()),
        (Some("protected"), Some(1), Some(2))
    );
    assert!(e.get("platform").is_none());
    let marker = format!("scaas.profile.{id}.protected");
    assert!(kc.get(&marker).unwrap().is_some(), "the protected marker");
    assert_eq!(
        code(o.set_passphrase(PASS, Some(TEST), None, None)),
        "Argument",
        "never back"
    );
    o.core().put_if(SDK, "x", None, &item(1, "x")).unwrap();
    drop(o);
    assert_eq!(code(p.open(&id, Some(PASS2))), "ProfileOpen");
    let o = p.open(&id, Some(PASS)).unwrap();
    assert_eq!(get(&o, SDK, "settings"), Some(settings(2, 2)));
    assert_eq!(get(&o, SDK, "x"), Some(item(1, "x")));
    // the settings dropped
    let (_p, _id, o, _dir) = fresh();
    o.set_passphrase(PASS, Some(TEST), None, None).unwrap();
    assert_eq!(get(&o, SDK, "settings"), None);
}

/// G4: a crash after each step of `set_passphrase` and of `change_passphrase` leaves the old or the new profile whole; the
/// next open rolls the journal back or removes the old generation.
#[test]
fn g4_crash_at_each_step() {
    let _k = kdf_lock();
    for step in [
        Step::Journal,
        Step::Generation,
        Step::Renamed,
        Step::Committed,
    ] {
        let new = matches!(step, Step::Renamed | Step::Committed);
        let (p, id, o, dir) = fresh();
        o.reseal_hook(Box::new(move |s| s == step));
        assert_eq!(
            code(o.set_passphrase(PASS, Some(TEST), Some(&settings(1, 1)), None)),
            "VaultIo"
        );
        drop(o);
        let o = match new {
            true => p.open(&id, Some(PASS)),
            false => p.open(&id, None),
        }
        .unwrap();
        assert_eq!(o.info().protected, new, "{step:?}");
        assert_eq!(get(&o, SDK, "settings"), Some(settings(1, 1)), "{step:?}");
        assert_eq!(gens(&dir), [if new { "g1" } else { "g0" }], "{step:?}");
        assert!(!dir.join(NEXT).exists());

        let (p, id, o, dir) = protected();
        o.reseal_hook(Box::new(move |s| s == step));
        assert_eq!(
            code(o.change_passphrase(PASS, PASS2, Some(TEST))),
            "VaultIo"
        );
        drop(o);
        let (good, bad) = if new { (PASS2, PASS) } else { (PASS, PASS2) };
        assert_eq!(code(p.open(&id, Some(bad))), "ProfileOpen", "{step:?}");
        let o = p.open(&id, Some(good)).unwrap();
        whole(&o);
        assert_eq!(gens(&dir), [if new { "g2" } else { "g1" }], "{step:?}");
        assert!(!dir.join(NEXT).exists());
    }
}

/// Re-seal writes (spec §7.3 step 1): a writer of part `sdk` issued while a `change_passphrase` holds the store write lock
/// waits, is never `StoreConflict`, and lands in `g2/` under the new keys after the commit; held past its (shortened) wait it
/// is `ProfileBusy` and writes nothing.
#[test]
fn writer_through_change_waits_and_lands() {
    let _k = kdf_lock();
    let (_p, _id, o, dir) = protected();
    let core = o.core().clone();
    // the re-seal stalls once `g<N+1>/` is complete, holding the store write lock
    let stall = |o: &OpenProfile| {
        let (at, go) = (mpsc::channel(), mpsc::channel::<()>());
        let (tx, rx) = (at.0, go.1);
        o.reseal_hook(Box::new(move |s| {
            if s == Step::Generation {
                tx.send(()).unwrap();
                // bounded: a failing assertion while it stalls must not hang the scope's join
                let _ = rx.recv_timeout(Duration::from_secs(10));
            }
            false
        }));
        (at.1, go.0)
    };
    let (at, go) = stall(&o);
    std::thread::scope(|sc| {
        let change = sc.spawn(|| o.change_passphrase(PASS, PASS2, Some(TEST)));
        at.recv().unwrap();
        let writer = sc.spawn(|| core.put_if(SDK, "w", None, &item(1, "w")));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!writer.is_finished(), "the writer waits for the commit");
        go.send(()).unwrap();
        assert_eq!(code(change.join().unwrap()), "ok");
        assert_eq!(code(writer.join().unwrap()), "ok", "never StoreConflict");
    });
    assert_eq!(get(&o, SDK, "w"), Some(item(1, "w")));
    assert_eq!(gens(&dir), ["g2"]);
    let keys = o.keys().unwrap();
    assert!(
        dir.join("g2")
            .join(keys.item_file("sdk", "w").unwrap())
            .exists(),
        "in the new generation, named under the new keys"
    );
    whole(&o);
    // past the wait
    core.set_write_wait(Duration::from_millis(50));
    let (at, go) = stall(&o);
    std::thread::scope(|sc| {
        let change = sc.spawn(|| o.change_passphrase(PASS2, PASS, Some(TEST)));
        at.recv().unwrap();
        assert_eq!(
            code(core.put_if(SDK, "late", None, &item(1, "late"))),
            "ProfileBusy"
        );
        go.send(()).unwrap();
        assert_eq!(code(change.join().unwrap()), "ok");
    });
    assert_eq!(get(&o, SDK, "late"), None, "nothing written");
    assert_eq!(get(&o, SDK, "w"), Some(item(1, "w")));
}

/// Generations at open (spec §7.3): an older envelope put back beside the live generation is `ProfileRollback` (the anchor
/// names a higher `gen`) or, without the anchor, `ProfileDamaged`, and nothing is removed; the live envelope with a wrong
/// passphrase removes nothing; with the right one the lower generation is removed only then.
#[test]
fn generations_older_envelope_kept() {
    let _k = kdf_lock();
    let (p, id, o, dir) = protected();
    let old = std::fs::read(dir.join("profile.envelope")).unwrap();
    o.reseal_hook(Box::new(|s| s == Step::Committed));
    assert_eq!(
        code(o.change_passphrase(PASS, PASS2, Some(TEST))),
        "VaultIo"
    );
    drop(o);
    assert_eq!(gens(&dir), ["g1", "g2"]);
    let live = std::fs::read(dir.join("profile.envelope")).unwrap();
    std::fs::write(dir.join("profile.envelope"), &old).unwrap();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileRollback");
    assert_eq!(gens(&dir), ["g1", "g2"]);
    std::fs::remove_file(dir.join("profile.head")).unwrap();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileDamaged");
    assert_eq!(gens(&dir), ["g1", "g2"]);
    std::fs::write(dir.join("profile.envelope"), &live).unwrap();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileOpen");
    assert_eq!(
        gens(&dir),
        ["g1", "g2"],
        "nothing removed before the wrap opens"
    );
    let o = p.open(&id, Some(PASS2)).unwrap();
    assert_eq!(gens(&dir), ["g2"]);
    whole(&o);
}

/// Generations at open: an envelope whose `gen` was edited upward beside the only generation is `ProfileDamaged` before any
/// KDF, nothing removed; a journaled `g<N+1>/` is removed before its journal (a `g2/` that cannot be removed keeps the
/// journal), then the profile opens as it was.
#[test]
fn generations_edited_gen_and_journal_order() {
    let _k = kdf_lock();
    let (p, id, o, dir) = protected();
    drop(o);
    let env = std::fs::read_to_string(dir.join("profile.envelope")).unwrap();
    std::fs::write(
        dir.join("profile.envelope"),
        env.replacen(r#""gen":1,"#, r#""gen":2,"#, 1),
    )
    .unwrap();
    let runs = ProfileKeys::kdf_runs();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileDamaged");
    assert_eq!(ProfileKeys::kdf_runs(), runs);
    assert_eq!(gens(&dir), ["g1"]);
    std::fs::write(dir.join("profile.envelope"), &env).unwrap();
    let o = p.open(&id, Some(PASS)).unwrap();
    o.reseal_hook(Box::new(|s| s == Step::Generation));
    assert_eq!(
        code(o.change_passphrase(PASS, PASS2, Some(TEST))),
        "VaultIo"
    );
    drop(o);
    assert_eq!(gens(&dir), ["g1", "g2"]);
    assert!(dir.join(NEXT).exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let g2 = dir.join("g2");
        std::fs::set_permissions(&g2, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert_eq!(code(p.open(&id, Some(PASS))), "VaultIo");
        assert!(dir.join(NEXT).exists(), "the journal outlives g2/");
        std::fs::set_permissions(&g2, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let o = p.open(&id, Some(PASS)).unwrap();
    assert_eq!(gens(&dir), ["g1"]);
    assert!(!dir.join(NEXT).exists());
    whole(&o);
}

/// G5 (spec §7.2): after a passphrase change the old envelope, put back with the old passphrase (its generation the new
/// one's files, no anchor), opens no item written after the change: `DEK_p` was rotated. Control: the new envelope reads it.
#[test]
fn g5_old_envelope_opens_nothing_after_change() {
    let _k = kdf_lock();
    let (p, id, o, dir) = protected();
    let old = std::fs::read(dir.join("profile.envelope")).unwrap();
    o.change_passphrase(PASS, PASS2, Some(TEST)).unwrap();
    o.core().put_if(SDK, "b", None, &item(1, "b")).unwrap();
    assert_eq!(get(&o, SDK, "b"), Some(item(1, "b")));
    drop(o);
    std::fs::write(dir.join("profile.envelope"), &old).unwrap();
    std::fs::rename(dir.join("g2"), dir.join("g1")).unwrap();
    std::fs::remove_file(dir.join("profile.head")).unwrap();
    let o = p.open(&id, Some(PASS)).unwrap();
    assert!(!matches!(o.core().get(SDK, "b"), Ok(Some(_))));
    assert!(!matches!(o.core().get(SDK, "a"), Ok(Some(_))));
}

/// Re-created items, tombstones (spec §7.2): the new generation's manifests hold no tombstone (control: the tombstone before);
/// a name deleted before the re-seal is created again from its caller's revision.
#[test]
fn tombstones_dropped_at_reseal() {
    let _k = kdf_lock();
    let (_p, _id, o, _dir) = protected();
    o.core().put_if(SDK, "t", None, &item(1, "t")).unwrap();
    o.core().delete(SDK, "t").unwrap();
    let before = o.core().manifest(SDK).unwrap();
    assert!(before.tombstones.contains_key("t"));
    o.change_passphrase(PASS, PASS2, Some(TEST)).unwrap();
    let m = o.core().manifest(SDK).unwrap();
    assert!(m.tombstones.is_empty());
    assert_eq!(m.rev, before.rev + 1, "the manifest's rev raised by one");
    assert!(m.items.contains_key("a"));
    assert_eq!(get(&o, SDK, "t"), None);
    o.core().put_if(SDK, "t", None, &item(1, "t2")).unwrap();
    assert_eq!(o.core().get(SDK, "t").unwrap().unwrap().1, 1);
    whole(&o);
}

/// The raise of the KDF parameters: `change_passphrase` with the same passphrase and new parameters; the envelope carries
/// them, the profile reopens under the passphrase.
#[test]
fn kdf_raise() {
    let _k = kdf_lock();
    let (p, id, o, dir) = protected();
    o.change_passphrase(PASS, PASS, Some(KdfParams::DEFAULT))
        .unwrap();
    let e = envelope(&dir);
    assert_eq!(
        (
            e["kdf"]["m"].as_u64(),
            e["kdf"]["t"].as_u64(),
            e["gen"].as_u64()
        ),
        (Some(65_536), Some(3), Some(2))
    );
    drop(o);
    whole(&p.open(&id, Some(PASS)).unwrap());
}
