// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md).
//! The store of `scaas-profile` (owner 2026-11-27: its own crate). UP5, the sealed store core (§5, §7.1 "Refusals by state", §7.2, §7.3 step 1; §17 G1, store files, G5, anchor, re-created
//! items, re-seal writes, G11): each negative test with its positive control; the manifest and anchor rows of
//! smartcontracts/vectors/profile/items.json. Profiles are built by hand: a generation directory and a `ProfileKeys` with a
//! fresh `DEK_p` (`create_dek`, no Argon2id).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use base64::Engine;
use scaas_profile::{
    Anchor, Core, CoreOpen, Error, Head, Manifest, ProfileKeychain, ProfilePart, Verdict,
};
use scaas_ua::wallet::ProfileKeys;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
#[cfg(feature = "test-hooks")]
use std::time::Duration;

const ID: &str = "01a21ce0-6e7b-7e63-9b1d-f667cc7d8daa";
const SDK: ProfilePart = ProfilePart::Sdk;
const PQCHAT: ProfilePart = ProfilePart::PqChat;
/// A pqchat-core key holding a UA and a Matrix room id (spec §7.2 "File name").
const SESSION: &str =
    "session:0x1b10fe0ecad6db2b08f128756e79939f5b6139551516e48fcc1cdde88b8be4d1:!AbCdEf:matrix.org";

fn tmp() -> PathBuf {
    use std::hash::{BuildHasher, RandomState};
    let d = std::env::temp_dir().join(format!(
        "scaas-profile-{}-{:x}",
        std::process::id(),
        RandomState::new().hash_one(0u8)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn keys() -> Arc<ProfileKeys> {
    let k = ProfileKeys::new();
    k.create_dek().unwrap();
    Arc::new(k)
}

fn at(dir: &Path, keys: &Arc<ProfileKeys>, envelope: Head) -> CoreOpen {
    CoreOpen {
        dir: dir.to_path_buf(),
        id: ID.into(),
        gen: 1,
        keys: Some(keys.clone()),
        keychain: None,
        envelope,
        migration_pending: false,
    }
}

fn env1() -> Head {
    Head::of(1, b"profile.envelope at rev 1")
}

fn open(dir: &Path, keys: &Arc<ProfileKeys>) -> Result<Core, Error> {
    Core::open(at(dir, keys, env1()))
}

fn item(rev: u64, body: &str) -> Vec<u8> {
    format!(r#"{{"rev":{rev},"body":"{body}"}}"#).into_bytes()
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn file_of(dir: &Path, keys: &ProfileKeys, part: &str, name: &str) -> PathBuf {
    dir.join("g1").join(keys.item_file(part, name).unwrap())
}

fn manifest_file(dir: &Path, keys: &ProfileKeys, part: &str) -> PathBuf {
    file_of(dir, keys, "profile", &format!("manifest:{part}"))
}

fn names(m: &BTreeMap<String, u64>) -> Vec<&str> {
    m.keys().map(String::as_str).collect()
}

/// G1: no item or part name in any file name of the generation nor in any byte of it; control: the opened manifests list them.
#[test]
fn g1_no_name_on_disk() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "endpoints"))
        .unwrap();
    c.put_if(SDK, "keystore", None, &item(1, "seeds")).unwrap();
    c.put_if(PQCHAT, SESSION, None, &item(1, "state")).unwrap();
    drop(c.lock_item(SDK, "keystore").unwrap());
    let words = [
        "settings",
        "keystore",
        "pqchat",
        "manifest",
        "profile",
        SESSION,
        "0x1b10fe0ecad6db2b08f128756e79939f5b6139551516e48fcc1cdde88b8be4d1",
        "!AbCdEf:matrix.org",
        "endpoints",
    ];
    let mut files = 0;
    for e in std::fs::read_dir(d.join("g1")).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().into_string().unwrap();
        let hex = name.strip_suffix(".lock").unwrap_or(&name);
        assert!(
            hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "file name {name}"
        );
        let bytes = std::fs::read(e.path()).unwrap();
        for w in words {
            assert!(!name.contains(w), "{w} in a file name");
            assert!(
                !bytes.windows(w.len()).any(|x| x == w.as_bytes()),
                "{w} in the bytes of {name}"
            );
        }
        files += 1;
    }
    // three items, two manifests, one lock
    assert_eq!(files, 6);
    // control: the manifests, opened, list every name
    assert_eq!(
        names(&c.manifest(SDK).unwrap().items),
        ["keystore", "settings"]
    );
    assert_eq!(names(&c.manifest(PQCHAT).unwrap().items), [SESSION]);
}

/// Store files (R2-A-1): a FileStore temporary a kill left is removed at the next open; `.lock` files are accepted; any other
/// file is `VaultFormat`. Control: a clean generation opens.
#[test]
fn store_files_temporaries_locks_others() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    drop(c.lock_item(SDK, "settings").unwrap());
    drop(c);
    assert_eq!(code(open(&d, &k)), "ok", "control: a clean generation");
    // what a process killed between a FileStore write and its rename leaves
    let f = file_of(&d, &k, "sdk", "settings");
    let tmp = d.join("g1").join(format!(
        "{}.tmp.4242.7",
        f.file_name().unwrap().to_str().unwrap()
    ));
    std::fs::write(&tmp, b"partial").unwrap();
    let c = open(&d, &k).unwrap();
    assert!(!tmp.exists(), "the temporary removed at open");
    assert!(
        d.join("g1")
            .join(format!("{}.lock", f.file_name().unwrap().to_str().unwrap()))
            .exists(),
        "the lock file kept"
    );
    assert_eq!(c.get(SDK, "settings").unwrap().unwrap().1, 1);
    drop(c);
    for other in ["notes.txt", "keystore", "settings.tmp.1.2"] {
        let p = d.join("g1").join(other);
        std::fs::write(&p, b"x").unwrap();
        assert_eq!(code(open(&d, &k)), "VaultFormat", "{other}");
        std::fs::remove_file(&p).unwrap();
    }
    std::fs::create_dir(d.join("g1").join("0".repeat(64))).unwrap();
    assert_eq!(code(open(&d, &k)), "VaultFormat", "a directory");
}

/// G5: an old copy of an item put back reads (rolled back, spec §7.2, review C-3) and refuses writes (`ProfileRollback`) until
/// `accept_rollback`; control: the current copy reads.
#[test]
fn g5_old_item_put_back() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "old")).unwrap();
    let f = file_of(&d, &k, "sdk", "settings");
    let old = std::fs::read(&f).unwrap();
    c.put_if(SDK, "settings", Some(1), &item(2, "new")).unwrap();
    let (pt, rev) = c.get(SDK, "settings").unwrap().unwrap();
    assert_eq!((&pt[..], rev), (&item(2, "new")[..], 2), "control");
    std::fs::write(&f, &old).unwrap();
    assert_eq!(
        &c.get(SDK, "settings").unwrap().unwrap().0[..],
        &item(1, "old")[..]
    );
    assert_eq!(
        code(c.put_if(SDK, "settings", Some(1), &item(2, "again"))),
        "ProfileRollback"
    );
    c.accept_rollback(SDK, "settings").unwrap();
    c.put_if(SDK, "settings", Some(1), &item(2, "again"))
        .unwrap();
}

/// G5: a deleted item put back (at its tombstone) reads as rolled back and refuses writes (`ProfileRollback`; spec §7.2,
/// review C-3; the next open removes it, review A-9); control: after the delete it reads as absent.
#[test]
fn g5_deleted_item_put_back() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    let f = file_of(&d, &k, "sdk", "settings");
    let old = std::fs::read(&f).unwrap();
    c.delete(SDK, "settings").unwrap();
    assert!(!f.exists());
    assert!(c.get(SDK, "settings").unwrap().is_none(), "control");
    assert_eq!(
        c.manifest(SDK).unwrap().tombstones.get("settings"),
        Some(&1)
    );
    std::fs::write(&f, &old).unwrap();
    assert_eq!(
        &c.get(SDK, "settings").unwrap().unwrap().0[..],
        &item(1, "a")[..]
    );
    assert_eq!(
        code(c.put_if(SDK, "settings", None, &item(1, "b"))),
        "ProfileRollback"
    );
}

/// G5: an item its manifest lists whose file is missing is `ProfileDamaged`; control: it reads before.
#[test]
fn g5_listed_item_removed() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    assert!(c.get(SDK, "settings").unwrap().is_some(), "control");
    std::fs::remove_file(file_of(&d, &k, "sdk", "settings")).unwrap();
    assert_eq!(code(c.get(SDK, "settings")), "ProfileDamaged");
    assert_eq!(
        code(c.put_if(SDK, "settings", None, &item(1, "b"))),
        "ProfileDamaged"
    );
}

/// G5, anchor: an old manifest under the anchor is `ProfileRollback`, and so is another manifest at the anchor's rev; control:
/// the current one opens.
#[test]
fn g5_old_manifest_under_anchor() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    let m = manifest_file(&d, &k, "sdk");
    let old = std::fs::read(&m).unwrap();
    c.put_if(SDK, "keystore", None, &item(1, "b")).unwrap();
    let now = std::fs::read(&m).unwrap();
    drop(c);
    assert_eq!(code(open(&d, &k)), "ok", "control");
    std::fs::write(&m, &old).unwrap();
    assert_eq!(code(open(&d, &k)), "ProfileRollback", "an old manifest");
    std::fs::write(&m, &now).unwrap();
    assert_eq!(code(open(&d, &k)), "ok", "control: put back");
    // another profile directory under the same keys: its manifest at the same rev opens, its hash differs
    let d2 = tmp();
    let c2 = open(&d2, &k).unwrap();
    c2.put_if(SDK, "sdk.state", None, &item(1, "c")).unwrap();
    c2.put_if(SDK, "keystore", None, &item(1, "d")).unwrap();
    std::fs::copy(manifest_file(&d2, &k, "sdk"), &m).unwrap();
    assert_eq!(
        code(open(&d, &k)),
        "ProfileRollback",
        "another hash at the same rev"
    );
}

/// G5: two writers of two items of one part both land in its manifest, though the second's manifest write lands between the
/// first's manifest read and its write (two cores over one directory, as two processes).
#[cfg(feature = "test-hooks")]
#[test]
fn g5_two_writers_both_land() {
    let (d, k) = (tmp(), keys());
    let a = open(&d, &k).unwrap();
    let b = Arc::new(open(&d, &k).unwrap());
    let b2 = b.clone();
    a.before_manifest_write(Box::new(move || {
        b2.put_if(SDK, "sdk.state", None, &item(1, "b")).unwrap();
    }));
    a.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    let m = a.manifest(SDK).unwrap();
    assert_eq!(names(&m.items), ["sdk.state", "settings"]);
    assert_eq!(m.rev, 2);
    assert!(b.get(SDK, "settings").unwrap().is_some());
    assert!(a.get(SDK, "sdk.state").unwrap().is_some());
}

/// Anchor (R3-A-1): a kill between a manifest write and its anchor, or between an envelope write and its anchor, opens with no
/// event and the anchor follows; an envelope below the anchor, or another hash at its rev, is `ProfileRollback`.
#[test]
fn anchor_follows_a_crash_refuses_a_rollback() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    let head = d.join("profile.head");
    let old = std::fs::read(&head).unwrap();
    c.put_if(SDK, "settings", Some(1), &item(2, "b")).unwrap();
    let now = std::fs::read(&head).unwrap();
    assert_ne!(old, now);
    drop(c);
    // the manifest's write landed, its anchor's did not
    std::fs::write(&head, &old).unwrap();
    let c = open(&d, &k).unwrap();
    assert_eq!(std::fs::read(&head).unwrap(), now, "the anchor followed");
    assert_eq!(c.get(SDK, "settings").unwrap().unwrap().1, 2);
    drop(c);
    // the envelope's write landed (rev 2), its anchor's did not
    let env2 = Head::of(2, b"profile.envelope at rev 2");
    let c = Core::open(at(&d, &k, env2.clone())).unwrap();
    let a: Value = serde_json::from_slice(&std::fs::read(&head).unwrap()).unwrap();
    assert_eq!(a["envelope"]["rev"], 2, "the anchor followed the envelope");
    drop(c);
    assert_eq!(
        code(Core::open(at(&d, &k, env1()))),
        "ProfileRollback",
        "an envelope below the anchor"
    );
    assert_eq!(
        code(Core::open(at(&d, &k, Head::of(2, b"another envelope")))),
        "ProfileRollback",
        "another envelope at the anchor's rev"
    );
    let c = Core::open(at(&d, &k, env2)).unwrap();
    // an envelope write through the core: the anchor follows at once
    c.set_envelope(Head::of(3, b"profile.envelope at rev 3"))
        .unwrap();
    let a: Value = serde_json::from_slice(&std::fs::read(&head).unwrap()).unwrap();
    assert_eq!(a["envelope"]["rev"], 3);
}

/// Re-created items (N-2, N-3): an item deleted then created again continues above its tombstone and reads with no event; the
/// face shows the caller its own revision. Control: an item never deleted is stored at the caller's revision.
#[test]
fn recreated_item_above_its_tombstone() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    c.put_if(SDK, "settings", Some(1), &item(2, "a")).unwrap();
    c.put_if(SDK, "keystore", None, &item(1, "k")).unwrap();
    c.delete(SDK, "settings").unwrap();
    c.put_if(SDK, "settings", None, &item(1, "again")).unwrap();
    drop(c);
    let c = open(&d, &k).unwrap();
    let (pt, rev) = c.get(SDK, "settings").unwrap().unwrap();
    assert_eq!((&pt[..], rev), (&item(1, "again")[..], 1));
    let m = c.manifest(SDK).unwrap();
    assert_eq!(m.items.get("settings"), Some(&3), "above the tombstone (2)");
    assert!(m.tombstones.is_empty());
    assert_eq!(m.items.get("keystore"), Some(&1), "control");
    c.put_if(SDK, "settings", Some(1), &item(2, "next"))
        .unwrap();
    assert_eq!(c.get(SDK, "settings").unwrap().unwrap().1, 2);
    assert_eq!(c.manifest(SDK).unwrap().items.get("settings"), Some(&4));
    // the caller's own revision is what put_if compares
    assert_eq!(
        code(c.put_if(SDK, "settings", Some(4), &item(5, "x"))),
        "StoreConflict"
    );
}

/// Re-seal writes (R2-A-2, §7.3 step 1): a writer waits for the store write lock (never `StoreConflict`) and lands after its
/// release; one held past the (shortened) wait is `ProfileBusy` and writes nothing.
#[cfg(feature = "test-hooks")]
#[test]
fn writer_waits_then_busy() {
    let (d, k) = (tmp(), keys());
    let c = Arc::new(open(&d, &k).unwrap());
    let g = c.write_lock().unwrap();
    let c2 = c.clone();
    let t = std::thread::spawn(move || c2.put_if(SDK, "settings", None, &item(1, "waited")));
    std::thread::sleep(Duration::from_millis(300));
    assert!(!t.is_finished(), "the writer waits");
    drop(g);
    t.join().unwrap().unwrap();
    assert_eq!(c.get(SDK, "settings").unwrap().unwrap().1, 1, "it landed");
    // a stalled re-seal: held past the wait
    c.set_write_wait(Duration::from_millis(100));
    let g = c.write_lock().unwrap();
    let c2 = c.clone();
    let r = std::thread::spawn(move || c2.put_if(SDK, "keystore", None, &item(1, "k")))
        .join()
        .unwrap();
    assert_eq!(code(r), "ProfileBusy");
    drop(g);
    assert!(c.get(SDK, "keystore").unwrap().is_none(), "nothing written");
    assert!(!file_of(&d, &k, "sdk", "keystore").exists());
}

/// G11: a sealed item that does not open is `VaultFormat` (not `VaultIo`); control: it reads before.
#[test]
fn sealed_item_not_opening_is_vault_format() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    assert!(c.get(SDK, "settings").unwrap().is_some(), "control");
    let f = file_of(&d, &k, "sdk", "settings");
    let mut v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut sealed = b64.decode(v["sealed"].as_str().unwrap()).unwrap();
    sealed[20] ^= 1;
    v["sealed"] = b64.encode(&sealed).into();
    std::fs::write(&f, serde_json::to_vec(&v).unwrap()).unwrap();
    assert_eq!(code(c.get(SDK, "settings")), "VaultFormat");
    std::fs::write(&f, b"{\"rev\":1,\"sealed\":\"not base64\"}").unwrap();
    assert_eq!(code(c.get(SDK, "settings")), "VaultFormat");
    std::fs::write(&f, b"{\"rev\":1,\"plain\":true}").unwrap();
    assert_eq!(code(c.get(SDK, "settings")), "VaultFormat", "a plain item");
}

/// Bounds: 65,536 manifest entries per part, tombstones included (`ProfilePartFull`, nothing written); the 16 MiB plain bound.
#[test]
fn part_and_item_bounds() {
    let (d, k) = (tmp(), keys());
    let c = open(&d, &k).unwrap();
    // a manifest of 65,534 items and one tombstone, sealed in place by hand
    let items: Vec<(String, u64)> = (0..65_534).map(|i| (format!("i{i}"), 1)).collect();
    let m = Manifest::from_lists(1, items, vec![("t".into(), 1)]).unwrap();
    let json = m.json("pqchat").unwrap();
    let sealed = k.seal_item("profile", "manifest:pqchat", 1, &json).unwrap();
    let file = format!(
        r#"{{"rev":1,"sealed":"{}"}}"#,
        base64::engine::general_purpose::STANDARD.encode(sealed)
    );
    std::fs::write(manifest_file(&d, &k, "pqchat"), file).unwrap();
    // the 65,536th entry (control), a re-creation over the tombstone (no new entry), then one more refused
    c.put_if(PQCHAT, "new", None, &item(1, "x")).unwrap();
    c.put_if(PQCHAT, "t", None, &item(1, "x")).unwrap();
    assert_eq!(
        code(c.put_if(PQCHAT, "one-more", None, &item(1, "x"))),
        "ProfilePartFull"
    );
    assert!(
        !file_of(&d, &k, "pqchat", "one-more").exists(),
        "nothing written"
    );
    assert_eq!(
        code(Manifest::from_lists(
            1,
            (0..65_537).map(|i| (format!("i{i}"), 1)).collect(),
            vec![]
        )),
        "ProfilePartFull"
    );
    // the plain bound: 16 MiB round-trips, one byte more is refused
    let mut big = br#"{"rev":1,"b":""#.to_vec();
    big.resize((16 << 20) - 2, b'A');
    big.extend_from_slice(br#""}"#);
    c.put_if(SDK, "sdk.state", None, &big).unwrap();
    let (pt, rev) = c.get(SDK, "sdk.state").unwrap().unwrap();
    assert_eq!((pt.len(), rev), (16 << 20, 1));
    big.insert(10, b' ');
    assert_eq!(code(c.put_if(SDK, "sdk.state", Some(1), &big)), "Argument");
    assert_eq!(
        code(c.put_if(SDK, "settings", None, b"{}")),
        "Argument",
        "no rev"
    );
}

/// §7.1 "Refusals by state", §5: the unprotected `g0` has plain names, part `sdk` and `settings` only (the legacy items only
/// under `migration: pending`), no manifest; a sealed item in it is `ProfileFormat`; a generation other than `g0` is refused.
#[test]
fn unprotected_g0() {
    let d = tmp();
    let o = |gen, migration_pending| CoreOpen {
        dir: d.clone(),
        id: ID.into(),
        gen,
        keys: None,
        keychain: None,
        envelope: Head::of(1, b"unprotected envelope"),
        migration_pending,
    };
    assert_eq!(
        code(Core::open(o(1, false))),
        "ProfileFormat",
        "g1 unprotected"
    );
    let mut protected = at(&d, &keys(), env1());
    protected.gen = 0;
    assert_eq!(code(Core::open(protected)), "ProfileFormat", "g0 protected");
    let c = Core::open(o(0, false)).unwrap();
    c.put_if(SDK, "settings", None, &item(1, "plain")).unwrap();
    assert_eq!(
        std::fs::read(d.join("g0/settings")).unwrap(),
        item(1, "plain")
    );
    assert_eq!(c.get(SDK, "settings").unwrap().unwrap().1, 1);
    for (part, name) in [(SDK, "keystore"), (SDK, "sdk.state"), (PQCHAT, "x")] {
        assert_eq!(
            code(c.put_if(part, name, None, &item(1, "secret"))),
            "ProfilePassphraseRequired",
            "{name}"
        );
    }
    assert!(c.get(SDK, "keystore").unwrap().is_none());
    // a sealed item in an unprotected profile: refused to read and to write
    let sealed = br#"{"rev":2,"sealed":"AAAA"}"#;
    assert_eq!(
        code(c.put_if(SDK, "settings", Some(1), sealed)),
        "ProfileFormat"
    );
    std::fs::write(d.join("g0/settings"), sealed).unwrap();
    assert_eq!(code(c.get(SDK, "settings")), "ProfileFormat");
    std::fs::write(d.join("g0/settings"), item(1, "plain")).unwrap();
    // a keystore item without `migration: pending`
    std::fs::write(d.join("g0/keystore"), item(3, "legacy")).unwrap();
    assert_eq!(code(c.get(SDK, "keystore")), "ProfileFormat");
    drop(c);
    // control: a migrated "default" holds them
    let c = Core::open(o(0, true)).unwrap();
    assert_eq!(c.get(SDK, "keystore").unwrap().unwrap().1, 3);
    c.put_if(SDK, "keystore", Some(3), &item(4, "legacy"))
        .unwrap();
    assert!(!d.join("g0").read_dir().unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_str()
        .unwrap()
        .starts_with("manifest")));
}

/// A test keychain (spec §11 `ProfileKeychain`).
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

/// Anchor (R3-A-1): with a keychain both anchors are written and compared by one rule. A client without a keychain taking a
/// turn leaves the keychain's anchor behind: the next open follows, no event. A manifest and `profile.head` put back together
/// pass the file (the residual of §14) and are `ProfileRollback` by the keychain's anchor.
#[test]
fn keychain_anchor() {
    let (d, k) = (tmp(), keys());
    let kc = Arc::new(Keychain::default());
    let with = || {
        let mut o = at(&d, &k, env1());
        o.keychain = Some(kc.clone() as Arc<dyn ProfileKeychain>);
        Core::open(o)
    };
    let name = format!("scaas.profile.{ID}.head");
    let c = with().unwrap();
    c.put_if(SDK, "settings", None, &item(1, "a")).unwrap();
    let file = std::fs::read(d.join("profile.head")).unwrap();
    assert_eq!(kc.0.lock().unwrap().get(&name), Some(&file));
    drop(c);
    // the CLI's turn (no keychain)
    let c = open(&d, &k).unwrap();
    c.put_if(SDK, "settings", Some(1), &item(2, "b")).unwrap();
    let m = manifest_file(&d, &k, "sdk");
    let (old_m, old_head) = (
        std::fs::read(&m).unwrap(),
        std::fs::read(d.join("profile.head")).unwrap(),
    );
    drop(c);
    let c = with().unwrap();
    let file = std::fs::read(d.join("profile.head")).unwrap();
    assert_eq!(kc.0.lock().unwrap().get(&name), Some(&file), "followed");
    c.put_if(SDK, "settings", Some(2), &item(3, "c")).unwrap();
    drop(c);
    // the manifest and the anchor file put back together
    std::fs::write(&m, old_m).unwrap();
    std::fs::write(d.join("profile.head"), old_head).unwrap();
    assert_eq!(code(open(&d, &k)), "ok", "the file alone does not see it");
    assert_eq!(code(with()), "ProfileRollback");
}

fn rows() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/profile/items.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn list(v: &Value) -> Vec<(String, u64)> {
    serde_json::from_value(v.clone()).unwrap()
}

/// Pinned format 7: every manifest row serialises to its bytes and parses back; the refusals (`ProfileFormat`, `VaultFormat`
/// at the store) refused.
#[test]
fn manifest_rows() {
    let v = rows();
    let ok = v["manifests"].as_array().unwrap();
    assert!(ok.len() >= 5);
    for r in ok {
        let (part, rev) = (r["part"].as_str().unwrap(), r["rev"].as_u64().unwrap());
        let m = Manifest::from_lists(rev, list(&r["items"]), list(&r["tombstones"])).unwrap();
        let json = r["json"].as_str().unwrap();
        assert_eq!(
            String::from_utf8(m.json(part).unwrap().to_vec()).unwrap(),
            json,
            "{}",
            r["case"]
        );
        let back = Manifest::parse(part, rev, json.as_bytes()).unwrap();
        assert_eq!(&back.json(part).unwrap()[..], json.as_bytes());
        assert_eq!(
            code(Manifest::parse("other", rev, json.as_bytes())),
            "VaultFormat"
        );
        assert_eq!(
            code(Manifest::parse(part, rev + 1, json.as_bytes())),
            "VaultFormat"
        );
    }
    let bad = v["manifest_refusals"].as_array().unwrap();
    assert!(!bad.is_empty());
    for r in bad {
        assert_eq!(r["error"], "ProfileFormat");
        let m = Manifest::from_lists(
            r["rev"].as_u64().unwrap(),
            list(&r["items"]),
            list(&r["tombstones"]),
        );
        assert_eq!(code(m), "ProfileFormat", "{}", r["case"]);
    }
}

fn anchor(v: &Value) -> Anchor {
    serde_json::from_value(v.clone()).unwrap()
}

/// Pinned format 8: the anchor row built from its files equals its bytes; every compare row (CLI-UPR-28) gives its verdict.
#[test]
fn anchor_rows() {
    let v = rows();
    for r in v["anchors"].as_array().unwrap() {
        let env = r["envelope_file"].as_str().unwrap();
        let env_v: Value = serde_json::from_str(env).unwrap();
        let parts = r["manifest_files"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(p, f)| {
                let f = f.as_str().unwrap().as_bytes();
                (p.clone(), Head::of(scaas_profile::rev_of(f), f))
            })
            .collect();
        let a = Anchor {
            gen: env_v["gen"].as_u64().unwrap(),
            envelope: Head::of(env_v["rev"].as_u64().unwrap(), env.as_bytes()),
            parts,
        };
        assert_eq!(a, anchor(&r["anchor"]));
        assert_eq!(
            String::from_utf8(a.json().unwrap()).unwrap(),
            r["json"].as_str().unwrap()
        );
        assert_eq!(
            Anchor::parse(r["json"].as_str().unwrap().as_bytes()),
            Some(a)
        );
    }
    let cmp = v["anchor_compare"].as_array().unwrap();
    assert!(cmp.len() >= 14);
    for r in cmp {
        let want = match r["verdict"].as_str().unwrap() {
            "same" => Verdict::Same,
            "follow" => Verdict::Follow,
            "rollback" => Verdict::Rollback,
            o => panic!("{o}"),
        };
        assert_eq!(
            anchor(&r["stored"]).compare(&anchor(&r["anchor"])),
            want,
            "{}",
            r["case"]
        );
    }
}
