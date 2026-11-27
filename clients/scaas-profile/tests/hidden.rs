// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md),
//! UP8: hidden profiles (§6 planted rows and hints, §7.1 the name hint, §8, §10; §17 G7, name hint R3-B-1, the lock row "the
//! hidden search locks only the match"). Argon2id runs at the test set (feature `test-hooks`), dummy runs too; runs are
//! counted with `ProfileKeys::kdf_runs()` (process-wide), so every test holds [`KDF`].
#![cfg(feature = "test-hooks")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::{uuid7, Error, KdfParams, OpenProfile, ProfileEvent, Profiles, ProfilesConfig};
use scaas_ua::wallet::ProfileKeys;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

const PASS: &[u8] = b"correct horse battery staple";
const PASS2: &[u8] = b"another passphrase, longer";
const PASS3: &[u8] = b"a third passphrase, at last";
const TEST: KdfParams = KdfParams { m_kib: 8192, t: 1 };

static KDF: Mutex<()> = Mutex::new(());

fn kdf_lock() -> MutexGuard<'static, ()> {
    KDF.lock().unwrap_or_else(|e| e.into_inner())
}

fn rnd(n: u8) -> [u8; 10] {
    use std::hash::{BuildHasher, RandomState};
    let s = RandomState::new();
    let mut r = [0u8; 10];
    r[..8].copy_from_slice(&s.hash_one(n).to_le_bytes());
    r[8..].copy_from_slice(&s.hash_one(n ^ 0xff).to_le_bytes()[..2]);
    r
}

/// A fresh root (its first run's "default", unprotected and visible).
fn fresh() -> (Profiles, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "scaas-profile-up8-{}-{}",
        std::process::id(),
        uuid7(0, &rnd(1))
    ));
    (
        Profiles::new(ProfilesConfig::new(root.clone())).unwrap(),
        root,
    )
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "ok")
}

/// `f`'s result and the Argon2id runs it made.
fn runs<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = ProfileKeys::kdf_runs();
    let r = f();
    (r, ProfileKeys::kdf_runs() - before)
}

fn index(root: &Path) -> Option<Vec<u8>> {
    std::fs::read(root.join("profiles.json")).ok()
}

/// A UUID-named directory without a usable envelope, created at `ms` (0 sorts it before every other candidate).
fn damaged(root: &Path, ms: u64, n: u8) {
    let d = root.join("p").join(uuid7(ms, &rnd(n)));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("profile.envelope"), b"{not an envelope").unwrap();
}

fn envelope(o: &OpenProfile) -> Value {
    serde_json::from_slice(&std::fs::read(o.core().dir().join("profile.envelope")).unwrap())
        .unwrap()
}

fn names(p: &Profiles) -> Vec<String> {
    let mut v: Vec<String> = p.list().unwrap().into_iter().map(|i| i.name).collect();
    v.sort();
    v
}

fn hidden(p: &Profiles, name: &str, pass: &[u8]) -> OpenProfile {
    p.create_hidden(name.as_bytes(), pass, Some(TEST)).unwrap()
}

/// A visible profile `name` protected under `pass`, open.
fn visible(p: &Profiles, name: &str, pass: &[u8]) -> OpenProfile {
    let id = p.create(name).unwrap().id;
    let o = p.open(&id, None).unwrap();
    o.set_passphrase(pass, Some(TEST), None, None).unwrap();
    o
}

/// G7 runs counted: max(candidates, 4) for 0, 1, 4 and 5 candidates, wrong passphrase or not; a corrupt candidate costs one
/// run and ends nothing, wherever it sorts; no early stop at the match; `create_hidden` and the hidden opens write no index
/// byte (`last` included). Controls: the one match opens, as itself.
#[test]
fn g7_runs_counted() {
    let _k = kdf_lock();
    let (p, root) = fresh();
    let ix = index(&root);
    assert!(ix.is_some());
    assert_eq!(
        runs(|| code(p.open_hidden(b"Nobody", PASS))),
        ("ProfileOpen", 4)
    );
    let (o, n) = runs(|| hidden(&p, "Alice", PASS));
    assert_eq!(n, 5, "the search (4) and the wrap (1)");
    assert_eq!(o.info().name, "Alice");
    assert!(o.info().protected);
    o.lock();
    assert_eq!(index(&root), ix, "create_hidden writes no index byte");
    assert_eq!(names(&p), ["default"]);
    let (o, n) = runs(|| p.open_hidden("aLICE".as_bytes(), PASS).unwrap());
    assert_eq!((o.info().name.as_str(), n), ("Alice", 4));
    o.lock();
    assert_eq!(
        runs(|| code(p.open_hidden(b"Alice", PASS2))),
        ("ProfileOpen", 4)
    );
    for name in ["Bea", "Cy", "Dee"] {
        hidden(&p, name, PASS).lock();
    }
    let (o, n) = runs(|| p.open_hidden(b"Alice", PASS).unwrap());
    assert_eq!((o.info().name.as_str(), n), ("Alice", 4));
    o.lock();
    assert_eq!(
        runs(|| code(p.open_hidden(b"Eve", PASS))),
        ("ProfileOpen", 4)
    );
    // a corrupt candidate sorted first: one run, and the search goes on (the match is the next, not the last)
    damaged(&root, 0, 2);
    for name in ["Alice", "Dee"] {
        let (o, n) = runs(|| p.open_hidden(name.as_bytes(), PASS).unwrap());
        assert_eq!((o.info().name.as_str(), n), (name, 5));
        o.lock();
    }
    assert_eq!(
        runs(|| code(p.open_hidden(b"Alice", PASS3))),
        ("ProfileOpen", 5)
    );
    damaged(&root, 1, 3);
    let (o, n) = runs(|| p.open_hidden(b"Cy", PASS).unwrap());
    assert_eq!((o.info().name.as_str(), n), ("Cy", 6));
    o.lock();
    assert_eq!(
        index(&root),
        ix,
        "a hidden open writes no index byte, `last` neither"
    );

    // one hidden and one corrupt candidate: two runs and two dummy runs
    let (p, root) = fresh();
    hidden(&p, "Solo", PASS).lock();
    damaged(&root, 0, 4);
    let (o, n) = runs(|| p.open_hidden(b"Solo", PASS).unwrap());
    assert_eq!((o.info().name.as_str(), n), ("Solo", 4));
}

/// G7 limits: the 17th `create_hidden` and a `hide()` at 16 hidden are `ProfileHiddenLimit` before any KDF; 16 hidden plus 16
/// damaged directories (32 candidates) each still open, at 32 runs; 33 candidates `ProfileSearchTooLarge` before any run; a
/// create past 32 directories `ProfileLimit` before any run.
#[test]
fn g7_limits() {
    let _k = kdf_lock();
    let (p, root) = fresh();
    let vis = visible(&p, "Vis", PASS2);
    for i in 0..16 {
        hidden(&p, &format!("h{i}"), PASS).lock();
    }
    assert_eq!(
        runs(|| code(p.create_hidden(b"h16", PASS, Some(TEST)))),
        ("ProfileHiddenLimit", 0)
    );
    assert_eq!(
        runs(|| code(p.hide(&vis, PASS2))),
        ("ProfileHiddenLimit", 0)
    );
    vis.lock();
    for i in 0..16 {
        damaged(&root, u64::from(i), 10 + i);
    }
    for i in 0..16 {
        let name = format!("h{i}");
        let (o, n) = runs(|| p.open_hidden(name.as_bytes(), PASS).unwrap());
        assert_eq!((o.info().name, n), (name, 32));
        o.lock();
    }
    damaged(&root, 99, 50);
    assert_eq!(
        runs(|| code(p.open_hidden(b"h0", PASS))),
        ("ProfileSearchTooLarge", 0)
    );
    assert_eq!(
        runs(|| code(p.create_hidden(b"x", PASS, Some(TEST)))),
        ("ProfileLimit", 0)
    );
}

/// G7 duplicates: a (name, passphrase) a hidden profile has is `ProfileNameTaken` at `create_hidden`, `hide()`, a hidden
/// rename and a hidden passphrase change; the same name under another passphrase, a raise of the profile's own parameters and
/// a free name are the controls. `hide()` and a hidden rename check the typed passphrase first (`ProfileOpen`); a hidden rename
/// without one is `Argument`.
#[test]
fn g7_duplicates() {
    let _k = kdf_lock();
    let (p, _root) = fresh();
    hidden(&p, "Alice", PASS).lock();
    assert_eq!(
        code(p.create_hidden(b"ALICE", PASS, Some(TEST))),
        "ProfileNameTaken"
    );
    let a2 = hidden(&p, "alice", PASS2);
    // a hidden passphrase change onto a taken pair; the raise of its own parameters is no duplicate
    assert_eq!(
        code(a2.change_passphrase(PASS2, PASS, Some(TEST))),
        "ProfileNameTaken"
    );
    a2.change_passphrase(PASS2, PASS2, Some(TEST)).unwrap();
    a2.change_passphrase(PASS2, PASS3, None).unwrap();
    a2.lock();
    assert_eq!(p.open_hidden(b"alice", PASS3).unwrap().info().name, "alice");

    // hide(): the visible "Bob" under PASS beside a hidden "bob" under PASS
    let bob = visible(&p, "Bob", PASS);
    let hb = hidden(&p, "bob", PASS);
    assert_eq!(code(p.hide(&bob, PASS2)), "ProfileOpen");
    assert_eq!(code(p.hide(&bob, PASS)), "ProfileNameTaken");
    assert_eq!(names(&p), ["Bob", "default"]);
    hb.change_passphrase(PASS, PASS2, None).unwrap();
    p.hide(&bob, PASS).unwrap();
    assert_eq!(names(&p), ["default"]);
    bob.lock();
    hb.lock();

    // a hidden rename
    hidden(&p, "Carol", PASS).lock();
    let dave = hidden(&p, "Dave", PASS);
    assert_eq!(
        code(p.rename(&dave, b"carol", Some(PASS))),
        "ProfileNameTaken"
    );
    assert_eq!(code(p.rename(&dave, b"Dave2", None)), "Argument");
    assert_eq!(code(p.rename(&dave, b"Dave2", Some(PASS2))), "ProfileOpen");
    p.rename(&dave, b"Dave2", Some(PASS)).unwrap();
    assert_eq!(dave.info().name, "Dave2");
    dave.lock();
    assert_eq!(code(p.open_hidden(b"Dave", PASS)), "ProfileOpen");
    assert_eq!(p.open_hidden(b"dave2", PASS).unwrap().info().name, "Dave2");
}

/// §6 / G7: a planted row on a hidden profile: not listed; the open through it `ProfileOpen` before any KDF, the row dropped,
/// nothing else written; the hidden prompt still finds the profile.
#[test]
fn g7_planted_row() {
    let _k = kdf_lock();
    let (p, root) = fresh();
    let h = hidden(&p, "Hid", PASS);
    let id = h.info().id;
    let env = std::fs::read(h.core().dir().join("profile.envelope")).unwrap();
    h.lock();
    let def = p.list().unwrap()[0].id.clone();
    std::fs::write(
        root.join("profiles.json"),
        format!(
            r#"{{"format":"scaas.profiles","v":1,"rev":9,"last":null,"profiles":[{{"id":"{def}","name":"default"}},{{"id":"{id}","name":"Planted"}}]}}"#
        ),
    )
    .unwrap();
    assert_eq!(names(&p), ["default"]);
    assert_eq!(runs(|| code(p.open(&id, Some(PASS)))), ("ProfileOpen", 0));
    let ix = String::from_utf8(index(&root).unwrap()).unwrap();
    assert!(!ix.contains(&id) && ix.contains(&def));
    let dir = root.join("p").join(&id);
    assert_eq!(std::fs::read(dir.join("profile.envelope")).unwrap(), env);
    assert_eq!(p.open_hidden(b"Hid", PASS).unwrap().info().id, id);
}

/// Name hint (R3-B-1): `rename`, `hide()` and `show()` re-seal only the label: `pass` stays byte-identical and the profile
/// opens after each (the wraps' AD holds no name); a hint changed on disk opens with `ProfileIndexMismatch` and is rewritten
/// from the label (the hint unchanged opens with no event); a hint planted on a hidden envelope takes it out of the prompt,
/// the open through the list is refused and removes the hint, and the prompt finds it again.
#[test]
fn name_hint() {
    let _k = kdf_lock();
    let (p, root) = fresh();
    let eve = visible(&p, "Eve", PASS);
    let id = eve.info().id;
    let pass = envelope(&eve)["pass"].clone();
    p.rename(&eve, b"Eve2", None).unwrap();
    assert_eq!(envelope(&eve)["pass"], pass);
    assert_eq!(envelope(&eve)["name"], "Eve2");
    assert_eq!(names(&p), ["Eve2", "default"]);
    eve.lock();
    let eve = p.open(&id, Some(PASS)).unwrap();
    assert_eq!(eve.info().name, "Eve2");
    assert!(p.drain_events().is_empty());
    p.hide(&eve, PASS).unwrap();
    let e = envelope(&eve);
    assert_eq!((e["pass"].clone(), e.get("name")), (pass.clone(), None));
    assert_eq!(names(&p), ["default"]);
    eve.lock();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileOpen");
    let eve = p.open_hidden(b"eve2", PASS).unwrap();
    p.show(&eve).unwrap();
    assert_eq!(envelope(&eve)["pass"], pass);
    assert_eq!(names(&p), ["Eve2", "default"]);
    eve.lock();
    let eve = p.open(&id, Some(PASS)).unwrap();
    assert!(p.drain_events().is_empty());
    eve.lock();

    // a hint changed on disk: at the anchored rev another hash is a rollback (pinned format 8); with the rev raised the
    // label does not open at that rev, a rollback too (owner 2026-11-28, review F-2: it opened before); with the file
    // anchor removed as well (an anchor file and what it covers put back together, spec §14) it opens, the label wins
    let f = root.join("p").join(&id).join("profile.envelope");
    let s = std::fs::read_to_string(&f).unwrap();
    let rev = serde_json::from_str::<Value>(&s).unwrap()["rev"]
        .as_u64()
        .unwrap();
    let s = s.replace(r#""name":"Eve2""#, r#""name":"Mallory""#);
    std::fs::write(&f, &s).unwrap();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileRollback");
    let raised = format!(r#""rev":{},"#, rev + 1);
    std::fs::write(&f, s.replace(&format!(r#""rev":{rev},"#), &raised)).unwrap();
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileRollback");
    std::fs::write(&f, &s).unwrap();
    std::fs::remove_file(f.with_file_name("profile.head")).unwrap();
    p.drain_events();
    let eve = p.open(&id, Some(PASS)).unwrap();
    assert_eq!(eve.info().name, "Eve2");
    assert_eq!(p.drain_events(), [ProfileEvent::ProfileIndexMismatch]);
    assert_eq!(envelope(&eve)["name"], "Eve2");
    eve.lock();

    // a hint planted on a hidden envelope
    let h = hidden(&p, "Hid", PASS);
    let hid = h.info().id;
    h.lock();
    let f = root.join("p").join(&hid).join("profile.envelope");
    let s = std::fs::read_to_string(&f).unwrap();
    std::fs::write(&f, s.replace(r#""gen":1,"#, r#""gen":1,"name":"Planted","#)).unwrap();
    assert_eq!(code(p.open_hidden(b"Hid", PASS)), "ProfileOpen");
    std::fs::remove_file(root.join("profiles.json")).unwrap();
    assert_eq!(names(&p), ["Eve2", "Planted", "default"]);
    assert_eq!(code(p.open(&hid, Some(PASS))), "ProfileOpen");
    assert!(!std::fs::read_to_string(&f).unwrap().contains("Planted"));
    assert_eq!(names(&p), ["Eve2", "default"]);
    assert_eq!(p.open_hidden(b"Hid", PASS).unwrap().info().id, hid);
}

/// The lock row: the hidden search reads every candidate without its lock and locks only the match: with another hidden
/// profile open (its instance lock held), the search still finds the match; the held one is `ProfileInUse`, and opens once
/// it is locked.
#[test]
fn search_locks_only_the_match() {
    let _k = kdf_lock();
    let (p, _root) = fresh();
    let a = hidden(&p, "Ann", PASS);
    hidden(&p, "Ben", PASS).lock();
    let b = p.open_hidden(b"Ben", PASS).unwrap();
    assert_eq!(b.info().name, "Ben");
    assert_eq!(code(p.open_hidden(b"Ann", PASS)), "ProfileInUse");
    a.lock();
    assert_eq!(p.open_hidden(b"Ann", PASS).unwrap().info().name, "Ann");
}
