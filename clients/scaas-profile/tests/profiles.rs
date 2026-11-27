// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md),
//! UP6: the profile root, the index, the envelope, start, create, open, list and lock (§4, §5, §6, §7.1, §7.5, §9, §10; §17
//! G3, G4 create, G8, G10, G11, G12, Matrix per profile, the vector rows of smartcontracts/vectors/profile/{ids,envelope}.json).
//! Each negative test with its positive control. Protected profiles run Argon2id at the test set (feature `test-hooks`) and
//! are built by hand (`ProfileKeys`, one wrap); every test that runs or counts a KDF holds [`KDF`] (`kdf_runs` is
//! process-wide). The lock tests across processes are in `lock.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::{
    check_name, name_key, uuid7, Envelope, Error, Kdf, KdfParams, ProfileEvent, ProfileInfo,
    ProfileKeychain, ProfilePart, Profiles, ProfilesConfig,
};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
#[cfg(feature = "test-hooks")]
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex};

const SDK: ProfilePart = ProfilePart::Sdk;
#[cfg(feature = "test-hooks")]
const PASS: &str = "correct horse battery staple";

/// Every test that runs or counts an Argon2id run.
#[cfg(feature = "test-hooks")]
static KDF: Mutex<()> = Mutex::new(());

#[cfg(feature = "test-hooks")]
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

/// A fresh root path (not created).
fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "scaas-profile-up6-{}-{}",
        std::process::id(),
        uuid7(0, &rnd(1))
    ))
}

fn new_id() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    uuid7(ms, &rnd(2))
}

fn cfg(root: &Path) -> ProfilesConfig {
    ProfilesConfig::new(root.to_path_buf())
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn rows(file: &str) -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/profile")
        .join(file);
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// `p/<id>/profile.envelope` written as given (a hand-built or vector profile), and a protected one's generation `g<gen>/`
/// (every path that makes a protected profile makes it; one without it is `ProfileDamaged`, review G-11).
fn plant(root: &Path, id: &str, envelope: &str) {
    let d = root.join("p").join(id);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("profile.envelope"), envelope).unwrap();
    let v: Value = serde_json::from_str(envelope).unwrap_or(Value::Null);
    if v["state"] == "protected" {
        std::fs::create_dir_all(d.join(format!("g{}", v["gen"]))).unwrap();
    }
}

fn unprotected(id: &str, name: &str) -> String {
    format!(
        r#"{{"format":"scaas.profile","v":1,"id":"{id}","state":"unprotected","rev":1,"gen":0,"name":"{name}"}}"#
    )
}

/// A protected profile at the test set, built by hand: one wrap of a fresh `DEK_p` under `pass`, its label; `name` its hint.
#[cfg(feature = "test-hooks")]
fn protected(root: &Path, hint: Option<&str>, label: &str, hidden: bool, pass: &str) -> String {
    use base64::Engine;
    use scaas_ua::wallet::ProfileKeys;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let id = new_id();
    let salt = rnd(3)[..8].repeat(2);
    let kdf = format!(
        r#"{{"alg":"argon2id","v":1,"m":8192,"t":1,"p":4,"salt":"{}"}}"#,
        b64(&salt)
    );
    let public = format!(
        r#"{{"format":"scaas.profile","v":1,"id":"{id}","state":"protected","gen":1,"kdf":{kdf}}}"#
    );
    let k = ProfileKeys::new();
    k.create_dek().unwrap();
    let wrap = k
        .wrap_pass(
            pass.as_bytes(),
            &salt,
            ProfileKeys::KDF_TEST,
            public.as_bytes(),
        )
        .unwrap();
    let sealed = k
        .seal_label(
            &id,
            1,
            format!(r#"{{"name":"{label}","hidden":{hidden}}}"#).as_bytes(),
        )
        .unwrap();
    let name = hint.map_or(String::new(), |n| format!(r#","name":"{n}""#));
    plant(
        root,
        &id,
        &format!(
            r#"{{"format":"scaas.profile","v":1,"id":"{id}","state":"protected","rev":1,"gen":1{name},"kdf":{kdf},"pass":"{}","label":"{}"}}"#,
            b64(&wrap),
            b64(&sealed)
        ),
    );
    id
}

fn names(p: &Profiles) -> Vec<(String, bool)> {
    let mut v: Vec<_> = p
        .list()
        .unwrap()
        .into_iter()
        .map(|i| (i.name, i.protected))
        .collect();
    v.sort();
    v
}

fn by_name(p: &Profiles, name: &str) -> ProfileInfo {
    p.list()
        .unwrap()
        .into_iter()
        .find(|i| i.name == name)
        .unwrap()
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

/// The id rows (spec §4, §6): UUIDv7 as `uuid`'s builder makes it; `name_key`; the name check.
#[test]
fn ids_rows() {
    let v = rows("ids.json");
    // review D-6: the Unicode version the name rows assume; Rust's char tables and unicode-normalization at it or later
    let want: Vec<u32> = v["unicode"]
        .as_str()
        .unwrap()
        .split('.')
        .map(|x| x.parse().unwrap())
        .collect();
    let (major, minor, _) = char::UNICODE_VERSION;
    assert!((major as u32, minor as u32) >= (want[0], want[1]), "char");
    let (major, minor, _) = unicode_normalization::UNICODE_VERSION;
    assert!(
        (major as u32, minor as u32) >= (want[0], want[1]),
        "unicode-normalization"
    );
    for r in v["uuid7"].as_array().unwrap() {
        let random: [u8; 10] = hex(r["random"].as_str().unwrap()).try_into().unwrap();
        assert_eq!(
            uuid7(r["ms"].as_u64().unwrap(), &random),
            r["uuid"].as_str().unwrap(),
            "{}",
            r["case"]
        );
    }
    for r in v["name_key"].as_array().unwrap() {
        let input = String::from_utf8(hex(r["input_utf8"].as_str().unwrap())).unwrap();
        assert_eq!(
            name_key(&input).as_bytes(),
            hex(r["name_key_utf8"].as_str().unwrap())
        );
    }
    for r in v["check_name"].as_array().unwrap() {
        let input = String::from_utf8(hex(r["input_utf8"].as_str().unwrap())).unwrap();
        match r.get("error") {
            Some(e) => assert_eq!(
                code(check_name(&input)),
                e.as_str().unwrap(),
                "{}",
                r["case"]
            ),
            None => assert_eq!(check_name(&input).unwrap(), r["nfc"].as_str().unwrap()),
        }
    }
}

/// The envelope rows (spec §7.1, §7.5): the files parse and write back byte-identical, their public JSON the row's; the KDF
/// bounds (the test set only under `test-hooks`); the name-hint file parses.
#[test]
fn envelope_rows() {
    let v = rows("envelope.json");
    for r in v["files"]
        .as_array()
        .unwrap()
        .iter()
        .chain(v["name_hint"].as_array().unwrap())
    {
        let file = r["file"].as_str().unwrap();
        let id = serde_json::from_str::<Value>(file).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let e = Envelope::parse(file.as_bytes(), &id);
        if file.contains(r#""m":8192,"t":1"#) && !cfg!(feature = "test-hooks") {
            assert_eq!(code(e), "ProfileFormat", "{}", r["case"]);
            continue;
        }
        let e = e.unwrap();
        assert_eq!(e.json().unwrap(), file.as_bytes());
        if let Some(p) = r.get("public_json") {
            assert_eq!(e.public_json().unwrap(), p.as_str().unwrap().as_bytes());
        }
        // its id is its directory's
        assert_eq!(
            code(Envelope::parse(file.as_bytes(), &new_id())),
            "ProfileFormat"
        );
    }
    // the default set (review D-5)
    let d = &v["kdf_sets"]["default"];
    assert_eq!(
        (
            u64::from(KdfParams::DEFAULT.m_kib),
            u64::from(KdfParams::DEFAULT.t),
            4
        ),
        (
            d["m"].as_u64().unwrap(),
            d["t"].as_u64().unwrap(),
            d["p"].as_u64().unwrap()
        )
    );
    for r in v["kdf_bounds"].as_array().unwrap() {
        // a kdf object of other fields is refused by its parse (the envelope's ProfileFormat)
        let Ok(k) = serde_json::from_value::<Kdf>(r["kdf"].clone()) else {
            assert_eq!(r["error"], "ProfileFormat", "{}", r["case"]);
            continue;
        };
        let test_set = k.m == 8192 && k.t == 1;
        if test_set && r["test_hooks"].as_bool().unwrap() != cfg!(feature = "test-hooks") {
            continue;
        }
        let want = r.get("error").map_or("ok", |e| e.as_str().unwrap());
        assert_eq!(code(k.check(KdfParams::MAX_KIB)), want, "{}", r["case"]);
    }
    // a version this build does not read; a field it does not know; a non-canonical form
    let u = unprotected("01a21ce0-6e7b-74ce-8fb7-42ad9d2a5b40", "default");
    let id = "01a21ce0-6e7b-74ce-8fb7-42ad9d2a5b40";
    assert_eq!(code(Envelope::parse(u.as_bytes(), id)), "ok");
    let v2 = u.replace(r#""v":1"#, r#""v":2"#);
    assert_eq!(code(Envelope::parse(v2.as_bytes(), id)), "ProfileVersion");
    let extra = u.replace(r#""name""#, r#""x":1,"name""#);
    assert_eq!(code(Envelope::parse(extra.as_bytes(), id)), "ProfileFormat");
    let spaced = u.replace(r#""rev":1"#, r#""rev": 1"#);
    assert_eq!(
        code(Envelope::parse(spaced.as_bytes(), id)),
        "ProfileFormat"
    );
}

/// First run (spec §10): a new root gets "default", unprotected, and a second start makes no second one.
#[test]
fn first_run_default() {
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(names(&p), [("default".to_string(), false)]);
    drop(p);
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(names(&p), [("default".to_string(), false)]);
    assert!(p.drain_events().is_empty());
}

/// Create (spec §10, G4 create): the envelope, `g0/`, the row; no `.tmp-*` or journal left; names checked and unique by
/// `name_key`; at most 32 directories.
#[test]
fn create_names_and_limit() {
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    let a = p.create("Work").unwrap();
    assert!(!a.protected);
    let dir = root.join("p").join(&a.id);
    assert_eq!(
        std::fs::read_to_string(dir.join("profile.envelope")).unwrap(),
        unprotected(&a.id, "Work")
    );
    assert!(dir.join("g0").is_dir());
    let left: Vec<_> = std::fs::read_dir(root.join("p"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(left.is_empty(), "{left:?}");
    assert!(!dir.join("build.lock").exists());
    assert_eq!(code(p.create("")), "ProfileNameInvalid");
    assert_eq!(code(p.create("a\u{202e}b")), "ProfileNameInvalid");
    assert_eq!(code(p.create("WORK")), "ProfileNameTaken");
    assert_eq!(code(p.create("Ｗork")), "ProfileNameTaken");
    for i in 2..32 {
        p.create(&format!("p{i}")).unwrap();
    }
    assert_eq!(code(p.create("one too many")), "ProfileLimit");
    assert_eq!(p.list().unwrap().len(), 32);
    // `Debug` shows neither the id nor the name
    let d = format!("{a:?}");
    assert!(!d.contains(&a.id) && !d.contains("Work"), "{d}");
}

/// Start (spec §10): a `.tmp-*` with a free `build.lock` and a free tombstone are removed (the tombstone's keychain items
/// too); a held one of each kept; a create's journal finished (row added) or dropped; a UUID directory without an envelope
/// reported, never removed; an open profile's lock untouched.
#[test]
fn start_cleans_up() {
    let root = tmp();
    let kc = Arc::new(Keychain::default());
    let mut c = cfg(&root);
    c.keychain = Some(kc.clone());
    let p = Profiles::new(c).unwrap();
    let open = p.open(&by_name(&p, "default").id, None).unwrap();
    let pd = root.join("p");
    let lock = |f: &Path| {
        let f = std::fs::File::create(f).unwrap();
        f.lock().unwrap();
        f
    };
    for d in [".tmp-free", ".tmp-held"] {
        std::fs::create_dir_all(pd.join(d)).unwrap();
    }
    // review A-16: start removes a build directory only when its `build.lock` exists and is free
    std::fs::write(pd.join(".tmp-free/build.lock"), b"").unwrap();
    let _held = lock(&pd.join(".tmp-held/build.lock"));
    let (t_free, t_held) = (new_id(), new_id());
    for t in [&t_free, &t_held] {
        std::fs::create_dir_all(pd.join(format!("{t}.deleted"))).unwrap();
    }
    let _held2 = lock(&pd.join(format!("{t_held}.deleted/instance.lock")));
    kc.put(&format!("scaas.profile.{t_free}.head"), b"x")
        .unwrap();
    // a journal whose directory is in place, without its row
    let j = new_id();
    plant(&root, &j, &unprotected(&j, "journaled"));
    std::fs::write(
        pd.join(".journal"),
        format!(r#"{{"op":"create","id":"{j}"}}"#),
    )
    .unwrap();
    let damaged = new_id();
    std::fs::create_dir_all(pd.join(&damaged)).unwrap();

    let q = Profiles::new({
        let mut c = cfg(&root);
        c.keychain = Some(kc.clone());
        c
    })
    .unwrap();
    assert!(!pd.join(".tmp-free").exists() && pd.join(".tmp-held").exists());
    assert!(!pd.join(format!("{t_free}.deleted")).exists());
    assert!(pd.join(format!("{t_held}.deleted")).exists());
    assert_eq!(
        kc.get(&format!("scaas.profile.{t_free}.head")).unwrap(),
        None
    );
    assert!(!pd.join(".journal").exists());
    assert_eq!(
        names(&q),
        [
            ("default".to_string(), false),
            ("journaled".to_string(), false)
        ]
    );
    assert!(pd.join(&damaged).is_dir());
    assert_eq!(q.drain_events(), [ProfileEvent::ProfileDamaged]);
    // the open profile kept its lock
    assert_eq!(code(q.open(&open.info().id, None)), "ProfileInUse");
    // a journal whose directory never came: dropped, nothing added
    std::fs::write(
        pd.join(".journal"),
        format!(r#"{{"op":"create","id":"{}"}}"#, new_id()),
    )
    .unwrap();
    let r = Profiles::new(cfg(&root)).unwrap();
    assert!(!pd.join(".journal").exists());
    assert_eq!(r.list().unwrap().len(), 2);
}

/// Lock (spec §10, G11): after it the store refuses (`ProfileLocked`) and the instance lock is free; control: the store works
/// while open, and two profiles open side by side.
#[test]
fn lock_closes_the_store() {
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    let b = p.create("b").unwrap();
    let a = p.open(&by_name(&p, "default").id, None).unwrap();
    let ob = p.open(&b.id, None).unwrap();
    let core = a.core().clone();
    core.put_if(SDK, "settings", None, br#"{"rev":1}"#).unwrap();
    assert_eq!(core.get(SDK, "settings").unwrap().unwrap().1, 1);
    assert_eq!(code(p.open(&a.info().id, None)), "ProfileInUse");
    a.lock();
    assert_eq!(code(core.get(SDK, "settings")), "ProfileLocked");
    assert_eq!(
        code(core.put_if(SDK, "settings", Some(1), br#"{"rev":2}"#)),
        "ProfileLocked"
    );
    assert_eq!(code(core.delete(SDK, "settings")), "ProfileLocked");
    drop(ob);
    let again = p.open(&a.info().id, None).unwrap();
    assert_eq!(again.core().get(SDK, "settings").unwrap().unwrap().1, 1);
    // `last` is the last visible profile opened
    let ix: Value =
        serde_json::from_slice(&std::fs::read(root.join("profiles.json")).unwrap()).unwrap();
    assert_eq!(ix["last"], a.info().id.as_str());
    // unknown ids
    assert_eq!(code(p.open(&new_id(), None)), "ProfileUnknown");
    assert_eq!(code(p.open("../p", None)), "ProfileUnknown");
}

/// G3: a sealed item in an unprotected profile is `ProfileFormat`; control: its plain `settings` round-trips. An unprotected
/// profile has no Matrix store key (`ProfilePassphraseRequired`).
#[test]
fn g3_unprotected_refuses_sealed() {
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    let o = p.open(&by_name(&p, "default").id, None).unwrap();
    o.core()
        .put_if(SDK, "settings", None, br#"{"rev":1}"#)
        .unwrap();
    assert!(o.core().get(SDK, "settings").unwrap().is_some());
    let g0 = o.core().dir().join("g0/settings");
    std::fs::write(&g0, br#"{"rev":2,"sealed":"AAAA"}"#).unwrap();
    assert_eq!(code(o.core().get(SDK, "settings")), "ProfileFormat");
    assert_eq!(code(o.matrix_store()), "ProfilePassphraseRequired");
}

/// G10: two envelopes with one visible `name_key` are both listed, with `ProfileIndexMismatch` at each read.
#[test]
fn g10_duplicate_names_both_listed() {
    let root = tmp();
    drop(Profiles::new(cfg(&root)).unwrap());
    let (x, y) = (new_id(), new_id());
    plant(&root, &x, &unprotected(&x, "Alice"));
    plant(&root, &y, &unprotected(&y, "alice"));
    std::fs::remove_file(root.join("profiles.json")).unwrap();
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(
        names(&p),
        [
            ("Alice".to_string(), false),
            ("alice".to_string(), false),
            ("default".to_string(), false)
        ]
    );
    // reported at each read of the index while both are there (review G-10): the start's and the list's
    assert_eq!(
        p.drain_events(),
        [
            ProfileEvent::ProfileIndexMismatch,
            ProfileEvent::ProfileIndexMismatch
        ]
    );
}

/// G12 paths (spec §5 "Modes"): a missing root is made `0700`; an existing `0755` root holding `p/` is tightened; a `0755`
/// foreign directory is `ProfileRootUnsafe` and left as it was; a symlinked root is refused (control: its target opens).
#[cfg(unix)]
#[test]
fn g12_root_modes_and_symlink() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let set =
        |p: &Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    let made = tmp();
    drop(Profiles::new(cfg(&made)).unwrap());
    assert_eq!(mode(&made), 0o700);
    set(&made, 0o755);
    drop(Profiles::new(cfg(&made)).unwrap());
    assert_eq!(mode(&made), 0o700);
    let foreign = tmp();
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(foreign.join("notes.txt"), b"x").unwrap();
    set(&foreign, 0o755);
    assert_eq!(code(Profiles::new(cfg(&foreign))), "ProfileRootUnsafe");
    assert_eq!(mode(&foreign), 0o755);
    assert_eq!(std::fs::read_dir(&foreign).unwrap().count(), 1);
    let link = tmp();
    std::os::unix::fs::symlink(&made, &link).unwrap();
    assert_eq!(code(Profiles::new(cfg(&link))), "ProfileRootUnsafe");
    assert_eq!(code(Profiles::new(cfg(&made))), "ok");
}

/// An envelope's fields but its label, which every envelope write re-seals at the new rev (owner 2026-11-28, review F-2).
fn resealed(env: &str) -> Value {
    let mut v: Value = serde_json::from_str(env).unwrap();
    v.as_object_mut().unwrap().remove("label").unwrap();
    v
}

/// The vector envelope files (envelope.json `files`, `name_hint`): the protected visible one opens with its passphrase
/// (label "Alice"), a wrong passphrase is `ProfileOpen`; the hidden one is not opened by id (`ProfileOpen`, no KDF run); a
/// changed hint opens with `ProfileIndexMismatch` and is rewritten from the label, after which it opens with no event.
#[cfg(feature = "test-hooks")]
#[test]
fn envelope_files_open() {
    use scaas_ua::wallet::ProfileKeys;
    let _k = kdf_lock();
    let v = rows("envelope.json");
    let file = |i: usize| v["files"][i]["file"].as_str().unwrap().to_string();
    let id_of = |f: &str| {
        serde_json::from_str::<Value>(f).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let root = tmp();
    let (vis, hid) = (file(0), file(1));
    plant(&root, &id_of(&vis), &vis);
    plant(&root, &id_of(&hid), &hid);
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(names(&p), [("Alice".to_string(), true)]);
    assert_eq!(
        code(p.open(&id_of(&vis), Some(b"wrong horse"))),
        "ProfileOpen"
    );
    assert_eq!(code(p.open(&id_of(&vis), None)), "Argument");
    let o = p.open(&id_of(&vis), Some(PASS.as_bytes())).unwrap();
    assert_eq!(
        (o.info().name.as_str(), o.info().protected),
        ("Alice", true)
    );
    assert!(p.drain_events().is_empty());
    let runs = ProfileKeys::kdf_runs();
    let nfd = v["pass"][2]["passphrase"].as_str().unwrap();
    assert_eq!(
        code(p.open(&id_of(&hid), Some(nfd.as_bytes()))),
        "ProfileOpen"
    );
    assert_eq!(ProfileKeys::kdf_runs(), runs);
    // a hint planted on the hidden profile, with a row: refused, the hint removed, the row dropped
    let planted = hid.replace(r#""gen":2,"#, r#""gen":2,"name":"Planted","#);
    std::fs::write(
        root.join("p").join(id_of(&hid)).join("profile.envelope"),
        &planted,
    )
    .unwrap();
    std::fs::remove_file(root.join("profiles.json")).unwrap();
    assert_eq!(
        names(&p),
        [("Alice".to_string(), true), ("Planted".to_string(), true)]
    );
    assert_eq!(
        code(p.open(&id_of(&hid), Some(nfd.as_bytes()))),
        "ProfileOpen"
    );
    let env =
        std::fs::read_to_string(root.join("p").join(id_of(&hid)).join("profile.envelope")).unwrap();
    assert_eq!(
        resealed(&env),
        resealed(&hid.replace(r#""rev":5"#, r#""rev":6"#))
    );
    assert_eq!(names(&p), [("Alice".to_string(), true)]);
    drop(o);

    let root = tmp();
    let changed = v["name_hint"][0]["file"].as_str().unwrap();
    let id = id_of(changed);
    plant(&root, &id, changed);
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(names(&p), [("Mallory".to_string(), true)]);
    let o = p.open(&id, Some(PASS.as_bytes())).unwrap();
    assert_eq!(o.info().name, "Alice");
    assert_eq!(p.drain_events(), [ProfileEvent::ProfileIndexMismatch]);
    let env = std::fs::read_to_string(root.join("p").join(&id).join("profile.envelope")).unwrap();
    assert_eq!(
        resealed(&env),
        resealed(&file(0).replace(r#""rev":3"#, r#""rev":4"#))
    );
    assert_eq!(names(&p), [("Alice".to_string(), true)]);
    o.lock();
    drop(p.open(&id, Some(PASS.as_bytes())).unwrap());
    assert!(p.drain_events().is_empty());
}

/// G3: the state flipped to `unprotected` (its generation 0) is refused; a plain item in a protected profile is
/// `VaultFormat`; with the keychain marker an unprotected envelope is `ProfileFormat` and a missing anchor `ProfileRollback`;
/// the marker is written at a protected open. Controls: the untouched profile opens; the anchor put back opens.
#[cfg(feature = "test-hooks")]
#[test]
fn g3_state_flipped_and_marker() {
    let _k = kdf_lock();
    let v = rows("envelope.json");
    let vis = v["files"][0]["file"].as_str().unwrap();
    let id = "01a21ce0-6e7b-7e63-9b1d-f667cc7d8daa";
    let root = tmp();
    plant(&root, id, vis);
    let kc = Arc::new(Keychain::default());
    let mut c = cfg(&root);
    c.keychain = Some(kc.clone());
    let p = Profiles::new(c).unwrap();
    let flipped = vis.replace(
        r#""state":"protected","rev":3,"gen":1"#,
        r#""state":"unprotected","rev":3,"gen":0"#,
    );
    std::fs::write(root.join("p").join(id).join("profile.envelope"), &flipped).unwrap();
    assert_eq!(code(p.open(id, Some(PASS.as_bytes()))), "ProfileFormat");
    std::fs::write(root.join("p").join(id).join("profile.envelope"), vis).unwrap();
    let o = p.open(id, Some(PASS.as_bytes())).unwrap();
    let marker = format!("scaas.profile.{id}.protected");
    assert!(kc.get(&marker).unwrap().is_some());
    let plain = o
        .core()
        .dir()
        .join("g1")
        .join(o.keys().unwrap().item_file("sdk", "settings").unwrap());
    o.lock();
    // a missing anchor beside the marker; control: put back, it opens
    let head = format!("scaas.profile.{id}.head");
    let saved = kc.get(&head).unwrap().unwrap();
    kc.delete(&head).unwrap();
    assert_eq!(code(p.open(id, Some(PASS.as_bytes()))), "ProfileRollback");
    kc.put(&head, &saved).unwrap();
    let o = p.open(id, Some(PASS.as_bytes())).unwrap();
    o.lock();
    std::fs::write(&plain, br#"{"rev":1}"#).unwrap();
    let o = p.open(id, Some(PASS.as_bytes())).unwrap();
    assert_eq!(code(o.core().get(SDK, "settings")), "VaultFormat");
    o.lock();
    // an unprotected envelope beside the marker; control: without the marker it opens
    let u = p.create("plain").unwrap();
    kc.put(&format!("scaas.profile.{}.protected", u.id), b"1")
        .unwrap();
    assert_eq!(code(p.open(&u.id, None)), "ProfileFormat");
    kc.delete(&format!("scaas.profile.{}.protected", u.id))
        .unwrap();
    assert_eq!(code(p.open(&u.id, None)), "ok");
}

/// G8: KDF parameters outside the general bounds are `ProfileFormat`, above this device's maximum `ProfileKdfTooLarge`, both
/// before any Argon2id run; a forced allocation failure is `ProfileKdfOutOfMemory`. Control: the in-bounds profile opens,
/// one run.
#[cfg(feature = "test-hooks")]
#[test]
fn g8_bounds_before_any_kdf() {
    use scaas_ua::wallet::ProfileKeys;
    let _k = kdf_lock();
    let vis = rows("envelope.json")["files"][0]["file"]
        .as_str()
        .unwrap()
        .to_string();
    let id = "01a21ce0-6e7b-7e63-9b1d-f667cc7d8daa";
    let root = tmp();
    plant(&root, id, &vis);
    let mut c = cfg(&root);
    c.kdf_max_kib = 65_536;
    let p = Profiles::new(c).unwrap();
    let env = root.join("p").join(id).join("profile.envelope");
    for (m_t, want) in [
        (r#""m":65535,"t":3"#, "ProfileFormat"),
        (r#""m":65536,"t":11"#, "ProfileFormat"),
        (r#""m":131072,"t":3"#, "ProfileKdfTooLarge"),
    ] {
        std::fs::write(&env, vis.replace(r#""m":8192,"t":1"#, m_t)).unwrap();
        let runs = ProfileKeys::kdf_runs();
        assert_eq!(code(p.open(id, Some(PASS.as_bytes()))), want, "{m_t}");
        assert_eq!(ProfileKeys::kdf_runs(), runs, "{m_t}");
    }
    std::fs::write(&env, &vis).unwrap();
    ProfileKeys::force_kdf_oom(true);
    let r = p.open(id, Some(PASS.as_bytes()));
    ProfileKeys::force_kdf_oom(false);
    assert_eq!(code(r), "ProfileKdfOutOfMemory");
    let runs = ProfileKeys::kdf_runs();
    assert_eq!(code(p.open(id, Some(PASS.as_bytes()))), "ok");
    assert_eq!(ProfileKeys::kdf_runs(), runs + 1);
}

/// G8: no KDF runs under the root lock: a second instance's start completes while an open's Argon2id run is held. Control:
/// the held open then completes.
#[cfg(feature = "test-hooks")]
#[test]
fn g8_start_during_held_kdf() {
    use std::sync::mpsc::channel;
    use std::time::Duration;
    let _k = kdf_lock();
    let root = tmp();
    drop(Profiles::new(cfg(&root)).unwrap());
    let id = protected(&root, Some("held"), "held", false, PASS);
    let p = Arc::new(Profiles::new(cfg(&root)).unwrap());
    let (inside_tx, inside) = channel();
    let (release, release_rx) = channel::<()>();
    p.before_kdf(Box::new(move || {
        inside_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    }));
    let opener = {
        let (p, id) = (p.clone(), id.clone());
        std::thread::spawn(move || code(p.open(&id, Some(PASS.as_bytes()))))
    };
    inside.recv().unwrap();
    let (done_tx, done) = channel();
    let r2 = root.clone();
    std::thread::spawn(move || done_tx.send(code(Profiles::new(cfg(&r2)))).unwrap());
    let started = done.recv_timeout(Duration::from_secs(20));
    release.send(()).unwrap();
    assert_eq!(opener.join().unwrap(), "ok");
    assert_eq!(started, Ok("ok"), "a start waited on a held KDF");
}

/// G10: a deleted and a corrupt index are rebuilt (never a first run) and list every visible profile, protected ones
/// included, never a hidden one. Control: the intact index lists the same.
#[cfg(feature = "test-hooks")]
#[test]
fn g10_rebuild_lists_every_visible() {
    let _k = kdf_lock();
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    p.create("a").unwrap();
    protected(&root, Some("b"), "b", false, PASS);
    protected(&root, None, "h", true, PASS);
    let want = [
        ("a".to_string(), false),
        ("b".to_string(), true),
        ("default".to_string(), false),
    ];
    std::fs::remove_file(root.join("profiles.json")).unwrap();
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(names(&p), want);
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(names(&p), want);
    std::fs::write(
        root.join("profiles.json"),
        b"{\"format\":\"scaas.profiles\"",
    )
    .unwrap();
    let p = Profiles::new(cfg(&root)).unwrap();
    assert_eq!(names(&p), want);
    assert!(p.drain_events().is_empty());
}

/// The Matrix store key (CLI-UPR-29): a sealed item of the profile, made once; two profiles, two keys, two directories.
#[cfg(feature = "test-hooks")]
#[test]
fn matrix_store_key_per_profile() {
    let _k = kdf_lock();
    let root = tmp();
    drop(Profiles::new(cfg(&root)).unwrap());
    let (x, y) = (
        protected(&root, Some("x"), "x", false, PASS),
        protected(&root, Some("y"), "y", false, PASS),
    );
    let p = Profiles::new(cfg(&root)).unwrap();
    let (ox, oy) = (
        p.open(&x, Some(PASS.as_bytes())).unwrap(),
        p.open(&y, Some(PASS.as_bytes())).unwrap(),
    );
    let (mx, my) = (ox.matrix_store().unwrap(), oy.matrix_store().unwrap());
    assert_eq!((mx.key.len(), my.key.len()), (32, 32));
    assert_ne!(*mx.key, *my.key);
    assert_ne!(mx.dir, my.dir);
    assert!(mx.dir.is_dir() && mx.dir.starts_with(root.join("p").join(&x)));
    assert_eq!(*ox.matrix_store().unwrap().key, *mx.key);
    // the key is in no plain byte of the profile
    ox.lock();
    for e in std::fs::read_dir(root.join("p").join(&x).join("g1")).unwrap() {
        let b = std::fs::read(e.unwrap().path()).unwrap();
        assert!(!b.windows(32).any(|w| w == &mx.key[..]));
    }
    let ox = p.open(&x, Some(PASS.as_bytes())).unwrap();
    assert_eq!(*ox.matrix_store().unwrap().key, *mx.key);
}
