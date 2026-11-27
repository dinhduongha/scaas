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

use scaas_profile::settings::{ChainSettings, Endpoint, EndpointList};
use scaas_profile::{
    keychain_name, uuid7, Envelope, Error, ImportSource, KdfParams, OpenProfile, ProfileEvent,
    ProfileKeychain, ProfilePart, ProfileSettings, Profiles, ProfilesConfig,
};
use scaas_ua::wallet::ProfileKeys;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

const PASS: &[u8] = b"correct horse battery staple";
const PASS2: &[u8] = b"another passphrase, longer";
const XPASS: &[u8] = b"export passphrase, typed twice";
const TEST: KdfParams = KdfParams { m_kib: 8192, t: 1 };
const SDK: ProfilePart = ProfilePart::Sdk;

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

/// The envelope of the profile directory `dir` with `f` applied, written back in its canonical form.
fn edit_envelope(dir: &Path, f: impl FnOnce(&mut Envelope)) {
    let id = dir.file_name().unwrap().to_str().unwrap();
    let mut e = Envelope::parse(&std::fs::read(dir.join("profile.envelope")).unwrap(), id).unwrap();
    f(&mut e);
    std::fs::write(dir.join("profile.envelope"), e.json().unwrap()).unwrap();
}

fn index_text(root: &Path) -> String {
    std::fs::read_to_string(root.join("profiles.json")).unwrap_or_default()
}

/// G-2 / A-12: an open hidden profile keeps its sealed label's hidden flag (`info().hidden`); a name planted into its
/// envelope meanwhile is not taken for "visible": a rename writes no row and removes the planted hint, an export says
/// hidden, a passphrase change keeps it hidden (the prompt finds it under the new passphrase). Control: a visible profile
/// is not hidden and its rename writes its row.
#[test]
fn g2_hidden_flag_from_the_label() {
    let _k = kdf_lock();
    let root = tmp();
    let p = Profiles::new(cfg(&root, None)).unwrap();
    let o = p.create_hidden(b"Hid", PASS, Some(TEST)).unwrap();
    assert!(o.info().hidden);
    let dir = o.core().dir().to_path_buf();
    edit_envelope(&dir, |e| e.name = Some("Planted".into()));
    p.rename(&o, b"Hid2", Some(PASS)).unwrap();
    assert!(!index_text(&root).contains("Hid2"), "no row for a hidden profile");
    let env = std::fs::read_to_string(dir.join("profile.envelope")).unwrap();
    assert!(!env.contains(r#""name""#), "the planted hint removed");
    edit_envelope(&dir, |e| e.name = Some("Planted".into()));
    let target = root.with_extension("export");
    o.export(b"Hid2", PASS, XPASS, Some(TEST), &target).unwrap();
    let r = p
        .import_preview(ImportSource::Path(&target), XPASS)
        .unwrap();
    assert!(r.hidden(), "exported as hidden");
    o.change_passphrase(PASS, PASS2, None).unwrap();
    o.lock();
    assert!(p.open_hidden(b"Hid2", PASS2).unwrap().info().hidden);
    let id = p.list().unwrap()[0].id.clone();
    let v = p.open(&id, None).unwrap();
    assert!(!v.info().hidden, "control");
    p.rename(&v, b"Vis", None).unwrap();
    assert!(index_text(&root).contains("Vis"), "control");
}

/// A-8: a visible protected profile whose hint was stripped (its rev raised, so the anchor follows) is refused by id (spec
/// §6), opens through the hidden prompt, and there has its hint and row rewritten from its label with
/// `ProfileIndexMismatch`: it is listed and opens by id again. Control: it opens by id before.
#[test]
fn a8_stripped_hint_rewritten_from_the_label() {
    let _k = kdf_lock();
    let root = tmp();
    let (p, o, id, dir) = protected(&root, None);
    o.lock();
    p.open(&id, Some(PASS)).unwrap().lock();
    edit_envelope(&dir, |e| {
        e.name = None;
        e.rev += 1;
    });
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileOpen");
    p.drain_events();
    let h = p.open_hidden(b"default", PASS).unwrap();
    assert!(!h.info().hidden);
    assert!(p.drain_events().contains(&ProfileEvent::ProfileIndexMismatch));
    assert_eq!(p.list().unwrap().len(), 1, "listed again");
    h.lock();
    p.open(&id, Some(PASS)).unwrap();
}

/// F-1: a passphrase that is not a valid OpaqueString (empty, a control character) still costs max(candidates, 4) runs,
/// with no hidden profile and with one. Control: a well-formed wrong passphrase costs the same.
#[test]
fn f1_invalid_passphrase_costs_every_run() {
    let _k = kdf_lock();
    let p = Profiles::new(cfg(&tmp(), None)).unwrap();
    for hidden in [false, true] {
        if hidden {
            p.create_hidden(b"Hid", PASS, Some(TEST)).unwrap().lock();
        }
        for pass in [&b""[..], b"tab\there passphrase", b"well formed but wrong"] {
            let before = ProfileKeys::kdf_runs();
            assert_eq!(code(p.open_hidden(b"Alice", pass)), "ProfileOpen");
            assert_eq!(ProfileKeys::kdf_runs() - before, 4, "{pass:?}");
        }
    }
}

/// F-5: `hide()`'s wrap check and duplicate search run before the store write lock: with the lock held elsewhere it makes
/// its KDF runs, then fails `ProfileBusy`. Control: the lock released, it hides.
#[test]
fn f5_search_before_the_store_write_lock() {
    let _k = kdf_lock();
    let (p, o, ..) = protected(&tmp(), None);
    o.core().set_write_wait(Duration::from_millis(50));
    let w = o.core().write_lock().unwrap();
    let before = ProfileKeys::kdf_runs();
    assert_eq!(code(p.hide(&o, PASS)), "ProfileBusy");
    assert!(ProfileKeys::kdf_runs() - before >= 5, "the wrap check and the search ran");
    drop(w);
    p.hide(&o, PASS).unwrap();
}

fn item(rev: u64, body: &str) -> Vec<u8> {
    format!(r#"{{"rev":{rev},"body":"{body}"}}"#).into_bytes()
}

/// `f` grown to 1 TiB, sparse (no block written): a read of it whole fails its allocation.
fn sparse(f: &Path) {
    let h = std::fs::OpenOptions::new().write(true).open(f).unwrap();
    h.set_len(1 << 40).unwrap();
}

/// G-4 / A-10: files are read bounded before any bound is checked: a sparse 1 TiB item is `VaultFormat` and a sparse 1 TiB
/// `profile.head` a rollback (an anchor is at most 2,560 bytes); read whole, each fails its allocation (`VaultIo`). Control:
/// the item reads before.
#[test]
fn g4_files_read_bounded() {
    let _k = kdf_lock();
    let (p, o, id, dir) = protected(&tmp(), None);
    o.core().put_if(SDK, "a", None, &item(1, "a")).unwrap();
    assert!(o.core().get(SDK, "a").unwrap().is_some(), "control");
    sparse(&dir.join("g1").join(o.keys().unwrap().item_file("sdk", "a").unwrap()));
    assert_eq!(code(o.core().get(SDK, "a")), "VaultFormat");
    o.lock();
    sparse(&dir.join("profile.head"));
    assert_eq!(code(p.open(&id, Some(PASS))), "ProfileRollback");
}

/// G-9: revisions above 2^53 are refused at parse: the index's (not an index: rebuilt, its rev small again) and an
/// envelope's (`ProfileFormat`). Control: an envelope at 2^53 opens.
#[test]
fn g9_revs_above_2_pow_53_refused() {
    let root = tmp();
    let p = Profiles::new(cfg(&root, None)).unwrap();
    let id = p.list().unwrap()[0].id.clone();
    let ix = index_text(&root);
    let rev = serde_json::from_str::<serde_json::Value>(&ix).unwrap()["rev"].clone();
    let planted = ix.replacen(&format!(r#""rev":{rev},"#), r#""rev":9007199254740993,"#, 1);
    std::fs::write(root.join("profiles.json"), planted).unwrap();
    assert_eq!(p.list().unwrap().len(), 1);
    assert!(!index_text(&root).contains("9007199254740993"), "rebuilt");
    let dir = root.join("p").join(&id);
    edit_envelope(&dir, |e| e.rev = 1 << 53);
    p.open(&id, None).unwrap().lock();
    edit_envelope(&dir, |e| e.rev = (1 << 53) + 1);
    assert_eq!(code(p.open(&id, None)), "ProfileFormat");
}

/// A-4 / G-7, G-6: settings refuse at parse (`VaultFormat`) a cap that is not 1 to 78 ASCII digits, global or per chain,
/// and an endpoint URL that is not plain `http(s)://` ASCII, or that holds a `\` or userinfo. Control: digits at the bound
/// and plain URLs with a port, a path, a query and an `@` in the path parse.
#[test]
fn a4_g6_settings_strings_bounded() {
    let parse = |s: &str| code(ProfileSettings::parse(s.as_bytes()));
    let cap = |v: &str| format!(r#"{{"caps":{{"max_cost":"{v}"}}}}"#);
    let chain_cap = |v: &str| format!(r#"{{"chains":{{"c":{{"caps":{{"max_fee_per_gas":"{v}"}}}}}}}}"#);
    let url = |u: &str| {
        format!(r#"{{"chains":{{"c":{{"endpoints":[{{"list":"rpc","label":"l","url":"{u}"}}]}}}}}}"#)
    };
    for ok in ["1", "0", &"9".repeat(78)] {
        assert_eq!(parse(&cap(ok)), "ok", "{ok}");
        assert_eq!(parse(&chain_cap(ok)), "ok", "{ok}");
    }
    for ok in [
        "https://rpc.example:8545/v1?x=1",
        "http://127.0.0.1:8545",
        "https://rpc.example/p@th",
    ] {
        assert_eq!(parse(&url(ok)), "ok", "{ok}");
    }
    for bad in ["", "12a", "-1", " 1", &"9".repeat(79), "\u{202e}1"] {
        assert_eq!(parse(&cap(bad)), "VaultFormat", "{bad:?}");
        assert_eq!(parse(&chain_cap(bad)), "VaultFormat", "{bad:?}");
    }
    for bad in [
        r"https://evil.example\\@good.example/",
        "https://user:pw@rpc.example/",
        "https://user@rpc.example",
        "ftp://rpc.example/",
        "javascript:alert(1)",
        "https://rpc example/",
        "https://rpc.\u{0435}xample/",
        "https://",
    ] {
        assert_eq!(parse(&url(bad)), "VaultFormat", "{bad:?}");
    }
}

/// E-4 / A-14: `set_settings` refuses (`Argument`) settings its own `parse` refuses (here above 1 MiB) before writing, and
/// `set_passphrase` refuses `keep_settings` that do not parse; the stored settings stay readable. Control: small settings
/// write and read back.
#[test]
fn e4_settings_written_only_when_readable() {
    let _k = kdf_lock();
    let p = Profiles::new(cfg(&tmp(), None)).unwrap();
    let o = p.open(&p.list().unwrap()[0].id, None).unwrap();
    let s = ProfileSettings {
        idle_lock_s: Some(60),
        ..ProfileSettings::default()
    };
    o.set_settings(&s, None).unwrap();
    let mut big = s.clone();
    big.chains.insert(
        "c".into(),
        ChainSettings {
            endpoints: vec![Endpoint {
                list: EndpointList::Rpc,
                label: "a".repeat(1 << 20),
                url: "https://rpc.example".into(),
                first: false,
            }],
            ..ChainSettings::default()
        },
    );
    assert_eq!(code(o.set_settings(&big, None)), "Argument");
    assert_eq!(o.settings().unwrap().idle_lock_s, Some(60));
    let keep = br#"{"rev":1,"unknown":true}"#;
    assert_eq!(code(o.set_passphrase(PASS, Some(TEST), Some(keep))), "Argument");
    assert!(!o.info().protected);
}

/// A-17: an item without a JSON `rev` is refused by `import` before any KDF run, as `ProfileImportOpen` (the preview's
/// check waits on the vector rows, whose fillers carry none). Control: the same file with a `rev` imports.
#[test]
fn a17_item_without_rev_refused_before_the_kdf() {
    let _k = kdf_lock();
    let p = Profiles::new(cfg(&tmp(), None)).unwrap();
    let file = |ks: &[u8]| {
        let label = br#"{"name":"Bob","hidden":false}"#;
        let pl = Profiles::test_payload(label, b"{}", &[("keystore", ks)]).unwrap();
        p.test_export(&pl, XPASS, TEST, &[7; 16], &[9; 7]).unwrap()
    };
    let r = p
        .import_preview(ImportSource::Bytes(&file(b"no json rev")), XPASS)
        .unwrap();
    let before = ProfileKeys::kdf_runs();
    assert_eq!(code(p.import(&r, &[], PASS, None, Some(TEST))), "ProfileImportOpen");
    assert_eq!(ProfileKeys::kdf_runs(), before, "before any KDF");
    let r = p
        .import_preview(ImportSource::Bytes(&file(br#"{"rev":1}"#)), XPASS)
        .unwrap();
    p.import(&r, &[], PASS, None, Some(TEST)).unwrap();
}

/// A-2: a re-seal whose steps after the commit's rename fail (the keychain refuses every put: the anchor's copy, the
/// `protected` marker) reports success, and the open store is on the new generation: a write lands there and reads back
/// after a reopen. Control: unprotected before.
#[test]
fn a2_reseal_committed_reports_success() {
    let _k = kdf_lock();
    let (root, kc) = (tmp(), Arc::new(Keychain::default()));
    let p = Profiles::new(cfg(&root, Some(&kc))).unwrap();
    let id = p.list().unwrap()[0].id.clone();
    let o = p.open(&id, None).unwrap();
    assert!(!o.info().protected, "control");
    kc.fail_put.store(true, SeqCst);
    let r = o.set_passphrase(PASS, Some(TEST), None);
    kc.fail_put.store(false, SeqCst);
    r.unwrap();
    assert!(o.info().protected);
    o.core().put_if(SDK, "a", None, &item(1, "a")).unwrap();
    o.lock();
    let o = p.open(&id, Some(PASS)).unwrap();
    assert!(o.core().get(SDK, "a").unwrap().is_some());
}

/// A-3: a create whose steps after its rename fail (the index cannot be written: the root is read-only) reports success;
/// its journal stays, so the next start adds its row. Control: the row is missing until then.
#[cfg(unix)]
#[test]
fn a3_create_committed_reports_success() {
    use std::os::unix::fs::PermissionsExt;
    let root = tmp();
    let p = Profiles::new(cfg(&root, None)).unwrap();
    let mode = |m| std::fs::set_permissions(&root, std::fs::Permissions::from_mode(m)).unwrap();
    mode(0o500);
    let r = p.create("New");
    mode(0o700);
    let info = r.unwrap();
    assert!(root.join("p").join(&info.id).is_dir());
    assert!(!index_text(&root).contains("New"), "control: no row yet");
    drop(p);
    let p = Profiles::new(cfg(&root, None)).unwrap();
    assert!(p.list().unwrap().iter().any(|i| i.name == "New"));
}
