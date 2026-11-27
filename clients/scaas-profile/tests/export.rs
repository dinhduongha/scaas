// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md),
//! UP10: export and import of a whole profile (§10.1; §17 G9): the rows of smartcontracts/vectors/profile/export.json (each
//! file reproduced byte for byte from its salt and nonce prefix, each refusal row `ProfileImportOpen` with its local reason and
//! nothing written), the export's refusals and payload, the preview, the import's filter, temporary directory and commit.
//! Argon2id at the test set (feature `test-hooks`); without it only the rows that need no test set run.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::{uuid7, Error, ImportSource, Profiles, ProfilesConfig};
use serde_json::Value;
use std::path::{Path, PathBuf};

const STEP: usize = 1_048_576 + 16;

fn rnd(n: u8) -> [u8; 10] {
    use std::hash::{BuildHasher, RandomState};
    let s = RandomState::new();
    let mut r = [0u8; 10];
    r[..8].copy_from_slice(&s.hash_one(n).to_le_bytes());
    r[8..].copy_from_slice(&s.hash_one(n ^ 0xff).to_le_bytes()[..2]);
    r
}

fn tmp() -> PathBuf {
    std::env::temp_dir().join(format!(
        "scaas-profile-up10-{}-{}",
        std::process::id(),
        uuid7(0, &rnd(4))
    ))
}

fn fresh() -> (Profiles, PathBuf) {
    let root = tmp();
    (
        Profiles::new(ProfilesConfig::new(root.clone())).unwrap(),
        root,
    )
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "ok")
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn rows() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/profile/export.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// Every file under `root` and its bytes, sorted: what a call that must write nothing leaves unchanged.
fn snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                todo.push(e.path());
            } else {
                out.push((e.path(), std::fs::read(e.path()).unwrap_or_default()));
            }
        }
    }
    out.sort();
    out
}

/// The refusal row `r`'s file: `file`, or `base` with `edit`, or `file_len` zeros led by `prefix_bytes`.
fn refusal_file(r: &Value, base: &dyn Fn(&str) -> Vec<u8>) -> Vec<u8> {
    if let Some(f) = r["file"].as_str() {
        return hex(f);
    }
    if let Some(n) = r["file_len"].as_u64() {
        let mut f = vec![0u8; n as usize];
        let p = hex(r["prefix_bytes"].as_str().unwrap());
        f[..p.len()].copy_from_slice(&p);
        return f;
    }
    let mut f = base(r["base"].as_str().unwrap());
    let e = &r["edit"];
    if e.is_null() {
        return f;
    }
    let hl = u32::from_be_bytes(f[8..12].try_into().unwrap()) as usize;
    let at = |i: u64| 12 + hl + i as usize * STEP;
    let chunk = |f: &[u8], i: u64| f[at(i)..(at(i) + STEP).min(f.len())].to_vec();
    match e["op"].as_str().unwrap() {
        "truncate" => f.truncate(f.len() - e["n"].as_u64().unwrap() as usize),
        "replace" => {
            let o = e["offset"].as_u64().unwrap() as usize;
            let b = hex(e["hex"].as_str().unwrap());
            f[o..o + b.len()].copy_from_slice(&b);
        }
        "drop_chunk" => {
            let i = e["i"].as_u64().unwrap();
            let c = chunk(&f, i).len();
            f.drain(at(i)..at(i) + c);
        }
        "swap_chunks" => {
            let (i, j) = (e["i"].as_u64().unwrap(), e["j"].as_u64().unwrap());
            let (ci, cj) = (chunk(&f, i), chunk(&f, j));
            let mut g = f[..at(0)].to_vec();
            for k in 0..((f.len() - at(0)).div_ceil(STEP) as u64) {
                g.extend(
                    if k == i {
                        &cj
                    } else if k == j {
                        &ci
                    } else {
                        &f[at(k)..(at(k) + STEP).min(f.len())]
                    }
                    .iter(),
                );
            }
            f = g;
        }
        "append_chunk" => {
            let c = chunk(&f, e["i"].as_u64().unwrap());
            f.extend(c);
        }
        op => panic!("edit {op}"),
    }
    f
}

/// Every refusal row of export.json, read as an import: `ProfileImportOpen` with its local reason, and nothing written under
/// the root. Without `test-hooks` only the rows that say so (the test set refused); with it the others, whose bases are
/// reproduced from their rows. Then the size control (the length bound itself passes the length check: `tag`).
#[test]
fn every_refusal_row() {
    let v = rows();
    let (p, root) = fresh();
    let files = v["files"].as_array().unwrap();
    let base = |name: &str| -> Vec<u8> {
        let f = files.iter().find(|f| f["case"] == name).unwrap();
        match f["file"].as_str() {
            Some(h) => hex(h),
            None => file_of(&p, f),
        }
    };
    let before = snapshot(&root);
    let mut n = 0;
    for r in v["refusals"].as_array().unwrap() {
        if r["test_hooks"].as_bool().unwrap() != cfg!(feature = "test-hooks") {
            continue;
        }
        let f = refusal_file(r, &base);
        let pass = r["passphrase"].as_str().unwrap().as_bytes();
        let got = code(p.import_preview(ImportSource::Bytes(&f), pass).map(drop));
        let case = r["case"].as_str().unwrap();
        assert_eq!(got, r["code"].as_str().unwrap(), "{case}");
        assert_eq!(p.last_import_refusal(), r["reason"].as_str(), "{case}");
        n += 1;
    }
    assert!(n >= 1, "rows read");
    if cfg!(feature = "test-hooks") {
        assert_eq!(n, 26, "every test-set row");
        let c = &v["size_control"];
        let f = refusal_file(c, &base);
        let pass = c["passphrase"].as_str().unwrap().as_bytes();
        assert_eq!(
            code(p.import_preview(ImportSource::Bytes(&f), pass).map(drop)),
            "ProfileImportOpen"
        );
        assert_eq!(
            p.last_import_refusal(),
            c["reason"].as_str(),
            "size_control"
        );
    }
    assert!(snapshot(&root) == before, "nothing written");
}

#[cfg(feature = "test-hooks")]
/// rnd(name, n): keccak256("scaas/profile/vectors/<name>/<i>") concatenated, the first n bytes.
fn filler(name: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + 32);
    let mut i = 0;
    while out.len() < n {
        out.extend(scaas_ua::keccak256(
            format!("scaas/profile/vectors/{name}/{i}").as_bytes(),
        ));
        i += 1;
    }
    out.truncate(n);
    out
}

#[cfg(feature = "test-hooks")]
fn row_items(f: &Value) -> Vec<(String, Vec<u8>)> {
    f["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            let n = i[0].as_str().unwrap().to_string();
            let b = match i[1].as_str() {
                Some(h) => hex(h),
                None => filler(
                    i[1]["filler"].as_str().unwrap(),
                    i[1]["len"].as_u64().unwrap() as usize,
                ),
            };
            (n, b)
        })
        .collect()
}

#[cfg(feature = "test-hooks")]
fn file_of(p: &Profiles, f: &Value) -> Vec<u8> {
    let items = row_items(f);
    let refs: Vec<(&str, &[u8])> = items.iter().map(|(n, b)| (n.as_str(), &b[..])).collect();
    let pl = Profiles::test_payload(
        f["label"].as_str().unwrap().as_bytes(),
        &hex(f["settings"].as_str().unwrap()),
        &refs,
    )
    .unwrap();
    let k = &f["kdf"];
    use base64::Engine;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(k["salt"].as_str().unwrap())
        .unwrap();
    p.test_export(
        &pl,
        f["passphrase"].as_str().unwrap().as_bytes(),
        scaas_profile::KdfParams {
            m_kib: k["m"].as_u64().unwrap() as u32,
            t: k["t"].as_u64().unwrap() as u32,
        },
        &salt.try_into().unwrap(),
        &hex(f["nonce_prefix"].as_str().unwrap()).try_into().unwrap(),
    )
    .unwrap()
}

#[cfg(not(feature = "test-hooks"))]
fn file_of(_: &Profiles, f: &Value) -> Vec<u8> {
    panic!("{}: a test-set file", f["case"])
}

/// Every file row reproduced byte for byte from its payload, salt and nonce prefix (the small file whole, the others by
/// length, chunk count, first and last 64 bytes), and opened by a preview to the same label, settings and items: payloads of
/// exactly 1 MiB, 1 MiB + 1 and 2 MiB round-trip.
#[cfg(feature = "test-hooks")]
#[test]
fn every_file_row_reproduced_and_opened() {
    let v = rows();
    let (p, _) = fresh();
    for f in v["files"].as_array().unwrap() {
        let case = f["case"].as_str().unwrap();
        let file = file_of(&p, f);
        if let Some(h) = f["file"].as_str() {
            assert!(file == hex(h), "{case}: the whole file");
        }
        assert_eq!(file.len() as u64, f["file_len"].as_u64().unwrap(), "{case}");
        let hl = f["header_len"].as_u64().unwrap() as usize;
        assert_eq!(
            (file.len() - 12 - hl).div_ceil(STEP) as u64,
            f["chunks"].as_u64().unwrap(),
            "{case}"
        );
        assert!(
            file[..64] == hex(f["first64"].as_str().unwrap())[..],
            "{case}"
        );
        assert!(
            file[file.len() - 64..] == hex(f["last64"].as_str().unwrap())[..],
            "{case}"
        );
        let pass = f["passphrase"].as_str().unwrap().as_bytes();
        let pl = p.test_open(&file, pass).unwrap();
        assert_eq!(
            pl.len() as u64,
            f["payload_len"].as_u64().unwrap(),
            "{case}"
        );
        if let Some(h) = f["payload"].as_str() {
            assert!(pl == hex(h), "{case}: the payload");
        }
        let r = p.import_preview(ImportSource::Bytes(&file), pass).unwrap();
        let label: Value = serde_json::from_str(f["label"].as_str().unwrap()).unwrap();
        assert_eq!(r.name(), label["name"].as_str().unwrap(), "{case}");
        assert_eq!(r.hidden(), label["hidden"].as_bool().unwrap(), "{case}");
        for (n, b) in row_items(f) {
            assert!(r.item(&n) == Some(&b[..]), "{case}: {n}");
        }
    }
}

/// The export refusal row: a payload of 64 MiB + 1 is `ProfileExportTooLarge`, before any KDF.
#[cfg(feature = "test-hooks")]
#[test]
fn export_refusal_row() {
    let v = rows();
    let (p, _) = fresh();
    for r in v["export_refusals"].as_array().unwrap() {
        use base64::Engine;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(r["kdf"]["salt"].as_str().unwrap())
            .unwrap();
        let pl = vec![0u8; r["payload_len"].as_u64().unwrap() as usize];
        let got = p.test_export(
            &pl,
            b"export passphrase, typed twice",
            scaas_profile::KdfParams { m_kib: 8192, t: 1 },
            &salt.try_into().unwrap(),
            &hex(r["nonce_prefix"].as_str().unwrap()).try_into().unwrap(),
        );
        assert_eq!(code(got), r["error"].as_str().unwrap());
    }
}

#[cfg(feature = "test-hooks")]
mod hooks {
    use super::*;
    use scaas_profile::settings::{
        ChainSettings, CredentialKind, CredentialRef, Endpoint, EndpointList,
    };
    use scaas_profile::{KdfParams, OpenProfile, ProfilePart, ProfileSettings, Step};

    const PASS: &[u8] = b"correct horse battery staple";
    const NEW: &[u8] = b"a new passphrase, typed twice";
    const XPASS: &[u8] = b"export passphrase, typed twice";
    const TEST: KdfParams = KdfParams { m_kib: 8192, t: 1 };
    const SALT: [u8; 16] = [7; 16];
    const PREFIX: [u8; 7] = [9; 7];
    const KEYSTORE: &[u8] = br#"{"rev":3,"seeds":["the keystore marker"]}"#;
    const STATE: &[u8] = br#"{"rev":2,"ops":[{"op":"o","state":"signed"}]}"#;

    /// A root whose "default" is renamed "Alice", protected at the test set, holding `keystore`, `keystore.prev`, `sdk.state`,
    /// a PqChat item, the Matrix key and settings with a credential reference.
    fn alice() -> (Profiles, OpenProfile, PathBuf) {
        let (p, root) = fresh();
        let id = p.list().unwrap()[0].id.clone();
        let o = p.open(&id, None).unwrap();
        p.rename(&o, b"Alice", None).unwrap();
        o.set_passphrase(PASS, Some(TEST), None).unwrap();
        let c = o.core();
        c.put_if(ProfilePart::Sdk, "keystore", None, KEYSTORE)
            .unwrap();
        c.put_if(
            ProfilePart::Sdk,
            "keystore.prev",
            None,
            br#"{"rev":1,"prev":"the prev marker"}"#,
        )
        .unwrap();
        c.put_if(ProfilePart::Sdk, "sdk.state", None, STATE)
            .unwrap();
        c.put_if(
            ProfilePart::PqChat,
            "session",
            None,
            br#"{"rev":1,"pqchat":"the pqchat marker"}"#,
        )
        .unwrap();
        o.matrix_store().unwrap();
        o.set_settings(&settings(), Some(PASS)).unwrap();
        (p, o, root)
    }

    fn settings() -> ProfileSettings {
        let mut s = ProfileSettings::default();
        s.chains.insert(
            "scaas-testnet".into(),
            ChainSettings {
                endpoints: vec![Endpoint {
                    list: EndpointList::Rpc,
                    label: "mine".into(),
                    url: "https://rpc.example".into(),
                    first: true,
                }],
                strict_majority: true,
                ..ChainSettings::default()
            },
        );
        s.caps.max_gas = Some(1000);
        s.default_chain = Some("scaas-testnet".into());
        s.idle_lock_s = Some(300);
        s.clipboard = true;
        s.credentials.push(CredentialRef {
            chain_profile: "scaas-testnet".into(),
            list: EndpointList::Rpc,
            label: "mine".into(),
            kind: CredentialKind::Bearer,
            file: None,
            env: Some("THE_CREDENTIAL_MARKER".into()),
        });
        s
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    /// G9 export: protected only, the name typed again, the export passphrase's rule, the profile passphrase; an existing
    /// file or a symlink at the target refused. The payload holds the label, the settings without credential references,
    /// `keystore` and `sdk.state`: never the id, `keystore.prev`, a PqChat item, the Matrix key.
    #[test]
    fn export_refusals_and_payload() {
        let (p, o, root) = alice();
        let d = tmp();
        std::fs::create_dir_all(&d).unwrap();
        let t = d.join("alice.scaasx");
        let x = |name: &[u8], pp: &[u8], xp: &[u8], at: &Path| {
            code(o.export(name, pp, xp, Some(TEST), at))
        };
        assert_eq!(x(b"Bob", PASS, XPASS, &t), "ConfirmationMissing");
        assert_eq!(x(b"alice", PASS, b"1234567", &t), "ProfilePassphraseWeak");
        assert_eq!(x(b"alice", b"a wrong passphrase", XPASS, &t), "ProfileOpen");
        assert!(!t.exists(), "nothing written");
        std::fs::write(d.join("taken"), b"x").unwrap();
        assert_eq!(x(b"alice", PASS, XPASS, &d.join("taken")), "Argument");
        assert_eq!(std::fs::read(d.join("taken")).unwrap(), b"x");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(d.join("elsewhere"), d.join("link")).unwrap();
            assert_eq!(x(b"alice", PASS, XPASS, &d.join("link")), "Argument");
            assert!(!d.join("elsewhere").exists());
        }
        assert_eq!(x(b"ALICE", PASS, XPASS, &t), "ok");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&t).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let file = std::fs::read(&t).unwrap();
        let pl = p.test_open(&file, XPASS).unwrap();
        let id = o.info().id;
        for (what, m) in [
            ("the id", id.as_bytes()),
            ("keystore.prev", &b"the prev marker"[..]),
            ("a PqChat item", b"the pqchat marker"),
            ("a credential reference", b"THE_CREDENTIAL_MARKER"),
            ("the Matrix key's item", b"matrix"),
        ] {
            assert!(!contains(&pl, m), "{what} in the payload");
        }
        assert!(contains(&pl, b"the keystore marker") && contains(&pl, b"strict_majority"));
        let r = p.import_preview(ImportSource::Path(&t), XPASS).unwrap();
        assert!(r.name() == "Alice" && !r.hidden());
        assert!(r.item("keystore") == Some(KEYSTORE));
        // the operation in flight marked `imported` by the preview (spec §10.1; review E-3: the crate marks it)
        let st: Value = serde_json::from_slice(r.item("sdk.state").unwrap()).unwrap();
        assert_eq!((st["rev"].as_u64(), &st["ops"][0]["state"]), (Some(2), &Value::from("imported")));
        // an unprotected profile is not exported
        let u = p.create("plain").unwrap();
        let u = p.open(&u.id, None).unwrap();
        assert_eq!(
            code(u.export(b"plain", PASS, XPASS, Some(TEST), &d.join("u"))),
            "ProfilePassphraseRequired"
        );
        drop(root);
    }

    /// G9: the preview writes nothing (a refused one neither), and lists every setting, kept ones included; the import
    /// without a confirm keeps only what cannot weaken, with every confirm still no credential reference (a crafted file
    /// carrying one); positive control: an unchanged file imports with a new id, opens under the new passphrase with the same
    /// items, and its `keystore` the same bytes.
    #[test]
    fn preview_then_import() {
        let (p, o, root) = alice();
        let mut crafted = settings();
        crafted.rev = 4;
        let pl = Profiles::test_payload(
            br#"{"name":"Alice","hidden":false}"#,
            &crafted.json().unwrap(),
            &[("keystore", KEYSTORE), ("sdk.state", STATE)],
        )
        .unwrap();
        let file = p.test_export(&pl, XPASS, TEST, &SALT, &PREFIX).unwrap();
        let before = snapshot(&root);
        assert_eq!(
            code(p.import_preview(ImportSource::Bytes(&file), PASS).map(drop)),
            "ProfileImportOpen"
        );
        let r = p.import_preview(ImportSource::Bytes(&file), XPASS).unwrap();
        assert!(snapshot(&root) == before, "the preview wrote nothing");
        let listed = r.settings();
        assert_eq!(
            listed.len(),
            7,
            "caps, default, strict, endpoint, first, idle, clipboard"
        );
        assert_eq!(listed.iter().filter(|i| i.kept).count(), 3);
        assert_eq!(
            code(p.import(&r, &[], NEW, None, Some(TEST)).map(drop)),
            "ProfileNameTaken"
        );
        let a = p
            .import(&r, &[], NEW, Some(b"Alice 2"), Some(TEST))
            .unwrap();
        assert!(a.id != o.info().id && a.protected && a.name == "Alice 2");
        let all: Vec<u32> = listed.iter().map(|i| i.id).collect();
        let b = p
            .import(&r, &all, NEW, Some(b"Alice 3"), Some(TEST))
            .unwrap();
        let open = |id: &str| p.open(id, Some(NEW)).unwrap();
        let s = open(&a.id).settings().unwrap();
        let c = &s.chains["scaas-testnet"];
        assert!(c.endpoints.is_empty() && c.strict_majority);
        assert!(
            s.caps.max_gas == Some(1000) && s.default_chain.as_deref() == Some("scaas-testnet")
        );
        assert!(s.idle_lock_s.is_none() && !s.clipboard && s.credentials.is_empty());
        let ob = open(&b.id);
        let s = ob.settings().unwrap();
        let c = &s.chains["scaas-testnet"];
        assert!(c.endpoints.len() == 1 && c.endpoints[0].first);
        assert!(s.idle_lock_s == Some(300) && s.clipboard);
        assert!(s.credentials.is_empty(), "never a credential reference");
        let k = ob
            .core()
            .get(ProfilePart::Sdk, "keystore")
            .unwrap()
            .unwrap();
        assert!(&k.0[..] == KEYSTORE && k.1 == 3);
        assert_eq!(code(p.open(&b.id, Some(PASS)).map(drop)), "ProfileInUse");
        drop(ob);
        assert_eq!(code(p.open(&b.id, Some(PASS)).map(drop)), "ProfileOpen");
    }

    /// G9 hidden: a hidden file imports hidden (no row), opens by its name and the new passphrase; the same (name,
    /// passphrase) again is `ProfileNameTaken`.
    #[test]
    fn hidden_import() {
        let (p, root) = fresh();
        let pl = Profiles::test_payload(
            br#"{"name":"Secret","hidden":true}"#,
            b"{}",
            &[("keystore", KEYSTORE)],
        )
        .unwrap();
        let file = p.test_export(&pl, XPASS, TEST, &SALT, &PREFIX).unwrap();
        let r = p.import_preview(ImportSource::Bytes(&file), XPASS).unwrap();
        let index = std::fs::read(root.join("profiles.json")).unwrap();
        p.import(&r, &[], NEW, None, Some(TEST)).unwrap();
        assert_eq!(
            std::fs::read(root.join("profiles.json")).unwrap(),
            index,
            "no row"
        );
        let o = p.open_hidden(b"secret", NEW).unwrap();
        assert!(o
            .core()
            .get(ProfilePart::Sdk, "keystore")
            .unwrap()
            .is_some());
        drop(o);
        assert_eq!(
            code(p.import(&r, &[], NEW, None, Some(TEST)).map(drop)),
            "ProfileNameTaken"
        );
    }

    /// Verify, then parse: a file whose label is refused and whose last chunk is changed is refused at the tag, never at the
    /// label; unchanged, at the label (the positive control).
    #[test]
    fn verify_before_parse() {
        let (p, _) = fresh();
        let pl =
            Profiles::test_payload(b"not a label", b"{}", &[("keystore", &vec![b'k'; 1 << 20])])
                .unwrap();
        let mut file = p.test_export(&pl, XPASS, TEST, &SALT, &PREFIX).unwrap();
        assert_eq!(
            code(
                p.import_preview(ImportSource::Bytes(&file), XPASS)
                    .map(drop)
            ),
            "ProfileImportOpen"
        );
        assert_eq!(p.last_import_refusal(), Some("label"));
        let n = file.len();
        file[n - 1] ^= 1;
        assert_eq!(
            code(
                p.import_preview(ImportSource::Bytes(&file), XPASS)
                    .map(drop)
            ),
            "ProfileImportOpen"
        );
        assert_eq!(p.last_import_refusal(), Some("tag"));
    }

    fn tmp_dirs(root: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(root.join("p"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with(".tmp-")
            })
            .collect()
    }

    /// G9 / G4 import: the temporary directory holds only sealed items (a stop after it is built: no plaintext byte in any
    /// file, every generation file a 64-hex name in sealed form), and a later start removes it (its lock free); another
    /// instance's start while the import runs leaves it (its `build.lock` held), and the import commits.
    #[test]
    fn import_temporary_directory() {
        let root = tmp();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let mut c = ProfilesConfig::new(root.clone());
        let (r2, seen2) = (root.clone(), seen.clone());
        c.hook = Some(Box::new(move |s| {
            if s != Step::ImportBuilt {
                return false;
            }
            let dirs = tmp_dirs(&r2);
            let stop = seen2.lock().unwrap().is_none();
            if stop {
                *seen2.lock().unwrap() = Some(snapshot(&dirs[0]));
            } else {
                // another instance's start meanwhile
                drop(Profiles::new(ProfilesConfig::new(r2.clone())).unwrap());
                assert_eq!(tmp_dirs(&r2), dirs, "start left the import's directory");
            }
            stop
        }));
        let p = Profiles::new(c).unwrap();
        let pl = Profiles::test_payload(
            br#"{"name":"Bob","hidden":false}"#,
            b"{}",
            &[("keystore", KEYSTORE), ("sdk.state", STATE)],
        )
        .unwrap();
        let file = p.test_export(&pl, XPASS, TEST, &SALT, &PREFIX).unwrap();
        let r = p.import_preview(ImportSource::Bytes(&file), XPASS).unwrap();
        assert_eq!(
            code(p.import(&r, &[], NEW, None, Some(TEST)).map(drop)),
            "VaultIo"
        );
        let files = seen.lock().unwrap().take().unwrap();
        assert!(files.iter().any(|(f, _)| f.ends_with("profile.envelope")));
        for (f, b) in &files {
            for m in [&b"keystore marker"[..], b"\"ops\""] {
                assert!(!contains(b, m), "{f:?} holds a plaintext");
            }
            let name = f.file_name().unwrap().to_str().unwrap();
            if f.parent().unwrap().ends_with("g1") {
                assert!(name.len() == 64 && b.starts_with(b"{\"rev\":"), "{name}");
                assert!(contains(b, b",\"sealed\":\""), "{name}");
            }
        }
        assert_eq!(tmp_dirs(&root).len(), 1, "left as a crash leaves it");
        drop(Profiles::new(ProfilesConfig::new(root.clone())).unwrap());
        assert!(tmp_dirs(&root).is_empty(), "a later start removes it");
        *seen.lock().unwrap() = Some(Vec::new());
        let b = p.import(&r, &[], NEW, None, Some(TEST)).unwrap();
        assert!(tmp_dirs(&root).is_empty());
        let o = p.open(&b.id, Some(NEW)).unwrap();
        assert!(
            &o.core()
                .get(ProfilePart::Sdk, "keystore")
                .unwrap()
                .unwrap()
                .0[..]
                == KEYSTORE
        );
    }
}
