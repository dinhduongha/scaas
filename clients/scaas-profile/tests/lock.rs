// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md §9, §10; §17 "lock"), UP6: one instance per profile.
//! A second instance is a child process: this test binary run again on the test [`child`] (env `SCAAS_PROFILE_CHILD_*`),
//! which opens the profile and prints `CHILD <code>`, then, when asked, holds it until its stdin closes. Each negative test
//! with its positive control.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_profile::{uuid7, Error, Profiles, ProfilesConfig};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn tmp() -> PathBuf {
    use std::hash::{BuildHasher, RandomState};
    let r = RandomState::new().hash_one(0u8).to_le_bytes();
    let mut b = [0u8; 10];
    b[..8].copy_from_slice(&r);
    std::env::temp_dir().join(format!(
        "scaas-profile-lock-{}-{}",
        std::process::id(),
        uuid7(0, &b)
    ))
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

fn default_id(p: &Profiles) -> String {
    p.list().unwrap().into_iter().next().unwrap().id
}

/// The child's side (does nothing in a normal run).
#[test]
fn child() {
    let (Ok(root), Ok(id)) = (
        std::env::var("SCAAS_PROFILE_CHILD_ROOT"),
        std::env::var("SCAAS_PROFILE_CHILD_ID"),
    ) else {
        return;
    };
    let p = Profiles::new(cfg(Path::new(&root))).unwrap();
    let r = p.open(&id, None);
    println!("CHILD {}", r.as_ref().map_or_else(|e| e.code(), |_| "ok"));
    if std::env::var("SCAAS_PROFILE_CHILD_HOLD").is_ok() {
        let mut s = String::new();
        let _ = std::io::stdin().read_to_string(&mut s);
    }
    drop(r);
}

/// A child process opening `id` under `root`; its `CHILD` line.
#[allow(clippy::zombie_processes)] // returned to the caller, which waits on it
fn spawn(root: &Path, id: &str, hold: bool) -> (Child, String) {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["child", "--exact", "--nocapture", "--test-threads=1"])
        .env("SCAAS_PROFILE_CHILD_ROOT", root)
        .env("SCAAS_PROFILE_CHILD_ID", id)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    if hold {
        c.env("SCAAS_PROFILE_CHILD_HOLD", "1");
    }
    let mut child = c.spawn().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    while out.read_line(&mut line).unwrap() > 0 {
        // the harness may print `test child ... ` before it on the same line
        if let Some((_, l)) = line.trim_end().split_once("CHILD ") {
            // the rest drained, so the child's harness never writes to a closed pipe
            std::thread::spawn(move || std::io::copy(&mut out, &mut std::io::sink()));
            return (child, l.to_string());
        }
        line.clear();
    }
    panic!("no CHILD line");
}

/// A second open in another process is `ProfileInUse`; control: after the holder's lock, the other process opens it.
#[test]
fn second_open_in_another_process() {
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    let id = default_id(&p);
    let held = p.open(&id, None).unwrap();
    let (mut c, line) = spawn(&root, &id, false);
    c.wait().unwrap();
    assert_eq!(line, "ProfileInUse");
    held.lock();
    let (mut c, line) = spawn(&root, &id, false);
    c.wait().unwrap();
    assert_eq!(line, "ok");
}

/// A SIGKILLed holder leaves a lock the next open takes at once (control: while it lives, the open is `ProfileInUse`).
#[test]
fn sigkilled_holder() {
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    let id = default_id(&p);
    let (mut c, line) = spawn(&root, &id, true);
    assert_eq!(line, "ok");
    assert_eq!(code(p.open(&id, None)), "ProfileInUse");
    c.kill().unwrap();
    c.wait().unwrap();
    assert_eq!(code(p.open(&id, None)), "ok");
}

/// Start takes no live profile's lock: a start while a profile is open completes, and leaves every other profile free for
/// another instance. Control: two profiles open side by side.
#[test]
fn start_takes_no_live_lock() {
    let root = tmp();
    let p = Profiles::new(cfg(&root)).unwrap();
    let (a, b) = (default_id(&p), p.create("b").unwrap().id);
    let held = p.open(&a, None).unwrap();
    let started = Profiles::new(cfg(&root)).unwrap();
    let (mut c, line) = spawn(&root, &b, false);
    c.wait().unwrap();
    assert_eq!(line, "ok");
    let ob = Profiles::new(cfg(&root)).unwrap().open(&b, None).unwrap();
    assert_eq!(code(started.open(&a, None)), "ProfileInUse");
    drop((held, ob, started));
}
