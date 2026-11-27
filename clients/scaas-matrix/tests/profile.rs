// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CLI-MTX-02 to CLI-MTX-04 without a server: one client per profile directory (a second open refused, the directory free
//! again after `close`, a transport handle dead after it), the store key and the sealed records on no file of the directory,
//! a wrong key and a missing session refused by name, a login over an existing store refused and `wipe` under the lock, and
//! the homeserver URL rule at the entry point. The session record is sealed into the store as `login_password` seals it
//! (`testing::seed_session`, feature `testing`); `restore` needs no network.
use scaas_matrix::{testing, Login, MatrixClient, MatrixError, Options, StoreKey};
use std::path::{Path, PathBuf};

const KEY: [u8; 32] = [0x5a; 32];
const TOKEN: &str = "syt_token-not-a-secret-but-findable";
const USER: &str = "@alice-profile-test:localhost";
const HS: &str = "http://127.0.0.1:9/";
const SHOWN: Options = Options { hidden: false };

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "scaas-matrix-profile-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A profile directory holding a session record as `login_password` seals it.
async fn seeded(name: &str) -> PathBuf {
    let d = dir(name);
    std::fs::create_dir_all(&d).unwrap();
    testing::seed_session(&d, &mut KEY.clone(), HS, USER, "DEVICEA", TOKEN)
        .await
        .unwrap();
    d
}

fn key() -> StoreKey {
    StoreKey::from_bytes(&mut KEY.clone())
}

fn err<T>(r: Result<T, MatrixError>) -> MatrixError {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// Every file under `d` that holds `needle` (a file that cannot be read fails the test, one removed meanwhile is skipped).
fn holders(d: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![d.to_path_buf()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                // a journal file SQLite removed meanwhile holds nothing any more; any other read failure fails the test
                let b = match std::fs::read(&p) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => panic!("{}: {e}", p.display()),
                };
                if b.windows(needle.len()).any(|w| w == needle) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// The forms nothing on disk may hold: the key (bytes, hex, base64), the token, the Matrix id, the homeserver, a room id.
fn secrets() -> Vec<Vec<u8>> {
    let hex: String = KEY.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        KEY.to_vec(),
        hex.into_bytes(),
        b"WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_vec(),
        TOKEN.as_bytes().to_vec(),
        USER.as_bytes().to_vec(),
        b"127.0.0.1:9".to_vec(),
        b"held-room-id".to_vec(),
    ]
}

fn clean(d: &Path) {
    for f in secrets() {
        assert_eq!(
            holders(d, &f),
            Vec::<PathBuf>::new(),
            "{:?}",
            String::from_utf8_lossy(&f)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_client_per_profile_directory() {
    let d = seeded("busy").await;
    let a = MatrixClient::restore(&d, key(), SHOWN).await.unwrap();
    assert_eq!(a.user_id().as_deref(), Some(USER));
    assert_eq!(
        err(MatrixClient::restore(&d, key(), SHOWN).await),
        MatrixError::MatrixProfileBusy
    );
    assert_eq!(MatrixClient::wipe(&d), Err(MatrixError::MatrixProfileBusy));
    let t = a.transport();
    a.close().await;
    // a transport handle kept past close is dead, and holds neither the client nor the lock
    assert!(t.create_room().await.is_err());
    assert_eq!(t.user_id(), "");
    assert_eq!(a.user_id(), None);
    assert_eq!(a.next_update().await, None);
    let b = MatrixClient::restore(&d, key(), SHOWN).await.unwrap();
    assert_eq!(b.device_id().as_deref(), Some("DEVICEA"));
    b.close().await;
    drop(t);
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn no_secret_on_any_file() {
    let d = seeded("key").await;
    let c = MatrixClient::restore(&d, key(), SHOWN).await.unwrap();
    c.set_public_receipts(false).await.unwrap();
    c.transport()
        .hold_invite("!held-room-id:localhost", true)
        .await
        .unwrap();
    // while the client is open (journal files included), then once it is closed
    clean(&d);
    c.close().await;
    clean(&d);
    // positive control: a planted copy in each form is found
    for f in secrets() {
        std::fs::write(d.join("planted"), &f).unwrap();
        assert_eq!(holders(&d, &f), vec![d.join("planted")]);
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_key_and_missing_session_refused() {
    let d = seeded("wrong").await;
    let wrong = StoreKey::from_bytes(&mut [0x5b; 32]);
    assert_eq!(
        err(MatrixClient::restore(&d, wrong, SHOWN).await),
        MatrixError::MatrixStore
    );
    // the refused open left the directory free
    MatrixClient::restore(&d, key(), SHOWN)
        .await
        .unwrap()
        .close()
        .await;
    std::fs::remove_dir_all(&d).unwrap();
    // no store at all
    let n = dir("none");
    assert_eq!(
        err(MatrixClient::restore(&n, key(), SHOWN).await),
        MatrixError::MatrixStore
    );
    let _ = std::fs::remove_dir_all(&n);
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_persist_with_private_defaults() {
    let d = seeded("settings").await;
    let c = MatrixClient::restore(&d, key(), SHOWN).await.unwrap();
    assert_eq!(c.settings(), scaas_matrix::Settings::default());
    assert!(!c.settings().public_receipts && !c.settings().typing);
    c.set_typing(true).await.unwrap();
    c.close().await;
    let c = MatrixClient::restore(&d, key(), SHOWN).await.unwrap();
    assert!(c.settings().typing && !c.settings().public_receipts);
    c.close().await;
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn marks_persist_and_refuse_a_non_room() {
    let d = seeded("marks").await;
    let c = MatrixClient::restore(&d, key(), SHOWN).await.unwrap();
    let t = c.transport();
    t.hold_invite("!pending:localhost", true).await.unwrap();
    assert!(t.hold_invite("not a room id", true).await.is_err());
    t.bound("!bound:localhost").await.unwrap();
    c.close().await;
    let c = MatrixClient::restore(&d, key(), SHOWN).await.unwrap();
    for r in ["!pending:localhost", "!bound:localhost"] {
        assert_eq!(c.kind(r), scaas_matrix::RoomKind::PqChat, "{r}");
    }
    assert_eq!(c.kind("!other:localhost"), scaas_matrix::RoomKind::Matrix);
    c.close().await;
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_login_over_a_store_is_refused_and_wipe_clears_it() {
    let d = seeded("over").await;
    let l = Login {
        homeserver: "http://127.0.0.1:9",
        user: "alice",
        password: "pw",
        device_name: "dev",
    };
    assert_eq!(
        err(MatrixClient::login_password(&d, Some(key()), SHOWN, l).await),
        MatrixError::MatrixSession
    );
    MatrixClient::wipe(&d).unwrap();
    assert!(!d.join("store").exists());
    assert_eq!(
        err(MatrixClient::restore(&d, key(), SHOWN).await),
        MatrixError::MatrixStore
    );
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn every_sync_says_presence_offline() {
    let s = format!(
        "{:?}",
        scaas_matrix::sync_settings(std::time::Duration::from_secs(30))
    );
    assert!(s.contains(r#"set_presence: "offline""#), "{s}");
    // the control: matrix-sdk's own default sets no presence, so the field is the crate's
    let d = format!("{:?}", matrix_sdk::config::SyncSettings::new());
    assert!(!d.contains("set_presence"), "{d}");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_refuses_plain_http_off_loopback() {
    let d = dir("http");
    let login = |hs| Login {
        homeserver: hs,
        user: "alice",
        password: "pw",
        device_name: "dev",
    };
    for hs in [
        "http://localhost:8008",
        "http://10.0.0.1:8008",
        "http://matrix.example",
    ] {
        let r = MatrixClient::login_password(&d, Some(key()), SHOWN, login(hs)).await;
        assert_eq!(err(r), MatrixError::EndpointScheme, "{hs}");
    }
    // the control: a loopback URL passes the rule and fails only at the login itself (nothing listens on port 9), leaving
    // no store behind
    let r = MatrixClient::login_password(&d, Some(key()), SHOWN, login("http://127.0.0.1:9")).await;
    assert_eq!(err(r), MatrixError::MatrixLogin);
    assert!(!d.join("store").exists());
    let _ = std::fs::remove_dir_all(&d);
}
