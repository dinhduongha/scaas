// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CLI-MTX-02 to CLI-MTX-04 without a server: one client per profile directory (a second open refused, the directory free
//! again after `close`), the store key on no file of the directory, a wrong key and a missing session refused by name, and the
//! homeserver URL rule at the entry point. The session record is written into the encrypted store as the crate writes it
//! after a login; `restore` needs no network (the first request would).
use matrix_sdk::{SqliteStateStore, StateStore};
use scaas_matrix::{MatrixClient, MatrixError, Options, StoreKey};
use std::path::{Path, PathBuf};

const KEY: [u8; 32] = [0x5a; 32];

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "scaas-matrix-profile-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// A profile directory holding a session record as `login_password` writes it.
async fn seeded(name: &str) -> PathBuf {
    let d = dir(name);
    let s = SqliteStateStore::open_with_key(d.join("store"), Some(&KEY[..]))
        .await
        .unwrap();
    let rec = serde_json::json!({
        "homeserver": "http://127.0.0.1:9/",
        "session": {"user_id": "@alice:localhost", "device_id": "DEVICEA", "access_token": "token-not-a-secret"},
    });
    s.set_custom_value(
        b"scaas-matrix/session/v1",
        serde_json::to_vec(&rec).unwrap(),
    )
    .await
    .unwrap();
    drop(s);
    d
}

fn key() -> StoreKey {
    StoreKey::from_bytes(KEY)
}

fn err<T>(r: Result<T, MatrixError>) -> MatrixError {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

/// Every file under `d` that holds `needle`.
fn holders(d: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![d.to_path_buf()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if std::fs::read(&p)
                .unwrap_or_default()
                .windows(needle.len())
                .any(|w| w == needle)
            {
                out.push(p);
            }
        }
    }
    out
}

fn forms() -> Vec<Vec<u8>> {
    let hex: String = KEY.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        KEY.to_vec(),
        hex.into_bytes(),
        b"WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo".to_vec(),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn one_client_per_profile_directory() {
    let d = seeded("busy").await;
    let a = MatrixClient::restore(&d, key(), Options::default())
        .await
        .unwrap();
    assert_eq!(a.user_id().as_deref(), Some("@alice:localhost"));
    assert_eq!(
        err(MatrixClient::restore(&d, key(), Options::default()).await),
        MatrixError::MatrixProfileBusy
    );
    a.close().await;
    // the directory is free once close returns
    let b = MatrixClient::restore(&d, key(), Options::default())
        .await
        .unwrap();
    assert_eq!(b.device_id().as_deref(), Some("DEVICEA"));
    b.close().await;
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn store_key_on_no_file() {
    let d = seeded("key").await;
    let c = MatrixClient::restore(&d, key(), Options::default())
        .await
        .unwrap();
    c.set_public_receipts(false).await.unwrap();
    c.close().await;
    for f in forms() {
        assert_eq!(
            holders(&d, &f),
            Vec::<PathBuf>::new(),
            "{:?}",
            String::from_utf8_lossy(&f)
        );
    }
    // positive control: a planted copy in each form is found
    for f in forms() {
        std::fs::write(d.join("planted"), &f).unwrap();
        assert_eq!(holders(&d, &f), vec![d.join("planted")]);
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_key_and_missing_session_refused() {
    let d = seeded("wrong").await;
    let wrong = StoreKey::from_bytes([0x5b; 32]);
    assert_eq!(
        err(MatrixClient::restore(&d, wrong, Options::default()).await),
        MatrixError::MatrixStore
    );
    // the refused open left the directory free
    MatrixClient::restore(&d, key(), Options::default())
        .await
        .unwrap()
        .close()
        .await;
    std::fs::remove_dir_all(&d).unwrap();
    // a store without a session record
    let e = dir("empty");
    drop(
        SqliteStateStore::open_with_key(e.join("store"), Some(&KEY[..]))
            .await
            .unwrap(),
    );
    assert_eq!(
        err(MatrixClient::restore(&e, key(), Options::default()).await),
        MatrixError::MatrixSession
    );
    // no store at all
    let n = dir("none");
    assert_eq!(
        err(MatrixClient::restore(&n, key(), Options::default()).await),
        MatrixError::MatrixStore
    );
    for p in [e, n] {
        std::fs::remove_dir_all(&p).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_persist_with_private_defaults() {
    let d = seeded("settings").await;
    let c = MatrixClient::restore(&d, key(), Options::default())
        .await
        .unwrap();
    assert_eq!(c.settings(), scaas_matrix::Settings::default());
    assert!(!c.settings().public_receipts && !c.settings().typing);
    c.set_typing(true).await.unwrap();
    c.close().await;
    let c = MatrixClient::restore(&d, key(), Options::default())
        .await
        .unwrap();
    assert!(c.settings().typing && !c.settings().public_receipts);
    c.close().await;
    std::fs::remove_dir_all(&d).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn login_refuses_plain_http_off_loopback() {
    let d = dir("http");
    for hs in [
        "http://localhost:8008",
        "http://10.0.0.1:8008",
        "http://matrix.example",
    ] {
        let r = MatrixClient::login_password(
            &d,
            Some(key()),
            Options::default(),
            hs,
            "alice",
            "pw",
            "dev",
        )
        .await;
        assert_eq!(err(r), MatrixError::EndpointScheme, "{hs}");
    }
    // the control: a loopback URL passes the rule and fails only at the login itself (nothing listens on port 9)
    let r = MatrixClient::login_password(
        &d,
        Some(key()),
        Options::default(),
        "http://127.0.0.1:9",
        "alice",
        "pw",
        "dev",
    )
    .await;
    assert_eq!(err(r), MatrixError::MatrixLogin);
    let _ = std::fs::remove_dir_all(&d);
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
