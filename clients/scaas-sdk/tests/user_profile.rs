// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! User profiles (spec docs/superpowers/specs/2026-11-27-user-profiles.md, plan docs/superpowers/plans/2026-11-27-user-profiles.md):
//! the SDK's side of the store `scaas-profile` (owner 2026-11-27; the store's own tests are clients/scaas-profile/tests/). UP5:
//! the `SecureStore` face and the codes. Profiles are built by hand: a generation directory and a `ProfileKeys` with a fresh
//! `DEK_p` (`create_dek`, no Argon2id).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use scaas_sdk::user_profile::{Core, CoreOpen, Error, Head, PartStore, ProfilePart};
use scaas_sdk::vault::{SecureStore, StoreError, StorePolicy};
use scaas_sdk::SdkError;
use scaas_ua::wallet::ProfileKeys;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const SDK: ProfilePart = ProfilePart::Sdk;

fn tmp() -> PathBuf {
    use std::hash::{BuildHasher, RandomState};
    let d = std::env::temp_dir().join(format!(
        "scaas-sdk-up-{}-{:x}",
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

fn open(dir: &Path, keys: &Arc<ProfileKeys>) -> Core {
    Core::open(CoreOpen {
        dir: dir.to_path_buf(),
        id: "01a21ce0-6e7b-7e63-9b1d-f667cc7d8daa".into(),
        gen: 1,
        keys: Some(keys.clone()),
        keychain: None,
        envelope: Head::of(1, b"profile.envelope at rev 1"),
        migration_pending: false,
    })
    .unwrap()
}

fn item(rev: u64, body: &str) -> Vec<u8> {
    format!(r#"{{"rev":{rev},"body":"{body}"}}"#).into_bytes()
}

fn file_of(dir: &Path, keys: &ProfileKeys, part: &str, name: &str) -> PathBuf {
    dir.join("g1").join(keys.item_file(part, name).unwrap())
}

/// The store's codes reach the SDK by name: each `scaas-profile` code is the `SdkError` of the same name (none collapsed).
#[test]
fn store_codes_are_the_sdks() {
    assert_eq!(Error::ALL.len(), 21);
    for e in Error::ALL {
        assert_eq!(SdkError::from(*e).code(), e.code());
    }
}

/// The `SecureStore` face: items round-trip under the face's revisions; `keystore.head` passes through unsealed to the profile
/// directory; `lock(name)` is the item's `.lock` file; the core's codes reach the store's.
#[tokio::test(flavor = "multi_thread")]
async fn secure_store_face() {
    let (d, k) = (tmp(), keys());
    let core = Arc::new(open(&d, &k));
    let s = PartStore::new(core.clone(), SDK).unwrap();
    let p = StorePolicy::default();
    s.put_if("keystore".into(), None, item(1, "k"), p)
        .await
        .unwrap();
    let got = s
        .get("keystore".into(), String::new())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((got.bytes, got.rev), (item(1, "k"), 1));
    assert_eq!(
        s.put_if("keystore".into(), None, item(1, "k"), p).await,
        Err(StoreError::Conflict)
    );
    let head = br#"{"rev":1,"sha256":"00112233445566778899aabbccddeeff"}"#.to_vec();
    s.put_if("keystore.head".into(), None, head.clone(), p)
        .await
        .unwrap();
    assert_eq!(std::fs::read(d.join("keystore.head")).unwrap(), head);
    assert_eq!(
        s.get("keystore.head".into(), String::new())
            .await
            .unwrap()
            .unwrap()
            .bytes,
        head
    );
    let held = s.lock("keystore".into()).await.unwrap();
    let lock = file_of(&d, &k, "sdk", "keystore").with_extension("lock");
    let other = std::fs::OpenOptions::new().write(true).open(&lock).unwrap();
    assert!(other.try_lock().is_err(), "held");
    drop(held);
    assert!(other.try_lock().is_ok(), "released");
    s.delete("keystore".into()).await.unwrap();
    assert!(s
        .get("keystore".into(), String::new())
        .await
        .unwrap()
        .is_none());
    // codes: a rollback and a busy writer through the face
    s.put_if("settings".into(), None, item(1, "a"), p)
        .await
        .unwrap();
    let f = file_of(&d, &k, "sdk", "settings");
    let old = std::fs::read(&f).unwrap();
    s.put_if("settings".into(), Some(1), item(2, "b"), p)
        .await
        .unwrap();
    std::fs::write(&f, old).unwrap();
    assert_eq!(
        s.get("settings".into(), String::new()).await,
        Err(StoreError::ProfileRollback)
    );
    core.set_write_wait(Duration::from_millis(50));
    let g = core.write_lock().unwrap();
    assert_eq!(
        s.put_if("sdk.state".into(), None, item(1, "s"), p).await,
        Err(StoreError::Unavailable)
    );
    drop(g);
}
