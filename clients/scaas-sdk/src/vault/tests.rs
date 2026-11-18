// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T2c: the writers' rules (spec §6.3) over a counting in-memory store and over `FileStore`; the parser's depth scan and
//! a property test.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use super::keystore::PARSED;
use super::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

fn rows() -> serde_json::Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/keystore/keystore.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

/// The "four seeds" row's entries.
fn entries() -> Vec<SeedEntry> {
    let v = rows();
    let four = v["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "four seeds")
        .unwrap();
    Keystore::parse(four["text"].as_str().unwrap().as_bytes())
        .unwrap()
        .seeds
}

fn entry(n: u32) -> SeedEntry {
    let mut e = entries()[0].clone();
    e.id = format!("{n:08x}-0000-4000-8000-000000000000");
    e.label = format!("Seed {n}");
    e
}

/// An in-memory store: the rev rule, a count of `put_if` calls, `conflicts` forced answers, a lock.
#[derive(Default)]
struct Mem {
    items: Mutex<HashMap<String, Vec<u8>>>,
    puts: AtomicUsize,
    conflicts: AtomicUsize,
    lock: Arc<tokio::sync::Mutex<()>>,
}

#[async_trait]
impl SecureStore for Mem {
    async fn get(&self, name: String, _: String) -> Result<Option<StoredItem>, StoreError> {
        Ok(self.items.lock().unwrap().get(&name).map(|b| StoredItem {
            rev: store::rev_of(b),
            bytes: b.clone(),
        }))
    }
    async fn put_if(
        &self,
        name: String,
        prev: Option<u64>,
        bytes: Vec<u8>,
        _: StorePolicy,
    ) -> Result<(), StoreError> {
        self.puts.fetch_add(1, Ordering::SeqCst);
        if name == KEYSTORE && self.conflicts.load(Ordering::SeqCst) > 0 {
            self.conflicts.fetch_sub(1, Ordering::SeqCst);
            return Err(StoreError::Conflict);
        }
        let mut items = self.items.lock().unwrap();
        if items.get(&name).map(|b| store::rev_of(b)) != prev {
            return Err(StoreError::Conflict);
        }
        items.insert(name, bytes);
        Ok(())
    }
    async fn delete(&self, name: String) -> Result<(), StoreError> {
        self.items.lock().unwrap().remove(&name);
        Ok(())
    }
    async fn lock(&self, _: String) -> Result<Arc<StoreLock>, StoreError> {
        Ok(StoreLock::new(Box::new(
            self.lock.clone().lock_owned().await,
        )))
    }
}

fn add(n: u32) -> impl FnMut(&mut Keystore) -> Result<(), SdkError> {
    move |ks| {
        ks.seeds.push(entry(n));
        Ok(())
    }
}

#[tokio::test]
async fn put_if_conflict() {
    let m = Arc::new(Mem::default());
    let f = KeystoreFile::new(m.clone());
    f.update(add(1)).await.unwrap();
    // the rev moved twice under the SDK: it reloads and reapplies, the third try lands
    m.conflicts.store(2, Ordering::SeqCst);
    let mut applied = 0;
    let ks = f
        .update(|ks| {
            applied += 1;
            ks.seeds.push(entry(2));
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!((applied, ks.rev, ks.seeds.len()), (3, 2, 2));
    // three in a row reach the caller, and nothing changed
    m.conflicts.store(3, Ordering::SeqCst);
    assert_eq!(f.update(add(3)).await.unwrap_err().code(), "StoreConflict");
    assert_eq!(f.load().await.unwrap().keystore.rev, 2);
}

#[tokio::test]
async fn keystore_prev_kept() {
    let m = Arc::new(Mem::default());
    let f = KeystoreFile::new(m.clone());
    f.update(add(1)).await.unwrap();
    assert!(
        m.items.lock().unwrap().get(PREV).is_none(),
        "nothing replaced yet"
    );
    for n in 2..5 {
        let before = m.items.lock().unwrap()[KEYSTORE].clone();
        f.update(add(n)).await.unwrap();
        assert_eq!(m.items.lock().unwrap()[PREV], before, "replace {n}");
    }
}

#[tokio::test]
async fn anchor_detects_rollback() {
    let m = Arc::new(Mem::default());
    let f = KeystoreFile::new(m.clone());
    f.update(add(1)).await.unwrap();
    let old = m.items.lock().unwrap()[KEYSTORE].clone();
    f.update(add(2)).await.unwrap();
    let l = f.load().await.unwrap();
    assert!(!l.rollback, "control: the current container");
    assert_eq!(l.keystore.seeds.len(), 2);
    // an older container put back behind the SDK: read, not fatal, flagged
    m.items.lock().unwrap().insert(KEYSTORE.into(), old.clone());
    let l = f.load().await.unwrap();
    assert!(l.rollback);
    assert_eq!(l.keystore.seeds.len(), 1);
    // another container at the anchor's rev: flagged too
    let mut other = Keystore::parse(&old).unwrap();
    other.rev = 2;
    other.seeds[0].label = "Other".into();
    m.items
        .lock()
        .unwrap()
        .insert(KEYSTORE.into(), other.serialize().unwrap().into_bytes());
    assert!(f.load().await.unwrap().rollback);
}

#[tokio::test]
async fn size_contract() {
    assert_eq!(anchor(999_999_999_999, b"x").unwrap().len(), 64);
    assert_eq!(
        anchor(1_000_000_000_000, b"x").unwrap_err().code(),
        "Argument"
    );
    let m = Arc::new(Mem::default());
    let mut ks = Keystore {
        rev: 1_000_000_000_000 - 1,
        seeds: vec![],
    };
    m.items
        .lock()
        .unwrap()
        .insert(KEYSTORE.into(), ks.serialize().unwrap().into_bytes());
    let f = KeystoreFile::new(m.clone());
    assert_eq!(f.update(add(1)).await.unwrap_err().code(), "Argument");
    assert_eq!(
        m.puts.load(Ordering::SeqCst),
        0,
        "refused before any put_if"
    );
    // control: one rev lower fits
    ks.rev -= 1;
    m.items
        .lock()
        .unwrap()
        .insert(KEYSTORE.into(), ks.serialize().unwrap().into_bytes());
    f.update(add(1)).await.unwrap();
    assert!(m.items.lock().unwrap()[HEAD].len() <= HEAD_MAX);
}

#[tokio::test]
async fn a_refusing_reader_never_writes() {
    let m = Arc::new(Mem::default());
    let f = KeystoreFile::new(m.clone());
    f.update(add(1)).await.unwrap();
    let puts = m.puts.load(Ordering::SeqCst);
    let good = m.items.lock().unwrap()[KEYSTORE].clone();
    let unknown = String::from_utf8(good.clone()).unwrap().replacen(
        "\"rev\":1,",
        "\"rev\":1,\"extra\":0,",
        1,
    );
    m.items
        .lock()
        .unwrap()
        .insert(KEYSTORE.into(), unknown.into_bytes());
    assert_eq!(f.update(add(2)).await.unwrap_err().code(), "VaultFormat");
    assert_eq!(f.load().await.unwrap_err().code(), "VaultFormat");
    assert_eq!(
        m.puts.load(Ordering::SeqCst),
        puts,
        "no put_if after a refusal"
    );
    // control: the container fixed, the write goes through
    m.items.lock().unwrap().insert(KEYSTORE.into(), good);
    f.update(add(2)).await.unwrap();
    assert!(m.puts.load(Ordering::SeqCst) > puts);
}

#[cfg(feature = "file-store")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sdks_one_directory() {
    let d = std::env::temp_dir().join(format!("scaas-sdk-two-{}-{:x}", std::process::id(), {
        use std::hash::{BuildHasher, RandomState};
        RandomState::new().hash_one(1u8)
    }));
    let (a, b) = (FileStore::new(&d).unwrap(), FileStore::new(&d).unwrap());
    let (fa, fb) = (
        Arc::new(KeystoreFile::new(a)),
        Arc::new(KeystoreFile::new(b)),
    );
    let mut tasks = vec![];
    for n in 0..8u32 {
        let f = if n % 2 == 0 { fa.clone() } else { fb.clone() };
        tasks.push(tokio::spawn(async move {
            f.update(add(n)).await.map(|ks| ks.rev)?;
            // a rename of this writer's seed, interleaved with the other's writes
            f.update(move |ks| {
                let s = ks
                    .seeds
                    .iter_mut()
                    .find(|s| s.id == entry(n).id)
                    .ok_or(SdkError::SeedUnknown)?;
                s.label = format!("Renamed {n}");
                Ok(())
            })
            .await
            .map(|ks| ks.rev)
        }));
    }
    let mut revs = vec![];
    for t in tasks {
        revs.push(t.await.unwrap().unwrap());
    }
    let l = fa.load().await.unwrap();
    assert_eq!(l.keystore.seeds.len(), 8, "every seed present");
    assert!(l
        .keystore
        .seeds
        .iter()
        .all(|s| s.label.starts_with("Renamed")));
    assert_eq!(l.keystore.rev, 16, "one rev per write");
    revs.sort();
    revs.dedup();
    assert_eq!(revs.len(), 8, "no two writes at one rev");
    assert!(!l.rollback);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn depth_is_scanned_before_parsing() {
    let before = PARSED.with(|n| n.get());
    let deep = format!("{}{}", "[".repeat(6), "]".repeat(6));
    assert_eq!(
        Keystore::parse(deep.as_bytes()).unwrap_err().code(),
        "VaultFormat"
    );
    let huge = "[".repeat(1 << 20);
    assert_eq!(
        Keystore::parse(huge.as_bytes()).unwrap_err().code(),
        "VaultFormat"
    );
    assert_eq!(
        PARSED.with(|n| n.get()),
        before,
        "neither reached serde_json"
    );
    // control: depth 5 reaches the parser (and is refused there for its shape)
    let five = format!("{}{}", "[".repeat(5), "]".repeat(5));
    assert_eq!(
        Keystore::parse(five.as_bytes()).unwrap_err().code(),
        "VaultFormat"
    );
    assert_eq!(PARSED.with(|n| n.get()), before + 1);
}

/// Random bytes and mutations of every valid row under the caps: a named refusal or a container, never a panic.
#[test]
fn parser_property() {
    let v = rows();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut n = 0;
    for r in v["valid"].as_array().unwrap() {
        let b = r["text"].as_str().unwrap().as_bytes().to_vec();
        for _ in 0..300 {
            let mut m = b.clone();
            let at = (next() as usize) % m.len();
            match next() % 4 {
                0 => m[at] = next() as u8,
                1 => m[at] = b'{',
                2 => {
                    m.remove(at);
                }
                _ => m.insert(at, b'"'),
            }
            match Keystore::parse(&m) {
                Ok(_) => {}
                Err(e) => assert!(
                    matches!(e.code(), "VaultFormat" | "VaultVersion"),
                    "{}",
                    e.code()
                ),
            }
            n += 1;
        }
    }
    for len in [0usize, 1, 7, 100, 4096] {
        let junk: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        assert!(Keystore::parse(&junk).is_err());
    }
    assert!(n >= 1500);
}

fn secret(b: &[u8]) -> Arc<scaas_ua::wallet::SecretBytes> {
    Arc::new(
        scaas_ua::wallet::SecretBytes::from_zeroizing(zeroize::Zeroizing::new(b.to_vec())).unwrap(),
    )
}

const PASS: &[u8] = "river-otter-7 ünï".as_bytes();
const REPO: &[u8] = b"bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

/// Owner 2026-11-18 (i): a passphrase unlock opens every vault of the seed at unlock (eager); the passphrase is not kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passphrase_unlock_opens_every_vault() {
    let s = crate::Sdk::open(crate::SdkConfig {
        profiles: vec![],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: crate::RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: crate::Limits::default(),
        clock: None,
    })
    .await
    .unwrap();
    let v = s.vault();
    let id = v
        .import_words(ImportWords {
            label: "Main".into(),
            words: secret(REPO),
            vault_passphrase: secret(PASS),
        })
        .await
        .unwrap()
        .id;
    let key = ImportKey {
        seed: id.clone(),
        network: "evm".into(),
        secret: secret(&[0x11; 32]),
        vault_passphrase: secret(PASS),
    };
    v.import_key(key).await.unwrap();
    v.lock(id.clone()).await;
    assert!(s.open_seed(&id).is_err(), "control: locked");
    v.unlock(id.clone(), Unlock::Passphrase(secret(PASS)))
        .await
        .unwrap();
    let w = s.open_seed(&id).unwrap();
    assert!(w.wallet.label_open("manifest"));
    assert!(
        w.wallet.label_open("native-import:evm:0"),
        "opened at unlock"
    );
    assert!(w
        .wallet
        .imported_key(scaas_ua::wallet::Network::Evm, 0)
        .is_ok());
}

/// A platform authenticator for the first-use tests: HMAC(handle, salt) as the platform secret.
struct Platform;

#[async_trait]
impl crate::platform::Authenticator for Platform {
    async fn create_passkey(
        &self,
        _: String,
        _: String,
        _: Vec<Vec<u8>>,
    ) -> Result<crate::platform::PasskeyCreated, crate::platform::AuthError> {
        Err(crate::platform::AuthError::Unavailable)
    }
    async fn get_assertion(
        &self,
        _: crate::platform::AssertionRequest,
        _: Arc<scaas_ua::wallet::SecretBytes>,
    ) -> Result<crate::platform::Assertion, crate::platform::AuthError> {
        Err(crate::platform::AuthError::Unavailable)
    }
    async fn platform_secret(
        &self,
        handle: String,
        salt: Vec<u8>,
        _: String,
        _: Option<crate::platform::KeyPolicy>,
        out: Arc<scaas_ua::wallet::SecretBytes>,
    ) -> Result<(), crate::platform::AuthError> {
        out.with_mut(|b| {
            b.copy_from_slice(&scaas_ua::wallet::hmac_sha256(handle.as_bytes(), &salt))
        });
        Ok(())
    }
    async fn p256_generate(
        &self,
        _: crate::platform::KeyPolicy,
    ) -> Result<crate::platform::SePublic, crate::platform::AuthError> {
        Err(crate::platform::AuthError::Unavailable)
    }
    async fn p256_sign(
        &self,
        _: String,
        _: Vec<u8>,
        _: String,
    ) -> Result<Vec<u8>, crate::platform::AuthError> {
        Err(crate::platform::AuthError::Unavailable)
    }
}

/// A seed with platform unlock and one import, locked, then unlocked by the platform secret.
async fn platform_session() -> (Arc<crate::Sdk>, String) {
    let s = crate::Sdk::open(crate::SdkConfig {
        profiles: vec![],
        store: MemoryStore::new(),
        authenticator: Some(Arc::new(Platform)),
        rp_id: None,
        runtime: crate::RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: crate::Limits::default(),
        clock: None,
    })
    .await
    .unwrap();
    let v = s.vault();
    let id = v
        .import_words(ImportWords {
            label: "Main".into(),
            words: secret(REPO),
            vault_passphrase: secret(PASS),
        })
        .await
        .unwrap()
        .id;
    let policy = crate::platform::KeyPolicy {
        biometry_current_set: true,
        invalidated_by_enrollment: true,
    };
    v.enable_platform_unlock(id.clone(), secret(PASS), policy)
        .await
        .unwrap();
    v.import_key(ImportKey {
        seed: id.clone(),
        network: "evm".into(),
        secret: secret(&[0x11; 32]),
        vault_passphrase: secret(PASS),
    })
    .await
    .unwrap();
    v.lock(id.clone()).await;
    v.unlock(id.clone(), Unlock::Platform).await.unwrap();
    (s, id)
}

/// Owner 2026-11-18 (b): a PRF unlock opens no import before its first use; the first use opens it with the retained key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imports_open_on_first_use() {
    let (s, id) = platform_session().await;
    let w = s.open_seed(&id).unwrap();
    assert!(w.wallet.label_open("manifest"));
    assert!(
        !w.wallet.label_open("native-import:evm:0"),
        "not opened at unlock"
    );
    assert!(w
        .wallet
        .imported_key(scaas_ua::wallet::Network::Evm, 0)
        .is_err());
    s.open_on_use(&id, "native-import:evm:0").await.unwrap();
    assert!(
        w.wallet.label_open("native-import:evm:0"),
        "opened at first use"
    );
    assert!(w
        .wallet
        .imported_key(scaas_ua::wallet::Network::Evm, 0)
        .is_ok());
    s.open_on_use(&id, "native-import:evm:0").await.unwrap();
}

/// Lock zeroes the retained key: after lock and a passphrase unlock, no vault opens through a kept key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lock_drops_the_retained_key() {
    let (s, id) = platform_session().await;
    s.vault().lock(id.clone()).await;
    s.vault()
        .unlock(id.clone(), Unlock::Passphrase(secret(PASS)))
        .await
        .unwrap();
    let w = s.open_seed(&id).unwrap();
    assert!(
        w.wallet.label_open("native-import:evm:0"),
        "a passphrase unlock opens every vault"
    );
    let v = super::unlock::vault_of(&s.entry(&id).await.unwrap(), "native-import:evm:0").unwrap();
    assert_eq!(
        w.wallet.open_label_vault_retained(&v),
        Err(scaas_ua::wallet::Error::Argument),
        "no key kept across lock"
    );
}

/// Closing review P2-7 (A): the keystore write of `import_key` fails after the open wallet took the key: the seed is locked, so
/// no later re-seal (`derive_child`, the next import) writes a manifest that lists an import without a vault; after the next
/// unlock the stored manifest has no such import, and the next import takes number 0 again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_key_failed_write_leaves_no_ghost_import() {
    let m = Arc::new(Mem::default());
    let s = crate::Sdk::open(crate::SdkConfig {
        profiles: vec![],
        store: m.clone(),
        authenticator: None,
        rp_id: None,
        runtime: crate::RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: crate::Limits::default(),
        clock: None,
    })
    .await
    .unwrap();
    let v = s.vault();
    let words = ImportWords {
        label: "Main".into(),
        words: secret(REPO),
        vault_passphrase: secret(PASS),
    };
    let id = v.import_words(words).await.unwrap().id;
    let key = |b: u8| ImportKey {
        seed: id.clone(),
        network: "evm".into(),
        secret: secret(&[b; 32]),
        vault_passphrase: secret(PASS),
    };
    m.conflicts.store(3, Ordering::SeqCst); // every try of the write conflicts
    assert_eq!(
        v.import_key(key(0x11)).await.unwrap_err().code(),
        "StoreConflict"
    );
    assert!(
        s.open_seed(&id).is_err(),
        "locked: the open wallet held an import the store has not"
    );
    v.unlock(id.clone(), Unlock::Passphrase(secret(PASS)))
        .await
        .unwrap();
    let w = s.open_seed(&id).unwrap();
    assert!(
        w.wallet
            .imported_key(scaas_ua::wallet::Network::Evm, 0)
            .is_err(),
        "no ghost import"
    );
    assert_eq!(
        v.import_key(key(0x22)).await.unwrap().index,
        0,
        "control: the number is free"
    );
}
