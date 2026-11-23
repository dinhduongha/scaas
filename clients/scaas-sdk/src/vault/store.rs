// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `SecureStore` (spec §6.9): the platform interface the SDK keeps its items in, and `FileStore`, the native default.
//!
//! **Items** (all public data: vault ciphertexts and public fields): `keystore`, `keystore.prev`, `sdk.state` (blobs up to
//! 16 MiB) and `keystore.head` (at most 64 bytes, for a keychain). Each is a JSON object whose top-level integer `rev` is the
//! item's revision: [`StoredItem::rev`], and what `put_if` compares. A store is trusted for availability and for that compare,
//! never for confidentiality.

use async_trait::async_trait;
use std::sync::Arc;

/// An item and its revision (its JSON `rev`; `u64::MAX` when the bytes hold none, so no `put_if` matches it).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct StoredItem {
    pub bytes: Vec<u8>,
    pub rev: u64,
}

impl std::fmt::Debug for StoredItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredItem")
            .field("len", &self.bytes.len())
            .field("rev", &self.rev)
            .finish()
    }
}

/// Whether the platform asks for the user before it gives the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Presence {
    #[default]
    None,
    Required,
}

/// How an item is kept: on this device only, out of cloud backups, behind user presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct StorePolicy {
    pub device_only: bool,
    pub no_cloud_backup: bool,
    pub user_presence: Presence,
}

impl Default for StorePolicy {
    fn default() -> Self {
        StorePolicy {
            device_only: true,
            no_cloud_backup: true,
            user_presence: Presence::None,
        }
    }
}

/// A store's failure; `Unexpected` is a foreign exception inside an app's implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum StoreError {
    /// `put_if`: the stored revision is not the expected one
    Conflict,
    Io,
    Unavailable,
    Unexpected,
}

/// A foreign store's lock release, run to its end on a thread of its own on a current-thread runtime (review T26 C-7): a
/// task of the SDK's runtime would be dropped by its shutdown, and a drop where no runtime runs could not run it at all.
#[cfg(any(feature = "uniffi", feature = "frb"))]
pub(crate) fn release_on_own_thread(f: impl std::future::Future<Output = ()> + Send + 'static) {
    let _ = std::thread::Builder::new()
        .name("scaas-store-unlock".into())
        .spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                rt.block_on(f);
            }
        });
}

/// A held store lock; released on drop.
pub struct StoreLock {
    _held: Box<dyn Send + Sync>,
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl StoreLock {
    pub fn new(held: Box<dyn Send + Sync>) -> Arc<StoreLock> {
        Arc::new(StoreLock { _held: held })
    }
}

/// The platform's store of the SDK's items.
#[async_trait]
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub trait SecureStore: Send + Sync {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError>;
    /// Replaces (or creates) `name` only when its stored revision is `prev_rev` (`None`: the item does not exist), else
    /// `Conflict`; a failed write leaves the old item.
    async fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError>;
    async fn delete(&self, name: String) -> Result<(), StoreError>;
    /// An exclusive lock for a read-modify-write of `name`, across processes; released when the returned lock drops.
    async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError>;
}

/// The revision of an item's bytes: its top-level JSON `rev`, else `u64::MAX`.
pub fn rev_of(bytes: &[u8]) -> u64 {
    #[derive(serde::Deserialize)]
    struct Rev {
        rev: u64,
    }
    if bytes.len() > super::keystore::MAX_BYTES || scaas_ua::json::depth_within(bytes, 64).is_err()
    {
        return u64::MAX;
    }
    serde_json::from_slice::<Rev>(bytes).map_or(u64::MAX, |r| r.rev)
}

/// Items in memory, under the same rev rule and an in-process lock: for tests and for an app's session-only use (nothing
/// survives the process).
#[derive(Default)]
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub struct MemoryStore {
    items: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    lock: Arc<tokio::sync::Mutex<()>>,
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl MemoryStore {
    pub fn new() -> Arc<MemoryStore> {
        Arc::new(MemoryStore::default())
    }
    fn items(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Vec<u8>>> {
        self.items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl SecureStore for MemoryStore {
    async fn get(&self, name: String, _: String) -> Result<Option<StoredItem>, StoreError> {
        Ok(self.items().get(&name).map(|b| StoredItem {
            rev: rev_of(b),
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
        let mut items = self.items();
        if items.get(&name).map(|b| rev_of(b)) != prev {
            return Err(StoreError::Conflict);
        }
        items.insert(name, bytes);
        Ok(())
    }
    async fn delete(&self, name: String) -> Result<(), StoreError> {
        self.items().remove(&name);
        Ok(())
    }
    async fn lock(&self, _: String) -> Result<Arc<StoreLock>, StoreError> {
        Ok(StoreLock::new(Box::new(
            self.lock.clone().lock_owned().await,
        )))
    }
}

#[cfg(feature = "file-store")]
pub use file::FileStore;

#[cfg(feature = "file-store")]
mod file {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Items as files of one directory (spec §6.9): written to a temporary file, `fsync`ed, renamed over the item, the directory
    /// `fsync`ed; mode `0600`; `lock(name)` an advisory lock on `<name>.lock` (across processes, and across instances of one
    /// process).
    pub struct FileStore {
        dir: PathBuf,
        #[cfg(test)]
        pub(crate) crash_before_rename: std::sync::atomic::AtomicBool,
    }

    fn item(name: &str) -> Result<&str, StoreError> {
        let ok = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && !name.starts_with('.');
        ok.then_some(name).ok_or(StoreError::Io)
    }

    fn io<T>(r: std::io::Result<T>) -> Result<T, StoreError> {
        r.map_err(|_| StoreError::Io)
    }

    async fn blocking<T: Send + 'static>(
        f: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        tokio::task::spawn_blocking(f)
            .await
            .map_err(|_| StoreError::Unexpected)?
    }

    fn open_new(p: &Path) -> std::io::Result<File> {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(p)
    }

    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    impl FileStore {
        /// The store of directory `dir` (created, mode `0700`, if missing).
        pub fn new(dir: impl Into<PathBuf>) -> Result<Arc<FileStore>, StoreError> {
            let dir = dir.into();
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            io(b.create(&dir))?;
            Ok(Arc::new(FileStore {
                dir,
                #[cfg(test)]
                crash_before_rename: Default::default(),
            }))
        }

        fn path(&self, name: &str) -> Result<PathBuf, StoreError> {
            Ok(self.dir.join(item(name)?))
        }

        fn read(p: &Path) -> Result<Option<StoredItem>, StoreError> {
            match std::fs::read(p) {
                Ok(bytes) => Ok(Some(StoredItem {
                    rev: rev_of(&bytes),
                    bytes,
                })),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(StoreError::Io),
            }
        }

        fn write(dir: &Path, p: &Path, bytes: &[u8], crash: bool) -> Result<(), StoreError> {
            static N: AtomicU64 = AtomicU64::new(0);
            let tmp = p.with_extension(format!(
                "tmp.{}.{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let r = (|| {
                let mut f = io(open_new(&tmp))?;
                io(f.write_all(bytes))?;
                io(f.sync_all())?;
                if crash {
                    return Err(StoreError::Io);
                }
                io(std::fs::rename(&tmp, p))?;
                io(File::open(dir).and_then(|d| d.sync_all()))
            })();
            if r.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            r
        }
    }

    #[async_trait]
    impl SecureStore for FileStore {
        async fn get(
            &self,
            name: String,
            _reason: String,
        ) -> Result<Option<StoredItem>, StoreError> {
            let p = self.path(&name)?;
            blocking(move || FileStore::read(&p)).await
        }

        async fn put_if(
            &self,
            name: String,
            prev_rev: Option<u64>,
            bytes: Vec<u8>,
            _: StorePolicy,
        ) -> Result<(), StoreError> {
            let (p, dir) = (self.path(&name)?, self.dir.clone());
            #[cfg(test)]
            let crash = self.crash_before_rename.load(Ordering::SeqCst);
            #[cfg(not(test))]
            let crash = false;
            blocking(move || {
                let now = FileStore::read(&p)?.map(|i| i.rev);
                if now != prev_rev {
                    return Err(StoreError::Conflict);
                }
                FileStore::write(&dir, &p, &bytes, crash)
            })
            .await
        }

        async fn delete(&self, name: String) -> Result<(), StoreError> {
            match std::fs::remove_file(self.path(&name)?) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(StoreError::Io),
            }
        }

        async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError> {
            let p = self.path(&format!("{name}.lock"))?;
            let f = blocking(move || {
                let mut o = OpenOptions::new();
                o.write(true).create(true).truncate(false);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
                let f = io(o.open(&p))?;
                io(f.lock())?;
                Ok(f)
            })
            .await?;
            Ok(StoreLock::new(Box::new(f)))
        }
    }
}

#[cfg(all(test, feature = "file-store"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "scaas-sdk-store-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u64 {
        use std::hash::{BuildHasher, RandomState};
        RandomState::new().hash_one(0u8)
    }

    #[tokio::test]
    async fn filestore_writes_atomically() {
        let d = dir();
        let s = FileStore::new(&d).unwrap();
        let p = StorePolicy::default();
        s.put_if("keystore".into(), None, br#"{"rev":1}"#.to_vec(), p)
            .await
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.join("keystore"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // a crash between the write and the rename leaves the old file and no temporary
        s.crash_before_rename.store(true, Ordering::SeqCst);
        assert_eq!(
            s.put_if("keystore".into(), Some(1), br#"{"rev":2}"#.to_vec(), p)
                .await,
            Err(StoreError::Io)
        );
        s.crash_before_rename.store(false, Ordering::SeqCst);
        let now = s
            .get("keystore".into(), String::new())
            .await
            .unwrap()
            .unwrap();
        assert_eq!((now.bytes.as_slice(), now.rev), (&br#"{"rev":1}"#[..], 1));
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("keystore")],
            "no temporary left"
        );
        // control: the same write without the crash replaces it
        s.put_if("keystore".into(), Some(1), br#"{"rev":2}"#.to_vec(), p)
            .await
            .unwrap();
        assert_eq!(
            s.get("keystore".into(), String::new())
                .await
                .unwrap()
                .unwrap()
                .rev,
            2
        );
        // the rev rule: another expected rev, or an item expected absent, is Conflict
        assert_eq!(
            s.put_if("keystore".into(), Some(1), b"{}".to_vec(), p)
                .await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            s.put_if("keystore".into(), None, b"{}".to_vec(), p).await,
            Err(StoreError::Conflict)
        );
        // the lock is exclusive across open files of one process (as across processes)
        let held = s.lock("keystore".into()).await.unwrap();
        let other = std::fs::OpenOptions::new()
            .write(true)
            .open(d.join("keystore.lock"))
            .unwrap();
        assert!(other.try_lock().is_err(), "held");
        drop(held);
        assert!(other.try_lock().is_ok(), "released on drop");
        drop(other);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rev_of_items() {
        assert_eq!(rev_of(br#"{"format":"x","rev":42,"seeds":[]}"#), 42);
        assert_eq!(rev_of(b"not json"), u64::MAX);
        assert_eq!(rev_of(br#"{"rev":-1}"#), u64::MAX);
    }
}
