// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `user_profile` (feature `user-profile`; spec docs/superpowers/specs/2026-11-27-user-profiles.md, rules CLI-UPR-* of
//! docs/clients/scaas-sdk.md §12): many protected local profiles. The store is the crate `scaas-profile` (owner
//! 2026-11-27, CLI-UPR-02's Change: an app's build without the SDK holds a profile with it); this module adds what needs the
//! SDK. Built so far (plan UP5): the store's `SecureStore` face ([`PartStore`]) and the mapping of its codes. UNAUDITED.
pub use scaas_profile::{
    keychain_name, Anchor, Core, CoreOpen, Error, Head, Item, Manifest, Plain, ProfileKeychain,
    ProfilePart, Verdict, WriteGuard, PART_MAX,
};

use crate::error::SdkError;
use crate::vault::store::blocking;
use crate::vault::{FileStore, SecureStore, StoreError, StoreLock, StorePolicy, StoredItem, HEAD};
use async_trait::async_trait;
use std::sync::Arc;
use zeroize::Zeroizing;

/// A store code as the SDK's: the code of the same name.
impl From<Error> for SdkError {
    fn from(e: Error) -> SdkError {
        match e {
            Error::Argument => SdkError::Argument,
            Error::VaultIo => SdkError::VaultIo,
            Error::VaultFormat => SdkError::VaultFormat,
            Error::StoreConflict => SdkError::StoreConflict,
            Error::ProfileFormat => SdkError::ProfileFormat,
            Error::ProfileLocked => SdkError::ProfileLocked,
            Error::ProfilePassphraseRequired => SdkError::ProfilePassphraseRequired,
            Error::ProfileRollback => SdkError::ProfileRollback,
            Error::ProfileDamaged => SdkError::ProfileDamaged,
            Error::ProfileBusy => SdkError::ProfileBusy,
            Error::ProfilePartFull => SdkError::ProfilePartFull,
        }
    }
}

/// A store code as the face's (CLI-UPR-22 names `StoreError`'s codes): `ProfileFormat` is `VaultFormat` at the store;
/// `ProfileBusy` and `ProfilePartFull`, which `StoreError` does not name, are `Unavailable` (the write is not taken now).
fn store_code(e: Error) -> StoreError {
    match e {
        Error::StoreConflict => StoreError::Conflict,
        Error::VaultFormat | Error::ProfileFormat => StoreError::VaultFormat,
        Error::ProfileLocked => StoreError::ProfileLocked,
        Error::ProfilePassphraseRequired => StoreError::ProfilePassphraseRequired,
        Error::ProfileRollback => StoreError::ProfileRollback,
        Error::ProfileDamaged => StoreError::ProfileDamaged,
        Error::ProfileBusy | Error::ProfilePartFull => StoreError::Unavailable,
        Error::Argument | Error::VaultIo => StoreError::Io,
    }
}

/// The SDK's `SecureStore` over one part of the core (spec §7.2 "One store core, two faces"), each call on `spawn_blocking`.
/// In part `sdk`, `keystore.head` passes through unsealed to the profile directory (public by contract).
pub struct PartStore {
    core: Arc<Core>,
    part: ProfilePart,
    head: Option<Arc<FileStore>>,
}

impl PartStore {
    pub fn new(core: Arc<Core>, part: ProfilePart) -> Result<Arc<PartStore>, SdkError> {
        let head = match part {
            ProfilePart::Sdk => Some(FileStore::new(core.dir()).map_err(crate::vault::io)?),
            _ => None,
        };
        Ok(Arc::new(PartStore { core, part, head }))
    }

    fn head(&self, name: &str) -> Option<&Arc<FileStore>> {
        self.head.as_ref().filter(|_| name == HEAD)
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Core, ProfilePart) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, StoreError> {
        let (core, part) = (self.core.clone(), self.part);
        blocking(move || f(&core, part).map_err(store_code)).await
    }
}

#[async_trait]
impl SecureStore for PartStore {
    async fn get(&self, name: String, reason: String) -> Result<Option<StoredItem>, StoreError> {
        if let Some(h) = self.head(&name) {
            return h.get(name, reason).await;
        }
        let got = self.run(move |c, p| c.get(p, &name)).await?;
        Ok(got.map(|(pt, rev)| StoredItem {
            bytes: pt.to_vec(),
            rev,
        }))
    }

    async fn put_if(
        &self,
        name: String,
        prev_rev: Option<u64>,
        bytes: Vec<u8>,
        policy: StorePolicy,
    ) -> Result<(), StoreError> {
        if let Some(h) = self.head(&name) {
            return h.put_if(name, prev_rev, bytes, policy).await;
        }
        let bytes = Zeroizing::new(bytes);
        self.run(move |c, p| c.put_if(p, &name, prev_rev, &bytes))
            .await
    }

    async fn delete(&self, name: String) -> Result<(), StoreError> {
        if let Some(h) = self.head(&name) {
            return h.delete(name).await;
        }
        self.run(move |c, p| c.delete(p, &name)).await
    }

    async fn lock(&self, name: String) -> Result<Arc<StoreLock>, StoreError> {
        if let Some(h) = self.head(&name) {
            return h.lock(name).await;
        }
        let f = self.run(move |c, p| c.lock_item(p, &name)).await?;
        Ok(StoreLock::new(Box::new(f)))
    }
}
