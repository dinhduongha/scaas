// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `vault` (spec §6, CLI-SDK-03 … CLI-SDK-06): the keystore container, the store it lives in, and the writers' rules of §6.3:
//! every read-modify-write under the store's lock and at the expected `rev` (`StoreConflict` after three tries), the replaced
//! container kept as `keystore.prev`, and the anchor `keystore.head` that detects an older container put back.
pub mod keystore;
pub mod prf;
#[cfg(feature = "classical-roots")]
mod roots;
pub mod seeds;
pub mod store;
mod unlock;

#[cfg(feature = "classical-roots")]
pub use roots::{DeriveFromKey, DeriveFromSignature};
pub use unlock::{SessionSet, Unlock};

#[cfg(feature = "account")]
pub(crate) use seeds::change_entry;
#[cfg(any(feature = "account", feature = "evm"))]
pub(crate) use seeds::uuid4;
pub(crate) use seeds::OpenSeed;
pub use seeds::{
    ConfirmRemove, ConfirmRemoveUnbacked, DeriveChild, Generate, ImportKey, ImportWords,
    ImportedKey, NewSeed, Remove, SeedBackup, SeedInfo, Vault,
};

pub use keystore::{AccountRow, Keystore, SeedEntry};
#[cfg(feature = "file-store")]
pub use store::FileStore;
pub use store::{
    MemoryStore, Presence, SecureStore, StoreError, StoreLock, StorePolicy, StoredItem,
};

use crate::error::SdkError;
use std::sync::Arc;

pub(crate) const KEYSTORE: &str = "keystore";
pub(crate) const PREV: &str = "keystore.prev";
pub(crate) const HEAD: &str = "keystore.head";
/// A key-locked import's vault label prefix (user-profiles spec §7.4, CLI-UPR-24): only its own passphrase opens it, so every
/// seed-wide loop skips it.
pub(crate) const KEY_LOCKED: &str = "native-import-locked:";
/// The anchor's size contract (spec §6.9): a keychain item.
pub(crate) const HEAD_MAX: usize = 64;
/// Tries of a read-modify-write before `StoreConflict` reaches the caller (spec §6.3).
const TRIES: usize = 3;

/// The keystore as read: the container (empty when there is none yet) and whether it is older than the anchor.
#[derive(Debug, Clone)]
pub(crate) struct Loaded {
    pub(crate) keystore: Keystore,
    /// `KeystoreRollback`: the container's `rev` is below the anchor's, or its hash differs at the same `rev` (shown, not
    /// fatal): `Event::KeystoreRollback` from every read of it ([`crate::Sdk::load_keystore`]), `Vault::keystore_rollback`
    pub(crate) rollback: bool,
}

/// A store's failure as the SDK's code (spec §6.9; user-profiles spec §7.2 "Errors": the profile codes by name); the one mapping
/// of the keystore and of `sdk.state`.
pub(crate) fn io(e: StoreError) -> SdkError {
    match e {
        StoreError::Conflict => SdkError::StoreConflict,
        StoreError::VaultFormat => SdkError::VaultFormat,
        StoreError::ProfileLocked => SdkError::ProfileLocked,
        StoreError::ProfilePassphraseRequired => SdkError::ProfilePassphraseRequired,
        StoreError::ProfileRollback => SdkError::ProfileRollback,
        StoreError::ProfileDamaged => SdkError::ProfileDamaged,
        StoreError::ProfileBusy => SdkError::ProfileBusy,
        StoreError::ProfilePartFull => SdkError::ProfilePartFull,
        StoreError::Io | StoreError::Unavailable | StoreError::Unexpected => SdkError::VaultIo,
    }
}

/// `{"rev":N,"sha256":"<the first 16 bytes of SHA-256 of the container, hex>"}`: 52 bytes and the digits of `rev`, so it keeps
/// within [`HEAD_MAX`] below rev 10^12. The hash is `scaas-ua`'s (no hashing in the SDK).
pub(crate) fn anchor(rev: u64, container: &[u8]) -> Result<Vec<u8>, SdkError> {
    let h = scaas_ua::sha256(container);
    let hex: String = h.iter().take(16).map(|b| format!("{b:02x}")).collect();
    let a = format!("{{\"rev\":{rev},\"sha256\":\"{hex}\"}}").into_bytes();
    if a.len() > HEAD_MAX {
        return Err(SdkError::Argument);
    }
    Ok(a)
}

/// The anchor's verdict on the stored container `item` (parsed as `keystore`): below the anchor's `rev`, or another hash at
/// the same `rev`, or none where an anchor exists.
fn rolled_back(
    item: &Option<StoredItem>,
    keystore: &Keystore,
    head: Option<StoredItem>,
) -> Result<bool, SdkError> {
    Ok(match head {
        None => false,
        Some(h) => match item {
            None => true,
            Some(i) => {
                let head_rev = store::rev_of(&h.bytes);
                keystore.rev < head_rev
                    || (keystore.rev == head_rev && anchor(keystore.rev, &i.bytes)? != h.bytes)
            }
        },
    })
}

/// The keystore item of one store, read and replaced under the rules of §6.3.
pub(crate) struct KeystoreFile {
    store: Arc<dyn SecureStore>,
}

impl KeystoreFile {
    pub(crate) fn new(store: Arc<dyn SecureStore>) -> KeystoreFile {
        KeystoreFile { store }
    }

    async fn get(&self, name: &str) -> Result<Option<StoredItem>, SdkError> {
        self.store
            .get(name.into(), "the keystore".into())
            .await
            .map_err(io)
    }

    /// The container and the anchor's verdict; a container that does not parse is its refusal (`VaultFormat`,
    /// `VaultVersion`), and the SDK then writes nothing.
    pub(crate) async fn load(&self) -> Result<Loaded, SdkError> {
        let item = self.get(KEYSTORE).await?;
        let keystore = match &item {
            Some(i) => Keystore::parse(&i.bytes)?,
            None => Keystore::default(),
        };
        let rollback = rolled_back(&item, &keystore, self.get(HEAD).await?)?;
        Ok(Loaded { keystore, rollback })
    }

    /// Review A-6 (spec §6.3: the user accepts an older copy deliberately): the anchor rewritten over the stored container as
    /// it is, under the store's lock, so it is no longer `KeystoreRollback` and writes resume. Nothing else changes.
    pub(crate) async fn accept_rollback(&self) -> Result<(), SdkError> {
        let _lock = self.store.lock(KEYSTORE.into()).await.map_err(io)?;
        let Some(item) = self.get(KEYSTORE).await? else {
            return Ok(());
        };
        let ks = Keystore::parse(&item.bytes)?;
        let prev = self.get(HEAD).await?.map(|h| h.rev);
        self.put(HEAD, prev, anchor(ks.rev, &item.bytes)?).await
    }

    /// Applies `change` to the stored container under the store's lock and writes it at `rev + 1`: the replaced bytes first
    /// become `keystore.prev`, then the container is replaced only at the `rev` it was read at, then the anchor follows (best
    /// effort: a missing anchor raises no false rollback). A `Conflict` reloads and reapplies `change`, at most three tries in
    /// all (`StoreConflict` after). A stored container that does not parse is refused and nothing is written (spec §6.1: a
    /// refusing reader never writes); an anchor above its size contract is refused before anything is written.
    pub(crate) async fn update(
        &self,
        mut change: impl FnMut(&mut Keystore) -> Result<(), SdkError>,
    ) -> Result<Keystore, SdkError> {
        for _ in 0..TRIES {
            let _lock = self.store.lock(KEYSTORE.into()).await.map_err(io)?;
            match self.try_once(&mut change).await {
                Err(SdkError::StoreConflict) => continue,
                Err(e) => return Err(e),
                Ok((ks, head)) => {
                    if let Ok(prev) = self.get(HEAD).await {
                        let _ = self.put(HEAD, prev.map(|h| h.rev), head).await;
                    }
                    return Ok(ks);
                }
            }
        }
        Err(SdkError::StoreConflict)
    }

    /// One read, change and write; the anchor to write after it.
    async fn try_once(
        &self,
        change: &mut impl FnMut(&mut Keystore) -> Result<(), SdkError>,
    ) -> Result<(Keystore, Vec<u8>), SdkError> {
        let item = self.get(KEYSTORE).await?;
        let mut ks = match &item {
            Some(i) => Keystore::parse(&i.bytes)?,
            None => Keystore::default(),
        };
        // the change first: a writer's own refusal (an entry whose MAC fails, A-1, locks its seed) comes before the verdict
        change(&mut ks)?;
        // review A-6: an older copy put back is never written over (the write would lower the anchor and erase the
        // evidence) until the user accepts it (`Vault::accept_rollback`)
        if rolled_back(&item, &ks, self.get(HEAD).await?)? {
            return Err(SdkError::KeystoreRollback);
        }
        ks.rev = ks.rev.checked_add(1).ok_or(SdkError::Argument)?;
        let text = ks.serialize()?.into_bytes();
        let head = anchor(ks.rev, &text)?;
        if let Some(old) = &item {
            let prev_rev = self.get(PREV).await?.map(|p| p.rev);
            self.put(PREV, prev_rev, old.bytes.clone()).await?;
        }
        self.put(KEYSTORE, item.as_ref().map(|i| i.rev), text)
            .await?;
        Ok((ks, head))
    }

    async fn put(&self, name: &str, prev_rev: Option<u64>, bytes: Vec<u8>) -> Result<(), SdkError> {
        self.store
            .put_if(name.into(), prev_rev, bytes, StorePolicy::default())
            .await
            .map_err(io)
    }
}

#[cfg(test)]
mod tests;
