// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The crate's store (spec §7, CLI-PQC-09): a cache with no secret and no source of truth, behind a small interface the app
//! implements. Items are keyed apart, each with its own revision; a write replaces one item at its expected revision, and
//! the crate retries a changed item at most three times (`StoreConflict`). The app keeps the storage encrypted at rest under
//! its own store key and out of backups; the crate holds no key.
use crate::PqChatError;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

/// A stored item: its bytes and its revision (1 for the first write, then one more per write).
#[derive(Clone, PartialEq, Eq)]
pub struct Item {
    pub revision: u64,
    pub value: Vec<u8>,
}

/// The app's storage failed. It carries nothing: no key, no path, no text of the app's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFault;

/// The storage interface the app implements.
pub trait PqChatStore: Send + Sync {
    /// The item `key`, `None` when absent.
    fn load(&self, key: &str) -> Result<Option<Item>, StoreFault>;
    /// Replaces the item `key` with `value` if its revision is `expected` (0: absent), then its revision is `expected + 1`;
    /// `Ok(false)` when the item's revision is another, nothing written. A fault keeps the old item.
    fn replace(&self, key: &str, expected: u64, value: &[u8]) -> Result<bool, StoreFault>;
}

/// An in-memory store: the reference implementation of [`PqChatStore`] and the tests' store.
#[derive(Default)]
pub struct MemoryStore {
    items: Mutex<HashMap<String, Item>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of every item (a copied data directory).
    pub fn copy(&self) -> Self {
        MemoryStore {
            items: Mutex::new(
                self.items
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ),
        }
    }
}

impl PqChatStore for MemoryStore {
    fn load(&self, key: &str) -> Result<Option<Item>, StoreFault> {
        Ok(self
            .items
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned())
    }

    fn replace(&self, key: &str, expected: u64, value: &[u8]) -> Result<bool, StoreFault> {
        let mut items = self.items.lock().unwrap_or_else(PoisonError::into_inner);
        let revision = items.get(key).map_or(0, |i| i.revision);
        if revision != expected {
            return Ok(false);
        }
        items.insert(
            key.to_string(),
            Item {
                revision: expected + 1,
                value: value.to_vec(),
            },
        );
        Ok(true)
    }
}

/// How often a changed item is read again before `StoreConflict`.
pub const TRIES: usize = 3;

fn io(_: StoreFault) -> PqChatError {
    tracing::debug!(code = "StoreIo", "store");
    PqChatError::StoreIo
}

/// Typed items over the app's store: JSON values of the crate's own types (never signed bytes).
pub struct Items<'a>(pub &'a dyn PqChatStore);

impl Items<'_> {
    /// The item `key` as a `T`; an item that does not decode is `StoreIo`.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, PqChatError> {
        match self.0.load(key).map_err(io)? {
            None => Ok(None),
            Some(i) => serde_json::from_slice(&i.value)
                .map(Some)
                .map_err(|_| io(StoreFault)),
        }
    }

    /// Reads the item `key`, applies `f` and writes the result at the revision read; a changed item is read again, at most
    /// [`TRIES`] times (`StoreConflict`). `f`'s error writes nothing.
    pub fn update<T, F>(&self, key: &str, mut f: F) -> Result<T, PqChatError>
    where
        T: Serialize + DeserializeOwned,
        F: FnMut(Option<T>) -> Result<T, PqChatError>,
    {
        for _ in 0..TRIES {
            let cur = self.0.load(key).map_err(io)?;
            let (revision, old) = match cur {
                None => (0, None),
                Some(i) => (
                    i.revision,
                    Some(serde_json::from_slice(&i.value).map_err(|_| io(StoreFault))?),
                ),
            };
            let new = f(old)?;
            let bytes = serde_json::to_vec(&new).map_err(|_| PqChatError::Internal)?;
            if self.0.replace(key, revision, &bytes).map_err(io)? {
                return Ok(new);
            }
        }
        tracing::debug!(code = "StoreConflict", "store");
        Err(PqChatError::StoreConflict)
    }
}
