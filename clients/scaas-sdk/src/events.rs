// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Events by subscription (spec §14): a bounded queue per subscriber; a slow subscriber gets `Lagged { missed }` and re-reads
//! state; nothing blocks the SDK. No event names a hidden set's account.

use std::sync::Arc;
use tokio::sync::broadcast;

/// An SDK event (appended only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    SeedUnlocked {
        seed: String,
    },
    SeedLocked {
        seed: String,
    },
    KeystoreChanged {
        rev: u64,
    },
    KeystoreMismatch {
        seed: String,
    },
    KeystoreRollback,
    HiddenOpsAbandoned {
        count: u32,
    },
    /// The subscriber's queue overflowed: `missed` events were dropped for it
    Lagged {
        missed: u64,
    },
}

/// One subscriber's queue.
pub struct Subscription {
    rx: tokio::sync::Mutex<broadcast::Receiver<Event>>,
}

impl Subscription {
    pub(crate) fn new(tx: &broadcast::Sender<Event>) -> Arc<Subscription> {
        Arc::new(Subscription {
            rx: tokio::sync::Mutex::new(tx.subscribe()),
        })
    }

    /// The next event, or `None` when none arrives within `timeout_ms`.
    pub async fn next(&self, timeout_ms: u64) -> Option<Event> {
        let mut rx = self.rx.lock().await;
        let wait = tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), rx.recv());
        match wait.await {
            Ok(Ok(e)) => Some(e),
            Ok(Err(broadcast::error::RecvError::Lagged(missed))) => Some(Event::Lagged { missed }),
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => None,
        }
    }
}
