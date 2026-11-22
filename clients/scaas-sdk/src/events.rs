// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Events by subscription (spec §14): a bounded queue per subscriber; a slow subscriber gets `Lagged { missed }` and re-reads
//! state; nothing blocks the SDK. No event names a hidden set's account.

use std::sync::Arc;
use tokio::sync::broadcast;

/// An SDK event (appended only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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
    /// An operation's state changed (spec §13.4, §13.5): every send result after `submit` arrives here, never as its error.
    OpState {
        op: String,
        state: OpState,
    },
    /// A watched token's balance moved at the profile's final block (spec §14).
    BalanceChanged {
        account: String,
        chain: String,
        token: String,
    },
    /// A watched account's new history items (spec §8.4), newest first.
    #[cfg(feature = "evm")]
    HistoryAdded {
        account: String,
        chain: String,
        items: Vec<crate::wallet::HistoryItem>,
    },
    /// Another process changed `sdk.state` (R17): its `rev` now.
    StateChanged {
        rev: u64,
    },
}

/// An operation's state (spec §13.5, CLI-SDK-18): terminal only on a chain fact from a decisive read at the profile's final
/// block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum OpState {
    /// the executed event of the operation's digest at or below the final block
    Landed { block: u64, hash: String },
    /// the lane's nonce spent at the final block without that event; a replaced native send
    Consumed,
    /// an EVM native send final at or below the final block and reverted (owner 2026-11-18, ruling 4; the node's `reverted`)
    Reverted { block: u64, hash: String },
    /// `validUntil` below the final block's timestamp while the nonce is unspent
    Expired,
    /// anything else, with what is known (never an end)
    InFlight { detail: InFlight },
}

impl OpState {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, OpState::InFlight { .. })
    }
}

/// What is known of an operation in flight (spec §13.5): none of it ends the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum InFlight {
    /// signed and written, not sent yet
    Signed,
    /// a gateway queued it
    Queued,
    /// every gateway it went to refused it or could not be reached (one node's `dead` covers its own sends only)
    GivenUpByEveryNode,
    /// the self-relay transaction was accepted by an endpoint
    Sent,
    /// no endpoint accepted the self-relay transaction (`BroadcastRejected`, an outcome, never final)
    BroadcastRejected,
    /// the self-relay transaction is in a block, not final, or final and successful while the event is not read yet
    TxIncluded,
    /// the self-relay transaction is final and failed: the signed operation may still land by another relayer
    TxFinalFailed,
    /// the self-relay transaction was replaced
    TxReplaced,
    /// the signed operation's simulation from the payer reverted, failed or needed more gas than the confirmed quote: not sent
    /// by this SDK (owner 2026-11-19, ruling A). It is signed and may still land by another relayer until its nonce is spent or
    /// `validUntil` passes; `resend` tries again, a cancel of the lane's nonce ends it.
    SimRefused,
}

/// One subscriber's queue.
pub struct Subscription {
    rx: tokio::sync::Mutex<broadcast::Receiver<Event>>,
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Subscription {
    pub(crate) fn new(tx: &broadcast::Sender<Event>) -> Arc<Subscription> {
        Arc::new(Subscription {
            rx: tokio::sync::Mutex::new(tx.subscribe()),
        })
    }

    /// The next event, or `None` when none arrives within `timeout_ms`.
    pub async fn next(&self, timeout_ms: u64) -> Option<Event> {
        let mut rx = self.rx.lock().await;
        let d = std::time::Duration::from_millis(timeout_ms);
        // wasm32: the JS clock (tokio's timer needs a runtime the page has not; closing review P2-9)
        #[cfg(not(target_arch = "wasm32"))]
        let wait = tokio::time::timeout(d, rx.recv());
        #[cfg(target_arch = "wasm32")]
        let wait = wasmtimer::tokio::timeout(d, rx.recv());
        match wait.await {
            Ok(Ok(e)) => Some(e),
            Ok(Err(broadcast::error::RecvError::Lagged(missed))) => Some(Event::Lagged { missed }),
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => None,
        }
    }
}
