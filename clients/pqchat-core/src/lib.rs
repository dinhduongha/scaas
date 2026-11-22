// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `pqchat-core`: PqChat's client core above `scaas-sdk` (CLI-PQC-01, docs/clients/pqchat-core.md; spec
//! docs/superpowers/specs/2026-11-17-pqchat-core.md). It owns the state machine (what to build, when, from which reads, and what
//! to show); every key operation, signature and chain read goes through the SDK, every Matrix call through the transport trait
//! the app implements. No cryptography, no signed or encrypted byte format, no key byte (CLI-PQC-03). UNAUDITED.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

pub mod chain_state;
pub mod chain_store;
pub mod check;
pub mod content;
pub mod drops;
pub mod error;
pub mod matrix;
pub mod message;
pub mod model;
pub mod net;
pub mod order;
pub mod reads;
pub mod session;
pub mod store;
pub mod stores;

pub use drops::{Drop, DropCounts};
pub use error::PqChatError;
pub use store::{Item, Items, MemoryStore, PqChatStore, StoreFault};

use scaas_sdk::app_core::{AppCore, AppDesc};
use scaas_sdk::Sdk;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

/// PqChat's label prefix (CLI-PQC-03): the one the crate declares to the SDK.
pub const LABELS: &str = "scaas/pqchat/v1/";
/// `PqChat`'s factory class (CTR-CHAT-02).
pub const CLASS: u16 = 3;

/// The crate's SDK scope: PqChat's label prefix and class 3, no app purpose (its records are signed by the SDK's PqChat
/// entries under `PURPOSE_PQCHAT`, CLI-PQC-04).
pub fn scope(sdk: &Arc<Sdk>) -> Result<Arc<AppCore>, PqChatError> {
    Ok(AppCore::new(
        sdk.clone(),
        AppDesc {
            app_id: None,
            name: "PqChat".into(),
            class: Some(CLASS),
            labels: vec![LABELS.into()],
        },
    )?)
}

/// One chain the app serves PqChat on: the SDK profile's key and the contracts the crate reads there.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainConf {
    /// the SDK profile's key
    pub chain: String,
    pub chain_uid: String,
    pub registry: String,
    pub factory: String,
}

/// The crate's configuration: the chains it serves.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PqChatConfig {
    pub chains: Vec<ChainConf>,
}

/// The PqChat client core: one per process, over one app-core scope of the SDK.
pub struct PqChat {
    pub(crate) app: Arc<AppCore>,
    pub(crate) net: Arc<dyn net::Net>,
    pub(crate) store: Arc<dyn PqChatStore>,
    pub(crate) conf: PqChatConfig,
    pub(crate) drops: DropCounts,
    pub(crate) chains: Mutex<message::Chains>,
    pub(crate) unwraps: AtomicU64,
    pub(crate) events: Mutex<Events>,
    /// complete children seen before their finality, by parent (CLI-PQC-07: sends held)
    pub(crate) unfinal: Mutex<std::collections::HashMap<String, String>>,
    pub(crate) in_use: Mutex<message::InUse>,
    pub(crate) timelines: Mutex<std::collections::HashMap<String, order::Timeline>>,
    pub(crate) matrix: Mutex<Option<Arc<dyn matrix::MatrixTransport>>>,
}

/// What the crate tells the app (spec §8); ids and UAs only, never a secret, handle, ciphertext, room id or Matrix id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// `member` holds a KEM version above the highest seen: a rekey is the user's choice, never started by the crate
    KemVersionRaised { session: String, member: String },
    /// a rekey by `author` lists a store the user has not confirmed (CLI-PQC-06); `by_admin` false flags a member's change
    StoresChanged {
        session: String,
        author: String,
        by_admin: bool,
    },
    /// `missed` events dropped, the queue full
    Lagged { missed: u64 },
}

/// Events kept until the app pulls them.
pub const EVENTS_MAX: usize = 256;

/// The bounded event queue: the oldest dropped and counted when full.
#[derive(Default)]
pub(crate) struct Events {
    q: std::collections::VecDeque<Event>,
    missed: u64,
}

impl PqChat {
    /// The crate over `sdk`: its scope declares PqChat's label prefix and class 3; reads and writes through the SDK.
    pub fn new(
        sdk: Arc<Sdk>,
        store: Arc<dyn PqChatStore>,
        conf: PqChatConfig,
    ) -> Result<Arc<Self>, PqChatError> {
        let app = scope(&sdk)?;
        let net = Arc::new(net::SdkNet {
            sdk,
            app: app.clone(),
        });
        Ok(Self::with_net(app, net, store, conf))
    }

    /// The crate over a scope and a chain port of the caller's (the tests' recording fakes).
    pub fn with_net(
        app: Arc<AppCore>,
        net: Arc<dyn net::Net>,
        store: Arc<dyn PqChatStore>,
        conf: PqChatConfig,
    ) -> Arc<Self> {
        Arc::new(PqChat {
            app,
            net,
            store,
            conf,
            drops: DropCounts::default(),
            chains: Mutex::new(message::Chains::default()),
            unwraps: AtomicU64::new(0),
            events: Mutex::new(Events::default()),
            unfinal: Mutex::new(Default::default()),
            in_use: Mutex::new(Default::default()),
            timelines: Mutex::new(Default::default()),
            matrix: Mutex::new(None),
        })
    }

    /// The drops of `session` per reason, on this device only (CLI-PQC-07).
    pub fn dropped(&self, session: &str) -> std::collections::BTreeMap<Drop, u64> {
        self.drops.of(&session.to_ascii_lowercase())
    }

    /// How many own wraps reached the KEM (a test's recording of K2's unwrap).
    pub fn unwrap_calls(&self) -> u64 {
        self.unwraps.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The events since the last pull, oldest first; `Lagged` first when some were dropped.
    pub fn events(&self) -> Vec<Event> {
        let mut e = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = Vec::with_capacity(e.q.len() + 1);
        if e.missed > 0 {
            out.push(Event::Lagged { missed: e.missed });
            e.missed = 0;
        }
        out.extend(e.q.drain(..));
        out
    }

    pub(crate) fn event(&self, ev: Event) {
        let mut e = self
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        e.q.push_back(ev);
        if e.q.len() > EVENTS_MAX {
            e.q.pop_front();
            e.missed += 1;
        }
    }

    /// The app's Matrix client, after its Matrix login (Rust only, spec §11).
    pub fn attach_matrix(&self, client: Arc<dyn matrix::MatrixTransport>) {
        *self
            .matrix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(client);
    }

    /// Before the app's Matrix logout: a session listing Matrix cannot send (`MatrixDetached`); chain stores still serve.
    pub fn detach_matrix(&self) {
        *self
            .matrix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub(crate) fn matrix(&self) -> Option<Arc<dyn matrix::MatrixTransport>> {
        self.matrix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn conf(&self, chain: &str) -> Result<&ChainConf, PqChatError> {
        self.conf
            .chains
            .iter()
            .find(|c| c.chain == chain)
            .ok_or(PqChatError::InstanceUnlisted)
    }
}
