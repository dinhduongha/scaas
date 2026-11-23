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

/// FRB 2's attributes as doc hints, read only by `flutter_rust_bridge_codegen`'s expansion (`--cfg frb_expand`; the SDK's
/// `frb_hint!`, plan T12); no effect on a build and no dependency. `ignore`: a Rust-only item, absent from every binding
/// (the storage interface, the chain port, the Matrix transport, spec §11).
#[allow(unused_macros)]
macro_rules! frb_hint {
    (ignore) => {
        "frb_encoded(235b6672622869676e6f7265295d)"
    };
}

pub mod chain_state;
pub mod chain_store;
pub mod check;
pub mod consent;
pub mod content;
pub mod device;
pub mod drops;
pub mod error;
pub mod file;
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub mod matrix;
pub mod message;
pub mod model;
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub mod net;
pub mod order;
pub mod reads;
pub mod recovery;
pub mod session;
pub mod signed;
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub mod store;
pub mod stores;
pub mod topics;

pub use drops::{DropCounts, DropReason};
pub use error::PqChatError;
pub use store::{Item, Items, MemoryStore, PqChatStore, StoreFault};

use scaas_sdk::app_core::{AppCore, AppDesc};
use scaas_sdk::Sdk;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

/// PqChat's label prefix (CLI-PQC-03): the one the crate declares to the SDK.
pub const LABELS: &str = "scaas/pqchat/v1/";
/// PqChat's app id (plan T10b, owner 2026-11-22): `keccak256("scaas.pqchat.v1")` (`scaas-ua` `wallet::pqchat::app_id`,
/// clientkeys `APP_ID`), the scope's storage root, from which `seal_for_arweave` derives the upload keys; no app record is
/// signed under it.
pub const APP_ID: &str = "0x0ff21b7d13e785d30f93c4ff2e8dd5a767392bb818ea221b73341d92a9f6eb9b";
/// `PqChat`'s factory class (CTR-CHAT-02).
pub const CLASS: u16 = 3;

/// The crate's SDK scope: PqChat's label prefix, class 3 and its app id [`APP_ID`] (its records are signed by the SDK's
/// PqChat entries under `PURPOSE_PQCHAT`, CLI-PQC-04, never under the app id's purpose).
pub fn scope(sdk: &Arc<Sdk>) -> Result<Arc<AppCore>, PqChatError> {
    Ok(AppCore::new(
        sdk.clone(),
        AppDesc {
            app_id: Some(APP_ID.into()),
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
    /// CLI-PQC-15 (owner 2026-11-23): also refuse a home that keeps no signatures (`sigStore` `none`). Off by default: an
    /// `sstore2` home is verified either way (no switch turns that off), a `none` home is read on the contract's check.
    #[serde(default)]
    pub require_signed_records: bool,
    /// CLI-PQC-16 (owner 2026-11-23, option d): the control-plane reads at an instance (`IPqChat`'s trusted views) as agreed
    /// reads (strict majority, CLI-RPC-05) whatever the chain's list policy. Off by default, never forced.
    #[serde(default)]
    pub agreed_reads: bool,
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
    /// the seed is locked: Matrix events are kept, never read (CLI-PQC-10)
    pub(crate) seed_locked: std::sync::atomic::AtomicBool,
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
    /// the session's Matrix room is not used (CLI-PQC-05's binding): the reason, shown with the session
    RoomNotUsed {
        session: String,
        reason: matrix::RoomRefusal,
    },
    /// recovery's progress on `chain`: instances read of all, sessions found so far
    RecoveryProgress {
        chain: String,
        instances_done: u64,
        instances: u64,
        found: u64,
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
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub fn new(
        sdk: Arc<Sdk>,
        store: Arc<dyn PqChatStore>,
        conf: PqChatConfig,
    ) -> Result<Arc<Self>, PqChatError> {
        let app = scope(&sdk)?;
        let sdk_net = net::SdkNet {
            sdk,
            app: app.clone(),
        };
        let net: Arc<dyn net::Net> = if conf.agreed_reads {
            Arc::new(net::AgreedNet(sdk_net))
        } else {
            Arc::new(sdk_net)
        };
        Ok(Self::with_net(app, net, store, conf))
    }

    /// The crate over a scope and a chain port of the caller's (the tests' recording fakes).
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
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
            seed_locked: Default::default(),
        })
    }

    /// The drops of `session` per reason, on this device only (CLI-PQC-07).
    pub fn dropped(&self, session: &str) -> std::collections::BTreeMap<DropReason, u64> {
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
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
    pub fn attach_matrix(&self, client: Arc<dyn matrix::MatrixTransport>) {
        *self
            .matrix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(client);
    }

    /// Before the app's Matrix logout: a session listing Matrix cannot send (`MatrixDetached`); chain stores still serve.
    #[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
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

    pub(crate) fn is_locked(&self) -> bool {
        self.seed_locked.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn set_locked(&self, on: bool) {
        self.seed_locked
            .store(on, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn conf(&self, chain: &str) -> Result<&ChainConf, PqChatError> {
        self.conf
            .chains
            .iter()
            .find(|c| c.chain == chain)
            .ok_or(PqChatError::InstanceUnlisted)
    }
}
