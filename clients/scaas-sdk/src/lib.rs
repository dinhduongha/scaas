// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas-sdk`: the one API apps call (CLI-SDK-01, docs/clients/scaas-sdk.md; spec docs/superpowers/specs/2026-11-17-scaas-sdk.md).
//! Every signature comes from `scaas-ua`, every chain read and send goes through `scaas-rpc`; the SDK holds no cryptography of
//! its own and no transport. UNAUDITED.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(not(feature = "vault"))]
compile_error!("scaas-sdk needs the feature `vault` (every module does)");

#[cfg(feature = "account")]
pub mod account;
pub mod config;
pub mod error;
pub mod events;
#[cfg(feature = "frb")]
pub mod frb;
#[cfg(feature = "wallet")]
pub mod op;
pub mod platform;
pub(crate) mod text;
pub mod vault;

pub use config::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, ListedToken, RuntimeChoice, SdkConfig,
};
pub use error::SdkError;
pub use events::{Event, InFlight, OpState, Subscription};
pub use vault::Vault;

use scaas_rpc::endpoint::{READ_TIMEOUT_MS, SLOW_TIMEOUT_MS, TIMEOUT_MS};
use scaas_rpc::{Endpoint, NodeList};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, Semaphore};

/// The binding surface's version (§16.3): starts at 1, raised by any change a generated binding could misread.
pub const API_VERSION: u32 = 1;

/// The feature bits of spec §3.3, appended only; bit 12 (the withdrawn `chat`) is never reused.
pub mod bits {
    pub const VAULT: u64 = 1 << 0;
    pub const ACCOUNT: u64 = 1 << 1;
    pub const WALLET: u64 = 1 << 2;
    pub const ZETHER: u64 = 1 << 4;
    pub const PQZ: u64 = 1 << 5;
    pub const PQZ_SET_N2048_KMAX1024: u64 = 1 << 6;
    pub const PQZ_SET_N2304_KMAX4096: u64 = 1 << 7;
    pub const PQZ_SET_N2560_KMAX16384: u64 = 1 << 8;
    pub const PQZ_SET_N2816_KMAX65536: u64 = 1 << 9;
    pub const DEX: u64 = 1 << 10;
    pub const ADMIN: u64 = 1 << 11;
    pub const MLOCK: u64 = 1 << 13;
    pub const SOROBAN: u64 = 1 << 14;
    pub const SOLANA: u64 = 1 << 15;
    pub const NEAR: u64 = 1 << 16;
    pub const ALGORAND: u64 = 1 << 17;
    pub const APTOS: u64 = 1 << 18;
    pub const SUI: u64 = 1 << 19;
    pub const COSMOS: u64 = 1 << 20;
    pub const TON: u64 = 1 << 21;
    pub const FILE_STORE: u64 = 1 << 22;
    pub const CLASSICAL_ROOTS: u64 = 1 << 24;
    pub const OPAQUE_CALLS: u64 = 1 << 25;
}

/// The bits of this build's features.
pub fn features() -> u64 {
    use bits::*;
    let on = [
        (cfg!(feature = "vault"), VAULT),
        (cfg!(feature = "account"), ACCOUNT),
        (cfg!(feature = "wallet"), WALLET),
        (cfg!(feature = "zether"), ZETHER),
        (cfg!(feature = "pqz"), PQZ),
        (
            cfg!(feature = "pqz-set-n2048-kmax1024"),
            PQZ_SET_N2048_KMAX1024,
        ),
        (
            cfg!(feature = "pqz-set-n2304-kmax4096"),
            PQZ_SET_N2304_KMAX4096,
        ),
        (
            cfg!(feature = "pqz-set-n2560-kmax16384"),
            PQZ_SET_N2560_KMAX16384,
        ),
        (
            cfg!(feature = "pqz-set-n2816-kmax65536"),
            PQZ_SET_N2816_KMAX65536,
        ),
        (cfg!(feature = "dex"), DEX),
        (cfg!(feature = "admin"), ADMIN),
        (cfg!(feature = "mlock"), MLOCK),
        (cfg!(feature = "soroban"), SOROBAN),
        (cfg!(feature = "solana"), SOLANA),
        (cfg!(feature = "near"), NEAR),
        (cfg!(feature = "algorand"), ALGORAND),
        (cfg!(feature = "aptos"), APTOS),
        (cfg!(feature = "sui"), SUI),
        (cfg!(feature = "cosmos"), COSMOS),
        (cfg!(feature = "ton"), TON),
        (cfg!(feature = "file-store"), FILE_STORE),
        (cfg!(feature = "classical-roots"), CLASSICAL_ROOTS),
        (cfg!(feature = "opaque-calls"), OPAQUE_CALLS),
    ];
    on.iter()
        .filter(|(enabled, _)| *enabled)
        .fold(0, |acc, (_, bit)| acc | bit)
}

/// A chain as the SDK holds it once its profile passed `Sdk::open`'s checks: the profile and its built lists.
#[allow(dead_code)] // read by the network tasks (T10 on)
pub(crate) struct Chain {
    pub(crate) profile: ChainProfile,
    pub(crate) rpc: NodeList,
    pub(crate) gateways: Option<NodeList>,
}

/// The runtime every exported async call is spawned on (§14). An owned one shuts down in the background when the SDK goes, so
/// dropping the SDK from inside an async context never blocks.
pub(crate) struct Rt {
    pub(crate) handle: tokio::runtime::Handle,
    #[cfg(not(target_arch = "wasm32"))]
    owned: Option<tokio::runtime::Runtime>,
}

impl Drop for Rt {
    fn drop(&mut self) {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(rt) = self.owned.take() {
            rt.shutdown_background();
        }
    }
}

/// The top object (spec §4).
pub struct Sdk {
    #[allow(dead_code)]
    pub(crate) chains: Vec<Chain>,
    pub(crate) limits: Limits,
    pub(crate) rt: Option<Rt>,
    pub(crate) authenticator: Option<Arc<dyn platform::Authenticator>>,
    pub(crate) rp_id: Option<String>,
    pub(crate) keystore: vault::KeystoreFile,
    pub(crate) events: broadcast::Sender<Event>,
    pub(crate) heavy: Arc<Semaphore>,
    /// heavy jobs running now and the most seen at once (`heavy_peak`)
    heavy_now: Arc<std::sync::atomic::AtomicU32>,
    heavy_max: Arc<std::sync::atomic::AtomicU32>,
    /// the seeds unlocked in this session, by id
    pub(crate) open: Mutex<HashMap<String, Arc<vault::OpenSeed>>>,
    /// hidden sets of this session: session id -> (its seed's id, its wallet); never written
    pub(crate) hidden: Mutex<HashMap<String, (String, Arc<vault::OpenSeed>)>>,
    /// the store of the keystore and of `sdk.state` (spec §6.9)
    #[allow(dead_code)]
    pub(crate) store: Arc<dyn vault::SecureStore>,
    /// the operations prepared in this session, by id (spec §13.1: a `Prepared` not here is `PreparedUnknown`)
    #[cfg(feature = "wallet")]
    pub(crate) prepared: Mutex<HashMap<String, Arc<op::Prepared>>>,
}

impl Sdk {
    /// Checks the configuration and builds the endpoint lists; no network I/O. Refuses: a profile without a `0x` + 64 hex
    /// `chain_uid` and two profiles with one `key` (`Argument`); an empty RPC list (`EndpointListEmpty`); `strict_majority` with
    /// one endpoint, a scheme other than `http` / `https`, or two equal endpoints (`scaas-rpc`'s codes).
    pub async fn open(config: SdkConfig) -> Result<Arc<Sdk>, SdkError> {
        let mut keys = HashSet::new();
        let mut chains = Vec::with_capacity(config.profiles.len());
        for p in config.profiles {
            if !config::is_word_hex(&p.chain_uid) {
                return Err(SdkError::Argument);
            }
            if !keys.insert(p.key.clone()) {
                return Err(SdkError::Argument);
            }
            let rpc = list(&p.rpc, p.rpc_policy)?;
            let gateways = if p.gateways.is_empty() {
                None
            } else {
                Some(list(&p.gateways, scaas_rpc::Policy::Failover)?)
            };
            chains.push(Chain {
                profile: p,
                rpc,
                gateways,
            });
        }
        let rt = runtime(config.runtime)?;
        let keystore = vault::KeystoreFile::new(config.store.clone());
        // the keystore is read once here: a container this build refuses is refused at open
        keystore.load().await?;
        let (events, _) = broadcast::channel(config.limits.event_queue.max(1) as usize);
        let heavy = Arc::new(Semaphore::new(
            config.limits.max_concurrent_heavy.max(1) as usize
        ));
        Ok(Arc::new(Sdk {
            chains,
            limits: config.limits,
            rt,
            authenticator: config.authenticator,
            rp_id: config.rp_id,
            keystore,
            events,
            heavy,
            heavy_now: Arc::default(),
            heavy_max: Arc::default(),
            open: Mutex::new(HashMap::new()),
            hidden: Mutex::new(HashMap::new()),
            store: config.store,
            #[cfg(feature = "wallet")]
            prepared: Mutex::new(HashMap::new()),
        }))
    }

    /// Runs `f` on the SDK's runtime and waits for it (spec §14): a generator that polls the caller's future from a foreign
    /// executor never runs I/O outside a reactor, a dropped caller future leaves the task to complete, and a panic inside it is
    /// `Internal`. Rust-only (outside the binding surface).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn spawn<T: Send + 'static>(
        &self,
        f: impl Future<Output = Result<T, SdkError>> + Send + 'static,
    ) -> Result<T, SdkError> {
        match &self.rt {
            Some(rt) => rt.handle.spawn(f).await.map_err(|_| SdkError::Internal)?,
            None => f.await,
        }
    }

    /// wasm32: one thread, the page's event loop; `f` is awaited where it is called (the RPC transport's futures are not
    /// `Send` there, so no runtime handle could take them).
    #[cfg(target_arch = "wasm32")]
    pub async fn spawn<T: 'static>(
        &self,
        f: impl Future<Output = Result<T, SdkError>> + 'static,
    ) -> Result<T, SdkError> {
        f.await
    }

    /// `f` off the async workers, at most `Limits::max_concurrent_heavy` at once (scrypt, Argon2id, proofs, slow keygen).
    pub(crate) async fn heavy<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> Result<T, SdkError> + Send + 'static,
    ) -> Result<T, SdkError> {
        use std::sync::atomic::Ordering::SeqCst;
        let _permit = self.heavy.acquire().await.map_err(|_| SdkError::Internal)?;
        let (now, max) = (self.heavy_now.clone(), self.heavy_max.clone());
        tokio::task::spawn_blocking(move || {
            max.fetch_max(now.fetch_add(1, SeqCst) + 1, SeqCst);
            let r = f();
            now.fetch_sub(1, SeqCst);
            r
        })
        .await
        .map_err(|_| SdkError::Internal)?
    }

    /// The most heavy jobs (scrypt, Argon2id, proofs) seen running at once in this SDK: a check of
    /// `Limits::max_concurrent_heavy` (Rust-only).
    pub fn heavy_peak(&self) -> u32 {
        self.heavy_max.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    /// A subscription to the SDK's events (spec §14).
    pub fn subscribe(&self) -> Arc<Subscription> {
        Subscription::new(&self.events)
    }

    /// The app's authenticator, if any (Rust-only).
    pub fn authenticator(&self) -> Option<Arc<dyn platform::Authenticator>> {
        self.authenticator.clone()
    }

    /// The seed module.
    pub fn vault(self: &Arc<Self>) -> Arc<Vault> {
        Arc::new(Vault { sdk: self.clone() })
    }

    /// The binding surface's version (§16.3).
    pub fn api_version() -> u32 {
        API_VERSION
    }

    /// This build's feature bits (§3.3).
    pub fn features() -> u64 {
        features()
    }

    /// The limits in force.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
}

fn list(entries: &[EndpointConfig], policy: scaas_rpc::Policy) -> Result<NodeList, SdkError> {
    let endpoints = entries
        .iter()
        .map(|e| Endpoint::new(&e.url, e.class, e.label.as_deref(), e.auth.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NodeList::new(
        endpoints,
        policy,
        TIMEOUT_MS,
        SLOW_TIMEOUT_MS,
        READ_TIMEOUT_MS,
    )?)
}

#[cfg(not(target_arch = "wasm32"))]
fn runtime(choice: RuntimeChoice) -> Result<Option<Rt>, SdkError> {
    Ok(Some(match choice {
        RuntimeChoice::Adopt(handle) => Rt {
            handle,
            owned: None,
        },
        RuntimeChoice::Own => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|_| SdkError::Internal)?;
            Rt {
                handle: rt.handle().clone(),
                owned: Some(rt),
            }
        }
    }))
}

/// wasm32: the futures run on the page's event loop; an adopted handle is kept, `Own` starts nothing.
#[cfg(target_arch = "wasm32")]
fn runtime(choice: RuntimeChoice) -> Result<Option<Rt>, SdkError> {
    Ok(match choice {
        RuntimeChoice::Adopt(handle) => Some(Rt { handle }),
        RuntimeChoice::Own => None,
    })
}
