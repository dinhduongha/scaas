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

pub mod config;
pub mod error;

pub use config::{
    ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, SdkConfig,
};
pub use error::SdkError;

use scaas_rpc::endpoint::{READ_TIMEOUT_MS, SLOW_TIMEOUT_MS, TIMEOUT_MS};
use scaas_rpc::{Endpoint, NodeList};
use std::collections::HashSet;
use std::sync::Arc;

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
#[allow(dead_code)] // used by the exported calls (T3 on)
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
    #[allow(dead_code)]
    pub(crate) rt: Option<Rt>,
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
        Ok(Arc::new(Sdk {
            chains,
            limits: config.limits,
            rt,
        }))
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
