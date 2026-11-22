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

/// An attribute for `flutter_rust_bridge_codegen`'s scan of this crate (spec §16.1; plan T20), written as the doc line its `frb`
/// macro encodes (`frb_encoded(<hex of "#[frb(...)]">)`), so the SDK needs no FRB dependency: active only under the codegen's
/// `--cfg frb_expand`, no effect on a build. Use: `#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]`.
#[allow(unused_macros)]
macro_rules! frb_hint {
    // #[frb(ignore)]: a Rust-only item, or one the FRB surface (clients/scaas-sdk/ffi/src/api) wraps
    (ignore) => {
        "frb_encoded(235b6672622869676e6f7265295d)"
    };
    // #[frb(non_opaque)]: a record or enum translated field by field (FRB makes a foreign crate's data enum opaque by default)
    (non_opaque) => {
        "frb_encoded(235b667262286e6f6e5f6f7061717565295d)"
    };
    // #[frb(opaque)]: a record holding a JSON value, built and read through the FRB surface's helpers
    (opaque) => {
        "frb_encoded(235b667262286f7061717565295d)"
    };
}

#[cfg(not(feature = "vault"))]
compile_error!("scaas-sdk needs the feature `vault` (every module does)");
#[cfg(all(feature = "vectors", not(debug_assertions)))]
compile_error!("scaas-sdk's feature `vectors` is test-only: never in a release build");

#[cfg(feature = "account")]
pub mod account;
#[cfg(feature = "admin")]
pub mod admin;
#[cfg(feature = "app-core")]
pub mod app_core;
#[cfg(any(feature = "zether", feature = "pqz"))]
pub mod confidential;
pub mod config;
#[cfg(feature = "dex")]
pub mod dex;
pub mod error;
pub mod events;
#[cfg(feature = "frb")]
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub mod frb;
#[cfg(any(feature = "account", feature = "wallet"))]
pub mod line;
#[cfg(feature = "wallet")]
pub mod op;
pub mod platform;
#[cfg(feature = "pqchat-records")]
pub mod pqchat_keys;
#[cfg(feature = "pqchat-records")]
pub mod pqchat_records;
pub mod surface;
pub(crate) mod text;
pub mod vault;
#[cfg(feature = "wallet")]
pub mod wallet;
#[cfg(feature = "wallet")]
mod watch;

pub use config::{
    ChainProfile, Clock, EndpointConfig, Family, FamilyParams, Finality, GasBase, GasLine,
    GasPerByte, GasPerItem, GasRows, GasTable, GasVerify, L1Fee, Limits, ListedDex, ListedToken,
    PositionReader, RuntimeChoice, SdkConfig,
};
pub use error::SdkError;
pub use events::{Event, InFlight, OpState, Subscription};
#[cfg(any(feature = "account", feature = "wallet"))]
pub use line::UaLine;
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
    pub const NATIVE_NETWORKS: u64 = 1 << 3;
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
    pub const RAW_NATIVE: u64 = 1 << 23;
    pub const CLASSICAL_ROOTS: u64 = 1 << 24;
    pub const OPAQUE_CALLS: u64 = 1 << 25;
    pub const APP_CORE: u64 = 1 << 26;
    pub const PQCHAT_RECORDS: u64 = 1 << 27;
    /// test-only entry points (pqchat-core T1): never in a release build nor a binding
    pub const VECTORS: u64 = 1 << 28;
    /// T32's read part: native DOT on Polkadot Hub's Substrate side
    pub const SUBSTRATE: u64 = 1 << 29;
}

/// The bits of this build's features.
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub fn features() -> u64 {
    use bits::*;
    let on = [
        (cfg!(feature = "vault"), VAULT),
        (cfg!(feature = "account"), ACCOUNT),
        (cfg!(feature = "wallet"), WALLET),
        (cfg!(feature = "native-networks"), NATIVE_NETWORKS),
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
        (cfg!(feature = "raw-native"), RAW_NATIVE),
        (cfg!(feature = "classical-roots"), CLASSICAL_ROOTS),
        (cfg!(feature = "opaque-calls"), OPAQUE_CALLS),
        (cfg!(feature = "app-core"), APP_CORE),
        (cfg!(feature = "pqchat-records"), PQCHAT_RECORDS),
        (cfg!(feature = "vectors"), VECTORS),
        (cfg!(feature = "substrate"), SUBSTRATE),
    ];
    on.iter()
        .filter(|(enabled, _)| *enabled)
        .fold(0, |acc, (_, bit)| acc | bit)
}

/// A chain as the SDK holds it once its profile passed `Sdk::open`'s checks: the profile, its EVM pool, its gateway list.
pub(crate) struct Chain {
    pub(crate) profile: ChainProfile,
    /// an EVM chain's one pool for the session (closing review P2-3): its identity checks, head floors and failover counts
    /// hold across calls; pinned to the profile's `chain_uid`
    #[cfg(any(feature = "account", feature = "wallet"))]
    pub(crate) pool: Option<Arc<scaas_rpc::evm::EvmPool>>,
    #[allow(dead_code)] // the gateways of a profile without the `wallet` feature
    pub(crate) gateways: Option<NodeList>,
    /// the profile's PQZ verifiers (spec §9.3; owner 2026-11-19, T16-a)
    #[cfg(feature = "pqz")]
    pub(crate) verifiers: Option<scaas_rpc::node::VerifierClient>,
    /// a NEAR profile's family client (plan T24), named by its genesis hash: `chain_uid`'s 32 bytes in base58
    #[cfg(all(feature = "wallet", feature = "near"))]
    pub(crate) near: Option<Arc<scaas_rpc::near::Near>>,
    /// an Algorand profile's family client (plan T24), named by its genesis hash: `chain_uid`'s 32 bytes in base64
    #[cfg(all(feature = "wallet", feature = "algorand"))]
    pub(crate) algorand: Option<Arc<scaas_rpc::algorand::Algorand>>,
    /// a Cosmos profile's family client (plan T24), named by its params' chain id
    #[cfg(all(feature = "wallet", feature = "cosmos"))]
    pub(crate) cosmos: Option<Arc<scaas_rpc::cosmos::Cosmos>>,
    /// an Aptos profile's family client (plan T24), named by its params' chain id
    #[cfg(all(feature = "wallet", feature = "aptos"))]
    pub(crate) aptos: Option<Arc<scaas_rpc::aptos::Aptos>>,
    /// a Solana profile's family client (plan T24.solana), named by its genesis hash (`chain_uid`'s 32 bytes in base58), and
    /// its params' program
    #[cfg(all(feature = "wallet", feature = "solana"))]
    pub(crate) solana: Option<(Arc<scaas_rpc::solana::Solana>, [u8; 32])>,
    /// a Soroban profile's family client (plan T24.soroban), named by its params' passphrase, and the XLM SAC's contract id
    #[cfg(all(feature = "wallet", feature = "soroban"))]
    pub(crate) soroban: Option<(Arc<scaas_rpc::soroban::Soroban>, [u8; 32])>,
    /// a Sui profile's GraphQL client (plan T24.sui), named by `chain_uid` (the genesis checkpoint's digest) in base58
    #[cfg(all(feature = "wallet", feature = "sui"))]
    pub(crate) sui: Option<Arc<scaas_rpc::sui::SuiGraphql>>,
    /// a TON profile's family client (plan T24.ton): its TON Center endpoints (`rpc`); endpoint 0 is this network by the
    /// profile constant, the later ones by its masterchain block's root hash (scaas-rpc T24.6)
    #[cfg(all(feature = "wallet", feature = "ton"))]
    pub(crate) ton: Option<Arc<scaas_rpc::ton::Ton>>,
    /// a profile's Substrate side (T32's read part: Polkadot Hub), named by its params' genesis, and its SS58 prefix
    #[cfg(all(feature = "wallet", feature = "substrate"))]
    pub(crate) substrate: Option<(Arc<scaas_rpc::substrate::Substrate>, u16)>,
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
    /// the module gas tables of the configuration and the SCaaS reference table (`reference`); a chain reads one only when its
    /// profile opts in (spec §13.3)
    #[allow(dead_code)] // read by the quote (`wallet`)
    pub(crate) gas_tables: Vec<GasTable>,
    clock: Option<Clock>,
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
    /// the registry writes prepared in this session, by id (spec §7: one not here is `PreparedUnknown`)
    #[cfg(all(feature = "account", feature = "wallet"))]
    pub(crate) registry_writes: Mutex<HashMap<String, Arc<account::RegistryWrite>>>,
    /// tokens read in this session, by (chain, address) (spec §8.2: metadata read once per session)
    #[cfg(feature = "wallet")]
    pub(crate) tokens: Mutex<HashMap<(String, String), wallet::TokenInfo>>,
    /// the next transaction nonce of each payer by (chain, address) after this session's own signed transactions: a quote's
    /// floor above the endpoints' pending nonce (spec §8.5; under `strict_majority` the agreed nonce is the committed one)
    #[cfg(feature = "wallet")]
    pub(crate) sent_nonces: Mutex<HashMap<(String, String), u64>>,
    /// the watched pairs and the polls' last reads (spec §14)
    #[cfg(feature = "wallet")]
    pub(crate) watching: Mutex<watch::Watching>,
    /// `sdk.state`'s `rev` last seen by a poll or written by this SDK (R17)
    #[cfg(feature = "wallet")]
    pub(crate) state_seen: std::sync::atomic::AtomicU64,
    /// the tests' count of SCaaS signatures made (`op::submit::sign`)
    #[cfg(all(test, feature = "wallet"))]
    pub(crate) signs: std::sync::atomic::AtomicU32,
}

/// The configuration's module gas tables, then the SCaaS reference table: `Argument` for a module named `reference`, two of one
/// name, or a family other than `evm` (the only one with a table today).
fn gas_tables(modules: Vec<GasTable>) -> Result<Vec<GasTable>, SdkError> {
    let mut names = HashSet::new();
    for t in &modules {
        if t.name == "reference" || t.family != "evm" || !names.insert(t.name.clone()) {
            return Err(SdkError::Argument);
        }
    }
    #[allow(unused_mut)]
    let mut out = modules;
    #[cfg(feature = "wallet")]
    out.push(GasTable::parse(op::gas::REFERENCE_FILE)?);
    Ok(out)
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Sdk {
    /// Checks the configuration and builds the endpoint lists; no network I/O. Refuses: a profile without a `0x` + 64 hex
    /// `chain_uid` and two profiles with one `key` (`Argument`); an empty RPC list (`EndpointListEmpty`); `strict_majority` with
    /// one endpoint, a scheme other than `http` / `https`, or two equal endpoints (`scaas-rpc`'s codes); a gas opt-in naming a
    /// table the SDK does not hold (or one twice), a module gas table named `reference`, of a family other than `evm`, or two of
    /// one name (`Argument`).
    pub async fn open(config: SdkConfig) -> Result<Arc<Sdk>, SdkError> {
        let gas_tables = gas_tables(config.gas_tables)?;
        let mut keys = HashSet::new();
        let mut chains = Vec::with_capacity(config.profiles.len());
        for p in config.profiles {
            if !config::is_word_hex(&p.chain_uid) {
                return Err(SdkError::Argument);
            }
            if !keys.insert(p.key.clone()) {
                return Err(SdkError::Argument);
            }
            if p.family_params.as_ref().is_some_and(|f| !f.fits(p.family)) {
                return Err(SdkError::Argument);
            }
            // an L1 data fee model is an EVM chain's (plan T38)
            if p.l1_fee.is_some() && p.family != Family::Evm {
                return Err(SdkError::Argument);
            }
            // a disabled kind is a UA kind's name or `pqz` (owner 2026-11-22)
            if p.disabled_kinds
                .iter()
                .any(|k| k != "pqz" && !scaas_ua::KINDS.iter().any(|x| x.name == k))
            {
                return Err(SdkError::Argument);
            }
            // the DEX list and the wrapper list hold addresses (CLI-SGN-35)
            let readers = p.dexes.iter().flat_map(|d| {
                d.position_readers
                    .iter()
                    .flat_map(|r| [&r.manager, &r.reader])
            });
            if !p
                .dexes
                .iter()
                .map(|d| &d.address)
                .chain(&p.wrappers)
                .chain(readers)
                .all(|a| config::is_address_hex(a))
            {
                return Err(SdkError::Argument);
            }
            // an opt-in names a table the SDK holds, once
            let mut seen = HashSet::new();
            if !p
                .gas_opt_in
                .iter()
                .all(|n| seen.insert(n) && gas_tables.iter().any(|t| &t.name == n))
            {
                return Err(SdkError::Argument);
            }
            let rpc = list(&p.rpc, p.rpc_policy)?;
            let gateways = if p.gateways.is_empty() {
                None
            } else {
                Some(list(&p.gateways, scaas_rpc::Policy::Failover)?)
            };
            #[cfg(all(feature = "wallet", feature = "near"))]
            let near = match p.family {
                Family::Near => {
                    let uid = op::unhex(&p.chain_uid.to_ascii_lowercase())?;
                    let client = scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?;
                    Some(Arc::new(scaas_rpc::near::Near::new(
                        client,
                        &bs58::encode(uid).into_string(),
                    )))
                }
                _ => None,
            };
            #[cfg(all(feature = "wallet", feature = "algorand"))]
            let algorand = match p.family {
                Family::Algorand => {
                    use base64::Engine;
                    let uid = op::unhex(&p.chain_uid.to_ascii_lowercase())?;
                    let client = scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?;
                    Some(Arc::new(scaas_rpc::algorand::Algorand::new(
                        client,
                        &base64::engine::general_purpose::STANDARD.encode(uid),
                    )))
                }
                _ => None,
            };
            // a Cosmos profile's family client (plan T24.cosmos): its CometBFT endpoints (`rpc`) and its REST gateways, named by
            // the chain id of its params
            #[cfg(all(feature = "wallet", feature = "cosmos"))]
            let cosmos = match &p.family_params {
                Some(FamilyParams::Cosmos {
                    chain_id,
                    rest,
                    rest_policy,
                    ..
                }) => Some(Arc::new(scaas_rpc::cosmos::Cosmos::new(
                    scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?,
                    scaas_rpc::family::Client::new(list(rest, *rest_policy)?)?,
                    chain_id,
                ))),
                _ => None,
            };
            // an Aptos profile's family client (plan T24.aptos): its REST endpoints (`rpc`), named by the chain id of its
            // params; the reads use no Indexer API, so the indexer slot holds the same list, never asked
            #[cfg(all(feature = "wallet", feature = "aptos"))]
            let aptos = match &p.family_params {
                Some(FamilyParams::Aptos { chain_id, .. }) => {
                    Some(Arc::new(scaas_rpc::aptos::Aptos::new(
                        scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?,
                        scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?,
                        *chain_id,
                    )))
                }
                _ => None,
            };
            // a Solana profile's family client (plan T24.solana): its JSON-RPC endpoints (`rpc`), named by the genesis hash;
            // the params' program decoded to its 32 bytes, else `Argument`
            #[cfg(all(feature = "wallet", feature = "solana"))]
            let solana = match &p.family_params {
                Some(FamilyParams::Solana { program }) => {
                    let program: [u8; 32] = bs58::decode(program)
                        .into_vec()
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or(SdkError::Argument)?;
                    let genesis =
                        bs58::encode(op::unhex(&p.chain_uid.to_ascii_lowercase())?).into_string();
                    let client = scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?;
                    Some((
                        Arc::new(scaas_rpc::solana::Solana::new(client, &genesis)),
                        program,
                    ))
                }
                _ => None,
            };
            // a Soroban profile's family client (plan T24.soroban): its RPC endpoints (`rpc`), named by the params' passphrase,
            // whose SHA-256 (`ua-rs`'s) must be `chain_uid`; the XLM SAC decoded from its strkey, else `Argument`
            #[cfg(all(feature = "wallet", feature = "soroban"))]
            let soroban = match &p.family_params {
                Some(FamilyParams::Soroban {
                    passphrase,
                    xlm_sac,
                }) => {
                    let uid = op::unhex(&p.chain_uid.to_ascii_lowercase())?;
                    if scaas_ua::sha256(passphrase.as_bytes()).as_slice() != uid.as_slice() {
                        return Err(SdkError::Argument);
                    }
                    let sac = match wallet::families::soroban::holder(xlm_sac) {
                        Some(wallet::families::soroban::Holder::Contract(k)) => k,
                        _ => return Err(SdkError::Argument),
                    };
                    let client = scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?;
                    Some((
                        Arc::new(scaas_rpc::soroban::Soroban::new(client, passphrase)),
                        sac,
                    ))
                }
                _ => None,
            };
            // a Sui profile's GraphQL client (plan T24.sui): its params' endpoints, pinned to `chain_uid` in base58
            #[cfg(all(feature = "wallet", feature = "sui"))]
            let sui = match &p.family_params {
                Some(FamilyParams::Sui {
                    graphql,
                    graphql_policy,
                }) => {
                    let uid =
                        bs58::encode(op::unhex(&p.chain_uid.to_ascii_lowercase())?).into_string();
                    Some(Arc::new(scaas_rpc::sui::SuiGraphql::pinned(
                        scaas_rpc::family::Client::new(list(graphql, *graphql_policy)?)?,
                        Some(&uid),
                    )))
                }
                _ => None,
            };
            // a TON profile's family client (plan T24.ton): its TON Center endpoints (`rpc`)
            #[cfg(all(feature = "wallet", feature = "ton"))]
            let ton = match p.family {
                Family::Ton => Some(Arc::new(scaas_rpc::ton::Ton::new(
                    scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?,
                ))),
                _ => None,
            };
            // a profile's Substrate side (T32's read part): its params' endpoints, named by the params' genesis
            #[cfg(all(feature = "wallet", feature = "substrate"))]
            let substrate = match &p.family_params {
                Some(FamilyParams::Substrate {
                    rpc,
                    rpc_policy,
                    genesis,
                    ss58_prefix,
                }) => Some((
                    Arc::new(scaas_rpc::substrate::Substrate::new(
                        scaas_rpc::family::Client::new(list(rpc, *rpc_policy)?)?,
                        genesis,
                    )),
                    *ss58_prefix,
                )),
                _ => None,
            };
            #[cfg(any(feature = "account", feature = "wallet"))]
            let pool = match (p.family, p.chain_id) {
                (Family::Evm, Some(id)) => {
                    let uid = p.chain_uid.parse().map_err(|_| SdkError::Argument)?;
                    Some(Arc::new(scaas_rpc::evm::EvmPool::connect(
                        rpc,
                        id,
                        Some(uid),
                    )?))
                }
                _ => None,
            };
            #[cfg(not(any(feature = "account", feature = "wallet")))]
            drop(rpc);
            // T16-a: the PQZ verifiers, a list with its own policy (ARCH-POS-15)
            #[cfg(feature = "pqz")]
            let verifiers = if p.verifiers.is_empty() {
                None
            } else {
                Some(scaas_rpc::node::VerifierClient::new(list(
                    &p.verifiers,
                    p.verifier_policy,
                )?)?)
            };
            chains.push(Chain {
                profile: p,
                #[cfg(any(feature = "account", feature = "wallet"))]
                pool,
                gateways,
                #[cfg(feature = "pqz")]
                verifiers,
                #[cfg(all(feature = "wallet", feature = "near"))]
                near,
                #[cfg(all(feature = "wallet", feature = "algorand"))]
                algorand,
                #[cfg(all(feature = "wallet", feature = "cosmos"))]
                cosmos,
                #[cfg(all(feature = "wallet", feature = "aptos"))]
                aptos,
                #[cfg(all(feature = "wallet", feature = "solana"))]
                solana,
                #[cfg(all(feature = "wallet", feature = "soroban"))]
                soroban,
                #[cfg(all(feature = "wallet", feature = "sui"))]
                sui,
                #[cfg(all(feature = "wallet", feature = "ton"))]
                ton,
                #[cfg(all(feature = "wallet", feature = "substrate"))]
                substrate,
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
            gas_tables,
            clock: config.clock,
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
            #[cfg(all(feature = "account", feature = "wallet"))]
            registry_writes: Mutex::new(HashMap::new()),
            #[cfg(feature = "wallet")]
            tokens: Mutex::new(HashMap::new()),
            #[cfg(feature = "wallet")]
            sent_nonces: Mutex::new(HashMap::new()),
            #[cfg(feature = "wallet")]
            watching: Mutex::default(),
            #[cfg(feature = "wallet")]
            state_seen: std::sync::atomic::AtomicU64::new(watch::REV_UNSEEN),
            #[cfg(all(test, feature = "wallet"))]
            signs: std::sync::atomic::AtomicU32::new(0),
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
        let job = move || {
            max.fetch_max(now.fetch_add(1, SeqCst) + 1, SeqCst);
            let r = f();
            now.fetch_sub(1, SeqCst);
            r
        };
        // wasm32: no blocking pool and no runtime of the SDK's own; the page's one thread runs it (closing review P2-9)
        #[cfg(target_arch = "wasm32")]
        return job();
        #[cfg(not(target_arch = "wasm32"))]
        tokio::task::spawn_blocking(job)
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

    /// Unix seconds now on the SDK's clock (the configured one, else the device's; 0 when the device's is unreadable, which
    /// refuses every window: fail closed).
    pub(crate) fn now(&self) -> u64 {
        if let Some(c) = &self.clock {
            return c();
        }
        #[cfg(not(target_arch = "wasm32"))]
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        #[cfg(target_arch = "wasm32")]
        let t = wasmtimer::std::SystemTime::now().duration_since(wasmtimer::std::UNIX_EPOCH);
        t.map_or(0, |d| d.as_secs())
    }

    /// The signing window of chain `chain`: its profile's, else `Limits::max_valid_secs`.
    #[cfg(feature = "wallet")]
    pub(crate) fn window(&self, chain: &str) -> u64 {
        self.chains
            .iter()
            .find(|c| c.profile.key == chain)
            .and_then(|c| c.profile.max_valid_secs)
            .unwrap_or(self.limits.max_valid_secs)
    }

    /// The verifier client of chain `chain`'s PQZ verifiers (`ChainUnknown`; `VerdictRefused`: the profile lists none).
    #[cfg(feature = "pqz")]
    pub(crate) fn verifiers(
        &self,
        chain: &str,
    ) -> Result<scaas_rpc::node::VerifierClient, SdkError> {
        let c = self
            .chains
            .iter()
            .find(|c| c.profile.key == chain)
            .ok_or(SdkError::ChainUnknown)?;
        c.verifiers.clone().ok_or(SdkError::VerdictRefused)
    }

    /// An EVM chain's profile, chain id and the session's pool (`ChainUnknown`; `Argument`: not an EVM profile with a chain id).
    #[cfg(any(feature = "account", feature = "wallet"))]
    /// The chain of profile `chain` (`ChainUnknown`).
    #[cfg(feature = "wallet")]
    pub(crate) fn chain(&self, chain: &str) -> Result<&Chain, SdkError> {
        self.chains
            .iter()
            .find(|c| c.profile.key == chain)
            .ok_or(SdkError::ChainUnknown)
    }

    pub(crate) fn evm(
        &self,
        chain: &str,
    ) -> Result<(ChainProfile, u64, Arc<scaas_rpc::evm::EvmPool>), SdkError> {
        let c = self
            .chains
            .iter()
            .find(|c| c.profile.key == chain)
            .ok_or(SdkError::ChainUnknown)?;
        let id = c.profile.chain_id.ok_or(SdkError::Argument)?;
        let pool = c.pool.clone().ok_or(SdkError::Argument)?;
        Ok((c.profile.clone(), id, pool))
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
