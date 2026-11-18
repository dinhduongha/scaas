// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The configuration (spec §4, CLI-SDK-15): chain profiles pinned by the app's release, never fetched and trusted; the runtime;
//! the limits. An endpoint's URL and credential never appear in a `Debug` output (CLI-RPC-11).

use crate::platform::Authenticator;
use crate::vault::SecureStore;
use scaas_rpc::{Class, EndpointAuth, Policy};
use std::sync::Arc;

/// A chain family (the `scaas-rpc` readers'). Hedera is `Evm` with its chain id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Evm,
    Soroban,
    Solana,
    Near,
    Algorand,
    Aptos,
    Sui,
    Cosmos,
    Ton,
}

/// One endpoint of a profile's RPC or gateway list (CLI-RPC-02): `{url, class, label, auth}`; `auth` belongs to this endpoint
/// only and is built by the app from its own secret source.
#[derive(Clone)]
pub struct EndpointConfig {
    pub url: String,
    pub class: Class,
    pub label: Option<String>,
    pub auth: Option<EndpointAuth>,
}

impl std::fmt::Debug for EndpointConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointConfig")
            .field("class", &self.class)
            .field("label", &self.label)
            .field("auth", &self.auth.as_ref().map(|_| "<secret>"))
            .finish()
    }
}

/// The block of every decisive and decryption read (§9.4 requirement 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finality {
    Finalized,
    Depth(u64),
}

/// A chain as the app's release pins it (spec §4). Tokens, DEXes and PQZ verifiers join with the tasks that read them.
#[derive(Debug, Clone)]
pub struct ChainProfile {
    /// `scaas-testnet`, `<chain>-mainnet`, `<chain>-testnet`
    pub key: String,
    pub family: Family,
    /// EVM and Hedera
    pub chain_id: Option<u64>,
    /// `0x` + 64 hex (NET-ALL-24): every SCaaS EIP-712 domain's salt, pinned on every connection
    pub chain_uid: String,
    pub rpc: Vec<EndpointConfig>,
    pub rpc_policy: Policy,
    /// scaas-node gateways; empty: no gateway path on this chain
    pub gateways: Vec<EndpointConfig>,
    pub registry: Option<String>,
    pub factory: Option<String>,
    pub router: Option<String>,
    pub finality: Finality,
    /// the chain's per-transaction gas cap (EIP-7825) when it has one, from the release data
    pub tx_gas_cap: Option<u64>,
}

/// The SDK's caps and queues (spec §4). The fee caps are the app's to set for its chains; the defaults below are a floor
/// against a runaway quote, never a value assumed of a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// decimal wei
    pub max_fee_per_gas: String,
    pub max_gas: u64,
    /// decimal wei
    pub max_cost: String,
    pub watch_poll_ms: u64,
    /// accounts × chains × tokens per poll
    pub max_watch: u32,
    /// scrypt, Argon2id, proofs, slow key generation at once
    pub max_concurrent_heavy: u32,
    pub event_queue: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_fee_per_gas: "1000000000000".into(),
            max_gas: 1 << 24,
            max_cost: "1000000000000000000".into(),
            watch_poll_ms: 15_000,
            max_watch: 256,
            max_concurrent_heavy: 1,
            event_queue: 1_024,
        }
    }
}

/// The tokio runtime the SDK spawns every exported async call on (§14): the app's, or one the SDK starts (two workers).
#[derive(Debug, Clone)]
pub enum RuntimeChoice {
    Adopt(tokio::runtime::Handle),
    Own,
}

/// Everything `Sdk::open` takes.
#[derive(Clone)]
pub struct SdkConfig {
    pub profiles: Vec<ChainProfile>,
    /// where the keystore and the SDK's state live (spec §6.9); `FileStore` on native by default
    pub store: Arc<dyn SecureStore>,
    /// passkeys, platform secrets, secure-element keys (spec §6.10); `None`: passphrase only
    pub authenticator: Option<Arc<dyn Authenticator>>,
    pub runtime: RuntimeChoice,
    pub limits: Limits,
}

impl std::fmt::Debug for SdkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdkConfig")
            .field("profiles", &self.profiles)
            .field("authenticator", &self.authenticator.is_some())
            .field("runtime", &self.runtime)
            .field("limits", &self.limits)
            .finish()
    }
}

/// `0x` and 64 hex digits.
pub(crate) fn is_word_hex(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
}
