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
    /// the reviewed token list (spec §8.2): a token not on it is `unlisted` wherever it is shown
    pub tokens: Vec<ListedToken>,
    /// gas figures measured on this chain, shipped with its release data (owner 2026-11-19, gas-table rulings; spec §13.3);
    /// first in every lookup
    pub gas: Vec<GasRow>,
    /// the further gas tables this chain uses, by name, only because it names them here (explicit opt-in): module tables of
    /// [`SdkConfig::gas_tables`] in this order, and `"reference"` for the SDK's forge-generated reference table, read after
    /// every module table; a name the SDK does not hold is `Argument` at `Sdk::open`
    pub gas_opt_in: Vec<String>,
    /// the longest an operation's `validUntil` may lie ahead of the SDK's clock on this chain, in seconds; `None`:
    /// `Limits::max_valid_secs` (default 86 400, one day) (owner 2026-11-19, T13b ruling 1)
    pub max_valid_secs: Option<u64>,
}

/// One row of a profile's gas table: the execution gas of `entry` (`mtxCancelNonce`, `mtxExecuteTransfer`, …) on a contract of
/// domain kind `kind` (`token`, `zether`, `pqz`, `wallet`, `account`, `dex`, `gov_router`), signed by a key of UA kind
/// `signer` (`0`: a native EVM key), on a lane whose nonce is 0 (`fresh`) or above. The quote adds the intrinsic cost, the
/// calldata and the margin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasRow {
    pub entry: String,
    pub kind: String,
    pub signer: u16,
    pub fresh: bool,
    pub gas: u64,
}

/// A gas table file (spec §13.3, the gas table format): `{format: "scaas.gas-table", v: 1, name, family, assumptions,
/// rows}`, each row `{entry, kind, signer, fresh, gas, measured, source, stand_in?}`, read by [`GasTable::parse`]. One format
/// for the chain's measured rows, a module's table and the SDK's reference table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasTable {
    /// a module's name, `reference`, or the chain key of a chain's measured rows
    pub name: String,
    /// `evm` (the only family with a table today)
    pub family: String,
    pub rows: Vec<GasRow>,
}

/// Bounds of a gas table's parse.
const GAS_TABLE_MAX_BYTES: usize = 256 * 1024;
const GAS_TABLE_MAX_ROWS: usize = 1_024;
const GAS_NAME_MAX: usize = 64;

impl GasTable {
    /// Parses and checks a gas table file: at most 256 KiB and 1,024 rows; the format and version; `name`, `entry` and `kind`
    /// 1–64 characters of `[A-Za-z0-9_:.-]`; `signer` a `u16`; each `gas` a positive multiple of 1,000 with `measured <= gas
    /// < measured + 1000` (owner 2026-11-19: rounded up to the next 1,000); `source` present; no key twice. `Argument` on any
    /// failure.
    pub fn parse(text: &str) -> Result<GasTable, crate::SdkError> {
        Self::parse_inner(text).ok_or(crate::SdkError::Argument)
    }

    fn parse_inner(text: &str) -> Option<GasTable> {
        if text.len() > GAS_TABLE_MAX_BYTES {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        if v.get("format")?.as_str()? != "scaas.gas-table" || v.get("v")?.as_u64()? != 1 {
            return None;
        }
        let name = |x: &serde_json::Value, k: &str| {
            x.get(k)
                .and_then(|s| s.as_str())
                .filter(|s| {
                    !s.is_empty()
                        && s.len() <= GAS_NAME_MAX
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b))
                })
                .map(str::to_string)
        };
        let rows = v.get("rows")?.as_array()?;
        if rows.len() > GAS_TABLE_MAX_ROWS {
            return None;
        }
        let mut out: Vec<GasRow> = Vec::with_capacity(rows.len());
        for r in rows {
            let row = GasRow {
                entry: name(r, "entry")?,
                kind: name(r, "kind")?,
                signer: u16::try_from(r.get("signer")?.as_u64()?).ok()?,
                fresh: r.get("fresh")?.as_bool()?,
                gas: r.get("gas")?.as_u64()?,
            };
            let measured = r.get("measured")?.as_u64()?;
            r.get("source")?.as_str().filter(|s| !s.is_empty())?;
            if row.gas == 0
                || !row.gas.is_multiple_of(1_000)
                || measured > row.gas
                || row.gas - measured >= 1_000
            {
                return None;
            }
            if out.iter().any(|o| o.key() == row.key()) {
                return None;
            }
            out.push(row);
        }
        Some(GasTable {
            name: name(&v, "name")?,
            family: name(&v, "family")?,
            rows: out,
        })
    }
}

impl GasRow {
    pub(crate) fn key(&self) -> (&str, &str, u16, bool) {
        (&self.entry, &self.kind, self.signer, self.fresh)
    }
}

/// A token of a profile's reviewed list (spec §8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedToken {
    /// `0x` + 40 hex
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
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
    /// the longest an operation's `validUntil` may lie ahead of the SDK's clock, in seconds (the signing check's window), where
    /// a profile names none
    pub max_valid_secs: u64,
    pub event_queue: u32,
    /// how long a terminal operation row stays in `sdk.state` after it ended, in seconds (default 90 days); a non-terminal row
    /// is never pruned (owner 2026-11-19, T13b ruling 2)
    pub state_retention_secs: u64,
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
            max_valid_secs: 86_400,
            event_queue: 1_024,
            state_retention_secs: 90 * 86_400,
        }
    }
}

/// The tokio runtime the SDK spawns every exported async call on (§14): the app's, or one the SDK starts (two workers).
#[derive(Debug, Clone)]
pub enum RuntimeChoice {
    Adopt(tokio::runtime::Handle),
    Own,
}

/// The SDK's clock: unix seconds now. `None` in [`SdkConfig::clock`] is the device's clock; a test gives a fixed one (owner
/// 2026-11-19, T13b ruling 1).
pub type Clock = std::sync::Arc<dyn Fn() -> u64 + Send + Sync>;

/// Everything `Sdk::open` takes.
#[derive(Clone)]
pub struct SdkConfig {
    pub profiles: Vec<ChainProfile>,
    /// where the keystore and the SDK's state live (spec §6.9); `FileStore` on native by default
    pub store: Arc<dyn SecureStore>,
    /// passkeys, platform secrets, secure-element keys (spec §6.10); `None`: passphrase only
    pub authenticator: Option<Arc<dyn Authenticator>>,
    /// the deployment's passkey RP ID (CLI-APP-14: never a SCaaS constant); `None`: no passkey unlock
    pub rp_id: Option<String>,
    pub runtime: RuntimeChoice,
    pub limits: Limits,
    /// the clock an operation's `validUntil` is held to; `None`: the device's
    pub clock: Option<Clock>,
    /// module gas tables (a module above the SDK ships its own, [`GasTable::parse`]); a chain uses one only when its profile
    /// names it in `gas_opt_in`; the name `reference` is the SDK's own and refused here (`Argument`), as are two of one name
    pub gas_tables: Vec<GasTable>,
}

impl std::fmt::Debug for SdkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdkConfig")
            .field("profiles", &self.profiles)
            .field("authenticator", &self.authenticator.is_some())
            .field("rp_id", &self.rp_id)
            .field("runtime", &self.runtime)
            .field("limits", &self.limits)
            .field("clock", &self.clock.is_some())
            .field("gas_tables", &self.gas_tables)
            .finish()
    }
}

/// `0x` and 64 hex digits.
pub(crate) fn is_word_hex(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
}
