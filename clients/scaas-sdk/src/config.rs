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
    /// first in every lookup, base and verify each on its own
    pub gas: GasRows,
    /// the further gas tables this chain uses, by name, only because it names them here (explicit opt-in): module tables of
    /// [`SdkConfig::gas_tables`] in this order, and `"reference"` for the SDK's forge-generated reference table, read after
    /// every module table; a name the SDK does not hold is `Argument` at `Sdk::open`
    pub gas_opt_in: Vec<String>,
    /// the longest an operation's `validUntil` may lie ahead of the SDK's clock on this chain, in seconds; `None`:
    /// `Limits::max_valid_secs` (default 86 400, one day) (owner 2026-11-19, T13b ruling 1)
    pub max_valid_secs: Option<u64>,
}

/// A base row (gas table v2, owner 2026-11-19): the execution gas of `entry` (`mtxCancelNonce`, `mtxExecuteTransfer`, …) on a
/// contract of domain kind `kind` (`token`, `zether`, `pqz`, `wallet`, `account`, `dex`, `gov_router`), on a lane whose nonce
/// is 0 (`fresh`) or above, signed by the reference signer, a native EVM key (its path makes no registry call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasBase {
    pub entry: String,
    pub kind: String,
    pub fresh: bool,
    pub gas: u64,
    /// the part that grows with an input's length (owner 2026-11-19, ruling B)
    pub per_byte: Option<GasPerByte>,
    /// the fixed gas added when the operation saves its `PayMeta` record (owner 2026-11-19, ruling 1)
    pub save: Option<u64>,
    /// the gas added when the operation's fee is > 0, measured paying a recipient holding nothing (owner 2026-11-19, ruling 3)
    pub fee_extra: Option<u64>,
    /// the regular gas a derived-UA signer adds on this entry over the native reference signer, beyond its verify row (owner
    /// 2026-11-19, A1: a derived id's ledger debit); added when the signer is a derived UA. `None`: nothing added
    pub ua_extra: Option<u64>,
    /// the part that grows with a count the operation names (owner 2026-11-19, I1); `None`: no count, nothing added
    pub per_item: Option<GasPerItem>,
}

/// A row's per-item part (owner 2026-11-19, I1), on a base or a verify row: `gas` (whole gas, the measured slope rounded
/// up) for each counted `item` of the operation, one of `GAS_ITEMS` (`legs`, `accounts`, `entries`, `members`,
/// `env_items`, `orders`). The row's own `gas` is its figure at a count of 0 (the line's intercept; the file states
/// `"base_count": 0`), so the quote adds `gas × count` with no offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasPerItem {
    pub item: String,
    pub gas: u64,
}

/// A base row's per-byte part (owner 2026-11-19, ruling B): `gas` (whole gas, rounded up) for each byte of the operation's
/// variable-length `input`: `meta.body` (a pay entry's `PayMeta` body, as encoded) or `data` (`mtxExecute`'s call data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasPerByte {
    pub input: String,
    pub gas: u64,
}

/// A verify row (gas table v2): what a signer of UA kind `signer` (`0`: a native EVM key, the reference) adds over the
/// reference signer's execution gas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasVerify {
    pub signer: u16,
    pub gas: u64,
    /// the signer kind's signature length in calldata, `UASig` key data and signature ABI-padded (owner 2026-11-19, ruling
    /// 2; for an `msig`, per member); the quote adds 64 gas a byte of it. Required in every row (owner 2026-11-19, A4); a
    /// variable-length kind's longest (A5)
    pub sig_bytes: u64,
    /// a safety margin added to the row's gas, where the kind's worst case cannot be determined and the row is the most
    /// expensive of many measurements (owner 2026-11-19, the sampled check's ruling 2 (b)); 0 when absent
    pub margin: u64,
    /// the part that grows with a count of the signer's (owner 2026-11-19, I1: `members`, a `0x0121` UA's n); `None`: none
    pub per_item: Option<GasPerItem>,
}

/// The rows of a gas table: base and verify, looked up independently (spec §13.3). The quote's figure is base + verify.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GasRows {
    pub base: Vec<GasBase>,
    pub verify: Vec<GasVerify>,
}

/// A gas table file (spec §13.3, the gas table format): `{format: "scaas.gas-table", v: 2, name, family, assumptions, base,
/// verify}`, each base row `{entry, kind, fresh, gas, measured, source, calldata_gas?, per_byte?: {input, gas, source},
/// save?: {gas, measured, source}, fee_extra?: {gas, measured, source}, ua_extra?: {gas, measured, source}, item?,
/// per_item?: {gas, base_count, source}, stand_in?}`, each verify row `{signer, gas, measured, source, sig_bytes, margin?,
/// item?, per_item?, stand_in?}`, read by [`GasTable::parse`]. One format for the chain's measured rows, a module's table
/// and the SDK's reference table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasTable {
    /// a module's name, `reference`, or the chain key of a chain's measured rows
    pub name: String,
    /// `evm` (the only family with a table today)
    pub family: String,
    pub rows: GasRows,
}

/// Bounds of a gas table's parse.
/// W3 (owner 2026-11-19, "approved"): 1 MiB, headroom over the full reference table (about 0.2 MB) and its growth.
const GAS_TABLE_MAX_BYTES: usize = 1024 * 1024;
const GAS_TABLE_MAX_ROWS: usize = 1_024;
const GAS_NAME_MAX: usize = 64;
/// A per-byte part's inputs and bound.
const GAS_PER_BYTE_INPUTS: [&str; 2] = ["meta.body", "data"];
const GAS_PER_BYTE_MAX: u64 = 1_000;
/// A verify row's largest `sig_bytes` (SLH-DSA-128s, the longest, is 7,872).
const GAS_SIG_BYTES_MAX: u64 = 65_536;
/// A verify row's largest `margin`.
const GAS_MARGIN_MAX: u64 = 100_000;
/// The counts a row's `item` may name (owner 2026-11-19, I1; K2 and P1 add `env_items` and `orders`), each read from the
/// operation by `op::gas::item_count`: `legs` (a multi-recipient transfer's `args.legs`, a list parameter `legs`,
/// `mtxCreateToken`'s `extra.config.legs`), `accounts` (`uas` of `mtxRollOverBatch`, a list parameter `accounts`),
/// `entries` (a PQZ rollover's `n` and its `skip` marks), `members` (a `0x0121` signer's n; not read by the SDK yet),
/// `env_items` (an env publish's four `Env` arrays), `orders` (a DEX cancel's orders).
pub(crate) const GAS_ITEMS: [&str; 6] = ["legs", "accounts", "entries", "members", "env_items", "orders"];
/// A per-item part's largest `gas`: EIP-7825's transaction cap, 2^24 (a Zether leg is about 3.1 M).
const GAS_PER_ITEM_MAX: u64 = 1 << 24;

/// A figure rounded up to the next 1,000 from `measured` (owner 2026-11-19): a multiple of 1,000, `measured <= gas < measured +
/// 1000`.
fn rounded(gas: u64, measured: u64) -> bool {
    gas.is_multiple_of(1_000) && measured <= gas && gas - measured < 1_000
}

impl GasTable {
    /// Parses and checks a gas table file: at most 1 MiB and 1,024 rows (base and verify together); the format and version
    /// 2; `name`, `entry` and `kind` 1–64 characters of `[A-Za-z0-9_:.-]`; `signer` a `u16`; each `gas` a multiple of 1,000
    /// with `measured <= gas < measured + 1000` (owner 2026-11-19: rounded up to the next 1,000), a base row's positive (a
    /// verify row's may be 0: the reference signer's own row); `source` present; a base row's optional `per_byte` names an
    /// input of [`GasPerByte`] with a `gas` of 1–1,000 and its `source`; a base row's optional `save`, `fee_extra` and
    /// `ua_extra` are `{gas, measured, source}` held like a row's figure, positive; a verify row's `sig_bytes` at most 65,536,
    /// its optional `margin` 1–100,000; a base or verify row's optional `item` and `per_item` come together (owner 2026-11-19,
    /// I1), `item` one of `GAS_ITEMS` (`legs`, `accounts`, `entries`, `members`, `env_items`, `orders`), `per_item` `{gas,
    /// base_count, source}` with a `gas` of 1–2^24 and `base_count` 0 (the row's figure is at a count of 0); no key twice.
    /// By name when the file is otherwise sound (the first such fault): `GasSigBytesMissing` when a verify row has no
    /// `sig_bytes` (owner 2026-11-19, A4), `GasItemUnpaired` when a row has `per_item` without `item` or the reverse,
    /// `GasItemUnknown` when an `item` is not one of `GAS_ITEMS`; `Argument` on any other failure.
    pub fn parse(text: &str) -> Result<GasTable, crate::SdkError> {
        match Self::parse_inner(text) {
            Some((t, None)) => Ok(t),
            Some((_, Some(named))) => Err(named),
            None => Err(crate::SdkError::Argument),
        }
    }

    /// The table, and the first fault refused by name (the row read on so the rest is still checked).
    fn parse_inner(text: &str) -> Option<(GasTable, Option<crate::SdkError>)> {
        if text.len() > GAS_TABLE_MAX_BYTES {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(text).ok()?;
        if v.get("format")?.as_str()? != "scaas.gas-table" || v.get("v")?.as_u64()? != 2 {
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
        // the figure, held to its measurement and its source
        let figure = |r: &serde_json::Value| {
            let gas = r.get("gas")?.as_u64()?;
            let measured = r.get("measured")?.as_u64()?;
            r.get("source")?.as_str().filter(|s| !s.is_empty())?;
            rounded(gas, measured).then_some(gas)
        };
        let (base, verify) = (v.get("base")?.as_array()?, v.get("verify")?.as_array()?);
        if base.len().saturating_add(verify.len()) > GAS_TABLE_MAX_ROWS {
            return None;
        }
        let mut rows = GasRows::default();
        let mut named = None;
        for r in base {
            let row = GasBase {
                entry: name(r, "entry")?,
                kind: name(r, "kind")?,
                fresh: r.get("fresh")?.as_bool()?,
                gas: figure(r).filter(|g| *g > 0)?,
                save: match r.get("save") {
                    None => None,
                    Some(x) => Some(figure(x).filter(|g| *g > 0)?),
                },
                fee_extra: match r.get("fee_extra") {
                    None => None,
                    Some(x) => Some(figure(x).filter(|g| *g > 0)?),
                },
                ua_extra: match r.get("ua_extra") {
                    None => None,
                    Some(x) => Some(figure(x).filter(|g| *g > 0)?),
                },
                per_byte: match r.get("per_byte") {
                    None => None,
                    Some(p) => {
                        p.get("source")?.as_str().filter(|s| !s.is_empty())?;
                        Some(GasPerByte {
                            input: name(p, "input")
                                .filter(|i| GAS_PER_BYTE_INPUTS.contains(&i.as_str()))?,
                            gas: p
                                .get("gas")?
                                .as_u64()
                                .filter(|g| (1..=GAS_PER_BYTE_MAX).contains(g))?,
                        })
                    }
                },
                per_item: per_item(r, &mut named)?,
            };
            if rows.base.iter().any(|o| o.key() == row.key()) {
                return None;
            }
            rows.base.push(row);
        }
        for r in verify {
            let row = GasVerify {
                signer: u16::try_from(r.get("signer")?.as_u64()?).ok()?,
                gas: figure(r)?,
                sig_bytes: match r.get("sig_bytes") {
                    None => {
                        named.get_or_insert(crate::SdkError::GasSigBytesMissing);
                        0
                    }
                    Some(b) => b.as_u64().filter(|b| *b <= GAS_SIG_BYTES_MAX)?,
                },
                margin: match r.get("margin") {
                    None => 0,
                    Some(m) => m.as_u64().filter(|m| (1..=GAS_MARGIN_MAX).contains(m))?,
                },
                per_item: per_item(r, &mut named)?,
            };
            if rows.verify.iter().any(|o| o.signer == row.signer) {
                return None;
            }
            rows.verify.push(row);
        }
        let t = GasTable {
            name: name(&v, "name")?,
            family: name(&v, "family")?,
            rows,
        };
        Some((t, named))
    }
}

/// A row's `item` and `per_item` (owner 2026-11-19, I1), together: `Some(None)` when the row has neither, or on a fault refused
/// by name (recorded in `named` if it is the first; the part's shape is still checked); `None` on any other fault.
fn per_item(
    r: &serde_json::Value,
    named: &mut Option<crate::SdkError>,
) -> Option<Option<GasPerItem>> {
    let (item, p) = match (r.get("item"), r.get("per_item")) {
        (None, None) => return Some(None),
        (Some(i), Some(p)) => (i.as_str()?, p),
        (_, p) => {
            if let Some(p) = p {
                per_item_gas(p)?;
            }
            named.get_or_insert(crate::SdkError::GasItemUnpaired);
            return Some(None);
        }
    };
    let gas = per_item_gas(p)?;
    if !GAS_ITEMS.contains(&item) {
        named.get_or_insert(crate::SdkError::GasItemUnknown);
        return Some(None);
    }
    Some(Some(GasPerItem {
        item: item.to_string(),
        gas,
    }))
}

/// A per-item part's `{gas, base_count, source}` (owner 2026-11-19, I1): its `gas` of 1–2^24, `base_count` 0 (the row's
/// figure is at a count of 0), `source` present.
fn per_item_gas(p: &serde_json::Value) -> Option<u64> {
    p.get("source")?.as_str().filter(|s| !s.is_empty())?;
    (p.get("base_count")?.as_u64()? == 0).then_some(())?;
    p.get("gas")?
        .as_u64()
        .filter(|g| (1..=GAS_PER_ITEM_MAX).contains(g))
}

impl GasBase {
    pub(crate) fn key(&self) -> (&str, &str, bool) {
        (&self.entry, &self.kind, self.fresh)
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
