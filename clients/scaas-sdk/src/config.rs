// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The configuration (spec §4, CLI-SDK-15): chain profiles pinned by the app's release, never fetched and trusted; the runtime;
//! the limits. An endpoint's URL and credential never appear in a `Debug` output (CLI-RPC-11).

use crate::platform::Authenticator;
use crate::vault::SecureStore;
use scaas_rpc::{Class, EndpointAuth, Policy};
use std::sync::Arc;

/// A chain family (the `scaas-rpc` readers'). Hedera is `Evm` with its chain id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct EndpointConfig {
    pub url: String,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::ClassDef"))]
    pub class: Class,
    pub label: Option<String>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::endpoint_auth"))]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Finality {
    Finalized,
    Depth(u64),
}

/// A chain as the app's release pins it (spec §4).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub struct ChainProfile {
    /// `scaas-testnet`, `<chain>-mainnet`, `<chain>-testnet`
    pub key: String,
    pub family: Family,
    /// EVM and Hedera
    pub chain_id: Option<u64>,
    /// `0x` + 64 hex (NET-ALL-24): every SCaaS EIP-712 domain's salt, pinned on every connection
    pub chain_uid: String,
    pub rpc: Vec<EndpointConfig>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::PolicyDef"))]
    pub rpc_policy: Policy,
    /// scaas-node gateways; empty: no gateway path on this chain
    pub gateways: Vec<EndpointConfig>,
    pub registry: Option<String>,
    pub factory: Option<String>,
    pub router: Option<String>,
    pub finality: Finality,
    /// the chain's per-transaction cap of the **regular** gas (EIP-7825 on a chain applying EIP-8037) when it has one, from
    /// the release data: a quote's regular bound is held to it, its gas limit (regular + state) to the block gas limit. A
    /// chain capping the whole gas limit (EIP-7825 without EIP-8037) is not supported (merged-tree review M19, 2026-11-20)
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
    /// the PQZ verifiers a verifier-mode token's verdict is asked of (spec §9.3): a list of endpoints with its own policy,
    /// `failover` (the default) or `strict_majority` (ARCH-POS-15; owner 2026-11-19, T16-a), each with its own credential;
    /// empty: no verdict on this chain (`VerdictRefused`)
    pub verifiers: Vec<EndpointConfig>,
    #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::PolicyDef"))]
    pub verifier_policy: Policy,
    /// the SCaaS DEXes of the chain (NET-ALL-24): an order or a cancel naming a DEX not here is refused before anything is
    /// signed (CLI-SGN-35, `DexNotListed`)
    pub dexes: Vec<ListedDex>,
    /// the reviewed wrapped tokens a `UAWrapOrder` may mint (`Expect::WrapOrder`'s list; `DexNotListed` for another)
    pub wrappers: Vec<String>,
    /// the family data a non-EVM read needs beyond the fields above (spec §8.7 rule 2), release data as the rest; `None` on a
    /// family that needs none. Params of another family than `family`, or a field out of its form, are `Argument` at
    /// `Sdk::open`
    pub family_params: Option<FamilyParams>,
    /// the chain's L1 data fee model, added to a self-relay quote's `max_cost` (plan T38, spec §27.3): `OpStack` on Base, Celo
    /// and OP (the node's `params.l1_fee = "op-stack"`); `None`: no L1 fee and no L1 read. EVM profiles only (`Argument` at
    /// `Sdk::open` on another family)
    pub l1_fee: Option<L1Fee>,
    /// the kinds this chain cannot carry, disabled by the owner (2026-11-22, ARCH-POS-18 confirmed: OP, Arbitrum, Base mainnet
    /// and Celo, the kinds whose largest transaction is above the chain's limit): a UA kind by its name (`mldsa65`), the PQZ token and key
    /// attachment as `pqz`; an operation signed by such a kind, a registration of it, a PQZ operation or attachment is
    /// `KindDisabled` before anything is signed. A name the SDK does not know is `Argument` at `Sdk::open`
    pub disabled_kinds: Vec<String>,
}

/// An L1 data fee model (plan T38).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum L1Fee {
    /// OP Stack: `GasPriceOracle.getL1Fee(bytes)` (`0x4200…000F`) over the unsigned transaction, read at the quote's block
    OpStack,
}

/// A family's own profile data (spec §8.7 rule 2; decisions CLI-SDK-15's Changes of 2026-11-21).
#[derive(Debug, Clone)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
pub enum FamilyParams {
    /// Cosmos: the chain id the gateways' `node_info` must name (the identity a Cosmos node answers; `chain_uid` stays the
    /// profile's 32-byte network id), the REST gateways with their policy (the profile's `rpc` are the CometBFT endpoints),
    /// the native denom and the bech32 prefix of the chain's addresses
    Cosmos {
        chain_id: String,
        rest: Vec<EndpointConfig>,
        #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::PolicyDef"))]
        rest_policy: Policy,
        denom: String,
        prefix: String,
    },
    /// Aptos: the chain id ledger info must name (`aptos_framework::chain_id`, 1 to 255; the identity an Aptos node answers)
    /// and the `scaas` package's address, whose view `meta::account_of(owner)` gives the Account an owner's tokens are in
    /// (NET-APT-05), as `0x` + 64 lowercase hex (AIP-40's long form)
    Aptos { chain_id: u8, package: String },
    /// Solana: the `scaas` program's id (base58 of 32 bytes), under which an owner's SCaaS Account is the `["acct", owner]`
    /// program address (`ua-rs` `families::solana`); the cluster's identity is its genesis hash, `chain_uid`'s 32 bytes
    Solana { program: String },
    /// Soroban: the network passphrase its RPC endpoints name (`getNetwork`; its SHA-256 is `chain_uid`, checked at `Sdk::open`)
    /// and the XLM SAC contract (`C…`), pinned, whose balance entry is a `C…` holder's native XLM (never derived here)
    Soroban { passphrase: String, xlm_sac: String },
    /// Sui: the GraphQL endpoints the reads go to, with their policy (public fullnodes refuse JSON-RPC, docs/networks/sui.md
    /// §14; the profile's `rpc` are the JSON-RPC endpoints), each named by `chain_uid`, the genesis checkpoint's digest, whose
    /// 32 bytes in base58 `chainIdentifier` must answer
    Sui {
        graphql: Vec<EndpointConfig>,
        #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::PolicyDef"))]
        graphql_policy: Policy,
    },
    /// Polkadot Hub's Substrate side on its EVM profile (decisions CLI-SDK-32's Change of 2026-11-22, plan T32's read part): the
    /// Substrate JSON-RPC endpoints with their policy, each named by `genesis` (`0x` + 64 hex, `chain_getBlockHash(0)`), and the
    /// SS58 prefix of the chain's addresses (0 to 16,383, not 46 or 47); `balances` of an SS58 id reads its `System.Account`
    /// there. The same params serve the relay chain's Substrate side
    Substrate {
        rpc: Vec<EndpointConfig>,
        #[cfg_attr(feature = "wasm", serde(with = "crate::wasm::PolicyDef"))]
        rpc_policy: Policy,
        genesis: String,
        ss58_prefix: u16,
    },
}

/// Base58 (Bitcoin's alphabet) of 32 to 44 characters: a Solana key's form (its exact 32 bytes are checked where it is
/// decoded, under the family's feature).
pub(crate) fn is_base58_key(s: &str) -> bool {
    (32..=44).contains(&s.len())
        && s.bytes()
            .all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
}

/// An Aptos address in AIP-40's long form: `0x` + 64 lowercase hex.
pub(crate) fn is_aptos_address(s: &str) -> bool {
    s.len() == 66
        && s.starts_with("0x")
        && s.bytes()
            .skip(2)
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl FamilyParams {
    /// Its family, and each field in its form: Cosmos, a chain id of 1 to 50 printable ASCII bytes (CometBFT's bound), a denom
    /// as the Cosmos SDK's rule (`[a-zA-Z][a-zA-Z0-9/:._-]{2,127}`), a prefix of 1 to 83 lowercase letters and digits; Aptos,
    /// a chain id other than 0 and the package in the long form; Solana, the program in base58's form; Soroban, a passphrase of 1 to 256 printable ASCII bytes and a `C…` SAC.
    pub(crate) fn fits(&self, family: Family) -> bool {
        match self {
            FamilyParams::Cosmos {
                chain_id,
                denom,
                prefix,
                ..
            } => {
                let d = denom.as_bytes();
                family == Family::Cosmos
                    && (1..=50).contains(&chain_id.len())
                    && chain_id.bytes().all(|b| b.is_ascii_graphic())
                    && (3..=128).contains(&d.len())
                    && d.first().is_some_and(u8::is_ascii_alphabetic)
                    && d.iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"/:._-".contains(b))
                    && (1..=83).contains(&prefix.len())
                    && prefix
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            }
            FamilyParams::Aptos { chain_id, package } => {
                family == Family::Aptos && *chain_id != 0 && is_aptos_address(package)
            }
            FamilyParams::Solana { program } => family == Family::Solana && is_base58_key(program),
            FamilyParams::Soroban {
                passphrase,
                xlm_sac,
            } => {
                family == Family::Soroban
                    && (1..=256).contains(&passphrase.len())
                    && passphrase.bytes().all(|b| (0x20..0x7f).contains(&b))
                    && xlm_sac.len() == 56
                    && xlm_sac.starts_with('C')
            }
            FamilyParams::Sui { .. } => family == Family::Sui,
            FamilyParams::Substrate {
                genesis,
                ss58_prefix,
                ..
            } => {
                family == Family::Evm
                    && is_word_hex(genesis)
                    && *ss58_prefix <= 16_383
                    && !matches!(ss58_prefix, 46 | 47)
            }
        }
    }
}

/// A DEX of the chain profile (NET-ALL-24): its address, its liquidity mark (a module of group 11 among its `modules()`,
/// CTR-DEX-30) and the position readers reviewed for it, each beside its position manager.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct ListedDex {
    /// `0x` + 40 hex
    pub address: String,
    pub liquidity: bool,
    pub position_readers: Vec<PositionReader>,
}

/// A reviewed position reader of a position manager (a liquidity order that receives a position names one).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct PositionReader {
    pub manager: String,
    pub reader: String,
}

/// A base row (gas table v2, owner 2026-11-19): the execution gas of `entry` (`mtxCancelNonce`, `mtxExecuteTransfer`, …) on a
/// contract of domain kind `kind` (`token`, `zether`, `pqz`, `wallet`, `account`, `dex`, `gov_router`), on a lane whose nonce
/// is 0 (`fresh`) or above, signed by the reference signer, a native EVM key (its path makes no registry call).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
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
    /// the row's regular gas, its figure's part EIP-7825's per-transaction cap holds under EIP-8037 (controller call, owner
    /// auto-run 2026-11-19; at a count of 0 on a counted row, whose `per_item` then carries its slope); `None`: the whole
    /// figure is held to the cap
    pub regular: Option<u64>,
}

/// A row's per-item part (owner 2026-11-19, I1), on a base or a verify row: `gas` (whole gas, the measured slope rounded
/// up) for each counted `item` of the operation, one of `GAS_ITEMS` (`legs`, `accounts`, `entries`, `members`,
/// `env_items`, `orders`). The row's own `gas` is its figure at a count of 0 (the line's intercept; the file states
/// `"base_count": 0`), so the quote adds `gas × count` with no offset.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct GasPerItem {
    pub item: String,
    pub gas: u64,
    /// the regular part of `gas` (EIP-8037), on a base row with a `regular` figure only
    pub regular: Option<u64>,
    /// the largest count the row was measured at (`gas/generate.py`); a count above it is `GasCountUnknown`, never a line
    /// extrapolated past its points (merged-tree review M18, 2026-11-20); `None`: a row that names none (the chain's own)
    pub measured_max: Option<u64>,
}

/// A base row's per-byte part (owner 2026-11-19, ruling B): `gas` (whole gas, rounded up) for each byte of the operation's
/// variable-length `input`: `meta.body` (a pay entry's `PayMeta` body, as encoded) or `data` (`mtxExecute`'s call data).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct GasPerByte {
    pub input: String,
    pub gas: u64,
}

/// A verify row (gas table v2): what a signer of UA kind `signer` (`0`: a native EVM key, the reference) adds over the
/// reference signer's execution gas.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
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
    /// the registry line's columns (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65); all absent: the holder's own
    /// check on any registry (every row before the line)
    #[serde(default)]
    pub line: GasLine,
}

/// A verify row's registry-line columns (spec 2026-11-19-registry-verify-only-kinds §12, CTR-UA-65; §13 Gas): the row is
/// keyed by chain (the table it is in), registry address and signer kind; the verify path, the depth and the write path are
/// columns. Within one table no two verify rows share signer, registry, path, depth and write.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct GasLine {
    /// the registry the row was measured through (`0x` + 40 hex): a quote bound to it takes it first; `None`: a row of no one
    /// registry
    pub registry: Option<String>,
    /// `cache`, `precompile` or `fallback` (the holder's verdict after the verify-only verifier gave no answer, §5); `None`:
    /// the holder's own check
    pub path: Option<String>,
    /// the generations between the registry asked and the holder (0: the registry holds the record), at most 15
    pub depth: u8,
    /// the write path of W1 (a registry write whose signature the holder checks), never a consumer operation's quote
    pub write: bool,
}

/// A verify row's paths.
const GAS_VERIFY_PATHS: [&str; 3] = ["cache", "precompile", "fallback"];
/// The deepest line: `MAX_GENERATION` (16) less one.
const GAS_DEPTH_MAX: u64 = 15;

/// The rows of a gas table: base and verify, looked up independently (spec §13.3). The quote's figure is base + verify.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct GasRows {
    pub base: Vec<GasBase>,
    pub verify: Vec<GasVerify>,
}

/// A gas table file (spec §13.3, the gas table format): `{format: "scaas.gas-table", v: 2, name, family, assumptions, base,
/// verify}`, each base row `{entry, kind, fresh, gas, measured, source, calldata_gas?, per_byte?: {input, gas, source},
/// save?: {gas, measured, source}, fee_extra?: {gas, measured, source}, ua_extra?: {gas, measured, source}, item?,
/// per_item?: {gas, base_count, source, regular?}, stand_in?, regular?: {gas, measured, source}}`, each verify row
/// `{signer, gas, measured, source, sig_bytes, margin?, item?, per_item?, stand_in?, registry?, path?, depth?, write?}` (the
/// line's columns, [`GasLine`]), read by [`GasTable::parse`]. One format for the chain's measured rows, a module's table
/// and the SDK's reference table.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
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
pub(crate) const GAS_ITEMS: [&str; 6] = [
    "legs",
    "accounts",
    "entries",
    "members",
    "env_items",
    "orders",
];
/// A per-item part's largest `gas`: EIP-7825's transaction cap, 2^24 (a Zether leg is about 3.1 M).
const GAS_PER_ITEM_MAX: u64 = 1 << 24;
/// The keys a gas table may carry (PR A review, finding 1): any other key at the top, on a row or inside a row's part is refused
/// by name, `GasFieldUnknown`, so a misspelt part, or one a newer table adds, is never dropped from a quote silently. Besides the
/// figures the SDK reads: `assumptions` (top), `stand_in` (a row), `calldata_gas` (a base row's per-key calldata pins, its keys
/// the source's, not checked), and inside `ua_extra` the generator's `second_party` (Q1, information only), `unmeasured` and
/// `from_kind` (G2).
const GAS_TOP_KEYS: &[&str] = &[
    "format",
    "v",
    "name",
    "family",
    "assumptions",
    "base",
    "verify",
];
const GAS_BASE_KEYS: &[&str] = &[
    "entry",
    "kind",
    "fresh",
    "gas",
    "measured",
    "source",
    "calldata_gas",
    "per_byte",
    "save",
    "fee_extra",
    "ua_extra",
    "item",
    "per_item",
    "stand_in",
    "regular",
];
const GAS_VERIFY_KEYS: &[&str] = &[
    "signer",
    "gas",
    "measured",
    "source",
    "sig_bytes",
    "margin",
    "item",
    "per_item",
    "stand_in",
    "registry",
    "path",
    "depth",
    "write",
];
/// A row's parts, each with its keys (`second_party` is a part of `ua_extra`).
const GAS_PART_KEYS: &[(&str, &[&str])] = &[
    ("per_byte", &["input", "gas", "source"]),
    (
        "per_item",
        &["gas", "base_count", "source", "regular", "measured_max"],
    ),
    ("save", &["gas", "measured", "source"]),
    ("fee_extra", &["gas", "measured", "source"]),
    (
        "ua_extra",
        &[
            "gas",
            "measured",
            "source",
            "second_party",
            "unmeasured",
            "from_kind",
        ],
    ),
    ("second_party", &["measured", "source"]),
    ("regular", &["gas", "measured", "source"]),
];

/// An object with a key outside `keys`, or a part (of [`GAS_PART_KEYS`]) with one outside its own.
fn unknown_key(x: &serde_json::Value, keys: &[&str]) -> bool {
    x.as_object().is_some_and(|o| {
        o.iter().any(|(k, v)| {
            !keys.contains(&k.as_str())
                || GAS_PART_KEYS
                    .iter()
                    .any(|(p, pk)| p == k && unknown_key(v, pk))
        })
    })
}

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
    /// its optional `margin` 1–100,000, its optional line columns ([`GasLine`]: `registry` an address, `path` one of `cache`, `precompile`, `fallback`, `depth` 0–15, `write` a bool); a base or verify row's optional `item` and `per_item` come together (owner 2026-11-19,
    /// I1), `item` one of `GAS_ITEMS` (`legs`, `accounts`, `entries`, `members`, `env_items`, `orders`), `per_item` `{gas,
    /// base_count, source}` with a `gas` of 1–2^24 and `base_count` 0 (the row's figure is at a count of 0); a base row's
    /// optional `regular` (EIP-8037, the part EIP-7825's cap holds) held like a row's figure, positive, and on a counted row
    /// together with its `per_item`'s `regular` (0–2^24), never on a verify row; no key twice.
    /// By name when the file is otherwise sound (the first such fault): `GasSigBytesMissing` when a verify row has no
    /// `sig_bytes` (owner 2026-11-19, A4), `GasItemUnpaired` when a row has `per_item` without `item` or the reverse,
    /// `GasItemUnknown` when an `item` is not one of `GAS_ITEMS`, `GasFieldUnknown` when a key is outside the format (at the top,
    /// on a base or verify row, or inside a row's `per_byte`, `per_item`, `save`, `fee_extra`, `ua_extra` or its
    /// `second_party`; PR A review, finding 1); `Argument` on any other failure.
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
        // PR A review, finding 1: no key outside the format, at the top, on a row or in a row's part
        if unknown_key(&v, GAS_TOP_KEYS)
            || base.iter().any(|r| unknown_key(r, GAS_BASE_KEYS))
            || verify.iter().any(|r| unknown_key(r, GAS_VERIFY_KEYS))
        {
            named = Some(crate::SdkError::GasFieldUnknown);
        }
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
                regular: match r.get("regular") {
                    None => None,
                    Some(x) => Some(figure(x).filter(|g| *g > 0)?),
                },
            };
            // a counted row's regular figure and its slope come together (EIP-8037)
            if row
                .per_item
                .as_ref()
                .is_some_and(|p| p.regular.is_some() != row.regular.is_some())
            {
                return None;
            }
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
                line: GasLine {
                    registry: match r.get("registry") {
                        None => None,
                        Some(a) => Some(
                            a.as_str()
                                .filter(|a| is_address_hex(a))?
                                .to_ascii_lowercase(),
                        ),
                    },
                    path: match r.get("path") {
                        None => None,
                        Some(p) => Some(
                            p.as_str()
                                .filter(|p| GAS_VERIFY_PATHS.contains(p))?
                                .to_string(),
                        ),
                    },
                    depth: match r.get("depth") {
                        None => 0,
                        Some(d) => {
                            u8::try_from(d.as_u64().filter(|d| *d <= GAS_DEPTH_MAX)?).ok()?
                        }
                    },
                    write: match r.get("write") {
                        None => false,
                        Some(w) => w.as_bool()?,
                    },
                },
            };
            // no regular part on a verify row: its gas is regular whole
            if row.per_item.as_ref().is_some_and(|p| p.regular.is_some()) {
                return None;
            }
            if rows
                .verify
                .iter()
                .any(|o| o.signer == row.signer && o.line == row.line)
            {
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
    let regular = match p.get("regular") {
        None => None,
        Some(x) => Some(x.as_u64().filter(|g| *g <= GAS_PER_ITEM_MAX)?),
    };
    let measured_max = match p.get("measured_max") {
        None => None,
        Some(x) => Some(
            x.as_u64()
                .filter(|n| (1..=u64::from(u32::MAX)).contains(n))?,
        ),
    };
    Some(Some(GasPerItem {
        item: item.to_string(),
        gas,
        regular,
        measured_max,
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct ListedToken {
    /// EVM: `0x` + 40 hex; another family: its token id as text, checked by the family's form (spec §8.7; a NEAR account)
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
}

/// The SDK's caps and queues (spec §4). The fee caps are the app's to set for its chains; the defaults below are a floor
/// against a runaway quote, never a value assumed of a chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
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
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub enum RuntimeChoice {
    Adopt(tokio::runtime::Handle),
    Own,
}

/// The SDK's clock: unix seconds now. `None` in [`SdkConfig::clock`] is the device's clock; a test gives a fixed one (owner
/// 2026-11-19, T13b ruling 1).
pub type Clock = std::sync::Arc<dyn Fn() -> u64 + Send + Sync>;

/// Everything `Sdk::open` takes.
#[derive(Clone)]
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
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

/// `0x` and 40 hex digits.
pub(crate) fn is_address_hex(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
}

/// `0x` and 64 hex digits.
pub(crate) fn is_word_hex(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
}
