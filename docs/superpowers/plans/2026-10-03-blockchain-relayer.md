# Relayer `scaas-node` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One Rust binary with three modules — `submit` (drain the Odoo outbox, simulate, sign the outer tx, broadcast, never abandon a nonce), `indexer` (final-range `eth_getLogs` behind a depth/tag + quorum gate, ingest into Odoo), `gateway` (open inbound meta-tx + DEX order book and matcher).

**Architecture:** A per-chain `Chain` context owns the RPC providers and the signer; one submit task per chain owns the outer nonce in memory (`_USER-DECISIONS` §23.1). All Odoo traffic is `/json/2` with two API keys (relay, indexer). Pure logic (digest, finality range, matcher, nonce plan) lives in small modules with unit tests; the moving parts are proven by one end-to-end test against `anvil` + the real contracts + a fake Odoo.

**Tech Stack:** Rust 1.90 (edition 2021), `alloy` 1.6 (`sol!`, providers, local signer), `tokio`, `axum` 0.8, `tower` 0.5, `reqwest` 0.12, `serde`, `toml`, `tracing`.

**Spec:** `docs/superpowers/specs/2026-10-03-blockchain-payments-design.md` §3, §6–§9, rulings R6, R15, R16, R18.

## Global Constraints

- No Redis, no Lua, no direct Postgres; Odoo only via `POST /json/2/<model>/<method>`, `Authorization: Bearer <key>`, `X-Odoo-Database: <db>`.
- Keys and secrets only from environment variables named in the config; never logged.
- Simulation (`eth_call`) before every signature; `estimate_gas > max_gas_per_tx` ⇒ refuse.
- Never abandon an outer nonce: replace with fee ×1.25 every `stuck_after_secs` up to `max_fee_cap_gwei`; an abandoned job's nonce is filled with a 0-value self-transfer.
- Report `signed` (tx_hash + nonce + signer) to Odoo **before** `eth_sendRawTransaction`.
- Indexer sends only logs in `[cursor+1, safe_head]`, and only when ≥ `quorum` endpoints agree on the hash of `to`.
- Gateway: body ≤ 64 KiB, global concurrency ≤ 32, no `unwrap()` on request data.
- Digest parity: `metatx::digest` must equal `smartcontracts/test/vectors/metatx_kat.json`.
- Event JSON to Odoo exactly as `dms_blockchain` plan Task 4 (`event, contract, block_number, block_hash, tx_hash, log_index, …`).

## Review Focus

- `node_config` journal says nonce 7 was signed but the node's pending count is 5: nonces 5,6,7 must be gap-filled and their jobs re-queued — pinned in Task 4 (`nonce::plan`).
- The `finalized` tag is absent (pre-merge or private chain without it): `tag` mode must not crash, it must wait — pinned in Task 2.
- One RPC endpoint disagrees on the block hash: indexer must not advance — pinned in Task 2.
- A gateway order whose fee recipient is unrestricted and zero: the gateway must fill the relayer's address before simulating — pinned in Task 6.
- Two crossing orders where one is expired: matcher must skip, not settle-and-revert — pinned in Task 3.

## File Structure

| File | Responsibility |
|---|---|
| `scaas-node/Cargo.toml`, `node.example.toml`, `README.md` | crate, sample config, run notes |
| `src/main.rs` | CLI, spawn modules per chain |
| `src/config.rs` | TOML config + validation |
| `src/abi.rs` | `sol!` bindings, revert decoding |
| `src/metatx.rs` | wire format ↔ `MetaTransaction`, canonical digest |
| `src/finality.rs` | pure: safe head, next range, quorum |
| `src/dex.rs` | pure: order book + matcher |
| `src/nonce.rs` | pure: cold-start plan, fee bump |
| `src/odoo.rs` | `/json/2` client + typed calls |
| `src/chain.rs` | providers, signer, simulate/sign/send, logs |
| `src/submit.rs` | outbox loop |
| `src/indexer.rs` | ingest loop |
| `src/gateway.rs` | axum routes |
| `tests/e2e.rs` | anvil + forge + fake Odoo end-to-end (`#[ignore]`) |

---

### Task 1: Crate, config, ABI, canonical digest (KAT)

**Files:**
- Create: `scaas-node/Cargo.toml`, `scaas-node/.gitignore` (`target/`), `src/main.rs` (stub `fn main(){}` + `mod`s), `src/config.rs`, `src/abi.rs`, `src/metatx.rs`

**Interfaces:**
- Produces: `config::Config::load(path) -> anyhow::Result<Config>` with `odoo: OdooCfg{url,database,relay_api_key_env,indexer_api_key_env}`, `modules: Modules{submit,indexer,gateway,gateway_bind}`, `chains: Vec<ChainCfg{evm_chain_number,rpc_urls,signer_key_env,finality:FinalityCfg{mode,depth,quorum},dex,poll_ms,stuck_after_secs,max_gas_per_tx,max_fee_cap_gwei}>`; `abi::{MetaTransaction, IMetaToken, IMetaTxDex, decode_revert(&[u8]) -> String}`; `metatx::{WireMetaTx, Domain, canonical(&MetaTransaction)->MetaTransaction, digest(&Domain,&MetaTransaction)->B256, WireMetaTx::to_sol()->Result<MetaTransaction>}`.

- [ ] **Step 1: Failing test** (in `src/metatx.rs`, `#[cfg(test)]`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn kat() -> serde_json::Value {
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/test/vectors/metatx_kat.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    #[test]
    fn digest_matches_forge_kat() {
        let k = kat();
        let s = |f: &str| k[f].as_str().unwrap().to_string();
        let wire = WireMetaTx {
            from: s("from"), to: s("to"), value: s("value"), data: s("data"), batch: s("batch"),
            nonce: s("nonce"), valid_until: s("valid_until"), mode: s("mode").parse().unwrap(),
            relayer: s("relayer"), fee: s("fee"), fee_recipient: s("fee_recipient"),
        };
        let domain = Domain {
            name: s("domain_name"), version: s("domain_version"),
            chain_id: s("chain_id").parse().unwrap(),
            verifying_contract: Address::from_str(&s("verifying_contract")).unwrap(),
        };
        let d = digest(&domain, &wire.to_sol().unwrap());
        assert_eq!(format!("{d:#x}"), s("digest").to_lowercase());
    }

    #[test]
    fn unflagged_fee_recipient_does_not_change_the_digest() {
        let mut m = WireMetaTx::default_for_test().to_sol().unwrap();
        let d = Domain::default_for_test();
        let a = digest(&d, &m);
        m.feeRecipient = Address::repeat_byte(0x11);
        assert_eq!(a, digest(&d, &m));
        m.mode |= MODE_RESTRICT_FEE_RECIPIENT;
        assert_ne!(a, digest(&d, &m));
    }

    #[test]
    fn wire_rejects_garbage() {
        let mut w = WireMetaTx::default_for_test();
        w.value = "01".into();
        assert!(w.to_sol().is_err());
        let mut w = WireMetaTx::default_for_test();
        w.from = "0x12".into();
        assert!(w.to_sol().is_err());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd scaas-node && cargo test metatx`
Expected: compile error (`WireMetaTx` not found).

- [ ] **Step 3: Implement**

`Cargo.toml`:

```toml
[package]
name = "scaas-node"
version = "0.1.0"
edition = "2021"
rust-version = "1.88"
publish = false

[dependencies]
alloy = { version = "1.6", default-features = false, features = ["std", "provider-http", "rpc-types", "signer-local", "sol-types", "contract", "network", "eips", "consensus", "reqwest", "json-rpc"] }
anyhow = "1"
axum = "0.8"
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tokio = { version = "1", features = ["full"] }
toml = "0.8"
tower = { version = "0.5", features = ["limit"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[dev-dependencies]
tempfile = "3"
```

`src/abi.rs`:

```rust
//! ABI — chép chữ ký từ `smartcontracts/src`, không suy luận. Sai một `indexed` là sai topic.
use alloy::sol;
use alloy::sol_types::SolInterface;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct MetaTransaction {
        address from; address to; uint256 value; bytes data;
        uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode;
        address relayer; uint256 fee; address feeRecipient;
    }

    #[derive(Debug)]
    interface IMetaToken {
        function executeMetaTransaction(MetaTransaction m, bytes signature) external returns (bool);
        function metaTxDigest(MetaTransaction m) external view returns (bytes32);
        function metaNonce(address from, uint256 batch) external view returns (uint256);
        function balanceOf(address who) external view returns (uint256);
        event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
            uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
        event PaymentSettled(address indexed from, address indexed to, uint256 amount, uint256 feeAmount,
            address feeRecipient, bytes32 indexed entryRef);
        error MetaTxExpired(uint256 validUntil, uint256 nowTs);
        error MetaTxBadNonce(uint256 expected, uint256 got);
        error MetaTxBadSignature();
        error MetaTxUnauthorizedRelayer(address allowed, address caller);
        error MetaTxUnknownMode(uint32 mode);
        error MetaTxInsufficientForFee(uint256 needed, uint256 available);
        error MetaTxUnknownOp(bytes4 op);
        error PayToZero();
        error TradeLegNotRestricted();
        error FeeExceedsCap(uint256 feeAmount, uint256 cap);
        error FeeRecipientRequired();
        error ModeFeeInvalid(uint32 mode);
        error ModeUnknownBits(uint32 mode);
    }

    #[derive(Debug)]
    struct Leg { address token; MetaTransaction m; bytes sig; }

    #[derive(Debug)]
    interface IMetaTxDex {
        function settle(Leg a, Leg b) external;
        event TradeSettled(address indexed partyA, address indexed partyB, address tokenA, address tokenB,
            uint256 valueA, uint256 valueB);
        error NotATradeLeg();
        error SameToken();
        error SameParty();
        error CounterTokenMismatch();
        error PriceNotMet(uint256 got, uint256 min);
        error CounterpartyMismatch();
        error LegNotRoutedHere();
        error FeeWouldStick();
        error DeltaMismatch(address token, uint256 got, uint256 expected);
    }
}

/// Tên lỗi đọc được cho `last_error` ở Odoo; hex thô nếu không nhận ra.
pub fn decode_revert(data: &[u8]) -> String {
    if let Ok(e) = IMetaToken::IMetaTokenErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IMetaTxDex::IMetaTxDexErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    format!("revert 0x{}", alloy::hex::encode(data))
}
```

`src/metatx.rs`:

```rust
//! Định dạng dây (chuỗi, như Odoo và gateway gửi) ↔ struct Solidity, và digest canonical.
//! Quy tắc canonical-zeroing phải giống `MetaTxLib.canon` từng bit (spec §6).
use std::str::FromStr;

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::sol_types::{Eip712Domain, SolStruct};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};

pub use crate::abi::MetaTransaction;

pub const MODE_RESTRICT_RELAYER: u32 = 0x01;
pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
pub const MODE_FEE_MASK: u32 = 0xF0;
pub const MODE_KNOWN_MASK: u32 = 0xF3;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct WireMetaTx {
    pub from: String,
    pub to: String,
    pub value: String,
    pub data: String,
    pub batch: String,
    pub nonce: String,
    pub valid_until: String,
    pub mode: u32,
    pub relayer: String,
    pub fee: String,
    pub fee_recipient: String,
}

#[derive(Debug, Clone)]
pub struct Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

fn addr(s: &str) -> Result<Address> {
    if s.len() != 42 || !s.starts_with("0x") {
        bail!("not an address: {s}");
    }
    Address::from_str(s).map_err(|e| anyhow!("not an address {s}: {e}"))
}

fn uint(s: &str) -> Result<U256> {
    if s.is_empty() || s.len() > 78 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        bail!("not a canonical uint256: {s}");
    }
    U256::from_str_radix(s, 10).map_err(|e| anyhow!("uint256 {s}: {e}"))
}

impl WireMetaTx {
    pub fn to_sol(&self) -> Result<MetaTransaction> {
        let data = alloy::hex::decode(self.data.trim_start_matches("0x")).map_err(|e| anyhow!("data: {e}"))?;
        if self.mode & !MODE_KNOWN_MASK != 0 || (self.mode & MODE_FEE_MASK) >> 4 > 2 {
            bail!("unknown mode bits {:#x}", self.mode);
        }
        Ok(MetaTransaction {
            from: addr(&self.from)?, to: addr(&self.to)?, value: uint(&self.value)?, data: Bytes::from(data),
            batch: uint(&self.batch)?, nonce: uint(&self.nonce)?, validUntil: uint(&self.valid_until)?,
            mode: self.mode, relayer: addr(&self.relayer)?, fee: uint(&self.fee)?,
            feeRecipient: addr(&self.fee_recipient)?,
        })
    }

    pub fn from_sol(m: &MetaTransaction) -> Self {
        Self {
            from: format!("{:#x}", m.from), to: format!("{:#x}", m.to), value: m.value.to_string(),
            data: format!("0x{}", alloy::hex::encode(&m.data)), batch: m.batch.to_string(),
            nonce: m.nonce.to_string(), valid_until: m.validUntil.to_string(), mode: m.mode,
            relayer: format!("{:#x}", m.relayer), fee: m.fee.to_string(),
            fee_recipient: format!("{:#x}", m.feeRecipient),
        }
    }

    #[cfg(test)]
    pub fn default_for_test() -> Self {
        Self {
            from: format!("{:#x}", Address::repeat_byte(0xab)), to: format!("{:#x}", Address::repeat_byte(0x01)),
            value: "100".into(), data: "0x".into(), batch: "7".into(), nonce: "0".into(),
            valid_until: "1800000300".into(), mode: MODE_RESTRICT_RELAYER,
            relayer: format!("{:#x}", Address::repeat_byte(0x02)), fee: "0".into(),
            fee_recipient: format!("{:#x}", Address::ZERO),
        }
    }
}

impl Domain {
    pub fn eip712(&self) -> Eip712Domain {
        Eip712Domain::new(
            Some(self.name.clone().into()), Some(self.version.clone().into()),
            Some(U256::from(self.chain_id)), Some(self.verifying_contract), None,
        )
    }

    #[cfg(test)]
    pub fn default_for_test() -> Self {
        Self { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: 9000,
               verifying_contract: Address::repeat_byte(0xcd) }
    }
}

/// Bản đã canonical-zero hoá: cái MetaTxLib thực sự băm.
pub fn canonical(m: &MetaTransaction) -> MetaTransaction {
    let mut c = m.clone();
    if m.mode & MODE_RESTRICT_RELAYER == 0 {
        c.relayer = Address::ZERO;
    }
    if m.mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
        c.feeRecipient = Address::ZERO;
    }
    c
}

pub fn digest(domain: &Domain, m: &MetaTransaction) -> B256 {
    canonical(m).eip712_signing_hash(&domain.eip712())
}
```

`src/config.rs`:

```rust
use std::path::Path;

use alloy::primitives::Address;
use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub odoo: OdooCfg,
    #[serde(default)]
    pub modules: Modules,
    pub chains: Vec<ChainCfg>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OdooCfg {
    pub url: String,
    pub database: String,
    pub relay_api_key_env: String,
    pub indexer_api_key_env: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Modules {
    #[serde(default = "yes")]
    pub submit: bool,
    #[serde(default = "yes")]
    pub indexer: bool,
    #[serde(default)]
    pub gateway: bool,
    #[serde(default = "default_bind")]
    pub gateway_bind: String,
}

impl Default for Modules {
    fn default() -> Self {
        Self { submit: true, indexer: true, gateway: false, gateway_bind: default_bind() }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FinalityCfg {
    pub mode: String,
    #[serde(default)]
    pub depth: u64,
    #[serde(default = "one")]
    pub quorum: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainCfg {
    pub evm_chain_number: u64,
    pub rpc_urls: Vec<String>,
    pub signer_key_env: String,
    pub finality: FinalityCfg,
    #[serde(default)]
    pub dex: Option<Address>,
    #[serde(default = "default_poll")]
    pub poll_ms: u64,
    #[serde(default = "default_stuck")]
    pub stuck_after_secs: u64,
    #[serde(default = "default_max_gas")]
    pub max_gas_per_tx: u64,
    #[serde(default = "default_fee_cap")]
    pub max_fee_cap_gwei: u64,
}

fn yes() -> bool { true }
fn one() -> usize { 1 }
fn default_bind() -> String { "127.0.0.1:8547".into() }
fn default_poll() -> u64 { 1000 }
fn default_stuck() -> u64 { 60 }
fn default_max_gas() -> u64 { 3_000_000 }
fn default_fee_cap() -> u64 { 500 }

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw).context("parse config")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.chains.is_empty() {
            bail!("no [[chains]]");
        }
        for c in &self.chains {
            if c.rpc_urls.len() < c.finality.quorum {
                bail!("chain {}: {} rpc_urls < quorum {}", c.evm_chain_number, c.rpc_urls.len(), c.finality.quorum);
            }
            if c.finality.mode != "depth" && c.finality.mode != "tag" {
                bail!("chain {}: finality.mode must be depth|tag", c.evm_chain_number);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"
[odoo]
url = "http://odoo:8069"
database = "odoo19"
relay_api_key_env = "R"
indexer_api_key_env = "I"
[[chains]]
evm_chain_number = 9000
rpc_urls = ["http://a"]
signer_key_env = "K"
finality = { mode = "depth", depth = 1, quorum = 1 }
"#;

    #[test]
    fn parses_with_defaults() {
        let c: Config = toml::from_str(OK).unwrap();
        c.validate().unwrap();
        assert!(c.modules.submit && c.modules.indexer && !c.modules.gateway);
        assert_eq!(c.chains[0].stuck_after_secs, 60);
    }

    #[test]
    fn quorum_above_endpoints_is_refused() {
        let c: Config = toml::from_str(&OK.replace("quorum = 1", "quorum = 2")).unwrap();
        assert!(c.validate().is_err());
    }
}
```

`src/main.rs` (Task 1 stub):

```rust
mod abi;
mod config;
mod metatx;

fn main() {}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd scaas-node && cargo test`
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add scaas-node
git commit -m "feat(node): scaas-node crate - config, ABI and canonical digest locked to the KAT"
```

---

### Task 2: Finality gate (pure)

**Files:** Create `scaas-node/src/finality.rs`; Modify `src/main.rs` (`mod finality;`).

**Interfaces:**
- Produces: `enum Mode { Depth(u64), Tag }`; `safe_head(mode: &Mode, latest: u64, finalized: Option<u64>) -> Option<u64>`; `next_range(cursor: u64, safe: u64, max_span: u64) -> Option<(u64, u64)>`; `quorum_ok(primary: B256, others: &[Option<B256>], quorum: usize) -> bool`.

- [ ] **Step 1: Failing tests** (bottom of `finality.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;

    #[test]
    fn depth_mode_subtracts_and_saturates() {
        assert_eq!(safe_head(&Mode::Depth(1), 10, None), Some(9));
        assert_eq!(safe_head(&Mode::Depth(20), 10, None), None);
        assert_eq!(safe_head(&Mode::Depth(0), 10, None), Some(10));
    }

    #[test]
    fn tag_mode_waits_without_a_finalized_block() {
        assert_eq!(safe_head(&Mode::Tag, 10, None), None);
        assert_eq!(safe_head(&Mode::Tag, 10, Some(4)), Some(4));
        assert_eq!(safe_head(&Mode::Tag, 3, Some(4)), Some(3)); // never above latest
    }

    #[test]
    fn ranges_are_contiguous_and_bounded() {
        assert_eq!(next_range(0, 5, 1000), Some((1, 5)));
        assert_eq!(next_range(5, 5, 1000), None);
        assert_eq!(next_range(0, 5000, 1000), Some((1, 1000)));
    }

    #[test]
    fn quorum_counts_the_primary() {
        let h = B256::repeat_byte(1);
        let x = B256::repeat_byte(2);
        assert!(quorum_ok(h, &[], 1));
        assert!(quorum_ok(h, &[Some(h)], 2));
        assert!(!quorum_ok(h, &[Some(x)], 2));
        assert!(!quorum_ok(h, &[None], 2));
    }
}
```

- [ ] **Step 2: Run** `cd scaas-node && cargo test finality` → FAIL (unresolved names).

- [ ] **Step 3: Implement** (top of `finality.rs`):

```rust
//! Cổng finality — thuần, không I/O. Odoo chỉ thấy log trong vùng `safe_head` trả về.
use alloy::primitives::B256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `latest - depth`. Chain BFT/Clique một signer: depth 1 (canon §C9).
    Depth(u64),
    /// Tag `finalized` của node. Vắng tag ⇒ đứng chờ, không đoán.
    Tag,
}

pub fn safe_head(mode: &Mode, latest: u64, finalized: Option<u64>) -> Option<u64> {
    match mode {
        Mode::Depth(d) => latest.checked_sub(*d),
        Mode::Tag => finalized.map(|f| f.min(latest)),
    }
}

pub fn next_range(cursor: u64, safe: u64, max_span: u64) -> Option<(u64, u64)> {
    (safe > cursor).then(|| (cursor + 1, safe.min(cursor + max_span)))
}

/// Endpoint chính luôn được đếm; `others` là các endpoint độc lập còn lại.
pub fn quorum_ok(primary: B256, others: &[Option<B256>], quorum: usize) -> bool {
    1 + others.iter().filter(|h| **h == Some(primary)).count() >= quorum
}
```

- [ ] **Step 4: Run** `cargo test finality` → PASS.
- [ ] **Step 5: Commit** `git add scaas-node && git commit -m "feat(node): pure finality gate - depth/tag safe head, contiguous ranges, RPC quorum"`

---

### Task 3: DEX order book + matcher (pure)

**Files:** Create `scaas-node/src/dex.rs`; Modify `main.rs`.

**Interfaces:**
- Consumes: `abi::{MetaTransaction}`, `metatx::{MODE_RESTRICT_RELAYER}`.
- Produces: `struct Order { token: Address, m: MetaTransaction, sig: Bytes }`; `Order::terms() -> Result<Terms{counter_token, min_counter, counterparty}>`; `Book::default()`, `Book::insert(order, now) -> Option<(Order, Order)>` (returns a crossing pair, removed from the book), `Book::list(sell, buy, now) -> Vec<&Order>`, `Book::purge(now)`; `OP_TRADE: [u8;4]`.

- [ ] **Step 1: Failing tests**:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolValue;

    const A: Address = Address::repeat_byte(0xaa);
    const B: Address = Address::repeat_byte(0xbb);
    const DEX: Address = Address::repeat_byte(0xde);

    fn order(from: u8, sell: Address, value: u64, buy: Address, min: u64, valid_until: u64, cp: Address) -> Order {
        let mut data = OP_TRADE.to_vec();
        data.extend((buy, U256::from(min), cp).abi_encode());
        Order {
            token: sell,
            m: MetaTransaction {
                from: Address::repeat_byte(from), to: DEX, value: U256::from(value), data: data.into(),
                batch: U256::from(from), nonce: U256::ZERO, validUntil: U256::from(valid_until),
                mode: MODE_RESTRICT_RELAYER, relayer: DEX, fee: U256::ZERO, feeRecipient: Address::ZERO,
            },
            sig: Bytes::new(),
        }
    }

    #[test]
    fn terms_decode() {
        let o = order(1, A, 100, B, 50, 99, Address::ZERO);
        let t = o.terms().unwrap();
        assert_eq!((t.counter_token, t.min_counter, t.counterparty), (B, U256::from(50), Address::ZERO));
    }

    #[test]
    fn crossing_orders_match_and_leave_the_book() {
        let mut book = Book::default();
        assert!(book.insert(order(1, A, 100, B, 50, 99, Address::ZERO), 10).is_none());
        let (maker, taker) = book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).unwrap();
        assert_eq!(maker.m.from, Address::repeat_byte(1));
        assert_eq!(taker.m.from, Address::repeat_byte(2));
        assert!(book.list(A, B, 10).is_empty());
    }

    #[test]
    fn non_crossing_orders_rest() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 70, 99, Address::ZERO), 10);
        assert!(book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
        assert_eq!(book.list(A, B, 10).len(), 1);
        assert_eq!(book.list(B, A, 10).len(), 1);
    }

    #[test]
    fn expired_resting_order_is_skipped() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 50, 5, Address::ZERO), 1);
        assert!(book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
        book.purge(10);
        assert!(book.list(A, B, 10).is_empty());
    }

    #[test]
    fn counterparty_is_respected() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 50, 99, Address::repeat_byte(9)), 10);
        assert!(book.insert(order(2, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
    }

    #[test]
    fn same_party_never_matches_itself() {
        let mut book = Book::default();
        book.insert(order(1, A, 100, B, 50, 99, Address::ZERO), 10);
        assert!(book.insert(order(1, B, 60, A, 100, 99, Address::ZERO), 10).is_none());
    }
}
```

- [ ] **Step 2: Run** `cargo test dex` → FAIL.

- [ ] **Step 3: Implement** (top of `dex.rs`):

```rust
//! Sổ lệnh trong bộ nhớ (ruling R16) và matcher fill-or-kill, FIFO.
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolValue;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::abi::MetaTransaction;
#[cfg(test)]
use crate::metatx::MODE_RESTRICT_RELAYER;

/// `bytes4(keccak256("trade(address,uint256,address)"))`
pub const OP_TRADE: [u8; 4] = [0x0e, 0x32, 0xdb, 0x52];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub token: Address,
    pub m: MetaTransaction,
    pub sig: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terms {
    pub counter_token: Address,
    pub min_counter: U256,
    pub counterparty: Address,
}

impl Order {
    pub fn terms(&self) -> Result<Terms> {
        let d = &self.m.data;
        if d.len() != 100 || d[..4] != OP_TRADE {
            bail!("not a trade leg");
        }
        let (counter_token, min_counter, counterparty) = <(Address, U256, Address)>::abi_decode(&d[4..])?;
        Ok(Terms { counter_token, min_counter, counterparty })
    }

    fn live(&self, now: u64) -> bool {
        self.m.validUntil >= U256::from(now)
    }
}

fn crosses(a: &Order, ta: &Terms, b: &Order, tb: &Terms) -> bool {
    a.m.from != b.m.from
        && ta.counter_token == b.token
        && tb.counter_token == a.token
        && b.m.value >= ta.min_counter
        && a.m.value >= tb.min_counter
        && (ta.counterparty == Address::ZERO || ta.counterparty == b.m.from)
        && (tb.counterparty == Address::ZERO || tb.counterparty == a.m.from)
}

#[derive(Debug, Default)]
pub struct Book {
    orders: Vec<(Order, Terms)>,
}

impl Book {
    /// Thêm lệnh; nếu khớp được lệnh đang nghỉ thì trả cặp `(resting, incoming)` và bỏ khỏi sổ.
    pub fn insert(&mut self, order: Order, now: u64) -> Option<(Order, Order)> {
        let terms = order.terms().ok()?;
        if !order.live(now) {
            return None;
        }
        let hit = self.orders.iter().position(|(r, rt)| r.live(now) && crosses(r, rt, &order, &terms));
        match hit {
            Some(i) => Some((self.orders.remove(i).0, order)),
            None => {
                self.orders.push((order, terms));
                None
            }
        }
    }

    pub fn list(&self, sell: Address, buy: Address, now: u64) -> Vec<&Order> {
        self.orders.iter()
            .filter(|(o, t)| o.token == sell && t.counter_token == buy && o.live(now))
            .map(|(o, _)| o)
            .collect()
    }

    pub fn purge(&mut self, now: u64) {
        self.orders.retain(|(o, _)| o.live(now));
    }
}
```

Also add to the tests module (`cast sig 'trade(address,uint256,address)'` = `0x0e32db52`):

```rust
    #[test]
    fn op_trade_constant_is_the_selector() {
        assert_eq!(alloy::primitives::keccak256(b"trade(address,uint256,address)")[..4], OP_TRADE);
    }
```

- [ ] **Step 4: Run** `cargo test dex` → PASS.
- [ ] **Step 5: Commit** `git commit -m "feat(node): in-memory DEX order book with fill-or-kill matcher"`

---

### Task 4: Nonce plan + fee bump (pure)

**Files:** Create `scaas-node/src/nonce.rs`; Modify `main.rs`.

**Interfaces:**
- Produces: `struct Inflight { job_id: i64, nonce: u64, state: String }`; `struct Plan { next: u64, gap_fill: Vec<u64>, requeue: Vec<i64>, track: Vec<i64> }`; `plan(pending: u64, journal_max: Option<u64>, inflight: &[Inflight]) -> Plan`; `bump(fee: u128, cap: u128) -> u128`.

- [ ] **Step 1: Failing tests**:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn j(id: i64, nonce: u64, state: &str) -> Inflight {
        Inflight { job_id: id, nonce, state: state.into() }
    }

    #[test]
    fn clean_start_uses_pending() {
        let p = plan(5, None, &[]);
        assert_eq!((p.next, p.gap_fill.len()), (5, 0));
    }

    #[test]
    fn journal_ahead_of_pending_is_gap_filled_and_requeued() {
        let p = plan(5, Some(7), &[j(1, 5, "broadcast"), j(2, 6, "signed"), j(3, 7, "broadcast")]);
        assert_eq!(p.next, 8);
        assert_eq!(p.gap_fill, vec![5, 6, 7]);
        assert_eq!(p.requeue, vec![1, 2, 3]);
    }

    #[test]
    fn jobs_below_pending_are_tracked_not_resent() {
        let p = plan(5, Some(4), &[j(1, 4, "broadcast"), j(9, 0, "nonce_leased")]);
        assert_eq!(p.next, 5);
        assert_eq!(p.track, vec![1]);
        assert_eq!(p.requeue, vec![9]);
    }

    #[test]
    fn bump_is_a_quarter_and_capped() {
        assert_eq!(bump(100, 1_000), 125);
        assert_eq!(bump(900, 1_000), 1_000);
        assert_eq!(bump(0, 1_000), 1);
    }
}
```

- [ ] **Step 2: Run** `cargo test nonce` → FAIL.

- [ ] **Step 3: Implement**:

```rust
//! Cold start (`_USER-DECISIONS` §23.1 + ruling R18). Thuần: đầu vào là con số của chain
//! và journal của Odoo, đầu ra là việc phải làm.

#[derive(Debug, Clone)]
pub struct Inflight {
    pub job_id: i64,
    pub nonce: u64,
    pub state: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub next: u64,
    /// Nonce journal đã ghi mà chain không thấy (không trong block, không trong mempool).
    pub gap_fill: Vec<u64>,
    /// Job phải về `queued`: chưa ký, hoặc nonce của nó vừa bị lấp.
    pub requeue: Vec<i64>,
    /// Job đã ký với nonce < pending: tx có thật (block hoặc mempool) — theo dõi, KHÔNG ký lại.
    pub track: Vec<i64>,
}

pub fn plan(pending: u64, journal_max: Option<u64>, inflight: &[Inflight]) -> Plan {
    let next = journal_max.map_or(pending, |j| pending.max(j + 1));
    let mut p = Plan { next, gap_fill: (pending..next).collect(), ..Default::default() };
    for job in inflight {
        if job.state == "nonce_leased" || job.nonce >= pending {
            p.requeue.push(job.job_id);
        } else {
            p.track.push(job.job_id);
        }
    }
    p
}

/// +25 % (SRS tích hợp §5.4), tối thiểu +1 wei, không vượt trần.
pub fn bump(fee: u128, cap: u128) -> u128 {
    (fee + fee / 4).max(fee + 1).min(cap)
}
```

- [ ] **Step 4: Run** `cargo test nonce` → PASS.
- [ ] **Step 5: Commit** `git commit -m "feat(node): cold-start nonce plan with gap-filling and capped fee bump"`

**Odoo dependency:** `node_config(evm_chain_number, relayer_address)` must additionally return `inflight: [{job_id, nonce, state, tx_hash, payload}]` for jobs of that signer (or claimed and unsigned) in `nonce_leased/signed/broadcast`. Add to `dms_blockchain` (plan "odoo-core" Task 3) as part of this task: extend `_node_config` with

```python
        inflight = []
        if relayer_address:
            jobs = self.env['blockchain.relay.job'].sudo().search([
                ('chain_id', '=', self.id), ('chain_state', 'in', ('nonce_leased', 'signed', 'broadcast')),
                '|', ('signer_address', '=', norm_address(relayer_address)), ('signer_address', '=', False)])
            inflight = [{'job_id': j.id, 'nonce': j.outer_nonce, 'state': j.chain_state,
                         'tx_hash': j.tx_hash or None, 'payload': j._payload()} for j in jobs]
```

and a test in `test_relay_job.py` asserting a `signed` job appears in `inflight`.

---

### Task 5: Odoo client + chain context + submit loop

**Files:** Create `scaas-node/src/odoo.rs`, `src/chain.rs`, `src/submit.rs`; Modify `main.rs`.

**Interfaces:**
- Consumes: Tasks 1, 4.
- Produces: `odoo::Odoo::new(cfg, key_env) -> Result<Odoo>`, `Odoo::call<T: DeserializeOwned>(&self, model, method, body: serde_json::Value) -> Result<T>`; typed: `node_config(chain, relayer: Option<Address>) -> NodeConfig`, `relay_poll(chain, limit) -> Vec<Job>`, `relay_claim(ids, worker) -> Vec<i64>`, `relay_report(Report) -> ()`, `ingest(chain, from, to, hash, events) -> IngestResult`; `chain::Chain::connect(cfg) -> Result<Chain>` with `primary() -> &DynProvider`, `others()`, `address() -> Address`, `simulate(to, data) -> Result<u64, String>`, `sign(nonce, to, data, gas, fees) -> Result<(Bytes, B256)>`, `send_raw(&Bytes) -> Result<()>`, `fees() -> Result<(u128,u128)>`; `submit::Work { job_id: Option<i64>, to: Address, data: Bytes, valid_until: u64 }`; `submit::run(chain, odoo, cfg, rx: mpsc::Receiver<Work>, node_id)`.

- [ ] **Step 1: Write the code** — `src/odoo.rs`:

```rust
//! `/json/2` — đường duy nhất vào Odoo (ruling R6). Một client cho mỗi API key.
use alloy::primitives::Address;
use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::OdooCfg;
use crate::metatx::WireMetaTx;

#[derive(Clone)]
pub struct Odoo {
    http: reqwest::Client,
    base: String,
    db: String,
    key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenCfg {
    pub address: Address,
    pub decimals: u8,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InflightJob {
    pub job_id: i64,
    pub nonce: Option<u64>,
    pub state: String,
    pub tx_hash: Option<String>,
    pub payload: Job,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub evm_chain_number: u64,
    pub finality_mode: String,
    pub finality_depth: u64,
    pub finality_quorum: usize,
    pub indexed_block: u64,
    pub tokens: Vec<TokenCfg>,
    pub journal_max_nonce: Option<u64>,
    #[serde(default)]
    pub inflight: Vec<InflightJob>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Job {
    pub id: i64,
    pub token: Address,
    pub digest: String,
    pub signature: String,
    pub metatx: WireMetaTx,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub job_id: i64,
    pub chain_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outer_nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestResult {
    pub indexed_block: u64,
    pub created: u64,
}

impl Odoo {
    pub fn new(cfg: &OdooCfg, key_env: &str) -> Result<Self> {
        let key = std::env::var(key_env).with_context(|| format!("env {key_env} not set"))?;
        Ok(Self::with_key(cfg, key))
    }

    pub fn with_key(cfg: &OdooCfg, key: String) -> Self {
        Self {
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build()
                .expect("reqwest client"),
            base: cfg.url.trim_end_matches('/').to_string(),
            db: cfg.database.clone(),
            key,
        }
    }

    pub async fn call<T: DeserializeOwned>(&self, model: &str, method: &str, body: Value) -> Result<T> {
        let res = self.http.post(format!("{}/json/2/{model}/{method}", self.base))
            .bearer_auth(&self.key).header("X-Odoo-Database", &self.db).json(&body).send().await
            .with_context(|| format!("{model}.{method}: transport"))?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            // Không log body nguyên văn: lỗi Odoo có thể kèm traceback; cắt ngắn.
            return Err(anyhow!("{model}.{method}: HTTP {status}: {}", &text[..text.len().min(300)]));
        }
        serde_json::from_str(&text).with_context(|| format!("{model}.{method}: decode"))
    }

    pub async fn node_config(&self, chain: u64, relayer: Option<Address>) -> Result<NodeConfig> {
        let mut body = json!({"evm_chain_number": chain});
        if let Some(r) = relayer {
            body["relayer_address"] = json!(format!("{r:#x}"));
        }
        self.call("blockchain.chain", "node_config", body).await
    }

    pub async fn relay_poll(&self, chain: u64, limit: u32) -> Result<Vec<Job>> {
        self.call("blockchain.relay.job", "relay_poll", json!({"evm_chain_number": chain, "limit": limit})).await
    }

    pub async fn relay_claim(&self, ids: &[i64], worker: &str) -> Result<Vec<i64>> {
        self.call("blockchain.relay.job", "relay_claim", json!({"job_ids": ids, "worker": worker})).await
    }

    pub async fn relay_report(&self, r: &Report) -> Result<()> {
        let _: Value = self.call("blockchain.relay.job", "relay_report", serde_json::to_value(r)?).await?;
        Ok(())
    }

    pub async fn ingest(&self, chain: u64, from: u64, to: u64, hash: &str, events: &[Value]) -> Result<IngestResult> {
        self.call("blockchain.chain.event", "chain_event_ingest", json!({
            "evm_chain_number": chain, "from_block": from, "to_block": to,
            "to_block_hash": hash, "events": events,
        })).await
    }
}
```

`src/chain.rs`:

```rust
//! Kết nối RPC + ký vỏ tx. Khoá chỉ đi qua trait `Signer` (ruling R15): bản này là
//! `PrivateKeySigner` từ biến môi trường; thay bằng custody broker không đổi nơi gọi.
use alloy::eips::BlockNumberOrTag;
use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::eips::eip2718::Encodable2718;
use anyhow::{anyhow, Context, Result};

use crate::abi::decode_revert;
use crate::config::ChainCfg;

pub struct Chain {
    pub number: u64,
    providers: Vec<DynProvider>,
    wallet: EthereumWallet,
    address: Address,
}

impl Chain {
    pub fn connect(cfg: &ChainCfg) -> Result<Self> {
        let key = std::env::var(&cfg.signer_key_env).with_context(|| format!("env {} not set", cfg.signer_key_env))?;
        let signer: PrivateKeySigner = key.parse().map_err(|e| anyhow!("signer key: {e}"))?;
        Self::with_signer(cfg, signer)
    }

    pub fn with_signer(cfg: &ChainCfg, signer: PrivateKeySigner) -> Result<Self> {
        let address = signer.address();
        let providers = cfg.rpc_urls.iter()
            .map(|u| Ok(ProviderBuilder::new().disable_recommended_fillers().connect_http(u.parse()?).erased()))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { number: cfg.evm_chain_number, providers, wallet: EthereumWallet::from(signer), address })
    }

    pub fn primary(&self) -> &DynProvider { &self.providers[0] }
    pub fn others(&self) -> &[DynProvider] { &self.providers[1..] }
    pub fn address(&self) -> Address { self.address }

    /// `eth_call` từ địa chỉ relayer. Err = lý do revert đã giải mã.
    pub async fn simulate(&self, to: Address, data: Bytes) -> std::result::Result<u64, String> {
        let tx = TransactionRequest::default().with_from(self.address).with_to(to).with_input(data);
        match self.primary().call(tx.clone()).await {
            Ok(_) => {}
            Err(e) => return Err(revert_reason(&e)),
        }
        self.primary().estimate_gas(tx).await.map_err(|e| revert_reason(&e))
    }

    /// `eth_call` giả làm `from` tuỳ ý (gateway mô phỏng chân DEX bằng địa chỉ DEX).
    pub async fn simulate_as(&self, from: Address, to: Address, data: Bytes) -> std::result::Result<(), String> {
        let tx = TransactionRequest::default().with_from(from).with_to(to).with_input(data);
        self.primary().call(tx).await.map(|_| ()).map_err(|e| revert_reason(&e))
    }

    pub async fn fees(&self) -> Result<(u128, u128)> {
        let est = self.primary().estimate_eip1559_fees().await?;
        Ok((est.max_fee_per_gas.max(1), est.max_priority_fee_per_gas))
    }

    pub async fn pending_nonce(&self) -> Result<u64> {
        Ok(self.primary().get_transaction_count(self.address).pending().await?)
    }

    pub async fn sign(&self, nonce: u64, to: Address, data: Bytes, gas: u64, fees: (u128, u128))
        -> Result<(Bytes, B256)>
    {
        let tx = TransactionRequest::default()
            .with_from(self.address).with_to(to).with_input(data).with_nonce(nonce)
            .with_chain_id(self.number).with_gas_limit(gas)
            .with_max_fee_per_gas(fees.0).with_max_priority_fee_per_gas(fees.1.min(fees.0));
        let env = tx.build(&self.wallet).await.map_err(|e| anyhow!("sign: {e}"))?;
        let hash = *env.tx_hash();
        Ok((Bytes::from(env.encoded_2718()), hash))
    }

    pub async fn send_raw(&self, raw: &Bytes) -> Result<()> {
        self.primary().send_raw_transaction(raw).await?;
        Ok(())
    }

    pub async fn finalized_number(&self) -> Result<Option<u64>> {
        Ok(self.primary().get_block_by_number(BlockNumberOrTag::Finalized).await.ok().flatten()
            .map(|b| b.header.number))
    }

    pub async fn block_hash(p: &DynProvider, n: u64) -> Option<B256> {
        p.get_block_by_number(BlockNumberOrTag::Number(n)).await.ok().flatten().map(|b| b.header.hash)
    }
}

pub fn revert_reason(e: &alloy::transports::TransportError) -> String {
    match e.as_error_resp().and_then(|r| r.as_revert_data()) {
        Some(data) => decode_revert(&data),
        None => format!("{e}"),
    }
}
```

`src/submit.rs`:

```rust
//! Mô-đun `submit`: MỘT task mỗi chain, sở hữu duy nhất nonce vỏ (§23.1).
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::abi::IMetaToken;
use crate::chain::Chain;
use crate::config::ChainCfg;
use crate::nonce::{bump, plan, Inflight};
use crate::odoo::{Job, Odoo, Report};

/// Một việc cần lên chain: job outbox Odoo (`job_id`) hoặc việc của gateway (`None`).
#[derive(Debug, Clone)]
pub struct Work {
    pub job_id: Option<i64>,
    pub to: Address,
    pub data: Bytes,
    pub valid_until: u64,
}

struct Sent {
    work: Option<Work>,
    hash: B256,
    gas: u64,
    fees: (u128, u128),
    at: Instant,
}

pub fn work_from_job(job: &Job) -> Result<Work> {
    let m = job.metatx.to_sol()?;
    let sig = alloy::hex::decode(job.signature.trim_start_matches("0x"))?;
    let data = IMetaToken::executeMetaTransactionCall { m: m.clone(), signature: sig.into() }.abi_encode();
    Ok(Work { job_id: Some(job.id), to: job.token, data: data.into(), valid_until: m.validUntil.saturating_to() })
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub struct Submitter {
    chain: Chain,
    odoo: Odoo,
    cfg: ChainCfg,
    node_id: String,
    next: u64,
    inflight: BTreeMap<u64, Sent>,
}

impl Submitter {
    pub async fn start(chain: Chain, odoo: Odoo, cfg: ChainCfg, node_id: String) -> Result<Self> {
        let nc = odoo.node_config(cfg.evm_chain_number, Some(chain.address())).await?;
        let pending = chain.pending_nonce().await?;
        let jobs: Vec<Inflight> = nc.inflight.iter().map(|j| Inflight {
            job_id: j.job_id, nonce: j.nonce.unwrap_or(u64::MAX), state: j.state.clone() }).collect();
        let p = plan(pending, nc.journal_max_nonce, &jobs);
        let mut me = Self { chain, odoo, cfg, node_id, next: p.next, inflight: BTreeMap::new() };
        for n in &p.gap_fill {
            me.gap_fill(*n).await?;
        }
        for id in &p.requeue {
            me.report(*id, "queued", None, None, None).await;
        }
        for j in nc.inflight.iter().filter(|j| p.track.contains(&j.job_id)) {
            let (Some(n), Some(h)) = (j.nonce, j.tx_hash.as_deref()) else { continue };
            let work = work_from_job(&j.payload).ok();
            let fees = me.chain.fees().await?;
            me.inflight.insert(n, Sent { work, hash: h.parse()?, gas: me.cfg.max_gas_per_tx, fees, at: Instant::now() });
        }
        info!(chain = me.cfg.evm_chain_number, next = me.next, "submit ready");
        Ok(me)
    }

    async fn report(&self, job: i64, state: &str, hash: Option<B256>, nonce: Option<u64>, err: Option<String>) {
        let r = Report {
            job_id: job, chain_state: state.into(), tx_hash: hash.map(|h| format!("{h:#x}")),
            outer_nonce: nonce, signer_address: nonce.map(|_| format!("{:#x}", self.chain.address())),
            error: err,
        };
        if let Err(e) = self.odoo.relay_report(&r).await {
            warn!(job, state, "relay_report failed: {e:#}");
        }
    }

    /// Tx 0-value tự chuyển ở đúng `nonce` — lấp lỗ, không bao giờ bỏ nonce (R18).
    async fn gap_fill(&mut self, nonce: u64) -> Result<()> {
        let fees = self.chain.fees().await?;
        let (raw, hash) = self.chain.sign(nonce, self.chain.address(), Bytes::new(), 21_000, fees).await?;
        self.chain.send_raw(&raw).await?;
        self.inflight.insert(nonce, Sent { work: None, hash, gas: 21_000, fees, at: Instant::now() });
        warn!(nonce, "gap-filled");
        Ok(())
    }

    pub async fn submit(&mut self, w: Work) {
        if w.valid_until <= now() {
            if let Some(id) = w.job_id {
                self.report(id, "dead", None, None, Some("expired before submit".into())).await;
            }
            return;
        }
        let gas = match self.chain.simulate(w.to, w.data.clone()).await {
            Ok(g) if g <= self.cfg.max_gas_per_tx => g + g / 5,
            Ok(g) => return self.fail(&w, format!("gas {g} above max_gas_per_tx")).await,
            Err(reason) => return self.fail(&w, reason).await,
        };
        let fees = match self.chain.fees().await {
            Ok(f) => f,
            Err(e) => return self.requeue(&w, format!("fees: {e:#}")).await,
        };
        let nonce = self.next;
        let (raw, hash) = match self.chain.sign(nonce, w.to, w.data.clone(), gas, fees).await {
            Ok(x) => x,
            Err(e) => return self.requeue(&w, format!("{e:#}")).await,
        };
        // Journal TRƯỚC khi gửi (review F5): crash giữa hai bước không dẫn tới ký lại.
        if let Some(id) = w.job_id {
            self.report(id, "signed", Some(hash), Some(nonce), None).await;
        }
        self.next += 1;
        if let Err(e) = self.chain.send_raw(&raw).await {
            warn!(nonce, "send failed, will replace: {e:#}");
        } else if let Some(id) = w.job_id {
            self.report(id, "broadcast", None, None, None).await;
        }
        self.inflight.insert(nonce, Sent { work: Some(w), hash, gas, fees, at: Instant::now() });
    }

    async fn fail(&self, w: &Work, reason: String) {
        warn!(job = ?w.job_id, "simulation refused: {reason}");
        if let Some(id) = w.job_id {
            self.report(id, "dead", None, None, Some(reason)).await;
        }
    }

    async fn requeue(&self, w: &Work, reason: String) {
        warn!(job = ?w.job_id, "transient, requeue: {reason}");
        if let Some(id) = w.job_id {
            self.report(id, "queued", None, None, Some(reason)).await;
        }
    }

    /// Receipt → mined/reverted; quá hạn → thay thế cùng nonce. Meta-tx hết hạn ⇒ lấp lỗ.
    pub async fn track(&mut self) {
        let nonces: Vec<u64> = self.inflight.keys().copied().collect();
        for n in nonces {
            let Some(s) = self.inflight.get(&n) else { continue };
            let hash = s.hash;
            match self.chain.primary().get_transaction_receipt(hash).await {
                Ok(Some(rc)) => {
                    let s = self.inflight.remove(&n).expect("present");
                    if let Some(id) = s.work.and_then(|w| w.job_id) {
                        let st = if rc.status() { "mined" } else { "reverted" };
                        self.report(id, st, None, None, None).await;
                    }
                    continue;
                }
                Ok(None) => {}
                Err(e) => { warn!(nonce = n, "receipt: {e:#}"); continue; }
            }
            if s.at.elapsed() < Duration::from_secs(self.cfg.stuck_after_secs) {
                continue;
            }
            let cap = u128::from(self.cfg.max_fee_cap_gwei) * 1_000_000_000;
            let fees = (bump(s.fees.0, cap), bump(s.fees.1, cap));
            let (to, data, gas, job) = match &s.work {
                Some(w) if w.valid_until > now() => (w.to, w.data.clone(), s.gas, w.job_id),
                _ => (self.chain.address(), Bytes::new(), 21_000, None),
            };
            if let (Some(id), None) = (s.work.as_ref().and_then(|w| w.job_id), job) {
                self.report(id, "dead", None, None, Some("expired while stuck; nonce gap-filled".into())).await;
            }
            match self.chain.sign(n, to, data, gas, fees).await {
                Ok((raw, h)) => {
                    let _ = self.chain.send_raw(&raw).await;
                    if let Some(id) = job {
                        self.report(id, "broadcast", Some(h), None, None).await;
                    }
                    let keep = if job.is_some() { s.work.clone() } else { None };
                    self.inflight.insert(n, Sent { work: keep, hash: h, gas, fees, at: Instant::now() });
                    info!(nonce = n, "replaced");
                }
                Err(e) => warn!(nonce = n, "replace sign: {e:#}"),
            }
        }
    }

    pub async fn poll_outbox(&mut self) {
        let jobs = match self.odoo.relay_poll(self.cfg.evm_chain_number, 10).await {
            Ok(j) => j,
            Err(e) => { warn!("relay_poll: {e:#}"); return; }
        };
        for job in jobs {
            match self.odoo.relay_claim(&[job.id], &self.node_id).await {
                Ok(ids) if ids.contains(&job.id) => {}
                Ok(_) => continue,
                Err(e) => { warn!("relay_claim: {e:#}"); continue; }
            }
            match work_from_job(&job) {
                Ok(w) => self.submit(w).await,
                Err(e) => self.report(job.id, "dead", None, None, Some(format!("bad payload: {e:#}"))).await,
            }
        }
    }
}

pub async fn run(mut s: Submitter, mut rx: mpsc::Receiver<Work>, poll: Duration) {
    loop {
        s.poll_outbox().await;
        while let Ok(w) = rx.try_recv() {
            s.submit(w).await;
        }
        s.track().await;
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            Some(w) = rx.recv() => s.submit(w).await,
        }
    }
}

#[allow(dead_code)]
fn _u256(v: u64) -> U256 { U256::from(v) }
```

(Delete the `_u256` helper if `U256` ends up unused; it only exists to keep the import set obvious to a reader of the plan.)

- [ ] **Step 2: Build** `cd scaas-node && cargo build` → compiles (warnings for unused `indexer/gateway` modules are fine at this step). Unit tests stay green: `cargo test`.
- [ ] **Step 3: Commit** `git commit -m "feat(node): json/2 client, chain context and outbox submitter that never abandons a nonce"`

(The submit loop's behaviour is proven in Task 8's end-to-end test; mocking alloy's provider for unit tests would test the mock.)

---

### Task 6: Indexer loop + gateway

**Files:** Create `scaas-node/src/indexer.rs`, `src/gateway.rs`; Modify `main.rs`.

**Interfaces:**
- Produces: `indexer::run(chain: Arc<Chain>, odoo: Odoo, poll: Duration)`; `indexer::encode_event(&Log) -> Option<serde_json::Value>`; `gateway::AppState { chains: HashMap<u64, GwChain> }`, `GwChain { chain: Arc<Chain>, tx: mpsc::Sender<Work>, tokens: Arc<RwLock<Vec<Address>>>, dex: Option<Address>, book: Arc<Mutex<Book>> }`, `gateway::router(state) -> axum::Router`, request bodies `MetaTxReq { chain: u64, token: Address, m: WireMetaTx, signature: String }`, `OrderReq { chain: u64, token: Address, m: WireMetaTx, signature: String }`.

- [ ] **Step 1: Failing test** for event encoding (in `indexer.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, LogData, B256, U256};
    use alloy::sol_types::SolEvent;

    #[test]
    fn payment_settled_is_encoded_for_odoo() {
        let ev = IMetaToken::PaymentSettled {
            from: Address::repeat_byte(1), to: Address::repeat_byte(2), amount: U256::from(250u64),
            feeAmount: U256::ZERO, feeRecipient: Address::repeat_byte(3), entryRef: B256::repeat_byte(4),
        };
        let data: LogData = ev.encode_log_data();
        let log = Log {
            inner: alloy::primitives::Log { address: Address::repeat_byte(9), data },
            block_hash: Some(B256::repeat_byte(0xb)), block_number: Some(5),
            transaction_hash: Some(B256::repeat_byte(0xe)), log_index: Some(2), ..Default::default()
        };
        let v = encode_event(&log).unwrap();
        assert_eq!(v["event"], "PaymentSettled");
        assert_eq!(v["amount"], "250");
        assert_eq!(v["entry_ref"], format!("{:#x}", B256::repeat_byte(4)));
        assert_eq!(v["log_index"], 2);
        assert_eq!(v["contract"], format!("{:#x}", Address::repeat_byte(9)));
    }
}
```

- [ ] **Step 2: Run** `cargo test indexer` → FAIL.

- [ ] **Step 3: Implement** — `src/indexer.rs`:

```rust
//! Mô-đun `indexer`: chỉ gửi vùng đã final, chỉ khi đủ quorum (spec §3.3).
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::SolEvent;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::abi::IMetaToken;
use crate::chain::Chain;
use crate::finality::{next_range, quorum_ok, safe_head, Mode};
use crate::odoo::Odoo;

const MAX_SPAN: u64 = 1000;

pub fn encode_event(log: &Log) -> Option<Value> {
    let base = json!({
        "contract": format!("{:#x}", log.address()),
        "block_number": log.block_number?,
        "block_hash": format!("{:#x}", log.block_hash?),
        "tx_hash": format!("{:#x}", log.transaction_hash?),
        "log_index": log.log_index?,
    });
    let mut v = base;
    match log.topic0().copied()? {
        t if t == IMetaToken::PaymentSettled::SIGNATURE_HASH => {
            let e = log.log_decode::<IMetaToken::PaymentSettled>().ok()?.inner.data;
            v["event"] = json!("PaymentSettled");
            v["from"] = json!(format!("{:#x}", e.from));
            v["to"] = json!(format!("{:#x}", e.to));
            v["amount"] = json!(e.amount.to_string());
            v["fee"] = json!(e.feeAmount.to_string());
            v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
            v["entry_ref"] = json!(format!("{:#x}", e.entryRef));
        }
        t if t == IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH => {
            let e = log.log_decode::<IMetaToken::MetaTransactionExecuted>().ok()?.inner.data;
            v["event"] = json!("MetaTransactionExecuted");
            v["from"] = json!(format!("{:#x}", e.from));
            v["relayer"] = json!(format!("{:#x}", e.relayer));
            v["batch"] = json!(e.batch.to_string());
            v["nonce"] = json!(e.nonce.to_string());
            v["digest"] = json!(format!("{:#x}", e.digest));
            v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
            v["fee"] = json!(e.fee.to_string());
        }
        _ => return None,
    }
    Some(v)
}

pub async fn run(chain: Arc<Chain>, odoo: Odoo, poll: Duration) {
    loop {
        if let Err(e) = step(&chain, &odoo).await {
            warn!(chain = chain.number, "indexer: {e:#}");
        }
        tokio::time::sleep(poll).await;
    }
}

/// Một vòng: đọc cấu hình (cursor + token) từ Odoo, tính vùng final, quorum, gửi.
pub async fn step(chain: &Chain, odoo: &Odoo) -> anyhow::Result<bool> {
    let nc = odoo.node_config(chain.number, None).await?;
    let mode = if nc.finality_mode == "tag" { Mode::Tag } else { Mode::Depth(nc.finality_depth) };
    let latest = chain.primary().get_block_number().await?;
    let finalized = if mode == Mode::Tag { chain.finalized_number().await? } else { None };
    let Some(safe) = safe_head(&mode, latest, finalized) else { return Ok(false) };
    let Some((from, to)) = next_range(nc.indexed_block, safe, MAX_SPAN) else { return Ok(false) };
    let Some(hash) = Chain::block_hash(chain.primary(), to).await else { return Ok(false) };
    let mut others = Vec::new();
    for p in chain.others() {
        others.push(Chain::block_hash(p, to).await);
    }
    if !quorum_ok(hash, &others, nc.finality_quorum) {
        warn!(chain = chain.number, block = to, "quorum not reached; not advancing");
        return Ok(false);
    }
    let addrs: Vec<Address> = nc.tokens.iter().map(|t| t.address).collect();
    let events: Vec<Value> = if addrs.is_empty() {
        vec![]
    } else {
        let f = Filter::new().from_block(from).to_block(to).address(addrs).event_signature(vec![
            IMetaToken::PaymentSettled::SIGNATURE_HASH, IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH]);
        chain.primary().get_logs(&f).await?.iter().filter_map(encode_event).collect()
    };
    let r = odoo.ingest(chain.number, from, to, &format!("{hash:#x}"), &events).await?;
    info!(chain = chain.number, from, to, created = r.created, "ingested");
    Ok(true)
}
```

`src/gateway.rs`:

```rust
//! Mô-đun `gateway`: relayer mở (SRS §4.9.4). Không xác thực; giới hạn kích thước và đồng thời.
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};

use alloy::primitives::{Address, Bytes};
use alloy::sol_types::SolCall;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::limit::GlobalConcurrencyLimitLayer;

use crate::abi::{IMetaToken, IMetaTxDex, Leg};
use crate::chain::Chain;
use crate::dex::{Book, Order};
use crate::metatx::{WireMetaTx, MODE_FEE_MASK, MODE_RESTRICT_FEE_RECIPIENT};
use crate::submit::Work;

#[derive(Clone)]
pub struct GwChain {
    pub chain: Arc<Chain>,
    pub tx: mpsc::Sender<Work>,
    pub tokens: Arc<RwLock<Vec<Address>>>,
    pub dex: Option<Address>,
    pub book: Arc<Mutex<Book>>,
}

#[derive(Clone, Default)]
pub struct AppState {
    pub chains: Arc<HashMap<u64, GwChain>>,
}

#[derive(Deserialize)]
pub struct SignedReq {
    pub chain: u64,
    pub token: Address,
    pub m: WireMetaTx,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct BookQuery {
    pub chain: u64,
    pub sell: Address,
    pub buy: Address,
}

type Reply = (StatusCode, Json<Value>);

fn bad(msg: impl ToString) -> Reply {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.to_string()})))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/metatx", post(post_metatx))
        .route("/v1/dex/orders", post(post_order).get(get_orders))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(GlobalConcurrencyLimitLayer::new(32))
        .with_state(state)
}

fn chain_of<'a>(s: &'a AppState, id: u64, token: Address) -> Result<&'a GwChain, Reply> {
    let c = s.chains.get(&id).ok_or_else(|| bad("unknown chain"))?;
    if !c.tokens.read().map(|t| t.contains(&token)).unwrap_or(false) {
        return Err(bad("token not served by this relayer"));
    }
    Ok(c)
}

fn sig_bytes(s: &str) -> Result<Bytes, Reply> {
    let raw = alloy::hex::decode(s.trim_start_matches("0x")).map_err(|_| bad("signature is not hex"))?;
    if raw.len() < 65 || raw.len() > 2048 {
        return Err(bad("signature length"));
    }
    Ok(raw.into())
}

async fn post_metatx(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
    let c = match chain_of(&s, r.chain, r.token) { Ok(c) => c, Err(e) => return e };
    let m = match r.m.to_sol() { Ok(m) => m, Err(e) => return bad(e) };
    let sig = match sig_bytes(&r.signature) { Ok(x) => x, Err(e) => return e };
    if m.validUntil <= alloy::primitives::U256::from(now()) {
        return bad("expired");
    }
    let data: Bytes = IMetaToken::executeMetaTransactionCall { m: m.clone(), signature: sig }.abi_encode().into();
    if let Err(reason) = c.chain.simulate(r.token, data.clone()).await {
        return bad(format!("simulation: {reason}"));
    }
    let w = Work { job_id: None, to: r.token, data, valid_until: m.validUntil.saturating_to() };
    if c.tx.send(w).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "submit stopped"})));
    }
    (StatusCode::ACCEPTED, Json(json!({"status": "queued"})))
}

async fn post_order(State(s): State<AppState>, Json(r): Json<SignedReq>) -> Reply {
    let c = match chain_of(&s, r.chain, r.token) { Ok(c) => c, Err(e) => return e };
    let Some(dex) = c.dex else { return bad("no DEX on this chain") };
    let mut m = match r.m.to_sol() { Ok(m) => m, Err(e) => return bad(e) };
    let sig = match sig_bytes(&r.signature) { Ok(x) => x, Err(e) => return e };
    if m.to != dex || m.relayer != dex {
        return bad("leg must be routed through this DEX");
    }
    // Phí không ràng buộc + feeRecipient 0 ⇒ phí rơi vào DEX: điền địa chỉ relayer (review F10).
    if m.mode & MODE_FEE_MASK != 0 {
        if m.mode & MODE_RESTRICT_FEE_RECIPIENT == 0 {
            if m.feeRecipient == Address::ZERO {
                m.feeRecipient = c.chain.address();
            }
        } else if m.feeRecipient == Address::ZERO || m.feeRecipient == dex {
            return bad("restricted fee recipient would strand the fee in the DEX");
        }
    }
    let order = Order { token: r.token, m: m.clone(), sig: sig.clone() };
    if order.terms().is_err() {
        return bad("not a trade leg");
    }
    let data: Bytes = IMetaToken::executeMetaTransactionCall { m, signature: sig }.abi_encode().into();
    if let Err(reason) = c.chain.simulate_as(dex, r.token, data).await {
        return bad(format!("simulation: {reason}"));
    }
    let matched = c.book.lock().map(|mut b| b.insert(order, now())).unwrap_or(None);
    if let Some((rest, inc)) = matched {
        let call = IMetaTxDex::settleCall {
            a: Leg { token: rest.token, m: rest.m.clone(), sig: rest.sig.clone() },
            b: Leg { token: inc.token, m: inc.m.clone(), sig: inc.sig.clone() },
        };
        let vu = rest.m.validUntil.min(inc.m.validUntil).saturating_to();
        let w = Work { job_id: None, to: dex, data: call.abi_encode().into(), valid_until: vu };
        if c.tx.send(w).await.is_err() {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "submit stopped"})));
        }
        return (StatusCode::ACCEPTED, Json(json!({"status": "matched"})));
    }
    (StatusCode::ACCEPTED, Json(json!({"status": "resting"})))
}

async fn get_orders(State(s): State<AppState>, Query(q): Query<BookQuery>) -> Reply {
    let Some(c) = s.chains.get(&q.chain) else { return bad("unknown chain") };
    let list: Vec<Value> = c.book.lock().map(|b| b.list(q.sell, q.buy, now()).into_iter().map(|o| json!({
        "from": format!("{:#x}", o.m.from), "value": o.m.value.to_string(),
        "valid_until": o.m.validUntil.to_string(),
        "m": WireMetaTx::from_sol(&o.m), "signature": format!("0x{}", alloy::hex::encode(&o.sig)),
    })).collect()).unwrap_or_default();
    (StatusCode::OK, Json(json!({"orders": list})))
}

#[allow(dead_code)]
fn _parse(a: &str) -> Option<Address> { Address::from_str(a).ok() }
```

(Remove `_parse` if `FromStr` is unused after compiling.)

Settle reverts after a match (state moved between simulation and inclusion) surface as a `reverted` receipt for a gateway work item with no Odoo job: logged, nothing to report. The orders are gone from the book; the signers resubmit — ruling R16.

- [ ] **Step 4: Run** `cargo test` → PASS; `cargo build` → OK.
- [ ] **Step 5: Commit** `git commit -m "feat(node): finality-gated indexer and open gateway with DEX matching"`

---

### Task 7: `main.rs` wiring, sample config, README

**Files:** Modify `scaas-node/src/main.rs`; Create `scaas-node/node.example.toml`, `scaas-node/README.md`.

- [ ] **Step 1: Implement** `main.rs`:

```rust
mod abi;
mod chain;
mod config;
mod dex;
mod finality;
mod gateway;
mod indexer;
mod metatx;
mod nonce;
mod odoo;
mod submit;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{bail, Result};
use tokio::sync::mpsc;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    let path = match args.iter().position(|a| a == "--config") {
        Some(i) if i + 1 < args.len() => PathBuf::from(&args[i + 1]),
        _ => bail!("usage: scaas-node --config node.toml"),
    };
    let cfg = config::Config::load(&path)?;
    let node_id = std::env::var("SCAAS_NODE_ID").unwrap_or_else(|_| "scaas-node".into());
    let mut gw_chains = HashMap::new();
    let mut tasks = Vec::new();

    for cc in &cfg.chains {
        let poll = Duration::from_millis(cc.poll_ms);
        let chain = Arc::new(chain::Chain::connect(cc)?);
        let (tx, rx) = mpsc::channel::<submit::Work>(256);
        let tokens = Arc::new(RwLock::new(Vec::new()));
        if cfg.modules.submit {
            let odoo = odoo::Odoo::new(&cfg.odoo, &cfg.odoo.relay_api_key_env)?;
            let s = submit::Submitter::start(chain::Chain::connect(cc)?, odoo.clone(), cc.clone(), node_id.clone()).await?;
            tasks.push(tokio::spawn(submit::run(s, rx, poll)));
            // Danh sách token của gateway = danh sách Odoo, làm mới mỗi 30 s.
            let (t, n, num) = (tokens.clone(), odoo, cc.evm_chain_number);
            tasks.push(tokio::spawn(async move {
                loop {
                    if let Ok(nc) = n.node_config(num, None).await {
                        if let Ok(mut w) = t.write() { *w = nc.tokens.iter().map(|x| x.address).collect(); }
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }));
        }
        if cfg.modules.indexer {
            let odoo = odoo::Odoo::new(&cfg.odoo, &cfg.odoo.indexer_api_key_env)?;
            tasks.push(tokio::spawn(indexer::run(chain.clone(), odoo, poll)));
        }
        gw_chains.insert(cc.evm_chain_number, gateway::GwChain {
            chain, tx, tokens, dex: cc.dex, book: Arc::new(Mutex::new(dex::Book::default())) });
    }
    if cfg.modules.gateway {
        if !cfg.modules.submit {
            bail!("gateway needs the submit module");
        }
        let app = gateway::router(gateway::AppState { chains: Arc::new(gw_chains) });
        let listener = tokio::net::TcpListener::bind(&cfg.modules.gateway_bind).await?;
        info!(bind = %cfg.modules.gateway_bind, "gateway listening");
        tasks.push(tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await { error!("gateway: {e}"); }
        }));
    }
    for t in tasks {
        t.await?;
    }
    Ok(())
}
```

`node.example.toml`: the TOML of spec §3.1 with `[modules] submit = true, indexer = true, gateway = true, gateway_bind = "127.0.0.1:8547"`.

`README.md` (Vietnamese): build (`cargo build --release`), env vars (`SCAAS_RELAY_API_KEY`, `SCAAS_INDEXER_API_KEY`, `SCAAS_RELAYER_KEY_9000`, `SCAAS_NODE_ID`), creating the two Odoo service users + API keys (Settings → Users; groups "Blockchain Relay Worker (service)" / "Blockchain Indexer (service)"; Account Security → New API Key), running against chain 9000, and the e2e test command.

- [ ] **Step 2: Build** `cargo build && cargo clippy -- -D warnings` (fix lints) → OK.
- [ ] **Step 3: Commit** `git commit -m "feat(node): wire submit, indexer and gateway into one binary"`

---

### Task 8: End-to-end test on anvil + real contracts + fake Odoo

**Files:** Create `scaas-node/tests/e2e.rs`. Modify `Cargo.toml` (`[lib]` so the test can use the crate: add `src/lib.rs` re-exporting modules and make `main.rs` use `scaas_node::*`).

**Interfaces:**
- Consumes: everything; `smartcontracts/script/Deploy.s.sol` (`deployments/9000.json`).

- [ ] **Step 1: Write the test** — `tests/e2e.rs`:

```rust
//! cargo test --test e2e -- --ignored --nocapture
//! Cần `anvil` và `forge` trong PATH. Chứng minh trên EVM thật: job outbox → simulate → ký →
//! broadcast → receipt → indexer gửi PaymentSettled + MetaTransactionExecuted; và DEX: hai lệnh
//! qua gateway → khớp → settle on-chain.
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{SolCall, SolValue};
use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use scaas_node::abi::{IMetaToken, MetaTransaction};
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use scaas_node::metatx::{digest, Domain, WireMetaTx, MODE_RESTRICT_RELAYER};
use serde_json::{json, Value};

const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const RELAYER: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const PAYER_PK: &str = "0x00000000000000000000000000000000000000000000000000000000000a11ce";

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) { let _ = self.0.kill(); }
}

#[derive(Default)]
struct FakeOdoo {
    jobs: Vec<Value>,
    reports: Vec<Value>,
    ingested: Vec<Value>,
    indexed_block: u64,
    token: String,
}

async fn fake(State(s): State<Arc<Mutex<FakeOdoo>>>, Path((model, method)): Path<(String, String)>,
              Json(body): Json<Value>) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "evm_chain_number": 9000, "finality_mode": "depth", "finality_depth": 0, "finality_quorum": 1,
            "indexed_block": o.indexed_block, "tokens": [{"address": o.token, "decimals": 6}],
            "journal_max_nonce": null, "inflight": []}),
        ("blockchain.relay.job", "relay_poll") => json!(std::mem::take(&mut o.jobs)),
        ("blockchain.relay.job", "relay_claim") => body["job_ids"].clone(),
        ("blockchain.relay.job", "relay_report") => { o.reports.push(body.clone()); json!({"ok": true}) }
        ("blockchain.chain.event", "chain_event_ingest") => {
            o.indexed_block = body["to_block"].as_u64().unwrap();
            o.ingested.extend(body["events"].as_array().unwrap().iter().cloned());
            json!({"indexed_block": o.indexed_block, "created": 0})
        }
        _ => json!({"error": "unexpected"}),
    };
    Json(out)
}

#[tokio::test]
#[ignore]
async fn outbox_payment_reaches_chain_and_comes_back_final() {
    let port = 18600 + (std::process::id() % 300) as u16;
    let rpc = format!("http://127.0.0.1:{port}");
    let _anvil = Anvil(Command::new("anvil").args(["--chain-id", "9000", "--hardfork", "prague",
        "--port", &port.to_string(), "--silent"]).stdout(Stdio::null()).spawn().expect("anvil"));
    tokio::time::sleep(Duration::from_millis(800)).await;

    let sc = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts");
    let payer = PrivateKeySigner::from_bytes(&PAYER_PK.parse().unwrap()).unwrap();
    let st = Command::new("forge").current_dir(sc)
        .args(["script", "script/Deploy.s.sol", "--rpc-url", &rpc, "--broadcast", "--silent"])
        .env("PRIVATE_KEY", DEPLOYER).env("DEMO_SUPPLY", "1000000000000")
        .env("DEMO_HOLDER", format!("{:#x}", payer.address())).env("FOUNDRY_PROFILE", "private9000")
        .status().expect("forge");
    assert!(st.success());
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(format!("{sc}/deployments/9000.json")).unwrap()).unwrap();
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();

    // Fake Odoo holding one signed payment job.
    let relayer = PrivateKeySigner::from_bytes(&RELAYER.parse().unwrap()).unwrap();
    let shop = Address::repeat_byte(0x5e);
    let entry_ref = keccak256(b"order-1");
    let mut data = keccak256(b"pay(bytes32)")[..4].to_vec();
    data.extend_from_slice(entry_ref.as_slice());
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let m = MetaTransaction {
        from: payer.address(), to: shop, value: U256::from(250_000_000u64), data: data.into(),
        batch: U256::from_be_bytes(keccak256(b"lane").0), nonce: U256::ZERO, validUntil: U256::from(now + 300),
        mode: MODE_RESTRICT_RELAYER, relayer: relayer.address(), fee: U256::ZERO, feeRecipient: Address::ZERO,
    };
    let domain = Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: 9000, verifying_contract: token };
    let d = digest(&domain, &m);
    let sig = payer.sign_hash_sync(&d).unwrap().as_bytes();
    let state = Arc::new(Mutex::new(FakeOdoo { token: format!("{token:#x}"), ..Default::default() }));
    state.lock().unwrap().jobs.push(json!({"id": 1, "token": format!("{token:#x}"), "digest": format!("{d:#x}"),
        "signature": format!("0x{}", alloy::hex::encode(sig)), "metatx": WireMetaTx::from_sol(&m)}));
    let app = Router::new().route("/json/2/{model}/{method}", post(fake)).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Fund the relayer wallet (anvil account #1 already has ETH) and run one submit + track cycle.
    let ccfg = ChainCfg {
        evm_chain_number: 9000, rpc_urls: vec![rpc.clone()], signer_key_env: String::new(),
        finality: FinalityCfg { mode: "depth".into(), depth: 0, quorum: 1 }, dex: None, poll_ms: 200,
        stuck_after_secs: 60, max_gas_per_tx: 3_000_000, max_fee_cap_gwei: 500,
    };
    let ocfg = OdooCfg { url: format!("http://{addr}"), database: "t".into(), relay_api_key_env: String::new(),
                         indexer_api_key_env: String::new() };
    let odoo = scaas_node::odoo::Odoo::with_key(&ocfg, "k".into());
    let chain = scaas_node::chain::Chain::with_signer(&ccfg, relayer.clone()).unwrap();
    let mut s = scaas_node::submit::Submitter::start(chain, odoo.clone(), ccfg.clone(), "e2e".into()).await.unwrap();
    s.poll_outbox().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    s.track().await;

    let reports = state.lock().unwrap().reports.clone();
    let states: Vec<&str> = reports.iter().map(|r| r["chain_state"].as_str().unwrap()).collect();
    assert_eq!(states, vec!["signed", "broadcast", "mined"], "{reports:?}");

    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let bal = IMetaToken::balanceOfCall { who: shop }.abi_encode();
    let out = p.call(alloy::rpc::types::TransactionRequest::default().to(token).input(bal.into())).await.unwrap();
    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(250_000_000u64));

    // Indexer: one step sends the finalized PaymentSettled + MetaTransactionExecuted.
    let ichain = scaas_node::chain::Chain::with_signer(&ccfg, relayer).unwrap();
    assert!(scaas_node::indexer::step(&ichain, &odoo).await.unwrap());
    let ingested = state.lock().unwrap().ingested.clone();
    let names: Vec<&str> = ingested.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert!(names.contains(&"PaymentSettled") && names.contains(&"MetaTransactionExecuted"), "{ingested:?}");
    let pay = ingested.iter().find(|e| e["event"] == "PaymentSettled").unwrap();
    assert_eq!(pay["entry_ref"], format!("{entry_ref:#x}"));
    assert_eq!(pay["digest"], Value::Null);
    let _ = Bytes::new();
}
```

A second test `dex_orders_match_through_the_gateway` in the same file: deploy, create a second token `BBB` via `forge create`-free path (call `OpenFactory.createMetaToken` with the deployer through alloy), fund alice/bob, start a `gateway::router` with a `GwChain` whose `tx` feeds a `Submitter` driven in the test loop, POST two crossing orders with `reqwest`, run `poll_outbox`/drain/`track`, and assert balances swapped. (Write it with the same helpers; the order JSON is `{"chain": 9000, "token": "<addr>", "m": <WireMetaTx>, "signature": "0x…"}`.)

- [ ] **Step 2: Run** `cd scaas-node && cargo test --test e2e -- --ignored --nocapture`
Expected: both PASS.
- [ ] **Step 3: Commit** `git commit -m "test(node): end-to-end on anvil - outbox payment and DEX match against the real contracts"`

---

## Self-review

| Spec item | Task |
|---|---|
| §3.1 config, quorum ≤ endpoints | 1 |
| §3.2 poll/claim/simulate/sign/report-before-send/track/replace/gap-fill, cold start | 4, 5, 8 |
| §3.3 safe head (depth/tag), contiguous range, quorum, registered contracts only, ingest | 2, 6, 8 |
| §3.4 gateway routes, body/concurrency limits, fee-recipient fill, DEX simulate-as | 6 |
| §3.4 matcher (FIFO, fill-or-kill, counterparty, expiry) | 3, 8 |
| §6 digest parity with KAT | 1 |
| §7 keys only from env, `Signer` seam | 5 (`Chain::connect`/`with_signer`) |
| §8 relayer down / crash after send / stuck tx | 4, 5 |

Gap noted and accepted: the gateway work items are not persisted (R16).
