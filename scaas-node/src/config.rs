use std::path::Path;

use crate::keys::{self, SecretSource, Seed};
use crate::signer::LocalSigner;

use alloy::primitives::{Address, B256};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::store;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    // legacy(R104): đường pull qua Odoo, xoá ở P9. Bắt buộc khi một mô-đun còn chạy trên đường đó.
    #[serde(default)]
    pub odoo: Option<OdooCfg>,
    /// Store v2, luôn mở (R88, R111). `url` chỉ ở toml/env (R95).
    pub store: StoreCfg,
    #[serde(default)]
    pub api: ApiCfg,
    /// Bootstrap (R95): import vào store khi vắng mặt, không ghi đè.
    #[serde(default)]
    pub namespaces: Vec<NamespaceCfg>,
    #[serde(default)]
    pub mesh: Option<MeshCfg>,
    /// Khoá Ed25519 của node (gossip §3.1, R116). Chỉ toml.
    #[serde(default)]
    pub identity: Option<IdentityCfg>,
    #[serde(default)]
    pub transport: TransportCfg,
    #[serde(default)]
    pub gossip: GossipCfg,
    /// Mnemonic BIP-39 24 từ cho mọi lane không có `private_key` riêng (R60).
    #[serde(default)]
    pub keys: Option<KeysCfg>,
    #[serde(default)]
    pub modules: Modules,
    /// Group 3f (spec 2026-11-06-attested-verify §11.1): the PQZ verifier (off-chain) endpoints and the shield switch, one section
    /// for every chain (copied into each [`ChainCfg::pqz_verifier`] at load). No secret: endpoint URLs only.
    #[serde(default)]
    pub pqz_verifier: PqzVerifierCfg,
    pub chains: Vec<ChainCfg>,
}

/// `[pqz_verifier]` (group 3f, NODE-JOB-22 draft): where the node asks for a `PqzVerdict` signature an `OFFCHAIN` PQZ job does not
/// carry (`POST {endpoint}/v1/pqz-verdict`, in order), the bounds of that answer, and the opt-in refusal of shields into a token
/// nobody serves. The node holds no verifier key and signs nothing.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PqzVerifierCfg {
    /// Base URLs of PQZ verifiers (off-chain), asked in order; empty: a job without `pqz_verdict` is `PQZ_VERDICT_MISSING`.
    #[serde(default)]
    pub endpoints: Vec<String>,
    /// Refuse shield and wrap-shield jobs into an `OFFCHAIN` token whose verifier is revoked or that no endpoint serves
    /// (`PQZ_VERIFIER_UNREACHABLE`; a probe transport error requeues). Off by default.
    #[serde(default)]
    pub refuse_shield_when_unserved: bool,
    /// One endpoint's whole request (connect, send, answer).
    #[serde(default = "default_pqz_timeout_ms")]
    pub timeout_ms: u64,
    /// An answer above this is no answer (read in chunks, never buffered past it).
    #[serde(default = "default_pqz_max_response")]
    pub max_response_bytes: usize,
    /// A verdict whose `validUntil` is within this many seconds of now is not sent (the expected inclusion plus the margin).
    #[serde(default = "default_pqz_margin")]
    pub valid_margin_secs: u64,
}

impl Default for PqzVerifierCfg {
    fn default() -> Self {
        Self { endpoints: vec![], refuse_shield_when_unserved: false, timeout_ms: default_pqz_timeout_ms(),
            max_response_bytes: default_pqz_max_response(), valid_margin_secs: default_pqz_margin() }
    }
}

fn default_pqz_timeout_ms() -> u64 {
    5_000
}
fn default_pqz_max_response() -> usize {
    256 * 1024
}
fn default_pqz_margin() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeysCfg {
    pub mnemonic: SecretSource,
    #[serde(default)]
    pub bip39_passphrase_env: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreCfg {
    /// `sqlite:///var/lib/scaas/node.db` (PostgreSQL/MySQL: P1b).
    pub url: String,
    #[serde(default = "default_job_retention")]
    pub job_retention_secs: u64,
    #[serde(default = "default_feed_retention")]
    pub feed_retention_secs: u64,
}

/// `[api]` (NI §7.1). Job API và đăng nhập admin chạy từ P2; P1 chỉ đọc và kiểm.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiCfg {
    /// Cổng riêng: không trùng `gateway_bind` (8547) hay `admin_bind` (9108) mặc định (review F12).
    #[serde(default = "default_api_bind")]
    pub bind: String,
    #[serde(default)]
    pub master_key: Option<SecretSource>,
    #[serde(default)]
    pub admin_cors_origins: Vec<String>,
    #[serde(default = "default_lease_hold")]
    pub lease_hold_after_start_secs: u64,
    #[serde(default)]
    pub admin_auth: AdminAuthCfg,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminAuthCfg {
    #[serde(default = "default_modes")]
    pub modes: Vec<String>,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    #[serde(default = "default_session_max_age")]
    pub session_max_age_secs: u64,
    #[serde(default = "default_login_failures")]
    pub login_max_failures: u32,
    #[serde(default = "default_login_lock")]
    pub login_lock_secs: u64,
}

/// Mọi trường đều có default riêng: một bảng rỗng là cấu hình mặc định.
macro_rules! default_from_empty_table {
    ($($t:ty),*) => {$(
        impl Default for $t {
            fn default() -> Self {
                toml::from_str("").expect("every field has a default")
            }
        }
    )*};
}
default_from_empty_table!(ApiCfg, AdminAuthCfg, TransportCfg, GossipCfg);

#[derive(Debug, Clone, Deserialize)]
pub struct NamespaceCfg {
    /// `[a-z0-9-]{3,40}`; tên bắt đầu `~` dành riêng cho node (R90).
    pub name: String,
    /// Chain được cấp (chain key của `[[chains]]`).
    #[serde(default)]
    pub chains: Vec<String>,
    #[serde(default)]
    pub allow_call: bool,
    #[serde(default = "default_max_live_jobs")]
    pub max_live_jobs: u32,
}

/// `[mesh]`: P1 chỉ đọc danh sách bootstrap; các tham số bus (bind, cert…) đến cùng S5.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MeshCfg {
    #[serde(default)]
    pub peers: Vec<PeerCfg>,
    #[serde(default)]
    pub policy: Vec<PolicyCfg>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerCfg {
    pub name: String,
    pub url: String,
    pub spki_sha256: String,
    /// `open` | `private`.
    pub class: String,
    #[serde(default)]
    pub chains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyCfg {
    pub chain: String,
    pub contract: String,
    pub selector: String,
    /// `none` | `forward_only` | `full`.
    pub support: String,
    #[serde(default)]
    pub submit: bool,
    /// `open` | `private` | `none`.
    pub pool_visibility: String,
    #[serde(default = "zero")]
    pub min_fee: String,
    /// `any` | `self_or_zero`.
    #[serde(default = "any")]
    pub fee_recipient_allow: String,
    #[serde(default)]
    pub gossip: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityCfg {
    pub key: SecretSource,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransportCfg {
    #[serde(default = "yes")]
    pub quic: bool,
    #[serde(default = "yes")]
    pub tcp: bool,
    #[serde(default = "yes")]
    pub https: bool,
}

/// `[gossip]` (gossip §3.1). P1: chỉ đọc và kiểm, không mạng (G1).
#[derive(Debug, Clone, Deserialize)]
pub struct GossipCfg {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub external: Vec<String>,
    #[serde(default)]
    pub bootstrap: Vec<String>,
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub allow_private_addrs: bool,
    #[serde(default = "default_max_established")]
    pub max_established: u32,
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
    /// `none` (chỉ khi bind loopback) | `bearer` | `hmac` (R54).
    #[serde(default = "auth_none")]
    pub gateway_auth: String,
    #[serde(default)]
    pub gateway_secret_env: Option<String>,
    /// Cổng quản trị `/healthz` `/readyz` `/metrics`, tách khỏi gateway (R51). Chuỗi rỗng = tắt.
    #[serde(default = "default_admin_bind")]
    pub admin_bind: String,
}

impl Default for Modules {
    fn default() -> Self {
        Self {
            submit: true,
            indexer: true,
            gateway: false,
            gateway_bind: default_bind(),
            gateway_auth: auth_none(),
            gateway_secret_env: None,
            admin_bind: default_admin_bind(),
        }
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
    /// `evm` (mặc định) | `hedera` | `sui` | `soroban` | `cosmos` | `ton` | `solana` | `aptos` | `near` | `algorand`.
    #[serde(default = "evm")]
    pub family: String,
    /// Mạng ngoài EVM: `localnet`, `testnet`, chain-id Cosmos, genesis hash Solana (base58), chain id Aptos (`1`, `2`,
    /// `4`)… (khoá `family:network`).
    #[serde(default)]
    pub network: Option<String>,
    /// EIP-155 chain id (EVM/Hedera); 0 cho họ khác.
    #[serde(default)]
    pub evm_chain_number: u64,
    pub rpc_urls: Vec<String>,
    /// Cũ: tên biến môi trường giữ khoá thô của MỘT lane EVM.
    #[serde(default)]
    pub signer_key_env: String,
    /// Khoá thô của MỘT lane (thay cho mnemonic).
    #[serde(default)]
    pub private_key: Option<SecretSource>,
    /// Account index của các lane dẫn xuất từ `[keys].mnemonic` (R62: nhiều lane, không khoá toàn cục).
    #[serde(default = "lane0")]
    pub lanes: Vec<u32>,
    /// Coin type SLIP-44 thay mặc định của họ mạng cho các lane mnemonic (Pi Network: `soroban` + 314159).
    #[serde(default)]
    pub coin_type: Option<u32>,
    /// Tham số riêng của adapter (package id Sui, passphrase mạng Stellar, prefix bech32…).
    #[serde(default)]
    pub params: toml::Table,
    #[serde(default = "default_finality")]
    pub finality: FinalityCfg,
    #[serde(default)]
    pub dex: Option<Address>,
    /// `chain_uid` (genesis hash, `smartcontracts/evm/chain-uids.json`): the salt of every SCaaS domain on this chain
    /// (NODE-GW-07). Set ⇒ the RPC's block 0 hash must equal it (a pruned RPC that has no block 0 trusts it); unset ⇒
    /// the RPC's block 0 hash.
    #[serde(default)]
    pub chain_uid: Option<B256>,
    /// The chain's `SmartKeyAccountFactory`: the target of the call-table row `deploy` (NODE-JOB-19).
    #[serde(default)]
    pub account_factory: Option<Address>,
    /// The token factory (`OpenFactory`): never a `call` target (NODE-JOB-01).
    #[serde(default)]
    pub token_factory: Option<Address>,
    /// The chain's UA registry (`UARegistry`, the generation that takes new registrations): the target of the call-table
    /// rows `register` / `setKemKey` / `storePqzPop` / `setPqzKey` (UA-8, ruling R-node; unset: refused).
    #[serde(default)]
    pub ua_registry: Option<Address>,
    /// The chain's `GovernanceRouter`s (NODE-JOB-19; spec 2026-11-02-governance §12.7): the only targets of a `gov_router` row, on
    /// the direct path and as the inner target of a relay fee. A list: a second router (another child of `GovernanceRouterBase`) is a
    /// config row. Empty: every router job is refused.
    #[serde(default)]
    pub governance_routers: Vec<Address>,
    /// The chain's canonical `ComplianceRegistry` (regulated-kinds spec §5, §7; the deployments JSON's `compliance_registry`): the
    /// registry the venue's pre-check reads for a regulated leg (NODE-DEX-11). An address, no secret. Set with
    /// `compliance_registry_codehash`, or neither.
    #[serde(default)]
    pub compliance_registry: Option<Address>,
    /// The registry's runtime code hash (the deployments JSON's `compliance_registry_codehash`, the releases' `COMPLIANCE_REGISTRY_CODEHASH`):
    /// checked against the chain's `eth_getCode` when the venue loads; another code or none stops it (fail closed).
    #[serde(default)]
    pub compliance_registry_codehash: Option<B256>,
    /// Proposed NODE-JOB-25 (spec 2026-11-09-service-pull §8): the chain's services, `[[chains.services]] address, entries =
    /// [{entry, op_type}]`, at most 32 entries each and 1,024 bytes per `op_type`; equal to the contract's
    /// `servicePullEntries()` both directions at startup; one kind per address. EVM only.
    #[serde(default)]
    pub services: Vec<crate::service::ServiceCfg>,
    /// Ví lạnh nhận phí của meta-tx không ràng buộc `feeRecipient` (R84, EVM/Hedera); không phải khoá lane.
    /// Không đặt ⇒ ghi 0: contract trả phí cho `msg.sender` (lane gửi).
    #[serde(default)]
    pub fee_recipient: Option<Address>,
    #[serde(default = "default_poll")]
    pub poll_ms: u64,
    #[serde(default = "default_stuck")]
    pub stuck_after_secs: u64,
    #[serde(default = "default_max_gas")]
    pub max_gas_per_tx: u64,
    #[serde(default = "default_fee_cap")]
    pub max_fee_cap_gwei: u64,
    /// Cầu dao gas (R55).
    #[serde(default)]
    pub breaker: BreakerCfg,
    /// `/readyz` đỏ khi `đỉnh final − indexed_block` vượt ngưỡng này (R51).
    #[serde(default = "default_max_lag")]
    pub max_index_lag: u64,
    /// Token đăng ký của chain (R95 bootstrap; MESH R86). Dạng chuẩn của họ mạng.
    #[serde(default)]
    pub tokens: Vec<TokenCfg>,
    /// `public` | `private` (MESH R76).
    #[serde(default = "private")]
    pub profile: String,
    /// Gossip mở (gossip §8.4); `private` ⇒ phải tắt.
    #[serde(default)]
    pub gossip: bool,
    #[serde(default = "default_exclusive_ms")]
    pub exclusive_ms: u64,
    /// The top-level `[pqz_verifier]`, set by [`Config::load`] (never read from a `[[chains]]` table).
    #[serde(skip)]
    pub pqz_verifier: PqzVerifierCfg,
    /// Fable recheck 3 R3-4: one chain read's time on one endpoint (its head check and its requests); past it the read fails
    /// over. Every request of the chain's client is bounded by the larger of this and `rpc_simulate_timeout_ms`.
    #[serde(default = "default_rpc_timeout_ms")]
    pub rpc_timeout_ms: u64,
    /// The same for a simulation (`eth_call` then `eth_estimateGas`, which runs the call several times): a PQZ or Zether proof
    /// check is the slowest call the node makes. Unmeasured default, generous.
    #[serde(default = "default_rpc_simulate_timeout_ms")]
    pub rpc_simulate_timeout_ms: u64,
    /// Fable recheck 3 R3-1: the highest block of this chain the node has seen from its first endpoint (the lanes' receipts, the
    /// heads the indexer, the venue and the health probe poll), shared by every `Chain` built from this table (clones share it);
    /// a runtime value, never read from the file, cleared by a restart.
    #[serde(skip)]
    pub head: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

fn default_rpc_timeout_ms() -> u64 {
    30_000
}
fn default_rpc_simulate_timeout_ms() -> u64 {
    120_000
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCfg {
    /// Dạng chuẩn của họ mạng (`addresses.canonical`): `0x…` EVM, `wasm1…` Cosmos, … (review H1).
    pub address: String,
    pub decimals: u8,
}

impl TokenCfg {
    /// Chỉ đường EVM: địa chỉ không phải `0x` 20 byte thì không phải token EVM.
    pub fn evm(&self) -> Option<Address> {
        self.address.parse().ok()
    }
}

/// R55. Số tiền theo đơn vị nhỏ nhất của coin gas: số nguyên TOML hoặc chuỗi (vượt i64). Lưu store dạng JSON,
/// số tiền là chuỗi thập phân.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakerCfg {
    /// Base fee hiện tại > `spike_ratio` × trung bình 1 h ⇒ ngưng nhận job mới (EVM). 0 = tắt.
    #[serde(default = "default_spike")]
    pub spike_ratio: f64,
    /// Dưới mức này (gwei) base fee không bao giờ là "spike": L2 phí gần 0 dao động ×3 là chuyện thường.
    #[serde(default = "one_u64")]
    pub spike_min_base_fee_gwei: u64,
    #[serde(default, deserialize_with = "amount")]
    #[serde(serialize_with = "amount_text", skip_serializing_if = "Option::is_none")]
    pub gas_budget_per_hour: Option<u128>,
    #[serde(default, deserialize_with = "amount")]
    #[serde(serialize_with = "amount_text", skip_serializing_if = "Option::is_none")]
    pub min_relayer_balance: Option<u128>,
    /// Soroban: `call` jobs stop at this share (%) of `gas_budget_per_hour`, every other kind runs to 100 %, so free registry
    /// writes cannot spend the whole hour's budget and stop payments.
    #[serde(default = "default_call_pct")]
    pub call_budget_pct: u8,
}

impl Default for BreakerCfg {
    fn default() -> Self {
        Self { spike_ratio: default_spike(), spike_min_base_fee_gwei: 1, gas_budget_per_hour: None, min_relayer_balance: None, call_budget_pct: default_call_pct() }
    }
}

fn default_call_pct() -> u8 {
    50
}

fn amount<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<u128>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum A {
        N(u64),
        S(String),
    }
    match A::deserialize(d)? {
        A::N(n) => Ok(Some(n.into())),
        A::S(s) => s.trim().parse().map(Some).map_err(serde::de::Error::custom),
    }
}

fn amount_text<S: serde::Serializer>(v: &Option<u128>, s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&v.unwrap_or_default().to_string()) // None is skipped
}

impl Default for ChainCfg {
    fn default() -> Self {
        Self {
            family: evm(),
            network: None,
            evm_chain_number: 0,
            rpc_urls: vec![],
            signer_key_env: String::new(),
            private_key: None,
            lanes: lane0(),
            coin_type: None,
            params: Default::default(),
            finality: default_finality(),
            dex: None,
            chain_uid: None,
            account_factory: None,
            token_factory: None,
            ua_registry: None,
            governance_routers: vec![],
            compliance_registry: None,
            compliance_registry_codehash: None,
            services: vec![],
            fee_recipient: None,
            poll_ms: default_poll(),
            stuck_after_secs: default_stuck(),
            max_gas_per_tx: default_max_gas(),
            max_fee_cap_gwei: default_fee_cap(),
            breaker: BreakerCfg::default(),
            max_index_lag: default_max_lag(),
            tokens: vec![],
            profile: private(),
            gossip: false,
            exclusive_ms: default_exclusive_ms(),
            pqz_verifier: PqzVerifierCfg::default(),
            rpc_timeout_ms: default_rpc_timeout_ms(),
            rpc_simulate_timeout_ms: default_rpc_simulate_timeout_ms(),
            head: Default::default(),
        }
    }
}

fn yes() -> bool {
    true
}
fn auth_none() -> String {
    "none".into()
}
fn evm() -> String {
    "evm".into()
}
fn lane0() -> Vec<u32> {
    vec![0]
}
fn default_finality() -> FinalityCfg {
    FinalityCfg { mode: "instant".into(), depth: 0, quorum: 1 }
}
fn one() -> usize {
    1
}
fn default_bind() -> String {
    "127.0.0.1:8547".into()
}
fn default_api_bind() -> String {
    "127.0.0.1:8548".into()
}
fn default_poll() -> u64 {
    1000
}
fn default_stuck() -> u64 {
    60
}
fn default_max_gas() -> u64 {
    3_000_000
}
fn default_fee_cap() -> u64 {
    500
}
fn one_u64() -> u64 {
    1
}
fn default_spike() -> f64 {
    3.0
}
fn default_max_lag() -> u64 {
    100
}
fn default_admin_bind() -> String {
    "127.0.0.1:9108".into()
}
fn default_job_retention() -> u64 {
    30 * 86_400
}
fn default_feed_retention() -> u64 {
    7 * 86_400
}
fn default_lease_hold() -> u64 {
    15
}
fn default_modes() -> Vec<String> {
    vec!["builtin".into()]
}
fn default_session_ttl() -> u64 {
    900
}
fn default_session_max_age() -> u64 {
    43_200
}
fn default_login_failures() -> u32 {
    10
}
fn default_login_lock() -> u64 {
    900
}
fn default_max_live_jobs() -> u32 {
    10_000
}
fn default_max_established() -> u32 {
    50
}
fn default_exclusive_ms() -> u64 {
    7000
}
fn private() -> String {
    "private".into()
}
fn zero() -> String {
    "0".into()
}
fn any() -> String {
    "any".into()
}

impl Config {
    /// The directory of the sqlite store (`sqlite:///var/lib/scaas/node.db` ⇒ `/var/lib/scaas`): where the node keeps its
    /// other small state files (the TON `PaymentMeta` wait, T17 fix 1).
    pub fn store_dir(&self) -> std::path::PathBuf {
        let path = self.store.url.strip_prefix("sqlite://").or_else(|| self.store.url.strip_prefix("sqlite:")).unwrap_or("");
        let path = path.split('?').next().unwrap_or("");
        std::path::Path::new(path).parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new(".")).to_path_buf()
    }

    /// The config an adapter is built from: the TON `params.meta_journal` defaults to a file under `store_dir`.
    pub fn adapter_cfg(&self, c: &ChainCfg) -> ChainCfg {
        let mut c = c.clone();
        if c.family == "ton" && !c.params.contains_key("meta_journal") {
            let f = self.store_dir().join(format!("ton-meta-{}.json", c.chain_key().replace([':', '/'], "_")));
            c.params.insert("meta_journal".into(), f.to_string_lossy().into_owned().into());
        }
        c
    }
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&raw).context("parse config")?;
        for c in &mut cfg.chains {
            c.pqz_verifier = cfg.pqz_verifier.clone();
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.chains.is_empty() {
            bail!("no [[chains]]");
        }
        if self.modules.gateway && self.modules.gateway_auth == "none" {
            let host = self.modules.gateway_bind.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
            let loopback = matches!(host, "127.0.0.1" | "localhost" | "[::1]" | "::1");
            if !loopback {
                bail!("gateway on {} without authentication: set gateway_auth = bearer|hmac", self.modules.gateway_bind);
            }
        }
        if self.modules.gateway_auth != "none" && self.modules.gateway_secret_env.is_none() {
            bail!("gateway_auth {} needs gateway_secret_env", self.modules.gateway_auth);
        }
        let mut seen = std::collections::HashSet::new();
        for c in &self.chains {
            let key = c.chain_key();
            if !seen.insert(key.clone()) {
                bail!("chain {key} configured twice");
            }
            keys::lane_path_coin(&c.family, 0, c.coin_type).with_context(|| format!("chain {key}"))?;
            if c.rpc_urls.is_empty() || c.rpc_urls.len() < c.finality.quorum {
                bail!("chain {key}: {} rpc_urls < quorum {}", c.rpc_urls.len(), c.finality.quorum);
            }
            if c.compliance_registry.is_some() != c.compliance_registry_codehash.is_some() {
                bail!("chain {key}: compliance_registry and compliance_registry_codehash are set together");
            }
            if c.is_evm() {
                if c.evm_chain_number == 0 {
                    bail!("chain {key}: evm_chain_number is required for {}", c.family);
                }
                // Hedera: aBFT, a record file is final (`instant` = depth 0).
                let instant = c.family == "hedera" && c.finality.mode == "instant";
                if c.finality.mode != "depth" && c.finality.mode != "tag" && !instant {
                    bail!("chain {key}: finality.mode must be depth|tag (hedera: also instant)");
                }
            } else if c.network.is_none() {
                bail!("chain {key}: network is required for {}", c.family);
            }
            if c.lanes.is_empty() {
                bail!("chain {key}: at least one lane");
            }
            let raw = c.private_key.is_some() || !c.signer_key_env.is_empty();
            if raw && c.lanes.len() > 1 {
                bail!("chain {key}: a raw private key is one lane; use [keys].mnemonic for several");
            }
            if raw && c.coin_type.is_some() {
                bail!("chain {key}: coin_type applies to [keys].mnemonic lanes, not to a raw private key");
            }
            if !raw && self.keys.is_none() {
                bail!("chain {key}: no key (private_key, signer_key_env or [keys].mnemonic)");
            }
            if c.profile != "public" && c.profile != "private" {
                bail!("chain {key}: profile must be public|private");
            }
            if c.gossip && c.profile == "private" {
                bail!("chain {key}: a private chain never gossips (MESH §9 rule 3)");
            }
            for t in &c.tokens {
                c.canonical(&t.address).with_context(|| format!("chain {key}: token {}", t.address))?;
            }
            c.relay_params().with_context(|| format!("chain {key}"))?;
            c.check_services().with_context(|| format!("chain {key}"))?;
            if !(1..=100).contains(&c.breaker.call_budget_pct) {
                bail!("chain {key}: breaker.call_budget_pct is a share of the budget, 1 to 100");
            }
            // NET-SOR-14: a Soroban job is free to the client and its fee is the lane's, so the limits are the operator's to name.
            let set = |v: Option<u128>| v.is_some_and(|v| v > 0);
            if c.family == "soroban" && self.modules.submit && !(set(c.breaker.gas_budget_per_hour) && set(c.breaker.min_relayer_balance)) {
                bail!("chain {key}: a soroban lane needs breaker.gas_budget_per_hour and breaker.min_relayer_balance, both above 0 (stroops; node.example.toml)");
            }
            if c.family == "soroban" && self.modules.submit && !c.params.get("max_resource_fee_per_job").and_then(|v| v.as_integer()).is_some_and(|n| n > 0) {
                bail!("chain {key}: a soroban lane needs params.max_resource_fee_per_job above 0 (stroops; node.example.toml)");
            }
        }
        let v = &self.pqz_verifier;
        if let Some(e) = v.endpoints.iter().find(|e| !(e.starts_with("https://") || e.starts_with("http://"))) {
            bail!("pqz_verifier.endpoints: {e:?} is not an http(s) URL");
        }
        if v.timeout_ms == 0 || v.max_response_bytes == 0 {
            bail!("pqz_verifier: timeout_ms and max_response_bytes above 0");
        }
        self.validate_store_sections(&seen)
    }

    /// `[store]`, `[api]`, danh sách bootstrap và `[gossip]` (P1: chỉ cấu hình, chưa có listener).
    fn validate_store_sections(&self, chains: &std::collections::HashSet<String>) -> Result<()> {
        // legacy(R104): submit, indexer and the admin refresh still run on the Odoo pull path.
        let legacy = self.modules.submit || self.modules.indexer || !self.modules.admin_bind.is_empty();
        if legacy && self.odoo.is_none() {
            bail!("[odoo] is required while submit/indexer/admin run on the legacy path (R104)");
        }
        if !self.store.url.starts_with("sqlite:") {
            bail!("[store] url: only sqlite: is built (PostgreSQL/MySQL arrive in P1b)");
        }
        const TEN_YEARS: u64 = 10 * 365 * 86_400;
        for (name, v) in [("job_retention_secs", self.store.job_retention_secs),
                          ("feed_retention_secs", self.store.feed_retention_secs)] {
            if v > TEN_YEARS {
                bail!("[store] {name} = {v}: at most 10 years ({TEN_YEARS})");
            }
        }
        // P2 serves [api]; refuse a clash now rather than at the first bind.
        let mut binds = vec![("[api] bind", self.api.bind.as_str())];
        if self.modules.gateway {
            binds.push(("[modules] gateway_bind", self.modules.gateway_bind.as_str()));
        }
        if !self.modules.admin_bind.is_empty() {
            binds.push(("[modules] admin_bind", self.modules.admin_bind.as_str()));
        }
        for (i, (an, a)) in binds.iter().enumerate() {
            if let Some((bn, b)) = binds[i + 1..].iter().find(|(_, b)| same_port(a, b)) {
                bail!("{an} {a} collides with {bn} {b}");
            }
        }
        let a = &self.api.admin_auth;
        if a.modes.is_empty() {
            bail!("[api.admin_auth] modes = [] would lock every admin out");
        }
        for m in &a.modes {
            match m.as_str() {
                "builtin" => {}
                "oidc" => bail!("[api.admin_auth] oidc needs [[api.oidc.issuers]] (P2b)"),
                other => bail!("[api.admin_auth] unknown mode {other}"),
            }
        }
        if self.api.admin_cors_origins.iter().any(|o| o == "*") {
            bail!("[api] admin_cors_origins: exact origins only, never *");
        }
        let mut names = std::collections::HashSet::new();
        for n in &self.namespaces {
            let ok = (3..=40).contains(&n.name.len())
                && n.name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok {
                bail!("namespace {:?}: [a-z0-9-]{{3,40}} (names starting with ~ are reserved)", n.name);
            }
            if !names.insert(&n.name) {
                bail!("namespace {} configured twice", n.name);
            }
            if let Some(c) = n.chains.iter().find(|c| !chains.contains(*c)) {
                bail!("namespace {}: chain {c} is not in [[chains]]", n.name);
            }
        }
        let public = |k: &str| self.chains.iter().any(|c| c.chain_key() == k && c.profile == "public");
        for p in self.mesh.iter().flat_map(|m| &m.peers) {
            if !p.url.starts_with("https://") {
                bail!("mesh peer {}: url must be https://", p.name);
            }
            if p.spki_sha256.len() != 64 || !p.spki_sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                bail!("mesh peer {}: spki_sha256 is 64 lowercase hex", p.name);
            }
            match p.class.as_str() {
                "open" => {}
                "private" if !p.chains.is_empty() => {}
                "private" => bail!("mesh peer {}: a private peer lists the chains it may receive", p.name),
                other => bail!("mesh peer {}: class {other} is not open|private", p.name),
            }
            if let Some(c) = p.chains.iter().find(|c| !chains.contains(*c)) {
                bail!("mesh peer {}: chain {c} is not in [[chains]]", p.name);
            }
        }
        for p in self.mesh.iter().flat_map(|m| &m.policy) {
            let at = format!("mesh policy {}/{}/{}", p.chain, p.contract, p.selector);
            if !chains.contains(&p.chain) {
                bail!("{at}: chain is not in [[chains]]");
            }
            if !matches!(p.support.as_str(), "none" | "forward_only" | "full") {
                bail!("{at}: support must be none|forward_only|full");
            }
            if !matches!(p.pool_visibility.as_str(), "open" | "private" | "none") {
                bail!("{at}: pool_visibility must be open|private|none");
            }
            if !matches!(p.fee_recipient_allow.as_str(), "any" | "self_or_zero") {
                bail!("{at}: fee_recipient_allow must be any|self_or_zero");
            }
            if p.contract == "*" && p.submit {
                bail!("{at}: never contract = \"*\" with submit = true (MESH R86)");
            }
            // The mesh compares the family's canonical form byte-exact: a checksummed or short spelling would be
            // a row that never matches, and a deny would fall through to `(*, *)` (review F2).
            if let Some(c) = self.chains.iter().find(|c| c.chain_key() == p.chain).filter(|_| p.contract != "*") {
                c.canonical(&p.contract).with_context(|| format!("{at}: contract"))?;
            }
            let sel = p.selector.as_str();
            let hex8 = sel.len() == 10 && sel.starts_with("0x") && sel[2..].bytes().all(|b| b.is_ascii_hexdigit());
            if !(hex8 || matches!(sel, "*" | "0x" | "pay")) {
                bail!("{at}: selector is 0x + 8 hex, 0x, pay or *");
            }
            if p.min_fee.is_empty() || !p.min_fee.bytes().all(|b| b.is_ascii_digit()) {
                bail!("{at}: min_fee is a decimal integer");
            }
            if p.gossip && !public(&p.chain) {
                bail!("{at}: gossip needs a public chain");
            }
        }
        if self.gossip.enabled {
            if self.identity.is_none() {
                bail!("[gossip] enabled needs [identity] key");
            }
            if !self.transport.quic && !self.transport.tcp {
                bail!("[gossip] enabled needs [transport] quic or tcp");
            }
            if self.gossip.listen.is_empty() {
                bail!("[gossip] enabled needs listen addresses");
            }
        }
        Ok(())
    }

    /// Cấu hình không bí mật của toml dưới dạng dòng store, cho bootstrap R95. `lane_labels[i]` = nhãn lane
    /// (địa chỉ EVM hoặc `pk:<hex>`) của `chains[i]`, theo thứ tự `lanes`.
    pub fn boot_set(&self, lane_labels: &[Vec<String>]) -> store::ConfigSet {
        let mut set = store::ConfigSet::default();
        for (c, labels) in self.chains.iter().zip(lane_labels) {
            let key = c.chain_key();
            set.chains.push(store::ChainRow {
                chain_key: key.clone(),
                family: c.family.clone(),
                state: "active".into(),
                profile: c.profile.clone(),
                finality_mode: c.finality.mode.clone(),
                finality_depth: c.finality.depth as i64,
                finality_quorum: c.finality.quorum as i64,
                fee_recipient: c.fee_recipient.map(|a| format!("{a:#x}")),
                poll_ms: c.poll_ms as i64,
                stuck_after_secs: c.stuck_after_secs as i64,
                max_gas_per_tx: c.max_gas_per_tx as i64,
                max_fee_cap_gwei: c.max_fee_cap_gwei as i64,
                max_index_lag: c.max_index_lag as i64,
                breaker: serde_json::to_string(&c.breaker).unwrap_or_default(),
                dex: c.dex.map(|a| format!("{a:#x}")),
                gossip: c.gossip,
                exclusive_ms: c.exclusive_ms as i64,
            });
            for t in &c.tokens {
                // One spelling per family (Odoo `addresses.canonical`), so byte-exact keys never split one token
                // in two and R95 client token subsets match. `validate` refused anything that does not parse.
                let address = c.canonical(&t.address).unwrap_or_else(|_| t.address.clone());
                set.tokens.push(store::TokenRow { chain_key: key.clone(), address, decimals: t.decimals.into(), active: true });
            }
            for (label, &i) in labels.iter().zip(&c.lanes) {
                set.lanes.push(store::LaneRow { chain_key: key.clone(), label: label.clone(), account_index: i.into(),
                                                journal_max: None });
            }
        }
        for n in &self.namespaces {
            let mut chains = n.chains.clone();
            chains.sort();
            chains.dedup();
            set.namespaces.push(store::NamespaceRow { name: n.name.clone(), state: "active".into(),
                                                      allow_call: n.allow_call, max_live_jobs: n.max_live_jobs.into(), chains });
        }
        for p in self.mesh.iter().flat_map(|m| &m.peers) {
            set.peers.push(store::PeerRow { name: p.name.clone(), url: p.url.clone(), spki_sha256: p.spki_sha256.clone(),
                                            class: p.class.clone(), chains: p.chains.join(" ") });
        }
        for p in self.mesh.iter().flat_map(|m| &m.policy) {
            // `as i64` above: TOML integers are i64, so a u64 read from toml never exceeds i64::MAX.
            let chain = self.chains.iter().find(|c| c.chain_key() == p.chain);
            let contract = match (p.contract.as_str(), chain) {
                ("*", _) | (_, None) => p.contract.clone(),
                (v, Some(c)) => c.canonical(v).unwrap_or_else(|_| p.contract.clone()),
            };
            set.policy.push(store::PolicyRow {
                chain_key: p.chain.clone(),
                contract,
                selector: p.selector.to_ascii_lowercase(), // hex as `hex0x` writes it; `*`, `0x`, `pay` unchanged
                support: p.support.clone(),
                submit: p.submit,
                pool_visibility: p.pool_visibility.clone(),
                min_fee: p.min_fee.clone(),
                fee_recipient_allow: p.fee_recipient_allow.clone(),
                gossip: p.gossip,
            });
        }
        set
    }

    /// Signer của từng lane (thứ tự `lanes`). Chỉ địa chỉ được log, không bao giờ bí mật.
    pub fn lane_signers(&self, c: &ChainCfg) -> Result<Vec<LocalSigner>> {
        if let Some(src) = &c.private_key {
            let key = keys::parse_raw_key(&src.read()?)?;
            let (curve, _) = keys::lane_path(&c.family, 0)?;
            return Ok(vec![LocalSigner::new(curve, &key)?]);
        }
        if !c.signer_key_env.is_empty() {
            let src = SecretSource { env: Some(c.signer_key_env.clone()), ..Default::default() };
            let key = keys::parse_raw_key(&src.read()?)?;
            let (curve, _) = keys::lane_path(&c.family, 0)?;
            return Ok(vec![LocalSigner::new(curve, &key)?]);
        }
        let k = self.keys.as_ref().ok_or_else(|| anyhow::anyhow!("no [keys] section"))?;
        let phrase = k.mnemonic.read()?;
        let pass = match &k.bip39_passphrase_env {
            Some(v) => Some(std::env::var(v).with_context(|| format!("environment variable {v} is not set"))?),
            None => None,
        };
        let seed = Seed::from_phrase(&phrase, pass.as_deref())?;
        c.lanes
            .iter()
            .map(|&i| {
                let (curve, key) = keys::lane_secret_coin(&seed, &c.family, i, c.coin_type)?;
                LocalSigner::new(curve, &key)
            })
            .collect()
    }
}

/// Two listeners on one port: same host, or either on the wildcard address.
fn same_port(a: &str, b: &str) -> bool {
    match (a.parse::<std::net::SocketAddr>(), b.parse::<std::net::SocketAddr>()) {
        (Ok(x), Ok(y)) => x.port() == y.port() && (x.ip() == y.ip() || x.ip().is_unspecified() || y.ip().is_unspecified()),
        _ => a == b,
    }
}

/// CTR-MTX-26 / -27 node keys, one set for every family (T17, controller ruling 2026-10-28, owner may override):
/// `params.relay_fee = { router, min_amount, relay_bound_payee, … }` and `params.max_pay_meta_bytes`. A key that is set
/// but invalid is a startup error (`Config::validate`), never a silent default. Each family parses `router` in its own
/// address form (unparsable = startup error there) and its own extra price keys (`min_ton_value`,
/// `min_lamports_value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayParams {
    /// `relay_fee.router` as written; `None` = no relay-fee jobs on this chain.
    pub router: Option<String>,
    /// `relay_fee.min_amount` (default 1): the smallest fee, in the token's base units, that reaches this node's lane.
    pub min_amount: u128,
    /// `relay_fee.relay_bound_payee` (default false): relay a job whose fee goes to a bound payee other than the lane,
    /// as a sponsored job (no `min_amount`).
    pub relay_bound_payee: bool,
    /// `max_pay_meta_bytes` (default 2,048, spec §9): the cap on a pay-meta `meta`.
    pub max_pay_meta_bytes: usize,
    /// `max_service_op_bytes` (default 2,048; proposed NODE-JOB-25): the cap on one `bytes` / `string` field of a service
    /// job's `<Op>`.
    pub max_service_op_bytes: usize,
}

pub const DEFAULT_MAX_PAY_META_BYTES: usize = 2048;

impl Default for RelayParams {
    /// The defaults of an unset key set: no router, `min_amount` 1, no bound-payee relays, 2,048 B of meta.
    fn default() -> Self {
        Self { router: None, min_amount: 1, relay_bound_payee: false, max_pay_meta_bytes: DEFAULT_MAX_PAY_META_BYTES,
            max_service_op_bytes: crate::service::DEFAULT_MAX_OP_BYTES }
    }
}

impl ChainCfg {
    /// [`RelayParams`] from `params`.
    pub fn relay_params(&self) -> Result<RelayParams> {
        let uint = |v: &toml::Value, k: &str| v.as_integer().and_then(|n| u64::try_from(n).ok())
            .with_context(|| format!("params.{k} must be a non-negative integer, not {v}"));
        let max_pay_meta_bytes = match self.params.get("max_pay_meta_bytes") {
            None => DEFAULT_MAX_PAY_META_BYTES,
            Some(v) => uint(v, "max_pay_meta_bytes")? as usize,
        };
        let max_service_op_bytes = match self.params.get("max_service_op_bytes") {
            None => crate::service::DEFAULT_MAX_OP_BYTES,
            Some(v) => uint(v, "max_service_op_bytes")? as usize,
        };
        let t = match self.params.get("relay_fee") {
            None => None,
            Some(toml::Value::Table(t)) => Some(t),
            Some(v) => bail!("params.relay_fee must be a table, not {v}"),
        };
        // T17 fix 1: a misspelt key (`min_ammount`) or another family's price key is an error, never ignored
        for k in t.into_iter().flat_map(|t| t.keys()) {
            let ok = match k.as_str() {
                "router" | "min_amount" | "relay_bound_payee" => true,
                "min_wei_value" => self.family == "evm",
                "min_ton_value" => self.family == "ton",
                "min_lamports_value" => self.family == "solana",
                "executor" | "min_yocto_value" => self.family == "near",
                "targets" => self.family == "near" || self.family == "algorand",
                "min_microalgo_value" => self.family == "algorand",
                _ => false,
            };
            if !ok {
                bail!("params.relay_fee.{k} is not a key of the {} family (router, min_amount, relay_bound_payee{})", self.family,
                    match self.family.as_str() {
                        "ton" => ", min_ton_value",
                        "solana" => ", min_lamports_value",
                        "near" => ", executor, min_yocto_value, targets",
                        "algorand" => ", min_microalgo_value, targets",
                        "evm" => ", min_wei_value",
                        _ => "",
                    });
            }
        }
        let get = |k: &str| t.and_then(|t| t.get(k));
        let router = match get("router") {
            None => None,
            Some(v) => Some(v.as_str().with_context(|| format!("params.relay_fee.router must be a string, not {v}"))?.to_string()),
        };
        let min_amount = match get("min_amount") {
            None => 1,
            Some(v) => u128::from(uint(v, "relay_fee.min_amount")?),
        };
        let relay_bound_payee = match get("relay_bound_payee") {
            None => false,
            Some(v) => v.as_bool().with_context(|| format!("params.relay_fee.relay_bound_payee must be true or false, not {v}"))?,
        };
        Ok(RelayParams { router, min_amount, relay_bound_payee, max_pay_meta_bytes, max_service_op_bytes })
    }

    /// Dạng chuẩn của một địa chỉ trên chain này (`addresses::canonical`, như Odoo `canonical_for_chain`).
    pub fn canonical(&self, value: &str) -> Result<String> {
        let prefix = self.params.get("prefix").and_then(|v| v.as_str());
        let ton_testnet = (self.family == "ton").then_some(()).and(self.network.as_deref()).map(|n| n == "-3");
        crate::addresses::canonical(&self.family, value, prefix, ton_testnet)
    }

    /// Proposed NODE-JOB-25 at startup: EVM only, each service under its bounds ([`crate::service::entries_of`]), no address
    /// twice, and one kind per address: a service is no other configured kind (the DEX, a `GovernanceRouter`, the UA registry,
    /// the account or token factory, the relay-fee router or its executor). A registered token is refused at run time (the
    /// list is the client's).
    pub fn check_services(&self) -> Result<()> {
        if self.services.is_empty() {
            return Ok(());
        }
        if !self.is_evm() {
            bail!("[[chains.services]] is EVM only (spec §9: each family's form in its own round)");
        }
        let router = self.relay_params()?.router.map(|r| crate::metatx::addr(&r)).transpose()?;
        let mut others: Vec<(Address, &str)> = vec![];
        others.extend(self.dex.map(|a| (a, "dex")));
        others.extend(self.governance_routers.iter().map(|a| (*a, "governance_routers")));
        others.extend(self.ua_registry.map(|a| (a, "ua_registry")));
        others.extend(self.account_factory.map(|a| (a, "account_factory")));
        others.extend(self.token_factory.map(|a| (a, "token_factory")));
        others.extend(router.map(|r| (r, "relay_fee.router")));
        others.extend(router.map(|r| (r.create(1), "the relay-fee executor")));
        crate::service::Types::from_cfg(&self.services, crate::service::DEFAULT_MAX_OP_BYTES)?;
        for s in &self.services {
            if let Some((_, k)) = others.iter().find(|(a, _)| *a == s.address) {
                bail!("service {:#x} is also {k} (one kind per address)", s.address);
            }
        }
        Ok(())
    }

    pub fn is_evm(&self) -> bool {
        self.family == "evm" || self.family == "hedera"
    }

    /// Chạy `adapters::build` + `lane_runner`/`index_runner` thay vì runner EVM pipeline (`submit.rs`).
    /// Hedera thuộc nhóm này (R6-1: không mempool, một tx bay mỗi lane) dù cấu hình kiểu EVM (`is_evm`).
    pub fn uses_adapter(&self) -> bool {
        self.family != "evm"
    }

    /// `evm:7622`, `hedera:296`, `sui:localnet`… — khoá chung với Odoo `blockchain.chain.chain_key`
    /// (EVM/Hedera: luôn theo `evm_chain_number`, `network` bị bỏ qua như ở Odoo).
    pub fn chain_key(&self) -> String {
        match &self.network {
            Some(n) if !self.is_evm() => format!("{}:{n}", self.family),
            _ => format!("{}:{}", self.family, self.evm_chain_number),
        }
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
[store]
url = "sqlite:///var/lib/scaas/node.db"
[[chains]]
evm_chain_number = 7622
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

    /// Group 3f (spec §11.1): the top-level `[pqz_verifier]` reaches every chain at load (off and empty by default, no secret: URLs
    /// only); an endpoint that is no http(s) URL, or a zero bound, is a startup error.
    #[test]
    fn pqz_verifier_section_reaches_every_chain() {
        let load = |extra: &str| -> Result<Config> {
            let p = std::env::temp_dir().join(format!("pqz-verifier-{}-{}.toml", std::process::id(), extra.len()));
            std::fs::write(&p, format!("{OK}{extra}"))?;
            let c = Config::load(&p);
            let _ = std::fs::remove_file(&p);
            c
        };
        let c = load("").unwrap();
        assert_eq!(c.chains[0].pqz_verifier, PqzVerifierCfg::default());
        assert!(!c.pqz_verifier.refuse_shield_when_unserved && c.pqz_verifier.endpoints.is_empty());
        let c = load("[pqz_verifier]\nendpoints = [\"https://v.example\", \"http://127.0.0.1:7\"]\nrefuse_shield_when_unserved = true\n").unwrap();
        assert_eq!((c.chains[0].pqz_verifier.endpoints.len(), c.chains[0].pqz_verifier.refuse_shield_when_unserved), (2, true));
        assert_eq!(c.chains[0].pqz_verifier.timeout_ms, 5_000);
        for bad in ["[pqz_verifier]\nendpoints = [\"v.example\"]\n", "[pqz_verifier]\ntimeout_ms = 0\n"] {
            assert!(load(bad).unwrap_err().to_string().contains("pqz_verifier"), "{bad}");
        }
    }

    /// Regulated-kinds spec §7: `compliance_registry` and its code hash are set together, or neither (no secret: an address and a
    /// hash; `chain::compliance_registry_code_hash_fails_closed` checks the code).
    #[test]
    fn compliance_registry_and_its_code_hash_together() {
        let with = |extra: &str| -> Result<Config> {
            let c: Config = toml::from_str(&OK.replace("signer_key_env = \"K\"", &format!("signer_key_env = \"K\"\n{extra}")))?;
            c.validate().map(|_| c)
        };
        let (a, h) = (format!("{:#x}", Address::repeat_byte(0xc0)), format!("{:#x}", B256::repeat_byte(1)));
        assert!(with(&format!("compliance_registry = \"{a}\"")).unwrap_err().to_string().contains("set together"));
        assert!(with(&format!("compliance_registry_codehash = \"{h}\"")).unwrap_err().to_string().contains("set together"));
        let c = with(&format!("compliance_registry = \"{a}\"\ncompliance_registry_codehash = \"{h}\"")).unwrap();
        assert_eq!((c.chains[0].compliance_registry, c.chains[0].compliance_registry_codehash), (Some(Address::repeat_byte(0xc0)), Some(B256::repeat_byte(1))));
        assert_eq!(with("").unwrap().chains[0].compliance_registry, None);
    }

    /// T17: the relay-fee / pay-meta keys of every family: defaults, and a set-but-invalid value is a startup error.
    #[test]
    fn relay_params_default_and_refuse_invalid_values() {
        let c: Config = toml::from_str(OK).unwrap();
        assert_eq!(c.chains[0].relay_params().unwrap(),
            RelayParams { router: None, min_amount: 1, relay_bound_payee: false, max_pay_meta_bytes: 2048, max_service_op_bytes: 2048 });
        let with = |p: &str| -> Result<RelayParams> {
            let c: Config = toml::from_str(&OK.replace("signer_key_env = \"K\"", &format!("signer_key_env = \"K\"\nparams = {{ {p} }}")))?;
            c.validate()?;
            c.chains[0].relay_params()
        };
        let p = with(r#"max_pay_meta_bytes = 4096, max_service_op_bytes = 512, relay_fee = { router = "0x7f", min_amount = 0, relay_bound_payee = true }"#).unwrap();
        assert_eq!(p, RelayParams { router: Some("0x7f".into()), min_amount: 0, relay_bound_payee: true, max_pay_meta_bytes: 4096,
            max_service_op_bytes: 512 });
        for bad in ["max_pay_meta_bytes = -1", "max_service_op_bytes = -1", r#"max_service_op_bytes = "2048""#, r#"max_pay_meta_bytes = "2048""#, "relay_fee = 7", "relay_fee = { router = 7 }",
                    "relay_fee = { min_amount = -1 }", r#"relay_fee = { min_amount = "9" }"#, "relay_fee = { min_amount = 1.5 }",
                    r#"relay_fee = { relay_bound_payee = "yes" }"#, "relay_fee = { min_ammount = 5 }",
                    "relay_fee = { min_ton_value = {} }", "relay_fee = { min_lamports_value = {} }"] {
            assert!(with(bad).is_err(), "{bad}");
        }
        let e = format!("{:#}", with("relay_fee = { min_ammount = 5 }").unwrap_err());
        assert!(e.contains("params.relay_fee.min_ammount"), "{e}");
        let fam = |family: &str, k: &str| ChainCfg { family: family.into(),
            params: toml::from_str(&format!("relay_fee = {{ {k} = {{}} }}")).unwrap(), ..Default::default() }.relay_params();
        assert!(fam("ton", "min_ton_value").is_ok() && fam("solana", "min_lamports_value").is_ok(), "each on its own family");
        assert!(fam("solana", "min_ton_value").is_err() && fam("ton", "min_lamports_value").is_err(), "never on another");
    }

    #[test]
    fn the_ton_meta_journal_lives_in_the_store_dir() {
        let mut c: Config = toml::from_str(OK).unwrap();
        assert_eq!(c.store_dir(), std::path::PathBuf::from("/var/lib/scaas"));
        let ton = ChainCfg { family: "ton".into(), network: Some("-239".into()), ..Default::default() };
        let a = c.adapter_cfg(&ton);
        assert_eq!(a.params["meta_journal"].as_str(), Some("/var/lib/scaas/ton-meta-ton_-239.json"));
        assert!(!c.adapter_cfg(&c.chains[0].clone()).params.contains_key("meta_journal"), "TON only");
        c.store.url = "sqlite:node.db".into();
        assert_eq!(c.store_dir(), std::path::PathBuf::from("."));
    }

    #[test]
    fn quorum_above_endpoints_is_refused() {
        let c: Config = toml::from_str(&OK.replace("quorum = 1", "quorum = 2")).unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn non_evm_chain_with_mnemonic_lanes() {
        let raw = format!("{OK}\n[keys]\nmnemonic = {{ env = \"SCAAS_TEST_MNEMONIC\" }}\n\
            [[chains]]\nfamily = \"sui\"\nnetwork = \"localnet\"\nrpc_urls = [\"http://s\"]\nlanes = [0, 1]\n\
            params = {{ package = \"0x2\" }}\n");
        let c: Config = toml::from_str(&raw).unwrap();
        c.validate().unwrap();
        assert_eq!(c.chains[1].chain_key(), "sui:localnet");
        assert_eq!(c.chains[0].chain_key(), "evm:7622");
        assert_eq!(c.chains[1].params["package"].as_str(), Some("0x2"));
        std::env::set_var("SCAAS_TEST_MNEMONIC", "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon art");
        let signers = c.lane_signers(&c.chains[1]).unwrap();
        assert_eq!(signers.len(), 2);
        assert_eq!(crate::signer::Signer::curve(&signers[0]), crate::signer::Curve::Ed25519);
    }

    #[test]
    fn raw_key_is_one_lane_and_keys_are_required() {
        let c: Config = toml::from_str(&OK.replace("signer_key_env = \"K\"", "signer_key_env = \"K\"\nlanes = [0, 1]")).unwrap();
        assert!(c.validate().is_err());
        let c: Config = toml::from_str(&OK.replace("signer_key_env = \"K\"\n", "")).unwrap();
        assert!(c.validate().is_err(), "no key at all");
        let c: Config = toml::from_str(&OK.replace("evm_chain_number = 7622\n", "")).unwrap();
        assert!(c.validate().is_err(), "evm needs a chain id");
    }

    #[test]
    fn open_gateway_must_be_authenticated() {
        let raw = OK.replace("[[chains]]", "[modules]\ngateway = true\ngateway_bind = \"0.0.0.0:8547\"\n[[chains]]");
        let c: Config = toml::from_str(&raw).unwrap();
        assert!(c.validate().is_err());
        let c: Config = toml::from_str(&raw.replace("gateway = true", "gateway = true\ngateway_auth = \"hmac\"\ngateway_secret_env = \"S\"")).unwrap();
        c.validate().unwrap();
        let c: Config = toml::from_str(&OK.replace("[[chains]]", "[modules]\ngateway = true\n[[chains]]")).unwrap();
        c.validate().unwrap();  // loopback default bind may stay open
    }

    #[test]
    fn breaker_amounts_accept_integers_and_big_strings() {
        let raw = OK.replace("finality =", "breaker = { gas_budget_per_hour = 5000, min_relayer_balance = \"100000000000000000000\" }\nfinality =");
        let c: Config = toml::from_str(&raw).unwrap();
        let b = &c.chains[0].breaker;
        assert_eq!(b.gas_budget_per_hour, Some(5000));
        assert_eq!(b.min_relayer_balance, Some(100_000_000_000_000_000_000));
        assert_eq!(b.spike_ratio, 3.0);
        let c: Config = toml::from_str(OK).unwrap();
        assert_eq!(c.chains[0].breaker.min_relayer_balance, None);
        assert_eq!(c.chains[0].max_index_lag, 100);
        assert_eq!(c.modules.admin_bind, "127.0.0.1:9108");
        assert!(toml::from_str::<Config>(&OK.replace("finality =", "breaker = { gas_budget_per_hour = \"x\" }\nfinality =")).is_err());
    }

    /// NET-SOR-14: a Soroban lane does not start without both spend limits, a job being free to the client. One key differs per
    /// case; an indexer-only node has no lane to limit.
    #[test]
    fn soroban_lanes_need_both_spend_limits() {
        let raw = |modules: &str, params: &str, breaker: &str| format!("{modules}{OK}\n[keys]\nmnemonic = {{ env = \"SCAAS_TEST_MNEMONIC\" }}\n\
            [[chains]]\nfamily = \"soroban\"\nnetwork = \"local\"\nrpc_urls = [\"http://p\"]\nlanes = [0]\n\
            params = {{ network_passphrase = \"x\"{params} }}\n{breaker}\n");
        let fee_cap = ", max_resource_fee_per_job = 1";
        let with_cap = |modules: &str, params: &str, breaker: &str| toml::from_str::<Config>(&raw(modules, params, breaker)).unwrap().validate();
        let check = |modules: &str, breaker: &str| with_cap(modules, fee_cap, breaker);
        check("", "breaker = { gas_budget_per_hour = 1, min_relayer_balance = 1 }").unwrap();
        for bad in ["", "breaker = { gas_budget_per_hour = 1 }", "breaker = { min_relayer_balance = 1 }",
                    "breaker = { gas_budget_per_hour = 1, min_relayer_balance = 0 }", "breaker = { gas_budget_per_hour = 0, min_relayer_balance = 1 }"] {
            let e = check("", bad).unwrap_err().to_string();
            assert!(e.contains("gas_budget_per_hour") && e.contains("min_relayer_balance"), "{bad}: {e}");
        }
        // the third limit, the per-job cap: as the budget, the amount is the operator's, so no default
        let limits = "breaker = { gas_budget_per_hour = 1, min_relayer_balance = 1 }";
        for bad in ["", ", max_resource_fee_per_job = 0", ", max_resource_fee_per_job = \"x\""] {
            let e = with_cap("", bad, limits).unwrap_err().to_string();
            assert!(e.contains("max_resource_fee_per_job"), "{bad}: {e}");
        }
        with_cap("[modules]\nsubmit = false\n", "", "").unwrap();
        for ok in [1, 100] {
            check("", &format!("breaker = {{ gas_budget_per_hour = 1, min_relayer_balance = 1, call_budget_pct = {ok} }}")).unwrap();
        }
        for bad in [0, 101] {
            let e = check("", &format!("breaker = {{ gas_budget_per_hour = 1, min_relayer_balance = 1, call_budget_pct = {bad} }}")).unwrap_err();
            assert!(e.to_string().contains("call_budget_pct"), "{bad}: {e}");
        }
    }

    #[test]
    fn pi_chain_lanes_use_the_chain_coin_type() {
        use crate::signer::Signer;
        // Soroban family, Pi Network passphrase, SLIP-44 314159 (bip_utils 2.9.3, the 24-word "abandon … art").
        let raw = format!("{OK}\n[keys]\nmnemonic = {{ env = \"SCAAS_TEST_MNEMONIC\" }}\n\
            [[chains]]\nfamily = \"soroban\"\nnetwork = \"pi-testnet\"\nrpc_urls = [\"http://p\"]\nlanes = [0, 1]\n\
            coin_type = 314159\nparams = {{ network_passphrase = \"Pi Testnet\", max_resource_fee_per_job = 1 }}\n\
            breaker = {{ gas_budget_per_hour = 1, min_relayer_balance = 1 }}\n");
        let c: Config = toml::from_str(&raw).unwrap();
        c.validate().unwrap();
        std::env::set_var("SCAAS_TEST_MNEMONIC", "abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
            abandon abandon art");
        let strkeys: Vec<String> = c.lane_signers(&c.chains[1]).unwrap().iter()
            .map(|s| crate::signer::stellar_account_strkey(&s.public_key()))
            .collect();
        assert_eq!(strkeys, ["GC34MI42VEGPVUDNHHM3FCVAQ2P6I2B4D3NANHXNDPFCWXQRX73S4DOB",
                             "GAUCCGUGT4FQU2USKSZWZXGGRGIWVA6LTDZLNSIXVR4RZTB6LS7VTI4E"]);
        let stellar: Config = toml::from_str(&raw.replace("coin_type = 314159\n", "")).unwrap();
        let s0 = crate::signer::stellar_account_strkey(&stellar.lane_signers(&stellar.chains[1]).unwrap()[0].public_key());
        assert_eq!(s0, "GB3TCCIC6KLYKM72PX7KA6RNYC2BHC7DQYDMEAAN7PDMUZQD7UKJGSSY", "no coin_type: Stellar 148");
        let bad: Config = toml::from_str(&raw.replace("314159", "2147483648")).unwrap();
        assert!(bad.validate().is_err(), "coin type must be a hardened SLIP-44 index");
        let raw_key: Config = toml::from_str(&OK.replace("signer_key_env", "coin_type = 1\nsigner_key_env")).unwrap();
        assert!(raw_key.validate().is_err(), "coin_type only applies to mnemonic lanes");
    }

    #[test]
    fn unknown_finality_mode_is_refused() {
        let c: Config = toml::from_str(&OK.replace("\"depth\"", "\"soft\"")).unwrap();
        assert!(c.validate().is_err());
    }

    const ODOO: &str = "[odoo]\nurl = \"http://odoo:8069\"\ndatabase = \"odoo19\"\nrelay_api_key_env = \"R\"\n\
                        indexer_api_key_env = \"I\"\n";
    const NO_LEGACY: &str = "[modules]\nsubmit = false\nindexer = false\nadmin_bind = \"\"\n[[chains]]";

    fn bad(raw: &str) -> bool {
        toml::from_str::<Config>(raw).map(|c| c.validate().is_err()).unwrap_or(true)
    }

    #[test]
    fn store_is_required_and_odoo_is_legacy() {
        assert!(OK.starts_with(&format!("\n{ODOO}")));
        assert!(toml::from_str::<Config>(&OK.replace("[store]\nurl = \"sqlite:///var/lib/scaas/node.db\"\n", "")).is_err(),
                "[store] is required");
        let no_odoo = OK.replace(ODOO, "");
        assert!(bad(&no_odoo), "submit/indexer/admin still need [odoo] (R104)");
        let c: Config = toml::from_str(&no_odoo.replace("[[chains]]", NO_LEGACY)).unwrap();
        c.validate().unwrap();
        assert!(c.odoo.is_none());
        assert!(bad(&OK.replace("sqlite:///var/lib/scaas/node.db", "postgres://u@h/db")), "P1b");
        let c: Config = toml::from_str(OK).unwrap();
        assert_eq!((c.store.job_retention_secs, c.store.feed_retention_secs), (30 * 86_400, 7 * 86_400));
        assert_eq!((c.api.bind.as_str(), c.api.lease_hold_after_start_secs), ("127.0.0.1:8548", 15));
        assert_eq!(c.api.admin_auth.modes, ["builtin"]);
        assert_eq!((c.api.admin_auth.session_ttl_secs, c.api.admin_auth.login_max_failures), (900, 10));
        assert!(!c.gossip.enabled && c.transport.quic && c.identity.is_none());
        assert_eq!((c.chains[0].profile.as_str(), c.chains[0].gossip, c.chains[0].exclusive_ms), ("private", false, 7000));
    }

    #[test]
    fn admin_auth_modes_are_validated() {
        let with = |t: &str| OK.replace("[[chains]]", &format!("{t}\n[[chains]]"));
        assert!(bad(&with("[api.admin_auth]\nmodes = []")));
        assert!(bad(&with("[api.admin_auth]\nmodes = [\"oidc\"]")), "no issuers before P2b");
        assert!(bad(&with("[api.admin_auth]\nmodes = [\"password\"]")));
        assert!(bad(&with("[api]\nadmin_cors_origins = [\"*\"]")));
        let c: Config = toml::from_str(&with("[api]\nbind = \"127.0.0.1:8600\"\nmaster_key = { env = \"M\" }\n\
                                              admin_cors_origins = [\"https://app.example.com\"]")).unwrap();
        c.validate().unwrap();
        assert_eq!(c.api.bind, "127.0.0.1:8600");
    }

    const C0: &str = "0x00000000000000000000000000000000000000c0";

    #[test]
    fn bootstrap_lists_are_validated() {
        let ns = |t: &str| format!("{OK}\n[[namespaces]]\n{t}\n");
        toml::from_str::<Config>(&ns("name = \"odoo-prod\"\nchains = [\"evm:7622\"]\nallow_call = true")).unwrap()
            .validate().unwrap();
        assert!(bad(&ns("name = \"~gateway\"")), "reserved");
        assert!(bad(&ns("name = \"Odoo\"")));
        assert!(bad(&ns("name = \"ab\"")));
        assert!(bad(&ns("name = \"odoo\"\nchains = [\"evm:1\"]")), "chain not configured");
        assert!(bad(&format!("{}\n[[namespaces]]\nname = \"odoo\"\n", ns("name = \"odoo\""))), "twice");
        let peer = |t: &str| format!("{OK}\n[[mesh.peers]]\nname = \"a\"\nurl = \"https://a.example.net:8550\"\n\
                                      spki_sha256 = \"{}\"\n{t}\n", "9f".repeat(32));
        toml::from_str::<Config>(&peer("class = \"open\"")).unwrap().validate().unwrap();
        toml::from_str::<Config>(&peer("class = \"private\"\nchains = [\"evm:7622\"]")).unwrap().validate().unwrap();
        assert!(bad(&peer("class = \"private\"")), "private peer without chains");
        assert!(bad(&peer("class = \"open\"").replace("https://", "http://")));
        assert!(bad(&peer("class = \"open\"").replace(&"9f".repeat(32), &"9F".repeat(32))));
        let pol = |t: &str| format!("{OK}\n[[mesh.policy]]\nchain = \"evm:7622\"\nsupport = \"full\"\n\
                                     pool_visibility = \"open\"\n{t}\n");
        toml::from_str::<Config>(&pol(&format!("contract = \"{C0}\"\nselector = \"0x12345678\"\nsubmit = true"))).unwrap()
            .validate().unwrap();
        toml::from_str::<Config>(&pol("contract = \"*\"\nselector = \"*\"")).unwrap().validate().unwrap();
        assert!(bad(&pol("contract = \"*\"\nselector = \"*\"\nsubmit = true")), "MESH R86");
        assert!(bad(&pol(&format!("contract = \"{C0}\"\nselector = \"0x1234\""))));
        assert!(bad(&pol(&format!("contract = \"{C0}\"\nselector = \"*\"\nmin_fee = \"1e3\""))));
        assert!(bad(&pol(&format!("contract = \"{C0}\"\nselector = \"*\"\ngossip = true"))), "private chain");
        assert!(bad(&pol("contract = \"0xC0\"\nselector = \"*\"")), "not an address of the chain's family");
    }

    #[test]
    fn gossip_sections_parse_without_networking() {
        let g = format!("{OK}\n[gossip]\nenabled = true\nlisten = [\"/ip4/0.0.0.0/udp/4001/quic-v1\"]\n");
        assert!(bad(&g), "needs [identity]");
        let c: Config = toml::from_str(&format!("{g}[identity]\nkey = {{ file = \"/etc/scaas/node.key\" }}\n\
                                                [transport]\ntcp = false\n")).unwrap();
        c.validate().unwrap();
        assert!(c.transport.quic && !c.transport.tcp && c.gossip.max_established == 50);
        assert!(bad(&OK.replace("finality =", "gossip = true\nfinality =")), "a private chain never gossips");
        toml::from_str::<Config>(&OK.replace("finality =", "profile = \"public\"\ngossip = true\nfinality ="))
            .unwrap().validate().unwrap();
        assert!(bad(&OK.replace("finality =", "profile = \"open\"\nfinality =")));
    }

    #[test]
    fn boot_set_maps_toml_to_store_rows() {
        let raw = OK.replace("finality =", "tokens = [{ address = \"0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD\", decimals = 6 }]\n\
            breaker = { gas_budget_per_hour = \"100000000000000000000\" }\nfinality =")
            + "\n[[namespaces]]\nname = \"odoo\"\nchains = [\"evm:7622\", \"evm:7622\"]\n";
        let c: Config = toml::from_str(&raw).unwrap();
        c.validate().unwrap();
        let set = c.boot_set(&[vec!["0xAA".into()]]);
        assert_eq!(set.chains[0].chain_key, "evm:7622");
        assert_eq!(set.chains[0].state, "active");
        assert_eq!(set.tokens[0].address, "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "one spelling per EVM token");
        assert_eq!(set.lanes, [store::LaneRow { chain_key: "evm:7622".into(), label: "0xAA".into(), account_index: 0,
                                                journal_max: None }]);
        assert_eq!(set.namespaces[0].chains, ["evm:7622"]);
        let b: serde_json::Value = serde_json::from_str(&set.chains[0].breaker).unwrap();
        assert_eq!(b["gas_budget_per_hour"], "100000000000000000000", "u128 amounts as decimal text");
        let back: BreakerCfg = serde_json::from_value(b).unwrap();
        assert_eq!(back.gas_budget_per_hour, Some(100_000_000_000_000_000_000));
    }

    #[test]
    fn addresses_and_selectors_take_one_spelling() {
        let ck = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"; // EIP-55, pasted from an explorer
        let low = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
        let hedera = "[[chains]]\nfamily = \"hedera\"\nevm_chain_number = 296\nrpc_urls = [\"http://h\"]\n\
                      signer_key_env = \"K\"\nfinality = { mode = \"instant\" }\n\
                      tokens = [{ address = \"0.0.1234\", decimals = 6 }]\n";
        let raw = OK.replace("finality =", &format!("tokens = [{{ address = \"{ck}\", decimals = 6 }}]\nfinality ="))
            + hedera
            + &format!("[[mesh.policy]]\nchain = \"evm:7622\"\ncontract = \"{ck}\"\nselector = \"0xA9059CBB\"\n\
                        support = \"none\"\npool_visibility = \"none\"\n\
                        [[mesh.policy]]\nchain = \"evm:7622\"\ncontract = \"*\"\nselector = \"*\"\n\
                        support = \"full\"\npool_visibility = \"open\"\n");
        let c: Config = toml::from_str(&raw).unwrap();
        c.validate().unwrap();
        let set = c.boot_set(&[vec!["0xaa".into()], vec!["0xbb".into()]]);
        assert_eq!(set.tokens[0].address, low);
        assert_eq!(set.tokens[1].address, "0x00000000000000000000000000000000000004d2", "Hedera 0.0.N = long-zero");
        assert_eq!((set.policy[0].contract.as_str(), set.policy[0].selector.as_str()), (low, "0xa9059cbb"));
        let rows: Vec<crate::mesh::accept::PolicyRow> = serde_json::from_value(serde_json::to_value(&set.policy).unwrap()).unwrap();
        let hit = crate::mesh::accept::lookup(&rows, "evm:7622", low, "0xa9059cbb");
        assert_eq!(hit.map(|r| r.support), Some(crate::mesh::accept::Support::None),
                   "the deny row matches; no fall-through to (*, *)");
        assert!(bad(&raw.replace(ck, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD")), "bad EIP-55 checksum (Odoo refuses it)");
        assert!(bad(&raw.replace("0.0.1234", "0.1.1234")));
    }

    #[test]
    fn listener_binds_never_collide() {
        let with = |t: &str| OK.replace("[[chains]]", &format!("{t}\n[[chains]]"));
        toml::from_str::<Config>(&with("[modules]\ngateway = true")).unwrap().validate().unwrap(); // distinct defaults
        assert!(bad(&with("[api]\nbind = \"127.0.0.1:9108\"")), "admin_bind");
        assert!(bad(&with("[api]\nbind = \"127.0.0.1:8547\"\n[modules]\ngateway = true")), "gateway_bind");
        assert!(bad(&with("[api]\nbind = \"0.0.0.0:8547\"\n[modules]\ngateway = true")), "the wildcard takes the port");
        assert!(bad(&with("[modules]\ngateway = true\ngateway_bind = \"127.0.0.1:9108\"")), "gateway vs admin");
        toml::from_str::<Config>(&with("[api]\nbind = \"127.0.0.1:8547\"")).unwrap().validate().unwrap(); // gateway off
        toml::from_str::<Config>(&with("[api]\nbind = \"127.0.0.2:9108\"")).unwrap().validate().unwrap(); // other host
    }

    #[test]
    fn retention_is_bounded() {
        assert!(bad(&OK.replace("[store]\n", "[store]\njob_retention_secs = 999999999999\n")));
        assert!(bad(&OK.replace("[store]\n", "[store]\nfeed_retention_secs = 999999999999\n")));
        toml::from_str::<Config>(&OK.replace("[store]\n", "[store]\njob_retention_secs = 315360000\n")).unwrap()
            .validate().unwrap();
    }

}
