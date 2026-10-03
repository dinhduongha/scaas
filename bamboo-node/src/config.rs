use std::path::Path;

use crate::keys::{self, SecretSource, Seed};
use crate::signer::LocalSigner;

use alloy::primitives::Address;
use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub odoo: OdooCfg,
    /// Mnemonic BIP-39 24 từ cho mọi lane không có `private_key` riêng (R60).
    #[serde(default)]
    pub keys: Option<KeysCfg>,
    #[serde(default)]
    pub modules: Modules,
    pub chains: Vec<ChainCfg>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeysCfg {
    pub mnemonic: SecretSource,
    #[serde(default)]
    pub bip39_passphrase_env: Option<String>,
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
    /// `evm` (mặc định) | `hedera` | `sui` | `soroban` | `cosmos` | `ton`.
    #[serde(default = "evm")]
    pub family: String,
    /// Mạng ngoài EVM: `localnet`, `testnet`, chain-id Cosmos… (khoá `family:network`).
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
    /// Tham số riêng của adapter (package id Sui, passphrase mạng Stellar, prefix bech32…).
    #[serde(default)]
    pub params: toml::Table,
    #[serde(default = "default_finality")]
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

fn yes() -> bool {
    true
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
        let mut seen = std::collections::HashSet::new();
        for c in &self.chains {
            let key = c.chain_key();
            if !seen.insert(key.clone()) {
                bail!("chain {key} configured twice");
            }
            keys::lane_path(&c.family, 0).with_context(|| format!("chain {key}"))?;
            if c.rpc_urls.is_empty() || c.rpc_urls.len() < c.finality.quorum {
                bail!("chain {key}: {} rpc_urls < quorum {}", c.rpc_urls.len(), c.finality.quorum);
            }
            if c.is_evm() {
                if c.evm_chain_number == 0 {
                    bail!("chain {key}: evm_chain_number is required for {}", c.family);
                }
                if c.finality.mode != "depth" && c.finality.mode != "tag" {
                    bail!("chain {key}: finality.mode must be depth|tag");
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
            if !raw && self.keys.is_none() {
                bail!("chain {key}: no key (private_key, signer_key_env or [keys].mnemonic)");
            }
        }
        Ok(())
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
                let (curve, key) = keys::lane_secret(&seed, &c.family, i)?;
                LocalSigner::new(curve, &key)
            })
            .collect()
    }
}

impl ChainCfg {
    pub fn is_evm(&self) -> bool {
        self.family == "evm" || self.family == "hedera"
    }

    /// `evm:9000`, `hedera:296`, `sui:localnet`… — khoá chung với Odoo `blockchain.chain.chain_key`.
    pub fn chain_key(&self) -> String {
        match &self.network {
            Some(n) => format!("{}:{n}", self.family),
            None => format!("{}:{}", self.family, self.evm_chain_number),
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

    #[test]
    fn non_evm_chain_with_mnemonic_lanes() {
        let raw = format!("{OK}\n[keys]\nmnemonic = {{ env = \"BAMBOO_TEST_MNEMONIC\" }}\n\
            [[chains]]\nfamily = \"sui\"\nnetwork = \"localnet\"\nrpc_urls = [\"http://s\"]\nlanes = [0, 1]\n\
            params = {{ package = \"0x2\" }}\n");
        let c: Config = toml::from_str(&raw).unwrap();
        c.validate().unwrap();
        assert_eq!(c.chains[1].chain_key(), "sui:localnet");
        assert_eq!(c.chains[0].chain_key(), "evm:9000");
        assert_eq!(c.chains[1].params["package"].as_str(), Some("0x2"));
        std::env::set_var("BAMBOO_TEST_MNEMONIC", "abandon abandon abandon abandon abandon abandon abandon abandon \
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
        let c: Config = toml::from_str(&OK.replace("evm_chain_number = 9000\n", "")).unwrap();
        assert!(c.validate().is_err(), "evm needs a chain id");
    }

    #[test]
    fn unknown_finality_mode_is_refused() {
        let c: Config = toml::from_str(&OK.replace("\"depth\"", "\"soft\"")).unwrap();
        assert!(c.validate().is_err());
    }
}
