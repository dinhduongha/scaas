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

fn yes() -> bool {
    true
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
        for c in &self.chains {
            if c.rpc_urls.is_empty() || c.rpc_urls.len() < c.finality.quorum {
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

    #[test]
    fn unknown_finality_mode_is_refused() {
        let c: Config = toml::from_str(&OK.replace("\"depth\"", "\"soft\"")).unwrap();
        assert!(c.validate().is_err());
    }
}
