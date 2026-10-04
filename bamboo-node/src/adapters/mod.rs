//! Một file mỗi họ mạng. `evm` dùng chung cho Hedera (HSCS qua JSON-RPC relay — R63).
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::adapter::ChainAdapter;
use crate::config::ChainCfg;
use crate::signer::LocalSigner;

pub mod cosmos;
pub mod evm;
pub mod hedera;
pub mod soroban;
pub mod sui;
pub mod ton;

/// Adapter giữ signer của nó; `LocalSigner` không `Clone` nên chép khoá bên trong.
fn own(s: &LocalSigner) -> LocalSigner {
    match s {
        LocalSigner::Secp(k) => LocalSigner::Secp(k.clone()),
        LocalSigner::Ed(k) => LocalSigner::Ed(k.clone()),
    }
}

/// Adapter cho một chain KHÔNG chạy runner EVM riêng. Mỗi luồng mạng thêm một nhánh ở đây.
pub fn build(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Arc<dyn ChainAdapter>> {
    match cfg.family.as_str() {
        "cosmos" => Ok(Arc::new(cosmos::CosmosAdapter::new(cfg, signers.iter().map(own).collect())?)),
        "hedera" => Ok(Arc::new(hedera::HederaAdapter::from_cfg(cfg, signers)?)),
        "soroban" => Ok(Arc::new(soroban::SorobanAdapter::new(cfg, signers)?)),
        "ton" => Ok(Arc::new(ton::TonAdapter::new(cfg, signers)?)),
        "sui" => Ok(Arc::new(sui::SuiAdapter::new(cfg, signers)?)),
        other => bail!("chain {}: no adapter for family {other} in this build", cfg.chain_key()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::config::Config;
    use crate::keys::{lane_secret, Seed};
    use crate::signer::LocalSigner;

    /// Merge TODO f: `node.example.toml` has a working `[[chains]]` for every family — it parses, validates, and
    /// every adapter builds from it (only the Sui package id and journal directory are swapped for real ones).
    #[test]
    fn example_config_builds_every_family() {
        let mut cfg: Config = toml::from_str(include_str!("../../node.example.toml")).unwrap();
        cfg.validate().unwrap();
        let families: BTreeSet<&str> = cfg.chains.iter().map(|c| c.family.as_str()).collect();
        assert_eq!(families, BTreeSet::from(["cosmos", "evm", "hedera", "soroban", "sui", "ton"]));
        let words = format!("{}art", "abandon ".repeat(23));
        let seed = Seed::from_words(&words, None).unwrap();
        let dir = std::env::temp_dir().join(format!("example-journal-{}", std::process::id()));
        for c in cfg.chains.iter_mut().filter(|c| c.uses_adapter()) {
            if c.family == "sui" {
                c.params.insert("package".into(), "0x2".into());
                c.params.insert("lane_journal".into(), dir.to_string_lossy().to_string().into());
            }
            let signers: Vec<LocalSigner> = c
                .lanes
                .iter()
                .map(|&i| {
                    let (curve, k) = lane_secret(&seed, &c.family, i).unwrap();
                    LocalSigner::new(curve, &k).unwrap()
                })
                .collect();
            if let Err(e) = super::build(c, &signers) {
                panic!("{}: {e:#}", c.family);
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
