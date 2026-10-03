//! Một file mỗi họ mạng. `evm` dùng chung cho Hedera (HSCS qua JSON-RPC relay — R63).
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::adapter::ChainAdapter;
use crate::config::ChainCfg;
use crate::signer::LocalSigner;

pub mod cosmos;
pub mod evm;

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
        other => bail!("chain {}: no adapter for family {other} in this build", cfg.chain_key()),
    }
}
