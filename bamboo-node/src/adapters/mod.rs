//! Một file mỗi họ mạng. `evm` dùng chung cho Hedera (HSCS qua JSON-RPC relay — R63).
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::adapter::ChainAdapter;
use crate::config::ChainCfg;
use crate::signer::LocalSigner;

pub mod evm;
pub mod ton;

/// Adapter cho một chain KHÔNG chạy runner EVM riêng. Mỗi luồng mạng thêm một nhánh ở đây.
#[allow(clippy::match_single_binding)] // one arm per network family as streams land
pub fn build(cfg: &ChainCfg, signers: &[LocalSigner]) -> Result<Arc<dyn ChainAdapter>> {
    match cfg.family.as_str() {
        "ton" => Ok(Arc::new(ton::TonAdapter::new(cfg, signers)?)),
        other => bail!("chain {}: no adapter for family {other} in this build", cfg.chain_key()),
    }
}
