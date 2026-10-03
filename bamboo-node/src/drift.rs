//! Drift C (R56, GA 2.2#7): mỗi giờ đọc `balanceOf(ví nhận)` tại đúng khối Odoo đã index (đã final) và báo
//! `blockchain.chain.balance_report`. Odoo so tổng với số dư sổ của journal token; node không phán xét gì.
use std::sync::Arc;
use std::time::Duration;

use alloy::eips::BlockId;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use anyhow::Result;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::abi::IMetaToken;
use crate::chain::Chain;
use crate::indexer::receiving_pairs;
use crate::odoo::Odoo;

const EVERY: Duration = Duration::from_secs(3600);
const STALE_RETRY: Duration = Duration::from_secs(20);
const STALE_TRIES: u32 = 10;

/// Thân báo cáo cho Odoo — số dư là chuỗi thập phân (uint256 vượt JSON number).
pub fn report_rows(rows: &[(Address, Address, U256)]) -> Vec<Value> {
    rows.iter()
        .map(|(t, a, b)| json!({"token": format!("{t:#x}"), "address": format!("{a:#x}"), "balance": b.to_string()}))
        .collect()
}

/// Một lần đo. `Ok(false)` = cursor đã chạy trước lúc đọc xong (thử lại); `Ok(true)` = xong (kể cả không có ví).
pub async fn step(chain: &Chain, odoo: &Odoo, chain_key: &str) -> Result<bool> {
    let nc = odoo.node_config(chain.number, None).await?;
    let pairs = receiving_pairs(&nc);
    let height = nc.indexed_block;
    if pairs.is_empty() || height == 0 {
        return Ok(true);
    }
    let mut rows = Vec::new();
    for (token, who) in pairs {
        let tx = TransactionRequest::default()
            .with_to(token)
            .with_input(IMetaToken::balanceOfCall { who }.abi_encode());
        let out = chain.primary().call(tx).block(BlockId::number(height)).await?;
        rows.push((token, who, IMetaToken::balanceOfCall::abi_decode_returns(&out)?));
    }
    let r = odoo.balance_report(chain_key, height, &report_rows(&rows)).await?;
    if !r.stale {
        info!(chain = chain.number, height, mismatch = r.mismatch, "balance drift reported");
    }
    Ok(!r.stale)
}

pub async fn run(chain: Arc<Chain>, odoo: Odoo, chain_key: String) {
    loop {
        for _ in 0..STALE_TRIES {
            match step(&chain, &odoo, &chain_key).await {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => warn!(chain = chain.number, "drift: {e:#}"),
            }
            tokio::time::sleep(STALE_RETRY).await;
        }
        tokio::time::sleep(EVERY).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_rows_are_decimal_strings() {
        let big = U256::from(10u64).pow(U256::from(30u64));
        let rows = report_rows(&[(Address::repeat_byte(1), Address::repeat_byte(2), big)]);
        assert_eq!(rows[0]["balance"], "1000000000000000000000000000000");
        assert_eq!(rows[0]["token"], format!("{:#x}", Address::repeat_byte(1)));
        assert_eq!(rows[0]["address"], format!("{:#x}", Address::repeat_byte(2)));
    }
}
