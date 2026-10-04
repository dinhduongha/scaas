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

/// Log đã giải mã theo đúng khoá Odoo đọc (`dms_blockchain` `_decode`). None = không phải
/// event ta theo dõi, hoặc log thiếu vị trí (log pending) — loại.
pub fn encode_event(log: &Log) -> Option<Value> {
    let mut v = json!({
        "contract": format!("{:#x}", log.address()),
        "block_number": log.block_number?,
        "block_hash": format!("{:#x}", log.block_hash?),
        "tx_hash": format!("{:#x}", log.transaction_hash?),
        "log_index": log.log_index?,
    });
    let topic0 = *log.topic0()?;
    if topic0 == IMetaToken::PaymentSettled::SIGNATURE_HASH {
        let e = log.log_decode::<IMetaToken::PaymentSettled>().ok()?.inner.data;
        v["event"] = json!("PaymentSettled");
        v["from"] = json!(format!("{:#x}", e.from));
        v["to"] = json!(format!("{:#x}", e.to));
        v["amount"] = json!(e.amount.to_string());
        v["fee"] = json!(e.feeAmount.to_string());
        v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
        v["entry_ref"] = json!(format!("{:#x}", e.entryRef));
    } else if topic0 == IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH {
        let e = log.log_decode::<IMetaToken::MetaTransactionExecuted>().ok()?.inner.data;
        v["event"] = json!("MetaTransactionExecuted");
        v["from"] = json!(format!("{:#x}", e.from));
        v["relayer"] = json!(format!("{:#x}", e.relayer));
        v["batch"] = json!(e.batch.to_string());
        v["nonce"] = json!(e.nonce.to_string());
        v["digest"] = json!(format!("{:#x}", e.digest));
        v["fee_recipient"] = json!(format!("{:#x}", e.feeRecipient));
        v["fee"] = json!(e.fee.to_string());
    } else {
        return None;
    }
    Some(v)
}

pub async fn run(chain: Arc<Chain>, odoo: Odoo, poll: Duration) {
    loop {
        match step(&chain, &odoo).await {
            Ok(true) => continue, // còn tồn đọng: đi tiếp ngay
            Ok(false) => {}
            Err(e) => warn!(chain = chain.number, "indexer: {e:#}"),
        }
        tokio::time::sleep(poll).await;
    }
}

/// Một vòng: đọc cursor + token từ Odoo, tính vùng final, kiểm quorum, gửi. `true` = đã tiến.
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
    let addrs: Vec<Address> = nc.tokens.iter().filter_map(crate::odoo::TokenCfg::evm).collect();
    let events: Vec<Value> = if addrs.is_empty() {
        vec![]
    } else {
        let f = Filter::new().from_block(from).to_block(to).address(addrs).event_signature(vec![
            IMetaToken::PaymentSettled::SIGNATURE_HASH,
            IMetaToken::MetaTransactionExecuted::SIGNATURE_HASH,
        ]);
        chain.primary().get_logs(&f).await?.iter().filter_map(encode_event).collect()
    };
    let r = odoo.ingest(chain.number, from, to, &format!("{hash:#x}"), &events).await?;
    info!(chain = chain.number, from, to, created = r.created, "ingested");
    Ok(r.indexed_block >= to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, LogData, B256, U256};

    fn log_of(data: LogData) -> Log {
        Log {
            inner: alloy::primitives::Log { address: Address::repeat_byte(9), data },
            block_hash: Some(B256::repeat_byte(0xb)),
            block_number: Some(5),
            transaction_hash: Some(B256::repeat_byte(0xe)),
            log_index: Some(2),
            ..Default::default()
        }
    }

    #[test]
    fn payment_settled_is_encoded_for_odoo() {
        let ev = IMetaToken::PaymentSettled {
            from: Address::repeat_byte(1),
            to: Address::repeat_byte(2),
            amount: U256::from(250u64),
            feeAmount: U256::ZERO,
            feeRecipient: Address::repeat_byte(3),
            entryRef: B256::repeat_byte(4),
        };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!(v["event"], "PaymentSettled");
        assert_eq!(v["amount"], "250");
        assert_eq!(v["entry_ref"], format!("{:#x}", B256::repeat_byte(4)));
        assert_eq!(v["log_index"], 2);
        assert_eq!(v["contract"], format!("{:#x}", Address::repeat_byte(9)));
    }

    #[test]
    fn executed_carries_the_digest() {
        let ev = IMetaToken::MetaTransactionExecuted {
            from: Address::repeat_byte(1),
            relayer: Address::repeat_byte(2),
            batch: U256::from(7u64),
            nonce: U256::ZERO,
            digest: B256::repeat_byte(5),
            feeRecipient: Address::repeat_byte(2),
            fee: U256::ZERO,
        };
        let v = encode_event(&log_of(ev.encode_log_data())).unwrap();
        assert_eq!(v["event"], "MetaTransactionExecuted");
        assert_eq!(v["digest"], format!("{:#x}", B256::repeat_byte(5)));
        assert_eq!(v["batch"], "7");
    }

    #[test]
    fn pending_or_foreign_logs_are_dropped() {
        let ev = IMetaToken::PaymentSettled {
            from: Address::ZERO,
            to: Address::ZERO,
            amount: U256::ZERO,
            feeAmount: U256::ZERO,
            feeRecipient: Address::ZERO,
            entryRef: B256::ZERO,
        };
        let mut pending = log_of(ev.encode_log_data());
        pending.block_number = None;
        assert!(encode_event(&pending).is_none());
        let foreign = log_of(LogData::new_unchecked(vec![B256::repeat_byte(7)], Default::default()));
        assert!(encode_event(&foreign).is_none());
    }
}
