// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T14 (a): Hedera's Relay reads on `EvmPool` (spec §5.3): the raw receipt (its `revertReason` kept for the node's Hedera
//! status classes), the transaction by hash and the gas price, from the first endpoint only, bounded like every EVM answer.
mod common;
use alloy::primitives::B256;
use common::*;
use scaas_rpc::evm::EvmPool;
use scaas_rpc::{Endpoint, NodeList, Policy};
use serde_json::{json, Value};
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;

const ID: B256 = B256::repeat_byte(0xab);

fn pool(urls: &[&str]) -> EvmPool {
    let e = urls.iter().map(|u| Endpoint::named(u).unwrap()).collect();
    EvmPool::connect(
        NodeList::new(e, Policy::Failover, 2_000, 2_000, 60_000).unwrap(),
        296,
        Some(genesis()),
    )
    .unwrap()
}

/// A Relay answering the receipt with `receipt`, the transaction by hash with `tx`, the gas price `0xca900a7c00`.
async fn relay(receipt: Value, tx: Value) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    fake_dyn(Arc::new(move |r: &Value| match r["method"].as_str() {
        Some("eth_getTransactionReceipt") => json!({"result": receipt}),
        Some("eth_getTransactionByHash") => json!({"result": tx}),
        Some("eth_gasPrice") => json!({"result": "0xca900a7c00"}),
        _ => json!({"error": {"code": -32601, "message": "no such method"}}),
    }))
    .await
}

/// The adapter's `recorded_receipt_decodes` and `hedera_revert_reasons` read these: the receipt comes back whole, its
/// `revertReason` (a Hedera status in ASCII hex) untouched; none is `null`; the transaction known or not.
#[tokio::test]
async fn the_relay_receipt_is_read_raw_from_the_first_endpoint() {
    let rc =
        json!({"status": "0x0", "blockNumber": "0x10", "revertReason": "0x57524f4e475f4e4f4e4345"});
    let (u, _) = relay(rc.clone(), Value::Null).await;
    assert_eq!(pool(&[&u]).first_relay_receipt(ID).await.unwrap(), rc);
    assert!(!pool(&[&u]).first_tx_known(ID).await.unwrap());
    let (u, _) = relay(Value::Null, json!({"hash": format!("{ID:#x}")})).await;
    assert_eq!(
        pool(&[&u]).first_relay_receipt(ID).await.unwrap(),
        Value::Null
    );
    assert!(pool(&[&u]).first_tx_known(ID).await.unwrap());
    assert_eq!(pool(&[&u]).first_gas_price().await.unwrap(), 0xca900a7c00);
}

/// F3: a status and the gas price are endpoint 0's only: with it down, an error, and endpoint 1 is never asked. Control: endpoint
/// 0 up answers.
#[tokio::test]
async fn the_relay_status_never_fails_over() {
    let (good, n) = relay(json!({"status": "0x1", "blockNumber": "0x10"}), Value::Null).await;
    let p = pool(&[DOWN, &good]);
    assert!(p.first_relay_receipt(ID).await.is_err());
    assert!(p.first_tx_known(ID).await.is_err());
    assert!(p.first_gas_price().await.is_err());
    assert_eq!(n.load(SeqCst), 0, "endpoint 1 is never asked");
    assert_eq!(
        pool(&[&good, DOWN]).first_relay_receipt(ID).await.unwrap()["status"],
        "0x1",
        "control"
    );
}

/// F5 over the Relay's answer shapes: a receipt answer of 16 MiB + 1 is the endpoint's failure (AnswerTooLarge). Control: the
/// same endpoint's small answer is read.
#[tokio::test]
async fn a_relay_answer_above_16_mib_is_refused() {
    async fn big(len: usize) -> String {
        let b0 = block(0, genesis());
        serve(axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
                let b0 = b0.clone();
                async move {
                    let result = match r["method"].as_str() {
                        Some("eth_chainId") => json!("0x128"),
                        Some("eth_getBlockByNumber") => b0,
                        _ => json!({"status": "0x1", "blockNumber": "0x10"}),
                    };
                    let mut b = serde_json::to_vec(
                        &json!({"jsonrpc": "2.0", "id": r["id"], "result": result}),
                    )
                    .unwrap();
                    if r["method"] == "eth_getTransactionReceipt" {
                        b.resize(len, b' ');
                    }
                    b
                }
            }),
        ))
        .await
    }
    let e = pool(&[&big((16 << 20) + 1).await])
        .first_relay_receipt(ID)
        .await
        .unwrap_err();
    assert!(
        e.to_string().contains("AnswerTooLarge") || e.to_string().contains("above"),
        "{e}"
    );
    assert_eq!(
        pool(&[&big(100).await])
            .first_relay_receipt(ID)
            .await
            .unwrap()["status"],
        "0x1",
        "control"
    );
}
