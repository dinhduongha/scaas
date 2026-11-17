// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T4: `EvmPool` against fake endpoints. The bounds through the alloy providers (F5), the first-endpoint reads (F4), and the
//! node's `chain::tests` copied with their names (F17; the node keeps its own as wiring tests).
mod common;
use alloy::primitives::{Address, Bytes, B256, U256};
use common::*;
use scaas_rpc::evm::{classify, is_contract, EvmPool, Shared, SimError};
use scaas_rpc::{NodeList, Policy, Purpose};
use serde_json::{json, Value};
use std::sync::atomic::Ordering::SeqCst;

fn list(urls: &[&str], timeout_ms: u64, slow_ms: u64) -> NodeList {
    let e = urls.iter().map(|u| scaas_rpc::Endpoint::named(u).unwrap()).collect();
    NodeList::new(e, Policy::Failover, timeout_ms, slow_ms, 60_000).unwrap()
}

/// The node's pool for chain 296 (`connect_shared`: endpoint 0 checked where the node checks it), pinned to [`genesis`].
fn node_pool(urls: &[&str]) -> EvmPool {
    node_pool_with(urls, Some(genesis()), Shared::default(), 30_000, 120_000)
}

fn node_pool_with(urls: &[&str], pin: Option<B256>, shared: Shared, timeout_ms: u64, slow_ms: u64) -> EvmPool {
    EvmPool::connect_shared(list(urls, timeout_ms, slow_ms), 296, pin, shared, scaas_rpc::evm::default_decode).unwrap()
}

/// The SDK's pool: every endpoint identity-checked.
fn sdk_pool(urls: &[&str], timeout_ms: u64) -> EvmPool {
    EvmPool::connect(list(urls, timeout_ms, timeout_ms), 296, Some(genesis())).unwrap()
}

fn five() -> Bytes {
    Bytes::from(U256::from(5).to_be_bytes::<32>().to_vec())
}

async fn call(c: &EvmPool) -> Result<Bytes, SimError> {
    c.call_tx(alloy::rpc::types::TransactionRequest::default().to(Address::ZERO).input(Bytes::new().into())).await
}

/// An endpoint whose `eth_getCode` answer is `body` (raw bytes, `chunked` or announced), chain id and block 0 as [`fake_rpc`].
async fn code_answer(body: fn(&Value) -> Vec<u8>, chunked: bool) -> String {
    let b0 = block(0, genesis());
    let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
        let b0 = b0.clone();
        async move {
            let small = |v: Value| axum::body::Body::from(serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": r["id"], "result": v})).unwrap());
            let out = match r["method"].as_str() {
                Some("eth_chainId") => small(json!("0x128")),
                Some("eth_getBlockByNumber") => small(b0),
                Some("eth_blockNumber") => small(json!("0x10")),
                _ if chunked => {
                    let all = body(&r);
                    let parts: Vec<Result<Vec<u8>, std::io::Error>> = all.chunks(1 << 16).map(|c| Ok(c.to_vec())).collect();
                    axum::body::Body::from_stream(futures::stream::iter(parts))
                }
                _ => axum::body::Body::from(body(&r)),
            };
            axum::response::Response::builder().header("content-type", "application/json").body(out).unwrap()
        }
    }));
    serve(app).await
}

/// A JSON-RPC answer of exactly `len` bytes: `{"jsonrpc":"2.0","id":…,"result":"0x"}` padded with spaces.
fn answer_of_len(r: &Value, len: usize) -> Vec<u8> {
    let mut b = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x6001"})).unwrap();
    b.resize(len, b' ');
    b
}

const CAP: usize = 16 << 20;

#[tokio::test]
async fn an_evm_answer_above_the_cap_is_that_endpoints_failure() {
    let (good, _) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x10"}),
        _ => json!({"result": "0x6002"}),
    }).await;
    for chunked in [false, true] {
        let big = code_answer(|r| answer_of_len(r, CAP + 1), chunked).await;
        assert_eq!(sdk_pool(&[&big, &good], 30_000).code(Address::ZERO).await.unwrap(), Bytes::from(vec![0x60, 0x02]),
            "fails over to endpoint 1 (chunked {chunked})");
        let e = sdk_pool(&[&big], 30_000).code(Address::ZERO).await.unwrap_err();
        assert!(matches!(&e, SimError::Transport(t) if t.contains("AnswerTooLarge") || t.contains("above")), "{e}");
    }
}

#[tokio::test]
async fn an_evm_answer_of_depth_65_is_too_deep() {
    // the answer object is depth 1: a result nested 64 deep is depth 65
    let deep = code_answer(|r| format!(r#"{{"jsonrpc":"2.0","id":{},"result":{}{}}}"#, r["id"], "[".repeat(64), "]".repeat(64)).into_bytes(), false).await;
    let e = sdk_pool(&[&deep], 30_000).code(Address::ZERO).await.unwrap_err();
    assert!(matches!(&e, SimError::Transport(t) if t.contains("AnswerTooDeep")), "{e}");
    let ok = code_answer(|r| format!(r#"{{"jsonrpc":"2.0","id":{},"result":{}{}}}"#, r["id"], "[".repeat(63), "]".repeat(63)).into_bytes(), false).await;
    let e = sdk_pool(&[&ok], 30_000).code(Address::ZERO).await.unwrap_err();
    assert!(!matches!(&e, SimError::Transport(t) if t.contains("AnswerTooDeep")), "control: depth 64 reaches the parser: {e}");
}

#[tokio::test]
async fn an_evm_answer_at_the_cap_is_read() {
    let at = code_answer(|r| answer_of_len(r, CAP), true).await;
    assert_eq!(sdk_pool(&[&at], 30_000).code(Address::ZERO).await.unwrap(), Bytes::from(vec![0x60, 0x01]));
}

#[tokio::test]
async fn the_lane_nonce_fee_and_receipt_never_fail_over() {
    let stuck = hung().await;
    let (good, good_n) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x10"}),
        Some("eth_getTransactionCount") => json!({"result": "0x7"}),
        Some("eth_getTransactionReceipt") => json!({"result": null}),
        Some("eth_getTransactionByHash") => json!({"result": null}),
        Some("eth_feeHistory") => json!({"result": {"oldestBlock": "0x1", "baseFeePerGas": ["0x7", "0x7"], "gasUsedRatio": [0.5],
            "reward": [["0x1"]]}}),
        Some("eth_maxPriorityFeePerGas") => json!({"result": "0x1"}),
        Some("eth_gasPrice") => json!({"result": "0x8"}),
        _ => json!({"result": "0x0"}),
    }).await;
    let p = sdk_pool(&[&stuck, &good], 300);
    let a = Address::repeat_byte(1);
    assert!(p.first_pending_nonce(a).await.is_err());
    assert!(p.first_nonce_at(a).await.is_err());
    assert!(p.first_fees().await.is_err());
    assert!(p.first_receipt(B256::ZERO).await.is_err());
    assert!(p.first_tx_fees(B256::ZERO).await.is_err());
    assert_eq!(p.first_finalized_number().await, None);
    assert_eq!(good_n.load(SeqCst), 0, "endpoint 1 is never asked");
    // control: the SDK's failover reads move to it
    assert_eq!(p.pending_nonce(a, Purpose::Plain).await.unwrap(), 7);
    assert!(p.fees(Purpose::Plain).await.unwrap().max_fee_per_gas >= 1);
    assert_eq!(p.receipt(B256::ZERO).await.unwrap(), None);
    assert!(good_n.load(SeqCst) > 0);
}

/// The node's `chain_reads_fail_over_on_transport_errors_never_on_a_revert`, on `EvmPool`.
#[tokio::test]
async fn chain_reads_fail_over_on_transport_errors_never_on_a_revert() {
    let (good, good_n) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x64"}),
        Some("eth_getLogs") => json!({"result": []}),
        _ => json!({"result": format!("0x{:064x}", 5)}),
    }).await;
    let (busy, busy_n) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "header not found"}})).await;
    let (rev, rev_n) = fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}})).await;
    assert_eq!(call(&node_pool(&[&good])).await.unwrap(), five(), "control");
    assert_eq!(call(&node_pool(&[DOWN, &good])).await.unwrap(), five(), "the first endpoint down");
    assert_eq!(call(&node_pool(&[&busy, &good])).await.unwrap(), five(), "an error answer that is no revert");
    assert_eq!(busy_n.load(SeqCst), 1);
    let before = good_n.load(SeqCst);
    assert!(matches!(call(&node_pool(&[&rev, &good])).await, Err(SimError::Revert(_))), "a revert is final");
    assert_eq!((rev_n.load(SeqCst), good_n.load(SeqCst)), (1, before), "the next endpoint is never asked after a revert");
    assert!(matches!(call(&node_pool(&[DOWN, &busy])).await, Err(SimError::Transport(_))), "all down");
    let (stale, stale_n) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x10"}),
        _ => json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}}),
    }).await;
    let (level, _) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x10"}),
        _ => json!({"result": format!("0x{:064x}", 5)}),
    }).await;
    let fresh = node_pool(&[DOWN, &stale]);
    assert_eq!(fresh.seen_head(), 0);
    assert!(matches!(call(&fresh).await, Err(SimError::Transport(e)) if e.contains("decides nothing")), "head 0: requeue");
    let at_head = node_pool(&[DOWN, &stale]);
    at_head.saw_block(0x10);
    assert!(matches!(call(&at_head).await, Err(SimError::Transport(e)) if e.contains("decides nothing")), "at the head too");
    assert!(matches!(call(&node_pool(&[&stale])).await, Err(SimError::Revert(_))), "control: the first endpoint's revert is final");
    let shared = Shared::default();
    let lane = node_pool_with(&[DOWN, &level], Some(genesis()), shared.clone(), 30_000, 120_000);
    let venue = node_pool_with(&[DOWN, &level], Some(genesis()), shared.clone(), 30_000, 120_000);
    assert_eq!(call(&venue).await.unwrap(), five(), "control: at the head, its answer is used");
    assert_eq!((venue.failover_answers(), lane.failover_answers()), (1, 0), "a failover answer is counted, per pool");
    assert_eq!(shared.failover.load(SeqCst), 1, "and per table, for health");
    let first = node_pool(&[&level]);
    call(&first).await.unwrap();
    assert_eq!(first.failover_answers(), 0, "control: the first endpoint's answer is not");
    assert_eq!(venue.seen_head(), 0, "a failover endpoint's own head raises nothing");
    lane.saw_block(0x11);
    let before = stale_n.load(SeqCst);
    assert!(matches!(call(&venue).await, Err(SimError::Transport(e)) if e.contains("behind 17")));
    let behind = node_pool(&[DOWN, &stale]);
    behind.saw_block(0x11);
    assert!(matches!(call(&behind).await, Err(SimError::Transport(e)) if e.contains("behind")), "stale: requeue, never final");
    assert_eq!(stale_n.load(SeqCst) - before, 1, "only its head was read");
    let (headless, _) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"error": {"code": -32000, "message": "header not found"}}),
        _ => json!({"error": {"code": 3, "message": "execution reverted", "data": "0xdeadbeef"}}),
    }).await;
    assert!(matches!(call(&node_pool(&[DOWN, &headless])).await, Err(SimError::Transport(_))),
        "a failover endpoint whose head is unread answers nothing");
    let answer = |r: &Value| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x64"}),
        _ => json!({"result": format!("0x{:064x}", 5)}),
    };
    for (id, zero) in [(1, genesis()), (296, B256::repeat_byte(0x61))] {
        let (other, other_n) = fake_rpc_on(answer, id, zero).await;
        let c = node_pool(&[DOWN, &other]);
        for _ in 0..2 {
            assert!(matches!(call(&c).await, Err(SimError::Transport(e)) if e.contains("not chain 296")));
        }
        assert_eq!(other_n.load(SeqCst), 0, "nothing but its chain id and block 0 was asked");
        assert_eq!(c.pool().identity_of(1), Some(false), "dropped, once");
    }
    let (same, _) = fake_rpc(answer).await;
    let c = node_pool_with(&[DOWN, &same], None, Shared::default(), 30_000, 120_000);
    assert!(matches!(call(&c).await, Err(SimError::Transport(e)) if e.contains("unreadable")));
    assert_eq!(c.pool().identity_of(1), None, "not kept");
    let (first, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "busy"}})).await;
    let c = node_pool_with(&[&first, &same], None, Shared::default(), 30_000, 120_000);
    assert_eq!(call(&c).await.unwrap(), five(), "the first endpoint's block 0 matches");
    let mute = serve(axum::Router::new().route("/", axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
        axum::Json(match r["method"].as_str() {
            Some("eth_chainId") => json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32000, "message": "busy"}}),
            Some("eth_blockNumber") => json!({"jsonrpc": "2.0", "id": r["id"], "result": "0x64"}),
            _ => json!({"jsonrpc": "2.0", "id": r["id"], "result": format!("0x{:064x}", 5)}),
        })
    }))).await;
    let c = node_pool(&[DOWN, &mute]);
    assert!(matches!(call(&c).await, Err(SimError::Transport(e)) if e.contains("chain id unreadable")), "unread chain id: not used");
    assert_eq!(c.pool().identity_of(1), None, "not kept");
    let c = node_pool(&[&busy, &good]);
    let before = good_n.load(SeqCst);
    assert!(c.logs_since(Address::ZERO, B256::ZERO, 10).await.unwrap().is_empty());
    assert_eq!(good_n.load(SeqCst) - before, 3, "its head check, eth_blockNumber and eth_getLogs, all on the good endpoint");
    assert_eq!(c.seen_head(), 0, "a failover endpoint's head in a log read raises nothing");
    let c = node_pool(&[&good]);
    c.logs_since(Address::ZERO, B256::ZERO, 10).await.unwrap();
    assert_eq!(c.seen_head(), 0x64, "control: the first endpoint's head does");
}

/// The node's `an_unspent_nonce_on_a_failover_answer_is_unread`, its pool part: a view answered by a failover endpoint moves the
/// failover counter (the node reads "not spent" as no verdict then); the first endpoint's answer does not.
#[tokio::test]
async fn an_unspent_nonce_on_a_failover_answer_is_unread() {
    let (unspent, _) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x10"}),
        _ => json!({"result": format!("0x{:064x}", 3)}),
    }).await;
    let first = node_pool(&[&unspent]);
    let mark = first.failover_answers();
    call(&first).await.unwrap();
    assert_eq!(first.failover_answers(), mark, "control: the first endpoint's answer");
    let over = node_pool(&[DOWN, &unspent]);
    let mark = over.failover_answers();
    call(&over).await.unwrap();
    assert_eq!(over.failover_answers(), mark + 1, "a failover endpoint answered");
}

/// An RPC at head 12,288 whose `eth_getLogs` caps the range at `cap` blocks and answers one log per accepted request, its
/// `blockNumber` the request's `fromBlock` and its `logIndex` the span's length.
fn capped_logs(r: &Value, cap: u64) -> Value {
    let n = |v: &Value| u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x3000"}),
        Some("eth_getLogs") => {
            let (from, to) = (n(&r["params"][0]["fromBlock"]), n(&r["params"][0]["toBlock"]));
            if to - from + 1 > cap {
                return json!({"error": {"code": -32005, "message": format!("query exceeds max block range {cap}")}});
            }
            json!({"result": [{"address": format!("{:#x}", Address::ZERO), "topics": [], "data": "0x",
                "blockNumber": format!("{from:#x}"), "blockHash": format!("{:#x}", B256::repeat_byte(9)),
                "transactionHash": format!("{:#x}", B256::repeat_byte(8)), "transactionIndex": "0x0",
                "logIndex": format!("{:#x}", to - from + 1), "removed": false}]})
        }
        _ => json!({"error": {"code": -32601, "message": "no such method"}}),
    }
}

#[tokio::test]
async fn each_log_span_has_its_own_timeout() {
    async fn slow(delay: u64) -> String {
        let b0 = block(0, genesis());
        serve(axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let b0 = b0.clone();
            async move {
                let mut a = match r["method"].as_str() {
                    Some("eth_chainId") => json!({"result": "0x128"}),
                    Some("eth_getBlockByNumber") => json!({"result": b0}),
                    _ => {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        capped_logs(&r, 2_000)
                    }
                };
                a["jsonrpc"] = json!("2.0");
                a["id"] = r["id"].clone();
                axum::Json(a)
            }
        }))).await
    }
    let c = |url: &str| node_pool_with(&[url], Some(genesis()), Shared::default(), 1_000, 120_000);
    let t = std::time::Instant::now();
    let logs = c(&slow(400).await).logs_since(Address::ZERO, B256::ZERO, 10_000).await.unwrap();
    assert!(logs.len() >= 3 && t.elapsed() > std::time::Duration::from_millis(1_200), "{} spans in {:?}", logs.len(), t.elapsed());
    assert!(c(&slow(2_500).await).logs_since(Address::ZERO, B256::ZERO, 10_000).await.is_err(), "control: one slow request");
}

#[tokio::test]
async fn a_log_window_is_chunked_for_an_rpc_that_caps_the_range() {
    let spans = |logs: Vec<alloy::rpc::types::Log>| logs.iter().map(|l| (l.block_number.unwrap(), l.log_index.unwrap())).collect::<Vec<_>>();
    let (open, _) = fake_rpc(|r| capped_logs(r, u64::MAX)).await;
    let (capped, _) = fake_rpc(|r| capped_logs(r, 1_000)).await;
    let (stingy, _) = fake_rpc(|r| capped_logs(r, 5)).await;
    let head = 0x3000u64;
    let read = |url: String| async move { node_pool(&[&url]).logs_since(Address::ZERO, B256::ZERO, 10_000).await };
    assert_eq!(spans(read(open).await.unwrap()), vec![(head - 10_000, 10_001)], "control: one request");
    let got = spans(read(capped).await.unwrap());
    let mut at = head - 10_000;
    for (from, len) in &got {
        assert_eq!(*from, at, "contiguous: {got:?}");
        assert!(*len <= 1_000, "within the cap: {got:?}");
        at += len;
    }
    assert_eq!(at, head + 1, "up to the head: {got:?}");
    assert!(got.len() <= 12, "the span grows back to the cap: {got:?}");
    let (wide, _) = fake_rpc(|r| capped_logs(r, 3_000)).await;
    let got = spans(read(wide).await.unwrap());
    assert_eq!(got.iter().map(|x| x.1).sum::<u64>(), 10_001, "{got:?}");
    assert!(got.len() <= 8 && got.iter().any(|x| x.1 > 1_000), "grows back: {got:?}");
    assert!(read(stingy.clone()).await.is_err(), "a cap below LOG_SPAN_MIN gives the endpoint up");
    assert!(node_pool(&[&stingy]).logs_since(Address::ZERO, B256::ZERO, 50).await.is_err(),
        "a 51-block window: a tenth is 5, floored at LOG_SPAN_MIN, still refused");
    let (capped2, _) = fake_rpc(|r| capped_logs(r, 1_000)).await;
    assert!(!node_pool(&[&stingy, &capped2]).logs_since(Address::ZERO, B256::ZERO, 10_000).await.unwrap().is_empty(),
        "and the read fails over to the next endpoint");
    let (tight, tight_n) = fake_rpc(|r| capped_logs(r, 400)).await;
    assert!(read(tight).await.is_err());
    assert!(tight_n.load(SeqCst) <= 5, "head, 10,001, 1,000, 501: given up");
    let n: std::sync::Arc<std::sync::atomic::AtomicUsize> = Default::default();
    let n2 = n.clone();
    let b0 = block(0, genesis());
    let down = serve(axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
        let (n2, b0) = (n2.clone(), b0.clone());
        async move {
            if r["method"] == "eth_getLogs" {
                n2.fetch_add(1, SeqCst);
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(json!({})));
            }
            let result = match r["method"].as_str() { Some("eth_chainId") => json!("0x128"), Some("eth_getBlockByNumber") => b0, _ => json!("0x3000") };
            (axum::http::StatusCode::OK, axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result})))
        }
    }))).await;
    let (capped3, _) = fake_rpc(|r| capped_logs(r, u64::MAX)).await;
    assert_eq!(node_pool(&[&down, &capped3]).logs_since(Address::ZERO, B256::ZERO, 10_000).await.unwrap().len(), 1);
    assert_eq!(n.load(SeqCst), 1, "one request, then the next endpoint");
}

#[tokio::test]
async fn a_hung_endpoint_and_the_block_gas_read_fail_over() {
    let stuck = hung().await;
    let (good, _) = fake_rpc(|r| match r["method"].as_str() {
        Some("eth_blockNumber") => json!({"result": "0x64"}),
        Some("eth_getBlockByNumber") => json!({"result": {"gasLimit": "0x1c9c380"}}),
        _ => json!({"result": format!("0x{:064x}", 5)}),
    }).await;
    assert_eq!(node_pool(&[&good]).block_gas().await.unwrap().limit, 30_000_000, "control");
    let quick = |urls: &[&str], read: u64, simulate: u64| node_pool_with(urls, Some(genesis()), Shared::default(), read, simulate);
    let two = quick(&[&stuck, &good], 500, 500);
    let got = tokio::time::timeout(std::time::Duration::from_secs(20), call(&two)).await;
    assert_eq!(got.expect("one timeout, then the next endpoint").unwrap().len(), 32);
    let b0 = block(0, genesis());
    let slow = serve(axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
        let b0 = b0.clone();
        async move {
            let result = match r["method"].as_str() {
                Some("eth_chainId") => json!("0x128"),
                Some("eth_getBlockByNumber") => b0,
                Some("eth_estimateGas") => { tokio::time::sleep(std::time::Duration::from_millis(1_500)).await; json!("0x5208") }
                _ => { tokio::time::sleep(std::time::Duration::from_millis(1_500)).await; json!("0x") }
            };
            axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": result}))
        }
    }))).await;
    let c = quick(&[&slow], 300, 10_000);
    assert_eq!(c.simulate_from(Address::ZERO, Address::ZERO, Bytes::new()).await.unwrap(), 21_000, "a simulation within its own limit");
    let t = std::time::Instant::now();
    let got = call(&quick(&[&slow], 300, 10_000)).await;
    assert!(matches!(&got, Err(SimError::Transport(_))) && t.elapsed() < std::time::Duration::from_millis(1_400),
        "control: a read of the same speed times out: {got:?} after {:?}", t.elapsed());
    let (busy, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "header not found"}})).await;
    assert_eq!(node_pool(&[&busy, &good]).block_gas().await.unwrap().limit, 30_000_000, "the gas cap's read fails over");
}

#[tokio::test]
async fn an_aborted_execution_is_transport() {
    let (aborted, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "execution aborted (timeout = 5s)"}})).await;
    let (exec, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "VM execution error."}})).await;
    let (rev, _) = fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted"}})).await;
    let (reason, _) = fake_rpc(|_| json!({"error": {"code": 3, "message": "execution reverted: timeout elapsed"}})).await;
    let (other, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "execution timeout aborted"}})).await;
    let (nethermind, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "eth_call request was canceled due to enabled timeout."}})).await;
    let c = |u: &str| node_pool(&[u]);
    assert!(matches!(call(&c(&aborted)).await, Err(SimError::Transport(_))));
    assert!(matches!(call(&c(&exec)).await, Err(SimError::Revert(_))), "control: an execution error");
    assert!(matches!(call(&c(&rev)).await, Err(SimError::Revert(_))), "control: a revert");
    assert!(matches!(call(&c(&reason)).await, Err(SimError::Revert(_))), "a revert whose reason names a timeout");
    assert!(matches!(call(&c(&other)).await, Err(SimError::Revert(_))), "not the node's phrase: the EVM's");
    assert!(matches!(call(&c(&nethermind)).await, Err(SimError::Transport(_))), "Nethermind's own timeout");
    let (cancelled, _) = fake_rpc(|_| json!({"error": {"code": -32000, "message": "err: Cancellation Requested (supplied gas 100000000)"}})).await;
    assert!(matches!(call(&c(&cancelled)).await, Err(SimError::Transport(_))), "the estimate's cancellation");
    assert!(matches!(c(&cancelled).simulate_from(Address::ZERO, Address::ZERO, Bytes::new()).await, Err(SimError::Transport(_))),
        "the same through classify_sim");
}

#[tokio::test]
async fn chain_uid_is_block_zero_and_a_wrong_pin_is_refused() {
    let g = B256::repeat_byte(0x42);
    let b = block(0x2760215, g);
    let url = serve(axum::Router::new().route("/", axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
        let b = b.clone();
        async move { axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": b})) }
    }))).await;
    let c = |u: &str, pin| node_pool_with(&[u], pin, Shared::default(), 30_000, 120_000);
    assert_eq!(c(&url, None).uid().await.unwrap(), g);
    assert_eq!(c(&url, Some(g)).uid().await.unwrap(), g);
    assert!(c(&url, Some(B256::repeat_byte(1))).uid().await.is_err());
    let pruned = serve(axum::Router::new().route("/", axum::routing::post(|axum::Json(r): axum::Json<Value>| async move {
        axum::Json(json!({"jsonrpc": "2.0", "id": r["id"], "result": null}))
    }))).await;
    assert_eq!(c(&pruned, Some(B256::repeat_byte(1))).uid().await.unwrap(), B256::repeat_byte(1));
    assert!(c(&pruned, None).uid().await.is_err());
    let d = c(DOWN, Some(g));
    assert!(d.uid().await.is_err() && d.uid().await.is_err(), "unreachable: not trusted, not kept");
}

/// `is_contract`: code that is not an EIP-7702 designator; `classify`: a revert's data, a "revert" or "execution" message (not a
/// node's own limit) is the EVM's answer, the rest the transport's.
#[test]
fn is_contract_and_classify_cases() {
    assert!(is_contract(&[0x60, 0x00]));
    assert!(!is_contract(&[]));
    let mut d = vec![0xef, 0x01, 0x00];
    d.extend([0u8; 20]);
    assert!(!is_contract(&d), "an EIP-7702 designator is an EOA");
    d.push(0);
    assert!(is_contract(&d), "control: 24 bytes are code");
    let resp = |code: i64, msg: &str, data: Option<&str>| {
        let raw = serde_json::value::to_raw_value(&data.map(|d| json!(d))).unwrap();
        alloy::transports::TransportError::ErrorResp(alloy::rpc::json_rpc::ErrorPayload {
            code, message: msg.to_string().into(), data: data.map(|_| raw) })
    };
    let err_string = "0x08c379a0".to_string() + &alloy::hex::encode(alloy::sol_types::SolValue::abi_encode(&"nope".to_string()));
    assert_eq!(classify(&resp(3, "execution reverted", Some(&err_string))), SimError::Revert("nope".into()));
    assert_eq!(classify(&resp(-32000, "execution aborted (timeout = 5s)", None)), SimError::Transport("execution aborted (timeout = 5s)".into()));
    assert_eq!(classify(&resp(-32000, "header not found", None)), SimError::Transport("header not found".into()));
}
