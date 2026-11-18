// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A fake EVM chain and scaas-node gateway on 127.0.0.1:0 (plan T10; local only), shared by the operation tests: chain 31337,
//! block 0 hash `0x60…`, block `n`'s hash `0x…7000+n`, one timestamp for every block. It answers the reads `scaas-rpc` makes,
//! keeps a lane nonce per contract, logs, receipts and code by address, records every raw transaction and every gateway body,
//! and **enforces a per-transaction gas cap**: a transaction whose gas limit is above `tx_cap` is refused at the send, as a
//! chain enforcing EIP-7825 does (its estimate still answers what the call needs).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const CHAIN_ID: u64 = 31337;

/// How the gateway answers `POST /v1/op`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Gw {
    Queue,
    Refuse,
}

pub struct Chain {
    pub head: u64,
    pub finalized: u64,
    pub timestamp: u64,
    pub gas: u64,
    pub block_gas_limit: u64,
    pub tx_cap: u64,
    /// the priority fee and base fee of `eth_feeHistory`
    pub prio: u64,
    pub base_fee: u64,
    /// lane nonce by contract (lower-case `0x` hex): `mtxNonce` answers it for any `from` and lane
    pub nonces: HashMap<String, u64>,
    pub code: HashMap<String, String>,
    pub logs: Vec<Value>,
    /// tx id -> status
    pub receipts: HashMap<String, bool>,
    pub sent: Vec<String>,
    pub gw: Gw,
    pub bodies: Vec<String>,
    /// called with each gateway body before the answer (a test's chain logic)
    pub on_body: Option<fn(&mut Chain, &Value)>,
}

impl Default for Chain {
    fn default() -> Self {
        Chain {
            head: 0x20,
            finalized: 0x20,
            timestamp: 1_800_000_000,
            gas: 100_000,
            block_gas_limit: 30_000_000,
            tx_cap: 1 << 24,
            prio: 1,
            base_fee: 7,
            nonces: HashMap::new(),
            code: HashMap::new(),
            logs: vec![],
            receipts: HashMap::new(),
            sent: vec![],
            gw: Gw::Queue,
            bodies: vec![],
            on_body: None,
        }
    }
}

pub type Fake = Arc<Mutex<Chain>>;

pub fn hash_of(n: u64) -> String {
    if n == 0 {
        format!("0x{}", "60".repeat(32))
    } else {
        format!("0x{:064x}", 0x7000 + n)
    }
}

fn number_of_hash(h: &str) -> Option<u64> {
    if h == hash_of(0) {
        return Some(0);
    }
    u64::from_str_radix(h.trim_start_matches("0x"), 16)
        .ok()
        .and_then(|v| v.checked_sub(0x7000))
}

fn block(c: &Chain, n: u64) -> Value {
    let z = format!("0x{}", "00".repeat(32));
    json!({"timestamp": format!("{:#x}", c.timestamp), "difficulty": "0x0", "extraData": "0x",
        "gasLimit": format!("{:#x}", c.block_gas_limit), "baseFeePerGas": format!("{:#x}", c.base_fee),
        "gasUsed": "0x0", "logsBloom": format!("0x{}", "00".repeat(256)), "miner": format!("0x{}", "00".repeat(20)),
        "mixHash": z, "nonce": "0x0000000000000000", "receiptsRoot": z, "sha3Uncles": z, "size": "0x200", "stateRoot": z,
        "totalDifficulty": "0x0", "transactions": [], "transactionsRoot": z, "uncles": [], "number": format!("{n:#x}"),
        "hash": hash_of(n), "parentHash": if n == 0 { z.clone() } else { hash_of(n - 1) }})
}

/// The `n`-th item of an RLP list's payload (`raw` after the type byte), as an unsigned integer.
fn rlp_uint_at(raw: &[u8], n: usize) -> u64 {
    let len = |b: &[u8], i: usize| -> (usize, usize) {
        let p = b[i];
        match p {
            0..=0x7f => (i, 1),
            0x80..=0xb7 => (i + 1, (p - 0x80) as usize),
            0xb8..=0xbf => {
                let l = (p - 0xb7) as usize;
                let n = b[i + 1..i + 1 + l]
                    .iter()
                    .fold(0usize, |a, x| a << 8 | *x as usize);
                (i + 1 + l, n)
            }
            0xc0..=0xf7 => (i + 1, (p - 0xc0) as usize),
            _ => {
                let l = (p - 0xf7) as usize;
                let n = b[i + 1..i + 1 + l]
                    .iter()
                    .fold(0usize, |a, x| a << 8 | *x as usize);
                (i + 1 + l, n)
            }
        }
    };
    let (mut i, _) = len(raw, 0);
    for _ in 0..n {
        let (s, l) = len(raw, i);
        i = s + l;
    }
    let (s, l) = len(raw, i);
    if raw[i] <= 0x7f {
        return raw[i] as u64;
    }
    raw[s..s + l].iter().fold(0u64, |a, x| a << 8 | *x as u64)
}

pub fn keccak_hex(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(scaas_ua::keccak256(b)))
}

fn rpc(c: &mut Chain, r: &Value) -> Value {
    let p = &r["params"];
    let ok = |v: Value| json!({"jsonrpc": "2.0", "id": r["id"], "result": v});
    let err =
        |m: &str| json!({"jsonrpc": "2.0", "id": r["id"], "error": {"code": -32000, "message": m}});
    let named = |c: &Chain, t: &Value| -> u64 {
        match t.as_str().unwrap_or("latest") {
            "latest" | "pending" => c.head,
            "finalized" | "safe" => c.finalized,
            "earliest" => 0,
            h => u64::from_str_radix(h.trim_start_matches("0x"), 16).unwrap(),
        }
    };
    match r["method"].as_str().unwrap_or_default() {
        "eth_chainId" => ok(json!(format!("{CHAIN_ID:#x}"))),
        "eth_blockNumber" => ok(json!(format!("{:#x}", c.head))),
        "eth_getBlockByNumber" => {
            let n = named(c, &p[0]);
            ok(if n <= c.head {
                block(c, n)
            } else {
                Value::Null
            })
        }
        "eth_getBlockByHash" => {
            ok(number_of_hash(p[0].as_str().unwrap_or_default())
                .map_or(Value::Null, |n| block(c, n)))
        }
        "eth_call" => {
            let to = p[0]["to"].as_str().unwrap_or_default().to_ascii_lowercase();
            let data = p[0]["input"]
                .as_str()
                .or(p[0]["data"].as_str())
                .unwrap_or_default();
            let sel = |s: &str| keccak_hex(s.as_bytes())[..10].to_string();
            if data.starts_with(&sel("mtxNonce(bytes32,uint256)"))
                || data.starts_with(&sel("mtxNonce(address,uint256)"))
            {
                ok(json!(format!(
                    "0x{:064x}",
                    c.nonces.get(&to).copied().unwrap_or(0)
                )))
            } else {
                ok(json!("0x"))
            }
        }
        "eth_estimateGas" => ok(json!(format!("{:#x}", c.gas))),
        "eth_getCode" => ok(json!(c
            .code
            .get(&p[0].as_str().unwrap_or_default().to_ascii_lowercase())
            .cloned()
            .unwrap_or("0x".into()))),
        "eth_getTransactionCount" => ok(json!("0x0")),
        "eth_feeHistory" => ok(
            json!({"oldestBlock": "0x1", "baseFeePerGas": [format!("{:#x}", c.base_fee), format!("{:#x}", c.base_fee)],
            "gasUsedRatio": [0.5], "reward": [[format!("{:#x}", c.prio)]]}),
        ),
        "eth_maxPriorityFeePerGas" => ok(json!(format!("{:#x}", c.prio))),
        "eth_gasPrice" => ok(json!(format!("{:#x}", c.base_fee + c.prio))),
        "eth_sendRawTransaction" => {
            let hex_raw = p[0].as_str().unwrap_or_default().to_string();
            let raw = alloy::hex::decode(hex_raw.trim_start_matches("0x")).unwrap();
            // type 2: [chainId, nonce, maxPrio, maxFee, gasLimit, …]
            if raw.first() == Some(&2) && rlp_uint_at(&raw[1..], 4) > c.tx_cap {
                return err("transaction gas limit too high (cap)");
            }
            c.sent.push(hex_raw);
            ok(json!(keccak_hex(&raw)))
        }
        "eth_getLogs" => {
            let f = &p[0];
            let (lo, hi) = (named(c, &f["fromBlock"]), named(c, &f["toBlock"]));
            let addr = f["address"]
                .as_str()
                .map(str::to_ascii_lowercase)
                .or(f["address"][0].as_str().map(str::to_ascii_lowercase));
            let t0 = f["topics"][0]
                .as_str()
                .or(f["topics"][0][0].as_str())
                .map(str::to_string);
            let logs: Vec<Value> = c
                .logs
                .iter()
                .filter(|l| {
                    let n = named(c, &l["blockNumber"]);
                    n >= lo
                        && n <= hi
                        && addr.as_ref().is_none_or(|a| l["address"] == json!(a))
                        && t0.as_ref().is_none_or(|t| l["topics"][0] == json!(t))
                })
                .cloned()
                .collect();
            ok(json!(logs))
        }
        "eth_getTransactionReceipt" => {
            let id = p[0].as_str().unwrap_or_default().to_string();
            ok(c.receipts.get(&id).map_or(Value::Null, |s| {
                let n = c.finalized;
                json!({"transactionHash": id, "transactionIndex": "0x0", "blockHash": hash_of(n), "blockNumber": format!("{n:#x}"),
                    "from": format!("0x{}", "11".repeat(20)), "to": format!("0x{}", "22".repeat(20)), "cumulativeGasUsed": "0x5208",
                    "gasUsed": "0x5208", "contractAddress": null, "logs": [], "logsBloom": format!("0x{}", "00".repeat(256)),
                    "type": "0x2", "status": if *s { "0x1" } else { "0x0" }, "effectiveGasPrice": "0x8"})
            }))
        }
        "eth_getTransactionByHash" => ok(Value::Null),
        _ => err("no such method"),
    }
}

/// The executed event of `contract` for `digest` in block `n`: `UAMetaTransactionExecuted` (`account` false) or
/// `MetaTransactionExecuted`.
pub fn executed_log(contract: &str, digest: &str, n: u64, account: bool) -> Value {
    let sig = if account {
        "MetaTransactionExecuted(address,address,uint256,uint256,bytes32,address,uint256)"
    } else {
        "UAMetaTransactionExecuted(bytes32,address,uint256,uint256,bytes32,address,uint256)"
    };
    let z = "00".repeat(32);
    json!({"address": contract.to_ascii_lowercase(), "topics": [keccak_hex(sig.as_bytes()), format!("0x{z}"), format!("0x{z}"), format!("0x{z}")],
        "data": format!("0x{z}{}{z}{z}", digest.trim_start_matches("0x")), "blockNumber": format!("{n:#x}"), "blockHash": hash_of(n),
        "transactionHash": format!("0x{}", "ab".repeat(32)), "transactionIndex": "0x0", "logIndex": "0x0", "removed": false})
}

/// Serves `c` on 127.0.0.1:0: JSON-RPC on `/`, the gateway on `/v1/op`. Returns the base URL.
pub async fn serve(c: Fake) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let c = c.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        let mut chunk = [0u8; 8192];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let len: usize = head
                        .to_ascii_lowercase()
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    while buf.len() < end + 4 + len {
                        let mut chunk = [0u8; 8192];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let body = buf[end + 4..end + 4 + len].to_vec();
                    buf.drain(..end + 4 + len);
                    let (status, out) = {
                        let mut c = c.lock().unwrap();
                        if path.ends_with("/v1/op") {
                            let text = String::from_utf8_lossy(&body).to_string();
                            c.bodies.push(text.clone());
                            if let (Some(f), Ok(v)) =
                                (c.on_body, serde_json::from_str::<Value>(&text))
                            {
                                f(&mut c, &v);
                            }
                            match c.gw {
                                Gw::Queue => (202, json!({"status": "queued", "intent_id": "i1"})),
                                Gw::Refuse => {
                                    (409, json!({"code": "NONCE_USED", "detail": "dead"}))
                                }
                            }
                        } else {
                            let req: Value = serde_json::from_slice(&body).unwrap();
                            (
                                200,
                                match &req {
                                    Value::Array(a) => {
                                        Value::Array(a.iter().map(|r| rpc(&mut c, r)).collect())
                                    }
                                    r => rpc(&mut c, r),
                                },
                            )
                        }
                    };
                    let body = serde_json::to_vec(&out).unwrap();
                    let resp = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", body.len());
                    if s.write_all(resp.as_bytes()).await.is_err()
                        || s.write_all(&body).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    url
}

pub fn fake() -> Fake {
    Arc::new(Mutex::new(Chain::default()))
}
