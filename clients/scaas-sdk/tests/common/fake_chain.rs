// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A fake EVM chain and scaas-node gateway on 127.0.0.1:0 (plan T10; local only), shared by the operation tests: chain 31337,
//! block 0 hash `0x60…`, block `n`'s hash `0x…7000+n`, one timestamp for every block. It answers the reads `scaas-rpc` makes,
//! keeps a lane nonce per contract, logs, receipts and code by address, records every raw transaction and every gateway body,
//! and **enforces EIP-8037 with EIP-7825** at the send: a transaction whose gas limit (regular + state) is above the block gas
//! limit is refused, and so is one whose regular gas is above `tx_cap` (2^24), the regular gas being the call's `regular_of`
//! figure (default: its estimate, all regular) since the fake executes nothing: an independent control of the SDK's own
//! bound (merged-tree review M8, 2026-11-20). Its estimate still answers what the call needs.
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
/// A verifier's answer `(status, body)` from its request.
pub type VerdictFn = fn(&Value) -> (u16, Value);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Gw {
    Queue,
    Refuse,
    /// a 503 on every write route (unreachable: the bytes may or may not have reached it); `GET /v1/gateway` still answers
    Down,
}

pub struct Chain {
    /// the chain id `eth_chainId` answers, [`CHAIN_ID`] by default (plan T40: a profile's own)
    pub chain_id: u64,
    pub head: u64,
    pub finalized: u64,
    pub timestamp: u64,
    pub gas: u64,
    pub block_gas_limit: u64,
    /// the priority fee and base fee of `eth_feeHistory`
    pub prio: u64,
    pub base_fee: u64,
    /// lane nonce by contract (lower-case `0x` hex): `mtxNonce` answers it for any `from` and lane
    pub nonces: HashMap<String, u64>,
    /// the first block whose state holds `nonces` (below it `mtxNonce` answers 0; review T26 B-11)
    pub nonces_from: u64,
    pub code: HashMap<String, String>,
    pub logs: Vec<Value>,
    /// tx id -> status
    pub receipts: HashMap<String, bool>,
    pub sent: Vec<String>,
    pub gw: Gw,
    pub bodies: Vec<String>,
    /// called with each gateway body before the answer (a test's chain logic)
    pub on_body: Option<fn(&mut Chain, &Value)>,
    /// `GET /v1/gateway`'s answer
    pub gw_info: Value,
    /// token metadata by address: `(name, symbol, decimals, chainUid)`
    pub tokens: HashMap<String, (String, String, u8, String)>,
    /// `balanceOfUA` by token and the native balance: the base, plus the number of the block read at (so a read at another
    /// block shows)
    pub balances: HashMap<String, u64>,
    pub native_balance: u64,
    /// the factory's token index (`contractsPage(1, …)`)
    pub index: Vec<String>,
    /// every JSON-RPC request body, as received
    pub requests: Vec<String>,
    /// `eth_call` and `eth_estimateGas` of a contract revert (an unsigned form the contract refuses)
    pub call_revert: bool,
    /// `eth_call` and `eth_estimateGas` fail as the node's own timeout (a transport failure, no revert; review T26 B-6)
    pub sim_down: bool,
    /// the blocks carry no `baseFeePerGas` (a chain without EIP-1559)
    pub no_base_fee: bool,
    /// ERC-5267 `eip712Domain()` by contract: `(name, salt)`, version "1", the fake's chain id, the contract
    pub domains: HashMap<String, (String, String)>,
    /// the gateway route of each body in `bodies`
    pub gw_paths: Vec<String>,
    /// block 0's hash (the chain's `chain_uid`), `hash_of(0)` by default
    pub genesis: String,
    /// `eth_call` and `eth_estimateGas` that send a value revert (a non-payable target)
    pub value_reverts: bool,
    /// `kindHome(uint16)` by registry (lower-case `0x` hex): the home it answers for every kind; a registry not listed answers
    /// itself (a generation 1 registering every kind)
    pub kind_home: HashMap<String, String>,
    /// storage words by (contract, slot as `0x` + 64 hex), lower case; an absent word is 0 (plan T15)
    pub storage: HashMap<(String, String), String>,
    /// `eth_call` answers by `(to, calldata prefix)`, read first (plan T13: the registry's views)
    pub answers: Vec<(String, String, String)>,
    /// `linea_estimateGas`'s answer (T26 B2-1); `None`: the chain's own `gas`, base fee and priority fee
    pub linea: Option<Value>,
    /// `eth_getLogs` answers every log, whatever the filter and the range asked (T26 B2-4)
    pub logs_unfiltered: bool,
    /// `eth_estimateGas` by the call's input (plan T13: a registration's size); `None`: `gas`
    pub gas_of: Option<fn(&str) -> u64>,
    /// the regular gas a transaction's input executes, held to `tx_cap` at the send; `None`: its estimate (`gas_of` / `gas`)
    pub regular_of: Option<fn(&str) -> u64>,
    /// EIP-7825's per-transaction cap of the regular gas (2^24)
    pub tx_cap: u64,
    /// `eth_estimateGas` reverts for the inputs this answers true (plan T13: a registry refusing a call)
    pub estimate_reverts: Option<fn(&str) -> bool>,
    /// a PQZ verifier's answer to `POST /v1/pqz-verdict` (status, body) (plan T16); `None`: 503, unreachable
    pub verdict: Option<(u16, Value)>,
    /// every verdict request body, as received
    pub verdict_bodies: Vec<String>,
    /// a verifier answering from the request (plan T16: a verdict over the statement it was sent); read before `verdict`
    pub verdict_fn: Option<VerdictFn>,
}

impl Default for Chain {
    fn default() -> Self {
        Chain {
            chain_id: CHAIN_ID,
            head: 0x20,
            finalized: 0x20,
            timestamp: 1_800_000_000,
            gas: 100_000,
            block_gas_limit: 30_000_000,
            prio: 1,
            base_fee: 7,
            nonces: HashMap::new(),
            nonces_from: 0,
            code: HashMap::new(),
            logs: vec![],
            receipts: HashMap::new(),
            sent: vec![],
            gw: Gw::Queue,
            bodies: vec![],
            on_body: None,
            gw_info: json!({"api": 1, "chains": [{"chain": CHAIN_ID, "chain_key": "evm:31337", "chain_uid": hash_of(0),
                "family": "evm", "routes": ["ops"]}]}),
            tokens: HashMap::new(),
            balances: HashMap::new(),
            native_balance: 0,
            index: vec![],
            requests: vec![],
            call_revert: false,
            sim_down: false,
            no_base_fee: false,
            domains: HashMap::new(),
            gw_paths: vec![],
            genesis: hash_of(0),
            value_reverts: false,
            kind_home: HashMap::new(),
            storage: HashMap::new(),
            answers: vec![],
            linea: None,
            logs_unfiltered: false,
            gas_of: None,
            regular_of: None,
            tx_cap: 1 << 24,
            estimate_reverts: None,
            verdict: None,
            verdict_bodies: vec![],
            verdict_fn: None,
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

fn genesis_or(c: &Chain, h: &str) -> Option<u64> {
    if h == c.genesis {
        Some(0)
    } else {
        number_of_hash(h)
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
    let mut b = json!({"timestamp": format!("{:#x}", c.timestamp), "difficulty": "0x0", "extraData": "0x",
        "gasLimit": format!("{:#x}", c.block_gas_limit), "baseFeePerGas": format!("{:#x}", c.base_fee),
        "gasUsed": "0x0", "logsBloom": format!("0x{}", "00".repeat(256)), "miner": format!("0x{}", "00".repeat(20)),
        "mixHash": z, "nonce": "0x0000000000000000", "receiptsRoot": z, "sha3Uncles": z, "size": "0x200", "stateRoot": z,
        "totalDifficulty": "0x0", "transactions": [], "transactionsRoot": z, "uncles": [], "number": format!("{n:#x}"),
        "hash": if n == 0 { c.genesis.clone() } else { hash_of(n) },
        "parentHash": if n == 0 { z.clone() } else if n == 1 { c.genesis.clone() } else { hash_of(n - 1) }});
    if c.no_base_fee {
        b.as_object_mut().unwrap().remove("baseFeePerGas");
    }
    b
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

/// The bytes of field `n` of the RLP list `raw` (a string item; one byte below 0x80 is itself).
fn rlp_bytes_at(raw: &[u8], n: usize) -> Vec<u8> {
    let head = |b: &[u8], i: usize| -> (usize, usize) {
        let p = b[i];
        let long = |l: usize| {
            b[i + 1..i + 1 + l]
                .iter()
                .fold(0usize, |a, x| a << 8 | *x as usize)
        };
        match p {
            0..=0x7f => (i, 1),
            0x80..=0xb7 => (i + 1, (p - 0x80) as usize),
            0xb8..=0xbf => (i + 1 + (p - 0xb7) as usize, long((p - 0xb7) as usize)),
            0xc0..=0xf7 => (i + 1, (p - 0xc0) as usize),
            _ => (i + 1 + (p - 0xf7) as usize, long((p - 0xf7) as usize)),
        }
    };
    let (mut i, _) = head(raw, 0);
    for _ in 0..n {
        let (s, l) = head(raw, i);
        i = s + l;
    }
    let (s, l) = head(raw, i);
    raw[s..s + l].to_vec()
}

pub fn keccak_hex(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(scaas_ua::keccak256(b)))
}

/// An ABI-encoded `string` return value.
pub fn abi_string(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = format!("{:064x}{:064x}{}", 32, b.len(), alloy::hex::encode(b));
    while (out.len() / 2) % 32 != 0 {
        out.push_str("00");
    }
    format!("0x{out}")
}

/// ERC-5267's answer: `(bytes1 0x0f, name, "1", chainId, contract, salt, uint256[] [])`.
pub fn eip712_domain(name: &str, contract: &str, salt: &str) -> String {
    let s = |t: &str| {
        let mut h = format!("{:064x}{}", t.len(), alloy::hex::encode(t));
        while (h.len() / 2) % 32 != 0 {
            h.push_str("00");
        }
        h
    };
    let (n, v) = (s(name), s("1"));
    let off_v = 7 * 32 + n.len() / 2;
    let off_e = off_v + v.len() / 2;
    format!(
        "0x0f{}{:064x}{:064x}{:064x}{:0>64}{}{:064x}{n}{v}{:064x}",
        "00".repeat(31),
        7 * 32,
        off_v,
        CHAIN_ID,
        contract.trim_start_matches("0x"),
        salt.trim_start_matches("0x"),
        off_e,
        0
    )
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
    let sends_value = p[0]["value"].as_str().is_some_and(|v| v != "0x0");
    match r["method"].as_str().unwrap_or_default() {
        "eth_call" | "eth_estimateGas" if c.sim_down => {
            err("eth_call request was canceled due to enabled timeout.")
        }
        "eth_call" | "eth_estimateGas" if c.value_reverts && sends_value => {
            err("execution reverted")
        }
        "linea_estimateGas" => ok(c.linea.clone().unwrap_or_else(|| {
            json!({"gasLimit": format!("{:#x}", c.gas), "baseFeePerGas": format!("{:#x}", c.base_fee),
                "priorityFeePerGas": format!("{:#x}", c.prio)})
        })),
        "eth_chainId" => ok(json!(format!("{:#x}", c.chain_id))),
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
            ok(genesis_or(c, p[0].as_str().unwrap_or_default())
                .map_or(Value::Null, |n| block(c, n)))
        }
        "eth_call" => {
            let to = p[0]["to"].as_str().unwrap_or_default().to_ascii_lowercase();
            let data = p[0]["input"]
                .as_str()
                .or(p[0]["data"].as_str())
                .unwrap_or_default();
            let sel = |s: &str| keccak_hex(s.as_bytes())[..10].to_string();
            let at = match &p[1] {
                Value::Object(o) => o
                    .get("blockHash")
                    .and_then(Value::as_str)
                    .and_then(|h| genesis_or(c, h))
                    .unwrap_or(c.head),
                t => named(c, t),
            };
            let meta = c.tokens.get(&to).cloned();
            if let Some((_, _, out)) = c
                .answers
                .iter()
                .find(|(t, d, _)| *t == to && data.starts_with(d.as_str()))
            {
                ok(json!(out))
            } else if data.starts_with(&sel("mtxNonce(bytes32,uint256)"))
                || data.starts_with(&sel("mtxNonce(address,uint256)"))
            {
                let n = if at >= c.nonces_from {
                    c.nonces.get(&to).copied().unwrap_or(0)
                } else {
                    0
                };
                ok(json!(format!("0x{n:064x}")))
            } else if let (Some((name, salt)), true) =
                (c.domains.get(&to), data == sel("eip712Domain()"))
            {
                ok(json!(eip712_domain(name, &to, salt)))
            } else if data.starts_with(&sel("kindHome(uint16)")) {
                let home = c.kind_home.get(&to).unwrap_or(&to);
                ok(json!(format!("0x{:0>64}", home.trim_start_matches("0x"))))
            } else if data.starts_with(&sel("balanceOfUA(bytes32)")) {
                ok(json!(format!(
                    "0x{:064x}",
                    c.balances.get(&to).copied().unwrap_or(0) + at
                )))
            } else if let (Some((name, symbol, decimals, uid)), true) = (meta, data.len() == 10) {
                if data == sel("name()") {
                    ok(json!(abi_string(&name)))
                } else if data == sel("symbol()") {
                    ok(json!(abi_string(&symbol)))
                } else if data == sel("decimals()") {
                    ok(json!(format!("0x{decimals:064x}")))
                } else if data == sel("chainUid()") {
                    ok(json!(uid))
                } else {
                    err("execution reverted")
                }
            } else if data.starts_with(&sel("contractsPage(uint16,uint256,uint256)")) {
                let from = usize::from_str_radix(&data[74..138], 16).unwrap();
                let page: Vec<&String> = c.index.iter().skip(from).take(100).collect();
                let mut out = format!("{:064x}{:064x}{:064x}", 0x40, c.index.len(), page.len());
                for a in page {
                    out.push_str(&format!("{:0>64}", a.trim_start_matches("0x")));
                    out.push_str(&format!(
                        "{:064x}{:064x}{:064x}{:064x}{:064x}{:064x}",
                        0, 1, 1, 1, 1, 1
                    ));
                }
                ok(json!(format!("0x{out}")))
            } else if c.call_revert {
                err("execution reverted")
            } else {
                ok(json!("0x"))
            }
        }
        "eth_estimateGas" if c.call_revert => err("execution reverted"),
        "eth_estimateGas"
            if c.estimate_reverts.is_some_and(|f| {
                f(p[0]["input"]
                    .as_str()
                    .or(p[0]["data"].as_str())
                    .unwrap_or_default())
            }) =>
        {
            err("execution reverted")
        }
        "eth_estimateGas" => {
            let input = p[0]["input"]
                .as_str()
                .or(p[0]["data"].as_str())
                .unwrap_or_default();
            ok(json!(format!(
                "{:#x}",
                c.gas_of.map_or(c.gas, |f| f(input))
            )))
        }
        "eth_getCode" => ok(json!(c
            .code
            .get(&p[0].as_str().unwrap_or_default().to_ascii_lowercase())
            .cloned()
            .unwrap_or("0x".into()))),
        "eth_getStorageAt" => {
            let who = p[0].as_str().unwrap_or_default().to_ascii_lowercase();
            let slot = format!(
                "0x{:0>64}",
                p[1].as_str()
                    .unwrap_or_default()
                    .trim_start_matches("0x")
                    .to_ascii_lowercase()
            );
            ok(json!(c
                .storage
                .get(&(who, slot))
                .cloned()
                .unwrap_or_else(|| format!("0x{}", "00".repeat(32)))))
        }
        "eth_getTransactionCount" => ok(json!("0x0")),
        "eth_getBalance" => {
            let at = match &p[1] {
                Value::Object(o) => o
                    .get("blockHash")
                    .and_then(Value::as_str)
                    .and_then(|h| genesis_or(c, h))
                    .unwrap_or(c.head),
                t => named(c, t),
            };
            ok(json!(format!("{:#x}", c.native_balance + at)))
        }
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
            if raw.first() == Some(&2) && rlp_uint_at(&raw[1..], 4) > c.block_gas_limit {
                return err("transaction gas limit exceeds the block gas limit");
            }
            // type 2's data is field 7: its regular gas held to the cap (EIP-7825 under EIP-8037)
            if raw.first() == Some(&2) {
                let input = format!("0x{}", alloy::hex::encode(rlp_bytes_at(&raw[1..], 7)));
                let regular = c
                    .regular_of
                    .map_or_else(|| c.gas_of.map_or(c.gas, |f| f(&input)), |f| f(&input));
                if regular > c.tx_cap {
                    return err("transaction regular gas above the per-transaction cap");
                }
            }
            c.sent.push(hex_raw);
            ok(json!(keccak_hex(&raw)))
        }
        "eth_getLogs" => {
            let f = &p[0];
            let (lo, hi) = (named(c, &f["fromBlock"]), named(c, &f["toBlock"]));
            let addr: Option<Vec<Value>> = match &f["address"] {
                Value::String(a) => Some(vec![json!(a.to_ascii_lowercase())]),
                Value::Array(a) => Some(
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(|a| json!(a.to_ascii_lowercase()))
                        .collect(),
                ),
                _ => None,
            };
            let ts: Vec<Option<String>> = (0..4)
                .map(|i| {
                    f["topics"][i]
                        .as_str()
                        .or(f["topics"][i][0].as_str())
                        .map(str::to_string)
                })
                .collect();
            let logs: Vec<Value> = c
                .logs
                .iter()
                .filter(|l| {
                    let n = named(c, &l["blockNumber"]);
                    c.logs_unfiltered || n >= lo
                        && n <= hi
                        && addr.as_ref().is_none_or(|a| a.contains(&l["address"]))
                        && ts
                            .iter()
                            .enumerate()
                            .all(|(i, t)| t.as_ref().is_none_or(|t| l["topics"][i] == json!(t)))
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
                        if path.ends_with("/v1/gateway") {
                            (200, c.gw_info.clone())
                        } else if path.ends_with("/v1/pqz-verdict") {
                            c.verdict_bodies
                                .push(String::from_utf8_lossy(&body).to_string());
                            match (c.verdict_fn, serde_json::from_slice::<Value>(&body)) {
                                (Some(f), Ok(v)) => f(&v),
                                _ => c.verdict.clone().unwrap_or((503, json!({"error": "BUSY"}))),
                            }
                        } else if path.contains("/v1/dex/") {
                            // the DEX venue's routes (plan T17): every body and path recorded; a place answers its state, a
                            // read its route, a refusing gateway the venue's `DEX_NOT_LISTED`
                            c.bodies.push(String::from_utf8_lossy(&body).to_string());
                            c.gw_paths.push(path.clone());
                            match c.gw {
                                Gw::Refuse => {
                                    (422, json!({"code": "DEX_NOT_LISTED", "detail": "dex"}))
                                }
                                Gw::Down => (503, json!({"error": "BUSY"})),
                                Gw::Queue if body.is_empty() => (200, json!({"route": path})),
                                Gw::Queue => (201, json!({"status": "resting", "fills": []})),
                            }
                        } else if path.ends_with("/v1/op") || path.ends_with("/v1/ua-metatx") {
                            let text = String::from_utf8_lossy(&body).to_string();
                            c.bodies.push(text.clone());
                            c.gw_paths.push(path.clone());
                            if let (Some(f), Ok(v)) =
                                (c.on_body, serde_json::from_str::<Value>(&text))
                            {
                                f(&mut c, &v);
                            }
                            match c.gw {
                                Gw::Queue => (202, json!({"status": "queued", "intent_id": "i1"})),
                                Gw::Down => (503, json!({"error": "BUSY"})),
                                Gw::Refuse => {
                                    (409, json!({"code": "NONCE_USED", "detail": "dead"}))
                                }
                            }
                        } else {
                            c.requests.push(String::from_utf8_lossy(&body).to_string());
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
