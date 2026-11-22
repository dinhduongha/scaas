// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! SDK plan T40: the EVM profiles of `smartcontracts/evm/chain-uids.json` (Ethereum, OP Mainnet, Arbitrum One, Linea; mainnet
//! and testnet each; Ethereum Classic dropped by the owner 2026-11-22, decisions CLI-SDK-32, its chain id 61 kept here as the
//! other chain of Ethereum's block 0), each with the values its row and its `src/chains/<key>/profile.json` pin, against
//! in-process fake nodes: the chain pair check drops an endpoint of the other chain (NET-ALL-25: Ethereum and ETC share block 0,
//! the chain id separates them; an endpoint naming the chain id over another block 0 is dropped too), and a `finalized` read is
//! pinned by the hash of the finalized block (EIP-1898, `requireCanonical`) where the profile's finality is the tag.
use alloy::primitives::{Address, B256, U256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::BlockChoice;
use scaas_rpc::{Endpoint, NodeList, Policy, Purpose, RpcError};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const KEYS: [&str; 8] = [
    "ethereum-mainnet",
    "ethereum-testnet",
    "op-mainnet",
    "op-testnet",
    "arbitrum-mainnet",
    "arbitrum-testnet",
    "linea-mainnet",
    "linea-testnet",
];
const EVM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/evm");
const WHO: Address = Address::repeat_byte(0x42);

/// A profile: the chain id and `chain_uid` of its chain-uids.json row, the finality of its profile.json (`"tag"` or
/// `{"depth": n}`; none is no profile).
struct Profile {
    key: &'static str,
    id: u64,
    uid: B256,
    finality: Option<BlockChoice>,
}

fn profiles() -> Vec<Profile> {
    let rows: Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{EVM}/chain-uids.json")).unwrap())
            .unwrap();
    KEYS.iter()
        .map(|&key| {
            let row = rows["chains"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["key"] == key)
                .unwrap_or_else(|| panic!("{key}: no chain-uids.json row"));
            let p: Value = serde_json::from_str(
                &std::fs::read_to_string(format!("{EVM}/src/chains/{key}/profile.json"))
                    .unwrap_or_else(|_| panic!("{key}: no profile.json")),
            )
            .unwrap();
            let finality = match &p["finality"] {
                Value::String(s) if s == "tag" => Some(BlockChoice::Finalized),
                Value::Object(o) => Some(BlockChoice::Depth(o["depth"].as_u64().unwrap())),
                f => panic!("{key}: finality {f}"),
            };
            Profile {
                key,
                id: row["chainId"].as_u64().unwrap(),
                uid: row["chainUid"].as_str().unwrap().parse().unwrap(),
                finality,
            }
        })
        .collect()
}

/// The canonical hash of block `n` on chain `id`.
fn hash(id: u64, n: u64) -> B256 {
    B256::from(U256::from(id) << 128 | U256::from(n))
}

fn block(id: u64, n: u64, h: B256) -> Value {
    json!({"timestamp": "0x6ac07487", "difficulty": "0x0", "extraData": "0x", "gasLimit": "0x1c9c380", "baseFeePerGas": "0x7",
        "gasUsed": "0x0", "logsBloom": format!("0x{}", "00".repeat(256)), "miner": format!("{:#x}", Address::ZERO),
        "mixHash": format!("{:#x}", B256::ZERO), "nonce": "0x0000000000000000", "receiptsRoot": format!("{:#x}", B256::ZERO),
        "sha3Uncles": format!("{:#x}", B256::ZERO), "size": "0x200", "stateRoot": format!("{:#x}", B256::ZERO),
        "totalDifficulty": "0x0", "transactions": [], "transactionsRoot": format!("{:#x}", B256::ZERO), "uncles": [],
        "number": format!("{n:#x}"), "hash": format!("{h:#x}"), "parentHash": format!("{:#x}", hash(id, n.saturating_sub(1)))})
}

const HEAD: u64 = 1_000;
const FINAL: u64 = 900;

/// A node of chain `id` whose block 0 is `uid`: head 1,000, `finalized` 900; every `eth_getBalance` block parameter is kept
/// in `seen` and answered 42 (the endpoint's own number when `own` is set, to tell which endpoint answered).
async fn node(id: u64, uid: B256, own: u64, seen: Arc<Mutex<Vec<Value>>>) -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(r): axum::Json<Value>| {
            let p = &r["params"];
            let n = |t: &Value| match t.as_str() {
                Some("latest") => HEAD,
                Some("finalized") | Some("safe") => FINAL,
                Some(x) => u64::from_str_radix(x.trim_start_matches("0x"), 16).unwrap(),
                None => HEAD,
            };
            let mut a = match r["method"].as_str() {
                Some("eth_chainId") => json!({"result": format!("{id:#x}")}),
                Some("eth_blockNumber") => json!({"result": format!("{HEAD:#x}")}),
                Some("eth_getBlockByNumber") => {
                    let k = n(&p[0]);
                    json!({"result": block(id, k, if k == 0 { uid } else { hash(id, k) })})
                }
                Some("eth_getBalance") => {
                    seen.lock().unwrap().push(p[1].clone());
                    json!({"result": format!("{own:#x}")})
                }
                _ => json!({"error": {"code": -32601, "message": "no such method"}}),
            };
            async move {
                a["jsonrpc"] = json!("2.0");
                a["id"] = r["id"].clone();
                axum::Json(a)
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

fn pool(urls: &[&str], p: &Profile) -> EvmPool {
    let e = urls.iter().map(|u| Endpoint::named(u).unwrap()).collect();
    EvmPool::connect(
        NodeList::new(e, Policy::Failover, 2_000, 2_000, 60_000).unwrap(),
        p.id,
        Some(p.uid),
    )
    .unwrap()
}

async fn balance(
    pool: &EvmPool,
    choice: BlockChoice,
) -> Result<(U256, usize, B256, u64), RpcError> {
    pool.read_at_block(choice, Purpose::Plain, |at| async move {
        pool.balance_at(&at, WHO).await
    })
    .await
    .map(|a| (a.value, a.members[0], a.hash, a.number))
}

/// The other chain of a pair: the same block 0 under another chain id (Ethereum's for ETC, ETC's for Ethereum, else the
/// chain id + 1), and the chain id over another block 0. Both are dropped; the profile's own endpoint answers.
#[tokio::test]
async fn each_profile_drops_an_endpoint_of_the_other_chain() {
    let ps = profiles();
    for p in &ps {
        let other_id = match p.id {
            1 => 61,
            61 => 1,
            id => id + 1,
        };
        let seen: Arc<Mutex<Vec<Value>>> = Default::default();
        let same_uid = node(other_id, p.uid, 1, seen.clone()).await;
        let same_id = node(p.id, B256::repeat_byte(0x5a), 2, seen.clone()).await;
        let own = node(p.id, p.uid, 3, seen.clone()).await;
        let choice = BlockChoice::Latest;
        let (v, member, _, _) = balance(&pool(&[&same_uid, &same_id, &own], p), choice)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", p.key));
        assert_eq!(
            (v, member),
            (U256::from(3), 2),
            "{}: the profile's own endpoint answers",
            p.key
        );
        // the other chain alone: no answer at all
        assert!(
            balance(&pool(&[&same_uid], p), choice).await.is_err(),
            "{}: an endpoint of chain {other_id} with the same block 0 is dropped",
            p.key
        );
        assert!(
            balance(&pool(&[&same_id], p), choice).await.is_err(),
            "{}: an endpoint of chain {} over another block 0 is dropped",
            p.key,
            p.id
        );
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "{}: a dropped endpoint is never asked the read",
            p.key
        );
    }
    // Ethereum and ETC (61): one block 0 (NET-ALL-25, chain-uids.json), told apart by the chain id only
    let rows = std::fs::read_to_string(format!("{EVM}/chain-uids.json")).unwrap();
    let uid = |id: u64| {
        let v: Value = serde_json::from_str(&rows).unwrap();
        v["chains"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["chainId"] == id)
            .unwrap()["chainUid"]
            .clone()
    };
    assert_eq!(uid(1), uid(61));
}

/// A profile whose finality is the tag (every profile here) reads at the `finalized` block, every request naming it by hash
/// with `requireCanonical`; the agreed read carries that block's number and hash.
#[tokio::test]
async fn a_finalized_read_is_pinned_by_hash() {
    for p in profiles() {
        let choice = p.finality.unwrap();
        assert_eq!(choice, BlockChoice::Finalized, "{}: the tag", p.key);
        let seen: Arc<Mutex<Vec<Value>>> = Default::default();
        let own = node(p.id, p.uid, 7, seen.clone()).await;
        let (v, _, h, n) = balance(&pool(&[&own], &p), choice).await.unwrap();
        assert_eq!(
            (v, n, h),
            (U256::from(7), FINAL, hash(p.id, FINAL)),
            "{}",
            p.key
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                json!({"blockHash": format!("{:#x}", hash(p.id, FINAL)), "requireCanonical": true})
            ],
            "{}: pinned by the finalized block's hash",
            p.key
        );
    }
}
