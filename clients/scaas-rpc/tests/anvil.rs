// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T6 / T7 against real chains: three `anvil` processes of equal genesis (`--chain-id 31337 --timestamp 1700000000`), each on
//! a port bound free first (F28), killed on drop. `ANVIL` names the binary, else `anvil` on `PATH`. Opt-in:
//!   cargo test --features evm --test anvil -- --ignored        (the gate step `rpc-anvil`, through scripts/capped)
use alloy::primitives::{address, Address, Bytes, B256, U256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::BlockChoice;
use scaas_rpc::{Class, Endpoint, NodeList, Policy, Purpose, RpcError};
use serde_json::{json, Value};
use std::process::{Child, Command, Stdio};

struct Anvil {
    child: Child,
    url: String,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn anvil_with(extra: &[&str]) -> Anvil {
    let port = free_port();
    let bin = std::env::var("ANVIL").unwrap_or_else(|_| "anvil".into());
    let child = Command::new(bin)
        .args(["--port", &port.to_string(), "--chain-id", "31337", "--timestamp", "1700000000", "--silent"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil (ANVIL or PATH)");
    let a = Anvil { child, url: format!("http://127.0.0.1:{port}") };
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return a;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("anvil did not listen on {port}");
}

fn anvil() -> Anvil {
    anvil_with(&[])
}

async fn rpc(url: &str, method: &str, params: Value) -> Value {
    let r: Value = reqwest::Client::new().post(url).json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send().await.unwrap().json().await.unwrap();
    r
}

async fn genesis(url: &str) -> B256 {
    rpc(url, "eth_getBlockByNumber", json!(["0x0", false])).await["result"]["hash"].as_str().unwrap().parse().unwrap()
}

fn list(urls: &[(&str, Class)], policy: Policy) -> NodeList {
    let e = urls.iter().map(|(u, c)| Endpoint::new(u, *c, None, None).unwrap()).collect();
    NodeList::new(e, policy, 10_000, 10_000, 30_000).unwrap()
}

async fn pool(anvils: &[&Anvil], policy: Policy) -> EvmPool {
    let urls: Vec<(&str, Class)> = anvils.iter().map(|a| (a.url.as_str(), Class::Named)).collect();
    EvmPool::connect(list(&urls, policy), 31337, Some(genesis(&anvils[0].url).await)).unwrap()
}

const WHO: Address = address!("00000000000000000000000000000000000c0de1");

async fn storage(p: &EvmPool, purpose: Purpose, choice: BlockChoice) -> Result<scaas_rpc::pool::Agreed<U256, B256>, RpcError> {
    p.read_at_block(choice, purpose, |at| async move { p.storage_at(&at, WHO, U256::ZERO).await }).await
}

async fn set_slot(a: &Anvil, v: u64) {
    let r = rpc(&a.url, "anvil_setStorageAt", json!([format!("{WHO:#x}"), "0x0", format!("0x{v:064x}")])).await;
    assert!(r.get("error").is_none(), "{r}");
}

/// The positive control of every test here: three anvils of the same arguments have the same block 0 (fails, never skips).
#[tokio::test]
#[ignore]
async fn the_three_genesis_hashes_are_equal() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    let g = genesis(&a.url).await;
    assert_eq!((genesis(&b.url).await, genesis(&c.url).await), (g, g));
}

#[tokio::test]
#[ignore]
async fn three_honest_agree() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    for x in [&a, &b, &c] {
        set_slot(x, 7).await;
    }
    let p = pool(&[&a, &b, &c], Policy::StrictMajority).await;
    let r = storage(&p, Purpose::Plain, BlockChoice::default()).await.unwrap();
    assert_eq!((r.value, r.number), (U256::from(7), 0));
    assert!(r.members.len() >= 2, "{:?}", r.members);
}

#[tokio::test]
#[ignore]
async fn one_altered_storage_slot_is_outvoted() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    set_slot(&a, 7).await;
    set_slot(&b, 99).await;
    set_slot(&c, 7).await;
    let p = pool(&[&a, &b, &c], Policy::StrictMajority).await;
    let r = storage(&p, Purpose::Plain, BlockChoice::default()).await.unwrap();
    assert_eq!((r.value, r.members), (U256::from(7), vec![0, 2]));
}

#[tokio::test]
#[ignore]
async fn two_altered_differently_is_no_majority() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    set_slot(&a, 7).await;
    set_slot(&b, 99).await;
    set_slot(&c, 98).await;
    let p = pool(&[&a, &b, &c], Policy::StrictMajority).await;
    let r = storage(&p, Purpose::Plain, BlockChoice::default()).await;
    assert!(matches!(r, Err(RpcError::EndpointNoMajority { n: 3, need: 2, .. })), "{r:?}");
}

#[tokio::test]
#[ignore]
async fn one_mined_ahead_does_not_move_the_block() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    let r = rpc(&b.url, "anvil_mine", json!(["0x1"])).await;
    assert!(r.get("error").is_none(), "{r}");
    let p = pool(&[&a, &b, &c], Policy::StrictMajority).await;
    let r = storage(&p, Purpose::Plain, BlockChoice::Depth(1)).await.unwrap();
    assert_eq!((r.number, r.highest_named), (0, 0), "at Depth(1) every endpoint names block 0");
    assert!(r.members.len() >= 2);
}

#[tokio::test]
#[ignore]
async fn a_revert_agreed_is_the_revert_with_its_bytes() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    // runtime code: mstore(0, 0xdeadbeef); revert(28, 4)
    let code = "0x63deadbeef6000526004601cfd";
    for x in [&a, &b, &c] {
        let r = rpc(&x.url, "anvil_setCode", json!([format!("{WHO:#x}"), code])).await;
        assert!(r.get("error").is_none(), "{r}");
    }
    let p = pool(&[&a, &b, &c], Policy::StrictMajority).await;
    let r = p.read_at_block(BlockChoice::default(), Purpose::Plain, |at| {
        let p = &p;
        async move { p.call_at(&at, WHO, Bytes::new()).await }
    }).await;
    match r {
        Err(RpcError::Revert { data, .. }) => assert_eq!(data, vec![0xde, 0xad, 0xbe, 0xef]),
        r => panic!("{r:?}"),
    }
}

#[tokio::test]
#[ignore]
async fn a_read_feeding_a_decryption_skips_a_discovered_endpoint() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    set_slot(&a, 99).await;
    set_slot(&b, 7).await;
    set_slot(&c, 7).await;
    let urls = [(a.url.as_str(), Class::Discovered), (b.url.as_str(), Class::Named), (c.url.as_str(), Class::Named)];
    let p = EvmPool::connect(list(&urls, Policy::Failover), 31337, Some(genesis(&b.url).await)).unwrap();
    let r = storage(&p, Purpose::FeedsDecryption, BlockChoice::default()).await.unwrap();
    assert_eq!((r.value, r.members), (U256::from(7), vec![1]), "the discovered endpoint is not asked");
    let r = storage(&p, Purpose::Plain, BlockChoice::default()).await.unwrap();
    assert_eq!((r.value, r.members), (U256::from(99), vec![0]), "control: a plain read is its");
}

#[tokio::test]
#[ignore]
async fn the_nonce_under_strict_majority_is_the_agreed_committed_nonce() {
    let (a, b, c) = (anvil(), anvil(), anvil());
    for (x, n) in [(&a, 5u64), (&b, 9), (&c, 5)] {
        let r = rpc(&x.url, "anvil_setNonce", json!([format!("{WHO:#x}"), format!("{n:#x}")])).await;
        assert!(r.get("error").is_none(), "{r}");
    }
    // the liar first: a failover read would take its 9
    let p = pool(&[&b, &a, &c], Policy::StrictMajority).await;
    assert_eq!(p.pending_nonce(WHO, Purpose::Plain).await.unwrap(), 5);
    let f = pool(&[&b, &a, &c], Policy::Failover).await;
    assert_eq!(f.pending_nonce(WHO, Purpose::Plain).await.unwrap(), 9, "control: failover takes the first endpoint's");
}

// ---------------------------------------------------------------- plan T7: broadcast and transaction state

/// anvil's dev key 0 (its well-known test key), signing in the test only (alloy's local signer is a dev-dependency).
const DEV0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async fn transfer(nonce: u64) -> (Vec<u8>, Address) {
    use alloy::eips::eip2718::Encodable2718;
    use alloy::network::{EthereumWallet, TransactionBuilder};
    let signer: alloy::signers::local::PrivateKeySigner = DEV0.parse().unwrap();
    let from = signer.address();
    let tx = alloy::rpc::types::TransactionRequest::default().with_from(from).with_to(WHO).with_value(U256::from(1))
        .with_nonce(nonce).with_chain_id(31337).with_gas_limit(21_000).with_max_fee_per_gas(10_000_000_000)
        .with_max_priority_fee_per_gas(1);
    (tx.build(&EthereumWallet::from(signer)).await.unwrap().encoded_2718(), from)
}

#[tokio::test]
#[ignore]
async fn one_signed_transfer_to_two_anvils_is_sent_then_final() {
    use scaas_rpc::evm::{BroadcastOutcome, Fanout, TxState};
    let (a, b) = (anvil(), anvil());
    let p = pool(&[&a, &b], Policy::Failover).await;
    let (raw, from) = transfer(0).await;
    let id = alloy::primitives::keccak256(&raw);
    match p.broadcast(&raw, Fanout::All).await.unwrap() {
        BroadcastOutcome::Sent { id: got, accepted, .. } => assert_eq!((got, accepted), (id, vec![0, 1])),
        o => panic!("{o:?}"),
    }
    // anvil mines the transaction just after it answers the send: wait (bounded) for its receipt on endpoint 0
    for _ in 0..100 {
        if p.first_receipt(id).await.unwrap().is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let s = p.tx_state(id, from, 0, BlockChoice::Depth(2)).await.unwrap();
    assert!(matches!(s, TxState::Included { number: 1, endpoint: 0, success: true, .. }), "{s:?}");
    let r = rpc(&a.url, "anvil_mine", json!(["0x2"])).await;
    assert!(r.get("error").is_none(), "{r}");
    let s = p.tx_state(id, from, 0, BlockChoice::Depth(2)).await.unwrap();
    assert!(matches!(s, TxState::Final { number: 1, success: true, .. }), "{s:?}");
}

/// F24: anvil's answer to the same transaction sent again (its pool holds it: no mining) is "already known", accepted.
#[tokio::test]
#[ignore]
async fn anvils_already_known_answer_is_accepted() {
    use scaas_rpc::evm::{BroadcastOutcome, Fanout};
    let a = anvil_with(&["--no-mining"]);
    let p = pool(&[&a], Policy::Failover).await;
    let (raw, _) = transfer(0).await;
    let first = rpc(&a.url, "eth_sendRawTransaction", json!([alloy::hex::encode_prefixed(&raw)])).await;
    assert!(first.get("result").is_some(), "{first}");
    let again = rpc(&a.url, "eth_sendRawTransaction", json!([alloy::hex::encode_prefixed(&raw)])).await;
    let msg = again["error"]["message"].as_str().unwrap_or_default().to_lowercase();
    assert!(scaas_rpc::evm::ALREADY_KNOWN.iter().any(|k| msg.contains(k)), "anvil's text: {again}");
    assert!(matches!(p.broadcast(&raw, Fanout::First).await.unwrap(), BroadcastOutcome::Sent { .. }));
}
