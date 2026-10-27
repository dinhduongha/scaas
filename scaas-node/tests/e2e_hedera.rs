//! cargo test --test e2e_hedera -- --ignored --nocapture
//!
//! Hedera (R63) end to end on a LOCAL devnet stand-in: anvil `--chain-id 298` (Hedera localnet id) with the
//! HIP-632 precompile 0x16a replaced by `MockHederaAccountService` (smartcontracts/evm/test/hedera/HederaMocks.sol), the
//! tokens `IS_HEDERA` `NoUnderlyingToken` clones from `OpenFactory` (`DeployHedera.s.sol`), payments `MetaTransfer`s.
//! hedera-local-node / solo (≥ 8 GB, many containers) does not run on the shared machine — gap recorded in
//! docs/history/specs/2026-10-03-net-hedera.md §9. Proven here through the real `HederaAdapter`:
//! 1. two relayer lanes from a 24-word mnemonic (`m/44'/3030'/0'/0/i`), each with its own key;
//! 2. a payment by a Hedera NATIVE account (`0.0.N`, long-zero `from`, 64-byte account signature checked by the
//!    precompile) through `lane_step`: signed → broadcast → mined;
//! 3. finality via `index_step`: `PaymentSettled` + `MetaTransactionExecuted` with the signed digest;
//! 4. ANTI-LOCK: the subject signs X on token 1 and Y on token 2; X is withheld; Y lands; then X lands;
//! 5. replaying X is refused by simulation (contract nonce) → dead.
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{SolCall, SolValue};
use axum::extract::{Path, State};
use axum::routing::post;
use axum::{Json, Router};
use scaas_node::abi::{IToken, MetaTransfer};
use scaas_node::adapter::{index_step, lane_step, recover_lane, Family};
use scaas_node::adapters;
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use scaas_node::keys::{lane_secret, Seed};
use scaas_node::metatx::{Domain, Mtx};
use scaas_node::odoo::Odoo;
use scaas_node::signer::LocalSigner;
use serde_json::{json, Value};

const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Address of `DEPLOYER`: forge needs `--sender` when a script links libraries and deploys by CREATE2.
const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const CHAIN_ID: u64 = 298;
const PORT: u16 = 31960;
const NATIVE: u64 = 1_234_567; // 0.0.1234567
const ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                   abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn sc() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm")
}

async fn start_anvil() -> (Anvil, String) {
    let child = Command::new("anvil")
        .args(["--chain-id", &CHAIN_ID.to_string(), "--hardfork", "amsterdam", "--gas-limit", "100000000", "--code-size-limit", "65536", "--port", &PORT.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil in PATH");
    let rpc = format!("http://127.0.0.1:{PORT}");
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_chain_id().await.is_ok() {
            break;
        }
    }
    (Anvil(child), rpc)
}

fn deploy(rpc: &str) -> Value {
    let status = Command::new("forge")
        .current_dir(sc())
        .args(["script", "script/hedera/DeployHedera.s.sol", "--rpc-url", rpc, "--broadcast", "--slow", "--silent", "--disable-code-size-limit", "--sender", DEPLOYER_ADDRESS])
        .env("PRIVATE_KEY", DEPLOYER)
        .env("DEMO_SUPPLY", "1000000000000")
        .env("FOUNDRY_PROFILE", "private7622")
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let raw = std::fs::read_to_string(format!("{}/deployments/hedera-{CHAIN_ID}.json", sc())).unwrap();
    serde_json::from_str(&raw).unwrap()
}

/// Runtime code of the 0x16a mock, from the forge build the deploy just ran.
fn mock_has_code() -> String {
    let raw = std::fs::read_to_string(format!("{}/out/HederaMocks.sol/MockHederaAccountService.json", sc()))
        .expect("forge build output for test/hedera/HederaMocks.sol");
    let v: Value = serde_json::from_str(&raw).unwrap();
    v["deployedBytecode"]["object"].as_str().unwrap().to_string()
}

fn allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("queued", "nonce_leased")
            | ("nonce_leased", "queued" | "signed" | "dead" | "consumed")
            | ("signed", "broadcast" | "mined" | "reverted" | "queued" | "dead" | "consumed")
            | ("broadcast", "mined" | "reverted" | "broadcast" | "queued" | "dead" | "consumed")
            | ("mined", "reverted")
    )
}

#[derive(Default)]
struct FakeOdoo {
    states: std::collections::HashMap<i64, String>,
    refused: Vec<Value>,
    jobs: Vec<Value>,
    reports: Vec<Value>,
    ingested: Vec<Value>,
    indexed_block: u64,
    /// Token Odoo đăng ký (review H2): địa chỉ thật của hai clone, như `node_config` của Odoo trả.
    tokens: Vec<String>,
}

async fn fake(
    State(s): State<Arc<Mutex<FakeOdoo>>>,
    Path((model, method)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "evm_chain_number": CHAIN_ID, "finality_mode": "depth", "finality_depth": 0, "finality_quorum": 1,
            "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|t| json!({"address": t, "decimals": 6})).collect::<Vec<_>>(), "journal_max_nonce": null, "inflight": []}),
        ("blockchain.relay.job", "relay_poll") => json!(std::mem::take(&mut o.jobs)),
        ("blockchain.relay.job", "relay_claim") => {
            for id in body["job_ids"].as_array().unwrap() {
                o.states.insert(id.as_i64().unwrap(), "nonce_leased".into());
            }
            body["job_ids"].clone()
        }
        ("blockchain.relay.job", "relay_report") => {
            let id = body["job_id"].as_i64().unwrap();
            let to = body["chain_state"].as_str().unwrap().to_string();
            let from = o.states.get(&id).cloned().unwrap_or_else(|| "queued".into());
            if !allowed(&from, &to) {
                o.refused.push(body.clone());
                return Json(json!({"error": format!("Transition {from} -> {to} is not allowed.")}));
            }
            o.states.insert(id, to);
            o.reports.push(body.clone());
            json!({"ok": true})
        }
        ("blockchain.chain.event", "chain_event_ingest") => {
            o.indexed_block = body["to_block"].as_u64().unwrap();
            o.ingested.extend(body["events"].as_array().unwrap().iter().cloned());
            json!({"indexed_block": o.indexed_block, "created": 0})
        }
        _ => json!({"error": "unexpected"}),
    };
    Json(out)
}

async fn start_fake(state: Arc<Mutex<FakeOdoo>>) -> SocketAddr {
    let app = Router::new().route("/json/2/{model}/{method}", post(fake)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn odoo_at(addr: SocketAddr) -> Odoo {
    let cfg = OdooCfg {
        url: format!("http://{addr}"),
        database: "t".into(),
        relay_api_key_env: String::new(),
        indexer_api_key_env: String::new(),
    };
    Odoo::with_key(&cfg, "k".into()).unwrap()
}

fn cfg(rpc: &str) -> ChainCfg {
    ChainCfg {
        family: "hedera".into(),
        network: None,
        evm_chain_number: CHAIN_ID,
        rpc_urls: vec![rpc.to_string()],
        signer_key_env: String::new(),
        private_key: None,
        lanes: vec![0, 1],
        params: Default::default(),
        finality: FinalityCfg { mode: "instant".into(), depth: 0, quorum: 1 },
        dex: None,
        poll_ms: 200,
        stuck_after_secs: 60,
        max_gas_per_tx: 3_000_000,
        max_fee_cap_gwei: 500,
        ..Default::default()
    }
}

async fn balance(rpc: &str, token: Address, who: Address) -> U256 {
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let data = IToken::balanceOfCall { who }.abi_encode();
    let out = p.call(TransactionRequest::default().to(token).input(data.into())).await.unwrap();
    U256::abi_decode(&out).unwrap()
}

fn domain(uid: B256, token: Address) -> Domain {
    Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id: CHAIN_ID, verifying_contract: token, salt: uid }
}

/// A payment `MetaTransfer` of the native account, signed with its "ED key" (mock: 64-byte compact signature).
fn native_pay(key: &PrivateKeySigner, uid: B256, token: Address, id: i64, tag: &[u8]) -> (Value, Mtx) {
    let entry_ref = keccak256(tag);
    let m = Mtx::Transfer(MetaTransfer {
        from: Address::left_padding_from(&NATIVE.to_be_bytes()),
        to: Address::repeat_byte(0x5e),
        value: U256::from(1_000u64),
        entryRef: entry_ref,
        batch: U256::from_be_bytes(keccak256([b"scaas.pay.lane".as_slice(), entry_ref.as_slice()].concat()).0),
        nonce: U256::ZERO,
        validUntil: U256::from(now() + 300),
        mode: 0,
        relayer: Address::ZERO,
        fee: U256::ZERO,
        feeRecipient: Address::ZERO,
    });
    let sig = key.sign_hash_sync(&m.digest(&domain(uid, token))).unwrap().as_erc2098();
    assert_eq!(sig.len(), 64);
    let (kind, wire) = m.to_wire();
    let job = json!({"id": id, "token": format!("{token:#x}"), "digest": "0x", "struct": kind,
                     "signature": format!("0x{}", alloy::hex::encode(sig)), "metatx": wire});
    (job, m)
}

fn states_of(state: &Arc<Mutex<FakeOdoo>>, id: i64) -> Vec<String> {
    state.lock().unwrap().reports.iter()
        .filter(|r| r["job_id"] == id)
        .map(|r| r["chain_state"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
#[ignore]
async fn hedera_native_account_pays_through_two_lanes_and_never_locks_itself() {
    let (_anvil, rpc) = start_anvil().await;
    let dep = deploy(&rpc);
    let t1: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let t2: Address = dep["demo_token_2"].as_str().unwrap().parse().unwrap();
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let native = Address::left_padding_from(&NATIVE.to_be_bytes());
    let native_key = PrivateKeySigner::from_bytes(&keccak256(b"hedera native account key")).unwrap();

    // Hedera state stand-in: the account 0.0.1234567 exists with that key (HIP-632), and holds both tokens.
    let deployer: PrivateKeySigner = DEPLOYER.parse().unwrap();
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(deployer)).connect_http(rpc.parse().unwrap());
    let _: Value = p.raw_request("anvil_setCode".into(), ("0x000000000000000000000000000000000000016a", mock_has_code())).await.unwrap();
    alloy::sol! { function setEdKey(address account, address key); function transfer(address to, uint256 value); }
    let has: Address = "0x000000000000000000000000000000000000016a".parse().unwrap();
    let calls = [
        (has, Bytes::from(setEdKeyCall { account: native, key: native_key.address() }.abi_encode())),
        (t1, Bytes::from(transferCall { to: native, value: U256::from(1_000_000u64) }.abi_encode())),
        (t2, Bytes::from(transferCall { to: native, value: U256::from(1_000_000u64) }.abi_encode())),
    ];
    for (to, input) in calls {
        p.send_transaction(TransactionRequest::default().to(to).input(input.into())).await.unwrap().get_receipt().await.unwrap();
    }

    // Two relayer lanes from the 24-word mnemonic on the Hedera path (coin 3030), funded like auto-created accounts.
    let seed = Seed::from_phrase(ART.as_bytes(), None).unwrap();
    let signers: Vec<LocalSigner> = (0..2)
        .map(|i| {
            let (c, k) = lane_secret(&seed, "hedera", i).unwrap();
            LocalSigner::new(c, &k).unwrap()
        })
        .collect();
    assert_eq!(signers[0].address_hex(), "0x04d0f262432d16cea929f228f5e53df042a7d7c5");
    let cfg = cfg(&rpc);
    // Built the way the binary builds it (review H1/H2): `adapters::build`, token list only from Odoo.
    let built = adapters::build(&cfg, &signers).unwrap();
    let adapter = built.as_ref();
    assert_eq!((adapter.family(), adapter.chain_key()), (Family::Hedera, "hedera:298"));

    let tokens = vec![format!("{t1:#x}"), format!("{t2:#x}")];
    let state = Arc::new(Mutex::new(FakeOdoo { tokens, ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    // as `lane_runner` starts a lane: the chain_uid check (NODE-GW-07), then recovery, which loads the registered tokens
    adapter.start_check().await.unwrap();
    recover_lane(adapter, &odoo, 0, "e2e#0").await.unwrap();

    // An unfunded lane does not take the job: back to the queue (Hedera accounts must exist and hold HBAR).
    let (job, m0) = native_pay(&native_key, uid, t1, 20, b"hedera-0");
    state.lock().unwrap().jobs.push(job);
    assert!(lane_step(adapter, &odoo, 0, "e2e#0").await.unwrap());
    assert_eq!(states_of(&state, 20), ["queued"]);
    let back = state.lock().unwrap().reports.last().cloned().unwrap();
    assert!(back["error"].as_str().unwrap().contains("not a funded Hedera account"), "{back}");

    for s in &signers {
        let _: Value = p.raw_request("anvil_setBalance".into(), (s.address_hex(), "0xde0b6b3a7640000")).await.unwrap();
    }
    let (job, _) = native_pay(&native_key, uid, t1, 21, b"hedera-0");
    state.lock().unwrap().jobs.push(job);
    assert!(lane_step(adapter, &odoo, 0, "e2e#0").await.unwrap());
    assert_eq!(states_of(&state, 21), ["signed", "broadcast", "mined"]);
    assert_eq!(balance(&rpc, t1, Address::repeat_byte(0x5e)).await, U256::from(1_000u64));

    // ANTI-LOCK: X (token 1) and Y (token 2) signed by the same subject; X withheld; Y lands; then X.
    let (x, mx) = native_pay(&native_key, uid, t1, 31, b"hedera-x");
    let (y, my) = native_pay(&native_key, uid, t2, 32, b"hedera-y");
    state.lock().unwrap().jobs.push(y);
    assert!(lane_step(adapter, &odoo, 1, "e2e#1").await.unwrap());
    assert_eq!(states_of(&state, 32), ["signed", "broadcast", "mined"]);
    assert_eq!(balance(&rpc, t2, Address::repeat_byte(0x5e)).await, U256::from(1_000u64));
    assert_eq!(balance(&rpc, t1, Address::repeat_byte(0x5e)).await, U256::from(1_000u64), "X still withheld");
    state.lock().unwrap().jobs.push(x.clone());
    assert!(lane_step(adapter, &odoo, 0, "e2e#0").await.unwrap());
    assert_eq!(states_of(&state, 31), ["signed", "broadcast", "mined"]);
    assert_eq!(balance(&rpc, t1, Address::repeat_byte(0x5e)).await, U256::from(2_000u64));

    // Each lane signed with its own key.
    let signed_by: std::collections::HashSet<String> = state.lock().unwrap().reports.iter()
        .filter(|r| r["chain_state"] == "signed").map(|r| r["signer_address"].as_str().unwrap().to_string()).collect();
    assert_eq!(signed_by, signers.iter().map(|s| s.address_hex()).collect());

    // Replay of X: the token's lane nonce is spent, simulation refuses → `consumed` (R80, mtxNonce), nothing sent.
    let mut replay = x;
    replay["id"] = json!(33);
    state.lock().unwrap().jobs.push(replay);
    assert!(lane_step(adapter, &odoo, 1, "e2e#1").await.unwrap());
    let last = state.lock().unwrap().reports.last().cloned().unwrap();
    assert_eq!((last["job_id"].as_i64(), last["chain_state"].as_str()), (Some(33), Some("consumed")), "{last}");
    assert!(state.lock().unwrap().refused.is_empty());

    // Finality: three payments, each with the digest the subject signed.
    while index_step(adapter, &odoo).await.unwrap() {}
    let ingested = state.lock().unwrap().ingested.clone();
    let settled: Vec<&Value> = ingested.iter().filter(|e| e["event"] == "PaymentSettled").collect();
    assert_eq!(settled.len(), 3);
    assert!(settled.iter().all(|e| e["from"] == format!("{native:#x}")));
    let digests: Vec<String> = ingested.iter().filter(|e| e["event"] == "MetaTransactionExecuted")
        .map(|e| e["digest"].as_str().unwrap().to_string()).collect();
    for (t, m) in [(t1, &mx), (t2, &my)] {
        assert!(digests.contains(&format!("{:#x}", m.digest(&domain(uid, t)))));
    }
    let _ = m0;
}
