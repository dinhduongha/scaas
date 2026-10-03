//! cargo test --test e2e -- --ignored --nocapture
//!
//! Cần `anvil` và `forge` trong PATH. Chứng minh trên EVM thật với contract thật:
//! 1. job outbox (giả Odoo) → simulate → ký → `signed` trước khi gửi → broadcast → receipt →
//!    indexer gửi `PaymentSettled` + `MetaTransactionExecuted` vùng final;
//! 2. DEX: hai lệnh qua gateway HTTP → khớp → `settle` on-chain → số dư hoán đổi;
//!    người ký không có một wei gas nào.
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, RwLock};
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
use bamboo_node::abi::{IMetaToken, IOpenFactory, MetaTransaction};
use bamboo_node::chain::Chain;
use bamboo_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use bamboo_node::dex::{Book, OP_TRADE};
use bamboo_node::gateway::{router, AppState, GwChain};
use bamboo_node::metatx::{digest, Domain, WireMetaTx, MODE_RESTRICT_RELAYER};
use bamboo_node::odoo::Odoo;
use bamboo_node::submit::{Submitter, Work};
use serde_json::{json, Value};
use tokio::sync::mpsc;

const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const RELAYER: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

struct Anvil(Child);
impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn key(hex: &str) -> PrivateKeySigner {
    hex.parse().expect("private key")
}

fn small_key(n: u64) -> PrivateKeySigner {
    PrivateKeySigner::from_bytes(&B256::from(U256::from(n))).expect("key")
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

async fn start_anvil(chain_id: u64, port: u16) -> (Anvil, String) {
    let child = Command::new("anvil")
        .args(["--chain-id", &chain_id.to_string(), "--hardfork", "prague", "--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("anvil in PATH");
    let rpc = format!("http://127.0.0.1:{port}");
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
        if p.get_chain_id().await.is_ok() {
            break;
        }
    }
    (Anvil(child), rpc)
}

/// Deploy factory + implementation + DEX + token demo (một nửa cung cho `holder`).
fn deploy(rpc: &str, chain_id: u64, holder: Address) -> Value {
    let sc = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts");
    let status = Command::new("forge")
        .current_dir(sc)
        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--silent"])
        .env("PRIVATE_KEY", DEPLOYER)
        .env("DEMO_SUPPLY", "1000000000000")
        .env("DEMO_HOLDER", format!("{holder:#x}"))
        .env("FOUNDRY_PROFILE", "private9000")
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let raw = std::fs::read_to_string(format!("{sc}/deployments/{chain_id}.json")).expect("deployments json");
    serde_json::from_str(&raw).unwrap()
}

#[derive(Default)]
struct FakeOdoo {
    jobs: Vec<Value>,
    reports: Vec<Value>,
    ingested: Vec<Value>,
    indexed_block: u64,
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
            "evm_chain_number": body["evm_chain_number"], "finality_mode": "depth", "finality_depth": 0,
            "finality_quorum": 1, "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|t| json!({"address": t, "decimals": 6})).collect::<Vec<_>>(),
            "journal_max_nonce": null, "inflight": []}),
        ("blockchain.relay.job", "relay_poll") => json!(std::mem::take(&mut o.jobs)),
        ("blockchain.relay.job", "relay_claim") => body["job_ids"].clone(),
        ("blockchain.relay.job", "relay_report") => {
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

fn chain_cfg(chain_id: u64, rpc: &str, dex: Option<Address>) -> ChainCfg {
    ChainCfg {
        evm_chain_number: chain_id,
        rpc_urls: vec![rpc.to_string()],
        signer_key_env: String::new(),
        finality: FinalityCfg { mode: "depth".into(), depth: 0, quorum: 1 },
        dex,
        poll_ms: 200,
        stuck_after_secs: 60,
        max_gas_per_tx: 3_000_000,
        max_fee_cap_gwei: 500,
    }
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

async fn balance(rpc: &str, token: Address, who: Address) -> U256 {
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let data = IMetaToken::balanceOfCall { who }.abi_encode();
    let out = p.call(TransactionRequest::default().to(token).input(data.into())).await.unwrap();
    U256::abi_decode(&out).unwrap()
}

fn sign(signer: &PrivateKeySigner, chain_id: u64, token: Address, m: &MetaTransaction) -> String {
    let d = Domain { name: "Bamboo MetaToken".into(), version: "1".into(), chain_id, verifying_contract: token };
    let sig = signer.sign_hash_sync(&digest(&d, m)).unwrap();
    format!("0x{}", alloy::hex::encode(sig.as_bytes()))
}

#[tokio::test]
#[ignore]
async fn outbox_payment_reaches_chain_and_comes_back_final() {
    let chain_id = 31901;
    let (_anvil, rpc) = start_anvil(chain_id, 18601).await;
    let payer = small_key(0xA11CE);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();

    let relayer = key(RELAYER);
    let shop = Address::repeat_byte(0x5e);
    let entry_ref = keccak256(b"order-1");
    let mut data = keccak256(b"pay(bytes32)")[..4].to_vec();
    data.extend_from_slice(entry_ref.as_slice());
    let m = MetaTransaction {
        from: payer.address(),
        to: shop,
        value: U256::from(250_000_000u64),
        data: data.into(),
        batch: U256::from_be_bytes(keccak256(b"lane").0),
        nonce: U256::ZERO,
        validUntil: U256::from(now() + 300),
        mode: MODE_RESTRICT_RELAYER,
        relayer: relayer.address(),
        fee: U256::ZERO,
        feeRecipient: Address::ZERO,
    };
    let signature = sign(&payer, chain_id, token, &m);
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    state.lock().unwrap().jobs.push(json!({
        "id": 1, "token": format!("{token:#x}"), "digest": "0x", "signature": signature,
        "metatx": WireMetaTx::from_sol(&m)}));
    let addr = start_fake(state.clone()).await;
    let odoo = odoo_at(addr);
    let cfg = chain_cfg(chain_id, &rpc, None);

    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo.clone(), cfg.clone(), "e2e".into())
        .await
        .unwrap();
    s.poll_outbox().await;
    s.track().await;
    assert_eq!(s.inflight_count(), 0, "receipt should be in after automine");

    let reports = state.lock().unwrap().reports.clone();
    let states: Vec<&str> = reports.iter().map(|r| r["chain_state"].as_str().unwrap()).collect();
    assert_eq!(states, vec!["signed", "broadcast", "mined"], "{reports:?}");
    assert!(reports[0]["tx_hash"].as_str().unwrap().starts_with("0x"));
    assert_eq!(reports[0]["outer_nonce"], 0);
    assert_eq!(balance(&rpc, token, shop).await, U256::from(250_000_000u64));

    let ichain = Chain::with_signer(&cfg, relayer).unwrap();
    assert!(bamboo_node::indexer::step(&ichain, &odoo).await.unwrap());
    let ingested = state.lock().unwrap().ingested.clone();
    let pay = ingested.iter().find(|e| e["event"] == "PaymentSettled").expect("PaymentSettled ingested");
    assert_eq!(pay["entry_ref"], format!("{entry_ref:#x}"));
    assert_eq!(pay["amount"], "250000000");
    let exe = ingested.iter().find(|e| e["event"] == "MetaTransactionExecuted").expect("executed ingested");
    let d = Domain { name: "Bamboo MetaToken".into(), version: "1".into(), chain_id, verifying_contract: token };
    assert_eq!(exe["digest"], format!("{:#x}", digest(&d, &m)));

    // Replay of the same signed job: simulation refuses it (nonce consumed) -> dead, no gas spent.
    state.lock().unwrap().jobs.push(json!({
        "id": 2, "token": format!("{token:#x}"), "digest": "0x", "signature": sign(&payer, chain_id, token, &m),
        "metatx": WireMetaTx::from_sol(&m)}));
    s.poll_outbox().await;
    let last = state.lock().unwrap().reports.last().cloned().unwrap();
    assert_eq!(last["chain_state"], "dead");
    assert!(last["error"].as_str().unwrap().contains("MetaTxBadNonce"), "{last}");
}

fn trade_leg(seller: &PrivateKeySigner, _sell: Address, value: u64, buy: Address, min: u64, dex: Address, batch: u64)
    -> MetaTransaction
{
    let mut data = OP_TRADE.to_vec();
    data.extend((buy, U256::from(min), Address::ZERO).abi_encode());
    MetaTransaction {
        from: seller.address(),
        to: dex,
        value: U256::from(value),
        data: data.into(),
        batch: U256::from(batch),
        nonce: U256::ZERO,
        validUntil: U256::from(now() + 300),
        mode: MODE_RESTRICT_RELAYER,
        relayer: dex,
        fee: U256::ZERO,
        feeRecipient: Address::ZERO,
    }
}

#[tokio::test]
#[ignore]
async fn dex_orders_match_through_the_gateway() {
    let chain_id = 31902;
    let (_anvil, rpc) = start_anvil(chain_id, 18602).await;
    let alice = small_key(0xA11CE);
    let bob = small_key(0xB0B);
    let dep = deploy(&rpc, chain_id, alice.address());
    let token_a: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["factory"].as_str().unwrap().parse().unwrap();
    let dex: Address = dep["dex"].as_str().unwrap().parse().unwrap();

    // Second token, minted to the deployer, then half to bob — plain txs from a funded account.
    let deployer = key(DEPLOYER);
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(deployer.clone())).connect_http(rpc.parse().unwrap());
    let init = ("Token BBB".to_string(), "BBB".to_string(), U256::from(6u8), U256::from(1_000_000_000u64), Address::ZERO).abi_encode_params();
    let create = IOpenFactory::createMetaTokenCall {
        version: 1,
        underlying: Address::ZERO,
        initData: init.into(),
        salt: B256::repeat_byte(0xbb),
    };
    let out = p.call(TransactionRequest::default().to(factory).input(create.abi_encode().into())).await.unwrap();
    let token_b = Address::abi_decode(&out).unwrap();
    p.send_transaction(TransactionRequest::default().to(factory).input(create.abi_encode().into()))
        .await.unwrap().get_receipt().await.unwrap();
    let give = IMetaToken::transferCall { to: bob.address(), value: U256::from(500_000_000u64) };
    p.send_transaction(TransactionRequest::default().to(token_b).input(give.abi_encode().into()))
        .await.unwrap().get_receipt().await.unwrap();

    let relayer = key(RELAYER);
    let cfg = chain_cfg(chain_id, &rpc, Some(dex));
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token_a:#x}"), format!("{token_b:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo, cfg.clone(), "e2e".into())
        .await
        .unwrap();
    let (tx, mut rx) = mpsc::channel::<Work>(16);
    let gw = GwChain {
        chain: Arc::new(Chain::with_signer(&cfg, relayer).unwrap()),
        tx,
        tokens: Arc::new(RwLock::new(vec![token_a, token_b])),
        dex: Some(dex),
        book: Arc::new(Mutex::new(Book::default())),
    };
    let app = router(AppState { chains: Arc::new([(chain_id, gw)].into_iter().collect()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let http = reqwest::Client::new();
    let post = |token: Address, m: MetaTransaction, sig: String| {
        let http = http.clone();
        async move {
            let r = http
                .post(format!("http://{gw_addr}/v1/dex/orders"))
                .json(&json!({"chain": chain_id, "token": token, "m": WireMetaTx::from_sol(&m), "signature": sig}))
                .send()
                .await
                .unwrap();
            let status = r.status();
            (status, r.json::<Value>().await.unwrap())
        }
    };
    let leg_a = trade_leg(&alice, token_a, 100_000_000, token_b, 50_000_000, dex, 1);
    let (st, body) = post(token_a, leg_a.clone(), sign(&alice, chain_id, token_a, &leg_a)).await;
    assert_eq!((st.as_u16(), body["status"].as_str()), (202, Some("resting")), "{body}");

    // A leg that is not routed through the DEX is refused at the door.
    let mut stray = trade_leg(&bob, token_b, 60_000_000, token_a, 100_000_000, dex, 2);
    stray.relayer = Address::repeat_byte(1);
    let (st, _) = post(token_b, stray.clone(), sign(&bob, chain_id, token_b, &stray)).await;
    assert_eq!(st.as_u16(), 400);

    let leg_b = trade_leg(&bob, token_b, 60_000_000, token_a, 100_000_000, dex, 3);
    let (st, body) = post(token_b, leg_b.clone(), sign(&bob, chain_id, token_b, &leg_b)).await;
    assert_eq!((st.as_u16(), body["status"].as_str()), (202, Some("matched")), "{body}");

    while let Ok(w) = rx.try_recv() {
        s.submit(w).await;
    }
    s.track().await;
    assert_eq!(s.inflight_count(), 0);
    assert_eq!(balance(&rpc, token_b, alice.address()).await, U256::from(60_000_000u64));
    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(100_000_000u64));
    assert_eq!(balance(&rpc, token_a, dex).await, U256::ZERO);
    let _ = Bytes::new();
}
