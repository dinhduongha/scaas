//! cargo test --test e2e -- --ignored --nocapture
//!
//! Cần `anvil` và `forge` trong PATH. Chứng minh trên EVM thật với contract thật:
//! 1. job outbox (giả Odoo) → simulate → ký → `signed` trước khi gửi → broadcast → receipt →
//!    indexer gửi `PaymentSettled` + `MetaTransactionExecuted` vùng final;
//! 2. DEX (R35): approve meta-tx qua gateway → lệnh ký EIP-712 qua gateway → khớp một phần →
//!    job `settle` qua outbox (giả Odoo) → số dư + phí; khởi động lại venue ⇒ sổ còn nguyên; huỷ ⇒
//!    đóng on-chain; watcher đưa event final về Odoo. Người ký không có một wei gas nào.
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{SolCall, SolValue};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use bamboo_node::abi::{IMetaToken, IOpenFactory, MetaTransaction};
use bamboo_node::chain::Chain;
use bamboo_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use bamboo_node::dex::venue::Venue;
use bamboo_node::dex::{cancel_digest, domain, order_hash, Order, WireOrder};
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

/// Bản sao bảng chuyển trạng thái của `dms_blockchain` (`blockchain_relay_job.TRANSITIONS`):
/// fake Odoo từ chối đúng như Odoo thật, để e2e không xanh giả (review I12).
fn allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("queued", "nonce_leased")
            | ("nonce_leased", "queued" | "signed" | "dead")
            | ("signed", "broadcast" | "mined" | "reverted" | "queued" | "dead")
            | ("broadcast", "mined" | "reverted" | "broadcast" | "queued" | "dead")
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
    tokens: Vec<String>,
    receiving: Vec<Value>,
    balance_reports: Vec<Value>,
    // --- DEX (dms_blockchain_dex) ---
    dex: String,
    markets: Vec<Value>,
    orders: BTreeMap<String, Value>,
    dex_trades: Vec<Value>,
    dex_events: Vec<Value>,
    dex_indexed: u64,
    next_job: i64,
    fail_commits: u32,
    failed: Vec<Value>,
}

async fn fake(
    State(s): State<Arc<Mutex<FakeOdoo>>>,
    Path((model, method)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let mut o = s.lock().unwrap();
    let out = match (model.as_str(), method.as_str()) {
        ("blockchain.chain", "node_config") => json!({
            "evm_chain_number": body["evm_chain_number"], "finality_mode": "depth", "finality_depth": 0,
            "finality_quorum": 1, "indexed_block": o.indexed_block,
            "tokens": o.tokens.iter().map(|t| json!({"address": t, "decimals": 6})).collect::<Vec<_>>(),
            "journal_max_nonce": null, "inflight": [], "receiving_addresses": o.receiving}),
        ("blockchain.chain", "balance_report") => {
            let stale = body["height"].as_u64() != Some(o.indexed_block);
            o.balance_reports.push(body.clone());
            json!({"stale": stale, "mismatch": 0})
        }
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
                return (StatusCode::OK, Json(json!({"error": format!("Transition {from} -> {to} is not allowed.")})));
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
        ("blockchain.dex.market", "dex_markets") => json!({"dex": o.dex, "markets": o.markets}),
        ("blockchain.dex.order", "dex_book_load") => {
            let rows: Vec<Value> = o
                .orders
                .values()
                .filter(|r| r["state"] == "open" || r["state"] == "partial")
                .map(|r| json!({"order_hash": r["order_hash"], "order": r["order"], "signature": r["signature"],
                                 "remaining": r["remaining"], "seq": r["seq"]}))
                .collect();
            json!({"rows": rows})
        }
        ("blockchain.dex.order", "dex_book_commit") => {
            if o.fail_commits > 0 {
                o.fail_commits -= 1;
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "db down"})));
            }
            for r in body["orders"].as_array().unwrap() {
                o.orders.insert(r["order_hash"].as_str().unwrap().to_string(), r.clone());
            }
            let trades = body["trades"].as_array().unwrap().clone();
            o.dex_trades.extend(trades);
            for j in body["jobs"].as_array().unwrap() {
                o.next_job += 1;
                let id = 1000 + o.next_job;
                o.jobs.push(json!({"id": id, "kind": "call", "call": {
                    "target": j["target"], "calldata": j["calldata"], "validUntil": j["valid_until"]}}));
            }
            json!({"ok": true})
        }
        ("blockchain.dex.trade", "dex_sync") => json!({"failed": std::mem::take(&mut o.failed)}),
        ("blockchain.dex.trade", "dex_cursor") => json!({"indexed_block": o.dex_indexed}),
        ("blockchain.dex.trade", "dex_fill_ingest") => {
            o.dex_indexed = body["to_block"].as_u64().unwrap();
            o.dex_events.extend(body["events"].as_array().unwrap().iter().cloned());
            json!({"indexed_block": o.dex_indexed})
        }
        _ => json!({"error": "unexpected"}),
    };
    (StatusCode::OK, Json(out))
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
        family: "evm".into(),
        network: None,
        evm_chain_number: chain_id,
        rpc_urls: vec![rpc.to_string()],
        signer_key_env: String::new(),
        private_key: None,
        lanes: vec![0],
        params: Default::default(),
        finality: FinalityCfg { mode: "depth".into(), depth: 0, quorum: 1 },
        dex,
        poll_ms: 200,
        stuck_after_secs: 60,
        max_gas_per_tx: 3_000_000,
        max_fee_cap_gwei: 500,
        ..Default::default()
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
    let (_anvil, rpc) = start_anvil(chain_id, 31901).await;
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
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: vec![format!("{token:#x}")],
        receiving: vec![json!({"token": format!("{token:#x}"), "address": format!("{shop:#x}")})],
        ..Default::default()
    }));
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
    for _ in 0..50 {
        s.track().await;
        if s.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(s.inflight_count(), 0, "receipt should be in after automine");

    let reports = state.lock().unwrap().reports.clone();
    let states: Vec<&str> = reports.iter().map(|r| r["chain_state"].as_str().unwrap()).collect();
    assert_eq!(states, vec!["signed", "broadcast", "mined"], "{reports:?}");
    assert!(state.lock().unwrap().refused.is_empty());
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
    // Drift A (R56): the ERC-20 Transfer to the receiving wallet rides along with the same tx hash, so
    // Odoo can see it is matched by the PaymentSettled.
    let tr = ingested.iter().find(|e| e["event"] == "Transfer").expect("Transfer to the receiving wallet");
    assert_eq!((&tr["tx_hash"], &tr["to"]), (&pay["tx_hash"], &json!(format!("{shop:#x}"))));
    // Drift C: balance at exactly the indexed height.
    assert!(bamboo_node::drift::step(&ichain, &odoo, "evm:31901").await.unwrap());
    let rep = state.lock().unwrap().balance_reports.last().cloned().unwrap();
    assert_eq!(rep["height"].as_u64(), Some(state.lock().unwrap().indexed_block));
    assert_eq!(rep["balances"][0]["balance"], "250000000");
    // R55: a lane under its balance floor takes no new work.
    let mut poor = cfg.clone();
    poor.breaker.min_relayer_balance = Some(u128::MAX / 2);
    let mut s2 = Submitter::start(Chain::with_signer(&poor, key(RELAYER)).unwrap(), odoo.clone(), poor, "e2e-2".into())
        .await
        .unwrap();
    assert!(s2.accepting(), "no sample yet: nothing known, nothing tripped");
    s2.sample().await;
    assert!(!s2.accepting(), "balance floor");

    // Replay of the same signed job: simulation refuses it (nonce consumed) -> dead, no gas spent.
    state.lock().unwrap().jobs.push(json!({
        "id": 2, "token": format!("{token:#x}"), "digest": "0x", "signature": sign(&payer, chain_id, token, &m),
        "metatx": WireMetaTx::from_sol(&m)}));
    s.poll_outbox().await;
    let last = state.lock().unwrap().reports.last().cloned().unwrap();
    assert_eq!(last["chain_state"], "dead");
    assert!(last["error"].as_str().unwrap().contains("MetaTxBadNonce"), "{last}");
}

fn sign_hash(signer: &PrivateKeySigner, h: B256) -> String {
    format!("0x{}", alloy::hex::encode(signer.sign_hash_sync(&h).unwrap().as_bytes()))
}

#[allow(clippy::too_many_arguments)]
fn order(maker: &PrivateKeySigner, sell: Address, sell_amt: u64, buy: Address, buy_amt: u64, nonce: u64, relayer: Address)
    -> Order
{
    Order {
        maker: maker.address(),
        taker: Address::ZERO,
        sellToken: sell,
        buyToken: buy,
        sellAmount: U256::from(sell_amt),
        buyAmount: U256::from(buy_amt),
        nonce: U256::from(nonce),
        expiry: U256::from(now() + 600),
        maxFeePpm: 5_000,
        flags: 0,
        relayer,
        feeMode: 0,
        fee: U256::ZERO,
        feeToken: Address::ZERO,
        feeRecipient: Address::ZERO,
    }
}

async fn send(rpc: &str, from: &PrivateKeySigner, to: Address, data: Vec<u8>) {
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(from.clone())).connect_http(rpc.parse().unwrap());
    let r = p.send_transaction(TransactionRequest::default().to(to).input(data.into())).await.unwrap();
    assert!(r.get_receipt().await.unwrap().status());
}

async fn drain(s: &mut Submitter, rx: &mut mpsc::Receiver<Work>) {
    while let Ok(w) = rx.try_recv() {
        s.submit(w).await;
    }
    s.poll_outbox().await;
    for _ in 0..50 {
        s.track().await;
        if s.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(s.inflight_count(), 0);
}

alloy::sol! {
    function setMarket(address tokenA, address tokenB, (bool,bool,uint32,uint32,address) m) external;
    function filled(bytes32 h) external view returns (uint256);
}

#[tokio::test]
#[ignore]
async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let chain_id = 31950; // S5 range
    let (_anvil, rpc) = start_anvil(chain_id, 18650).await;
    let alice = small_key(0xA11CE);
    let bob = small_key(0xB0B);
    let dep = deploy(&rpc, chain_id, alice.address());
    let token_a: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["factory"].as_str().unwrap().parse().unwrap();
    let dex: Address = dep["order_book_dex"].as_str().unwrap().parse().unwrap();

    // Quote token B, half to bob — plain txs from the funded deployer (= DEX admin).
    let deployer = key(DEPLOYER);
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(deployer.clone())).connect_http(rpc.parse().unwrap());
    let init = ("Token BBB".to_string(), "BBB".to_string(), U256::from(6u8), U256::from(1_000_000_000u64), Address::ZERO).abi_encode_params();
    let create = IOpenFactory::createMetaTokenCall { version: 1, underlying: Address::ZERO, initData: init.into(), salt: B256::repeat_byte(0xbb) };
    let out = p.call(TransactionRequest::default().to(factory).input(create.abi_encode().into())).await.unwrap();
    let token_b = Address::abi_decode(&out).unwrap();
    send(&rpc, &deployer, factory, create.abi_encode()).await;
    send(&rpc, &deployer, token_b, IMetaToken::transferCall { to: bob.address(), value: U256::from(500_000_000u64) }.abi_encode()).await;
    let fee_to = Address::repeat_byte(0xfe);
    send(&rpc, &deployer, dex, setMarketCall { tokenA: token_a, tokenB: token_b, m: (true, true, 1_000, 2_000, fee_to) }.abi_encode()).await;

    let relayer = key(RELAYER);
    let cfg = chain_cfg(chain_id, &rpc, Some(dex));
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: vec![format!("{token_a:#x}"), format!("{token_b:#x}")],
        dex: format!("{dex:#x}"),
        markets: vec![json!({"id": 1, "base": format!("{token_a:#x}"), "quote": format!("{token_b:#x}"),
            "base_decimals": 6, "quote_decimals": 6, "fee_on": true, "maker_fee_ppm": 1000, "taker_fee_ppm": 2000,
            "fee_recipient": format!("{fee_to:#x}"), "min_base_amount": "1000"})],
        ..Default::default()
    }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo.clone(), cfg.clone(), "e2e".into())
        .await
        .unwrap();
    let shared = Arc::new(Chain::with_signer(&cfg, relayer.clone()).unwrap());
    let venue = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
    let (tx, mut rx) = mpsc::channel::<Work>(16);
    let fee_wallet = Address::repeat_byte(0xfa);
    let gw = GwChain { chain: shared.clone(), tx, tokens: Arc::new(RwLock::new(vec![token_a, token_b])), dex: Some(venue.clone()), breaker: None, fee_recipient: Some(fee_wallet) };
    let app = router(AppState { chains: Arc::new([(chain_id, gw)].into_iter().collect()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18651").await.unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = reqwest::Client::new();
    let gw = "http://127.0.0.1:18651";
    let post = |path: &'static str, body: Value| {
        let http = http.clone();
        async move {
            let r = http.post(format!("{gw}{path}")).json(&body).send().await.unwrap();
            let st = r.status().as_u16();
            (st, r.json::<Value>().await.unwrap())
        }
    };

    // 1. Gasless approve (MetaToken op, R26/R35) through the open gateway.
    for (who, token) in [(&alice, token_a), (&bob, token_b)] {
        let mut data = keccak256(b"approve(address,uint256)")[..4].to_vec();
        data.extend((dex, U256::MAX).abi_encode_params());
        let m = MetaTransaction {
            from: who.address(), to: dex, value: U256::ZERO, data: data.into(),
            batch: U256::from_be_bytes(keccak256(b"bamboo.dex.approve").0), nonce: U256::ZERO,
            validUntil: U256::from(now() + 300), mode: MODE_RESTRICT_RELAYER, relayer: relayer.address(),
            fee: U256::ZERO, feeRecipient: Address::ZERO,
        };
        let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": token, "m": WireMetaTx::from_sol(&m),
            "signature": sign(who, chain_id, token, &m)})).await;
        assert_eq!(st, 202, "{body}");
    }
    drain(&mut s, &mut rx).await;

    // 1b. R84 (review C1): `feeRecipient`/`relayer` of an open-mode intent are not signed, so a client can put
    //     anything there; the fee still lands in our configured wallet.
    let thief = Address::repeat_byte(0x7e);
    let m = MetaTransaction {
        from: alice.address(), to: Address::repeat_byte(0x5e), value: U256::from(1_000_000u64), data: Default::default(),
        batch: U256::from_be_bytes(keccak256(b"e2e.r84").0), nonce: U256::ZERO, validUntil: U256::from(now() + 300),
        mode: 0x20, // FIXED fee, neither relayer nor fee recipient bound
        relayer: thief, fee: U256::from(1_000u64), feeRecipient: thief,
    };
    let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": token_a, "m": WireMetaTx::from_sol(&m),
        "signature": sign(&alice, chain_id, token_a, &m)})).await;
    assert_eq!(st, 202, "{body}");
    drain(&mut s, &mut rx).await;
    assert_eq!((balance(&rpc, token_a, fee_wallet).await, balance(&rpc, token_a, thief).await), (U256::from(1_000u64), U256::ZERO));

    let d = domain(chain_id, dex);
    let place = |o: Order, signer: &PrivateKeySigner| {
        let sig = sign_hash(signer, order_hash(&d, &o));
        post("/v1/dex/orders", json!({"chain": chain_id, "order": WireOrder::from_sol(&o), "signature": sig}))
    };

    // 2. Order without the relayer restriction is refused (RS5-9).
    let (st, _) = place(order(&alice, token_a, 100_000_000, token_b, 200_000_000, 1, Address::ZERO), &alice).await;
    assert_eq!(st, 400);

    // 3. Ask rests; a smaller bid fills partially against it.
    let ask = order(&alice, token_a, 100_000_000, token_b, 200_000_000, 2, relayer.address());
    let ask_hash = order_hash(&d, &ask);
    let (st, body) = place(ask.clone(), &alice).await;
    assert_eq!((st, body["status"].as_str()), (202, Some("resting")), "{body}");
    let bid = order(&bob, token_b, 80_000_000, token_a, 40_000_000, 3, relayer.address());
    let (st, body) = place(bid, &bob).await;
    assert_eq!((st, body["status"].as_str()), (202, Some("filled")), "{body}");
    drain(&mut s, &mut rx).await; // the settle job went through the Odoo outbox
    // maker fee 0.1 % of 80 B, taker fee 0.2 % of 40 A
    assert_eq!(balance(&rpc, token_b, alice.address()).await, U256::from(80_000_000u64 - 80_000));
    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(40_000_000u64 - 80_000));
    assert_eq!(balance(&rpc, token_b, fee_to).await, U256::from(80_000u64));
    assert_eq!(balance(&rpc, token_a, fee_to).await, U256::from(80_000u64));
    assert_eq!(balance(&rpc, token_a, dex).await + balance(&rpc, token_b, dex).await, U256::ZERO);

    // 4. Restart: a fresh venue on the same Odoo has the same book.
    let before = venue.rows().await;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].remaining, "60000000");
    let venue2 = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
    assert_eq!(venue2.rows().await, before);

    // 5. A failed commit leaves the book exactly as Odoo has it (review D20).
    state.lock().unwrap().fail_commits = 1;
    let (st, _) = place(order(&bob, token_b, 20_000_000, token_a, 10_000_000, 4, relayer.address()), &bob).await;
    assert_eq!(st, 503);
    assert_eq!(venue.rows().await, before);

    // 6. Cancel: a high-s copy of a valid signature is refused like the contract would (review I4);
    //    the canonical one takes the order off the book now and closes it on-chain at the next sync.
    let high_s = {
        let s = alice.sign_hash_sync(&cancel_digest(&d, ask_hash)).unwrap();
        let n = U256::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
        let flipped = alloy::primitives::Signature::new(s.r(), n - s.s(), !s.v());
        format!("0x{}", alloy::hex::encode(flipped.as_bytes()))
    };
    let (st, _) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"),
        "signature": high_s})).await;
    assert_eq!(st, 400);
    assert_eq!(venue.rows().await, before);
    let (st, body) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"),
        "signature": sign_hash(&alice, cancel_digest(&d, ask_hash))})).await;
    assert_eq!(st, 202, "{body}");
    assert!(venue.rows().await.is_empty());
    venue.sync_once().await.unwrap();
    drain(&mut s, &mut rx).await;
    let out = p.call(TransactionRequest::default().to(dex).input(filledCall { h: ask_hash }.abi_encode().into())).await.unwrap();
    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(100_000_000u64));

    // 7. The watcher brings final DEX events to Odoo with its own cursor.
    while venue.watch_once().await.unwrap() {}
    let ev = state.lock().unwrap().dex_events.clone();
    let names: Vec<&str> = ev.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert!(names.contains(&"OrderFilled") && names.contains(&"Matched") && names.contains(&"OrderCancelled"), "{names:?}");
    let filled_alice = ev.iter().find(|e| e["event"] == "OrderFilled" && e["order_hash"] == format!("{ask_hash:#x}")).unwrap();
    assert_eq!(filled_alice["dex_fee"], "80000");
    assert_eq!(state.lock().unwrap().dex_trades.len(), 1);

    // 8. A settle job that dies: Odoo marks its trade failed, sync hands both healthy sides back,
    //    and they trade again as a NEW trade (no crossed book, no tag collision).
    let ask3 = order(&alice, token_a, 10_000_000, token_b, 20_000_000, 7, relayer.address());
    let bid3 = order(&bob, token_b, 20_000_000, token_a, 10_000_000, 8, relayer.address());
    assert_eq!(place(ask3.clone(), &alice).await.1["status"], "resting");
    assert_eq!(place(bid3.clone(), &bob).await.1["status"], "filled");
    let dead_tag = {
        let mut o = state.lock().unwrap();
        o.jobs.clear(); // the settle job never reaches the chain
        let t = o.dex_trades.last().unwrap().clone();
        let row = |h: B256| {
            let r = o.orders[&format!("{h:#x}")].clone();
            json!({"order_hash": r["order_hash"], "order": r["order"], "signature": r["signature"],
                   "remaining": r["remaining"], "seq": r["seq"]})
        };
        let f = json!({"tag": t["tag"], "maker": row(order_hash(&d, &ask3)), "taker": row(order_hash(&d, &bid3)),
                       "maker_fill": t["maker_fill"], "taker_fill": t["taker_fill"]});
        o.failed.push(f);
        t["tag"].clone()
    };
    venue.sync_once().await.unwrap();
    let last = state.lock().unwrap().dex_trades.last().unwrap().clone();
    assert_ne!(last["tag"], dead_tag);
    assert!(venue.rows().await.is_empty(), "both sides traded again; nothing rests crossed");
    drain(&mut s, &mut rx).await;
    assert_eq!(balance(&rpc, token_b, alice.address()).await, U256::from(79_920_000u64 + 20_000_000 - 20_000));
    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(39_920_000u64 + 10_000_000 - 20_000));

    // 9. A dead trade whose taker is closed in Odoo (null row, review I3): the maker alone goes back
    //    to the book AND to Odoo, so a restart still has it.
    let ask4 = order(&alice, token_a, 10_000_000, token_b, 20_000_000, 9, relayer.address());
    let bid4 = order(&bob, token_b, 20_000_000, token_a, 10_000_000, 10, relayer.address());
    let ask4_hash = format!("{:#x}", order_hash(&d, &ask4));
    assert_eq!(place(ask4.clone(), &alice).await.1["status"], "resting");
    assert_eq!(place(bid4.clone(), &bob).await.1["status"], "filled");
    {
        let mut o = state.lock().unwrap();
        o.jobs.clear();
        let t = o.dex_trades.last().unwrap().clone();
        let r = o.orders[&ask4_hash].clone();
        assert_eq!(r["state"], "filled");
        let row = json!({"order_hash": r["order_hash"], "order": r["order"], "signature": r["signature"],
                         "remaining": r["remaining"], "seq": r["seq"]});
        o.failed.push(json!({"tag": t["tag"], "maker": row, "taker": null,
                             "maker_fill": t["maker_fill"], "taker_fill": t["taker_fill"]}));
    }
    venue.sync_once().await.unwrap();
    let rows = venue.rows().await;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].order_hash.as_str(), rows[0].remaining.as_str()), (ask4_hash.as_str(), "10000000"));
    let stored = state.lock().unwrap().orders[&ask4_hash].clone();
    assert_eq!((stored["state"].as_str(), stored["remaining"].as_str()), (Some("open"), Some("10000000")));
    let venue3 = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
    assert_eq!(venue3.rows().await, rows);
}

fn pay_job(payer: &PrivateKeySigner, chain_id: u64, token: Address, id: i64, tag: &[u8]) -> Value {
    let entry_ref = keccak256(tag);
    let mut data = keccak256(b"pay(bytes32)")[..4].to_vec();
    data.extend_from_slice(entry_ref.as_slice());
    let m = MetaTransaction {
        from: payer.address(),
        to: Address::repeat_byte(0x5e),
        value: U256::from(1_000u64),
        data: data.into(),
        batch: U256::from_be_bytes(entry_ref.0),
        nonce: U256::ZERO,
        validUntil: U256::from(now() + 300),
        mode: 0,
        relayer: Address::ZERO,
        fee: U256::ZERO,
        feeRecipient: Address::ZERO,
    };
    json!({"id": id, "token": format!("{token:#x}"), "digest": "0x",
           "signature": sign(payer, chain_id, token, &m), "metatx": WireMetaTx::from_sol(&m)})
}

/// R58/R62: the same EVM chain driven through the generic `ChainAdapter` + `lane_step` +
/// `index_step` path, with TWO relayer lanes derived from a 24-word mnemonic: each lane signs with
/// its own key, both payments land, the indexer ingests both.
#[tokio::test]
#[ignore]
async fn evm_adapter_runs_the_generic_lane_runner_on_two_mnemonic_lanes() {
    use bamboo_node::adapter::{index_step, lane_step, ChainAdapter};
    use bamboo_node::adapters::evm::EvmAdapter;
    use bamboo_node::keys::{lane_secret, Seed};
    use bamboo_node::signer::LocalSigner;

    let chain_id = 31903;
    let (_anvil, rpc) = start_anvil(chain_id, 31903).await;
    let payer = small_key(0xB0B);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let art = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
               abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let seed = Seed::from_phrase(art.as_bytes(), None).unwrap();
    let signers: Vec<LocalSigner> = (0..2)
        .map(|i| {
            let (c, k) = lane_secret(&seed, "evm", i).unwrap();
            LocalSigner::new(c, &k).unwrap()
        })
        .collect();
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    for s in &signers {
        let _: Value = p.raw_request("anvil_setBalance".into(), (s.address_hex(), "0xde0b6b3a7640000")).await.unwrap();
    }
    let mut cfg = chain_cfg(chain_id, &rpc, None);
    cfg.lanes = vec![0, 1];
    let chains = Chain::connect_lanes(&cfg, &signers).unwrap();
    let adapter = EvmAdapter::new(&cfg, chains, Arc::new(RwLock::new(vec![token]))).unwrap();
    assert_eq!(adapter.lanes().len(), 2);

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    state.lock().unwrap().jobs.push(pay_job(&payer, chain_id, token, 11, b"generic-1"));
    assert!(lane_step(&adapter, &odoo, 0, "e2e#0").await.unwrap());
    state.lock().unwrap().jobs.push(pay_job(&payer, chain_id, token, 12, b"generic-2"));
    assert!(lane_step(&adapter, &odoo, 1, "e2e#1").await.unwrap());
    assert!(!lane_step(&adapter, &odoo, 1, "e2e#1").await.unwrap(), "nothing left");

    let reports = state.lock().unwrap().reports.clone();
    let states: Vec<(i64, String)> = reports.iter()
        .map(|r| (r["job_id"].as_i64().unwrap(), r["chain_state"].as_str().unwrap().to_string())).collect();
    for id in [11, 12] {
        let seq: Vec<&str> = states.iter().filter(|(j, _)| *j == id).map(|(_, s)| s.as_str()).collect();
        assert_eq!(seq, vec!["signed", "broadcast", "mined"], "{reports:?}");
    }
    let signed_by: std::collections::HashSet<String> = reports.iter()
        .filter(|r| r["chain_state"] == "signed").map(|r| r["signer_address"].as_str().unwrap().to_string()).collect();
    assert_eq!(signed_by, signers.iter().map(|s| s.address_hex()).collect());
    assert!(state.lock().unwrap().refused.is_empty());
    assert_eq!(balance(&rpc, token, Address::repeat_byte(0x5e)).await, U256::from(2_000u64));

    while index_step(&adapter, &odoo).await.unwrap() {}
    let settled = state.lock().unwrap().ingested.iter().filter(|e| e["event"] == "PaymentSettled").count();
    assert_eq!(settled, 2);
}
