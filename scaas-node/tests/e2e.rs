//! cargo test --test e2e -- --ignored --nocapture
//!
//! Cần `anvil` và `forge` trong PATH. Chứng minh trên EVM thật với contract thật:
//! 1. job outbox (giả Odoo) → simulate → ký → `signed` trước khi gửi → broadcast → receipt →
//!    indexer gửi `PaymentSettled` + `MetaTransactionExecuted` vùng final;
//! 2. DEX (R35, NODE-DEX-15) on a `SCaaSDex` clone: `TradeOrder`s signed in the sell token's domain (a `DexOrder` in
//!    the DEX's domain for an outside token) through the gateway → one settlement per taker → `mtxSettle` job through
//!    the outbox (fake Odoo) → balances, fees, relayer share; restart ⇒ same book; cancels on the token (entry job)
//!    and on the DEX; the watcher brings final events back. No signer holds a wei of gas.
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
use scaas_node::abi::{IToken, MetaTransfer};
use scaas_node::chain::Chain;
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use scaas_node::dex::venue::Venue;
use scaas_node::abi::TradeOrder;
use scaas_node::dex::{cancel_digest, dex_order_hash, domain, invalidate_digest, trade_order_hash, WireOrder};
use scaas_node::gateway::{router, AppState, GwChain};
use scaas_node::metatx::{Domain, Mtx, MODE_RESTRICT_RELAYER};
use scaas_node::odoo::Odoo;
use scaas_node::submit::{work_from_job, Submitter, Work, BUMP_SKIPPED_CONSUMED};
use serde_json::{json, Value};
use tokio::sync::mpsc;

const DEPLOYER: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// Address of `DEPLOYER`: forge needs `--sender` when a script links libraries and deploys by CREATE2.
const DEPLOYER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
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
        .args(["--chain-id", &chain_id.to_string(), "--hardfork", "amsterdam", "--gas-limit", "100000000", "--code-size-limit", "65536", "--port", &port.to_string(), "--silent"])
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
    let sc = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm");
    let status = Command::new("forge")
        .current_dir(sc)
        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--slow", "--silent", "--disable-code-size-limit", "--sender", DEPLOYER_ADDRESS])
        .env("PRIVATE_KEY", DEPLOYER)
        .env("DEMO_SUPPLY", "1000000000000")
        .env("DEMO_HOLDER", format!("{holder:#x}"))
        .env("FOUNDRY_PROFILE", "private7622")
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let raw = std::fs::read_to_string(format!("{sc}/deployments/{chain_id}.json")).expect("deployments json");
    let dep: Value = serde_json::from_str(&raw).unwrap();
    // P4: the account keys are `smart_key_account_*` (the node reads neither; Odoo seeds from them)
    assert!(dep["smart_key_account_factory"].is_string() && dep["smart_key_account_implementation"].is_string());
    assert!(dep.get("subject_account_factory").is_none(), "pre-P4 deploy JSON key");
    // P5: the v1 line left the deploy (`legacy/p5/`); two demo tokens from the `OpenFactory`
    for k in ["factory", "implementation", "dex", "scaas_dex"] {
        assert!(dep.get(k).is_none(), "v1 deploy JSON key {k}");
    }
    assert!(dep["demo_token"].is_string() && dep["demo_token_2"].is_string());
    dep
}

/// Bản sao bảng chuyển trạng thái của `dms_blockchain` (`blockchain_relay_job.TRANSITIONS`):
/// fake Odoo từ chối đúng như Odoo thật, để e2e không xanh giả (review I12).
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
                .map(row_of)
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
                // a token-side order entry is a `metatx` job naming its entry; everything else a `call` on the DEX
                o.jobs.push(if j["kind"] == "metatx" {
                    let mut x = j.clone();
                    x["id"] = json!(id);
                    x
                } else {
                    json!({"id": id, "kind": "call", "call": {
                        "target": j["target"], "calldata": j["calldata"], "validUntil": j["valid_until"]}})
                });
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

/// A stored order as `dex_book_load` / `dex_sync` return it.
fn row_of(r: &Value) -> Value {
    json!({"order_hash": r["order_hash"], "sell_token": r["sell_token"], "order": r["order"], "signature": r["signature"],
           "remaining": r["remaining"], "seq": r["seq"]})
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
    let data = IToken::balanceOfCall { who }.abi_encode();
    let out = p.call(TransactionRequest::default().to(token).input(data.into())).await.unwrap();
    U256::abi_decode(&out).unwrap()
}

/// The token's salted domain: `chain_uid` from the deploy JSON (the script checked it against block 0).
fn token_domain(dep: &Value, chain_id: u64, token: Address) -> Domain {
    Domain { name: "SCaaS MetaToken".into(), version: "1".into(), chain_id, verifying_contract: token,
             salt: dep["chain_uid"].as_str().unwrap().parse().unwrap() }
}

fn sign(signer: &PrivateKeySigner, d: &Domain, m: &Mtx) -> String {
    let sig = signer.sign_hash_sync(&m.digest(d)).unwrap();
    format!("0x{}", alloy::hex::encode(sig.as_bytes()))
}

/// A payment `MetaTransfer` (`entryRef` = `r`) on lane `batch`.
#[allow(clippy::too_many_arguments)]
fn payment(from: Address, to: Address, value: u64, r: B256, batch: U256, mode: u32, relayer: Address, fee: u64,
    fee_recipient: Address) -> Mtx
{
    Mtx::Transfer(MetaTransfer {
        from, to, value: U256::from(value), entryRef: r, batch, nonce: U256::ZERO, validUntil: U256::from(now() + 300),
        mode, relayer, fee: U256::from(fee), feeRecipient: fee_recipient,
    })
}

/// An outbox job as the client stores it: `struct` names the signed struct (CTR-MTX-15).
fn job(id: i64, token: Address, m: &Mtx, digest: &str, signature: String) -> Value {
    let (kind, wire) = m.to_wire();
    json!({"id": id, "token": format!("{token:#x}"), "digest": digest, "signature": signature, "struct": kind, "metatx": wire})
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
    let d = token_domain(&dep, chain_id, token);
    let m = payment(payer.address(), shop, 250_000_000, entry_ref, U256::from_be_bytes(keccak256(b"lane").0),
        MODE_RESTRICT_RELAYER, relayer.address(), 0, Address::ZERO);
    let signature = sign(&payer, &d, &m);
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: vec![format!("{token:#x}")],
        receiving: vec![json!({"token": format!("{token:#x}"), "address": format!("{shop:#x}")})],
        ..Default::default()
    }));
    state.lock().unwrap().jobs.push(job(1, token, &m, "0x", signature));
    let addr = start_fake(state.clone()).await;
    let odoo = odoo_at(addr);
    let cfg = chain_cfg(chain_id, &rpc, None);

    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo.clone(), cfg.clone(), "e2e".into(), Default::default())
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

    let ichain = Chain::with_signer(&cfg, relayer.clone()).unwrap();
    assert!(scaas_node::indexer::step(&ichain, &odoo, None).await.unwrap());
    let ingested = state.lock().unwrap().ingested.clone();
    let pay = ingested.iter().find(|e| e["event"] == "PaymentSettled").expect("PaymentSettled ingested");
    assert_eq!(pay["entry_ref"], format!("{entry_ref:#x}"));
    assert_eq!(pay["amount"], "250000000");
    let exe = ingested.iter().find(|e| e["event"] == "MetaTransactionExecuted").expect("executed ingested");
    assert_eq!(exe["digest"], format!("{:#x}", m.digest(&d)));
    // Drift A (R56): the ERC-20 Transfer to the receiving wallet rides along with the same tx hash, so
    // Odoo can see it is matched by the PaymentSettled.
    let tr = ingested.iter().find(|e| e["event"] == "Transfer").expect("Transfer to the receiving wallet");
    assert_eq!((&tr["tx_hash"], &tr["to"]), (&pay["tx_hash"], &json!(format!("{shop:#x}"))));
    // Drift C: balance at exactly the indexed height.
    assert!(scaas_node::drift::step(&ichain, &odoo, "evm:31901").await.unwrap());
    let rep = state.lock().unwrap().balance_reports.last().cloned().unwrap();
    assert_eq!(rep["height"].as_u64(), Some(state.lock().unwrap().indexed_block));
    assert_eq!(rep["balances"][0]["balance"], "250000000");
    // R55: a lane under its balance floor takes no new work.
    let mut poor = cfg.clone();
    poor.breaker.min_relayer_balance = Some(u128::MAX / 2);
    let mut s2 = Submitter::start(Chain::with_signer(&poor, key(RELAYER)).unwrap(), odoo.clone(), poor, "e2e-2".into(), Default::default())
        .await
        .unwrap();
    assert!(s2.accepting(), "no sample yet: nothing known, nothing tripped");
    s2.sample().await;
    assert!(!s2.accepting(), "balance floor");

    // Replay of the same signed job: simulation refuses it, but the subject nonce is spent by this very intent (R80)
    // -> `consumed` (classified from the MetaTransactionExecuted log: our lane landed it), never `dead`; no gas spent.
    state.lock().unwrap().jobs.push(job(2, token, &m, &format!("{:#x}", m.digest(&d)), sign(&payer, &d, &m)));
    s.poll_outbox().await;
    let last = state.lock().unwrap().reports.last().cloned().unwrap();
    assert_eq!((last["job_id"].as_i64(), last["chain_state"].as_str(), last["error"].as_str()), (Some(2), Some("consumed"), Some("landed")), "{last}");

    // PAY-FIX2 on a real chain: the lane holds fee income in the token, and a `call` job that would move it is refused
    // before simulation; a meta-transaction to a contract that is not a registered token (here: no contract) too.
    let steal = IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1u64) }.abi_encode();
    let mut jobs = vec![json!({"id": 3, "kind": "call", "call": {"target": format!("{token:#x}"),
        "calldata": format!("0x{}", alloy::hex::encode(steal)), "validUntil": (now() + 300).to_string()}})];
    let elsewhere = Address::repeat_byte(0x99);
    jobs.push(job(4, elsewhere, &m, "0x", sign(&payer, &token_domain(&dep, chain_id, elsewhere), &m)));
    state.lock().unwrap().jobs.extend(jobs);
    let nonce = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_count(relayer.address()).await.unwrap();
    s.poll_outbox().await;
    let reports = state.lock().unwrap().reports.clone();
    let of = |id: i64| reports.iter().rev().find(|r| r["job_id"] == id).unwrap().clone();
    assert_eq!(of(3)["chain_state"], "dead");
    assert!(of(3)["error"].as_str().unwrap().starts_with("CALL_TARGET_REFUSED"), "{}", of(3));
    assert_eq!(of(4)["chain_state"], "dead");
    assert!(of(4)["error"].as_str().unwrap().starts_with("TOKEN_NOT_SERVED"), "{}", of(4));
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), nonce, "nothing signed or sent");

    // NODE-JOB-20 against the real token: a `call` struct runs only a selector of its published allowlist. A self-call
    // of `transfer` is refused before simulation; `cancelNonce(99)` lands and moves the payer's lane 99.
    let call = |data: Vec<u8>, batch: u64| Mtx::Call(scaas_node::abi::MetaTransaction { from: payer.address(), data: data.into(),
        batch: U256::from(batch), nonce: U256::ZERO, validUntil: U256::from(now() + 300), mode: 0, relayer: Address::ZERO,
        fee: U256::ZERO, feeRecipient: Address::ZERO });
    let bad = call(IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1u64) }.abi_encode(), 5);
    let good = call(alloy::hex::decode(format!("cfdd7aea{:064x}", 99)).unwrap(), 6);
    state.lock().unwrap().jobs.extend([job(5, token, &bad, "0x", sign(&payer, &d, &bad)), job(6, token, &good, "0x", sign(&payer, &d, &good))]);
    s.poll_outbox().await;
    for _ in 0..50 {
        s.track().await;
        if s.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let reports = state.lock().unwrap().reports.clone();
    let of = |id: i64| reports.iter().rev().find(|r| r["job_id"] == id).unwrap().clone();
    assert_eq!(of(5)["chain_state"], "dead");
    assert!(of(5)["error"].as_str().unwrap().starts_with("SELECTOR_NOT_ALLOWED"), "{}", of(5));
    assert_eq!(of(6)["chain_state"], "mined", "{}", of(6));
    let lane99 = IToken::mtxNonceCall { from: payer.address(), batch: U256::from(99) }.abi_encode();
    let out = p.call(TransactionRequest::default().to(token).input(lane99.into())).await.unwrap();
    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(1u64));

    // T17 (CTR-MTX-26) on the real token: a pay-meta job relays `mtxPayMeta`, and the indexer gives the meta to its
    // PaymentSettled (never a row of its own)
    let (salt, meta) = (B256::repeat_byte(0x51), alloy::hex::decode("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000568656c6c6f000000000000000000000000000000000000000000000000000000").unwrap());
    let pid = scaas_node::metatx::meta_pay_id(&salt, &meta);
    let pm = payment(payer.address(), shop, 1_000, pid, scaas_node::metatx::pay_lane(&pid), MODE_RESTRICT_RELAYER, relayer.address(), 0, Address::ZERO);
    let mut j = job(7, token, &pm, "0x", sign(&payer, &d, &pm));
    (j["salt"], j["meta"]) = (json!(format!("{salt:#x}")), json!(format!("0x{}", alloy::hex::encode(&meta))));
    state.lock().unwrap().jobs.push(j);
    s.poll_outbox().await;
    for _ in 0..50 {
        s.track().await;
        if s.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let reports = state.lock().unwrap().reports.clone();
    let of = |id: i64| reports.iter().rev().find(|r| r["job_id"] == id).unwrap().clone();
    assert_eq!(of(7)["chain_state"], "mined", "{}", of(7));
    while scaas_node::indexer::step(&ichain, &odoo, None).await.unwrap() {}
    let ingested = state.lock().unwrap().ingested.clone();
    assert!(ingested.iter().all(|e| e["event"] != "PaymentMeta"), "never a row");
    let paid = ingested.iter().find(|e| e["event"] == "PaymentSettled" && e["entry_ref"] == format!("{pid:#x}")).expect("pay-meta settled");
    assert_eq!((paid["amount"].as_str(), paid["meta"].as_str()), (Some("1000"), Some(format!("0x{}", alloy::hex::encode(&meta)).as_str())));

    // T17 (CTR-MTX-27) on the real router: a fee-less `cancelNonce(77)` of the payer, its fee of 10 in open mode; the
    // node relays `relay` (call-table row MtxRelayFee.relay), the fee reaches the lane, the indexer joins RelayFeePaid
    let router: Address = dep["mtx_relay_fee"].as_str().expect("mtx_relay_fee in the deploy JSON").parse().unwrap();
    let inner = call(alloy::hex::decode(format!("cfdd7aea{:064x}", 77)).unwrap(), 8);
    let call_data = inner.calldata(alloy::hex::decode(&sign(&payer, &d, &inner)[2..]).unwrap().into());
    let r = scaas_node::metatx::relay_ref(chain_id, token, &call_data);
    let Mtx::Transfer(t) = payment(payer.address(), router, 10, r, scaas_node::metatx::pay_lane(&r), MODE_RESTRICT_RELAYER, router, 0, Address::ZERO)
        else { unreachable!() };
    let fee_sig = sign(&payer, &d, &Mtx::Transfer(t.clone()));
    let relay = scaas_node::abi::IMtxRelayFee::relayCall { target: token, callData: call_data, token, t,
        sig: alloy::hex::decode(&fee_sig[2..]).unwrap().into() }.abi_encode();
    let mut rcfg = cfg.clone();
    rcfg.params = toml::toml! { relay_fee = { min_amount = 10 } };
    rcfg.params["relay_fee"].as_table_mut().unwrap().insert("router".into(), format!("{router:#x}").into());
    let before = balance(&rpc, token, relayer.address()).await;
    let mut s3 = Submitter::start(Chain::with_signer(&rcfg, relayer.clone()).unwrap(), odoo.clone(), rcfg.clone(), "e2e-3".into(), Default::default())
        .await
        .unwrap();
    state.lock().unwrap().jobs.push(json!({"id": 9, "kind": "call", "call": {"target": format!("{router:#x}"),
        "calldata": format!("0x{}", alloy::hex::encode(relay)), "validUntil": (now() + 300).to_string()}}));
    s3.poll_outbox().await;
    for _ in 0..50 {
        s3.track().await;
        if s3.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let reports = state.lock().unwrap().reports.clone();
    let of = |id: i64| reports.iter().rev().find(|r| r["job_id"] == id).unwrap().clone();
    assert_eq!(of(9)["chain_state"], "mined", "{}", of(9));
    assert_eq!(balance(&rpc, token, relayer.address()).await, before + U256::from(10u64), "the fee reached the lane");
    let lane77 = IToken::mtxNonceCall { from: payer.address(), batch: U256::from(8) }.abi_encode();
    let out = p.call(TransactionRequest::default().to(token).input(lane77.into())).await.unwrap();
    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(1u64), "the inner call ran");
    while scaas_node::indexer::step(&ichain, &odoo, Some(router)).await.unwrap() {}
    let ingested = state.lock().unwrap().ingested.clone();
    assert!(ingested.iter().all(|e| e["event"] != "RelayFeePaid"), "never a row");
    let fee = ingested.iter().find(|e| e["event"] == "PaymentSettled" && e["entry_ref"] == format!("{r:#x}")).expect("fee settled");
    assert_eq!((fee["relay_target"].as_str(), fee["relay_payee"].as_str()),
        (Some(format!("{token:#x}").as_str()), Some(format!("{:#x}", relayer.address()).as_str())));
}

fn sign_hash(signer: &PrivateKeySigner, h: B256) -> String {
    format!("0x{}", alloy::hex::encode(signer.sign_hash_sync(&h).unwrap().as_bytes()))
}

/// A `TradeOrder` on the venue's DEX: sells `amount` for at least `receive_amount` of `receive`, home-bound to the lane.
#[allow(clippy::too_many_arguments)]
fn order(from: &PrivateKeySigner, receive: Address, amount: u64, receive_amount: u64, fee: u64, nonce: u64, relayer: Address,
    dex: Address) -> TradeOrder
{
    TradeOrder {
        from: from.address(),
        receiveToken: receive,
        amount: U256::from(amount),
        receiveAmount: U256::from(receive_amount),
        minFill: U256::ZERO,
        fee: U256::from(fee),
        relayer,
        dex,
        destination: Address::ZERO,
        flags: 0,
        batch: U256::from(1),
        nonce: U256::from(nonce),
        validUntil: U256::from(now() + 600),
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
    struct DexConfig { address admin; uint32 relayerSharePpm; address treasury; bool listedOnly; }
    function createDex(uint64 version, bytes initArgs, bytes32 salt) external returns (address dex);
    function setMarket(address base, address quote, bool listed) external;
    function approve(address spender, uint256 value) external returns (bool);
    function mint(address to, uint256 value) external;
    function puller() external view returns (address);
}

/// `eth_call` then send: the return value of a state-changing call (the DEX address from `createDex`).
async fn create(rpc: &str, from: &PrivateKeySigner, to: Address, data: Vec<u8>) -> Address {
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let out = p.call(TransactionRequest::default().from(from.address()).to(to).input(data.clone().into())).await.unwrap();
    send(rpc, from, to, data).await;
    Address::abi_decode(&out).unwrap()
}

/// A plain ERC-20 the factory never made (an "outside" token): `MockERC20` from `test/helpers/Mocks.sol`, built here
/// (`forge script` compiles only the script's own sources, so the deploy leaves no test artifacts).
async fn deploy_outside_token(rpc: &str, from: &PrivateKeySigner) -> Address {
    let sc = concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm");
    let built = Command::new("forge").current_dir(sc).args(["build", "test/helpers/Mocks.sol"]).env("FOUNDRY_PROFILE", "private7622").status();
    assert!(built.expect("forge in PATH").success(), "forge build test/helpers/Mocks.sol failed");
    let raw = std::fs::read_to_string(format!("{sc}/out/Mocks.sol/MockERC20.json")).expect("forge build output of test/helpers/Mocks.sol");
    let v: Value = serde_json::from_str(&raw).unwrap();
    let mut code = alloy::hex::decode(v["bytecode"]["object"].as_str().unwrap()).unwrap();
    code.extend(("USD Coin".to_string(), "USDC".to_string(), U256::from(6u8)).abi_encode_params());
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(from.clone())).connect_http(rpc.parse().unwrap());
    let tx = alloy::network::TransactionBuilder::with_deploy_code(TransactionRequest::default(), code);
    p.send_transaction(tx).await.unwrap().get_receipt().await.unwrap().contract_address.unwrap()
}

#[tokio::test]
#[ignore]
async fn dex_order_book_settles_partial_fills_persists_and_cancels() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let chain_id = 31950; // S5 range
    let (_anvil, rpc) = start_anvil(chain_id, 18650).await;
    let alice = small_key(0xA11CE);
    let bob = small_key(0xB0B);
    let dave = small_key(0xDA7E);
    let dep = deploy(&rpc, chain_id, alice.address());
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let token_a: Address = dep["demo_token"].as_str().unwrap().parse().unwrap(); // half to alice
    // the quote token is the deploy's second demo token (half to alice as well): no `TokenConfig` encoded here
    let token_b: Address = dep["demo_token_2"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();

    // 500 B to bob, a DEX clone with a 50 % relayer share, both markets listed — plain txs from the funded deployer
    // (= DEX admin).
    let deployer = key(DEPLOYER);
    let alice_b0 = balance(&rpc, token_b, alice.address()).await;
    send(&rpc, &deployer, token_b, IToken::transferCall { to: bob.address(), value: U256::from(500_000_000u64) }.abi_encode()).await;
    let treasury = Address::repeat_byte(0x7a);
    let dex = create(&rpc, &deployer, factory, createDexCall { version: 1, initArgs: DexConfig { admin: deployer.address(),
        relayerSharePpm: 500_000, treasury, listedOnly: false }.abi_encode().into(), salt: B256::repeat_byte(0xde) }.abi_encode()).await;
    send(&rpc, &deployer, dex, setMarketCall { base: token_a, quote: token_b, listed: true }.abi_encode()).await;
    let usdc = deploy_outside_token(&rpc, &deployer).await;
    send(&rpc, &deployer, usdc, mintCall { to: dave.address(), value: U256::from(1_000_000_000u64) }.abi_encode()).await;
    send(&rpc, &deployer, dex, setMarketCall { base: token_a, quote: usdc, listed: true }.abi_encode()).await;

    let relayer = key(RELAYER);
    let lane = relayer.address();
    let cfg = chain_cfg(chain_id, &rpc, Some(dex));
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: vec![format!("{token_a:#x}"), format!("{token_b:#x}")],
        dex: format!("{dex:#x}"),
        markets: vec![
            json!({"id": 1, "base": format!("{token_a:#x}"), "quote": format!("{token_b:#x}"), "base_decimals": 6,
                   "quote_decimals": 6, "maker_fee_ppm": 1000, "taker_fee_ppm": 2000, "min_base_amount": "1000"}),
            json!({"id": 2, "base": format!("{token_a:#x}"), "quote": format!("{usdc:#x}"), "base_decimals": 6,
                   "quote_decimals": 6, "maker_fee_ppm": 0, "taker_fee_ppm": 0, "min_base_amount": "0"}),
        ],
        ..Default::default()
    }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo.clone(), cfg.clone(), "e2e".into(), Default::default())
        .await
        .unwrap();
    let shared = Arc::new(Chain::with_signer(&cfg, relayer.clone()).unwrap());
    let venue = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
    assert_eq!(venue.markets().await.len(), 2, "both markets listed on the DEX, B SCaaS and USDC outside");
    let (tx, mut rx) = mpsc::channel::<Work>(16);
    let fee_wallet = Address::repeat_byte(0xfa);
    let tokens = Arc::new(RwLock::new(vec![token_a, token_b]));
    let guard = Arc::new(scaas_node::guard::Guard::new(&cfg, tokens.clone()).unwrap());
    let gw = GwChain { chain: shared.clone(), tx, tokens, dex: Some(venue.clone()), breaker: None, fee_recipient: Some(fee_wallet), guard };
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

    // 1. R84 (review C1): `feeRecipient`/`relayer` of an open-mode `MetaTransfer` are not signed, so a client can put
    //    anything there; through the open gateway the fee still lands in our configured wallet.
    let thief = Address::repeat_byte(0x7e);
    let m = payment(alice.address(), Address::repeat_byte(0x5e), 1_000_000, B256::ZERO,
        U256::from_be_bytes(keccak256(b"e2e.r84").0), 0x20, thief, 1_000, thief); // FIXED fee, nothing bound
    let (kind, wire) = m.to_wire();
    let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": token_a, "struct": kind, "m": wire,
        "signature": sign(&alice, &token_domain(&dep, chain_id, token_a), &m)})).await;
    assert_eq!(st, 202, "{body}");
    drain(&mut s, &mut rx).await;
    assert_eq!((balance(&rpc, token_a, fee_wallet).await, balance(&rpc, token_a, thief).await), (U256::from(1_000u64), U256::ZERO));

    // SCaaS orders are signed in their sell token's salted domain: no allowance anywhere (CTR-TOK-01).
    let hash = |sell: Address, o: &TradeOrder| trade_order_hash(&domain("SCaaS MetaToken", chain_id, sell, uid), o);
    let place = |sell: Address, o: TradeOrder, signer: &PrivateKeySigner| {
        let sig = sign_hash(signer, hash(sell, &o));
        post("/v1/dex/orders", json!({"chain": chain_id, "sellToken": sell, "order": WireOrder::from_sol(&o), "signature": sig}))
    };

    // 2. Not home-bound (RS5-9) or another DEX (NODE-DEX-16) ⇒ refused at the door.
    let (st, _) = place(token_a, order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 1, Address::ZERO, dex), &alice).await;
    assert_eq!(st, 400);
    let (st, _) = place(token_a, order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 1, lane, token_b), &alice).await;
    assert_eq!(st, 400);

    // 3. The ask rests; a bid of more than half of it is the taker of one settlement (NODE-DEX-15).
    let ask = order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 2, lane, dex);
    let ask_hash = hash(token_a, &ask);
    let (st, body) = place(token_a, ask.clone(), &alice).await;
    assert_eq!((st, body["status"].as_str()), (202, Some("resting")), "{body}");
    let small = order(&bob, token_a, 80_000_000, 40_000_000, 2_000, 3, lane, dex);
    let (st, body) = place(token_b, small, &bob).await;
    assert_eq!((st, body["status"].as_str()), (202, Some("cancelled")), "below the ask's minimum fill, it cannot rest crossed: {body}");
    let bid = order(&bob, token_a, 120_000_000, 60_000_000, 2_000, 4, lane, dex);
    let (st, body) = place(token_b, bid, &bob).await;
    assert_eq!((st, body["status"].as_str()), (202, Some("filled")), "{body}");
    drain(&mut s, &mut rx).await; // the mtxSettle job went through the client outbox
    // the maker gets 120 B less its fee ceil(120e6 × 1000 / 1e6); the taker 60 A less ceil(60e6 × 2000 / 1e6);
    // half of each fee to the lane that submitted, half to the treasury
    assert_eq!(balance(&rpc, token_b, alice.address()).await, alice_b0 + U256::from(120_000_000u64 - 120_000));
    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(60_000_000u64 - 120_000));
    assert_eq!((balance(&rpc, token_b, lane).await, balance(&rpc, token_b, treasury).await), (U256::from(60_000u64), U256::from(60_000u64)));
    assert_eq!((balance(&rpc, token_a, lane).await, balance(&rpc, token_a, treasury).await), (U256::from(60_000u64), U256::from(60_000u64)));
    assert_eq!(balance(&rpc, token_a, dex).await + balance(&rpc, token_b, dex).await, U256::ZERO);

    // 4. Restart: a fresh venue on the same client has the same book.
    let before = venue.rows().await;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].remaining, "40000000");
    let venue2 = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
    assert_eq!(venue2.rows().await, before);

    // 5. A failed commit leaves the book exactly as the client has it (review D20).
    state.lock().unwrap().fail_commits = 1;
    let (st, _) = place(token_b, order(&bob, token_a, 80_000_000, 40_000_000, 2_000, 5, lane, dex), &bob).await;
    assert_eq!(st, 503);
    assert_eq!(venue.rows().await, before);

    // 6. Cancel in the token's domain: a high-s copy of a valid signature is refused like the contract would (review
    //    I4); the canonical one takes the order off the book now and closes it on the token at the next sync (an
    //    `mtxCancelOrder` entry job).
    let td = domain("SCaaS MetaToken", chain_id, token_a, uid);
    let high_s = {
        let s = alice.sign_hash_sync(&cancel_digest(&td, ask_hash)).unwrap();
        let n = U256::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
        let flipped = alloy::primitives::Signature::new(s.r(), n - s.s(), !s.v());
        format!("0x{}", alloy::hex::encode(flipped.as_bytes()))
    };
    let (st, _) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"), "signature": high_s})).await;
    assert_eq!(st, 400);
    assert_eq!(venue.rows().await, before);
    let (st, body) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"),
        "signature": sign_hash(&alice, cancel_digest(&td, ask_hash))})).await;
    assert_eq!(st, 202, "{body}");
    assert!(venue.rows().await.is_empty());
    venue.sync_once().await.unwrap();
    drain(&mut s, &mut rx).await;
    let pulled = |token: Address, h: B256| {
        let rpc = rpc.clone();
        async move {
            let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
            let out = p.call(TransactionRequest::default().to(token).input(IToken::pulledCall { orderHash: h }.abi_encode().into())).await.unwrap();
            U256::abi_decode(&out).unwrap()
        }
    };
    assert_eq!(pulled(token_a, ask_hash).await, U256::from(100_000_000u64), "closed on the token");

    // 7. The watcher brings final DEX and token events to the client with its own cursor.
    while venue.watch_once().await.unwrap() {}
    let ev = state.lock().unwrap().dex_events.clone();
    let names: Vec<&str> = ev.iter().map(|e| e["event"].as_str().unwrap()).collect();
    assert!(names.contains(&"LegSettled") && names.contains(&"OrderCancelled"), "{names:?}");
    let filled_alice = ev.iter().find(|e| e["event"] == "LegSettled" && e["order_hash"] == format!("{ask_hash:#x}")).unwrap();
    assert_eq!((filled_alice["dex_fee"].as_str(), filled_alice["relayer_share"].as_str()), (Some("120000"), Some("60000")));
    assert_eq!(state.lock().unwrap().dex_trades.len(), 1);

    // 8. A settle job that dies: the client marks its trade failed, sync hands both healthy sides back and they
    //    trade again as a NEW trade (no crossed book, no tag collision).
    let ask3 = order(&alice, token_b, 10_000_000, 20_000_000, 1_000, 7, lane, dex);
    let bid3 = order(&bob, token_a, 20_000_000, 10_000_000, 2_000, 8, lane, dex);
    assert_eq!(place(token_a, ask3.clone(), &alice).await.1["status"], "resting");
    assert_eq!(place(token_b, bid3.clone(), &bob).await.1["status"], "filled");
    let dead_tag = {
        let mut o = state.lock().unwrap();
        o.jobs.clear(); // the settle job never reaches the chain
        let t = o.dex_trades.last().unwrap().clone();
        let row = |h: B256| row_of(&o.orders[&format!("{h:#x}")]);
        let f = json!({"tag": t["tag"], "taker": {"row": row(hash(token_b, &bid3)), "fill": t["taker_fill"]},
                       "makers": [{"row": row(hash(token_a, &ask3)), "fill": t["makers"][0]["fill"]}]});
        o.failed.push(f);
        t["tag"].clone()
    };
    venue.sync_once().await.unwrap();
    let last = state.lock().unwrap().dex_trades.last().unwrap().clone();
    assert_ne!(last["tag"], dead_tag);
    assert!(venue.rows().await.is_empty(), "both sides traded again; nothing rests crossed");
    drain(&mut s, &mut rx).await;
    assert_eq!(balance(&rpc, token_b, alice.address()).await, alice_b0 + U256::from(119_880_000u64 + 20_000_000 - 20_000));
    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(59_880_000u64 + 10_000_000 - 20_000));

    // 9. A dead trade whose taker is closed in the client (null row, review I3): the maker alone goes back to the
    //    book AND to the client, so a restart still has it.
    let ask4 = order(&alice, token_b, 10_000_000, 20_000_000, 1_000, 9, lane, dex);
    let bid4 = order(&bob, token_a, 20_000_000, 10_000_000, 2_000, 10, lane, dex);
    let ask4_hash = format!("{:#x}", hash(token_a, &ask4));
    assert_eq!(place(token_a, ask4.clone(), &alice).await.1["status"], "resting");
    assert_eq!(place(token_b, bid4.clone(), &bob).await.1["status"], "filled");
    {
        let mut o = state.lock().unwrap();
        o.jobs.clear();
        let t = o.dex_trades.last().unwrap().clone();
        let r = o.orders[&ask4_hash].clone();
        assert_eq!(r["state"], "filled");
        o.failed.push(json!({"tag": t["tag"], "taker": {"row": null, "fill": t["taker_fill"]},
                             "makers": [{"row": row_of(&r), "fill": t["makers"][0]["fill"]}]}));
    }
    venue.sync_once().await.unwrap();
    let rows = venue.rows().await;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].order_hash.as_str(), rows[0].remaining.as_str()), (ask4_hash.as_str(), "10000000"));
    let stored = state.lock().unwrap().orders[&ask4_hash].clone();
    assert_eq!((stored["state"].as_str(), stored["remaining"].as_str()), (Some("open"), Some("10000000")));
    let venue3 = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
    assert_eq!(venue3.rows().await, rows);

    // 10. Cancel-all on the token's order lane (`InvalidateNonces` in A's domain, an `mtxInvalidateNonces` entry job).
    let (st, body) = post("/v1/dex/cancel-all", json!({"chain": chain_id, "sellToken": token_a, "from": alice.address(),
        "batch": "1", "minNonce": "21", "signature": sign_hash(&alice, invalidate_digest(&td, alice.address(), U256::from(1), U256::from(21)))})).await;
    assert_eq!((st, body["orders"].as_u64()), (202, Some(1)), "{body}");
    assert!(venue.rows().await.is_empty());
    venue.sync_once().await.unwrap();
    drain(&mut s, &mut rx).await;
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let min = IToken::minNonceCall { from: alice.address(), batch: U256::from(1) }.abi_encode();
    let out = p.call(TransactionRequest::default().to(token_a).input(min.into())).await.unwrap();
    assert_eq!(U256::abi_decode(&out).unwrap(), U256::from(21));

    // 11. An outside token (CTR-DEX-18, -22): dave's USDC order is a `DexOrder` in the DEX's domain, pulled through
    //     the `DexPuller` he approved (never the DEX); alice's A order takes it.
    let pull = {
        let out = p.call(TransactionRequest::default().to(dex).input(pullerCall {}.abi_encode().into())).await.unwrap();
        Address::abi_decode(&out).unwrap()
    };
    let _: Value = p.raw_request("anvil_setBalance".into(), (dave.address(), "0xde0b6b3a7640000")).await.unwrap();
    send(&rpc, &dave, usdc, approveCall { spender: pull, value: U256::MAX }.abi_encode()).await;
    let dd = domain("SCaaS Dex", chain_id, dex, uid);
    let usd = order(&dave, token_a, 200_000_000, 100_000_000, 0, 30, lane, dex);
    let usd_hash = dex_order_hash(&dd, usdc, &usd);
    let (st, body) = post("/v1/dex/orders", json!({"chain": chain_id, "sellToken": usdc, "order": WireOrder::from_sol(&usd),
        "signature": sign_hash(&dave, usd_hash)})).await;
    assert_eq!((st, body["status"].as_str(), body["order_hash"].as_str()), (202, Some("resting"), Some(&*format!("{usd_hash:#x}"))), "{body}");
    let take = order(&alice, usdc, 100_000_000, 200_000_000, 0, 31, lane, dex);
    assert_eq!(place(token_a, take, &alice).await.1["status"], "filled");
    drain(&mut s, &mut rx).await;
    assert_eq!(balance(&rpc, usdc, alice.address()).await, U256::from(200_000_000u64));
    assert_eq!(balance(&rpc, token_a, dave.address()).await, U256::from(100_000_000u64));
    assert_eq!(balance(&rpc, usdc, dex).await + balance(&rpc, usdc, pull).await, U256::ZERO);
}

fn pay_job(payer: &PrivateKeySigner, dep: &Value, chain_id: u64, token: Address, id: i64, tag: &[u8]) -> Value {
    let entry_ref = keccak256(tag);
    let m = payment(payer.address(), Address::repeat_byte(0x5e), 1_000, entry_ref, U256::from_be_bytes(entry_ref.0), 0,
        Address::ZERO, 0, Address::ZERO);
    let d = token_domain(dep, chain_id, token);
    job(id, token, &m, &format!("{:#x}", m.digest(&d)), sign(payer, &d, &m))
}

/// R80 (S2, review H3): another relayer lands OUR intent. (1) While our tx is pending (dropped from anvil's pool so the
/// next block cannot include it — anvil evicts, rather than keeps, a tx under the base fee, review N11): the stuck re-check sees the subject nonce spent, reports `consumed`, never resends the meta-tx and frees the
/// outer nonce with a gap-filler (R18). (2) Same block, the peer pays more tip: our tx is mined and reverts ⇒ still
/// `consumed`, never `reverted`. No `dead`/`reverted` for either job; each payment lands exactly once.
#[tokio::test]
#[ignore]
async fn a_peer_landing_our_intent_makes_the_job_consumed_never_dead() {
    let chain_id = 31904;
    let (_anvil, rpc) = start_anvil(chain_id, 31904).await;
    let payer = small_key(0xC0FFEE);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let relayer = key(RELAYER);
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let peer = ProviderBuilder::new().wallet(EthereumWallet::from(key(DEPLOYER))).connect_http(rpc.parse().unwrap());
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut cfg = chain_cfg(chain_id, &rpc, None);
    cfg.stuck_after_secs = 1;
    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo, cfg, "e2e".into(), Default::default())
        .await
        .unwrap();
    let _: Value = p.raw_request("evm_setAutomine".into(), (false,)).await.unwrap();
    let gwei = 1_000_000_000u128;
    let mine = || async { p.raw_request::<_, Value>("evm_mine".into(), ()).await.unwrap() };
    let peer_sends = |job: &Value, max_fee: u128, tip: u128| {
        let w = work_from_job(&serde_json::from_value(job.clone()).unwrap(), None).unwrap();
        let tx = TransactionRequest::default().to(w.to).input(w.data.into()).gas_limit(500_000).max_fee_per_gas(max_fee).max_priority_fee_per_gas(tip);
        let peer = peer.clone();
        async move { peer.send_transaction(tx).await.unwrap() }
    };
    let states = |id: i64| -> Vec<String> {
        state.lock().unwrap().reports.iter().filter(|r| r["job_id"] == id).map(|r| r["chain_state"].as_str().unwrap().to_string()).collect()
    };
    let error = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).unwrap()["error"].clone();

    // (1) Ours pending, the peer's lands.
    let j1 = pay_job(&payer, &dep, chain_id, token, 41, b"r80-stuck");
    state.lock().unwrap().jobs.push(j1.clone());
    s.poll_outbox().await;
    assert_eq!(states(41), ["signed", "broadcast"]);
    let ours = state.lock().unwrap().reports.iter().find(|r| r["job_id"] == 41).unwrap()["tx_hash"].clone();
    let _: Value = p.raw_request("anvil_dropTransaction".into(), (ours,)).await.unwrap();
    let landed = peer_sends(&j1, 50 * gwei, 2 * gwei).await;
    mine().await;
    assert!(landed.get_receipt().await.unwrap().status(), "the peer landed it");
    let before = BUMP_SKIPPED_CONSUMED.load(std::sync::atomic::Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    s.track().await;
    assert!(BUMP_SKIPPED_CONSUMED.load(std::sync::atomic::Ordering::Relaxed) > before);
    assert_eq!(states(41), ["signed", "broadcast", "consumed"]);
    assert_eq!(error(41), "landed_elsewhere");
    let pool: Value = p.raw_request("txpool_content".into(), ()).await.unwrap();
    let ours = pool["pending"].as_object().unwrap().iter().find(|(k, _)| k.eq_ignore_ascii_case(&format!("{:#x}", relayer.address()))).unwrap_or_else(|| panic!("{pool}")).1;
    let at0 = &ours["0"];
    assert_eq!((at0["input"].as_str(), at0["to"].as_str().map(str::to_lowercase)), (Some("0x"), Some(format!("{:#x}", relayer.address()))),
        "outer nonce 0 now carries a gap-filler, never the meta-tx again: {at0}");
    mine().await;
    for _ in 0..30 {
        s.track().await;
        if s.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(s.inflight_count(), 0, "the gap-filler settles the outer nonce");
    assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), 1, "R18: no outer nonce abandoned");

    // (2) Same block, the peer outbids our tip: our tx is mined and reverts.
    let j2 = pay_job(&payer, &dep, chain_id, token, 42, b"r80-race");
    state.lock().unwrap().jobs.push(j2.clone());
    s.poll_outbox().await;
    assert_eq!(states(42), ["signed", "broadcast"]);
    let landed = peer_sends(&j2, 50 * gwei, 10 * gwei).await;
    mine().await;
    assert!(landed.get_receipt().await.unwrap().status());
    for _ in 0..30 {
        s.track().await;
        if s.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(s.inflight_count(), 0);
    assert_eq!(states(42), ["signed", "broadcast", "consumed"], "our reverted receipt is not `reverted`");
    assert_eq!(error(42), "landed_elsewhere");
    assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), 2, "our losing tx was mined (and reverted)");

    assert!(state.lock().unwrap().refused.is_empty(), "{:?}", state.lock().unwrap().refused);
    assert_eq!(balance(&rpc, token, Address::repeat_byte(0x5e)).await, U256::from(2_000u64), "each payment once");
}

/// R58/R62: the same EVM chain driven through the generic `ChainAdapter` + `lane_step` +
/// `index_step` path, with TWO relayer lanes derived from a 24-word mnemonic: each lane signs with
/// its own key, both payments land, the indexer ingests both.
#[tokio::test]
#[ignore]
async fn evm_adapter_runs_the_generic_lane_runner_on_two_mnemonic_lanes() {
    use scaas_node::adapter::{index_step, lane_step, ChainAdapter};
    use scaas_node::adapters::evm::EvmAdapter;
    use scaas_node::keys::{lane_secret, Seed};
    use scaas_node::signer::LocalSigner;

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
    state.lock().unwrap().jobs.push(pay_job(&payer, &dep, chain_id, token, 11, b"generic-1"));
    assert!(lane_step(&adapter, &odoo, 0, "e2e#0").await.unwrap());
    state.lock().unwrap().jobs.push(pay_job(&payer, &dep, chain_id, token, 12, b"generic-2"));
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
