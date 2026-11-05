//! cargo test --test e2e -- --ignored --nocapture
//!
//! Cần `anvil` và `forge` trong PATH. Chứng minh trên EVM thật với contract thật, on the merged entries (CTR-MTX-30,
//! ua-mtx-merge T18): every token, router and mandate-wallet job is a `ua_metatx` job (`UAMetaTransfer` / a named `UA<Op>` on
//! `bytes32` ids, `auth` a `UASig`); an EOA signs with its own key, no registry call (registry 0 too), fee 0 relayable.
//! 1. job outbox (giả Odoo) → simulate → ký → `signed` trước khi gửi → broadcast → receipt → the chain's UA events
//!    (`UAPaymentSettled`, `UAMetaTransactionExecuted`, never the address ones, R18) → indexer gửi `PaymentSettled` +
//!    `MetaTransactionExecuted` vùng final (the client's row names for both shapes);
//! 2. DEX (R35, NODE-DEX-15) on a `SCaaSDex` clone: a SCaaS sell token's `UATradeOrder` in its domain (`auth`), an outside
//!    token's `DexOrder` in the DEX's domain, through the gateway → one settlement per taker → `mtxSettle` job through
//!    the outbox (fake Odoo) → balances, fees, relayer share; restart ⇒ same book; the UA cancels on the token (`ua_metatx`
//!    entry jobs) and on the DEX; the watcher brings final events back (`UALegSettled` for a SCaaS leg). No signer holds a wei
//!    of gas.
//! 3. The three gateway doors, the ordered cancel, a derived subject, an EOA to a UA, a relayed Zether proof under the UA tag
//!    and a mandate payment by an EOA delegate, each on its own anvil.
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{SolCall, SolEvent, SolValue};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use scaas_node::abi::{IMtxIds, IToken, IUALedger, UAMetaTransaction, UAMetaTransfer, UASig};
use scaas_node::chain::Chain;
use scaas_node::config::{ChainCfg, FinalityCfg, OdooCfg};
use scaas_node::dex::venue::Venue;
use scaas_node::abi::TradeOrder;
use scaas_node::dex::{cancel_digest, canon, dex_order_hash, domain, trade_order_hash, ua_invalidate_digest, WireOrder};
use scaas_node::gateway::{router, AppState, GwChain};
use scaas_node::metatx::{Domain, UaMtx, MODE_RESTRICT_RELAYER};
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

/// The block gas limit is the SCaaS testnet's (genesis 200 M, NET-EVM-06): a creation's forge estimate (x1.30 here, no
/// `--gas-estimate-multiplier`) must fit it.
async fn start_anvil(chain_id: u64, port: u16) -> (Anvil, String) {
    let child = Command::new("anvil")
        .args(["--chain-id", &chain_id.to_string(), "--hardfork", "amsterdam", "--gas-limit", "200000000", "--code-size-limit", "65536", "--port", &port.to_string(), "--silent"])
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

fn sc() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm")
}

/// Deploy factory + implementation + DEX + token demo (một nửa cung cho `holder`).
fn deploy(rpc: &str, chain_id: u64, holder: Address) -> Value {
    deploy_with(rpc, chain_id, holder, false)
}

/// As [`deploy`]; `zether`: the Zether stack too (`DEPLOY_ZETHER=1`, `deploy.sh`'s `--gas-estimate-multiplier 105`).
fn deploy_with(rpc: &str, chain_id: u64, holder: Address, zether: bool) -> Value {
    let sc = sc();
    let mut cmd = Command::new("forge");
    cmd.current_dir(sc)
        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--slow", "--silent", "--disable-code-size-limit", "--sender", DEPLOYER_ADDRESS]);
    if zether {
        cmd.args(["--gas-estimate-multiplier", "105"]).env("DEPLOY_ZETHER", "true");
    }
    let status = cmd
        .env("PRIVATE_KEY", DEPLOYER)
        .env("DEMO_SUPPLY", "1000000000000")
        .env("DEMO_HOLDER", format!("{holder:#x}"))
        .env("FOUNDRY_PROFILE", "scaas-testnet")
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
            // the client's `_decode` (bamboo-dms 81cea08, review C1): an EVM row's addresses are 0x + 40 hex, or the
            // whole range is refused
            let addr = |v: &Value| v.as_str().is_some_and(|s| s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit()));
            if let Some(bad) = body["events"].as_array().unwrap().iter()
                .find(|e| ["contract", "from", "to", "fee_recipient", "relayer"].iter().any(|k| !e[*k].is_null() && !addr(&e[*k]))) {
                o.refused.push(bad.clone());
                return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": format!("not an EVM address in {bad}")})));
            }
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
                // every job carries its named op; a client keeps the kind it was given (`settle` and `cancel` go as `call`, a
                // SCaaS leg's cancel and invalidate as `ua_metatx`, R43)
                let kind = j["kind"].as_str().filter(|k| matches!(*k, "metatx" | "ua_metatx")).unwrap_or("call");
                o.jobs.push(json!({"id": id, "kind": kind, "op": j["op"]}));
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

/// A stored order as `dex_book_load` / `dex_sync` return it: a SCaaS leg's `auth` (T17) beside an outside leg's `signature`.
fn row_of(r: &Value) -> Value {
    let mut row = json!({"order_hash": r["order_hash"], "sell_token": r["sell_token"], "order": r["order"], "signature": r["signature"],
           "remaining": r["remaining"], "seq": r["seq"]});
    if !r["auth"].is_null() {
        row["auth"] = r["auth"].clone();
    }
    row
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

/// A native id's `UASig` (R17: no key data, no members): its own ECDSA signature over `h`.
fn native_auth(signer: &PrivateKeySigner, h: B256) -> Value {
    json!({"keyData": "0x", "signature": format!("0x{}", alloy::hex::encode(signer.sign_hash_sync(&h).unwrap().as_bytes())), "members": []})
}

/// `signer`'s `UASig` over the token's digest of `m`.
fn sign(signer: &PrivateKeySigner, d: &Domain, m: &UaMtx) -> Value {
    native_auth(signer, m.digest(d))
}

/// A payment `UAMetaTransfer` (`entryRef` = `r`) on lane `batch` between two native ids.
#[allow(clippy::too_many_arguments)]
fn payment(from: Address, to: Address, value: u64, r: B256, batch: U256, mode: u32, relayer: Address, fee: u64,
    fee_recipient: Address) -> UaMtx
{
    ua_payment(from.into_word(), to.into_word(), value, r, batch, mode, relayer, fee, fee_recipient)
}

/// A payment `UAMetaTransfer` between ids.
#[allow(clippy::too_many_arguments)]
fn ua_payment(from: B256, to: B256, value: u64, r: B256, batch: U256, mode: u32, relayer: Address, fee: u64, fee_recipient: Address) -> UaMtx {
    UaMtx::Transfer(UAMetaTransfer {
        from, to, value: U256::from(value), entryRef: r, batch, nonce: U256::ZERO, validUntil: U256::from(now() + 300),
        mode, relayer, fee: U256::from(fee), feeRecipient: fee_recipient,
    })
}

/// An outbox `ua_metatx` job as the client stores it: `struct` names the signed struct (CTR-MTX-15), `auth` its `UASig`.
fn job(id: i64, token: Address, m: &UaMtx, digest: &str, auth: Value) -> Value {
    let (kind, wire) = m.to_wire();
    json!({"id": id, "kind": "ua_metatx", "token": format!("{token:#x}"), "digest": digest, "auth": auth, "struct": kind, "m": wire})
}

/// R18 on the chain: a merged entry's receipt carries the UA events and neither address event.
async fn merged_events_only(rpc: &str, tx: &str) {
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let rc = p.get_transaction_receipt(tx.parse().unwrap()).await.unwrap().expect("a receipt");
    let topics: Vec<B256> = rc.inner.logs().iter().filter_map(|l| l.topic0().copied()).collect();
    for t in [IUALedger::UAPaymentSettled::SIGNATURE_HASH, IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH] {
        assert!(topics.contains(&t), "{tx}: no UA event {t:#x}");
    }
    for t in [IToken::PaymentSettled::SIGNATURE_HASH, IToken::MetaTransactionExecuted::SIGNATURE_HASH] {
        assert!(!topics.contains(&t), "{tx}: an address event {t:#x} on a merged path");
    }
}

/// The hash of job `id`'s first signed transaction.
fn tx_of(state: &Arc<Mutex<FakeOdoo>>, id: i64) -> String {
    state.lock().unwrap().reports.iter().find(|r| r["job_id"] == id && r["chain_state"] == "signed")
        .map(|r| r["tx_hash"].as_str().unwrap().to_string()).expect("a signed report")
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
    let auth = sign(&payer, &d, &m);
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: vec![format!("{token:#x}")],
        receiving: vec![json!({"token": format!("{token:#x}"), "address": format!("{shop:#x}")})],
        ..Default::default()
    }));
    state.lock().unwrap().jobs.push(job(1, token, &m, "0x", auth));
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
    merged_events_only(&rpc, reports[0]["tx_hash"].as_str().unwrap()).await;

    let ichain = Chain::with_signer(&cfg, relayer.clone()).unwrap();
    assert!(scaas_node::indexer::step(&ichain, &odoo, None).await.unwrap());
    let ingested = state.lock().unwrap().ingested.clone();
    let pay = ingested.iter().find(|e| e["event"] == "PaymentSettled").expect("PaymentSettled ingested");
    assert_eq!(pay["entry_ref"], format!("{entry_ref:#x}"));
    // a native id is its address on the row, no `from_ua` (indexer::put_id)
    assert_eq!((pay["from"].as_str(), pay.get("from_ua")), (Some(format!("{:#x}", payer.address()).as_str()), None));
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
    // before simulation; a meta-transaction to a contract that is not a registered token (here: no contract) too. The address
    // `MetaTransfer` job of before the merge is refused by name (R43), nothing sent.
    let steal = IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1u64) }.abi_encode();
    let mut jobs = vec![json!({"id": 3, "kind": "call", "call": {"target": format!("{token:#x}"),
        "calldata": format!("0x{}", alloy::hex::encode(steal)), "validUntil": (now() + 300).to_string()}}),
        json!({"id": 33, "kind": "call", "op": {"entry": "transfer", "token": format!("{token:#x}"), "args": {}}})];
    let elsewhere = Address::repeat_byte(0x99);
    jobs.push(job(4, elsewhere, &m, "0x", sign(&payer, &token_domain(&dep, chain_id, elsewhere), &m)));
    let (kind, mut old) = m.to_wire();
    (old["from"], old["to"]) = (json!(format!("{:#x}", payer.address())), json!(format!("{shop:#x}")));
    jobs.push(json!({"id": 44, "token": format!("{token:#x}"), "digest": "0x", "struct": kind, "metatx": old,
        "signature": format!("0x{}", "11".repeat(65))}));
    state.lock().unwrap().jobs.extend(jobs);
    let nonce = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_count(relayer.address()).await.unwrap();
    s.poll_outbox().await;
    let reports = state.lock().unwrap().reports.clone();
    let of = |id: i64| reports.iter().rev().find(|r| r["job_id"] == id).unwrap().clone();
    assert_eq!(of(3)["chain_state"], "dead");
    assert!(of(3)["error"].as_str().unwrap().contains("HEX_DATA_REFUSED"), "{}", of(3));
    assert!(of(33)["error"].as_str().unwrap().contains("UNKNOWN_ENTRY"), "{}", of(33));
    assert_eq!(of(4)["chain_state"], "dead");
    assert!(of(4)["error"].as_str().unwrap().starts_with("TOKEN_NOT_SERVED"), "{}", of(4));
    assert_eq!(of(44)["chain_state"], "dead");
    assert!(of(44)["error"].as_str().unwrap().contains("OP_KIND_MISMATCH"), "{}", of(44));
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), nonce, "nothing signed or sent");

    // Against the real token: a `call` struct is hex, refused before simulation; the named merged `mtxCancelNonce` (Q2: on its
    // own lane, nonce-ordered) lands at fee 0, its typed digest computed by the node, and moves the payer's lane 99.
    let call = |data: Vec<u8>, batch: u64| UaMtx::Call(UAMetaTransaction { from: payer.address().into_word(), data: data.into(),
        batch: U256::from(batch), nonce: U256::ZERO, validUntil: U256::from(now() + 300), mode: 0, relayer: Address::ZERO,
        fee: U256::ZERO, feeRecipient: Address::ZERO });
    let bad = call(IToken::transferCall { to: Address::repeat_byte(0x7e), value: U256::from(1u64) }.abi_encode(), 5);
    // the node reads no digest from a contract any more, so the contract checks the local ones here, on the live token
    let UaMtx::Call(ref as_call) = bad else { unreachable!() };
    assert_eq!(view(&rpc, token, IMtxIds::mtxDigestCall { m: as_call.clone() }).await, bad.digest(&d), "mtxDigest");
    let UaMtx::Transfer(ref as_transfer) = m else { unreachable!() };
    assert_eq!(view(&rpc, token, IMtxIds::mtxTransferDigestCall { t: as_transfer.clone() }).await, m.digest(&d), "mtxTransferDigest");
    let good = json!({"id": 6, "kind": "ua_metatx", "op": signed_op(&payer, cancel_op(payer.address(), token, 99, 6), chain_id, d.salt)});
    state.lock().unwrap().jobs.extend([job(5, token, &bad, "0x", sign(&payer, &d, &bad)), good]);
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
    assert!(of(5)["error"].as_str().unwrap().contains("HEX_DATA_REFUSED"), "{}", of(5));
    assert_eq!(of(6)["chain_state"], "mined", "{}", of(6));
    assert_eq!(view(&rpc, token, IMtxIds::mtxNonceCall { from: payer.address().into_word(), batch: U256::from(99) }).await, U256::from(1u64));

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
    // node relays `relay` (call-table row MtxRelayFee.relay, the `UARelayFee` of the payer's padded id), the fee reaches the
    // lane, the indexer joins RelayFeePaid
    let router: Address = dep["mtx_relay_fee"].as_str().expect("mtx_relay_fee in the deploy JSON").parse().unwrap();
    let out = p.call(TransactionRequest::default().to(router).input(scaas_node::abi::IMtxRelayFee::EXECUTORCall {}.abi_encode().into()))
        .await.unwrap();
    assert_eq!(Address::abi_decode(&out).unwrap(), router.create(1), "the executor the node derives (never paid)");
    let inner = signed_op(&payer, cancel_op(payer.address(), token, 77, 8), chain_id, d.salt);
    let parsed = scaas_node::typed::Op::parse(&inner, None).unwrap();
    let r = scaas_node::metatx::relay_ref(chain_id, token, &parsed.data);
    let inner_digest = parsed.typed.digest_on(chain_id, d.salt).unwrap();
    let relay = signed_op(&payer, json!({"entry": "mtxRelayFee", "contract": "token", "token": format!("{token:#x}"), "call": inner,
        "args": {"from": format!("{:#x}", payer.address().into_word()), "payee": format!("{:#x}", router.into_word()), "value": "10",
            "validUntil": (now() + 300).to_string(), "relayer": format!("{router:#x}")}}), chain_id, d.salt);
    let mut rcfg = cfg.clone();
    rcfg.params = toml::toml! { relay_fee = { min_amount = 10 } };
    rcfg.params["relay_fee"].as_table_mut().unwrap().insert("router".into(), format!("{router:#x}").into());
    let before = balance(&rpc, token, relayer.address()).await;
    let mut s3 = Submitter::start(Chain::with_signer(&rcfg, relayer.clone()).unwrap(), odoo.clone(), rcfg.clone(), "e2e-3".into(), Default::default())
        .await
        .unwrap();
    state.lock().unwrap().jobs.push(json!({"id": 9, "kind": "ua_metatx", "op": relay}));
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
    assert_eq!(view(&rpc, token, IMtxIds::mtxNonceCall { from: payer.address().into_word(), batch: U256::from(8) }).await, U256::from(1u64),
        "the inner call ran");
    while scaas_node::indexer::step(&ichain, &odoo, Some(router)).await.unwrap() {}
    let ingested = state.lock().unwrap().ingested.clone();
    assert!(ingested.iter().all(|e| e["event"] != "RelayFeePaid"), "never a row");
    assert!(ingested.iter().any(|e| e["event"] == "MetaTransactionExecuted" && e["digest"] == format!("{inner_digest:#x}")),
        "the chain emitted the named entry's digest as the node computed it");
    let fee = ingested.iter().find(|e| e["event"] == "PaymentSettled" && e["entry_ref"] == format!("{r:#x}")).expect("fee settled");
    assert_eq!((fee["relay_target"].as_str(), fee["relay_payee"].as_str()),
        (Some(format!("{token:#x}").as_str()), Some(format!("{:#x}", relayer.address()).as_str())));

    // T17 fix 1 (spec §9, R8): a SmartKeyAccount-signed mtxExecute(UAMetaTransaction, UASig) (a native contract id: its address
    // padded, ERC-1271 over `auth.signature`) sent with exactly the node's ERC-1271 floor for its calldata settles (the ERC-1271
    // call two frames below the token keeps its 400 k cap)
    let owner = small_key(0x5ca);
    let factory: Address = dep["smart_key_account_factory"].as_str().unwrap().parse().unwrap();
    let first = SubjectKey { kind: 2, x: owner.address().into_word(), y: B256::ZERO, rpIdHash: B256::ZERO, originHash: B256::ZERO };
    let acct = create(&rpc, &relayer, factory, deployCall { firstKey: first, guardian: Address::repeat_byte(0x6a) }.abi_encode()).await;
    let m = UaMtx::Call(UAMetaTransaction { from: acct.into_word(), data: alloy::hex::decode(format!("cfdd7aea{:064x}", 9)).unwrap().into(),
        batch: U256::from(3), nonce: U256::ZERO, validUntil: U256::from(now() + 300), mode: 0, relayer: Address::ZERO, fee: U256::ZERO,
        feeRecipient: Address::ZERO });
    let ecdsa = owner.sign_hash_sync(&m.digest(&d)).unwrap().as_bytes().to_vec();
    let sig = (U256::ZERO, Vec::<B256>::new(), Bytes::from(ecdsa)).abi_encode_params();
    let data = m.calldata(UASig { keyData: Bytes::new(), signature: sig.into(), members: vec![] });
    let floor = scaas_node::guard::erc1271_floor(data.len());
    let w = ProviderBuilder::new().wallet(EthereumWallet::from(relayer.clone())).connect_http(rpc.parse().unwrap());
    let rc = w.send_transaction(TransactionRequest::default().to(token).input(data.into()).gas_limit(floor)).await.unwrap()
        .get_receipt().await.unwrap();
    assert!(rc.status(), "settles at the floor {floor} (used {})", rc.gas_used);
    assert_eq!(view(&rpc, token, IMtxIds::mtxNonceCall { from: acct.into_word(), batch: U256::from(3) }).await, U256::from(1u64),
        "the account's lane moved");
}

fn sign_hash(signer: &PrivateKeySigner, h: B256) -> String {
    format!("0x{}", alloy::hex::encode(signer.sign_hash_sync(&h).unwrap().as_bytes()))
}

/// A `TradeOrder` on the venue's DEX: sells `amount` for at least `receive_amount` of `receive`, home-bound to the lane.
/// The plain rows against forge's ABI: names and order of every argument and nested field, which a selector cannot pin
/// (`pop` / `pqzPop` swapped keep it). Reads `out/`: the deploy of any other test here builds it.
#[test]
#[ignore]
fn plain_rows_match_the_forge_abi() {
    use scaas_node::typed::{nested, rows};
    fn same(inputs: &[Value], fields: &[(String, String)], at: &str) {
        assert_eq!(inputs.len(), fields.len(), "{at}");
        for (i, (ty, name)) in inputs.iter().zip(fields) {
            let abi = i["type"].as_str().unwrap();
            // `SmartKeyAccount.mtxExecuteAsOwner` calls its last argument `signature`, the wallet `sig`: one row, the position counts
            let abi_name = i["name"].as_str().unwrap().trim_end_matches('_');
            assert!(abi_name == name || (abi_name == "signature" && name == "sig"), "{at}: {abi_name} / {name}");
            let base = ty.trim_end_matches("[]");
            match nested(base) {
                Some(f) => {
                    assert_eq!(abi.trim_start_matches("tuple"), &ty[base.len()..], "{at}.{name}");
                    same(i["components"].as_array().unwrap(), f, &format!("{at}.{name}"));
                }
                None => assert_eq!(abi, ty, "{at}.{name}"),
            }
        }
    }
    let mut n = 0;
    for r in rows().iter().filter(|r| !r.typed) {
        for c in r.contracts {
            // ua-mtx-merge T18 (MD-11 (a)): no plain row is left on a mandate wallet (`mtxExecuteAsOwner(Raw)`, the flat
            // `mtxPayUnderMandate` / `mtxRevoke` in `legacy/ua-mtx-merge/typed.rs`)
            let art = match *c {
                "dex" => "ISCaaSDex",
                "registry" => "IUARegistry",
                "factory" => "SmartKeyAccountFactory",
                "account" => "SmartKeyAccount",
                other => panic!("a plain row on {other}: {}", r.entry),
            };
            let p = format!("{}/../smartcontracts/evm/out/{art}.sol/{art}.json", env!("CARGO_MANIFEST_DIR"));
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e} (forge build)"))).unwrap();
            let f = v["abi"].as_array().unwrap().iter()
                .find(|f| f["type"] == "function" && f["name"] == r.entry && f["inputs"].as_array().unwrap().len() == r.fields.len())
                .unwrap_or_else(|| panic!("{art}.{} with {} arguments", r.entry, r.fields.len()));
            same(f["inputs"].as_array().unwrap(), &r.fields, r.entry);
            n += 1;
        }
    }
    assert_eq!(n, 18, "18 rows, one contract each (22 before MD-11 (a): the wallet's four flat rows retired)");
}

/// The `UAEnvelope` of a native signer `from` (its padded id) on lane `batch` at `nonce`, fee 0, open relayer.
fn envelope(from: Address, batch: U256, nonce: u64) -> Value {
    let z = format!("{:#x}", Address::ZERO);
    json!({"from": format!("{:#x}", from.into_word()), "batch": batch.to_string(), "nonce": nonce.to_string(),
        "validUntil": (now() + 300).to_string(), "mode": 0, "relayer": z, "fee": "0", "feeRecipient": z})
}

/// The merged `mtxCancelNonce(UAEnvelope, lane, UASig)` (`UACancelNonce`, Q2) of `from` on `token`, on its own lane `batch`.
fn cancel_op(from: Address, token: Address, lane: u64, batch: u64) -> Value {
    json!({"entry": "mtxCancelNonce", "contract": "token", "token": format!("{token:#x}"), "args": {"lane": lane.to_string()},
        "envelope": envelope(from, U256::from(batch), 0)})
}

/// `op` signed by `key` (a native id's `UASig`) over the typed digest the node computes for it.
fn signed_op(key: &PrivateKeySigner, mut op: Value, chain_id: u64, uid: B256) -> Value {
    op["auth"] = json!({"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []});
    let d = scaas_node::typed::Op::parse(&op, None).unwrap().typed.digest_on(chain_id, uid).unwrap();
    op["auth"] = native_auth(key, d);
    op
}

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
    // `owner` a UA id (CTR-GOV-01 Change): a native account's is its address padded to 32 bytes
    struct DexConfig { bytes32 owner; uint32 relayerSharePpm; address treasury; bool listedOnly; uint64 grantDelay; address rescueTo; }
    function createDex(uint64 version, bytes initArgs, bytes32 salt) external returns (address dex);
    function setMarket(address base, address quote, bool listed) external;
    function approve(address spender, uint256 value) external returns (bool);
    function mint(address to, uint256 value) external;
    function puller() external view returns (address);
    function listedOnly() external view returns (bool);
    struct SubjectKey { uint8 kind; bytes32 x; bytes32 y; bytes32 rpIdHash; bytes32 originHash; }
    function deploy(SubjectKey firstKey, address guardian) external returns (address account);
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
    let built = Command::new("forge").current_dir(sc).args(["build", "test/helpers/Mocks.sol"]).env("FOUNDRY_PROFILE", "scaas-testnet").status();
    assert!(built.expect("forge in PATH").success(), "forge build test/helpers/Mocks.sol failed");
    let raw = std::fs::read_to_string(format!("{sc}/out/Mocks.sol/MockERC20.json")).expect("forge build output of test/helpers/Mocks.sol");
    let v: Value = serde_json::from_str(&raw).unwrap();
    let mut code = alloy::hex::decode(v["bytecode"]["object"].as_str().unwrap()).unwrap();
    code.extend(("USD Coin".to_string(), "USDC".to_string(), U256::from(6u8)).abi_encode_params());
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(from.clone())).connect_http(rpc.parse().unwrap());
    let tx = alloy::network::TransactionBuilder::with_deploy_code(TransactionRequest::default(), code);
    p.send_transaction(tx).await.unwrap().get_receipt().await.unwrap().contract_address.unwrap()
}

/// The node's book on the merged DEX leg (§3.4, CTR-DEX-26, T17 on a chain): a SCaaS sell token's order is a `UATradeOrder` in
/// its token's domain with `auth`, an outside token's a `DexOrder`; partial fills, persistence across a restart, the UA cancel
/// and cancel-all as `ua_metatx` jobs on the token, an outside leg against a SCaaS one; a `TradeOrder` for a SCaaS leg is
/// refused `LEG_SHAPE`.
#[tokio::test]
#[ignore]
async fn dex_order_with_a_ua_trade_order_leg() {
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
    // (= DEX owner, holding both of its powers from creation).
    let deployer = key(DEPLOYER);
    let alice_b0 = balance(&rpc, token_b, alice.address()).await;
    send(&rpc, &deployer, token_b, IToken::transferCall { to: bob.address(), value: U256::from(500_000_000u64) }.abi_encode()).await;
    let treasury = Address::repeat_byte(0x7a);
    let dex = create(&rpc, &deployer, factory, createDexCall { version: 1, initArgs: DexConfig { owner: deployer.address().into_word(),
        relayerSharePpm: 500_000, treasury, listedOnly: false, grantDelay: 0, rescueTo: Address::ZERO }.abi_encode().into(), salt: B256::repeat_byte(0xde) }.abi_encode()).await;
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

    // 1. R84 (review C1): `feeRecipient`/`relayer` of an open-mode `UAMetaTransfer` are not signed, so a client can put
    //    anything there; through the open gateway (`/v1/ua-metatx`) the fee still lands in our configured wallet.
    let thief = Address::repeat_byte(0x7e);
    let m = payment(alice.address(), Address::repeat_byte(0x5e), 1_000_000, B256::ZERO,
        U256::from_be_bytes(keccak256(b"e2e.r84").0), 0x20, thief, 1_000, thief); // FIXED fee, nothing bound
    let (kind, wire) = m.to_wire();
    let (st, body) = post("/v1/ua-metatx", json!({"chain": chain_id, "token": token_a, "struct": kind, "m": wire,
        "auth": sign(&alice, &token_domain(&dep, chain_id, token_a), &m)})).await;
    assert_eq!(st, 202, "{body}");
    drain(&mut s, &mut rx).await;
    assert_eq!((balance(&rpc, token_a, fee_wallet).await, balance(&rpc, token_a, thief).await), (U256::from(1_000u64), U256::ZERO));

    // SCaaS orders are `UATradeOrder`s signed in their sell token's salted domain: no allowance anywhere (CTR-TOK-01).
    let hash = |sell: Address, o: &TradeOrder| trade_order_hash(&domain("SCaaS MetaToken", chain_id, sell, uid), &canon(o));
    let place = |sell: Address, o: TradeOrder, signer: &PrivateKeySigner| {
        let auth = native_auth(signer, hash(sell, &o));
        post("/v1/dex/orders", json!({"chain": chain_id, "sellToken": sell, "order": WireOrder::from_ua(&canon(&o)), "auth": auth}))
    };
    // R43 / T17: the address `TradeOrder` with a `signature` for a SCaaS sell token is refused by name, never booked
    let o = order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 2, lane, dex);
    let (st, body) = post("/v1/dex/orders", json!({"chain": chain_id, "sellToken": token_a, "order": WireOrder::from_sol(&o),
        "signature": sign_hash(&alice, hash(token_a, &o))})).await;
    assert!(st == 400 && body["error"].as_str().unwrap().starts_with("LEG_SHAPE"), "{st} {body}");

    // 2. Not home-bound (RS5-9) or another DEX (NODE-DEX-16) ⇒ refused at the door.
    let (st, _) = place(token_a, order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 1, Address::ZERO, dex), &alice).await;
    assert_eq!(st, 400);
    let (st, _) = place(token_a, order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 1, lane, token_b), &alice).await;
    assert_eq!(st, 400);

    // 3. The ask rests; a bid is the taker of one settlement (NODE-DEX-15).
    let ask = order(&alice, token_b, 100_000_000, 200_000_000, 1_000, 2, lane, dex);
    let ask_hash = hash(token_a, &ask);
    let (st, body) = place(token_a, ask.clone(), &alice).await;
    assert_eq!((st, body["status"].as_str()), (202, Some("resting")), "{body}");
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

    // 6. Cancel in the token's domain (`CancelUAOrder`, `auth`): a high-s copy of a valid signature is refused like the
    //    contract would (review I4); the canonical one takes the order off the book now and closes it on the token at the
    //    next sync (a `ua_metatx` `mtxCancelOrder` entry job).
    let td = domain("SCaaS MetaToken", chain_id, token_a, uid);
    let high_s = {
        let s = alice.sign_hash_sync(&cancel_digest(&td, &canon(&ask))).unwrap();
        let n = U256::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap();
        let flipped = alloy::primitives::Signature::new(s.r(), n - s.s(), !s.v());
        format!("0x{}", alloy::hex::encode(flipped.as_bytes()))
    };
    let (st, _) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"),
        "auth": {"keyData": "0x", "signature": high_s, "members": []}})).await;
    assert_eq!(st, 400);
    assert_eq!(venue.rows().await, before);
    let (st, body) = post("/v1/dex/cancel", json!({"chain": chain_id, "orderHash": format!("{ask_hash:#x}"),
        "auth": native_auth(&alice, cancel_digest(&td, &canon(&ask)))})).await;
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
    // a SCaaS leg settles as `UALegSettled`, never `LegSettled` (R18)
    assert!(names.contains(&"UALegSettled") && names.contains(&"OrderCancelled") && !names.contains(&"LegSettled"), "{names:?}");
    let filled_alice = ev.iter().find(|e| e["event"] == "UALegSettled" && e["order_hash"] == format!("{ask_hash:#x}")).unwrap();
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

    // 10. Cancel-all on the token's order lane (`UAInvalidateNonces` on alice's id in A's domain, a `ua_metatx`
    //     `mtxInvalidateNonces` entry job).
    let (st, body) = post("/v1/dex/cancel-all", json!({"chain": chain_id, "sellToken": token_a, "from": format!("{:#x}", alice.address().into_word()),
        "batch": "1", "minNonce": "21", "auth": native_auth(&alice, ua_invalidate_digest(&td, alice.address().into_word(), U256::from(1), U256::from(21)))})).await;
    assert_eq!((st, body["orders"].as_u64()), (202, Some(1)), "{body}");
    assert!(venue.rows().await.is_empty());
    venue.sync_once().await.unwrap();
    drain(&mut s, &mut rx).await;
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let min = IToken::minNonceCall { from: alice.address().into_word(), batch: U256::from(1) }.abi_encode();
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

#[tokio::test]
#[ignore]
async fn dex_fill_below_half_settles_on_anvil() {
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
    let chain_id = 31951;
    let (_anvil, rpc) = start_anvil(chain_id, 18652).await;
    let alice = small_key(0xA11CE);
    let bob = small_key(0xB0B);
    let dep = deploy(&rpc, chain_id, alice.address());
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let token_a: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let token_b: Address = dep["demo_token_2"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
    let deployer = key(DEPLOYER);
    let alice_b0 = balance(&rpc, token_b, alice.address()).await;
    send(&rpc, &deployer, token_b, IToken::transferCall { to: bob.address(), value: U256::from(500_000_000u64) }.abi_encode()).await;
    let treasury = Address::repeat_byte(0x7a);
    let dex = create(&rpc, &deployer, factory, createDexCall { version: 1, initArgs: DexConfig { owner: deployer.address().into_word(),
        relayerSharePpm: 500_000, treasury, listedOnly: false, grantDelay: 0, rescueTo: Address::ZERO }.abi_encode().into(), salt: B256::repeat_byte(0xde) }.abi_encode()).await;
    send(&rpc, &deployer, dex, setMarketCall { base: token_a, quote: token_b, listed: true }.abi_encode()).await;

    let relayer = key(RELAYER);
    let lane = relayer.address();
    let cfg = chain_cfg(chain_id, &rpc, Some(dex));
    // market: no fees, min_base_amount 100 (< the 200 bid, so it is not a junk leg)
    let state = Arc::new(Mutex::new(FakeOdoo {
        tokens: vec![format!("{token_a:#x}"), format!("{token_b:#x}")],
        dex: format!("{dex:#x}"),
        markets: vec![json!({"id": 1, "base": format!("{token_a:#x}"), "quote": format!("{token_b:#x}"), "base_decimals": 6,
                             "quote_decimals": 6, "maker_fee_ppm": 0, "taker_fee_ppm": 0, "min_base_amount": "100"})],
        ..Default::default()
    }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo.clone(), cfg.clone(), "e2e".into(), Default::default())
        .await
        .unwrap();
    let shared = Arc::new(Chain::with_signer(&cfg, relayer.clone()).unwrap());
    let venue = Venue::start(shared.clone(), odoo.clone(), Some(odoo.clone()), dex).await.unwrap();
    let (tx, mut rx) = mpsc::channel::<Work>(16);
    let tokens = Arc::new(RwLock::new(vec![token_a, token_b]));
    let guard = Arc::new(scaas_node::guard::Guard::new(&cfg, tokens.clone()).unwrap());
    let gw = GwChain { chain: shared.clone(), tx, tokens, dex: Some(venue.clone()), breaker: None, fee_recipient: None, guard };
    let app = router(AppState { chains: Arc::new([(chain_id, gw)].into_iter().collect()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:18653").await.unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = reqwest::Client::new();
    let post = |body: Value| {
        let http = http.clone();
        async move { http.post("http://127.0.0.1:18653/v1/dex/orders").json(&body).send().await.unwrap().json::<Value>().await.unwrap() }
    };
    let place = |sell: Address, o: TradeOrder, signer: &PrivateKeySigner| {
        let auth = native_auth(signer, trade_order_hash(&domain("SCaaS MetaToken", chain_id, sell, uid), &canon(&o)));
        post(json!({"chain": chain_id, "sellToken": sell, "order": WireOrder::from_ua(&canon(&o)), "auth": auth}))
    };

    // ask: 1000 A for 2000 B, minFill 0 (order() default)
    let ask = order(&alice, token_b, 1_000, 2_000, 0, 1, lane, dex);
    let ask_hash = format!("{:#x}", trade_order_hash(&domain("SCaaS MetaToken", chain_id, token_a, uid), &canon(&ask)));
    assert_eq!(place(token_a, ask, &alice).await["status"], "resting");

    // bid 200 A (400 B) is 20 % of the ask: it fills, the ask stays partial with 800 left
    assert_eq!(place(token_b, order(&bob, token_a, 400, 200, 0, 2, lane, dex), &bob).await["status"], "filled");
    drain(&mut s, &mut rx).await;
    let stored = state.lock().unwrap().orders[&ask_hash].clone();
    assert_eq!((stored["state"].as_str(), stored["remaining"].as_str()), (Some("partial"), Some("800")));
    assert_eq!(balance(&rpc, token_b, alice.address()).await, alice_b0 + U256::from(400u64));
    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(200u64));

    // a second bid of 100 A (200 B) fills again
    assert_eq!(place(token_b, order(&bob, token_a, 200, 100, 0, 3, lane, dex), &bob).await["status"], "filled");
    drain(&mut s, &mut rx).await;
    let stored = state.lock().unwrap().orders[&ask_hash].clone();
    assert_eq!((stored["state"].as_str(), stored["remaining"].as_str()), (Some("partial"), Some("700")));
    assert_eq!(balance(&rpc, token_b, alice.address()).await, alice_b0 + U256::from(600u64));
    assert_eq!(balance(&rpc, token_a, bob.address()).await, U256::from(300u64));
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

alloy::sol! {
    // the typed registration (IUARegistry; accounts.md CTR-UA-07 / CTR-UA-31)
    struct KemKey { uint8 scheme; bytes mlkemEk; bytes32 x25519; }
    struct UAAttrs { bytes pqzKey; bytes32 pqzPopHash; KemKey kem; bytes32 kemPkHash; }
    function register(uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop) external returns (bytes32 ua);
    function uaOf(uint16 kind, bytes keyData) external pure returns (bytes32);
    function kemRecordHash(bytes32 ua, uint64 version, KemKey kem) external pure returns (bytes32);
    function registrationDigest(bytes32 ua, uint16 kind, bytes32 pqzKeyHash, bytes32 kemRecordHash, bytes32 pqzPopHash) external pure returns (bytes32);
    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32);
}

/// `(gas limit, max fee per gas)` of transaction `hash` (a replaced one is gone once its replacement lands).
async fn tx_fees(rpc: &str, hash: &str) -> (u64, u128) {
    use alloy::consensus::Transaction as _;
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let tx = p.get_transaction_by_hash(hash.parse().unwrap()).await.unwrap().expect("a signed tx");
    (tx.gas_limit(), tx.max_fee_per_gas())
}

/// One outbox poll, then track until every sent job settles.
async fn run_outbox(s: &mut Submitter) {
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

/// `UAKinds.SECP256K1`: a derived UA over a secp256k1 key (`keyData = x ‖ y`, ECDSA over `ua_msg`).
const UA_SECP256K1: u16 = 0x0108;

async fn view<C: SolCall>(rpc: &str, to: Address, c: C) -> C::Return {
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    C::abi_decode_returns(&p.call(TransactionRequest::default().to(to).input(c.abi_encode().into())).await.unwrap()).unwrap()
}

/// A derived secp256k1 UA of `owner`, registered by `deployer` with its PoP (no KEM key, no PQZ key): its id.
async fn register_ua(rpc: &str, registry: Address, deployer: &PrivateKeySigner, owner: &PrivateKeySigner) -> B256 {
    let key_data = Bytes::from(owner.public_key().to_vec());
    let ua = view(rpc, registry, uaOfCall { kind: UA_SECP256K1, keyData: key_data.clone() }).await;
    // no KEM key: kemRecordHash = hashStruct(UAKemRecord{ua, 0, 0, 0}), not 0
    let no_kem = KemKey { scheme: 0, mlkemEk: Default::default(), x25519: B256::ZERO };
    let krh = view(rpc, registry, kemRecordHashCall { ua, version: 0, kem: no_kem.clone() }).await;
    let rd = view(rpc, registry, registrationDigestCall { ua, kind: UA_SECP256K1, pqzKeyHash: B256::ZERO, kemRecordHash: krh, pqzPopHash: B256::ZERO }).await;
    let pm = view(rpc, registry, uaMessageCall { kind: UA_SECP256K1, purposeTag: keccak256(b"scaas.ua.purpose.pop.v2"), digest: rd }).await;
    let pop = owner.sign_hash_sync(&pm).unwrap().as_bytes().to_vec();
    send(rpc, deployer, registry, registerCall { kind: UA_SECP256K1, keyData: key_data, attrs: UAAttrs { pqzKey: Default::default(), pqzPopHash: B256::ZERO, kem: no_kem, kemPkHash: B256::ZERO },
        pop: pop.into(), pqzPop: Default::default() }.abi_encode()).await;
    ua
}

/// A derived UA's `UASig` as explicit JSON: the key, the signature over the registry's `uaMessage(kind, purpose, digest)`.
async fn ua_auth(rpc: &str, registry: Address, owner: &PrivateKeySigner, purpose: &[u8], digest: B256) -> Value {
    let msg = view(rpc, registry, uaMessageCall { kind: UA_SECP256K1, purposeTag: keccak256(purpose), digest }).await;
    let sig = owner.sign_hash_sync(&msg).unwrap().as_bytes().to_vec();
    json!({"keyData": format!("0x{}", alloy::hex::encode(owner.public_key())), "signature": format!("0x{}", alloy::hex::encode(sig)), "members": []})
}

/// Review I1 / minor 4: every transaction the lane signed for a priced relay-fee job (`hashes`: the first and each
/// replacement, `(gas limit, max fee)` read while each was known to the node) stays at or under the job's fee ceiling
/// (`FEE_HEADROOM` x the first max fee), and the lane's actual ETH cost (`spent`) is covered by the quote at that
/// ceiling. Prints a QUOTE line; returns the quote.
fn quote_covers(sent: &[(u64, u128)], spent: U256, what: &str) -> u128 {
    let (gas, first) = sent[0];
    let ceiling = scaas_node::guard::fee_ceiling(first);
    let quote = scaas_node::guard::relay_quote(gas, ceiling, 0);
    let fees: Vec<u128> = sent.iter().map(|s| s.1).collect();
    println!("QUOTE {what}: quote {quote} wei (gas limit {gas} x ceiling {ceiling} = 2 x first max fee {first}); sends' max fees \
              {fees:?}; the lane's ETH decrease {spent}");
    assert!(fees.iter().all(|f| *f <= ceiling), "{what}: a send above the fee ceiling {ceiling}: {fees:?}");
    assert!(sent.iter().all(|s| s.0 == gas), "{what}: replacements keep the gas limit");
    assert!(U256::from(quote) >= spent, "{what}: the quote {quote} under-prices the lane's {spent} wei");
    quote
}

/// `ua_metatx` (job-api.md) on the real token: a derived secp256k1 UA, registered and funded on the UA ledger, pays
/// (1) a pay-meta job (`mtxPayMeta` on ids), and (2) a relay fee for a fee-less call through `MtxRelayFee.relay` (`UARelayFee`,
/// open mode: the fee reaches the lane); the node's quote covers the lane's real ETH cost of each, a fee worth less than
/// the quote at `min_wei_value` is refused before any signature, and the indexer gives the UA payments (ids) their meta
/// and relay fee.
#[tokio::test]
#[ignore]
async fn ua_pay_meta_and_relay_fee_jobs_on_anvil() {
    use scaas_node::metatx::{meta_pay_id, pay_lane, relay_ref};
    let chain_id = 31905;
    let (_anvil, rpc) = start_anvil(chain_id, 31905).await;
    let payer = small_key(0xA11CE);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let registry: Address = dep["ua_registry"].as_str().unwrap().parse().unwrap();
    let router: Address = dep["mtx_relay_fee"].as_str().unwrap().parse().unwrap();
    let (relayer, deployer) = (key(RELAYER), key(DEPLOYER));
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());

    // a derived secp256k1 UA: registered (its PoP), then funded on the token's UA ledger
    let owner = small_key(0x05ec);
    let ua = register_ua(&rpc, registry, &deployer, &owner).await;
    send(&rpc, &deployer, token, IUALedger::transferToUACall { to: ua, amount: U256::from(1_000_000u64) }.abi_encode()).await;
    assert_eq!(view(&rpc, token, IUALedger::balanceOfUACall { ua }).await, U256::from(1_000_000u64));

    // wei per base unit: a fee of 1 is worth 10^11 wei, of 1,000 10^14 (anvil's quotes here are ~10^13)
    let price: u128 = 100_000_000_000;
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut cfg = chain_cfg(chain_id, &rpc, None);
    cfg.params = toml::toml! { relay_fee = { min_amount = 1 } };
    let rf = cfg.params["relay_fee"].as_table_mut().unwrap();
    rf.insert("router".into(), format!("{router:#x}").into());
    rf.insert("min_wei_value".into(), toml::Value::Table([(format!("{token:#x}"), toml::Value::from(price.to_string()))].into_iter().collect()));
    let mut s = Submitter::start(Chain::with_signer(&cfg, relayer.clone()).unwrap(), odoo.clone(), cfg.clone(), "e2e-ua".into(), Default::default())
        .await
        .unwrap();
    let d = token_domain(&dep, chain_id, token);
    let ua_job = |id: i64, m: &UaMtx, auth: &Value| {
        let (kind, wire) = m.to_wire();
        json!({"id": id, "kind": "ua_metatx", "token": format!("{token:#x}"), "digest": format!("{:#x}", m.digest(&d)),
               "struct": kind, "m": wire, "auth": auth})
    };
    let last = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap();
    let signed = |id: i64| state.lock().unwrap().reports.iter().find(|r| r["job_id"] == id && r["chain_state"] == "signed")
        .map(|r| r["tx_hash"].as_str().unwrap().to_string()).unwrap();
    let eth = || async { p.get_balance(relayer.address()).await.unwrap() };

    // (1) UA pay-meta: mtxPayMeta on ids, the node's digest is the token's
    let shop = Address::repeat_byte(0x5e);
    let (salt, meta) = (B256::repeat_byte(0x52), b"invoice 77".to_vec());
    let pid = meta_pay_id(&salt, &meta);
    let t = UAMetaTransfer { from: ua, to: shop.into_word(), value: U256::from(1_000u64), entryRef: pid, batch: pay_lane(&pid),
        nonce: U256::ZERO, validUntil: U256::from(now() + 300), mode: MODE_RESTRICT_RELAYER, relayer: relayer.address(),
        fee: U256::ZERO, feeRecipient: Address::ZERO };
    let m = UaMtx::Transfer(t.clone());
    assert_eq!(view(&rpc, token, IMtxIds::mtxTransferDigestCall { t }).await, m.digest(&d), "mtxTransferDigest");
    let mut j = ua_job(1, &m, &ua_auth(&rpc, registry, &owner, b"scaas.ua.purpose.metatx.v1", m.digest(&d)).await);
    (j["salt"], j["meta"]) = (json!(format!("{salt:#x}")), json!(format!("0x{}", alloy::hex::encode(&meta))));
    state.lock().unwrap().jobs.push(j);
    run_outbox(&mut s).await;
    assert_eq!(last(1)["chain_state"], "mined", "{}", last(1));
    assert_eq!(balance(&rpc, token, shop).await, U256::from(1_000u64), "the UA paid the shop");

    // (2) UA relay fee for the payer's fee-less merged cancelNonce(55) (its native id), open mode
    let inner = signed_op(&payer, cancel_op(payer.address(), token, 55, 12), chain_id, d.salt);
    let r = relay_ref(chain_id, token, &scaas_node::typed::Op::parse(&inner, None).unwrap().data);
    let relay_job = |id: i64, value: u64, inner: Value| {
        let mut op = json!({"entry": "mtxRelayFee", "contract": "token", "token": format!("{token:#x}"), "call": inner,
            "args": {"from": format!("{ua:#x}"), "payee": format!("{:#x}", router.into_word()), "value": value.to_string(),
                "validUntil": (now() + 300).to_string(), "relayer": format!("{router:#x}")},
            "auth": {"keyData": "0x", "signature": "0x", "members": []}});
        let digest = scaas_node::typed::Op::parse(&op, None).unwrap().typed.digest_on(chain_id, d.salt).unwrap();
        let (rpc, owner) = (rpc.clone(), owner.clone());
        async move {
            op["auth"] = ua_auth(&rpc, registry, &owner, b"scaas.ua.purpose.metatx.v1", digest).await;
            json!({"id": id, "kind": "ua_metatx", "op": op})
        }
    };
    // a fee of 1 is worth 10^11 wei, under the quote: nothing signed, retried later (the quote follows the fees)
    let n0 = p.get_transaction_count(relayer.address()).await.unwrap();
    let j = relay_job(2, 1, inner.clone()).await;
    state.lock().unwrap().jobs.push(j);
    run_outbox(&mut s).await;
    let l = last(2);
    assert!(l["chain_state"] == "queued" && l["error"].as_str().unwrap().starts_with("RELAY_FEE_REFUSED"), "{l}");
    assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), n0, "nothing signed or sent");
    // a fee of 1,000 (10^14 wei at the price) covers it
    let j = relay_job(3, 1_000, inner.clone()).await;
    state.lock().unwrap().jobs.push(j);
    let (b0, f0) = (eth().await, balance(&rpc, token, relayer.address()).await);
    run_outbox(&mut s).await;
    assert_eq!(last(3)["chain_state"], "mined", "{}", last(3));
    let quote = quote_covers(&[tx_fees(&rpc, &signed(3)).await], b0 - eth().await, "relay (secp256k1 UA payer, open mode)");
    assert!(1_000 * price >= quote, "the fee at min_wei_value covers the quote");
    assert_eq!(balance(&rpc, token, relayer.address()).await, f0 + U256::from(1_000u64), "the fee reached the lane");
    let lane12 = IMtxIds::mtxNonceCall { from: payer.address().into_word(), batch: U256::from(12) };
    assert_eq!(view(&rpc, token, lane12).await, U256::from(1u64), "the inner call ran");
    assert_eq!(view(&rpc, token, IUALedger::balanceOfUACall { ua }).await, U256::from(1_000_000u64 - 2_000));

    // the indexer: the UA payments are PaymentSettled rows of the id, with their meta and relay fee
    let ichain = Chain::with_signer(&cfg, relayer.clone()).unwrap();
    while scaas_node::indexer::step(&ichain, &odoo, Some(router)).await.unwrap() {}
    let ingested = state.lock().unwrap().ingested.clone();
    assert!(ingested.iter().all(|e| e["event"] != "PaymentMeta" && e["event"] != "RelayFeePaid"), "never rows");
    // review C1: the client's ingest (mirrored by the fake) takes every row; a derived UA is UA_POOL + its id
    assert!(state.lock().unwrap().refused.is_empty(), "{:?}", state.lock().unwrap().refused);
    let (pool, uid) = (format!("{:#x}", scaas_node::metatx::ua_pool()), format!("{ua:#x}"));
    let paid = ingested.iter().find(|e| e["event"] == "PaymentSettled" && e["entry_ref"] == format!("{pid:#x}")).expect("UA pay-meta settled");
    assert_eq!((paid["from"].as_str(), paid["from_ua"].as_str(), paid["to"].as_str(), paid["amount"].as_str()),
        (Some(pool.as_str()), Some(uid.as_str()), Some(format!("{shop:#x}").as_str()), Some("1000")));
    assert_eq!(paid["meta"], format!("0x{}", alloy::hex::encode(&meta)));
    let fee = ingested.iter().find(|e| e["event"] == "PaymentSettled" && e["entry_ref"] == format!("{r:#x}")).expect("UA relay fee settled");
    assert_eq!((fee["from_ua"].as_str(), fee["relay_target"].as_str(), fee["relay_payee"].as_str()),
        (Some(uid.as_str()), Some(format!("{token:#x}").as_str()), Some(format!("{:#x}", relayer.address()).as_str())));
    let exe = ingested.iter().find(|e| e["event"] == "MetaTransactionExecuted" && e["from_ua"] == uid.as_str()).expect("UA executed");
    assert_eq!((exe["from"].as_str(), exe["digest"].clone()), (Some(pool.as_str()), json!(format!("{:#x}", m.digest(&d)))));

    // review I1 / minor 4: a priced relay whose send is stuck (no blocks) is replaced, every replacement at or under
    // the job's fee ceiling (2 x the first max fee; unclamped, 25 % bumps pass it on the fourth); once mined, the lane's
    // cost is inside the quote. A second lane runner (stuck after 1 s) on the same key, the first one idle.
    let inner = signed_op(&payer, cancel_op(payer.address(), token, 56, 13), chain_id, d.salt);
    let mut cfg2 = cfg.clone();
    cfg2.stuck_after_secs = 1;
    let mut s2 = Submitter::start(Chain::with_signer(&cfg2, relayer.clone()).unwrap(), odoo.clone(), cfg2, "e2e-ua-2".into(), Default::default())
        .await
        .unwrap();
    let _: Value = p.raw_request("evm_setAutomine".into(), (false,)).await.unwrap();
    let j = relay_job(4, 1_000, inner).await;
    state.lock().unwrap().jobs.push(j);
    let b0 = eth().await;
    s2.poll_outbox().await;
    assert_eq!(last(4)["chain_state"], "broadcast", "{}", last(4));
    let hashes = || -> Vec<String> { state.lock().unwrap().reports.iter()
        .filter(|r| r["job_id"] == 4 && r["tx_hash"].is_string()).map(|r| r["tx_hash"].as_str().unwrap().to_string()).collect() };
    let mut sent = vec![tx_fees(&rpc, &hashes()[0]).await];
    for _ in 0..7 {
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        s2.track().await;
        let h = hashes();
        if h.len() > sent.len() {
            sent.push(tx_fees(&rpc, h.last().unwrap()).await);
        }
    }
    assert!(sent.len() >= 3, "replaced while stuck: {sent:?}");
    let _: Value = p.raw_request("evm_mine".into(), ()).await.unwrap();
    let _: Value = p.raw_request("evm_setAutomine".into(), (true,)).await.unwrap();
    for _ in 0..30 {
        s2.track().await;
        if s2.inflight_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(last(4)["chain_state"], "mined", "{}", last(4));
    quote_covers(&sent, b0 - eth().await, "relay replaced while stuck");
    assert_eq!(view(&rpc, token, IMtxIds::mtxNonceCall { from: payer.address().into_word(), batch: U256::from(13) }).await, U256::from(1u64));
}

/// Spec 2026-11-02-governance §3.6, §12.7 (plan T15) on the real contracts, the router's merged entry (ua-mtx-merge T7): a DEX
/// owner EOA with no gas signs `mtxSetListedOnly(UAEnvelope, …, UASig)` on the chain's `GovernanceRouter` with its own key (its
/// padded id, `batch` = the target, one lane per target); as a `ua_metatx` job on a chain with no `governance_routers` it goes
/// `dead` `CALL_TARGET_REFUSED` with nothing sent; on a chain that names the router it is relayed at fee 0, and the DEX's
/// `listedOnly()` reads true: the router authenticated the owner's native id for that one call.
#[tokio::test]
#[ignore]
async fn router_op_signed_by_an_eoa() {
    let chain_id = 31906;
    let (_anvil, rpc) = start_anvil(chain_id, 31906).await;
    let owner = small_key(0x60F); // never funded
    let dep = deploy(&rpc, chain_id, owner.address());
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let router: Address = dep["governance_router"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let deployer = key(DEPLOYER);
    let dex = create(&rpc, &deployer, factory, createDexCall { version: 1, initArgs: DexConfig { owner: owner.address().into_word(),
        relayerSharePpm: 0, treasury: Address::repeat_byte(0x7a), listedOnly: false, grantDelay: 0, rescueTo: Address::ZERO }.abi_encode().into(),
        salt: B256::repeat_byte(0x60) }.abi_encode()).await;
    assert!(!view(&rpc, dex, listedOnlyCall {}).await);
    let op = signed_op(&owner, json!({"entry": "mtxSetListedOnly", "contract": "gov_router", "token": format!("{router:#x}"),
        "args": {"target": format!("{dex:#x}"), "on": true},
        "envelope": envelope(owner.address(), U256::from_be_slice(dex.as_slice()), 0)}), chain_id, uid);
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let relayer = key(RELAYER);
    let report = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap();

    let without = chain_cfg(chain_id, &rpc, None);
    let mut s = Submitter::start(Chain::with_signer(&without, relayer.clone()).unwrap(), odoo.clone(), without.clone(), "e2e-gov-0".into(),
        Default::default()).await.unwrap();
    state.lock().unwrap().jobs.push(json!({"id": 1, "kind": "ua_metatx", "op": op.clone()}));
    run_outbox(&mut s).await;
    assert_eq!(report(1)["chain_state"], "dead", "{}", report(1));
    assert!(report(1)["error"].as_str().unwrap().contains("CALL_TARGET_REFUSED"), "{}", report(1));
    assert!(!view(&rpc, dex, listedOnlyCall {}).await, "nothing sent");

    let with = ChainCfg { governance_routers: vec![router], ..without };
    let mut s = Submitter::start(Chain::with_signer(&with, relayer.clone()).unwrap(), odoo.clone(), with.clone(), "e2e-gov-1".into(),
        Default::default()).await.unwrap();
    state.lock().unwrap().jobs.push(json!({"id": 2, "kind": "ua_metatx", "op": op}));
    run_outbox(&mut s).await;
    assert_eq!(report(2)["chain_state"], "mined", "{}", report(2));
    assert!(view(&rpc, dex, listedOnlyCall {}).await, "the owner's op ran through the router");
    let lane = IMtxIds::mtxNonceCall { from: owner.address().into_word(), batch: U256::from_be_slice(dex.as_slice()) };
    assert_eq!(view(&rpc, router, lane).await, U256::from(1u64), "the router's nonce, on the target's lane");
}

// ------------------------------------------------------------------ the merged entries on anvil (ua-mtx-merge T18)

alloy::sol! {
    // `IFactoryToken` (CTR-TOK-25) and the release calls of `OpenFactory` (plan 5g-Z2); `TokenKind` as its `uint8`
    #[derive(Default)]
    struct Roles { bytes32 minter; bytes32 rateAdmin; bytes32 guardian; bytes32 issuer; bytes32 compliance; }
    #[derive(Default)]
    struct Leg { address underlying; uint256 num; uint256 den; }
    #[derive(Default)]
    struct RateConfig { uint32 rateDelay; uint16 maxRateStepBps; }
    #[derive(Default)]
    struct ConfidentialConfig { bytes auditorKey; uint256 shieldScale; uint256 maxShielded; uint256 confidentialFee; uint8 disclosureMode;
        uint8 auditorMode; uint256 minDecoyFee; }
    /// Regulated-kinds spec §2.4 (plan T25): the regulated kinds' (8-13) only; a plain kind refuses any set field.
    #[derive(Default)]
    struct RegulatedParams { address complianceRegistry; uint64 requiredFlags; uint64 deniedFlags; bytes32 termsHash; }
    #[derive(Default)]
    struct TokenConfig { string name; string symbol; uint8 decimals; uint256 features; uint256 lockedFeatures; bytes32 owner; Roles roles;
        uint256 initialSupply; address initialHolder; Leg[] legs; RateConfig rate; ConfidentialConfig conf; uint64 grantDelay;
        address rescueTo; uint256 maxSupply; RegulatedParams reg; }
    struct FactoryEnv { address factory; bytes32 chainUid; address registry; address smartKeyAccountImpl; bool hedera; address[] deps;
        address[] libs; bytes32[] libCodeHashes; address govRouter; }
    function envOf(uint8 kind, uint16 envVersion) external view returns (FactoryEnv);
    function publishEnv(uint8 kind, uint16 envVersion, FactoryEnv env) external;
    function deployImplementation(uint8 kind, uint64 version, uint16 envVersion, bytes initcode, bytes implArgs) external returns (address);
    function createToken(uint8 kind, uint64 version, bytes initArgs, bytes32 salt) external returns (address);
    function registry() external view returns (address);
    function epoch(address token) external view returns (uint64);
}

/// The init code of forge's artifact `out/<file>/<name>.json`, each library linked at the address the deploy of `chain_id` gave it
/// (`broadcast/Deploy.s.sol/<chain_id>/run-latest.json`).
fn linked(chain_id: u64, file: &str, name: &str) -> Vec<u8> {
    let read = |p: String| -> Value { serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap() };
    let art = read(format!("{}/out/{file}/{name}.json", sc()));
    let run = read(format!("{}/broadcast/Deploy.s.sol/{chain_id}/run-latest.json", sc()));
    let libs: std::collections::HashMap<String, String> = run["libraries"].as_array().unwrap().iter().map(|l| {
        let (path, addr) = l.as_str().unwrap().rsplit_once(':').unwrap();
        (path.to_string(), addr[2..].to_lowercase())
    }).collect();
    let mut code = art["bytecode"]["object"].as_str().unwrap().trim_start_matches("0x").to_string();
    for (path, by) in art["bytecode"]["linkReferences"].as_object().unwrap() {
        for (lib, at) in by.as_object().unwrap() {
            let addr = &libs[&format!("{path}:{lib}")];
            for o in at.as_array().unwrap() {
                let i = 2 * o["start"].as_u64().unwrap() as usize;
                code.replace_range(i..i + 40, addr);
            }
        }
    }
    alloy::hex::decode(code).unwrap()
}

/// A `NORMAL` token whose `registry()` is 0 (the UA path off: CTR-UA-18 at registry 0): the deploy's env 1 with `registry` 0 as
/// env 2, a `NormalToken` release on it (version 2) and a clone holding `supply` for `holder`, all through the factory.
async fn registry_zero_token(rpc: &str, chain_id: u64, dep: &Value, holder: Address, supply: u64) -> Address {
    let deployer = key(DEPLOYER);
    let f: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
    let mut env = view(rpc, f, envOfCall { kind: 0, envVersion: 1 }).await;
    assert_ne!(env.registry, Address::ZERO, "the deploy's NORMAL release is on the registry");
    env.registry = Address::ZERO;
    send(rpc, &deployer, f, publishEnvCall { kind: 0, envVersion: 2, env }.abi_encode()).await;
    let code = linked(chain_id, "NormalToken.sol", "NormalToken");
    send(rpc, &deployer, f, deployImplementationCall { kind: 0, version: 2, envVersion: 2, initcode: code.into(), implArgs: Bytes::new() }.abi_encode()).await;
    let c = TokenConfig { name: "SCaaS Registry Zero".into(), symbol: "bRZ".into(), decimals: 6, features: U256::from(1u8), // PAYABLE
        initialSupply: U256::from(supply), initialHolder: holder, ..Default::default() };
    let t = create(rpc, &deployer, f, createTokenCall { kind: 0, version: 2, initArgs: c.abi_encode().into(), salt: B256::repeat_byte(0x20) }.abi_encode()).await;
    assert_eq!(view(rpc, t, registryCall {}).await, Address::ZERO);
    t
}

/// The last report of job `id`.
fn report(state: &Arc<Mutex<FakeOdoo>>, id: i64) -> Value {
    state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap_or_else(|| panic!("no report of job {id}"))
}

/// A fake client serving `tokens`, and one submitter on the `RELAYER` lane.
async fn outbox(chain_id: u64, rpc: &str, tokens: &[Address]) -> (Arc<Mutex<FakeOdoo>>, Odoo, Submitter) {
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: tokens.iter().map(|t| format!("{t:#x}")).collect(), ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let cfg = chain_cfg(chain_id, rpc, None);
    let s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo.clone(), cfg, format!("e2e-{chain_id}"), Default::default())
        .await
        .unwrap();
    (state, odoo, s)
}

/// Spec §8 invariant 4, R1 / C: an EOA's `UAMetaTransfer` at fee 0 (mode `NONE`, open relayer) on a token whose `registry()` is
/// 0 is relayed: its own key, no registry asked, the UA events on the chain. A derived side on that token is refused by the node
/// by name (R44), nothing sent.
#[tokio::test]
#[ignore]
async fn eoa_mtx_transfer_relayed_at_fee_zero_registry_zero() {
    let chain_id = 31907;
    let (_anvil, rpc) = start_anvil(chain_id, 31907).await;
    let payer = small_key(0xEE0A);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token = registry_zero_token(&rpc, chain_id, &dep, payer.address(), 1_000_000).await;
    let (state, odoo, mut s) = outbox(chain_id, &rpc, &[token]).await;
    let d = token_domain(&dep, chain_id, token);
    let shop = Address::repeat_byte(0x5e);
    let m = payment(payer.address(), shop, 700, keccak256(b"rz-1"), U256::from(1), 0, Address::ZERO, 0, Address::ZERO);
    state.lock().unwrap().jobs.push(job(1, token, &m, "0x", sign(&payer, &d, &m)));
    let derived = ua_payment(payer.address().into_word(), B256::repeat_byte(0xaa), 1, keccak256(b"rz-2"), U256::from(2), 0,
        Address::ZERO, 0, Address::ZERO);
    state.lock().unwrap().jobs.push(job(2, token, &derived, "0x", sign(&payer, &d, &derived)));
    let n0 = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_count(key(RELAYER).address()).await.unwrap();
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    assert_eq!(balance(&rpc, token, shop).await, U256::from(700u64));
    merged_events_only(&rpc, &tx_of(&state, 1)).await;
    let r2 = report(&state, 2);
    assert!(r2["chain_state"] == "dead" && r2["error"].as_str().unwrap().contains("registry() = 0"), "{r2}");
    let n1 = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_count(key(RELAYER).address()).await.unwrap();
    assert_eq!(n1, n0 + 1, "one transaction: the EOA's");
    while scaas_node::indexer::step(&Chain::with_signer(&chain_cfg(chain_id, &rpc, None), key(RELAYER)).unwrap(), &odoo, None).await.unwrap() {}
    let paid = state.lock().unwrap().ingested.iter().find(|e| e["event"] == "PaymentSettled").cloned().expect("settled");
    assert_eq!((paid["from"].as_str(), paid.get("from_ua")), (Some(format!("{:#x}", payer.address()).as_str()), None));
}

/// R1 / R2: an EOA pays a derived UA (`to` its id) through `mtxExecuteTransfer(UAMetaTransfer, UASig)`: the EOA's own key, the
/// id credited on the UA ledger, the client's row carrying `to_ua`.
#[tokio::test]
#[ignore]
async fn eoa_mtx_transfer_to_a_ua() {
    let chain_id = 31908;
    let (_anvil, rpc) = start_anvil(chain_id, 31908).await;
    let payer = small_key(0xEE0B);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let registry: Address = dep["ua_registry"].as_str().unwrap().parse().unwrap();
    let ua = register_ua(&rpc, registry, &key(DEPLOYER), &small_key(0x05ed)).await;
    let (state, odoo, mut s) = outbox(chain_id, &rpc, &[token]).await;
    let d = token_domain(&dep, chain_id, token);
    let m = ua_payment(payer.address().into_word(), ua, 4_200, keccak256(b"to-ua"), U256::from(3), 0, Address::ZERO, 0, Address::ZERO);
    state.lock().unwrap().jobs.push(job(1, token, &m, "0x", sign(&payer, &d, &m)));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    assert_eq!(view(&rpc, token, IUALedger::balanceOfUACall { ua }).await, U256::from(4_200u64));
    merged_events_only(&rpc, &tx_of(&state, 1)).await;
    while scaas_node::indexer::step(&Chain::with_signer(&chain_cfg(chain_id, &rpc, None), key(RELAYER)).unwrap(), &odoo, None).await.unwrap() {}
    let paid = state.lock().unwrap().ingested.iter().find(|e| e["event"] == "PaymentSettled").cloned().expect("settled");
    assert_eq!((paid["from"].as_str(), paid["to_ua"].as_str()), (Some(format!("{:#x}", payer.address()).as_str()), Some(format!("{ua:#x}").as_str())));
}

/// R2 / B: a derived UA (secp256k1, registered, funded on the UA ledger) signs a `UAMetaTransfer` through the registry
/// (`uaMessage`, purpose metatx); the node relays it at fee 0 and the row carries `from_ua`, `from` the `UA_POOL`.
#[tokio::test]
#[ignore]
async fn derived_mtx_transfer_relayed() {
    let chain_id = 31909;
    let (_anvil, rpc) = start_anvil(chain_id, 31909).await;
    let dep = deploy(&rpc, chain_id, key(DEPLOYER).address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let registry: Address = dep["ua_registry"].as_str().unwrap().parse().unwrap();
    let owner = small_key(0x05ee);
    let ua = register_ua(&rpc, registry, &key(DEPLOYER), &owner).await;
    send(&rpc, &key(DEPLOYER), token, IUALedger::transferToUACall { to: ua, amount: U256::from(10_000u64) }.abi_encode()).await;
    let (state, odoo, mut s) = outbox(chain_id, &rpc, &[token]).await;
    let d = token_domain(&dep, chain_id, token);
    let shop = Address::repeat_byte(0x5e);
    let m = ua_payment(ua, shop.into_word(), 2_500, keccak256(b"derived"), U256::from(4), 0, Address::ZERO, 0, Address::ZERO);
    let auth = ua_auth(&rpc, registry, &owner, b"scaas.ua.purpose.metatx.v1", m.digest(&d)).await;
    state.lock().unwrap().jobs.push(job(1, token, &m, "0x", auth));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    assert_eq!(balance(&rpc, token, shop).await, U256::from(2_500u64));
    assert_eq!(view(&rpc, token, IUALedger::balanceOfUACall { ua }).await, U256::from(7_500u64));
    merged_events_only(&rpc, &tx_of(&state, 1)).await;
    while scaas_node::indexer::step(&Chain::with_signer(&chain_cfg(chain_id, &rpc, None), key(RELAYER)).unwrap(), &odoo, None).await.unwrap() {}
    let paid = state.lock().unwrap().ingested.iter().find(|e| e["event"] == "PaymentSettled").cloned().expect("settled");
    let pool = format!("{:#x}", scaas_node::metatx::ua_pool());
    assert_eq!((paid["from"].as_str(), paid["from_ua"].as_str()), (Some(pool.as_str()), Some(format!("{ua:#x}").as_str())));
}

/// Q2 (R19): the merged `mtxCancelNonce(UAEnvelope, lane, UASig)` of an EOA is nonce-ordered on its own lane: relayed at fee 0
/// it bumps the cancelled lane, so the transfer signed there never lands; on the cancel's lane a nonce out of order is not
/// sent, the next in order is.
#[tokio::test]
#[ignore]
async fn ordered_cancel_relayed() {
    let chain_id = 31910;
    let (_anvil, rpc) = start_anvil(chain_id, 31910).await;
    let payer = small_key(0xEE0C);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let (state, _odoo, mut s) = outbox(chain_id, &rpc, &[token]).await;
    let d = token_domain(&dep, chain_id, token);
    let shop = Address::repeat_byte(0x5e);
    let nonce = |lane: u64| view(&rpc, token, IMtxIds::mtxNonceCall { from: payer.address().into_word(), batch: U256::from(lane) });
    // the payment signed on lane 5, withheld; the cancel of lane 5 on the cancel's own lane 6 at nonce 0
    let t = payment(payer.address(), shop, 900, keccak256(b"cancelled"), U256::from(5), 0, Address::ZERO, 0, Address::ZERO);
    let cancel = |lane: u64, at: u64| {
        let mut op = cancel_op(payer.address(), token, lane, 6);
        op["envelope"]["nonce"] = json!(at.to_string());
        signed_op(&payer, op, chain_id, d.salt)
    };
    state.lock().unwrap().jobs.push(json!({"id": 1, "kind": "ua_metatx", "op": cancel(5, 0)}));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    assert_eq!((nonce(5).await, nonce(6).await), (U256::from(1u64), U256::from(1u64)));
    // the cancelled payment: its nonce is spent by no intent of its own (R80: `consumed`, never `dead`), never sent
    let sent = |st: &Arc<Mutex<FakeOdoo>>, id: i64| st.lock().unwrap().reports.iter().any(|r| r["job_id"] == id && r["chain_state"] == "signed");
    state.lock().unwrap().jobs.push(job(2, token, &t, "0x", sign(&payer, &d, &t)));
    // lane 6 at nonce 2 skips nonce 1: out of order, the simulation refuses it (the subject nonce is behind it: `dead`), never sent
    state.lock().unwrap().jobs.push(json!({"id": 3, "kind": "ua_metatx", "op": cancel(8, 2)}));
    run_outbox(&mut s).await;
    let (r2, r3) = (report(&state, 2), report(&state, 3));
    assert!(!sent(&state, 2) && r2["chain_state"] == "consumed", "{r2}");
    assert!(!sent(&state, 3) && r3["chain_state"] == "dead" && r3["error"].as_str().unwrap().contains("MetaTxBadNonce"), "{r3}");
    assert_eq!(balance(&rpc, token, shop).await, U256::ZERO);
    // the next in order lands
    state.lock().unwrap().jobs.push(json!({"id": 4, "kind": "ua_metatx", "op": cancel(8, 1)}));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 4)["chain_state"], "mined", "{}", report(&state, 4));
    assert_eq!((nonce(6).await, nonce(8).await), (U256::from(2u64), U256::from(1u64)));
    assert!(state.lock().unwrap().refused.is_empty(), "{:?}", state.lock().unwrap().refused);
}

/// The three gateway doors (T15, R43 / R44, Q7) on a chain: `/v1/metatx` refuses an address `MetaTransfer` on a token by name,
/// `/v1/ua-metatx` relays an EOA's `UAMetaTransfer` at fee 0, `/v1/op` a named merged entry (`mtxCancelNonce`); each lands.
#[tokio::test]
#[ignore]
async fn gateway_doors_end_to_end() {
    let chain_id = 31911;
    let (_anvil, rpc) = start_anvil(chain_id, 31911).await;
    let payer = small_key(0xEE0D);
    let dep = deploy(&rpc, chain_id, payer.address());
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let (_state, _odoo, mut s) = outbox(chain_id, &rpc, &[token]).await;
    let cfg = chain_cfg(chain_id, &rpc, None);
    let (tx, mut rx) = mpsc::channel::<Work>(16);
    let tokens = Arc::new(RwLock::new(vec![token]));
    let guard = Arc::new(scaas_node::guard::Guard::new(&cfg, tokens.clone()).unwrap());
    let gw = GwChain { chain: Arc::new(Chain::with_signer(&cfg, key(RELAYER)).unwrap()), tx, tokens, dex: None, breaker: None,
        fee_recipient: None, guard };
    let app = router(AppState { chains: Arc::new([(chain_id, gw)].into_iter().collect()) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gw_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = reqwest::Client::new();
    let post = |path: &str, body: Value| {
        let (http, url) = (http.clone(), format!("{gw_url}{path}"));
        async move {
            let r = http.post(url).json(&body).send().await.unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap())
        }
    };
    let d = token_domain(&dep, chain_id, token);
    let shop = Address::repeat_byte(0x5e);
    let m = payment(payer.address(), shop, 1_234, keccak256(b"door"), U256::from(1), 0, Address::ZERO, 0, Address::ZERO);
    let (kind, wire) = m.to_wire();
    // the address door: an address `MetaTransfer` on a token names no entry any more (R43)
    let mut old = wire.clone();
    (old["from"], old["to"]) = (json!(format!("{:#x}", payer.address())), json!(format!("{shop:#x}")));
    let (st, body) = post("/v1/metatx", json!({"chain": chain_id, "token": token, "struct": kind, "m": old,
        "signature": format!("0x{}", "11".repeat(65))})).await;
    assert!(st == 400 && body["error"].as_str().unwrap().starts_with("OP_KIND_MISMATCH"), "{st} {body}");
    // the UA door
    let (st, body) = post("/v1/ua-metatx", json!({"chain": chain_id, "token": token, "struct": kind, "m": wire, "auth": sign(&payer, &d, &m)})).await;
    assert_eq!(st, 202, "{body}");
    drain(&mut s, &mut rx).await;
    assert_eq!(balance(&rpc, token, shop).await, U256::from(1_234u64));
    // door A: a named merged entry
    let (st, body) = post("/v1/op", json!({"chain": chain_id, "op": signed_op(&payer, cancel_op(payer.address(), token, 41, 42), chain_id, d.salt)})).await;
    assert_eq!(st, 202, "{body}");
    drain(&mut s, &mut rx).await;
    assert_eq!(view(&rpc, token, IMtxIds::mtxNonceCall { from: payer.address().into_word(), batch: U256::from(41) }).await, U256::from(1u64));
    // R18: the token emitted the UA events of both, never an address one
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let logs = p.get_logs(&alloy::rpc::types::Filter::new().address(token).from_block(0)).await.unwrap();
    let count = |t: B256| logs.iter().filter(|l| l.topic0() == Some(&t)).count();
    assert_eq!(count(IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH), 2);
    assert_eq!(count(IUALedger::UAPaymentSettled::SIGNATURE_HASH), 1);
    assert_eq!(count(IToken::PaymentSettled::SIGNATURE_HASH) + count(IToken::MetaTransactionExecuted::SIGNATURE_HASH), 0);
}

/// Q6 (MD-11), CTR-ACC-12 on a chain: a `MandateWallet` of an EOA owner with no registry (`registry_ = 0`); the owner sets the
/// mandate and the payee through the wallet's merged entries, and the delegate, an EOA with no gas, pays through
/// `mtxPayUnderMandate(UAEnvelope, …, UASig)` on `mandatePayLane(entryRef)`, each a `ua_metatx` job at fee 0. The flat builder
/// (`mtxExecuteAsOwnerRaw`, MD-11 (a)) is refused by name, nothing sent.
#[tokio::test]
#[ignore]
async fn mandate_payment_relayed_by_an_eoa_delegate() {
    let chain_id = 31912;
    let (_anvil, rpc) = start_anvil(chain_id, 31912).await;
    let (owner, delegate) = (small_key(0x0A11), small_key(0xDE1E)); // neither funded
    let dep = deploy(&rpc, chain_id, key(DEPLOYER).address());
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let built = Command::new("forge").current_dir(sc()).args(["build", "src/wallet/MandateWallet.sol"]).env("FOUNDRY_PROFILE", "scaas-testnet").status();
    assert!(built.expect("forge in PATH").success(), "forge build src/wallet/MandateWallet.sol failed");
    let mut code = linked(chain_id, "MandateWallet.sol", "MandateWallet");
    code.extend((owner.address().into_word(), uid, Address::ZERO, false).abi_encode_params());
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(key(DEPLOYER))).connect_http(rpc.parse().unwrap());
    let tx = alloy::network::TransactionBuilder::with_deploy_code(TransactionRequest::default(), code);
    let wallet = p.send_transaction(tx).await.unwrap().get_receipt().await.unwrap().contract_address.unwrap();
    assert_eq!(view(&rpc, wallet, registryCall {}).await, Address::ZERO, "no registry");
    send(&rpc, &key(DEPLOYER), token, IToken::transferCall { to: wallet, value: U256::from(1_000_000u64) }.abi_encode()).await;
    let (state, _odoo, mut s) = outbox(chain_id, &rpc, &[token]).await;
    let shop = Address::repeat_byte(0x5e);
    let w = |entry: &str, args: Value, from: Address, batch: U256| json!({"entry": entry, "contract": "wallet", "token": format!("{wallet:#x}"),
        "args": args, "envelope": envelope(from, batch, 0)});
    let t = format!("{token:#x}");
    let set = signed_op(&owner, w("mtxSetMandate", json!({"token": t, "delegate": format!("{:#x}", delegate.address().into_word()),
        "maxPerPayment": "500000", "maxPerPeriod": "800000", "periodSeconds": "86400", "expiry": (now() + 86_400).to_string()}),
        owner.address(), U256::from(1)), chain_id, uid);
    let payee = signed_op(&owner, w("mtxSetPayee", json!({"token": t, "payee": format!("{:#x}", shop.into_word()), "allowed": true}),
        owner.address(), U256::from(2)), chain_id, uid);
    state.lock().unwrap().jobs.extend([json!({"id": 1, "kind": "ua_metatx", "op": set}), json!({"id": 2, "kind": "ua_metatx", "op": payee})]);
    run_outbox(&mut s).await;
    for id in [1, 2] {
        assert_eq!(report(&state, id)["chain_state"], "mined", "{}", report(&state, id));
    }
    let epoch = view(&rpc, wallet, epochCall { token }).await;
    assert_eq!(epoch, 1);
    // the delegate's payment on the lane of its entryRef, nonce 0
    let entry_ref = keccak256(b"invoice 9");
    let pay = |entry: &str| signed_op(&delegate, w(entry, json!({"token": t, "payee": format!("{:#x}", shop.into_word()), "amount": "300000",
        "entryRef": format!("{entry_ref:#x}"), "epoch": epoch.to_string()}), delegate.address(),
        scaas_node::typed::mandate_pay_lane(entry_ref.as_slice())), chain_id, uid);
    let n0 = p.get_transaction_count(key(RELAYER).address()).await.unwrap();
    state.lock().unwrap().jobs.push(json!({"id": 3, "kind": "ua_metatx", "op": pay("mtxPayUnderMandate")}));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 3)["chain_state"], "mined", "{}", report(&state, 3));
    assert_eq!(balance(&rpc, token, shop).await, U256::from(300_000u64));
    assert_eq!(balance(&rpc, token, wallet).await, U256::from(700_000u64));
    assert_eq!(p.get_transaction_count(key(RELAYER).address()).await.unwrap(), n0 + 1);
    // the wallet's own event of the merged path, on the delegate's id
    let rc = p.get_transaction_receipt(tx_of(&state, 3).parse().unwrap()).await.unwrap().unwrap();
    assert!(rc.inner.logs().iter().any(|l| l.address() == wallet && l.topic0() == Some(&IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH)
        && l.topics()[1] == delegate.address().into_word()), "UAMetaTransactionExecuted of the delegate's id");
    // MD-11 (a): the flat builder is no entry of the node any more
    let mut flat = json!({"entry": "mtxExecuteAsOwnerRaw", "contract": "wallet", "token": format!("{wallet:#x}"),
        "args": {"data": "0x", "nonce": "0", "validUntil": (now() + 300).to_string(), "sig": "0x"}});
    flat["signature"] = json!("0x");
    state.lock().unwrap().jobs.push(json!({"id": 4, "kind": "metatx", "op": flat}));
    run_outbox(&mut s).await;
    let r4 = report(&state, 4);
    assert!(r4["chain_state"] == "dead" && r4["error"].as_str().unwrap().contains("UNKNOWN_ENTRY"), "{r4}");
    assert_eq!(p.get_transaction_count(key(RELAYER).address()).await.unwrap(), n0 + 1, "nothing sent");
}

alloy::sol! {
    // the Zether layer's direct entries and views (`IZetherToken`, `ZetherLayer`), `UAMetaTransaction` by its ABI
    struct AccountState { bytes accC; bytes accD; bytes pendingC; bytes pendingD; uint64 accSeq; uint64 pendingSeq; uint64 sendCounter;
        uint64 modeNonce; uint8 mode; }
    struct ZetherEnvelope { bytes32 from; bytes data; uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode; address relayer;
        uint256 fee; address feeRecipient; }
    function accountState(bytes32 ua) external view returns (AccountState);
    function envelopeBinding(ZetherEnvelope m) external view returns (bytes32);
    function mtxShield(bytes32 toUA, uint256 amount) external;
    function mtxRollOver(bytes32 ua, uint256 n) external;
}

/// `zether-cli <cmd>` (clients/zether-prover, `ZETHER_CLI` overrides the path) on the JSON request `req`.
fn zether_cli(cmd: &str, req: &Value) -> Value {
    use std::io::Write;
    let cli = std::env::var("ZETHER_CLI")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../clients/zether-prover/target/release/zether-cli").into());
    let mut c = Command::new(&cli).arg(cmd).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()
        .unwrap_or_else(|e| panic!("{cli}: {e} (cargo build --release --bin zether-cli in clients/zether-prover)"));
    c.stdin.take().unwrap().write_all(req.to_string().as_bytes()).unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success(), "zether-cli {cmd} failed");
    serde_json::from_slice(&out.stdout).unwrap()
}

/// CTR-ZTH-51 (R35) through the node: a classical Zether unshield proof bound to the UA binding of an EOA's envelope
/// (`SCAAS-ZETHER-UA-ENVELOPE-V1`, `from` the payer's padded id), relayed as the named merged entry `mtxUnshield(UAEnvelope, …,
/// UASig)` (`UAZetherUnshield`) in a `ua_metatx` job at fee 0: the payer signs with its own key, the proof is the Zether UA's.
/// The binding the client computes equals the token's `envelopeBinding`; the node's digest equals `zether-cli namedCall`'s.
#[tokio::test]
#[ignore]
async fn relayed_zether_proof_under_the_ua_tag() {
    let chain_id = 31913;
    let (_anvil, rpc) = start_anvil(chain_id, 31913).await;
    let deployer = key(DEPLOYER);
    let dep = deploy_with(&rpc, chain_id, deployer.address(), true);
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
    let registry: Address = dep["zether_registry"].as_str().unwrap().parse().unwrap();
    // the Zether UA of a test key x (< r), its portable PoP from clientkeys, registered by the deployer
    let mut x = keccak256(b"scaas.e2e.node.zether.x");
    x.0[0] = 0;
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/..");
    let js = format!("import {{ zetherPop }} from '{root}/clients/clientkeys/src/zether.js'; import {{ fromHex }} from '{root}/clients/clientkeys/src/bytes.js';\
        const p = zetherPop('bls12381', fromHex('{x:#x}')); console.log(JSON.stringify({{Y: p.Y, UA: p.UA, pop: p.pop}}));");
    let out = Command::new("node").args(["--input-type=module", "-e", &js]).output().expect("node in PATH");
    assert!(out.status.success(), "clientkeys zetherPop: {}", String::from_utf8_lossy(&out.stderr));
    let p: Value = serde_json::from_slice(&out.stdout).unwrap();
    let hexb = |v: &Value| Bytes::from(alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap());
    let ua: B256 = p["UA"].as_str().unwrap().parse().unwrap();
    send(&rpc, &deployer, registry, registerCall { kind: 0x0141, keyData: hexb(&p["Y"]), attrs: UAAttrs { pqzKey: Bytes::new(), pqzPopHash: B256::ZERO,
        kem: KemKey { scheme: 0, mlkemEk: Bytes::new(), x25519: B256::ZERO }, kemPkHash: B256::ZERO }, pop: hexb(&p["pop"]),
        pqzPop: Bytes::new() }.abi_encode()).await;
    // a NORMAL_ZETHER token (BUNDLE, no auditor, scale 1), 1234 shielded to the UA and rolled over
    let c = TokenConfig { name: "Zether Node E2E".into(), symbol: "zN".into(), decimals: 6, features: U256::from(1u8),
        initialSupply: U256::from(1_000_000u64), initialHolder: deployer.address(),
        conf: ConfidentialConfig { shieldScale: U256::from(1u8), maxShielded: U256::from(1u64 << 40), ..Default::default() }, ..Default::default() };
    let t = create(&rpc, &deployer, factory, createTokenCall { kind: 2, version: 1, initArgs: c.abi_encode().into(), salt: B256::repeat_byte(0x2e) }.abi_encode()).await;
    send(&rpc, &deployer, t, mtxShieldCall { toUA: ua, amount: U256::from(1_234u64) }.abi_encode()).await;
    send(&rpc, &deployer, t, mtxRollOverCall { ua, n: U256::from(1u8) }.abi_encode()).await;
    let st = view(&rpc, t, accountStateCall { ua }).await;
    // the payer EOA's envelope (fee 0, open relayer) and its UA binding under the UA tag, as a client computes it
    let payer = small_key(0xEE0E);
    let from = payer.address().into_word();
    let (batch, valid_until) = (U256::from(7u8), U256::from(now() + 3_600));
    let nonce = view(&rpc, t, IMtxIds::mtxNonceCall { from, batch }).await;
    let binding = keccak256((keccak256(b"SCAAS-ZETHER-UA-ENVELOPE-V1"), U256::from(chain_id), uid, t, from, batch, nonce, valid_until,
        U256::ZERO, Address::ZERO, U256::ZERO, Address::ZERO).abi_encode_params());
    let m = ZetherEnvelope { from, data: Bytes::new(), batch, nonce, validUntil: valid_until, mode: 0, relayer: Address::ZERO, fee: U256::ZERO,
        feeRecipient: Address::ZERO };
    assert_eq!(view(&rpc, t, envelopeBindingCall { m }).await, binding, "the token's envelopeBinding");
    // the prover binds the unshield of 20 to it; `namedCall` gives the typed message and the digest the payer signs
    let block = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_block_number().await.unwrap();
    let hx = |b: &Bytes| format!("0x{}", alloy::hex::encode(b));
    let burn = zether_cli("proveBurn", &json!({"curve": "bls12381", "key": {"x": format!("{x:#x}")}, "chainId": chain_id,
        "chainUid": format!("{uid:#x}"), "token": format!("{t:#x}"), "sendCounter": st.sendCounter, "accSeq": st.accSeq,
        "validUntilBlock": block + 100_000, "acc": {"C": hx(&st.accC), "D": hx(&st.accD)}, "balance": 1_234, "fee": 0,
        "disclosureMode": "bundle", "auditorMode": "none", "yAud": null, "includeWitness": true, "envelopeBinding": format!("{binding:#x}"),
        "amount": 20, "recipient": format!("{:#x}", deployer.address())}));
    let z = format!("{:#x}", Address::ZERO);
    let env = json!({"from": format!("{from:#x}"), "batch": batch.to_string(), "nonce": nonce.to_string(), "validUntil": valid_until.to_string(),
        "mode": "0", "relayer": z, "fee": "0", "feeRecipient": z});
    let named = zether_cli("namedCall", &json!({"op": "UAZetherUnshield", "chainId": chain_id, "chainUid": format!("{uid:#x}"),
        "token": format!("{t:#x}"), "env": env, "payload": burn["payload"], "proof": burn["proof"], "beneficiary": format!("{:#x}", B256::ZERO),
        "amount": "20", "recipient": format!("{:#x}", deployer.address().into_word())}));
    // the node's op: the typed message's envelope fields apart, the rest its named arguments
    let mut args = named["message"].as_object().unwrap().clone();
    let mut envelope = serde_json::Map::new();
    for k in ["from", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"] {
        envelope.insert(k.into(), args.remove(k).unwrap());
    }
    envelope["mode"] = json!(0);
    let op = json!({"entry": "mtxUnshield", "contract": "zether", "struct": "UAZetherUnshield", "token": format!("{t:#x}"),
        "envelope": envelope, "args": args});
    let op = signed_op(&payer, op, chain_id, uid);
    let node_digest = scaas_node::typed::Op::parse(&op, None).unwrap().typed.digest_on(chain_id, uid).unwrap();
    assert_eq!(format!("{node_digest:#x}"), named["digest"].as_str().unwrap().to_lowercase(), "the node's digest is the prover's");
    let (state, _odoo, mut s) = outbox(chain_id, &rpc, &[t]).await;
    let public = balance(&rpc, t, deployer.address()).await;
    state.lock().unwrap().jobs.push(json!({"id": 1, "kind": "ua_metatx", "op": op}));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    assert_eq!(balance(&rpc, t, deployer.address()).await, public + U256::from(20u8), "the unshield paid the recipient");
    assert_eq!(view(&rpc, t, IMtxIds::mtxNonceCall { from, batch }).await, nonce + U256::from(1u8), "the payer's lane moved");
    let rc = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_receipt(tx_of(&state, 1).parse().unwrap()).await.unwrap().unwrap();
    assert!(rc.inner.logs().iter().any(|l| l.topic0() == Some(&IUALedger::UAMetaTransactionExecuted::SIGNATURE_HASH) && l.topics()[1] == from),
        "UAMetaTransactionExecuted of the payer's id");
    let after = view(&rpc, t, accountStateCall { ua }).await;
    let left = zether_cli("decrypt", &json!({"curve": "bls12381", "key": {"x": format!("{x:#x}")}, "ct": {"C": hx(&after.accC), "D": hx(&after.accD)},
        "tableBits": 18, "boundBits": 32}));
    assert_eq!(left["amount"].as_str().map(str::to_string).unwrap_or_else(|| left["amount"].to_string()), "1214", "the UA's balance by decryption");
}
