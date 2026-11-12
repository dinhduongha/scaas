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
use scaas_node::abi::{IERC165, IMtxIds, IToken, IUALedger, UAMetaTransaction, UAMetaTransfer, UASig};
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

/// The anvil's `DEPLOY_NAME` (NET-EVM-13: a chain not in `chain-uids.json`), its book `deployments/<name>.json`.
fn book_name(chain_id: u64) -> String {
    format!("local-{chain_id}-testnet")
}

/// Deploy factory + implementation + DEX + token demo (một nửa cung cho `holder`).
fn deploy(rpc: &str, chain_id: u64, holder: Address) -> Value {
    deploy_with(rpc, chain_id, holder, false)
}

/// As [`deploy`]; `zether`: the Zether stack too (`DEPLOY_ZETHER=1`, `deploy.sh`'s `--gas-estimate-multiplier 105`).
fn deploy_with(rpc: &str, chain_id: u64, holder: Address, zether: bool) -> Value {
    deploy_env(rpc, chain_id, holder, zether, &[])
}

/// As [`deploy_with`], with more environment for the script (`DEPLOY_PQCHAT`).
fn deploy_env(rpc: &str, chain_id: u64, holder: Address, zether: bool, env: &[(&str, &str)]) -> Value {
    let sc = sc();
    let mut cmd = Command::new("forge");
    cmd.current_dir(sc)
        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--slow", "--silent", "--disable-code-size-limit", "--sender", DEPLOYER_ADDRESS]);
    if zether {
        cmd.args(["--gas-estimate-multiplier", "105"]).env("DEPLOY_ZETHER", "true");
    }
    cmd.envs(env.iter().copied());
    let status = cmd
        .env("PRIVATE_KEY", DEPLOYER)
        .env("DEMO_SUPPLY", "1000000000000")
        .env("DEMO_HOLDER", format!("{holder:#x}"))
        .env("FOUNDRY_PROFILE", "scaas-testnet")
        .env("DEPLOY_NAME", book_name(chain_id))
        .status()
        .expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let raw = std::fs::read_to_string(format!("{sc}/deployments/{}.json", book_name(chain_id))).expect("deployments json");
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

    // pay-meta-tax T42 (`pay_with_meta_on_anvil`): a pay job is the named entry `mtxPay(t, auth, meta)`, `meta` named per
    // schema (the node builds the body), on a free lane; the indexer gives `PaymentMeta`'s fields to its PaymentSettled
    // plan T83: `payNo` a right-aligned UUIDv7, `save` on: the token stores the record (`paymentsOf`)
    let named = json!({"salt": format!("{:#x}", B256::repeat_byte(0x51)), "payNo": "0x00000000000000000000000000000000019a6e3c5f007a3b8c4d5e6f708192a3", "save": true, "schema": 1,
        "body": {"note": "hello"}});
    let pid = scaas_node::metatx::meta_pay_id(&scaas_node::typed::pay_meta_of(&scaas_node::typed::parse("PayMeta", &named, "meta").unwrap()).unwrap());
    let pm = payment(payer.address(), shop, 1_000, pid, U256::from(41), MODE_RESTRICT_RELAYER, relayer.address(), 0, Address::ZERO);
    let pay = signed_op(&payer, json!({"entry": "mtxPay", "contract": "token", "token": format!("{token:#x}"),
        "args": {"t": pm.to_wire().1, "meta": named}}), chain_id, d.salt);
    state.lock().unwrap().jobs.push(json!({"id": 7, "kind": "ua_metatx", "op": pay}));
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
    assert_eq!((paid["amount"].as_str(), paid["pay_no"].as_str(), paid["meta_body"].as_str()),
        (Some("1000"), Some("0x00000000000000000000000000000000019a6e3c5f007a3b8c4d5e6f708192a3"), Some(format!("0x{}", alloy::hex::encode(b"hello")).as_str())));
    assert_eq!(paid["meta_save"], true);

    // T17 (CTR-MTX-27) on the real router: a fee-less `cancelNonce(77)` of the payer, its fee of 10 in open mode; the
    // node relays `relay` (call-table row RelayFeeRouter.relay, the `UARelayFee` of the payer's padded id), the fee reaches the
    // lane, the indexer joins RelayFeePaid
    let router: Address = dep["relay_fee_router"].as_str().expect("relay_fee_router in the deploy JSON").parse().unwrap();
    let out = p.call(TransactionRequest::default().to(router).input(scaas_node::abi::IRelayFeeRouter::EXECUTORCall {}.abi_encode().into()))
        .await.unwrap();
    assert_eq!(Address::abi_decode(&out).unwrap(), router.create(1), "the executor the node derives (never paid)");
    let inner = signed_op(&payer, cancel_op(payer.address(), token, 77, 8), chain_id, d.salt);
    let parsed = scaas_node::typed::Op::parse(&inner, None).unwrap();
    let r = scaas_node::metatx::relay_ref(chain_id, token, &parsed.data);
    let inner_digest = parsed.typed.digest_on(chain_id, d.salt).unwrap();
    let relay = signed_op(&payer, json!({"entry": "mtxRelayFee", "contract": "token", "token": format!("{token:#x}"), "call": inner,
        "args": {"from": format!("{:#x}", payer.address().into_word()), "payee": format!("{:#x}", router.into_word()), "value": "10",
            "batch": "9", "nonce": "0", "validUntil": (now() + 300).to_string(), "relayer": format!("{router:#x}")}}), chain_id, d.salt);
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
                // T93 (UA-7 P17, topics P45): the twelve `PqChat` writes
                "pqchat" => "IPqChat",
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
    assert_eq!(n, 32, "32 rows, one contract each (22 before MD-11 (a): the wallet's four flat rows retired; 18 -> 30, T93: PqChat's twelve; \
        30 -> 32: the DEX's mtxLiquidity (CTR-DEX-30) and PqChat's remove (UA-7 P48))");
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
/// (1) a pay-meta job (`mtxPayMeta` on ids), and (2) a relay fee for a fee-less call through `RelayFeeRouter.relay` (`UARelayFee`,
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
    let router: Address = dep["relay_fee_router"].as_str().unwrap().parse().unwrap();
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
    let last = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap();
    let signed = |id: i64| state.lock().unwrap().reports.iter().find(|r| r["job_id"] == id && r["chain_state"] == "signed")
        .map(|r| r["tx_hash"].as_str().unwrap().to_string()).unwrap();
    let eth = || async { p.get_balance(relayer.address()).await.unwrap() };

    // (1) a UA's pay (pay-meta-tax T42): the named entry mtxPay with its PayMeta, the node's digest is the token's
    let shop = Address::repeat_byte(0x5e);
    let named = json!({"salt": format!("{:#x}", B256::repeat_byte(0x52)), "payNo": format!("{:#x}", B256::with_last_byte(77))});
    let pid = meta_pay_id(&scaas_node::typed::pay_meta_of(&scaas_node::typed::parse("PayMeta", &named, "meta").unwrap()).unwrap());
    let t = UAMetaTransfer { from: ua, to: shop.into_word(), value: U256::from(1_000u64), entryRef: pid, batch: pay_lane(&pid),
        nonce: U256::ZERO, validUntil: U256::from(now() + 300), mode: MODE_RESTRICT_RELAYER, relayer: relayer.address(),
        fee: U256::ZERO, feeRecipient: Address::ZERO };
    let m = UaMtx::Transfer(t.clone());
    assert_eq!(view(&rpc, token, IMtxIds::mtxTransferDigestCall { t }).await, m.digest(&d), "mtxTransferDigest");
    let pay = json!({"entry": "mtxPay", "contract": "token", "token": format!("{token:#x}"), "args": {"t": m.to_wire().1, "meta": named},
        "auth": ua_auth(&rpc, registry, &owner, b"scaas.ua.purpose.metatx.v1", m.digest(&d)).await});
    state.lock().unwrap().jobs.push(json!({"id": 1, "kind": "ua_metatx", "op": pay}));
    run_outbox(&mut s).await;
    assert_eq!(last(1)["chain_state"], "mined", "{}", last(1));
    assert_eq!(balance(&rpc, token, shop).await, U256::from(1_000u64), "the UA paid the shop");

    // (2) UA relay fee for the payer's fee-less merged cancelNonce(55) (its native id), open mode
    let inner = signed_op(&payer, cancel_op(payer.address(), token, 55, 12), chain_id, d.salt);
    let r = relay_ref(chain_id, token, &scaas_node::typed::Op::parse(&inner, None).unwrap().data);
    // pay-meta-tax T38: the UA payer's own relay-fee lane 12, at `nonce`
    let relay_job = |id: i64, value: u64, inner: Value, nonce: u64| {
        let mut op = json!({"entry": "mtxRelayFee", "contract": "token", "token": format!("{token:#x}"), "call": inner,
            "args": {"from": format!("{ua:#x}"), "payee": format!("{:#x}", router.into_word()), "value": value.to_string(),
                "batch": "12", "nonce": nonce.to_string(), "validUntil": (now() + 300).to_string(), "relayer": format!("{router:#x}")},
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
    let j = relay_job(2, 1, inner.clone(), 0).await;
    state.lock().unwrap().jobs.push(j);
    run_outbox(&mut s).await;
    let l = last(2);
    assert!(l["chain_state"] == "queued" && l["error"].as_str().unwrap().starts_with("RELAY_FEE_REFUSED"), "{l}");
    assert_eq!(p.get_transaction_count(relayer.address()).await.unwrap(), n0, "nothing signed or sent");
    // a fee of 1,000 (10^14 wei at the price) covers it
    let j = relay_job(3, 1_000, inner.clone(), 0).await;
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
    assert_eq!(paid["pay_no"], format!("{:#x}", B256::with_last_byte(77)));
    assert_eq!(paid["meta_save"], false);
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
    let j = relay_job(4, 1_000, inner, 1).await;
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

alloy::sol! {
    function predictAddress(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt) external view returns (address);
    function isDex(address dex) external view returns (bool);
    function isToken(address token) external view returns (bool);
    /// `PqChat`'s owner (class 3, kind 0): 0 or its creator.
    function owner() external view returns (bytes32);
}

/// Owner 2026-11-12 (every state-changing `mtx*` relayable, fee 0 too): an EOA with no gas signs `mtxCreateDex` and `mtxCreateToken`
/// on the chain's `GovernanceRouter`, the config as named JSON; the node encodes it as the factory's `initArgs` and relays both at
/// fee 0: the factory records a DEX and a token at the creator's predicted addresses. The negative: the same creation with a job
/// `initHash` is `dead` `BAD_PAYLOAD`, nothing sent (the lane's nonce does not move).
#[tokio::test]
#[ignore]
async fn router_creations_signed_by_an_eoa() {
    let chain_id = 31918;
    let (_anvil, rpc) = start_anvil(chain_id, 31918).await;
    let owner = small_key(0x61F); // never funded
    let dep = deploy(&rpc, chain_id, owner.address());
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let router: Address = dep["governance_router"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    let lane = U256::from_be_slice(factory.as_slice());
    let z = |b: u8| format!("{:#x}", B256::repeat_byte(b));
    let a = |b: u8| format!("{:#x}", Address::repeat_byte(b));
    let me = format!("{:#x}", owner.address().into_word());
    let dex_op = signed_op(&owner, json!({"entry": "mtxCreateDex", "contract": "gov_router", "token": format!("{router:#x}"),
        "args": {"target": format!("{factory:#x}"), "version": "1", "salt": z(0x61),
            "config": {"admin": me, "relayerSharePpm": 0, "treasury": a(0x7a), "listedOnly": true, "grantDelay": "0", "rescueTo": a(0)}},
        "envelope": envelope(owner.address(), lane, 0)}), chain_id, uid);
    let token_op = signed_op(&owner, json!({"entry": "mtxCreateToken", "contract": "gov_router", "token": format!("{router:#x}"),
        "args": {"target": format!("{factory:#x}"), "kind": 0, "version": "1", "salt": z(0x62),
            "config": {"name": "Relayed", "symbol": "RLY", "decimals": 6, "features": "1", "lockedFeatures": "0", "admin": me,
                "roles": {"minter": z(0), "rateAdmin": z(0), "guardian": z(0), "issuer": z(0), "compliance": z(0)},
                "initialSupply": "1000", "initialHolder": format!("{:#x}", owner.address()), "legs": [], "rate": {"rateDelay": 0, "maxRateStepBps": 0},
                "conf": {"auditorKey": "0x", "shieldScale": "0", "maxShielded": "0", "confidentialFee": "0", "disclosureMode": 0, "auditorMode": 0,
                    "minDecoyFee": "0", "pqzVerifyMode": 0, "pqzVerifierUA": z(0), "pqzVerifierFixed": false, "proofStore": 0, "verifierFee": "0",
                    "verifierFeeMax": "0"},
                "grantDelay": "0", "rescueTo": a(0), "maxSupply": "0",
                "reg": {"complianceRegistry": a(0), "requiredFlags": "0", "deniedFlags": "0", "termsHash": z(0), "taxRecipient": z(0)}}},
        "envelope": envelope(owner.address(), lane, 1)}), chain_id, uid);
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let report = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap();
    let cfg = ChainCfg { governance_routers: vec![router], ..chain_cfg(chain_id, &rpc, None) };
    let mut s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo.clone(), cfg.clone(), "e2e-create".into(),
        Default::default()).await.unwrap();
    let mut forged = dex_op.clone();
    forged["args"]["initHash"] = json!(z(1));
    state.lock().unwrap().jobs.push(json!({"id": 1, "kind": "ua_metatx", "op": forged}));
    run_outbox(&mut s).await;
    assert_eq!(report(1)["chain_state"], "dead", "{}", report(1));
    assert!(report(1)["error"].as_str().unwrap().contains("BAD_PAYLOAD: args.initHash"), "{}", report(1));
    let nonce = IMtxIds::mtxNonceCall { from: owner.address().into_word(), batch: lane };
    assert_eq!(view(&rpc, router, nonce.clone()).await, U256::ZERO, "nothing sent");
    for (id, op) in [(2, dex_op), (3, token_op)] {
        state.lock().unwrap().jobs.push(json!({"id": id, "kind": "ua_metatx", "op": op}));
        run_outbox(&mut s).await;
        assert_eq!(report(id)["chain_state"], "mined", "{}", report(id));
    }
    let dex = view(&rpc, factory, predictAddressCall { creatorId: owner.address().into_word(), contractClass: 2, kind: 0,
        salt: B256::repeat_byte(0x61) }).await;
    let tok = view(&rpc, factory, predictAddressCall { creatorId: owner.address().into_word(), contractClass: 1, kind: 0,
        salt: B256::repeat_byte(0x62) }).await;
    assert!(view(&rpc, factory, isDexCall { dex }).await && view(&rpc, dex, listedOnlyCall {}).await, "the DEX, its named config");
    assert!(view(&rpc, factory, isTokenCall { token: tok }).await, "the token");
    assert_eq!(view(&rpc, router, nonce).await, U256::from(2u64), "two creations on the factory's lane");
}

/// Owner 2026-11-12 (`mtxCreateInstance`, "both the generic row and the per-class ones"): an EOA with no gas signs two `PqChat`
/// creations (class 3, kind 0) on the chain's `GovernanceRouter`, relayed at fee 0: one names its `init_call` bytes
/// (`initialize(0)`), the other the class's named config `{owner: <creator>}`, which the node builds into the call; both instances
/// stand at the creator's predicted addresses with their owners. The negatives, `dead` with nothing sent (the lane's nonce does
/// not move): both forms in one job, an owner that is not the creator, an unpublished release (`RELEASE_UNKNOWN`, read from the
/// factory before the simulation).
#[tokio::test]
#[ignore]
async fn router_instance_creations_signed_by_an_eoa() {
    let chain_id = 31919;
    let (_anvil, rpc) = start_anvil(chain_id, 31919).await;
    let owner = small_key(0x620); // never funded
    let dep = deploy_env(&rpc, chain_id, owner.address(), false, &[("DEPLOY_PQCHAT", "true")]);
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let router: Address = dep["governance_router"].as_str().unwrap().parse().unwrap();
    let factory: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
    let token: Address = dep["demo_token"].as_str().unwrap().parse().unwrap();
    assert!(dep["pqchat_implementation"].is_string(), "PqChat release 1 of (3, 0)");
    let lane = U256::from_be_slice(factory.as_slice());
    let z = |b: u8| format!("{:#x}", B256::repeat_byte(b));
    let me = format!("{:#x}", owner.address().into_word());
    let op = |args: Value, nonce: u64| signed_op(&owner, json!({"entry": "mtxCreateInstance", "contract": "gov_router",
        "token": format!("{router:#x}"), "args": args, "envelope": envelope(owner.address(), lane, nonce)}), chain_id, uid);
    let base = |salt: u8, version: &str| json!({"target": format!("{factory:#x}"), "contractClass": 3, "kind": 0, "version": version,
        "salt": z(salt)});
    let with = |mut a: Value, k: &str, v: Value| { a[k] = v; a };
    let init_zero = json!(format!("0x{}{}", alloy::hex::encode(&alloy::primitives::keccak256("initialize(bytes32)")[..4]), "00".repeat(32)));
    let raw_op = op(with(base(0x71, "1"), "init_call", init_zero.clone()), 0);
    let named_op = op(with(base(0x72, "1"), "config", json!({"owner": me})), 1);
    let both = op(with(with(base(0x73, "1"), "config", json!({"owner": me})), "init_call", init_zero), 2);
    let stranger = op(with(base(0x74, "1"), "config", json!({"owner": z(0x0b)})), 2);
    let unpublished = op(with(base(0x75, "9"), "config", json!({"owner": me})), 2);
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let report = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap();
    let cfg = ChainCfg { governance_routers: vec![router], ..chain_cfg(chain_id, &rpc, None) };
    let mut s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo.clone(), cfg.clone(), "e2e-instance".into(),
        Default::default()).await.unwrap();
    let nonce = IMtxIds::mtxNonceCall { from: owner.address().into_word(), batch: lane };
    for (id, op, want) in [(1, both, "BAD_PAYLOAD: args.config and args.init_call"), (2, stranger, "args.config.owner: 0 or the creator"),
                           (3, unpublished, "RELEASE_UNKNOWN")] {
        state.lock().unwrap().jobs.push(json!({"id": id, "kind": "ua_metatx", "op": op}));
        run_outbox(&mut s).await;
        assert_eq!(report(id)["chain_state"], "dead", "{}", report(id));
        assert!(report(id)["error"].as_str().unwrap().contains(want), "{want}: {}", report(id));
    }
    assert_eq!(view(&rpc, router, nonce.clone()).await, U256::ZERO, "nothing sent");
    for (id, op) in [(4, raw_op), (5, named_op)] {
        state.lock().unwrap().jobs.push(json!({"id": id, "kind": "ua_metatx", "op": op}));
        run_outbox(&mut s).await;
        assert_eq!(report(id)["chain_state"], "mined", "{}", report(id));
    }
    let at = |salt: u8| predictAddressCall { creatorId: owner.address().into_word(), contractClass: 3, kind: 0, salt: B256::repeat_byte(salt) };
    let (raw_at, named_at) = (view(&rpc, factory, at(0x71)).await, view(&rpc, factory, at(0x72)).await);
    assert_eq!(view(&rpc, raw_at, ownerCall {}).await, B256::ZERO, "init_call: initialize(0)");
    assert_eq!(view(&rpc, named_at, ownerCall {}).await, owner.address().into_word(), "the named config: the creator owns it");
    assert_eq!(view(&rpc, router, nonce).await, U256::from(2u64), "two creations on the factory's lane");
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
    // group 3f (spec §3, AV-2): `pqzVerifyMode`, `pqzVerifierUA`, `pqzVerifierFixed` appended (0, 0, false for every other kind);
    // group 3h T60 (pqz-proof-path spec §4.1): `proofStore` (0 NONE, 1 LOG; 0 for every other kind)
    struct ConfidentialConfig { bytes auditorKey; uint256 shieldScale; uint256 maxShielded; uint256 confidentialFee; uint8 disclosureMode;
        uint8 auditorMode; uint256 minDecoyFee; uint8 pqzVerifyMode; bytes32 pqzVerifierUA; bool pqzVerifierFixed; uint8 proofStore;
        uint64 verifierFee; uint64 verifierFeeMax; } // round 3t (CTR-PQZ-36): the verifier fee and its cap (0 off)
    /// Regulated-kinds spec §2.4 (plan T25): the regulated kinds' (8-13) only; a plain kind refuses any set field.
    #[derive(Default)]
    struct RegulatedParams { address complianceRegistry; uint64 requiredFlags; uint64 deniedFlags; bytes32 termsHash;
        bytes32 taxRecipient; }
    #[derive(Default)]
    struct TokenConfig { string name; string symbol; uint8 decimals; uint256 features; uint256 lockedFeatures; bytes32 owner; Roles roles;
        uint256 initialSupply; address initialHolder; Leg[] legs; RateConfig rate; ConfidentialConfig conf; uint64 grantDelay;
        address rescueTo; uint256 maxSupply; RegulatedParams reg; }
    // chain-neutral releases (CTR-TOK-29, plan T71 / T74): the factory fills its own `chainUid` and router; `params` the
    // class's chain values
    struct FactoryEnv { address registry; address smartKeyAccountImpl; bool hedera; address[] deps; bytes32[] params;
        address[] libs; bytes32[] libCodeHashes; }
    function tokenEnvOf(uint8 kind, uint16 envVersion) external view returns (FactoryEnv);
    function publishTokenEnv(uint8 kind, uint16 envVersion, bytes32 chainUid, FactoryEnv env) external;
    function deployTokenImplementation(uint8 kind, uint64 version, uint16 envVersion, bytes initcode, bytes implArgs, bytes32 chainUid) external returns (address);
    function createToken(uint8 kind, uint64 version, bytes initArgs, bytes32 salt) external returns (address);
    function registry() external view returns (address);
    function epoch(address token) external view returns (uint64);
    // T66b §4.5 (CTR-TOK-30): a token release names its body modules in `implArgs`, one named struct; `modules()` lists them
    struct ImplArgs { address[] modules; }
    function implementationOf(uint8 kind, uint64 version) external view returns (address);
    function modules() external view returns (address[]);
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
    let mut env = view(rpc, f, tokenEnvOfCall { kind: 0, envVersion: 1 }).await;
    assert_ne!(env.registry, Address::ZERO, "the deploy's NORMAL release is on the registry");
    env.registry = Address::ZERO;
    let chain_uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap(); // the factory's word (CTR-GOV-27)
    send(rpc, &deployer, f, publishTokenEnvCall { kind: 0, envVersion: 2, chainUid: chain_uid, env }.abi_encode()).await;
    let code = linked(chain_id, "NormalToken.sol", "NormalToken");
    // T66b §4.5: version 2 names version 1's body modules (pinned in env 1, so in env 2)
    let v1 = view(rpc, f, implementationOfCall { kind: 0, version: 1 }).await;
    let impl_args = ImplArgs { modules: view(rpc, v1, modulesCall {}).await }.abi_encode().into();
    let chain_uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    send(rpc, &deployer, f, deployTokenImplementationCall { kind: 0, version: 2, envVersion: 2, initcode: code.into(), implArgs: impl_args,
        chainUid: chain_uid }.abi_encode()).await;
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
    // the delegate's payment on the lane of its entryRef, nonce 0; pay-meta-tax T42: its `PayMeta` last, `entryRef` the commitment
    let named = json!({"salt": format!("{:#x}", keccak256(b"invoice 9")), "payNo": format!("{:#x}", keccak256(b"invoice 9")), "save": true});
    let entry_ref = scaas_node::metatx::meta_pay_id(&scaas_node::typed::pay_meta_of(&scaas_node::typed::parse("PayMeta", &named, "meta").unwrap()).unwrap());
    let pay = |entry: &str| signed_op(&delegate, w(entry, json!({"token": t, "payee": format!("{:#x}", shop.into_word()), "amount": "300000",
        "entryRef": format!("{entry_ref:#x}"), "epoch": epoch.to_string(), "meta": named.clone()}), delegate.address(),
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

// ------------------------------------------------------------------ regulated kinds 8-13 on anvil (plan T35)

alloy::sol! {
    function isFrozen(bytes32 account) external view returns (bool);
}

/// The deploy with the regulated releases and the canonical `ComplianceRegistry` (`DEPLOY_REGULATED`, its admin a UA id since
/// round 3r, CTR-GOV-23: `COMPLIANCE_ADMIN` the native id of a contract, code set by `anvil_setCode`), a `SmartKeyAccount` of
/// `issuer_key` as the `issuer` (bit 5 is contract-only), and a kind-8 token with `FREEZE` whose supply is `holder`'s. No list
/// is on: no registry read.
async fn regulated_token(chain_id: u64, rpc: &str, issuer_key: &PrivateKeySigner, holder: Address) -> (Value, Address, Address) {
    let admin = Address::repeat_byte(0xad);
    let p = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let _: Value = p.raw_request("anvil_setCode".into(), (admin, "0x00")).await.unwrap();
    let sc = sc();
    let status = Command::new("forge").current_dir(sc)
        .args(["script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast", "--slow", "--silent", "--disable-code-size-limit", "--sender", DEPLOYER_ADDRESS])
        .env("PRIVATE_KEY", DEPLOYER).env("DEMO_SUPPLY", "1000000000000").env("DEMO_HOLDER", format!("{holder:#x}"))
        .env("FOUNDRY_PROFILE", "scaas-testnet").env("DEPLOY_REGULATED", "true").env("COMPLIANCE_ADMIN", format!("{:#x}", admin.into_word()))
        .env("DEPLOY_NAME", book_name(chain_id))
        .status().expect("forge in PATH");
    assert!(status.success(), "forge script failed");
    let dep: Value = serde_json::from_str(&std::fs::read_to_string(format!("{sc}/deployments/{}.json", book_name(chain_id))).unwrap()).unwrap();
    assert!(dep["implementation_normal_regulated"].is_string() && dep["compliance_registry"].is_string(), "{dep}");
    let deployer = key(DEPLOYER);
    let factory: Address = dep["smart_key_account_factory"].as_str().unwrap().parse().unwrap();
    let first = SubjectKey { kind: 2, x: issuer_key.address().into_word(), y: B256::ZERO, rpIdHash: B256::ZERO, originHash: B256::ZERO };
    let issuer = create(rpc, &deployer, factory, deployCall { firstKey: first, guardian: Address::repeat_byte(0x6a) }.abi_encode()).await;
    let f: Address = dep["token_factory"].as_str().unwrap().parse().unwrap();
    let c = TokenConfig { name: "SCaaS Regulated".into(), symbol: "bREG".into(), decimals: 6, features: U256::from(1u64 << 5), // FREEZE
        owner: deployer.address().into_word(), roles: Roles { issuer: issuer.into_word(), ..Default::default() },
        initialSupply: U256::from(1_000_000u64), initialHolder: holder,
        reg: RegulatedParams { termsHash: B256::repeat_byte(0x7e), ..Default::default() }, ..Default::default() };
    let t = create(rpc, &deployer, f, createTokenCall { kind: 8, version: 1, initArgs: c.abi_encode().into(), salt: B256::repeat_byte(0x35) }.abi_encode()).await;
    let id = view(rpc, t, IERC165::supportsInterfaceCall { id: scaas_node::abi::regulated_interface_id().into() }).await;
    assert!(id, "a kind-8 token answers type(IRegulatedToken).interfaceId (the node's XOR)");
    (dep, t, issuer)
}


/// The router's `mtxFreeze` (`mtx<Op>`, op `UA<Op>`), or another of the eight, signed by the issuer account through ERC-1271 (its
/// owner key's ECDSA in the account's `(keyIndex, proof, sig)` form), on the target's lane.
#[allow(clippy::too_many_arguments)]
fn issuer_op(entry: &str, args: Value, issuer: Address, owner: &PrivateKeySigner, router: Address, token: Address, nonce: u64, chain_id: u64,
    uid: B256) -> Value
{
    let mut op = json!({"entry": entry, "contract": "gov_router", "token": format!("{router:#x}"), "args": args,
        "envelope": envelope(issuer, U256::from_be_slice(token.as_slice()), nonce),
        "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}});
    let d = scaas_node::typed::Op::parse(&op, None).unwrap().typed.digest_on(chain_id, uid).unwrap();
    let ecdsa = owner.sign_hash_sync(&d).unwrap().as_bytes().to_vec();
    let sig = (U256::ZERO, Vec::<B256>::new(), Bytes::from(ecdsa)).abi_encode_params();
    op["auth"]["signature"] = json!(format!("0x{}", alloy::hex::encode(sig)));
    op
}

/// Regulated-kinds spec §3.1, §7 (plan T35): the issuer's `mtxFreeze` on the chain's `GovernanceRouter`, a `ua_metatx` job relayed at
/// fee 0 by a lane that holds no role (the issuer a contract, ERC-1271); the token's `isFrozen` reads true, and the indexer
/// sends `AccountFrozen` with an `alert`.
#[tokio::test]
#[ignore]
async fn regulated_freeze_relayed_by_router() {
    let chain_id = 31914;
    let (_anvil, rpc) = start_anvil(chain_id, 31914).await;
    let (owner, holder) = (small_key(0x35A), small_key(0x35B));
    let (dep, token, issuer) = regulated_token(chain_id, &rpc, &owner, holder.address()).await;
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let router: Address = dep["governance_router"].as_str().unwrap().parse().unwrap();
    let a = holder.address().into_word();
    let op = issuer_op("mtxFreeze", json!({"target": format!("{token:#x}"), "account": format!("{a:#x}"),
        "ref": format!("{:#x}", B256::repeat_byte(0x5e)), "recordId": format!("{:#x}", B256::ZERO)}), issuer, &owner, router, token, 0, chain_id, uid);
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let cfg = ChainCfg { governance_routers: vec![router], ..chain_cfg(chain_id, &rpc, None) };
    let mut s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo.clone(), cfg.clone(), "e2e-reg-0".into(),
        Default::default()).await.unwrap();
    assert!(!view(&rpc, token, isFrozenCall { account: a }).await);
    state.lock().unwrap().jobs.push(json!({"id": 1, "kind": "ua_metatx", "op": op}));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    assert!(view(&rpc, token, isFrozenCall { account: a }).await, "the issuer's freeze ran through the router");
    let ichain = Chain::with_signer(&cfg, key(RELAYER)).unwrap();
    while scaas_node::indexer::step(&ichain, &odoo, Some(router)).await.unwrap() {}
    let ingested = state.lock().unwrap().ingested.clone();
    let f = ingested.iter().find(|e| e["event"] == "AccountFrozen").unwrap_or_else(|| panic!("no AccountFrozen in {ingested:?}"));
    assert_eq!((f["account"].as_str(), f["alert"].as_bool()), (Some(format!("{a:#x}").as_str()), Some(true)), "{f}");
}

/// Regulated-kinds spec §7 (plan T35): a frozen holder's transfer is refused by name and never `dead` while it may still land: the
/// simulation reverts `Frozen`, the job goes back `queued` with `REGULATED_REFUSED: Frozen(…)` and nothing is sent; after the
/// issuer's `mtxUnfreeze` the same job is relayed and mined.
#[tokio::test]
#[ignore]
async fn regulated_transfer_refused_frozen() {
    let chain_id = 31915;
    let (_anvil, rpc) = start_anvil(chain_id, 31915).await;
    let (owner, holder) = (small_key(0x35C), small_key(0x35D));
    let (dep, token, issuer) = regulated_token(chain_id, &rpc, &owner, holder.address()).await;
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let router: Address = dep["governance_router"].as_str().unwrap().parse().unwrap();
    let a = holder.address().into_word();
    let ref_ = format!("{:#x}", B256::repeat_byte(0x5e));
    let freeze = issuer_op("mtxFreeze", json!({"target": format!("{token:#x}"), "account": format!("{a:#x}"), "ref": ref_,
        "recordId": format!("{:#x}", B256::ZERO)}), issuer, &owner, router, token, 0, chain_id, uid);
    let unfreeze = issuer_op("mtxUnfreeze", json!({"target": format!("{token:#x}"), "account": format!("{a:#x}"), "ref": ref_}),
        issuer, &owner, router, token, 1, chain_id, uid);
    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{token:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let cfg = ChainCfg { governance_routers: vec![router], ..chain_cfg(chain_id, &rpc, None) };
    let mut s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo.clone(), cfg.clone(), "e2e-reg-1".into(),
        Default::default()).await.unwrap();
    state.lock().unwrap().jobs.push(json!({"id": 1, "kind": "ua_metatx", "op": freeze}));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    let to = Address::repeat_byte(0x77);
    let m = payment(holder.address(), to, 5, B256::ZERO, U256::from(4), 0, Address::ZERO, 0, Address::ZERO);
    let d = token_domain(&dep, chain_id, token);
    let sent_before = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_count(key(RELAYER).address()).await.unwrap();
    let transfer = job(2, token, &m, &format!("{:#x}", m.digest(&d)), sign(&holder, &d, &m));
    state.lock().unwrap().jobs.push(transfer.clone());
    run_outbox(&mut s).await;
    let r = report(&state, 2);
    assert_eq!(r["chain_state"], "queued", "a refusal, never dead: {r}");
    assert!(r["error"].as_str().unwrap().starts_with("REGULATED_REFUSED: Frozen("), "{r}");
    let sent_after = ProviderBuilder::new().connect_http(rpc.parse().unwrap()).get_transaction_count(key(RELAYER).address()).await.unwrap();
    assert_eq!(sent_after, sent_before, "nothing sent");
    state.lock().unwrap().jobs.push(json!({"id": 3, "kind": "ua_metatx", "op": unfreeze}));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 3)["chain_state"], "mined", "{}", report(&state, 3));
    state.lock().unwrap().jobs.push(transfer); // the client's queue hands a `queued` job out again
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 2)["chain_state"], "mined", "the refused job landed after the unfreeze: {}", report(&state, 2));
    assert_eq!(balance(&rpc, token, to).await, U256::from(5u8));
}

/// Group 3g (spec 2026-11-06-pqz-key-versions §7.3, T55): a PQZ key rotation's registry half through the node on anvil (no PQZ
/// precompile here, so the registry has no `0x0142` verifier: a version is eligible by this build's set length with its proof
/// bytes stored, KV-2). portable.json's `fndsa512` (a Falcon key, verified on chain): `register` without a PQZ key, then version 0
/// (`setPqzKey(ua, 0, …)`, `storePqzPop(ua, 0, …)`) and version 1 as `call` jobs from named fields, the version a field; version
/// 1 stored without its proof is the pending version (latest 1, current 0); its proof moves current to 1. The indexer's rows
/// carry the pending and the current feed, and the node finds the `UAPqzKeyCurrent` a `PQZ_KEY_ROTATED` needs. UNAUDITED.
#[tokio::test]
#[ignore]
async fn pqz_rotation_on_anvil() {
    use scaas_node::abi::IUARegistry;
    let chain_id = 31916;
    let (_anvil, rpc) = start_anvil(chain_id, 31916).await;
    let dep = deploy(&rpc, chain_id, key(DEPLOYER).address());
    let registry: Address = dep["ua_registry"].as_str().unwrap().parse().unwrap();
    let p: Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/../vectors/ua/portable.json", sc())).unwrap()).unwrap();
    let named = |table: &str, name: &str| p[table].as_array().unwrap().iter().find(|r| r["name"] == name).unwrap().clone();
    let set = "n2304-kmax4096"; // the committed PqzSet.sol the deploy built
    let (reg, v0, v1) = (named("registrations", "fndsa512"), named("pqzKeyRecords", &format!("fndsa512/{set}")),
        named("pqzKeyVersions", &format!("fndsa512/v1/{set}")));
    let ua: B256 = reg["ua"].as_str().unwrap().parse().unwrap();

    let state = Arc::new(Mutex::new(FakeOdoo::default()));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let mut cfg = chain_cfg(chain_id, &rpc, None);
    cfg.ua_registry = Some(registry);
    cfg.max_gas_per_tx = 64_000_000; // a Falcon registration with its KEM key, the SCaaS testnet's relayer cap
    let mut s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo, cfg.clone(), "e2e-pqzver".into(), Default::default())
        .await
        .unwrap();
    let until = (now() + 300).to_string();
    let mut id = 0;
    let mut job = |entry: &str, args: Value| {
        id += 1;
        let mut a = args;
        a.as_object_mut().unwrap().remove("entry");
        state.lock().unwrap().jobs.push(json!({"id": id, "kind": "call", "op": {"entry": entry, "token": format!("{registry:#x}"),
            "validUntil": until, "args": a}}));
        id
    };
    let last = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap_or_default();
    let mined = |id: i64| last(id)["chain_state"] == "mined";
    let key_of = || async { view(&rpc, registry, IUARegistry::pqzKeyOfCall { ua }).await };
    let latest = || async { view(&rpc, registry, IUARegistry::pqzKeyLatestCall { ua }).await };

    let r = job("register", reg["args"].clone());
    run_outbox(&mut s).await;
    assert!(mined(r), "register fndsa512: {}", last(r));
    let mut a0 = v0["args"].clone();
    a0["version"] = json!("0");
    let (k0, s0) = (job("setPqzKey", a0), job("storePqzPop", json!({"ua": format!("{ua:#x}"), "version": "0",
        "pqzPop": named("registrations", &format!("mldsa65/{set}"))["pqzPop"]})));
    run_outbox(&mut s).await;
    assert!(mined(k0) && mined(s0), "version 0 through the node: {} {}", last(k0), last(s0));
    assert_eq!((key_of().await.version, latest().await), (0, 0), "version 0 current");
    let mut a1 = v1["args"].clone();
    a1["version"] = json!("1"); // the node's uint64 is a decimal string (job-api.md), the vector's a number
    let k1 = job("setPqzKey", a1);
    run_outbox(&mut s).await;
    assert!(mined(k1), "version 1 through the node: {}", last(k1));
    let (c, l) = (key_of().await, latest().await);
    assert_eq!((c.version, l), (0, 1), "version 1 stored without its proof: pending, current stays 0");
    let at = view(&rpc, registry, IUARegistry::pqzKeyAtCall { ua, version: 1 }).await;
    let chain = Chain::with_signer(&cfg, key(RELAYER)).unwrap();
    assert_eq!(chain.code_len(at.ptr).await.unwrap(), chain.code_len(c.ptr).await.unwrap(), "the pending version has this set's length");
    let s1 = job("storePqzPop", json!({"ua": format!("{ua:#x}"), "version": "1", "pqzPop": v1["pqzPop"]}));
    run_outbox(&mut s).await;
    assert!(mined(s1), "version 1's proof through the node: {}", last(s1));
    assert_eq!(key_of().await.version, 1, "version 1 current");
    assert!(chain.pqz_key_current_since(registry, &[ua], 100).await.unwrap(), "the UAPqzKeyCurrent a PQZ_KEY_ROTATED reads");
    assert!(!chain.pqz_key_current_since(registry, &[B256::repeat_byte(7)], 100).await.unwrap(), "another UA has none");
    // the indexer's rows of the registry's events
    let pr = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let head = pr.get_block_number().await.unwrap();
    let logs = pr.get_logs(&scaas_node::indexer::pay_filter_with(0, head, &mut vec![], None, Some(registry))).await.unwrap();
    let rows = scaas_node::indexer::pqz_key_origin(scaas_node::indexer::pay_events(&logs, None), Some(registry));
    let feed = |f: &str| rows.iter().filter(|r| r["feed"] == f && r["ua"] == json!(format!("{ua:#x}"))).map(|r| r["version"].clone()).collect::<Vec<_>>();
    assert_eq!((feed("pqz_pending"), feed("pqz_current")), (vec![json!(0), json!(1)], vec![json!(0), json!(1)]), "{rows:?}");
}


// ------------------------------------------------------------------ group 3f: PQZ verifier mode, OFFCHAIN on anvil (T47)

mod pqz3f {
    alloy::sol! {
        // group 3h (T59): `ownTag` after `salt`
        struct PqzTransferArgs { uint64 p; uint256 validUntilBlock; uint256 shieldIn; bytes32 fromUA; uint64 keyVersion; bytes32 toUA;
            bytes32 beneficiaryUA; bytes16 salt; bytes32 ownTag; bytes u; bytes vTo; bytes vFrom; bytes vAuditor; bytes sealedMemo; }
        function transferSingleStatement(PqzTransferArgs t, bytes32 binding) external view returns (bytes);
        function pqzRevokeVerifier() external;
        function setTokenKindEnabled(uint8 kind, bool on, bytes32 chainUid) external;
        function latestTokenEnvVersion(uint8 kind) external view returns (uint16);
        function latestVersion(uint8 kind) external view returns (uint64);
        function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32);
        function mtxShield(bytes32 toUA, uint256 amount) external;
        function totalShielded() external view returns (uint256);
        function keyHashOf(uint16 kind, bytes keyData) external pure returns (bytes32);
        // group 3h (T58, T63): the debit record's view
        struct DebitRecordView { address prevBlob; uint64 p; uint16 deltaP; uint8 proofStore; uint64 shieldIn; uint64 keyVersion;
            uint64 prevCounter; bool hasPrev; }
        function pqzDebitRecord(bytes32 ua, uint64 counter) external view returns (DebitRecordView memory);
    }
}

/// `UAKinds.FNDSA512`: Falcon-512 over the 32-byte `ua_msg` (pure Solidity, `FndsaVerifier`; no precompile).
const UA_FNDSA512: u16 = 0x0132;

/// A plain CREATE of `code` by `from`: the new contract.
async fn deploy_code(rpc: &str, from: &PrivateKeySigner, code: Vec<u8>) -> Address {
    use alloy::network::TransactionBuilder;
    let p = ProviderBuilder::new().wallet(EthereumWallet::from(from.clone())).connect_http(rpc.parse().unwrap());
    let r = p.send_transaction(TransactionRequest::default().with_deploy_code(code)).await.unwrap().get_receipt().await.unwrap();
    assert!(r.status(), "CREATE reverted");
    r.contract_address.unwrap()
}

/// The init code of `out/<name>.sol/<name>.json`, every library linked by placeholder: the base deploy's
/// (`broadcast/Deploy.s.sol/<chain_id>/run-latest.json`) or `extra`'s; with the transitive library closure, leaf first.
fn linked_closure(chain_id: u64, name: &str, extra: &BTreeMap<String, Address>) -> (Vec<u8>, Vec<Address>) {
    linked_closure_in(chain_id, None, name, extra)
}

/// As [`linked_closure`] for contract `name` of the artifact file `file` (`<name>.sol` when `None`; a body module sits in
/// its kind's `<Kind>Modules.sol`).
fn linked_closure_in(chain_id: u64, file: Option<&str>, name: &str, extra: &BTreeMap<String, Address>) -> (Vec<u8>, Vec<Address>) {
    let read = |p: String| -> Value { serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap() };
    let run = read(format!("{}/broadcast/Deploy.s.sol/{chain_id}/run-latest.json", sc()));
    let mut libs: BTreeMap<String, Address> = run["libraries"].as_array().unwrap().iter().map(|l| {
        let (path, addr) = l.as_str().unwrap().rsplit_once(':').unwrap();
        (path.to_string(), addr.parse().unwrap())
    }).collect();
    libs.extend(extra.iter().map(|(k, v)| (k.clone(), *v)));
    fn walk(file: &str, name: &str, libs: &BTreeMap<String, Address>, out: &mut Vec<Address>) -> Vec<u8> {
        let p = format!("{}/out/{file}/{name}.json", sc());
        let art: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))).unwrap();
        let mut code = art["bytecode"]["object"].as_str().unwrap().trim_start_matches("0x").to_string();
        for (path, by) in art["bytecode"]["linkReferences"].as_object().unwrap() {
            for (lib, at) in by.as_object().unwrap() {
                let a = *libs.get(&format!("{path}:{lib}")).unwrap_or_else(|| panic!("{path}:{lib} not deployed"));
                walk(path.rsplit('/').next().unwrap(), lib, libs, out);
                if !out.contains(&a) {
                    out.push(a);
                }
                for o in at.as_array().unwrap() {
                    let i = 2 * o["start"].as_u64().unwrap() as usize;
                    code.replace_range(i..i + 40, &alloy::hex::encode(a));
                }
            }
        }
        alloy::hex::decode(code).unwrap()
    }
    let mut closure = Vec::new();
    let code = walk(file.unwrap_or(&format!("{name}.sol")), name, &libs, &mut closure);
    (code, closure)
}

/// T66b §4.5: `kind`'s body modules as (artifact file, contract) in its `implArgs` order, from the generated
/// `script/KindModules.sol` (`kindModuleNames`, the list DeployBase reads).
fn kind_module_names(kind: u8) -> Vec<(String, String)> {
    let src = std::fs::read_to_string(format!("{}/script/KindModules.sol", sc())).unwrap();
    let at = src.find(&format!("if (kind == {kind}) {{")).unwrap_or_else(|| panic!("kind {kind} in KindModules.sol"));
    let body = &src[at..at + src[at..].find("return n;").unwrap()];
    body.split('"').skip(1).step_by(2).map(|q| {
        let (f, n) = q.split_once(':').unwrap();
        (f.to_string(), n.to_string())
    }).collect()
}

/// `kind`'s body modules for `factory` (`core`: the kind's constructor argument, "" on 0-5), each a plain CREATE, its
/// libraries linked as `linked_closure`; the modules and the union of their link closures.
async fn kind_modules(rpc: &str, chain_id: u64, from: &PrivateKeySigner, factory: Address, kind: u8, core: Bytes,
    extra: &BTreeMap<String, Address>) -> (Vec<Address>, Vec<Address>)
{
    let (mut ms, mut libs) = (Vec::new(), Vec::new());
    for (file, name) in kind_module_names(kind) {
        let (mut code, closure) = linked_closure_in(chain_id, Some(&file), &name, extra);
        code.extend((factory, core.clone()).abi_encode_params());
        ms.push(deploy_code(rpc, from, code).await);
        libs.extend(closure.into_iter().filter(|l| !libs.contains(l)).collect::<Vec<_>>());
    }
    (ms, libs)
}

/// The typed `PqzAuth` digest of a debit statement (`PqzCore.authDigest`, pqz-core `pqz-vectors`'s `auth_digest`): the typehash,
/// `op`, the 640 header bytes, `bodyHash = keccak256(stmt[640..])`, in the token's domain (the header's chainId, token, chainUid).
fn pqz_auth_digest(op: u8, stmt: &[u8]) -> B256 {
    const T: &[u8] = b"PqzAuth(uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,\
bytes32 to,bytes32 beneficiary,uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,\
bool auditorOn,uint256 shieldIn,bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash)";
    let d = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    let domain = keccak256([&d[..], &keccak256(b"SCaaS PqzToken")[..], &keccak256(b"1")[..], &stmt[64..96], &stmt[96..128], &stmt[512..544]].concat());
    let mut o = [0u8; 32];
    o[31] = op;
    let h = keccak256([&keccak256(T)[..], &o[..], &stmt[..640], &keccak256(&stmt[640..])[..]].concat());
    keccak256([&[0x19, 0x01][..], &domain[..], &h[..]].concat())
}

/// A fresh `fndsa512` UA (the PQ signer a PQZ key needs, verified in Solidity on anvil) registered with an unproven PQZ key of the
/// set's length and its proof bytes stored unchecked (no `pqz-mlwe` verifier on this registry; an `OFFCHAIN` token accepts it).
struct PqHolder {
    ua: B256,
    pk: Vec<u8>,
    sk: pqcrypto_falcon::falconpadded512::SecretKey,
}

impl PqHolder {
    async fn register(rpc: &str, registry: Address, deployer: &PrivateKeySigner, pqz_key: Vec<u8>, pqz_pop: Vec<u8>) -> Self {
        use pqcrypto_falcon::falconpadded512 as falcon;
        use pqcrypto_traits::sign::PublicKey as _;
        let (pk, sk) = falcon::keypair();
        let pk = pk.as_bytes().to_vec();
        let ua = view(rpc, registry, uaOfCall { kind: UA_FNDSA512, keyData: pk.clone().into() }).await;
        let no_kem = KemKey { scheme: 0, mlkemEk: Default::default(), x25519: B256::ZERO };
        let krh = view(rpc, registry, kemRecordHashCall { ua, version: 0, kem: no_kem.clone() }).await;
        // the registry's own key hash of a PQZ key (`keyHashOf(pqz-mlwe, key)`, not its keccak)
        let kh = view(rpc, registry, pqz3f::keyHashOfCall { kind: 0x0142, keyData: pqz_key.clone().into() }).await;
        let ph = keccak256(&pqz_pop);
        let rd = view(rpc, registry, registrationDigestCall { ua, kind: UA_FNDSA512, pqzKeyHash: kh, kemRecordHash: krh, pqzPopHash: ph }).await;
        let me = Self { ua, pk, sk };
        let pop = me.sign(rpc, registry, b"scaas.ua.purpose.pop.v2", rd).await;
        send(rpc, deployer, registry, registerCall { kind: UA_FNDSA512, keyData: me.pk.clone().into(),
            attrs: UAAttrs { pqzKey: pqz_key.into(), pqzPopHash: ph, kem: no_kem, kemPkHash: B256::ZERO }, pop: pop.into(),
            pqzPop: pqz_pop.into() }.abi_encode()).await;
        me
    }

    /// The Falcon signature over the registry's `uaMessage(fndsa512, purpose, digest)`.
    async fn sign(&self, rpc: &str, registry: Address, purpose: &[u8], digest: B256) -> Vec<u8> {
        use pqcrypto_falcon::falconpadded512 as falcon;
        use pqcrypto_traits::sign::DetachedSignature as _;
        let m = view(rpc, registry, uaMessageCall { kind: UA_FNDSA512, purposeTag: keccak256(purpose), digest }).await;
        falcon::detached_sign(m.as_slice(), &self.sk).as_bytes().to_vec()
    }

    /// Its `UASig`: a stored kind's carries the signature only (CTR-UA-17: `keyData` empty, the key from the record).
    async fn auth(&self, rpc: &str, registry: Address, purpose: &[u8], digest: B256) -> Value {
        let sig = self.sign(rpc, registry, purpose, digest).await;
        json!({"keyData": "0x", "signature": format!("0x{}", alloy::hex::encode(sig)), "members": []})
    }
}

/// An `OFFCHAIN` NORMAL_PQZ token on anvil, from the artifacts (no PQZ precompile here, so only a zero-dep release works): the
/// base stack by the deploy script; the four PQZ libraries and the release (kind 4, `deps = [0]`) on the base factory (notice 0
/// on an e2e chain); the token's verifier the test EOA `verifier` (transferable), owner the deployer; two `fndsa512` holders.
struct OffchainStack {
    _anvil: Anvil,
    rpc: String,
    chain_id: u64,
    uid: B256,
    registry: Address,
    token: Address,
    verifier: PrivateKeySigner,
    from: PqHolder,
    to: PqHolder,
    /// The set's ciphertext part lengths (`PqzSet.PK`, `PqzSet.V`).
    pk_len: usize,
    v_len: usize,
}

async fn offchain_stack(chain_id: u64) -> OffchainStack {
    offchain_stack_vf(chain_id, 0).await
}

/// Round 3t (CTR-PQZ-36): the stack with `verifierFee = verifierFeeMax = vf`.
async fn offchain_stack_vf(chain_id: u64, vf: u64) -> OffchainStack {
    let deployer = key(DEPLOYER);
    let (anvil, rpc) = start_anvil(chain_id, chain_id as u16).await;
    let dep = deploy(&rpc, chain_id, deployer.address());
    let at = |k: &str| -> Address { dep[k].as_str().unwrap_or_else(|| panic!("{k}")).parse().unwrap() };
    let (factory, registry) = (at("token_factory"), at("ua_registry"));
    let mut extra = BTreeMap::new();
    for lib in ["PqzBurnLib", "PqzStateLib", "PqzTransferLib", "PqzViewLib"] {
        let (code, _) = linked_closure(chain_id, lib, &BTreeMap::new());
        extra.insert(format!("src/pqz/{lib}.sol:{lib}"), deploy_code(&rpc, &deployer, code).await);
    }
    let (code, mut libs) = linked_closure(chain_id, "NormalPqzToken", &extra);
    // T66b §4.5: the kind's body modules, their link closures beside the face's, the modules pinned after the libraries
    let (ms, mlibs) = kind_modules(&rpc, chain_id, &deployer, factory, 4, Bytes::new(), &extra).await;
    libs.extend(mlibs.into_iter().filter(|l| !libs.contains(l)).collect::<Vec<_>>());
    libs.extend(ms.iter().copied());
    let pr = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let mut hashes = Vec::new();
    for l in &libs {
        hashes.push(keccak256(pr.get_code_at(*l).await.unwrap()));
    }
    let mut env = view(&rpc, factory, tokenEnvOfCall { kind: 0, envVersion: 1 }).await;
    (env.deps, env.libs, env.libCodeHashes) = (vec![Address::ZERO], libs, hashes);
    let ev = view(&rpc, factory, pqz3f::latestTokenEnvVersionCall { kind: 4 }).await + 1;
    let chain_uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    send(&rpc, &deployer, factory, publishTokenEnvCall { kind: 4, envVersion: ev, chainUid: chain_uid, env }.abi_encode()).await;
    let ver = view(&rpc, factory, pqz3f::latestVersionCall { kind: 4 }).await + 1;
    send(&rpc, &deployer, factory, deployTokenImplementationCall { kind: 4, version: ver, envVersion: ev, initcode: code.into(),
        implArgs: ImplArgs { modules: ms }.abi_encode().into(), chainUid: chain_uid }.abi_encode()).await;
    send(&rpc, &deployer, factory, pqz3f::setTokenKindEnabledCall { kind: 4, on: true, chainUid: chain_uid }.abi_encode()).await;
    let verifier = small_key(0x3f47);
    let c = TokenConfig { name: "SCaaS PQZ OFFCHAIN".into(), symbol: "pqOFF".into(), decimals: 6, features: U256::from(1u8), // PAYABLE
        owner: deployer.address().into_word(), initialSupply: U256::from(1_000_000u64), initialHolder: deployer.address(),
        conf: ConfidentialConfig { shieldScale: U256::from(1u8), maxShielded: U256::from(1u64 << 40), pqzVerifyMode: 1,
            pqzVerifierUA: verifier.address().into_word(), pqzVerifierFixed: false, verifierFee: vf, verifierFeeMax: vf, ..Default::default() },
        ..Default::default() };
    let token = create(&rpc, &deployer, factory, createTokenCall { kind: 4, version: ver, initArgs: c.abi_encode().into(),
        salt: B256::repeat_byte(0x3f) }.abi_encode()).await;
    let cfg = view(&rpc, token, scaas_node::abi::IPqzToken::pqzVerifyConfigCall {}).await;
    assert_eq!((cfg.pqzVerifyMode, cfg.verifier, cfg.fixed_), (1, verifier.address().into_word(), false), "an OFFCHAIN token");
    // the holders: real PQZ keys of this set from portable.json (two different ones), the proof bytes stored unchecked
    let set = std::fs::read_to_string(format!("{}/src/pqz/PqzSet.sol", sc())).unwrap();
    let constant = |n: &str| -> usize {
        let at = format!("uint256 internal constant {n} = ");
        let i = set.find(&at).unwrap_or_else(|| panic!("PqzSet.{n}")) + at.len();
        set[i..i + set[i..].find(';').unwrap()].replace('_', "").trim().parse().unwrap()
    };
    let name = set.split("string internal constant NAME = \"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let p: Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/../vectors/ua/portable.json", sc())).unwrap()).unwrap();
    let row = |t: &str, n: &str| p[t].as_array().unwrap().iter().find(|r| r["name"] == n).unwrap_or_else(|| panic!("{t} {n}")).clone();
    let hexb = |v: &Value| alloy::hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let pop = hexb(&row("registrations", &format!("mldsa65/{name}"))["pqzPop"]);
    let from = PqHolder::register(&rpc, registry, &deployer, hexb(&row("pqzKeyRecords", &format!("fndsa512/{name}"))["pqzKey"]), pop.clone()).await;
    let to = PqHolder::register(&rpc, registry, &deployer, hexb(&row("pqzKeyRecords", &format!("mldsa87/{name}"))["pqzKey"]), pop).await;
    let uid = pr.get_block_by_number(0.into()).await.unwrap().unwrap().header.hash;
    OffchainStack { _anvil: anvil, rpc, chain_id, uid, registry, token, verifier, from, to, pk_len: constant("PK"), v_len: constant("V") }
}

impl OffchainStack {
    /// Op 1 from `from` to `to` (nothing shielded: in `OFFCHAIN` mode the token never checks the proof, the verifier's verdict
    /// does), at the subject's next nonce: the job without `pqz_verdict`, the statement the token builds, the proof.
    async fn transfer_job(&self, id: i64, nonce: u64) -> (Value, Vec<u8>, Vec<u8>) {
        self.transfer_job_tagged(id, nonce, B256::ZERO).await
    }

    /// `transfer_job` with the debit's `ownTag` (group 3h: a named field of the args).
    async fn transfer_job_tagged(&self, id: i64, nonce: u64, own_tag: B256) -> (Value, Vec<u8>, Vec<u8>) {
        use scaas_node::abi::{IPqzToken, UAMetaTransaction};
        let pr = ProviderBuilder::new().connect_http(self.rpc.parse().unwrap());
        let block = pr.get_block_number().await.unwrap();
        let lanes = |n: usize, b: u8| -> Vec<u8> { (0..n / 8).flat_map(|_| { let mut w = [0u8; 8]; w[7] = b; w }).collect() };
        let t = pqz3f::PqzTransferArgs { p: 0, validUntilBlock: U256::from(block + 200), shieldIn: U256::ZERO, fromUA: self.from.ua,
            keyVersion: 0, toUA: self.to.ua, beneficiaryUA: B256::ZERO, salt: alloy::primitives::FixedBytes([0x5a; 16]), ownTag: own_tag,
            u: lanes(self.pk_len, 1).into(), vTo: lanes(self.v_len, 1).into(), vFrom: lanes(self.v_len, 1).into(),
            vAuditor: Bytes::new(), sealedMemo: Bytes::new() };
        let until = now() + 600;
        let m = UAMetaTransaction { from: self.from.ua, data: Bytes::new(), batch: U256::ZERO, nonce: U256::from(nonce),
            validUntil: U256::from(until), mode: 0, relayer: Address::ZERO, fee: U256::ZERO, feeRecipient: Address::ZERO };
        let binding = view(&self.rpc, self.token, IPqzToken::envelopeBindingCall { m }).await;
        let stmt = view(&self.rpc, self.token, pqz3f::transferSingleStatementCall { t: t.clone(), binding }).await.to_vec();
        let pqz_auth = self.from.auth(&self.rpc, self.registry, b"scaas.ua.purpose.zether-auth.v1", pqz_auth_digest(1, &stmt)).await;
        let proof = vec![0x9f; 96];
        let h = |b: &[u8]| format!("0x{}", alloy::hex::encode(b));
        let args = json!({"p": "0", "validUntilBlock": (block + 200).to_string(), "shieldIn": "0", "fromUA": format!("{:#x}", self.from.ua),
            "keyVersion": "0", "toUA": format!("{:#x}", self.to.ua), "beneficiaryUA": format!("{:#x}", B256::ZERO), "salt": h(&[0x5a; 16]),
            "ownTag": format!("{own_tag:#x}"), "u": h(&t.u), "vTo": h(&t.vTo), "vFrom": h(&t.vFrom), "vAuditor": "0x", "sealedMemo": "0x"});
        let envelope = json!({"from": format!("{:#x}", self.from.ua), "batch": "0", "nonce": nonce.to_string(), "validUntil": until.to_string(),
            "mode": 0, "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)});
        let mut op = json!({"entry": "mtxConfidentialTransferSingle", "contract": "pqz", "token": format!("{:#x}", self.token),
            // round 3t (CTR-PQZ-36): an OFFCHAIN debit names its proved fee word, word 256 of the statement the token built
            "envelope": envelope, "args": {"args": args, "proof": h(&proof), "pqzAuth": pqz_auth, "accHint": "0x",
                "pqz_fee": U256::from_be_slice(&stmt[256..288]).to_string()},
            "auth": {"keyData": "0x", "signature": "0x", "members": []}});
        let (w, _) = scaas_node::submit::work_of_op(Some(id), &op, None).unwrap();
        let digest = w.typed.unwrap().digest_on(self.chain_id, self.uid).unwrap();
        op["auth"] = self.from.auth(&self.rpc, self.registry, b"scaas.ua.purpose.metatx.v1", digest).await;
        (json!({"id": id, "kind": "ua_metatx", "op": op}), stmt, proof)
    }

    /// The verifier EOA's `pqz_verdict` over the token's own statement and the proof at the token's epoch: what a PQZ verifier
    /// (off-chain) signs (spec §11.2); the test makes it, the node never signs.
    async fn verdict(&self, stmt: &[u8], proof: &[u8]) -> Value {
        use scaas_node::abi::IPqzToken;
        let epoch = view(&self.rpc, self.token, IPqzToken::pqzVerifyConfigCall {}).await.pqzVerifierEpoch;
        let psid = view(&self.rpc, self.token, IPqzToken::proofSystemIdCall {}).await;
        let until = now() + 300;
        let pv = json!({"token": format!("{:#x}", self.token), "chainId": self.chain_id.to_string(), "proofSystemId": format!("{psid:#x}"),
            "statementHash": format!("{:#x}", keccak256(stmt)), "proofHash": format!("{:#x}", keccak256(proof)), "pqzVerifierEpoch": epoch,
            "validUntil": until.to_string()});
        let sh = scaas_node::typed::struct_hash_of("PqzVerdict", &scaas_node::typed::parse("PqzVerdict", &pv, "v").unwrap()).unwrap();
        let sep = scaas_node::dex::domain("SCaaS PqzToken", self.chain_id, self.token, self.uid).separator();
        let d = keccak256([&[0x19, 0x01][..], &sep[..], &sh[..]].concat());
        let ua = self.verifier.address().into_word();
        let ad = view(&self.rpc, self.registry, pqz3f::uaAuthDigestCall { ua, purposeTag: keccak256(b"scaas.ua.purpose.pqz-verdict.v1"),
            digest: d }).await;
        let sig = self.verifier.sign_hash_sync(&ad).unwrap().as_bytes().to_vec();
        json!({"pqzVerifierEpoch": epoch, "validUntil": until.to_string(),
            "auth": {"keyData": "0x", "signature": format!("0x{}", alloy::hex::encode(sig)), "members": []}})
    }

    /// A lane on a fake client serving the token, `[pqz_verifier]` as given.
    async fn lane(&self, pqz: scaas_node::config::PqzVerifierCfg) -> (Arc<Mutex<FakeOdoo>>, Submitter) {
        let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{:#x}", self.token)], ..Default::default() }));
        let odoo = odoo_at(start_fake(state.clone()).await);
        let mut cfg = chain_cfg(self.chain_id, &self.rpc, None);
        cfg.ua_registry = Some(self.registry);
        cfg.max_gas_per_tx = 64_000_000;
        cfg.pqz_verifier = pqz;
        let s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo, cfg.clone(), format!("e2e-3f-{}", self.chain_id),
            Default::default()).await.unwrap();
        (state, s)
    }

    /// The token's rows of the whole chain through the indexer's decoder and joins, with the health state stamped.
    async fn rows(&self) -> Vec<Value> {
        let pr = ProviderBuilder::new().connect_http(self.rpc.parse().unwrap());
        let head = pr.get_block_number().await.unwrap();
        let logs = pr.get_logs(&scaas_node::indexer::pay_filter(0, head, vec![self.token], None)).await.unwrap();
        let mut rows = scaas_node::indexer::pay_events(&logs, None);
        scaas_node::indexer::pqz_health(&mut Default::default(), &mut rows);
        rows
    }
}

/// A PQZ verifier (off-chain) stand-in for the e2e: `POST /v1/pqz-verdict` signs, with the test's verifier EOA, a verdict over the
/// request's own `statement` and `proof` at the request's epoch and answers in the reference service's shape (`scaas-pqz-verifier`
/// also rebuilds and checks them and runs `pqz-ffi`, which would refuse the e2e's dummy proof; this one shows the node's request
/// carries what a verifier needs).
async fn fake_pqz_verifier(stack: &OffchainStack) -> (String, Arc<Mutex<Vec<Value>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (rpc, registry, token, chain_id, uid, verifier) =
        (stack.rpc.clone(), stack.registry, stack.token, stack.chain_id, stack.uid, stack.verifier.clone());
    let s2 = seen.clone();
    let app = Router::new().route("/v1/pqz-verdict", post(move |Json(req): Json<Value>| {
        let (rpc, verifier, seen) = (rpc.clone(), verifier.clone(), s2.clone());
        async move {
            seen.lock().unwrap().push(req.clone());
            let b = |k: &str| alloy::hex::decode(req[k].as_str().unwrap_or("0x").trim_start_matches("0x")).unwrap_or_default();
            let (stmt, proof) = (b("statement"), b("proof"));
            let epoch = req["pqzVerifierEpoch"].as_u64().unwrap_or(0);
            let psid = view(&rpc, token, scaas_node::abi::IPqzToken::proofSystemIdCall {}).await;
            let until = now() + 300;
            let pv = json!({"token": format!("{token:#x}"), "chainId": chain_id.to_string(), "proofSystemId": format!("{psid:#x}"),
                "statementHash": format!("{:#x}", keccak256(&stmt)), "proofHash": format!("{:#x}", keccak256(&proof)),
                "pqzVerifierEpoch": epoch, "validUntil": until.to_string()});
            let sh = scaas_node::typed::struct_hash_of("PqzVerdict", &scaas_node::typed::parse("PqzVerdict", &pv, "v").unwrap()).unwrap();
            let sep = scaas_node::dex::domain("SCaaS PqzToken", chain_id, token, uid).separator();
            let d = keccak256([&[0x19, 0x01][..], &sep[..], &sh[..]].concat());
            let ad = view(&rpc, registry, pqz3f::uaAuthDigestCall { ua: verifier.address().into_word(),
                purposeTag: keccak256(b"scaas.ua.purpose.pqz-verdict.v1"), digest: d }).await;
            let sig = verifier.sign_hash_sync(&ad).unwrap().as_bytes().to_vec();
            // the reference verifier's answer (scaas-pqz-verifier `Signed`): the verdict and its signature
            let mut pv = pv;
            (pv["chainId"], pv["validUntil"]) = (json!(chain_id), json!(until));
            Json(json!({"pqzVerdict": pv, "pqzVerdictSig": {"keyData": "0x", "signature": format!("0x{}", alloy::hex::encode(sig)), "members": []}}))
        }
    }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

/// Group 3f (spec §11.1, T47), on anvil with no PQZ precompile: an `OFFCHAIN` token's op 1 through the node, twice. The first job
/// names `pqz_verdict` (the verifier EOA's signature, made by the test); the second names none and the node fetches it from the
/// configured endpoint, whose request carries the statement and proof the node rebuilt. The node rebuilds each `PqzVerdict`, the
/// token accepts it (`PqzVerified` over exactly `keccak256(statement)`, `keccak256(proof)`), and the indexer joins it to the
/// `ConfidentialTransfer` of the same transaction with its position. The node signs nothing and never reads the precompile.
/// Round 3t (CTR-PQZ-36, spec §15 (10)): the token charges `verifierFee = 3`, so the holder shields first (the fee leaves
/// `totalShielded`: at 0 the debit underflows); each job names `pqz_fee` = word 256 = 3 (no beneficiary), the verifier EOA's
/// ERC-20 balance grows by 3 per op and `totalShielded` falls by 3. UNAUDITED.
#[tokio::test]
#[ignore]
async fn pqz_offchain_transfer_on_anvil() {
    const VF: u64 = 3;
    let st = offchain_stack_vf(31947, VF).await;
    let deployer = key(DEPLOYER);
    send(&st.rpc, &deployer, st.token, pqz3f::mtxShieldCall { toUA: st.from.ua, amount: U256::from(100u8) }.abi_encode()).await;
    let shielded = || async { view(&st.rpc, st.token, pqz3f::totalShieldedCall {}).await };
    let paid = || async { balance(&st.rpc, st.token, st.verifier.address()).await };
    assert_eq!((shielded().await, paid().await), (U256::from(100u8), U256::ZERO), "shielded first");
    let (url, seen) = fake_pqz_verifier(&st).await;
    let (state, mut s) = st.lane(scaas_node::config::PqzVerifierCfg { endpoints: vec![url], ..Default::default() }).await;
    let last = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap_or_default();
    let (mut j1, stmt1, proof1) = st.transfer_job(1, 0).await;
    assert_eq!(U256::from_be_slice(&stmt1[256..288]), U256::from(VF), "the fee word: vf alone, no beneficiary");
    j1["op"]["args"]["pqz_verdict"] = st.verdict(&stmt1, &proof1).await;
    state.lock().unwrap().jobs.push(j1);
    run_outbox(&mut s).await;
    assert_eq!(last(1)["chain_state"], "mined", "the job's verdict: {}", last(1));
    assert!(seen.lock().unwrap().is_empty(), "a usable job verdict: no endpoint asked");
    let (j2, stmt2, proof2) = st.transfer_job(2, 1).await;
    state.lock().unwrap().jobs.push(j2);
    run_outbox(&mut s).await;
    assert_eq!(last(2)["chain_state"], "mined", "the fetched verdict: {}", last(2));
    let req = seen.lock().unwrap()[0].clone();
    assert_eq!((req["statement"].as_str(), req["op"]["entry"].as_str()),
        (Some(format!("0x{}", alloy::hex::encode(&stmt2)).as_str()), Some("mtxConfidentialTransferSingle")), "the statement the node rebuilt");
    let rows = st.rows().await;
    let pr = ProviderBuilder::new().connect_http(st.rpc.parse().unwrap());
    for (id, stmt, proof) in [(1, &stmt1, &proof1), (2, &stmt2, &proof2)] {
        let hash: B256 = last(id)["tx_hash"].as_str().unwrap_or_default().parse().unwrap_or_default();
        let hash = if hash == B256::ZERO { tx_of(&state, id).parse().unwrap() } else { hash };
        let rc = pr.get_transaction_receipt(hash).await.unwrap().unwrap();
        let row = rows.iter().find(|r| r["event"] == "ConfidentialTransfer" && r["tx_hash"] == json!(format!("{hash:#x}")))
            .unwrap_or_else(|| panic!("job {id}: no ConfidentialTransfer row: {rows:?}"));
        assert_eq!(row["pqz_verified"]["statement_hash"], json!(format!("{:#x}", keccak256(stmt))), "job {id}");
        assert_eq!(row["pqz_verified"]["proof_hash"], json!(format!("{:#x}", keccak256(proof))), "job {id}");
        assert_eq!(row["pqz_verified"]["verifier"], json!(format!("{:#x}", st.verifier.address().into_word())), "job {id}");
        assert_eq!(row["tx_index"].as_u64(), rc.transaction_index, "job {id}: the transaction's position");
        assert_eq!(row["pqz_last_verdict_at"].as_u64(), rc.block_number, "job {id}: the health signal");
    }
    assert!(rows.iter().all(|r| r["event"] != "PqzVerified"), "joined, never a row of its own");
    assert_eq!((shielded().await, paid().await), (U256::from(100 - 2 * VF), U256::from(2 * VF)), "the verifier paid vf per op");
    let chain = Chain::with_signer(&chain_cfg(st.chain_id, &st.rpc, None), key(RELAYER)).unwrap();
    let pqz: Address = "0x000000000000000000000000000000005caa0f01".parse().unwrap();
    assert!(!chain.is_contract_at(pqz).await.unwrap(), "no PQZ precompile on this chain");
}

/// Group 3h (pqz-proof-path spec §3.2, §10, T63), on anvil (the 3f `OFFCHAIN` stack: no PQZ precompile here): a PQZ debit job
/// naming a non-zero `ownTag` goes through the node and is mined; the op blob's tail is `ownTag ‖ kv ‖ u8(n)` with that tag and
/// the receiver's version 0; the token is on `NONE` and the debit's record is a narrow first one; no `PqzDebitProof` log is
/// emitted and no such row is indexed. UNAUDITED.
#[tokio::test]
#[ignore]
async fn pqz_debit_with_own_tag_on_anvil() {
    let st = offchain_stack(31949).await;
    let (url, _) = fake_pqz_verifier(&st).await;
    let (state, mut s) = st.lane(scaas_node::config::PqzVerifierCfg { endpoints: vec![url], ..Default::default() }).await;
    let last = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap_or_default();
    let tag = B256::repeat_byte(0x7a);
    let (j, _, _) = st.transfer_job_tagged(1, 0, tag).await;
    assert_eq!(j["op"]["args"]["args"]["ownTag"], json!(format!("{tag:#x}")), "a named field of the job");
    state.lock().unwrap().jobs.push(j);
    run_outbox(&mut s).await;
    assert_eq!(last(1)["chain_state"], "mined", "{}", last(1));
    let rows = st.rows().await;
    let row = rows.iter().find(|r| r["event"] == "ConfidentialTransfer").unwrap_or_else(|| panic!("no ConfidentialTransfer: {rows:?}"));
    let blob: Address = row["blob"].as_str().unwrap().parse().unwrap();
    let pr = ProviderBuilder::new().connect_http(st.rpc.parse().unwrap());
    let code = pr.get_code_at(blob).await.unwrap();
    let d = &code[1..]; // SSTORE2: a STOP byte, then the data
    let n = usize::from(d[d.len() - 1]);
    assert_eq!(n, 1, "op 1 without the auditor: one key version");
    let at = d.len() - 1 - 8 * n - 32;
    assert_eq!((&d[at..at + 32], &d[at + 32..at + 40]), (tag.as_slice(), &[0u8; 8][..]), "ownTag, then the receiver's version 0");
    assert_eq!(view(&st.rpc, st.token, scaas_node::abi::IPqzToken::proofStoreCall {}).await, 0, "NONE");
    let rec = view(&st.rpc, st.token, pqz3f::pqzDebitRecordCall { ua: st.from.ua, counter: 0 }).await;
    assert_eq!((rec.proofStore, rec.hasPrev, rec.shieldIn, rec.keyVersion), (0, false, 0, 0), "a narrow first record under NONE");
    let head = pr.get_block_number().await.unwrap();
    let logs = pr.get_logs(&alloy::rpc::types::Filter::new().address(st.token).from_block(0).to_block(head)).await.unwrap();
    let proof_event = <scaas_node::abi::IPqzToken::PqzDebitProof as alloy::sol_types::SolEvent>::SIGNATURE_HASH;
    assert!(logs.iter().all(|l| l.topic0() != Some(&proof_event)), "NONE: no PqzDebitProof");
    assert!(rows.iter().all(|r| r["event"] != "PqzDebitProof"));
}

/// Group 3f (spec §4.3, §11.1, T47), on anvil: the owner revokes the token's verifier at once; a debit with a verdict of the old
/// epoch is back in the queue by name (`PqzVerifierRevoked`, never `dead`, zero sends); the indexer's `PqzVerifierRevoked` row is
/// an alert and the health signal reads revoked; with `refuse_shield_when_unserved` a shield into the token is refused
/// `PQZ_VERIFIER_UNREACHABLE`, without it the same shield is mined. UNAUDITED.
#[tokio::test]
#[ignore]
async fn pqz_revoked_verifier_on_anvil() {
    let st = offchain_stack(31948).await;
    let deployer = key(DEPLOYER);
    let (j1, stmt, proof) = st.transfer_job(1, 0).await;
    let mut j1 = j1;
    j1["op"]["args"]["pqz_verdict"] = st.verdict(&stmt, &proof).await;
    send(&st.rpc, &deployer, st.token, pqz3f::pqzRevokeVerifierCall {}.abi_encode()).await;
    let cfg = view(&st.rpc, st.token, scaas_node::abi::IPqzToken::pqzVerifyConfigCall {}).await;
    assert_eq!(cfg.verifier, B256::ZERO, "revoked at once");
    let (url, seen) = fake_pqz_verifier(&st).await;
    let on = scaas_node::config::PqzVerifierCfg { endpoints: vec![url.clone()], refuse_shield_when_unserved: true, ..Default::default() };
    let (state, mut s) = st.lane(on).await;
    let last = |id: i64| state.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == id).cloned().unwrap_or_default();
    state.lock().unwrap().jobs.push(j1);
    // the deployer's shield of its public units into `from`: `UAShield`, its own key (a native id)
    let shield = |id: i64, nonce: u64| {
        let until = (now() + 600).to_string();
        json!({"id": id, "kind": "ua_metatx", "op": {"entry": "mtxShield", "contract": "pqz", "token": format!("{:#x}", st.token),
            "envelope": {"from": format!("{:#x}", deployer.address().into_word()), "batch": "0", "nonce": nonce.to_string(), "validUntil": until,
                "mode": 0, "relayer": format!("{:#x}", Address::ZERO), "fee": "0", "feeRecipient": format!("{:#x}", Address::ZERO)},
            "args": {"toUA": format!("{:#x}", st.from.ua), "amount": "5"}, "auth": {"keyData": "0x", "signature": "0x", "members": []}}})
    };
    let signed = |mut j: Value| {
        let (w, _) = scaas_node::submit::work_of_op(Some(1), &j["op"], None).unwrap();
        let d = w.typed.unwrap().digest_on(st.chain_id, st.uid).unwrap();
        j["op"]["auth"]["signature"] = json!(format!("0x{}", alloy::hex::encode(deployer.sign_hash_sync(&d).unwrap().as_bytes())));
        j
    };
    state.lock().unwrap().jobs.push(signed(shield(2, 0)));
    run_outbox(&mut s).await;
    let (r1, r2) = (last(1), last(2));
    assert!(r1["chain_state"] == "queued" && r1["error"].as_str().unwrap_or_default().contains("PqzVerifierRevoked"), "{r1}");
    assert!(r2["chain_state"] == "dead" && r2["error"].as_str().unwrap_or_default().starts_with("PQZ_VERIFIER_UNREACHABLE"), "{r2}");
    assert!(seen.lock().unwrap().is_empty(), "nothing fetched for a revoked verifier");
    let pr = ProviderBuilder::new().connect_http(st.rpc.parse().unwrap());
    assert_eq!(pr.get_transaction_count(key(RELAYER).address()).await.unwrap(), 0, "zero sends");
    let (state2, mut s2) = st.lane(scaas_node::config::PqzVerifierCfg { endpoints: vec![url], ..Default::default() }).await;
    state2.lock().unwrap().jobs.push(signed(shield(3, 0)));
    run_outbox(&mut s2).await;
    let r3 = state2.lock().unwrap().reports.iter().rev().find(|r| r["job_id"] == 3).cloned().unwrap_or_default();
    assert_eq!(r3["chain_state"], "mined", "the switch off: the shield is sent: {r3}");
    let rows = st.rows().await;
    let rv = rows.iter().find(|r| r["event"] == "PqzVerifierRevoked").unwrap_or_else(|| panic!("{rows:?}"));
    assert_eq!((rv["alert"].as_bool(), rv["pqz_verifier_revoked"].as_bool(), rv["previous"].as_str()),
        (Some(true), Some(true), Some(format!("{:#x}", st.verifier.address().into_word()).as_str())), "{rv}");
}

// ------------------------------------------------------------------ mtxLiquidity's pre-checks on a chain (ua-mtx-liquidity L6c)

mod liq {
    alloy::sol! {
        function mint(address to) external returns (uint256 liquidity);
    }
}

/// `test/liquidity/LiquidityMocks.sol`'s contract `name`: its init code, or its runtime code (`runtime`), built here as
/// [`deploy_outside_token`] builds its mock.
fn liquidity_mock(name: &str, runtime: bool) -> Vec<u8> {
    let built = Command::new("forge").current_dir(sc()).args(["build", "test/liquidity/LiquidityMocks.sol"])
        .env("FOUNDRY_PROFILE", "scaas-testnet").status();
    assert!(built.expect("forge in PATH").success(), "forge build test/liquidity/LiquidityMocks.sol failed");
    let raw = std::fs::read_to_string(format!("{}/out/LiquidityMocks.sol/{name}.json", sc())).expect("forge build output");
    let v: Value = serde_json::from_str(&raw).unwrap();
    alloy::hex::decode(v[if runtime { "deployedBytecode" } else { "bytecode" }]["object"].as_str().unwrap()).unwrap()
}

/// A `mtxLiquidity` job on `dex` of `(chain_id, chain_uid, dex)` (spec 2026-11-10-dex-liquidity.md §11's shape): `who`'s native
/// order of `inputs` (each pulled whole) for at least `min_lp` of `lp` to `to` (`out`), fee 0, bound to the lane, lane 7 at nonce
/// `id`; signed by `who` over the node's `h` in `dex`'s domain ([`sign_liquidity`]).
fn liquidity_job(id: i64, (chain_id, uid, dex): (u64, B256, Address), who: &PrivateKeySigner, inputs: &[(Address, u64)],
    (lp, min_lp, to): (Address, u64, Address), interactions: Value) -> Value {
    let toks = |v: &[(Address, u64)]| v.iter().map(|(t, a)| json!({"token": format!("{t:#x}"), "amount": a.to_string()})).collect::<Vec<_>>();
    let until = (now() + 600).to_string();
    let mut j = json!({"id": id, "kind": "call", "op": {"entry": "mtxLiquidity", "contract": "dex", "token": format!("{dex:#x}"),
        "validUntil": until,
        "args": {"p": {"ref": format!("{:#x}", B256::left_padding_from(&(id as u64).to_be_bytes())), "order": {
                "from": format!("{:#x}", who.address().into_word()), "inputs": toks(inputs), "outputs": toks(&[(lp, min_lp)]),
                "positionManager": format!("{:#x}", Address::ZERO), "positionReader": format!("{:#x}", Address::ZERO), "positionIn": "0",
                "positionPool": format!("{:#x}", B256::ZERO), "tickLower": 0, "tickUpper": 0, "minLiquidity": "0",
                "recipient": format!("{:#x}", to.into_word()), "fee": "0", "relayer": format!("{:#x}", key(RELAYER).address()), "flags": 0,
                "batch": "7", "nonce": id.to_string(), "validUntil": until},
            "auth": {"keyData": "0x", "signature": "0x", "members": []},
            "pull": inputs.iter().map(|(_, a)| a.to_string()).collect::<Vec<_>>(), "positionId": "0", "extraTokens": []},
            "interactions": interactions}}});
    sign_liquidity(&mut j, (chain_id, uid, dex), who);
    j
}

/// `who`'s signature over the node's `h` of the job's order in `dex`'s domain, again after an edit of the order.
fn sign_liquidity(j: &mut Value, (chain_id, uid, dex): (u64, B256, Address), who: &PrivateKeySigner) {
    let (w, _) = scaas_node::submit::work_of_op(None, &j["op"], None).unwrap();
    let o = scaas_node::abi::ISCaaSDex::mtxLiquidityCall::abi_decode(&w.data).unwrap().p.order;
    let h = scaas_node::dex::liquidity_order_hash(&domain("SCaaS Dex", chain_id, dex, uid), &o);
    j["op"]["args"]["p"]["auth"]["signature"] = json!(sign_hash(who, h));
}

/// A submitter on the `RELAYER` lane for a chain whose profile lists `dex` as its DEX.
async fn liquidity_lane(chain_id: u64, rpc: &str, odoo: &Odoo, dex: Address, name: &str) -> Submitter {
    let cfg = chain_cfg(chain_id, rpc, Some(dex));
    Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo.clone(), cfg, name.into(), Default::default()).await.unwrap()
}

/// Spec 2026-11-10-dex-liquidity.md §11 through the RPC (review P1-2 (b), P2-6, re-check P3): the deployed liquidity DEX takes a
/// v2 add of two SCaaS inputs (mined: the positive control); a DEX bound to the chain whose `modules()` lacks group 11 is
/// `DEX_NOT_LIQUIDITY`; a listed SCaaS input whose code answers no `ILiquidityPullToken` (a token of an earlier release, its
/// code set by `anvil_setCode` after the listing) is `LIQUIDITY_TOKEN_UNSUPPORTED`; a marked DEX whose simulation answers
/// `NotLiquidityDex(dex)` (T7 starved) is requeued, never `dead`; `LIQUIDITY_TOO_LARGE` under a lane's `max_gas_per_tx` of 1 M
/// (the block 200 M; two inputs, 1.1 M) and under a 1 M block (`max_gas_per_tx` 3 M; one input, 1.05 M). L6d, the order's own
/// pre-checks on the deployed DEX, each one change from a mined add: the same order again is `consumed`
/// (`LIQUIDITY_ORDER_CLOSED`, pulled), a signature over
/// another digest `BAD_SIGNATURE`, another relayer `LIQUIDITY_WRONG_RELAYER`, a signed `validUntil` past while the job's is
/// ahead `expired before submit`, a marked DEX answering another `liquidityOrderDigest` `LIQUIDITY_DIGEST_MISMATCH`. Every
/// refusal sends nothing.
#[tokio::test]
#[ignore]
async fn liquidity_pre_checks_on_a_chain() {
    let chain_id = 31917;
    let (_anvil, rpc) = start_anvil(chain_id, 31917).await;
    let alice = small_key(0xA11CE);
    let carol = Address::repeat_byte(0xca);
    let dep = deploy(&rpc, chain_id, alice.address());
    let at = |k: &str| -> Address { dep[k].as_str().unwrap().parse().unwrap() };
    let uid: B256 = dep["chain_uid"].as_str().unwrap().parse().unwrap();
    let (a, b, factory) = (at("demo_token"), at("demo_token_2"), at("token_factory"));
    let deployer = key(DEPLOYER);
    let dex = create(&rpc, &deployer, factory, createDexCall { version: 1, initArgs: DexConfig { owner: deployer.address().into_word(),
        relayerSharePpm: 0, treasury: Address::repeat_byte(0x7a), listedOnly: false, grantDelay: 0, rescueTo: Address::ZERO }.abi_encode().into(),
        salt: B256::repeat_byte(0x11) }.abi_encode()).await;
    send(&rpc, &deployer, dex, setMarketCall { base: a, quote: b, listed: true }.abi_encode()).await;
    let ms = view(&rpc, dex, scaas_node::abi::ISCaaSDex::modulesCall {}).await;
    assert_eq!(ms.len(), 2, "the governance and the liquidity module");
    let mut pair_code = liquidity_mock("MockV2LiquidityPair", false);
    pair_code.extend((a, b).abi_encode_params());
    let pair = deploy_code(&rpc, &deployer, pair_code).await;
    let node_dex = |ms: Vec<Address>, wrong: bool| {
        let mut c = liquidity_mock("MockNodeDex", false);
        c.extend((uid, ms, wrong).abi_encode_params());
        c
    };
    let old_dex = deploy_code(&rpc, &deployer, node_dex(vec![ms[0]], false)).await;
    let starved_dex = deploy_code(&rpc, &deployer, node_dex(ms.clone(), false)).await;
    let wrong_dex = deploy_code(&rpc, &deployer, node_dex(ms.clone(), true)).await;

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![format!("{a:#x}"), format!("{b:#x}")], ..Default::default() }));
    let odoo = odoo_at(start_fake(state.clone()).await);
    let pr = ProviderBuilder::new().connect_http(rpc.parse().unwrap());
    let sends = || async { pr.get_transaction_count(key(RELAYER).address()).await.unwrap() };
    let reports = |id: i64| state.lock().unwrap().reports.iter().filter(|r| r["job_id"] == id).cloned().collect::<Vec<_>>();
    let ix = |t: Address, d: Vec<u8>| json!({"target": format!("{t:#x}"), "data": format!("0x{}", alloy::hex::encode(d))});
    let add_n = |x: u64| json!([ix(a, IToken::transferCall { to: pair, value: U256::from(x) }.abi_encode()),
        ix(b, IToken::transferCall { to: pair, value: U256::from(x) }.abi_encode()),
        ix(pair, liq::mintCall { to: dex }.abi_encode())]);
    let add = add_n(100_000);

    // the positive control: the deployed DEX, two SCaaS inputs, mined; the node's `h` is the DEX's
    let mut s = liquidity_lane(chain_id, &rpc, &odoo, dex, "e2e-liq-dex").await;
    let j1 = liquidity_job(1, (chain_id, uid, dex), &alice, &[(a, 100_000), (b, 100_000)], (pair, 98_000, carol), add.clone());
    let (w1, _) = scaas_node::submit::work_of_op(Some(1), &j1["op"], None).unwrap();
    let o1 = scaas_node::abi::ISCaaSDex::mtxLiquidityCall::abi_decode(&w1.data).unwrap().p.order;
    assert_eq!(view(&rpc, dex, scaas_node::abi::ISCaaSDex::liquidityOrderDigestCall { o: o1.clone() }).await,
        scaas_node::dex::liquidity_order_hash(&domain("SCaaS Dex", chain_id, dex, uid), &o1), "the node's h is the DEX's");
    state.lock().unwrap().jobs.push(j1.clone());
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 1)["chain_state"], "mined", "{}", report(&state, 1));
    assert!(balance(&rpc, pair, carol).await >= U256::from(98_000u64), "the LP to the recipient");
    // L6d's positive control: a second add of 1 000 each, mined; jobs 7-9 and 11 are this shape with one change
    let two = [(a, 1_000), (b, 1_000)];
    let dom = (chain_id, uid, dex);
    state.lock().unwrap().jobs.push(liquidity_job(12, dom, &alice, &two, (pair, 1, carol), add_n(1_000)));
    run_outbox(&mut s).await;
    assert_eq!(report(&state, 12)["chain_state"], "mined", "{}", report(&state, 12));
    let n0 = sends().await;

    // L6d: the order's own pre-checks (spec §11), each one change from a passing job; every miss listed at once
    let mut red: Vec<String> = vec![];
    let mut want = |id: i64, st: &str, code: &str| {
        let r = reports(id).pop().unwrap_or_default();
        if !(r["chain_state"] == st && r["error"].as_str().unwrap_or_default().contains(code)) {
            red.push(format!("job {id}: want {st} {code}, got {r}"));
        }
    };
    let mut j6 = j1.clone();
    j6["id"] = json!(6);
    let mut j7 = liquidity_job(7, dom, &alice, &two, (pair, 1, carol), add_n(1_000));
    j7["op"]["args"]["p"]["auth"]["signature"] = json!(sign_hash(&alice, B256::repeat_byte(7)));
    let mut j8 = liquidity_job(8, dom, &alice, &two, (pair, 1, carol), add_n(1_000));
    j8["op"]["args"]["p"]["order"]["relayer"] = json!(format!("{:#x}", Address::repeat_byte(0xbe)));
    sign_liquidity(&mut j8, dom, &alice);
    let mut j9 = liquidity_job(9, dom, &alice, &two, (pair, 1, carol), add_n(1_000));
    j9["op"]["args"]["p"]["order"]["validUntil"] = json!((now() - 1).to_string());
    sign_liquidity(&mut j9, dom, &alice);
    state.lock().unwrap().jobs.extend([j6, j7, j8, j9]);
    run_outbox(&mut s).await;
    want(6, "consumed", "LIQUIDITY_ORDER_CLOSED");
    want(7, "dead", "BAD_SIGNATURE");
    want(8, "dead", "LIQUIDITY_WRONG_RELAYER");
    want(9, "dead", "expired before submit");
    let mut s = liquidity_lane(chain_id, &rpc, &odoo, wrong_dex, "e2e-liq-wrong").await;
    state.lock().unwrap().jobs.push(liquidity_job(10, (chain_id, uid, wrong_dex), &alice, &two, (pair, 1, carol), add_n(1_000)));
    run_outbox(&mut s).await;
    want(10, "dead", "LIQUIDITY_DIGEST_MISMATCH");
    // the budget against the lane's per-transaction cap, below the block's 200 M: two inputs need 1.1 M, the lane allows 1 M
    let cfg = ChainCfg { max_gas_per_tx: 1_000_000, ..chain_cfg(chain_id, &rpc, Some(dex)) };
    let mut s = Submitter::start(Chain::with_signer(&cfg, key(RELAYER)).unwrap(), odoo.clone(), cfg, "e2e-liq-pertx".into(),
        Default::default()).await.unwrap();
    state.lock().unwrap().jobs.push(liquidity_job(11, dom, &alice, &two, (pair, 1, carol), add_n(1_000)));
    run_outbox(&mut s).await;
    want(11, "dead", "LIQUIDITY_TOO_LARGE");
    assert!(red.is_empty(), "{red:#?}");

    // a DEX of the release before the liquidity module: bound, on the profile, no group 11
    let mut s = liquidity_lane(chain_id, &rpc, &odoo, old_dex, "e2e-liq-old").await;
    state.lock().unwrap().jobs.push(liquidity_job(2, (chain_id, uid, old_dex), &alice, &[(a, 1_000)], (pair, 1, carol), add.clone()));
    run_outbox(&mut s).await;
    let r2 = report(&state, 2);
    assert!(r2["chain_state"] == "dead" && r2["error"].as_str().unwrap_or_default().starts_with("DEX_NOT_LIQUIDITY"), "{r2}");

    // a token of an earlier release as a SCaaS input: the DEX still lists it SCaaS, its code answers no ILiquidityPullToken
    let earlier = format!("0x{}", alloy::hex::encode(liquidity_mock("MockEarlierToken", true)));
    let _: Value = pr.raw_request("anvil_setCode".into(), (b, earlier)).await.unwrap();
    assert_eq!(view(&rpc, dex, scaas_node::abi::ISCaaSDex::tokenKindCall { token: b }).await, 1, "still a SCaaS input to the DEX");
    let mut s = liquidity_lane(chain_id, &rpc, &odoo, dex, "e2e-liq-earlier").await;
    state.lock().unwrap().jobs.push(liquidity_job(3, (chain_id, uid, dex), &alice, &[(a, 1_000), (b, 1_000)], (pair, 1, carol), add.clone()));
    run_outbox(&mut s).await;
    let r3 = report(&state, 3);
    assert!(r3["chain_state"] == "dead" && r3["error"].as_str().unwrap_or_default().starts_with("LIQUIDITY_TOKEN_UNSUPPORTED"), "{r3}");

    // T7 starved on a marked DEX: requeued, never dead
    let mut s = liquidity_lane(chain_id, &rpc, &odoo, starved_dex, "e2e-liq-starved").await;
    state.lock().unwrap().jobs.push(liquidity_job(4, (chain_id, uid, starved_dex), &alice, &[(a, 1_000)], (pair, 1, carol), add.clone()));
    run_outbox(&mut s).await;
    let r4 = reports(4);
    assert!(!r4.is_empty() && r4.iter().all(|r| r["chain_state"] == "queued"), "requeued, never dead: {r4:?}");
    assert!(r4.iter().all(|r| r["error"].as_str().unwrap_or_default().contains("NotLiquidityDex(")), "{r4:?}");

    // the verify budget against this chain's block: a native signer's one input needs 1.05 M, the block holds 1 M, the lane's
    // max_gas_per_tx 3 M
    let _: Value = pr.raw_request("evm_setBlockGasLimit".into(), (U256::from(1_000_000u64),)).await.unwrap();
    let _: Value = pr.raw_request("evm_mine".into(), ()).await.unwrap();
    let mut s = liquidity_lane(chain_id, &rpc, &odoo, dex, "e2e-liq-large").await;
    state.lock().unwrap().jobs.push(liquidity_job(5, (chain_id, uid, dex), &alice, &[(a, 1_000)], (pair, 1, carol), add));
    run_outbox(&mut s).await;
    let r5 = report(&state, 5);
    assert!(r5["chain_state"] == "dead" && r5["error"].as_str().unwrap_or_default().starts_with("LIQUIDITY_TOO_LARGE"), "{r5}");
    assert_eq!(sends().await, n0, "no refusal sends");
}
